//! Delivering an [`NftRuleset`] to the kernel through `nft --json`.
//!
//! Two halves on purpose. [`render_batch`] turns our IR into the nftables JSON
//! model and is pure — it runs and is tested on any host, including the Windows
//! dev machine. [`NftCliEnforcement`] is the thin part that actually shells out
//! to `nft`, and it is the only piece that needs Linux, root and the binary
//! installed.
//!
//! ## Why the whole table is replaced every time
//!
//! The batch always reads: add our table (a no-op if it exists), flush it, then
//! add the chain and every rule. `nft` applies a batch as one transaction, so
//! the kernel goes from the old ruleset to the new one with nothing in between
//! — no window where a rule is missing and traffic leaks. It also makes
//! reconcile idempotent by construction: applying the same plan twice produces
//! the same table, with no diffing and no state to drift.
//!
//! Flushing is scoped to OUR table, never the ruleset: anything another program
//! installed is untouched, which is the difference between a routing product
//! and a firewall that owns the machine.

use std::borrow::Cow;

use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField};
use nftables::schema::{Chain, NfListObject, Nftables, Rule, Table};
use nftables::stmt::{Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use crate::nft_ir::{NftMatch, NftRule, NftRuleset, NftVerdict};

/// Render the ruleset as a single nftables transaction.
///
/// Pure: no process is started and no kernel is touched, so the shape of what
/// would be applied is assertable in a unit test.
pub fn render_batch<'a>(ruleset: &'a NftRuleset) -> Nftables<'a> {
    let family = NfFamily::INet;
    let table_name: Cow<'a, str> = Cow::Borrowed(ruleset.table.as_str());
    let chain_name: Cow<'a, str> = Cow::Borrowed(ruleset.chain.as_str());

    let mut batch = Batch::new();

    // Create-then-flush: `add` is idempotent, and the flush that follows means
    // the rules below are the complete content of our table rather than an
    // append to whatever was there before.
    batch.add(NfListObject::Table(Table {
        family,
        name: table_name.clone(),
        handle: None,
    }));
    batch.add_cmd(nftables::schema::NfCmd::Flush(
        nftables::schema::FlushObject::Table(Table {
            family,
            name: table_name.clone(),
            handle: None,
        }),
    ));

    batch.add(NfListObject::Chain(Chain {
        family,
        table: table_name.clone(),
        name: chain_name.clone(),
        newname: None,
        handle: None,
        _type: Some(NfChainType::Filter),
        hook: Some(NfHook::Output),
        prio: Some(0),
        dev: None,
        // Accept: this product routes traffic, it does not firewall the host.
        // A `drop` policy would cut every flow the plan says nothing about.
        policy: Some(NfChainPolicy::Accept),
    }));

    for rule in &ruleset.rules {
        batch.add(NfListObject::Rule(Rule {
            family,
            table: table_name.clone(),
            chain: chain_name.clone(),
            expr: Cow::Owned(render_rule(rule)),
            handle: None,
            index: None,
            comment: (!rule.comment.is_empty()).then_some(Cow::Borrowed(rule.comment.as_str())),
        }));
    }

    batch.to_nftables()
}

fn render_rule(rule: &NftRule) -> Vec<Statement<'static>> {
    let mut statements: Vec<Statement<'static>> = rule.matches.iter().map(render_match).collect();
    statements.push(match rule.verdict {
        NftVerdict::Accept => Statement::Accept(None),
        NftVerdict::Drop => Statement::Drop(None),
    });
    statements
}

fn render_match(m: &NftMatch) -> Statement<'static> {
    match m {
        NftMatch::DstV4 { net, prefix } => address_match("ip", &net.to_string(), *prefix, 32),
        NftMatch::DstV6 { net, prefix } => address_match("ip6", &net.to_string(), *prefix, 128),
        NftMatch::Protocol(proto) => Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::Number(u32::from(*proto)),
            op: Operator::EQ,
        }),
        NftMatch::DstPort(port) => Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("th"),
                    field: Cow::Borrowed("dport"),
                },
            ))),
            right: Expression::Number(u32::from(*port)),
            op: Operator::EQ,
        }),
        NftMatch::OutInterface(dev) => Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::Oifname,
            })),
            right: Expression::String(Cow::Owned(dev.clone())),
            op: Operator::EQ,
        }),
        NftMatch::SkUid(uid) => Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::Skuid,
            })),
            right: Expression::Number(*uid),
            op: Operator::EQ,
        }),
    }
}

/// A host match is `daddr == addr`; a subnet is `daddr & mask == net`, which
/// nftables expresses as a prefix on the right-hand side.
fn address_match(
    protocol: &'static str,
    address: &str,
    prefix: u8,
    host_prefix: u8,
) -> Statement<'static> {
    let left = Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Borrowed(protocol),
            field: Cow::Borrowed("daddr"),
        },
    )));
    let right = if prefix == host_prefix {
        Expression::String(Cow::Owned(address.to_owned()))
    } else {
        Expression::Named(NamedExpression::Prefix(nftables::expr::Prefix {
            addr: Box::new(Expression::String(Cow::Owned(address.to_owned()))),
            len: u32::from(prefix),
        }))
    };
    Statement::Match(Match {
        left,
        right,
        op: Operator::EQ,
    })
}

// ── The Linux-only half ──────────────────────────────────────────────────────

/// Why applying a ruleset failed. Separated from the render step so a caller
/// can tell "we built something invalid" from "the host cannot run `nft`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NftApplyError {
    /// `nft` is not installed, or is too old for the JSON API.
    NftUnavailable { detail: String },
    /// `nft` ran and refused the ruleset.
    Rejected { detail: String },
}

impl std::fmt::Display for NftApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NftUnavailable { detail } => write!(
                f,
                "the nftables command-line tool (nft) is unavailable: {detail}. \
                 Install the `nftables` package and retry"
            ),
            Self::Rejected { detail } => write!(f, "nft refused the ruleset: {detail}"),
        }
    }
}

impl std::error::Error for NftApplyError {}

/// Applies rulesets by driving `nft`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NftCliEnforcement;

impl NftCliEnforcement {
    pub const fn new() -> Self {
        Self
    }

    /// Apply the ruleset as one transaction.
    #[cfg(target_os = "linux")]
    pub fn apply(&self, ruleset: &NftRuleset) -> Result<(), NftApplyError> {
        let batch = render_batch(ruleset);
        nftables::helper::apply_ruleset(&batch).map_err(classify_error)
    }

    /// Remove everything this product installed, and nothing else: our table is
    /// deleted whole. A ruleset-wide flush would take other programs' rules
    /// with it.
    #[cfg(target_os = "linux")]
    pub fn teardown(&self, table: &str) -> Result<(), NftApplyError> {
        let mut batch = Batch::new();
        batch.delete(NfListObject::Table(Table {
            family: NfFamily::INet,
            name: Cow::Owned(table.to_owned()),
            handle: None,
        }));
        nftables::helper::apply_ruleset(&batch.to_nftables()).map_err(classify_error)
    }

    /// Whether `nft` can be reached at all. Called at daemon start so a missing
    /// package is a clear refusal up front, rather than a failure on the first
    /// rule the user expects to be enforced.
    #[cfg(target_os = "linux")]
    pub fn probe(&self) -> Result<(), NftApplyError> {
        nftables::helper::get_current_ruleset()
            .map(|_| ())
            .map_err(classify_error)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self, _ruleset: &NftRuleset) -> Result<(), NftApplyError> {
        Err(Self::not_linux())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn teardown(&self, _table: &str) -> Result<(), NftApplyError> {
        Err(Self::not_linux())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn probe(&self) -> Result<(), NftApplyError> {
        Err(Self::not_linux())
    }

    #[cfg(not(target_os = "linux"))]
    fn not_linux() -> NftApplyError {
        NftApplyError::NftUnavailable {
            detail: "nftables exists only on Linux".to_owned(),
        }
    }
}

/// Map the crate's error onto ours. The distinction that matters to a caller is
/// "the tool is missing" (tell the user to install a package) versus "the tool
/// rejected what we built" (our bug, and the detail belongs in a report).
#[cfg(target_os = "linux")]
fn classify_error(err: nftables::helper::NftablesError) -> NftApplyError {
    use nftables::helper::NftablesError;
    match err {
        NftablesError::NftExecution { inner, .. } => NftApplyError::NftUnavailable {
            detail: inner.to_string(),
        },
        other => NftApplyError::Rejected {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nft_ir::{NftFamily, NftRule};
    use std::net::Ipv4Addr;

    fn ruleset(rules: Vec<NftRule>) -> NftRuleset {
        NftRuleset {
            family: NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            rules,
        }
    }

    fn json_of(ruleset: &NftRuleset) -> String {
        serde_json::to_string(&render_batch(ruleset)).expect("the batch must serialise")
    }

    /// The transaction has to create the table, flush it, then rebuild — in
    /// that order. Rebuilding without the flush would append to the previous
    /// ruleset; flushing without re-adding first fails on a clean machine.
    #[test]
    fn the_batch_adds_the_table_then_flushes_it_before_any_rule() {
        let json = json_of(&ruleset(Vec::new()));
        let add_at = json.find(r#""add""#).expect("an add command");
        let flush_at = json.find(r#""flush""#).expect("a flush command");
        assert!(
            add_at < flush_at,
            "table must exist before it is flushed: {json}"
        );
    }

    /// Scoped to our table on purpose: a ruleset-wide flush would delete rules
    /// other programs on the host installed.
    #[test]
    fn the_flush_targets_our_table_never_the_whole_ruleset() {
        let json = json_of(&ruleset(Vec::new()));
        assert!(json.contains(r#""flush":{"table""#), "{json}");
        assert!(!json.contains(r#""flush":{"ruleset""#), "{json}");
    }

    #[test]
    fn the_chain_is_an_output_filter_hook_with_an_accept_policy() {
        let json = json_of(&ruleset(Vec::new()));
        assert!(json.contains(r#""hook":"output""#), "{json}");
        assert!(json.contains(r#""type":"filter""#), "{json}");
        assert!(json.contains(r#""policy":"accept""#), "{json}");
    }

    #[test]
    fn a_rule_renders_its_matches_and_a_terminal_verdict() {
        let json = json_of(&ruleset(vec![NftRule {
            matches: vec![
                NftMatch::SkUid(1000),
                NftMatch::DstV4 {
                    net: Ipv4Addr::new(93, 184, 216, 34),
                    prefix: 32,
                },
                NftMatch::OutInterface("tun0".into()),
            ],
            verdict: NftVerdict::Accept,
            comment: "route-secondary#0".into(),
        }]));
        assert!(json.contains(r#""skuid""#), "{json}");
        assert!(json.contains("93.184.216.34"), "{json}");
        assert!(json.contains(r#""oifname""#), "{json}");
        assert!(json.contains(r#""accept":null"#), "{json}");
        assert!(json.contains("route-secondary#0"), "{json}");
    }

    #[test]
    fn a_subnet_renders_as_a_prefix_and_a_host_does_not() {
        let subnet = json_of(&ruleset(vec![NftRule {
            matches: vec![NftMatch::DstV4 {
                net: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8,
            }],
            verdict: NftVerdict::Drop,
            comment: String::new(),
        }]));
        assert!(subnet.contains(r#""prefix""#), "{subnet}");

        let host = json_of(&ruleset(vec![NftRule {
            matches: vec![NftMatch::DstV4 {
                net: Ipv4Addr::new(10, 0, 0, 1),
                prefix: 32,
            }],
            verdict: NftVerdict::Drop,
            comment: String::new(),
        }]));
        assert!(!host.contains(r#""prefix""#), "{host}");
    }

    /// Rule order is the whole arbitration mechanism on this platform, so the
    /// batch must preserve it exactly.
    #[test]
    fn rules_keep_the_order_the_lowering_produced() {
        let json = json_of(&ruleset(vec![
            NftRule {
                matches: Vec::new(),
                verdict: NftVerdict::Accept,
                comment: "first".into(),
            },
            NftRule {
                matches: Vec::new(),
                verdict: NftVerdict::Drop,
                comment: "second".into(),
            },
        ]));
        let first = json.find("first").expect("first rule");
        let second = json.find("second").expect("second rule");
        assert!(first < second, "{json}");
    }

    /// Same input, same transaction — the property that makes re-apply a no-op.
    #[test]
    fn rendering_is_deterministic() {
        let set = ruleset(vec![NftRule {
            matches: vec![NftMatch::Protocol(17), NftMatch::DstPort(53)],
            verdict: NftVerdict::Accept,
            comment: "catch-all-exempt#0".into(),
        }]);
        assert_eq!(json_of(&set), json_of(&set));
    }
}

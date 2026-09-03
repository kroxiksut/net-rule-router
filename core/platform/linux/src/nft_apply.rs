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

/// One rule the kernel would not accept, dropped so the rest could apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedNftRule {
    /// Position in the ruleset as it was built.
    pub index: usize,
    /// The rule's comment — the only human-readable thing it carries, and what
    /// names the user rule behind it in a report.
    pub comment: String,
}

/// What a best-effort apply actually put in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftApplyOutcome {
    /// Rules the kernel accepted.
    pub applied: usize,
    /// Rules dropped to get there. Empty on a clean apply.
    pub skipped: Vec<SkippedNftRule>,
}

/// Why applying a ruleset failed. Separated from the render step so a caller
/// can tell "we built something invalid" from "the host cannot run `nft`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NftApplyError {
    /// `nft` is not installed, or is too old for the JSON API.
    NftUnavailable { detail: String },
    /// The process lacks the privilege to change the ruleset, or the kernel has
    /// no `nf_tables` at all. Distinct from [`Self::Rejected`] because it is
    /// about the ENVIRONMENT, not about what we built: retrying the same
    /// ruleset can only fail the same way, and the operator has something to
    /// fix (run privileged, load the module, leave the restricted container).
    NotPermitted { detail: String },
    /// `nft` ran and refused the ruleset. Our bug: the detail belongs in a
    /// report, and a retry is pointless until the ruleset changes.
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
            Self::NotPermitted { detail } => write!(
                f,
                "the kernel refused the nftables change: {detail}.                  Check that the service runs privileged (CAP_NET_ADMIN) and                  that this kernel has nf_tables"
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

    /// Apply, and if the kernel refuses the batch, apply everything it does
    /// accept — naming what it would not.
    ///
    /// nft applies a batch as ONE transaction, so a single rule the kernel
    /// rejects takes the whole ruleset with it. That is the right default for a
    /// plan we built ourselves; it is the wrong one for a plan built partly
    /// from somebody else's imported rules, where one unexpressible rule left
    /// the user with no policy at all instead of all-but-one. Windows already
    /// draws that line ([`FilterFailureMode::BestEffort`]); this is the same
    /// line here.
    ///
    /// The search runs on `nft --check`, which validates a batch and applies
    /// NOTHING, so the live ruleset is untouched until the final apply. Halving
    /// costs `log2(n)` checks per offending rule, and the whole thing only runs
    /// on a failure.
    ///
    /// An environment failure (no `nft`, no privilege, no `nf_tables`) is
    /// returned as-is: every subset would fail the same way, and searching
    /// through them says nothing.
    #[cfg(target_os = "linux")]
    pub fn apply_best_effort(
        &self,
        ruleset: &NftRuleset,
    ) -> Result<NftApplyOutcome, NftApplyError> {
        match self.apply(ruleset) {
            Ok(()) => Ok(NftApplyOutcome {
                applied: ruleset.rules.len(),
                skipped: Vec::new(),
            }),
            Err(
                e @ (NftApplyError::NftUnavailable { .. } | NftApplyError::NotPermitted { .. }),
            ) => Err(e),
            Err(rejected) => {
                let offenders = self.offending_rules(ruleset);
                if offenders.is_empty() {
                    // The batch is refused but no single rule is: the ruleset is
                    // wrong as a whole, and dropping rules would be guessing.
                    return Err(rejected);
                }
                let (kept, skipped) = without_rules(ruleset, &offenders);
                self.apply(&kept)?;
                Ok(NftApplyOutcome {
                    applied: kept.rules.len(),
                    skipped,
                })
            }
        }
    }

    /// Indices of the rules the kernel will not accept, found by halving.
    ///
    /// Each probe is an `nft --check` of a ruleset built from the candidate
    /// rules alone. Testing a subset in isolation is fair because nft rejects a
    /// rule on its own merits — an unknown match, an interface that cannot be
    /// named — not on its neighbours.
    ///
    /// Budgeted: a ruleset where a large share of the rules are bad would
    /// otherwise turn one failed apply into hundreds of probes. Past the budget
    /// the search gives up and reports nothing, which the caller reads as "no
    /// single rule is at fault" and surfaces the original refusal.
    #[cfg(target_os = "linux")]
    fn offending_rules(&self, ruleset: &NftRuleset) -> Vec<usize> {
        /// Enough for `log2` over a few thousand rules with room for many
        /// offenders, and small enough that a pathological set gives up fast.
        const PROBE_BUDGET: usize = 256;

        let mut budget = PROBE_BUDGET;
        let mut found = Vec::new();
        let all: Vec<usize> = (0..ruleset.rules.len()).collect();
        self.search_offenders(ruleset, &all, &mut budget, &mut found);
        found.sort_unstable();
        found
    }

    #[cfg(target_os = "linux")]
    fn search_offenders(
        &self,
        ruleset: &NftRuleset,
        candidates: &[usize],
        budget: &mut usize,
        found: &mut Vec<usize>,
    ) {
        if candidates.is_empty() || *budget == 0 {
            return;
        }
        *budget -= 1;
        if self.check_subset(ruleset, candidates).is_ok() {
            return;
        }
        if candidates.len() == 1 {
            found.push(candidates[0]);
            return;
        }
        let (left, right) = candidates.split_at(candidates.len() / 2);
        self.search_offenders(ruleset, left, budget, found);
        self.search_offenders(ruleset, right, budget, found);
    }

    /// `nft --check` over the ruleset restricted to `indices`. Validates only —
    /// the kernel is not modified.
    #[cfg(target_os = "linux")]
    fn check_subset(&self, ruleset: &NftRuleset, indices: &[usize]) -> Result<(), NftApplyError> {
        let subset = NftRuleset {
            family: ruleset.family,
            table: ruleset.table.clone(),
            chain: ruleset.chain.clone(),
            rules: indices.iter().map(|&i| ruleset.rules[i].clone()).collect(),
        };
        let batch = render_batch(&subset);
        nftables::helper::apply_ruleset_with_args(
            &batch,
            nftables::helper::DEFAULT_NFT,
            ["--check"],
        )
        .map_err(classify_error)
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
        match nftables::helper::apply_ruleset(&batch.to_nftables()) {
            Ok(()) => Ok(()),
            Err(e) => {
                let detail = e.to_string();
                // A table that is already gone is the state teardown wants.
                // Windows says so for its own delete (`FWP_E_FILTER_NOT_FOUND`
                // classifies as `Idempotent`); here the same answer arrived as a
                // failure, so a second stop — or a stop after somebody flushed
                // the ruleset — reported that it could not clean up something
                // that was already clean.
                if is_absent_object(&detail) {
                    return Ok(());
                }
                Err(classify_error(e))
            }
        }
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
    pub fn apply_best_effort(
        &self,
        _ruleset: &NftRuleset,
    ) -> Result<NftApplyOutcome, NftApplyError> {
        Err(Self::not_linux())
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
        other => {
            let detail = other.to_string();
            // One variant carried three very different answers — "the ruleset
            // is invalid", "we lack CAP_NET_ADMIN" and "this kernel has no
            // nf_tables" — and the orchestrator could not tell "retry" from
            // "pointless". The tool's own words are what separate them; the C
            // locale forced in `crate::command` is what keeps them readable.
            if is_permission_or_kernel_refusal(&detail) {
                NftApplyError::NotPermitted { detail }
            } else {
                NftApplyError::Rejected { detail }
            }
        }
    }
}

/// The ruleset without `offenders`, plus what was taken out.
///
/// Pure, and separate from the search for exactly that reason: dropping the
/// wrong rule is silent — the apply succeeds either way — so this is the part
/// that has to be assertable without a kernel. Order is preserved; nft
/// evaluates rules in order, and a set that keeps the right rules in the wrong
/// sequence is a different policy.
///
/// `offenders` must be sorted and in range; the search that produces them
/// guarantees both.
///
/// Its only caller is Linux-gated, but the function is pure and its tests run
/// everywhere — which is the point of keeping it separate from the search.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn without_rules(ruleset: &NftRuleset, offenders: &[usize]) -> (NftRuleset, Vec<SkippedNftRule>) {
    let skipped = offenders
        .iter()
        .filter_map(|&i| {
            ruleset.rules.get(i).map(|rule| SkippedNftRule {
                index: i,
                comment: rule.comment.clone(),
            })
        })
        .collect();
    let kept = NftRuleset {
        family: ruleset.family,
        table: ruleset.table.clone(),
        chain: ruleset.chain.clone(),
        rules: ruleset
            .rules
            .iter()
            .enumerate()
            .filter(|(i, _)| !offenders.contains(i))
            .map(|(_, rule)| rule.clone())
            .collect(),
    };
    (kept, skipped)
}

/// Does this `nft` failure say the object was not there to begin with?
///
/// `nft` answers a delete of an absent table with `No such file or directory`
/// (ENOENT). Teardown wants the table gone; it already is.
#[cfg(target_os = "linux")]
fn is_absent_object(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no such file or directory")
        || lower.contains("does not exist")
        || lower.contains("no such table")
}

/// Does this `nft` failure describe the environment rather than our ruleset?
#[cfg(target_os = "linux")]
fn is_permission_or_kernel_refusal(detail: &str) -> bool {
    const MARKERS: &[&str] = &[
        "operation not permitted",
        "permission denied",
        "not permitted",
        "no such file or directory",
        "protocol not supported",
        "could not process rule: no such file or directory",
    ];
    let lowered = detail.to_ascii_lowercase();
    MARKERS.iter().any(|marker| lowered.contains(marker))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn an_environment_refusal_is_not_reported_as_our_bad_ruleset() {
        // What `nft` says when the caller has no CAP_NET_ADMIN, and when the
        // kernel has no nf_tables at all.
        assert!(is_permission_or_kernel_refusal(
            "Error: Could not process rule: Operation not permitted"
        ));
        assert!(is_permission_or_kernel_refusal(
            "Error: Could not process rule: No such file or directory"
        ));
        // What it says when the ruleset really is wrong — retrying it is
        // pointless for a different reason, and the operator can fix nothing.
        assert!(!is_permission_or_kernel_refusal(
            "Error: syntax error, unexpected string"
        ));
    }
    /// Dropping a refused rule keeps every OTHER rule, in order.
    ///
    /// The failure this guards is silent: the apply succeeds whichever rules
    /// survive, so an off-by-one would enforce a different policy and report
    /// success. Order matters too — nft evaluates in sequence, and the same set
    /// in a different order is a different policy.
    #[test]
    fn removing_the_refused_rules_keeps_the_rest_in_order() {
        let rule = |comment: &str| NftRule {
            matches: Vec::new(),
            verdict: NftVerdict::Accept,
            comment: comment.to_owned(),
        };
        let ruleset = NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: "t".into(),
            chain: "c".into(),
            rules: vec![rule("a"), rule("b"), rule("c"), rule("d")],
        };
        let (kept, skipped) = without_rules(&ruleset, &[1, 3]);
        assert_eq!(
            kept.rules
                .iter()
                .map(|r| r.comment.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "c"],
        );
        assert_eq!(
            skipped
                .iter()
                .map(|s| (s.index, s.comment.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "b"), (3, "d")],
        );
        // Nothing refused: the ruleset comes back whole.
        let (all, none) = without_rules(&ruleset, &[]);
        assert_eq!(all.rules.len(), 4);
        assert!(none.is_empty());
    }
}

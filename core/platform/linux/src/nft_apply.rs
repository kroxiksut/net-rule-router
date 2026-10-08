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
//! The batch always reads: add our table (a no-op if it exists), flush it,
//! recreate the chain, then add every rule. `nft` applies a batch as one transaction, so
//! the kernel goes from the old ruleset to the new one with nothing in between
//! — no window where a rule is missing and traffic leaks. It also makes
//! reconcile idempotent by construction: applying the same plan twice produces
//! the same table, with no diffing and no state to drift.
//!
//! Flushing is scoped to OUR table, never the ruleset: anything another program
//! installed is untouched, which is the difference between a routing product
//! and a firewall that owns the machine.

use std::borrow::Cow;
use std::time::Duration;

use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField};
use nftables::schema::{Chain, FlushObject, NfCmd, NfListObject, Nftables, Rule, Table};
use nftables::stmt::{Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};

use crate::nft_ir::{NftMatch, NftRule, NftRuleset, NftVerdict, NRR_CHAIN_PRIORITY};

const FAMILY: NfFamily = NfFamily::INet;

/// The scratch twin of `table`, where a refused batch is taken apart while the
/// live table keeps enforcing. Derived, not random: every apply of `table`
/// clears a twin a crash left behind inside its own transaction, with no
/// listing of the ruleset first.
pub fn probe_table_name(table: &str) -> String {
    format!("{table}_probe")
}

/// Render the ruleset as a single nftables transaction.
///
/// Pure: no process is started and no kernel is touched, so the shape of what
/// would be applied is assertable in a unit test.
pub fn render_batch<'a>(ruleset: &'a NftRuleset) -> Nftables<'a> {
    let table: Cow<'a, str> = Cow::Borrowed(ruleset.table.as_str());
    let chain: Cow<'a, str> = Cow::Borrowed(ruleset.chain.as_str());

    let mut batch = Batch::new();
    remove_table(&mut batch, Cow::Owned(probe_table_name(&ruleset.table)));

    // Create-then-flush: `add` is idempotent, and the flush that follows means
    // the rules below are the complete content of our table rather than an
    // append to whatever was there before.
    batch.add(NfListObject::Table(table_object(table.clone())));
    batch.add_cmd(NfCmd::Flush(FlushObject::Table(table_object(
        table.clone(),
    ))));

    // Recreated rather than re-added: `add` of a chain whose hook or priority
    // changed is EEXIST, so an upgrade moving either would fail every apply
    // until the table was deleted by hand. The hookless `add` first makes the
    // `delete` valid on a fresh table too.
    batch.add(NfListObject::Chain(chain_object(
        table.clone(),
        chain.clone(),
        false,
    )));
    batch.delete(NfListObject::Chain(chain_object(
        table.clone(),
        chain.clone(),
        false,
    )));
    batch.add(NfListObject::Chain(chain_object(
        table.clone(),
        chain.clone(),
        true,
    )));

    for rule in &ruleset.rules {
        batch.add(rule_object(&table, &chain, rule));
    }
    batch.to_nftables()
}

/// `indices` of the ruleset, applied for real into the probe twin: the kernel
/// judges them as it would in our table, which `nft --check` never asks it to.
/// The chain opens with an unconditional accept, so a probed rule never sees a
/// packet, even if the twin outlives the search.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_probe_batch<'a>(ruleset: &'a NftRuleset, indices: &[usize]) -> Nftables<'a> {
    let table: Cow<'a, str> = Cow::Owned(probe_table_name(&ruleset.table));
    let chain: Cow<'a, str> = Cow::Borrowed(ruleset.chain.as_str());

    let mut batch = Batch::new();
    remove_table(&mut batch, table.clone());
    batch.add(NfListObject::Table(table_object(table.clone())));
    batch.add(NfListObject::Chain(chain_object(
        table.clone(),
        chain.clone(),
        true,
    )));
    batch.add(NfListObject::Rule(Rule {
        family: FAMILY,
        table: table.clone(),
        chain: chain.clone(),
        expr: Cow::Owned(vec![Statement::Accept(None)]),
        handle: None,
        index: None,
        comment: None,
    }));
    for rule in indices.iter().filter_map(|&i| ruleset.rules.get(i)) {
        batch.add(rule_object(&table, &chain, rule));
    }
    batch.to_nftables()
}

/// Our table and its probe twin gone, whether or not either exists.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn render_teardown(table: &str) -> Nftables<'static> {
    let mut batch = Batch::new();
    remove_table(&mut batch, Cow::Owned(table.to_owned()));
    remove_table(&mut batch, Cow::Owned(probe_table_name(table)));
    batch.to_nftables()
}

/// `add` then `delete`: a delete alone fails the whole transaction when the
/// table is absent.
fn remove_table<'a>(batch: &mut Batch<'a>, name: Cow<'a, str>) {
    batch.add(NfListObject::Table(table_object(name.clone())));
    batch.delete(NfListObject::Table(table_object(name)));
}

fn table_object(name: Cow<'_, str>) -> Table<'_> {
    Table {
        family: FAMILY,
        name,
        handle: None,
    }
}

/// `hooked` = our output base chain; otherwise a bare declaration, which an
/// existing base chain accepts whatever its hook.
fn chain_object<'a>(table: Cow<'a, str>, name: Cow<'a, str>, hooked: bool) -> Chain<'a> {
    Chain {
        family: FAMILY,
        table,
        name,
        newname: None,
        handle: None,
        _type: hooked.then_some(NfChainType::Filter),
        hook: hooked.then_some(NfHook::Output),
        prio: hooked.then_some(NRR_CHAIN_PRIORITY),
        dev: None,
        // Accept: this product routes traffic, it does not firewall the host.
        // A `drop` policy would cut every flow the plan says nothing about.
        policy: hooked.then_some(NfChainPolicy::Accept),
    }
}

fn rule_object<'a>(
    table: &Cow<'a, str>,
    chain: &Cow<'a, str>,
    rule: &'a NftRule,
) -> NfListObject<'a> {
    NfListObject::Rule(Rule {
        family: FAMILY,
        table: table.clone(),
        chain: chain.clone(),
        expr: Cow::Owned(render_rule(rule)),
        handle: None,
        index: None,
        comment: (!rule.comment.is_empty()).then_some(Cow::Borrowed(rule.comment.as_str())),
    })
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
        NftMatch::DstSetV4(blocks) => set_match("ip", blocks),
        NftMatch::DstSetV6(blocks) => set_match("ip6", blocks),
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

/// `daddr` in an anonymous set: one lookup in the kernel however many blocks.
fn set_match(
    protocol: &'static str,
    blocks: &[nrr_shared::ip_block::IpBlock],
) -> Statement<'static> {
    let items = blocks
        .iter()
        .map(|block| {
            let address = Expression::String(Cow::Owned(block.network().to_string()));
            nftables::expr::SetItem::Element(if block.is_single_address() {
                address
            } else {
                Expression::Named(NamedExpression::Prefix(nftables::expr::Prefix {
                    addr: Box::new(address),
                    len: u32::from(block.prefix_len()),
                }))
            })
        })
        .collect();
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Borrowed(protocol),
                field: Cow::Borrowed("daddr"),
            },
        ))),
        right: Expression::Named(NamedExpression::Set(items)),
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
    /// `nft` did not finish within its budget and was killed. Whether the
    /// transaction landed is unknown; the next pass replaces the table whole.
    TimedOut { detail: String },
    /// `nft` ran and refused the ruleset. Our bug: the detail belongs in a
    /// report, and a retry is pointless until the ruleset changes.
    Rejected { detail: String },
}

impl NftApplyError {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn detail(&self) -> &str {
        match self {
            Self::NftUnavailable { detail }
            | Self::NotPermitted { detail }
            | Self::TimedOut { detail }
            | Self::Rejected { detail } => detail,
        }
    }
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
                "the kernel refused the nftables change: {detail}. \
                 Check that the service runs privileged (CAP_NET_ADMIN) and \
                 that this kernel has nf_tables"
            ),
            Self::TimedOut { detail } => {
                write!(f, "the nftables command-line tool (nft) hung: {detail}")
            }
            Self::Rejected { detail } => write!(f, "nft refused the ruleset: {detail}"),
        }
    }
}

impl std::error::Error for NftApplyError {}

/// Budget for one `nft` run. A batch of thousands of rules commits in about a
/// second; past this it is wedged, and the whole enforcement pass waits on it.
const NFT_TIMEOUT: Duration = Duration::from_secs(20);

/// `nft`'s exit status when it cannot open a netlink socket to the kernel.
const NFT_EXIT_NONL: i32 = 3;

/// Applies rulesets by driving `nft`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct NftCliEnforcement {
    /// `None` = the installed `nft`. Tests put a shell stand-in here.
    program: Option<&'static str>,
    /// Placed before our own arguments; lets a test's `sh -c` see them as `$@`.
    leading_args: &'static [&'static str],
    timeout: Duration,
}

impl Default for NftCliEnforcement {
    fn default() -> Self {
        Self::new()
    }
}

impl NftCliEnforcement {
    pub const fn new() -> Self {
        Self {
            program: None,
            leading_args: &[],
            timeout: NFT_TIMEOUT,
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) const fn with_program(
        program: &'static str,
        leading_args: &'static [&'static str],
        timeout: Duration,
    ) -> Self {
        Self {
            program: Some(program),
            leading_args,
            timeout,
        }
    }

    /// Apply the ruleset as one transaction.
    #[cfg(target_os = "linux")]
    pub fn apply(&self, ruleset: &NftRuleset) -> Result<(), NftApplyError> {
        self.run_batch(&render_batch(ruleset), &[])
            .map_err(classify)
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
    /// The search applies subsets for real into the probe twin
    /// ([`probe_table_name`]): `nft --check` stops in userspace, and a refusal
    /// only the kernel makes (`EOPNOTSUPP`, `EINVAL`) would go unattributed and
    /// leave the user with no policy at all. The live table is untouched until
    /// the final apply, whose transaction also removes the twin.
    ///
    /// Only a refused apply pays for it: a clean one is still one `nft` run.
    ///
    /// An environment failure (no `nft`, no privilege, no `nf_tables`, a hung
    /// `nft`) is returned as-is: every subset would fail the same way.
    #[cfg(target_os = "linux")]
    pub fn apply_best_effort(
        &self,
        ruleset: &NftRuleset,
    ) -> Result<NftApplyOutcome, NftApplyError> {
        let failure = match self.run_batch(&render_batch(ruleset), &[]) {
            Ok(()) => {
                return Ok(NftApplyOutcome {
                    applied: ruleset.rules.len(),
                    skipped: Vec::new(),
                })
            }
            Err(failure) => failure,
        };
        let worth_a_search = kernel_answered(&failure);
        let refusal = classify(failure);
        if !worth_a_search {
            return Err(refusal);
        }
        // The bare table and chain are the control: refused too, the host or
        // our layout is at fault and no rule is to blame. That also settles an
        // errno `classify` reads as the host's but a single rule can earn.
        match self.apply_in_probe(ruleset, &[]) {
            Ok(()) => {}
            Err(NftApplyError::Rejected { .. }) => return Err(refusal),
            Err(environment) => return Err(environment),
        }
        let outcome = refused_rules(ruleset.rules.len(), refusal, PROBE_BUDGET, |idx| {
            self.apply_in_probe(ruleset, idx)
        })
        .and_then(|offenders| {
            let (kept, skipped) = without_rules(ruleset, &offenders);
            self.apply(&kept)?;
            Ok(NftApplyOutcome {
                applied: kept.rules.len(),
                skipped,
            })
        });
        if outcome.is_err() {
            // Harmless if it fails too: the next apply of the table removes it.
            let mut batch = Batch::new();
            remove_table(&mut batch, Cow::Owned(probe_table_name(&ruleset.table)));
            let _ = self.run_batch(&batch.to_nftables(), &[]);
        }
        outcome
    }

    /// The rules at `indices` applied into the probe twin.
    #[cfg(target_os = "linux")]
    fn apply_in_probe(&self, ruleset: &NftRuleset, indices: &[usize]) -> Result<(), NftApplyError> {
        self.run_batch(&render_probe_batch(ruleset, indices), &[])
            .map_err(classify_probe)
    }

    /// Remove everything this product installed, and nothing else: our table
    /// and its probe twin are deleted whole. A ruleset-wide flush would take
    /// other programs' rules with it.
    #[cfg(target_os = "linux")]
    pub fn teardown(&self, table: &str) -> Result<(), NftApplyError> {
        match self.run_batch(&render_teardown(table), &[]) {
            Ok(()) => Ok(()),
            // A table that is already gone is the state teardown wants —
            // Windows classifies `FWP_E_FILTER_NOT_FOUND` the same way.
            Err(failure) if is_absent_table(&failure) => Ok(()),
            Err(failure) => Err(classify(failure)),
        }
    }

    /// Whether `nft` can be reached at all. Called at daemon start so a missing
    /// package is a clear refusal up front, rather than a failure on the first
    /// rule the user expects to be enforced.
    #[cfg(target_os = "linux")]
    pub fn probe(&self) -> Result<(), NftApplyError> {
        self.run(&["-j", "list", "tables"], None)
            .map(drop)
            .map_err(classify)
    }

    /// How many rules `chain` of `table` holds in the kernel now; `None` when
    /// the table or chain is gone (another program flushed the ruleset). Terse,
    /// so named sets are not listed: this is the cheap check that lets an
    /// unchanged ruleset skip a full apply.
    #[cfg(target_os = "linux")]
    pub fn installed_rule_count(
        &self,
        table: &str,
        chain: &str,
    ) -> Result<Option<usize>, NftApplyError> {
        match self.run(&["-j", "-t", "list", "chain", "inet", table, chain], None) {
            Ok(stdout) => count_listed_rules(&String::from_utf8_lossy(&stdout))
                .map(Some)
                .ok_or_else(|| NftApplyError::Rejected {
                    detail: "nft listed the chain in a form that could not be read".to_owned(),
                }),
            Err(failure) if is_absent_table(&failure) => Ok(None),
            Err(failure) => Err(classify(failure)),
        }
    }

    #[cfg(target_os = "linux")]
    fn run_batch(&self, batch: &Nftables<'_>, extra: &[&str]) -> Result<(), NftRunFailure> {
        let payload = serde_json::to_string(batch).map_err(|e| NftRunFailure::Exited {
            code: None,
            stderr: format!("the batch could not be serialised: {e}"),
        })?;
        let mut args = extra.to_vec();
        args.extend(["-j", "-f", "-"]);
        self.run(&args, Some(&payload)).map(drop)
    }

    /// One `nft` run under a deadline, in the C locale, with both pipes
    /// drained — so a wedged `nft` cannot stall the enforcement pass and its
    /// words can be classified whatever the system language. Returns stdout.
    #[cfg(target_os = "linux")]
    fn run(&self, args: &[&str], input: Option<&str>) -> Result<Vec<u8>, NftRunFailure> {
        let program = self.program.unwrap_or("nft");
        let mut full: Vec<&str> = self.leading_args.to_vec();
        full.extend_from_slice(args);
        let output = match input {
            Some(text) => crate::command::output_with_input(program, &full, text, self.timeout),
            None => crate::command::output_with_timeout(program, &full, self.timeout),
        };
        match output {
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(NftRunFailure::TimedOut(e.to_string()))
            }
            Err(e) => Err(NftRunFailure::Spawn(format!(
                "unable to execute {program}: {e}"
            ))),
            Ok(out) if out.status.success() => Ok(out.stdout),
            Ok(out) => Err(NftRunFailure::Exited {
                code: out.status.code(),
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            }),
        }
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
    pub fn installed_rule_count(
        &self,
        _table: &str,
        _chain: &str,
    ) -> Result<Option<usize>, NftApplyError> {
        Err(Self::not_linux())
    }

    #[cfg(not(target_os = "linux"))]
    fn not_linux() -> NftApplyError {
        NftApplyError::NftUnavailable {
            detail: "nftables exists only on Linux".to_owned(),
        }
    }
}

/// How one `nft` run failed, before it is named for a caller.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum NftRunFailure {
    /// The process never started — no binary, or not executable. Its error
    /// text can read "No such file or directory" too, which is why absence of
    /// a TABLE is only ever read from [`Self::Exited`].
    Spawn(String),
    TimedOut(String),
    Exited {
        code: Option<i32>,
        stderr: String,
    },
}

/// Map a failed run onto what a caller acts on: install a package, fix the
/// environment, wait, or report our bug.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn classify(failure: NftRunFailure) -> NftApplyError {
    match failure {
        NftRunFailure::Spawn(detail) => NftApplyError::NftUnavailable { detail },
        NftRunFailure::TimedOut(detail) => NftApplyError::TimedOut { detail },
        NftRunFailure::Exited { code, stderr } => {
            let environment =
                code == Some(NFT_EXIT_NONL) || is_permission_or_kernel_refusal(&stderr);
            let detail = match code {
                _ if !stderr.is_empty() => stderr,
                Some(status) => format!("nft exited with status {status}"),
                None => "nft was killed by a signal".to_owned(),
            };
            if environment {
                NftApplyError::NotPermitted { detail }
            } else {
                NftApplyError::Rejected { detail }
            }
        }
    }
}

/// Did the refusal come from `nft` or the kernel judging the batch, so that
/// taking it apart could name a rule? Not when `nft` never started, hung, or
/// had no netlink socket.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn kernel_answered(failure: &NftRunFailure) -> bool {
    matches!(failure, NftRunFailure::Exited { code, .. } if *code != Some(NFT_EXIT_NONL))
}

/// A failed probe once the bare probe table was accepted: the host has shown
/// it takes our table, so what is refused now is the rules' doing, even an
/// errno [`classify`] would blame on the host.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn classify_probe(failure: NftRunFailure) -> NftApplyError {
    let judged = kernel_answered(&failure);
    match classify(failure) {
        NftApplyError::NotPermitted { detail } if judged => NftApplyError::Rejected { detail },
        other => other,
    }
}

/// Did `nft` run and say the table was not there to begin with?
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_absent_table(failure: &NftRunFailure) -> bool {
    matches!(failure, NftRunFailure::Exited { stderr, .. } if is_absent_object(stderr))
}

/// Enough for `log2` over a few thousand rules with room for many offenders,
/// and small enough that a pathological set gives up fast.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROBE_BUDGET: usize = 256;

/// Indices of the rules the kernel will not accept, found by halving; `check`
/// applies a subset into the probe twin and answers `Rejected` when refused.
///
/// Testing a subset in isolation is fair because nft rejects a rule on its own
/// merits — an unknown match, an interface that cannot be named — not on its
/// neighbours. Every outcome that would leave a partial or empty policy looking
/// applied is an error instead: a spent budget (unchecked rules may still be
/// bad), every rule refused (the table would be empty), no rule isolated (the
/// ruleset is wrong as a whole, and dropping rules would be guessing).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn refused_rules<F>(
    rule_count: usize,
    refusal: NftApplyError,
    budget: usize,
    mut check: F,
) -> Result<Vec<usize>, NftApplyError>
where
    F: FnMut(&[usize]) -> Result<(), NftApplyError>,
{
    let all: Vec<usize> = (0..rule_count).collect();
    let mut left = budget;
    let mut found = Vec::new();
    if !descend(&all, &mut left, &mut found, &mut check)? {
        return Err(NftApplyError::Rejected {
            detail: format!(
                "{}; the refused rules could not be isolated within {budget} checks",
                refusal.detail()
            ),
        });
    }
    if found.is_empty() {
        return Err(refusal);
    }
    if found.len() == rule_count {
        return Err(NftApplyError::Rejected {
            detail: format!("{}; every rule is refused on its own", refusal.detail()),
        });
    }
    found.sort_unstable();
    Ok(found)
}

/// `Ok(false)` = the budget ran out before `candidates` were settled.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn descend<F>(
    candidates: &[usize],
    budget: &mut usize,
    found: &mut Vec<usize>,
    check: &mut F,
) -> Result<bool, NftApplyError>
where
    F: FnMut(&[usize]) -> Result<(), NftApplyError>,
{
    if candidates.is_empty() {
        return Ok(true);
    }
    if *budget == 0 {
        return Ok(false);
    }
    *budget -= 1;
    match check(candidates) {
        Ok(()) => return Ok(true),
        Err(NftApplyError::Rejected { .. }) => {}
        // A hung or unprivileged `nft` refuses every subset alike: naming
        // rules after it would blame the policy for the host.
        Err(environment) => return Err(environment),
    }
    if let [only] = candidates {
        found.push(*only);
        return Ok(true);
    }
    let (left, right) = candidates.split_at(candidates.len() / 2);
    Ok(descend(left, budget, found, check)? && descend(right, budget, found, check)?)
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_absent_object(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no such file or directory")
        || lower.contains("does not exist")
        || lower.contains("no such table")
}

/// The rules in an `nft -j list chain` answer; `None` when it is not one.
#[cfg(any(target_os = "linux", test))]
fn count_listed_rules(json: &str) -> Option<usize> {
    let listing: serde_json::Value = serde_json::from_str(json).ok()?;
    let objects = listing.get("nftables")?.as_array()?;
    Some(objects.iter().filter(|o| o.get("rule").is_some()).count())
}

/// Does this `nft` failure describe the environment rather than our ruleset?
/// Reliable only because every run is forced to the C locale.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_permission_or_kernel_refusal(detail: &str) -> bool {
    const MARKERS: &[&str] = &[
        "not permitted",
        "permission denied",
        "no such file or directory",
        "protocol not supported",
        // EOPNOTSUPP: a kernel built without the nf_tables piece we asked for.
        "operation not supported",
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

    /// The text reaches the tray and the archive: a source line break must not
    /// leave a run of indentation inside it.
    #[test]
    fn error_texts_carry_no_source_indentation() {
        let detail = "x".to_string();
        for error in [
            NftApplyError::NftUnavailable {
                detail: detail.clone(),
            },
            NftApplyError::NotPermitted {
                detail: detail.clone(),
            },
            NftApplyError::TimedOut {
                detail: detail.clone(),
            },
            NftApplyError::Rejected { detail },
        ] {
            let text = error.to_string();
            assert!(!text.contains("  "), "{text:?}");
        }
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
        assert!(json.contains(r#""prio":-10"#), "{json}");
    }

    /// Each command as `verb kind table[/chain][ hooked]`, in batch order.
    fn commands(batch: &Nftables<'_>) -> Vec<String> {
        let value = serde_json::to_value(batch).expect("the batch must serialise");
        value["nftables"]
            .as_array()
            .expect("a command list")
            .iter()
            .map(|item| {
                let (verb, body) = item
                    .as_object()
                    .and_then(|o| o.iter().next())
                    .expect("one verb per command");
                let (kind, object) = body
                    .as_object()
                    .and_then(|o| o.iter().next())
                    .expect("one object per command");
                let name = match kind.as_str() {
                    "table" => object["name"].as_str().unwrap_or_default().to_owned(),
                    "chain" => format!(
                        "{}/{}",
                        object["table"].as_str().unwrap_or_default(),
                        object["name"].as_str().unwrap_or_default()
                    ),
                    _ => format!(
                        "{}/{}",
                        object["table"].as_str().unwrap_or_default(),
                        object["chain"].as_str().unwrap_or_default()
                    ),
                };
                let hooked = if object.get("hook").is_some() {
                    " hooked"
                } else {
                    ""
                };
                format!("{verb} {kind} {name}{hooked}")
            })
            .collect()
    }

    fn plain(comment: &str) -> NftRule {
        NftRule {
            matches: Vec::new(),
            verdict: NftVerdict::Accept,
            comment: comment.to_owned(),
        }
    }

    #[test]
    fn the_probe_table_is_derived_from_ours_and_distinct() {
        assert_eq!(probe_table_name("nrr"), "nrr_probe");
        assert_ne!(probe_table_name("nrr"), "nrr");
    }

    /// A probe twin a crash left behind goes in the next apply's own
    /// transaction, and the chain is recreated so a hook or priority change
    /// cannot meet an EEXIST from the chain an older version installed.
    #[test]
    fn an_apply_clears_the_probe_twin_and_recreates_the_chain() {
        assert_eq!(
            commands(&render_batch(&ruleset(vec![plain("r")]))),
            vec![
                "add table nrr_probe",
                "delete table nrr_probe",
                "add table nrr",
                "flush table nrr",
                "add chain nrr/output",
                "delete chain nrr/output",
                "add chain nrr/output hooked",
                "add rule nrr/output",
            ]
        );
    }

    /// The probe touches only its twin, sees no packet (an unconditional
    /// accept comes first) and carries exactly the rules asked for.
    #[test]
    fn a_probe_batch_holds_only_the_asked_rules_behind_an_accept() {
        let set = ruleset(vec![plain("a"), plain("b"), plain("c")]);
        let batch = render_probe_batch(&set, &[0, 2]);
        assert_eq!(
            commands(&batch),
            vec![
                "add table nrr_probe",
                "delete table nrr_probe",
                "add table nrr_probe",
                "add chain nrr_probe/output hooked",
                "add rule nrr_probe/output",
                "add rule nrr_probe/output",
                "add rule nrr_probe/output",
            ]
        );
        let value = serde_json::to_value(&batch).expect("the batch must serialise");
        let rules: Vec<&serde_json::Value> = value["nftables"]
            .as_array()
            .expect("a command list")
            .iter()
            .filter_map(|c| c["add"].get("rule"))
            .collect();
        assert_eq!(rules[0]["expr"], serde_json::json!([{ "accept": null }]));
        assert_eq!(rules[1]["comment"], "a");
        assert_eq!(rules[2]["comment"], "c");
        // Same chain shape as ours, so the kernel judges the rules alike.
        let json = serde_json::to_string(&batch).expect("the batch must serialise");
        assert!(json.contains(r#""prio":-10"#), "{json}");
    }

    #[test]
    fn teardown_removes_our_table_and_the_probe_twin_whether_or_not_they_exist() {
        assert_eq!(
            commands(&render_teardown("nrr")),
            vec![
                "add table nrr",
                "delete table nrr",
                "add table nrr_probe",
                "delete table nrr_probe",
            ]
        );
    }

    #[test]
    fn a_chain_listing_counts_its_rules_only() {
        let listing = r#"{"nftables":[{"metainfo":{"json_schema_version":1}},
            {"chain":{"family":"inet","table":"nrr","name":"output"}},
            {"rule":{"handle":4}},{"rule":{"handle":5}}]}"#;
        assert_eq!(count_listed_rules(listing), Some(2));
        assert_eq!(
            count_listed_rules(r#"{"nftables":[{"chain":{}}]}"#),
            Some(0)
        );
        assert_eq!(count_listed_rules("Error: something"), None);
    }

    /// Once the bare probe table was accepted, even an errno `classify` reads
    /// as the host's is the rule's doing; a missing netlink socket stays the
    /// host's.
    #[test]
    fn a_probe_refusal_after_the_control_is_blamed_on_the_rules() {
        let exited = |code, stderr: &str| NftRunFailure::Exited {
            code: Some(code),
            stderr: stderr.to_owned(),
        };
        let enoent = exited(
            1,
            "Error: Could not process rule: No such file or directory",
        );
        assert!(matches!(
            classify(enoent.clone()),
            NftApplyError::NotPermitted { .. }
        ));
        assert!(matches!(
            classify_probe(enoent),
            NftApplyError::Rejected { .. }
        ));
        assert!(matches!(
            classify_probe(exited(NFT_EXIT_NONL, "")),
            NftApplyError::NotPermitted { .. }
        ));
        assert!(matches!(
            classify_probe(NftRunFailure::TimedOut("hung".into())),
            NftApplyError::TimedOut { .. }
        ));
        assert!(!kernel_answered(&NftRunFailure::Spawn("absent".into())));
        assert!(kernel_answered(&exited(1, "Error: Invalid argument")));
    }

    #[test]
    fn a_rule_renders_its_matches_and_a_terminal_verdict() {
        let json = json_of(&ruleset(vec![NftRule {
            matches: vec![
                NftMatch::SkUid(1000),
                NftMatch::DstV4 {
                    net: Ipv4Addr::new(203, 0, 113, 138),
                    prefix: 32,
                },
                NftMatch::OutInterface("tun0".into()),
            ],
            verdict: NftVerdict::Accept,
            comment: "route-secondary#0".into(),
        }]));
        assert!(json.contains(r#""skuid""#), "{json}");
        assert!(json.contains("203.0.113.138"), "{json}");
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

    #[test]
    fn an_environment_refusal_is_not_reported_as_our_bad_ruleset() {
        // One line per marker: no privilege, no nf_tables, no netlink family,
        // a kernel built without the piece asked for.
        for stderr in [
            "Error: Could not process rule: Operation not permitted",
            "netlink: Error: cannot open socket: Permission denied",
            "Error: Could not process rule: No such file or directory",
            "Error: cannot open netlink socket: Protocol not supported",
            "Error: Could not process rule: Operation not supported",
        ] {
            assert!(is_permission_or_kernel_refusal(stderr), "{stderr}");
            // Persistent downstream: the same host refuses the same way.
            assert!(
                matches!(
                    classify(NftRunFailure::Exited {
                        code: Some(1),
                        stderr: stderr.to_owned(),
                    }),
                    NftApplyError::NotPermitted { .. }
                ),
                "{stderr}"
            );
        }
        // What it says when the ruleset really is wrong — retrying it is
        // pointless for a different reason, and the operator can fix nothing.
        assert!(!is_permission_or_kernel_refusal(
            "Error: syntax error, unexpected string"
        ));
    }

    /// A missing `nft` binary says "No such file or directory" too; only a run
    /// of `nft` that answered it may mean "the table is already gone".
    #[test]
    fn only_a_run_nft_can_report_the_table_absent() {
        let missing = NftRunFailure::Spawn(
            "unable to execute nft: No such file or directory (os error 2)".into(),
        );
        assert!(!is_absent_table(&missing));
        assert!(matches!(
            classify(missing),
            NftApplyError::NftUnavailable { .. }
        ));

        let absent = NftRunFailure::Exited {
            code: Some(1),
            stderr: "Error: Could not process rule: No such file or directory".into(),
        };
        assert!(is_absent_table(&absent));
    }

    #[test]
    fn a_run_is_classified_by_its_exit_status_and_stderr() {
        let exited = |code, stderr: &str| NftRunFailure::Exited {
            code: Some(code),
            stderr: stderr.to_owned(),
        };
        assert!(matches!(
            classify(exited(NFT_EXIT_NONL, "")),
            NftApplyError::NotPermitted { .. }
        ));
        assert!(matches!(
            classify(exited(
                1,
                "Error: Could not process rule: Operation not permitted"
            )),
            NftApplyError::NotPermitted { .. }
        ));
        assert!(matches!(
            classify(exited(1, "Error: syntax error, unexpected string")),
            NftApplyError::Rejected { .. }
        ));
        assert!(matches!(
            classify(NftRunFailure::TimedOut(
                "nft did not answer within 20s".into()
            )),
            NftApplyError::TimedOut { .. }
        ));
        // The detail is never empty, even when nft said nothing.
        assert!(!classify(exited(1, "")).to_string().ends_with(": "));
    }

    fn refused(detail: &str) -> NftApplyError {
        NftApplyError::Rejected {
            detail: detail.to_owned(),
        }
    }

    /// A stand-in for a probe apply: refuses any subset holding a bad index.
    fn checker(bad: &'static [usize]) -> impl FnMut(&[usize]) -> Result<(), NftApplyError> {
        move |subset: &[usize]| {
            if subset.iter().any(|i| bad.contains(i)) {
                Err(refused("bad rule"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn the_search_names_exactly_the_refused_rules() {
        let found = refused_rules(8, refused("batch"), PROBE_BUDGET, checker(&[3, 6]));
        assert_eq!(found, Ok(vec![3, 6]));
    }

    /// Out of budget with rules unchecked: a partial list would apply rules
    /// nobody checked and call it success.
    #[test]
    fn a_spent_budget_is_an_error_not_a_partial_list() {
        let bad: &'static [usize] = &[0, 2, 4, 6, 8, 10, 12, 14];
        let result = refused_rules(16, refused("batch"), 6, checker(bad));
        assert!(
            matches!(&result, Err(NftApplyError::Rejected { detail }) if detail.contains("isolated")),
            "{result:?}"
        );
    }

    /// Every rule refused alone leaves an empty table: that is no policy, not
    /// an applied one.
    #[test]
    fn every_rule_refused_is_an_error_not_an_empty_success() {
        let result = refused_rules(3, refused("batch"), PROBE_BUDGET, checker(&[0, 1, 2]));
        assert!(
            matches!(&result, Err(NftApplyError::Rejected { detail }) if detail.contains("every rule")),
            "{result:?}"
        );
    }

    #[test]
    fn no_single_rule_at_fault_returns_the_original_refusal() {
        let result = refused_rules(4, refused("batch"), PROBE_BUDGET, checker(&[]));
        assert_eq!(result, Err(refused("batch")));
    }

    /// A hung `nft` refuses every subset alike; the search must stop at once
    /// rather than blame the rules for the host.
    #[test]
    fn an_environment_failure_stops_the_search() {
        let mut probes = 0;
        let result = refused_rules(64, refused("batch"), PROBE_BUDGET, |_: &[usize]| {
            probes += 1;
            Err(NftApplyError::TimedOut {
                detail: "hung".into(),
            })
        });
        assert!(matches!(result, Err(NftApplyError::TimedOut { .. })));
        assert_eq!(probes, 1);
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

/// The runner against shell stand-ins for `nft`: `sh -c <script> nft <args…>`.
#[cfg(all(test, target_os = "linux"))]
mod cli_tests {
    use super::*;
    use std::time::Instant;

    fn fake(script: &'static str) -> NftCliEnforcement {
        NftCliEnforcement::with_program("/bin/sh", leak(["-c", script, "nft"]), NFT_TIMEOUT)
    }

    fn leak(args: [&'static str; 3]) -> &'static [&'static str] {
        Box::leak(Box::new(args))
    }

    /// The daemon's own locale must not reach `nft`: translated text used to
    /// turn a privilege refusal into "our ruleset is wrong".
    #[test]
    fn a_localised_host_still_reads_a_permission_refusal() {
        let cli = fake(
            r#"if [ "$LC_ALL" = C ]; then echo 'Error: Could not process rule: Operation not permitted' >&2; else echo 'Ошибка: операция не позволена' >&2; fi; exit 1"#,
        );
        assert!(matches!(
            cli.probe(),
            Err(NftApplyError::NotPermitted { .. })
        ));
    }

    /// A missing binary is not a clean machine: the chain may still be in the
    /// kernel, dropping traffic until reboot.
    #[test]
    fn teardown_without_nft_is_a_failure_not_a_clean_stop() {
        let cli = NftCliEnforcement::with_program("/nonexistent/nft", &[], NFT_TIMEOUT);
        assert!(matches!(
            cli.teardown("nrr"),
            Err(NftApplyError::NftUnavailable { .. })
        ));

        // Positive control: nft itself saying the table is gone is success.
        let gone = fake(
            "cat >/dev/null; echo 'Error: Could not process rule: No such file or directory' >&2; exit 1",
        );
        assert_eq!(gone.teardown("nrr"), Ok(()));
    }

    #[test]
    fn a_wedged_nft_is_cut_at_the_budget() {
        let cli = NftCliEnforcement::with_program(
            "/bin/sh",
            leak(["-c", "sleep 30", "nft"]),
            Duration::from_millis(300),
        );
        let started = Instant::now();
        assert!(matches!(cli.probe(), Err(NftApplyError::TimedOut { .. })));
        assert!(started.elapsed() < Duration::from_secs(10));

        // Positive control: an answering nft is not cut.
        assert_eq!(fake("exit 0").probe(), Ok(()));
    }

    /// Far past a pipe buffer on stderr, with the batch still on stdin.
    #[test]
    fn a_large_stderr_does_not_deadlock_the_apply() {
        let cli = fake("cat >/dev/null; yes 'Error: syntax error' | head -c 1048576 >&2; exit 1");
        let empty = NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            rules: Vec::new(),
        };
        assert!(matches!(
            cli.apply(&empty),
            Err(NftApplyError::Rejected { .. })
        ));
    }

    /// The batch reaches `nft` on stdin with the JSON flags, and a probe is a
    /// real apply, never `--check`.
    #[test]
    fn the_batch_goes_to_nft_as_json_on_stdin() {
        let cli = fake(r#"[ "$*" = "-j -f -" ] || exit 7; grep -q '"nrr_probe"' || exit 8"#);
        assert_eq!(cli.apply_in_probe(&set_of(&["a"]), &[0]), Ok(()));
    }

    fn set_of(comments: &[&str]) -> NftRuleset {
        NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            rules: comments
                .iter()
                .map(|c| NftRule {
                    matches: Vec::new(),
                    verdict: crate::nft_ir::NftVerdict::Accept,
                    comment: (*c).to_owned(),
                })
                .collect(),
        }
    }

    /// A stand-in that records every batch it is given, then runs `verdict`
    /// with the batch in `$input`.
    fn recording(test: &str, verdict: &str) -> (NftCliEnforcement, std::path::PathBuf) {
        let log = std::env::temp_dir().join(format!("nrr-nft-{test}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let script = format!(
            "input=$(cat); printf '%s\\n----\\n' \"$input\" >> '{}'; {verdict}",
            log.display()
        );
        let script: &'static str = Box::leak(script.into_boxed_str());
        (fake(script), log)
    }

    fn batches(log: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .split("----\n")
            .filter(|b| !b.trim().is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// The kernel refuses one rule with an errno `classify` would blame on the
    /// host. The probe twin names it, the rest is applied, and the final
    /// transaction removes the twin.
    #[test]
    fn a_rule_only_the_kernel_refuses_is_named_and_the_rest_applied() {
        let (cli, log) = recording(
            "attributed",
            r#"case "$input" in *kernel-refuses*) echo 'Error: Could not process rule: No such file or directory' >&2; exit 1;; esac"#,
        );
        let outcome = cli.apply_best_effort(&set_of(&["a", "kernel-refuses", "c", "d"]));
        assert_eq!(
            outcome,
            Ok(NftApplyOutcome {
                applied: 3,
                skipped: vec![SkippedNftRule {
                    index: 1,
                    comment: "kernel-refuses".into(),
                }],
            })
        );
        let runs = batches(&log);
        let (last, search) = runs[1..].split_last().expect("a search and a final apply");
        for probe in search {
            assert!(!probe.contains(r#""table":"nrr""#), "{probe}");
            assert!(!probe.contains(r#""name":"nrr""#), "{probe}");
        }
        assert!(
            last.contains(r#""delete":{"table":{"family":"inet","name":"nrr_probe""#),
            "{last}"
        );
        assert!(!last.contains("kernel-refuses"), "{last}");
        let _ = std::fs::remove_file(&log);
    }

    /// No privilege: the bare probe table is refused too, so the host is at
    /// fault and no rule is named. One control run, nothing more.
    #[test]
    fn a_refused_control_returns_the_hosts_failure_without_a_search() {
        let (cli, log) = recording(
            "control",
            "echo 'Error: Could not process rule: Operation not permitted' >&2; exit 1",
        );
        assert!(matches!(
            cli.apply_best_effort(&set_of(&["a", "b"])),
            Err(NftApplyError::NotPermitted { .. })
        ));
        assert_eq!(batches(&log).len(), 2);
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn no_netlink_socket_is_not_searched() {
        let (cli, log) = recording("nonl", "exit 3");
        assert!(matches!(
            cli.apply_best_effort(&set_of(&["a"])),
            Err(NftApplyError::NotPermitted { .. })
        ));
        assert_eq!(batches(&log).len(), 1);
        let _ = std::fs::remove_file(&log);
    }

    /// Our table is refused, the probe takes every rule: nothing to drop, the
    /// original refusal stands, and the twin the search left is removed.
    #[test]
    fn a_search_that_names_no_rule_removes_the_probe_twin() {
        let (cli, log) = recording(
            "unnamed",
            r#"case "$input" in *'"flush"'*) echo 'Error: Could not process rule: Invalid argument' >&2; exit 1;; esac"#,
        );
        assert!(matches!(
            cli.apply_best_effort(&set_of(&["a", "b"])),
            Err(NftApplyError::Rejected { .. })
        ));
        let runs = batches(&log);
        let cleanup = runs.last().expect("a cleanup run");
        assert!(
            cleanup.contains(r#""delete":{"table":{"family":"inet","name":"nrr_probe""#),
            "{cleanup}"
        );
        assert!(!cleanup.contains(r#""rule""#), "{cleanup}");
        let _ = std::fs::remove_file(&log);
    }

    /// Live: the folded forms — address sets of both families, hosts beside
    /// networks, next to the user and interface conditions — are taken by this
    /// kernel and this `nft` as they are, not just by the parser. Needs root,
    /// nft and nf_tables.
    #[test]
    #[ignore = "needs root, nft and nf_tables; run with --ignored"]
    fn live_address_sets_apply_on_this_kernel() {
        use nrr_shared::ip_block::IpBlock;
        let table: &'static str =
            Box::leak(format!("nrr_live_sets_{}", std::process::id()).into_boxed_str());
        struct Guard(&'static str);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = NftCliEnforcement::new().teardown(self.0);
            }
        }
        let _guard = Guard(table);
        let blocks = |texts: &[&str]| -> Vec<IpBlock> {
            texts
                .iter()
                .map(|t| IpBlock::parse(t).expect("block"))
                .collect()
        };
        let set = NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: table.to_owned(),
            chain: "output".into(),
            rules: vec![
                NftRule {
                    matches: vec![
                        NftMatch::SkUid(65534),
                        NftMatch::DstSetV4(blocks(&["192.0.2.1/32", "198.51.100.0/24"])),
                        NftMatch::OutInterface("lo".into()),
                    ],
                    verdict: crate::nft_ir::NftVerdict::Accept,
                    comment: "sets-via".into(),
                },
                NftRule {
                    matches: vec![
                        NftMatch::SkUid(65534),
                        NftMatch::DstSetV4(blocks(&["192.0.2.1/32", "198.51.100.0/24"])),
                    ],
                    verdict: crate::nft_ir::NftVerdict::Drop,
                    comment: "sets-guard".into(),
                },
                NftRule {
                    matches: vec![
                        NftMatch::SkUid(65534),
                        NftMatch::DstSetV6(blocks(&["2001:db8::1/128", "2001:db8:1::/48"])),
                        NftMatch::Protocol(6),
                        NftMatch::DstPort(443),
                    ],
                    verdict: crate::nft_ir::NftVerdict::Drop,
                    comment: "sets-v6".into(),
                },
            ],
        };
        let outcome = NftCliEnforcement::new()
            .apply_best_effort(&set)
            .expect("the folded rules must apply");
        assert!(outcome.skipped.is_empty(), "{:?}", outcome.skipped);
        let out = std::process::Command::new("nft")
            .args(["list", "table", "inet", table])
            .output()
            .expect("nft must be runnable");
        let listed = String::from_utf8_lossy(&out.stdout);
        for want in [
            "192.0.2.1",
            "198.51.100.0/24",
            "2001:db8::1",
            "2001:db8:1::/48",
        ] {
            assert!(
                listed.contains(want),
                "{want} missing from:
{listed}"
            );
        }
        for comment in ["sets-via", "sets-guard", "sets-v6"] {
            assert!(
                listed.contains(comment),
                "{comment} missing from:
{listed}"
            );
        }
    }

    /// Live: a rule the kernel refuses (a `fib` lookup by input interface,
    /// which the output hook cannot do), swapped in by a wrapper since our IR
    /// cannot say it. A current `nft --check` passes it and an older one (0.9.x)
    /// already refuses it; the apply never asks `--check`, so either way it must
    /// name that rule and keep the rest. Needs root, nft and nf_tables.
    #[test]
    #[ignore = "needs root, nft and nf_tables; run with --ignored"]
    fn live_a_kernel_only_refusal_is_attributed_through_the_probe_table() {
        let table: &'static str =
            Box::leak(format!("nrr_live_probe_{}", std::process::id()).into_boxed_str());
        struct Guard(&'static str);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = NftCliEnforcement::new().teardown(self.0);
            }
        }
        let _guard = Guard(table);
        let cli = fake(
            r#"sed 's/{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.99"/{"fib":{"result":"oif","flags":["daddr","iif"]}},"right":0/' | nft "$@""#,
        );
        let host = |last: u8, comment: &str| NftRule {
            matches: vec![NftMatch::DstV4 {
                net: std::net::Ipv4Addr::new(192, 0, 2, last),
                prefix: 32,
            }],
            verdict: crate::nft_ir::NftVerdict::Drop,
            comment: comment.to_owned(),
        };
        let set = NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: table.to_owned(),
            chain: "output".into(),
            rules: vec![host(1, "kept-1"), host(99, "refused"), host(3, "kept-3")],
        };
        let outcome = cli
            .apply_best_effort(&set)
            .expect("the other rules must apply");
        assert_eq!(
            outcome.skipped,
            vec![SkippedNftRule {
                index: 1,
                comment: "refused".into(),
            }]
        );
        let listed = |name: &str| {
            let out = std::process::Command::new("nft")
                .args(["list", "table", "inet", name])
                .output()
                .expect("nft must be runnable");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        };
        let (present, ours) = listed(table);
        assert!(present, "our table must be applied");
        assert!(ours.contains("kept-1") && ours.contains("kept-3"), "{ours}");
        assert!(ours.contains("priority filter - 10"), "{ours}");
        assert!(
            !listed(&probe_table_name(table)).0,
            "the probe twin must be gone"
        );
    }
}

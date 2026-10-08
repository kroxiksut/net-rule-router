//! The Linux [`PolicyEnforcer`]: every active user's plan onto one ruleset.
//!
//! Sits above [`crate::nft_backend`] and holds the two things the neutral
//! service cannot: which adapters each principal bound, and what those bindings
//! resolve to on the machine RIGHT NOW.
//!
//! ## Why one pass, never one apply per user
//!
//! Applying our table replaces its whole contents, so looping per user would
//! leave only the last one enforced. Their rules interleave safely because each
//! carries `meta skuid` — a rule scoped to one uid cannot match another user's
//! packet, whatever order it sits in.
//!
//! ## Why resolution happens here, per pass
//!
//! A binding is a name the user saw; the link behind it can go down, be renamed
//! or come back different. Resolving on every pass means a rule whose interface
//! is gone is reported unenforced rather than applied without its pin — which is
//! exactly the moment a pin exists for.

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_platform_api::adapters::AdapterEventSource;
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EgressBindingSource, EnforcementFailure, EnforcementPlan,
    PolicyEnforcer, UserPrincipal,
};
use nrr_platform_api::fake_ip::stale_flows::FlowLinks;

use crate::lower_linux::{lower_scoped, EgressNames, ScopedPlan};
use crate::nft_apply::{NftApplyError, NftCliEnforcement};
use crate::nft_ir::NftRuleset;

/// How long an unchanged ruleset is trusted to still be in the kernel without
/// asking. Past it the next pass lists our chain (a terse `nft list`, far
/// cheaper than an apply) and reapplies only if it is gone. Shorter than the
/// cycle's 5-min full pass, so every full pass checks and the two clocks cannot
/// add up to a longer blind window.
const UNCHANGED_RECHECK: Duration = Duration::from_secs(60);

/// The last ruleset the kernel took whole, and when it was last seen there.
struct Applied {
    ruleset: NftRuleset,
    verified_at: Instant,
    rules: usize,
}

pub struct NftPolicyEnforcer {
    bindings: Arc<dyn EgressBindingSource>,
    adapters: Arc<dyn AdapterEventSource>,
    cli: NftCliEnforcement,
    /// The table this enforcer owns — the product's unless a live test moved it
    /// aside, so a test run can never replace or tear down a daemon's ruleset.
    table: String,
    /// Asks a layer above whether the additional link is actually carrying
    /// traffic, by interface index. A link can be `Up` with an address and still
    /// be a tunnel whose far end is gone — the state of the interface says
    /// nothing about the path behind it.
    ///
    /// A callback rather than the tracker itself: the hysteresis, the baseline
    /// requirement and the evidence-freshness rules are policy and live in the
    /// neutral layer, which this crate must not depend on.
    liveness: Option<LivenessOracle>,
    /// Lets a pass whose ruleset did not change skip the `nft` run — the most
    /// expensive part of an idle pass.
    applied: Mutex<Option<Applied>>,
    /// Set by an explicit apply: the next unchanged pass checks the kernel
    /// whatever the recheck clock says.
    verify_next: AtomicBool,
}

/// `false` = this interface has been declared dead. Anything else — alive,
/// unprobeable, feature off — is `true`, because the only safe direction for an
/// indeterminate answer is "still usable".
pub type LivenessOracle = Arc<dyn Fn(u32) -> bool + Send + Sync>;

impl NftPolicyEnforcer {
    pub fn new(
        bindings: Arc<dyn EgressBindingSource>,
        adapters: Arc<dyn AdapterEventSource>,
    ) -> Self {
        Self {
            bindings,
            adapters,
            cli: NftCliEnforcement::new(),
            table: crate::lower_linux::NRR_TABLE.to_owned(),
            liveness: None,
            applied: Mutex::new(None),
            verify_next: AtomicBool::new(false),
        }
    }

    /// Consult `oracle` about the additional link before calling it available.
    /// Builder-style: without it the enforcer trusts the interface state alone,
    /// which is what it did before any probe existed.
    #[must_use]
    pub fn with_liveness(mut self, oracle: LivenessOracle) -> Self {
        self.liveness = Some(oracle);
        self
    }

    /// Install into `table` instead of the product's own. For live tests only:
    /// the daemon and a test sharing one table would wipe each other's rules.
    #[doc(hidden)]
    #[must_use]
    pub fn with_table(mut self, table: impl Into<String>) -> Self {
        self.table = table.into();
        self
    }

    /// Whether the host can enforce at all — asked once at start so a missing
    /// `nftables` package is a clear refusal rather than a failure on the first
    /// rule the user expects to be applied.
    pub fn probe(&self) -> Result<(), EnforcementFailure> {
        self.cli.probe().map_err(failure)
    }
}

/// Only a hung `nft` may go through on the next pass unchanged; a refusal, a
/// missing privilege or a missing tool meets the same plans the same way.
fn failure(e: NftApplyError) -> EnforcementFailure {
    match e {
        NftApplyError::TimedOut { .. } => EnforcementFailure::transient(e.to_string()),
        NftApplyError::NftUnavailable { .. }
        | NftApplyError::NotPermitted { .. }
        | NftApplyError::Rejected { .. } => EnforcementFailure::persistent(e.to_string()),
    }
}

/// Splits a slow apply into lowering and the `nft` run (render included), which
/// the caller's pass timing sees only as one phase.
fn report_apply_cost(lower: Duration, nft: Duration, rules: usize) {
    const SLOW: Duration = Duration::from_millis(300);
    if lower + nft < SLOW {
        return;
    }
    tracing::info!(
        target: "nrr::enforcement-cost",
        msg_key = "nft-apply-cost",
        lower_ms = lower.as_millis(),
        nft_ms = nft.as_millis(),
        rules,
        "nft apply was slow — lowering vs the nft run",
    );
}

impl NftPolicyEnforcer {
    /// Resolve one principal's bindings against the links present now.
    fn resolve(
        &self,
        principal: &UserPrincipal,
        adapters: &[nrr_platform_api::adapters::AdapterInfo],
    ) -> EgressNames {
        let binding = self.bindings.bindings_for(principal);
        EgressNames::resolve_from_adapters(
            adapters,
            binding.primary.as_deref(),
            binding.secondary.as_deref(),
        )
    }
}

impl PolicyEnforcer for NftPolicyEnforcer {
    fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        // Read the links ONCE for the pass: every plan is resolved against the
        // same snapshot, so two users cannot be enforced against two different
        // states of the machine.
        let adapters = self.adapters.enumerate_all().map_err(|e| {
            EnforcementFailure::transient(format!("adapters could not be read: {e}"))
        })?;

        let resolved: Vec<EgressNames> = plans
            .iter()
            .map(|plan| self.resolve(&plan.principal, &adapters))
            .collect();

        let scoped: Vec<ScopedPlan<'_>> = plans
            .iter()
            .zip(resolved.iter())
            .map(|(plan, egress)| ScopedPlan { plan, egress })
            .collect();

        let started = Instant::now();
        let mut lowered = lower_scoped(&scoped);
        lowered.ruleset.table.clone_from(&self.table);
        let lowered_at = Instant::now();
        let notes_for_unsupported = || -> Vec<String> {
            lowered
                .unsupported
                .iter()
                .map(crate::nft_backend::note_for)
                .collect()
        };

        let mut applied = self.applied.lock().unwrap_or_else(|p| p.into_inner());
        let verify_requested = self.verify_next.swap(false, Ordering::AcqRel);
        if let Some(last) = applied.as_mut() {
            if last.ruleset == lowered.ruleset {
                let verify = verify_requested || last.verified_at.elapsed() >= UNCHANGED_RECHECK;
                // Anything but "our chain, holding every rule" reapplies: a
                // check that failed proves nothing about the kernel.
                let in_place = !verify
                    || matches!(
                        self.cli.installed_rule_count(&self.table, &lowered.ruleset.chain),
                        Ok(Some(n)) if n == last.rules
                    );
                if in_place {
                    if verify {
                        last.verified_at = Instant::now();
                    }
                    return Ok(ApplyReport {
                        applied: last.rules,
                        skipped: lowered.unsupported.len(),
                        failed: 0,
                        notes: notes_for_unsupported(),
                    });
                }
            }
        }
        // Forgotten before the run: a failed or partial apply leaves the kernel
        // holding something other than this ruleset.
        *applied = None;
        // Best-effort for the same reason as the other enforcement entry: a
        // single rule the kernel refuses must not cost the user every other
        // rule they have.
        let outcome = self
            .cli
            .apply_best_effort(&lowered.ruleset)
            .map_err(failure)?;
        report_apply_cost(
            lowered_at.duration_since(started),
            lowered_at.elapsed(),
            lowered.ruleset.rules.len(),
        );
        if outcome.skipped.is_empty() {
            *applied = Some(Applied {
                ruleset: lowered.ruleset.clone(),
                verified_at: Instant::now(),
                rules: outcome.applied,
            });
        }
        drop(applied);

        let mut notes = notes_for_unsupported();
        notes.extend(
            outcome
                .skipped
                .iter()
                .map(crate::nft_backend::note_for_skipped),
        );

        Ok(ApplyReport {
            applied: outcome.applied,
            skipped: lowered.unsupported.len() + outcome.skipped.len(),
            failed: 0,
            notes,
        })
    }

    fn channel_availability(&self, principal: &UserPrincipal) -> ChannelAvailability {
        // A read failure reports both channels down. That is the safe reading:
        // the caller's fail-closed branch blocks rather than routes, and
        // claiming a link is up when we could not look is how traffic leaves
        // over the wrong one.
        let Ok(adapters) = self.adapters.enumerate_all() else {
            return ChannelAvailability::default();
        };
        let names = self.resolve(principal, &adapters);
        // A resolved name is necessary but not sufficient for the additional
        // link: a tunnel whose peer stopped answering still presents an `Up`
        // interface with an address, and routing traffic into it is a silent
        // black hole rather than a leak the user can see.
        let secondary_alive = names.secondary.as_ref().is_some_and(|name| {
            let Some(oracle) = self.liveness.as_ref() else {
                return true;
            };
            adapters
                .iter()
                .find(|a| &a.friendly_name == name || &a.adapter_name == name)
                .is_none_or(|adapter| oracle(adapter.index))
        });
        ChannelAvailability {
            primary: names.primary.is_some(),
            secondary: secondary_alive,
        }
    }

    fn flow_links(&self, principal: &UserPrincipal) -> FlowLinks {
        let Ok(adapters) = self.adapters.enumerate_all() else {
            return FlowLinks::default();
        };
        let names = self.resolve(principal, &adapters);
        let index_of = |name: Option<&String>| {
            let name = name?;
            adapters
                .iter()
                .find(|a| &a.friendly_name == name || &a.adapter_name == name)
                .map(|a| a.index)
        };
        FlowLinks::from_adapters(
            &adapters,
            index_of(names.primary.as_ref()),
            index_of(names.secondary.as_ref()),
        )
    }

    fn teardown(&self) -> Result<(), EnforcementFailure> {
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.cli.teardown(&self.table).map_err(failure)
    }

    fn distrust_installed(&self) {
        self.verify_next.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::MockAdapterEventSource;
    use nrr_platform_api::enforcement::EgressBinding;

    struct Unbound;
    impl EgressBindingSource for Unbound {
        fn bindings_for(&self, _: &UserPrincipal) -> EgressBinding {
            EgressBinding::default()
        }
    }

    /// An enforcer whose `nft` is a shell stand-in: each apply logs `run`, each
    /// listing logs `list` and answers with `listing` if that file exists, or
    /// as `nft` does for a table that is gone.
    fn counting(log: &std::path::Path, listing: &std::path::Path) -> NftPolicyEnforcer {
        let script: &'static str = Box::leak(
            format!(
                "case \"$*\" in *list*) echo list >> '{log}'; \
                 if [ -f '{listing}' ]; then exec cat '{listing}'; fi; \
                 echo 'Error: No such file or directory' >&2; exit 1;; \
                 *) cat >/dev/null; echo run >> '{log}';; esac",
                log = log.display(),
                listing = listing.display(),
            )
            .into_boxed_str(),
        );
        let args: &'static [&'static str] = Box::leak(Box::new(["-c", script, "nft"]));
        let mut enforcer =
            NftPolicyEnforcer::new(Arc::new(Unbound), Arc::new(MockAdapterEventSource::new()));
        enforcer.cli = NftCliEnforcement::with_program("/bin/sh", args, Duration::from_secs(10));
        enforcer
    }

    fn logged(log: &std::path::Path, what: &str) -> usize {
        std::fs::read_to_string(log).map_or(0, |s| s.lines().filter(|l| *l == what).count())
    }

    /// The kernel's answer for our chain holding `rules` rules.
    fn put_listing(listing: &std::path::Path, rules: usize) {
        let mut objects = vec![r#"{"chain":{}}"#];
        objects.extend(std::iter::repeat_n(r#"{"rule":{}}"#, rules));
        let body = format!(r#"{{"nftables":[{}]}}"#, objects.join(","));
        std::fs::write(listing, body).expect("write listing");
    }

    fn installed_rules(enforcer: &NftPolicyEnforcer) -> usize {
        enforcer
            .applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map_or(0, |a| a.rules)
    }

    fn age_past_recheck(enforcer: &NftPolicyEnforcer) {
        if let Some(applied) = enforcer
            .applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            applied.verified_at = Instant::now()
                .checked_sub(UNCHANGED_RECHECK)
                .expect("the clock is past one window");
        }
    }

    /// An unchanged pass inside the window costs no `nft` run at all; past it,
    /// a listing that finds our chain whole is enough, and a teardown always
    /// means a real apply.
    #[test]
    fn an_unchanged_ruleset_is_not_applied_again_while_it_is_in_place() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let listing = dir.path().join("listing");
        let enforcer = counting(&log, &listing);

        enforcer.enforce(&[]).expect("first apply");
        put_listing(&listing, installed_rules(&enforcer));
        enforcer.enforce(&[]).expect("unchanged apply");
        assert_eq!(
            logged(&log, "run"),
            1,
            "the unchanged ruleset was handed to nft again"
        );
        assert_eq!(
            logged(&log, "list"),
            0,
            "a pass inside the window asked the kernel"
        );

        age_past_recheck(&enforcer);
        enforcer.enforce(&[]).expect("recheck");
        assert_eq!(logged(&log, "list"), 1, "the recheck did not look");
        assert_eq!(
            logged(&log, "run"),
            1,
            "a table found in place was reapplied"
        );

        enforcer.teardown().expect("teardown");
        let after_teardown = logged(&log, "run");
        enforcer.enforce(&[]).expect("apply after teardown");
        assert_eq!(
            logged(&log, "run"),
            after_teardown + 1,
            "a teardown must not be mistaken for the ruleset still being in force"
        );
    }

    /// Somebody else's `flush ruleset` took our table: an explicit apply must
    /// put it back at once, not trust the cache until the window runs out.
    #[test]
    fn an_explicit_apply_restores_a_table_flushed_behind_our_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let listing = dir.path().join("listing");
        let enforcer = counting(&log, &listing);

        enforcer.enforce(&[]).expect("first apply");
        put_listing(&listing, installed_rules(&enforcer));

        // Positive control: the table is in place, so the check alone answers.
        enforcer.distrust_installed();
        enforcer.enforce(&[]).expect("verified apply");
        assert_eq!(logged(&log, "list"), 1, "an explicit apply did not look");
        assert_eq!(logged(&log, "run"), 1);

        std::fs::remove_file(&listing).expect("flush");
        enforcer.enforce(&[]).expect("cached pass");
        assert_eq!(logged(&log, "run"), 1, "a request is consumed by one pass");

        enforcer.distrust_installed();
        enforcer.enforce(&[]).expect("restoring apply");
        assert_eq!(logged(&log, "run"), 2, "a flushed table was not put back");

        // A chain holding other than our rules is not in place either.
        put_listing(&listing, installed_rules(&enforcer) + 1);
        enforcer.distrust_installed();
        enforcer.enforce(&[]).expect("restoring apply");
        assert_eq!(logged(&log, "run"), 3, "a chain that differs was trusted");
    }

    #[test]
    fn only_a_hung_nft_is_worth_retrying_unchanged() {
        let detail = || "x".to_owned();
        assert!(!failure(NftApplyError::TimedOut { detail: detail() }).is_persistent());
        for refusal in [
            NftApplyError::NftUnavailable { detail: detail() },
            NftApplyError::NotPermitted { detail: detail() },
            NftApplyError::Rejected { detail: detail() },
        ] {
            assert!(failure(refusal).is_persistent());
        }
    }
}

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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_platform_api::adapters::AdapterEventSource;
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EgressBindingSource, EnforcementFailure, EnforcementPlan,
    PolicyEnforcer, UserPrincipal,
};

use crate::lower_linux::{lower_scoped, EgressNames, ScopedPlan};
use crate::nft_apply::{NftApplyError, NftCliEnforcement};
use crate::nft_ir::NftRuleset;

/// How long a ruleset identical to the one applied is trusted to still be in
/// the kernel. Past it the same ruleset is applied again, which is what puts
/// back a table somebody else flushed.
const UNCHANGED_RECHECK: Duration = Duration::from_secs(5 * 60);

/// The last ruleset the kernel took whole, and when.
struct Applied {
    ruleset: NftRuleset,
    at: Instant,
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
        if let Some(last) = applied.as_ref() {
            if last.ruleset == lowered.ruleset && last.at.elapsed() < UNCHANGED_RECHECK {
                return Ok(ApplyReport {
                    applied: last.rules,
                    skipped: lowered.unsupported.len(),
                    failed: 0,
                    notes: notes_for_unsupported(),
                });
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
                at: Instant::now(),
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

    fn teardown(&self) -> Result<(), EnforcementFailure> {
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.cli.teardown(&self.table).map_err(failure)
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

    /// An enforcer whose `nft` is a shell stand-in that records each run.
    fn counting(log: &std::path::Path) -> NftPolicyEnforcer {
        let script: &'static str =
            Box::leak(format!("cat >/dev/null; echo run >> '{}'", log.display()).into_boxed_str());
        let args: &'static [&'static str] = Box::leak(Box::new(["-c", script, "nft"]));
        let mut enforcer =
            NftPolicyEnforcer::new(Arc::new(Unbound), Arc::new(MockAdapterEventSource::new()));
        enforcer.cli = NftCliEnforcement::with_program("/bin/sh", args, Duration::from_secs(10));
        enforcer
    }

    fn runs(log: &std::path::Path) -> usize {
        std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
    }

    /// An idle pass hands the kernel nothing new, so it must not pay for an
    /// `nft` run — but the same ruleset is still reapplied once the recheck
    /// window has passed, and after a teardown, both of which may have left the
    /// kernel without it.
    #[test]
    fn an_unchanged_ruleset_is_not_applied_again_until_the_recheck() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let enforcer = counting(&log);

        enforcer.enforce(&[]).expect("first apply");
        enforcer.enforce(&[]).expect("unchanged apply");
        assert_eq!(
            runs(&log),
            1,
            "the unchanged ruleset was handed to nft again"
        );

        if let Some(applied) = enforcer
            .applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            applied.at = Instant::now()
                .checked_sub(UNCHANGED_RECHECK)
                .expect("the clock is past one window");
        }
        enforcer.enforce(&[]).expect("recheck apply");
        assert_eq!(runs(&log), 2, "the recheck did not reapply");

        enforcer.teardown().expect("teardown");
        let after_teardown = runs(&log);
        enforcer.enforce(&[]).expect("apply after teardown");
        assert_eq!(
            runs(&log),
            after_teardown + 1,
            "a teardown must not be mistaken for the ruleset still being in force"
        );
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

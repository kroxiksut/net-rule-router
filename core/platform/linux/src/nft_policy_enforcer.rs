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

use nrr_platform_api::adapters::{replacement_candidates, AdapterEventSource};
use nrr_platform_api::enforcement::{
    ApplyNote, ApplyReport, ChannelAvailability, ChannelReport, ChannelState, EgressBindingSource,
    EnforcementFailure, EnforcementPlan, PolicyEnforcer, UserPrincipal,
};
use nrr_platform_api::fake_ip::stale_flows::FlowLinks;

use crate::kernel_capabilities::{self, KernelCapability};
use crate::lower_linux::{
    lower_scoped_with, EgressNames, LoweredPlan, ScopedPlan, ServiceAccountScope,
};
use crate::nft_apply::{NftApplyError, NftApplyOutcome, NftCliEnforcement};
use crate::nft_ir::{NftMatch, NftRule, NftRuleset};

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
    /// Notes for the rules the kernel refused. Remembered with the ruleset so
    /// an unchanged pass does not repeat the refusal search; an explicit apply
    /// searches again, in case what the kernel lacked has appeared.
    refused_notes: Vec<String>,
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
    /// Who owns the route table and which uids are service accounts, read per
    /// pass. `None` lowers no service-account rule.
    service_accounts: Option<ServiceAccountScopeSource>,
}

/// The route-table owner and the service uids as they stand this pass, given
/// the uids of the users present (their own plans cover them).
pub type ServiceAccountScopeSource = Arc<dyn Fn(&[u32]) -> ServiceAccountScope + Send + Sync>;

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
            service_accounts: None,
        }
    }

    /// Lower the route-table owner's service-account rules onto the uids
    /// `source` names. Without it they are left out.
    #[must_use]
    pub fn with_service_accounts(mut self, source: ServiceAccountScopeSource) -> Self {
        self.service_accounts = Some(source);
        self
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

    /// What the kernel holds of ours, as a pass input: `0` for no table, else
    /// the rule count plus one; `None` when `nft` cannot say. One terse chain
    /// listing per tick. A ruleset another program flushed (`systemctl restart
    /// nftables`) moves nothing else a pass reads, and the enforcer's own
    /// "unchanged" shortcut would keep trusting it until the recheck, so a
    /// mismatch with the last apply forgets that apply as well.
    pub fn installed_fingerprint(&self) -> Option<u64> {
        let listed = self
            .cli
            .installed_rule_count(&self.table, crate::lower_linux::NRR_CHAIN)
            .ok()?;
        let mut applied = self.applied.lock().unwrap_or_else(|p| p.into_inner());
        if applied
            .as_ref()
            .is_some_and(|last| listed != Some(last.rules))
        {
            tracing::info!(
                target: "nrr::enforcement",
                msg_key = "nft-ruleset-changed-outside",
                present = listed.is_some(),
                rules = listed.unwrap_or(0),
                "our nftables rules were changed or removed by another program; this pass reapplies them",
            );
            *applied = None;
        }
        Some(listed.map_or(0, |rules| rules as u64 + 1))
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

/// Whether a link answers to `name` in any state — the same match the binding
/// resolution makes, without its "up" requirement.
fn link_named(adapters: &[nrr_platform_api::adapters::AdapterInfo], name: &str) -> bool {
    adapters
        .iter()
        .any(|a| a.friendly_name == name || a.adapter_name == name)
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

impl NftPolicyEnforcer {
    /// The ruleset `plans` lower to on the links present now. Links are read
    /// ONCE, so two users cannot be lowered against two states of the machine.
    fn lower(&self, plans: &[EnforcementPlan]) -> Result<LoweredPlan, EnforcementFailure> {
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

        let service_accounts = self
            .service_accounts
            .as_ref()
            .map(|source| {
                let present: Vec<u32> = plans
                    .iter()
                    .filter_map(|plan| plan.principal.as_unix_uid())
                    .collect();
                source(&present)
            })
            .unwrap_or_default();
        let mut lowered = lower_scoped_with(&scoped, &service_accounts);
        lowered.ruleset.table.clone_from(&self.table);
        // A kernel that refused the match once refuses it on every pass; without
        // it the IPsec networks stay cut, as they would without these rules.
        if !kernel_capabilities::is_available(KernelCapability::IpsecNetworks) {
            lowered.ruleset.rules.retain(|rule| !matches_ipsec(rule));
        }
        Ok(lowered)
    }
}

fn matches_ipsec(rule: &NftRule) -> bool {
    rule.matches.contains(&NftMatch::RouteIpsec)
}

/// Takes the IPsec rules out of what the kernel refused: a refusal of theirs
/// is a missing capability, reported once in the clients' list, not a rule
/// failure on every report. Returns whether any was there.
fn settle_ipsec_refusals(ruleset: &NftRuleset, outcome: &mut NftApplyOutcome) -> bool {
    let before = outcome.skipped.len();
    outcome
        .skipped
        .retain(|skipped| !ruleset.rules.get(skipped.index).is_some_and(matches_ipsec));
    outcome.skipped.len() != before
}

/// Bounds `nft`'s words before they travel into a refusal the user reads and
/// the audit keeps: the tool echoes the offending input back.
fn bounded_detail(detail: &str) -> String {
    const MAX: usize = 1024;
    if detail.len() <= MAX {
        return detail.to_owned();
    }
    let mut end = MAX;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &detail[..end])
}

impl PolicyEnforcer for NftPolicyEnforcer {
    // Every rule of a plan matches its owner's uid, packet blocks included.
    fn packet_blocks_follow_the_principal(&self) -> bool {
        true
    }

    fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        let started = Instant::now();
        let lowered = self.lower(plans)?;
        let lowered_at = Instant::now();
        let notes_for_unsupported = || -> Vec<ApplyNote> {
            lowered
                .unsupported
                .iter()
                .map(crate::nft_backend::note_for)
                .collect()
        };

        let mut applied = self.applied.lock().unwrap_or_else(|p| p.into_inner());
        let verify_requested = self.verify_next.swap(false, Ordering::AcqRel);
        if let Some(last) = applied.as_mut() {
            let search_again = verify_requested && !last.refused_notes.is_empty();
            if last.ruleset == lowered.ruleset && !search_again {
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
                    let mut notes = notes_for_unsupported();
                    notes.extend(last.refused_notes.iter().cloned().map(ApplyNote::machine));
                    return Ok(ApplyReport {
                        applied: last.rules,
                        skipped: lowered.unsupported.len() + last.refused_notes.len(),
                        failed: 0,
                        notes,
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
        let mut outcome = self
            .cli
            .apply_best_effort(&lowered.ruleset)
            .map_err(failure)?;
        if settle_ipsec_refusals(&lowered.ruleset, &mut outcome) {
            kernel_capabilities::record(KernelCapability::IpsecNetworks, false);
        }
        report_apply_cost(
            lowered_at.duration_since(started),
            lowered_at.elapsed(),
            lowered.ruleset.rules.len(),
        );
        let refused_notes: Vec<String> = outcome
            .skipped
            .iter()
            .map(crate::nft_backend::note_for_skipped)
            .collect();
        *applied = Some(Applied {
            ruleset: lowered.ruleset.clone(),
            verified_at: Instant::now(),
            rules: outcome.applied,
            refused_notes: refused_notes.clone(),
        });
        drop(applied);

        let mut notes = notes_for_unsupported();
        notes.extend(refused_notes.into_iter().map(ApplyNote::machine));

        Ok(ApplyReport {
            applied: outcome.applied,
            skipped: lowered.unsupported.len() + outcome.skipped.len(),
            failed: 0,
            notes,
        })
    }

    /// The whole batch `enforce` would hand over, under `nft --check`. Strict:
    /// a rule the best-effort apply would drop refuses the plans here. Never
    /// moves the record of what is installed.
    fn check(&self, plans: &[EnforcementPlan]) -> Result<(), EnforcementFailure> {
        let lowered = self.lower(plans)?;
        // The kernel already took this exact ruleset whole.
        let accepted = self
            .applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|last| last.ruleset == lowered.ruleset);
        if accepted {
            return Ok(());
        }
        let checked = match self.cli.check(&lowered.ruleset) {
            // An `nft` too old for the IPsec match refuses only those rules,
            // which the apply would drop as well; nothing else is excused.
            Err(refused)
                if !matches!(refused, NftApplyError::TimedOut { .. })
                    && lowered.ruleset.rules.iter().any(matches_ipsec) =>
            {
                let mut without = lowered.ruleset.clone();
                without.rules.retain(|rule| !matches_ipsec(rule));
                match self.cli.check(&without) {
                    Ok(()) => {
                        kernel_capabilities::record(KernelCapability::IpsecNetworks, false);
                        Ok(())
                    }
                    Err(_) => Err(refused),
                }
            }
            other => other,
        };
        checked.map_err(|e| {
            let bounded = bounded_detail(&e.to_string());
            match e {
                NftApplyError::TimedOut { .. } => EnforcementFailure::transient(bounded),
                _ => EnforcementFailure::persistent(bounded),
            }
        })
    }

    fn channel_availability(&self, principal: &UserPrincipal) -> ChannelAvailability {
        self.channel_report(principal).availability()
    }

    fn channel_report(&self, principal: &UserPrincipal) -> ChannelReport {
        // A read failure reports both channels unusable. That is the safe
        // reading: the caller's fail-closed branch blocks rather than routes,
        // and claiming a link is up when we could not look is how traffic
        // leaves over the wrong one.
        let Ok(adapters) = self.adapters.enumerate_all() else {
            return ChannelReport::default();
        };
        let binding = self.bindings.bindings_for(principal);
        let names = EgressNames::resolve_from_adapters(
            &adapters,
            binding.primary.as_deref(),
            binding.secondary.as_deref(),
        );
        // A resolved name is necessary but not sufficient for the additional
        // link: a tunnel whose peer stopped answering still presents an `Up`
        // interface with an address, and routing traffic into it is a silent
        // black hole rather than a leak the user can see.
        let secondary_alive = |name: &String| {
            let Some(oracle) = self.liveness.as_ref() else {
                return true;
            };
            adapters
                .iter()
                .find(|a| &a.friendly_name == name || &a.adapter_name == name)
                .is_none_or(|adapter| oracle(adapter.index))
        };
        let secondary = match names.secondary.as_ref() {
            Some(name) if secondary_alive(name) => ChannelState::Usable,
            Some(_) => ChannelState::Down,
            // A tunnel's link exists here only while it is connected, so a
            // missing additional link is one switched off, not one to replace.
            None => match binding.secondary {
                Some(_) => ChannelState::Down,
                None => ChannelState::Unbound,
            },
        };
        let primary = match (names.primary, binding.primary.as_deref()) {
            (Some(_), _) => ChannelState::Usable,
            (None, None) => ChannelState::Unbound,
            (None, Some(bound)) if link_named(&adapters, bound) => ChannelState::Down,
            (None, Some(_)) => ChannelState::Absent {
                replacements: replacement_candidates(&adapters, false),
            },
        };
        ChannelReport { primary, secondary }
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

    /// A rule the kernel refused is remembered with its ruleset: an unchanged
    /// pass does not search for it again, an explicit apply does.
    #[test]
    fn a_refused_rule_does_not_make_every_unchanged_pass_search_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let listing = dir.path().join("listing");
        let enforcer = counting(&log, &listing);

        enforcer.enforce(&[]).expect("first apply");
        put_listing(&listing, installed_rules(&enforcer));
        enforcer
            .applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
            .expect("applied")
            .refused_notes = vec!["refused".to_owned()];

        let report = enforcer.enforce(&[]).expect("unchanged pass");
        assert_eq!(logged(&log, "run"), 1, "an unchanged pass searched again");
        assert_eq!(report.skipped, 1);
        assert!(report.notes.iter().any(|n| n.text == "refused"));

        enforcer.distrust_installed();
        enforcer.enforce(&[]).expect("explicit apply");
        assert_eq!(
            logged(&log, "run"),
            2,
            "an explicit apply trusted the cache"
        );
    }

    /// The pass input: a flushed or altered table reads as a different value,
    /// and the pass it wakes reapplies at once instead of trusting the cache
    /// until the recheck window runs out.
    #[test]
    fn a_table_flushed_behind_our_back_moves_the_pass_input_and_is_reapplied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let listing = dir.path().join("listing");
        let enforcer = counting(&log, &listing);

        enforcer.enforce(&[]).expect("first apply");
        put_listing(&listing, installed_rules(&enforcer));
        let in_place = enforcer.installed_fingerprint().expect("nft answered");
        assert_ne!(in_place, 0, "a present table reads as absent");
        enforcer.enforce(&[]).expect("unchanged apply");
        assert_eq!(logged(&log, "run"), 1, "an unchanged table was reapplied");

        std::fs::remove_file(&listing).expect("flush");
        assert_eq!(enforcer.installed_fingerprint(), Some(0));
        enforcer.enforce(&[]).expect("restoring apply");
        assert_eq!(logged(&log, "run"), 2, "a flushed table was not put back");

        put_listing(&listing, installed_rules(&enforcer) + 1);
        assert_ne!(enforcer.installed_fingerprint(), Some(in_place));
        enforcer.enforce(&[]).expect("restoring apply");
        assert_eq!(logged(&log, "run"), 3, "an altered chain was trusted");

        std::fs::remove_file(&listing).expect("nft gone");
        let broken: &'static [&'static str] = Box::leak(Box::new(["-c", "exit 2", "nft"]));
        let mut mute = counting(&log, &listing);
        mute.cli = NftCliEnforcement::with_program("/bin/sh", broken, Duration::from_secs(10));
        assert_eq!(
            mute.installed_fingerprint(),
            None,
            "an unreadable kernel must not settle"
        );
    }

    /// Down asks the user to wait, absent to choose again: a missing tunnel
    /// is one switched off, a missing main link one to replace.
    #[test]
    fn the_report_tells_a_link_that_is_down_from_one_that_is_gone() {
        use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};

        struct Bound(Option<&'static str>, Option<&'static str>);
        impl EgressBindingSource for Bound {
            fn bindings_for(&self, _: &UserPrincipal) -> EgressBinding {
                EgressBinding {
                    primary: self.0.map(str::to_owned),
                    secondary: self.1.map(str::to_owned),
                }
            }
        }
        let link = |name: &str, index: u32, up: bool| AdapterInfo {
            index,
            adapter_name: name.to_owned(),
            description: String::new(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: if up {
                IfOperStatus::Up
            } else {
                IfOperStatus::Down
            },
            ipv4_addresses: vec![std::net::Ipv4Addr::new(192, 0, 2, index as u8)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        };
        let report = |bound: Bound, links: Vec<AdapterInfo>| {
            let adapters = MockAdapterEventSource::new();
            *adapters.adapters.lock().unwrap_or_else(|p| p.into_inner()) = links;
            NftPolicyEnforcer::new(Arc::new(bound), Arc::new(adapters))
                .channel_report(&UserPrincipal::from_linux_uid(1000))
        };

        let all_up = report(
            Bound(Some("eth0"), Some("wg0")),
            vec![link("eth0", 2, true), link("wg0", 7, true)],
        );
        assert_eq!(all_up.primary, ChannelState::Usable);
        assert_eq!(all_up.secondary, ChannelState::Usable);
        assert_eq!(
            all_up.availability(),
            ChannelAvailability {
                primary: true,
                secondary: true
            }
        );

        let tunnel_off = report(
            Bound(Some("eth0"), Some("wg0")),
            vec![link("eth0", 2, true)],
        );
        assert_eq!(tunnel_off.secondary, ChannelState::Down);

        let cable_out = report(Bound(Some("eth0"), None), vec![link("eth0", 2, false)]);
        assert_eq!(cable_out.primary, ChannelState::Down);
        assert_eq!(cable_out.secondary, ChannelState::Unbound);

        let dongle_gone = report(Bound(Some("usb0"), None), vec![link("wlan0", 3, true)]);
        assert_eq!(
            dongle_gone.primary,
            ChannelState::Absent {
                replacements: vec!["wlan0".to_owned()]
            }
        );
        assert!(!dongle_gone.availability().primary);
    }

    /// A stand-in `nft` that logs `check` for a `--check` run and `run` for an
    /// apply, and refuses every check when `refuse` is set.
    fn checking(log: &std::path::Path, refuse: bool) -> NftPolicyEnforcer {
        let verdict = if refuse {
            "echo 'Error: Could not process rule: Invalid argument' >&2; exit 1"
        } else {
            "exit 0"
        };
        let script: &'static str = Box::leak(
            format!(
                "case \"$*\" in *--check*) cat >/dev/null; echo check >> '{log}'; {verdict};; \
                 *) cat >/dev/null; echo run >> '{log}';; esac",
                log = log.display(),
            )
            .into_boxed_str(),
        );
        let args: &'static [&'static str] = Box::leak(Box::new(["-c", script, "nft"]));
        let mut enforcer =
            NftPolicyEnforcer::new(Arc::new(Unbound), Arc::new(MockAdapterEventSource::new()));
        enforcer.cli = NftCliEnforcement::with_program("/bin/sh", args, Duration::from_secs(10));
        enforcer
    }

    #[test]
    fn a_ruleset_nft_refuses_to_check_is_refused_and_nothing_is_applied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let enforcer = checking(&log, true);

        let refusal = enforcer.check(&[]).expect_err("a refused check passed");
        assert!(refusal.is_persistent(), "a refusal is not worth a timer");
        assert!(
            refusal.reason.contains("Invalid argument"),
            "the refusal lost nft's words: {}",
            refusal.reason
        );
        assert_eq!(logged(&log, "check"), 1);
        assert_eq!(logged(&log, "run"), 0, "a check touched the live table");
        assert!(
            enforcer
                .applied
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_none(),
            "a check moved the record of what is installed"
        );
    }

    #[test]
    fn a_ruleset_nft_accepts_is_checked_once_and_not_applied() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let enforcer = checking(&log, false);

        enforcer.check(&[]).expect("an accepted check refused");
        assert_eq!(logged(&log, "check"), 1);
        assert_eq!(logged(&log, "run"), 0, "a check touched the live table");

        // What the kernel already took whole needs no second opinion.
        enforcer.enforce(&[]).expect("apply");
        enforcer.check(&[]).expect("the installed ruleset refused");
        assert_eq!(logged(&log, "check"), 1, "an installed ruleset was checked");
    }

    /// One user's catch-all plus the permit for what IPsec protects.
    fn ipsec_plan() -> EnforcementPlan {
        use nrr_platform_api::enforcement::{
            AppScope, Coverage, DstMatch, EgressConstraint, FlowMatch, FlowRule, Precedence,
            PrecedenceClass, PrincipalScope, Verdict,
        };
        let principal = UserPrincipal::from_linux_uid(1000);
        let flow = |verdict, class, dst, egress| FlowRule {
            verdict,
            precedence: Precedence { class, ordinal: 0 },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope::User(principal.clone()),
            app: AppScope::Any,
            egress,
            coverage: Coverage::AllPackets,
            observed_by_program: false,
        };
        EnforcementPlan {
            principal: principal.clone(),
            flows: vec![
                flow(
                    Verdict::Permit,
                    PrecedenceClass::CatchAllExempt,
                    DstMatch::SubnetV4 {
                        net: std::net::Ipv4Addr::new(10, 0, 0, 0),
                        prefix: 8,
                    },
                    EgressConstraint::UnderIpsecPolicy,
                ),
                flow(
                    Verdict::Block,
                    PrecedenceClass::CatchAllBlock,
                    DstMatch::Any,
                    EgressConstraint::Any,
                ),
            ],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }
    }

    /// An `nft` too old for `rt ipsec`: its check refuses any batch naming it.
    fn without_rt_ipsec(log: &std::path::Path) -> NftPolicyEnforcer {
        let script: &'static str = Box::leak(
            format!(
                "case \"$*\" in *--check*) echo check >> '{log}'; \
                 if grep '\"ipsec\"' >/dev/null; then echo 'Error: syntax error' >&2; exit 1; fi;; \
                 *) cat >/dev/null; echo run >> '{log}';; esac",
                log = log.display(),
            )
            .into_boxed_str(),
        );
        let args: &'static [&'static str] = Box::leak(Box::new(["-c", script, "nft"]));
        let mut enforcer =
            NftPolicyEnforcer::new(Arc::new(Unbound), Arc::new(MockAdapterEventSource::new()));
        enforcer.cli = NftCliEnforcement::with_program("/bin/sh", args, Duration::from_secs(10));
        enforcer
    }

    /// A host without the IPsec match: the check still passes, the capability
    /// is recorded missing, and later passes lower no IPsec rule at all.
    #[test]
    fn an_nft_without_the_ipsec_match_costs_only_those_rules() {
        let _held = kernel_capabilities::TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        kernel_capabilities::record(KernelCapability::IpsecNetworks, true);
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("runs");
        let enforcer = without_rt_ipsec(&log);
        let plans = [ipsec_plan()];

        let lowered = enforcer.lower(&plans).expect("lowered");
        assert!(lowered.ruleset.rules.iter().any(matches_ipsec));

        enforcer
            .check(&plans)
            .expect("the rest of the plan refused");
        assert_eq!(logged(&log, "run"), 0, "a check touched the live table");
        assert!(!kernel_capabilities::is_available(
            KernelCapability::IpsecNetworks
        ));
        let lowered = enforcer.lower(&plans).expect("lowered");
        assert!(!lowered.ruleset.rules.iter().any(matches_ipsec));
        assert!(
            lowered
                .ruleset
                .rules
                .iter()
                .any(|r| r.comment.starts_with("catch-all-block")),
            "the catch-all stays"
        );
        kernel_capabilities::record(KernelCapability::IpsecNetworks, true);
    }

    /// A kernel that refused the IPsec rules on apply: the refusal moves to the
    /// capability list and out of the rule failures.
    #[test]
    fn a_refused_ipsec_rule_is_a_missing_capability_not_a_rule_failure() {
        use crate::nft_apply::SkippedNftRule;
        let ruleset = NftRuleset {
            family: crate::nft_ir::NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            forward: Vec::new(),
            rules: vec![
                NftRule {
                    matches: vec![NftMatch::SkUid(1000), NftMatch::RouteIpsec],
                    verdict: crate::nft_ir::NftVerdict::Accept,
                    comment: "catch-all-exempt#0".into(),
                },
                NftRule {
                    matches: vec![NftMatch::SkUid(1000), NftMatch::DstPort(53)],
                    verdict: crate::nft_ir::NftVerdict::Accept,
                    comment: "route-primary#0".into(),
                },
            ],
        };
        let skipped = |index: usize| SkippedNftRule {
            index,
            comment: ruleset.rules[index].comment.clone(),
        };
        let mut outcome = NftApplyOutcome {
            applied: 0,
            skipped: vec![skipped(0), skipped(1)],
        };
        assert!(settle_ipsec_refusals(&ruleset, &mut outcome));
        assert_eq!(outcome.skipped, vec![skipped(1)]);
        assert!(!settle_ipsec_refusals(&ruleset, &mut outcome));
        assert_eq!(outcome.skipped.len(), 1, "another rule's refusal stays");
    }

    #[test]
    fn a_long_refusal_is_cut_on_a_character_boundary() {
        let long = "ж".repeat(2000);
        let cut = bounded_detail(&long);
        assert!(cut.len() <= 1024 + "…".len());
        assert!(cut.ends_with('…'));
        assert_eq!(bounded_detail("short"), "short");
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

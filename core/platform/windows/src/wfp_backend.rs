//! The Windows [`EnforcementBackend`]: plan in, WFP filters out.
//!
//! Mirror of `nrr_platform_linux::nft_backend` and deliberately as thin: the
//! parts worth testing are the lowering (pure) on one side and the WFP session
//! (kernel) on the other. What lives here is the join, plus the honest report
//! of what could not be expressed.
//!
//! ## Why this exists at all
//!
//! The per-SID orchestrator drives WFP directly today — it holds an
//! `Arc<WfpSession>` and calls `wfp_codegen` itself. That works, and only on
//! Windows: the coupling is invisible because it lives in the TYPES rather than
//! in `cfg` attributes, so nothing flags it. This backend is the seam that lets
//! the same orchestration run against nftables (or, later, pf) by swapping the
//! implementation instead of rewriting the caller.
//!
//! ## LUIDs are supplied per reconcile, never cached
//!
//! A plan names egress neutrally (`Primary` / `Secondary`); the LUID behind it
//! is resolved by the caller and handed in on every call. A tunnel that
//! reconnects comes back with a different LUID, and a cached one pins traffic
//! to an interface that no longer exists — while every rule still reads as
//! applied. Same rule the Linux backend follows with interface names.

#![cfg(target_os = "windows")]

use std::sync::Arc;

use nrr_platform_api::enforcement::{
    ApplyReport, EnforcementBackend, EnforcementCapabilities, EnforcementPlan,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::types::{WfpFilterAction, WfpFilterSpec};
use nrr_platform_api::wfp::{FilterFailureMode, WfpSession};

use crate::lower_windows::{lower_plan, EgressLuids};

/// Enforces a plan with the Windows Filtering Platform.
pub struct WfpEnforcement {
    session: Arc<WfpSession>,
    egress: EgressLuids,
    mode: FilterFailureMode,
}

impl WfpEnforcement {
    /// Build a backend over an open session. Construct it per reconcile from
    /// freshly-read adapter facts — see the module note on LUIDs.
    pub fn new(session: Arc<WfpSession>, egress: EgressLuids) -> Self {
        Self {
            session,
            egress,
            mode: FilterFailureMode::default(),
        }
    }

    /// Choose what an un-materializable filter does to the rest of the apply.
    /// `BestEffort` (the default) skips it and records a diagnostic;
    /// `Strict` aborts the whole revision. The service reads the user's
    /// apply-failure policy and passes it in.
    #[must_use]
    pub fn with_failure_mode(mut self, mode: FilterFailureMode) -> Self {
        self.mode = mode;
        self
    }
}

impl EnforcementBackend for WfpEnforcement {
    type Error = PlatformError;

    fn reconcile(&self, plan: &EnforcementPlan) -> Result<ApplyReport, Self::Error> {
        let filters = lower_plan(plan, self.egress);
        let requested = filters.len();
        let actions = additions(filters);

        let outcome = self
            .session
            .execute_wfp_plan_resilient(&actions, self.mode)?;

        // What could not be materialized is REPORTED, never dropped in silence:
        // a backend that quietly enforces less than it was given is
        // indistinguishable from one that enforced all of it.
        let notes = outcome
            .skipped
            .iter()
            .map(|s| format!("filter {} was not materialized: {}", s.id.raw, s.reason))
            .collect::<Vec<_>>();

        Ok(ApplyReport {
            applied: requested.saturating_sub(outcome.skipped.len()),
            skipped: outcome.skipped.len(),
            failed: 0,
            notes,
        })
    }

    /// Per-SID filter sets are independent objects in the engine, so one apply
    /// per principal is the mechanism's own shape here — nothing is replaced
    /// wholesale, and a failure isolates to the user it belongs to. The reports
    /// are summed so the caller still sees one answer for the whole pass.
    fn reconcile_all(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, Self::Error> {
        let mut total = ApplyReport {
            applied: 0,
            skipped: 0,
            failed: 0,
            notes: Vec::new(),
        };
        for plan in plans {
            let report = self.reconcile(plan)?;
            total.applied += report.applied;
            total.skipped += report.skipped;
            total.failed += report.failed;
            total.notes.extend(report.notes);
        }
        Ok(total)
    }

    fn capabilities(&self) -> EnforcementCapabilities {
        EnforcementCapabilities::windows()
    }
}

/// Turn lowered filters into the add-actions the session executes.
fn additions(filters: Vec<WfpFilterSpec>) -> Vec<WfpFilterAction> {
    filters
        .into_iter()
        .map(WfpFilterAction::AddFilter)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::enforcement::UserPrincipal;

    fn empty_plan() -> EnforcementPlan {
        EnforcementPlan {
            principal: UserPrincipal::from_windows_sid("S-1-5-21-1-2-3-1001").expect("valid sid"),
            flows: Vec::new(),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }
    }

    #[test]
    fn an_empty_plan_lowers_to_no_actions() {
        assert!(additions(lower_plan(&empty_plan(), EgressLuids::default())).is_empty());
    }

    #[test]
    fn every_lowered_filter_becomes_an_add_action() {
        // The session's plan executor is add/remove-driven; a lowering that
        // produced anything else would silently drop rules here.
        let filters = lower_plan(
            &empty_plan(),
            EgressLuids {
                secondary: 7,
                primary: 3,
            },
        );
        let actions = additions(filters.clone());
        assert_eq!(actions.len(), filters.len());
        assert!(actions
            .iter()
            .all(|a| matches!(a, WfpFilterAction::AddFilter(_))));
    }
}

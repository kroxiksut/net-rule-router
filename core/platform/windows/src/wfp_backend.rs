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
use nrr_platform_api::types::WfpFilterId;
use nrr_platform_api::wfp::{FilterFailureMode, RetireHeld, WfpSession};

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
        let desired: std::collections::HashSet<u64> = filters.iter().map(|f| f.id.raw).collect();

        // Reconcile means DRIVE THE PLATFORM TO MATCH THE PLAN, and this
        // session is not dynamic — its filters outlive the process. Adding only
        // what the plan lists left every filter the user has since deleted
        // still enforced, across restarts, until something else swept them.
        //
        // Removal is scoped to THIS principal: filter sets are per-SID objects
        // in the engine, `reconcile_all` walks one plan per user, and a sweep of
        // "everything not in this plan" would take the other users' policy with
        // it. A record with no user condition belongs to no principal and is
        // left alone here.
        // On Windows the stored principal IS the SID string, which is what the
        // `ALE_USER_ID` condition carries back on enumeration.
        let sid = plan.principal.as_stored();
        let removals: Vec<WfpFilterId> = self
            .session
            .enumerate_our_filters()?
            .into_iter()
            .filter(|record| {
                record.user_sid.as_deref() == Some(sid) && !desired.contains(&record.id.raw)
            })
            .map(|record| record.id)
            .collect();

        // Adds before deletes: a filter whose id changed is replaced, and
        // deleting first left a committed state with neither copy.
        let outcome = self
            .session
            .execute_replacement(&filters, &removals, self.mode)?;

        // What could not be materialized is REPORTED, never dropped in silence:
        // a backend that quietly enforces less than it was given is
        // indistinguishable from one that enforced all of it.
        let mut notes = outcome
            .skipped
            .iter()
            .map(|s| format!("filter {} was not materialized: {}", s.id.raw, s.reason))
            .collect::<Vec<_>>();
        match &outcome.retire_held {
            None => {}
            Some(RetireHeld::ReplacementSkipped) => notes.push(format!(
                "{} superseded filter(s) kept: a replacement block was not materialized",
                removals.len()
            )),
            Some(RetireHeld::Failed(e)) => notes.push(format!(
                "{} superseded filter(s) kept: delete failed: {e}",
                removals.len()
            )),
        }

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
    fn an_empty_plan_lowers_to_no_filters() {
        assert!(lower_plan(&empty_plan(), EgressLuids::default()).is_empty());
    }

    /// A filter whose id changed (an update re-derives ids) is replaced
    /// add-first: no recorded state lacks both the old and the new copy.
    #[test]
    fn a_filter_whose_id_changed_is_never_absent_during_reconcile() {
        use nrr_platform_api::enforcement::{
            AppScope, Coverage, DstMatch, EgressConstraint, FlowMatch, FlowRule, Precedence,
            PrecedenceClass, PrincipalScope, Verdict,
        };
        use nrr_platform_api::types::WfpFilterRecord;
        use nrr_platform_api::windows_api::MockWindowsApi;
        use nrr_platform_api::WindowsApiPort;
        use nrr_shared::RouteRole;

        let sid = "S-1-5-21-1-2-3-1001";
        let mut plan = empty_plan();
        plan.flows.push(FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(RouteRole::Secondary),
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(std::net::Ipv4Addr::new(192, 0, 2, 7)),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(UserPrincipal::from_windows_sid(sid).ok()),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        });
        let new = lower_plan(&plan, EgressLuids::default());
        assert!(!new.is_empty());
        let old: Vec<WfpFilterRecord> = new
            .iter()
            .map(|f| WfpFilterRecord {
                id: WfpFilterId { raw: f.id.raw ^ 1 },
                layer: f.layer,
                action: f.action,
                remote_ip: f.remote_ip,
                remote_ip_set: f.remote_ip_set.clone(),
                remote_ip_set_v6: f.remote_ip_set_v6.clone(),
                remote_port: f.remote_port,
                weight: f.weight,
                user_sid: Some(sid.to_string()),
                app_pattern: f.app_pattern.clone(),
                local_interface_luid: f.local_interface_luid,
                remote_subnet: f.remote_subnet,
                remote_subnet_v6: f.remote_subnet_v6,
                ip_protocol: f.ip_protocol,
            })
            .collect();
        let old_ids: Vec<u64> = old.iter().map(|r| r.id.raw).collect();
        let new_ids: Vec<u64> = new.iter().map(|f| f.id.raw).collect();

        let api = Arc::new(MockWindowsApi::new());
        *api.wfp_filters.lock().expect("lock") = old;
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).expect("open"));
        api.record_wfp_history();
        WfpEnforcement::new(session, EgressLuids::default())
            .reconcile(&plan)
            .expect("reconcile");

        for (step, state) in api.wfp_history().iter().enumerate() {
            let holds = |ids: &[u64]| ids.iter().all(|id| state.contains(id));
            assert!(
                holds(&old_ids) || holds(&new_ids),
                "step {step}: neither copy of the filter set is installed",
            );
        }
        let live: Vec<u64> = api
            .wfp_filters
            .lock()
            .expect("lock")
            .iter()
            .map(|f| f.id.raw)
            .collect();
        assert_eq!(live, new_ids);
    }
    /// Reconcile REMOVES what the plan no longer lists.
    ///
    /// The session is not dynamic — its filters outlive the process — so an
    /// add-only reconcile left every rule the user had deleted still enforced,
    /// across restarts, until something else swept them. And the removal is
    /// scoped to the principal: filter sets are per-SID objects, `reconcile_all`
    /// walks one plan per user, and an unscoped sweep would take another user's
    /// policy with it.
    #[test]
    fn reconcile_deletes_this_principals_filters_that_the_plan_dropped() {
        use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterRecord, WfpLayerKey};
        use nrr_platform_api::windows_api::MockWindowsApi;
        use nrr_platform_api::WindowsApiPort;

        let mine = "S-1-5-21-1-2-3-1001";
        let theirs = "S-1-5-21-1-2-3-1002";
        let record = |raw: u64, sid: &str| WfpFilterRecord {
            id: WfpFilterId { raw },
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight: 1,
            user_sid: Some(sid.to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        };
        let api = Arc::new(MockWindowsApi::new());
        *api.wfp_filters.lock().expect("lock") = vec![record(0xAAAA, mine), record(0xBBBB, theirs)];
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).expect("open"));
        let backend = WfpEnforcement::new(session, EgressLuids::default());

        // An empty plan for `mine` asks for nothing, so everything of theirs
        // stays and everything of mine goes.
        backend.reconcile(&empty_plan()).expect("reconcile");
        let left = api.wfp_filters.lock().expect("lock");
        assert!(
            left.iter().any(|f| f.id.raw == 0xBBBB),
            "another principal's filter must survive",
        );
        assert!(
            !left.iter().any(|f| f.id.raw == 0xAAAA),
            "our own filter that the plan dropped must be removed",
        );
    }
}

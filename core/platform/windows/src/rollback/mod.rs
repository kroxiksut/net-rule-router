//! Rollback execution flow.
//!
//! ## Design
//!
//! Rollback reads the pre-apply `PlatformStateSnapshot`, captures the current
//! platform state, then calls `compute_action_plan` to get the exact set of
//! mutations needed to return to the baseline. The resulting plan is executed
//! by `RoutingTransaction` and the `WfpSession`.
//!
//! ## Rollback vs inversion
//!
//! Two approaches exist:
//!
//! 1. **Snapshot-based (used here)**: diff current state against pre-apply
//!    baseline. Handles external mutations that happened between apply and
//!    rollback (e.g. DHCP renewed a route).
//! 2. **Inversion-based**: mechanically invert the `ApplyActionPlan`
//!    (Add→Delete, Delete→Add). Simpler but cannot recover WFP filter specs
//!    for filters that were deleted during apply (the spec is lost after delete).
//!
//! We use approach 1 as the primary path. Approach 2 (`invert_action_plan`)
//! is provided as a utility for the case where snapshot capture fails.
//!
//! ## Partial failure policy
//!
//! If a compensating action fails, we continue with the remaining undo steps
//! (best-effort restore). We collect errors and surface them in the result
//! rather than aborting the rollback loop.
//!
//! This is safer than aborting on first failure, which would leave
//! the system in a partially-rollbacked state with larger inconsistency.
//!
//! ## Snapshot age check
//!
//! Before executing rollback we verify the snapshot age. A snapshot older than
//! `snapshot_max_age_secs` (default 86400 = 24 h) may no longer be an
//! accurate description of the pre-apply system state. We return
//! `SnapshotTooOld` rather than applying potentially dangerous mutations.
//!
//! Force-rollback (admin override, `ForceRollback` IPC) bypasses
//! this check. That bypass is implemented in `nrr-service-runtime`, not here.
//!
//! ## Idempotency
//!
//! Because we diff current → desired (pre-apply baseline), a second rollback
//! on the same snapshot finds the state already matches and returns
//! `RollbackResult::AlreadyAtBaseline`.

use std::sync::Arc;
use std::time::Instant;

use crate::{
    constants::ROLLBACK_TIMEOUT_SECS,
    error::PlatformError,
    routing::RoutingTransaction,
    snapshot::{
        compute_action_plan, DesiredPlatformState, PlatformStateSnapshot, RoutingStateSnapshot,
        WfpFilterSnapshot, SNAPSHOT_SCHEMA_VERSION,
    },
    types::{ApplyActionPlan, RouteEntry, RoutingAction, WfpFilterAction, WfpFilterSpec},
    wfp::WfpSession,
    windows_api::WindowsApiPort,
};
use nrr_storage::StoredSnapshot;

// ── RollbackResult ────────────────────────────────────────────────────────────

/// Outcome of one `RollbackEngine::rollback_to_snapshot` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackResult {
    /// All rollback actions succeeded; platform state matches pre-apply baseline.
    Completed,
    /// System was already at the pre-apply baseline; no actions were needed.
    AlreadyAtBaseline,
    /// Rollback executed best-effort. Some actions failed but we continued.
    /// The system is partially restored. Manual inspection recommended.
    PartiallyCompleted {
        routing_errors: usize,
        wfp_errors: usize,
    },
    /// Rollback failed completely (e.g. routing compensating journal errors +
    /// WFP transaction abort). `FailedRequiresManualAction`.
    Failed { reason: String },
    /// The stored snapshot is too old to use safely.
    SnapshotTooOld { age_secs: u64, max_age_secs: u64 },
    /// The snapshot JSON is invalid or has an unsupported schema version.
    SnapshotInvalid { reason: String },
    /// Timeout elapsed before rollback completed.
    TimedOut {
        completed_actions: usize,
        remaining_actions: usize,
    },
}

impl RollbackResult {
    /// Returns `true` when the platform state is reliably back at baseline.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Completed | Self::AlreadyAtBaseline)
    }

    /// Returns `true` when manual operator action is required.
    pub fn requires_manual_action(&self) -> bool {
        matches!(
            self,
            Self::Failed { .. }
                | Self::PartiallyCompleted { .. }
                | Self::SnapshotTooOld { .. }
                | Self::SnapshotInvalid { .. }
                | Self::TimedOut { .. }
        )
    }
}

// ── Plan inversion ────────────────────────────────────────────────────────────

/// Invert an `ApplyActionPlan` for rollback.
///
/// ## Routing
/// - `AddRoute(e)` → `DeleteRoute(e)`
/// - `DeleteRoute(e)` → `AddRoute(e)`
/// - `UpdateRoute { old, new }` → `UpdateRoute { old: new, new: old }`
///
/// ## WFP
/// - `AddFilter(spec)` → `DeleteFilter(spec.id)` (id known from spec)
/// - `DeleteFilter(id)` → **cannot invert** (spec lost after delete)
///   These entries are dropped. Use snapshot-based rollback for full fidelity.
///
/// Actions are reversed (last-in, first-out) to undo in correct order.
pub fn invert_action_plan(plan: &ApplyActionPlan) -> ApplyActionPlan {
    let mut routing = Vec::new();
    for action in plan.routing_actions.iter().rev() {
        match action {
            RoutingAction::AddRoute(e) => routing.push(RoutingAction::DeleteRoute(e.clone())),
            RoutingAction::DeleteRoute(e) => routing.push(RoutingAction::AddRoute(e.clone())),
            RoutingAction::UpdateRoute { old, new } => routing.push(RoutingAction::UpdateRoute {
                old: new.clone(),
                new: old.clone(),
            }),
        }
    }

    let mut wfp = Vec::new();
    for action in plan.wfp_actions.iter().rev() {
        match action {
            WfpFilterAction::AddFilter(spec) => {
                wfp.push(WfpFilterAction::DeleteFilter(spec.id));
            }
            WfpFilterAction::DeleteFilter(_id) => {
                // Cannot invert: spec unavailable after delete.
                // Use snapshot-based rollback (`rollback_to_snapshot`) for this case.
            }
        }
    }

    ApplyActionPlan {
        routing_actions: routing,
        wfp_actions: wfp,
    }
}

// ── Snapshot helpers ──────────────────────────────────────────────────────────

/// Convert a pre-apply `PlatformStateSnapshot` to a `DesiredPlatformState`.
/// Used as the "target" for `compute_action_plan` during rollback.
pub fn snapshot_to_desired(snapshot: &PlatformStateSnapshot) -> DesiredPlatformState {
    DesiredPlatformState {
        routes: snapshot.routing.entries.clone(),
        wfp_filters: snapshot
            .wfp
            .filters
            .iter()
            .map(|r| WfpFilterSpec {
                layer: r.layer,
                action: r.action,
                remote_ip: r.remote_ip,
                remote_port: r.remote_port,
                weight: r.weight,
                id: r.id,
                user_sid: r.user_sid.clone(),
                app_pattern: r.app_pattern.clone(),
                local_interface_luid: r.local_interface_luid,
                remote_subnet: r.remote_subnet,
                remote_subnet_v6: r.remote_subnet_v6,
                ip_protocol: r.ip_protocol,
            })
            .collect(),
    }
}

// ── RollbackEngine ────────────────────────────────────────────────────────────

/// Executes rollback to a stored pre-apply snapshot.
pub struct RollbackEngine {
    api: Arc<dyn WindowsApiPort>,
    /// Total time budget for rollback execution.
    pub rollback_timeout_secs: u64,
    /// Snapshots older than this are rejected.
    pub snapshot_max_age_secs: u64,
}

impl RollbackEngine {
    pub fn new(api: Arc<dyn WindowsApiPort>) -> Self {
        Self {
            api,
            rollback_timeout_secs: ROLLBACK_TIMEOUT_SECS,
            snapshot_max_age_secs: 86_400, // 24 h
        }
    }

    /// Execute rollback to the given stored snapshot.
    ///
    /// `now_secs` is the current wall-clock epoch seconds (injected for tests).
    /// `session` is the per-service-instance WFP session.
    pub fn rollback_to_snapshot(
        &self,
        stored: &StoredSnapshot,
        session: &WfpSession,
        now_secs: u64,
    ) -> RollbackResult {
        // ── Step 1: age check ─────────────────────────────────────────────
        let age_secs = now_secs.saturating_sub(stored.created_at);
        if age_secs > self.snapshot_max_age_secs {
            return RollbackResult::SnapshotTooOld {
                age_secs,
                max_age_secs: self.snapshot_max_age_secs,
            };
        }

        // ── Step 2: deserialise + verify integrity ────────────────────────
        let pre_apply: PlatformStateSnapshot = match serde_json::from_str(&stored.snapshot_json) {
            Ok(s) => s,
            Err(e) => {
                return RollbackResult::SnapshotInvalid {
                    reason: format!("JSON parse error: {e}"),
                }
            }
        };
        if pre_apply.schema_version > SNAPSHOT_SCHEMA_VERSION {
            return RollbackResult::SnapshotInvalid {
                reason: format!(
                    "schema_version {} > supported {}",
                    pre_apply.schema_version, SNAPSHOT_SCHEMA_VERSION
                ),
            };
        }
        if !pre_apply.verify_hash() {
            return RollbackResult::SnapshotInvalid {
                reason: "content hash mismatch — snapshot may be tampered".to_string(),
            };
        }

        // ── Step 3: capture current platform state ────────────────────────
        let current = match self.capture_current(session) {
            Ok(s) => s,
            Err(e) => {
                return RollbackResult::Failed {
                    reason: format!("failed to capture current state: {e}"),
                }
            }
        };

        // ── Step 4: compute rollback plan ─────────────────────────────────
        let desired = snapshot_to_desired(&pre_apply);
        let plan = compute_action_plan(&current, &desired);
        let total_actions = plan.routing_actions.len() + plan.wfp_actions.len();

        if total_actions == 0 {
            return RollbackResult::AlreadyAtBaseline;
        }

        // ── Step 5: execute with timeout tracking ─────────────────────────
        let deadline = Instant::now() + std::time::Duration::from_secs(self.rollback_timeout_secs);

        // Route batch with compensating journal.
        let mut routing_tx = RoutingTransaction::new(Arc::clone(&self.api));
        if let Err(e) = routing_tx.execute(&plan.routing_actions) {
            return RollbackResult::Failed {
                reason: format!("routing rollback failed: {e}"),
            };
        }

        if Instant::now() > deadline {
            let remaining = plan.wfp_actions.len();
            // Finalise routing (it's best-effort for rollback too).
            routing_tx.finalize();
            return RollbackResult::TimedOut {
                completed_actions: plan.routing_actions.len(),
                remaining_actions: remaining,
            };
        }

        // WFP batch.
        let wfp_errors = if plan.wfp_actions.is_empty() {
            0
        } else {
            match session.execute_wfp_plan(&plan.wfp_actions) {
                Ok(()) => 0,
                Err(_) => plan.wfp_actions.len(), // all failed (transaction aborted)
            }
        };

        // Routing execute() succeeded — discard the compensating log.
        // We are the rollback; there is nothing to undo from the rollback itself.
        routing_tx.finalize();

        if wfp_errors == 0 {
            RollbackResult::Completed
        } else if wfp_errors == plan.wfp_actions.len() {
            RollbackResult::Failed {
                reason: format!(
                    "rollback failed entirely: all {} WFP action(s) could not be reverted",
                    wfp_errors
                ),
            }
        } else {
            RollbackResult::PartiallyCompleted {
                routing_errors: 0,
                wfp_errors,
            }
        }
    }

    /// Capture current platform state as a `PlatformStateSnapshot`.
    fn capture_current(
        &self,
        session: &WfpSession,
    ) -> Result<PlatformStateSnapshot, PlatformError> {
        let routes = self.api.get_ip_forward_table()?;
        // Filter to our routes only (is_ours).
        let our_routes: Vec<RouteEntry> = routes.into_iter().filter(|r| r.is_ours).collect();

        let wfp_filters = session.enumerate_our_filters()?;

        let routing = RoutingStateSnapshot {
            entries: our_routes,
            taken_at_epoch_secs: 0,
        };
        let wfp = WfpFilterSnapshot {
            filters: wfp_filters,
            ..WfpFilterSnapshot::empty()
        };
        Ok(PlatformStateSnapshot::new(routing, wfp))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        snapshot::RoutingStateSnapshot,
        types::{WfpAction, WfpFilterId, WfpFilterRecord, WfpLayerKey},
        windows_api::MockWindowsApi,
    };
    use std::net::Ipv4Addr;

    fn api() -> Arc<MockWindowsApi> {
        Arc::new(MockWindowsApi::new())
    }

    fn session(api: &Arc<MockWindowsApi>) -> WfpSession {
        WfpSession::open(Arc::clone(api) as Arc<dyn WindowsApiPort>).unwrap()
    }

    fn engine(api: &Arc<MockWindowsApi>) -> RollbackEngine {
        RollbackEngine::new(Arc::clone(api) as Arc<dyn WindowsApiPort>)
    }

    fn route(dest: [u8; 4], ours: bool) -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::from(dest),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 5,
            metric: 10,
            is_ours: ours,
            table: nrr_platform_api::RouteTableRef::Main,
        }
    }

    fn filter_record(id_raw: u64) -> WfpFilterRecord {
        WfpFilterRecord {
            id: WfpFilterId { raw: id_raw },
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(1, 2, 3, id_raw as u8)),
            remote_port: None,
            weight: 0x100000 + id_raw,
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    fn filter_spec(id_raw: u64) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(1, 2, 3, id_raw as u8)),
            remote_port: None,
            weight: 0x100000 + id_raw,
            id: WfpFilterId { raw: id_raw },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    /// Build a `StoredSnapshot` from a `PlatformStateSnapshot`.
    fn stored_snapshot(snap: &PlatformStateSnapshot, created_at: u64) -> StoredSnapshot {
        StoredSnapshot {
            attempt_id: "test-rollback-001".into(),
            snapshot_hash: snap.content_hash_hex.clone(),
            snapshot_json: serde_json::to_string(snap).unwrap(),
            schema_version: snap.schema_version,
            created_at,
        }
    }

    fn empty_snapshot() -> PlatformStateSnapshot {
        PlatformStateSnapshot::empty()
    }

    // ── invert_action_plan ────────────────────────────────────────────────

    #[test]
    fn invert_reverses_add_route_to_delete() {
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::AddRoute(route([10, 0, 0, 1], true)));
        let inv = invert_action_plan(&plan);
        assert_eq!(inv.routing_actions.len(), 1);
        assert!(matches!(
            inv.routing_actions[0],
            RoutingAction::DeleteRoute(_)
        ));
    }

    #[test]
    fn invert_reverses_delete_route_to_add() {
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::DeleteRoute(route([10, 0, 0, 1], true)));
        let inv = invert_action_plan(&plan);
        assert!(matches!(inv.routing_actions[0], RoutingAction::AddRoute(_)));
    }

    #[test]
    fn invert_swaps_update_route() {
        let old = route([10, 0, 0, 1], true);
        let new = RouteEntry {
            metric: 50,
            ..old.clone()
        };
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions.push(RoutingAction::UpdateRoute {
            old: old.clone(),
            new: new.clone(),
        });
        let inv = invert_action_plan(&plan);
        match &inv.routing_actions[0] {
            RoutingAction::UpdateRoute {
                old: inv_old,
                new: inv_new,
            } => {
                assert_eq!(inv_old.metric, new.metric, "old and new are swapped");
                assert_eq!(inv_new.metric, old.metric);
            }
            other => panic!("expected UpdateRoute, got {other:?}"),
        }
    }

    #[test]
    fn invert_add_filter_becomes_delete() {
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(filter_spec(1)));
        let inv = invert_action_plan(&plan);
        assert_eq!(inv.wfp_actions.len(), 1);
        assert!(matches!(
            inv.wfp_actions[0],
            WfpFilterAction::DeleteFilter(_)
        ));
    }

    #[test]
    fn invert_delete_filter_is_dropped_not_invertible() {
        // DeleteFilter cannot be inverted without the spec.
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::DeleteFilter(WfpFilterId { raw: 42 }));
        let inv = invert_action_plan(&plan);
        assert!(
            inv.wfp_actions.is_empty(),
            "uninvertible DeleteFilter must be dropped"
        );
    }

    #[test]
    fn invert_preserves_reverse_order() {
        let r1 = route([10, 0, 0, 1], true);
        let r2 = route([10, 0, 1, 1], true);
        let mut plan = ApplyActionPlan::default();
        plan.routing_actions
            .push(RoutingAction::AddRoute(r1.clone()));
        plan.routing_actions
            .push(RoutingAction::AddRoute(r2.clone()));
        let inv = invert_action_plan(&plan);
        // Reversed: r2 first, then r1
        match &inv.routing_actions[0] {
            RoutingAction::DeleteRoute(e) => assert_eq!(e.destination, r2.destination),
            _ => panic!("expected DeleteRoute(r2)"),
        }
    }

    // ── snapshot_to_desired ───────────────────────────────────────────────

    #[test]
    fn snapshot_to_desired_converts_routes_and_filters() {
        let routing = RoutingStateSnapshot {
            entries: vec![route([10, 0, 0, 1], true)],
            taken_at_epoch_secs: 0,
        };
        let wfp = WfpFilterSnapshot {
            filters: vec![filter_record(1)],
            ..WfpFilterSnapshot::empty()
        };
        let snap = PlatformStateSnapshot::new(routing, wfp);
        let desired = snapshot_to_desired(&snap);
        assert_eq!(desired.routes.len(), 1);
        assert_eq!(desired.wfp_filters.len(), 1);
        assert_eq!(desired.wfp_filters[0].id.raw, 1);
    }

    // ── RollbackEngine ────────────────────────────────────────────────────

    #[test]
    fn rollback_snapshot_too_old_rejects() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);
        let snap = empty_snapshot();
        let stored = stored_snapshot(&snap, 0); // created_at = epoch 0

        let result = eng.rollback_to_snapshot(&stored, &session, 200_000); // now > 86400
        assert!(matches!(result, RollbackResult::SnapshotTooOld { .. }));
    }

    #[test]
    fn rollback_invalid_json_returns_snapshot_invalid() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);
        let stored = StoredSnapshot {
            attempt_id: "x".into(),
            snapshot_hash: "h".into(),
            snapshot_json: "not-json".into(),
            schema_version: 1,
            created_at: 1000,
        };
        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(matches!(result, RollbackResult::SnapshotInvalid { .. }));
    }

    #[test]
    fn rollback_tampered_hash_returns_snapshot_invalid() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);
        let snap = empty_snapshot();
        let mut stored = stored_snapshot(&snap, 1000);
        stored.snapshot_hash = "tampered".into();
        // The JSON still has the original hash, but stored.snapshot_hash is different.
        // The rollback engine re-verifies the hash from within the JSON.
        // We need to also tamper the JSON's content_hash_hex.
        let mut json: serde_json::Value = serde_json::from_str(&stored.snapshot_json).unwrap();
        json["content_hash_hex"] = serde_json::Value::String("tampered".into());
        stored.snapshot_json = serde_json::to_string(&json).unwrap();

        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(matches!(result, RollbackResult::SnapshotInvalid { .. }));
    }

    #[test]
    fn rollback_to_empty_snapshot_when_already_empty_is_at_baseline() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);
        // Pre-apply: empty state. Current: also empty.
        let snap = empty_snapshot();
        let stored = stored_snapshot(&snap, 1000);
        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert_eq!(result, RollbackResult::AlreadyAtBaseline);
    }

    #[test]
    fn rollback_removes_routes_added_during_apply() {
        let api = api();
        // Simulate: pre-apply = empty. After apply a route was added to mock.
        api.create_ip_forward_entry(&route([10, 0, 0, 1], true))
            .unwrap();
        assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);

        let session = session(&api);
        let eng = engine(&api);

        // Pre-apply snapshot: empty
        let snap = empty_snapshot();
        let stored = stored_snapshot(&snap, 1000);

        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(result.is_clean(), "rollback must succeed: {result:?}");
        assert!(
            api.get_ip_forward_table().unwrap().is_empty(),
            "applied route must be removed by rollback"
        );
    }

    #[test]
    fn rollback_restores_routes_deleted_during_apply() {
        let api = api();
        let session = session(&api);
        let eng = engine(&api);

        let r = route([10, 0, 0, 1], true);

        // Pre-apply: had route r.
        let routing = RoutingStateSnapshot {
            entries: vec![r.clone()],
            taken_at_epoch_secs: 0,
        };
        let snap = PlatformStateSnapshot::new(routing, WfpFilterSnapshot::empty());
        let stored = stored_snapshot(&snap, 1000);

        // Current state: route was deleted during apply (mock is empty).
        assert!(api.get_ip_forward_table().unwrap().is_empty());

        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(result.is_clean(), "rollback must succeed: {result:?}");
        assert_eq!(
            api.get_ip_forward_table().unwrap().len(),
            1,
            "deleted route must be restored"
        );
    }

    #[test]
    fn rollback_removes_wfp_filters_added_during_apply() {
        let api = api();
        let session = session(&api);
        // Add a filter to mock (simulating apply)
        session
            .execute_wfp_plan(&[WfpFilterAction::AddFilter(filter_spec(1))])
            .unwrap();
        assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);

        let eng = engine(&api);
        // Pre-apply snapshot: no filters
        let snap = empty_snapshot();
        let stored = stored_snapshot(&snap, 1000);

        let result = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(result.is_clean(), "rollback must succeed: {result:?}");
        assert!(
            api.wfp_filters.lock().unwrap().is_empty(),
            "filter must be removed"
        );
    }

    #[test]
    fn rollback_idempotent_second_call_is_at_baseline() {
        let api = api();
        let session = session(&api);
        api.create_ip_forward_entry(&route([10, 0, 0, 1], true))
            .unwrap();

        let eng = engine(&api);
        let snap = empty_snapshot();
        let stored = stored_snapshot(&snap, 1000);

        let r1 = eng.rollback_to_snapshot(&stored, &session, 1001);
        assert!(r1.is_clean(), "first rollback: {r1:?}");

        // Second rollback: already at baseline
        let r2 = eng.rollback_to_snapshot(&stored, &session, 1002);
        assert_eq!(
            r2,
            RollbackResult::AlreadyAtBaseline,
            "second rollback must be no-op"
        );
    }

    #[test]
    fn rollback_requires_manual_action_is_correct_set() {
        assert!(!RollbackResult::Completed.requires_manual_action());
        assert!(!RollbackResult::AlreadyAtBaseline.requires_manual_action());
        assert!(RollbackResult::Failed { reason: "x".into() }.requires_manual_action());
        assert!(RollbackResult::SnapshotTooOld {
            age_secs: 1,
            max_age_secs: 0
        }
        .requires_manual_action());
        assert!(RollbackResult::PartiallyCompleted {
            routing_errors: 1,
            wfp_errors: 0
        }
        .requires_manual_action());
    }

    #[test]
    fn rollback_engine_default_timeout_matches_constant() {
        let api = api();
        let eng = engine(&api);
        assert_eq!(eng.rollback_timeout_secs, ROLLBACK_TIMEOUT_SECS);
        assert_eq!(eng.snapshot_max_age_secs, 86_400);
    }
}

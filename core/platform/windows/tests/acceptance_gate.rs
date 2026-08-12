//! Cross-cutting acceptance gate tests.
//!
//! Gate 1  — Full round-trip: apply action plan → verify = Clean
//! Gate 2  — Rollback restores baseline after apply
//! Gate 3  — Idempotency: second apply on unchanged state produces empty plan
//! Gate 4  — Fail-Closed blocks intended IPs; exempt addresses are never blocked
//! Gate 5  — Drift detection fires when state is mutated after apply
//! Gate 6  — Stale snapshot rejected; fresh snapshot accepted
//! Gate 7  — Plan inversion roundtrip: apply then invert restores baseline
//! Gate 8  — cleanup_wfp removes all our filters (orphan-cleanup on service stop)
//! Gate 9  — Stress: 20 rapid apply/rollback cycles do not leak state
//! Gate 10 — DeleteFilter is uninvertible; snapshot-based rollback handles it
//! Gate 11 — Negative: routing failure leaves no partial state
//! Gate 12 — Negative: apply without WFP session fails gracefully
//! Gate 13 — Rollback is idempotent on repeated calls
//! Gate 14 — FailClosedPlan block/unblock ID roundtrip
//! Gate 15 — Captured snapshot hash is always valid; tampered hash fails
//!
//! Manual Windows checklist (requires real hardware — not executable here):
//!
//! [ ] apply on real routing table: verify route appears (`route print` / `netsh`)
//! [ ] rollback on real routing table: verify route removed
//! [ ] WFP filter visible in Windows Firewall with Advanced Security
//! [ ] cleanup_wfp at service stop: orphan filters absent after process kill
//! [ ] Fail-Closed: secondary VPN disconnected → secondary-bound traffic is blocked
//! [ ] Fail-Closed: primary traffic is not affected when secondary is down
//! [ ] Real Windows coexistence: loopback/link-local routes not touched by apply
//! [ ] WFP coexistence: Windows Defender Firewall allows DNS (53/udp) after our filters
//! [ ] Third-party AV (ESET/Kaspersky): our sub-layer filters shown in their UI
//! [ ] Drift detection: external VPN adds a conflicting route → Warning logged
//! [ ] SCM: service starts as LocalSystem (confirmed by the privilege matrix)

// Integration test crate: `unwrap()`/`expect()` in setup helpers assert invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use nrr_platform_windows::adapters::AdapterAvailability;
use nrr_platform_windows::{
    // snapshot
    compute_action_plan,
    // fail_closed
    compute_block_filters,
    compute_unblock_filter_ids,
    fail_closed_filter_id,
    // rollback
    invert_action_plan,
    is_exempt_from_blocking,
    // types
    ApplyActionPlan,
    DesiredPlatformState,
    // verify
    DriftSeverity,
    // apply
    EngineResult,
    FailClosedPlan,
    FailClosedRuleSpec,
    // windows_api
    MockWindowsApi,
    PlatformStateSnapshot,
    RouteEntry,
    RoutingAction,
    WfpAction,
    WfpFilterAction,
    WfpFilterSpec,
    WfpLayerKey,
    WindowsApiPort,
    WindowsApplyEngine,
};
use nrr_storage::StoredSnapshot;

// ── Test scaffolding ──────────────────────────────────────────────────────────

fn api() -> Arc<MockWindowsApi> {
    Arc::new(MockWindowsApi::new())
}

fn engine(api: &Arc<MockWindowsApi>) -> WindowsApplyEngine {
    let eng = WindowsApplyEngine::new(Arc::clone(api) as Arc<dyn WindowsApiPort>);
    eng.open_session().unwrap();
    eng
}

fn route(dest: [u8; 4], ifindex: u32) -> RouteEntry {
    RouteEntry {
        destination: Ipv4Addr::from(dest),
        prefix_length: 24,
        next_hop: Ipv4Addr::new(192, 168, 1, 1),
        interface_index: ifindex,
        metric: 10,
        is_ours: true,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

fn filter_spec_for(rule_id: &str, ip: [u8; 4], position: u64) -> WfpFilterSpec {
    let remote_ip = Ipv4Addr::from(ip);
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(remote_ip),
        remote_port: None,
        weight: 0x100_000 + position,
        id: fail_closed_filter_id(rule_id, remote_ip),
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

fn stored_snapshot(snap: &PlatformStateSnapshot, created_at: u64) -> StoredSnapshot {
    StoredSnapshot {
        attempt_id: "gate-attempt-001".into(),
        snapshot_hash: snap.content_hash_hex.clone(),
        snapshot_json: serde_json::to_string(snap).unwrap(),
        schema_version: snap.schema_version,
        created_at,
    }
}

fn empty_snapshot() -> PlatformStateSnapshot {
    PlatformStateSnapshot::empty()
}

fn assert_apply_ok(eng: &WindowsApplyEngine, plan: &ApplyActionPlan) {
    let r = eng.execute_plan(plan);
    assert!(
        matches!(r, EngineResult::Success { .. }),
        "apply must succeed: {r:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 1: Full round-trip apply → verify = Clean
//
// Starting from empty state, compute a plan A→B, execute it, then verify
// the resulting platform state matches the intended desired state.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate1_full_apply_then_verify_clean() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 0, 0, 0], 5);
    let spec = filter_spec_for("gate1-rule", [1, 2, 3, 4], 0);

    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![spec.clone()],
    };

    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert!(!plan.is_empty(), "plan must not be empty");

    assert_apply_ok(&eng, &plan);

    // Post-apply verify must be clean.
    let result = eng.verify_apply(&desired, 2000);
    assert!(
        result.is_clean(),
        "state must be clean after apply: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 2: Rollback restores baseline
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate2_rollback_restores_baseline() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 1, 0, 0], 5);
    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![],
    };

    let pre_apply = empty_snapshot();
    let stored = stored_snapshot(&pre_apply, 1000);

    let plan = compute_action_plan(&pre_apply, &desired);
    assert_apply_ok(&eng, &plan);
    assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);

    let rollback_result = eng.rollback_with_snapshot(&stored, 1001);
    assert!(
        matches!(rollback_result, EngineResult::RollbackCompleted { .. }),
        "rollback must complete: {rollback_result:?}"
    );
    assert!(
        api.get_ip_forward_table().unwrap().is_empty(),
        "route must be removed after rollback"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 3: Idempotency — second apply produces empty plan
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate3_second_apply_produces_empty_plan() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 2, 0, 0], 5);
    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![],
    };

    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert_apply_ok(&eng, &plan);

    let current = eng.capture_current_snapshot(2000).unwrap();
    let second_plan = compute_action_plan(&current, &desired);
    assert!(
        second_plan.is_empty(),
        "second plan must be no-op: routing={}, wfp={}",
        second_plan.routing_actions.len(),
        second_plan.wfp_actions.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4a: Fail-Closed blocks secondary-bound IPs
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate4a_fail_closed_blocks_secondary_ips() {
    let secondary_ip = Ipv4Addr::new(10, 100, 0, 1);
    let filters = compute_block_filters(
        &[secondary_ip],
        "rule-001",
        AdapterAvailability::PresentDown,
        0,
    );
    assert_eq!(filters.len(), 1, "one block filter must be produced");
    let f = &filters[0];
    assert_eq!(f.remote_ip, Some(secondary_ip));
    assert_eq!(f.action, WfpAction::Block);
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4b: Exempt addresses (loopback, link-local) are never blocked
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate4b_fail_closed_exempts_loopback_and_link_local() {
    assert!(is_exempt_from_blocking(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(is_exempt_from_blocking(Ipv4Addr::new(127, 255, 255, 255)));
    assert!(is_exempt_from_blocking(Ipv4Addr::new(169, 254, 0, 1)));
    assert!(is_exempt_from_blocking(Ipv4Addr::new(169, 254, 255, 255)));

    // Non-exempt addresses must NOT be exempt.
    assert!(!is_exempt_from_blocking(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(!is_exempt_from_blocking(Ipv4Addr::new(1, 2, 3, 4)));
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4c: Fail-Closed filter IDs are stable (same input → same ID)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate4c_fail_closed_filter_ids_are_stable() {
    let ip = Ipv4Addr::new(10, 100, 0, 1);
    let id1 = fail_closed_filter_id("rule-abc", ip);
    let id2 = fail_closed_filter_id("rule-abc", ip);
    assert_eq!(id1, id2, "same input must produce same filter ID");

    let id3 = fail_closed_filter_id("rule-xyz", ip);
    assert_ne!(
        id1, id3,
        "different rule_id must produce different filter ID"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4d: Fail-Closed produces no filters when secondary is available
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate4d_fail_closed_no_filters_when_secondary_available() {
    let filters = compute_block_filters(
        &[Ipv4Addr::new(10, 100, 0, 1)],
        "rule-001",
        AdapterAvailability::Available,
        0,
    );
    assert!(filters.is_empty(), "no filters when secondary is available");
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 5: Drift detection fires on route removal after apply
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate5_drift_fires_on_route_removal() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 3, 0, 0], 5);
    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![],
    };

    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert_apply_ok(&eng, &plan);

    // Immediately after apply: clean.
    let clean = eng.verify_apply(&desired, 2000);
    assert!(
        clean.is_clean(),
        "must be clean right after apply: {clean:?}"
    );

    // External removal of our route.
    (Arc::clone(&api) as Arc<dyn WindowsApiPort>)
        .delete_ip_forward_entry(&r)
        .unwrap();

    // Now verify must detect Critical drift.
    let drift = eng.verify_apply(&desired, 2001);
    assert!(
        drift.requires_rollback(),
        "missing route must be Critical: {drift:?}"
    );
    assert_eq!(drift.max_severity(), Some(&DriftSeverity::Critical));
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 5b: Drift detection fires on WFP filter removal after apply
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate5b_drift_fires_on_filter_removal() {
    let api = api();
    let eng = engine(&api);

    let spec = filter_spec_for("gate5b-rule", [5, 6, 7, 8], 0);
    let desired = DesiredPlatformState {
        routes: vec![],
        wfp_filters: vec![spec.clone()],
    };

    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert_apply_ok(&eng, &plan);

    // External removal of the filter.
    {
        let mut wfp_filters = api.wfp_filters.lock().unwrap();
        wfp_filters.retain(|f| f.id != spec.id);
    }

    let drift = eng.verify_apply(&desired, 3000);
    assert!(
        drift.requires_rollback(),
        "missing WFP filter must be Critical: {drift:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 6: Stale snapshot rejected; fresh snapshot accepted
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate6_stale_snapshot_rejected() {
    let api = api();
    let eng = engine(&api);

    let snap = empty_snapshot();
    // created_at = 0; now = 200_000 → age > 86_400 s limit.
    let stale = stored_snapshot(&snap, 0);
    let result = eng.rollback_with_snapshot(&stale, 200_000);
    assert!(
        matches!(result, EngineResult::Failed { .. }),
        "stale snapshot must be rejected: {result:?}"
    );
}

#[test]
fn gate6_fresh_snapshot_executes_rollback() {
    let api = api();
    let eng = engine(&api);

    // Add a route to simulate post-apply state.
    let r = route([10, 4, 0, 0], 5);
    (Arc::clone(&api) as Arc<dyn WindowsApiPort>)
        .create_ip_forward_entry(&r)
        .unwrap();
    assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);

    // Pre-apply: empty, 10 seconds ago.
    let snap = empty_snapshot();
    let fresh = stored_snapshot(&snap, 1000);
    let result = eng.rollback_with_snapshot(&fresh, 1010);
    assert!(
        matches!(result, EngineResult::RollbackCompleted { .. }),
        "fresh snapshot must be accepted: {result:?}"
    );
    assert!(
        api.get_ip_forward_table().unwrap().is_empty(),
        "route must be removed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 7: Plan inversion roundtrip restores baseline
//
// apply(plan) then apply(invert(plan)) == baseline.
// Only Add* actions are invertible; this test uses only adds.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate7_plan_inversion_roundtrip() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 5, 0, 0], 5);
    let spec = filter_spec_for("gate7-rule", [7, 7, 7, 7], 0);

    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![spec.clone()],
    };

    // Forward apply.
    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert!(!plan.is_empty());
    assert_apply_ok(&eng, &plan);

    assert_eq!(api.get_ip_forward_table().unwrap().len(), 1);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);

    // Invert and apply: should restore baseline.
    let inv = invert_action_plan(&plan);
    assert!(!inv.is_empty(), "inverted plan must not be empty");
    assert_apply_ok(&eng, &inv);

    assert!(
        api.get_ip_forward_table().unwrap().is_empty(),
        "routes gone after inversion"
    );
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "filters gone after inversion"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 8: cleanup_wfp removes all our filters (orphan-cleanup on service stop)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate8_cleanup_wfp_removes_all_filters() {
    let api = api();
    let eng = engine(&api);

    for i in 0..5u64 {
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(filter_spec_for(
                &format!("cleanup-rule-{i}"),
                [i as u8 + 1, 0, 0, 1],
                i,
            )));
        assert_apply_ok(&eng, &plan);
    }
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 5);

    let deleted = eng.cleanup_wfp().unwrap();
    assert_eq!(deleted, 5, "all 5 filters must be deleted on cleanup");
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "no orphan filters"
    );

    // Second cleanup is idempotent.
    assert_eq!(eng.cleanup_wfp().unwrap(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 9: Stress — 20 rapid apply/rollback cycles do not leak state
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate9_rapid_apply_rollback_no_state_leak() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 99, 0, 0], 5);
    let spec = filter_spec_for("stress-rule", [9, 9, 9, 9], 0);
    let desired = DesiredPlatformState {
        routes: vec![r.clone()],
        wfp_filters: vec![spec.clone()],
    };

    for cycle in 0..20u64 {
        let pre = empty_snapshot();
        let stored = stored_snapshot(&pre, 1000 + cycle);

        let plan = compute_action_plan(&pre, &desired);
        let apply_result = eng.execute_plan(&plan);
        assert!(
            matches!(apply_result, EngineResult::Success { .. }),
            "cycle {cycle}: apply failed: {apply_result:?}"
        );

        let rollback_result = eng.rollback_with_snapshot(&stored, 1001 + cycle);
        assert!(
            matches!(rollback_result, EngineResult::RollbackCompleted { .. }),
            "cycle {cycle}: rollback failed: {rollback_result:?}"
        );

        assert!(
            api.get_ip_forward_table().unwrap().is_empty(),
            "cycle {cycle}: route leaked"
        );
        assert!(
            api.wfp_filters.lock().unwrap().is_empty(),
            "cycle {cycle}: filter leaked"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 10: DeleteFilter is uninvertible; snapshot-based rollback handles it
//
// A filter that was deleted during apply cannot be re-added by inverting the
// plan (the spec is lost). But rollback_with_snapshot can restore it because
// it reads the spec from the pre-apply snapshot.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate10_snapshot_rollback_restores_deleted_filter() {
    let api = api();
    let eng = engine(&api);

    let spec = filter_spec_for("gate10-rule", [5, 5, 5, 5], 0);

    // Add the filter to establish pre-apply state.
    {
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::AddFilter(spec.clone()));
        assert_apply_ok(&eng, &plan);
    }
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 1);

    // Capture pre-apply snapshot (filter is present).
    let pre_apply = eng.capture_current_snapshot(1000).unwrap();
    let stored = stored_snapshot(&pre_apply, 1000);

    // Apply a plan that deletes the filter.
    {
        let mut plan = ApplyActionPlan::default();
        plan.wfp_actions
            .push(WfpFilterAction::DeleteFilter(spec.id));
        assert_apply_ok(&eng, &plan);
    }
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "filter must be deleted"
    );

    // Plan inversion cannot restore the deleted filter.
    let delete_plan = {
        let mut p = ApplyActionPlan::default();
        p.wfp_actions.push(WfpFilterAction::DeleteFilter(spec.id));
        p
    };
    let inv = invert_action_plan(&delete_plan);
    assert!(
        inv.wfp_actions.is_empty(),
        "DeleteFilter must be uninvertible by invert_action_plan"
    );

    // Snapshot-based rollback CAN restore the filter.
    let rollback_result = eng.rollback_with_snapshot(&stored, 1001);
    assert!(
        matches!(rollback_result, EngineResult::RollbackCompleted { .. }),
        "snapshot rollback must restore deleted filter: {rollback_result:?}"
    );
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        1,
        "filter must be restored by snapshot rollback"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 11: Negative — routing failure leaves no partial state
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate11_negative_routing_failure_leaves_no_partial_state() {
    use nrr_platform_windows::PlatformError;

    let api = api();
    let eng = engine(&api);

    api.set_force_error(Some(PlatformError::Win32 {
        operation: "create_ip_forward_entry",
        code: 5,
        message: "injected failure".into(),
    }));

    let mut plan = ApplyActionPlan::default();
    plan.routing_actions
        .push(RoutingAction::AddRoute(route([10, 6, 0, 0], 5)));

    let result = eng.execute_plan(&plan);
    assert!(
        matches!(
            result,
            EngineResult::RollbackStarted { .. } | EngineResult::Failed { .. }
        ),
        "failed apply must not succeed: {result:?}"
    );

    api.set_force_error(None);
    assert!(
        api.get_ip_forward_table().unwrap().is_empty(),
        "partial route must not persist after apply failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 12: Negative — apply without WFP session fails gracefully
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate12_negative_apply_without_session_fails_gracefully() {
    let api = api();
    // Deliberately NOT calling open_session().
    let eng = WindowsApplyEngine::new(Arc::clone(&api) as Arc<dyn WindowsApiPort>);

    let mut plan = ApplyActionPlan::default();
    plan.wfp_actions
        .push(WfpFilterAction::AddFilter(filter_spec_for(
            "no-session",
            [1, 1, 1, 1],
            0,
        )));

    let result = eng.execute_plan(&plan);
    assert!(
        matches!(
            result,
            EngineResult::RollbackStarted { .. } | EngineResult::RequiresUserAction { .. }
        ),
        "missing session must fail gracefully: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 13: Rollback idempotency — second call returns RollbackCompleted
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate13_rollback_idempotent() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 7, 0, 0], 5);
    let pre = empty_snapshot();
    let stored = stored_snapshot(&pre, 1000);

    let mut plan = ApplyActionPlan::default();
    plan.routing_actions.push(RoutingAction::AddRoute(r));
    assert_apply_ok(&eng, &plan);

    let r1 = eng.rollback_with_snapshot(&stored, 1001);
    assert!(
        matches!(r1, EngineResult::RollbackCompleted { .. }),
        "first rollback: {r1:?}"
    );

    // Second rollback: already at baseline → still RollbackCompleted.
    let r2 = eng.rollback_with_snapshot(&stored, 1002);
    assert!(
        matches!(r2, EngineResult::RollbackCompleted { .. }),
        "second rollback must be idempotent: {r2:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 14: FailClosedPlan block/unblock filter ID roundtrip
//
// The IDs produced by `compute_block_filters` must exactly match the IDs
// returned by `compute_unblock_filter_ids` for the same inputs.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate14_fail_closed_block_unblock_id_roundtrip() {
    let ips = vec![Ipv4Addr::new(10, 200, 0, 1), Ipv4Addr::new(10, 200, 0, 2)];

    let block_filters = compute_block_filters(&ips, "r1", AdapterAvailability::PresentDown, 0);
    assert_eq!(block_filters.len(), 2);

    let block_ids: std::collections::HashSet<_> = block_filters.iter().map(|f| f.id).collect();

    let unblock_ids: std::collections::HashSet<_> =
        compute_unblock_filter_ids(&ips, "r1").into_iter().collect();

    assert_eq!(block_ids, unblock_ids, "block IDs must match unblock IDs");
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 14b: FailClosedPlan struct produces same filters as raw compute_block_filters
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate14b_fail_closed_plan_matches_raw_compute() {
    let specs = vec![
        FailClosedRuleSpec {
            rule_id: "r1".to_string(),
            destination_ips: vec![Ipv4Addr::new(10, 200, 0, 1)],
            canonical_position: 0,
        },
        FailClosedRuleSpec {
            rule_id: "r2".to_string(),
            destination_ips: vec![Ipv4Addr::new(10, 200, 0, 2)],
            canonical_position: 1,
        },
    ];

    // FailClosedPlan::compute when secondary is down.
    let plan = FailClosedPlan::compute(&specs, AdapterAvailability::PresentDown);
    assert_eq!(plan.block_filters.len(), 2);
    assert!(plan.reason.is_some());

    // When secondary is available: no filters.
    let empty_plan = FailClosedPlan::compute(&specs, AdapterAvailability::Available);
    assert!(empty_plan.block_filters.is_empty());
    assert!(empty_plan.reason.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 15: Captured snapshot hash is always valid; tampered hash fails
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn gate15_captured_snapshot_hash_valid_and_tamper_detected() {
    let api = api();
    let eng = engine(&api);

    let r = route([10, 8, 0, 0], 5);
    let desired = DesiredPlatformState {
        routes: vec![r],
        wfp_filters: vec![],
    };
    let plan = compute_action_plan(&empty_snapshot(), &desired);
    assert_apply_ok(&eng, &plan);

    let snap = eng.capture_current_snapshot(3000).unwrap();
    assert!(
        snap.verify_hash(),
        "freshly captured snapshot hash must be valid"
    );

    // Tamper the hash field.
    let mut tampered = snap.clone();
    tampered.content_hash_hex =
        "0000000000000000000000000000000000000000000000000000000000000000".into();
    assert!(
        !tampered.verify_hash(),
        "tampered hash must fail verification"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual Windows checklist stub
//
// Presence of this test confirms the manual checklist items are in scope.
// The items listed in the module comment require a real Windows environment.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn manual_windows_checklist_is_documented() {
    // No assertions — the checklist is documented in the module comment above.
}

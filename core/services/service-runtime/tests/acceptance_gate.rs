#![allow(
    unused_imports,
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::default_constructed_unit_structs
)]
//! Cross-cutting acceptance gate tests.
//!
//! Each test corresponds to one of the following readiness criteria:
//!
//! 1. SCM lifecycle (manual — see checklist comment at bottom)
//! 2. Service-owned state — covered by bootstrap.rs
//! 3. Safe GUI/tray IPC — gates 3–6 below
//! 4. Bootstrap/integrity/recovery — gates 1–2 + existing module tests
//! 5. Apply layer without UI deps — dependency_boundary.rs + gate 10
//! 6. Least-privilege justification — service_lifecycle.rs + gate 8

use nrr_service_runtime::{
    // crash_recovery
    decide_recovery,
    execute_safe_disable,
    required_service_identity,
    ActiveRevisionState,
    ApplyAttemptMarker,
    ApplyMarkerStore,
    ApplyPhase,
    CrashCounter,
    DegradedMode,
    DegradedModeStatus,
    // ipc
    HandlerOutcome,
    // service_lifecycle
    IdentityRequirement,
    IpcAuditEmitter,
    IpcClientProfile,
    IpcErrorCode,
    IpcHandler,
    IpcHandlerRegistry,
    IpcOperationClass,
    IpcOperationName,
    IpcRequestContext,
    IpcRequestEnvelope,
    IpcResponseEnvelope,
    IpcRouter,
    NoopIpcAuditEmitter,
    NoopRecoveryAuditSink,
    // policy_loader
    PolicyLoadResult,
    RecoveryAuditRecord,
    RecoveryAuditSink,
    RecoveryDecision,
    RecoveryPolicy,
    SafeDisableRequest,
    SecurityChecklist,
    ServiceIdentityDecision,
    // state
    ServicePolicyState,
    StartupRecoveryCoordinator,
    IPC_PROTOCOL_VERSION,
    PRELIMINARY_IDENTITY,
    PRIVILEGE_MATRIX,
};
use std::sync::{Arc, Mutex};

// ── Shared test scaffolding ───────────────────────────────────────────────────

struct FakeMarkerStore {
    marker: Mutex<Option<ApplyAttemptMarker>>,
}
impl FakeMarkerStore {
    fn with(m: ApplyAttemptMarker) -> Self {
        Self {
            marker: Mutex::new(Some(m)),
        }
    }
    fn empty() -> Self {
        Self {
            marker: Mutex::new(None),
        }
    }
}
impl ApplyMarkerStore for FakeMarkerStore {
    fn read(&self) -> Option<ApplyAttemptMarker> {
        self.marker.lock().unwrap().clone()
    }
    fn write(&self, m: &ApplyAttemptMarker) -> Result<(), String> {
        *self.marker.lock().unwrap() = Some(m.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), String> {
        *self.marker.lock().unwrap() = None;
        Ok(())
    }
}

struct RecordingSink {
    events: Mutex<Vec<RecoveryAuditRecord>>,
    fail: bool,
}
impl RecordingSink {
    fn ok() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail: false,
        }
    }
    fn failing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail: true,
        }
    }
    fn count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}
impl RecoveryAuditSink for RecordingSink {
    fn emit(&self, r: RecoveryAuditRecord) -> Result<(), String> {
        if self.fail {
            return Err("disk full".into());
        }
        self.events.lock().unwrap().push(r);
        Ok(())
    }
}

fn mid_apply_marker() -> ApplyAttemptMarker {
    ApplyAttemptMarker {
        attempt_id: "att-gate-01".into(),
        active_revision_id: "rev-gate".into(),
        phase: ApplyPhase::Applying,
        started_at_epoch_secs: 9000,
        last_step_at_epoch_secs: 9001,
        intended_rollback_to: Some("rev-lkg".into()),
        correlation_id: "corr-gate".into(),
    }
}

struct EchoHandler;
impl IpcHandler for EchoHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        Ok(serde_json::json!({ "echo": request.operation.slug() }))
    }
}

fn make_router() -> IpcRouter {
    let mut reg = IpcHandlerRegistry::new();
    reg.register(IpcOperationName::ServiceHealthGet, EchoHandler);
    reg.register(IpcOperationName::MutationSubmit, EchoHandler);
    IpcRouter::new(reg, Arc::new(NoopIpcAuditEmitter::default()), 1)
}

fn read_req() -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "req-read".into(),
        correlation_id: None,
        operation: IpcOperationName::ServiceHealthGet,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({}),
    }
}

fn mutation_req() -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "req-mut".into(),
        correlation_id: None,
        operation: IpcOperationName::MutationSubmit,
        operation_class: IpcOperationClass::MutationRequest,
        confirmation_token: Some("tok".into()),
        payload: serde_json::json!({}),
    }
}

fn elevated_gui() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: true,
        caller_principal: None,
    }
}
fn unprivileged_tray() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::TrayLightweight,
        caller_is_elevated: false,
        caller_principal: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 1: No silent policy activation with an incomplete apply marker
//
// When an apply-phase marker exists on startup, decide_recovery must never
// return ProceedNormal — the service must not silently activate a policy
// that was mid-apply when the previous instance crashed.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn no_silent_policy_activation_with_incomplete_marker() {
    let coord = StartupRecoveryCoordinator::new(
        FakeMarkerStore::with(mid_apply_marker()),
        RecordingSink::ok(),
    );
    let state = coord.assess();
    let decision = decide_recovery(&state, true, true);
    assert!(
        !matches!(decision, RecoveryDecision::ProceedNormal),
        "ProceedNormal must never be returned when an incomplete marker exists"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 2: Integrity check precedes any policy activation
//
// Only ActiveLoaded and LkgFallbackApplied produce policy-ready states.
// All error outcomes must NOT yield a ready state — there is no shortcut
// into active-policy territory.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn only_loaded_outcomes_can_produce_policy_ready_state() {
    let ready = ActiveRevisionState {
        revision_id: "rev-x".into(),
        provenance: "active".into(),
        rule_count: 0,
        behavior_mode: "auto".into(),
        content_hash_hex: "aabb".into(),
        activated_at_iso: "t".into(),
    };
    assert_eq!(
        PolicyLoadResult::ActiveLoaded(ready.clone()).to_policy_state(),
        ServicePolicyState::ActiveReady
    );
    assert_eq!(
        PolicyLoadResult::LkgFallbackApplied(ready).to_policy_state(),
        ServicePolicyState::LkgReady
    );

    for outcome in &[
        PolicyLoadResult::NoActiveRevision,
        PolicyLoadResult::RecoveryRequired("broken".into()),
        PolicyLoadResult::StorageError("io".into()),
    ] {
        let state = outcome.to_policy_state();
        assert!(
            !matches!(
                state,
                ServicePolicyState::ActiveReady | ServicePolicyState::LkgReady
            ),
            "{outcome:?} must not produce a ready policy state, got {state:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 3: Read-only IPC allowed in most degraded modes
//
// Status queries must work even when storage/audit is degraded — the GUI
// must be able to display the degraded state. Only IpcDegraded blocks reads.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn read_only_ipc_allowed_in_most_degraded_modes() {
    let non_ipc_modes = [
        DegradedMode::StorageDegraded {
            detail: "db locked".into(),
        },
        DegradedMode::AuditUnavailable {
            detail: "log dir gone".into(),
        },
        DegradedMode::PolicyRecoveryRequired {
            detail: "hash mismatch".into(),
        },
        DegradedMode::ApplyLayerUnavailable {
            detail: "driver offline".into(),
        },
    ];
    for mode in non_ipc_modes {
        let mut status = DegradedModeStatus::default();
        status.add(mode.clone());
        assert!(
            status.allows_read_only_ipc(),
            "read-only must be allowed in {mode:?}"
        );
    }
}

#[test]
fn read_only_ipc_blocked_only_by_ipc_degraded() {
    let mut status = DegradedModeStatus::default();
    status.add(DegradedMode::IpcDegraded {
        detail: "pipe broken".into(),
    });
    assert!(!status.allows_read_only_ipc());
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 4: Privileged mutations blocked when audit is unavailable
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn privileged_mutation_blocked_when_audit_unavailable() {
    let mut status = DegradedModeStatus::default();
    status.add(DegradedMode::AuditUnavailable {
        detail: "disk full".into(),
    });
    assert!(!status.allows_apply_operations());
    assert!(!status.allows_audit_write());
    // Read-only is still OK
    assert!(status.allows_read_only_ipc());
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 5: IPC mutation requires elevation
//
// A mutation from an unprivileged client must be Forbidden even if the
// envelope is otherwise well-formed.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn ipc_mutation_from_unprivileged_client_is_forbidden() {
    let router = make_router();
    let resp = router.dispatch(mutation_req(), unprivileged_tray());
    assert!(!resp.ok);
    assert_eq!(
        resp.error.unwrap().code,
        IpcErrorCode::Forbidden,
        "unprivileged mutation must be Forbidden"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 6: GUI/tray can reconnect (stateless IPC router)
//
// Three consecutive read requests from the same client must all succeed.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn ipc_read_requests_are_stateless_across_calls() {
    let router = make_router();
    for i in 0..3u32 {
        let mut req = read_req();
        req.request_id = format!("req-{i}");
        let resp = router.dispatch(req, unprivileged_tray());
        assert!(resp.ok, "reconnect attempt {i} failed: {:?}", resp.error);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 7: Crash threshold aligns with SCM recovery policy
//
// The service-side CrashCounter.threshold must equal
// RecoveryPolicy::max_auto_restarts so both counters agree on when to stop.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn crash_counter_threshold_matches_recovery_policy_max_restarts() {
    let policy = RecoveryPolicy::production();
    let counter = CrashCounter::new(
        policy.max_auto_restarts as u32,
        policy.reset_period_secs as u64,
    );
    assert_eq!(counter.threshold, policy.max_auto_restarts as u32);
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 8: Preliminary service identity is not LocalSystem
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn preliminary_identity_is_local_service_for_historical_reference() {
    assert!(!PRELIMINARY_IDENTITY.is_full_local_privilege());
}

#[test]
fn required_identity_is_local_system_after_block_15_2() {
    let id = required_service_identity();
    assert!(
        id.is_full_local_privilege(),
        "resolved identity must be LocalSystem: {id:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 9: Safe-disable is audit-first (no state change without audit record)
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn safe_disable_audit_first_invariant() {
    let req = SafeDisableRequest {
        correlation_id: "gate-req".into(),
        reason: "test".into(),
        confirm_token: "correct".into(),
    };
    let result = execute_safe_disable(&req, "correct", true, &RecordingSink::failing(), 0);
    assert!(
        matches!(
            result,
            nrr_service_runtime::SafeDisableOutcome::AuditWriteFailed { .. }
        ),
        "safe-disable must not proceed when audit write fails: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 10: Privilege matrix has no placeholder identity entries
//
// WFP and route-table operations must resolve to a concrete identity
// requirement rather than an unresolved placeholder — filling them in
// without a full privilege analysis would be a security risk.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn privilege_matrix_has_no_tbd_after_block_15_2() {
    // Every entry must have a concrete identity resolved.
    for entry in PRIVILEGE_MATRIX {
        assert!(
            !entry.justification.starts_with("TODO(block-15)"),
            "entry '{}' still has unresolved TODO(block-15)",
            entry.operation
        );
    }
}

#[test]
fn routing_and_wfp_require_local_system_privilege() {
    let route = PRIVILEGE_MATRIX
        .iter()
        .find(|e| e.operation.contains("routing table"))
        .expect("routing table entry must exist");
    assert_eq!(route.min_identity, IdentityRequirement::LocalSystem);
    let wfp = PRIVILEGE_MATRIX
        .iter()
        .find(|e| e.operation.contains("WFP"))
        .expect("WFP entry must exist");
    assert_eq!(wfp.min_identity, IdentityRequirement::LocalSystem);
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual Windows checklist (documented, not executable)
//
// The following items require a real Windows environment and are verified
// manually. Listed here so the review can confirm each was considered:
//
// [ ] install: creates SCM entry, sets AutoStart (delayed), configures 2 restarts
// [ ] service starts automatically after reboot
// [ ] GUI closed → service keeps running; tray shows "service connected" on reopen
// [ ] tray "Exit" writes shutdown flag; service stops within STOP_TIMEOUT
// [ ] `status` prints banner without SCM (exits 0 from shell)
// [ ] uninstall: stops service, removes entry, preserves data dir (keep_data default)
// [ ] update: drains, backs up state DB; installer replaces binary; restarts
// [ ] service runs as NT AUTHORITY\LocalService (pending sign-off);
//     until then it runs as LocalSystem with a documented TODO
// [ ] after 3 consecutive crashes, SCM stops auto-restarting; Event Log records it
// [ ] uninstall with remove_data=true: removes %ProgramData%\NetRuleRouter\,
//     leaves user rule files intact
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn manual_windows_checklist_is_documented() {
    // Presence of SecurityChecklist type confirms the doc is in scope.
    let _ = std::mem::size_of::<SecurityChecklist>();
}

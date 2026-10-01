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
//! 5. Apply layer without UI deps — dependency_boundary.rs

use nrr_service_runtime::{
    // crash_recovery
    decide_recovery,
    execute_safe_disable,
    ActiveRevisionState,
    ApplyAttemptMarker,
    ApplyMarkerStore,
    ApplyPhase,
    DegradedMode,
    DegradedModeStatus,
    // ipc
    HandlerOutcome,
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
    SafeDisableRequest,
    // state
    ServicePolicyState,
    StartupRecoveryCoordinator,
    IPC_PROTOCOL_VERSION,
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
        caller_pid: None,
    }
}
fn unprivileged_tray() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::TrayLightweight,
        caller_is_elevated: false,
        caller_principal: None,
        caller_pid: None,
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
    let decision = decide_recovery(&state, true);
    assert!(
        !matches!(decision, RecoveryDecision::ProceedNormal),
        "ProceedNormal must never be returned when an incomplete marker exists"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 2: Integrity check precedes any policy activation
//
// Only ActiveLoaded produces a policy-ready state.
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
        PolicyLoadResult::ActiveLoaded(ready).to_policy_state(),
        ServicePolicyState::ActiveReady
    );

    for outcome in &[
        PolicyLoadResult::IntegrityFailureReported("tampered".into()),
        PolicyLoadResult::NoActiveRevision,
        PolicyLoadResult::RecoveryRequired("broken".into()),
        PolicyLoadResult::StorageError("io".into()),
    ] {
        let state = outcome.to_policy_state();
        assert!(
            !matches!(state, ServicePolicyState::ActiveReady),
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

/// A GUI-only operation must be refused to the tray by the per-operation
/// catalogue check, since the read/mutation class check alone would allow it.
#[test]
fn a_gui_only_operation_is_refused_to_the_tray() {
    let router = make_router();
    let mut req = read_req();
    // Read-only, and GUI-only in the catalogue: the class check would let it
    // through, so only the per-operation check can refuse it.
    req.operation = IpcOperationName::ThirdPartyComponentsList;
    req.operation_class = IpcOperationClass::ReadSnapshot;
    let resp = router.dispatch(req, unprivileged_tray());
    assert!(!resp.ok, "a GUI-only operation must not answer the tray");
    assert_eq!(resp.error.expect("error").code, IpcErrorCode::Forbidden);
}

/// The push-event subscription must stay open to the tray — it is how the
/// tray reflects state — even though the per-operation refusal above exists.
#[test]
fn the_tray_may_still_subscribe_to_push_events() {
    let router = make_router();
    let mut req = read_req();
    req.operation = IpcOperationName::StatusUpdatesSubscribe;
    req.operation_class = IpcOperationClass::ReadSnapshot;
    let resp = router.dispatch(req, unprivileged_tray());
    let refused_by_profile = resp
        .error
        .as_ref()
        .is_some_and(|e| e.code == IpcErrorCode::Forbidden);
    assert!(
        !refused_by_profile,
        "the tray must keep its push subscription: {:?}",
        resp.error
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Gate 6: A finished call leaves nothing behind for the next one
//
// The router's only cross-call state is the mutation queue. A client that
// reconnects after a mutation — even one its handler refused — must not find
// the slot still taken, or every later mutation is BusyConflict.
// ─────────────────────────────────────────────────────────────────────────────
/// Refuses the request whose id is `req-refused`, echoes every other one.
struct RefusingHandler;
impl IpcHandler for RefusingHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        if request.request_id == "req-refused" {
            return Err(nrr_service_runtime::IpcError {
                code: IpcErrorCode::Internal,
                message: "refused by handler".into(),
                diagnostics_id: None,
            });
        }
        EchoHandler.handle(request, ctx)
    }
}

#[test]
fn a_finished_mutation_releases_its_slot_for_the_next_caller() {
    let mut reg = IpcHandlerRegistry::new();
    reg.register(IpcOperationName::MutationSubmit, RefusingHandler);
    // One slot: a leaked guard shows up as BusyConflict on the very next call.
    let router = IpcRouter::new(reg, Arc::new(NoopIpcAuditEmitter::default()), 1);

    let first = router.dispatch(mutation_req(), elevated_gui());
    assert!(first.ok, "first mutation: {:?}", first.error);
    assert_eq!(
        first.payload,
        Some(serde_json::json!({ "echo": IpcOperationName::MutationSubmit.slug() })),
        "the handler itself must have answered"
    );

    let mut refused = mutation_req();
    refused.request_id = "req-refused".into();
    let refused = router.dispatch(refused, elevated_gui());
    assert_eq!(
        refused.error.map(|e| e.code),
        Some(IpcErrorCode::Internal),
        "the handler's own refusal must come back, not a queue conflict"
    );

    let mut after = mutation_req();
    after.request_id = "req-after".into();
    let after = router.dispatch(after, elevated_gui());
    assert!(
        after.ok,
        "slot leaked by a refused mutation: {:?}",
        after.error
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

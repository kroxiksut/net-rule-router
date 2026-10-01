#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cross-cutting integration tests.
//!
//! These exercise wiring chains that cross module boundaries:
//! - `ProductionMutationExecutor::safe_disable` → recovery audit sink →
//!   `RecoveryAuditRecord::SafeDisableExecuted`.
//! - `ProductionMutationExecutor::rollback` → `ActivationCoordinator`
//!   `PolicyError::NoLastKnownGood`.
//! - `EventBus` publish / subscribe / cursor lifecycle as observed by
//!   the named-pipe push pump's `peek_pending_for` / `advance_cursor`
//!   protocol.
//!
//! Per-module unit tests cover the inner logic of each component; this
//! file is what ensures the components compose correctly.

use std::sync::{Arc, Mutex};

use nrr_service_runtime::activation_coordinator::{
    ActivationCoordinator, ApplyFailurePolicy, CounterIds, FixedClock, IdGenerator,
    InMemoryMarkerStore, NoopActivationAudit, RulesApplyDispatcher, ScriptedDispatcher,
};
use nrr_service_runtime::active_sid_registry::ActiveSidRegistry;
use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
use nrr_service_runtime::ipc_handlers::payloads::StatusUpdateEvent;
use nrr_service_runtime::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use nrr_service_runtime::{
    ApplyMarkerStore, Clock, NoopPauseDispatcher, NoopRecoveryAuditSink, NoopRoutingPauseAudit,
    PauseDispatcher, ProductionMutationExecutor, RecoveryAuditRecord, RecoveryAuditSink,
    RoutingPauseAudit, RoutingPauseCoordinator,
};
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;

// ── Fixture ──────────────────────────────────────────────────────────────────

struct CoordFixture {
    coordinator: Arc<ActivationCoordinator>,
    _dir: tempfile::TempDir,
}

fn build_coordinator() -> CoordFixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    let conn = Arc::new(Mutex::new(conn));

    let registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher: Arc<dyn RulesApplyDispatcher> = Arc::new(ScriptedDispatcher::new());
    let marker: Arc<dyn ApplyMarkerStore> = Arc::new(InMemoryMarkerStore::new());
    let clock: Arc<dyn Clock> = FixedClock::new(1_700_000_000);
    let ids: Arc<dyn IdGenerator> = Arc::new(CounterIds::new());

    let coordinator = Arc::new(ActivationCoordinator::new(
        conn,
        registry,
        dispatcher,
        marker,
        Arc::new(NoopActivationAudit),
        clock,
        ids,
        ApplyFailurePolicy::AllOrNothing,
    ));
    CoordFixture {
        coordinator,
        _dir: dir,
    }
}

/// A minimal wired `RoutingPauseCoordinator` so the
/// safe-disable path reaches the real completion/audit code instead of
/// short-circuiting on `apply-layer-unavailable`. The apply layer is
/// considered "available" iff a pause coordinator is wired (production
/// always wires one). An empty
/// `ActiveSidRegistry` makes `pause_all_active` a no-op — all these tests need,
/// since they assert the audit + outcome, not the per-SID teardown fan-out.
/// The returned tempdir backs the coordinator's state DB and must be kept alive
/// by the caller for the duration of the test.
fn build_pause_coordinator() -> (Arc<RoutingPauseCoordinator>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pause_state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(Mutex::new(runner.into_connection()));

    let registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher: Arc<dyn PauseDispatcher> = Arc::new(NoopPauseDispatcher);
    let audit: Arc<dyn RoutingPauseAudit> = Arc::new(NoopRoutingPauseAudit);
    let clock: Arc<dyn Clock> = FixedClock::new(1_700_000_000);

    let coord = Arc::new(RoutingPauseCoordinator::new(
        conn, registry, dispatcher, audit, clock,
    ));
    (coord, dir)
}

// ── Recovery audit sink fakes ────────────────────────────────────────────────

struct RecordingRecoveryAuditSink {
    events: Mutex<Vec<RecoveryAuditRecord>>,
}

impl RecordingRecoveryAuditSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    fn snapshot(&self) -> Vec<RecoveryAuditRecord> {
        self.events.lock().expect("audit poisoned").clone()
    }
}

impl RecoveryAuditSink for RecordingRecoveryAuditSink {
    fn emit(&self, record: RecoveryAuditRecord) -> Result<(), String> {
        self.events.lock().expect("audit poisoned").push(record);
        Ok(())
    }
}

struct FailingRecoveryAuditSink;

impl RecoveryAuditSink for FailingRecoveryAuditSink {
    fn emit(&self, _record: RecoveryAuditRecord) -> Result<(), String> {
        Err("simulated audit ndjson append failure".to_string())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// `safe_disable` end-to-end with a recording audit sink: `MutationOutcome::Completed`
/// is returned and a `RecoveryAuditRecord::SafeDisableExecuted` lands on the
/// sink. The reason flows through the audit record verbatim.
#[test]
fn safe_disable_with_recording_sink_completes_and_audits() {
    let fx = build_coordinator();
    let (pause, _pause_dir) = build_pause_coordinator();
    let sink = Arc::new(RecordingRecoveryAuditSink::new());
    let exec = ProductionMutationExecutor::new(Arc::clone(&fx.coordinator))
        .with_recovery_audit_sink(Arc::clone(&sink) as Arc<dyn RecoveryAuditSink>)
        .with_pause_coordinator(pause);

    let outcome = exec.safe_disable("operator triggered safe-disable");
    match outcome {
        MutationOutcome::Completed(payload) => {
            assert_eq!(payload["outcome"], "safe-disabled");
            assert_eq!(payload["reason"], "operator triggered safe-disable");
            assert!(payload["disabled-at-secs"].is_number());
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    let events = sink.snapshot();
    assert_eq!(events.len(), 1, "exactly one audit event expected");
    match &events[0] {
        RecoveryAuditRecord::SafeDisableExecuted { reason, .. } => {
            assert_eq!(reason, "operator triggered safe-disable");
        }
        other => panic!("expected SafeDisableExecuted, got {other:?}"),
    }
}

/// Without a recovery audit sink wired, `safe_disable` refuses with
/// `audit-unavailable` rather than silently no-op'ing or running without
/// an audit trail.
#[test]
fn safe_disable_without_sink_returns_audit_unavailable() {
    let fx = build_coordinator();
    let exec = ProductionMutationExecutor::new(Arc::clone(&fx.coordinator));
    match exec.safe_disable("test") {
        MutationOutcome::Failed(err) => {
            assert_eq!(err.code, "audit-unavailable");
        }
        other => panic!("expected Failed(audit-unavailable), got {other:?}"),
    }
}

/// If the audit sink fails to persist the event, the safe-disable is
/// aborted with `audit-write-failed` — matches the
/// `crash_recovery::execute_safe_disable` invariant that audit-before-act
/// is mandatory.
#[test]
fn safe_disable_when_audit_sink_fails_returns_audit_write_failed() {
    let fx = build_coordinator();
    let (pause, _pause_dir) = build_pause_coordinator();
    let exec = ProductionMutationExecutor::new(Arc::clone(&fx.coordinator))
        .with_recovery_audit_sink(Arc::new(FailingRecoveryAuditSink) as Arc<dyn RecoveryAuditSink>)
        .with_pause_coordinator(pause);
    match exec.safe_disable("test") {
        MutationOutcome::Failed(err) => {
            assert_eq!(err.code, "audit-write-failed");
            assert!(err.message.contains("simulated"));
        }
        other => panic!("expected Failed(audit-write-failed), got {other:?}"),
    }
}

/// Rollback to the LKG slot when no LKG exists ⇒ structured failure
/// (`no-last-known-good`). Validates the executor surface layer maps
/// `PolicyError::NoLastKnownGood` correctly without panicking.
#[test]
fn rollback_to_lkg_without_lkg_returns_no_last_known_good() {
    let fx = build_coordinator();
    let exec = ProductionMutationExecutor::new(Arc::clone(&fx.coordinator));
    let outcome = MutationExecutor::rollback(&exec, nrr_storage::BASELINE_PRINCIPAL, None);
    match outcome {
        MutationOutcome::Failed(err) => {
            assert_eq!(err.code, "no-last-known-good");
        }
        other => panic!("expected Failed(no-last-known-good), got {other:?}"),
    }
}

/// `EventBus` lifecycle as the push pump observes it: subscribe with
/// no cursor → publish multiple events → `peek_pending_for` returns
/// them in order → `advance_cursor` to the last id → re-peek empty.
/// This is the contract the named-pipe transport (`flush_push_frames`
/// in `nrr-windows-service`) relies on.
#[test]
fn event_bus_publish_subscribe_advance_round_trip() {
    let bus = EventBus::new();
    let s = bus.subscribe("client-1".to_string(), None);

    let id1 = bus.publish(StatusUpdateEvent::AdaptersChanged {
        data_source: "wmi".to_string(),
    });
    let id2 = bus.publish(StatusUpdateEvent::HealthChanged {
        service_state: "running".to_string(),
        worst_severity: "ok".to_string(),
    });
    let id3 = bus.publish(StatusUpdateEvent::Overflow { dropped_count: 2 });

    let pending = bus.peek_pending_for(&s.subscription_id, 16);
    assert_eq!(pending.len(), 3);
    assert_eq!(pending[0].event_id, id1);
    assert_eq!(pending[1].event_id, id2);
    assert_eq!(pending[2].event_id, id3);

    bus.advance_cursor(&s.subscription_id, id3);
    assert!(
        bus.peek_pending_for(&s.subscription_id, 16).is_empty(),
        "after advance to {id3}, no pending events should remain"
    );

    // Drop counter is 0 after a clean delivery (no record_drop calls).
    assert_eq!(bus.take_dropped_count(&s.subscription_id), 0);

    // NoopRecoveryAuditSink import sanity — the type is part of the
    // public surface and constructible without args. (Compile-time
    // check; nothing observable to assert.)
    let _: Arc<dyn RecoveryAuditSink> = Arc::new(NoopRecoveryAuditSink);
}

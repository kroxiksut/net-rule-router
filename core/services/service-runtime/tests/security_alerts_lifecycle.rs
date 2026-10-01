#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for alert acknowledge / resolve
//! flows through `ProductionMutationExecutor` + `SecurityAlertsRepository`.
//!
//! Per-module unit tests live next to each component:
//! - `nrr_service_runtime::production_security_alerts::tests` — SQLite
//!   repo lifecycle + persistence across reopen.
//! - `nrr_service_runtime::ipc_handlers::security_alerts::tests` — list
//!   handler with state filter.
//!
//! This file ties them together: the executor calls into the repo, the
//! state survives, and illegal transitions are rejected. Token validation
//! itself is exercised by the existing `MutationSubmitHandler` tests
//! (kind-agnostic), so the spec's "ack mutation requires confirmation
//! token" requirement is satisfied through the handler's two-phase flow,
//! not duplicated here.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{
    InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState, SecurityAlertsRepository,
};
use nrr_service_runtime::activation_coordinator::{
    ActivationCoordinator, ApplyFailurePolicy, CounterIds, FixedClock, IdGenerator,
    InMemoryMarkerStore, NoopActivationAudit, RulesApplyDispatcher, ScriptedDispatcher,
};
use nrr_service_runtime::active_sid_registry::ActiveSidRegistry;
use nrr_service_runtime::ipc_handlers::payloads::MutationKind;
use nrr_service_runtime::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use nrr_service_runtime::{ApplyMarkerStore, Clock, ProductionMutationExecutor, StoredMutation};
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;

// ── Fixture ──────────────────────────────────────────────────────────────────

struct Fixture {
    coordinator: Arc<ActivationCoordinator>,
    repo: Arc<InMemorySecurityAlertsRepository>,
    _dir: tempfile::TempDir,
}

fn build_fixture() -> Fixture {
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
    Fixture {
        coordinator,
        repo: Arc::new(InMemorySecurityAlertsRepository::new()),
        _dir: dir,
    }
}

fn sample_alert(id: &str, state: SecurityAlertState) -> SecurityAlert {
    SecurityAlert {
        alert_id: id.into(),
        kind: "tamper_alert_raised".into(),
        state,
        raised_event_seq: 1,
        raised_file: "nrr_audit_20260509-1.ndjson".into(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: 100,
        updated_at: 100,
        reason_code: "integrity.audit_chain_mismatch".into(),
    }
}

fn build_executor(fx: &Fixture) -> ProductionMutationExecutor {
    ProductionMutationExecutor::new(Arc::clone(&fx.coordinator))
        .with_alerts_repo(Arc::clone(&fx.repo) as Arc<dyn SecurityAlertsRepository>)
}

fn submit_kind(kind: MutationKind, alert_id: &str) -> StoredMutation {
    StoredMutation {
        kind,
        payload: serde_json::json!({"alert-id": alert_id, "reason": "operator request"}),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: true,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Full lifecycle: raise (insert) → ack via executor → resolve via
/// executor. Each transition reflects in the repo state.
#[test]
fn alert_lifecycle_raise_ack_resolve() {
    let fx = build_fixture();
    fx.repo
        .insert(&sample_alert("alt-1", SecurityAlertState::Active))
        .expect("insert");
    let exec = build_executor(&fx);

    // Acknowledge.
    let outcome = exec.execute(
        submit_kind(MutationKind::SecurityAlertAck, "alt-1"),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    match outcome {
        MutationOutcome::Completed(payload) => {
            assert_eq!(payload["outcome"], "alert-acknowledged");
            assert_eq!(payload["alert-id"], "alt-1");
            assert_eq!(payload["previous-state"], "active");
            assert_eq!(payload["new-state"], "acknowledged");
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert_eq!(
        fx.repo
            .find_by_id("alt-1")
            .expect("find")
            .expect("present")
            .state,
        SecurityAlertState::Acknowledged
    );

    // Resolve.
    let outcome = exec.execute(
        submit_kind(MutationKind::SecurityAlertResolve, "alt-1"),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    match outcome {
        MutationOutcome::Completed(payload) => {
            assert_eq!(payload["outcome"], "alert-resolved");
            assert_eq!(payload["previous-state"], "acknowledged");
            assert_eq!(payload["new-state"], "resolved");
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert_eq!(
        fx.repo
            .find_by_id("alt-1")
            .expect("find")
            .expect("present")
            .state,
        SecurityAlertState::Resolved
    );
}

/// Resolve on an already-resolved alert is illegal (`Resolved` is
/// terminal). Executor refuses with `illegal-state-transition`.
#[test]
fn resolve_already_resolved_alert_returns_illegal_transition() {
    let fx = build_fixture();
    fx.repo
        .insert(&sample_alert("alt-2", SecurityAlertState::Resolved))
        .expect("insert");
    let exec = build_executor(&fx);
    match exec.execute(
        submit_kind(MutationKind::SecurityAlertResolve, "alt-2"),
        nrr_storage::BASELINE_PRINCIPAL,
    ) {
        MutationOutcome::Failed(err) => {
            assert_eq!(err.code, "illegal-state-transition");
            assert!(err.message.contains("alt-2"));
        }
        other => panic!("expected Failed(illegal-state-transition), got {other:?}"),
    }
}

/// Ack on a Superseded alert is illegal (Superseded is terminal too).
#[test]
fn ack_superseded_alert_returns_illegal_transition() {
    let fx = build_fixture();
    fx.repo
        .insert(&sample_alert("alt-3", SecurityAlertState::Superseded))
        .expect("insert");
    let exec = build_executor(&fx);
    match exec.execute(
        submit_kind(MutationKind::SecurityAlertAck, "alt-3"),
        nrr_storage::BASELINE_PRINCIPAL,
    ) {
        MutationOutcome::Failed(err) => assert_eq!(err.code, "illegal-state-transition"),
        other => panic!("expected illegal-state-transition, got {other:?}"),
    }
}

/// Targeting an unknown alert id returns `alert-not-found`.
#[test]
fn unknown_alert_id_returns_alert_not_found() {
    let fx = build_fixture();
    let exec = build_executor(&fx);
    match exec.execute(
        submit_kind(MutationKind::SecurityAlertAck, "missing"),
        nrr_storage::BASELINE_PRINCIPAL,
    ) {
        MutationOutcome::Failed(err) => assert_eq!(err.code, "alert-not-found"),
        other => panic!("expected alert-not-found, got {other:?}"),
    }
}

/// Without a wired alerts repo the executor returns
/// `alerts-store-unavailable` rather than panicking.
#[test]
fn missing_repo_returns_alerts_store_unavailable() {
    let fx = build_fixture();
    let exec = ProductionMutationExecutor::new(Arc::clone(&fx.coordinator));
    match exec.execute(
        submit_kind(MutationKind::SecurityAlertAck, "alt-x"),
        nrr_storage::BASELINE_PRINCIPAL,
    ) {
        MutationOutcome::Failed(err) => assert_eq!(err.code, "alerts-store-unavailable"),
        other => panic!("expected alerts-store-unavailable, got {other:?}"),
    }
}

/// Malformed payload (missing `alert-id`) is rejected with
/// `malformed-payload` before any repo lookup.
#[test]
fn malformed_payload_rejected() {
    let fx = build_fixture();
    let exec = build_executor(&fx);
    let bad = StoredMutation {
        kind: MutationKind::SecurityAlertAck,
        payload: serde_json::json!({}),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: true,
    };
    match exec.execute(bad, nrr_storage::BASELINE_PRINCIPAL) {
        MutationOutcome::Failed(err) => assert_eq!(err.code, "malformed-payload"),
        other => panic!("expected malformed-payload, got {other:?}"),
    }
}

/// Preview returns a benign review summary mentioning the alert id —
/// the GUI uses it to render the "Confirm acknowledge?" pre-mutation
/// dialog.
#[test]
fn preview_ack_returns_low_risk_review_summary_naming_alert() {
    let fx = build_fixture();
    fx.repo
        .insert(&sample_alert("alt-4", SecurityAlertState::Active))
        .expect("insert");
    let exec = build_executor(&fx);
    let summary = exec.preview(
        MutationKind::SecurityAlertAck,
        &serde_json::json!({"alert-id": "alt-4"}),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert!(summary.diff_summary.contains("alt-4"));
    assert!(summary.diff_summary.contains("acknowledge"));
    assert_eq!(summary.changed_fields, vec!["alert-id:alt-4".to_string()]);
}

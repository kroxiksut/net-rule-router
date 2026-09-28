//! Boot after a signing-key reset: the re-sign marker in the key store, not
//! an alert row, decides whether the integrity sweep may roll anything back.

use super::*;
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::payloads::MutationKind;
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use crate::production_mutation_executor::ProductionMutationExecutor;
use crate::tamper_bootstrap::{run_tamper_bootstrap, TamperBootstrapOutcome};
use nrr_diagnostics::audit::alert::{
    InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState, SecurityAlertsRepository,
};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_platform_api::key_store::{InMemKeyStore, KeyStore};

const BOOT_MS: i64 = 1_745_000_000_000;
const USER: &str = "S-1-5-21-0-0-0-1001";
const PRINCIPALS: [&str; 2] = [nrr_storage::BASELINE_PRINCIPAL, USER];

fn empty_alerts() -> Arc<dyn SecurityAlertsRepository> {
    Arc::new(InMemorySecurityAlertsRepository::new())
}

fn boot(
    fx: &Fixture,
    key_store: &InMemKeyStore,
    alerts: &Arc<dyn SecurityAlertsRepository>,
    now_ms: i64,
) -> TamperBootstrapOutcome {
    run_tamper_bootstrap(&fx.conn, key_store, alerts, now_ms).expect("tamper bootstrap")
}

/// What the next service start builds from the bootstrap's key.
fn rekeyed(
    fx: &Fixture,
    outcome: &TamperBootstrapOutcome,
    key_store: &Arc<InMemKeyStore>,
) -> Arc<ActivationCoordinator> {
    Arc::new(
        ActivationCoordinator::new(
            fx.conn.clone(),
            fx.registry.clone(),
            fx.dispatcher.clone() as Arc<dyn RulesApplyDispatcher>,
            fx.marker.clone() as Arc<dyn ApplyMarkerStore>,
            fx.audit.clone() as Arc<dyn ActivationAuditEmitter>,
            fx.clock.clone() as Arc<dyn Clock>,
            Arc::new(CounterIds::new()),
            ApplyFailurePolicy::AllOrNothing,
        )
        .with_signing_key(outcome.signing_key.clone())
        .with_key_store(Arc::clone(key_store) as Arc<dyn KeyStore>),
    )
}

fn activate_for(fx: &Fixture, principal: &str, hash: &str) -> RevisionId {
    let id = submit_for(fx, principal, hash);
    let token = issue_token(fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");
    id
}

fn active_ids(coord: &ActivationCoordinator) -> Vec<Option<String>> {
    PRINCIPALS
        .iter()
        .map(|p| {
            coord
                .current_active_for(p)
                .expect("current active")
                .map(|r| r.revision_id)
        })
        .collect()
}

/// Two principals, each with an active revision signed by the original key.
fn seeded() -> (Fixture, Vec<Option<String>>) {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x31u8; 32]);
    let baseline = activate_for(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-baseline");
    let user = activate_for(&fx, USER, "h-user");
    let expected = vec![
        Some(baseline.as_str().to_string()),
        Some(user.as_str().to_string()),
    ];
    (fx, expected)
}

fn key_reset_alerts(
    alerts: &Arc<dyn SecurityAlertsRepository>,
    state: SecurityAlertState,
) -> Vec<SecurityAlert> {
    alerts
        .list_by_state(state)
        .expect("list alerts")
        .into_iter()
        .filter(|a| a.kind == AuditEventKind::KeyResetWithExistingData.as_str())
        .collect()
}

fn key_reset_alert(alert_id: &str, state: SecurityAlertState) -> SecurityAlert {
    SecurityAlert {
        alert_id: alert_id.to_string(),
        kind: AuditEventKind::KeyResetWithExistingData
            .as_str()
            .to_string(),
        state,
        raised_event_seq: 0,
        raised_file: "scan".into(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: 1,
        updated_at: 1,
        reason_code: "integrity.key_reset_with_existing_data".into(),
    }
}

/// Acknowledges through the real IPC executor path.
fn acknowledge(
    coord: &Arc<ActivationCoordinator>,
    alerts: &Arc<dyn SecurityAlertsRepository>,
    alert_id: &str,
) {
    let exec =
        ProductionMutationExecutor::new(Arc::clone(coord)).with_alerts_repo(Arc::clone(alerts));
    let outcome = exec.execute(
        StoredMutation {
            kind: MutationKind::SecurityAlertAck,
            payload: serde_json::json!({ "alert-id": alert_id }),
            correlation_id: None,
            issuer_sid: String::new(),
            caller_is_elevated: false,
        },
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "{outcome:?}"
    );
}

fn marker_present(key_store: &InMemKeyStore) -> bool {
    key_store
        .load_resign_marker()
        .expect("load marker")
        .is_some()
}

#[test]
fn a_key_reset_sets_the_marker_raises_an_alert_and_keeps_every_active_revision() {
    let (fx, expected) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let alerts = empty_alerts();

    let reset = boot(&fx, &key_store, &alerts, BOOT_MS);
    assert!(reset.key_was_reset && reset.key_reset_unacknowledged);
    assert!(
        marker_present(&key_store),
        "the reset must leave the marker"
    );
    let raised = key_reset_alerts(&alerts, SecurityAlertState::Active);
    assert_eq!(raised.len(), 1);
    assert!(
        raised[0].alert_id.starts_with("alt-keyreset-"),
        "{}",
        raised[0].alert_id
    );

    let coord = rekeyed(&fx, &reset, &key_store);
    let swept = coord
        .enforce_active_integrity_at_boot(&reset, "corr-boot")
        .expect("boot sweep");
    assert!(swept.is_empty(), "nothing may be rolled back: {swept:?}");
    assert_eq!(active_ids(&coord), expected);
}

#[test]
fn the_marker_holds_the_sweep_off_whatever_the_alerts_table_says() {
    let (fx, expected) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let reset = boot(&fx, &key_store, &empty_alerts(), BOOT_MS);
    let coord = rekeyed(&fx, &reset, &key_store);

    // Next start over a wiped alerts table: the marker alone decides.
    let wiped = empty_alerts();
    let restart = boot(&fx, &key_store, &wiped, BOOT_MS + 1_000);
    assert!(!restart.key_was_reset && restart.key_reset_unacknowledged);
    let swept = coord
        .enforce_active_integrity_at_boot(&restart, "corr-boot-2")
        .expect("boot sweep");
    assert!(swept.is_empty(), "nothing may be rolled back: {swept:?}");
    assert_eq!(active_ids(&coord), expected);
    assert_eq!(
        key_reset_alerts(&wiped, SecurityAlertState::Active).len(),
        1,
        "the reset must stay acknowledgeable after its alert row vanished",
    );

    // An edited table that shows the alert acknowledged changes nothing either.
    let edited = empty_alerts();
    edited
        .insert(&key_reset_alert(
            "alt-keyreset-1",
            SecurityAlertState::Acknowledged,
        ))
        .expect("seed");
    let restart = boot(&fx, &key_store, &edited, BOOT_MS + 2_000);
    assert!(restart.key_reset_unacknowledged);
    let swept = coord
        .enforce_active_integrity_at_boot(&restart, "corr-boot-3")
        .expect("boot sweep");
    assert!(swept.is_empty(), "nothing may be rolled back: {swept:?}");
    assert_eq!(active_ids(&coord), expected);
}

#[test]
fn a_forged_active_key_reset_alert_does_not_spare_a_tampered_revision() {
    let key = vec![0x32u8; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    let trusted = activate_for(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-1");
    let tampered = activate_for(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-2");
    tamper_rules_json(&fx, tampered.as_str());

    let alerts = empty_alerts();
    alerts
        .insert(&key_reset_alert("alt-keyreset", SecurityAlertState::Active))
        .expect("forge");
    let key_store = Arc::new(InMemKeyStore::with_key(key));
    let boot_out = boot(&fx, &key_store, &alerts, BOOT_MS);
    assert!(!boot_out.key_reset_unacknowledged, "no marker, no hold");

    // The fixture's own coordinator: the rollback mints a revision id, and a
    // second id generator would collide with the fixture's.
    let swept = fx
        .coordinator
        .enforce_active_integrity_at_boot(&boot_out, "corr-boot")
        .expect("boot sweep");
    match swept
        .iter()
        .find(|(p, _)| p == nrr_storage::BASELINE_PRINCIPAL)
        .map(|(_, o)| o)
    {
        Some(ActiveIntegrityOutcome::RolledBack {
            rejected_revision_id,
            trusted_source_revision_id,
            ..
        }) => {
            assert_eq!(rejected_revision_id, tampered.as_str());
            assert_eq!(trusted_source_revision_id, trusted.as_str());
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }
}

#[test]
fn acknowledging_the_reset_re_signs_clears_the_marker_and_the_next_sweep_runs_clean() {
    let (fx, expected) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let alerts = empty_alerts();
    let reset = boot(&fx, &key_store, &alerts, BOOT_MS);
    let coord = rekeyed(&fx, &reset, &key_store);
    let alert_id = key_reset_alerts(&alerts, SecurityAlertState::Active)[0]
        .alert_id
        .clone();

    acknowledge(&coord, &alerts, &alert_id);
    assert!(
        !marker_present(&key_store),
        "a successful re-sign clears the marker"
    );

    let clean = boot(&fx, &key_store, &alerts, BOOT_MS + 1_000);
    assert!(!clean.key_reset_unacknowledged);
    assert!(clean.tampered_revision_ids.is_empty());
    let swept = coord
        .enforce_active_integrity_at_boot(&clean, "corr-boot-2")
        .expect("boot sweep");
    assert!(
        swept
            .iter()
            .all(|(_, o)| matches!(o, ActiveIntegrityOutcome::Trusted { .. })),
        "{swept:?}"
    );
    assert_eq!(active_ids(&coord), expected);
}

#[test]
fn a_second_key_loss_after_an_acknowledged_first_raises_a_new_alert_and_keeps_the_rules() {
    let (fx, expected) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let alerts = empty_alerts();
    let first = boot(&fx, &key_store, &alerts, BOOT_MS);
    let first_id = key_reset_alerts(&alerts, SecurityAlertState::Active)[0]
        .alert_id
        .clone();
    acknowledge(&rekeyed(&fx, &first, &key_store), &alerts, &first_id);

    key_store.delete().expect("lose the key again");
    let second = boot(&fx, &key_store, &alerts, BOOT_MS + 60_000);
    assert!(second.key_was_reset && second.key_reset_unacknowledged);
    assert!(marker_present(&key_store));
    let active = key_reset_alerts(&alerts, SecurityAlertState::Active);
    assert_eq!(active.len(), 1, "{active:?}");
    assert_ne!(
        active[0].alert_id, first_id,
        "a new incident gets a new alert"
    );

    let coord = rekeyed(&fx, &second, &key_store);
    let restart = boot(&fx, &key_store, &alerts, BOOT_MS + 120_000);
    assert!(restart.key_reset_unacknowledged);
    let swept = coord
        .enforce_active_integrity_at_boot(&restart, "corr-boot-3")
        .expect("boot sweep");
    assert!(swept.is_empty(), "nothing may be rolled back: {swept:?}");
    assert_eq!(active_ids(&coord), expected);
}

#[test]
fn a_legacy_fixed_id_key_reset_alert_is_still_acknowledged_by_kind() {
    let (fx, _) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let reset = boot(&fx, &key_store, &empty_alerts(), BOOT_MS);
    let alerts = empty_alerts();
    alerts
        .insert(&key_reset_alert("alt-keyreset", SecurityAlertState::Active))
        .expect("legacy row");

    acknowledge(&rekeyed(&fx, &reset, &key_store), &alerts, "alt-keyreset");
    assert!(!marker_present(&key_store));
}

#[test]
fn acknowledging_without_a_signing_key_keeps_the_marker() {
    let (fx, _) = seeded();
    let key_store = Arc::new(InMemKeyStore::new());
    let alerts = empty_alerts();
    boot(&fx, &key_store, &alerts, BOOT_MS);
    let alert_id = key_reset_alerts(&alerts, SecurityAlertState::Active)[0]
        .alert_id
        .clone();
    // Bootstrap degraded to unsigned: nothing gets re-signed.
    let unsigned = Arc::new(
        ActivationCoordinator::new(
            fx.conn.clone(),
            fx.registry.clone(),
            fx.dispatcher.clone() as Arc<dyn RulesApplyDispatcher>,
            fx.marker.clone() as Arc<dyn ApplyMarkerStore>,
            fx.audit.clone() as Arc<dyn ActivationAuditEmitter>,
            fx.clock.clone() as Arc<dyn Clock>,
            Arc::new(CounterIds::new()),
            ApplyFailurePolicy::AllOrNothing,
        )
        .with_key_store(Arc::clone(&key_store) as Arc<dyn KeyStore>),
    );

    acknowledge(&unsigned, &alerts, &alert_id);
    assert!(marker_present(&key_store), "rows still predate the key");
}

#[test]
fn a_tampered_revision_under_an_intact_key_is_still_rolled_back() {
    let key = vec![0x33u8; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    let trusted = activate_for(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-1");
    let tampered = activate_for(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-2");
    tamper_rules_json(&fx, tampered.as_str());

    let key_store = Arc::new(InMemKeyStore::with_key(key));
    let boot_out = boot(&fx, &key_store, &empty_alerts(), BOOT_MS);
    assert!(!boot_out.key_reset_unacknowledged);
    assert!(boot_out
        .tampered_revision_ids
        .contains(&tampered.as_str().to_string()));

    let swept = fx
        .coordinator
        .enforce_active_integrity_at_boot(&boot_out, "corr-boot")
        .expect("boot sweep");
    match swept
        .iter()
        .find(|(p, _)| p == nrr_storage::BASELINE_PRINCIPAL)
        .map(|(_, o)| o)
    {
        Some(ActiveIntegrityOutcome::RolledBack {
            rejected_revision_id,
            trusted_source_revision_id,
            ..
        }) => {
            assert_eq!(rejected_revision_id, tampered.as_str());
            assert_eq!(trusted_source_revision_id, trusted.as_str());
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }
}

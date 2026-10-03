use super::*;
use crate::activation_coordinator::{
    ActivationAuditEmitter, ApplyFailurePolicy, Clock, CounterIds, FixedClock, InMemoryMarkerStore,
    RecordingAudit, RulesApplyDispatcher, ScriptedDispatcher,
};
use crate::active_sid_registry::ActiveSidRegistry;
use crate::crash_recovery::ApplyMarkerStore;
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::payloads::MutationKind;
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use crate::production_mutation_executor::ProductionMutationExecutor;
use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlertState};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::CapturingSink;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::key_store::InMemKeyStore;
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::RevisionsRepository;

const BOOT_MS: i64 = 1_747_000_000_000;
const USER: &str = "S-1-5-21-0-0-0-3001";
const RULES: &str = r#"{"rules":[]}"#;

/// One state database the "service" reopens across starts, as a host does.
struct Host {
    path: std::path::PathBuf,
    conn: Arc<Mutex<Connection>>,
    alerts: Arc<dyn SecurityAlertsRepository>,
    health: Arc<HealthAggregator>,
    /// Shared across starts, as real ids never repeat.
    ids: Arc<CounterIds>,
    _dir: tempfile::TempDir,
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nrr_service_state.db");
    let runner = SqliteMigrationRunner::for_state_db(open_connection(&path).expect("open"));
    runner.run_pending_migrations().expect("migrate");
    Host {
        path,
        conn: Arc::new(Mutex::new(runner.into_connection())),
        alerts: Arc::new(InMemorySecurityAlertsRepository::new()),
        health: Arc::new(HealthAggregator::new()),
        ids: Arc::new(CounterIds::new()),
        _dir: dir,
    }
}

fn start(host: &Host, key_store: Arc<dyn KeyStore>, now_ms: i64) -> RevisionSigning {
    RevisionSigning::bootstrap(
        &host.conn,
        key_store,
        Arc::clone(&host.alerts),
        Some(Arc::new(CapturingSink::new()) as Arc<AuditTrail>),
        Arc::clone(&host.health),
        now_ms,
    )
}

fn unsigned_coordinator(host: &Host) -> ActivationCoordinator {
    ActivationCoordinator::new(
        Arc::clone(&host.conn),
        Arc::new(ActiveSidRegistry::new()),
        Arc::new(ScriptedDispatcher::new()) as Arc<dyn RulesApplyDispatcher>,
        Arc::new(InMemoryMarkerStore::new()) as Arc<dyn ApplyMarkerStore>,
        Arc::new(RecordingAudit::new()) as Arc<dyn ActivationAuditEmitter>,
        FixedClock::new(1_700_000_000) as Arc<dyn Clock>,
        Arc::clone(&host.ids) as _,
        ApplyFailurePolicy::AllOrNothing,
    )
}

/// A rule change through the one channel allowed to make it.
fn activate(coord: &Arc<ActivationCoordinator>, hash: &str) -> String {
    let outcome = ProductionMutationExecutor::new(Arc::clone(coord)).execute(
        StoredMutation {
            kind: MutationKind::RulesUpdate,
            payload: serde_json::json!({ "rules-json": RULES, "content-hash": hash }),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    );
    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "{outcome:?}"
    );
    active(coord).expect("something active")
}

fn active(coord: &ActivationCoordinator) -> Option<String> {
    coord
        .current_active_for(USER)
        .expect("active")
        .map(|r| r.revision_id)
}

/// The active revision is a trusted one again: not the edited row, and
/// carrying the content the app wrote.
fn assert_recovered_from(coord: &ActivationCoordinator, edited: &str) {
    let record = coord
        .current_active_for(USER)
        .expect("active")
        .expect("something active");
    assert_ne!(record.revision_id, edited);
    assert_eq!(record.rules_json, RULES);
}

fn edit_from_outside(host: &Host, id: &str) {
    open_connection(&host.path)
        .expect("outside connection")
        .execute(
            "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
            rusqlite::params![r#"{"tampered":true}"#, id],
        )
        .expect("outside edit");
}

fn active_alerts(host: &Host, kind: AuditEventKind) -> usize {
    host.alerts
        .list_by_state(SecurityAlertState::Active)
        .expect("alerts")
        .iter()
        .filter(|a| a.kind == kind.as_str())
        .count()
}

/// A previous run that left two activations signed under `key_store`'s key;
/// the second is active.
fn previous_run(host: &Host, key_store: &Arc<InMemKeyStore>) -> String {
    let signing = start(host, Arc::clone(key_store) as _, BOOT_MS);
    let coord = Arc::new(signing.sign(unsigned_coordinator(host)));
    activate(&coord, "h-1");
    activate(&coord, "h-2")
}

struct UnreadableKeyStore;

impl KeyStore for UnreadableKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Err(PlatformError::AccessDenied {
            operation: "key_store::load",
        })
    }
    fn save(&self, _: &[u8]) -> Result<(), PlatformError> {
        unreachable!("never reached past a failed load")
    }
    fn delete(&self) -> Result<(), PlatformError> {
        Ok(())
    }
    fn save_resign_marker(&self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn load_resign_marker(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(None)
    }
    fn delete_resign_marker(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[test]
fn a_first_start_persists_the_key_and_the_coordinator_signs_with_it() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS);

    let key = signing.signing_key().expect("a key").to_vec();
    assert_eq!(key_store.load().expect("load"), Some(key.clone()));
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let id = activate(&coord, "h-1");
    let verdict = {
        let conn = host.conn.lock().expect("conn");
        RevisionsRepository::with_signing_key(&conn, key)
            .verify_row_hmac(&id)
            .expect("verify")
    };
    assert_eq!(verdict, Some(HmacVerification::Verified));
    assert!(signing.enforce_and_watch(Some(&coord)).is_some());
}

/// No key: nothing is signed, so nothing could be checked — no watch either,
/// and the outage is on record.
#[test]
fn without_a_key_the_coordinator_stays_unsigned_and_nothing_is_watched() {
    let host = host();
    let signing = start(&host, Arc::new(UnreadableKeyStore), BOOT_MS);

    assert!(signing.signing_key().is_none());
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    assert!(
        coord.audit_restart_key().is_none(),
        "coordinator stays unsigned"
    );
    assert!(signing.enforce_and_watch(Some(&coord)).is_none());
    assert_eq!(
        active_alerts(&host, AuditEventKind::IntegrityCheckUnavailable),
        1
    );
}

#[test]
fn a_revision_edited_while_stopped_is_rolled_back_before_anything_reads_it() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    edit_from_outside(&host, &second);

    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    assert_eq!(active(&coord), Some(second.clone()));
    let watch = signing.enforce_and_watch(Some(&coord));

    assert!(watch.is_some());
    assert_recovered_from(&coord, &second);
    assert_eq!(
        active_alerts(&host, AuditEventKind::UntrustedRevisionRejected),
        1
    );
}

#[test]
fn the_watch_rolls_back_a_revision_edited_while_running() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);

    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let mut watch = signing.enforce_and_watch(Some(&coord)).expect("watch");
    watch.tick(BOOT_MS + 2_000);
    assert_eq!(active(&coord), Some(second.clone()));

    edit_from_outside(&host, &second);
    watch.tick(BOOT_MS + 3_000);

    assert_recovered_from(&coord, &second);
    assert_eq!(
        active_alerts(&host, AuditEventKind::UntrustedRevisionRejected),
        1
    );
}

/// After a lost key every row fails against the new one; until the reset is
/// acknowledged neither the boot sweep nor the watch may roll anything back.
#[test]
fn a_pending_key_reset_holds_every_rollback() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    key_store.delete().expect("lose the key");

    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    assert!(key_store.load_resign_marker().expect("marker").is_some());
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let mut watch = signing.enforce_and_watch(Some(&coord)).expect("watch");
    watch.tick(BOOT_MS + 2_000);
    edit_from_outside(&host, &second);
    watch.tick(BOOT_MS + 3_000);

    assert_eq!(active(&coord), Some(second.clone()));
    assert_eq!(
        active_alerts(&host, AuditEventKind::KeyResetWithExistingData),
        1
    );
    assert_eq!(
        active_alerts(&host, AuditEventKind::UntrustedRevisionRejected),
        0
    );
}

#[test]
fn only_another_users_revisions_make_an_acknowledgement_speak_for_them() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);
    let reads = other_principals_hold_revisions(Arc::clone(&host.conn));

    assert!(
        !reads(USER),
        "the caller's own and the baseline's rows only"
    );
    assert!(reads("S-1-5-21-0-0-0-3002"));
}

fn gated_executor(host: &Host, coord: &Arc<ActivationCoordinator>) -> ProductionMutationExecutor {
    ProductionMutationExecutor::new(Arc::clone(coord)).with_alerts_repo(Arc::clone(&host.alerts))
}

fn rules_update(exec: &ProductionMutationExecutor, hash: &str) -> MutationOutcome {
    exec.execute(
        StoredMutation {
            kind: MutationKind::RulesUpdate,
            payload: serde_json::json!({ "rules-json": RULES, "content-hash": hash }),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    )
}

/// Acknowledges as the dialog does, echoing the rows the dry-run listed.
fn acknowledge(exec: &ProductionMutationExecutor, alert_id: &str) -> serde_json::Value {
    let shown: Vec<_> = exec
        .unverified_rows(
            MutationKind::SecurityAlertAck,
            &serde_json::json!({ "alert-id": alert_id }),
        )
        .into_iter()
        .map(|r| r.row)
        .collect();
    assert_eq!(shown.len(), 1, "the dialog lists the rolled-back row");
    match exec.execute(
        StoredMutation {
            kind: MutationKind::SecurityAlertAck,
            payload: serde_json::json!({ "alert-id": alert_id, "adopt-rows": shown }),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    ) {
        MutationOutcome::Completed(v) => v,
        other => panic!("acknowledgement refused: {other:?}"),
    }
}

fn only_tamper_alert(host: &Host) -> String {
    let active: Vec<_> = host
        .alerts
        .list_by_state(SecurityAlertState::Active)
        .expect("alerts")
        .into_iter()
        .filter(|a| a.kind == AuditEventKind::DbTamperDetected.as_str())
        .collect();
    assert_eq!(active.len(), 1, "{active:?}");
    active[0].alert_id.clone()
}

/// One acknowledgement settles it: the alert is raised for the row as the
/// rollback left it, so the dialog lists it and nothing is raised again.
fn assert_one_acknowledgement_settles(host: &Host, coord: &Arc<ActivationCoordinator>) {
    let exec = gated_executor(host, coord);
    let alert_id = only_tamper_alert(host);
    assert!(
        matches!(rules_update(&exec, "h-blocked"), MutationOutcome::Failed(_)),
        "rule changes wait for the acknowledgement"
    );

    let result = acknowledge(&exec, &alert_id);

    assert_eq!(result["rows-adopted"], 1, "{result}");
    assert_eq!(active_alerts(host, AuditEventKind::DbTamperDetected), 0);
    assert!(!crate::tamper_bootstrap::mutations_blocked_by_alert(
        host.alerts.as_ref()
    ));
    assert!(
        matches!(
            rules_update(&exec, "h-after"),
            MutationOutcome::Completed(_)
        ),
        "edits are unblocked"
    );
}

#[test]
fn a_tampered_active_revision_found_at_boot_needs_one_acknowledgement() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    edit_from_outside(&host, &second);

    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    assert_eq!(
        active_alerts(&host, AuditEventKind::DbTamperDetected),
        0,
        "no alert before the rollback rewrites the row"
    );
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let _watch = signing.enforce_and_watch(Some(&coord));

    assert_recovered_from(&coord, &second);
    assert_eq!(
        active_alerts(&host, AuditEventKind::UntrustedRevisionRejected),
        1
    );
    assert!(
        only_tamper_alert(&host).contains(&second),
        "names the edited revision"
    );
    assert_one_acknowledgement_settles(&host, &coord);
}

#[test]
fn a_tampered_active_revision_caught_live_needs_one_acknowledgement() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let mut watch = signing.enforce_and_watch(Some(&coord)).expect("watch");
    watch.tick(BOOT_MS + 2_000);

    edit_from_outside(&host, &second);
    watch.tick(BOOT_MS + 3_000);

    assert_recovered_from(&coord, &second);
    assert!(
        only_tamper_alert(&host).contains(&second),
        "names the edited revision"
    );
    assert_one_acknowledgement_settles(&host, &coord);
}

/// No coordinator means no rollback, and still the alert for every row found.
#[test]
fn without_a_coordinator_the_tamper_alert_is_still_raised() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    edit_from_outside(&host, &second);

    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    assert!(signing.enforce_and_watch(None).is_none());

    assert!(only_tamper_alert(&host).contains(&second));
}

/// A recheck that could not roll the row back still raises its alert, for the
/// content the row holds.
#[test]
fn a_recheck_that_failed_still_alerts_the_active_row() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    edit_from_outside(&host, &second);

    signing.report().raise_after_recheck(
        &coord,
        Some(&[(
            USER.to_string(),
            crate::activation_coordinator::ActiveIntegrityOutcome::CheckFailed {
                error: crate::activation_coordinator::PolicyError::StorageFailure {
                    operation: "test",
                    message: "rollback failed".into(),
                },
            },
        )]),
    );

    assert_eq!(active(&coord), Some(second.clone()), "nothing rolled back");
    assert!(only_tamper_alert(&host).contains(&second));
}

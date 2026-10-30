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
/// Distinct bytes per change: the service hashes the content itself, so one
/// body under two labels would dedupe into one revision.
fn rules(label: &str) -> String {
    format!(r#"{{"rules":[],"label":"{label}"}}"#)
}

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
            payload: built_on_rules_in_force(coord, hash),
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

/// The active revision is a trusted one again: not the edited row, but the
/// one [`previous_run`] activated before it, with the content the app wrote.
fn assert_recovered_from(coord: &ActivationCoordinator, edited: &str) {
    let record = coord
        .current_active_for(USER)
        .expect("active")
        .expect("something active");
    assert_ne!(record.revision_id, edited);
    assert_eq!(record.rules_json, rules("h-1"));
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
    fn save_rules_anchor(&self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn load_rules_anchor(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        Ok(None)
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

    assert!(!reads(USER), "the caller's own rows only");
    assert!(reads("S-1-5-21-0-0-0-3002"));
}

/// The baseline is the administrator's: an unelevated user clearing an alert
/// must not re-sign its rows, which every user who has not diverged runs.
#[test]
fn the_baselines_revisions_make_an_acknowledgement_speak_for_the_administrator() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);
    host.conn
        .lock()
        .expect("conn")
        .execute(
            "INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status,
                 source, correlation_id, created_at)
             VALUES (?1, 'rev-base', 'h-base', '{}', 'superseded', 'gui-rules-edit', 'c', 1)",
            [nrr_storage::BASELINE_PRINCIPAL],
        )
        .expect("baseline row");
    let reads = other_principals_hold_revisions(Arc::clone(&host.conn));
    assert!(
        reads(USER),
        "the baseline's rows are not the caller's to adopt"
    );
}

fn gated_executor(host: &Host, coord: &Arc<ActivationCoordinator>) -> ProductionMutationExecutor {
    ProductionMutationExecutor::new(Arc::clone(coord)).with_alerts_repo(Arc::clone(&host.alerts))
}

/// A rules update as a client that read the rules sends it.
fn built_on_rules_in_force(coord: &ActivationCoordinator, hash: &str) -> serde_json::Value {
    serde_json::json!({
        "rules-json": rules(hash),
        "content-hash": hash,
        "base-revision": coord.base_revision_for(USER).expect("base"),
    })
}

fn rules_update(
    exec: &ProductionMutationExecutor,
    coord: &ActivationCoordinator,
    hash: &str,
) -> MutationOutcome {
    exec.execute(
        StoredMutation {
            kind: MutationKind::RulesUpdate,
            payload: built_on_rules_in_force(coord, hash),
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
        matches!(
            rules_update(&exec, coord, "h-blocked"),
            MutationOutcome::Failed(_)
        ),
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
            rules_update(&exec, coord, "h-after"),
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

/// An acknowledgement that adopted nothing (a client that sent no row list)
/// does not lift the alert: the tampered row would stay in the database with
/// no alert left to name it, since a raised alert is never raised twice.
#[test]
fn an_acknowledgement_that_adopts_nothing_leaves_the_tamper_alert_standing() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    edit_from_outside(&host, &second);
    let signing = start(&host, Arc::clone(&key_store) as _, BOOT_MS + 1_000);
    let coord = Arc::new(signing.sign(unsigned_coordinator(&host)));
    let _watch = signing.enforce_and_watch(Some(&coord));
    let exec = gated_executor(&host, &coord);
    let alert_id = only_tamper_alert(&host);

    let _ = exec.execute(
        StoredMutation {
            kind: MutationKind::SecurityAlertAck,
            payload: serde_json::json!({ "alert-id": alert_id }),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    );

    assert_eq!(only_tamper_alert(&host), alert_id, "the alert still stands");
    assert!(crate::tamper_bootstrap::mutations_blocked_by_alert(
        host.alerts.as_ref()
    ));
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

// ── The record of the active rules beside the key ───────────────────────────

/// A start on `key_store` with the boot sweep run, as a service starts.
fn boot(
    host: &Host,
    key_store: &Arc<InMemKeyStore>,
    now_ms: i64,
) -> (Arc<ActivationCoordinator>, Option<RevisionWatch>) {
    let signing = start(host, Arc::clone(key_store) as _, now_ms);
    let coord = Arc::new(signing.sign(unsigned_coordinator(host)));
    let watch = signing.enforce_and_watch(Some(&coord));
    (coord, watch)
}

fn rules_store_alerts(host: &Host) -> Vec<String> {
    host.alerts
        .list_by_state(SecurityAlertState::Active)
        .expect("alerts")
        .into_iter()
        .filter(|a| a.kind == AuditEventKind::RulesStoreRolledBack.as_str())
        .map(|a| a.alert_id)
        .collect()
}

fn outside(host: &Host) -> Connection {
    open_connection(&host.path).expect("outside connection")
}

fn delete_from_outside(host: &Host, id: &str) {
    let conn = outside(host);
    conn.execute(
        "DELETE FROM active_revision_pointer WHERE revision_id = ?1",
        [id],
    )
    .expect("delete pointer");
    conn.execute("DELETE FROM revisions WHERE revision_id = ?1", [id])
        .expect("delete row");
}

/// Copies the rules tables as they are now, signatures and all.
fn copy_rules(host: &Host, to: &std::path::Path) {
    outside(host)
        .execute("VACUUM INTO ?1", [to.to_string_lossy()])
        .expect("copy the database");
}

/// Puts back the rules tables of an earlier copy, as a restored backup does.
fn restore_rules(host: &Host, from: &std::path::Path) {
    let conn = outside(host);
    conn.execute("ATTACH DATABASE ?1 AS old", [from.to_string_lossy()])
        .expect("attach");
    conn.execute_batch(
        "DELETE FROM main.active_revision_pointer;
         DELETE FROM main.revisions;
         INSERT INTO main.revisions SELECT * FROM old.revisions;
         INSERT INTO main.active_revision_pointer SELECT * FROM old.active_revision_pointer;",
    )
    .expect("restore");
}

fn acknowledge_as_administrator(
    exec: &ProductionMutationExecutor,
    alert_id: &str,
) -> MutationOutcome {
    exec.execute(
        StoredMutation {
            kind: MutationKind::SecurityAlertAck,
            payload: serde_json::json!({ "alert-id": alert_id }),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: true,
        },
        USER,
    )
}

#[test]
fn an_active_rule_set_deleted_while_stopped_raises_a_blocking_alert() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    delete_from_outside(&host, &second);

    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 1_000);

    assert_eq!(
        rules_store_alerts(&host).len(),
        1,
        "the deletion went unnoticed"
    );
    assert!(crate::tamper_bootstrap::mutations_blocked_by_alert(
        host.alerts.as_ref()
    ));
    assert!(matches!(
        rules_update(&gated_executor(&host, &coord), &coord, "h-blocked"),
        MutationOutcome::Failed(_)
    ));
}

#[test]
fn an_older_copy_of_the_database_raises_a_blocking_alert() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let copy = host._dir.path().join("older-copy.db");
    {
        let (coord, _watch) = boot(&host, &key_store, BOOT_MS);
        activate(&coord, "h-1");
        copy_rules(&host, &copy);
        activate(&coord, "h-2");
    }
    restore_rules(&host, &copy);

    boot(&host, &key_store, BOOT_MS + 1_000);

    assert_eq!(
        rules_store_alerts(&host).len(),
        1,
        "the restore went unnoticed"
    );
    assert_eq!(
        active_alerts(&host, AuditEventKind::DbTamperDetected),
        0,
        "every row of the copy verifies on its own"
    );
}

#[test]
fn an_install_from_before_the_record_raises_nothing_and_starts_one() {
    let host = host();
    let old_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &old_store);
    let key = old_store.load().expect("load").expect("key");
    let upgraded = Arc::new(InMemKeyStore::with_key(key));

    boot(&host, &upgraded, BOOT_MS + 1_000);
    assert!(rules_store_alerts(&host).is_empty());
    assert!(upgraded.load_rules_anchor().expect("load").is_some());

    boot(&host, &upgraded, BOOT_MS + 2_000);
    assert!(rules_store_alerts(&host).is_empty());
}

#[test]
fn activation_rollback_and_reset_keep_the_record_in_step() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);

    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 1_000);
    activate(&coord, "h-3");
    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 2_000);
    assert!(rules_store_alerts(&host).is_empty(), "after an activation");

    // Going back to an earlier rule set re-activates it from history.
    let back = activate(&coord, "h-1");
    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 3_000);
    assert_eq!(active(&coord), Some(back));
    assert!(rules_store_alerts(&host).is_empty(), "after a rollback");

    let reset = ProductionMutationExecutor::new(Arc::clone(&coord)).execute(
        StoredMutation {
            kind: MutationKind::RulesResetToBaseline,
            payload: serde_json::json!({}),
            correlation_id: None,
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    );
    assert!(matches!(reset, MutationOutcome::Completed(_)), "{reset:?}");
    assert_eq!(active(&coord), None);
    boot(&host, &key_store, BOOT_MS + 4_000);
    assert!(rules_store_alerts(&host).is_empty(), "after a reset");
}

#[test]
fn the_alert_holds_rule_changes_until_an_administrator_accepts_the_rules() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    delete_from_outside(&host, &second);
    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 1_000);
    let exec = gated_executor(&host, &coord);
    let alert = rules_store_alerts(&host).pop().expect("alert");

    assert!(matches!(
        rules_update(&exec, &coord, "h-blocked"),
        MutationOutcome::Failed(_)
    ));
    assert!(matches!(
        acknowledge_as_administrator(&exec, &alert),
        MutationOutcome::Completed(_)
    ));
    assert!(!crate::tamper_bootstrap::mutations_blocked_by_alert(
        host.alerts.as_ref()
    ));
    // Judged on the record itself: the dedup of an acknowledged alert would
    // hide a record left disagreeing.
    let found = crate::rules_anchor::active_set(&host.conn.lock().expect("conn")).expect("read");
    let key = key_store.load().expect("load").expect("key");
    let stored = key_store.load_rules_anchor().expect("load");
    assert_eq!(
        crate::rules_anchor::check_at_boot(&found, stored.as_deref(), &key).alert,
        None,
        "the acknowledgement recorded the rules as they are now"
    );

    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 2_000);
    assert!(
        rules_store_alerts(&host).is_empty(),
        "the accepted rules are the recorded ones from here"
    );
    assert!(matches!(
        rules_update(&gated_executor(&host, &coord), &coord, "h-after"),
        MutationOutcome::Completed(_)
    ));
}

#[test]
fn a_record_not_signed_by_the_key_is_an_alert_not_a_fresh_start() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);
    let forged = crate::rules_anchor::AnchorRecord::of(Default::default()).encode(&[0x11; 32]);
    key_store.save_rules_anchor(&forged).expect("plant");

    boot(&host, &key_store, BOOT_MS + 1_000);

    assert_eq!(rules_store_alerts(&host).len(), 1);
    assert_eq!(
        key_store.load_rules_anchor().expect("load"),
        Some(forged),
        "the planted record is kept as found, never overwritten as trusted"
    );
}

#[test]
fn the_watch_catches_an_active_rule_set_deleted_while_running() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    let second = previous_run(&host, &key_store);
    let (_coord, watch) = boot(&host, &key_store, BOOT_MS + 1_000);
    let mut watch = watch.expect("watch");
    watch.tick(BOOT_MS + 2_000);

    delete_from_outside(&host, &second);
    watch.tick(BOOT_MS + 3_000);

    assert_eq!(rules_store_alerts(&host).len(), 1);
}

/// The database the next install creates after the data folder was removed,
/// born after `old`.
fn created_after(old: &Host) -> Host {
    let born: i64 = outside(old)
        .query_row("SELECT MIN(applied_at) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .expect("birth");
    let fresh = host();
    outside(&fresh)
        .execute(
            "UPDATE schema_migrations SET applied_at = ?1",
            [born + 60_000],
        )
        .expect("later birth");
    fresh
}

/// The uninstaller's data removal: the database goes, and so does the record
/// beside the key; the key stays for the audit trail.
#[test]
fn an_install_over_a_removed_data_folder_raises_nothing() {
    let old = host();
    let old_store = Arc::new(InMemKeyStore::new());
    previous_run(&old, &old_store);
    let fresh = created_after(&old);
    let key_store = Arc::new(InMemKeyStore::with_key(
        old_store.load().expect("load").expect("key"),
    ));

    let (coord, _watch) = boot(&fresh, &key_store, BOOT_MS + 1_000);

    assert!(rules_store_alerts(&fresh).is_empty());
    assert!(matches!(
        rules_update(&gated_executor(&fresh, &coord), &coord, "h-new-1"),
        MutationOutcome::Completed(_)
    ));
    // The new record guards the new database.
    let second = activate(&coord, "h-new-2");
    delete_from_outside(&fresh, &second);
    boot(&fresh, &key_store, BOOT_MS + 2_000);
    assert_eq!(rules_store_alerts(&fresh).len(), 1);
}

/// What is inside the database says nothing about which database it is:
/// a new, empty one put where the recorded one was is still a lost rule set.
#[test]
fn an_empty_database_in_place_of_the_recorded_one_raises_an_alert() {
    let old = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&old, &key_store);
    let fresh = created_after(&old);

    boot(&fresh, &key_store, BOOT_MS + 1_000);

    assert_eq!(rules_store_alerts(&fresh).len(), 1);
}

#[test]
fn every_rule_set_deleted_from_the_recorded_database_still_raises_an_alert() {
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);
    outside(&host)
        .execute_batch("DELETE FROM active_revision_pointer; DELETE FROM revisions;")
        .expect("wipe the rules");

    boot(&host, &key_store, BOOT_MS + 1_000);

    assert_eq!(
        rules_store_alerts(&host).len(),
        1,
        "emptied in place is not a new database"
    );
}

#[test]
fn a_full_reset_then_a_restart_raises_nothing() {
    use crate::ipc_handlers::providers::PrincipalDataPurger;
    let host = host();
    let key_store = Arc::new(InMemKeyStore::new());
    previous_run(&host, &key_store);
    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 1_000);

    // As `principal-data.purge` with the rules history runs it.
    let reset = gated_executor(&host, &coord).execute(
        StoredMutation {
            kind: MutationKind::RulesResetToBaseline,
            payload: serde_json::json!({}),
            correlation_id: Some("full-reset".into()),
            issuer_sid: USER.to_string(),
            caller_is_elevated: false,
        },
        USER,
    );
    assert!(matches!(reset, MutationOutcome::Completed(_)), "{reset:?}");
    crate::production_handlers_misc::ProductionPrincipalDataPurger::new(Arc::clone(&host.conn))
        .purge_for_sid(USER, true)
        .expect("purge");

    let (coord, _watch) = boot(&host, &key_store, BOOT_MS + 2_000);
    assert!(rules_store_alerts(&host).is_empty());
    assert!(matches!(
        rules_update(&gated_executor(&host, &coord), &coord, "h-after-reset"),
        MutationOutcome::Completed(_)
    ));
}

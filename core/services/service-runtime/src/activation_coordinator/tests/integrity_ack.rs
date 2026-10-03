//! Acknowledging a blocking integrity alert adopts exactly the rows the
//! dry-run listed, and only while they hold the content that was listed.

use super::*;
use crate::integrity_review::tamper_alert_id;
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::payloads::MutationKind;
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use crate::production_mutation_executor::ProductionMutationExecutor;
use crate::tamper_bootstrap::{
    mutations_blocked_by_alert, raise_tamper_alerts, run_tamper_bootstrap,
};
use nrr_diagnostics::audit::alert::{
    InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState, SecurityAlertsRepository,
};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_platform_api::key_store::{InMemKeyStore, KeyStore};
use nrr_shared::ipc_payloads::{IntegrityRowKind, IntegrityRowRef};

const BOOT_MS: i64 = 1_746_000_000_000;
const USER: &str = "S-1-5-21-0-0-0-1002";

struct Env {
    fx: Fixture,
    key_store: Arc<InMemKeyStore>,
    alerts: Arc<dyn SecurityAlertsRepository>,
}

/// Two principals with an active revision each, signed by `key`.
fn env(key: u8) -> (Env, RevisionId, RevisionId) {
    let key = vec![key; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    let baseline = activate(&fx, nrr_storage::BASELINE_PRINCIPAL, "h-base");
    let user = activate(&fx, USER, "h-user");
    let env = Env {
        fx,
        key_store: Arc::new(InMemKeyStore::with_key(key)),
        alerts: Arc::new(InMemorySecurityAlertsRepository::new()),
    };
    (env, baseline, user)
}

fn activate(fx: &Fixture, principal: &str, hash: &str) -> RevisionId {
    let id = submit_for(fx, principal, hash);
    let token = issue_token(fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");
    id
}

fn edit(env: &Env, revision_id: &RevisionId, rules_json: &str) {
    env.fx
        .conn
        .lock()
        .expect("conn")
        .execute(
            "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
            rusqlite::params![rules_json, revision_id.as_str()],
        )
        .expect("edit outside the app");
}

/// A start with no sweep to wait for: the alerts name the rows as found.
fn boot(env: &Env, now_ms: i64) -> crate::tamper_bootstrap::TamperBootstrapOutcome {
    let out = run_tamper_bootstrap(&env.fx.conn, env.key_store.as_ref(), &env.alerts, now_ms)
        .expect("bootstrap");
    raise_tamper_alerts(&env.alerts, &out.pending_tamper_alerts, None, now_ms);
    out
}

/// The service a boot with `signing_key` builds.
fn executor(env: &Env, signing_key: Vec<u8>) -> ProductionMutationExecutor {
    let coord = Arc::new(
        ActivationCoordinator::new(
            env.fx.conn.clone(),
            env.fx.registry.clone(),
            env.fx.dispatcher.clone() as Arc<dyn RulesApplyDispatcher>,
            env.fx.marker.clone() as Arc<dyn ApplyMarkerStore>,
            env.fx.audit.clone() as Arc<dyn ActivationAuditEmitter>,
            env.fx.clock.clone() as Arc<dyn Clock>,
            Arc::new(CounterIds::new()),
            ApplyFailurePolicy::AllOrNothing,
        )
        .with_signing_key(signing_key)
        .with_key_store(Arc::clone(&env.key_store) as Arc<dyn KeyStore>),
    );
    ProductionMutationExecutor::new(coord).with_alerts_repo(Arc::clone(&env.alerts))
}

/// What the dialog lists for `alert_id`.
fn shown(exec: &ProductionMutationExecutor, alert_id: &str) -> Vec<IntegrityRowRef> {
    exec.unverified_rows(
        MutationKind::SecurityAlertAck,
        &serde_json::json!({ "alert-id": alert_id }),
    )
    .into_iter()
    .map(|r| r.row)
    .collect()
}

fn decide(
    exec: &ProductionMutationExecutor,
    kind: MutationKind,
    alert_id: &str,
    rows: &[IntegrityRowRef],
) -> serde_json::Value {
    let outcome = exec.execute(
        StoredMutation {
            kind,
            payload: serde_json::json!({ "alert-id": alert_id, "adopt-rows": rows }),
            correlation_id: None,
            issuer_sid: String::new(),
            caller_is_elevated: true,
        },
        nrr_storage::BASELINE_PRINCIPAL,
    );
    match outcome {
        MutationOutcome::Completed(v) => v,
        other => panic!("expected Completed, got {other:?}"),
    }
}

fn verdict(env: &Env, key: &[u8], revision_id: &RevisionId) -> HmacVerification {
    let conn = env.fx.conn.lock().expect("conn");
    RevisionsRepository::with_signing_key(&conn, key.to_vec())
        .verify_row_hmac(revision_id.as_str())
        .expect("verify")
        .expect("row present")
}

fn active_of(env: &Env, kind: AuditEventKind) -> Vec<SecurityAlert> {
    env.alerts
        .list_by_state(SecurityAlertState::Active)
        .expect("list")
        .into_iter()
        .filter(|a| a.kind == kind.as_str())
        .collect()
}

fn only_tamper_alert(env: &Env) -> String {
    let active = active_of(env, AuditEventKind::DbTamperDetected);
    assert_eq!(active.len(), 1, "{active:?}");
    active[0].alert_id.clone()
}

#[test]
fn a_tamper_acknowledgement_adopts_the_row_it_showed_and_nothing_else() {
    let (env, baseline, user) = env(0x61);
    let key = vec![0x61; 32];
    edit(&env, &user, r#"{"edited":"user"}"#);
    boot(&env, BOOT_MS);
    let alert_id = only_tamper_alert(&env);
    edit(&env, &baseline, r#"{"edited":"baseline"}"#);
    let exec = executor(&env, key.clone());

    let rows = shown(&exec, &alert_id);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].revision_id, user.as_str());
    assert_eq!(rows[0].principal, USER);
    assert_eq!(rows[0].row_kind, IntegrityRowKind::Revision);

    let result = decide(&exec, MutationKind::SecurityAlertAck, &alert_id, &rows);
    assert_eq!(result["rows-adopted"], 1);
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Verified);
    assert_eq!(
        verdict(&env, &key, &baseline),
        HmacVerification::Tampered,
        "a row outside the alert is not adopted by it"
    );
    // The row left behind gets its own alert, so the gate stays up for it.
    let remaining = only_tamper_alert(&env);
    assert_ne!(remaining, alert_id);
    assert!(mutations_blocked_by_alert(env.alerts.as_ref()));
}

#[test]
fn a_row_edited_after_it_was_shown_is_not_adopted_and_raises_a_fresh_alert() {
    let (env, _, user) = env(0x62);
    let key = vec![0x62; 32];
    edit(&env, &user, r#"{"shown":true}"#);
    boot(&env, BOOT_MS);
    let first = only_tamper_alert(&env);
    let exec = executor(&env, key.clone());
    let rows = shown(&exec, &first);
    assert_eq!(rows.len(), 1);

    edit(&env, &user, r#"{"swapped":true}"#);
    let result = decide(&exec, MutationKind::SecurityAlertAck, &first, &rows);
    assert_eq!(result["rows-adopted"], 0);
    assert_eq!(result["rows-changed"], 1);
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Tampered);
    let fresh = only_tamper_alert(&env);
    assert_ne!(fresh, first, "the new content is a new incident");
    assert!(mutations_blocked_by_alert(env.alerts.as_ref()));

    // Positive control: the fresh alert, shown and acknowledged, adopts it.
    let rows = shown(&exec, &fresh);
    assert_eq!(rows.len(), 1);
    decide(&exec, MutationKind::SecurityAlertAck, &fresh, &rows);
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Verified);
    assert!(!mutations_blocked_by_alert(env.alerts.as_ref()));
}

#[test]
fn a_key_reset_acknowledgement_skips_rows_under_an_active_tamper_alert() {
    let (env, baseline, user) = env(0x63);
    edit(&env, &user, r#"{"edited":"before the key loss"}"#);
    boot(&env, BOOT_MS);
    let tamper = only_tamper_alert(&env);

    env.key_store.delete().expect("lose the key");
    let reset = boot(&env, BOOT_MS + 1_000);
    assert!(reset.key_was_reset);
    let new_key = reset.signing_key.clone();
    let key_reset = active_of(&env, AuditEventKind::KeyResetWithExistingData);
    assert_eq!(key_reset.len(), 1);
    let exec = executor(&env, new_key.clone());

    let rows = shown(&exec, &key_reset[0].alert_id);
    assert!(
        rows.iter().any(|r| r.revision_id == baseline.as_str()),
        "{rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|r| r.row_kind == IntegrityRowKind::Revision && r.revision_id == user.as_str()),
        "a row under an active tamper alert is not the key reset's to adopt: {rows:?}"
    );
    decide(
        &exec,
        MutationKind::SecurityAlertAck,
        &key_reset[0].alert_id,
        &rows,
    );
    assert_eq!(
        verdict(&env, &new_key, &baseline),
        HmacVerification::Verified
    );
    assert_eq!(verdict(&env, &new_key, &user), HmacVerification::Tampered);
    assert_eq!(
        only_tamper_alert(&env),
        tamper,
        "the evidence keeps its alert"
    );

    // Positive control: the tamper alert still names the row under the new key.
    let rows = shown(&exec, &tamper);
    assert_eq!(rows.len(), 1);
    decide(&exec, MutationKind::SecurityAlertAck, &tamper, &rows);
    assert_eq!(verdict(&env, &new_key, &user), HmacVerification::Verified);
}

#[test]
fn a_restart_does_not_raise_a_second_alert_for_the_same_content() {
    let (env, _, user) = env(0x64);
    edit(&env, &user, r#"{"edited":1}"#);
    boot(&env, BOOT_MS);
    boot(&env, BOOT_MS + 1_000);
    let alert_id = only_tamper_alert(&env);

    // Acknowledged without adopting: the row still fails, and still is not
    // alerted twice.
    let exec = executor(&env, vec![0x64; 32]);
    decide(&exec, MutationKind::SecurityAlertAck, &alert_id, &[]);
    boot(&env, BOOT_MS + 2_000);
    assert!(active_of(&env, AuditEventKind::DbTamperDetected).is_empty());
    assert_eq!(
        verdict(&env, &[0x64; 32], &user),
        HmacVerification::Tampered,
        "silencing a repeat never makes the row verify"
    );

    // Positive control: another edit of the same row is a new alert.
    edit(&env, &user, r#"{"edited":2}"#);
    boot(&env, BOOT_MS + 3_000);
    assert_ne!(only_tamper_alert(&env), alert_id);
}

#[test]
fn a_pending_key_reset_raises_no_per_row_alert_on_restart() {
    let (env, _, _) = env(0x65);
    env.key_store.delete().expect("lose the key");
    boot(&env, BOOT_MS);
    let restart = boot(&env, BOOT_MS + 1_000);
    assert!(restart.key_reset_unacknowledged);
    assert!(
        !restart.tampered_revision_ids.is_empty(),
        "the rows do fail under the new key"
    );
    assert!(active_of(&env, AuditEventKind::DbTamperDetected).is_empty());
    assert_eq!(
        active_of(&env, AuditEventKind::KeyResetWithExistingData).len(),
        1
    );
}

#[test]
fn a_forged_list_adopts_nothing() {
    let (env, baseline, user) = env(0x66);
    let key = vec![0x66; 32];
    edit(&env, &user, r#"{"edited":true}"#);
    boot(&env, BOOT_MS);
    let alert_id = only_tamper_alert(&env);
    let exec = executor(&env, key.clone());
    let honest = shown(&exec, &alert_id);
    assert_eq!(honest.len(), 1);

    let wrong_hash = IntegrityRowRef {
        content_hash: "0".repeat(64),
        ..honest[0].clone()
    };
    let other_row = IntegrityRowRef {
        revision_id: baseline.as_str().to_string(),
        principal: nrr_storage::BASELINE_PRINCIPAL.to_string(),
        ..honest[0].clone()
    };
    let result = decide(
        &exec,
        MutationKind::SecurityAlertAck,
        &alert_id,
        &[wrong_hash, other_row],
    );
    assert_eq!(result["rows-adopted"], 0);
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Tampered);
    assert_eq!(verdict(&env, &key, &baseline), HmacVerification::Verified);

    // Positive control: the honest list, on the same alert, adopts the row.
    decide(
        &exec,
        MutationKind::SecurityAlertResolve,
        &alert_id,
        &honest,
    );
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Verified);
}

/// The widest adoption rests on the re-sign marker, never on an alert row: a
/// planted key-reset alert over an intact key lists nothing and adopts nothing.
#[test]
fn a_forged_key_reset_alert_adopts_nothing_without_the_marker() {
    let (env, _, user) = env(0x67);
    let key = vec![0x67; 32];
    edit(&env, &user, r#"{"edited":true}"#);
    boot(&env, BOOT_MS);
    let tamper = only_tamper_alert(&env);
    env.alerts
        .insert(&SecurityAlert {
            alert_id: "alt-keyreset-forged".into(),
            kind: AuditEventKind::KeyResetWithExistingData.as_str().into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: "scan".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1,
            updated_at: 1,
            reason_code: "integrity.key_reset_with_existing_data".into(),
        })
        .expect("forge");
    let exec = executor(&env, key.clone());
    assert!(shown(&exec, "alt-keyreset-forged").is_empty());

    let honest = shown(&exec, &tamper);
    decide(
        &exec,
        MutationKind::SecurityAlertAck,
        "alt-keyreset-forged",
        &honest,
    );
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Tampered);

    // Positive control: the same row, through its own alert.
    decide(&exec, MutationKind::SecurityAlertAck, &tamper, &honest);
    assert_eq!(verdict(&env, &key, &user), HmacVerification::Verified);
}

#[test]
fn the_tamper_alert_id_names_the_content() {
    let (env, _, user) = env(0x68);
    edit(&env, &user, r#"{"edited":true}"#);
    let scan = {
        let conn = env.fx.conn.lock().expect("conn");
        RevisionsRepository::with_signing_key(&conn, vec![0x68; 32])
            .integrity_scan()
            .expect("scan")
    };
    let row = scan
        .iter()
        .find(|r| r.revision_id() == user.as_str())
        .expect("row");
    assert_eq!(
        tamper_alert_id(row),
        format!("alt-dbtamper-{}@{}", user.as_str(), row.fingerprint)
    );
}

//! Startup integrity bootstrap for the `nrr_service_state.db` row-MAC
//! chain.
//!
//! Run once at service startup, after the storage migrations and before
//! the IPC server accepts mutations. It ties together three components:
//!
//! - **Key loading** [`KeyStore`] — load the DPAPI-protected signing key,
//!   or generate + persist a fresh one on first start.
//! - **HMAC verification** [`RevisionsRepository`] — compare the stored
//!   `row_hmac` of every revision against a fresh recomputation.
//! - **Tamper alerting** [`SecurityAlertsRepository`] — raise a tamper /
//!   key-reset alert so the GUI surfaces it and the mutation gate blocks
//!   further changes until the user acknowledges.
//!
//! ## Decision matrix
//!
//! ```text
//! key file present?
//!  ├─ yes → load key; verify every row:
//!  │         Verified → ok
//!  │         Unsigned → lazy backfill (legacy v10→v11 row; re-sign)
//!  │         Tampered → emit DbTamperDetected (one per revision), block
//!  └─ no  → generate + save key:
//!            revisions empty     → fresh install, no alert
//!            revisions non-empty → emit KeyResetWithExistingData, block
//! ```
//!
//! Tamper detection is a **notification**, never fail-closed: the
//! kernel WFP filters for the active revision are already applied and
//! keep routing traffic. Blocking applies only to *new* mutations from
//! the GUI, lifted when the user acknowledges the alert (which triggers
//! a full re-sign — see `ProductionMutationExecutor`'s ack path).
//!
//! ## Residual risk (documented, accepted by spec)
//!
//! An attacker who can write the DB but lacks the key can zero a row's
//! `row_hmac` to make a tampered row read as `Unsigned` rather than
//! `Tampered`, and the lazy backfill would then bless it. Closing this
//! fully needs persistent "backfill already ran" state; the spec
//! (TASKS_RU.md §16.QoL+8) accepts it because the same attacker can
//! reach the key only by impersonating `LocalSystem` (`psexec -s`),
//! which is already an explicit non-goal of the threat model.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::reason::integrity;
use nrr_platform_api::key_store::{generate_signing_key, KeyStore};
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::RevisionsRepository;
use rusqlite::Connection;

/// Synthetic NDJSON pointer for bootstrap-raised alerts. The audit
/// `AuditWriter::append` API does not return the assigned seq/filename,
/// so — consistent with the existing `TODO:` in `production_mutation_executor`
/// — we record a stable marker rather than a real line. The alert UI reads
/// the alert row directly; it does not dereference this pointer.
const BOOTSTRAP_AUDIT_FILE: &str = "nrr_bootstrap_integrity_scan.ndjson";

/// Singleton alert id for the key-reset condition (only one is ever
/// meaningful at a time).
const KEY_RESET_ALERT_ID: &str = "alt-keyreset";

/// Deterministic alert id for a tampered revision, so re-detecting the
/// same row across restarts updates the single alert rather than
/// spamming a new one each boot (dedup: one alert per revision).
fn tamper_alert_id(revision_id: &str) -> String {
    format!("alt-dbtamper-{revision_id}")
}

/// Errors from [`run_tamper_bootstrap`]. Each wraps the underlying
/// layer's message; the caller logs and degrades (a bootstrap failure
/// must not crash the service — routing is independent of this scan).
#[derive(Debug)]
pub enum TamperBootstrapError {
    KeyStore(String),
    Storage(String),
    Alerts(String),
}

impl std::fmt::Display for TamperBootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyStore(m) => write!(f, "key store: {m}"),
            Self::Storage(m) => write!(f, "state storage: {m}"),
            Self::Alerts(m) => write!(f, "alerts repository: {m}"),
        }
    }
}

impl std::error::Error for TamperBootstrapError {}

/// Result of the startup integrity scan.
pub struct TamperBootstrapOutcome {
    /// The signing key to thread into the `ActivationCoordinator`
    /// (`with_signing_key`). Always present — loaded or freshly
    /// generated.
    pub signing_key: Vec<u8>,
    /// `true` when a freshly generated key replaced a missing one while
    /// the `revisions` table was non-empty.
    pub key_was_reset: bool,
    /// Revisions whose `row_hmac` failed verification at load.
    pub tampered_revision_ids: Vec<String>,
    /// Number of legacy `Unsigned` rows that were lazily backfilled.
    pub backfilled_rows: usize,
    /// `true` when at least one blocking alert (tamper or key-reset) was
    /// raised this boot. Informational — the live mutation gate
    /// recomputes from the alerts repo, since acknowledgement lifts it
    /// at runtime (see [`mutations_blocked_by_alert`]).
    pub raised_blocking_alert: bool,
}

/// Whether `kind` is a slug that, while in the `Active` state, must
/// block new GUI mutations.
#[must_use]
pub fn is_blocking_alert_kind(kind: &str) -> bool {
    kind == AuditEventKind::DbTamperDetected.as_str()
        || kind == AuditEventKind::KeyResetWithExistingData.as_str()
}

/// Live mutation gate: `true` when an unacknowledged (`Active`)
/// tamper / key-reset alert is present. Acknowledging such an alert
/// moves it to `Acknowledged`, so this returns `false` and the gate
/// lifts. Fails **open** (returns `false`) on a repository error — a
/// transient lock must not brick the user's ability to push rules,
/// and the protection is a notification, not fail-closed.
#[must_use]
pub fn mutations_blocked_by_alert(alerts_repo: &dyn SecurityAlertsRepository) -> bool {
    match alerts_repo.list_by_state(SecurityAlertState::Active) {
        Ok(alerts) => alerts.iter().any(|a| is_blocking_alert_kind(&a.kind)),
        Err(e) => {
            tracing::warn!(
                target: "nrr::tamper",
                error = %e,
                "failed to query active alerts for mutation gate; failing open",
            );
            false
        }
    }
}

/// Run the startup integrity scan. See the module docs for the full
/// decision matrix. `now_ms` is UTC Unix milliseconds (injected for
/// deterministic tests).
pub fn run_tamper_bootstrap(
    conn: &Arc<Mutex<Connection>>,
    key_store: &dyn KeyStore,
    alerts_repo: &Arc<dyn SecurityAlertsRepository>,
    now_ms: i64,
) -> Result<TamperBootstrapOutcome, TamperBootstrapError> {
    // 1. Load or generate the signing key.
    let (signing_key, key_loaded) = match key_store
        .load()
        .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?
    {
        Some(k) => (k, true),
        None => {
            let k = generate_signing_key()
                .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?;
            key_store
                .save(&k)
                .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?;
            (k, false)
        }
    };

    // The production alerts repository shares this same connection
    // mutex, so the guard must never be held across an `emit_alert`
    // call — the nested lock would deadlock the startup thread.
    // Every storage pass below takes the lock in its own scope.
    let mut outcome = TamperBootstrapOutcome {
        signing_key: signing_key.clone(),
        key_was_reset: false,
        tampered_revision_ids: Vec::new(),
        backfilled_rows: 0,
        raised_blocking_alert: false,
    };

    if !key_loaded {
        // Freshly generated key.
        let count = {
            let guard = lock_state(conn)?;
            RevisionsRepository::with_signing_key(&guard, signing_key.clone())
                .count()
                .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?
        };
        if count == 0 {
            // Fresh install — nothing signed yet, no alert. Future
            // inserts sign with the new key.
            tracing::info!(
                target: "nrr::tamper",
                "fresh install: generated DB-MAC key, no existing revisions",
            );
        } else {
            // Key reset with existing data: the old key is gone, so the
            // existing rows can no longer be verified. Do NOT re-sign
            // (that would bless possibly-forged data); raise one alert
            // and block mutations until the user accepts the state.
            outcome.key_was_reset = true;
            outcome.raised_blocking_alert = true;
            tracing::warn!(
                target: "nrr::tamper",
                revision_count = count,
                "DB-MAC key was missing with existing revisions; \
                 regenerated and blocking mutations pending acknowledgement",
            );
            emit_alert(
                alerts_repo,
                KEY_RESET_ALERT_ID.to_string(),
                AuditEventKind::KeyResetWithExistingData.as_str(),
                integrity::KEY_RESET_WITH_EXISTING_DATA.as_str(),
                now_ms,
            )?;
        }
        return Ok(outcome);
    }

    // Key loaded — verify every row.
    let verifications = {
        let guard = lock_state(conn)?;
        RevisionsRepository::with_signing_key(&guard, signing_key.clone())
            .verify_all()
            .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?
    };
    let mut backfill_ids: Vec<String> = Vec::new();
    for (revision_id, verification) in verifications {
        match verification {
            HmacVerification::Verified => {}
            HmacVerification::Unsigned => backfill_ids.push(revision_id),
            HmacVerification::Tampered => {
                tracing::warn!(
                    target: "nrr::tamper",
                    revision_id = %revision_id,
                    "revision row failed HMAC verification; raising tamper alert",
                );
                emit_alert(
                    alerts_repo,
                    tamper_alert_id(&revision_id),
                    AuditEventKind::DbTamperDetected.as_str(),
                    integrity::DB_ROW_HMAC_MISMATCH.as_str(),
                    now_ms,
                )?;
                outcome.tampered_revision_ids.push(revision_id);
                outcome.raised_blocking_alert = true;
            }
        }
    }

    // Lazy backfill of legacy unsigned rows (the v10→v11 migration
    // added the column with an empty default). Safe to re-sign: these
    // predate signing and are not tampered. See module-level residual
    // risk note.
    if !backfill_ids.is_empty() {
        let guard = lock_state(conn)?;
        let repo = RevisionsRepository::with_signing_key(&guard, signing_key.clone());
        for revision_id in &backfill_ids {
            repo.re_sign_row(revision_id)
                .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?;
        }
    }
    outcome.backfilled_rows = backfill_ids.len();
    if !backfill_ids.is_empty() {
        tracing::info!(
            target: "nrr::tamper",
            backfilled = backfill_ids.len(),
            "lazily backfilled legacy unsigned revision rows",
        );
    }

    Ok(outcome)
}

/// Lock the shared state connection for one storage pass. Kept narrow on
/// purpose — see the deadlock note at the top of [`run_tamper_bootstrap`].
fn lock_state(
    conn: &Arc<Mutex<Connection>>,
) -> Result<std::sync::MutexGuard<'_, Connection>, TamperBootstrapError> {
    conn.lock()
        .map_err(|_| TamperBootstrapError::Storage("state connection mutex poisoned".into()))
}

/// Insert an alert unless one with this id already exists (dedup across
/// restarts). Idempotent: a pre-existing alert in any state is left
/// untouched. `pub` so other startup integrity sweeps (e.g. the active-
/// revision integrity gate) can raise alerts through the same dedup
/// path without duplicating it.
pub fn emit_alert(
    alerts_repo: &Arc<dyn SecurityAlertsRepository>,
    alert_id: String,
    kind: &str,
    reason_code: &str,
    now_ms: i64,
) -> Result<(), TamperBootstrapError> {
    let existing = alerts_repo
        .find_by_id(&alert_id)
        .map_err(|e| TamperBootstrapError::Alerts(e.to_string()))?;
    if existing.is_some() {
        // Already tracked (active, acknowledged, or resolved). Do not
        // re-raise — that would either duplicate or reopen a closed
        // alert on every restart of a still-tampered DB.
        return Ok(());
    }
    let alert = SecurityAlert {
        alert_id,
        kind: kind.to_string(),
        state: SecurityAlertState::Active,
        raised_event_seq: 0,
        raised_file: BOOTSTRAP_AUDIT_FILE.to_string(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: now_ms,
        updated_at: now_ms,
        reason_code: reason_code.to_string(),
    };
    alerts_repo
        .insert(&alert)
        .map_err(|e| TamperBootstrapError::Alerts(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
    use nrr_domain::revision::RiskLevel;
    use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
    use nrr_platform_api::key_store::InMemKeyStore;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::revisions::RevisionRecord;

    const NOW: i64 = 1_745_000_000_000;
    fn key() -> Vec<u8> {
        vec![0x11u8; 32]
    }

    fn open_state() -> Arc<Mutex<Connection>> {
        let dir = tempfile::tempdir().expect("tempdir");
        // Leak the dir so the file outlives the test body (we only need
        // the connection; the temp file is cleaned by the OS later).
        let path = dir.keep().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn record(id: &str, hash: &str) -> RevisionRecord {
        RevisionRecord {
            revision_id: id.to_string(),
            content_hash: hash.to_string(),
            rules_json: "{}".to_string(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr".to_string(),
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: Some(RiskLevel::Low),
        }
    }

    fn alerts() -> Arc<dyn SecurityAlertsRepository> {
        Arc::new(InMemorySecurityAlertsRepository::new())
    }

    // ── Scenario 3: fresh install (key absent, revisions empty) ───────────────
    #[test]
    fn fresh_install_generates_key_no_alert() {
        let conn = open_state();
        let ks = InMemKeyStore::new();
        let repo = alerts();
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

        assert!(!out.key_was_reset);
        assert!(!out.raised_blocking_alert);
        assert!(out.tampered_revision_ids.is_empty());
        assert_eq!(out.signing_key.len(), 32);
        // Key was persisted for next boot.
        assert!(ks.load().expect("load").is_some());
        assert!(!mutations_blocked_by_alert(repo.as_ref()));
    }

    // ── Scenario 2: key deleted + revisions non-empty ─────────────────────────
    #[test]
    fn key_reset_with_existing_data_blocks_mutations() {
        let conn = open_state();
        // Seed a signed row, then "delete" the key by using an empty store.
        {
            let guard = conn.lock().unwrap();
            let signed = RevisionsRepository::with_signing_key(&guard, key());
            signed
                .insert_candidate(&record("rev-1", "h-1"))
                .expect("insert");
        }
        let ks = InMemKeyStore::new(); // key file absent
        let repo = alerts();
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

        assert!(out.key_was_reset);
        assert!(out.raised_blocking_alert);
        // Single key-reset alert, Active, blocking.
        let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(
            active[0].kind,
            AuditEventKind::KeyResetWithExistingData.as_str()
        );
        assert!(mutations_blocked_by_alert(repo.as_ref()));
    }

    // ── Scenario 1: tampered row detected ─────────────────────────────────────
    #[test]
    fn external_tamper_raises_alert_but_keeps_key() {
        let conn = open_state();
        {
            let guard = conn.lock().unwrap();
            let signed = RevisionsRepository::with_signing_key(&guard, key());
            signed
                .insert_candidate(&record("rev-ok", "h-ok"))
                .expect("insert");
            signed
                .insert_candidate(&record("rev-bad", "h-bad"))
                .expect("insert");
            // External mutation of rev-bad outside the service write path.
            guard
                .execute(
                    "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
                    rusqlite::params![r#"{"tampered":true}"#, "rev-bad"],
                )
                .expect("tamper");
        }
        let ks = InMemKeyStore::with_key(key()); // key present
        let repo = alerts();
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

        assert!(!out.key_was_reset);
        assert_eq!(out.tampered_revision_ids, vec!["rev-bad".to_string()]);
        assert!(out.raised_blocking_alert);
        let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kind, AuditEventKind::DbTamperDetected.as_str());
        assert!(mutations_blocked_by_alert(repo.as_ref()));
    }

    #[test]
    fn legacy_unsigned_rows_are_backfilled_silently() {
        let conn = open_state();
        {
            let guard = conn.lock().unwrap();
            // Insert WITHOUT a key → empty-blob (Unsigned) rows, exactly
            // like a v10→v11 upgrade.
            let unsigned = RevisionsRepository::new(&guard);
            unsigned
                .insert_candidate(&record("rev-a", "h-a"))
                .expect("insert");
            unsigned
                .insert_candidate(&record("rev-b", "h-b"))
                .expect("insert");
        }
        let ks = InMemKeyStore::with_key(key());
        let repo = alerts();
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

        assert!(!out.raised_blocking_alert);
        assert_eq!(out.backfilled_rows, 2);
        assert!(!mutations_blocked_by_alert(repo.as_ref()));
        // After backfill the rows verify clean.
        let guard = conn.lock().unwrap();
        let repo2 = RevisionsRepository::with_signing_key(&guard, key());
        for (_id, v) in repo2.verify_all().unwrap() {
            assert_eq!(v, HmacVerification::Verified);
        }
    }

    #[test]
    fn tamper_alert_is_deduped_across_restarts() {
        let conn = open_state();
        {
            let guard = conn.lock().unwrap();
            let signed = RevisionsRepository::with_signing_key(&guard, key());
            signed
                .insert_candidate(&record("rev-bad", "h-bad"))
                .expect("insert");
            guard
                .execute(
                    "UPDATE revisions SET rules_json = '{\"x\":1}' WHERE revision_id = 'rev-bad'",
                    [],
                )
                .expect("tamper");
        }
        let ks = InMemKeyStore::with_key(key());
        let repo = alerts();
        // Two consecutive boots over the same tampered DB.
        run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("boot1");
        run_tamper_bootstrap(&conn, &ks, &repo, NOW + 1000).expect("boot2");
        // Only one alert exists despite two scans.
        let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
        assert_eq!(
            active.len(),
            1,
            "tamper alert must be deduped by revision id"
        );
    }

    #[test]
    fn blocking_kind_helper_matches_only_tamper_kinds() {
        assert!(is_blocking_alert_kind("db_tamper_detected"));
        assert!(is_blocking_alert_kind("key_reset_with_existing_data"));
        assert!(!is_blocking_alert_kind("tamper_alert_raised"));
        assert!(!is_blocking_alert_kind("review_approved"));
    }
}

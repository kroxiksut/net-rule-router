//! Startup integrity bootstrap for the `nrr_service_state.db` row-MAC
//! chain.
//!
//! Run once at service startup, after the storage migrations and before
//! the IPC server accepts mutations. It ties together three components:
//!
//! - **Key loading** [`KeyStore`] — load the signing key from the platform
//!   store (DPAPI on Windows, a root-only file on Linux), or generate +
//!   persist a fresh one on first start.
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
//!  │         Tampered → DbTamperDetected (one per row content) once the
//!  │                    active-revision sweep has run, block; none while
//!  │                    a key reset is pending
//!  └─ no  → generate + save key:
//!            revisions empty     → fresh install, no alert
//!            revisions non-empty → write the re-sign marker, emit a new
//!                                  KeyResetWithExistingData, block;
//!                                  no rollback until acknowledged
//! ```
//!
//! The tamper alert waits for the sweep because rolling a revision back
//! rewrites its row: an alert keyed by the content before the rollback would
//! list nothing to acknowledge, and the row would need a second one. The
//! verdict itself is taken here, before anything changes, and carried in
//! [`TamperBootstrapOutcome::pending_tamper_alerts`].
//!
//! The "no rollback" hold is the re-sign marker in the [`KeyStore`], never an
//! alert row: `security_alerts` is not MAC-protected, so a forged active alert
//! must not be able to switch the rollback of tampered rows off.
//!
//! Tamper detection is a **notification**, never fail-closed: the
//! kernel WFP filters for the active revision are already applied and
//! keep routing traffic. Blocking applies only to *new* mutations from
//! the GUI, lifted when the user acknowledges the alert, which re-signs
//! exactly the rows the acknowledgement dialog listed (see
//! [`crate::integrity_review`]).
//!
//! ## Residual risk (documented, accepted by spec)
//!
//! An attacker who can write the DB but lacks the key can zero a row's
//! `row_hmac` to make a tampered row read as `Unsigned` rather than
//! `Tampered`, and the lazy backfill would then bless it. Closing this
//! fully needs persistent "backfill already ran" state; accepted because
//! the same attacker can reach the key only with the service's own rights
//! (`LocalSystem`, root), which is already an explicit non-goal of the
//! threat model.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::reason::integrity;
use nrr_platform_api::key_store::{generate_signing_key, KeyStore};
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::{RevisionsRepository, ScannedContent, ScannedRow};

use crate::integrity_review::{row_label, row_ref, same_row, tamper_alert_id};
use crate::ipc_handlers::payloads::MutationKind;
use rusqlite::Connection;

/// Synthetic NDJSON pointer for bootstrap-raised alerts. The audit
/// `AuditWriter::append` API does not return the assigned seq/filename,
/// so — consistent with the existing `TODO:` in `production_mutation_executor`
/// — we record a stable marker rather than a real line. The alert UI reads
/// the alert row directly; it does not dereference this pointer.
const BOOTSTRAP_AUDIT_FILE: &str = "nrr_bootstrap_integrity_scan.ndjson";

/// One alert per key loss: a fixed id would dedup a second incident into an
/// alert the user already acknowledged, and nobody would be told.
fn key_reset_alert_id(now_ms: i64) -> String {
    format!("alt-keyreset-{now_ms}")
}

/// Domain label for [`resign_marker_for`].
const RESIGN_MARKER_LABEL: &[u8] = b"nrr-db-mac-resign-pending-v1";

/// The marker is derived from the key it was written for, so a marker from an
/// earlier incident, or one written without the key, never matches.
fn resign_marker_for(key: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(RESIGN_MARKER_LABEL);
    h.update(key);
    h.finalize().to_vec()
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
    /// `true` while the stored rows predate the current key: it was
    /// regenerated this boot, or the key store still holds the re-sign
    /// marker of an unacknowledged regeneration. Every row then reads as
    /// tampered, so nothing may be rolled back on that verdict — see
    /// `ActivationCoordinator::enforce_active_integrity_at_boot`.
    pub key_reset_unacknowledged: bool,
    /// Revisions whose `row_hmac` failed verification at load.
    pub tampered_revision_ids: Vec<String>,
    /// The failing rows as found, each owed a tamper alert: raised by
    /// [`raise_tamper_alerts`] once the sweep has rewritten what it rolls
    /// back. Empty while a key reset is pending.
    pub pending_tamper_alerts: Vec<ScannedRow>,
    /// Number of legacy `Unsigned` rows that were lazily backfilled.
    pub backfilled_rows: usize,
    /// `true` when this boot reached a blocking verdict (tamper or key reset),
    /// even if writing its alert row failed. Informational — the live mutation
    /// gate recomputes from the alerts repo (see [`mutations_blocked_by_alert`]).
    pub raised_blocking_alert: bool,
}

/// Whether `kind` is a slug that, while in the `Active` state, must
/// block new GUI mutations.
#[must_use]
pub fn is_blocking_alert_kind(kind: &str) -> bool {
    kind == AuditEventKind::DbTamperDetected.as_str()
        || kind == AuditEventKind::KeyResetWithExistingData.as_str()
}

/// Refusal code of [`mutation_refused_by_alert`], passed through to whoever
/// asked for the change (the tray's authoring actions included). The same slug
/// the wire refusal reaches clients as.
pub const SECURITY_ALERT_GATE_CODE: &str =
    nrr_shared::ipc_transport::SECURITY_ALERT_UNACKNOWLEDGED_CLIENT_SLUG;
pub const SECURITY_ALERT_GATE_MESSAGE: &str = "Verify rules and acknowledge security alert";

/// The tamper gate: while a blocking alert is active, only the
/// acknowledgement or resolution that clears it may run.
#[must_use]
pub fn mutation_refused_by_alert(
    kind: MutationKind,
    alerts_repo: &dyn SecurityAlertsRepository,
) -> bool {
    !matches!(
        kind,
        MutationKind::SecurityAlertAck | MutationKind::SecurityAlertResolve
    ) && mutations_blocked_by_alert(alerts_repo)
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
                msg_key = "tamper-mutation-gate-query-failed",
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
    //
    // A key too short to be usable counts as ABSENT, not as a key: HMAC accepts
    // any length, so a truncated blob would sign and verify every row against
    // itself and the tamper detector would be silently disarmed forever. The
    // missing-key path below is the honest one — it regenerates and, when the
    // table already holds rows, raises the blocking key-reset alert that says
    // the existing rows can no longer be vouched for.
    let loaded = key_store
        .load()
        .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?
        .filter(|k| {
            let usable = nrr_storage::revision_hmac::is_usable_signing_key(k);
            if !usable {
                tracing::warn!(
                    target: "nrr::tamper",
                    msg_key = "tamper-signing-key-too-short",
                    bytes = k.len(),
                    "stored signing key is too short to be usable — treating it as missing and generating a fresh one",
                );
            }
            usable
        });
    // The production alerts repository shares this same connection
    // mutex, so the guard must never be held across an `emit_alert`
    // call — the nested lock would deadlock the startup thread.
    // Every storage pass below takes the lock in its own scope.
    let Some(signing_key) = loaded else {
        let signing_key =
            generate_signing_key().map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?;
        let count = {
            let guard = lock_state(conn)?;
            RevisionsRepository::new(&guard)
                .count()
                .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?
        };
        // Marker before key: a crash in between leaves no key, so the next
        // boot resets again; the reverse order would leave a loadable key
        // with nothing holding the sweep off the unverifiable rows.
        if count > 0 {
            key_store
                .save_resign_marker(&resign_marker_for(&signing_key))
                .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?;
        }
        key_store
            .save(&signing_key)
            .map_err(|e| TamperBootstrapError::KeyStore(e.to_string()))?;
        let mut outcome = TamperBootstrapOutcome::clean(signing_key);
        if count == 0 {
            // Fresh install — nothing signed yet, no alert. Future
            // inserts sign with the new key.
            tracing::info!(
                target: "nrr::tamper",
                msg_key = "tamper-fresh-install-key-generated",
                "fresh install: generated DB-MAC key, no existing revisions",
            );
        } else {
            // Key reset with existing data: the old key is gone, so the
            // existing rows can no longer be verified. Do NOT re-sign
            // (that would bless possibly-forged data); raise one alert
            // and block mutations until the user accepts the state.
            outcome.key_was_reset = true;
            outcome.key_reset_unacknowledged = true;
            outcome.raised_blocking_alert = true;
            tracing::warn!(
                target: "nrr::tamper",
                msg_key = "tamper-key-reset-existing-data",
                revision_count = count,
                "DB-MAC key was missing with existing revisions; \
                 regenerated and blocking mutations pending acknowledgement",
            );
            log_unrecorded_alert(
                AuditEventKind::KeyResetWithExistingData.as_str(),
                emit_alert(
                    alerts_repo,
                    key_reset_alert_id(now_ms),
                    AuditEventKind::KeyResetWithExistingData.as_str(),
                    integrity::KEY_RESET_WITH_EXISTING_DATA.as_str(),
                    now_ms,
                ),
            );
        }
        return Ok(outcome);
    };
    let mut outcome = TamperBootstrapOutcome::clean(signing_key.clone());

    // The key a previous boot regenerated loads fine, but until the user
    // acknowledges that reset the rows are still signed by the lost one.
    outcome.key_reset_unacknowledged = resign_pending(key_store, &signing_key);
    if outcome.key_reset_unacknowledged {
        ensure_key_reset_alert_active(alerts_repo, now_ms);
    }

    // Key loaded — verify every row and pointer.
    let scan = {
        let guard = lock_state(conn)?;
        RevisionsRepository::with_signing_key(&guard, signing_key.clone())
            .integrity_scan()
            .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?
    };
    let mut backfill: Vec<&ScannedRow> = Vec::new();
    for row in &scan {
        match row.verification {
            HmacVerification::Verified => {}
            HmacVerification::Unsigned => backfill.push(row),
            HmacVerification::Tampered => {
                outcome.tampered_revision_ids.push(row_label(row));
                outcome.raised_blocking_alert = true;
                // Under a pending reset every row the lost key signed reads as
                // tampered; the key-reset alert already covers all of them.
                if outcome.key_reset_unacknowledged {
                    continue;
                }
                tracing::warn!(
                    target: "nrr::tamper",
                    msg_key = "tamper-row-hmac-mismatch",
                    revision_id = %row_label(row),
                    "revision row failed HMAC verification; raising tamper alert",
                );
                outcome.pending_tamper_alerts.push(row.clone());
            }
        }
    }

    // Lazy backfill of rows written before signing existed (the v10→v11
    // migration added the column with an empty default). Safe to re-sign:
    // these predate signing and are not tampered. See module-level residual
    // risk note.
    if !backfill.is_empty() {
        let guard = lock_state(conn)?;
        let repo = RevisionsRepository::with_signing_key(&guard, signing_key.clone());
        for row in &backfill {
            match row.content {
                ScannedContent::Revision(_) => repo.re_sign_row(row.revision_id()),
                ScannedContent::Pointer(_) => repo.re_sign_pointer_for(&row.principal),
            }
            .map_err(|e| TamperBootstrapError::Storage(e.to_string()))?;
        }
    }
    outcome.backfilled_rows = backfill.len();
    if !backfill.is_empty() {
        tracing::info!(
            target: "nrr::tamper",
            msg_key = "tamper-legacy-rows-backfilled",
            backfilled = backfill.len(),
            "lazily backfilled legacy unsigned revision rows",
        );
    }

    Ok(outcome)
}

impl TamperBootstrapOutcome {
    fn clean(signing_key: Vec<u8>) -> Self {
        Self {
            signing_key,
            key_was_reset: false,
            key_reset_unacknowledged: false,
            tampered_revision_ids: Vec::new(),
            pending_tamper_alerts: Vec::new(),
            backfilled_rows: 0,
            raised_blocking_alert: false,
        }
    }
}

/// Raises the alert owed to every row in `found`, keyed by the content it holds
/// in `current` — a scan taken after the sweep — so the acknowledgement dialog
/// lists exactly that row. A row that verifies or is gone in `current`, or no
/// `current` at all, keeps the content it was found with: the incident is
/// reported either way, and a sweep that failed has changed nothing.
pub fn raise_tamper_alerts(
    alerts_repo: &Arc<dyn SecurityAlertsRepository>,
    found: &[ScannedRow],
    current: Option<&[ScannedRow]>,
    now_ms: i64,
) {
    for row in found {
        let found_ref = row_ref(row);
        let still_failing = current.and_then(|rows| {
            rows.iter().find(|r| {
                r.verification == HmacVerification::Tampered && same_row(&row_ref(r), &found_ref)
            })
        });
        log_unrecorded_alert(
            AuditEventKind::DbTamperDetected.as_str(),
            raise_tamper_alert(alerts_repo, still_failing.unwrap_or(row), now_ms),
        );
    }
}

/// Whether the key store holds the re-sign marker written for `key`.
///
/// An unreadable marker counts as pending: the file sits beside the key under
/// the same protection, so failing to read it is an OS fault, and guessing
/// "acknowledged" there would roll every principal's rules back to nothing.
pub(crate) fn resign_pending(key_store: &dyn KeyStore, key: &[u8]) -> bool {
    match key_store.load_resign_marker() {
        Ok(None) => false,
        Ok(Some(marker)) if marker == resign_marker_for(key) => true,
        Ok(Some(_)) => {
            tracing::warn!(
                target: "nrr::tamper",
                "re-sign marker does not belong to the current signing key; ignoring it",
            );
            false
        }
        Err(e) => {
            tracing::error!(
                target: "nrr::tamper",
                error = %e,
                "could not read the re-sign marker; keeping every revision until the key reset is acknowledged",
            );
            true
        }
    }
}

/// The marker outlives the alert row it was raised with — that row sits in an
/// unprotected table and may be gone. Re-raise one, so the reset stays
/// acknowledgeable. Best effort: the marker alone already holds the sweep off.
fn ensure_key_reset_alert_active(alerts_repo: &Arc<dyn SecurityAlertsRepository>, now_ms: i64) {
    let kind = AuditEventKind::KeyResetWithExistingData.as_str();
    let already = match alerts_repo.list_by_state(SecurityAlertState::Active) {
        Ok(active) => active.iter().any(|a| a.kind == kind),
        Err(e) => {
            tracing::warn!(
                target: "nrr::tamper",
                error = %e,
                "could not list active alerts; not re-raising the key-reset alert",
            );
            return;
        }
    };
    if already {
        return;
    }
    if let Err(e) = emit_alert(
        alerts_repo,
        key_reset_alert_id(now_ms),
        kind,
        integrity::KEY_RESET_WITH_EXISTING_DATA.as_str(),
        now_ms,
    ) {
        tracing::warn!(
            target: "nrr::tamper",
            error = %e,
            "could not re-raise the key-reset alert",
        );
    }
}

/// A failed alert write never fails the bootstrap: the verdict is already in
/// the outcome, and the boot sweep acts on the key it returns. Propagating it
/// dropped the key, and with it the rollback of the tampered revision.
fn log_unrecorded_alert(kind: &str, written: Result<(), TamperBootstrapError>) {
    if let Err(e) = written {
        tracing::error!(
            target: "nrr::tamper",
            msg_key = "tamper-alert-write-failed",
            kind,
            error = %e,
            "could not record the security alert; the integrity verdict still stands for this start",
        );
    }
}

/// Lock the shared state connection for one storage pass. Kept narrow on
/// purpose — see the deadlock note at the top of [`run_tamper_bootstrap`].
fn lock_state(
    conn: &Arc<Mutex<Connection>>,
) -> Result<std::sync::MutexGuard<'_, Connection>, TamperBootstrapError> {
    conn.lock()
        .map_err(|_| TamperBootstrapError::Storage("state connection mutex poisoned".into()))
}

/// Raise the tamper alert for `row`'s current content. Deduped by id, so the
/// same content never alerts twice; the dedup only silences a repeat, it never
/// makes the row verify.
pub fn raise_tamper_alert(
    alerts_repo: &Arc<dyn SecurityAlertsRepository>,
    row: &ScannedRow,
    now_ms: i64,
) -> Result<(), TamperBootstrapError> {
    emit_alert(
        alerts_repo,
        tamper_alert_id(row),
        AuditEventKind::DbTamperDetected.as_str(),
        integrity::DB_ROW_HMAC_MISMATCH.as_str(),
        now_ms,
    )
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

    /// A truncated key blob (interrupted write, clipped file, substitution)
    /// must never be accepted verbatim — HMAC takes any length, so every row
    /// would verify against the broken key and no alarm could ever fire. It
    /// must take the same route as a missing key, alert included.
    #[test]
    fn a_truncated_signing_key_is_treated_as_missing_not_used() {
        let conn = open_state();
        {
            let guard = conn.lock().unwrap();
            let signed = RevisionsRepository::with_signing_key(&guard, key());
            signed
                .insert_candidate(&record("rev-1", "h-1"))
                .expect("insert");
        }
        let ks = InMemKeyStore::new();
        ks.save(&[0xAB; 8]).expect("save truncated key");
        let repo = alerts();
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

        assert_eq!(out.signing_key.len(), 32, "a usable key replaced it");
        assert!(out.key_was_reset);
        assert!(
            out.raised_blocking_alert,
            "the user must be told the existing rows can no longer be vouched for"
        );
        assert!(mutations_blocked_by_alert(repo.as_ref()));
        assert_eq!(
            ks.load().expect("load").expect("stored").len(),
            32,
            "the unusable blob must not survive in the store",
        );
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
        assert!(
            repo.list_by_state(SecurityAlertState::Active)
                .unwrap()
                .is_empty(),
            "the alert waits for the sweep"
        );

        raise_tamper_alerts(&repo, &out.pending_tamper_alerts, None, NOW);
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
        for now in [NOW, NOW + 1000] {
            let out = run_tamper_bootstrap(&conn, &ks, &repo, now).expect("boot");
            raise_tamper_alerts(&repo, &out.pending_tamper_alerts, None, now);
        }
        // Only one alert exists despite two scans.
        let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
        assert_eq!(
            active.len(),
            1,
            "tamper alert must be deduped by revision id"
        );
    }

    /// The alert names the row as it stands after the sweep, not as found.
    #[test]
    fn the_alert_follows_the_content_the_sweep_left() {
        let conn = open_state();
        {
            let guard = conn.lock().unwrap();
            RevisionsRepository::with_signing_key(&guard, key())
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
        let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");
        let found = out.pending_tamper_alerts[0].clone();
        conn.lock()
            .unwrap()
            .execute(
                "UPDATE revisions SET status = 'rejected' WHERE revision_id = 'rev-bad'",
                [],
            )
            .expect("rewritten as a rollback would");
        let current = {
            let guard = conn.lock().unwrap();
            RevisionsRepository::with_signing_key(&guard, key())
                .integrity_scan()
                .unwrap()
        };

        raise_tamper_alerts(&repo, &out.pending_tamper_alerts, Some(&current), NOW);

        let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
        assert_eq!(active.len(), 1);
        let now = current
            .iter()
            .find(|r| r.revision_id() == "rev-bad")
            .unwrap();
        assert_ne!(now.fingerprint, found.fingerprint);
        assert_eq!(active[0].alert_id, tamper_alert_id(now));
    }

    #[test]
    fn a_marker_not_bound_to_the_current_key_holds_nothing() {
        let conn = open_state();
        let ks = InMemKeyStore::with_key(key());
        ks.save_resign_marker(&resign_marker_for(&[0x22u8; 32]))
            .expect("marker of an earlier key");
        let out = run_tamper_bootstrap(&conn, &ks, &alerts(), NOW).expect("bootstrap");
        assert!(!out.key_reset_unacknowledged);

        ks.save_resign_marker(&resign_marker_for(&key()))
            .expect("marker of this key");
        let out = run_tamper_bootstrap(&conn, &ks, &alerts(), NOW).expect("bootstrap");
        assert!(out.key_reset_unacknowledged);
    }

    /// Key present, marker unreadable.
    struct UnreadableMarker(InMemKeyStore);
    impl KeyStore for UnreadableMarker {
        fn load(&self) -> Result<Option<Vec<u8>>, nrr_platform_api::error::PlatformError> {
            self.0.load()
        }
        fn save(&self, k: &[u8]) -> Result<(), nrr_platform_api::error::PlatformError> {
            self.0.save(k)
        }
        fn delete(&self) -> Result<(), nrr_platform_api::error::PlatformError> {
            self.0.delete()
        }
        fn save_resign_marker(
            &self,
            m: &[u8],
        ) -> Result<(), nrr_platform_api::error::PlatformError> {
            self.0.save_resign_marker(m)
        }
        fn load_resign_marker(
            &self,
        ) -> Result<Option<Vec<u8>>, nrr_platform_api::error::PlatformError> {
            Err(nrr_platform_api::error::PlatformError::Transient {
                operation: "test",
                detail: "read failed".into(),
            })
        }
        fn delete_resign_marker(&self) -> Result<(), nrr_platform_api::error::PlatformError> {
            self.0.delete_resign_marker()
        }
    }

    #[test]
    fn an_unreadable_marker_keeps_the_rules() {
        let conn = open_state();
        let ks = UnreadableMarker(InMemKeyStore::with_key(key()));
        let out = run_tamper_bootstrap(&conn, &ks, &alerts(), NOW).expect("bootstrap");
        assert!(out.key_reset_unacknowledged);
    }

    #[test]
    fn blocking_kind_helper_matches_only_tamper_kinds() {
        assert!(is_blocking_alert_kind("db_tamper_detected"));
        assert!(is_blocking_alert_kind("key_reset_with_existing_data"));
        assert!(!is_blocking_alert_kind("tamper_alert_raised"));
        assert!(!is_blocking_alert_kind("review_approved"));
    }
}

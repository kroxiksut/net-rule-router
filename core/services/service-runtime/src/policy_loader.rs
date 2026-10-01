//! Boot-time load of the active pointer and the keyless integrity check.
//!
//! ```text
//!  active OK ───────────────────────────► ActiveReady
//!  corruption found (any principal) ─────► ActiveInvalid  (reported, nothing moved)
//!  schema newer than this binary ────────► RecoveryRequired
//!  no active pointer ────────────────────► NoState
//! ```
//!
//! The loader only reports. It runs before the signing key is loaded, so it
//! cannot tell whose revision to trust, and the one pointer it could move is
//! the baseline's: moving it for another principal's corruption left the
//! pointer and the `active` status naming different rows, and the next
//! activation undid the "recovery". Recovery is
//! `ActivationCoordinator::enforce_active_integrity_all`, keyed and per
//! principal, moving status and pointer together.

use std::sync::{Arc, Mutex};

use nrr_domain::revision::RevisionId;
use nrr_storage::dto::{IntegrityCheckResult, RecoveryAction};
use nrr_storage::repository::RevisionMetadataRepository;
use sha2::{Digest, Sha256};

use crate::state::{ActiveRevisionState, ServicePolicyState};

// ── Outcome enum ─────────────────────────────────────────────────────────────

/// What `PolicyLoader::load` produced. Carries enough context for the
/// runtime to transition into the right `ServicePolicyState` and emit the
/// right audit/health events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyLoadResult {
    /// Active revision loaded and validated.
    ActiveLoaded(ActiveRevisionState),
    /// The keyless check found corruption and changed nothing; the keyed
    /// per-principal sweep that runs later in the same boot recovers.
    IntegrityFailureReported(String),
    /// No active revision is set. Treated as a fresh install.
    NoActiveRevision,
    /// The runtime cannot proceed without user action.
    RecoveryRequired(String),
    /// Underlying storage call failed.
    StorageError(String),
}

impl PolicyLoadResult {
    /// Map the outcome into the canonical `ServicePolicyState` so the
    /// runtime / `HealthReporter` can use a single enum.
    pub fn to_policy_state(&self) -> ServicePolicyState {
        match self {
            Self::ActiveLoaded(_) => ServicePolicyState::ActiveReady,
            Self::IntegrityFailureReported(_) => ServicePolicyState::ActiveInvalid,
            Self::NoActiveRevision => ServicePolicyState::NoState,
            Self::RecoveryRequired(_) | Self::StorageError(_) => {
                ServicePolicyState::RecoveryRequired
            }
        }
    }

    pub fn current_revision(&self) -> Option<&ActiveRevisionState> {
        match self {
            Self::ActiveLoaded(s) => Some(s),
            _ => None,
        }
    }
}

// ── Audit emitter abstraction ────────────────────────────────────────────────

/// What the loader records. The emitter must persist the event durably
/// before returning `Ok`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAuditEvent {
    /// The keyless check found corruption; nothing was changed.
    IntegrityFailureReported { details: String },
    /// The runtime cannot proceed without user action.
    RecoveryRequired { details: String },
}

/// Abstract audit sink used by the loader. Production wiring plugs in
/// the real `AuditWriter` from `nrr-diagnostics`; for unit tests we
/// inject a recording fake. The trait is intentionally minimal — the
/// loader doesn't know what AuditEvent kind/seq looks like, just
/// "did the durable write succeed".
///
/// No `Send + Sync` bounds: the loader is called from a single thread
/// during bootstrap (`SqliteStateStore` itself is `!Sync` because it
/// holds a `RefCell<Connection>`). Cross-thread access is the
/// responsibility of the runtime loop, which wraps the
/// loader in `spawn_blocking`-style barriers.
pub trait RecoveryAuditEmitter {
    fn emit(&self, event: RecoveryAuditEvent) -> Result<(), String>;
}

/// Audit sink that swallows every event. Used only by tests/unit
/// scenarios that don't care about audit. **Not** safe for production:
/// the runtime contract requires a real durable sink.
#[derive(Default)]
pub struct NoopAuditEmitter;

impl RecoveryAuditEmitter for NoopAuditEmitter {
    fn emit(&self, _event: RecoveryAuditEvent) -> Result<(), String> {
        Ok(())
    }
}

// ── Loader ───────────────────────────────────────────────────────────────────

/// Reads the active pointer and reports what the keyless integrity check
/// finds. Never writes the store.
pub struct PolicyLoader<R, A>
where
    R: RevisionMetadataRepository,
    A: RecoveryAuditEmitter,
{
    repo: Arc<R>,
    audit: Arc<A>,
    /// Best-effort time provider. Tests inject a fixed clock so the
    /// `activated_at_iso` field is deterministic.
    clock: Arc<dyn Fn() -> String>,
    /// Cached "current" summary. Updated on every successful load so a
    /// `PolicyManager` impl can answer `current_revision()` in O(1).
    current: Mutex<Option<ActiveRevisionState>>,
}

impl<R, A> PolicyLoader<R, A>
where
    R: RevisionMetadataRepository,
    A: RecoveryAuditEmitter,
{
    pub fn new(repo: Arc<R>, audit: Arc<A>) -> Self {
        Self {
            repo,
            audit,
            clock: Arc::new(default_clock),
            current: Mutex::new(None),
        }
    }

    /// Replace the time provider (test-only).
    #[doc(hidden)]
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> String>) -> Self {
        self.clock = clock;
        self
    }

    /// Walk the state machine end-to-end. Updates the cached `current`
    /// summary on `ActiveLoaded`.
    pub fn load(&self) -> PolicyLoadResult {
        let active = match self.repo.get_active_revision() {
            Ok(v) => v,
            Err(e) => return PolicyLoadResult::StorageError(e.to_string()),
        };
        let integrity = match self.repo.check_integrity() {
            Ok(t) => t,
            Err(e) => return PolicyLoadResult::StorageError(e.to_string()),
        };

        match (active, integrity) {
            // Before the baseline pointer: the corruption may belong to any
            // principal, including one the baseline has nothing to do with.
            (_, (IntegrityCheckResult::PolicyIntegrityFailed { details }, action)) => {
                self.report_integrity_failure(details, action)
            }
            (Some(active_id), (IntegrityCheckResult::Ok, _)) => {
                let summary = self.summary_for(&active_id);
                self.set_current(Some(summary.clone()));
                PolicyLoadResult::ActiveLoaded(summary)
            }
            (None, _) => {
                self.set_current(None);
                PolicyLoadResult::NoActiveRevision
            }
            (
                Some(_),
                (
                    IntegrityCheckResult::UnsupportedSchemaVersion {
                        found,
                        max_supported,
                    },
                    _,
                ),
            ) => {
                let msg = format!(
                    "schema {found} is newer than supported {max_supported}; cannot proceed"
                );
                let _ = self.audit.emit(RecoveryAuditEvent::RecoveryRequired {
                    details: msg.clone(),
                });
                self.set_current(None);
                PolicyLoadResult::RecoveryRequired(msg)
            }
            (Some(_), (IntegrityCheckResult::StorageUnavailable(msg), _)) => {
                self.set_current(None);
                PolicyLoadResult::StorageError(msg)
            }
            // Cache integrity does not affect policy load.
            (Some(_), (IntegrityCheckResult::CacheCorruptRebuildable, _)) => {
                self.try_active_after_cache_only_failure()
            }
        }
    }

    fn try_active_after_cache_only_failure(&self) -> PolicyLoadResult {
        match self.repo.get_active_revision() {
            Ok(Some(id)) => {
                let summary = self.summary_for(&id);
                self.set_current(Some(summary.clone()));
                PolicyLoadResult::ActiveLoaded(summary)
            }
            Ok(None) => {
                self.set_current(None);
                PolicyLoadResult::NoActiveRevision
            }
            Err(e) => PolicyLoadResult::StorageError(e.to_string()),
        }
    }

    fn report_integrity_failure(
        &self,
        details: String,
        action: RecoveryAction,
    ) -> PolicyLoadResult {
        let details = match action {
            RecoveryAction::RequireUserAction(why) => format!("{details}; {why}"),
            _ => details,
        };
        // A lost audit line does not change the outcome: nothing was mutated,
        // and the health snapshot carries the same text.
        let _ = self
            .audit
            .emit(RecoveryAuditEvent::IntegrityFailureReported {
                details: details.clone(),
            });
        self.set_current(None);
        PolicyLoadResult::IntegrityFailureReported(details)
    }

    fn summary_for(&self, id: &RevisionId) -> ActiveRevisionState {
        ActiveRevisionState {
            revision_id: id.as_str().to_string(),
            provenance: "active".to_string(),
            // The canonical-profile load (rule_count, behavior_mode) belongs to
            // the caller once the rule engine context exists.
            rule_count: 0,
            behavior_mode: "auto".to_string(),
            content_hash_hex: sha256_hex(id.as_str()),
            activated_at_iso: (self.clock)(),
        }
    }

    fn set_current(&self, summary: Option<ActiveRevisionState>) {
        if let Ok(mut guard) = self.current.lock() {
            *guard = summary;
        }
    }

    /// Cheap read of the cached current revision summary.
    pub fn current(&self) -> Option<ActiveRevisionState> {
        self.current.lock().ok().and_then(|g| g.clone())
    }
}

fn sha256_hex(s: &str) -> String {
    use std::fmt::Write as _;
    Sha256::digest(s.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

// ── Default clock ────────────────────────────────────────────────────────────

fn default_clock() -> String {
    // Minimal ISO-8601 UTC string assembled from `SystemTime`. We
    // intentionally avoid `chrono` to keep the runtime free of an
    // additional crate just for one timestamp. Format:
    // `1970-01-01T00:00:00Z` plus integer seconds since UNIX epoch
    // appended for tie-breaking.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch+{secs}s")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::revisions::{ActiveRevisionPointer, RevisionsRepository};
    use nrr_storage::{
        open_connection, repository::MigrationRunner, SqliteMigrationRunner, SqliteStateStore,
        BASELINE_PRINCIPAL,
    };
    use rusqlite::Connection;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    // ── Test scaffolding ────────────────────────────────────────────────

    /// Integrity rests on `row_hmac`, so a "corrupt" revision is a signed row
    /// edited afterwards — what tampering does.
    const TEST_SIGNING_KEY: &[u8] = b"policy-loader-test-key-0123456789";

    const OTHER_PRINCIPAL: &str = "S-1-5-21-1000-1000-1000-1001";

    fn fresh_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let conn = open_connection(&dir.path().join("nrr_service_state.db")).unwrap();
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().unwrap();
        runner.verify_schema().unwrap();
        (dir, runner.into_connection())
    }

    fn keyed(conn: Connection) -> SqliteStateStore {
        SqliteStateStore::new(conn).with_signing_key(TEST_SIGNING_KEY.to_vec())
    }

    fn repo(conn: &Connection) -> RevisionsRepository<'_> {
        RevisionsRepository::with_signing_key(conn, TEST_SIGNING_KEY.to_vec())
    }

    #[derive(Default)]
    struct RecordingAudit {
        events: StdMutex<Vec<RecoveryAuditEvent>>,
        fail: bool,
    }
    impl RecoveryAuditEmitter for RecordingAudit {
        fn emit(&self, event: RecoveryAuditEvent) -> Result<(), String> {
            if self.fail {
                return Err("simulated audit write failure".into());
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn rev(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(format!("rev-{s}")).unwrap()
    }

    /// Signed revision rows for `principal`; `superseded_at > 0` marks history.
    fn seed(conn: &Connection, principal: &str, rows: &[(&RevisionId, &str, i64)]) {
        for (id, status, superseded_at) in rows {
            conn.execute(
                "INSERT INTO revisions (principal, revision_id, content_hash, rules_json,
                                        status, source, correlation_id, created_at,
                                        superseded_at)
                 VALUES (?1, ?2, ?3, '{}', ?4, 'gui-rules-edit', 'c', 0, ?5)",
                rusqlite::params![
                    principal,
                    id.as_str(),
                    format!("h-{}", id.as_str()),
                    status,
                    (*superseded_at > 0).then_some(*superseded_at)
                ],
            )
            .unwrap();
            repo(conn).re_sign_row(id.as_str()).unwrap();
        }
    }

    fn point(conn: &Connection, principal: &str, id: &RevisionId) {
        repo(conn)
            .set_active_pointer_for(
                principal,
                &ActiveRevisionPointer {
                    revision_id: id.as_str().to_string(),
                    activated_at: 1,
                    apply_attempt_id: None,
                },
            )
            .unwrap();
    }

    fn tamper(conn: &Connection, id: &RevisionId) {
        conn.execute(
            "UPDATE revisions SET rules_json = '{\"tampered\":true}' WHERE revision_id = ?1",
            rusqlite::params![id.as_str()],
        )
        .unwrap();
    }

    fn pointer_of(conn: &Connection, principal: &str) -> Option<String> {
        repo(conn)
            .get_active_pointer_for(principal)
            .unwrap()
            .map(|p| p.revision_id)
    }

    fn status_active_of(conn: &Connection, principal: &str) -> Option<String> {
        repo(conn)
            .get_active_for(principal)
            .unwrap()
            .map(|r| r.revision_id)
    }

    fn load(
        store: SqliteStateStore,
        audit: RecordingAudit,
    ) -> (PolicyLoadResult, Arc<SqliteStateStore>, Arc<RecordingAudit>) {
        #[allow(clippy::arc_with_non_send_sync)] // test fixture: single-threaded store
        let store = Arc::new(store);
        let audit = Arc::new(audit);
        let loader = PolicyLoader::new(Arc::clone(&store), Arc::clone(&audit))
            .with_clock(Arc::new(|| "fixed-test-time".to_string()));
        (loader.load(), store, audit)
    }

    fn into_conn(store: Arc<SqliteStateStore>) -> Connection {
        Arc::try_unwrap(store)
            .unwrap_or_else(|_| panic!("store still shared"))
            .into_connection()
    }

    // ── Cases ────────────────────────────────────────────────────────────

    #[test]
    fn first_run_with_no_active_returns_no_state() {
        let (_dir, conn) = fresh_db();
        let (outcome, _, _) = load(keyed(conn), RecordingAudit::default());
        assert_eq!(outcome, PolicyLoadResult::NoActiveRevision);
        assert_eq!(outcome.to_policy_state(), ServicePolicyState::NoState);
    }

    #[test]
    fn active_present_with_valid_signature_loads_active_ready() {
        let (_dir, conn) = fresh_db();
        let id = rev("11111111-2222-3333-4444-555555555555");
        seed(&conn, BASELINE_PRINCIPAL, &[(&id, "active", 0)]);
        point(&conn, BASELINE_PRINCIPAL, &id);
        match load(keyed(conn), RecordingAudit::default()).0 {
            PolicyLoadResult::ActiveLoaded(summary) => {
                assert_eq!(summary.revision_id, id.as_str());
                assert_eq!(summary.provenance, "active");
                assert_eq!(summary.activated_at_iso, "fixed-test-time");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// The bug this loader was cut down for: corruption at one principal made
    /// the loader rewrite the BASELINE pointer onto the baseline's superseded
    /// row while the baseline's `active` status stayed where it was.
    #[test]
    fn corruption_at_another_principal_leaves_the_baseline_untouched() {
        let (_dir, conn) = fresh_db();
        let b1 = rev("b1b1b1b1-0000-0000-0000-000000000001");
        let b2 = rev("b2b2b2b2-0000-0000-0000-000000000002");
        let x1 = rev("c1c1c1c1-0000-0000-0000-000000000003");
        seed(
            &conn,
            BASELINE_PRINCIPAL,
            &[(&b1, "superseded", 1_000), (&b2, "active", 0)],
        );
        seed(&conn, OTHER_PRINCIPAL, &[(&x1, "active", 0)]);
        point(&conn, BASELINE_PRINCIPAL, &b2);
        point(&conn, OTHER_PRINCIPAL, &x1);
        tamper(&conn, &x1);

        let (outcome, store, audit) = load(keyed(conn), RecordingAudit::default());
        assert!(
            matches!(outcome, PolicyLoadResult::IntegrityFailureReported(_)),
            "got {outcome:?}"
        );
        assert_eq!(outcome.to_policy_state(), ServicePolicyState::ActiveInvalid);
        assert!(matches!(
            audit.events.lock().unwrap().as_slice(),
            [RecoveryAuditEvent::IntegrityFailureReported { .. }]
        ));

        let conn = into_conn(store);
        for (principal, expected) in [(BASELINE_PRINCIPAL, &b2), (OTHER_PRINCIPAL, &x1)] {
            assert_eq!(
                pointer_of(&conn, principal).as_deref(),
                Some(expected.as_str())
            );
            assert_eq!(
                pointer_of(&conn, principal),
                status_active_of(&conn, principal),
                "pointer and status of {principal} must still agree"
            );
        }
    }

    /// The production shape: the boot store has no key, and the only thing it
    /// can see is a pointer whose revision was deleted behind its back.
    #[test]
    fn a_keyless_store_reports_a_dangling_pointer_and_moves_nothing() {
        let (_dir, conn) = fresh_db();
        let b1 = rev("b1b1b1b1-0000-0000-0000-000000000001");
        let b2 = rev("b2b2b2b2-0000-0000-0000-000000000002");
        let x1 = rev("c1c1c1c1-0000-0000-0000-000000000003");
        seed(
            &conn,
            BASELINE_PRINCIPAL,
            &[(&b1, "superseded", 1_000), (&b2, "active", 0)],
        );
        seed(&conn, OTHER_PRINCIPAL, &[(&x1, "active", 0)]);
        point(&conn, BASELINE_PRINCIPAL, &b2);
        point(&conn, OTHER_PRINCIPAL, &x1);
        conn.execute_batch(&format!(
            "PRAGMA foreign_keys = OFF;
             DELETE FROM revisions WHERE revision_id = '{}';
             PRAGMA foreign_keys = ON;",
            x1.as_str()
        ))
        .unwrap();

        let (outcome, store, _) = load(SqliteStateStore::new(conn), RecordingAudit::default());
        match &outcome {
            PolicyLoadResult::IntegrityFailureReported(details) => {
                assert!(details.contains("is missing"), "details = {details}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        let conn = into_conn(store);
        assert_eq!(
            pointer_of(&conn, BASELINE_PRINCIPAL).as_deref(),
            Some(b2.as_str())
        );
        assert_eq!(
            pointer_of(&conn, OTHER_PRINCIPAL).as_deref(),
            Some(x1.as_str())
        );
    }

    #[test]
    fn a_tampered_active_row_is_reported_and_its_pointer_stays() {
        let (_dir, conn) = fresh_db();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let lkg = rev("bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        seed(
            &conn,
            BASELINE_PRINCIPAL,
            &[(&lkg, "superseded", 1_000), (&active, "active", 0)],
        );
        point(&conn, BASELINE_PRINCIPAL, &active);
        tamper(&conn, &active);

        let (outcome, store, _) = load(keyed(conn), RecordingAudit::default());
        assert!(matches!(
            outcome,
            PolicyLoadResult::IntegrityFailureReported(_)
        ));
        assert!(outcome.current_revision().is_none());
        let conn = into_conn(store);
        assert_eq!(
            pointer_of(&conn, BASELINE_PRINCIPAL).as_deref(),
            Some(active.as_str())
        );
        assert_eq!(
            status_active_of(&conn, BASELINE_PRINCIPAL).as_deref(),
            Some(active.as_str())
        );
    }

    /// A tampered rollback target is reported like any other finding: the
    /// keyed sweep skips it when it looks for a trusted revision.
    #[test]
    fn a_tampered_rollback_target_is_reported_with_its_hint() {
        let (_dir, conn) = fresh_db();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let lkg = rev("bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        seed(
            &conn,
            OTHER_PRINCIPAL,
            &[(&lkg, "superseded", 1_000), (&active, "active", 0)],
        );
        point(&conn, OTHER_PRINCIPAL, &active);
        tamper(&conn, &lkg);

        match load(keyed(conn), RecordingAudit::default()).0 {
            PolicyLoadResult::IntegrityFailureReported(details) => {
                assert!(details.contains("fallback target"), "details = {details}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn a_failed_audit_write_does_not_turn_a_report_into_a_mutation() {
        let (_dir, conn) = fresh_db();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        seed(&conn, BASELINE_PRINCIPAL, &[(&active, "active", 0)]);
        point(&conn, BASELINE_PRINCIPAL, &active);
        tamper(&conn, &active);

        let audit = RecordingAudit {
            fail: true,
            ..Default::default()
        };
        let (outcome, store, _) = load(keyed(conn), audit);
        assert!(matches!(
            outcome,
            PolicyLoadResult::IntegrityFailureReported(_)
        ));
        let conn = into_conn(store);
        assert_eq!(
            pointer_of(&conn, BASELINE_PRINCIPAL).as_deref(),
            Some(active.as_str())
        );
    }

    #[test]
    fn policy_state_mapping_is_total() {
        let ready = ActiveRevisionState {
            revision_id: "rev-x".into(),
            provenance: "active".into(),
            rule_count: 0,
            behavior_mode: "auto".into(),
            content_hash_hex: "deadbeef".into(),
            activated_at_iso: "t".into(),
        };
        let cases = [
            (
                PolicyLoadResult::ActiveLoaded(ready),
                ServicePolicyState::ActiveReady,
            ),
            (
                PolicyLoadResult::IntegrityFailureReported("x".into()),
                ServicePolicyState::ActiveInvalid,
            ),
            (
                PolicyLoadResult::NoActiveRevision,
                ServicePolicyState::NoState,
            ),
            (
                PolicyLoadResult::RecoveryRequired("x".into()),
                ServicePolicyState::RecoveryRequired,
            ),
            (
                PolicyLoadResult::StorageError("x".into()),
                ServicePolicyState::RecoveryRequired,
            ),
        ];
        for (outcome, expected) in cases {
            assert_eq!(outcome.to_policy_state(), expected);
        }
    }
}

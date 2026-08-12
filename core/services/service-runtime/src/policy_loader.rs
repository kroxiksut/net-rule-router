//! Active revision load + integrity verification + LKG
//! coordination.
//!
//! State machine (matches `ServicePolicyState` in `state.rs`):
//!
//! ```text
//!  NoState ── (no active pointer, no LKG, fresh install)
//!     │
//!  LoadingActive
//!     │
//!     ├── active OK ─────────────────────────────► ActiveReady
//!     ├── active corrupt + LKG OK + audit OK ────► LkgReady
//!     │           (active pointer is rewritten to LKG via the
//!     │            audited recovery flow; see `try_lkg_fallback`)
//!     ├── active corrupt + LKG corrupt ───────────► RecoveryRequired
//!     ├── active corrupt + LKG missing ───────────► RecoveryRequired
//!     ├── active corrupt + audit write failure ──► RecoveryRequired
//!     │           (we do NOT silently mutate the active pointer
//!     │            without an audit record)
//!     └── active missing + LKG missing ───────────► NoState
//!         (first-run path; tamper detection lives in 14.6 health
//!          aggregator that combines this with security_alerts)
//! ```
//!
//! Invariants enforced here:
//! - No `ActiveReady`/`LkgReady` outcome ever returns until both the
//!   integrity check passes (delegated to `nrr_storage::check_integrity`)
//!   AND the audit emitter has accepted the recovery event (when a
//!   recovery happened).
//! - `set_active_revision` is only called by the loader itself, and only
//!   inside `try_lkg_fallback` after the audit emitter signals success.
//! - The candidate/pending revision flow is **not** in this module —
//!   block 8/16 owns that controlled flow with its own audit chain.

use std::sync::{Arc, Mutex};

use nrr_domain::revision::RevisionId;
use nrr_storage::dto::{IntegrityCheckResult, RecoveryAction};
use nrr_storage::repository::RevisionMetadataRepository;

use crate::state::{ActiveRevisionState, ServicePolicyState};

// ── Outcome enum ─────────────────────────────────────────────────────────────

/// What `PolicyLoader::load` produced. Mirrors task 14.4's
/// `PolicyLoadResult`. Carries enough context for the runtime to
/// transition into the right `ServicePolicyState` and emit the right
/// audit/health events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyLoadResult {
    /// Active revision loaded and validated. Carries a summary the
    /// runtime publishes through `HealthReporter` (block 14.6).
    ActiveLoaded(ActiveRevisionState),
    /// Active loaded after the recovery flow flipped the active
    /// pointer to the LKG revision. The summary's `provenance` is
    /// `recovery-fallback` so the GUI can surface the fact.
    LkgFallbackApplied(ActiveRevisionState),
    /// No active revision is set and there is no LKG either. Treated
    /// as a fresh install.
    NoActiveRevision,
    /// Active revision is broken and the runtime cannot proceed without
    /// user action. The string carries the human-readable detail (used
    /// for audit + GUI).
    RecoveryRequired(String),
    /// Underlying storage call failed. Caller should surface this
    /// alongside a Blocking severity and let the runtime stay in
    /// `RecoveryRequired`.
    StorageError(String),
}

impl PolicyLoadResult {
    /// Map the outcome into the canonical `ServicePolicyState` so the
    /// runtime / `HealthReporter` can use a single enum.
    pub fn to_policy_state(&self) -> ServicePolicyState {
        match self {
            Self::ActiveLoaded(_) => ServicePolicyState::ActiveReady,
            Self::LkgFallbackApplied(_) => ServicePolicyState::LkgReady,
            Self::NoActiveRevision => ServicePolicyState::NoState,
            Self::RecoveryRequired(_) | Self::StorageError(_) => {
                ServicePolicyState::RecoveryRequired
            }
        }
    }

    pub fn current_revision(&self) -> Option<&ActiveRevisionState> {
        match self {
            Self::ActiveLoaded(s) | Self::LkgFallbackApplied(s) => Some(s),
            _ => None,
        }
    }
}

// ── Audit emitter abstraction ────────────────────────────────────────────────

/// Outcome the loader sends to the audit emitter when it considers an
/// LKG fallback. The emitter must persist the event durably *before*
/// returning `Ok`. If persistence fails, returning `Err` causes the
/// loader to fall through to `RecoveryRequired` rather than silently
/// mutate the active pointer (see 14.4 invariant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAuditEvent {
    /// Active revision found corrupt; about to switch to LKG.
    LkgFallbackStarted {
        broken_active: String,
        lkg_target: String,
        details: String,
    },
    /// LKG target validated, active pointer rewritten.
    LkgFallbackCompleted {
        broken_active: String,
        new_active: String,
    },
    /// Active is corrupt and no usable LKG is available; user must
    /// take action.
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

/// Pulls active revision state, verifies integrity, executes LKG
/// fallback when necessary. Stateless — `load()` can be called multiple
/// times and the outcome is deterministic given the same store + audit
/// emitter behaviour.
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

    /// Walk the state machine end-to-end. Returns the final outcome.
    /// Updates the cached `current` summary on `ActiveLoaded` /
    /// `LkgFallbackApplied`.
    pub fn load(&self) -> PolicyLoadResult {
        let active = match self.repo.get_active_revision() {
            Ok(v) => v,
            Err(e) => return PolicyLoadResult::StorageError(e.to_string()),
        };
        let lkg = match self.repo.get_last_known_good() {
            Ok(v) => v,
            Err(e) => return PolicyLoadResult::StorageError(e.to_string()),
        };

        // Run the storage-layer integrity check. It validates SQLite
        // structural integrity AND the SHA-256 hashes of both the
        // active pointer and the LKG.
        let integrity = match self.repo.check_integrity() {
            Ok(t) => t,
            Err(e) => return PolicyLoadResult::StorageError(e.to_string()),
        };

        match (active, integrity) {
            // Happy path: active OK and integrity OK.
            (Some(active_id), (IntegrityCheckResult::Ok, _)) => {
                let summary = self.summary_for(&active_id, "active");
                self.set_current(Some(summary.clone()));
                PolicyLoadResult::ActiveLoaded(summary)
            }
            // No active pointer at all.
            (None, _) => {
                self.set_current(None);
                PolicyLoadResult::NoActiveRevision
            }
            // Active corrupt — try the LKG.
            (
                Some(active_id),
                (IntegrityCheckResult::PolicyIntegrityFailed { details }, action),
            ) => self.try_lkg_fallback(&active_id, lkg, &details, action),
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
            (Some(_), (IntegrityCheckResult::CacheCorruptRebuildable, _)) => {
                // Cache integrity does not affect policy load — block
                // already handled the rebuild. Treat as Ok for the
                // policy state machine.
                self.try_active_after_cache_only_failure()
            }
        }
    }

    fn try_active_after_cache_only_failure(&self) -> PolicyLoadResult {
        match self.repo.get_active_revision() {
            Ok(Some(id)) => {
                let summary = self.summary_for(&id, "active");
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

    fn try_lkg_fallback(
        &self,
        broken_active: &RevisionId,
        lkg: Option<RevisionId>,
        details: &str,
        action: RecoveryAction,
    ) -> PolicyLoadResult {
        // Without an LKG pointer we cannot recover automatically. This
        // also covers `RequireUserAction` from `check_integrity` — even
        // if an LKG row exists, its hash failed, so we must not switch.
        let lkg_id = match lkg {
            Some(id) if !matches!(action, RecoveryAction::RequireUserAction(_)) => id,
            _ => {
                let msg = format!("active revision integrity failed and no usable LKG: {details}");
                let _ = self.audit.emit(RecoveryAuditEvent::RecoveryRequired {
                    details: msg.clone(),
                });
                self.set_current(None);
                return PolicyLoadResult::RecoveryRequired(msg);
            }
        };

        // 1. Audit the *intent* before mutating anything. Failure to
        // audit means we MUST NOT change the active pointer.
        if let Err(e) = self.audit.emit(RecoveryAuditEvent::LkgFallbackStarted {
            broken_active: broken_active.as_str().to_string(),
            lkg_target: lkg_id.as_str().to_string(),
            details: details.to_string(),
        }) {
            self.set_current(None);
            return PolicyLoadResult::RecoveryRequired(format!(
                "LKG fallback aborted because audit write failed: {e}"
            ));
        }

        // 2. Switch the active pointer to the LKG revision.
        if let Err(e) = self.repo.set_active_revision(&lkg_id) {
            // The audit "started" event is now orphaned, but that is
            // acceptable — the audit chain is append-only and the
            // forensic trail is preserved.
            self.set_current(None);
            return PolicyLoadResult::RecoveryRequired(format!(
                "LKG fallback aborted: failed to write active pointer: {e}"
            ));
        }

        // 3. Audit completion. Failure here is non-fatal — the active
        // pointer is already on the LKG, the runtime can proceed in
        // LkgReady, and block 14.11 will surface the audit drop via
        // the operational health snapshot.
        let _ = self.audit.emit(RecoveryAuditEvent::LkgFallbackCompleted {
            broken_active: broken_active.as_str().to_string(),
            new_active: lkg_id.as_str().to_string(),
        });

        let summary = self.summary_for(&lkg_id, "recovery-fallback");
        self.set_current(Some(summary.clone()));
        PolicyLoadResult::LkgFallbackApplied(summary)
    }

    fn summary_for(&self, id: &RevisionId, provenance: &str) -> ActiveRevisionState {
        let hash = nrr_storage::compute_revision_hash(id.as_str());
        let activated_at_iso = (self.clock)();
        ActiveRevisionState {
            revision_id: id.as_str().to_string(),
            provenance: provenance.to_string(),
            // This loader's scope is the active-pointer state machine. The
            // canonical-profile load (rule_count, behavior_mode) is wired
            // in once the rule engine context is constructed
            // here. Using stable defaults keeps the DTO shape pinned.
            rule_count: 0,
            behavior_mode: "auto".to_string(),
            content_hash_hex: hash,
            activated_at_iso,
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

// ── Default clock ────────────────────────────────────────────────────────────

fn default_clock() -> String {
    // Minimal ISO-8601 UTC string assembled from `SystemTime`. We
    // intentionally avoid `chrono` to keep the runtime free of an
    // additional crate just for one timestamp. Format:
    // `1970-01-01T00:00:00Z` plus integer seconds since UNIX epoch
    // appended for tie-breaking — replaced by the real chrono format
    // when the diagnostics layer is wired in 14.6.
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
    use nrr_storage::{
        open_connection, repository::MigrationRunner, SqliteMigrationRunner, SqliteStateStore,
    };
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    // ── Test scaffolding ────────────────────────────────────────────────

    /// Open + migrate a state DB in a temp dir. Returns the store and the
    /// dir so it stays alive for the test.
    fn fresh_state_store() -> (TempDir, SqliteStateStore) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nrr_service_state.db");
        let conn = open_connection(&path).unwrap();
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().unwrap();
        runner.verify_schema().unwrap();
        (dir, SqliteStateStore::new(runner.into_connection()))
    }

    /// Recording audit emitter — records every event. The closure-driven
    /// variant lets tests force a write failure.
    #[derive(Default)]
    struct RecordingAudit {
        events: StdMutex<Vec<RecoveryAuditEvent>>,
        fail_on_started: bool,
    }
    impl RecoveryAuditEmitter for RecordingAudit {
        fn emit(&self, event: RecoveryAuditEvent) -> Result<(), String> {
            if self.fail_on_started
                && matches!(event, RecoveryAuditEvent::LkgFallbackStarted { .. })
            {
                return Err("simulated audit write failure".into());
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn rev(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(format!("rev-{s}")).unwrap()
    }

    fn loader_for(
        store: SqliteStateStore,
        audit: RecordingAudit,
    ) -> (
        Arc<SqliteStateStore>,
        Arc<RecordingAudit>,
        PolicyLoader<SqliteStateStore, RecordingAudit>,
    ) {
        #[allow(clippy::arc_with_non_send_sync)] // test fixture: single-threaded store
        let repo = Arc::new(store);
        let aud = Arc::new(audit);
        let loader = PolicyLoader::new(repo.clone(), aud.clone())
            .with_clock(Arc::new(|| "fixed-test-time".to_string()));
        (repo, aud, loader)
    }

    // ── Cases ────────────────────────────────────────────────────────────

    #[test]
    fn first_run_with_no_active_returns_no_state() {
        let (_dir, store) = fresh_state_store();
        let (_, _, loader) = loader_for(store, RecordingAudit::default());
        assert_eq!(loader.load(), PolicyLoadResult::NoActiveRevision);
        assert_eq!(loader.load().to_policy_state(), ServicePolicyState::NoState);
    }

    #[test]
    fn active_present_with_valid_hash_loads_active_ready() {
        let (_dir, store) = fresh_state_store();
        let id = rev("11111111-2222-3333-4444-555555555555");
        store.set_active_revision(&id).unwrap();
        let (_, _, loader) = loader_for(store, RecordingAudit::default());
        match loader.load() {
            PolicyLoadResult::ActiveLoaded(summary) => {
                assert_eq!(summary.revision_id, id.as_str());
                assert_eq!(summary.provenance, "active");
                assert_eq!(summary.activated_at_iso, "fixed-test-time");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn active_with_lkg_recovery_flips_pointer_to_lkg() {
        let (_dir, store) = fresh_state_store();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let lkg = rev("bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        store.set_active_revision(&active).unwrap();
        store.set_last_known_good(&lkg).unwrap();
        // Corrupt the active row's stored hash so check_integrity reports
        // PolicyIntegrityFailed for the active pointer.
        let conn = store.into_connection();
        conn.execute(
            "UPDATE active_revision SET integrity_hash = 'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();
        let store = SqliteStateStore::new(conn);

        let (repo, audit, loader) = loader_for(store, RecordingAudit::default());
        match loader.load() {
            PolicyLoadResult::LkgFallbackApplied(summary) => {
                assert_eq!(summary.revision_id, lkg.as_str());
                assert_eq!(summary.provenance, "recovery-fallback");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Active pointer was flipped to the LKG.
        let now_active = repo.get_active_revision().unwrap().unwrap();
        assert_eq!(now_active.as_str(), lkg.as_str());
        // Audit emitted started + completed.
        let events = audit.events.lock().unwrap().clone();
        assert!(matches!(
            events.first(),
            Some(RecoveryAuditEvent::LkgFallbackStarted { .. })
        ));
        assert!(matches!(
            events.last(),
            Some(RecoveryAuditEvent::LkgFallbackCompleted { .. })
        ));
    }

    #[test]
    fn active_corrupt_with_missing_lkg_requires_recovery() {
        let (_dir, store) = fresh_state_store();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        store.set_active_revision(&active).unwrap();
        let conn = store.into_connection();
        conn.execute(
            "UPDATE active_revision SET integrity_hash = 'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();
        let store = SqliteStateStore::new(conn);

        let (repo, audit, loader) = loader_for(store, RecordingAudit::default());
        match loader.load() {
            PolicyLoadResult::RecoveryRequired(msg) => {
                assert!(msg.contains("no usable LKG"), "msg = {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Active pointer is NOT silently mutated.
        let now_active = repo.get_active_revision().unwrap().unwrap();
        assert_eq!(now_active.as_str(), active.as_str());
        // Audit emitted RecoveryRequired (not LkgFallbackStarted).
        let events = audit.events.lock().unwrap().clone();
        assert!(matches!(
            events.first(),
            Some(RecoveryAuditEvent::RecoveryRequired { .. })
        ));
    }

    #[test]
    fn audit_write_failure_during_fallback_blocks_pointer_mutation() {
        let (_dir, store) = fresh_state_store();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let lkg = rev("bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        store.set_active_revision(&active).unwrap();
        store.set_last_known_good(&lkg).unwrap();
        let conn = store.into_connection();
        conn.execute(
            "UPDATE active_revision SET integrity_hash = 'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();
        let store = SqliteStateStore::new(conn);

        let audit = RecordingAudit {
            fail_on_started: true,
            ..Default::default()
        };
        let (repo, _audit, loader) = loader_for(store, audit);
        match loader.load() {
            PolicyLoadResult::RecoveryRequired(msg) => {
                assert!(msg.contains("audit write failed"), "msg = {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Active pointer must remain on the broken active — we refuse to
        // touch it without a durable audit event.
        let now_active = repo.get_active_revision().unwrap().unwrap();
        assert_eq!(now_active.as_str(), active.as_str());
    }

    #[test]
    fn lkg_with_corrupt_hash_blocks_silent_fallback() {
        let (_dir, store) = fresh_state_store();
        let active = rev("aaaa1111-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let lkg = rev("bbbb2222-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        store.set_active_revision(&active).unwrap();
        store.set_last_known_good(&lkg).unwrap();
        let conn = store.into_connection();
        // Corrupt LKG hash so check_integrity returns RequireUserAction.
        conn.execute(
            "UPDATE last_known_good SET integrity_hash = 'deadbeef' WHERE id = 1",
            [],
        )
        .unwrap();
        let store = SqliteStateStore::new(conn);

        let (repo, _audit, loader) = loader_for(store, RecordingAudit::default());
        match loader.load() {
            PolicyLoadResult::RecoveryRequired(msg) => {
                assert!(msg.contains("no usable LKG"), "msg = {msg}");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // Active pointer is unchanged.
        let now_active = repo.get_active_revision().unwrap().unwrap();
        assert_eq!(now_active.as_str(), active.as_str());
    }

    #[test]
    fn policy_state_mapping_is_total() {
        // Mapping covers every variant; future PolicyLoadResult variants
        // will fail to compile here unless added to to_policy_state.
        let cases = [
            (
                PolicyLoadResult::ActiveLoaded(ActiveRevisionState {
                    revision_id: "rev-x".into(),
                    provenance: "active".into(),
                    rule_count: 0,
                    behavior_mode: "auto".into(),
                    content_hash_hex: "deadbeef".into(),
                    activated_at_iso: "t".into(),
                }),
                ServicePolicyState::ActiveReady,
            ),
            (
                PolicyLoadResult::LkgFallbackApplied(ActiveRevisionState {
                    revision_id: "rev-y".into(),
                    provenance: "recovery-fallback".into(),
                    rule_count: 0,
                    behavior_mode: "auto".into(),
                    content_hash_hex: "deadbeef".into(),
                    activated_at_iso: "t".into(),
                }),
                ServicePolicyState::LkgReady,
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

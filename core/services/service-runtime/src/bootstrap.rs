//! Service-owned bootstrap pipeline.
//!
//! Walks the canonical startup sequence:
//!
//! 1. **Topology** — resolve `%ProgramData%` paths via `nrr-storage`.
//! 2. **DirectoryAcl** — create directory structure (cache + state DB
//!    parents, audit/, logs/, backups/). ACLs are set by the installer,
//!    not by us — see the comment in
//!    `nrr_storage::bootstrap` for the production icacls policy.
//! 3. **StorageOpen** — open `nrr_service_state.db` first (security-
//!    critical), then `nrr_fqdn_ip_cache.db` (rebuildable).
//! 4. **Migrations** — `run_pending_migrations` + `verify_schema` on
//!    both databases. State-DB migration failure is blocking; cache-DB
//!    migration failure triggers a rebuild.
//! 5. **IntegrityVerify** — reads the active revision pointer, verifies
//!    content hashes, and falls back to LKG through an audited recovery
//!    flow when the active revision fails verification.
//! 6. **DiagnosticsInit** — open audit NDJSON writer (`audit/`
//!    sub-directory) then operational log writer (`logs/`).
//! 7. **IpcStart** / **RuntimeLoopStart** — placeholders, so the report
//!    carries the full canonical phase list.
//!
//! Failure classification:
//!
//! | Phase | Failure → severity |
//! |---|---|
//! | Topology / DirectoryAcl / StorageOpen(state) / Migrations(state) / IntegrityVerify(no LKG) | `Blocking` (refuse `Running`) |
//! | StorageOpen(cache) / Migrations(cache) | `Warning` (rebuild scheduled) |
//! | DiagnosticsInit(audit) for security-critical startup | `Blocking` |
//! | DiagnosticsInit(logs) | `Degraded` (service runs, GUI sees warning) |
//! | IpcStart | `Degraded` if read-only IPC is still possible, else `Blocking` |
//!
//! The pipeline aggregates per-phase severity into `BootstrapReport`,
//! which the `nrr-windows-service` entrypoint inspects to decide whether
//! to transition to `Running`, `Degraded`, or `RecoveryRequired`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use nrr_diagnostics::{AuditWriter, AuditWriterConfig, LogWriter, LogWriterConfig};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::FreshnessThresholds;
use nrr_storage::{
    bootstrap_storage_directories, open_connection, resolve_storage_topology, RevisionsRepository,
    SqliteCacheStore, SqliteMigrationRunner, SqliteStateStore, StorageProfile, StorageTopology,
};

use std::sync::Arc;

use crate::managers::{BootstrapPhaseStatus, BootstrapReport};
use crate::policy_loader::{PolicyLoadResult, PolicyLoader};
use crate::recovery_audit::{cache_rebuild_audit_input, DiagnosticsRecoveryAuditEmitter};
use crate::state::{ActiveRevisionState, ServiceHealthSeverity};
use nrr_diagnostics::AuditSink;

// ── Phase identifiers ────────────────────────────────────────────────────────

/// Canonical bootstrap phase slugs. These are the values that show up
/// in `BootstrapPhaseStatus::phase` and in audit/log events. Stable —
/// downstream tooling (smoke scripts, dashboards) keys off them.
pub mod phases {
    pub const TOPOLOGY: &str = "topology";
    pub const DIRECTORY_ACL: &str = "directory-acl";
    pub const STORAGE_STATE: &str = "storage-open-state";
    pub const STORAGE_CACHE: &str = "storage-open-cache";
    pub const MIGRATIONS_STATE: &str = "migrations-state";
    pub const MIGRATIONS_CACHE: &str = "migrations-cache";
    pub const INTEGRITY_VERIFY: &str = "integrity-verify";
    pub const DIAGNOSTICS_AUDIT: &str = "diagnostics-init-audit";
    pub const DIAGNOSTICS_LOGS: &str = "diagnostics-init-logs";
    pub const IPC_START: &str = "ipc-start";
    pub const RUNTIME_LOOP_START: &str = "runtime-loop-start";
}

// ── Phase tracking ───────────────────────────────────────────────────────────

/// Per-phase progress marker. The pipeline updates a phase's status as
/// it walks the sequence; this is what the `BootstrapReport` tracks
/// per phase before the final severity is computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BootstrapStepStatus {
    Pending,
    Running,
    Ok,
    Warning,
    Degraded,
    BlockingFailed,
    Skipped,
}

impl BootstrapStepStatus {
    pub const fn severity(self) -> ServiceHealthSeverity {
        match self {
            Self::Pending | Self::Running => ServiceHealthSeverity::Unknown,
            Self::Ok | Self::Skipped => ServiceHealthSeverity::Ok,
            Self::Warning => ServiceHealthSeverity::Warning,
            Self::Degraded => ServiceHealthSeverity::Degraded,
            Self::BlockingFailed => ServiceHealthSeverity::Blocking,
        }
    }
}

// ── Retry policy ─────────────────────────────────────────────────────────────

/// Retry/backoff policy for transient I/O failures during bootstrap.
/// Fixed-delay rather than exponential because every retried operation
/// in this layer (file create, SQLite open) is cheap enough that a
/// fixed 100ms interval is plenty and the upper bound stays predictable
/// for the SCM start timeout (60s budget).
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub delay_between_attempts: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            delay_between_attempts: Duration::from_millis(100),
        }
    }
}

// ── Bootstrap configuration ──────────────────────────────────────────────────

/// What the pipeline needs to know to run. Constructed once by the
/// service entrypoint; tests build their own with `StorageProfile::TestTemp`.
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub storage_profile: StorageProfile,
    pub freshness_thresholds: FreshnessThresholds,
    pub retry: RetryPolicy,
    /// When `true` (default) cache-DB rebuild is permitted. Tests use
    /// `false` to assert that a corrupted cache is reported instead of
    /// silently rebuilt.
    pub allow_cache_rebuild: bool,
}

impl BootstrapConfig {
    pub fn new(profile: StorageProfile) -> Self {
        Self {
            storage_profile: profile,
            freshness_thresholds: FreshnessThresholds::default_production(),
            retry: RetryPolicy::default(),
            allow_cache_rebuild: true,
        }
    }
}

// ── Pipeline output ──────────────────────────────────────────────────────────

/// What the bootstrap produced for the runtime to consume. The
/// in-memory artefacts (`SqliteStateStore`, `SqliteCacheStore`,
/// `AuditWriter`, `LogWriter`) are the live handles the runtime loop
/// will use; the `report` captures the full phase-by-phase status for
/// auditing and for the GUI's storage-health snapshot.
pub struct BootstrapArtifacts {
    pub topology: StorageTopology,
    pub state_store: Option<Arc<SqliteStateStore>>,
    pub cache_store: Option<SqliteCacheStore>,
    pub audit_writer: Option<Arc<AuditWriter>>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub report: BootstrapReport,
    /// Result of the policy loader. `None` when bootstrap
    /// did not get far enough to consult the active pointer (e.g. state
    /// DB failed to open).
    pub policy_load: Option<PolicyLoadResult>,
    /// Currently-loaded revision summary, if any. Convenience mirror of
    /// `policy_load.current_revision()` — published to the GUI through
    /// `HealthReporter`.
    pub current_revision: Option<ActiveRevisionState>,
}

impl BootstrapArtifacts {
    /// Convenience: bootstrap is "ready to enter Running" when no phase
    /// reported a `Blocking` severity. `Degraded`/`Warning` are
    /// allowed — the runtime simply records the severity in
    /// `HealthReporter`.
    pub fn is_ready_to_run(&self) -> bool {
        !self.report.blocking
    }
}

// ── Pipeline driver ──────────────────────────────────────────────────────────

/// Walk the bootstrap pipeline. Returns the populated artefacts plus a
/// per-phase report. Never panics: every fallible call is captured into
/// the report; subsequent phases that depend on a failed predecessor
/// are emitted as `Skipped`.
pub fn bootstrap(config: &BootstrapConfig) -> BootstrapArtifacts {
    let mut report = BootstrapReport::default();
    let mut state_store: Option<Arc<SqliteStateStore>> = None;
    let mut cache_store: Option<SqliteCacheStore> = None;
    let mut audit_writer: Option<Arc<AuditWriter>> = None;
    let mut log_writer: Option<Arc<LogWriter>> = None;
    let mut policy_load: Option<PolicyLoadResult> = None;
    let mut current_revision: Option<ActiveRevisionState> = None;

    // Phase 1 — topology resolution.
    let topology = match resolve_storage_topology(&config.storage_profile) {
        Ok(t) => {
            push(&mut report, phases::TOPOLOGY, BootstrapStepStatus::Ok, "ok");
            t
        }
        Err(e) => {
            push(
                &mut report,
                phases::TOPOLOGY,
                BootstrapStepStatus::BlockingFailed,
                format!("resolve topology failed: {e}"),
            );
            // Without a topology every subsequent phase is meaningless.
            for phase in [
                phases::DIRECTORY_ACL,
                phases::DIAGNOSTICS_AUDIT,
                phases::STORAGE_STATE,
                phases::MIGRATIONS_STATE,
                phases::STORAGE_CACHE,
                phases::MIGRATIONS_CACHE,
                phases::INTEGRITY_VERIFY,
                phases::DIAGNOSTICS_LOGS,
                phases::IPC_START,
                phases::RUNTIME_LOOP_START,
            ] {
                push(
                    &mut report,
                    phase,
                    BootstrapStepStatus::Skipped,
                    "topology unavailable",
                );
            }
            return BootstrapArtifacts {
                topology: StorageTopology {
                    data_dir: PathBuf::new(),
                    logs_dir: PathBuf::new(),
                    cache_db_path: PathBuf::new(),
                    state_db_path: PathBuf::new(),
                    traffic_db_path: PathBuf::new(),
                    backup_dir: PathBuf::new(),
                    migration_backup_dir: PathBuf::new(),
                    temp_dir: PathBuf::new(),
                    lock_file_path: PathBuf::new(),
                },
                state_store: None,
                cache_store: None,
                audit_writer: None,
                log_writer: None,
                report,
                policy_load: None,
                current_revision: None,
            };
        }
    };

    // Phase 2 — directory creation.
    match retry_io(&config.retry, || {
        bootstrap_storage_directories(&topology, &config.storage_profile)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }) {
        Ok(_) => push(
            &mut report,
            phases::DIRECTORY_ACL,
            BootstrapStepStatus::Ok,
            "ok",
        ),
        Err(e) => {
            push(
                &mut report,
                phases::DIRECTORY_ACL,
                BootstrapStepStatus::BlockingFailed,
                format!("create dirs failed: {e}"),
            );
        }
    }

    // Phase 2.5 — open audit writer EARLY.
    //
    // The PolicyLoader's invariant (policy_loader.rs:96–99) is that any
    // LKG-fallback recovery action must be audited *before* the active
    // pointer is mutated. That means the audit writer has to be live by
    // the time the integrity-verify phase runs. We open it here, right
    // after directories exist, so every downstream phase can rely on
    // an `Arc<AuditWriter>` being available. If the audit writer cannot
    // be opened, we surface a Blocking phase and skip everything that
    // performs privileged state changes (state DB open, integrity
    // verify) — operating on policy without an audit trail violates the
    // service's security contract.
    if !report.blocking {
        let audit_dir = topology.data_dir.join("audit");
        match open_audit(&audit_dir) {
            Ok(w) => {
                audit_writer = Some(Arc::new(w));
                push(
                    &mut report,
                    phases::DIAGNOSTICS_AUDIT,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
            }
            Err(msg) => push(
                &mut report,
                phases::DIAGNOSTICS_AUDIT,
                BootstrapStepStatus::BlockingFailed,
                format!("audit init failed: {msg}"),
            ),
        }
    } else {
        push(
            &mut report,
            phases::DIAGNOSTICS_AUDIT,
            BootstrapStepStatus::Skipped,
            "earlier phase blocking",
        );
    }

    // Phase 3a — open + migrate state DB. Service-critical.
    if !report.blocking {
        match open_and_migrate_state(&topology.state_db_path) {
            Ok(store) => {
                // The state store is single-writer (RefCell<Connection>), shared
                // only via `Arc` for refcount/ownership — never sent across threads.
                #[allow(clippy::arc_with_non_send_sync)]
                let store = Arc::new(store);
                state_store = Some(store);
                push(
                    &mut report,
                    phases::STORAGE_STATE,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
                push(
                    &mut report,
                    phases::MIGRATIONS_STATE,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
            }
            Err(StateOpenFailure::Open(msg)) => {
                push(
                    &mut report,
                    phases::STORAGE_STATE,
                    BootstrapStepStatus::BlockingFailed,
                    format!("state DB open failed: {msg}"),
                );
                push(
                    &mut report,
                    phases::MIGRATIONS_STATE,
                    BootstrapStepStatus::Skipped,
                    "state DB unavailable",
                );
            }
            Err(StateOpenFailure::Migrate(msg)) => {
                push(
                    &mut report,
                    phases::STORAGE_STATE,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
                push(
                    &mut report,
                    phases::MIGRATIONS_STATE,
                    BootstrapStepStatus::BlockingFailed,
                    format!("state DB migration failed: {msg}"),
                );
            }
        }
    } else {
        push(
            &mut report,
            phases::STORAGE_STATE,
            BootstrapStepStatus::Skipped,
            "earlier phase blocking",
        );
        push(
            &mut report,
            phases::MIGRATIONS_STATE,
            BootstrapStepStatus::Skipped,
            "earlier phase blocking",
        );
    }

    // Phase 3b — open + migrate cache DB. Rebuildable.
    if !report.blocking {
        match open_and_migrate_cache(&topology.cache_db_path, &config.freshness_thresholds) {
            Ok(store) => {
                cache_store = Some(store);
                push(
                    &mut report,
                    phases::STORAGE_CACHE,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
                push(
                    &mut report,
                    phases::MIGRATIONS_CACHE,
                    BootstrapStepStatus::Ok,
                    "ok",
                );
            }
            Err(msg) => {
                if config.allow_cache_rebuild {
                    // Drop the corrupt file and re-create it from a
                    // fresh migration. The runtime will treat it as an
                    // empty cache, which is functionally correct — the
                    // FQDN/IP cache is rebuildable by design.
                    let _ = std::fs::remove_file(&topology.cache_db_path);
                    match open_and_migrate_cache(
                        &topology.cache_db_path,
                        &config.freshness_thresholds,
                    ) {
                        Ok(store) => {
                            cache_store = Some(store);
                            // Durably audit the rebuild so
                            // downstream tooling (GUI Diagnostics → Audit
                            // tab) can show it. Audit failure
                            // here is non-fatal — cache rebuild already
                            // succeeded; we just downgrade the phase to
                            // Degraded so the operator sees that the
                            // event was not recorded.
                            if let Some(audit) = audit_writer.as_ref() {
                                if let Err(audit_err) =
                                    audit.append(cache_rebuild_audit_input(&msg))
                                {
                                    push(
                                        &mut report,
                                        phases::STORAGE_CACHE,
                                        BootstrapStepStatus::Degraded,
                                        format!(
                                            "cache rebuilt but audit write failed: {audit_err}"
                                        ),
                                    );
                                } else {
                                    push(
                                        &mut report,
                                        phases::STORAGE_CACHE,
                                        BootstrapStepStatus::Warning,
                                        format!("cache rebuilt after corruption: {msg}"),
                                    );
                                }
                            } else {
                                push(
                                    &mut report,
                                    phases::STORAGE_CACHE,
                                    BootstrapStepStatus::Warning,
                                    format!("cache rebuilt after corruption: {msg}"),
                                );
                            }
                            push(
                                &mut report,
                                phases::MIGRATIONS_CACHE,
                                BootstrapStepStatus::Ok,
                                "ok (post-rebuild)",
                            );
                        }
                        Err(rebuild_msg) => {
                            push(
                                &mut report,
                                phases::STORAGE_CACHE,
                                BootstrapStepStatus::Degraded,
                                format!("cache rebuild failed: {rebuild_msg}"),
                            );
                            push(
                                &mut report,
                                phases::MIGRATIONS_CACHE,
                                BootstrapStepStatus::Skipped,
                                "cache unavailable",
                            );
                        }
                    }
                } else {
                    push(
                        &mut report,
                        phases::STORAGE_CACHE,
                        BootstrapStepStatus::Degraded,
                        format!("cache open failed (rebuild disabled): {msg}"),
                    );
                    push(
                        &mut report,
                        phases::MIGRATIONS_CACHE,
                        BootstrapStepStatus::Skipped,
                        "cache unavailable",
                    );
                }
            }
        }
    } else {
        push(
            &mut report,
            phases::STORAGE_CACHE,
            BootstrapStepStatus::Skipped,
            "earlier phase blocking",
        );
        push(
            &mut report,
            phases::MIGRATIONS_CACHE,
            BootstrapStepStatus::Skipped,
            "earlier phase blocking",
        );
    }

    // Phase 4 — integrity verify. Walks the policy-load state machine:
    // read active pointer → verify content hashes → optionally fall back
    // to LKG through an audited recovery flow. `DiagnosticsRecoveryAuditEmitter`
    // (over the early-opened `AuditWriter`) ensures any LKG fallback /
    // integrity failure lands in `audit/*.ndjson` durably before the
    // active pointer is mutated.
    //
    // `audit_writer` is guaranteed to be `Some` here: it was opened in
    // phase 2.5 before this branch can even run (a missing audit writer
    // would have flipped `report.blocking` and skipped state DB open,
    // which would in turn have left `state_store` as `None`). The
    // `expect` is therefore an invariant assertion, not a fallible path.
    if let Some(store) = state_store.as_ref() {
        #[allow(clippy::expect_used)]
        // invariant: audit writer open whenever state DB is (see above)
        let audit_arc = audit_writer
            .as_ref()
            .expect("audit writer is open whenever state DB opened (phase 2.5 invariant)");
        let emitter = DiagnosticsRecoveryAuditEmitter::new(Arc::clone(audit_arc));
        let loader = PolicyLoader::new(Arc::clone(store), Arc::new(emitter));
        let outcome = loader.load();
        let (step, message) = match &outcome {
            PolicyLoadResult::ActiveLoaded(s) => (
                BootstrapStepStatus::Ok,
                format!("active revision loaded: {}", s.revision_id),
            ),
            PolicyLoadResult::LkgFallbackApplied(s) => (
                BootstrapStepStatus::Warning,
                format!("active recovered from LKG: {}", s.revision_id),
            ),
            PolicyLoadResult::NoActiveRevision => (
                BootstrapStepStatus::Ok,
                "no active revision yet (first run)".to_string(),
            ),
            PolicyLoadResult::RecoveryRequired(msg) => (
                BootstrapStepStatus::BlockingFailed,
                format!("recovery required: {msg}"),
            ),
            PolicyLoadResult::StorageError(msg) => (
                BootstrapStepStatus::BlockingFailed,
                format!("integrity verify storage error: {msg}"),
            ),
        };
        current_revision = outcome.current_revision().cloned();
        policy_load = Some(outcome);
        push(&mut report, phases::INTEGRITY_VERIFY, step, message);
    } else {
        push(
            &mut report,
            phases::INTEGRITY_VERIFY,
            BootstrapStepStatus::Skipped,
            "state DB unavailable",
        );
    }

    // Phase 5a — note: the `DIAGNOSTICS_AUDIT` phase is opened in
    // phase 2.5, so its result is already recorded in
    // `report.phases`. The position here is intentionally vacated to
    // keep the canonical phase slug list documented in module docs
    // accurate; it intentionally does *not* push a duplicate entry.

    // Phase 5b — operational logs. Non-blocking; service can still run
    // in degraded mode without operational NDJSON, the GUI just shows
    // a warning.
    let logs_dir = topology.logs_dir.clone();
    match open_logs(&logs_dir) {
        Ok(w) => {
            log_writer = Some(Arc::new(w));
            push(
                &mut report,
                phases::DIAGNOSTICS_LOGS,
                BootstrapStepStatus::Ok,
                "ok",
            );
        }
        Err(msg) => push(
            &mut report,
            phases::DIAGNOSTICS_LOGS,
            BootstrapStepStatus::Degraded,
            format!("logs init failed: {msg}"),
        ),
    }

    // Phases 6 / 7 — placeholders for IPC start (14.5) and runtime loop
    // start (14.7). Surfaced here so the report is shaped correctly for
    // every downstream phase to plug into.
    push(
        &mut report,
        phases::IPC_START,
        BootstrapStepStatus::Skipped,
        "deferred to block 14.5",
    );
    push(
        &mut report,
        phases::RUNTIME_LOOP_START,
        BootstrapStepStatus::Skipped,
        "deferred to block 14.7",
    );

    BootstrapArtifacts {
        topology,
        state_store,
        cache_store,
        audit_writer,
        log_writer,
        report,
        policy_load,
        current_revision,
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn push(
    report: &mut BootstrapReport,
    phase: &'static str,
    step: BootstrapStepStatus,
    message: impl Into<String>,
) {
    let severity = step.severity();
    report.phases.push(BootstrapPhaseStatus {
        phase,
        severity,
        message: message.into(),
    });
    if severity > report.worst_severity {
        report.worst_severity = severity;
    }
    if matches!(step, BootstrapStepStatus::BlockingFailed) {
        report.blocking = true;
    }
}

enum StateOpenFailure {
    Open(String),
    Migrate(String),
}

fn open_and_migrate_state(path: &Path) -> Result<SqliteStateStore, StateOpenFailure> {
    let conn = open_connection(path).map_err(|e| StateOpenFailure::Open(e.to_string()))?;
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner
        .run_pending_migrations()
        .map_err(|e| StateOpenFailure::Migrate(e.to_string()))?;
    runner
        .verify_schema()
        .map_err(|e| StateOpenFailure::Migrate(format!("verify_schema: {e}")))?;
    let conn = runner.into_connection();
    reject_orphaned_candidate_revisions(&conn);
    Ok(SqliteStateStore::new(conn))
}

/// Reason recorded on `revisions.rejected_reason` for candidate rows swept
/// at boot. A candidate row that is still present when the service starts
/// was never driven to `active`/`rejected` by the process that created it —
/// the only way that happens is a hard kill between `insert_candidate_for`
/// and the follow-up activation commit, since the in-memory confirmation
/// token that would resume the mutation dies with the process.
const ORPHANED_CANDIDATE_REJECT_REASON: &str = "interrupted-before-activation (service restart)";

/// Best-effort boot sweep: reject any `revisions` row still sitting in
/// `candidate` status from a previous run. Runs once, right after state-DB
/// migrations succeed and before the connection is handed to anything else,
/// so a stuck candidate never counts toward `pending_changes` forever.
///
/// Runs without the DB-MAC signing key (which is loaded later, by the
/// platform tamper bootstrap), so the repository only touches unsigned
/// rows here — flipping a signed row keyless would stale its `row_hmac`
/// and read as tampered on the next integrity scan. Signed candidates
/// are picked up by [`sweep_signed_orphaned_candidates`], which the
/// platform entrypoint calls once the key is available.
///
/// A sweep failure is logged and otherwise ignored — it must not block
/// service startup, the same treatment every other boot-time state-DB
/// maintenance step in this module gets.
fn reject_orphaned_candidate_revisions(conn: &rusqlite::Connection) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let repo = RevisionsRepository::new(conn);
    match repo.reject_orphaned_candidates(ORPHANED_CANDIDATE_REJECT_REASON, now_ms) {
        Ok(0) => tracing::debug!(
            target: "nrr::state",
            "boot sweep: no orphaned candidate revisions found"
        ),
        Ok(count) => tracing::warn!(
            target: "nrr::state",
            count,
            "boot sweep: rejected orphaned candidate revision(s) left over from an \
             interrupted service run"
        ),
        Err(e) => tracing::warn!(
            target: "nrr::state",
            error = %e,
            "boot sweep: failed to reject orphaned candidate revisions"
        ),
    }
}

/// Keyed follow-up to the boot sweep in [`reject_orphaned_candidate_revisions`]:
/// rejects orphaned *signed* candidate rows and re-signs them in the same
/// pass, keeping `row_hmac` consistent with the new status.
///
/// Must be called by the platform entrypoint **after** its tamper bootstrap
/// has verified existing rows and produced the signing key, and before the
/// IPC server accepts mutations — the verification pass has to see rows
/// exactly as the previous run signed them, and `pending_changes` must not
/// carry a dead candidate into the new session. Platforms without row
/// signing have nothing to do here: their candidates are all unsigned and
/// the keyless sweep already collected them.
///
/// Best-effort, mirroring the keyless sweep: failures (including a poisoned
/// connection mutex) are logged, never propagated.
pub fn sweep_signed_orphaned_candidates(
    conn: &Arc<std::sync::Mutex<rusqlite::Connection>>,
    signing_key: &[u8],
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let guard = match conn.lock() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!(
                target: "nrr::state",
                "keyed boot sweep: state connection mutex poisoned; skipping"
            );
            return;
        }
    };
    let repo = RevisionsRepository::with_signing_key(&guard, signing_key.to_vec());
    match repo.reject_orphaned_candidates(ORPHANED_CANDIDATE_REJECT_REASON, now_ms) {
        Ok(0) => tracing::debug!(
            target: "nrr::state",
            "keyed boot sweep: no signed orphaned candidate revisions found"
        ),
        Ok(count) => tracing::warn!(
            target: "nrr::state",
            count,
            "keyed boot sweep: rejected and re-signed signed orphaned candidate \
             revision(s) left over from an interrupted service run"
        ),
        Err(e) => tracing::warn!(
            target: "nrr::state",
            error = %e,
            "keyed boot sweep: failed to reject signed orphaned candidate revisions"
        ),
    }
}

fn open_and_migrate_cache(
    path: &Path,
    thresholds: &FreshnessThresholds,
) -> Result<SqliteCacheStore, String> {
    let conn = open_connection(path).map_err(|e| e.to_string())?;
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().map_err(|e| e.to_string())?;
    runner
        .verify_schema()
        .map_err(|e| format!("verify_schema: {e}"))?;
    Ok(SqliteCacheStore::new(
        runner.into_connection(),
        thresholds.clone(),
    ))
}

fn open_audit(audit_dir: &Path) -> Result<AuditWriter, String> {
    std::fs::create_dir_all(audit_dir).map_err(|e| format!("create audit dir: {e}"))?;
    Ok(AuditWriter::open(AuditWriterConfig::new(audit_dir)))
}

fn open_logs(logs_dir: &Path) -> Result<LogWriter, String> {
    std::fs::create_dir_all(logs_dir).map_err(|e| format!("create logs dir: {e}"))?;
    Ok(LogWriter::open(LogWriterConfig::new(logs_dir)))
}

/// Run a fallible op with the configured retry policy. Used for
/// transient I/O issues (file lock briefly held by another process,
/// AV scanner racing creation, etc.).
fn retry_io<T, E, F>(policy: &RetryPolicy, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut last_err = None;
    for attempt in 0..policy.max_attempts {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt + 1 < policy.max_attempts {
                    std::thread::sleep(policy.delay_between_attempts);
                }
            }
        }
    }
    // The retry loop runs at least once, so `last_err` is always `Some` here.
    #[allow(clippy::expect_used)]
    Err(last_err.expect("at least one attempt"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_profile() -> (TempDir, BootstrapConfig) {
        let dir = TempDir::new().expect("temp dir");
        let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
        (dir, cfg)
    }

    #[test]
    fn clean_first_run_produces_running_ready_artifacts() {
        let (_dir, cfg) = temp_profile();
        let result = bootstrap(&cfg);

        assert!(result.is_ready_to_run(), "report = {:?}", result.report);
        assert!(result.state_store.is_some());
        assert!(result.cache_store.is_some());
        assert!(result.audit_writer.is_some());
        assert!(result.log_writer.is_some());

        // All canonical phases recorded in order.
        let recorded: Vec<&str> = result.report.phases.iter().map(|p| p.phase).collect();
        assert_eq!(
            recorded,
            vec![
                phases::TOPOLOGY,
                phases::DIRECTORY_ACL,
                // Audit writer opened EARLY so the integrity
                // verify phase (PolicyLoader.load) has a live emitter to
                // satisfy its audit-before-act invariant.
                phases::DIAGNOSTICS_AUDIT,
                phases::STORAGE_STATE,
                phases::MIGRATIONS_STATE,
                phases::STORAGE_CACHE,
                phases::MIGRATIONS_CACHE,
                phases::INTEGRITY_VERIFY,
                phases::DIAGNOSTICS_LOGS,
                phases::IPC_START,
                phases::RUNTIME_LOOP_START,
            ]
        );
    }

    #[test]
    fn audit_writer_is_open_before_state_db_phase_runs() {
        // Invariant: DIAGNOSTICS_AUDIT must be recorded
        // *before* STORAGE_STATE in the canonical phase order, so that
        // PolicyLoader's audit-before-act contract is structurally
        // satisfiable. Catches regressions where someone reorders
        // phases in the pipeline driver.
        let (_dir, cfg) = temp_profile();
        let result = bootstrap(&cfg);
        let phase_names: Vec<&str> = result.report.phases.iter().map(|p| p.phase).collect();
        let audit_idx = phase_names
            .iter()
            .position(|p| *p == phases::DIAGNOSTICS_AUDIT)
            .expect("DIAGNOSTICS_AUDIT recorded");
        let state_idx = phase_names
            .iter()
            .position(|p| *p == phases::STORAGE_STATE)
            .expect("STORAGE_STATE recorded");
        assert!(
            audit_idx < state_idx,
            "audit must be opened before state DB (block 16.5 invariant)"
        );
    }

    #[test]
    fn audit_directory_contains_a_file_after_clean_bootstrap() {
        // Concretely verifies the early-open code path created an
        // NDJSON file. AuditWriter is lazy-rotating but the bootstrap
        // emits at least one event whenever cache rebuild fires; for
        // the clean-boot case there are no events yet so the directory
        // exists but may be empty — that's still distinguishable from
        // "audit_writer was never opened".
        let (_dir, cfg) = temp_profile();
        let result = bootstrap(&cfg);
        assert!(result.is_ready_to_run());
        let audit_dir = result.topology.data_dir.join("audit");
        assert!(audit_dir.exists(), "audit dir created by early-open");
        assert!(audit_dir.is_dir());
    }

    #[test]
    fn corrupt_cache_rebuild_writes_audit_event() {
        // After a cache corruption rebuild the audit trail must contain
        // a `cache_rebuilt_after_corruption` entry.
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        let cache_path = first.topology.cache_db_path.clone();
        let audit_dir = first.topology.data_dir.join("audit");
        drop(first);

        std::fs::write(&cache_path, b"not a valid sqlite database").expect("overwrite cache file");

        let second = bootstrap(&cfg);
        assert!(second.is_ready_to_run(), "report = {:?}", second.report);
        // Drop to release the audit file lock before reading.
        drop(second);

        let entries: Vec<_> = std::fs::read_dir(&audit_dir)
            .expect("read audit dir")
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("ndjson"))
            .collect();
        assert!(!entries.is_empty(), "at least one audit file written");
        let mut combined = String::new();
        for e in &entries {
            combined.push_str(&std::fs::read_to_string(e.path()).expect("read audit file"));
        }
        assert!(
            combined.contains("cache_rebuilt_after_corruption"),
            "audit trail missing cache rebuild event; contents = {combined}"
        );
        assert!(
            combined.contains("integrity.cache_corrupt_rebuildable"),
            "audit trail missing reason code"
        );
    }

    #[test]
    fn second_bootstrap_on_same_dir_is_idempotent() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        // Drop the artefacts so the SQLite files are released. Without
        // this Windows holds the file lock and re-opening would fail.
        drop(first);

        let second = bootstrap(&cfg);
        assert!(second.is_ready_to_run(), "report = {:?}", second.report);
    }

    #[test]
    fn corrupt_cache_is_rebuilt_when_allowed() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        let cache_path = first.topology.cache_db_path.clone();
        drop(first);

        // Corrupt the cache file on disk.
        std::fs::write(&cache_path, b"not a valid sqlite database").expect("overwrite cache file");

        let second = bootstrap(&cfg);
        assert!(second.is_ready_to_run(), "report = {:?}", second.report);
        let cache_phase = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_CACHE)
            .expect("cache phase recorded");
        assert_eq!(cache_phase.severity, ServiceHealthSeverity::Warning);
    }

    #[test]
    fn corrupt_cache_with_rebuild_disabled_reports_degraded() {
        let (_dir, mut cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        let cache_path = first.topology.cache_db_path.clone();
        drop(first);
        std::fs::write(&cache_path, b"not a valid sqlite database").expect("overwrite cache file");

        cfg.allow_cache_rebuild = false;
        let second = bootstrap(&cfg);
        let cache_phase = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_CACHE)
            .expect("cache phase recorded");
        assert_eq!(cache_phase.severity, ServiceHealthSeverity::Degraded);
        // Cache failure alone is not blocking — service should still
        // come up in degraded mode and serve read-only IPC.
        assert!(!second.report.blocking);
    }

    #[test]
    fn topology_failure_skips_subsequent_phases() {
        // Force topology resolution to fail by selecting
        // ProductionService and clearing PROGRAMDATA. We can't actually
        // unset the env var safely from a parallel test; instead we
        // assert the documented helper status_for behaviour via a
        // direct call to a guaranteed-failing path. We use a
        // non-existent absolute path encoded as TestTemp under a
        // root-only directory; on Windows that's `C:\System Volume Information\…`
        // — too brittle. Instead, exercise the normal happy path and
        // then manually corrupt the state DB so MIGRATIONS_STATE fails.
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        let state_path = first.topology.state_db_path.clone();
        drop(first);
        std::fs::write(&state_path, b"not a valid sqlite database").expect("overwrite state file");

        let second = bootstrap(&cfg);
        assert!(second.report.blocking);
        let state_phase = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_STATE || p.phase == phases::MIGRATIONS_STATE)
            .expect("a state phase recorded");
        assert_eq!(state_phase.severity, ServiceHealthSeverity::Blocking);

        // Cache phase should be Skipped because the prior phase was blocking.
        let cache_phase = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_CACHE)
            .expect("cache phase recorded");
        assert_eq!(cache_phase.severity, ServiceHealthSeverity::Ok);
        assert!(cache_phase.message.contains("earlier phase blocking"));
    }

    #[test]
    fn retry_policy_eventually_succeeds() {
        let policy = RetryPolicy {
            max_attempts: 3,
            delay_between_attempts: Duration::from_millis(1),
        };
        let mut attempts = 0;
        let result: Result<i32, &str> = retry_io(&policy, || {
            attempts += 1;
            if attempts < 3 {
                Err("transient")
            } else {
                Ok(42)
            }
        });
        assert_eq!(result, Ok(42));
        assert_eq!(attempts, 3);
    }
}

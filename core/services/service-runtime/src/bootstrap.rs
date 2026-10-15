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
    /// The apply-marker assessment the platform entrypoint runs after bootstrap.
    pub const CRASH_RECOVERY: &str = "crash-recovery";
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
/// Delete a SQLite database together with its WAL sidecars.
///
/// Every store here runs in WAL mode, so a database is three files. Removing
/// only the `.db` leaves `-wal` and `-shm` behind, and the fresh database
/// created next opens beside a write-ahead log written for the file that no
/// longer exists — the corruption we were recovering from, carried forward.
fn remove_sqlite_triplet(db_path: &Path) {
    let _ = std::fs::remove_file(db_path);
    for suffix in SQLITE_SIDECARS {
        let _ = std::fs::remove_file(with_suffix(db_path, suffix));
    }
}

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
                let integrity = w.tail_integrity().clone();
                audit_writer = Some(Arc::new(w));
                if let nrr_diagnostics::AuditTailIntegrity::Truncated {
                    anchor_seq,
                    found_seq,
                } = integrity
                {
                    // The chain now continues from the anchor, so the gap stays
                    // visible in the files; say so where an operator will see it.
                    tracing::error!(
                        target: "nrr::audit",
                        msg_key = "bootstrap-audit-tail-truncated",
                        anchor_seq,
                        found_seq = found_seq.unwrap_or(0),
                        "audit tail is shorter than the anchor — events were removed"
                    );
                    push(
                        &mut report,
                        phases::DIAGNOSTICS_AUDIT,
                        BootstrapStepStatus::Degraded,
                        format!(
                            "audit tail truncated: anchored seq {anchor_seq}, found {}",
                            found_seq
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "none".to_string())
                        ),
                    );
                } else {
                    push(
                        &mut report,
                        phases::DIAGNOSTICS_AUDIT,
                        BootstrapStepStatus::Ok,
                        "ok",
                    );
                }
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
        let opened = open_and_migrate_state(&topology.state_db_path, &config.retry);
        // A database that will not open or migrate blocks the start, and a
        // blocked start protects nobody. The last snapshot is worth more than
        // that; the damaged file is kept beside it for whoever investigates.
        let opened = opened.or_else(|failure| {
            // A newer build's database is not damaged: replacing it with an
            // older snapshot would quietly undo every change made since.
            if matches!(failure, StateOpenFailure::NewerSchema(_)) {
                return Err(failure);
            }
            match restore_state_db_from_backup(&topology, &config.retry) {
                Ok((store, restored)) => {
                    tracing::error!(
                        target: "nrr::bootstrap",
                        msg_key = "svc-boot-state-db-restored-from-backup",
                        failure = %failure.message(),
                        backup = %restored.backup.display(),
                        damaged = %restored.damaged.display(),
                        "the state database could not be used and was restored from its newest backup — changes made after that backup are gone; the damaged file is kept",
                    );
                    push(
                        &mut report,
                        phases::STORAGE_STATE,
                        BootstrapStepStatus::Degraded,
                        format!(
                            "state DB restored from backup {} after: {}; damaged copy kept at {}",
                            restored.backup.display(),
                            failure.message(),
                            restored.damaged.display()
                        ),
                    );
                    Ok(store)
                }
                Err(restore) => Err(failure.with_restore_attempt(&restore)),
            }
        });
        match opened {
            Ok(store) => {
                // The state store is single-writer (RefCell<Connection>), shared
                // only via `Arc` for refcount/ownership — never sent across threads.
                #[allow(clippy::arc_with_non_send_sync)]
                let store = Arc::new(store);
                state_store = Some(store);
                if !report
                    .phases
                    .iter()
                    .any(|p| p.phase == phases::STORAGE_STATE)
                {
                    push(
                        &mut report,
                        phases::STORAGE_STATE,
                        BootstrapStepStatus::Ok,
                        "ok",
                    );
                }
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
            Err(StateOpenFailure::Migrate(msg) | StateOpenFailure::NewerSchema(msg)) => {
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
        match open_and_migrate_cache(
            &topology.cache_db_path,
            &config.freshness_thresholds,
            &config.retry,
        ) {
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
                    // Drop the corrupt database and re-create it from a
                    // fresh migration. The runtime will treat it as an
                    // empty cache, which is functionally correct — the
                    // FQDN/IP cache is rebuildable by design.
                    remove_sqlite_triplet(&topology.cache_db_path);
                    match open_and_migrate_cache(
                        &topology.cache_db_path,
                        &config.freshness_thresholds,
                        &config.retry,
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

    // Phase 4 — integrity verify. The keyless loader reports what it finds
    // (durably, through the early-opened `AuditWriter`) and changes nothing;
    // the keyed per-principal sweep recovers once the signing key is loaded.
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
            PolicyLoadResult::IntegrityFailureReported(details) => (
                BootstrapStepStatus::Warning,
                format!("integrity failure reported: {details}"),
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

    // Phases 6 / 7 — placeholders for IPC start and runtime loop start, not
    // yet implemented. Surfaced here so the report is shaped correctly for
    // every downstream phase to plug into.
    push(
        &mut report,
        phases::IPC_START,
        BootstrapStepStatus::Skipped,
        "not yet implemented",
    );
    push(
        &mut report,
        phases::RUNTIME_LOOP_START,
        BootstrapStepStatus::Skipped,
        "not yet implemented",
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
    /// Written by a newer build; nothing to repair.
    NewerSchema(String),
}

impl StateOpenFailure {
    fn message(&self) -> &str {
        match self {
            Self::Open(m) | Self::Migrate(m) | Self::NewerSchema(m) => m,
        }
    }

    /// The same failure, saying why no backup replaced the database either.
    fn with_restore_attempt(self, restore: &str) -> Self {
        match self {
            Self::Open(m) => Self::Open(format!("{m}; backup restore: {restore}")),
            Self::Migrate(m) => Self::Migrate(format!("{m}; backup restore: {restore}")),
            Self::NewerSchema(m) => Self::NewerSchema(m),
        }
    }
}

/// What a backup restore left behind.
struct RestoredStateDb {
    /// The snapshot now in place.
    backup: PathBuf,
    /// Where the unusable database was moved.
    damaged: PathBuf,
}

/// Replace an unusable state database with its newest backup that opens and
/// migrates. Snapshots the migration runner and the update verb made are the
/// candidates, newest first; the damaged file is moved into the backup
/// directory, never deleted.
fn restore_state_db_from_backup(
    topology: &StorageTopology,
    retry: &RetryPolicy,
) -> Result<(SqliteStateStore, RestoredStateDb), String> {
    let candidates = state_db_backups_newest_first(topology);
    if candidates.is_empty() {
        return Err("no backup of the state database exists".to_string());
    }
    let damaged = park_damaged_state_db(topology)?;
    let mut last_error = String::new();
    for backup in candidates {
        if let Err(e) = std::fs::copy(&backup, &topology.state_db_path) {
            last_error = format!("copy {}: {e}", backup.display());
            continue;
        }
        match open_and_migrate_state(&topology.state_db_path, retry) {
            Ok(store) => return Ok((store, RestoredStateDb { backup, damaged })),
            Err(e) => {
                last_error = format!("{}: {}", backup.display(), e.message());
                remove_sqlite_triplet(&topology.state_db_path);
            }
        }
    }
    let put_back = put_damaged_state_db_back(topology, &damaged);
    Err(format!(
        "no backup could be used; last: {last_error}; the original {}",
        match put_back {
            Ok(()) => "is back in place".to_string(),
            Err(e) => format!("could not be put back: {e}"),
        }
    ))
}

/// Every snapshot of the state database on disk, newest first. Bounded to
/// what the backup retention keeps, so a directory somebody filled by hand
/// cannot turn the start into a tour of it.
fn state_db_backups_newest_first(topology: &StorageTopology) -> Vec<PathBuf> {
    let Some(stem) = topology
        .state_db_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_owned)
    else {
        return Vec::new();
    };
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for dir in [&topology.backup_dir, &topology.migration_backup_dir] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let is_snapshot =
                name.starts_with(&stem) && name.ends_with(".db") && !name.contains(".damaged-");
            if !is_snapshot {
                continue;
            }
            if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                found.push((modified, path));
            }
        }
    }
    // The update verb's copy sits beside the database itself.
    let update_copy = topology.state_db_path.with_extension("db.bak");
    if let Ok(modified) = std::fs::metadata(&update_copy).and_then(|m| m.modified()) {
        found.push((modified, update_copy));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found
        .into_iter()
        .map(|(_, path)| path)
        .take(nrr_storage::backup::BACKUP_RETENTION_PER_DATABASE)
        .collect()
}

/// Move the unusable database into the backup directory and drop its
/// write-ahead sidecars: left beside the restored file they would be applied
/// to it.
fn park_damaged_state_db(topology: &StorageTopology) -> Result<PathBuf, String> {
    let stem = topology
        .state_db_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "state DB path has no file stem".to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();
    std::fs::create_dir_all(&topology.backup_dir)
        .map_err(|e| format!("create {}: {e}", topology.backup_dir.display()))?;
    let parked = topology
        .backup_dir
        .join(format!("{stem}.damaged-{stamp}.db"));
    match std::fs::rename(&topology.state_db_path, &parked) {
        Ok(()) => {}
        // A database that never came into being leaves nothing to keep.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("move damaged state DB aside: {e}")),
    }
    // The journal may hold the last changes; it travels with its database.
    for suffix in SQLITE_SIDECARS {
        let _ = std::fs::rename(
            with_suffix(&topology.state_db_path, suffix),
            with_suffix(&parked, suffix),
        );
    }
    remove_sqlite_triplet(&topology.state_db_path);
    Ok(parked)
}

/// Undo [`park_damaged_state_db`] when no backup could replace the database:
/// with nothing in place, the next start would create an empty one and run
/// with no rules and none of the protection the user had set.
fn put_damaged_state_db_back(topology: &StorageTopology, parked: &Path) -> Result<(), String> {
    if !parked.exists() {
        return Ok(());
    }
    remove_sqlite_triplet(&topology.state_db_path);
    std::fs::rename(parked, &topology.state_db_path)
        .map_err(|e| format!("move {} back: {e}", parked.display()))?;
    for suffix in SQLITE_SIDECARS {
        let _ = std::fs::rename(
            with_suffix(parked, suffix),
            with_suffix(&topology.state_db_path, suffix),
        );
    }
    Ok(())
}

const SQLITE_SIDECARS: [&str; 2] = ["-wal", "-shm"];

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn open_and_migrate_state(
    path: &Path,
    retry: &RetryPolicy,
) -> Result<SqliteStateStore, StateOpenFailure> {
    // Only the OPEN retries. A migration that failed will fail the same way on
    // the next pass, and repeating it buys nothing but a longer start.
    let conn = retry_io(retry, || open_connection(path))
        .map_err(|e| StateOpenFailure::Open(e.to_string()))?;
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().map_err(|e| match e {
        nrr_storage::StorageError::UnsupportedSchemaVersion { .. } => {
            StateOpenFailure::NewerSchema(e.to_string())
        }
        other => StateOpenFailure::Migrate(other.to_string()),
    })?;
    let verification = runner
        .verify_schema()
        .map_err(|e| StateOpenFailure::Migrate(format!("verify_schema: {e}")))?;
    // The verdict must actually be checked: an interrupted migration — a
    // missing table, a missing index — would otherwise report a clean start
    // and fail only on the first query.
    if !verification.is_ok() {
        return Err(StateOpenFailure::Migrate(describe_schema_failure(
            "state",
            &verification,
        )));
    }
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
            msg_key = "bootstrap-orphaned-candidates-rejected",
            count,
            "boot sweep: rejected orphaned candidate revision(s) left over from an \
             interrupted service run"
        ),
        Err(e) => tracing::warn!(
            target: "nrr::state",
            msg_key = "bootstrap-orphaned-candidates-reject-failed",
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
                msg_key = "bootstrap-keyed-sweep-mutex-poisoned",
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
            msg_key = "bootstrap-keyed-orphaned-candidates-rejected",
            count,
            "keyed boot sweep: rejected and re-signed signed orphaned candidate \
             revision(s) left over from an interrupted service run"
        ),
        Err(e) => tracing::warn!(
            target: "nrr::state",
            msg_key = "bootstrap-keyed-orphaned-candidates-reject-failed",
            error = %e,
            "keyed boot sweep: failed to reject signed orphaned candidate revisions"
        ),
    }
}

fn open_and_migrate_cache(
    path: &Path,
    thresholds: &FreshnessThresholds,
    retry: &RetryPolicy,
) -> Result<SqliteCacheStore, String> {
    let conn = retry_io(retry, || open_connection(path)).map_err(|e| e.to_string())?;
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().map_err(|e| e.to_string())?;
    let verification = runner
        .verify_schema()
        .map_err(|e| format!("verify_schema: {e}"))?;
    if !verification.is_ok() {
        return Err(describe_schema_failure("cache", &verification));
    }
    Ok(SqliteCacheStore::new(
        runner.into_connection(),
        thresholds.clone(),
    ))
}

/// Name what the schema check actually found. `is_ok()` is three separate
/// conditions, and "schema verification failed" without saying which one
/// leaves the reader to re-run the query by hand.
fn describe_schema_failure(db: &str, v: &nrr_storage::dto::SchemaVerification) -> String {
    let mut faults = Vec::new();
    if !v.required_tables_present {
        faults.push("required tables missing");
    }
    if !v.indexes_ok {
        faults.push("indexes missing");
    }
    if !v.foreign_keys_ok {
        faults.push("foreign-key check failed");
    }
    format!(
        "{db} DB schema verification failed at version {}: {}",
        v.version,
        faults.join(", ")
    )
}

fn open_audit(audit_dir: &Path) -> Result<AuditWriter, String> {
    std::fs::create_dir_all(audit_dir).map_err(|e| format!("create audit dir: {e}"))?;
    let anchor = Arc::new(nrr_diagnostics::FileAnchorStore::in_dir(audit_dir));
    Ok(AuditWriter::open_anchored(
        AuditWriterConfig::new(audit_dir),
        Some(anchor),
    ))
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
    // A policy of zero attempts is a configuration mistake, not an instruction
    // to skip the work: reading it literally meant bootstrap never ran the
    // operation and then panicked on the error it never collected.
    let attempts = policy.max_attempts.max(1);
    for attempt in 0..attempts {
        match op() {
            Ok(value) => return Ok(value),
            Err(e) if attempt + 1 == attempts => return Err(e),
            Err(_) => std::thread::sleep(policy.delay_between_attempts),
        }
    }
    unreachable!("the loop runs at least once and returns on its last attempt")
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
            "audit must be opened before state DB"
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
    fn a_cache_rebuild_takes_the_wal_sidecars_with_it() {
        // WAL mode makes a database three files. Deleting only the `.db` left
        // the fresh one to open beside a write-ahead log written for a file
        // that no longer exists — the corruption carried forward.
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run());
        let cache_path = first.topology.cache_db_path.clone();
        drop(first);

        let sidecars: Vec<std::path::PathBuf> = ["-wal", "-shm"]
            .iter()
            .map(|suffix| {
                let mut p = cache_path.as_os_str().to_owned();
                p.push(suffix);
                std::path::PathBuf::from(p)
            })
            .collect();
        std::fs::write(&cache_path, b"not a valid sqlite database").expect("overwrite cache");
        for sidecar in &sidecars {
            std::fs::write(sidecar, b"stale sidecar").expect("plant sidecar");
        }

        let second = bootstrap(&cfg);
        assert!(second.is_ready_to_run(), "report = {:?}", second.report);
        drop(second);

        for sidecar in &sidecars {
            let content = std::fs::read(sidecar).unwrap_or_default();
            assert_ne!(
                content,
                b"stale sidecar",
                "{} survived the rebuild",
                sidecar.display()
            );
        }
    }

    /// A state database that no longer opens is replaced by its newest backup
    /// and the start goes on; the damaged file is kept for whoever looks.
    #[test]
    fn an_unusable_state_db_is_restored_from_its_newest_backup() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        assert!(first.is_ready_to_run(), "report = {:?}", first.report);
        let topology = first.topology.clone();
        drop(first);

        std::fs::create_dir_all(&topology.backup_dir).expect("backup dir");
        let backup = nrr_storage::backup_database(
            &topology.state_db_path,
            &topology.backup_dir,
            &nrr_storage::BackupReason::ManualExport,
        )
        .expect("backup");
        std::fs::write(&topology.state_db_path, b"not a sqlite database at all")
            .expect("damage the state DB");

        let second = bootstrap(&cfg);
        assert!(second.is_ready_to_run(), "report = {:?}", second.report);
        assert!(second.state_store.is_some());
        let storage = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_STATE)
            .expect("storage phase");
        assert_eq!(storage.severity, ServiceHealthSeverity::Degraded);
        assert!(
            storage.message.contains(&backup.display().to_string()),
            "{}",
            storage.message
        );
        let parked: Vec<_> = std::fs::read_dir(&topology.backup_dir)
            .expect("read backups")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".damaged-"))
            .collect();
        assert_eq!(parked.len(), 1, "the damaged file is kept, once");
        assert_eq!(
            std::fs::read(parked[0].path()).expect("damaged copy"),
            b"not a sqlite database at all"
        );
    }

    /// Without a backup the damaged database is left where it is and the
    /// start stays blocked, with the restore attempt in the reason.
    #[test]
    fn an_unusable_state_db_with_no_backup_still_blocks() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        let topology = first.topology.clone();
        drop(first);
        std::fs::write(&topology.state_db_path, b"not a sqlite database at all")
            .expect("damage the state DB");

        let second = bootstrap(&cfg);
        assert!(!second.is_ready_to_run());
        let storage = second
            .report
            .phases
            .iter()
            .find(|p| p.phase == phases::STORAGE_STATE)
            .expect("storage phase");
        assert_eq!(storage.severity, ServiceHealthSeverity::Blocking);
        assert!(storage.message.contains("no backup"), "{}", storage.message);
        assert_eq!(
            std::fs::read(&topology.state_db_path).expect("state DB"),
            b"not a sqlite database at all",
            "nothing is moved when nothing replaces it"
        );
    }

    /// Backups exist but none of them takes: the original goes back where it
    /// was. Left missing, the next start would create an empty database and run
    /// with no rules and none of the protection the user had set.
    #[test]
    fn an_unusable_state_db_whose_backups_all_fail_is_put_back() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        let topology = first.topology.clone();
        drop(first);
        let stem = topology
            .state_db_path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("stem")
            .to_owned();
        std::fs::create_dir_all(&topology.backup_dir).expect("backup dir");
        std::fs::write(
            topology.backup_dir.join(format!("{stem}-broken.db")),
            b"a broken backup",
        )
        .expect("broken backup");
        std::fs::write(&topology.state_db_path, b"not a sqlite database at all")
            .expect("damage the state DB");

        let second = bootstrap(&cfg);
        assert!(!second.is_ready_to_run());
        drop(second);
        assert_eq!(
            std::fs::read(&topology.state_db_path).expect("state DB"),
            b"not a sqlite database at all",
            "the original is back in place, not an empty database"
        );
        let parked = std::fs::read_dir(&topology.backup_dir)
            .expect("read backups")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".damaged-"))
            .count();
        assert_eq!(parked, 0, "nothing is left parked once it is put back");
    }

    /// A database a newer build wrote is not damaged: no backup replaces it,
    /// or a rollback to an older build would quietly undo every later change.
    #[test]
    fn a_state_db_from_a_newer_build_is_not_replaced_by_a_backup() {
        let (_dir, cfg) = temp_profile();
        let first = bootstrap(&cfg);
        let topology = first.topology.clone();
        drop(first);
        std::fs::create_dir_all(&topology.backup_dir).expect("backup dir");
        nrr_storage::backup_database(
            &topology.state_db_path,
            &topology.backup_dir,
            &nrr_storage::BackupReason::ManualExport,
        )
        .expect("backup");
        {
            let conn = rusqlite::Connection::open(&topology.state_db_path).expect("open");
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at, checksum, app_version) VALUES (999999, 'from-the-future', 0, 'x', '9.9.9')",
                [],
            )
            .expect("a newer build's step");
        }

        let second = bootstrap(&cfg);
        assert!(!second.is_ready_to_run());
        drop(second);
        let conn = rusqlite::Connection::open(&topology.state_db_path).expect("reopen");
        let newest: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .expect("version");
        assert_eq!(newest, 999_999, "the newer database is left as it was");
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
        // Topology failure itself is impractical to trigger here — no safe way
        // to clear PROGRAMDATA in a parallel test, and Windows-specific paths
        // are too brittle — so this corrupts the state DB after a clean
        // bootstrap instead, to exercise the same downstream-skip behavior.
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

    /// Zero attempts is a misconfiguration, not "skip the work". Read
    /// literally it ran nothing and then panicked on the error it never got —
    /// during bootstrap, which is the one place a panic is fatal to the start.
    #[test]
    fn a_policy_of_zero_attempts_still_runs_the_operation_once() {
        let policy = RetryPolicy {
            max_attempts: 0,
            delay_between_attempts: Duration::from_millis(0),
        };
        let mut calls = 0;
        let ok: Result<i32, &str> = retry_io(&policy, || {
            calls += 1;
            Ok(7)
        });
        assert_eq!(ok, Ok(7));
        assert_eq!(calls, 1, "exactly one attempt, no panic");

        let mut calls = 0;
        let err: Result<i32, &str> = retry_io(&policy, || {
            calls += 1;
            Err("nope")
        });
        assert_eq!(err, Err("nope"), "the failure is returned, not panicked on");
        assert_eq!(calls, 1);
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

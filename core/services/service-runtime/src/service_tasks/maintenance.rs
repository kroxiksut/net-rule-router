//! Housekeeping tasks: log and audit cleanup, revision retention, the WAL
//! checkpoint and operation-result GC. None of them affect routing.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

// ── Diagnostics cleanup ──────────────────────────────────────────────────────

/// Periodic operational-log cleanup. Audit files are never touched (see
/// `CleanupJob::run_logs` doc-comment). The task is `Optional` because
/// disk pressure is a degraded-mode condition, not a service-stop one;
/// even if cleanup fails permanently, routing policy enforcement
/// continues unaffected.
pub fn build_diagnostics_cleanup_task(
    logs_dir: PathBuf,
    policy: LogRetentionPolicy,
    scope: ManualCleanupScope,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_DIAGNOSTICS_CLEANUP,
        TaskClass::Optional,
        DIAGNOSTICS_CLEANUP_INTERVAL,
        // Optional ignores max_restarts (drops on first failure).
        0,
        move |_stop| {
            report_cleanup(
                "operational logs",
                CleanupJob::run_logs(&logs_dir, &policy, &scope),
            );
            TaskOutcome::Continue
        },
    )
}

/// Periodic AUDIT NDJSON retention pass. Runs
/// `CleanupJob::run_audit`, which only ever touches `nrr_audit_*` files in
/// `audit_dir` (never operational logs, never the `security_alerts` table).
/// This is the SERVICE-side retention pruner — audit is never user-deletable.
/// `Optional` for the same degraded-mode reasoning as `diagnostics-cleanup`.
pub fn build_diagnostics_audit_cleanup_task(
    audit_dir: PathBuf,
    policy: AuditRetentionPolicy,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_DIAGNOSTICS_AUDIT_CLEANUP,
        TaskClass::Optional,
        DIAGNOSTICS_CLEANUP_INTERVAL,
        0,
        move |_stop| {
            report_cleanup("audit", CleanupJob::run_audit(&audit_dir, &policy));
            TaskOutcome::Continue
        },
    )
}

/// Say what a retention pass did. Dropping `CleanupResult` silently would leave
/// a sweep that removed every log — or failed to remove anything — with no
/// trace of itself in the very logs it was managing. A pass that deletes
/// nothing stays quiet; there is one of these every hour and silence is the
/// normal case.
fn report_cleanup(what: &str, result: nrr_diagnostics::CleanupResult) {
    if !result.errors.is_empty() {
        tracing::warn!(
            target: "nrr::retention",
            kind = what,
            deleted = result.files_deleted,
            errors = ?result.errors,
            "retention pass could not delete some files",
        );
    }
    if result.files_deleted > 0 {
        tracing::info!(
            target: "nrr::retention",
            kind = what,
            deleted = result.files_deleted,
            bytes_freed = result.bytes_freed,
            "retention pass removed rotated files",
        );
    }
}

// ── Revisions retention prune ────────────────────────────────────────────────

/// Periodic revisions retention pass. Reads the active
/// `RetentionSettings` from `nrr_service_state.db`, runs
/// `RevisionsRepository::prune_by_retention`, then calls
/// `touch_last_cleanup` so the next pass sees an updated timestamp. The
/// task is `Optional` for the same reason as `diagnostics-cleanup` — a
/// stalled prune produces a degraded mode (DB grows), not a routing
/// failure. Failures are logged and swallowed; the next tick retries.
pub fn build_revisions_retention_task(conn: Arc<Mutex<rusqlite::Connection>>) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_REVISIONS_RETENTION,
        TaskClass::Optional,
        DIAGNOSTICS_CLEANUP_INTERVAL,
        0,
        move |_stop| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let conn = match conn.lock() {
                Ok(c) => c,
                Err(_) => return TaskOutcome::Continue,
            };
            let retention_repo = nrr_storage::RetentionSettingsRepository::new(&conn);
            let settings = match retention_repo.get_or_default() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::retention",
                        error = %e,
                        "retention settings read failed; skipping prune",
                    );
                    return TaskOutcome::Continue;
                }
            };
            let revisions_repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
            match revisions_repo.prune_by_retention(&settings, now) {
                Ok(summary) => {
                    if summary.superseded_dropped
                        + summary.rejected_dropped
                        + summary.rolledback_dropped
                        > 0
                    {
                        tracing::info!(
                            target: "nrr::retention",
                            superseded = summary.superseded_dropped,
                            rejected = summary.rejected_dropped,
                            rolled_back = summary.rolledback_dropped,
                            "revisions retention prune completed",
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::retention",
                        error = %e,
                        "revisions retention prune failed",
                    );
                }
            }
            if let Err(e) = retention_repo.touch_last_cleanup(now) {
                tracing::warn!(
                    target: "nrr::retention",
                    error = %e,
                    "touch_last_cleanup failed",
                );
            }
            TaskOutcome::Continue
        },
    )
}

// ── Storage WAL checkpoint ───────────────────────────────────────────────────

/// Handles to the databases the service keeps open for its whole uptime.
/// Every field is optional: a degraded boot may have opened none of them.
#[derive(Clone, Default)]
pub struct StorageCheckpointDeps {
    /// `nrr_fqdn_ip_cache.db`, through the same handle the DNS refresh writes.
    pub cache: Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    /// `nrr_service_state.db`.
    pub state: Option<Arc<Mutex<rusqlite::Connection>>>,
    /// `nrr_traffic_stats.db`, through the sampler that owns it.
    pub traffic: Option<Arc<Mutex<crate::traffic_sampler::TrafficSampler>>>,
}

impl StorageCheckpointDeps {
    /// True when at least one database is available to check point.
    pub fn is_empty(&self) -> bool {
        self.cache.is_none() && self.state.is_none() && self.traffic.is_none()
    }
}

/// Periodic WAL checkpoint over every open database.
///
/// The connection factory truncates the journal on open, which is enough for
/// a process that restarts often and nothing at all for a service that runs for
/// weeks: SQLite's automatic checkpoint folds pages into the database but never
/// shrinks the journal, so the ledger ends up living almost entirely in a file
/// that a crash cleanup or a restore-from-copy drops while leaving an
/// intact-looking database behind. `Optional` — a skipped pass costs disk, not
/// routing. Failures are swallowed: with a second connection live SQLite
/// declines, and the next pass retries.
pub fn build_storage_checkpoint_task(deps: StorageCheckpointDeps) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_STORAGE_CHECKPOINT,
        TaskClass::Optional,
        DIAGNOSTICS_CLEANUP_INTERVAL,
        0,
        move |_stop| {
            if let Some(cache) = deps.cache.as_ref() {
                if let Ok(c) = cache.lock() {
                    checkpoint_logged("fqdn-cache", c.periodic_vacuum());
                }
            }
            if let Some(state) = deps.state.as_ref() {
                if let Ok(c) = state.lock() {
                    checkpoint_logged(
                        "service-state",
                        nrr_storage::migration::checkpoint_wal_truncate(&c),
                    );
                }
            }
            if let Some(traffic) = deps.traffic.as_ref() {
                if let Ok(s) = traffic.lock() {
                    checkpoint_logged("traffic-stats", s.checkpoint_wal());
                }
            }
            TaskOutcome::Continue
        },
    )
}

fn checkpoint_logged(database: &str, outcome: nrr_storage::StorageResult<()>) {
    if let Err(e) = outcome {
        tracing::debug!(
            target: "nrr::retention",
            database,
            error = %e,
            "WAL checkpoint declined; retrying next pass",
        );
    }
}

// ── Operation-results GC ─────────────────────────────────────────────────────

/// Periodic GC for the in-memory operation-results table. Operation
/// records carry a `retain_until: Option<Instant>` deadline; this tick
/// drops everything past the deadline. `Optional` for the same reason
/// as the diagnostics cleanup — a stalled GC produces a memory-growth
/// degradation, not a routing failure.
pub fn build_operation_results_gc_task(
    store: Arc<OperationStatusStore>,
    tokens: Option<Arc<crate::ipc_handlers::mutation_token_store::MutationTokenStore>>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_OPERATION_RESULTS_GC,
        TaskClass::Optional,
        OPERATION_RESULTS_GC_INTERVAL,
        0,
        move |_stop| {
            let now = Instant::now();
            let _expired = store.gc_expired(now);
            // Same tick collects the dry-run confirmation tokens: they are
            // issued by an unelevated, unqueued, unlimited call and each parks
            // its payload until confirmed or expired.
            if let Some(tokens) = tokens.as_ref() {
                let dropped = tokens.gc_expired(now);
                if dropped > 0 {
                    tracing::debug!(
                        target: "nrr::ipc",
                        dropped,
                        "expired confirmation tokens collected",
                    );
                }
            }
            TaskOutcome::Continue
        },
    )
}

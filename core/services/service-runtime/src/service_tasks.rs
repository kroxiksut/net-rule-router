//! Task constructors for the production `ServiceSupervisor`.
//!
//! Five long-lived `ServiceTask` shapes consumed by the runtime entry-point.
//! Each builder returns a freshly-constructed `ServiceTask` that the
//! supervisor can `spawn()` — no global state, no implicit ordering.
//! Cross-task dependencies (`ipc-accept-loop` ↔ `ipc-shutdown-watcher`) are
//! threaded through `Arc` so each task sees the same listener state.
//!
//! | Task id                  | Class       | Interval | Failure semantics                                 |
//! |--------------------------|-------------|----------|----------------------------------------------------|
//! | `health-aggregator-tick` | Recoverable | 5s       | Restarted up to 20× with supervisor backoff        |
//! | `adapter-monitor-tick`   | Recoverable | 1s       | Restarted up to 20×; degraded mode on retire       |
//! | `diagnostics-cleanup`    | Optional    | 1h       | Dropped quietly on failure                         |
//! | `operation-results-gc`   | Optional    | 5min     | Dropped quietly on failure                         |
//! | `ipc-accept-loop`        | per policy  | event    | Recoverable / Critical from `ServiceStabilityConfig` |
//!
//! The IPC bundle is special:
//!
//! - `bind()` happens **once** during the bundle build, before any
//!   `spawn()` — bind errors surface to the caller synchronously so they
//!   can be folded into the bootstrap report.
//! - The accept-task tick calls `acceptor.accept_one()`, which blocks until
//!   a client connects, the shutdown event fires, or accept fails.
//! - Because `accept_one` blocks, the supervisor's `StopToken` cannot
//!   reach it directly. A second task — `ipc-shutdown-watcher` — polls
//!   the stop token every 100 ms and calls `acceptor.request_shutdown()`
//!   when set, which wakes the blocking `ConnectNamedPipe`.
//! - On `AcceptOutcome::Err` the accept-task drops the current acceptor,
//!   asks the `IpcServer` for a fresh `bind()`, and returns
//!   `TaskOutcome::Failed`. The supervisor's policy then decides whether
//!   to retry (Recoverable) or terminate fatally (Critical), in line
//!   with `IpcAcceptFailurePolicy`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nrr_diagnostics::{AuditRetentionPolicy, CleanupJob, LogRetentionPolicy, ManualCleanupScope};
use nrr_platform_api::AdapterMonitor;

use crate::health::{HealthAggregator, HealthComponent};
use crate::ipc_handlers::event_bus::EventBus;
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::lifecycle::StopToken;
use crate::managers::{AcceptOutcome, IpcAcceptor, IpcBindError, IpcServer};
use crate::runtime_loop::{BackoffSchedule, ServiceTask, TaskClass, TaskId, TaskOutcome};
use crate::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};
use crate::state::ServiceHealthSeverity;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

// ── Constants ────────────────────────────────────────────────────────────────

/// Cadence the health aggregator recomputes its rolled-up snapshot at.
pub const HEALTH_AGGREGATOR_INTERVAL: Duration = Duration::from_secs(5);
/// Cadence the adapter monitor polls its underlying source at. Tight
/// (1 s) so adapter availability transitions land in the GUI within
/// the debounce window without burning CPU on enumeration.
pub const ADAPTER_MONITOR_INTERVAL: Duration = Duration::from_secs(1);
/// Cadence of the periodic route-reconcile safety net. The adapter
/// monitor only reacts to availability
/// *transitions* (`Absent`/`PresentDown`/`PresentNoIp` ↔ `Available`); it
/// is blind to a secondary that changes its internal IP / gateway while
/// staying continuously `Available` — e.g. a secondary adapter renewing its tunnel
/// address without dropping the interface. This slow tick re-drives the
/// active user's route table so such a silent re-IP (and, under
/// service-driven rule-scope with no tray, a baseline change) converges
/// within one interval. `recompute_active` re-derives the secondary
/// next-hop FRESH and reconciles to a no-op when nothing changed, so the
/// steady-state cost is one route-table enumeration plus a diff.
pub const ROUTE_RECONCILE_SAFETY_INTERVAL: Duration = Duration::from_secs(30);
/// Cadence the operational-log cleanup job runs at. 1 hour is the
/// retention spec — fast enough that disk pressure from a verbose
/// session resolves within an hour, slow enough to keep file IO load
/// negligible.
pub const DIAGNOSTICS_CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
/// Cadence operation-result GC runs at. Operation results carry a 5-min
/// TTL; GC matches so expired records leave memory promptly after the
/// GUI has had a chance to poll.
pub const OPERATION_RESULTS_GC_INTERVAL: Duration = Duration::from_secs(300);
/// Cadence the IPC shutdown watcher polls `StopToken` at. 100 ms is
/// short enough that GUI/SCM-driven shutdown latency stays under one
/// poll round, long enough that the watcher contributes negligible CPU.
pub const IPC_SHUTDOWN_WATCHER_INTERVAL: Duration = Duration::from_millis(100);

/// `max_restarts` for Recoverable tasks whose failure policy is implicit
/// (everything except `ipc-accept-loop`, which derives its budget from
/// `IpcAcceptFailurePolicy`).
pub const RECOVERABLE_DEFAULT_MAX_RESTARTS: u8 = 20;

// ── Task-id slugs ────────────────────────────────────────────────────────────

/// Stable task ids. Surface in audit / health snapshots — do not rename
/// without coordinating with the GUI side.
pub const TASK_ID_HEALTH_AGGREGATOR: &str = "health-aggregator-tick";
pub const TASK_ID_ADAPTER_MONITOR: &str = "adapter-monitor-tick";
pub const TASK_ID_ROUTE_RECONCILE_SAFETY: &str = "route-reconcile-safety-tick";
pub const TASK_ID_DIAGNOSTICS_CLEANUP: &str = "diagnostics-cleanup";
/// Scheduled audit NDJSON retention pruner. Distinct task from
/// `diagnostics-cleanup` because it targets `nrr_audit_*` files under
/// the same dir via `CleanupJob::run_audit` (never user-triggered).
pub const TASK_ID_DIAGNOSTICS_AUDIT_CLEANUP: &str = "diagnostics-audit-cleanup";
pub const TASK_ID_OPERATION_RESULTS_GC: &str = "operation-results-gc";
/// Periodic revisions retention pruner. Runs the same 1-hour cadence
/// as `diagnostics-cleanup`. Optional class.
pub const TASK_ID_REVISIONS_RETENTION: &str = "revisions-retention-prune";
pub const TASK_ID_IPC_ACCEPT_LOOP: &str = "ipc-accept-loop";
pub const TASK_ID_IPC_SHUTDOWN_WATCHER: &str = "ipc-shutdown-watcher";
/// Periodic DNS refresh tick. Optional class — DNS failures degrade
/// rule matching (SuffixDomain/ExactFqdn lose stale IPs over time) but
/// never block routing policy enforcement.
pub const TASK_ID_DNS_REFRESH: &str = "dns-refresh-tick";

/// Cadence the DNS refresh task runs at. 60 s is a compromise: short
/// enough that a TTL=30 s record becomes fresh again within ~1.5
/// minutes of expiry, long enough that the resolver cost is amortised
/// (DnsQuery_W typically returns in <50 ms for cached entries; cold
/// queries can take 200–1000 ms but are batched at `DNS_REFRESH_BATCH`).
pub const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum hostnames the DNS refresh task processes in a single tick.
/// Bounded so a backlog after a long offline period (e.g. laptop wake
/// from suspend) does not stall the supervisor tick thread.
pub const DNS_REFRESH_BATCH: usize = 50;

/// Rule-hostname seed task id.
pub const TASK_ID_RULE_HOSTNAME_SEED: &str = "rule-hostname-seed-tick";

/// DNS-observation pump task id.
pub const TASK_ID_DNS_OBSERVE: &str = "dns-observe-tick";

/// Cadence the DNS-observation pump drains the observation buffer. Tight
/// (1 s) so a freshly-observed subdomain under a suffix/zone rule becomes a
/// route quickly: under an armed block-all, the first SYN to a
/// freshly-observed rule host is dropped until its permit compiles, so a
/// short observe cadence shrinks that window to about one TCP SYN
/// retransmit — the browser's own retry usually lands after the permit
/// exists. The drain itself stays a cheap ETW buffer read, not a network
/// call, so a 1 s cadence costs nothing at idle.
pub const DNS_OBSERVE_INTERVAL: Duration = Duration::from_secs(1);

/// Connection-observation pump task id.
pub const TASK_ID_CONN_OBSERVE: &str = "conn-observe-tick";

/// Cadence the connection-observation pump drains its buffer. Matches the
/// DNS-observe cadence (5 s) — frequent enough for a live trace, while
/// debouncing high-volume connection bursts into one drain per tick.
pub const CONN_OBSERVE_INTERVAL: Duration = Duration::from_secs(5);

/// Companion-domain proposal tick — task id.
pub const TASK_ID_AUTO_RULES: &str = "auto-rules-tick";

/// Cadence the companion-domain proposal tick runs at.
///
/// The feature is judged on one behaviour: the prompt has to arrive while the
/// user is still on the page that was half-broken. A brand-related companion
/// qualifies from its FIRST window, so waiting out a slow tick is dead time,
/// not evidence-gathering — and the recompute is a walk over a
/// browsing-session-sized table, cheap enough to repeat.
pub const AUTO_RULES_INTERVAL: Duration = Duration::from_secs(10);

/// External-address notice — task id.
pub const TASK_ID_SECONDARY_EXTERNAL_ADDRESS: &str = "secondary-external-address-tick";

/// Cadence the external-address notice tick runs at.
///
/// Two ticks make up
/// [`crate::secondary_external_address::LINK_SETTLE`], so the notice lands
/// within roughly half a minute of the additional link coming up — prompt
/// enough to read as "it just connected". The steady-state cost is one route
/// resolution plus an adapter enumeration; the network probe happens once per
/// connection, on its own thread, never on this one.
pub const SECONDARY_EXTERNAL_ADDRESS_INTERVAL: Duration = Duration::from_secs(2);

/// Cadence the rule-hostname seed task runs at. Matches the DNS refresh
/// cadence: the seeder only resolves NOT-yet-cached `ExactFqdn` rule
/// hostnames (each pass skips already-cached ones), so steady-state cost
/// is near zero — work happens once after a new domain rule lands, then
/// the DNS refresh task keeps it warm.
pub const RULE_HOSTNAME_SEED_INTERVAL: Duration = Duration::from_secs(60);

/// Application-destination write-back — task id.
pub const TASK_ID_APP_DESTINATION_FLUSH: &str = "app-destination-flush-tick";

/// Cadence the application-destination write-back runs at. The same 60 s as the
/// rule-hostname seed, and for the same reason: both read one rule snapshot and
/// then do work proportional to what the rule book actually names, so a rule book
/// with no application routed over the additional link costs a snapshot read and
/// nothing else. Fast enough that a crash loses at most a minute of freshly
/// learned destinations, slow enough to be invisible.
pub const APP_DESTINATION_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

// ── Health aggregator ────────────────────────────────────────────────────────

/// Periodic snapshot recompute. Cheap — `HealthAggregator::snapshot()`
/// is O(N) over component count. The task body throws the snapshot away
/// because the GUI polls on demand; the only purpose of the periodic
/// run is to keep `snapshot_refreshed_at` fresh and to detect aggregator
/// poisoning (a poisoned mutex makes `snapshot()` return a synthesised
/// `RecoveryRequired` snapshot, which is observable even from a tick
/// that doesn't read the result).
pub fn build_health_aggregator_task(health: Arc<HealthAggregator>) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_HEALTH_AGGREGATOR,
        TaskClass::Recoverable,
        HEALTH_AGGREGATOR_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            // Touch the aggregator so a poisoned mutex is detected.
            // Discarding the snapshot is intentional — the GUI reads
            // through `service.health.get` on its own cadence.
            let _ = health.snapshot();
            TaskOutcome::Continue
        },
    )
}

// ── Traffic sampler ──────────────────────────────────────────────────────────

/// Cadence the traffic sampler reads interface octet counters at. Reading a
/// counter is O(adapters), independent of traffic volume, so a tight 2 s tick is
/// cheap.
pub const TRAFFIC_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
pub const TASK_ID_TRAFFIC_SAMPLE: &str = "traffic-sample-tick";

/// Resolves the active user's `(primary, secondary)` adapter display names for
/// the current tick (from route bindings); `(None, None)` when there is no
/// active user / bindings.
pub type TrafficRoleResolver = Arc<dyn Fn() -> (Option<String>, Option<String>) + Send + Sync>;

/// Reads the current service-global traffic-stats settings each tick.
pub type TrafficSettingsResolver = Arc<dyn Fn() -> nrr_storage::TrafficStatsSettings + Send + Sync>;

/// Dependencies for [`build_traffic_sample_task`].
#[derive(Clone)]
pub struct TrafficTickDeps {
    pub sampler: Arc<Mutex<crate::traffic_sampler::TrafficSampler>>,
    pub roles: TrafficRoleResolver,
    pub settings: TrafficSettingsResolver,
    /// Supplies the machine's civil offset from UTC so "today" is the USER'S
    /// day, not Greenwich's.
    pub timezone: Arc<dyn nrr_platform_api::local_time::LocalTimeZonePort>,
}

/// Periodic interface-octet sampling. Reads the counters, buckets by
/// role, folds deltas into the day's ledger + session totals, and sweeps
/// retention once per day rollover. Skips entirely while the master toggle is
/// off. Recoverable — a transient counter-read error never retires it.
pub fn build_traffic_sample_task(deps: TrafficTickDeps) -> ServiceTask {
    use nrr_domain::traffic_accountant::CountingToggles;
    use std::sync::atomic::{AtomicI64, Ordering};

    let TrafficTickDeps {
        sampler,
        roles,
        settings,
        timezone,
    } = deps;
    let last_pruned_day = AtomicI64::new(i64::MIN);

    ServiceTask::periodic(
        TASK_ID_TRAFFIC_SAMPLE,
        TaskClass::Recoverable,
        TRAFFIC_SAMPLE_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            // LOCAL epoch-day: a midnight-UTC boundary would flip "today"
            // mid-morning east of Greenwich. The GUI must key its "today"
            // request off the local date the same way.
            let day = nrr_platform_api::local_time::local_epoch_day(
                now_ms,
                timezone.utc_offset_seconds(now_ms),
            );

            let cfg = settings();
            if !cfg.enabled {
                return TaskOutcome::Continue;
            }
            let (primary, secondary) = roles();
            let toggles = CountingToggles {
                count_loopback: cfg.count_loopback,
                count_virtual: cfg.count_virtual,
            };

            let mut s = sampler.lock().unwrap_or_else(|p| p.into_inner());
            let _ = s.tick(
                primary.as_deref(),
                secondary.as_deref(),
                toggles,
                day,
                now_ms,
            );
            // Retention sweep once per day rollover (cheap DELETE on a tiny table).
            if last_pruned_day.swap(day, Ordering::Relaxed) != day {
                let _ = s.prune_before(day - cfg.retention_days as i64);
            }
            TaskOutcome::Continue
        },
    )
}

// ── Adapter monitor ──────────────────────────────────────────────────────────

/// Periodic adapter-availability poll. Wraps `AdapterMonitor::update`
/// which itself is idempotent and never panics; on internal source
/// errors it returns an empty `Vec<AdapterAvailabilityChange>` so a
/// single transient enumeration glitch does not propagate as a task
/// failure. The task records `Adapters` health on every tick — this
/// is what tells the supervisor that the adapter pipeline is alive.
///
/// Note: published `AdapterAvailabilityChange` events are intentionally
/// dropped here. A future IPC push wiring is expected to carry them
/// through; the service-side enrichment (per-event audit, GUI notify)
/// belongs there, not in this task.
pub fn build_adapter_monitor_task(
    monitor: Arc<AdapterMonitor>,
    health: Arc<HealthAggregator>,
    route_recompute_hook: Option<crate::supervised_runtime::RouteRecomputeHook>,
    event_bus: Option<Arc<EventBus>>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_ADAPTER_MONITOR,
        TaskClass::Recoverable,
        ADAPTER_MONITOR_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let changes = monitor.update(now_ms);
            // An adapter coming up/down (the secondary adapter connecting
            // mid-session, or dropping) must PROMPTLY re-drive the route table:
            // secondary traffic should start flowing through the tunnel the
            // moment it is up, and stop the moment it is gone — not wait up to
            // a DNS-refresh interval. Recompute only on an actual change, so
            // the steady-state 1 s tick stays cheap.
            if !changes.is_empty() {
                if let Some(hook) = &route_recompute_hook {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        adapter_changes = changes.len(),
                        "adapter state changed (e.g. secondary up/down) — recomputing routes",
                    );
                    hook();
                }
                // Notify subscribed GUIs so the
                // Interfaces page refreshes on a secondary up/down instead of showing a
                // stale "available". Additive `AdaptersChanged` push (the client
                // refetches SnapshotInterfacesGet); no-op when no bus is wired.
                if let Some(bus) = &event_bus {
                    bus.publish(StatusUpdateEvent::AdaptersChanged {
                        data_source: "adapter-monitor".to_string(),
                    });
                }
            }
            health.record(
                HealthComponent::Adapters,
                ServiceHealthSeverity::Ok,
                "adapter monitor tick ok",
            );
            TaskOutcome::Continue
        },
    )
}

// ── Route-reconcile safety net ───────────────────────────────────────────────

/// Periodic idempotent re-drive of the active user's route table.
/// Complements `build_adapter_monitor_task`, which only fires on
/// an adapter availability *transition* and is therefore blind to a secondary
/// that re-IPs while staying continuously `Available` (a secondary adapter renewing its
/// tunnel address without dropping the interface) and to a baseline rule change
/// applied with no tray connected under service-driven scope. This slow tick
/// closes both gaps: `recompute_active` re-resolves the secondary next-hop
/// FRESH and reconciles to a no-op when nothing changed, so the worst case is
/// one wasted route-table enumeration + diff per [`ROUTE_RECONCILE_SAFETY_INTERVAL`].
///
/// `Recoverable` (not `Optional`): converging the route table is the product's
/// core job, so a persistently failing recompute should surface as a supervised
/// fault rather than being silently dropped. The hook itself swallows and logs
/// per-cycle errors, so a single transient failure never trips the restart budget.
pub fn build_route_reconcile_safety_task(
    route_recompute_hook: crate::supervised_runtime::RouteRecomputeHook,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_ROUTE_RECONCILE_SAFETY,
        TaskClass::Recoverable,
        ROUTE_RECONCILE_SAFETY_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            route_recompute_hook();
            TaskOutcome::Continue
        },
    )
}

// ── Secondary-liveness probe ─────────────────────────────────────────────────

/// Cadence the active-probe liveness tick runs at. Fast (5 s) so a short
/// liveness window (e.g. 10 s) is honoured; the probe is cheap (one ICMP echo
/// per bound secondary) and a no-op while the feature is off (window 0).
pub const SECONDARY_LIVENESS_INTERVAL: Duration = Duration::from_secs(5);
pub const TASK_ID_SECONDARY_LIVENESS: &str = "secondary-liveness-tick";

/// Periodic active-probe of each active user's bound secondary tunnel next-hop.
/// `Optional`: liveness detection hardens the kill-switch, but its failure must
/// never stop the service; the hook swallows per-cycle work internally and is a
/// no-op while the feature is disabled (window 0).
pub fn build_secondary_liveness_task(
    liveness_hook: crate::supervised_runtime::RouteRecomputeHook,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_SECONDARY_LIVENESS,
        TaskClass::Optional,
        SECONDARY_LIVENESS_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            liveness_hook();
            TaskOutcome::Continue
        },
    )
}

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
            let _result = CleanupJob::run_logs(&logs_dir, &policy, &scope);
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
            let _result = CleanupJob::run_audit(&audit_dir, &policy);
            TaskOutcome::Continue
        },
    )
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

// ── Operation-results GC ─────────────────────────────────────────────────────

/// Periodic GC for the in-memory operation-results table. Operation
/// records carry a `retain_until: Option<Instant>` deadline; this tick
/// drops everything past the deadline. `Optional` for the same reason
/// as the diagnostics cleanup — a stalled GC produces a memory-growth
/// degradation, not a routing failure.
pub fn build_operation_results_gc_task(store: Arc<OperationStatusStore>) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_OPERATION_RESULTS_GC,
        TaskClass::Optional,
        OPERATION_RESULTS_GC_INTERVAL,
        0,
        move |_stop| {
            let _expired = store.gc_expired(Instant::now());
            TaskOutcome::Continue
        },
    )
}

// ── DNS refresh ───────────────────────────────────────────────────────────────

/// Periodic DNS refresh tick. Walks
/// [`CacheRepository::list_expired_resolutions`][nrr_storage::repository::CacheRepository::list_expired_resolutions]
/// hot-first, re-resolves each via [`DnsResolverPort`][nrr_platform_api::dns::DnsResolverPort],
/// and writes the outcome back. `Optional` class — DNS unavailability
/// degrades rule matching over time (stale IPs expire from the cache)
/// but never blocks routing policy enforcement.
///
/// The orchestrator is shared via `Arc` so other entry points (manual
/// cache refresh IPC handler, on-demand admin command) can drive the
/// same code path.
pub fn build_dns_refresh_task(
    orchestrator: Arc<crate::dns_refresh::DnsRefreshOrchestrator>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_DNS_REFRESH,
        TaskClass::Optional,
        DNS_REFRESH_INTERVAL,
        0,
        move |_stop| {
            let summary = orchestrator.run_once(SystemTime::now(), DNS_REFRESH_BATCH);
            if summary.made_progress() {
                tracing::info!(
                    target: "nrr::dns",
                    attempted = summary.attempted,
                    succeeded = summary.succeeded,
                    failed_authoritative = summary.failed_authoritative,
                    failed_transient = summary.failed_transient,
                    cache_errors = summary.cache_errors,
                    skipped = summary.skipped,
                    fake_intercepted = summary.fake_intercepted,
                    loopback_pinned = summary.loopback_pinned,
                    "DNS refresh tick"
                );
                // Fresh IPs landed in the FQDN cache, so a domain/zone rule
                // whose hosts were cold may now produce routes. Recompute
                // the active user's route table. Cheap and idempotent (a
                // no-op diff when nothing changed).
                if let Some(hook) = on_progress.as_ref() {
                    hook();
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Periodic task that resolves the active user's not-yet-cached
/// `ExactFqdn` rule hostnames into the FQDN cache, then (if
/// it seeded anything) recomputes the route table so the freshly-resolved
/// IPs become routes. Without this nothing ever populates the cache from
/// the rule book, so domain rules would never route.
///
/// `active_sid` returns the routing-active SID (Free single-active-user);
/// `None`/empty → nothing to seed. Off the mutation path: DNS resolution
/// runs on the supervisor's background tick, never blocking an apply.
pub fn build_rule_hostname_seed_task(
    seeder: Arc<crate::rule_hostname_seeder::RuleHostnameSeeder>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_RULE_HOSTNAME_SEED,
        TaskClass::Optional,
        RULE_HOSTNAME_SEED_INTERVAL,
        0,
        move |_stop| {
            if let Some(sid) = active_sid() {
                let summary = seeder.seed_for_principal(&sid, SystemTime::now());
                if summary.made_progress() {
                    tracing::info!(
                        target: "nrr::rule-seed",
                        sid = %sid,
                        resolved = summary.resolved,
                        already_cached = summary.already_cached,
                        failed = summary.failed,
                        apex_absent = summary.apex_absent,
                        "rule-hostname seed tick",
                    );
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Application-destination write-back.
///
/// Persists the destinations of the applications the active user routes over the
/// additional link, so the next session's routes exist before those applications
/// connect (see [`crate::app_destination_memory`]). Purely a memory refresh — it
/// installs nothing and never recomputes routes, so no progress hook.
pub fn build_app_destination_flush_task(
    memory: Arc<crate::app_destination_memory::AppDestinationMemory>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_APP_DESTINATION_FLUSH,
        TaskClass::Optional,
        APP_DESTINATION_FLUSH_INTERVAL,
        0,
        move |_stop| {
            let summary = memory.flush(SystemTime::now());
            if summary.made_progress() {
                tracing::debug!(
                    target: "nrr::app-routing",
                    apps = summary.apps,
                    destinations = summary.destinations,
                    "application-destination write-back tick",
                );
            }
            TaskOutcome::Continue
        },
    )
}

/// Periodic pump that drains passively-observed DNS resolutions and
/// feeds them to the consumer, which caches the ones
/// matching an active suffix/zone/exact rule. When anything matched (so the
/// cache gained a new sub-hostname), recompute the route table — this is
/// how `*.example.com` / `.ru` rules become real routes. The DNS resolution
/// happens elsewhere (ETW observer); this task only matches + caches +
/// recomputes, so it never blocks on the network.
pub fn build_dns_observe_task(
    source: Arc<dyn nrr_platform_api::dns_observe::DnsObservationSource>,
    consumer: Arc<crate::dns_observation_consumer::DnsObservationConsumer>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    // Seed the FQDN cache from the OS resolver cache on a SLOW cadence (every
    // SEED_EVERY_TICKS observe ticks ≈ 30 s at the 1 s observe interval) in
    // addition to the boot seed. Reading the whole OS cache + a cache-only
    // query per name is heavier than draining the ETW ring, so it must NOT
    // run at the observe cadence. This catches rule hosts that were served
    // from the OS cache (no wire query, so the observer missed them) after
    // boot. First tick (counter 0) seeds early.
    const SEED_EVERY_TICKS: u64 = 30;
    let seed_tick = std::sync::atomic::AtomicU64::new(0);
    ServiceTask::periodic(
        TASK_ID_DNS_OBSERVE,
        TaskClass::Optional,
        DNS_OBSERVE_INTERVAL,
        0,
        move |_stop| {
            let batch = source.drain();
            if !batch.is_empty() {
                let summary = consumer.consume(&batch, SystemTime::now());
                if summary.made_progress() {
                    tracing::info!(
                        target: "nrr::dns-observe",
                        matched = summary.matched,
                        ignored = summary.ignored,
                        collateral = summary.collateral,
                        "DNS observation tick cached new suffix/zone hosts",
                    );
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            let n = seed_tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(SEED_EVERY_TICKS) {
                let seeded = consumer.seed_from_os_cache(SystemTime::now());
                if seeded.made_progress() {
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}

/// Companion-domain proposal tick.
///
/// Harvests the suggestions the DNS-observation feed has been accumulating and
/// acts on them per the active user's `auto_rules_mode`. Deliberately a separate,
/// SLOW task rather than work folded into the 1 Hz observe drain: proposal
/// computation walks the whole candidate table and the exclusions read the rule
/// book, neither of which belongs on a per-observation path. Optional class —
/// the discovery pass is a convenience and its failure must never affect routing.
pub fn build_auto_rules_task(
    engine: Arc<crate::auto_rules::AutoRulesEngine>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_AUTO_RULES,
        TaskClass::Optional,
        AUTO_RULES_INTERVAL,
        0,
        move |_stop| {
            let Some(sid) = active_sid() else {
                tracing::debug!(
                    target: "nrr::auto-rules",
                    "companion-domain tick skipped: no routing-active user",
                );
                return TaskOutcome::Continue;
            };
            let summary = engine.tick(&sid, SystemTime::now());
            if summary.parked > 0 || summary.authored > 0 {
                tracing::info!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    parked = summary.parked,
                    authored = summary.authored,
                    pending = summary.pending,
                    published = summary.published,
                    "companion-domain tick: found addresses a routed site needs",
                );
            } else {
                // An empty tick and a tick that never ran look identical from
                // the outside; say which one happened.
                tracing::debug!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    pending = summary.pending,
                    "companion-domain tick: nothing new",
                );
            }
            TaskOutcome::Continue
        },
    )
}

/// External-address notice tick.
///
/// Watches the routing-active users' additional links and, once one has settled
/// after (re)connecting, asks what address the outside world sees behind it and
/// pushes that to the tray. `Optional`: telling the user their exit address is a
/// courtesy, never a routing dependency.
///
/// The tick itself does no I/O beyond resolving the current link — the probe
/// runs on a detached worker inside the announcer, so a slow or filtered path
/// can never hold this task (or the supervisor behind it) open.
pub fn build_secondary_external_address_task(
    wiring: crate::secondary_external_address::ExternalAddressWiring,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_SECONDARY_EXTERNAL_ADDRESS,
        TaskClass::Optional,
        SECONDARY_EXTERNAL_ADDRESS_INTERVAL,
        0,
        move |_stop| {
            wiring.announcer.tick(&(wiring.links)());
            TaskOutcome::Continue
        },
    )
}

/// Periodic pump that drains passively-observed outbound connections and
/// feeds them to the consumer, which derives each
/// connection's egress interface and emits the trace. Opt-in: only spawned when
/// a connection-observation source + consumer are wired (off by default).
pub fn build_conn_observe_task(
    source: Arc<dyn nrr_platform_api::conn_observe::ConnectionObservationSource>,
    consumer: Arc<crate::conn_observation_consumer::ConnectionObservationConsumer>,
    on_progress: Option<crate::supervised_runtime::RouteRecomputeHook>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_CONN_OBSERVE,
        TaskClass::Optional,
        CONN_OBSERVE_INTERVAL,
        0,
        move |_stop| {
            let batch = source.drain();
            if !batch.is_empty() {
                let summary = consumer.consume(&batch, SystemTime::now());
                if summary.made_progress() {
                    tracing::info!(
                        target: "nrr::conn-trace",
                        total = summary.total,
                        primary = summary.primary,
                        secondary = summary.secondary,
                        loopback = summary.loopback,
                        other = summary.other,
                        unknown = summary.unknown,
                        app_ips_added = summary.app_ips_added,
                        vpn_endpoints_learned = summary.vpn_endpoints_learned,
                        vpn_client_apps_learned = summary.vpn_client_apps_learned,
                        blocked_nrr = summary.blocked_nrr,
                        blocked_foreign = summary.blocked_foreign,
                        // Scope-bug indicator; must stay ~0 (see
                        // `ConnConsumeSummary::killswitch_drops_live_secondary`).
                        // The app-pin half is split out separately below since
                        // it is expected first-contact behaviour, so this line
                        // shows at a glance whether the remainder is the
                        // actionable destination-scoped kind.
                        killswitch_drops_live_secondary = summary.killswitch_drops_live_secondary,
                        killswitch_drops_live_secondary_app_scope =
                            summary.killswitch_drops_live_secondary_app_scope,
                        "connection-observation tick",
                    );
                }
                // New app→IP pairs may give an `Application` rule new
                // destinations; recompute now so they route promptly instead
                // of waiting for the next apply. A newly-learned VPN
                // bootstrap endpoint must likewise arm its exemption before
                // the client's retry, so recompute on that too (not just the
                // 30 s safety tick) — same for a newly-learned VPN client app
                // arming its app-scoped exemption before the client's next
                // check.
                if summary.app_ips_added > 0
                    || summary.vpn_endpoints_learned > 0
                    || summary.vpn_client_apps_learned > 0
                {
                    if let Some(hook) = on_progress.as_ref() {
                        hook();
                    }
                }
            }
            TaskOutcome::Continue
        },
    )
}

// ── IPC accept loop + shutdown watcher ───────────────────────────────────────

/// Shared cell holding the currently-bound `IpcAcceptor`. Replaced
/// atomically when the accept tick rebinds after an `Err` outcome.
/// Both the accept tick (reads to call `accept_one`) and the shutdown
/// watcher (reads to call `request_shutdown`) hold an `Arc` of this cell.
struct IpcAcceptorCell {
    inner: Mutex<Arc<dyn IpcAcceptor>>,
}

impl IpcAcceptorCell {
    fn new(initial: Arc<dyn IpcAcceptor>) -> Self {
        Self {
            inner: Mutex::new(initial),
        }
    }

    /// Snapshot the currently-installed acceptor as an `Arc` clone.
    /// Cheap (one mutex acquire + Arc bump). The mutex is released
    /// before the caller invokes any blocking method on the acceptor.
    fn current(&self) -> Arc<dyn IpcAcceptor> {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(&*g)
    }

    /// Replace the installed acceptor. Used by the accept tick after a
    /// successful rebind in response to `AcceptOutcome::Err`.
    fn replace(&self, new: Arc<dyn IpcAcceptor>) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        *g = new;
    }
}

/// Bundle returned by `build_ipc_accept_task_bundle`. The caller is
/// responsible for spawning **both** tasks on the supervisor — the
/// accept task on its own carries no shutdown affordance, because
/// `IpcAcceptor::accept_one` blocks indefinitely until a client connects
/// or `request_shutdown` is called.
pub struct IpcAcceptTaskBundle {
    pub accept: ServiceTask,
    pub shutdown_watcher: ServiceTask,
}

/// Build the IPC accept-loop and matching shutdown-watcher tasks.
///
/// `bind()` is called eagerly so a misconfigured security descriptor
/// surfaces here instead of deep inside the supervisor's first tick.
/// The resulting `IpcAcceptor` is shared with the watcher via an
/// `IpcAcceptorCell`; every successful rebind in response to
/// `AcceptOutcome::Err` updates the cell so the watcher always signals
/// the *current* listener.
///
/// `TaskClass` and `max_restarts` are derived from
/// `ServiceStabilityConfig.ipc_accept_policy`:
/// - `Recoverable { max_restarts, backoff_base, backoff_cap }` →
///   `Recoverable`, with `max_restarts` clamped into `u8` (the
///   supervisor's restart-attempt counter type) and a per-task
///   `BackoffSchedule` derived from `backoff_base` / `backoff_cap`.
/// - `Critical` → `Critical`, `max_restarts = 0`, default backoff
///   schedule (Critical ignores both, but the fields are populated for
///   telemetry consistency).
///
/// Per-task backoff: the supervisor uses
/// `(backoff_base × attempt).min(backoff_cap)` saturating instead of a
/// hardcoded `100 ms × attempt cap 1 s` schedule.
pub fn build_ipc_accept_task_bundle(
    server: Arc<dyn IpcServer>,
    health: Arc<HealthAggregator>,
    config: &ServiceStabilityConfig,
) -> Result<IpcAcceptTaskBundle, IpcBindError> {
    let (class, max_restarts, accept_backoff) = match &config.ipc_accept_policy {
        IpcAcceptFailurePolicy::Critical => (TaskClass::Critical, 0u8, BackoffSchedule::default()),
        IpcAcceptFailurePolicy::Recoverable {
            max_restarts,
            backoff_base,
            backoff_cap,
        } => {
            let clamped = (*max_restarts).min(u8::MAX as u32) as u8;
            (
                TaskClass::Recoverable,
                clamped,
                BackoffSchedule::new(*backoff_base, *backoff_cap),
            )
        }
    };

    // Eager bind — surfaces misconfiguration to the caller.
    let initial: Arc<dyn IpcAcceptor> = Arc::from(server.bind()?);
    let cell = Arc::new(IpcAcceptorCell::new(initial));

    health.record(
        HealthComponent::Ipc,
        ServiceHealthSeverity::Ok,
        "ipc accept loop bound",
    );

    // Surface the resolved schedule in NDJSON on every bundle build
    // (= service start + every full rebind cycle). Pairs with the
    // "service_stability_config loaded"
    // log emitted by `runtime_deps.rs` so an operator can confirm the
    // wiring end-to-end without provoking IPC failures.
    tracing::info!(
        target: "nrr::stability",
        task = TASK_ID_IPC_ACCEPT_LOOP,
        class = ?class,
        max_restarts,
        backoff_base_ms = u64::try_from(accept_backoff.base.as_millis())
            .unwrap_or(u64::MAX),
        backoff_cap_ms = u64::try_from(accept_backoff.cap.as_millis())
            .unwrap_or(u64::MAX),
        "ipc-accept-loop task scheduled with backoff",
    );

    // ── Accept task ─────────────────────────────────────────────────────
    let accept_cell = Arc::clone(&cell);
    let accept_server = Arc::clone(&server);
    let accept_health = Arc::clone(&health);
    let accept_tick = move |stop: &StopToken| {
        if stop.is_stop_requested() {
            // Drain the current acceptor's workers before exiting so
            // any in-flight request finishes cleanly.
            let acc = accept_cell.current();
            acc.request_shutdown();
            acc.join_workers();
            return TaskOutcome::Done;
        }

        let acc = accept_cell.current();
        match acc.accept_one() {
            AcceptOutcome::Connected | AcceptOutcome::Idle => TaskOutcome::Continue,
            AcceptOutcome::ShutdownRequested => {
                acc.join_workers();
                TaskOutcome::Done
            }
            AcceptOutcome::Err(err) => {
                accept_health.record(
                    HealthComponent::Ipc,
                    ServiceHealthSeverity::Degraded,
                    format!("ipc accept failed: {err}"),
                );
                // Drop our reference to the failed acceptor so the
                // worker handles can wind down. The cell still holds
                // one Arc — replace it after we get a fresh listener.
                drop(acc);
                match accept_server.bind() {
                    Ok(b) => {
                        accept_cell.replace(Arc::from(b));
                        // Returning `Failed` so the supervisor's policy
                        // decides whether to keep going (Recoverable)
                        // or retire (Critical / budget exhausted).
                        TaskOutcome::Failed(format!("accept failed: {err}; rebound"))
                    }
                    Err(rebind_err) => {
                        accept_health.record(
                            HealthComponent::Ipc,
                            ServiceHealthSeverity::Blocking,
                            format!("ipc rebind failed: {rebind_err}"),
                        );
                        TaskOutcome::Failed(format!(
                            "accept failed: {err}; rebind failed: {rebind_err}"
                        ))
                    }
                }
            }
        }
    };
    let accept = ServiceTask {
        id: TaskId::new(TASK_ID_IPC_ACCEPT_LOOP),
        class,
        // Event-driven: one tick = one accept_one call, which itself blocks
        // until a client connects or the shutdown event fires. Supervisor
        // sleeps a token 50 ms between ticks if interval is None — fine
        // here, since accept_one is the time-consuming step.
        interval: None,
        max_restarts,
        backoff: accept_backoff,
        tick: Box::new(accept_tick),
    };

    // ── Shutdown watcher ────────────────────────────────────────────────
    let watcher_cell = Arc::clone(&cell);
    let watcher = ServiceTask::periodic(
        TASK_ID_IPC_SHUTDOWN_WATCHER,
        TaskClass::Optional,
        IPC_SHUTDOWN_WATCHER_INTERVAL,
        0,
        move |stop| {
            if stop.is_stop_requested() {
                let acc = watcher_cell.current();
                acc.request_shutdown();
                TaskOutcome::Done
            } else {
                TaskOutcome::Continue
            }
        },
    );

    Ok(IpcAcceptTaskBundle {
        accept,
        shutdown_watcher: watcher,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_handlers::operation_status_store::OperationStatusStore;
    use crate::managers::{AcceptError, AcceptErrorCategory};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fresh_health() -> Arc<HealthAggregator> {
        Arc::new(HealthAggregator::new())
    }

    #[test]
    fn health_aggregator_task_has_correct_shape() {
        let task = build_health_aggregator_task(fresh_health());
        assert_eq!(task.id.0, TASK_ID_HEALTH_AGGREGATOR);
        assert_eq!(task.class, TaskClass::Recoverable);
        assert_eq!(task.interval, Some(HEALTH_AGGREGATOR_INTERVAL));
        assert_eq!(task.max_restarts, RECOVERABLE_DEFAULT_MAX_RESTARTS);
    }

    #[test]
    fn route_reconcile_safety_task_shape_and_fires_hook_each_tick() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_hook = Arc::clone(&calls);
        let hook: crate::supervised_runtime::RouteRecomputeHook = Arc::new(move || {
            calls_in_hook.fetch_add(1, Ordering::SeqCst);
        });
        let mut task = build_route_reconcile_safety_task(hook);
        assert_eq!(task.id.0, TASK_ID_ROUTE_RECONCILE_SAFETY);
        assert_eq!(task.class, TaskClass::Recoverable);
        assert_eq!(task.interval, Some(ROUTE_RECONCILE_SAFETY_INTERVAL));
        assert_eq!(task.max_restarts, RECOVERABLE_DEFAULT_MAX_RESTARTS);
        // Each tick drives exactly one idempotent recompute.
        let stop = StopToken::new();
        assert_eq!((task.tick)(&stop), TaskOutcome::Continue);
        assert_eq!((task.tick)(&stop), TaskOutcome::Continue);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn diagnostics_cleanup_task_is_optional_with_one_hour_interval() {
        let task = build_diagnostics_cleanup_task(
            PathBuf::from("/tmp/nonexistent"),
            LogRetentionPolicy::default(),
            ManualCleanupScope::default(),
        );
        assert_eq!(task.id.0, TASK_ID_DIAGNOSTICS_CLEANUP);
        assert_eq!(task.class, TaskClass::Optional);
        assert_eq!(task.interval, Some(DIAGNOSTICS_CLEANUP_INTERVAL));
    }

    #[test]
    fn operation_results_gc_task_runs_gc_on_underlying_store() {
        let store = Arc::new(OperationStatusStore::default());
        let mut task = build_operation_results_gc_task(Arc::clone(&store));
        // Tick once to verify it doesn't panic on an empty store.
        let stop = StopToken::new();
        let outcome = (task.tick)(&stop);
        assert_eq!(outcome, TaskOutcome::Continue);
        assert_eq!(task.id.0, TASK_ID_OPERATION_RESULTS_GC);
        assert_eq!(task.class, TaskClass::Optional);
    }

    #[test]
    fn dns_refresh_task_has_optional_class_and_60s_interval() {
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use nrr_platform_api::dns::MockDnsResolver;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::{CacheRepository, MigrationRunner};
        use nrr_storage::store::SqliteCacheStore;
        use rusqlite::Connection;

        let resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort> =
            Arc::new(MockDnsResolver::new());
        let conn = Connection::open_in_memory().expect("in-memory");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let orch = Arc::new(crate::dns_refresh::DnsRefreshOrchestrator::new(
            resolver, cache,
        ));

        let mut task = build_dns_refresh_task(Arc::clone(&orch), None);
        let stop = StopToken::new();
        let outcome = (task.tick)(&stop);
        assert_eq!(outcome, TaskOutcome::Continue);
        assert_eq!(task.id.0, TASK_ID_DNS_REFRESH);
        assert_eq!(task.class, TaskClass::Optional);
        assert_eq!(task.interval, Some(DNS_REFRESH_INTERVAL));
    }

    /// Mock IPC server / acceptor for the bundle tests. The server hands
    /// out acceptors that return a programmable sequence of `AcceptOutcome`
    /// values, then loop on `ShutdownRequested` so tests can drive the
    /// state machine without real Win32 calls.
    #[derive(Default)]
    struct MockServer {
        binds: AtomicUsize,
        // Pre-programmed sequence. Each acceptor pops items as it ticks;
        // when empty, returns ShutdownRequested.
        scripted: Mutex<Vec<AcceptOutcome>>,
        bind_should_fail: AtomicUsize, // remaining bind failures
    }

    impl MockServer {
        fn with_outcomes(outs: Vec<AcceptOutcome>) -> Arc<Self> {
            Arc::new(Self {
                binds: AtomicUsize::new(0),
                scripted: Mutex::new(outs),
                bind_should_fail: AtomicUsize::new(0),
            })
        }
        fn fail_first_bind(self: &Arc<Self>, count: usize) {
            self.bind_should_fail.store(count, Ordering::SeqCst);
        }
    }

    impl IpcServer for MockServer {
        fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
            self.binds.fetch_add(1, Ordering::SeqCst);
            let prev = self.bind_should_fail.load(Ordering::SeqCst);
            if prev > 0 {
                self.bind_should_fail.store(prev - 1, Ordering::SeqCst);
                return Err(IpcBindError::Other("scripted bind failure".into()));
            }
            let drained =
                std::mem::take(&mut *self.scripted.lock().unwrap_or_else(|p| p.into_inner()));
            Ok(Box::new(MockAcceptor {
                outcomes: Mutex::new(drained.into_iter().collect()),
                join_calls: AtomicUsize::new(0),
                shutdown_calls: AtomicUsize::new(0),
            }))
        }
    }

    struct MockAcceptor {
        outcomes: Mutex<std::collections::VecDeque<AcceptOutcome>>,
        join_calls: AtomicUsize,
        shutdown_calls: AtomicUsize,
    }
    impl IpcAcceptor for MockAcceptor {
        fn accept_one(&self) -> AcceptOutcome {
            let mut g = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
            g.pop_front().unwrap_or(AcceptOutcome::ShutdownRequested)
        }
        fn request_shutdown(&self) {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn join_workers(&self) {
            self.join_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn ipc_bundle_recoverable_policy_maps_to_recoverable_task_class() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig {
            ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
                max_restarts: 7,
                backoff_base: Duration::from_millis(100),
                backoff_cap: Duration::from_secs(5),
            },
        };
        let bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind succeeds");
        assert_eq!(bundle.accept.id.0, TASK_ID_IPC_ACCEPT_LOOP);
        assert_eq!(bundle.accept.class, TaskClass::Recoverable);
        assert_eq!(bundle.accept.max_restarts, 7);
        assert_eq!(bundle.accept.interval, None);
        assert_eq!(bundle.shutdown_watcher.id.0, TASK_ID_IPC_SHUTDOWN_WATCHER);
        assert_eq!(bundle.shutdown_watcher.class, TaskClass::Optional);
        assert_eq!(server.binds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ipc_bundle_critical_policy_maps_to_critical_task_class() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig {
            ipc_accept_policy: IpcAcceptFailurePolicy::Critical,
        };
        let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        assert_eq!(bundle.accept.class, TaskClass::Critical);
        assert_eq!(bundle.accept.max_restarts, 0);
    }

    #[test]
    fn ipc_bundle_clamps_huge_max_restarts_into_u8() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig {
            ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
                max_restarts: 10_000,
                backoff_base: Duration::from_millis(100),
                backoff_cap: Duration::from_secs(5),
            },
        };
        let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        assert_eq!(bundle.accept.max_restarts, u8::MAX);
    }

    #[test]
    fn ipc_bundle_carries_backoff_schedule_from_recoverable_policy() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig {
            ipc_accept_policy: IpcAcceptFailurePolicy::Recoverable {
                max_restarts: 30,
                backoff_base: Duration::from_millis(250),
                backoff_cap: Duration::from_secs(15),
            },
        };
        let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        assert_eq!(
            bundle.accept.backoff,
            BackoffSchedule::new(Duration::from_millis(250), Duration::from_secs(15))
        );
        // Sanity: delay_for_attempt actually reflects the wired values.
        assert_eq!(
            bundle.accept.backoff.delay_for_attempt(1),
            Duration::from_millis(250)
        );
        assert_eq!(
            bundle.accept.backoff.delay_for_attempt(100),
            Duration::from_secs(15)
        );
    }

    #[test]
    fn ipc_bundle_uses_default_backoff_for_critical_policy() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig {
            ipc_accept_policy: IpcAcceptFailurePolicy::Critical,
        };
        let bundle = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        // Critical never uses the recoverable arm so the value is moot;
        // but we surface defaults rather than Duration::ZERO so logs /
        // telemetry have a sane value if anyone reads it.
        assert_eq!(bundle.accept.backoff, BackoffSchedule::default());
    }

    #[test]
    fn ipc_bundle_propagates_initial_bind_error() {
        let server = MockServer::with_outcomes(vec![]);
        server.fail_first_bind(1);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let result = build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg);
        assert!(matches!(result, Err(IpcBindError::Other(_))));
    }

    #[test]
    fn ipc_accept_tick_returns_continue_on_connected() {
        let server = MockServer::with_outcomes(vec![AcceptOutcome::Connected]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let mut bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        let stop = StopToken::new();
        let outcome = (bundle.accept.tick)(&stop);
        assert_eq!(outcome, TaskOutcome::Continue);
    }

    #[test]
    fn ipc_accept_tick_returns_done_on_shutdown_requested() {
        let server = MockServer::with_outcomes(vec![AcceptOutcome::ShutdownRequested]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let mut bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        let stop = StopToken::new();
        let outcome = (bundle.accept.tick)(&stop);
        assert_eq!(outcome, TaskOutcome::Done);
    }

    #[test]
    fn ipc_accept_tick_short_circuits_when_stop_already_requested() {
        // Empty outcome script — if the tick read it, accept_one would
        // fall through to ShutdownRequested and then to Done. We want to
        // verify the explicit stop check at the start of the tick fires
        // before that, returning Done without calling accept_one.
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let mut bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        let stop = StopToken::new();
        stop.request_stop();
        let outcome = (bundle.accept.tick)(&stop);
        assert_eq!(outcome, TaskOutcome::Done);
    }

    #[test]
    fn ipc_accept_tick_rebinds_on_err_and_returns_failed() {
        // First tick returns Err → tick rebinds → returns Failed.
        // Bind counter should go from 1 (initial) to 2 (rebind).
        let server = MockServer::with_outcomes(vec![AcceptOutcome::Err(AcceptError {
            category: AcceptErrorCategory::PipeCreate,
            message: "boom".into(),
        })]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let mut bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        let stop = StopToken::new();
        let outcome = (bundle.accept.tick)(&stop);
        assert!(matches!(outcome, TaskOutcome::Failed(_)));
        assert_eq!(server.binds.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn ipc_accept_tick_reports_blocking_when_rebind_fails() {
        let server = MockServer::with_outcomes(vec![AcceptOutcome::Err(AcceptError {
            category: AcceptErrorCategory::PipeCreate,
            message: "boom".into(),
        })]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let health = fresh_health();
        // Initial bind during bundle build must succeed; we arm the
        // failure for the rebind that will follow the Err outcome.
        let mut bundle = build_ipc_accept_task_bundle(server_dyn, Arc::clone(&health), &cfg)
            .expect("first bind");
        server.fail_first_bind(1);
        let stop = StopToken::new();
        let outcome = (bundle.accept.tick)(&stop);
        assert!(matches!(outcome, TaskOutcome::Failed(_)));
        let snap = health.snapshot();
        let ipc = snap
            .components
            .iter()
            .find(|c| c.component == HealthComponent::Ipc)
            .expect("ipc component");
        assert_eq!(ipc.severity, ServiceHealthSeverity::Blocking);
        assert!(ipc.message.contains("rebind failed"));
    }

    #[test]
    fn ipc_shutdown_watcher_returns_done_when_stop_fires() {
        let server = MockServer::with_outcomes(vec![]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let cfg = ServiceStabilityConfig::default();
        let mut bundle =
            build_ipc_accept_task_bundle(server_dyn, fresh_health(), &cfg).expect("bind");
        let stop = StopToken::new();
        // Pre-stop: watcher returns Continue.
        assert_eq!((bundle.shutdown_watcher.tick)(&stop), TaskOutcome::Continue);
        stop.request_stop();
        // Post-stop: watcher returns Done.
        assert_eq!((bundle.shutdown_watcher.tick)(&stop), TaskOutcome::Done);
    }
}

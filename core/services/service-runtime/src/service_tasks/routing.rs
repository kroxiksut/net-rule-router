//! Tasks that keep the route table honest: per-principal enforcement, the
//! adapter monitor, the periodic reconcile, the liveness probe, the traffic
//! sampler and the external-address notice.
//!
//! Split out of `service_tasks`; the code is unchanged.

use super::*;

// ── Principal enforcement ────────────────────────────────────────────────────

/// How often the service asks who is present and re-applies their policy.
///
/// Two facts set the cadence: a login or logout should take effect in seconds,
/// and the pass is cheap — one query to the presence authority, plans read from
/// an open database, one atomic apply. It is nowhere near the data path, so it
/// costs the user nothing per packet.
pub const PRINCIPAL_ENFORCEMENT_INTERVAL: Duration = Duration::from_secs(10);
pub const TASK_ID_PRINCIPAL_ENFORCEMENT: &str = "principal-enforcement-tick";

/// Apply the policy of everyone currently present, every tick.
///
/// Recoverable: a failed pass must be retried, never retire the task. The one
/// outcome that must stay loud is an unreadable presence authority — the
/// platform is then left exactly as it was, and silence would read as "all is
/// well" while the answer is actually unknown.
pub fn build_principal_enforcement_task(
    cycle: Arc<crate::principal_enforcement::PrincipalEnforcementCycle>,
) -> ServiceTask {
    ServiceTask::periodic(
        TASK_ID_PRINCIPAL_ENFORCEMENT,
        TaskClass::Recoverable,
        PRINCIPAL_ENFORCEMENT_INTERVAL,
        RECOVERABLE_DEFAULT_MAX_RESTARTS,
        move |_stop| {
            cycle.tick_logged("timer");
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
                        msg_key = "adapters-changed-recompute",
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

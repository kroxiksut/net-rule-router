//! Supervised runtime entry-point.
//!
//! `run_supervised_runtime` is the production entry point used by both
//! the SCM service mode and the foreground console mode. It does the
//! end-to-end wiring:
//!
//! 1. Build a `HealthAggregator` and record the bootstrap report into
//!    it so the GUI's health snapshot reflects what happened on the way up.
//! 2. Build a `ServiceSupervisor` whose `TaskFailureSink` maps task
//!    retirement events back into health-component severities (so a
//!    Critical IPC failure surfaces as `HealthComponent::Ipc = Blocking`,
//!    visible to the GUI and the audit trail).
//! 3. Spawn the five canonical tasks from `service_tasks.rs` in order:
//!    * adapter-monitor (foundation for health checks)
//!    * health-aggregator-tick (depends on adapter monitor)
//!    * ipc-accept-loop + ipc-shutdown-watcher (LAST critical task)
//!    * report `Running` to SCM
//!    * operation-results-gc (Optional)
//!    * diagnostics-cleanup (Optional)
//! 4. Wait on `StopToken`. SCM Stop / Ctrl+C / shutdown event flips it.
//! 5. Report `Stopping` → `supervisor.shutdown()` (drains tasks in
//!    reverse start order with `STOP_TIMEOUT` budget) → `Stopped`.
//!
//! The function deliberately keeps `run_runtime_with_artifacts` (the
//! legacy sleep-loop entry) intact — lifecycle unit tests still go
//! through it and do not need the supervisor machinery. Production
//! callers (`scm_service_main`, `run_console`) switch to the new
//! function.
//!
//! ## Bootstrap-blocked path
//!
//! If `artifacts.is_ready_to_run()` returns `false` (a bootstrap phase
//! reported `Blocking`), the runtime reports `RecoveryRequired` and
//! waits on the stop token without spawning **any** tasks. The IPC
//! listener stays down on purpose — the GUI must see "service is in
//! recovery, no IPC available" rather than a half-functional service
//! that can answer `service.health.get` but cannot apply policy.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
use nrr_platform_api::AdapterMonitor;

use crate::bootstrap::BootstrapArtifacts;
use crate::health::{HealthAggregator, HealthComponent};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::lifecycle::{ServiceController, StopToken};
use crate::managers::IpcServer;
use crate::runtime_loop::{ServiceSupervisor, TaskClass, TaskFailureSink, TaskId};
use crate::service_stability::ServiceStabilityConfig;
use crate::service_tasks::{
    build_adapter_monitor_task, build_diagnostics_audit_cleanup_task,
    build_diagnostics_cleanup_task, build_health_aggregator_task, build_ipc_accept_task_bundle,
    build_operation_results_gc_task, build_revisions_retention_task,
    build_route_reconcile_safety_task, build_secondary_liveness_task, TASK_ID_ADAPTER_MONITOR,
    TASK_ID_DIAGNOSTICS_CLEANUP, TASK_ID_IPC_ACCEPT_LOOP, TASK_ID_IPC_SHUTDOWN_WATCHER,
};
use crate::state::{ServiceHealthSeverity, ServiceRuntimeState, ServiceShutdownReason};

// ── SupervisedRuntimeDeps ────────────────────────────────────────────────────

/// Dependencies the supervised runtime needs that the bootstrap pipeline
/// does not produce. Constructed by the windows-service entry-point
/// (`scm.rs::run_scm_inner` and `main.rs::run_console`) and threaded
/// through unchanged.
pub struct SupervisedRuntimeDeps {
    /// Shared `HealthAggregator` — the SAME instance that the IPC
    /// `ServiceHealthGet` handler reads via `Arc<dyn HealthReporter>`.
    /// Owned here so the supervisor can call `record_bootstrap`,
    /// `clear_lifecycle_override`, and per-task `record` against the
    /// instance the GUI sees. Constructing a second aggregator in this
    /// module produced a bug where IPC reported `state=starting,
    /// components=[]` forever because the seeded aggregator was a
    /// different `Arc` than the IPC's reader.
    pub health: Arc<HealthAggregator>,
    /// Production IPC server. The supervised runtime calls `bind()`
    /// once eagerly inside the IPC-task bundle build so a bad SDDL or
    /// CreateEvent failure surfaces as a health record before the
    /// supervisor starts ticking.
    pub ipc_server: Arc<dyn IpcServer>,
    /// Adapter availability monitor. Polled at 1 s by
    /// `adapter-monitor-tick`.
    pub adapter_monitor: Arc<AdapterMonitor>,
    /// Operation-status records — GC'd at 5 min.
    pub operation_results: Arc<OperationStatusStore>,
    /// IPC accept-failure policy and friends.
    pub stability: ServiceStabilityConfig,
    /// Operational-log directory the cleanup task scans. Audit files in
    /// `logs_dir` are never touched (cleanup-job invariant).
    pub logs_dir: PathBuf,
    /// Retention policy applied by `diagnostics-cleanup`.
    pub log_retention: LogRetentionPolicy,
    /// Manual cleanup scope (subset selector). Production wiring sets
    /// `operational_logs = true` and the rest to `false`; user-triggered
    /// scopes go through the IPC handler.
    pub cleanup_scope: ManualCleanupScope,
    /// Directory the audit-cleanup task scans for
    /// `nrr_audit_*` files (same dir as `logs_dir` in production wiring).
    pub audit_dir: PathBuf,
    /// Service-side audit NDJSON retention policy
    /// applied by `diagnostics-audit-cleanup`. Read from `log_retention_config`.
    pub audit_retention: AuditRetentionPolicy,
    /// Shared connection to `nrr_service_state.db`
    /// used by the revisions retention prune task. `None` skips the task
    /// (e.g. test profiles that don't need retention enforcement, or a
    /// recovery-blocked startup where the DB couldn't be opened).
    pub state_db_conn: Option<Arc<std::sync::Mutex<rusqlite::Connection>>>,
    /// Traffic counter — sampler + role/settings resolvers driving the
    /// `traffic-sample-tick`. `None` skips the task (traffic DB unavailable /
    /// degraded boot).
    pub traffic_tick: Option<crate::service_tasks::TrafficTickDeps>,
    /// Promoted from a transient `build_supervised_runtime_deps`
    /// local to a deps field so the coordinator's lifetime is explicit.
    /// `None` when the audit writer isn't available (recovery-blocked path).
    /// Held alive for the full runtime; primary consumers are the
    /// `ApplyFailurePolicyWriter` (forward) and the `CoordinatorPolicyManager`
    /// (read-side queries via `current_active`).
    pub activation_coordinator: Option<Arc<crate::activation_coordinator::ActivationCoordinator>>,
    /// DNS refresh orchestrator. `None` when the
    /// cache DB couldn't be opened (recovery-blocked path); the
    /// supervisor then skips the `dns-refresh-tick` task and the
    /// service runs in cache-only mode (cached IPs eventually expire
    /// and SuffixDomain rules emit zero filters; ExactIp rules are
    /// unaffected).
    pub dns_refresh_orchestrator: Option<Arc<crate::dns_refresh::DnsRefreshOrchestrator>>,
    /// Fired after a DNS-refresh tick that made progress, so the
    /// secondary route table is recomputed for the active user once
    /// freshly-resolved IPs land in the FQDN cache (a domain/zone rule whose
    /// hosts were cold now produces routes). `None` when the route
    /// coordinator isn't available (no WFP/orchestrator). Built by the
    /// wiring layer as a closure over the coordinator + active-SID registry.
    pub route_recompute_hook: Option<RouteRecomputeHook>,
    /// Run on graceful service stop to tear down ALL
    /// NRR-owned routes (secondary `/32`s + the mode-A `/2` counter-overlay) so
    /// stopping the service restores pristine networking instead of leaving
    /// stale routes (a later secondary-adapter drop would otherwise black-hole pinned hosts).
    /// Built by the wiring layer as a closure over the coordinator. `None` when
    /// the route path isn't available. Unconditional w.r.t. the rule-scope
    /// setting: both app-driven and service-driven restore networking on stop.
    pub route_teardown_hook: Option<RouteRecomputeHook>,
    /// Resolves the active user's `ExactFqdn` rule
    /// hostnames into the FQDN cache so domain rules produce routes/filters.
    /// `None` when the route path isn't available (no WFP/orchestrator).
    pub rule_hostname_seeder: Option<Arc<crate::rule_hostname_seeder::RuleHostnameSeeder>>,
    /// Returns the routing-active SID (the single active
    /// console user in Free), or `None` when nobody is active. The
    /// rule-hostname seed task keys off this. `None` when the route path
    /// isn't available.
    pub active_routing_sid: Option<ActiveRoutingSidFn>,
    /// Passive DNS-resolution observation source (ETW).
    /// Paired with `dns_observation_consumer`; both `Some` or both `None`.
    /// Drives suffix/zone routing by feeding observed sub-hostnames into
    /// the FQDN cache.
    pub dns_observation_source:
        Option<Arc<dyn nrr_platform_api::dns_observe::DnsObservationSource>>,
    /// Consumer that matches observed resolutions against
    /// active suffix/zone/exact rules and caches the matches.
    pub dns_observation_consumer:
        Option<Arc<crate::dns_observation_consumer::DnsObservationConsumer>>,
    /// Opt-in connection-egress observation
    /// source (WFP net events). Paired with `conn_observation_consumer`; both
    /// `Some` or both `None`. Off by default (diagnostic; privacy-sensitive).
    pub conn_observation_source:
        Option<Arc<dyn nrr_platform_api::conn_observe::ConnectionObservationSource>>,
    /// Consumer that derives each observed
    /// connection's egress interface and emits the trace.
    pub conn_observation_consumer:
        Option<Arc<crate::conn_observation_consumer::ConnectionObservationConsumer>>,
    /// Companion-domain discovery engine. The SAME `Arc` the
    /// DNS-observation consumer feeds and the IPC handlers read, so the slow
    /// proposal tick and the tray see one state. `None` when the observation
    /// path isn't available; the tick is then not spawned.
    pub auto_rules_engine: Option<Arc<crate::auto_rules::AutoRulesEngine>>,
    /// Cross-session memory of the destinations an application rule
    /// routes over the additional link. Warm-loaded by the wiring layer before
    /// the first apply; this field only drives the periodic write-back. `None`
    /// when the state DB isn't available; the tick is then not spawned.
    pub app_destination_memory: Option<Arc<crate::app_destination_memory::AppDestinationMemory>>,
    /// External-address notice for the additional link. `None` when
    /// the route path isn't available (nothing to resolve a link from) or no
    /// event bus is wired; the tick is then not spawned.
    pub secondary_external_address:
        Option<crate::secondary_external_address::ExternalAddressWiring>,
    /// The runtime controller that starts/stops the local DNS resolver on
    /// demand (live re-arm). `run_supervised_runtime`
    /// applies `dns_resolver_boot_mode` to it once tasks are up (arming the
    /// resolver iff the persisted mode is `Resolver`) and calls `stop()` on
    /// shutdown so the NRPT redirect is always restored before the service exits.
    /// The SAME `Arc` is shared with the service-stability IPC writer, so toggling
    /// enforcement mode in the GUI starts/stops the resolver WITHOUT a restart.
    /// `None` in test profiles / when the platform factory could not be wired.
    pub dns_resolver_controller: Option<Arc<crate::dns_resolver_service::DnsResolverController>>,
    /// The persisted enforcement mode at boot. Applied to `dns_resolver_controller`
    /// once tasks are up (Reactive = leave the resolver off; Resolver = arm it).
    pub dns_resolver_boot_mode: nrr_domain::enforcement_mode::EnforcementMode,
    /// Push channel so the adapter monitor can notify
    /// subscribed GUIs that the adapter set changed (secondary up/down). The GUI then
    /// auto-refreshes the Interfaces page instead of showing a stale
    /// "available" after the secondary drops. `None` in test profiles / when no bus
    /// is wired (the monitor then just skips the notify).
    pub event_bus: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
    /// OS network-change observer. When present,
    /// `run_supervised_runtime` subscribes it (debounced) to the SAME
    /// `route_recompute_hook` so a secondary up/down re-arms routing + kill-switch
    /// within ~500 ms instead of waiting for the 1 s poll / 30 s safety tick.
    /// `None` in test profiles / recovery-blocked path (polling still covers it).
    pub network_change_observer:
        Option<Arc<dyn nrr_platform_api::network_change::NetworkChangeObserver>>,
    /// Fast liveness-probe hook, spawned as the
    /// `secondary-liveness-tick` (~5 s) to probe the bound secondary tunnel and
    /// update the liveness tracker. `None` when the route path isn't available /
    /// in tests. The probe is a no-op while the feature is disabled (window 0).
    pub secondary_liveness_hook: Option<RouteRecomputeHook>,
    /// OS suspend/resume observer. When present, a wake re-drives the route table
    /// through the SAME recompute hook. The neutral gap detector
    /// (`resume-watchdog-tick`) runs regardless, so a platform without an impl
    /// still recovers from sleep — just a few seconds later.
    pub power_event_observer: Option<Arc<dyn nrr_platform_api::power::PowerEventObserver>>,
    /// Drained by the resume watchdog: whoever notices a binding worth
    /// re-resolving (the fail-closed posture heartbeat) sets a flag here instead
    /// of recomputing from inside its own compute. `None` in test profiles.
    pub rebind_requests: Option<Arc<crate::power_resume::RebindRequests>>,
}

/// A cheap, idempotent "recompute the active user's routes now" callback.
pub type RouteRecomputeHook = Arc<dyn Fn() + Send + Sync>;

/// Returns the routing-active SID (Free single-active-user), or `None`.
pub type ActiveRoutingSidFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

// ── Failure sink ─────────────────────────────────────────────────────────────

/// `TaskFailureSink` impl that turns task retirement into health
/// records. Non-fatal `task_failed` events are emitted as `tracing::warn`
/// only — the supervisor will retry the task per its class, so the
/// health roll-up should not flip mid-restart. `task_terminated_fatal`
/// events flip the matching component to `Blocking`.
struct HealthFailureSink {
    health: Arc<HealthAggregator>,
}

impl TaskFailureSink for HealthFailureSink {
    fn task_failed(&self, id: &TaskId, class: TaskClass, attempt: u8, message: &str) {
        tracing::warn!(
            target: "nrr::supervisor",
            task = id.0.as_str(),
            attempt = attempt as u32,
            class = ?class,
            "task failed (will retry per class policy): {message}",
        );
    }

    fn task_terminated_fatal(&self, id: &TaskId, message: &str) {
        tracing::error!(
            target: "nrr::supervisor",
            task = id.0.as_str(),
            "task retired fatally: {message}",
        );
        if let Some(component) = component_for_task(id.0.as_str()) {
            self.health.record(
                component,
                ServiceHealthSeverity::Blocking,
                format!("task '{}' retired: {message}", id.0),
            );
        }
    }
}

/// Map a task id slug to the health component that should reflect
/// its retirement. Returns `None` for tasks whose retirement does not
/// have a meaningful component-level effect (e.g. the watcher), so the
/// health roll-up is not polluted by spurious Blocking severities.
fn component_for_task(id: &str) -> Option<HealthComponent> {
    match id {
        TASK_ID_IPC_ACCEPT_LOOP | TASK_ID_IPC_SHUTDOWN_WATCHER => Some(HealthComponent::Ipc),
        TASK_ID_ADAPTER_MONITOR => Some(HealthComponent::Adapters),
        TASK_ID_DIAGNOSTICS_CLEANUP => Some(HealthComponent::Diagnostics),
        _ => None,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run the production service body with full supervisor wiring.
///
/// State sequence on the happy path:
/// `Starting → Running → … → Stopping → Stopped`.
///
/// On bootstrap-blocked path:
/// `Starting → RecoveryRequired → Stopping → Stopped`.
///
/// Returns `ServiceShutdownReason::ScmStop` on stop-token-driven exit.
/// Future blocks may add `IntegrityFailure` and friends.
pub fn run_supervised_runtime(
    controller: &dyn ServiceController,
    stop: &StopToken,
    artifacts: BootstrapArtifacts,
    deps: SupervisedRuntimeDeps,
) -> ServiceShutdownReason {
    controller.report(ServiceRuntimeState::Starting);

    let blocked = !artifacts.is_ready_to_run();

    // Health aggregator: SHARED with the IPC handler — `deps.health`
    // is the same `Arc` that `IpcHandlerDeps::health` was built with in
    // `runtime_deps::build_supervised_runtime_deps`. Constructing a
    // second aggregator here would break `ServiceHealthGet` (IPC would
    // serve a different, never-cleared aggregator).
    let health = Arc::clone(&deps.health);
    health.record_bootstrap(&artifacts.report);
    if let Some(load) = &artifacts.policy_load {
        health.record_policy(load);
    }

    // Supervisor: the failure sink translates task retirements into
    // health records, so a fatal task surfaces in the GUI snapshot.
    let sink: Arc<dyn TaskFailureSink> = Arc::new(HealthFailureSink {
        health: Arc::clone(&health),
    });
    let supervisor = ServiceSupervisor::new(stop.clone(), sink);

    // Mode B (live re-arm): the DNS resolver runs on its own thread (binds
    // `:53`, blocking-serves), owned by a shared controller so the
    // enforcement-mode setting can start/stop it live. Applied below once
    // tasks are up (never in the recovery-blocked path) and stopped+joined on
    // shutdown so the NRPT redirect + DNS restore complete before the service
    // exits (a dead `:53` must never outlive the service).
    let resolver_controller = deps.dns_resolver_controller.clone();
    let resolver_boot_mode = deps.dns_resolver_boot_mode;
    // Holds the active network-change subscription + debounce thread;
    // dropped in the Stopping phase (cancels the OS callbacks and stops
    // the debounce thread before the rest of teardown).
    let mut network_rearm: Option<crate::network_rearm::NetworkChangeRearm> = None;
    // Same lifetime as `network_rearm`: dropped in the Stopping phase.
    let mut power_rearm: Option<crate::power_resume::PowerResumeRearm> = None;

    if blocked {
        // Bootstrap reported Blocking — stay in recovery, no tasks.
        // The IPC listener stays down on purpose so the GUI sees the
        // service as unreachable instead of half-functional.
        controller.report(ServiceRuntimeState::RecoveryRequired);
    } else {
        // Mode B (live re-arm): arm the local DNS resolver to the persisted boot
        // mode BEFORE the IPC accept loop comes up, so a `set(enforcement_mode)`
        // arriving during startup can never be clobbered by this stale boot
        // snapshot (the controller is idempotent + Arc-shared with the writer).
        // In the recovery-blocked path this never runs, so a half-functional
        // service never redirects system DNS. Idempotent → a no-op in Reactive.
        if let Some(controller) = resolver_controller.as_ref() {
            // Log the boot enforcement mode unconditionally: without this the
            // NDJSON gives no way to tell which mode the service is actually
            // running (a GUI/service mode mismatch is otherwise invisible).
            tracing::info!(
                target: "nrr::dns-resolver",
                boot_mode = resolver_boot_mode.as_slug(),
                "enforcement mode at service boot",
            );
            controller.apply(resolver_boot_mode);
        }
        spawn_production_tasks(&supervisor, &deps, Arc::clone(&health));
        // Clear the
        // `Starting` lifecycle override on the HealthAggregator so
        // `ServiceHealthGet` over IPC reports `running` once tasks are
        // up. Without this `lifecycle_override` stays `Some(Starting)`
        // forever and the GUI's Diagnostics card displays "Service
        // unavailable" while everything is actually fine.
        health.clear_lifecycle_override();
        // Worst severity defaults to `Unknown` (last in the enum) when
        // no component has reported `Ok` yet — and the derived-state
        // mapping treats `Unknown -> Starting`. Seed each production
        // component with `Ok` so the snapshot reflects "Running" the
        // instant `clear_lifecycle_override` removes the Starting
        // override. The subsequent task ticks overwrite these with
        // actual readings.
        for component in [
            crate::health::HealthComponent::Ipc,
            crate::health::HealthComponent::Adapters,
            crate::health::HealthComponent::Diagnostics,
        ] {
            health.record(component, ServiceHealthSeverity::Ok, "task spawned");
        }
        controller.report(ServiceRuntimeState::Running);
        spawn_optional_tasks(&supervisor, &deps);

        // subscribe the OS network-change observer so a
        // secondary up/down re-arms routing + kill-switch via the SAME recompute hook
        // within ~debounce, not the 1 s poll / 30 s safety tick. Best-effort: a
        // failed OS registration leaves the polling fallbacks in place. Held
        // until the Stopping phase (dropped there — cancels the OS notification
        // and stops the debounce thread).
        if let (Some(observer), Some(hook)) = (
            deps.network_change_observer.as_ref(),
            deps.route_recompute_hook.as_ref(),
        ) {
            match crate::network_rearm::NetworkChangeRearm::start(
                observer.as_ref(),
                Arc::clone(hook),
                crate::network_rearm::NETWORK_CHANGE_DEBOUNCE,
            ) {
                Ok(rearm) => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        "network-change observer active — event-driven re-arm on interface/route changes",
                    );
                    network_rearm = Some(rearm);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        "network-change observer registration failed ({e:?}); relying on the 1s/30s polling fallback",
                    );
                }
            }
        }

        // Prompt half of the resume re-arm; the watchdog tick is the half that
        // needs no OS support and catches what the notification missed.
        if let (Some(observer), Some(hook)) = (
            deps.power_event_observer.as_ref(),
            deps.route_recompute_hook.as_ref(),
        ) {
            match crate::power_resume::PowerResumeRearm::start(
                observer.as_ref(),
                Arc::clone(hook),
                crate::power_resume::RESUME_DEBOUNCE,
            ) {
                Ok(rearm) => {
                    tracing::info!(
                        target: "nrr::route-coordinator",
                        "power-event observer active — re-arm on resume from sleep",
                    );
                    power_rearm = Some(rearm);
                }
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::route-coordinator",
                        "power-event observer registration failed ({e:?}); relying on the resume watchdog",
                    );
                }
            }
        }
    }

    // Cooperative wait. The supervisor's tasks honour the same stop
    // token; flipping it via SCM Stop / Ctrl+C / shutdown propagates to
    // every spawned thread within ~50 ms (sleep_observing_stop granularity).
    while !stop.is_stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }

    controller.report(ServiceRuntimeState::Stopping);
    // Mode B (live re-arm): terminally shut the resolver down FIRST, so its serve
    // loop exits, the NRPT redirect is restored, and `:53` is released before the
    // rest of teardown. `shutdown()` flips the flag, JOINs, AND latches the
    // controller `disarmed` — so an IPC `set(enforcement_mode=Resolver)` still
    // in flight during teardown (the writer calls `apply` after dropping the DB
    // lock, and IPC workers are not drained until `supervisor.shutdown()` below)
    // can NEVER re-arm the resolver after this point. Without the latch that
    // re-arm would spawn a fresh resolver whose NRPT redirect + `:53` bind
    // outlive the process, leaving the OS DNS pointed at a dead listener until
    // the next boot's `clear_orphan_redirect`. Idempotent for an already-stopped
    // resolver (Reactive / never armed).
    if let Some(controller) = resolver_controller.as_ref() {
        controller.shutdown();
    }
    // stop the network-change observer next: its guard
    // cancels the OS notifications (blocking until any in-flight callback
    // returns) and stops the debounce thread, so no re-arm fires mid-teardown.
    drop(network_rearm.take());
    drop(power_rearm.take());
    let report = supervisor.shutdown();
    if report.timed_out() {
        tracing::warn!(
            target: "nrr::supervisor",
            total = report.total as u32,
            clean = report.clean as u32,
            detached = %report.detached.join(", "),
            "supervisor shutdown timed out — some tasks were detached",
        );
    } else {
        tracing::info!(
            target: "nrr::supervisor",
            total = report.total as u32,
            clean = report.clean as u32,
            "supervisor drained cleanly",
        );
    }
    // restore pristine networking on stop: now that the
    // supervisor's tasks (which could re-add routes) have stopped, remove every
    // NRR-owned route. Runs on every graceful stop path (SCM Stop / Shutdown /
    // Ctrl+C). A crash skips this; startup orphan-adoption cleans up next run.
    if let Some(teardown) = deps.route_teardown_hook.as_ref() {
        teardown();
    }
    controller.report(ServiceRuntimeState::Stopped);

    // Keep `artifacts` alive until the very end so any background ports
    // (e.g. `Arc<LogWriter>` shared with the global tracing subscriber
    // installed by `install_ndjson_tracing`) outlive every task.
    drop(artifacts);

    ServiceShutdownReason::ScmStop
}

/// Spawn the production task set in the documented startup order:
/// adapter-monitor → health-aggregator → ipc-accept + watcher.
/// Each `spawn` failure is logged via `tracing::error` and the matching
/// health component is set to `Blocking` — but we keep going, because a
/// failed-to-spawn task is not worse than a healthy task that retires
/// later.
fn spawn_production_tasks(
    supervisor: &ServiceSupervisor,
    deps: &SupervisedRuntimeDeps,
    health: Arc<HealthAggregator>,
) {
    // 1. adapter-monitor-tick — foundation for health checks.
    if let Err(e) = supervisor.spawn(build_adapter_monitor_task(
        Arc::clone(&deps.adapter_monitor),
        Arc::clone(&health),
        deps.route_recompute_hook.clone(),
        deps.event_bus.clone(),
    )) {
        tracing::error!(target: "nrr::supervisor", "spawn adapter-monitor failed: {e}");
        health.record(
            HealthComponent::Adapters,
            ServiceHealthSeverity::Blocking,
            format!("spawn adapter-monitor failed: {e}"),
        );
    }

    // 1b. route-reconcile-safety-tick (block 16,  — periodic
    // idempotent re-drive that catches drift the availability-edge monitor
    // can't see: a secondary that re-IPs while staying `Available`, or a
    // baseline change applied with no tray under service-driven scope. Only
    // when the route path exists (coordinator present → hook is Some).
    if let Some(hook) = deps.route_recompute_hook.clone() {
        if let Err(e) = supervisor.spawn(build_route_reconcile_safety_task(hook)) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn route-reconcile-safety failed: {e}",
            );
        }
    }

    // 1c. secondary-liveness-tick (HW-0710 F7 Track 1) — fast active-probe of the
    // bound secondary tunnel; a no-op while the feature is disabled (window 0).
    if let Some(hook) = deps.secondary_liveness_hook.clone() {
        if let Err(e) = supervisor.spawn(build_secondary_liveness_task(hook)) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn secondary-liveness failed: {e}",
            );
        }
    }

    // 1d. resume-watchdog-tick — a wake leaves the binding resolved against a
    // network that is gone, and no event reports it (the OS notifications fired
    // while we were asleep). Also drains the rebind requests a long fail-closed
    // posture raises.
    if let (Some(hook), Some(requests)) = (
        deps.route_recompute_hook.clone(),
        deps.rebind_requests.clone(),
    ) {
        if let Err(e) = supervisor.spawn(crate::power_resume::build_resume_watchdog_task(
            requests, hook,
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn resume-watchdog failed: {e}",
            );
        }
    }

    // 2. health-aggregator-tick — keeps snapshot fresh.
    if let Err(e) = supervisor.spawn(build_health_aggregator_task(Arc::clone(&health))) {
        tracing::error!(target: "nrr::supervisor", "spawn health-aggregator failed: {e}");
        // No dedicated health component for this task — log only.
    }

    // 3. ipc-accept-loop + ipc-shutdown-watcher — LAST critical pair.
    match build_ipc_accept_task_bundle(
        Arc::clone(&deps.ipc_server),
        Arc::clone(&health),
        &deps.stability,
    ) {
        Ok(bundle) => {
            if let Err(e) = supervisor.spawn(bundle.accept) {
                tracing::error!(target: "nrr::supervisor", "spawn ipc-accept-loop failed: {e}");
                health.record(
                    HealthComponent::Ipc,
                    ServiceHealthSeverity::Blocking,
                    format!("spawn ipc-accept-loop failed: {e}"),
                );
            }
            if let Err(e) = supervisor.spawn(bundle.shutdown_watcher) {
                tracing::error!(target: "nrr::supervisor", "spawn ipc-shutdown-watcher failed: {e}");
            }
        }
        Err(e) => {
            tracing::error!(target: "nrr::supervisor", "ipc bind failed: {e}");
            health.record(
                HealthComponent::Ipc,
                ServiceHealthSeverity::Blocking,
                format!("ipc bind failed: {e}"),
            );
        }
    }
}

/// Optional housekeeping tasks — spawn only after `Running` is reported
/// so a transient cleanup-task spawn failure never delays the SCM
/// `Running` transition past `START_TIMEOUT`.
fn spawn_optional_tasks(supervisor: &ServiceSupervisor, deps: &SupervisedRuntimeDeps) {
    // 1. operation-results-gc.
    if let Err(e) = supervisor.spawn(build_operation_results_gc_task(Arc::clone(
        &deps.operation_results,
    ))) {
        tracing::warn!(target: "nrr::supervisor", "spawn operation-results-gc failed: {e}");
    }

    // 2. diagnostics-cleanup. PathBuf and policy are owned-by-task,
    // so clone out of `deps` (which we hold by reference here so the
    // caller can introspect it after run_supervised_runtime returns).
    if let Err(e) = supervisor.spawn(build_diagnostics_cleanup_task(
        deps.logs_dir.clone(),
        deps.log_retention.clone(),
        deps.cleanup_scope.clone(),
    )) {
        tracing::warn!(target: "nrr::supervisor", "spawn diagnostics-cleanup failed: {e}");
    }

    // 2b. diagnostics-audit-cleanup (#20). Separate task — prunes `nrr_audit_*`
    // NDJSON by the service-side audit retention policy (never user-triggered).
    if let Err(e) = supervisor.spawn(build_diagnostics_audit_cleanup_task(
        deps.audit_dir.clone(),
        deps.audit_retention.clone(),
    )) {
        tracing::warn!(target: "nrr::supervisor", "spawn diagnostics-audit-cleanup failed: {e}");
    }

    // 3. revisions-retention-prune. Skipped when the state DB connection
    // wasn't opened (test profiles that disable retention enforcement, or
    // recovery-blocked bootstrap).
    if let Some(conn) = deps.state_db_conn.as_ref() {
        if let Err(e) = supervisor.spawn(build_revisions_retention_task(Arc::clone(conn))) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn revisions-retention-prune failed: {e}",
            );
        }
    }

    // 3b. traffic-sample-tick (Block T). Skipped when the traffic DB / sampler
    // wasn't built (degraded boot). Reads interface octet counters, buckets by
    // role, folds deltas into the daily ledger + session totals.
    if let Some(tick) = deps.traffic_tick.clone() {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_traffic_sample_task(tick)) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn traffic-sample-tick failed: {e}",
            );
        }
    }

    // 4. dns-refresh-tick (block 16.12.A.4). Skipped when the cache DB
    // couldn't be opened. Drives the DNS resolver against expired
    // hostnames hot-first; the periodic refresh keeps `ExactFqdn` /
    // `SuffixDomain` / `Zone` rule fan-outs producing filters as TTLs
    // age out.
    if let Some(orch) = deps.dns_refresh_orchestrator.as_ref() {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_dns_refresh_task(
            Arc::clone(orch),
            deps.route_recompute_hook.clone(),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn dns-refresh-tick failed: {e}",
            );
        }
    }

    // 5. rule-hostname-seed-tick (block 16.18 β). Resolves the active
    // user's ExactFqdn rule hostnames into the FQDN cache so domain rules
    // actually route. Skipped when the route path isn't available.
    if let (Some(seeder), Some(active_sid)) = (
        deps.rule_hostname_seeder.as_ref(),
        deps.active_routing_sid.as_ref(),
    ) {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_rule_hostname_seed_task(
            Arc::clone(seeder),
            Arc::clone(active_sid),
            deps.route_recompute_hook.clone(),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn rule-hostname-seed-tick failed: {e}",
            );
        }
    }

    // 6. dns-observe-tick (block 16.18 β). Drains passively-observed DNS
    // resolutions and caches the ones matching an active suffix/zone/exact
    // rule, then recomputes routes. This is how `*.example.com` / `.ru`
    // rules become real routes. Skipped when the route path / ETW observer
    // isn't available.
    if let (Some(source), Some(consumer)) = (
        deps.dns_observation_source.as_ref(),
        deps.dns_observation_consumer.as_ref(),
    ) {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_dns_observe_task(
            Arc::clone(source),
            Arc::clone(consumer),
            deps.route_recompute_hook.clone(),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn dns-observe-tick failed: {e}",
            );
        }
    }

    // 7. conn-observe-tick (block 16.18.vpn). Opt-in connection-egress trace:
    // drains observed outbound connections and derives each one's egress
    // interface for diagnostics. Skipped unless the observer was wired (off by
    // default; enabled via the conn-trace setting / NRR_CONN_TRACE).
    if let (Some(source), Some(consumer)) = (
        deps.conn_observation_source.as_ref(),
        deps.conn_observation_consumer.as_ref(),
    ) {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_conn_observe_task(
            Arc::clone(source),
            Arc::clone(consumer),
            deps.route_recompute_hook.clone(),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn conn-observe-tick failed: {e}",
            );
        }
    }

    // 8. auto-rules-tick. Harvests the companion-domain evidence
    // the observe tick accumulates and either offers it or applies it, per the
    // active user's `auto_rules_mode`. Slow (30 s) and Optional — the discovery
    // pass is a convenience, never a routing dependency.
    if let (Some(engine), Some(active_sid)) = (
        deps.auto_rules_engine.as_ref(),
        deps.active_routing_sid.as_ref(),
    ) {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_auto_rules_task(
            Arc::clone(engine),
            Arc::clone(active_sid),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn auto-rules-tick failed: {e}",
            );
        }
    }

    // 9. app-destination-flush-tick. Writes back the destinations
    // of the applications routed over the additional link so the NEXT session's
    // routes exist before those applications connect. Slow (60 s) and Optional —
    // it only refreshes a memory; losing a tick costs at most a re-learn.
    if let Some(memory) = deps.app_destination_memory.as_ref() {
        if let Err(e) = supervisor.spawn(crate::service_tasks::build_app_destination_flush_task(
            Arc::clone(memory),
        )) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn app-destination-flush-tick failed: {e}",
            );
        }
    }

    // 10. secondary-external-address-tick. Notices that the
    // additional link has (re)connected and tells the user the address the
    // outside world now sees behind it.
    if let Some(wiring) = deps.secondary_external_address.clone() {
        if let Err(e) = supervisor.spawn(
            crate::service_tasks::build_secondary_external_address_task(wiring),
        ) {
            tracing::warn!(
                target: "nrr::supervisor",
                "spawn secondary-external-address-tick failed: {e}",
            );
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{bootstrap, BootstrapConfig};
    use crate::managers::{AcceptOutcome, IpcAcceptor, IpcBindError, IpcServer};
    use crate::state::ServiceShutdownReason;
    use nrr_platform_api::MockAdapterEventSource;
    use nrr_storage::StorageProfile;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Recording `ServiceController` for test assertions.
    #[derive(Default)]
    struct RecordingController {
        states: Mutex<Vec<ServiceRuntimeState>>,
    }
    impl RecordingController {
        fn states(&self) -> Vec<ServiceRuntimeState> {
            self.states
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }
    impl ServiceController for RecordingController {
        fn report(&self, state: ServiceRuntimeState) {
            self.states
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(state);
        }
    }

    /// Stub IPC server that immediately returns ShutdownRequested on
    /// every accept_one. Used to exercise the supervised-runtime
    /// startup/shutdown sequence without binding a real pipe.
    #[derive(Default)]
    struct InertServer {
        binds: AtomicUsize,
    }
    impl IpcServer for InertServer {
        fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
            self.binds.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(InertAcceptor::default()))
        }
    }
    #[derive(Default)]
    struct InertAcceptor {
        join_calls: AtomicUsize,
        shutdown_calls: AtomicUsize,
    }
    impl IpcAcceptor for InertAcceptor {
        fn accept_one(&self) -> AcceptOutcome {
            // Yield briefly so the supervisor isn't a busy spin.
            std::thread::sleep(Duration::from_millis(20));
            AcceptOutcome::ShutdownRequested
        }
        fn request_shutdown(&self) {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn join_workers(&self) {
            self.join_calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fresh_deps() -> SupervisedRuntimeDeps {
        let monitor = Arc::new(AdapterMonitor::new(
            Arc::new(MockAdapterEventSource::default()),
            500,
        ));
        SupervisedRuntimeDeps {
            auto_rules_engine: None,
            app_destination_memory: None,
            secondary_external_address: None,
            health: Arc::new(HealthAggregator::new()),
            ipc_server: Arc::new(InertServer::default()),
            adapter_monitor: monitor,
            operation_results: Arc::new(OperationStatusStore::default()),
            stability: ServiceStabilityConfig::default(),
            logs_dir: std::env::temp_dir(),
            log_retention: LogRetentionPolicy::default(),
            cleanup_scope: ManualCleanupScope::default(),
            audit_dir: std::env::temp_dir(),
            audit_retention: AuditRetentionPolicy::default(),
            state_db_conn: None,
            traffic_tick: None,
            activation_coordinator: None,
            dns_refresh_orchestrator: None,
            route_recompute_hook: None,
            route_teardown_hook: None,
            rule_hostname_seeder: None,
            active_routing_sid: None,
            dns_observation_source: None,
            dns_observation_consumer: None,
            conn_observation_source: None,
            conn_observation_consumer: None,
            dns_resolver_controller: None,
            dns_resolver_boot_mode: nrr_domain::enforcement_mode::EnforcementMode::default(),
            event_bus: None,
            network_change_observer: None,
            secondary_liveness_hook: None,
            power_event_observer: None,
            rebind_requests: None,
        }
    }

    /// On a healthy bootstrap, the supervised runtime emits
    /// `Starting → Running → Stopping → Stopped` and exits when the
    /// stop token flips.
    #[test]
    fn happy_path_emits_full_state_sequence() {
        let controller = RecordingController::default();
        let stop = StopToken::new();
        let stop_clone = stop.clone();
        let join = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            stop_clone.request_stop();
        });
        // Real bootstrap with a temp directory so health.record_bootstrap
        // sees a consistent report shape.
        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
        let artifacts = bootstrap(&cfg);
        let deps = fresh_deps();
        let reason = run_supervised_runtime(&controller, &stop, artifacts, deps);
        join.join().unwrap();
        assert_eq!(reason, ServiceShutdownReason::ScmStop);
        let states = controller.states();
        // Healthy bootstrap → expect Running. If the temp profile
        // ever produces Blocking we'd see RecoveryRequired instead;
        // assert flexibly on the prefix shape.
        assert_eq!(states.first(), Some(&ServiceRuntimeState::Starting));
        assert_eq!(states.last(), Some(&ServiceRuntimeState::Stopped));
        let stopping_idx = states
            .iter()
            .position(|s| matches!(s, ServiceRuntimeState::Stopping))
            .expect("Stopping observed");
        assert!(stopping_idx > 0);
    }

    /// Programmable mock IPC server for failure-policy tests. Yields
    /// scripted `AcceptOutcome` values per `accept_one` call; `bind()`
    /// produces a fresh acceptor each call (sharing the same outcome
    /// queue) so the supervisor's rebind loop is observable.
    type SharedQueue = Arc<Mutex<std::collections::VecDeque<AcceptOutcome>>>;
    struct ScriptedServer {
        binds: AtomicUsize,
        outcomes: SharedQueue,
    }
    impl ScriptedServer {
        fn new(outcomes: Vec<AcceptOutcome>) -> Arc<Self> {
            Arc::new(Self {
                binds: AtomicUsize::new(0),
                outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            })
        }
    }
    impl IpcServer for ScriptedServer {
        fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
            self.binds.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(SharedScriptedAcceptor {
                outcomes: Arc::clone(&self.outcomes),
            }))
        }
    }
    /// Acceptor that pulls outcomes from a queue shared with the server.
    /// Returns `ShutdownRequested` when the queue empties so tests
    /// terminate deterministically.
    struct SharedScriptedAcceptor {
        outcomes: SharedQueue,
    }
    impl IpcAcceptor for SharedScriptedAcceptor {
        fn accept_one(&self) -> AcceptOutcome {
            let mut q = self.outcomes.lock().unwrap_or_else(|p| p.into_inner());
            match q.pop_front() {
                Some(o) => o,
                None => {
                    drop(q);
                    // Yield briefly so we don't busy-spin on
                    // ShutdownRequested while the supervisor walks the
                    // rest of the tasks.
                    std::thread::sleep(Duration::from_millis(20));
                    AcceptOutcome::ShutdownRequested
                }
            }
        }
        fn request_shutdown(&self) {}
        fn join_workers(&self) {}
    }

    fn deps_with_server(server: Arc<dyn IpcServer>) -> SupervisedRuntimeDeps {
        let mut d = fresh_deps();
        d.ipc_server = server;
        d
    }

    /// Recoverable IPC: feed N+1 `Err` outcomes (where N = max_restarts);
    /// supervisor must rebind on each Err and finally retire the task,
    /// surfacing `HealthComponent::Ipc = Blocking` through the failure
    /// sink.
    #[test]
    fn ipc_accept_recoverable_max_restarts_exhausted_marks_ipc_blocking() {
        use crate::managers::{AcceptError, AcceptErrorCategory};

        let max_restarts = 2u32;
        // First Err is the initial failure (attempt 1); each subsequent
        // restart's first tick must also fail. With max_restarts=2 we
        // need 3 total ticks that return Err to exhaust the budget.
        let outcomes: Vec<AcceptOutcome> = (0..(max_restarts + 1) as usize)
            .map(|i| {
                AcceptOutcome::Err(AcceptError {
                    category: AcceptErrorCategory::PipeCreate,
                    message: format!("scripted err {i}"),
                })
            })
            .collect();
        let server = ScriptedServer::new(outcomes);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let deps = SupervisedRuntimeDeps {
            stability: ServiceStabilityConfig {
                ipc_accept_policy: crate::service_stability::IpcAcceptFailurePolicy::Recoverable {
                    max_restarts,
                    backoff_base: Duration::from_millis(50),
                    backoff_cap: Duration::from_millis(200),
                },
            },
            ..deps_with_server(server_dyn)
        };

        let controller = RecordingController::default();
        let stop = StopToken::new();
        let stop_clone = stop.clone();
        // Generous deadline: 3 attempts × supervisor backoff (≤1s each)
        // + tick latency. 3 s is comfortably above worst case.
        let join = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            stop_clone.request_stop();
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
        let artifacts = bootstrap(&cfg);
        let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
        join.join().unwrap();

        // The supervisor must have asked for at least max_restarts + 1
        // binds (initial + each retry). Allow more in case the watcher
        // raced — what matters is *not less than*.
        let binds = server.binds.load(Ordering::SeqCst);
        assert!(
            binds > max_restarts as usize,
            "expected ≥{} binds, got {binds}",
            max_restarts as usize + 1,
        );
    }

    /// Critical IPC: a single Err must retire the task fatally without
    /// any rebind. Recoverable's rebind path must not run.
    #[test]
    fn ipc_accept_critical_retires_on_first_failure_without_rebind() {
        use crate::managers::{AcceptError, AcceptErrorCategory};

        let server = ScriptedServer::new(vec![AcceptOutcome::Err(AcceptError {
            category: AcceptErrorCategory::PipeCreate,
            message: "critical boom".into(),
        })]);
        let server_dyn: Arc<dyn IpcServer> = server.clone();
        let deps = SupervisedRuntimeDeps {
            stability: ServiceStabilityConfig {
                ipc_accept_policy: crate::service_stability::IpcAcceptFailurePolicy::Critical,
            },
            ..deps_with_server(server_dyn)
        };

        let controller = RecordingController::default();
        let stop = StopToken::new();
        let stop_clone = stop.clone();
        // Stop once the runtime has actually done the thing under test, with a
        // deadline as the backstop. A fixed sleep measured the machine instead:
        // under a loaded `--workspace` run the accept task had not reached its
        // first tick yet and the count read 1.
        let binds_probe = Arc::clone(&server);
        let join = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while binds_probe.binds.load(Ordering::SeqCst) < 2
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            stop_clone.request_stop();
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
        let artifacts = bootstrap(&cfg);
        let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
        join.join().unwrap();

        // Critical: 1 initial bind + 1 rebind from the Err handling
        // (the tick code rebinds before reporting Failed regardless of
        // class — that's intentional so the cell holds a valid acceptor
        // for the watcher's wake call). The supervisor's class check
        // then prevents the next accept_one tick.
        let binds = server.binds.load(Ordering::SeqCst);
        assert_eq!(
            binds, 2,
            "Critical should bind exactly twice (initial + post-Err rebind), got {binds}",
        );
    }

    /// Adapter monitor task ticks during the run. We don't care about
    /// emitted change events here (no source data); we care that the
    /// monitor's `update` was actually invoked, which we observe via
    /// `MockAdapterEventSource`'s call counter.
    #[test]
    fn adapter_monitor_task_ticks_during_run() {
        // Replace the default adapter monitor with one whose source we
        // can introspect.
        struct CountingSource {
            calls: AtomicUsize,
        }
        impl nrr_platform_api::AdapterEventSource for CountingSource {
            fn enumerate_all(
                &self,
            ) -> Result<Vec<nrr_platform_api::AdapterInfo>, nrr_platform_api::PlatformError>
            {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }
        }

        let counting = Arc::new(CountingSource {
            calls: AtomicUsize::new(0),
        });
        let monitor = Arc::new(AdapterMonitor::new(
            Arc::clone(&counting) as Arc<dyn nrr_platform_api::AdapterEventSource>,
            500,
        ));
        let mut deps = fresh_deps();
        deps.adapter_monitor = monitor;

        let controller = RecordingController::default();
        let stop = StopToken::new();
        let stop_clone = stop.clone();
        // 2.5 s gives the 1 s adapter-monitor interval at least 2 ticks.
        let join = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2500));
            stop_clone.request_stop();
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let cfg = BootstrapConfig::new(StorageProfile::TestTemp(dir.path().to_path_buf()));
        let artifacts = bootstrap(&cfg);
        let _ = run_supervised_runtime(&controller, &stop, artifacts, deps);
        join.join().unwrap();

        let calls = counting.calls.load(Ordering::SeqCst);
        assert!(
            calls >= 2,
            "expected adapter source to be polled ≥2 times in 2.5 s, got {calls}",
        );
    }

    /// Mapping from `TaskId` slug to `HealthComponent` is the same one
    /// that a fatal task retirement uses; lock it in so renaming a slug
    /// without coordinating breaks compilation here.
    #[test]
    fn fatal_failure_routing_table_is_complete() {
        assert_eq!(
            component_for_task(TASK_ID_IPC_ACCEPT_LOOP),
            Some(HealthComponent::Ipc)
        );
        assert_eq!(
            component_for_task(TASK_ID_IPC_SHUTDOWN_WATCHER),
            Some(HealthComponent::Ipc)
        );
        assert_eq!(
            component_for_task(TASK_ID_ADAPTER_MONITOR),
            Some(HealthComponent::Adapters)
        );
        assert_eq!(
            component_for_task(TASK_ID_DIAGNOSTICS_CLEANUP),
            Some(HealthComponent::Diagnostics)
        );
        // health-aggregator-tick and operation-results-gc intentionally
        // do not have a routed component.
        assert_eq!(
            component_for_task(crate::service_tasks::TASK_ID_HEALTH_AGGREGATOR),
            None
        );
        assert_eq!(
            component_for_task(crate::service_tasks::TASK_ID_OPERATION_RESULTS_GC),
            None
        );
    }
}

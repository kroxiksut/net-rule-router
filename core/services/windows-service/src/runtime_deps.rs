//! Production `SupervisedRuntimeDeps` builder.
//!
//! This file exists in the windows-service binary crate (rather than in
//! `nrr-service-runtime`) for two reasons:
//!
//! 1. Construction of `WindowsNamedPipeServer` is Windows-specific and
//!    lives here.
//! 2. The dep bundle gathers things from across the workspace (storage
//!    topology, platform-windows API, diagnostics retention defaults).
//!    Having one place that wires them keeps both call sites — SCM
//!    `scm_service_main` and console `run_console` — consistent.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
use nrr_domain::decision_lookup::FreshnessThresholds;
use nrr_platform_windows::dns::WindowsDnsResolver;
use nrr_platform_windows::wfp::{FilterFailureMode, WfpSession};
use nrr_platform_windows::{
    autostart::{AutostartHelper, ProductionAutostartRegistry},
    AdapterMonitor, ProductionWindowsApi, WindowsApiAdapterSource, WindowsApiPort,
};
use nrr_service_runtime::{
    activation_coordinator::{ActivationCoordinator, ApplyFailurePolicy},
    active_sid_registry::ActiveSidRegistry,
    bootstrap::BootstrapArtifacts,
    dns_refresh::DnsRefreshOrchestrator,
    fqdn_cache_lookup::{FqdnCacheLookup, SqliteFqdnCacheLookup},
    health::{HealthAggregator, HealthComponent},
    ipc_handlers::event_bus::EventBus,
    ipc_handlers::mutation_token_store::MutationTokenStore,
    ipc_handlers::operation_status_store::OperationStatusStore,
    managers::{HealthReporter, PolicyManager},
    per_sid_orchestrator::{
        wire_orchestrator_to_registry, NoopPerSidApplyAudit, OrchestratorRoutePolicyApplyTrigger,
        PerSidApplyAudit, PerSidApplyOrchestrator, RoutePolicySource, RulesProvider,
    },
    production_handlers_misc::ProductionRoutePolicySource,
    production_per_sid_audit::ProductionPerSidApplyAudit,
    production_rules_provider::ProductionRulesProvider,
    register_production_handlers,
    routing_pause::{NoopRoutingPauseAudit, PauseDispatcher, RoutingPauseCoordinator},
    service_stability::ServiceStabilityConfig,
    tamper_bootstrap::run_tamper_bootstrap,
    AdaptersSnapshotProvider, ApplyFailurePolicyProvider, ApplyFailurePolicyWriter,
    AutostartProvider, AutostartWriter, CoordinatorPolicyManager, FakeIpApplyRequest,
    IpcAuditEmitter, IpcHandlerDeps, IpcHandlerRegistry, IpcRouter, IpcServer,
    LogRetentionConfigProvider, LogRetentionConfigWriter, MigrationCompletionWriter,
    MigrationStatusProvider, MonitoredAdaptersSnapshotProvider, MutationExecutor,
    NoopIpcAuditEmitter, NoopPauseDispatcher, NoopRulesApplyDispatcher,
    OrchestratorPauseDispatcher, ProductionActivationAuditEmitter, ProductionApplyFailurePolicy,
    ProductionApplyMarkerStore, ProductionAutostart, ProductionDiagnosticsFacade,
    ProductionIdGenerator, ProductionLogRetentionConfig, ProductionMigrationCompletionWriter,
    ProductionMigrationStatusProvider, ProductionMutationExecutor, ProductionRecoveryAuditSink,
    ProductionRetentionSettings, ProductionRoutePolicyProvider, ProductionRoutePolicyWriter,
    ProductionRoutingPause, ProductionRulesApplyDispatcher, ProductionRulesSnapshotProvider,
    ProductionSecurityAlertsRepository, ProductionServiceStability, ProductionStorageUsage,
    RecoveryAuditSink, RetentionSettingsProvider, RetentionSettingsWriter, RoutePolicyProvider,
    RoutePolicyWriter, RoutingPauseProvider, RoutingPauseWriter, RulesSnapshotProvider,
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter, StorageUsageProvider,
    SupervisedRuntimeDeps, SystemClock, TracingVerbosityHandle, VerbosityControl,
};
use rusqlite::Connection;

use crate::named_pipe_server::WindowsNamedPipeServer;

mod ipc_surface;
mod per_sid_apply;
mod storage_integrity;

/// Adapter-monitor debounce, in milliseconds. Matches block-15.x default;
/// short enough that a Wi-Fi flicker resolves before the GUI render
/// settles, long enough to avoid double-firing on a normal cable plug.
pub(crate) const ADAPTER_DEBOUNCE_MS: u64 = 500;

/// UTC Unix milliseconds, the timestamp unit every state-DB table stores.
/// A pre-epoch clock reads as `0` — a stamp that is merely very old, which the
/// freshness windows already handle, rather than a panic on a machine whose RTC
/// has not been set yet.
fn unix_millis(at: std::time::SystemTime) -> i64 {
    at.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The per-SID WFP orchestrator plus the route-table coordinator,
/// rule-hostname seeder, and DNS-observation consumer — all `Some`
/// together (built from the same providers when WFP is available) or all
/// `None`.
type RoutePathBundle = (
    Option<Arc<PerSidApplyOrchestrator>>,
    Option<Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>>,
    Option<Arc<nrr_service_runtime::rule_hostname_seeder::RuleHostnameSeeder>>,
    Option<Arc<nrr_service_runtime::dns_observation_consumer::DnsObservationConsumer>>,
    // Session known-direct registry shared by the orchestrator (block-all
    // exemptions), the FCrDNS direct-learning sink, and the Mode-B
    // direct-answer gate.
    Option<Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    // Companion-domain discovery engine, fed by the DNS-observation
    // consumer above and read by the tray through the `autorules.candidates.*`
    // ops. Same `Arc` in both places, so the tick and the tray see one state.
    Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    // Cross-session memory of the destinations application rules route
    // over the additional link, so those routes exist before the app's
    // first connection instead of being learned from its refusal.
    Option<Arc<nrr_service_runtime::app_destination_memory::AppDestinationMemory>>,
);

/// Build the production dependency bundle that `run_supervised_runtime`
/// needs. Both SCM mode and console mode call this with the same
/// artifacts; the only thing they differ on is the
/// `ServiceController` impl (SCM vs eprintln) which lives outside the
/// deps bundle.
///
/// Opens a second `Connection` to the state DB
/// (alongside the bootstrap-owned `SqliteStateStore`) and wraps it in
/// `Arc<Mutex<_>>` so production settings providers and the routing-
/// pause coordinator can share access. WAL mode allows multiple
/// connections; busy_timeout is 5000 ms (set by storage layer
/// invariants).
pub(crate) fn build_supervised_runtime_deps(
    artifacts: &BootstrapArtifacts,
    // The boot-time tracing-reload handle (`None` on a degraded boot with
    // no log writer). Threaded into
    // `ProductionServiceStability`'s writer below so a mid-session
    // "Verbose service logging" Save takes effect live, no service restart.
    verbosity_handle: Option<TracingVerbosityHandle>,
) -> SupervisedRuntimeDeps {
    // Bound here, not inline at the IPC surface, so the housekeeping tick can
    // collect expired dry-run tokens: a dry-run needs no elevation, skips the
    // mutation queue and parks its payload here until confirmed or expired.
    let mutation_tokens = Arc::new(MutationTokenStore::new());
    // ── Shared HealthAggregator ────────────────────────────────────────
    // Constructed once at the top of the function so that:
    //   * `IpcHandlerDeps.health` (read-side, accessed via the IPC
    //     `ServiceHealthGet` handler) and
    //   * `SupervisedRuntimeDeps.health` (write-side, accessed by
    //     `supervised_runtime` to record bootstrap / clear lifecycle
    //     override / seed component severities)
    // resolve to THE SAME `Arc<HealthAggregator>` — otherwise the GUI would see
    // `service-state=starting, components=[]` forever even after the
    // supervisor transitions to `Running`, because it would be reading a
    // different aggregator than the one the supervisor seeds.
    let health_agg = Arc::new(HealthAggregator::new());

    // Drained by the resume watchdog; filled by whoever notices a binding worth
    // re-resolving (today the fail-closed posture heartbeat).
    let rebind_requests = Arc::new(nrr_service_runtime::power_resume::RebindRequests::new());

    // ── Settings DB connection ──────────────────────────────────────────
    // Same stage announcements as the SCM boot: everything from here to the
    // first component log is silent, so a boot that stops answering inside this
    // function is otherwise indistinguishable from one that stopped at its door.
    tracing::info!(target: "nrr::boot", stage = "open-state-db", "boot stage entered");
    let settings_conn = open_settings_connection(&artifacts.topology.state_db_path);

    // User-configurable FQDN cache refresh cadence (Settings →
    // service-stability). Read once at startup; it becomes the refresh FLOOR
    // (`FreshnessThresholds::fallback_ttl_secs`) of the cache store + lookup.
    // The storage read path already clamps to the SSOT range; default 5 min
    // when no row exists or the settings DB is unavailable.
    let cache_refresh_secs = settings_conn
        .as_ref()
        .and_then(|c| c.lock().ok())
        .and_then(|g| {
            nrr_storage::service_stability_config::ServiceStabilityConfigRepository::new(&g)
                .get_or_default()
                .ok()
        })
        .map(|r| r.cache_refresh_interval_secs)
        .unwrap_or(nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS);

    // ── FQDN cache store ─────────────────────────────────────────────
    // Shared by the per-SID orchestrator's `SqliteFqdnCacheLookup` and
    // the DNS refresh task. Both consumers serialise through the same
    // mutex; the cache DB's WAL mode keeps reads from blocking the
    // engine's lookup path.
    tracing::info!(target: "nrr::boot", stage = "open-cache-db", "boot stage entered");
    let cache_store = open_cache_store(&artifacts.topology.cache_db_path, cache_refresh_secs);

    // ── Autostart helper ───────────────────────────────────────────────
    tracing::info!(target: "nrr::boot", stage = "autostart-probe", "boot stage entered");
    let tray_path = resolve_tray_binary_path();
    let autostart_helper = Arc::new(AutostartHelper::new(ProductionAutostartRegistry));

    // No startup probe here. The service runs as LocalSystem, so its
    // `HKEY_CURRENT_USER` is the SYSTEM hive — a probe would persist a reading
    // that cannot be true for the interactive user. The launcher owns autostart
    // (it runs as that user) and answers `autostart.*` before the pipe hop; an
    // absent row states "the service does not know", which is the truth.

    // ── Event bus ────────────────────────────────────────────────────
    // Shared across all settings writers so push events surface on the
    // existing `StatusUpdatesSubscribe` channel. The
    // `SnapshotInitialResponse` carries the initial snapshot that primes
    // the GUI; subsequent state changes ride this bus.
    let event_bus = Arc::new(EventBus::new());

    // ── Routing-pause coordinator ───────────────────────────────────
    // Built LATER, after the per-SID orchestrator exists, so it can use
    // the REAL `OrchestratorPauseDispatcher` (immediate WFP
    // remove/reinstall) instead of a `NoopPauseDispatcher` that only
    // persists the flag. See below.
    let sid_registry = Arc::new(ActiveSidRegistry::new());
    // Open the rebuildable traffic DB + build the sampler over the
    // Windows octet-counter source. Function-scope so both the IPC
    // provider (reads) and the `traffic-sample-tick` (writes) share it.
    tracing::info!(target: "nrr::boot", stage = "open-traffic-db", "boot stage entered");
    let traffic_sampler = open_traffic_sampler(&artifacts.topology.traffic_db_path);
    // Active-probe liveness shared state + the ICMP probe. The tracker
    // starts DISABLED (window 0 = safe default; nothing is ever
    // fail-closed by the probe until the user opts in via the setting). Shared
    // with the coordinator (dead/alive reader), the fast probe tick (writer of
    // verdicts), and — later — the setting handler (window writer).
    let liveness_tracker =
        Arc::new(nrr_service_runtime::secondary_liveness::SecondaryLivenessTracker::new(0));
    let reachability_probe: Arc<dyn nrr_platform_windows::reachability::ReachabilityProbe> =
        Arc::new(nrr_platform_windows::reachability::WindowsIcmpProbe);
    // Seed the tracker window from the persisted config at boot, so a
    // previously-set liveness window is active from startup (not only
    // after the first GUI Set). Best-effort: any read failure leaves the tracker
    // disabled (window 0), which never fail-closes.
    if let Some(conn) = settings_conn.as_ref() {
        if let Ok(c) = conn.lock() {
            let repo =
                nrr_storage::service_stability_config::ServiceStabilityConfigRepository::new(&c);
            if let Ok(rec) = repo.get_or_default() {
                liveness_tracker.set_window_secs(rec.secondary_liveness_window_secs as u64);
            }
        }
    }

    // The shared DNS-resolver controller (Mode B live re-arm). Created
    // empty here (before the IPC writer that will drive it); the platform factory
    // + persisted boot mode are installed below, once the cache / routing-SID /
    // recompute-hook inputs are available. Sharing the SAME `Arc` with the
    // service-stability writer is what lets a GUI enforcement-mode toggle start/
    // stop the resolver WITHOUT a service restart.
    let dns_resolver_controller =
        Arc::new(nrr_service_runtime::dns_resolver_service::DnsResolverController::new());
    // The fake-IP TUN/relay controller. Built here so the
    // service-stability writer's live-apply hook (below) and the boot
    // reconcile (further down) share ONE instance, exactly like the
    // resolver controller above. Its Wintun-backed factory is installed later,
    // once the cache / rules / routing-SID inputs exist.
    let fake_ip_controller = Arc::new(nrr_service_runtime::fake_ip::FakeIpController::new());

    // The shared allocator the DNS answerer, the direct-host answerer and the
    // packet relay all draw from, so a hostname's virtual address means the
    // same thing on both sides. Built ONCE here (not per resolver instance)
    // precisely because the resolver is rebuilt on every start — two allocators
    // would hand out addresses the relay could not resolve back. Constructed
    // this early so the diagnostics handlers (cache viewer + explain probe) can
    // share its read-only `binding_view()`; persistence + factories attach to
    // the same Arc further down.
    let (fake_ip_scope, fake_ip_pool) = fake_ip_policy();
    let fake_ip_assembly = Arc::new(
        nrr_service_runtime::fake_ip::FakeIpAssembly::new(fake_ip_scope, fake_ip_pool)
            // The tunnel's own interior is off limits to virtual addresses: a
            // caller sent to our TUN for an address that only exists inside the
            // tunnel gets nothing. Read through the process cell because the
            // coordinator that learns these subnets is built further down.
            .with_secondary_subnets({
                let cell = nrr_service_runtime::secondary_subnets::global_secondary_subnets();
                std::sync::Arc::new(move || cell.current())
            })
            // A relayed flow owned by the VPN client the user confirmed leaves
            // over the PRIMARY link: that client's traffic is the tunnel's own
            // transport, so carrying it over the secondary routes the tunnel
            // through itself and its probes die on every reconnect. Costs one
            // atomic load per flow until a client is actually confirmed.
            .with_vpn_client_bypass(Arc::new(
                nrr_service_runtime::fake_ip::OwnerLookupVpnClientBypass::new(
                    Arc::new(nrr_platform_windows::flow_owner::WindowsFlowOwnerLookup::new()),
                    nrr_service_runtime::vpn_client_registry::global_confirmed_vpn_clients(),
                ),
            ))
            // A service restart leaves the fake-IP addresses in place (they are
            // the hostname's stable identity) but rebuilds the userspace stack
            // empty — an application still holding a socket to one never gets
            // reset and sits on a dead connection instead of re-resolving.
            .with_stale_flow_reset(Arc::new(
                nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
            )),
    );

    // ── ActivationCoordinator stack ────────────────────────────────
    // Built only when settings_conn opened cleanly. The coordinator owns
    // the SQLite revisions table, the file-backed apply marker, the audit
    // emitter (which publishes `RevisionStatusChanged` push events on
    // terminal transitions), and a `NoopRulesApplyDispatcher` that swaps
    // for `ProductionRulesApplyDispatcher` once the orchestrator's
    // RoutePolicySource adapter lands.
    let id_generator = Arc::new(ProductionIdGenerator::new());

    // Recovery audit sink for safe-disable. Built once when
    // the audit writer is available; threaded into the
    // `ProductionMutationExecutor` so `safe_disable` can record
    // `SafeDisableExecuted` audit events.
    let recovery_audit_sink: Option<Arc<dyn RecoveryAuditSink>> =
        artifacts.audit_writer.as_ref().map(|w| {
            Arc::new(ProductionRecoveryAuditSink::new(
                Arc::clone(w),
                Arc::clone(&id_generator),
            )) as Arc<dyn RecoveryAuditSink>
        });

    // ── Per-SID apply orchestrator ──────────────────────────────────
    // Lives in `runtime_deps::per_sid_apply`; see that module for why it moved
    // and what crosses the boundary.
    let per_sid_apply::PerSidApplyStack {
        api,
        app_enforcement,
        shared_ip_exemptions,
        block_all_posture,
        learned_vpn_endpoints,
        learned_vpn_client_apps,
        killswitch_drop_registry,
        main_route_verdicts,
        dns_resolve_now_slot,
        block_notice_mute_store,
        block_notice_journal_store,
        block_notice_center,
        pause_coordinator,
        fake_ip_replan,
        route_path:
            (
                per_sid_orchestrator,
                route_coordinator,
                rule_hostname_seeder,
                dns_observation_consumer,
                known_direct_registry,
                auto_rules_engine,
                app_destination_memory,
            ),
    } = per_sid_apply::build(per_sid_apply::PerSidApplyInputs {
        artifacts,
        cache_refresh_secs,
        cache_store: cache_store.clone(),
        event_bus: Arc::clone(&event_bus),
        fake_ip_controller: Arc::clone(&fake_ip_controller),
        health_agg: Arc::clone(&health_agg),
        id_generator: Arc::clone(&id_generator),
        liveness_tracker: Arc::clone(&liveness_tracker),
        reachability_probe: Arc::clone(&reachability_probe),
        rebind_requests: Arc::clone(&rebind_requests),
        settings_conn: settings_conn.clone(),
        sid_registry: Arc::clone(&sid_registry),
    });

    // ── DB-MAC tamper bootstrap ───────────────────────────────────────
    // Lives in `runtime_deps::storage_integrity`.
    let storage_integrity::StorageIntegrity {
        activation_coordinator,
        block_notice_rule_author,
    } = storage_integrity::build(storage_integrity::StorageIntegrityInputs {
        artifacts,
        settings_conn: settings_conn.clone(),
        cache_store: cache_store.clone(),
        event_bus: Arc::clone(&event_bus),
        sid_registry: Arc::clone(&sid_registry),
        id_generator: Arc::clone(&id_generator),
        per_sid_orchestrator: per_sid_orchestrator.clone(),
        route_coordinator: route_coordinator.clone(),
        auto_rules_engine: auto_rules_engine.clone(),
    });

    // ── Full IPC handler registration ─────────────────
    // Lives in `runtime_deps::ipc_surface`; the router and the named pipe
    // server that consume its registry stay here.
    let ipc_surface::IpcSurface {
        conn_trace_persisted_ndjson,
        conn_trace_ring,
        auto_probe_wiring,
        registry,
    } = ipc_surface::build(ipc_surface::IpcSurfaceInputs {
        artifacts,
        activation_coordinator: activation_coordinator.clone(),
        api: Arc::clone(&api),
        app_enforcement: app_enforcement.clone(),
        auto_rules_engine: auto_rules_engine.clone(),
        autostart_helper: Arc::clone(&autostart_helper),
        block_all_posture: block_all_posture.clone(),
        block_notice_center: Arc::clone(&block_notice_center),
        block_notice_journal_store: block_notice_journal_store.clone(),
        block_notice_mute_store: block_notice_mute_store.clone(),
        block_notice_rule_author: block_notice_rule_author.clone(),
        cache_store: cache_store.clone(),
        dns_resolver_controller: Arc::clone(&dns_resolver_controller),
        event_bus: Arc::clone(&event_bus),
        fake_ip_assembly: Arc::clone(&fake_ip_assembly),
        fake_ip_controller: Arc::clone(&fake_ip_controller),
        fake_ip_replan: Arc::clone(&fake_ip_replan),
        health_agg: Arc::clone(&health_agg),
        liveness_tracker: Arc::clone(&liveness_tracker),
        main_route_verdicts: Arc::clone(&main_route_verdicts),
        mutation_tokens: Arc::clone(&mutation_tokens),
        pause_coordinator: pause_coordinator.clone(),
        per_sid_orchestrator: per_sid_orchestrator.clone(),
        recovery_audit_sink: recovery_audit_sink.clone(),
        route_coordinator: route_coordinator.clone(),
        settings_conn: settings_conn.clone(),
        shared_ip_exemptions: shared_ip_exemptions.clone(),
        sid_registry: Arc::clone(&sid_registry),
        traffic_sampler: traffic_sampler.clone(),
        tray_path: tray_path.clone(),
        verbosity_handle,
    });

    // The router refuses a privileged mutation whose audit record cannot be
    // written. With the no-op emitter that safeguard could never fire and the
    // trail was empty; wired to the real writer it does both jobs.
    let audit: Arc<dyn IpcAuditEmitter> = match artifacts.audit_writer.as_ref() {
        Some(writer) => Arc::new(
            nrr_service_runtime::production_ipc_audit::ProductionIpcAuditEmitter::new(Arc::clone(
                writer,
            )),
        ),
        None => Arc::new(NoopIpcAuditEmitter),
    };
    let router = Arc::new(IpcRouter::new(
        registry,
        Arc::clone(&audit),
        nrr_service_runtime::ipc::MUTATION_QUEUE_CAPACITY,
    ));
    // The pipe server MUST share the SAME
    // `ActiveSidRegistry` the route coordinator + WFP orchestrator read. With
    // the plain `::new` (active_sids = None) no connection ever called
    // `on_connect`, so `registry.active_sids()` was ALWAYS empty: routing
    // `recompute_active([])` cleared everything and WFP activations reported
    // `succeeded: 0`. Wiring the registry here is what makes a tray connection
    // mark its SID routing-active so enforcement actually targets the user.
    let ipc_server: Arc<dyn IpcServer> = Arc::new(
        WindowsNamedPipeServer::new_with_active_sid_registry(
            router,
            audit,
            Arc::clone(&sid_registry),
        )
        .with_event_bus(Arc::clone(&event_bus)),
    );

    // ── Adapter monitor ─────────────────────────────────────────────────
    // Shares the `Arc<dyn WindowsApiPort>` constructed above for the
    // per-SID orchestrator. One platform handle, two consumers.
    let source = WindowsApiAdapterSource::new(Arc::clone(&api));
    let adapter_monitor = Arc::new(AdapterMonitor::new(Arc::new(source), ADAPTER_DEBOUNCE_MS));

    // ── Operation results ───────────────────────────────────────────────
    let operation_results = Arc::new(OperationStatusStore::default());

    // ── DNS refresh orchestrator ─────────────────────────────────────
    // Production resolver + the shared cache mutex. Constructed only
    // when the cache opened — without a cache there's nothing to
    // refresh. The orchestrator is `Arc`-shared between the supervisor
    // task (constructed below by `spawn_optional_tasks`) and any
    // future manual-refresh IPC handler.
    let dns_refresh_orchestrator: Option<Arc<DnsRefreshOrchestrator>> =
        cache_store.as_ref().map(|cache_arc| {
            // Same hosts-bypass decorator as the seeder, so refreshed
            // rule hosts also skip a hosts/adblock loopback pin while the
            // active user's posture is ON (the default).
            let refresh_active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn = {
                let reg = Arc::clone(&sid_registry);
                let coord = route_coordinator.clone();
                Arc::new(move || match coord.as_ref() {
                    Some(c) => c.effective_routing_sid(&reg.active_sids()),
                    None => reg.active_sids().first().cloned(),
                })
            };
            let refresh_egress = route_coordinator
                .as_ref()
                .map(|coord| build_dns_egress_policy(coord, Arc::clone(&refresh_active_sid)));
            let resolver: Arc<dyn nrr_platform_windows::dns::DnsResolverPort> =
                build_hosts_bypass_resolver(
                    settings_conn.as_ref().map(Arc::clone),
                    Some(Arc::clone(&refresh_active_sid)),
                    refresh_egress,
                );
            Arc::new(DnsRefreshOrchestrator::new(resolver, Arc::clone(cache_arc)))
        });
    // Hand the refresher to the apply path (see `with_unresolved_hosts_sink`).
    // Before this point a rule naming an unresolved host simply waits for the
    // ordinary refresh, which is the old behaviour.
    if let Some(refresher) = dns_refresh_orchestrator.as_ref() {
        let _ = dns_resolve_now_slot.set(Arc::clone(refresher));
    }

    // ── Diagnostics cleanup wiring ──────────────────────────────────────
    let logs_dir: PathBuf = artifacts.topology.logs_dir.clone();
    // Read the persisted log/audit retention (age + size caps) so both
    // cleanup tasks enforce the operator's saved config on startup. Audit files
    // live in the same `logs_dir` (run_audit targets only `nrr_audit_*`). Falls
    // back to CLAUDE.md defaults when the settings DB / row is unavailable.
    let (log_retention, audit_retention) =
        match settings_conn.as_ref().and_then(read_log_retention_config) {
            Some(cfg) => (
                LogRetentionPolicy {
                    max_age_days: cfg.log_max_age_days,
                    max_total_size_bytes: cfg.log_max_size_bytes,
                    ..LogRetentionPolicy::default()
                },
                AuditRetentionPolicy {
                    max_age_days: cfg.audit_max_age_days,
                    max_total_size_bytes: cfg.audit_max_size_bytes,
                },
            ),
            None => (
                LogRetentionPolicy::default(),
                AuditRetentionPolicy::default(),
            ),
        };
    let cleanup_scope = ManualCleanupScope {
        operational_logs: true,
        diagnostic_temp_data: false,
        exported_archives: false,
    };

    // ── Service stability config ────────────────────────────────────────
    // Read the persisted policy from `service_stability_config` so the
    // `ipc-accept-loop` task picks up the operator's saved
    // backoff_base / backoff_cap / max_restarts on startup. If the row
    // is missing or the settings DB never opened, fall back to canonical
    // defaults, consistent with the
    // GUI's "config not yet written" state. When the read returns None
    // (DB missing OR row missing OR error) we emit a defaults-applied
    // log so the operator can tell from NDJSON that the supervisor is
    // running on factory values rather than what they last saved.
    let stability_config: ServiceStabilityConfig = match settings_conn
        .as_ref()
        .and_then(read_service_stability_config)
    {
        Some(cfg) => cfg,
        None => {
            tracing::info!(
                target: "nrr::stability",
                source = "default",
                "service_stability_config defaults applied (no persisted row or settings DB unavailable)",
            );
            ServiceStabilityConfig::default()
        }
    };

    // Last-logged "leak-guard reconciled" `added` count per
    // SID. `reconcile_secondary_coverage` fires on every hook tick (DNS
    // warm-up, adapter up/down, the 30 s safety tick) and re-derives the same
    // non-zero `added` count in bursts while nothing actually changed — log
    // at INFO only when a SID's count differs from what was last logged,
    // DEBUG otherwise.
    let leak_guard_log_state: Arc<Mutex<std::collections::HashMap<String, usize>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Recompute the active user's routes after a DNS
    // refresh tick warms the FQDN cache (a previously-cold domain/zone rule
    // can now produce routes). Closes over the coordinator + registry.
    let route_recompute_hook: Option<nrr_service_runtime::supervised_runtime::RouteRecomputeHook> =
        route_coordinator.as_ref().map(|coord| {
            let coord = Arc::clone(coord);
            let registry = Arc::clone(&sid_registry);
            let leak_guard_log_state = Arc::clone(&leak_guard_log_state);
            // This hook fires on the DNS warm-up
            // tick, the adapter-monitor tick (secondary up/down/reconnect) AND the 30 s
            // route-reconcile safety tick. It (a) grows the route table + the
            // kill-switch block set for freshly-observed secondary IPs (else a
            // new IP routes via the secondary adapter yet leaks out the primary the instant the
            // secondary drops), and (b) reconciles the leak-guard against the freshly-
            // resolved secondary LUID. `reconcile_secondary_coverage` is make-before-
            // break (adds new before deleting superseded — blocks never lift, so
            // window-free) and a no-op when nothing changed. It supersedes the
            // add-only `refresh_secondary_coverage` here because add-only cannot
            // reap the DEAD-LUID egress permit a secondary reconnect leaves:
            // the stale permit would otherwise keep blocking legit secondary traffic
            // until a policy recompile. The 30 s safety tick also catches a same-
            // ifindex LUID swap the availability monitor cannot see.
            let orch = per_sid_orchestrator.clone();
            // Proactively
            // resolve each active user's rule hostnames into the FQDN cache
            // BEFORE recompute, on every hook fire (apply, adapter up/down/
            // reconnect, and the 30 s safety tick). Without this the /32 set —
            // which gates BOTH the secondary route AND the fail-closed block —
            // was only warmed by the 60 s seed tick or by observed traffic, so
            // right after boot with the secondary adapter still absent a rule
            // host had no /32 and leaked to the primary even with leak-guard ON.
            // Seeding here is cheap in steady state (already-cached hosts skip
            // DNS) and runs on the background supervisor tick, never the
            // synchronous mutation/apply path.
            let seeder = rule_hostname_seeder.clone();
            // Piggy-back the Mode-B resolver watchdog on this
            // periodic hook: if the resolver is enabled but its serve thread exited
            // unexpectedly, re-arm it.
            let dns_ctl = Arc::clone(&dns_resolver_controller);
            // Pause state for the boot self-apply
            // reconcile below (a paused SID's filters must never reinstall
            // from a periodic tick).
            let pause = pause_coordinator.clone();
            // The IPv6 route table, written to the log whenever it CHANGES.
            // This hook already fires on every adapter/network change, so it is
            // the cheapest honest place to notice one; the logger itself stays
            // silent while the table is stable.
            let v6_routes = Arc::new(nrr_service_runtime::ipv6_route_log::Ipv6RouteTableLog::new());
            let v6_api = Arc::clone(&api);
            Arc::new(move || {
                // A recompute that lands after the stop teardown stripped the
                // filters puts them back into a process that is about to exit —
                // and a non-dynamic WFP filter outlives the process.
                if nrr_service_runtime::teardown_in_progress() {
                    return;
                }
                // What this pass costs, phase by phase. A 10 s median with
                // requests queueing behind it was measured as ONE number, which
                // says nothing about what to take off the periodic path.
                let mut timings = nrr_service_runtime::phase_timings::PhaseTimings::start();
                v6_routes.log_if_changed(v6_api.as_ref(), "network-change");
                let tray_active = registry.active_sids();
                // Enforce for the effective routing
                // user even with NO tray connected (console-session user,
                // service-driven scope). The seeder and the WFP
                // orchestrator below must not only ever see tray-connected SIDs — a
                // tray-less boot (or a dead tray subscription) would otherwise
                // leave the WFP half completely unarmed while the route half
                // enforced normally.
                let active = coord.effective_enforcement_sids(&tray_active);
                if let Some(seeder) = seeder.as_ref() {
                    for sid in &active {
                        let summary = seeder.seed_for_principal(sid, std::time::SystemTime::now());
                        if summary.made_progress() {
                            tracing::info!(
                                target: "nrr::rule-seed",
                                sid = %sid,
                                resolved = summary.resolved,
                                "proactively seeded rule hostnames before recompute (leak-guard coverage)",
                            );
                        }
                    }
                }
                timings.mark("seed");
                if let Err(e) = coord.recompute_active(&tray_active) {
                    tracing::error!(
                        target: "nrr::route-coordinator",
                        "route recompute after DNS warm-up failed: {e:?}",
                    );
                }
                timings.mark("routes");
                if let Some(orch) = orch.as_ref() {
                    // NEVER reconcile the
                    // orchestrator to an EMPTY effective set from a periodic
                    // tick. `effective_enforcement_sids` returns empty both for
                    // "genuinely nobody" AND for a transient console-SID lookup
                    // failure (fast-user-switch, RDP console grab, a momentary
                    // `WTSQueryUserToken` `ERROR_NO_TOKEN`). Reconciling to `[]`
                    // there would STRIP every installed fail-closed / kill-switch
                    // filter for one tick — a leak window on the primary link.
                    // A genuine user departure is handled by the registry
                    // `on_disconnect` reconcile listener and by stop-teardown, so
                    // the periodic hook has no reason to strip on empty; leaving
                    // the filters in place fails SAFE (they block, never leak).
                    if active.is_empty() {
                        dns_ctl.tick();
                        report_recompute_cost(&timings);
                        return;
                    }
                    // Boot self-apply: reconcile the
                    // orchestrator against the effective set FIRST, so a SID
                    // that became routing-active without a registry transition
                    // (service boot, console user, dead tray) gets its full
                    // per-SID filter set installed from persisted state. This
                    // very tick fires immediately at task spawn, on every
                    // adapter/network change, and every 30 s. Fail-CLOSED on a
                    // pause-state read error: touch nothing (an empty want-set
                    // would strip a healthy SID's filters).
                    let paused = match pause.as_ref().map(|c| c.paused_sids()).transpose() {
                        Ok(p) => p.unwrap_or_default(),
                        Err(e) => {
                            tracing::error!(
                                target: "nrr::per_sid_orchestrator",
                                "pause-state read failed; skipping enforcement reconcile: {e:?}",
                            );
                            dns_ctl.tick();
                            report_recompute_cost(&timings);
                            return;
                        }
                    };
                    let unpaused: Vec<String> = active
                        .iter()
                        .filter(|s| !paused.iter().any(|p| p == *s))
                        .cloned()
                        .collect();
                    if let Err(e) = orch.reconcile(&unpaused) {
                        tracing::error!(
                            target: "nrr::per_sid_orchestrator",
                            "periodic enforcement reconcile failed: {e:?}",
                        );
                    }
                    timings.mark("filters");
                    for sid in &unpaused {
                        match orch.reconcile_secondary_coverage(sid) {
                            Ok(0) => {}
                            Ok(n) => {
                                let changed = {
                                    let mut g = leak_guard_log_state
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner());
                                    g.insert(sid.clone(), n) != Some(n)
                                };
                                if changed {
                                    tracing::info!(
                                        target: "nrr::per_sid_orchestrator",
                                        sid = %sid,
                                        added = n,
                                        "leak-guard reconciled (coverage grown / LUID-aware permit refresh)",
                                    );
                                } else {
                                    tracing::debug!(
                                        target: "nrr::per_sid_orchestrator",
                                        sid = %sid,
                                        added = n,
                                        "leak-guard reconciled (deduped; same coverage count as last log)",
                                    );
                                }
                            }
                            Err(e) => tracing::warn!(
                                target: "nrr::per_sid_orchestrator",
                                sid = %sid,
                                "leak-guard reconcile failed: {e:?}",
                            ),
                        }
                    }
                }
                // A new link usually means a new resolver, and the old one can
                // keep answering while pointing at the network we just left.
                // Rate-limited inside the pool. Runs BEFORE the watchdog so an
                // upstream that just appeared clears the re-arm backoff in the
                // same pass instead of the tick after next.
                timings.mark("leak-guard");
                let upstream = upstream_dns_pool().note_network_change();
                dns_ctl.note_upstream_present(upstream.is_some());
                // Mode-B resolver watchdog (see above): re-arm the
                // resolver if it is enabled but its serve thread has died.
                dns_ctl.tick();
                timings.mark("dns-watchdog");
                report_recompute_cost(&timings);
            }) as nrr_service_runtime::supervised_runtime::RouteRecomputeHook
        });

    // Fast liveness-probe hook: probes each active user's
    // bound secondary tunnel next-hop and feeds the result to the tracker (a
    // no-op when the feature is disabled). Driven by the ~5 s
    // `secondary-liveness-tick`. Closes over the coordinator + registry.
    let secondary_liveness_hook: Option<
        nrr_service_runtime::supervised_runtime::RouteRecomputeHook,
    > = route_coordinator.as_ref().map(|coord| {
        let coord = Arc::clone(coord);
        let registry = Arc::clone(&sid_registry);
        Arc::new(move || {
            // Probe for the effective routing user
            // too, not only tray-connected SIDs (same fallback as the
            // recompute hook above).
            let sids = coord.effective_enforcement_sids(&registry.active_sids());
            coord.probe_active_secondaries(&sids);
        }) as nrr_service_runtime::supervised_runtime::RouteRecomputeHook
    });

    // External-address notice for the additional link. The link
    // snapshot comes from the SAME resolution the routing path uses, so the
    // notice can only ever describe a link the product itself considers usable.
    // The probe is `nrr-platform-api`'s source-bound STUN batch of one; it runs
    // on the announcer's own detached worker, never on the tick.
    let secondary_external_address: Option<
        nrr_service_runtime::secondary_external_address::ExternalAddressWiring,
    > = route_coordinator.as_ref().map(|coord| {
        let announcer = Arc::new(
            nrr_service_runtime::secondary_external_address::ExternalAddressAnnouncer::new(
                Arc::clone(&event_bus),
                Arc::new(|source| {
                    nrr_platform_api::probe_external_ipv4_batch(&[source])
                        .first()
                        .and_then(|outcome| outcome.address())
                }),
            ),
        );
        let links: nrr_service_runtime::secondary_external_address::SecondaryLinkSourceFn = {
            let coord = Arc::clone(coord);
            let registry = Arc::clone(&sid_registry);
            Arc::new(move || {
                coord
                    .effective_routing_sid(&registry.active_sids())
                    .and_then(|sid| coord.resolve_secondary_link(&sid))
                    .into_iter()
                    .collect()
            })
        };
        nrr_service_runtime::secondary_external_address::ExternalAddressWiring { announcer, links }
    });

    // Persist-on-stop — graceful-stop hook, gated by the fresh
    // `routing_stop_policy` setting (read at stop time, NOT a boot snapshot,
    // so a mid-session change takes effect). Built only when the full route
    // path is available (coordinator + orchestrator come as a bundle, so both
    // are Some together, and `settings_conn` is Some whenever the bundle is).
    //
    // - **persist** (the default — VPN-type-aware "keep VPN"): KEEP the
    //   secondary /32 rule-routes but remove NRR's overlays (the mode-A /2
    //   counter-overlay / mode-B /1 split-default), so rule-matched hosts keep
    //   egressing the VPN after stop while general traffic returns to whatever
    //   the OS/VPN provides — the primary for a gateway-less VPN, the VPN's own
    //   default for a full-tunnel one (no fabricated default → a split / corp
    //   VPN is not forced to carry its non-org traffic).
    // - **teardown**: full restore-pristine — remove EVERY NRR route.
    // Both strip ALL WFP filters (routing is route-table-based; a lingering
    // block with no service to lift it would be a lockout).
    let route_teardown_hook: Option<nrr_service_runtime::supervised_runtime::RouteRecomputeHook> =
        match (
            route_coordinator.as_ref(),
            per_sid_orchestrator.as_ref(),
            settings_conn.as_ref(),
        ) {
            (Some(coord), Some(orch), Some(conn)) => {
                let coord = Arc::clone(coord);
                let orch = Arc::clone(orch);
                let conn = Arc::clone(conn);
                Some(
                    Arc::new(move || {
                        // Who was connected at the moment the paths go away.
                        // Removing our routes changes the outgoing path for
                        // live sessions, and TCP does not survive that — so
                        // an application losing its connection right at the
                        // stop looks like our doing and cannot be told apart
                        // from a coincidence. This line is the evidence.
                        let connected =
                            nrr_platform_windows::stale_flows::established_connections_by_process(
                                8,
                            );
                        if !connected.is_empty() {
                            let summary = connected
                                .iter()
                                .map(|(name, n)| format!("{name} ({n})"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            tracing::info!(
                                target: "nrr::lifecycle",
                                processes = %summary,
                                "connections live at teardown — removing our routes changes their path, and an established session does not survive that",
                            );
                        }
                        if read_routing_stop_persist(&conn) {
                            // persist (default): keep the /32 rule-routes on the
                            // VPN, remove NRR's overlays.
                            match coord.teardown_keep_secondary_hosts() {
                                Ok(delta) => tracing::info!(
                                    target: "nrr::route-coordinator",
                                    removed_overlays = delta.removed as u64,
                                    "service stopping — kept secondary rule-routes on the VPN; removed NRR overlays (general traffic returns to the OS/VPN default)",
                                ),
                                Err(e) => tracing::warn!(
                                    target: "nrr::route-coordinator",
                                    "route keep-secondary teardown on shutdown failed: {e:?}",
                                ),
                            }
                        } else {
                            // teardown: full restore-pristine — remove every route.
                            match coord.teardown() {
                                Ok(_) => tracing::info!(
                                    target: "nrr::route-coordinator",
                                    "service stopping — all NRR routes torn down (routing restored to pristine)",
                                ),
                                Err(e) => tracing::warn!(
                                    target: "nrr::route-coordinator",
                                    "route teardown on shutdown failed: {e:?}",
                                ),
                            }
                        }
                        // Both policies strip ALL WFP filters — a lingering block
                        // with no service to lift it would be a lockout.
                        match orch.cleanup_wfp() {
                            Ok(n) => tracing::info!(
                                target: "nrr::route-coordinator",
                                stripped_filters = n as u64,
                                "service stopping — all NRR WFP filters stripped",
                            ),
                            Err(e) => tracing::warn!(
                                target: "nrr::route-coordinator",
                                "WFP filter strip on shutdown failed: {e:?}",
                            ),
                        }
                    })
                        as nrr_service_runtime::supervised_runtime::RouteRecomputeHook,
                )
            }
            _ => None,
        };

    // The routing-active SID for the seed task, console-SID-aware via the
    // coordinator's gate: the
    // connected-tray SID, or — service-driven scope with no tray — the active
    // console user, so the seeder resolves THEIR ExactFqdn rules from boot (not
    // just ExactIp). Defensive registry-only fallback if the coordinator is
    // absent (it never is when the seeder exists, but keep the closure total).
    let active_routing_sid: Option<nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn> =
        rule_hostname_seeder.as_ref().map(|_| {
            let registry = Arc::clone(&sid_registry);
            let coord = route_coordinator.clone();
            Arc::new(move || match coord.as_ref() {
                Some(c) => c.effective_routing_sid(&registry.active_sids()),
                None => registry.active_sids().first().cloned(),
            }) as nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn
        });

    // "Is anyone signed in?" A connected tray proves a session; on a cold boot
    // none is running yet, so the console session is what answers first.
    let signed_in: Arc<dyn Fn() -> bool + Send + Sync> = {
        let reg = Arc::clone(&sid_registry);
        Arc::new(move || {
            !reg.active_sids().is_empty()
                || nrr_platform_windows::win32_ffi::console_session::active_console_user_sid()
                    .is_some()
        })
    };
    // Machine-wide network work waits for that user: the resolver arm's
    // reason, one level wider (TUN bring-up, OS cache flush).
    let sign_in_gate = Arc::new(nrr_service_runtime::logon_rearm::SignInGate::new(
        Arc::clone(&signed_in),
    ));

    // Start the DNS-Client ETW observer that feeds the
    // observation consumer. Only when the route path is available. Failure
    // to start (no privilege, ETW unavailable) degrades gracefully: the
    // service runs, suffix/zone routing simply has no observation feed.
    let dns_observation_source: Option<
        Arc<dyn nrr_platform_windows::dns_observe::DnsObservationSource>,
    > =
        dns_observation_consumer.as_ref().and_then(|consumer| {
            match nrr_platform_windows::dns_observe::etw::EtwDnsObserver::start() {
                Ok(obs) => {
                    // BEFORE flushing, read the OS resolver cache and
                    // seed the rule-matching hosts into our FQDN cache. This
                    // recovers exactly the pre-boot resolutions the flush is
                    // about to discard (and that the observer would otherwise
                    // never see), so their zone/suffix permits compile on the
                    // first recompile instead of waiting for a fresh wire query.
                    // Order matters: seed reads the cache, THEN the flush clears
                    // it so future lookups are observable. Both wait for a
                    // signed-in user: the seed reads the ACTIVE user's rules
                    // (none before), and the flush is machine-wide churn that
                    // must not land in the logon phase. Best-effort.
                    let consumer = Arc::clone(consumer);
                    sign_in_gate.defer(
                        "dns-cache-seed-and-flush",
                        Arc::new(move || {
                            let seeded =
                                consumer.seed_from_os_cache(std::time::SystemTime::now());
                            if seeded.matched > 0 {
                                tracing::info!(
                                    target: "nrr::dns-observe",
                                    matched = seeded.matched,
                                    "seed from OS resolver cache before flush",
                                );
                            }
                            // The observer only sees WIRE queries; anything the
                            // OS resolver cached before this service start would
                            // stay invisible until its TTL expires (its
                            // zone→primary permit never built). Flush once, so
                            // every next lookup re-queries observably.
                            use nrr_platform_windows::DnsCacheControlPort as _;
                            match nrr_platform_windows::WindowsDnsCacheControl::new()
                                .flush_resolver_cache()
                            {
                                Ok(()) => tracing::info!(
                                    target: "nrr::dns-observe",
                                    "flushed OS DNS resolver cache — names cached before the service started will re-query and become observable",
                                ),
                                Err(e) => tracing::warn!(
                                    target: "nrr::dns-observe",
                                    error = ?e,
                                    "OS DNS resolver cache flush failed — names cached before the service started stay invisible until their TTL expires",
                                ),
                            }
                        }),
                    );
                    Some(Arc::new(obs)
                        as Arc<dyn nrr_platform_windows::dns_observe::DnsObservationSource>)
                }
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::dns-observe",
                        "DNS-Client ETW observer unavailable; suffix/zone routing will not \
                         observe new sub-hostnames: {e}",
                    );
                    None
                }
            }
        });

    // Opt-in connection-egress observer.
    // Enabled by the persisted toggles (NDJSON sink + GUI stream) on
    // service_stability_config; a dev sentinel/env (NRR_CONN_TRACE /
    // conn-trace.enabled) additionally forces the NDJSON path on without the
    // GUI. The observer starts if either output is on. Captures outbound
    // connections (process + remote + egress interface) for diagnostics; never
    // installs routes/filters. Paired source+consumer (both Some or both None).
    // Flags (conn_trace_persisted_ndjson, conn_trace_gui) and the shared ring
    // were read/created at the top of this fn (the ring must reach the IPC deps
    // built earlier). Reuse them here for the observer construction.
    let conn_trace_ndjson = conn_trace_persisted_ndjson || conn_trace_requested();
    // Wire FCrDNS reverse-learning only when the
    // DNS-observation consumer exists (it owns the rule-gated cache sink). The
    // conn-trace consumer's drop hook feeds this channel; the worker (below) drains
    // it and does the PTR + forward-confirm off the hot path.
    let (fcrdns_tx, fcrdns_rx) = std::sync::mpsc::sync_channel::<(std::net::Ipv4Addr, bool)>(256);
    let fcrdns_hook = dns_observation_consumer.as_ref().map(|_| fcrdns_tx.clone());
    // Proactive VPN-client learning: best-effort write-through
    // of a newly-learned client path so the app-scoped exemption survives a
    // service restart. Absent state DB → the registry stays session-scoped.
    let vpn_client_app_persist: Option<VpnClientAppPersistFn> =
        settings_conn.as_ref().map(|conn| {
            let conn = Arc::clone(conn);
            Arc::new(move |path: &str| {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                if let Err(e) = nrr_storage::vpn_client_apps::VpnClientAppsRepository::new(&guard)
                    .upsert(path, now)
                {
                    tracing::warn!(
                        target: "nrr::vpn-learn",
                        error = %e,
                        "failed to persist learned VPN client app — continuing",
                    );
                }
            }) as VpnClientAppPersistFn
        });
    let (conn_observation_source, conn_observation_consumer) = build_conn_trace_pair(
        &api,
        route_coordinator.as_ref(),
        active_routing_sid.as_ref(),
        conn_trace_ndjson,
        conn_trace_ring.clone(),
        ObservationSinks {
            reverse_dns_learner_tx: fcrdns_hook,
            app_destination_forget: settings_conn.as_ref().map(|conn| {
            let conn = Arc::clone(conn);
            Arc::new(move |app: &str, ip: std::net::Ipv4Addr| {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                if let Err(e) =
                    nrr_storage::app_destinations::AppDestinationsRepository::new(&guard)
                        .forget(app, ip)
                {
                    tracing::warn!(
                        target: "nrr::app-routing",
                        error = %e,
                        "failed to delete a withdrawn application destination — it will age out of the freshness window instead",
                    );
                }
            })
                    as nrr_service_runtime::conn_observation_consumer::AppDestinationForgetFn
            }),
            // Read fresh on every batch, so a rule the user just added or
            // removed changes what may own a pin without a restart.
            routed_apps: match (settings_conn.as_ref(), active_routing_sid.as_ref()) {
                (Some(conn), Some(active_sid)) => {
                    let rules: Arc<dyn nrr_service_runtime::per_sid_orchestrator::RulesProvider> =
                        Arc::new(ProductionRulesProvider::new(Arc::clone(conn)));
                    let active_sid = Arc::clone(active_sid);
                    Some(Arc::new(move || {
                        let Some(sid) = active_sid() else {
                            return Vec::new();
                        };
                        let Some(snapshot) = rules.active_rules_for(&sid) else {
                            return Vec::new();
                        };
                        nrr_service_runtime::app_destination_memory::routed_app_patterns(
                            &snapshot.rule_book.secondary,
                        )
                        .into_iter()
                        .collect()
                    })
                        as nrr_service_runtime::conn_observation_consumer::RoutedAppsFn)
                }
                _ => None,
            },
        },
        VpnLearningDeps {
            learned_vpn_endpoints: &learned_vpn_endpoints,
            killswitch_drop_registry: &killswitch_drop_registry,
            learned_vpn_client_apps: &learned_vpn_client_apps,
            vpn_client_app_persist,
            auto_rules_engine: auto_rules_engine.as_ref(),
            block_notice_center: &block_notice_center,
            block_all_posture: &block_all_posture,
        },
    );
    drop(fcrdns_tx); // the hook holds the only retained sender (if wired)
    if let Some(dns_consumer) = dns_observation_consumer.as_ref() {
        let companion = match (auto_rules_engine.as_ref(), active_routing_sid.as_ref()) {
            (Some(engine), Some(active_sid)) => {
                Some(CompanionFromReverseDeps { engine, active_sid })
            }
            _ => None,
        };
        spawn_fcrdns_learner_worker(fcrdns_rx, Arc::clone(dns_consumer), companion);
    }

    // Clear any orphaned NRPT redirect a prior
    // crashed Resolver session may have left (a dead :53 would break ALL DNS),
    // regardless of the current mode, then arm the local resolver iff the
    // persisted mode is Resolver.
    match nrr_platform_windows::dns_redirect::clear_orphan_redirect(
        &nrr_platform_windows::dns_redirect::TransactedNrptStore,
    ) {
        Ok(removed) => tracing::info!(
            target: "nrr::dns-resolver",
            removed,
            "startup: orphaned NRPT redirect sweep finished",
        ),
        Err(e) => tracing::warn!(
            target: "nrr::dns-resolver",
            "Mode B: orphan NRPT cleanup at boot failed ({e})",
        ),
    }
    // Install the platform resolver factory now that the cache / routing-SID /
    // recompute-hook inputs exist, and read the persisted boot mode. The factory
    // re-captures the current upstream DNS on each start (correct after a network
    // change). Missing inputs → no factory installed → the controller stays
    // reactive (fail-safe). Must read the boot mode BEFORE `settings_conn` is
    // moved into the deps below.
    // The Mode-B direct-answer gate needs "is any block-all armed?"
    // from the orchestrator plus the shared known-direct registry.
    let block_all_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>> =
        per_sid_orchestrator.as_ref().map(|orch| {
            let orch = Arc::clone(orch);
            Arc::new(move || orch.any_block_all_armed()) as Arc<dyn Fn() -> bool + Send + Sync>
        });
    // The answer gate keys on the WIDER posture: with the default per-IP guard
    // the block-all latch stays disarmed while the additional link is
    // unresolved and rule destinations are very much being blocked.
    let fail_closed_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>> =
        per_sid_orchestrator.as_ref().map(|orch| {
            let orch = Arc::clone(orch);
            Arc::new(move || orch.any_fail_closed_armed()) as Arc<dyn Fn() -> bool + Send + Sync>
        });
    // A hostname's fake address is its stable identity across restarts: seed
    // the allocator from the persisted bindings and mirror every later change
    // back. Without this the in-memory allocator re-deals the same indices to
    // different hostnames each run, and anything that remembered the old pair
    // (a browser's DNS cache, a diagnostics page) watches addresses swap
    // owners. Best-effort: with no cache DB the allocator just starts empty.
    if let Some(cache) = cache_store.as_ref() {
        let stamp = fake_ip_pool.stamp();
        let persisted = {
            let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
            match guard.load_fake_ip_bindings(&stamp) {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        error = %e,
                        "loading persisted fake-IP bindings failed — starting with an empty pool",
                    );
                    Vec::new()
                }
            }
        };
        let restored = persisted.len();
        let sink: nrr_platform_api::fake_ip::BindingChangeSink = {
            let cache = Arc::clone(cache);
            Arc::new(move |change| {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
                let result = match change {
                    nrr_platform_api::fake_ip::BindingChange::Bound { domain, index } => {
                        guard.record_fake_ip_binding(domain, *index, now_ms)
                    }
                    nrr_platform_api::fake_ip::BindingChange::Released { index } => {
                        guard.remove_fake_ip_binding(*index)
                    }
                };
                if let Err(e) = result {
                    tracing::debug!(
                        target: "nrr::fake-ip",
                        error = %e,
                        "persisting a fake-IP binding change failed (stability only, never routing)",
                    );
                }
            })
        };
        fake_ip_assembly.attach_binding_persistence(persisted, sink);
        if restored > 0 {
            tracing::info!(
                target: "nrr::fake-ip",
                restored,
                "restored persisted fake-IP bindings — hostnames keep their virtual addresses",
            );
        }
    }
    // The fail-open gate: the DNS side hands out a virtual address ONLY while the
    // relay stack is actually running. Driver missing / stack down → real path.
    let fake_ip_running: Arc<dyn Fn() -> bool + Send + Sync> = {
        let controller = Arc::clone(&fake_ip_controller);
        Arc::new(move || controller.is_running())
    };
    // Second gate, for SCOPE hosts only (the ones the relay carries over the
    // additional route). A running stack whose secondary is unresolved refuses
    // every such dial — "dialing would leak via the primary link" — so the
    // virtual address it handed out is a guaranteed reset. A cold boot hits
    // exactly that: the service arms while the VPN client is still starting,
    // and every rule host gets a fake address nothing can carry. The real
    // addresses were resolved and cached a moment earlier, so falling back to
    // them leaves enforcement to WFP, which blocks or pins them by policy
    // instead of resetting the client.
    //
    // Deliberately NOT folded into `fake_ip_running`: direct and collateral
    // fake-IP relay over the PRIMARY link and must keep working while the
    // additional route is down.
    let fake_ip_secondary_ready: Option<Arc<dyn Fn() -> bool + Send + Sync>> =
        match (route_coordinator.as_ref(), active_routing_sid.as_ref()) {
            (Some(coord), Some(sid)) => {
                let source = Arc::new(CoordinatorRelaySourceAddrs {
                    coordinator: Arc::clone(coord),
                    active_sid: Arc::clone(sid),
                    cache: Mutex::new(None),
                });
                Some(Arc::new(move || source.current().1.is_some()))
            }
            _ => None,
        };
    // Pre-seed the fake-IP exclusion set with the previously learned VPN
    // servers, so the first VPN connect of THIS session goes direct instead of
    // paying one failed relay round to re-learn them.
    if let Some(conn) = settings_conn.as_ref() {
        let hosts = {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            nrr_storage::fake_ip_heal_exclusions::FakeIpHealExclusionsRepository::new(&guard)
                .load()
                .unwrap_or_default()
        };
        if !hosts.is_empty() {
            let exclusions = fake_ip_assembly.runtime_exclusions();
            let mut seeded = 0usize;
            for host in &hosts {
                if exclusions.insert(host) {
                    seeded += 1;
                }
            }
            tracing::info!(
                target: "nrr::fake-ip",
                seeded,
                total = hosts.len(),
                "pre-seeded VPN self-heal exclusions from persistence — known VPN servers resolve to their real addresses from the first query",
            );
        }
    }
    let fake_ip_armed = if let Some(stack_factory) = build_fake_ip_stack_factory(
        Arc::clone(&fake_ip_assembly),
        cache_store.as_ref(),
        settings_conn.as_ref(),
        active_routing_sid.as_ref(),
        route_coordinator.as_ref(),
        auto_rules_engine.as_ref(),
    ) {
        fake_ip_controller.set_factory(stack_factory);
        true
    } else {
        false
    };
    // Relay datapath watchdog: guards against the stack thread staying
    // alive while the TUN below it silently stops delivering packets —
    // under block-all the relay is the machine's only escape hatch. The
    // controller compares the shared answers/ingress pulse every tick and
    // rebuilds the stack when answers keep flowing with zero ingress; after a
    // rebuild this worker re-runs the same replan + OS-cache flush a boot
    // bring-up does, so the pool permit and client caches match the fresh
    // adapter.
    fake_ip_controller.set_health(fake_ip_assembly.health());
    // Only when there is a stack to watch. `set_factory` is the single arming
    // path, so without it every tick is a no-op — and a recovery-BLOCKED boot
    // (settings/cache/WFP unopenable) would otherwise leave a thread outside
    // the supervisor holding a `replan()` closure for enforcement that was
    // never established.
    if fake_ip_armed {
        let controller = Arc::clone(&fake_ip_controller);
        let replan = Arc::clone(&fake_ip_replan);
        let spawned = std::thread::Builder::new()
            .name("nrr-fakeip-watchdog".into())
            .spawn(move || {
                use nrr_platform_api::DnsCacheControlPort;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    // `replan()` reinstalls filters, so a tick during teardown
                    // would undo the strip.
                    if controller.is_shut_down() || nrr_service_runtime::teardown_in_progress() {
                        break;
                    }
                    if controller.watchdog_tick() {
                        replan();
                        if let Err(e) = nrr_platform_windows::WindowsDnsCacheControl::new()
                            .flush_resolver_cache()
                        {
                            tracing::warn!(
                                target: "nrr::fake-ip",
                                error = ?e,
                                "OS DNS resolver cache flush after watchdog rebuild failed — stale answers persist until TTL",
                            );
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!(
                target: "nrr::fake-ip",
                error = %e,
                "could not spawn fake-IP datapath watchdog worker",
            );
        }
    }
    let dns_egress_policy = match (route_coordinator.as_ref(), active_routing_sid.as_ref()) {
        (Some(coord), Some(sid)) => Some(build_dns_egress_policy(coord, Arc::clone(sid))),
        _ => None,
    };
    // Forwarded queries should leave over the link the policy routes traffic
    // over, not over whichever link happens to own the default route: only the
    // bound primary's resolver knows that network's internal names.
    if let (Some(coord), Some(sid)) = (route_coordinator.as_ref(), active_routing_sid.as_ref()) {
        let coord = Arc::clone(coord);
        let sid = Arc::clone(sid);
        upstream_dns_pool().set_preferred_interface(Arc::new(move || {
            coord.resolve_primary_interface_index(&sid()?)
        }));
    }
    // The Mode-B direct-answer steering is not gated on the
    // secondary being usable: that is precisely when the fail-closed posture
    // BLOCKS the shared addresses, so standing steering down handed direct
    // hosts a set of addresses that could only be dropped. See
    // `ActiveSecondaryOwnedIps`.
    if let Some(factory) = build_dns_resolver_factory(
        settings_conn.as_ref(),
        cache_store.as_ref(),
        active_routing_sid.as_ref(),
        route_recompute_hook.as_ref(),
        known_direct_registry.as_ref(),
        block_all_armed,
        fail_closed_armed,
        Some(Arc::clone(&fake_ip_assembly)),
        Some(Arc::clone(&fake_ip_running)),
        fake_ip_secondary_ready,
        dns_egress_policy,
        auto_rules_engine.clone(),
        Some(Arc::clone(&signed_in)),
    ) {
        dns_resolver_controller.set_factory(factory);
    }
    // DNS-over-secondary — seed the shared live flag from storage at boot, so
    // the setting holds from the first query instead of only after the user
    // touches it (the class of bug the verbose-logging toggle had).
    if let Some(conn) = settings_conn.as_ref() {
        let enabled = read_dns_via_secondary(conn);
        nrr_service_runtime::dns_egress::global_dns_via_secondary()
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "nrr::dns-resolver",
            enabled,
            "DNS-over-secondary setting loaded at boot",
        );
        let fast = read_dns_fast_answers(conn);
        nrr_service_runtime::dns_resolver::global_dns_fast_answers()
            .store(fast, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "nrr::dns-resolver",
            enabled = fast,
            "fast-DNS-answers setting loaded at boot",
        );
        // Fake-IP UDP relay — same boot-seed contract as the two flags above,
        // so the pool permit's UDP handling is correct from the very first
        // per-SID compute instead of only after the user re-saves the toggle.
        let udp_relay = read_fake_ip_udp_relay(conn);
        nrr_service_runtime::fake_ip::global_udp_relay_enabled()
            .store(udp_relay, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "nrr::fake-ip",
            enabled = udp_relay,
            "fake-IP UDP relay setting loaded at boot",
        );
        // Fake-IP instant reset — same boot-seed contract as the flags above,
        // so the relay dial path is correct from the very first dial instead
        // of only after the user re-saves the toggle.
        let instant_rst = read_fake_ip_instant_rst(conn);
        nrr_service_runtime::fake_ip::global_instant_rst_enabled()
            .store(instant_rst, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "nrr::fake-ip",
            enabled = instant_rst,
            "fake-IP instant reset setting loaded at boot",
        );
        // Same boot-seed contract as the flags above.
        let isp_block_candidates = read_isp_block_candidates_enabled(conn);
        nrr_service_runtime::auto_rules::global_isp_block_candidates_enabled()
            .store(isp_block_candidates, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(
            target: "nrr::auto-rules",
            enabled = isp_block_candidates,
            "ISP block-page rule candidates setting loaded at boot",
        );
    }
    let dns_resolver_boot_mode = settings_conn
        .as_ref()
        .map(read_enforcement_mode)
        .unwrap_or_default();
    // Boot-reconcile the fake-IP stack to the persisted state. Desired =
    // toggle ON *and* mode Resolver (fake answers ride the Mode-B resolver).
    // Bring-up waits for a signed-in user (creating an adapter is network
    // churn the logon phase must not carry) and then runs on its own thread so
    // a slow driver never delays the caller; the fail-open gate keeps traffic
    // on real addresses if it fails.
    if let Some(conn) = settings_conn.as_ref() {
        let toggle = read_fake_ip_enabled(conn);
        let desired = toggle
            && dns_resolver_boot_mode == nrr_domain::enforcement_mode::EnforcementMode::Resolver;
        // The master toggle decides whether every other fake-IP setting means
        // anything, so its boot value has to be visible on its own.
        tracing::info!(
            target: "nrr::fake-ip",
            enabled = toggle,
            mode = ?dns_resolver_boot_mode,
            bringing_up = desired,
            "fake-IP setting loaded at boot",
        );
        if desired {
            let controller = Arc::clone(&fake_ip_controller);
            let replan = Arc::clone(&fake_ip_replan);
            sign_in_gate.defer(
                "fake-ip-bring-up",
                Arc::new(move || {
                    let controller = Arc::clone(&controller);
                    let replan = Arc::clone(&replan);
                    std::thread::spawn(move || {
                use nrr_platform_api::DnsCacheControlPort;
                controller.apply(true);
                // The stack usually comes up after the first per-SID applies
                // have run; recompile so the session starts with the pool
                // permit in place instead of waiting for the next recompute.
                replan();
                // The observer-start flush runs before the driver finishes
                // loading, so real answers cached in that window would keep
                // clients off the pool until TTL. Flush again now that fake
                // answers are being served.
                if let Err(e) =
                    nrr_platform_windows::WindowsDnsCacheControl::new().flush_resolver_cache()
                {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        error = ?e,
                        "OS DNS resolver cache flush after fake-IP boot bring-up failed — stale real answers persist until TTL",
                    );
                }
                    });
                }),
            );
        }
    }
    // The production OS network-change observer. Always
    // Windows here (windows-service crate); `run_supervised_runtime` subscribes
    // it and degrades to the 1s/30s polling fallback if OS registration fails.
    let network_change_observer: Arc<
        dyn nrr_platform_windows::network_change::NetworkChangeObserver,
    > = Arc::new(nrr_platform_windows::network_change::WindowsNetworkChangeObserver);

    // Assemble the traffic-counter sampling-tick deps: the sampler
    // plus resolvers for the active user's route roles and the current settings.
    let traffic_tick = match (traffic_sampler.as_ref(), settings_conn.as_ref()) {
        (Some(sampler), Some(state_conn)) => {
            let roles: nrr_service_runtime::TrafficRoleResolver = {
                let conn = Arc::clone(state_conn);
                let registry = Arc::clone(&sid_registry);
                Arc::new(move || {
                    let sids = registry.active_sids();
                    let Some(sid) = sids.first() else {
                        return (None, None);
                    };
                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                    match nrr_storage::RouteBindingsRepository::new(&guard).load_for_sid(sid) {
                        Ok(policy) => (
                            policy.primary.map(|b| b.display_name),
                            policy.secondary.map(|b| b.display_name),
                        ),
                        Err(_) => (None, None),
                    }
                })
            };
            let settings: nrr_service_runtime::TrafficSettingsResolver = {
                let access =
                    nrr_service_runtime::production_traffic::ProductionTrafficSettings::new(
                        Arc::clone(state_conn),
                    );
                Arc::new(move || {
                    use nrr_service_runtime::production_traffic::TrafficSettingsAccess;
                    access
                        .get()
                        .unwrap_or(nrr_storage::TrafficStatsSettings::DEFAULT)
                })
            };
            Some(nrr_service_runtime::TrafficTickDeps {
                sampler: Arc::clone(sampler),
                roles,
                settings,
                timezone: Arc::new(nrr_platform_windows::local_time::WindowsTimeZone),
            })
        }
        _ => None,
    };

    SupervisedRuntimeDeps {
        health: Arc::clone(&health_agg),
        ipc_server,
        adapter_monitor,
        operation_results,
        mutation_tokens: Some(mutation_tokens),
        stability: stability_config,
        // Audit files share `logs_dir`; clone before `logs_dir` moves.
        audit_dir: logs_dir.clone(),
        audit_retention,
        logs_dir,
        log_retention,
        cleanup_scope,
        state_db_conn: settings_conn,
        // Windows enforces through `PerSidApplyOrchestrator`, which owns its own
        // trigger (activation, drift, adapter change) rather than a poll. Wiring
        // the neutral cycle beside it would give one machine two authorities on
        // what is applied, and the losing one would still be writing filters.
        principal_enforcement: None,
        traffic_tick,
        activation_coordinator,
        dns_refresh_orchestrator,
        route_recompute_hook,
        route_teardown_hook,
        rule_hostname_seeder,
        active_routing_sid,
        dns_observation_source,
        dns_observation_consumer,
        conn_observation_source,
        conn_observation_consumer,
        auto_rules_engine,
        auto_rule_probe: auto_probe_wiring,
        app_destination_memory,
        dns_resolver_controller: Some(dns_resolver_controller),
        dns_resolver_boot_mode,
        // The SAME EventBus the IPC handlers publish
        // through, so the adapter monitor's `AdaptersChanged` push reaches every
        // subscribed GUI and the Interfaces page auto-refreshes on secondary up/down.
        event_bus: Some(Arc::clone(&event_bus)),
        network_change_observer: Some(network_change_observer),
        // Under SCM this is the OS wake notification; in console mode nothing
        // dispatches into it and the watchdog tick carries the recovery alone.
        power_event_observer: Some(Arc::new(crate::power_scm::ScmPowerEventObserver)),
        logon_session_observer: Some(Arc::new(crate::logon_scm::ScmLogonSessionObserver)),
        sign_in_gate: Some(sign_in_gate),
        fake_ip_shutdown: Some({
            let controller = Arc::clone(&fake_ip_controller);
            Arc::new(move || controller.shutdown())
        }),
        rebind_requests: Some(rebind_requests),
        secondary_liveness_hook,
        secondary_external_address,
        // Windows learns application destinations and resolutions through the
        // observation CONSUMERS above (WFP net-events and ETW), which do more
        // than fold addresses into a store — attribution, traces, collateral
        // detection. These two ticks are the leaner path a platform without
        // those sources uses instead; running both would record every
        // destination twice.
        app_observation: None,
        dns_observation: None,
        // One console user at a time here, so the per-user tasks keep reading
        // `active_routing_sid`. The list form exists for platforms where several
        // people are logged in at once.
        present_principals: None,
    }
}

/// Whether the opt-in connection trace is requested. True if the
/// `NRR_CONN_TRACE` env var is set OR the sentinel file
/// `%ProgramData%\NetRuleRouter\conn-trace.enabled` exists. The sentinel file
/// is the service-friendly knob (SCM caches the env block at boot, so a new env
/// var needs a reboot; a file just needs a service restart). Slice D replaces
/// both with the persisted GUI settings toggle.
fn conn_trace_requested() -> bool {
    if std::env::var_os("NRR_CONN_TRACE").is_some() {
        return true;
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        return PathBuf::from(program_data)
            .join("NetRuleRouter")
            .join("conn-trace.enabled")
            .exists();
    }
    false
}

/// Read the persisted connection-trace toggles (NDJSON sink, GUI stream) from
/// `service_stability_config`. Returns `(false, false)` on any error — the
/// trace stays off unless explicitly enabled. Read once at bootstrap; the GUI
/// Save persists the row, so a toggle change takes effect on the next service
/// start (consistent with the sibling `verbose_logging` flag).
fn read_conn_trace_flags(conn: Option<&Arc<Mutex<Connection>>>) -> (bool, bool) {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Some(conn) = conn else {
        return (false, false);
    };
    let Ok(guard) = conn.lock() else {
        return (false, false);
    };
    match ServiceStabilityConfigRepository::new(&guard).get_or_default() {
        Ok(r) => (r.conn_trace_ndjson, r.conn_trace_gui),
        Err(_) => (false, false),
    }
}

/// Persist-on-stop (recovery-blocked guarantee) — a minimal, standalone strip
/// of orphaned block/fail-closed/kill-switch WFP filters.
///
/// Opens its OWN short-lived WFP engine session (independent of the full
/// per-SID orchestrator, which is only constructed on a healthy boot), strips
/// the block filters, and drops the session. Runs on every startup alongside
/// crash recovery so a hard-killed prior instance's kill-switch is removed even
/// on a recovery-BLOCKED boot where [`build_supervised_runtime_deps`] never
/// builds the orchestrator (settings/cache/WFP open failed → orchestrator is
/// `None`, so the inline startup strip there would not run). Permit filters and
/// routes are untouched. Best-effort: any failure is logged and ignored —
/// booting must not hinge on it, and the healthy-path strip is defence in depth.
/// How long the startup strip may take before boot goes on without it. A wedged
/// filtering engine otherwise parks the whole service in START_PENDING with no
/// way back: the strip is a defensive cleanup, never a reason not to start.
const ORPHAN_STRIP_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// Budget for bringing a connection observer up. Shorter than the strip's: the
/// trace is pure diagnostics and nothing downstream waits on it.
const CONN_OBSERVER_START_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Budget for the boot-path engine handle behind the apply layer. `FwpmEngineOpen0`
/// is an RPC into BFE, and a wedged engine never answers it — this call sits on
/// the only path to Running, so without a ceiling the service parks in
/// START_PENDING for good. Timing out costs enforcement (the apply layer drops to
/// noop) and buys a service that is up, reachable over IPC and diagnosable.
const WFP_OPEN_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// How long the offline sweep waits on the filtering engine.
///
/// Generous: a real sweep of a few thousand filters measures in seconds, and
/// this runs when something is already wrong. Bounded all the same — the whole
/// point of this tool is to rescue a machine whose engine may be the thing that
/// is stuck, and a recovery command that hangs forever rescues nobody.
const WFP_SWEEP_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// How slow an engine open has to be before it is worth a line in the log. A
/// healthy open is single-digit milliseconds.
const WFP_OPEN_SLOW_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);

fn open_wfp_session_budgeted(
    api: Arc<dyn WindowsApiPort>,
) -> Result<WfpSession, nrr_platform_windows::PlatformError> {
    let started = std::time::Instant::now();
    let opened = with_budget(
        "WFP engine open (apply layer)",
        WFP_OPEN_BUDGET,
        move || WfpSession::open(api),
    );
    let elapsed = started.elapsed();
    match &opened {
        Ok(_) if elapsed >= WFP_OPEN_SLOW_THRESHOLD => tracing::warn!(
            target: "nrr::boot",
            elapsed_ms = elapsed.as_millis() as u64,
            "the filtering engine took a long time to hand out a session — enforcement is up, \
             but the engine on this machine is answering slowly",
        ),
        Ok(_) => {}
        Err(_) => tracing::error!(
            target: "nrr::boot",
            elapsed_ms = elapsed.as_millis() as u64,
            budget_secs = WFP_OPEN_BUDGET.as_secs(),
            "could not get a filtering-engine session within the boot budget — the service will \
             start WITHOUT enforcement (rules are not applied). Restart the Base Filtering Engine \
             (BFE) service and then restart this service",
        ),
    }
    opened
}

/// Run `work` on its own thread and give up waiting after `budget`.
///
/// A thread left behind is deliberate: whatever it is stuck in would not answer
/// a cancel either, and every caller here does work that is safe to land late
/// or never. Returns the timeout as a `Transient` error so callers degrade
/// through their existing error path.
fn with_budget<T, F>(
    what: &'static str,
    budget: std::time::Duration,
    work: F,
) -> Result<T, nrr_platform_windows::PlatformError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, nrr_platform_windows::PlatformError> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    if std::thread::Builder::new()
        .name("nrr-budgeted-start".to_string())
        .spawn(move || {
            let _ = tx.send(work());
        })
        .is_err()
    {
        return Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            detail: format!("could not spawn a worker for {what}"),
        });
    }
    rx.recv_timeout(budget).unwrap_or_else(|_| {
        tracing::warn!(
            target: "nrr::boot",
            what,
            budget_secs = budget.as_secs(),
            "step did not answer within its budget — continuing without it",
        );
        Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            detail: format!("{what} did not finish within {:?}", budget),
        })
    })
}

pub(crate) fn strip_orphaned_block_filters_standalone() {
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached on purpose: if it is stuck in the engine it will not answer a
    // cancel either, and the cleanup it performs is idempotent whenever it lands.
    std::thread::Builder::new()
        .name("nrr-orphan-strip".to_string())
        .spawn(move || {
            strip_orphaned_block_filters_blocking();
            let _ = tx.send(());
        })
        .ok();
    if rx.recv_timeout(ORPHAN_STRIP_BUDGET).is_err() {
        tracing::warn!(
            target: "nrr::runtime",
            budget_secs = ORPHAN_STRIP_BUDGET.as_secs(),
            "startup: orphaned-filter strip did not finish in time — continuing the boot without it \
             (a leftover kill-switch may still be in force until the strip lands)",
        );
    }
}

fn strip_orphaned_block_filters_blocking() {
    tracing::debug!(target: "nrr::runtime", "startup: opening WFP to strip orphaned block filters");
    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);
    match WfpSession::open(Arc::clone(&api)) {
        Ok(session) => match session.cleanup_blocks_only() {
            Ok(0) => {}
            Ok(n) => tracing::warn!(
                target: "nrr::runtime",
                stripped_blocks = n as u64,
                "startup: stripped orphaned block/kill-switch WFP filter(s) \
                 (standalone recovery path)",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::runtime",
                "standalone block-filter strip failed: {e:?}",
            ),
        },
        Err(e) => tracing::warn!(
            target: "nrr::runtime",
            "standalone block-filter strip: WFP engine open failed: {e:?}",
        ),
    }
    tracing::debug!(target: "nrr::runtime", "startup: orphaned-filter strip finished");
}

/// Disaster-recovery offline reset — strip **every** NetRuleRouter WFP filter
/// (block AND permit) and any leftover NRR-owned route WITHOUT the service
/// running. Backs the `cleanup` console subcommand.
///
/// A crashed / hard-killed service leaves its non-dynamic WFP session's filters
/// behind: they survive `taskkill /F` until an explicit delete or a reboot, and
/// an orphaned kill-switch / fail-closed block can lock the machine off the
/// network with no service left to lift it. This opens its OWN short-lived WFP
/// engine session — the same enumerate-by-provider-GUID sweep
/// [`nrr_service_runtime::per_sid_orchestrator::PerSidApplyOrchestrator::cleanup_wfp`]
/// runs via [`WfpSession::cleanup_all`] — deletes all our filters, then sweeps
/// the OS route table for routes carrying our signature and removes them. Safe
/// to run when the service is installed but stopped (nothing else holds the
/// engine).
///
/// Requires elevation: `FwpmEngineOpen0` returns access-denied for a
/// non-elevated caller, which we detect via [`ErrorClass::PrivilegeRequired`]
/// and turn into a "re-run elevated" message (no new `unsafe` token probe).
pub(crate) fn run_offline_reset() -> std::process::ExitCode {
    match sweep_orphaned_machine_state() {
        SweepOutcome::Done => std::process::ExitCode::SUCCESS,
        // The console relays this verbatim as its own "needs privilege" code,
        // which is what its documented contract promises and what makes its
        // elevation offer fire. Reported as a plain failure it was
        // indistinguishable from a wedged engine, and the one command a locked-
        // out user is told to run gave the wrong advice back.
        SweepOutcome::PrivilegeRequired => std::process::ExitCode::from(3),
        SweepOutcome::Failed => std::process::ExitCode::from(1),
    }
}

/// Why an offline sweep stopped.
pub(crate) enum SweepOutcome {
    /// Everything reachable was cleared.
    Done,
    /// The engine refused this caller — the console has to be elevated.
    PrivilegeRequired,
    /// Anything else; already reported on stderr.
    Failed,
}

/// The sweep itself. Not a `bool`: "we were refused" and "it did not work" ask
/// opposite things of the person running it, and only the sweep knows which
/// happened.
pub(crate) fn sweep_orphaned_machine_state() -> SweepOutcome {
    use nrr_platform_windows::ErrorClass;

    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);

    // ── WFP filter sweep (the lockout risk) ────────────────────────────
    // Opening the engine and sweeping it are one budgeted unit: both are RPC
    // into the Base Filtering Engine, and a wedged engine answers neither. This
    // command exists to rescue a machine that is already in trouble, so it must
    // come back and say so rather than sit there.
    //
    // `cleanup_all` enumerates every filter under the NRR provider GUID and
    // deletes it in one transaction (block AND permit) — the same sweep the
    // orchestrator's `cleanup_wfp` runs, minus the in-memory tracked-id pass
    // (there is no live orchestrator state to consult offline).
    let swept = with_budget("WFP filter sweep", WFP_SWEEP_BUDGET, {
        let api = Arc::clone(&api);
        move || WfpSession::open(api).and_then(|session| session.cleanup_all())
    });
    let filters_removed = match swept {
        Ok(n) => n,
        Err(e) if e.classify() == ErrorClass::PrivilegeRequired => {
            eprintln!(
                "cleanup: access denied opening the WFP engine. Re-run from an elevated \
                 (Administrator) console (the `scripts/reset-network.ps1` wrapper \
                 self-elevates via UAC)."
            );
            return SweepOutcome::PrivilegeRequired;
        }
        Err(nrr_platform_windows::PlatformError::Transient {
            operation: "budgeted start",
            ..
        }) => {
            eprintln!(
                "cleanup: the Windows Base Filtering Engine did not answer within \
                 {} s — it is wedged, and nothing here can move it.",
                WFP_SWEEP_BUDGET.as_secs()
            );
            eprintln!(
                "  Our filters are not persistent: a REBOOT clears them and restores \
                 the network. Restarting the `BFE` service first is worth a try."
            );
            return SweepOutcome::Failed;
        }
        Err(e) => {
            eprintln!("cleanup: WFP filter sweep failed: {e:?}");
            return SweepOutcome::Failed;
        }
    };

    // Machine-wide Base Filtering Engine options. An instance that was killed
    // rather than stopped never ran its own restore and left them changed; it
    // wrote down what they held, which is what makes this possible from here.
    nrr_platform_windows::conn_observe::wfp_events::restore_engine_options();

    // ── Route sweep (best-effort) ──────────────────────────────────────
    // Enumerate the live OS route table and adopt every route carrying our
    // signature (`SECONDARY_ROUTE_METRIC` at prefix /32 or /2 — the secondary
    // host routes and the mode-A counter-overlay halves), then `clear()`
    // deletes them. Purely signature-based, so it needs no per-SID binding
    // state and works fully offline — the same shapes
    // `SecondaryRouteCoordinator::adopt_orphans_from_table` adopts on startup.
    // Any failure is non-fatal: our routes are non-persistent and clear on the
    // next reboot regardless.
    let routes_removed: Option<usize> = match api.get_ip_forward_table() {
        Ok(table) => {
            let orphans: Vec<_> = table
                .into_iter()
                .filter(|r| {
                    r.metric == nrr_service_runtime::route_codegen::SECONDARY_ROUTE_METRIC
                        && (r.prefix_length == 32 || r.prefix_length == 2)
                })
                .map(|mut r| {
                    r.is_ours = true;
                    r
                })
                .collect();
            if orphans.is_empty() {
                Some(0)
            } else {
                let reconciler =
                    nrr_service_runtime::route_reconciler::SecondaryRouteReconciler::new(
                        Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                    );
                reconciler.adopt_owned(orphans);
                match reconciler.clear() {
                    Ok(delta) => Some(delta.removed),
                    Err(e) => {
                        eprintln!(
                            "cleanup: route sweep failed ({e:?}); a reboot fully clears any \
                             remaining NetRuleRouter routes."
                        );
                        None
                    }
                }
            }
        }
        Err(e) => {
            eprintln!(
                "cleanup: could not enumerate the route table ({e:?}); a reboot fully clears \
                 any remaining NetRuleRouter routes."
            );
            None
        }
    };

    // ── NRPT / DNS-redirect sweep (the DNS-lockout risk) ───────────────
    // A crashed Mode-B (Resolver) session leaves an NRPT catch-all rule
    // pointing ALL name resolution at our loopback :53 listener. With the
    // service dead that listener is gone, so EVERY DNS query fails until the
    // rule is removed or the machine reboots — a worse lockout than the WFP
    // filters (no name resolves at all). `clear_orphan_redirect` removes only
    // rules carrying our marker, so an admin's or a VPN's own NRPT rule is
    // untouched. Same sweep the service runs at boot; here it runs offline.
    // Best-effort — the marker-scoped removal is safe to attempt regardless of
    // whether a rule exists.
    let nrpt_cleared = match nrr_platform_windows::dns_redirect::clear_orphan_redirect(
        &nrr_platform_windows::dns_redirect::TransactedNrptStore,
    ) {
        Ok(removed) => Some(removed),
        Err(e) => {
            eprintln!(
                "cleanup: NRPT/DNS-redirect sweep failed ({e:?}); if DNS is broken, remove the \
                 rule manually (`Get-DnsClientNrptRule | Where Comment -eq \
                 'NetRuleRouter-ModeB-DnsRedirect' | Remove-DnsClientNrptRule -Force`) or reboot."
            );
            None
        }
    };

    // ── Summary ────────────────────────────────────────────────────────
    println!("NetRuleRouter offline reset complete.");
    println!("  WFP filters removed: {filters_removed}");
    match routes_removed {
        Some(n) => println!("  routes removed: {n}"),
        None => println!("  routes removed: <sweep skipped — clears on reboot>"),
    }
    match nrpt_cleared {
        Some(n) => println!("  DNS redirect (NRPT) rules removed: {n}"),
        None => println!("  DNS redirect (NRPT) rules: <sweep failed — see above>"),
    }
    println!("Reboot to fully clear any remainder.");
    if nrpt_cleared.is_some() {
        SweepOutcome::Done
    } else {
        SweepOutcome::Failed
    }
}

/// Persist-on-stop — read the `routing_stop_policy` FRESH from
/// `service_stability_config`. Returns `true` only for the explicit `persist`
/// slug; any error, a missing row, or the default row all yield `false`
/// (teardown). Called from the graceful-stop hook at stop time (not a boot
/// snapshot) so a mid-session Save takes effect. Failing to `false` is the safe
/// posture: teardown always cleans up, so a corrupted row can never strand
/// routes or an orphaned block.
fn read_routing_stop_persist(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::{
        RoutingStopPolicy, ServiceStabilityConfigRepository,
    };
    let Ok(guard) = conn.lock() else {
        return false;
    };
    match ServiceStabilityConfigRepository::new(&guard).get_or_default() {
        Ok(r) => matches!(r.routing_stop_policy, RoutingStopPolicy::Persist),
        Err(_) => false,
    }
}

/// Build the opt-in connection-egress trace source+consumer pair. Returns
/// `(None, None)` unless the trace is requested ([`conn_trace_requested`]) AND
/// the route path
/// (coordinator + active-SID resolver) is available. The WFP net-event source
/// is started here; failure to start degrades to no trace (a WARN only), the
/// same graceful-degradation contract as the DNS-Client observer.
/// Spawn the FCrDNS learner worker. Owns the
/// `ReverseDnsLearner` (PTR + forward-confirm against the CURRENT captured
/// upstream, re-captured on a 5-min TTL like the hosts-bypass resolver) and the
/// rule-gated cache sink (the DNS-observation consumer's `learn_reverse_confirmed`
/// keep-logic), draining dropped IPs off the observe-tick hot path. The thread
/// ends when the sender (held by the conn-trace consumer) is dropped at shutdown.
fn spawn_fcrdns_learner_worker(
    rx: std::sync::mpsc::Receiver<(std::net::Ipv4Addr, bool)>,
    consumer: Arc<nrr_service_runtime::dns_observation_consumer::DnsObservationConsumer>,
    companion: Option<CompanionFromReverseDeps<'_>>,
) {
    use nrr_service_runtime::dns_resolver_ports::{
        ConsumerConfirmedHostSink, FcrdnsUpstreamResolver,
    };
    use nrr_service_runtime::fcrdns_learner::{LearnOutcome, ReverseDnsLearner};
    use std::time::Duration;

    // Cap distinct IPs named per service run — a backstop against a drop storm
    // turning into a PTR/A query flood (each IP is attempted at most once anyway).
    const MAX_ATTEMPTS_PER_SESSION: usize = 512;

    let pool = upstream_dns_pool();
    let upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync> =
        Arc::new(move || pool.current().or_else(|| pool.note_network_change()));

    let resolver = FcrdnsUpstreamResolver::new(upstream, Duration::from_millis(1500));
    // Two sinks over the same consumer: one for the exact-match fast path
    // below, one owned by the reverse-lookup learner.
    let exact_sink = ConsumerConfirmedHostSink::new(Arc::clone(&consumer));
    let mut sink = ConsumerConfirmedHostSink::new(consumer);
    // A forward-confirmed name that matches no rule is the DoH / browser-cache
    // blind spot made visible: nothing else in the service ever learned it
    // exists. If it loaded beside a routed site, that is a companion worth
    // asking about.
    if let Some(deps) = companion {
        let engine = Arc::clone(deps.engine);
        let active_sid = Arc::clone(deps.active_sid);
        sink = sink.with_companion_sink(Arc::new(move |hostname: &str| {
            let Some(sid) = active_sid() else {
                return;
            };
            engine.note_candidate_in_use(&sid, hostname, std::time::SystemTime::now());
        }));
    }
    let learner = ReverseDnsLearner::new(resolver, sink, MAX_ATTEMPTS_PER_SESSION);
    let recent = nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses();

    let spawned = std::thread::Builder::new()
        .name("nrr-fcrdns".into())
        .spawn(move || {
            for (ip, allow_direct) in rx {
                // Exact match first: if our own resolver saw this address in a
                // rule host's answer recently, the address needs no naming — we
                // already know whose it is. This is the common case for a
                // provider pool an app cached behind our back, where the
                // reverse name belongs to infrastructure that matches no rule
                // and the lookup below would never tie it back.
                if let Some(host) = recent.lookup(ip) {
                    if nrr_service_runtime::fcrdns_learner::ConfirmedHostSink::record_confirmed(
                        &exact_sink,
                        &host,
                        &[ip],
                    ) {
                        tracing::info!(
                            target: "nrr::fcrdns",
                            ip = %ip,
                            host = %host,
                            "dropped destination matched a recent answer for a rule host — permit compiles on the next reconcile",
                        );
                        continue;
                    }
                }
                match learner.learn_scoped(ip, allow_direct) {
                    LearnOutcome::Learned => tracing::info!(
                        target: "nrr::fcrdns",
                        ip = %ip,
                        "reverse-confirmed a dropped destination into a rule host — permit compiles on the next reconcile",
                    ),
                    // Forward-confirmed but matches NO rule: a
                    // positively-direct destination the block-all was cutting.
                    LearnOutcome::LearnedDirect => tracing::info!(
                        target: "nrr::fcrdns",
                        ip = %ip,
                        "reverse-confirmed a dropped destination into a DIRECT host — block-all exemption compiles on the next reconcile",
                    ),
                    LearnOutcome::NotConfirmed | LearnOutcome::Skipped => {}
                }
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(target: "nrr::fcrdns", error = %e, "could not spawn FCrDNS learner worker");
    }
}

/// Reactive VPN-endpoint learning deps for [`build_conn_trace_pair`], bundled
/// to keep the function's argument count sane: the bounded, session-scoped
/// server set the learner writes into (see
/// `nrr_service_runtime::vpn_endpoint_learning`) and the kill-switch/
/// fail-closed Block-id registry that role-verifies a drop before the
/// learner trusts it (see `nrr_service_runtime::killswitch_drop_registry`).
struct VpnLearningDeps<'a> {
    learned_vpn_endpoints: &'a Arc<nrr_service_runtime::vpn_endpoint_learning::LearnedVpnEndpoints>,
    killswitch_drop_registry:
        &'a Arc<nrr_service_runtime::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    /// Proactive VPN-client learning: the verified-client
    /// registry the app sink writes into (the same one the per-SID
    /// orchestrator reads for the block-all app exemption).
    learned_vpn_client_apps:
        &'a Arc<nrr_service_runtime::vpn_client_registry::LearnedVpnClientApps>,
    /// Best-effort persistence for a newly-learned client path (state DB
    /// `vpn_client_apps`). `None` when the state DB is unavailable — the
    /// registry then stays session-scoped.
    vpn_client_app_persist: Option<VpnClientAppPersistFn>,
    /// Companion discovery, fed from the same observations: a flow leaving
    /// over the primary while a routed site is open names an address that
    /// site needed and did not get. `None` keeps the observer diagnostic.
    auto_rules_engine: Option<&'a Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    /// Block-notice reporting — unrelated to VPN learning, bundled here for
    /// the same "keep the argument count sane" reason as `auto_rules_engine`
    /// above. Always wired (unlike the VPN learners, it needs no gate).
    block_notice_center: &'a Arc<nrr_service_runtime::block_notice_center::BlockNoticeCenter>,
    /// The live fail-closed posture, read when a drop is explained: during an
    /// outage window the outage is the reason, whichever filter caught it.
    block_all_posture: &'a nrr_service_runtime::app_enforcement_status::BlockAllPostureStatus,
}

/// Best-effort write-through of one learned VPN client exe path.
type VpnClientAppPersistFn = Arc<dyn Fn(&str) + Send + Sync>;

/// What the FCrDNS worker needs to report a reverse-named non-rule host to
/// companion discovery: the engine to tell, and whose session it belongs to.
struct CompanionFromReverseDeps<'a> {
    engine: &'a Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    active_sid: &'a nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
}

/// Map an OBSERVED process path to the Win32 drive-letter form the WFP
/// `ALE_APP_ID` builder accepts. WFP-sourced observations carry the kernel's
/// NT-device form (`\device\harddiskvolumeN\...`); ETW-sourced ones already
/// carry a drive letter and pass through. `None` (and always on non-Windows,
/// where no observer produces NT paths) means "skip — never guess".
fn observed_path_to_win32(path: &str) -> Option<std::path::PathBuf> {
    #[cfg(target_os = "windows")]
    {
        nrr_platform_windows::win32_path_from_nt_path(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        None
    }
}

/// Optional hooks the connection observer feeds as it classifies a batch.
/// Grouped because they arrive together and are wired from the same place —
/// and because passing them loose put the builder over the argument limit.
struct ObservationSinks {
    /// When the FCrDNS worker is active, this sender is the drop hook: OUR
    /// block of a routable V4 enqueues the IP for the worker to name +
    /// forward-confirm. `None` disables reverse-learning.
    reverse_dns_learner_tx: Option<std::sync::mpsc::SyncSender<(std::net::Ipv4Addr, bool)>>,
    /// Deletes one remembered application destination. Wired when the state DB
    /// is open: a destination withdrawn for moving another process's traffic
    /// must not be re-seeded from disk at the next start.
    app_destination_forget:
        Option<nrr_service_runtime::conn_observation_consumer::AppDestinationForgetFn>,
    /// The rule book's routed application patterns. Without it the collateral
    /// check cannot tell a pin from an ordinary observation and stays silent.
    routed_apps: Option<nrr_service_runtime::conn_observation_consumer::RoutedAppsFn>,
}

fn build_conn_trace_pair(
    api: &Arc<dyn WindowsApiPort>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    ndjson_on: bool,
    trace_ring: Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>>,
    sinks: ObservationSinks,
    vpn_learning: VpnLearningDeps<'_>,
) -> (
    Option<Arc<dyn nrr_platform_windows::conn_observe::ConnectionObservationSource>>,
    Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionObservationConsumer>>,
) {
    let ObservationSinks {
        reverse_dns_learner_tx,
        app_destination_forget,
        routed_apps,
    } = sinks;
    // The observer runs whenever the route path is available (it is a
    // passive kernel event subscription that also feeds app-routing's observed
    // app→IP store) and ALWAYS feeds the in-memory GUI ring, so "Show
    // connections" works without a service restart. The on-disk NDJSON sink is
    // written only when explicitly enabled (`ndjson_on`).
    let (Some(coord), Some(active_sid)) = (route_coordinator, active_routing_sid) else {
        tracing::warn!(
            target: "nrr::conn-trace",
            "connection observer: route path unavailable — trace disabled",
        );
        return (None, None);
    };
    let mut consumer_builder =
        nrr_service_runtime::conn_observation_consumer::ConnectionObservationConsumer::new(
            Arc::clone(api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
            Arc::clone(coord),
            Arc::clone(active_sid),
            // Write to the on-disk NDJSON sink only when explicitly enabled;
            // the in-memory GUI ring is always fed (wired below).
            ndjson_on,
        )
        // App-routing via observation: feed the process-wide
        // observed app→IP store the codegen reads for `Application` rules.
        .with_app_observations(
            nrr_service_runtime::app_observation_lookup::global_app_observations(),
        );
    if let Some(forget) = app_destination_forget {
        consumer_builder = consumer_builder.with_app_destination_forget(forget);
    }
    if let Some(routed) = routed_apps {
        consumer_builder = consumer_builder.with_routed_apps(routed);
    }
    // Feed the connection-trace ring so the Diagnostics panel can read
    // recent connections (only wired when the GUI stream is on → ring is Some).
    let trace_ring_flag = trace_ring.clone();
    if let Some(ring) = trace_ring {
        consumer_builder = consumer_builder.with_trace_ring(ring);
    }
    // Reactive VPN self-learning: a flow our kill-switch/fail-closed BLOCK
    // drops, from a process matching a VPN-client pattern, teaches the
    // exemption set the tunnel's server IP so the client's own retry gets
    // through and the tunnel can reconnect without the user disabling
    // protection. A bare process-name glob, provider- not role-based drop
    // attribution, and an unbounded system-wide persisted exemption were all
    // rejected as too loose to ship; each concern is closed here:
    //   1. Role, not just ownership: the consumer only trusts a drop whose
    //      decoded WFP spec id is a member of `killswitch_drop_registry`
    //      (published from the per-SID orchestrator's kill-switch/fail-closed
    //      Block set) — a user's own Block rule can never pass this gate.
    //   2. Bounded: `learned_vpn_endpoints` caps at a handful of entries with
    //      a hard TTL (see `LearnedVpnEndpoints`), each independently expiring.
    //   3. In-memory only, never persisted — the set is session-scoped and
    //      rebuilds itself on the next handshake if the service restarts.
    // Rides the existing sid-scoped bootstrap-server exemption band (merged in
    // `SecondaryRouteCoordinator::kill_switch_exemptions` /
    // `fail_closed_exemptions`), so no new codegen surface is introduced.
    {
        let learned = Arc::clone(vpn_learning.learned_vpn_endpoints);
        let learner: nrr_service_runtime::conn_observation_consumer::VpnEndpointLearnFn =
            Arc::new(move |ip: std::net::Ipv4Addr| {
                if learned.register(ip, std::time::SystemTime::now()) {
                    tracing::info!(
                        target: "nrr::vpn-learn",
                        server = %ip,
                        "reactive learner: new role-verified VPN bootstrap endpoint",
                    );
                }
            });
        let registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        // Learner and its role-verification gate go in together — see the
        // builder: apart, the learner is inert and says nothing about it.
        consumer_builder = consumer_builder
            .with_vpn_endpoint_learner(learner, Arc::new(move |id| registry.contains(id)));
        // The same registry classifies the drop's blocking scope,
        // so the scope-bug detector can tell an app pin's expected first
        // contact from a destination pin that outran its route.
        let scope_registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        consumer_builder = consumer_builder
            .with_killswitch_app_scope_check(Arc::new(move |id| scope_registry.is_app_scoped(id)));
        // …and identifies the blanket IPv6 cut, so a drop of the closed family
        // is announced as that instead of as one of the user's rules.
        let v6_registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        consumer_builder = consumer_builder
            .with_ipv6_cut_drop_check(Arc::new(move |id| v6_registry.is_ipv6_cut(id)));
        // …and the DoH/DoT lockdown, so an app reaching for its own resolver
        // is told about the switch that closed it, not about a rule.
        let dns_registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        consumer_builder = consumer_builder
            .with_dns_lockdown_drop_check(Arc::new(move |id| dns_registry.is_dns_lockdown(id)));
        // The same posture the GUI banner reads decides how a drop is
        // EXPLAINED: while the block-all is armed, an outage is the cause.
        let posture = vpn_learning.block_all_posture.clone();
        consumer_builder =
            consumer_builder.with_fail_closed_armed(Arc::new(move || posture.armed()));
    }
    // Proactive VPN-client learning: the SAME role-verified drop
    // that teaches a server IP also identifies the CLIENT PROCESS. Register
    // its on-disk exe path so the next reconcile permits the whole process
    // through any block-all posture (its egress is the tunnel's transport),
    // and persist it so the exemption arms at STARTUP in later sessions —
    // closing the rotating-check-IP loop the per-IP learner cannot (each
    // rotation was a fresh hang-until-drop in field observations).
    // Gated by the same drop-registry role check wired above; the sink
    // additionally requires the mapped path to exist on disk.
    {
        let registry = Arc::clone(vpn_learning.learned_vpn_client_apps);
        let persist = vpn_learning.vpn_client_app_persist.clone();
        let app_learner: nrr_service_runtime::conn_observation_consumer::VpnClientAppLearnFn =
            Arc::new(move |observed_path: &str| {
                let Some(win32) = observed_path_to_win32(observed_path) else {
                    tracing::debug!(
                        target: "nrr::vpn-learn",
                        path = observed_path,
                        "VPN client path has no drive-letter mapping — skipping app-scoped learning",
                    );
                    return false;
                };
                if !win32.is_file() {
                    tracing::debug!(
                        target: "nrr::vpn-learn",
                        path = %win32.display(),
                        "mapped VPN client path does not exist on disk — skipping app-scoped learning",
                    );
                    return false;
                }
                let path_str = win32.to_string_lossy().into_owned();
                if !registry.register(&path_str, std::time::SystemTime::now()) {
                    return false;
                }
                tracing::info!(
                    target: "nrr::vpn-learn",
                    path = %path_str,
                    "learned VPN client application from a role-verified kill-switch drop — app-scoped block-all exemption compiles on the next reconcile",
                );
                if let Some(persist) = persist.as_ref() {
                    persist(&path_str);
                }
                true
            });
        consumer_builder = consumer_builder.with_vpn_client_app_learner(app_learner);
    }
    // FCrDNS reverse-learning drop hook. When
    // OUR enforcement drops a routable destination under block-all (the browser
    // reached it from its own cache / DoH so the observer never saw the name), the
    // dropped IP is enqueued (bounded, non-blocking) for the worker to name (PTR +
    // forward-confirm) and — iff it matches a rule — cache; the next coverage
    // reconcile then compiles the permit. SAFE: grants NO exemption (unlike the
    // disabled VPN learner), only feeds the rule-gated cache, so an over-attributed
    // `blocked_by_nrr` can never punch a hole. The hook only enqueues, so the
    // observe tick never blocks on DNS I/O.
    if let Some(tx) = reverse_dns_learner_tx {
        consumer_builder = consumer_builder.with_reverse_dns_learner(Arc::new(
            move |ip: std::net::Ipv4Addr, allow_direct: bool| {
                let _ = tx.try_send((ip, allow_direct));
            },
        ));
    }
    // Companion discovery from real traffic: a flow leaving over the primary
    // while the user sits on a routed site is the half-broken page. The name
    // comes from the recent-resolution memory the resolver already keeps — no
    // extra lookup, and an address nobody resolved is simply not reported.
    if let Some(engine) = vpn_learning.auto_rules_engine {
        let recent = nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses();
        let engine_health = Arc::clone(engine);
        let engine = Arc::clone(engine);
        let sid_for_companion = Arc::clone(active_sid);
        consumer_builder = consumer_builder.with_companion_in_use(
            Arc::new(move |ip| recent.lookup(ip)),
            Arc::new(move |hostname: &str| {
                let Some(sid) = sid_for_companion() else {
                    return;
                };
                engine.note_candidate_in_use(&sid, hostname, std::time::SystemTime::now());
            }),
        );
        // How the host fares on the primary link. The offer is "move this into
        // the tunnel", so whether it already works without one is the fact that
        // most changes the user's answer.
        let sid_for_health = Arc::clone(active_sid);
        // The same signal feeds two readers with different scopes. The engine
        // keeps it only for hosts it already tracks as companion candidates and
        // drops it for anything else; the registry keeps it for every named
        // destination, which is the only record of "this host does not open"
        // for a host nobody has a theory about yet.
        let stalls = nrr_service_runtime::primary_stall_registry::global_primary_stalls();
        consumer_builder =
            consumer_builder.with_companion_primary_health(Arc::new(move |hostname, stalled| {
                let event = if stalled {
                    nrr_domain::companion_affinity::PrimaryHealthEvent::Stalled
                } else {
                    nrr_domain::companion_affinity::PrimaryHealthEvent::Completed
                };
                let report = stalls.note(hostname, event);
                if let Some(report) = report.as_ref() {
                    nrr_service_runtime::primary_stall_registry::log_report(report);
                }
                let Some(sid) = sid_for_health() else {
                    return;
                };
                engine_health.note_primary_health(&sid, hostname, event);
                // A verdict that just turned to "stalls" is the product
                // finding out, by measurement, that the main link will
                // not carry this site. Offering the additional route is
                // the whole point of having noticed. Only on the CHANGE:
                // the registry stays silent while the verdict holds, so
                // this cannot fire per packet.
                if report.is_some_and(|r| {
                    r.behavior == nrr_domain::companion_affinity::PrimaryBehavior::Stalls
                }) {
                    // Evidence for the threshold, recorded exactly where the
                    // offer is born: this is the moment the product decides a
                    // host is worth asking about.
                    let nav = nrr_service_runtime::navigation_registry::global_navigation();
                    nrr_service_runtime::navigation_registry::log_counts(
                        hostname,
                        &nav.counts_of(hostname),
                    );
                    engine_health.note_main_link_blocked_host(
                        &sid,
                        hostname,
                        std::time::SystemTime::now(),
                    );
                }
            }));
        // Did the user go to this host, or did a page take them there? Pure
        // measurement for now: nothing reads the counts to decide anything,
        // they only travel beside the verdict below so the thresholds can be
        // picked from real traffic instead of guessed.
        {
            let nav = nrr_service_runtime::navigation_registry::global_navigation();
            consumer_builder = consumer_builder.with_navigation_attempt(Arc::new(
                move |process: Option<&str>, hostname: Option<&str>, at_ms: u64| {
                    if let Some(dist) = nav.note_attempt(process, hostname, at_ms) {
                        nrr_service_runtime::navigation_registry::log_distribution(&dist);
                    }
                },
            ));
        }
        // Names for the hosts the rule index cannot name. Health-only: a
        // rule-less name may say how a host fares, never bring it into
        // companion discovery.
        consumer_builder = consumer_builder.with_health_name_fallback({
            let observed = nrr_service_runtime::observed_host_names::global_observed_host_names();
            Arc::new(move |ip| observed.lookup(ip))
        });
    }
    // Block-notice reporting: the observer decides which OUR drops are
    // notice-worthy (see `conn_observation_consumer::block_reason_for`); the
    // center folds them into episodes and logs the survivors. Always wired —
    // unlike the VPN learners this needs no role-verification gate of its
    // own beyond what the consumer already applies.
    {
        let recent = nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses();
        let center = Arc::clone(vpn_learning.block_notice_center);
        consumer_builder = consumer_builder.with_block_notice(
            Arc::new(move |ip| recent.lookup(ip)),
            Arc::new(move |sid: &str, attempt| center.record(sid, &attempt)),
        );
    }
    // A flow older than the pin that caught it can never reach the tunnel;
    // tearing it down turns a stalled socket into an immediate reconnect.
    consumer_builder = consumer_builder.with_stale_flow_reset(Arc::new(
        nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
    ));
    let consumer = Arc::new(consumer_builder);
    let backend = conn_trace_backend();
    type DynSource = Arc<dyn nrr_platform_windows::conn_observe::ConnectionObservationSource>;
    // Local starters so the merged path can attempt both backends without
    // duplicating the Arc-coercion boilerplate.
    let start_etw = || -> Result<DynSource, nrr_platform_windows::PlatformError> {
        nrr_platform_windows::conn_observe::etw_tcpip::EtwKernelNetworkObserver::start()
            .map(|o| Arc::new(o) as DynSource)
    };
    let start_wfp = || -> Result<DynSource, nrr_platform_windows::PlatformError> {
        // Subscribing goes into the filtering engine, and a wedged engine never
        // answers: on Win11 this is where a boot stopped for good. The trace is
        // a diagnostic, so it gets a budget and the service starts without it.
        with_budget(
            "WFP net-event observer start",
            CONN_OBSERVER_START_BUDGET,
            || {
                nrr_platform_windows::conn_observe::wfp_events::WfpConnectionObserver::start()
                    .map(|o| Arc::new(o) as DynSource)
            },
        )
    };
    let started: Result<DynSource, nrr_platform_windows::PlatformError> = match backend {
        ConnTraceBackend::Etw => start_etw(),
        ConnTraceBackend::Wfp => start_wfp(),
        // Default: run BOTH and merge. ETW captures
        // every TCP connect (so codex/browser connects appear), WFP adds the
        // allow/block verdict (notably drops). Degrade gracefully to whichever
        // single backend starts; error only if BOTH fail. Merging is pure
        // fan-in over `drain()` — it adds NO observe-filter to the live WFP
        // filter set, so there is no lockout risk.
        ConnTraceBackend::Both => {
            let mut live: Vec<DynSource> = Vec::new();
            match start_etw() {
                Ok(s) => live.push(s),
                Err(e) => tracing::warn!(
                    target: "nrr::conn-trace",
                    "ETW connection observer unavailable (merged mode) — continuing with WFP only: {e}",
                ),
            }
            match start_wfp() {
                Ok(s) => live.push(s),
                Err(e) => tracing::warn!(
                    target: "nrr::conn-trace",
                    "WFP connection observer unavailable (merged mode) — continuing with ETW only: {e}",
                ),
            }
            if live.len() >= 2 {
                Ok(Arc::new(
                    nrr_platform_windows::conn_observe::MergedConnectionObservationSource::new(
                        live,
                    ),
                ) as DynSource)
            } else {
                live.into_iter()
                    .next()
                    .ok_or(nrr_platform_windows::PlatformError::Transient {
                        operation: "conn-trace start (both backends)",
                        detail: "neither the ETW nor the WFP connection observer could start"
                            .to_string(),
                    })
            }
        }
    };
    match started {
        Ok(source) => {
            tracing::info!(
                target: "nrr::conn-trace",
                backend = backend.slug(),
                "connection trace enabled",
            );
            // Only now is the ring actually being fed: the panel may say so.
            if let Some(ring) = trace_ring_flag {
                ring.mark_observer_active();
            }
            (Some(source), Some(consumer))
        }
        Err(e) => {
            tracing::warn!(
                target: "nrr::conn-trace",
                backend = backend.slug(),
                "connection observer unavailable; connection trace disabled: {e}",
            );
            (None, None)
        }
    }
}

/// Which connection-observation backend(s) to start. `Both` (the default)
/// runs ETW + WFP merged: ETW captures every TCP connect, WFP adds the
/// allow/block verdict. `Wfp` / `Etw` force a single backend for diagnostics.
#[derive(Clone, Copy)]
enum ConnTraceBackend {
    Wfp,
    Etw,
    Both,
}

impl ConnTraceBackend {
    fn slug(self) -> &'static str {
        match self {
            ConnTraceBackend::Wfp => "wfp",
            ConnTraceBackend::Etw => "etw",
            ConnTraceBackend::Both => "both",
        }
    }
}

/// Select the backend. `NRR_CONN_TRACE=wfp|etw|both` forces a choice; the
/// `conn-trace-etw.enabled` sentinel forces ETW-only (back-compat). Otherwise
/// the default is BOTH (merged): WFP alone produces a near-empty trace
/// because it rarely emits CLASSIFY_ALLOW without a permit observe-filter,
/// which is deliberately omitted.
fn conn_trace_backend() -> ConnTraceBackend {
    if let Ok(v) = std::env::var("NRR_CONN_TRACE") {
        if v.eq_ignore_ascii_case("etw") {
            return ConnTraceBackend::Etw;
        }
        if v.eq_ignore_ascii_case("wfp") {
            return ConnTraceBackend::Wfp;
        }
        if v.eq_ignore_ascii_case("both") {
            return ConnTraceBackend::Both;
        }
    }
    if let Some(program_data) = std::env::var_os("ProgramData") {
        if PathBuf::from(program_data)
            .join("NetRuleRouter")
            .join("conn-trace-etw.enabled")
            .exists()
        {
            return ConnTraceBackend::Etw;
        }
    }
    ConnTraceBackend::Both
}

/// Opens the FQDN/IP cache database and wraps it in an
/// `Arc<Mutex<dyn CacheRepository + Send>>` so multiple consumers can
/// share one connection serialised behind the mutex: the per-SID
/// orchestrator's [`SqliteFqdnCacheLookup`], the DNS refresh task, and
/// any future cache lookup port the engine consumes. `None` is returned
/// if migrations fail or the file cannot be opened — callers degrade to
/// a noop cache lookup + disable the DNS refresh task.
/// Build the `RoutePolicyApplyTrigger` wired to a
/// policy change. The base trigger recompiles the SID's WFP filters; when
/// a route coordinator is present it is wrapped so the same change also
/// recomputes the active user's system route table.
fn build_apply_trigger(
    orch: &Arc<PerSidApplyOrchestrator>,
    sid_registry: &Arc<ActiveSidRegistry>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    pause_coordinator: Option<&Arc<nrr_service_runtime::routing_pause::RoutingPauseCoordinator>>,
) -> Arc<dyn nrr_service_runtime::ipc_handlers::providers::RoutePolicyApplyTrigger> {
    let mut orchestrator_trigger =
        OrchestratorRoutePolicyApplyTrigger::new(Arc::clone(orch), Arc::clone(sid_registry));
    // A policy update from a GUI-only connection
    // (dead tray subscription) must still recompile for the console user.
    if let Some(coord) = route_coordinator {
        let coord = Arc::clone(coord);
        orchestrator_trigger = orchestrator_trigger
            .with_fallback_routing_sid(Arc::new(move || coord.effective_routing_sid(&[])));
    }
    // A policy edit by a routing-PAUSED user
    // must not reinstall their filters. Fail-CLOSED to paused on a pause-state
    // read error (skip the recompile) so a transient DB error never re-arms a
    // paused user's block-all.
    if let Some(pause) = pause_coordinator {
        let pause = Arc::clone(pause);
        orchestrator_trigger =
            orchestrator_trigger.with_paused_check(Arc::new(move |sid: &str| {
                match pause.paused_sids() {
                    Ok(paused) => paused.iter().any(|s| s == sid),
                    Err(_) => true,
                }
            }));
    }
    let base: Arc<dyn nrr_service_runtime::ipc_handlers::providers::RoutePolicyApplyTrigger> =
        Arc::new(orchestrator_trigger);
    match route_coordinator {
        Some(coord) => Arc::new(
            nrr_service_runtime::route_coordinator::RouteAndFilterApplyTrigger::new(
                base,
                Arc::clone(coord),
                Arc::clone(sid_registry),
            ),
        ),
        None => base,
    }
}

fn open_cache_store(
    path: &std::path::Path,
    cache_refresh_secs: u32,
) -> Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>> {
    use nrr_domain::decision_lookup::{clamp_cache_refresh_secs, FreshnessThresholds};
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::store::SqliteCacheStore;

    let conn = match nrr_storage::migration::open_connection(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "failed to open FQDN cache connection; FQDN lookups + DNS refresh disabled",
            );
            return None;
        }
    };
    // Rebuildable cache DB — WAL for reader/writer concurrency (the leak-guard
    // reads while the DNS-refresh task writes), `synchronous = NORMAL` because a
    // corrupt cache is deleted + rebuilt anyway, so full fsync durability is
    // wasted overhead. Best-effort; on failure the connection keeps its defaults.
    let _: rusqlite::Result<()> = conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;",
    );
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    if let Err(e) = runner.run_pending_migrations() {
        tracing::warn!(
            target: "nrr::runtime",
            error = %e,
            path = %path.display(),
            "FQDN cache migration failed; FQDN lookups + DNS refresh disabled",
        );
        return None;
    }
    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds {
            // The user-configured refresh interval is the cadence FLOOR.
            fallback_ttl_secs: clamp_cache_refresh_secs(cache_refresh_secs),
            ..FreshnessThresholds::default_production()
        },
    );
    // Fake-pool addresses are virtual; any cached as "real" resolutions (or
    // census rows) corrupt the routing model — sweep them on every open. The
    // ingestion paths filter the pool too, so this only ever removes rows
    // written by older builds. Best-effort: a failed sweep degrades heuristics,
    // not correctness.
    {
        use nrr_storage::repository::CacheRepository;
        let (lo, hi) = nrr_platform_api::fake_ip::FakeIpPoolConfig::default().v4_range();
        match store.purge_ip_range_v4(lo, hi) {
            Ok(0) => {}
            Ok(removed) => tracing::info!(
                target: "nrr::fake-ip",
                removed,
                "purged fake-pool addresses from the FQDN cache at open",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::fake-ip",
                error = %e,
                "fake-pool FQDN-cache sweep failed at open",
            ),
        }
    }
    Some(Arc::new(Mutex::new(store))
        as Arc<
            Mutex<dyn nrr_storage::repository::CacheRepository + Send>,
        >)
}

/// Open the rebuildable `nrr_traffic_stats.db` and
/// build the [`TrafficSampler`] over the Windows octet-counter source, wrapped
/// in `Arc<Mutex<…>>` so the IPC provider (reads) and the sampling tick (writes)
/// share the one connection. `None` on any error — the traffic-stats IPC ops
/// then resolve to `UnimplementedHandler` and the GUI hides the surface.
fn open_traffic_sampler(
    path: &std::path::Path,
) -> Option<Arc<Mutex<nrr_service_runtime::traffic_sampler::TrafficSampler>>> {
    use nrr_platform_windows::interface_traffic::WindowsInterfaceCounterSource;
    use nrr_service_runtime::traffic_sampler::TrafficSampler;
    use nrr_storage::SqliteTrafficStore;

    // Rebuildable ledger — a corrupt open (structural damage, stale migration
    // checksum) deletes the DB with its WAL sidecars and recreates it once
    // inside the storage helper. A DB from a newer build is refused instead of
    // rebuilt, so a downgrade keeps the ledger and only loses the counter.
    let opened = match nrr_storage::open_traffic_connection_or_rebuild(path) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "traffic-stats DB migration failed; traffic counter disabled",
            );
            return None;
        }
    };
    if let Some(reason) = &opened.rebuilt_reason {
        tracing::info!(
            target: "nrr::runtime",
            path = %path.display(),
            reason = %reason,
            "traffic-stats DB was deleted and recreated after an open/migration failure",
        );
    }
    let store = SqliteTrafficStore::new(opened.connection);
    let source = Arc::new(WindowsInterfaceCounterSource::new())
        as Arc<dyn nrr_platform_api::InterfaceCounterSource>;
    match TrafficSampler::new(source, store) {
        Ok(sampler) => Some(Arc::new(Mutex::new(sampler))),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "failed to prime traffic sampler; traffic counter disabled",
            );
            None
        }
    }
}

/// Opens a separate connection to the state DB for settings providers.
/// `None` is returned on failure; callers must skip the partial-handler
/// registration in that case (the bootstrap path will already have
/// surfaced the failure as a Blocking phase).
fn open_settings_connection(path: &std::path::Path) -> Option<Arc<Mutex<Connection>>> {
    if !path.exists() {
        return None;
    }
    // The storage factory applies (and VERIFIES) the same baseline this used to
    // set by hand and discard the result of: a failed pragma left the
    // connection with no busy timeout and nobody the wiser.
    match nrr_storage::migration::open_connection(path) {
        Ok(conn) => Some(Arc::new(Mutex::new(conn))),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "failed to open settings connection; settings IPC ops will be unavailable",
            );
            None
        }
    }
}

/// Run the DB-MAC tamper bootstrap over the
/// state DB and return the row-MAC signing key (loaded or freshly
/// generated). On failure, returns `None` so the coordinator runs
/// unsigned (routing is unaffected). Alerts raised here land in the
/// same `security_alerts` table the IPC handlers read, so the GUI
/// surfaces them and the mutation gate engages until acknowledged.
///
/// This whole module is `#![cfg(target_os = "windows")]`, so the DPAPI
/// key store is always available here.
fn run_db_mac_tamper_bootstrap(conn: &Arc<Mutex<Connection>>) -> Option<Vec<u8>> {
    use nrr_platform_windows::key_store::WindowsDpapiKeyStore;
    let key_store = WindowsDpapiKeyStore::default_systemprofile();
    let alerts_repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    match run_tamper_bootstrap(conn, &key_store, &alerts_repo, now_ms) {
        Ok(outcome) => {
            if outcome.raised_blocking_alert {
                tracing::warn!(
                    target: "nrr::tamper",
                    tampered = outcome.tampered_revision_ids.len(),
                    key_reset = outcome.key_was_reset,
                    backfilled = outcome.backfilled_rows,
                    "DB-MAC tamper bootstrap raised blocking alert(s); \
                     mutations gated until acknowledged",
                );
            } else {
                tracing::info!(
                    target: "nrr::tamper",
                    backfilled = outcome.backfilled_rows,
                    "DB-MAC tamper bootstrap clean",
                );
            }
            Some(outcome.signing_key)
        }
        Err(e) => {
            tracing::error!(
                target: "nrr::tamper",
                error = %e,
                "DB-MAC tamper bootstrap failed; coordinator will run unsigned",
            );
            None
        }
    }
}

/// Runs [`ActivationCoordinator::enforce_active_integrity_all`] and, for
/// every principal it rolled back or cleared, raises a (non-blocking)
/// `security_alerts` row so the GUI surfaces it — same dedup mechanism
/// as [`run_db_mac_tamper_bootstrap`]'s alerts, reused via
/// `tamper_bootstrap::emit_alert`. Best effort: a sweep failure is
/// logged and does not block startup, matching the tamper bootstrap's
/// own failure posture.
fn run_active_integrity_enforcement(
    coordinator: &ActivationCoordinator,
    conn: &Arc<Mutex<Connection>>,
) {
    use nrr_service_runtime::activation_coordinator::ActiveIntegrityOutcome;
    use nrr_service_runtime::tamper_bootstrap::emit_alert;

    let outcomes = match coordinator.enforce_active_integrity_all("svc-boot-integrity-scan") {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                target: "nrr::tamper",
                error = ?e,
                "active-revision integrity sweep failed",
            );
            return;
        }
    };
    let rejected: Vec<_> = outcomes
        .into_iter()
        .filter(|(_, outcome)| {
            matches!(
                outcome,
                ActiveIntegrityOutcome::RolledBack { .. }
                    | ActiveIntegrityOutcome::ClearedNoTrustedFallback { .. }
            )
        })
        .collect();
    if rejected.is_empty() {
        return;
    }
    let alerts_repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    for (principal, outcome) in rejected {
        let rejected_revision_id = match &outcome {
            ActiveIntegrityOutcome::RolledBack {
                rejected_revision_id,
                ..
            }
            | ActiveIntegrityOutcome::ClearedNoTrustedFallback {
                rejected_revision_id,
                ..
            } => rejected_revision_id.clone(),
            _ => continue,
        };
        tracing::warn!(
            target: "nrr::tamper",
            principal = %principal,
            rejected_revision_id = %rejected_revision_id,
            outcome = ?outcome,
            "active revision failed the integrity gate; rolled back to last trusted revision",
        );
        if let Err(e) = emit_alert(
            &alerts_repo,
            format!("alt-revintegrity-{rejected_revision_id}"),
            nrr_diagnostics::audit::AuditEventKind::UntrustedRevisionRejected.as_str(),
            nrr_diagnostics::reason::integrity::UNTRUSTED_REVISION_REJECTED.as_str(),
            now_ms,
        ) {
            tracing::error!(
                target: "nrr::tamper",
                error = ?e,
                rejected_revision_id = %rejected_revision_id,
                "failed to raise untrusted-revision-rejected alert",
            );
        }
    }
}

/// Reads the persisted `service_stability_config` row
/// and converts it into the runtime-side `ServiceStabilityConfig` the
/// supervisor consumes. Returns `None` on any error so the caller can
/// fall back to `ServiceStabilityConfig::default()` (canonical
/// recoverable / 20 / 100ms / 5s — same as the GUI's default state).
///
/// The lock-acquire failure path uses `_ = ...` rather than `?` because
/// poisoning is non-fatal: a poisoned mutex around the settings
/// connection means another thread panicked mid-op; we still want the
/// supervisor to start with defaults rather than refuse to boot.
/// Read the persisted operational-log + audit
/// retention config so the cleanup tasks enforce the operator's saved caps.
/// `None` on lock/read failure → the caller falls back to documented defaults.
fn read_log_retention_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<nrr_storage::LogRetentionConfig> {
    let guard = conn.lock().ok()?;
    let repo = nrr_storage::LogRetentionConfigRepository::new(&guard);
    match repo.get_or_default() {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "log_retention_config read failed; using retention defaults",
            );
            None
        }
    }
}

fn read_service_stability_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<nrr_service_runtime::service_stability::ServiceStabilityConfig> {
    use nrr_service_runtime::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};
    use nrr_storage::service_stability_config::{
        IpcAcceptPolicyRecord, ServiceStabilityConfigRepository,
    };
    use std::time::Duration;

    let guard = conn.lock().ok()?;
    let repo = ServiceStabilityConfigRepository::new(&guard);
    let record = match repo.get_or_default() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "service_stability_config read failed; using runtime defaults",
            );
            return None;
        }
    };
    let policy = match record.ipc_accept_policy {
        IpcAcceptPolicyRecord::Critical => {
            tracing::info!(
                target: "nrr::stability",
                kind = "critical",
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Critical
        }
        IpcAcceptPolicyRecord::Recoverable {
            max_restarts,
            backoff_base_ms,
            backoff_cap_ms,
        } => {
            // Emit the loaded numbers so an operator who saves new
            // values in GUI Settings → Service stability can verify
            // via NDJSON that the supervisor picked them up after
            // restart. Without this, the only signal would be timing
            // between `task_failed` events — useless when IPC is
            // healthy.
            tracing::info!(
                target: "nrr::stability",
                kind = "recoverable",
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Recoverable {
                max_restarts,
                backoff_base: Duration::from_millis(u64::from(backoff_base_ms)),
                backoff_cap: Duration::from_millis(u64::from(backoff_cap_ms)),
            }
        }
    };
    Some(ServiceStabilityConfig {
        ipc_accept_policy: policy,
    })
}

/// Read the persisted `enforcement_mode` from
/// `service_stability_config`. Defaults to Reactive on any lock/read error or a
/// missing row (same fail-safe posture as `read_service_stability_config`). The
/// runtime `ServiceStabilityConfig` intentionally does not carry this field, so
/// it is read straight off the storage record here.
fn read_enforcement_mode(
    conn: &Arc<Mutex<Connection>>,
) -> nrr_domain::enforcement_mode::EnforcementMode {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return nrr_domain::enforcement_mode::EnforcementMode::default();
    };
    let repo = ServiceStabilityConfigRepository::new(&guard);
    repo.get_or_default()
        .map(|record| record.enforcement_mode)
        .unwrap_or_default()
}

/// The ONE place the production fake-IP policy values come from: the scope
/// (broad coverage, no user host-exclusions yet) and the pool geometry. Shared
/// by the assembly (DNS answerer + relay) and the per-SID WFP context provider,
/// so the two sides can never disagree about what is fake-routed.
fn fake_ip_policy() -> (
    nrr_platform_api::fake_ip::FakeIpScope,
    nrr_platform_api::fake_ip::FakeIpPoolConfig,
) {
    (
        nrr_platform_api::fake_ip::FakeIpScope::enabled(Vec::<String>::new()),
        nrr_platform_api::fake_ip::FakeIpPoolConfig::default(),
    )
}

/// The persisted machine-wide fake-IP toggle, read at boot
/// to reconcile the stack (mirrors [`read_enforcement_mode`]). Defaults to
/// `false` on any lock/read failure — the safe direction (feature off).
fn read_fake_ip_enabled(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_enabled)
        .unwrap_or(false)
}

/// The persisted DNS-over-secondary toggle, read at boot to seed the shared
/// live flag (mirrors [`read_fake_ip_enabled`]). Defaults to `false` on any
/// lock/read failure — the safe direction (feature off).
fn read_dns_via_secondary(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.dns_via_secondary)
        .unwrap_or(false)
}

/// The persisted fast-DNS-answers toggle, read at boot to seed the shared live
/// flag (mirrors [`read_dns_via_secondary`]). Defaults to `true` on any
/// lock/read failure — answering immediately is the safe direction (the hold
/// is the measured page-stall, not the protection).
fn read_dns_fast_answers(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return true;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.dns_fast_answers)
        .unwrap_or(true)
}

/// The persisted fake-IP UDP relay toggle, read at boot to seed the shared
/// live flag (mirrors [`read_dns_fast_answers`]). Defaults to `false` on any
/// lock/read failure — hard-blocking UDP into the pool is the safe direction
/// (today's "QUIC falls back to TCP" behaviour).
fn read_fake_ip_udp_relay(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_udp_relay)
        .unwrap_or(false)
}

/// The persisted fake-IP instant-reset toggle, read at boot to seed the
/// shared live flag (mirrors [`read_fake_ip_udp_relay`]). Defaults to `true`
/// on any lock/read failure — instant reset is today's behaviour and the
/// safe direction (never silently starts holding client connections).
fn read_fake_ip_instant_rst(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return true;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.fake_ip_instant_rst)
        .unwrap_or(true)
}

/// The persisted ISP block-page rule-candidates toggle, read at boot to seed
/// the shared live flag (mirrors [`read_fake_ip_instant_rst`]). Defaults to
/// `false` on any lock/read failure — the safe direction (feature off).
fn read_isp_block_candidates_enabled(conn: &Arc<Mutex<Connection>>) -> bool {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return false;
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.isp_block_candidates_enabled)
        .unwrap_or(false)
}

/// Build the resolver FACTORY (Mode B live re-arm): a
/// closure the [`DnsResolverController`] calls on each start to (re)construct a
/// `DnsResolverService`, re-capturing the CURRENT upstream DNS so a runtime start
/// after a network change is correct. `None` if any required input (settings
/// conn, FQDN cache, routing-SID fn, reconcile hook) is missing — the controller
/// then can never arm and stays reactive (fail-safe). The enforcement-mode gate
/// lives in the controller, NOT here: the factory always tries to build when
/// asked, and the controller only asks when the mode is `Resolver`.
///
/// [`DnsResolverController`]: nrr_service_runtime::dns_resolver_service::DnsResolverController
#[allow(clippy::too_many_arguments)]
fn build_dns_resolver_factory(
    settings_conn: Option<&Arc<Mutex<Connection>>>,
    cache_store: Option<&Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    route_recompute_hook: Option<&nrr_service_runtime::supervised_runtime::RouteRecomputeHook>,
    // Both optional: absent (WFP unavailable) leaves the direct-answer
    // gate off, everything else about Mode B unchanged.
    known_direct: Option<&Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    block_all_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    // "Is the guard blocking an unresolved additional link?" — wider than
    // `block_all_armed`, which the default per-IP posture leaves disarmed.
    // Absent keeps the historic fail-open on a missed reconcile deadline.
    fail_closed_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    // The shared fake-IP assembly + the "stack running?"
    // gate. Both absent leaves Mode B exactly as before fake-IP.
    fake_assembly: Option<Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>>,
    fake_ip_running: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    // "Can the relay actually carry a scope host right now?" Absent leaves the
    // scope answerer gated on the stack alone, as before.
    fake_ip_secondary_ready: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    // DNS-over-secondary policy. `None` (no route coordinator) leaves every
    // query on the captured primary upstream, exactly as before.
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
    // Parked companion suggestions. Absent leaves the collateral rescue
    // unvetoed, exactly as before the port existed.
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    // "Is anyone signed in?" Absent leaves the arm ungated (test profiles).
    signed_in: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
) -> Option<nrr_service_runtime::dns_resolver_service::DnsResolverFactory> {
    let settings_conn = Arc::clone(settings_conn?);
    let cache = Arc::clone(cache_store?);
    let active_sid = Arc::clone(active_routing_sid?);
    let hook = route_recompute_hook?.clone();
    let known_direct = known_direct.map(Arc::clone);
    let factory: nrr_service_runtime::dns_resolver_service::DnsResolverFactory =
        Arc::new(move || {
            build_dns_resolver_instance(
                &settings_conn,
                &cache,
                &active_sid,
                &hook,
                known_direct.as_ref(),
                block_all_armed.clone(),
                fail_closed_armed.clone(),
                fake_assembly.as_ref(),
                fake_ip_running.clone(),
                fake_ip_secondary_ready.clone(),
                egress.clone(),
                auto_rules.clone(),
                signed_in.as_ref(),
            )
        });
    Some(factory)
}

/// The Wintun-backed stack factory the
/// [`FakeIpController`] calls to (re)build the TUN + relay on each start.
///
/// It shares `assembly`'s allocator with the DNS answerer (so a fake address
/// resolves back to the hostname that was handed it) and reads real upstream
/// addresses / routes from the SAME FQDN cache + rule book the WFP path uses —
/// no second copy of that policy to drift. Returns `None` if a required input is
/// missing. The closure itself returns `None` when the Wintun driver is
/// unavailable or the adapter fails to open, so an absent/failed driver leaves
/// the feature off (fail-open) rather than erroring.
///
/// [`FakeIpController`]: nrr_service_runtime::fake_ip::FakeIpController
/// Live source-address policy for the fake-IP relay dialer, backed by the SAME
/// route resolution the enforcement layer uses. The relay runs as SYSTEM and is
/// outside the per-user kill-switch scope, so an unbound dial follows the OS
/// default route wherever it points; binding to the role's adapter address (or
/// refusing when the secondary is unresolved) keeps a relayed flow on the link
/// its policy chose. Resolution is cached briefly — it enumerates adapters and
/// logs its findings, and every new flow dials.
struct CoordinatorRelaySourceAddrs {
    coordinator: Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
    cache: RelaySourceAddrCache,
}

type ResolvedSourceIps = (Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>);
type RelaySourceAddrCache = Mutex<Option<(std::time::Instant, ResolvedSourceIps)>>;

/// How long one adapter-source resolution serves relay dials before a fresh
/// look at the live adapters. Short enough to track a VPN reconnect promptly,
/// long enough that a burst of new flows costs one resolution.
const RELAY_SOURCE_ADDR_TTL: std::time::Duration = std::time::Duration::from_secs(3);

impl CoordinatorRelaySourceAddrs {
    fn current(&self) -> ResolvedSourceIps {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((resolved_at, ips)) = cache.as_ref() {
            if resolved_at.elapsed() < RELAY_SOURCE_ADDR_TTL {
                return *ips;
            }
        }
        let ips = match (self.active_sid)() {
            Some(sid) => self.coordinator.resolve_egress_source_ips(&sid),
            None => (None, None),
        };
        *cache = Some((std::time::Instant::now(), ips));
        ips
    }
}

/// The same 3 s-memoized adapter resolution the relay dialer uses, reused as
/// the DNS-over-secondary source: the query sockets and the relay must agree on
/// what "the secondary link right now" means, and a second resolver would
/// double the adapter enumeration for no benefit.
impl nrr_service_runtime::dns_egress::SecondarySourceAddr for CoordinatorRelaySourceAddrs {
    fn current(&self) -> Option<std::net::Ipv4Addr> {
        CoordinatorRelaySourceAddrs::current(self).1
    }
}

/// Build the live DNS-egress policy: public resolvers over the secondary link
/// while the toggle is on and the tunnel has a source address, the caller's own
/// captured upstream otherwise. Reads the SAME process flag the route
/// coordinator uses to install the resolver `/32` routes.
fn build_dns_egress_policy(
    coordinator: &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
) -> Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy> {
    let source = Arc::new(CoordinatorRelaySourceAddrs {
        coordinator: Arc::clone(coordinator),
        active_sid,
        cache: Mutex::new(None),
    });
    Arc::new(
        nrr_service_runtime::dns_egress::SecondaryPreferredEgress::new(
            nrr_service_runtime::dns_egress::global_dns_via_secondary(),
            source,
        ),
    )
}

impl nrr_service_runtime::fake_ip::RelaySourceAddrs for CoordinatorRelaySourceAddrs {
    fn decide(
        &self,
        route: nrr_shared::RouteRole,
        remote: &std::net::SocketAddr,
    ) -> nrr_service_runtime::fake_ip::SourceBindDecision {
        use nrr_service_runtime::fake_ip::SourceBindDecision;
        use nrr_shared::RouteRole;
        // Route resolution is IPv4-only today. An IPv6 dial cannot be steered:
        // the primary may ride the default route (that IS the primary's
        // semantics), the secondary must not silently do so.
        if !remote.is_ipv4() {
            return match route {
                RouteRole::Primary => SourceBindDecision::Unbound,
                RouteRole::Secondary => SourceBindDecision::Refuse {
                    reason: "secondary source binding is IPv4-only; an IPv6 dial cannot be steered",
                },
            };
        }
        let (primary, secondary) = self.current();
        match route {
            RouteRole::Primary => primary.map_or(SourceBindDecision::Unbound, |ip| {
                SourceBindDecision::Bind(ip.into())
            }),
            RouteRole::Secondary => secondary.map_or(
                SourceBindDecision::Refuse {
                    reason:
                        "secondary adapter unresolved — dialing would leak via the primary link",
                },
                |ip| SourceBindDecision::Bind(ip.into()),
            ),
        }
    }
}

fn build_fake_ip_stack_factory(
    assembly: Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>,
    cache_store: Option<&Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    settings_conn: Option<&Arc<Mutex<Connection>>>,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    auto_rules_engine: Option<&Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
) -> Option<nrr_service_runtime::fake_ip::FakeIpStackFactory> {
    use nrr_platform_api::fake_ip::tun::{TunAdapterConfig, TunAdapterPort};
    use nrr_platform_windows::fake_ip::WintunTunAdapter;
    use nrr_service_runtime::fake_ip::{
        CacheUpstreamResolver, RuleBookRouteSelector, StackWaker, SystemRelayDialer,
    };

    let cache = Arc::clone(cache_store?);
    let settings_conn = Arc::clone(settings_conn?);
    let active_sid = Arc::clone(active_routing_sid?);
    let route_coordinator = route_coordinator.map(Arc::clone);
    let auto_rules_engine = auto_rules_engine.map(Arc::clone);
    let factory: nrr_service_runtime::fake_ip::FakeIpStackFactory = Arc::new(move || {
        let adapter = WintunTunAdapter::new();
        if !adapter.is_available() {
            tracing::warn!(
                target: "nrr::fake-ip",
                "fake-IP requested but the Wintun driver is unavailable; feature stays off (fail-open)",
            );
            return None;
        }
        // The config is derived from the SAME pool the assembly uses
        // (`TunAdapterConfig::for_pool`), so the adapter's address range can
        // never disagree with the fake addresses the answerer hands out.
        let config = TunAdapterConfig::default();
        let device = match adapter.open(&config) {
            Ok(device) => device,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::fake-ip",
                    error = %e,
                    "fake-IP: TUN adapter open failed; feature stays off (fail-open)",
                );
                return None;
            }
        };
        // Upstream = the direct-host session map layered over the FQDN
        // cache: one resolver serves both rule-host and direct-host flows.
        let cache_lookup = Arc::new(
            nrr_service_runtime::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
                Arc::clone(&cache),
                nrr_domain::decision_lookup::FreshnessThresholds::default_production(),
            ),
        );
        let upstream = Arc::new(
            assembly.direct_aware_resolver(Arc::new(CacheUpstreamResolver::new(cache_lookup))),
        );
        let routes = Arc::new(RuleBookRouteSelector::new(
            Arc::new(ProductionRulesProvider::new(Arc::clone(&settings_conn))),
            Arc::clone(&active_sid),
        ));
        // Source-bound dialing: without it the SYSTEM relay follows the OS
        // default route (it sits outside the per-user kill-switch scope), so a
        // secondary-bound flow would leak via the primary whenever the tunnel
        // is down. No coordinator → dials stay unbound, which is only sound
        // while no secondary policy exists at all.
        let mut dialer = SystemRelayDialer::new();
        match route_coordinator.as_ref() {
            Some(coordinator) => {
                dialer = dialer.with_source_addrs(Arc::new(CoordinatorRelaySourceAddrs {
                    coordinator: Arc::clone(coordinator),
                    active_sid: Arc::clone(&active_sid),
                    cache: Mutex::new(None),
                }));
            }
            None => {
                tracing::warn!(
                    target: "nrr::fake-ip",
                    "no route coordinator — relay dials are unbound (OS default route decides the egress link)",
                );
            }
        }
        // Dial-time resolution: a rule host whose address nothing has learned
        // yet (a filtering provider answered its DNS with a placeholder, so
        // nothing was cached) used to cost the user a reset. The name is the
        // durable fact, so the dial thread — where a lookup is affordable —
        // finds the address through the same confirmed resolver the rest of the
        // service uses, and writes it to the cache the routes read from.
        let names = Arc::new(nrr_service_runtime::fake_ip::ConfirmedNameResolver::new(
            build_hosts_bypass_resolver(
                Some(Arc::clone(&settings_conn)),
                Some(Arc::clone(&active_sid)),
                route_coordinator
                    .as_ref()
                    .map(|coord| build_dns_egress_policy(coord, Arc::clone(&active_sid))),
            ),
            Arc::clone(&cache),
        ));
        let dialer = Arc::new(dialer.with_name_resolver(names));
        // VPN self-heal: notice a VPN client reaching its own server through the
        // relay (an extra hop that hides its real remote), exclude that server
        // from fake-IP, and flush DNS so the client reconnects directly. The
        // owner lookup reads the OS connection table; the exclusion set is the
        // assembly's own, so both answerers honour it.
        // Persist each newly learned exclusion so the NEXT service session
        // pre-seeds it and the VPN's first connect goes direct instead of
        // paying one failed relay round to re-learn it.
        let heal_persist: nrr_service_runtime::fake_ip::HealPersistFn = {
            let conn = Arc::clone(&settings_conn);
            Arc::new(move |hostname: &str| {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                if let Err(e) =
                    nrr_storage::fake_ip_heal_exclusions::FakeIpHealExclusionsRepository::new(
                        &guard,
                    )
                    .upsert(hostname, now)
                {
                    tracing::warn!(
                        target: "nrr::fake-ip",
                        error = %e,
                        "failed to persist a VPN self-heal exclusion — it will be re-learned next session",
                    );
                }
            })
        };
        let self_heal = Arc::new(nrr_service_runtime::fake_ip::VpnSelfHealObserver::new(
            Arc::new(nrr_platform_windows::flow_owner::WindowsFlowOwnerLookup::new()),
            // A client the user confirmed heals even when its file name carries
            // no VPN keyword; the keyword heuristic stays the fallback.
            nrr_service_runtime::vpn_client_registry::global_confirmed_vpn_clients(),
            assembly.runtime_exclusions(),
            Arc::new(|| {
                use nrr_platform_api::DnsCacheControlPort;
                match nrr_platform_windows::WindowsDnsCacheControl::new().flush_resolver_cache() {
                    Ok(()) => tracing::info!(
                        target: "nrr::fake-ip",
                        "flushed OS DNS resolver cache after a VPN self-heal exclusion",
                    ),
                    Err(e) => tracing::warn!(
                        target: "nrr::fake-ip",
                        error = ?e,
                        "DNS flush after a VPN self-heal exclusion failed — the client reconnects on its own TTL",
                    ),
                }
            }),
            Some(heal_persist),
        ));
        let flow_observer: Arc<dyn nrr_service_runtime::fake_ip::FlowObserver> =
            match auto_rules_engine.as_ref() {
                Some(engine) => Arc::new(nrr_service_runtime::fake_ip::CompositeFlowObserver::new(
                    vec![
                        self_heal,
                        Arc::new(nrr_service_runtime::fake_ip::FlowActivityObserver::new(
                            Arc::clone(engine),
                            Arc::clone(&active_sid),
                        )),
                    ],
                )),
                None => self_heal,
            };
        tracing::info!(
            target: "nrr::fake-ip",
            "fake-IP TUN adapter is open with the pool route in place — bringing the userspace stack up",
        );
        Some(
            assembly
                .build_stack(device, dialer, upstream, routes, StackWaker::new())
                .with_dial_time_resolution(true)
                // Two things care about a relayed flow: self-heal (is this a
                // VPN client reaching its own server?) and companion discovery
                // (the user is ON this site right now — a fact DNS cannot
                // deliver when the browser answers from its own cache).
                .with_flow_observer(flow_observer)
                // Fake-IP instant reset — the same process-wide flag
                // `ProductionServiceStability::set` flips live, so a rebuilt
                // stack (watchdog rebuild, restart after a toggle) always
                // starts on the CURRENT persisted value instead of the
                // constructor default.
                .with_instant_rst(nrr_service_runtime::fake_ip::global_instant_rst_enabled()),
        )
    });
    Some(factory)
}

/// Build the rule-host resolver used by the seeder and the DNS
/// refresh: the system port decorated with the hosts-bypass direct-UDP path
/// (`HostsBypassDnsResolver`). While the active routing user's
/// `resolve_hosts_bypass` posture is ON (the default), rule hosts resolve
/// straight against the captured upstream server over a raw socket — so a
/// hosts/adblock `127.0.0.1` pin can no
/// longer starve a rule of its routable public IP. The upstream comes from the
/// shared pool, so this path retires a dead resolver on the same evidence as
/// the others. Missing settings DB / no active user read as the DEFAULT posture
/// (bypass ON).
fn build_hosts_bypass_resolver(
    settings_conn: Option<Arc<Mutex<Connection>>>,
    active_sid: Option<nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
) -> Arc<dyn nrr_platform_windows::dns::DnsResolverPort> {
    use std::time::Duration;

    let bypass_enabled: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
        let (Some(conn), Some(active_sid)) = (settings_conn.as_ref(), active_sid.as_ref()) else {
            return true;
        };
        let Some(sid) = active_sid() else {
            return true;
        };
        let Ok(guard) = conn.lock() else {
            return true;
        };
        nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
            .load_for_sid(&sid)
            .map(|record| record.resolve_hosts_bypass)
            .unwrap_or(true)
    });
    let pool = upstream_dns_pool();
    let upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync> =
        Arc::new(move || pool.current().or_else(|| pool.note_network_change()));
    let mut resolver = nrr_service_runtime::dns_resolver_ports::HostsBypassDnsResolver::new(
        Arc::new(WindowsDnsResolver::new()),
        bypass_enabled,
        upstream,
        Duration::from_millis(1500),
    );
    if let Some(policy) = egress.clone() {
        resolver = resolver.with_egress(policy);
    }
    // Same second-source confirmation the intercept path uses. These two
    // callers fill the FQDN cache the relay dials from, so a placeholder taken
    // at face value here is a rule that quietly points at nowhere — and the
    // hosts-bypass path cannot spot one, because a provider answering for names
    // it filters answers a raw socket just as readily.
    let mut confirmed =
        nrr_service_runtime::dns_resolver_ports::PoisonFallbackUpstreamResolver::new(Arc::new(
            nrr_service_runtime::dns_resolver_ports::PortUpstreamResolver::new(Arc::new(resolver)),
        ))
        .with_recent_addresses(
            nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses(),
        );
    if let Some(policy) = egress {
        confirmed = confirmed.with_egress(policy);
    }
    Arc::new(
        nrr_service_runtime::dns_resolver_ports::UpstreamResolverPort::new(Arc::new(confirmed)),
    )
}

/// Build ONE resolver instance: capture the CURRENT upstream DNS (BEFORE any
/// redirect) and wire the listener + NRPT redirect. `None` if no upstream IPv4
/// DNS can be captured — refuse to arm rather than redirect the OS to a resolver
/// that would black-hole general DNS. Called by the controller on every start.
#[allow(clippy::too_many_arguments)]
/// Adapts the auto-rules engine to the resolver's companion-candidate port.
struct PendingCompanionCandidates(Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>);

impl nrr_service_runtime::dns_resolver::CompanionCandidateLookup for PendingCompanionCandidates {
    fn is_pending_secondary_companion(&self, hostname: &str) -> bool {
        self.0.covers_pending_secondary_host(hostname)
    }
}

/// Reports a collateral host to the engine under its own name.
struct RescuedCompanions {
    engine: Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
}

impl nrr_service_runtime::dns_resolver::CompanionRescueObserver for RescuedCompanions {
    fn note_rescued_companion(&self, hostname: &str) {
        let Some(sid) = (self.active_sid)() else {
            return;
        };
        self.engine
            .note_candidate_in_use(&sid, hostname, std::time::SystemTime::now());
    }
}

/// The process-wide upstream-DNS choice.
///
/// One pool, not one per resolver instance: it must outlive resolver restarts
/// (a mode toggle rebuilds the resolver) and it is what the adapter hook pokes
/// on a network change, long before any resolver exists.
fn upstream_dns_pool() -> Arc<nrr_service_runtime::dns_upstream::UpstreamDnsPool> {
    use nrr_service_runtime::dns_upstream::{UdpUpstreamProbe, UpstreamDnsPool};
    static POOL: std::sync::OnceLock<Arc<UpstreamDnsPool>> = std::sync::OnceLock::new();
    Arc::clone(POOL.get_or_init(|| {
        Arc::new(UpstreamDnsPool::new(
            Arc::new(nrr_platform_windows::dns_redirect::WindowsSystemDnsServers),
            Arc::new(UdpUpstreamProbe::default()),
        ))
    }))
}

#[allow(clippy::too_many_arguments)]
fn build_dns_resolver_instance(
    settings_conn: &Arc<Mutex<Connection>>,
    cache: &Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    active_sid: &nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
    hook: &nrr_service_runtime::supervised_runtime::RouteRecomputeHook,
    known_direct: Option<&Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    block_all_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fail_closed_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fake_assembly: Option<&Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>>,
    fake_ip_running: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fake_ip_secondary_ready: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    // "Is anyone signed in?" Absent leaves the arm ungated (test profiles).
    signed_in: Option<&Arc<dyn Fn() -> bool + Send + Sync>>,
) -> Option<nrr_service_runtime::dns_resolver_service::DnsResolverService> {
    use nrr_platform_windows::dns_redirect::{
        NrptDnsRedirect, PowerShellRunner, SystemDnsRedirectPort, TransactedNrptStore,
    };
    use nrr_service_runtime::dns_listener::DnsInterceptListener;
    use nrr_service_runtime::dns_resolver_ports::{
        ActiveRuleHostOracle, CacheFactSink, DirectUdpUpstreamResolver, HookSyncReconciler,
    };
    use nrr_service_runtime::dns_resolver_service::DnsResolverService;
    use std::time::Duration;

    // Mode B applies the ACTIVE user's rules; with nobody signed in there are
    // none, and the resolver would be a plain forwarder bought at the price of
    // rewriting machine-wide name resolution — inside the logon phase, where
    // that costs the user a frozen screen while the OS resolves through a
    // listener still coming up. The sign-in event re-arms.
    //
    // The question is "is anyone signed in", NOT "who do we route for":
    // `effective_routing_sid` answers `None` under an app-driven scope with no
    // tray even though a user is right there, and gating on it would leave Mode
    // B off for the whole session.
    if let Some(signed_in) = signed_in.as_ref() {
        if !signed_in() {
            tracing::info!(
                target: "nrr::dns-resolver",
                "Mode B: no signed-in user yet — staying reactive until sign-in",
            );
            return None;
        }
    }

    // Settle the real upstream DNS BEFORE redirecting: once NRPT points the
    // whole machine at our listener, an upstream that does not answer takes
    // every name with it. The pool probes candidates and refuses to hand back
    // one that is merely configured — a disconnected adapter keeps its static
    // DNS, and at boot (no default route yet) that entry can be enumerated
    // first.
    let upstream_pool = upstream_dns_pool();
    let upstream_dns = match upstream_pool.refresh() {
        Some(addr) => addr,
        None => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                "Mode B requested but no upstream IPv4 DNS answered a probe; staying reactive",
            );
            return None;
        }
    };

    let oracle = Arc::new(ActiveRuleHostOracle::new(
        Arc::new(ProductionRulesProvider::new(Arc::clone(settings_conn))),
        Arc::clone(active_sid),
    ));
    // The intercept path resolves rule hosts DIRECTLY against the
    // captured upstream over a raw UDP socket. A `DnsQuery_W`-based port
    // would honour the very NRPT catch-all Mode B installs, so every
    // rule-host query would loop back into this listener and time out.
    // A raw socket is invisible to NRPT and skips the hosts file, matching
    // the `resolve_hosts_bypass` posture for rule hosts.
    let mut direct_upstream =
        DirectUdpUpstreamResolver::new(upstream_dns, Duration::from_millis(1500), 2)
            .with_upstream_pool(Arc::clone(&upstream_pool));
    // DNS-over-secondary — when the setting is on and the tunnel is up, these
    // queries leave source-bound over the secondary link to a public resolver
    // instead of asking the primary provider's.
    if let Some(policy) = egress.clone() {
        direct_upstream = direct_upstream.with_egress(policy);
    }
    // A filtering provider answers rule hosts with a placeholder instead of a
    // destination (loopback pins, NXDOMAINed video nodes, one synthetic address
    // pair reused for every blocked name). When the captured upstream's answer
    // is unusable, re-ask the public resolvers — through the tunnel when one is
    // up, because on the primary link the provider intercepts that query too.
    // The recent-resolution memory arms the address-reuse trigger; without it
    // only the first trigger is live.
    let mut poison_fallback =
        nrr_service_runtime::dns_resolver_ports::PoisonFallbackUpstreamResolver::new(Arc::new(
            direct_upstream,
        ))
        .with_recent_addresses(
            nrr_service_runtime::recent_rule_addresses::global_recent_rule_addresses(),
        );
    if let Some(policy) = egress.clone() {
        poison_fallback = poison_fallback.with_egress(policy);
    }
    // Last stop before an application is told a name does not exist: ask the
    // machine's own private resolvers, which are the only ones that can hold a
    // namespace the public internet never heard of. Costs nothing on the
    // answered path — it runs only for names that already failed.
    let upstream = Arc::new(
        nrr_service_runtime::local_namespace_fallback::LocalNamespaceFallbackResolver::new(
            Arc::new(poison_fallback),
            Arc::new(nrr_platform_windows::dns_redirect::WindowsSystemDnsServers),
            std::time::Duration::from_millis(700),
        )
        .already_asked(match upstream_dns.ip() {
            std::net::IpAddr::V4(v4) => vec![v4],
            std::net::IpAddr::V6(_) => Vec::new(),
        }),
    );
    let sink = Arc::new(CacheFactSink::new(Arc::clone(cache)));
    let reconciler = Arc::new(HookSyncReconciler::new(hook.clone()));
    // Direct-answer steering: replies for non-rule
    // hosts are filtered against the secondary-pinned set so a shared-CDN host
    // (www.search.example vs gemini/video-site) gets clean addresses that stay on the
    // primary path even under a STRICT kill-switch.
    let owned_ips = nrr_service_runtime::dns_resolver_ports::ActiveSecondaryOwnedIps::new(
        Arc::new(ProductionRulesProvider::new(Arc::clone(settings_conn))),
        Arc::clone(active_sid),
        Arc::new(
            nrr_service_runtime::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
                Arc::clone(cache),
                nrr_domain::decision_lookup::FreshnessThresholds::default_production(),
            ),
        ),
    );
    let secondary_owned = Arc::new(owned_ips);

    // Re-ask the machine's own private resolvers when one server calls a name
    // non-existent. Windows asked every interface's server before we pointed
    // the whole system at ourselves; a corporate host and a machine on the
    // LAN stopped resolving because of it.
    let private_resolvers: nrr_service_runtime::dns_listener::PrivateResolversFn = Arc::new(|| {
        use nrr_platform_api::dns::SystemDnsServersPort;
        nrr_platform_windows::dns_redirect::WindowsSystemDnsServers
            .upstream_candidates_v4()
            .into_iter()
            .map(|c| c.server)
            .filter(|s| nrr_service_runtime::local_namespace_fallback::is_private_resolver(*s))
            .collect()
    });
    let mut listener = DnsInterceptListener::new(
        oracle,
        upstream,
        sink,
        Arc::clone(&reconciler) as Arc<dyn nrr_service_runtime::dns_resolver::SyncReconciler>,
        upstream_dns,
        // Latency budget → fail-open on slow reconcile. A smaller budget fails
        // open on most rule-host answers — every first-seen host's first
        // connect races ahead of its route and egresses the wrong link.
        // 900 ms matches the direct-gate budget below and stalls only the
        // querying host's own answer. The hook was ~150-900 ms when this was
        // chosen; it is now measured in seconds, which is why the gate consults
        // `typical_run` instead of spending this budget on a wait that cannot
        // finish.
        Duration::from_millis(900),
        Duration::from_millis(2000), // forward timeout for non-intercepted queries
    )
    .with_upstream_pool(Arc::clone(&upstream_pool))
    .with_direct_answer_steering(secondary_owned)
    // What the machine actually enforces, so the answer gate stops reading the
    // FQDN cache as proof that an address is carried.
    .with_enforced_view(Arc::new(
        nrr_service_runtime::dns_resolver_ports::ActiveSidEnforcedAddresses::new(Arc::clone(
            active_sid,
        )),
    ));
    listener = listener.with_private_resolvers(private_resolvers);
    // Withhold a rule-host answer whose enforcement missed its deadline while
    // the guard is blocking an unresolved link — handing it over is the leak
    // the guard exists to prevent.
    if let Some(armed) = fail_closed_armed {
        listener = listener.with_leak_guard_posture(Arc::new(move || armed()));
    }
    // When the shared fake-IP assembly is present,
    // answer scope rule hosts with virtual addresses (gated on the relay
    // actually running — no stack → real path), and under the armed block-all
    // answer DIRECT hosts with virtual addresses too, so their
    // first connect never races the catch-all. Wired UNCONDITIONALLY of the
    // toggle: the live `fake_ip_running` gate — not a resolver rebuild — is what
    // turns the feature on and off, so a toggle needs no resolver restart.
    if let Some(assembly) = fake_assembly {
        let running = fake_ip_running
            .clone()
            .unwrap_or_else(|| Arc::new(|| false) as Arc<dyn Fn() -> bool + Send + Sync>);
        // Scope hosts ride the additional route, so they need the relay to be
        // able to dial there — see `fake_ip_secondary_ready`.
        let scope_gate: Arc<dyn Fn() -> bool + Send + Sync> = match fake_ip_secondary_ready {
            Some(ready) => {
                let running_for_scope = Arc::clone(&running);
                Arc::new(move || running_for_scope() && ready())
            }
            None => Arc::clone(&running),
        };
        let answerer: Arc<dyn nrr_service_runtime::dns_resolver::FakeIpAnswerer> =
            Arc::new(nrr_service_runtime::dns_resolver::GatedFakeIpAnswerer::new(
                Arc::new(assembly.answerer()),
                scope_gate,
            ));
        listener = listener.with_fake_ip(answerer);
        if let Some(block_armed) = block_all_armed.clone() {
            let running_for_direct = Arc::clone(&running);
            let armed: Arc<dyn Fn() -> bool + Send + Sync> =
                Arc::new(move || block_armed() && running_for_direct());
            listener = listener.with_direct_fake_ip(Arc::new(assembly.direct_answerer(armed)));
        }
        // Collateral rescue — a direct host whose whole answer is
        // secondary-pinned gets a virtual address whenever the stack is live
        // (NOT gated on the block-all: the collateral egresses the wrong link
        // in every posture). Same shared assembly → same allocator/scope/map.
        listener = listener
            .with_collateral_fake_ip(Arc::new(assembly.direct_answerer(Arc::clone(&running))));
    }
    // …but never for a host already parked as a suggestion for the additional
    // route: that one is part of a site the user routes there, and the rescue
    // would push it onto the primary and break the page the suggestion exists
    // to fix.
    if let Some(engine) = auto_rules.as_ref() {
        listener = listener
            .with_companion_candidates(Arc::new(PendingCompanionCandidates(Arc::clone(engine))));
        // A host whose whole answer belongs to a routed site is reported from
        // here because this is the only path that knows its real name.
        listener = listener.with_companion_rescue_observer(Arc::new(RescuedCompanions {
            engine: Arc::clone(engine),
            active_sid: Arc::clone(active_sid),
        }));
    }
    // The notice-page learner is NOT wired: on a live machine its signal —
    // "this name was queried right after an uncovered one" — fires on ordinary
    // background traffic, which never lets the query stream go quiet. See the
    // module docs for what a working signal has to key on.
    // While the fail-closed block-all is armed, a DIRECT host's
    // steered answer registers as known-direct and drives a bounded reconcile
    // BEFORE the answer is sent, so the client's first connect is not cut by
    // the catch-all. The budget is deliberately larger
    // than the rule-host budget above: it only ever applies in the degraded
    // armed posture, where "answer a beat later but reachable" beats "answer
    // fast and the connect dies with no retry". Measured boot-time reconciles
    // run roughly 600-900 ms, so 900 ms is chosen to cover the real
    // distribution rather than losing most of the time to a tighter budget.
    // With the coalescing reconcile worker and the concurrent serve
    // pool this wait stalls only the querying host's own answer, and an
    // installed exemption is worth one extra beat of DNS latency. (Fake-IP
    // for direct hosts bypasses this gate entirely when active.)
    if let (Some(registry), Some(armed)) = (known_direct, block_all_armed) {
        listener = listener.with_direct_answer_gate(Arc::new(
            nrr_service_runtime::dns_resolver_ports::ReconcilingDirectAnswerGate::new(
                Arc::clone(registry),
                reconciler,
                armed,
                Duration::from_millis(900),
            ),
        ));
    }
    let redirect: Arc<dyn SystemDnsRedirectPort> =
        Arc::new(NrptDnsRedirect::new(PowerShellRunner, TransactedNrptStore));
    let listen_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 53));
    tracing::info!(
        target: "nrr::dns-resolver",
        upstream = %upstream_dns,
        "Mode B armed: local DNS resolver will bind 127.0.0.1:53 and forward non-rule \
         queries to an upstream that answered a probe",
    );
    Some(
        DnsResolverService::new(listener, redirect, listen_addr)
            // Namespaces other connections claim as their own. A corporate
            // VPN announces its domain and its servers over DHCP, so the
            // product can stay out of names it has no business answering —
            // without asking the user for a domain they may not know.
            .with_namespace_exemptions(Arc::new(claimed_namespaces)),
    )
}

/// The namespaces the product must not answer for, read fresh on every call.
///
/// Two exclusions beyond the neutral rules. Our OWN tunnel never counts — a
/// namespace pointed back at us is the loop this feature exists to break. And
/// a claim from a connection the OS is not currently using is dropped: a
/// disconnected VPN keeps its registry values, and honouring them would send
/// a whole namespace to a resolver nothing can reach.
fn claimed_namespaces() -> Vec<nrr_platform_api::dns_redirect::DnsNamespaceExemption> {
    use nrr_platform_api::dns_scope::{is_actionable_scope, InterfaceDnsScopePort};
    use nrr_platform_api::route_table::RouteTablePort;

    let live = nrr_platform_windows::windows_api::ProductionWindowsApi
        .get_adapter_infos()
        .unwrap_or_default();
    nrr_platform_windows::dns_scope::WindowsInterfaceDnsScopes
        .dns_scopes()
        .into_iter()
        .filter(is_actionable_scope)
        .filter_map(|scope| {
            let adapter = live
                .iter()
                .find(|a| a.adapter_name.eq_ignore_ascii_case(&scope.adapter_id))?;
            if nrr_platform_api::classify_availability(adapter)
                != Some(nrr_platform_api::AdapterAvailability::Available)
            {
                return None;
            }
            if adapter
                .description
                .contains(nrr_shared::product_identity::PRODUCT_NAME)
                || adapter
                    .friendly_name
                    .contains(nrr_shared::product_identity::PRODUCT_NAME)
            {
                return None;
            }
            Some(nrr_platform_api::dns_redirect::DnsNamespaceExemption {
                suffix: scope.suffix,
                servers: scope.servers,
            })
        })
        .collect()
}

/// Resolves the absolute path to `NetRuleRouterTray.exe`. Used for the
/// autostart helper's `set_enabled` and `get_state` calls. In production
/// the tray binary lives next to the service binary in
/// `%ProgramFiles%\NetRuleRouter\`; in dev runs it sits next to the
/// service in `target/debug/`. We use the `current_exe()` parent directory
/// joined with `NetRuleRouterTray.exe`. If the file does not exist, autostart
/// `set_enabled` will reject with `InvalidPath` at call time — better
/// than silently writing a dangling registry value.
fn resolve_tray_binary_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let parent = exe
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    parent.join("NetRuleRouterTray.exe")
}

/// Log what one enforcement recompute cost, phase by phase, when it was slow
/// enough to matter.
///
/// The threshold exists because this hook fires every 30 s plus on every
/// adapter change: a healthy sub-second pass logging its breakdown would bury
/// the log in noise and teach everyone to filter the target out. A slow pass is
/// the one worth a line, because it is the one that queues DNS answers and the
/// GUI's own requests behind it.
fn report_recompute_cost(timings: &nrr_service_runtime::phase_timings::PhaseTimings) {
    const SLOW_PASS: std::time::Duration = std::time::Duration::from_secs(1);
    nrr_service_runtime::phase_timings::report_if_slow(timings, "recompute", SLOW_PASS);
}

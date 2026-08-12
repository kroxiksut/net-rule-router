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
    run_autostart_startup_probe,
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

/// `MutationQueue` slot count. The queue serialises privileged mutations
/// (`Apply`, `Rollback`, `SafeDisable`); 32 covers the GUI's worst-case
/// burst of mass-toggle clicks comfortably without hoarding memory.
pub(crate) const MUTATION_QUEUE_CAPACITY: usize = 32;

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

    // Once-per-startup probe so the GUI sees up-to-date `last_known_state`
    // (incl. external overrides) on the first SnapshotInitial after boot.
    if let Some(conn) = settings_conn.as_ref() {
        run_autostart_startup_probe(conn.as_ref(), autostart_helper.as_ref(), &tray_path);
    }

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
    // Built only when settings_conn AND cache_store both opened and a
    // WFP session can be acquired. Failure on any of the three drops
    // the orchestrator to `None`; the dispatcher path then falls back
    // to `NoopRulesApplyDispatcher` so the supervisor can still come
    // up in a degraded mode (settings work, rules-apply is a no-op).
    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);
    // Alongside the per-SID WFP orchestrator we build a
    // `SecondaryRouteCoordinator` that drives the **system route table**
    // for the active console user (real interface routing of IP/FQDN/
    // domain-suffix/zone rules out the secondary adapter). It shares the
    // same providers as the orchestrator, so the Arcs are cloned before the
    // orchestrator consumes them.
    // Shared "unenforced application rules" status. The per-SID
    // orchestrator publishes app rules whose exe resolved to no path
    // into it on every filter compute; the SnapshotInitial handler reads the
    // same clone (Arc inside → same Mutex) for the GUI banner. Created once
    // here so both consumers below share it.
    let app_enforcement = nrr_service_runtime::app_enforcement_status::AppEnforcementStatus::new();
    // Shared smart-kill-switch shared-IP exclusion count, same
    // writer/reader split as `app_enforcement` above.
    let shared_ip_exemptions =
        nrr_service_runtime::app_enforcement_status::SharedIpExemptionStatus::new();
    // Shared block-all posture flag, same writer/reader split.
    let block_all_posture =
        nrr_service_runtime::app_enforcement_status::BlockAllPostureStatus::new();
    // Reactive VPN-endpoint learning — bounded, session-scoped, role-verified
    // server IPs (see `nrr_service_runtime::vpn_endpoint_learning`) plus the
    // kill-switch/fail-closed Block-id registry that role-verifies a drop
    // before the learner trusts it (see `nrr_service_runtime::killswitch_drop_registry`).
    // Shared: the route coordinator merges the learned set into its exemption
    // bands, the per-SID orchestrator publishes into the registry on every
    // compute, and the conn-trace consumer (built later) reads/writes both.
    let learned_vpn_endpoints =
        Arc::new(nrr_service_runtime::vpn_endpoint_learning::LearnedVpnEndpoints::new());
    // Proactive VPN-client exemption — registry of client exe
    // paths whose VPN role was verified by a kill-switch drop. Shared: the
    // per-SID orchestrator folds it into the block-all app-exemption set on
    // every compute; the conn-trace consumer (built later) writes into it; the
    // state DB pre-seeds it below so the exemption survives a restart.
    let learned_vpn_client_apps =
        Arc::new(nrr_service_runtime::vpn_client_registry::LearnedVpnClientApps::new());
    let killswitch_drop_registry = Arc::new(
        nrr_service_runtime::killswitch_drop_registry::KillswitchBlockFilterRegistry::new(),
    );
    // Block-notice reporting — folds the connection observer's qualifying
    // drops into episodes and logs the notices that survive (see
    // `nrr_service_runtime::block_notice_center`). Shared for the same
    // reason as the registries above: constructed once, read/written by the
    // conn-trace consumer built later.
    //
    // Durable per-SID mute store backing `block-notices.mutes.*`. Built
    // alongside `block_notice_center` (same connection) so the two are
    // wired together at every call site — a mute write that reached the
    // store but not the live ledger would only take effect after a restart.
    let block_notice_mute_store: Option<
        Arc<dyn nrr_service_runtime::block_notice_mute_store::BlockNoticeMuteStore>,
    > = settings_conn.as_ref().map(|conn| {
        Arc::new(
            nrr_service_runtime::block_notice_mute_store::SqliteBlockNoticeMuteStore::new(
                Arc::clone(conn),
            ),
        ) as Arc<dyn nrr_service_runtime::block_notice_mute_store::BlockNoticeMuteStore>
    });
    let block_notice_center = {
        let center = nrr_service_runtime::block_notice_center::BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&event_bus));
        // Mutes are personal and must outlive a restart: without the store a
        // silenced host would start shouting again on every service start.
        match settings_conn.as_ref() {
            Some(conn) => {
                let conn = Arc::clone(conn);
                Arc::new(center.with_mute_loader(Arc::new(move |sid: &str| {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                    nrr_storage::block_notice_mutes::BlockNoticeMutesRepository::new(&guard)
                        .list_active(sid, now_ms)
                        .unwrap_or_default()
                })))
            }
            None => Arc::new(center),
        }
    };
    let (
        per_sid_orchestrator,
        route_coordinator,
        rule_hostname_seeder,
        dns_observation_consumer,
        known_direct_registry,
        auto_rules_engine,
        app_destination_memory,
    ): RoutePathBundle = match (settings_conn.as_ref(), cache_store.as_ref()) {
        (Some(state_conn), Some(cache_arc)) => match open_wfp_session_budgeted(Arc::clone(&api)) {
            Ok(session) => {
                let fqdn_cache: Arc<dyn FqdnCacheLookup> = Arc::new(SqliteFqdnCacheLookup::new(
                    Arc::clone(cache_arc),
                    FreshnessThresholds {
                        // Same refresh-cadence floor as the store.
                        fallback_ttl_secs: nrr_domain::decision_lookup::clamp_cache_refresh_secs(
                            cache_refresh_secs,
                        ),
                        ..FreshnessThresholds::default_production()
                    },
                ));
                // Seed the shared DoH-resolver baseline on first run
                // (no-op once the list is non-empty, so user edits
                // are never overwritten). Best-effort — a seed failure must not
                // block service start.
                {
                    use nrr_storage::doh_lockdown::DohResolverEntriesRepository;
                    let seed = nrr_service_runtime::doh_seed::builtin_seed();
                    if let Ok(guard) = state_conn.lock() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        match DohResolverEntriesRepository::new(&guard).seed_if_empty(&seed, now) {
                            Ok(n) if n > 0 => tracing::info!(
                                target: "nrr::doh",
                                seeded = n,
                                "seeded the DoH/DoT resolver baseline on first run",
                            ),
                            Ok(_) => {}
                            Err(e) => tracing::warn!(
                                target: "nrr::doh",
                                error = %e,
                                "DoH resolver seed failed (non-fatal)",
                            ),
                        }
                    }
                }
                // The policy source resolves DoH-resolver HOST entries
                // through the FQDN cache (IP entries need no cache).
                let route_source: Arc<dyn RoutePolicySource> = Arc::new(
                    ProductionRoutePolicySource::new(Arc::clone(state_conn))
                        .with_fqdn_cache(Arc::clone(&fqdn_cache)),
                );
                let rules_provider: Arc<dyn RulesProvider> =
                    Arc::new(ProductionRulesProvider::new(Arc::clone(state_conn)));
                // Swap Noop → Production audit
                // sink when the audit writer is available. Without
                // an audit writer (boot before audit init or
                // missing dir ACLs) the orchestrator silently
                // drops records, same as before.
                let audit: Arc<dyn PerSidApplyAudit> = match artifacts.audit_writer.as_ref() {
                    Some(writer) => Arc::new(ProductionPerSidApplyAudit::new(
                        Arc::clone(writer),
                        Arc::clone(&id_generator),
                    )),
                    None => Arc::new(NoopPerSidApplyAudit),
                };
                // Build the route coordinator with cloned providers BEFORE
                // the orchestrator moves them.
                // Live routing-scope read for the
                // coordinator: service-driven (default) vs app-driven. Reads
                // the SAME settings connection the rules provider uses, so it
                // is only ever locked outside a recompute (no re-entrancy).
                let rule_scope_provider: nrr_service_runtime::route_coordinator::RuleScopeProvider = {
                    let scope_conn = Arc::clone(state_conn);
                    Arc::new(move || {
                        scope_conn
                                .lock()
                                .ok()
                                .and_then(|g| {
                                    nrr_storage::service_stability_config::ServiceStabilityConfigRepository::new(&g)
                                        .get_or_default()
                                        .ok()
                                })
                                .map(|r| r.rule_scope_service_driven)
                                .unwrap_or(true)
                    })
                };
                // Persist an auto-healed secondary/primary binding
                // (autosave the healed binding + banner).
                // When the coordinator matches a stale stored id to exactly
                // one live adapter by saved name, it calls this to rewrite the
                // stored id + name, ending the per-restart NOT-FOUND churn and
                // making the GUI show the real adapter. Same settings
                // connection; invoked OUTSIDE any recompute lock (the binding
                // was loaded and released before the heal), so no re-entrancy.
                let binding_heal_persist: nrr_service_runtime::route_coordinator::BindingHealPersistFn = {
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str, role: &str, healed_id: &str, healed_name: &str| {
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            // Fold the healed id into the binding,
                            // KEEPING the prior GUID in known_stable_ids so either
                            // adapter identity is recognised directly next session
                            // (no dependence on the friendly-name heal re-firing).
                            // Idempotent + no-op when the binding row is absent.
                            match repo.heal_binding_identity(sid, role, healed_id, healed_name, now) {
                                Ok(()) => tracing::info!(target: "nrr::route-coordinator", sid = %sid, role = role, healed_id = %healed_id, "persisted auto-healed binding (stale id folded into known-id set)"),
                                Err(e) => tracing::warn!(target: "nrr::route-coordinator", sid = %sid, error = %e, "auto-heal persist: heal_binding_identity failed"),
                            }
                        })
                    };
                // Safe-disable (ROUTE-half) — the route coordinator gates
                // EVERY recompute on the persistent pause flag, so a paused
                // user's routes are never (re)installed by any re-drive path
                // (active-user listener, 30 s tick, apply-trigger, boot).
                // Reads the SAME settings DB the rules/scope providers use, so
                // it is only ever locked outside a recompute (no re-entrancy).
                let pause_reader: nrr_service_runtime::route_coordinator::PausedCheckFn = {
                    use nrr_service_runtime::route_coordinator::PausedRouteDisposition;
                    let conn = Arc::clone(state_conn);
                    Arc::new(move |sid: &str| {
                        // Poisoned lock → treat as not-paused (Active), matching
                        // the prior forgiving behaviour (never lock a user out).
                        let Ok(g) = conn.lock() else {
                            return PausedRouteDisposition::Active;
                        };
                        let paused = nrr_storage::pause_state::RoutingPauseStateRepository::new(&g)
                            .is_paused(sid)
                            .unwrap_or(false);
                        if !paused {
                            return PausedRouteDisposition::Active;
                        }
                        // Honour the stop-policy
                        // read FRESH under the same lock: Persist keeps the /32
                        // rule-routes (work/corp adapter keeps carrying matched
                        // traffic), Teardown (default) full-clears. Read from the
                        // SAME settings DB `teardown_routes` uses so the safety
                        // tick and the pause action agree.
                        let persist = matches!(
                                nrr_storage::service_stability_config::ServiceStabilityConfigRepository::new(&g)
                                    .get_or_default()
                                    .map(|r| r.routing_stop_policy),
                                Ok(nrr_storage::service_stability_config::RoutingStopPolicy::Persist)
                            );
                        if persist {
                            PausedRouteDisposition::KeepSecondaryHosts
                        } else {
                            PausedRouteDisposition::ClearAll
                        }
                    })
                };
                // Persist observed VPN bootstrap server
                // IPs so the kill-switch exemption survives a service restart
                // (the catch-all block-all refuses to arm without a server hole,
                // and the live set is otherwise lost on restart). The write-
                // through closure fires whenever the live route table yields a
                // fresh set; the loader seeds the fail-closed exemptions at
                // startup. Both use the SAME settings connection the other
                // coordinator callbacks use, invoked OUTSIDE any recompute lock.
                let server_ip_persist: nrr_service_runtime::route_coordinator::ServerIpPersistFn = {
                    let conn = Arc::clone(state_conn);
                    Arc::new(move |ips: &[std::net::Ipv4Addr]| {
                        let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);
                        if let Err(e) = nrr_storage::vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository::new(&guard)
                                .upsert_observed(ips, now)
                            {
                                tracing::warn!(target: "nrr::route-coordinator", error = %e, "failed to persist observed VPN bootstrap server IPs — continuing");
                            }
                    })
                };
                let server_ip_loader: nrr_service_runtime::route_coordinator::ServerIpLoaderFn = {
                    let conn = Arc::clone(state_conn);
                    Arc::new(move || {
                        let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                        nrr_storage::vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository::new(
                            &guard,
                        )
                        .load_ips()
                        .unwrap_or_default()
                    })
                };
                let route_coord = Arc::new(
                    nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator::new(
                        Arc::clone(&api),
                        Arc::clone(&rules_provider),
                        Arc::clone(&route_source),
                        Arc::clone(&fqdn_cache),
                        rule_scope_provider,
                    )
                    .with_binding_heal_persist(binding_heal_persist)
                    .with_bootstrap_server_persistence(server_ip_persist, server_ip_loader)
                    .with_pause_state(pause_reader)
                    .with_liveness_probe(
                        Arc::clone(&liveness_tracker),
                        Arc::clone(&reachability_probe),
                    )
                    // Same store the connection observer fills and the per-SID
                    // filter codegen reads: an application rule's route and its
                    // permit must be derived from one set of destinations.
                    .with_app_observations(
                        nrr_service_runtime::app_observation_lookup::global_app_observations(),
                    )
                    // DNS-over-secondary — the SAME flag the egress policy
                    // reads, so the resolver /32 routes and the source-bound
                    // query sockets can never disagree about the path.
                    .with_dns_via_secondary(
                        nrr_service_runtime::dns_egress::global_dns_via_secondary(),
                    )
                    // Reactive VPN-endpoint learning — fold role-verified
                    // learned server IPs into the kill-switch/fail-closed
                    // exemption bands alongside the route-observed set.
                    .with_learned_vpn_endpoints(Arc::clone(&learned_vpn_endpoints)),
                );
                // The rule-hostname seeder resolves the active user's
                // `ExactFqdn` rule hostnames into the FQDN cache so domain
                // rules actually produce routes/filters. Shares the cache +
                // rules provider + FQDN lookup. The resolver is the
                // hosts-bypass decorator, so a hosts/adblock loopback pin no
                // longer starves rule seeding.
                let seeder_active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn = {
                    let reg = Arc::clone(&sid_registry);
                    let coord = Arc::clone(&route_coord);
                    Arc::new(move || coord.effective_routing_sid(&reg.active_sids()))
                };
                let route_seeder = Arc::new(
                    nrr_service_runtime::rule_hostname_seeder::RuleHostnameSeeder::new(
                        build_hosts_bypass_resolver(
                            Some(Arc::clone(state_conn)),
                            Some(Arc::clone(&seeder_active_sid)),
                            Some(build_dns_egress_policy(
                                &route_coord,
                                Arc::clone(&seeder_active_sid),
                            )),
                        ),
                        Arc::clone(cache_arc),
                        Arc::clone(&fqdn_cache),
                        Arc::clone(&rules_provider),
                    ),
                );
                // Carry the destinations of applications routed over the
                // additional link across restarts. An application rule is
                // pinned to that link for every destination, but only a host
                // route derived from an already-known address can put a flow
                // there — so without this every session refuses each of the
                // app's addresses once before learning it. The same
                // observation store the conn-trace consumer writes and the
                // codegen reads, so a
                // remembered destination is indistinguishable from a live one.
                let app_destination_memory =
                    Arc::new(
                        nrr_service_runtime::app_destination_memory::AppDestinationMemory::new(
                            nrr_service_runtime::app_observation_lookup::global_app_observations(),
                            Arc::clone(&rules_provider),
                            Arc::clone(&seeder_active_sid),
                            {
                                let conn = Arc::clone(state_conn);
                                Arc::new(move |app: &str, ips: &[std::net::Ipv4Addr], now| {
                                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                                    if let Err(e) =
                                    nrr_storage::app_destinations::AppDestinationsRepository::new(
                                        &guard,
                                    )
                                    .upsert(app, ips, unix_millis(now))
                                {
                                    tracing::warn!(
                                        target: "nrr::app-routing",
                                        error = %e,
                                        "failed to persist application destinations — continuing",
                                    );
                                }
                                })
                            },
                            {
                                let conn = Arc::clone(state_conn);
                                Arc::new(move |cutoff| {
                                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                                    let repo =
                                    nrr_storage::app_destinations::AppDestinationsRepository::new(
                                        &guard,
                                    );
                                    let cutoff = unix_millis(cutoff);
                                    // Rows past the window can never be enforced
                                    // again, so the read is also where they go: one
                                    // statement, on a path that already holds the
                                    // lock, instead of a retention task of its own.
                                    let _ = repo.prune_before(cutoff);
                                    repo.load_confirmed_since(cutoff).unwrap_or_default()
                                })
                            },
                        ),
                    );
                // Before the first apply: the routes must exist ahead of the
                // applications' first connections, which is the whole point.
                app_destination_memory.warm_load(std::time::SystemTime::now());
                // DNS-observation consumer: matches observed resolutions
                // against the active user's suffix/zone/exact rules and
                // caches the matches. Console-SID-aware: route through the
                // coordinator's effective-routing-SID gate so suffix/zone
                // rules get cached for the active CONSOLE user under
                // service-driven scope with no tray (otherwise only ExactIp
                // enforces from boot).
                // OS resolver-cache reader for the seed path
                // (`seed_from_os_cache`). Windows reads the real cache;
                // other targets get the no-op (empty) reader — the
                // policy/mechanism seam: neutral port, per-OS mechanism.
                let dns_cache_read: Arc<dyn nrr_platform_windows::DnsCacheReadPort> = {
                    #[cfg(target_os = "windows")]
                    {
                        Arc::new(nrr_platform_windows::WindowsDnsCacheRead::new())
                    }
                    #[cfg(not(target_os = "windows"))]
                    {
                        Arc::new(nrr_platform_windows::NoopDnsCacheRead)
                    }
                };
                // Session registry of positively-direct destinations,
                // shared by the orchestrator (block-all exemptions), the FCrDNS
                // direct-learning sink, and the Mode-B direct-answer gate.
                let known_direct =
                    Arc::new(nrr_service_runtime::known_direct::KnownDirectRegistry::default());
                // Companion-domain discovery. Built here because
                // the DNS-observation consumer below is its feed; the rule
                // AUTHOR is attached later, once the activation coordinator
                // exists. The mode comes straight from the caller's own per-SID
                // `secondary_block_policy` row, so a user who turned discovery
                // off pays nothing at all.
                let auto_rules_engine = Arc::new(
                    nrr_service_runtime::auto_rules::AutoRulesEngine::new(
                        Arc::clone(&rules_provider),
                        {
                            let conn = Arc::clone(state_conn);
                            Arc::new(move |sid: &str| {
                                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                                nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
                                    .load_for_sid(sid)
                                    .map(|record| record.auto_rules_mode)
                                    // A read failure must not silently widen
                                    // what the service may do on the user's
                                    // behalf, so fall back to the default
                                    // (`suggest`, which applies nothing).
                                    .unwrap_or_default()
                            })
                        },
                        Arc::new(nrr_service_runtime::auto_rules::SqliteDismissalStore::new(
                            Arc::clone(state_conn),
                        )),
                        Arc::new(nrr_service_runtime::auto_rules::SqlitePendingStore::new(
                            Arc::clone(state_conn),
                        )),
                        std::time::SystemTime::now(),
                    )
                    // Same per-SID row as the mode: whether the user asked for
                    // delivery-named hosts to be offered without waiting for the
                    // evidence. A read failure leaves them not opted in.
                    .with_eager_delivery_names({
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str| {
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
                                .load_for_sid(sid)
                                .map(|record| record.auto_rules_eager_delivery_names)
                                .unwrap_or(false)
                        })
                    })
                    .with_event_bus(Arc::clone(&event_bus))
                    // Evidence across restarts: without it a machine that
                    // restarts a few times a day never reaches the second
                    // window a proposal needs.
                    .with_evidence_store(Arc::new(
                        nrr_service_runtime::auto_rules::SqliteEvidenceStore::new(Arc::clone(
                            state_conn,
                        )),
                    ))
                    // Shares the process singleton with the settings writer
                    // below, so a Save flips this gate live, no restart.
                    .with_isp_block_candidates_flag(
                        nrr_service_runtime::auto_rules::global_isp_block_candidates_enabled(),
                    ),
                );
                let observe_consumer = Arc::new(
                    nrr_service_runtime::dns_observation_consumer::DnsObservationConsumer::new(
                        Arc::clone(&rules_provider),
                        Arc::clone(cache_arc),
                        Arc::clone(&fqdn_cache),
                        {
                            let reg = Arc::clone(&sid_registry);
                            let coord = Arc::clone(&route_coord);
                            Arc::new(move || coord.effective_routing_sid(&reg.active_sids()))
                        },
                    )
                    .with_dns_cache_read(dns_cache_read)
                    // FCrDNS direct-learning target.
                    .with_known_direct_registry(Arc::clone(&known_direct))
                    // Silence the collateral WARN while fake-IP is live: the
                    // relay steers those hosts onto the primary by name, so the
                    // shared IP is no longer forcing them out the secondary.
                    .with_fake_ip_gate({
                        let controller = Arc::clone(&fake_ip_controller);
                        Arc::new(move || controller.is_running())
                    })
                    // Collateral pin gate: while the secondary is
                    // unusable (the gated resolve yields no secondary interface,
                    // or a fail-closed block-all is armed) a shared-IP collateral
                    // is logged as "pin skipped" instead of "egresses the
                    // secondary". Same usability source of truth the conn-observe
                    // live-secondary drop counter reads.
                    .with_secondary_usable_gate({
                        let reg = Arc::clone(&sid_registry);
                        let coord = Arc::clone(&route_coord);
                        let posture = block_all_posture.clone();
                        Arc::new(move || {
                            if posture.armed() {
                                return false;
                            }
                            coord
                                .effective_routing_sid(&reg.active_sids())
                                .map(|sid| coord.resolve_egress_ifindexes(&sid).1.is_some())
                                .unwrap_or(false)
                        })
                    })
                    // The observations this consumer discards are
                    // the companion candidates. Feeding them costs one hash
                    // insert per observation on a drain that already runs.
                    .with_auto_rules(Arc::clone(&auto_rules_engine)),
                );
                // Per-filter apply-failure mode tracks the admin's stored
                // `ApplyFailurePolicy` (Settings → Routing behavior). Read
                // fresh on every apply so a mid-session change takes effect
                // on the next reconcile/recompile. Map: best-effort → skip
                // un-materializable filters; all-or-nothing / pre-flight →
                // strict (one bad filter aborts the whole revision).
                let failure_mode_source: nrr_service_runtime::per_sid_orchestrator::FilterFailureModeSource = {
                        let conn = Arc::clone(state_conn);
                        Arc::new(move || {
                            let slug = {
                                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                                nrr_storage::policy_settings::ApplyFailurePolicySettingsRepository::new(&guard)
                                    .get_or_default()
                                    .map(|r| r.policy)
                                    .unwrap_or_else(|_| {
                                        nrr_storage::policy_settings::DEFAULT_POLICY_SLUG.to_string()
                                    })
                            };
                            match slug.as_str() {
                                "best-effort" => FilterFailureMode::BestEffort,
                                // all-or-nothing + pre-flight-then-all-or-nothing
                                _ => FilterFailureMode::Strict,
                            }
                        })
                    };
                // Kill-switch: the orchestrator
                // resolves the active user's secondary (VPN) interface and
                // catch-all exemptions through the route coordinator — the
                // same resolution that drives the route table — so the
                // kill-switch pins its egress condition to the live
                // interface and never traps the tunnel / LAN / DHCP. Read
                // fresh on every apply (a secondary reconnect changes the LUID /
                // server IP). Returns `None` → kill-switch off (fail-open);
                // it only activates when the user also enables
                // `block_secondary_when_unavailable`.
                let kill_switch_resolver: nrr_service_runtime::per_sid_orchestrator::KillSwitchResolver = {
                        let coord = Arc::clone(&route_coord);
                        Arc::new(move |sid: &str| coord.kill_switch_exemptions(sid))
                    };
                // Fail-closed exemptions: resolved even
                // when the secondary is gone, so a fail-closed block-all
                // (mode B) keeps LAN / manageability and lets the tunnel
                // reconnect. Same route coordinator, different entrypoint.
                let fail_closed_exemptions_resolver: nrr_service_runtime::per_sid_orchestrator::FailClosedExemptionsResolver = {
                        let coord = Arc::clone(&route_coord);
                        Arc::new(move |sid: &str| coord.fail_closed_exemptions(sid))
                    };
                // Learned VPN client apps: pre-seed the
                // verified-client registry from the state DB so the proactive
                // app-scoped exemption arms on the FIRST compute of the
                // session. Survivors only: a since-uninstalled client must not
                // keep its hole in the block-all.
                {
                    let loaded = {
                        let guard = state_conn.lock().unwrap_or_else(|p| p.into_inner());
                        nrr_storage::vpn_client_apps::VpnClientAppsRepository::new(&guard)
                            .load()
                            .unwrap_or_default()
                    };
                    let survivors: Vec<String> = loaded
                        .into_iter()
                        .filter(|p| std::path::Path::new(p).is_file())
                        .collect();
                    if !survivors.is_empty() {
                        tracing::info!(
                            target: "nrr::vpn-learn",
                            clients = survivors.len(),
                            "pre-seeded verified VPN client apps from the state DB",
                        );
                        learned_vpn_client_apps.seed(&survivors, std::time::SystemTime::now());
                    }
                }
                // On-disk filter-id ledger so a hard-killed
                // prior instance's orphaned filters reap BY ID at the next
                // start (robust vs. an unreliable WFP enumerate). Sibling of
                // logs/ under the service data dir.
                let filter_ledger = Arc::new(
                    nrr_service_runtime::wfp_filter_ledger::WfpFilterLedger::new(
                        artifacts.topology.data_dir.join("wfp-filters.ledger"),
                    ),
                );
                let orch = Arc::new(
                        PerSidApplyOrchestrator::new(
                            Arc::new(session),
                            route_source,
                            rules_provider,
                            fqdn_cache,
                            audit,
                        )
                        .with_failure_mode_source(failure_mode_source)
                        .with_kill_switch_resolver(kill_switch_resolver)
                        .with_fail_closed_exemptions_resolver(fail_closed_exemptions_resolver)
                        // App-routing via observation: read the
                        // process-wide observed app→IP store the conn-observe
                        // consumer writes into.
                        .with_app_observations(
                            nrr_service_runtime::app_observation_lookup::global_app_observations(),
                        )
                        // Resolve exe name/glob app rules to
                        // concrete paths so their ALE_APP_ID filters materialize.
                        // Wrap the live Windows resolver in the persistence
                        // decorator so a VPN client that is not currently
                        // running/discoverable still resolves to its
                        // last-good on-disk path (the built-in exemptions need a real
                        // path, or the kill-switch traps the client). `state_conn` is
                        // available in this arm, so persistence is always on here.
                        // Wrap THAT in the confirmed-client
                        // fallback, so an exe the user pointed at in onboarding
                        // resolves even on a machine that has never seen it run:
                        // its permit then exists BEFORE the client's first
                        // connection attempt instead of after it.
                        .with_app_resolver(Arc::new(
                            nrr_service_runtime::confirmed_client_app_resolver::ConfirmedClientAppPathResolver::new(
                                Arc::new(
                                    nrr_service_runtime::persistent_app_resolver::PersistentAppPathResolver::new(
                                        Arc::new(nrr_platform_windows::WindowsAppPathResolver::new()),
                                        Arc::clone(state_conn),
                                    ),
                                ),
                                nrr_service_runtime::vpn_client_registry::global_confirmed_vpn_clients(),
                            ),
                        ))
                        // Publish app rules that resolved to
                        // no path into the shared status the SnapshotInitial
                        // handler reads for the GUI banner.
                        .with_app_enforcement_status(app_enforcement.clone())
                        // Publish the smart-kill-switch shared-IP
                        // exclusion count for the GUI warning.
                        .with_shared_ip_exemption_status(shared_ip_exemptions.clone())
                        // Publish the block-all posture for the GUI
                        // "leak protection is blocking unknown traffic" banner.
                        .with_block_all_posture_status(block_all_posture.clone())
                        .with_filter_ledger(Arc::clone(&filter_ledger))
                        // Flush the OS resolver cache
                        // on the fail-closed block-all arming edge so names the
                        // OS cached BEFORE the block re-query on the wire and
                        // become observable (a zone→primary host absent from
                        // the FQDN cache would otherwise get no permit).
                        .with_dns_cache_control(Arc::new(
                            nrr_platform_windows::WindowsDnsCacheControl::new(),
                        ))
                        // Known-direct block-all exemptions (Mode-B
                        // steered answers + FCrDNS non-rule confirmations).
                        .with_known_direct_registry(Arc::clone(&known_direct))
                        // Reactive VPN-endpoint learning — publish this SID's
                        // kill-switch/fail-closed Block ids so the conn-trace
                        // consumer's learner can role-verify a drop.
                        .with_killswitch_drop_registry(Arc::clone(&killswitch_drop_registry))
                        // A fail-closed posture that keeps blocking asks the
                        // watchdog for a fresh binding resolution — after a
                        // wake the bound adapter is often a different one.
                        .with_rebind_requests(Arc::clone(&rebind_requests))
                        // Route before block: a destination pin
                        // only tolerates traffic egressing the additional link,
                        // so the destination's `/32` must be in place before
                        // the pin is. The filter pass and the route pass read
                        // the same live caches at different instants, so a
                        // freshly-learned address could otherwise be pinned by
                        // one pass after the other had already run — and be
                        // dropped until the next recompute. Fires only when a
                        // reconcile actually installs a NEW destination block;
                        // an unchanged coverage set never calls it. The route
                        // recompute never re-enters the orchestrator.
                        .with_route_sync({
                            let coord = Arc::clone(&route_coord);
                            let registry = Arc::clone(&sid_registry);
                            Arc::new(move || {
                                if let Err(e) = coord.recompute_active(&registry.active_sids()) {
                                    tracing::warn!(
                                        target: "nrr::route-coordinator",
                                        "route sync before installing new destination pins failed: {e:?}",
                                    );
                                }
                            })
                        })
                        // Proactive VPN-client exemption: fold
                        // the verified client paths into the block-all app
                        // exemption set on every compute, so a known client is
                        // permitted BEFORE its first drop of the session.
                        .with_vpn_client_apps_provider({
                            let registry = Arc::clone(&learned_vpn_client_apps);
                            Arc::new(move || registry.current())
                        })
                        // Fake-IP: the WFP additions (pool permit +
                        // UDP block, real-/32 suppression, real-IP hard-blocks)
                        // follow the LIVE feature state: the persisted toggle,
                        // Resolver mode, AND the TUN stack actually running.
                        // Live in both directions: a plan compiled before the
                        // toggle gains the pool permit on the next compute, and
                        // the plan never suppresses/blocks REAL addresses while
                        // the stack is down and applications still receive them
                        // from DNS (the answerer's fail-open gate keys on the
                        // same `is_running`).
                        .with_fake_ip_context_provider({
                            let conn = Arc::clone(state_conn);
                            let controller = Arc::clone(&fake_ip_controller);
                            Arc::new(move || {
                                if !read_fake_ip_enabled(&conn) {
                                    return None;
                                }
                                let mode = read_enforcement_mode(&conn);
                                if mode
                                    != nrr_domain::enforcement_mode::EnforcementMode::Resolver
                                {
                                    return None;
                                }
                                if !controller.is_running() {
                                    return None;
                                }
                                let (scope, pool) = fake_ip_policy();
                                Some(
                                    nrr_service_runtime::fake_ip::FakeIpEnforcementContext {
                                        scope,
                                        pool,
                                    },
                                )
                            })
                        }),
                    );
                // The orchestrator's install listener is registered AFTER
                // the pause coordinator is built (below), as a PAUSE-AWARE
                // reconcile that skips paused SIDs. The registry is empty at
                // construction (no active SID yet), so deferring the
                // registration races nothing.
                // Startup orphan cleanup: adopt our /32
                // secondary routes left in the OS table by a previous run so
                // the first recompute reconciles them. Runs before any
                // listener can fire (no active SID yet at construction).
                route_coord.adopt_orphans_from_table();
                // Persist-on-stop (startup guarantee) — ALWAYS strip any
                // orphaned block/fail-closed/kill-switch WFP filter a dead
                // prior instance left behind, in BOTH stop modes. A
                // non-dynamic WFP session's block filters survive
                // taskkill/F until reboot, so a hard-killed kill-switch with
                // no service to lift it would lock the user out. Runs before
                // any active-SID listener fires (registry empty at
                // construction), so it never races per-SID reconcile.
                //
                // Reap the prior instance's filters by PERSISTED ID first
                // (robust even when enumerate under-reports), then the
                // enumerate-based block strip as defence in depth.
                orch.cleanup_persisted_orphans();
                match orch.cleanup_wfp_blocks_only() {
                    Ok(0) => {}
                    Ok(n) => tracing::warn!(
                        target: "nrr::runtime",
                        stripped_blocks = n as u64,
                        "startup reconciliation: stripped orphaned block/kill-switch \
                         WFP filter(s) left by a prior instance",
                    ),
                    Err(e) => tracing::warn!(
                        target: "nrr::runtime",
                        "startup block-filter reconciliation failed: {e:?}",
                    ),
                }
                // Recompute the route table on every active-user transition
                // (login/logout/switch). The Free model routes for the single
                // active console user; an empty active set tears the table
                // down (no user → no routes).
                {
                    let coord = Arc::clone(&route_coord);
                    sid_registry.add_listener(Arc::new(move |snapshot: &[String]| {
                        if let Err(e) = coord.recompute_active(snapshot) {
                            tracing::error!(
                                target: "nrr::route-coordinator",
                                "route recompute on active-user change failed: {e:?}",
                            );
                        }
                    }));
                }
                (
                    Some(orch),
                    Some(route_coord),
                    Some(route_seeder),
                    Some(observe_consumer),
                    Some(known_direct),
                    Some(auto_rules_engine),
                    Some(app_destination_memory),
                )
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::runtime",
                    error = %format!("{e:?}"),
                    "no filtering-engine session for orchestrator construction (failed or timed \
                     out); per-SID apply layer will run in noop mode",
                );
                // Without this the degradation is log-only: the service reports
                // Running, the GUI shows rules as applied, and nothing is
                // enforced. `Degraded` (not `Blocking`) — editing rules still
                // works, they just do not reach the kernel until a restart.
                health_agg.record(
                    HealthComponent::Apply,
                    nrr_service_runtime::state::ServiceHealthSeverity::Degraded,
                    "the filtering engine did not hand out a session at startup — rules are not \
                     being enforced; restart the service once the Base Filtering Engine (BFE) is \
                     healthy",
                );
                (None, None, None, None, None, None, None)
            }
        },
        _ => (None, None, None, None, None, None, None),
    };

    // Routing-pause coordinator, wired to the REAL
    // orchestrator dispatcher now that the orchestrator exists. `pause` /
    // `pause_all_active` (safe-disable) / `resume` therefore actually
    // remove/reinstall the SID's WFP filters, instead of the old Noop that only
    // persisted the flag. Falls back to Noop when WFP is unavailable.
    let pause_coordinator = settings_conn.as_ref().map(|conn| {
        let dispatcher: Arc<dyn PauseDispatcher> = match per_sid_orchestrator.as_ref() {
            Some(orch) => Arc::new(OrchestratorPauseDispatcher::new(Arc::clone(orch))),
            None => Arc::new(NoopPauseDispatcher),
        };
        let mut coord = RoutingPauseCoordinator::new(
            Arc::clone(conn),
            Arc::clone(&sid_registry),
            dispatcher,
            Arc::new(NoopRoutingPauseAudit),
            Arc::new(SystemClock),
        );
        // Safe-disable (ROUTE-half) — hand the route coordinator to the pause
        // coordinator so `pause` / `pause_all_active` / `resume` tear down and
        // restore the single-owner ROUTE table (not just WFP filters) for the
        // effective routing user. `Arc::clone` (borrow) so `route_coordinator`
        // stays available for the hooks/triggers built later. When WFP/route
        // path is unavailable (`None`) the pause coordinator stays WFP-only.
        if let Some(rc) = route_coordinator.as_ref() {
            coord = coord.with_route_coordinator(Arc::clone(rc));
        }
        Arc::new(coord)
    });

    // Register the orchestrator's install listener as a PAUSE-AWARE reconcile:
    // persisted-paused SIDs are subtracted from the active snapshot before
    // `reconcile`, so a paused SID's filters are removed and NOT reinstalled on
    // an active-user transition or reboot (durable pause / safe-disable).
    // Replaces the old `wire_orchestrator_to_registry` direct wiring.
    match (per_sid_orchestrator.as_ref(), pause_coordinator.as_ref()) {
        (Some(orch), Some(coord)) => {
            let orch = Arc::clone(orch);
            let coord = Arc::clone(coord);
            let routing = route_coordinator.clone();
            sid_registry.add_listener(Arc::new(move |snapshot: &[String]| {
                // Fail-CLOSED on a pause-state read error: do NOT touch the
                // platform, so a transient DB error can never reinstall a paused
                // SID's filters (mirrors
                // `RoutingPauseCoordinator::make_pause_aware_listener`).
                let paused = match coord.paused_sids() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            target: "nrr::per_sid_orchestrator",
                            "pause-state read failed; skipping reconcile: {e:?}",
                        );
                        return;
                    }
                };
                // With NO tray connected, the console-
                // session user (service-driven scope) is still the routing
                // user: a tray disconnect must not strip their enforcement,
                // and a tray-less boot must still install it. Connected trays
                // pass through unchanged.
                let effective: Vec<String> = match routing.as_ref() {
                    Some(rc) => rc.effective_enforcement_sids(snapshot),
                    None => snapshot.to_vec(),
                };
                let active_unpaused: Vec<String> = effective
                    .iter()
                    .filter(|s| !paused.iter().any(|p| p == *s))
                    .cloned()
                    .collect();
                if let Err(e) = orch.reconcile(&active_unpaused) {
                    tracing::error!(
                        target: "nrr::per_sid_orchestrator",
                        "pause-aware reconcile failed: {e:?}",
                    );
                }
            }));
        }
        // No pause state (no settings DB) but WFP is up → plain reconcile wiring
        // so enforcement still installs on tray connect.
        (Some(orch), None) => {
            wire_orchestrator_to_registry(Arc::clone(orch), sid_registry.as_ref())
        }
        // No orchestrator (WFP unavailable) → nothing to install.
        (None, _) => {}
    }

    // Recompile the active SIDs' filter sets right after a
    // fake-IP stack transition. The per-SID codegen reads the fake-IP context
    // LIVE (see `with_fake_ip_context_provider`), but nothing else would
    // recompute at the moment of a toggle — the pool permit (or its removal)
    // would otherwise wait for the next unrelated recompute. Pause-aware and
    // fail-closed on a pause-state read error, mirroring the listener above.
    let fake_ip_replan: Arc<dyn Fn() + Send + Sync> = {
        let orch = per_sid_orchestrator.clone();
        let pause = pause_coordinator.clone();
        let routing = route_coordinator.clone();
        let registry = Arc::clone(&sid_registry);
        Arc::new(move || {
            let Some(orch) = orch.as_ref() else {
                return;
            };
            let paused = match pause.as_ref() {
                Some(coord) => match coord.paused_sids() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(
                            target: "nrr::fake-ip",
                            "pause-state read failed; skipping fake-IP replan: {e:?}",
                        );
                        return;
                    }
                },
                None => Vec::new(),
            };
            let snapshot = registry.active_sids();
            let effective: Vec<String> = match routing.as_ref() {
                Some(rc) => rc.effective_enforcement_sids(&snapshot),
                None => snapshot,
            };
            for sid in effective.iter().filter(|s| !paused.iter().any(|p| p == *s)) {
                // Window-free RECOMPILE, not the add-only install:
                // a fake-IP transition also REMOVES filters (pool permit /
                // real-IP blocks on toggle-off; the shared-IP exemption permits
                // when the datapath drops and the strict subtraction re-arms).
                // `install_for_sid` only adds and re-tracks, so the superseded
                // filters would stay live in WFP yet untracked — invisible to
                // every later diff until a service restart. The MAKE-then-BREAK
                // diff deletes them in the same pass.
                if let Err(e) = orch.recompile_for_sid(sid) {
                    tracing::error!(
                        target: "nrr::fake-ip",
                        sid = %sid,
                        "fake-IP replan: per-SID recompile failed: {e:?}",
                    );
                }
            }
        })
    };

    // ── DB-MAC tamper bootstrap ───────────────────────────────────────
    // Load (or generate) the row-MAC signing key from the DPAPI key
    // store, verify existing revisions, and raise tamper / key-reset
    // alerts. The returned key is threaded into the
    // ActivationCoordinator below so every revision write is signed.
    // Best effort: a bootstrap failure (or a non-Windows build with no
    // DPAPI) logs and degrades to unsigned operation — routing is
    // independent of this integrity scan.
    let tamper_signing_key: Option<Vec<u8>> =
        settings_conn.as_ref().and_then(run_db_mac_tamper_bootstrap);
    // Keyed follow-up to the keyless boot sweep: signed candidate rows
    // orphaned by a hard kill can only be rejected once the signing key
    // exists (re-signing keeps their row_hmac consistent). Runs after
    // verification so the scan saw the rows exactly as the previous run
    // signed them. No key (bootstrap failed) → they stay pending until
    // a healthy boot rather than being corrupted by a keyless flip.
    if let (Some(conn), Some(key)) = (settings_conn.as_ref(), tamper_signing_key.as_ref()) {
        nrr_service_runtime::bootstrap::sweep_signed_orphaned_candidates(conn, key);
    }

    let activation_coordinator = match (settings_conn.as_ref(), artifacts.audit_writer.as_ref()) {
        (Some(conn), Some(audit_writer)) => {
            let marker_store = Arc::new(ProductionApplyMarkerStore::new(
                &artifacts.topology.data_dir,
            ));
            let audit_emitter = Arc::new(
                ProductionActivationAuditEmitter::new(
                    Arc::clone(audit_writer),
                    Arc::clone(&id_generator),
                )
                .with_event_bus(Arc::clone(&event_bus)),
            );
            // Swap `NoopRulesApplyDispatcher` for
            // `ProductionRulesApplyDispatcher` when the per-SID
            // orchestrator is available. The Noop path stays as a
            // fallback so a WFP-engine-open failure on a development
            // VM doesn't block the rest of the service.
            let dispatcher: Arc<
                dyn nrr_service_runtime::activation_coordinator::RulesApplyDispatcher,
            > = match per_sid_orchestrator.as_ref() {
                // The settings conn lets the
                // dispatched snapshot pick up the caller's
                // `include_subdomains` widening, matching the provider read.
                Some(orch) => Arc::new(
                    ProductionRulesApplyDispatcher::new(Arc::clone(orch))
                        .with_settings_conn(Arc::clone(conn)),
                ),
                None => Arc::new(NoopRulesApplyDispatcher),
            };
            // Load the admin's persisted apply-failure policy at startup so the
            // coordinator's SID-level revert/keep behaviour matches Settings
            // across restarts (the IPC setter keeps it in sync mid-session via
            // `set_failure_policy`). No row yet → storage default (best-effort).
            let startup_failure_policy = {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                let slug =
                    nrr_storage::policy_settings::ApplyFailurePolicySettingsRepository::new(&guard)
                        .get_or_default()
                        .map(|r| r.policy)
                        .unwrap_or_else(|_| {
                            nrr_storage::policy_settings::DEFAULT_POLICY_SLUG.to_string()
                        });
                ApplyFailurePolicy::from_slug(&slug).unwrap_or(ApplyFailurePolicy::BestEffort)
            };
            let mut coordinator = ActivationCoordinator::new(
                Arc::clone(conn),
                Arc::clone(&sid_registry),
                dispatcher,
                marker_store,
                audit_emitter,
                Arc::new(SystemClock),
                Arc::clone(&id_generator)
                    as Arc<dyn nrr_service_runtime::activation_coordinator::IdGenerator>,
                startup_failure_policy,
            );
            // Sign revision rows when the tamper bootstrap produced a key.
            // Without it the coordinator runs unsigned (back-compat /
            // non-Windows / bootstrap error).
            if let Some(key) = tamper_signing_key.clone() {
                coordinator = coordinator.with_signing_key(key);
            }
            // No-tray routing-user fallback: an
            // activation with a dead tray subscription must still dispatch to
            // the console-session user (service-driven scope), not to nobody.
            if let Some(rc) = route_coordinator.as_ref() {
                let rc = Arc::clone(rc);
                coordinator = coordinator
                    .with_fallback_routing_sid(Arc::new(move || rc.effective_routing_sid(&[])));
            }
            Some(Arc::new(coordinator))
        }
        _ => None,
    };

    // Verify every principal's active revision (HMAC + Free rule cap)
    // before any SID install can read it — none have started yet this
    // early in bootstrap (the IPC server isn't listening). A row that
    // reached `revisions` outside the app is rolled back to the last
    // trusted revision here instead of being enforced as-is.
    if let (Some(coord), Some(conn)) = (activation_coordinator.as_ref(), settings_conn.as_ref()) {
        run_active_integrity_enforcement(coord, conn);
    }

    // Build the rule author, now that the activation coordinator exists.
    // Shared by the companion-domain engine's `accept` path AND the
    // "route this blocked host" notice action: both go through the ORDINARY
    // mutation executor, so an authored rule passes the same Free rule cap,
    // tamper gate, revision audit and push events a rule the user typed does
    // — the reason on the rule is the only difference. A dedicated executor
    // instance rather than the handler-registry one below: that one is built
    // inline inside `IpcHandlerDeps::new`, and the extra wiring it carries
    // (`recovery_audit_sink` for safe-disable, `alerts_repo` for alert
    // ack/resolve) governs mutation kinds this path never submits.
    let block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>> =
        match (activation_coordinator.as_ref(), settings_conn.as_ref()) {
            (Some(coord), Some(conn)) => {
                let executor = ProductionMutationExecutor::new(Arc::clone(coord))
                    .with_state_conn(Arc::clone(conn))
                    .with_event_bus(Arc::clone(&event_bus))
                    // The author reaches the executor without passing any IPC
                    // handler, so the administrative rules lock has to be wired
                    // here too or this path would be the way around it.
                    .with_stability_provider(Arc::new(ProductionServiceStability::new(Arc::clone(
                        conn,
                    )))
                        as Arc<dyn ServiceStabilityConfigProvider>);
                let rules: Arc<dyn RulesProvider> =
                    Arc::new(ProductionRulesProvider::new(Arc::clone(conn)));
                let mut production_author =
                    nrr_service_runtime::auto_rules::ProductionAutoRuleAuthor::new(
                        rules,
                        Arc::new(executor)
                            as Arc<dyn nrr_service_runtime::ipc_handlers::MutationExecutor>,
                    );
                // A new rule only governs connections opened after it. Without
                // this the user adds the address, nothing visibly changes, and
                // they have to reload the page by hand.
                if let Some(cache_arc) = cache_store.as_ref() {
                    let fqdn: Arc<dyn FqdnCacheLookup> = Arc::new(SqliteFqdnCacheLookup::new(
                        Arc::clone(cache_arc),
                        FreshnessThresholds::default_production(),
                    ));
                    production_author = production_author.with_flow_refresh(Arc::new(
                        nrr_service_runtime::routed_host_flow_refresh::RoutedHostFlowRefresh::new(
                            fqdn,
                            Arc::new(
                                nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
                            ),
                        ),
                    ));
                }
                let author: Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor> =
                    Arc::new(production_author);
                if let Some(engine) = auto_rules_engine.as_ref() {
                    engine.attach_author(Arc::clone(&author));
                }
                Some(author)
            }
            _ => None,
        };

    // ── Full IPC handler registration ─────────────────────────────────
    // Registered via `register_production_handlers`. All catalog ops have
    // a production handler; a few fall back to Noop/degraded impls
    // (`NoopMutationExecutor`, etc.) when their dependency chain (WFP
    // session, settings DB) could not be built at boot.
    //
    // Connection-trace ring, shared between the observer (writer,
    // built later in `build_conn_trace_pair`) and the `conn-trace.entries.list`
    // IPC handler (reader, wired into the deps below). ALWAYS created (a
    // cheap ~1000-entry in-memory bounded buffer) so the handler is always
    // registered — the "Show connections" panel works WITHOUT a service
    // restart. The ring is in-memory only and never persisted; the on-disk NDJSON sink stays
    // opt-in (`conn_trace_ndjson`), which is the privacy-sensitive output.
    // Declared at function scope so it reaches BOTH the handler registration
    // (inside the settings-DB block) and the observer construction (after it).
    // `_conn_trace_gui` is retained in the row but no longer gates the ring
    // (the ring is always built now); the on-disk NDJSON sink is gated by
    // `conn_trace_persisted_ndjson` below.
    let (conn_trace_persisted_ndjson, _conn_trace_gui) =
        read_conn_trace_flags(settings_conn.as_ref());
    let conn_trace_ring: Option<
        Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>,
    > = Some(Arc::new(
        nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing::new(1000),
    ));

    let mut registry = IpcHandlerRegistry::new();
    if let (Some(conn), Some(coord)) = (settings_conn.as_ref(), pause_coordinator.as_ref()) {
        let cache_db_path = artifacts.topology.cache_db_path.clone();
        let logs_dir_for_usage = artifacts.topology.logs_dir.clone();

        // Security alerts repository, shared between the
        // SecurityAlertsList handler (read filter) and the
        // ProductionMutationExecutor (ack/resolve writes).
        let alerts_repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
            Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(conn)));

        // ApplyFailurePolicy writer: bus + coordinator forward.
        let mut apply_failure_writer = ProductionApplyFailurePolicy::new(Arc::clone(conn))
            .with_event_bus(Arc::clone(&event_bus));
        if let Some(c) = activation_coordinator.as_ref() {
            apply_failure_writer = apply_failure_writer.with_coordinator(Arc::clone(c));
        }

        // Health reporter: real `HealthAggregator` impl. CRITICAL:
        // pulled from the outer `health_agg` so the SAME Arc is shared
        // with `SupervisedRuntimeDeps.health`. Constructing a second
        // aggregator here (the pre-fix shape) made `ServiceHealthGet`
        // serve a stale "starting / no components" snapshot forever,
        // because the supervisor's `clear_lifecycle_override` + seeding
        // ran against a different instance.
        let health: Arc<dyn HealthReporter> = Arc::clone(&health_agg) as Arc<dyn HealthReporter>;

        // Policy manager: production `CoordinatorPolicyManager` when
        // coordinator is available; otherwise a degraded read-only stub.
        let policy: Arc<dyn PolicyManager> = match activation_coordinator.as_ref() {
            Some(c) => Arc::new(CoordinatorPolicyManager::new(
                Arc::clone(c),
                Arc::clone(conn),
            )),
            None => Arc::new(DegradedPolicyManager),
        };

        // Read the state DB schema
        // version once for the diagnostic archive's `health.json`. Uses the
        // SAME already-open `conn` (shared `Arc<Mutex<Connection>>`) rather
        // than opening a second connection; a lock/query failure degrades to
        // `None` (health.json omits the field) rather than failing startup.
        let state_schema_version: Option<u32> = conn
            .lock()
            .ok()
            .and_then(|guard| nrr_storage::migration::read_schema_version(&guard).ok());

        // Production diagnostics facade. Composes
        // existing readers (LogReader, AuditReader, alerts repo) +
        // raw SQLite reads of cache/state DBs into the wire-shaped
        // DTOs the GUI's diagnostics section consumes. Opens its own
        // cache connection so it doesn't contend with the per-SID
        // orchestrator's `SqliteFqdnCacheLookup` (WAL allows
        // concurrent readers; the per-call Mutex is the only point
        // of contention and reads are inexpensive single-row
        // queries).
        let diagnostics_cache_conn: Option<Arc<Mutex<Connection>>> = {
            let path = &artifacts.topology.cache_db_path;
            match Connection::open(path) {
                Ok(c) => Some(Arc::new(Mutex::new(c))),
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::runtime",
                        error = %e,
                        path = %path.display(),
                        "diagnostics facade: cache connection open failed; \
                         cache_health card will report unhealthy",
                    );
                    None
                }
            }
        };
        let diagnostics: Arc<dyn DiagnosticsFacade> = Arc::new(ProductionDiagnosticsFacade::new(
            artifacts.topology.logs_dir.clone(),
            artifacts.topology.data_dir.join("audit"),
            diagnostics_cache_conn,
            Arc::clone(&alerts_repo),
            Some(Arc::clone(conn)),
        ));

        // Build the sampler-backed traffic-counter provider + writer
        // from the function-scope `traffic_sampler`. `None` keeps
        // `traffic-stats.get`/`set` as `UnimplementedHandler`.
        let traffic_stats = traffic_sampler.as_ref().map(|sampler| {
            let settings = Arc::new(
                nrr_service_runtime::production_traffic::ProductionTrafficSettings::new(
                    Arc::clone(conn),
                ),
            )
                as Arc<dyn nrr_service_runtime::production_traffic::TrafficSettingsAccess>;
            Arc::new(
                nrr_service_runtime::production_traffic::ProductionTrafficStats::new(
                    Arc::clone(sampler),
                    settings,
                ),
            )
        });

        // Wire the address-recorder into the adapters
        // snapshot provider so a user-requested external-IP probe persists
        // through the SAME `TrafficSampler` connection the routine sampler
        // tick already owns (never a second connection to
        // `nrr_traffic_stats.db`). `None` when the traffic sampler itself
        // failed to open — the probe still runs, it just does not persist.
        let mut adapters_snapshot_provider =
            MonitoredAdaptersSnapshotProvider::new(Arc::clone(&api));
        if let Some(sampler) = traffic_sampler.as_ref() {
            adapters_snapshot_provider = adapters_snapshot_provider.with_address_recorder(
                Arc::new(
                    nrr_service_runtime::production_traffic::SamplerAdapterAddressRecorder::new(
                        Arc::clone(sampler),
                    ),
                ) as Arc<dyn nrr_service_runtime::AdapterAddressRecorder>,
            );
        }

        let mut deps = IpcHandlerDeps::new(
            Arc::new(NoopIpcAuditEmitter) as Arc<dyn nrr_service_runtime::IpcAuditEmitter>,
            health,
            policy,
            Arc::new(adapters_snapshot_provider) as Arc<dyn AdaptersSnapshotProvider>,
            Arc::new(ProductionRulesSnapshotProvider::new(Arc::clone(conn)))
                as Arc<dyn RulesSnapshotProvider>,
            diagnostics,
            // ProductionMutationExecutor handles RulesUpdate
            // end-to-end via the coordinator. Other MutationKind variants
            // return structured "not implemented" errors. When the
            // coordinator isn't available (recovery-blocked path),
            // executors can't be constructed — fall through to nothing
            // (the registry path below is gated on coord presence anyway).
            match activation_coordinator.as_ref() {
                Some(c) => {
                    let mut exec = ProductionMutationExecutor::new(Arc::clone(c));
                    if let Some(sink) = recovery_audit_sink.as_ref() {
                        exec = exec.with_recovery_audit_sink(Arc::clone(sink));
                    }
                    exec = exec.with_alerts_repo(Arc::clone(&alerts_repo));
                    // Thread the state DB connection
                    // through so the dry-run path runs real
                    // `score_candidate` instead of the count-based
                    // heuristic.
                    exec = exec.with_state_conn(Arc::clone(conn));
                    // Emit MutationProgress push
                    // events through the shared event bus so the
                    // GUI's MutationsModel tracks `hasInFlight`.
                    exec = exec.with_event_bus(Arc::clone(&event_bus));
                    // A `RulesResetToBaseline` deletes the
                    // caller's per-SID revisions and must recompile their
                    // live WFP filters from the now-effective baseline. Use
                    // the same orchestrator trigger `route.policy.update`
                    // uses; only when WFP/orchestrator is available.
                    if let Some(orch) = per_sid_orchestrator.as_ref() {
                        let trigger = build_apply_trigger(
                            orch,
                            &sid_registry,
                            route_coordinator.as_ref(),
                            pause_coordinator.as_ref(),
                        );
                        exec = exec.with_apply_trigger(trigger);
                    }
                    // Thread the pause coordinator
                    // so `safe_disable` performs the REAL enforcement teardown
                    // (per-active-SID remove + persisted pause) via routing-pause.
                    exec = exec.with_pause_coordinator(Arc::clone(coord));
                    // Administrative rules lock, enforced where mutations
                    // land — the IPC handler refuses the same submission
                    // earlier, this is the backstop.
                    exec = exec.with_stability_provider(Arc::new(
                        ProductionServiceStability::new(Arc::clone(conn)),
                    )
                        as Arc<dyn ServiceStabilityConfigProvider>);
                    Arc::new(exec) as Arc<dyn MutationExecutor>
                }
                None => {
                    Arc::new(nrr_service_runtime::NoopMutationExecutor) as Arc<dyn MutationExecutor>
                }
            },
            Arc::new(MutationTokenStore::new()),
            Arc::new(OperationStatusStore::default()),
            Arc::clone(&event_bus),
            Arc::new(ProductionRoutePolicyProvider::new(Arc::clone(conn)))
                as Arc<dyn RoutePolicyProvider>,
            Arc::new(ProductionRoutePolicyWriter::new(Arc::clone(conn)))
                as Arc<dyn RoutePolicyWriter>,
            Arc::new(ProductionMigrationStatusProvider::new(Arc::clone(conn)))
                as Arc<dyn MigrationStatusProvider>,
            Arc::new(ProductionMigrationCompletionWriter::new(Arc::clone(conn)))
                as Arc<dyn MigrationCompletionWriter>,
            // Settings (phase 1+2)
            Arc::new(ProductionRetentionSettings::new(Arc::clone(conn)))
                as Arc<dyn RetentionSettingsProvider>,
            Arc::new(
                ProductionRetentionSettings::new(Arc::clone(conn))
                    .with_event_bus(Arc::clone(&event_bus)),
            ) as Arc<dyn RetentionSettingsWriter>,
            // Log/audit retention config (provider + writer share the conn).
            Arc::new(ProductionLogRetentionConfig::new(Arc::clone(conn)))
                as Arc<dyn LogRetentionConfigProvider>,
            Arc::new(ProductionLogRetentionConfig::new(Arc::clone(conn)))
                as Arc<dyn LogRetentionConfigWriter>,
            Arc::new(ProductionApplyFailurePolicy::new(Arc::clone(conn)))
                as Arc<dyn ApplyFailurePolicyProvider>,
            Arc::new(apply_failure_writer) as Arc<dyn ApplyFailurePolicyWriter>,
            Arc::new(ProductionStorageUsage::new(
                artifacts.topology.state_db_path.clone(),
                cache_db_path,
                logs_dir_for_usage,
            )) as Arc<dyn StorageUsageProvider>,
            Arc::new(ProductionRoutingPause::new(
                Arc::clone(conn),
                Arc::clone(coord),
            )) as Arc<dyn RoutingPauseProvider>,
            Arc::new(
                ProductionRoutingPause::new(Arc::clone(conn), Arc::clone(coord))
                    .with_event_bus(Arc::clone(&event_bus)),
            ) as Arc<dyn RoutingPauseWriter>,
            Arc::new(ProductionAutostart::new(
                Arc::clone(conn),
                Arc::clone(&autostart_helper),
                tray_path.clone(),
            )) as Arc<dyn AutostartProvider>,
            Arc::new(
                ProductionAutostart::new(
                    Arc::clone(conn),
                    Arc::clone(&autostart_helper),
                    tray_path.clone(),
                )
                .with_event_bus(Arc::clone(&event_bus)),
            ) as Arc<dyn AutostartWriter>,
        )
        .with_alerts_repo(Arc::clone(&alerts_repo))
        // Service stability config. One ProductionServiceStability impl
        // satisfies both provider and writer traits; share via
        // Arc<Mutex<Connection>> with the rest of the settings providers.
        .with_service_stability(
            Arc::new(ProductionServiceStability::new(Arc::clone(conn)))
                as Arc<dyn ServiceStabilityConfigProvider>,
            Arc::new({
                let mut writer = ProductionServiceStability::new(Arc::clone(conn))
                    // The writer drives the live liveness
                    // window: a `set` applies it to the tracker without a restart.
                    .with_liveness_tracker(Arc::clone(&liveness_tracker))
                    // The writer also starts/stops
                    // the local DNS resolver on an `enforcement_mode` change,
                    // without a restart (Mode B live re-arm). Same shared
                    // controller the boot path arms.
                    .with_resolver_controller(Arc::clone(&dns_resolver_controller))
                    // A fake-IP toggle (or a mode
                    // flip) reconciles the TUN/relay stack live, no restart. The
                    // apply is offloaded to a thread: bringing the driver up can
                    // take seconds and must never stall the IPC reply (the
                    // writer's live-apply contract). The controller serialises
                    // concurrent applies internally, so racing toggles are safe.
                    // The replan after `apply` recompiles the active SIDs'
                    // WFP sets so the pool permit / real-IP suppression track
                    // the stack transition immediately (the codegen reads the
                    // fake-IP context live, but needs a compute to happen).
                    .with_fake_ip_apply({
                        let controller = Arc::clone(&fake_ip_controller);
                        let replan = Arc::clone(&fake_ip_replan);
                        Arc::new(move |req: FakeIpApplyRequest| {
                            let controller = Arc::clone(&controller);
                            let replan = Arc::clone(&replan);
                            std::thread::spawn(move || {
                                use nrr_platform_api::DnsCacheControlPort;
                                controller.apply(req.desired);
                                replan();
                                // Either direction of a REAL transition leaves
                                // the OS resolver cache full of answers from
                                // the previous world (real addresses when
                                // enabling, pool addresses when disabling —
                                // the latter are unreachable once the TUN
                                // route is gone). Flush so clients re-query
                                // instead of riding stale answers until their
                                // TTL expires — but ONLY when the writer
                                // reports a resolve-affecting change: a save
                                // that merely re-applies the current config
                                // must not trigger a machine-wide re-resolve
                                // wave (every CDN name re-queried at once).
                                if req.dns_flush_reasons.is_empty() {
                                    return;
                                }
                                let reason = req.dns_flush_reasons.join(",");
                                match nrr_platform_windows::WindowsDnsCacheControl::new()
                                    .flush_resolver_cache()
                                {
                                    Ok(()) => tracing::info!(
                                        target: "nrr::fake-ip",
                                        enabled = req.desired,
                                        reason = %reason,
                                        "flushed OS DNS resolver cache after fake-IP transition",
                                    ),
                                    Err(e) => tracing::warn!(
                                        target: "nrr::fake-ip",
                                        error = ?e,
                                        enabled = req.desired,
                                        reason = %reason,
                                        "OS DNS resolver cache flush after fake-IP transition failed — stale answers persist until TTL",
                                    ),
                                }
                            });
                        })
                    })
                    // DNS-over-secondary — a toggle stores into the shared
                    // process flag the query sockets and the route coordinator
                    // both read, so it takes effect on the next query and the
                    // next reconcile, with no restart.
                    .with_dns_via_secondary_flag(
                        nrr_service_runtime::dns_egress::global_dns_via_secondary(),
                    )
                    // Fast DNS answers — same live-flag contract: the Mode-B
                    // resolver reads it per query.
                    .with_dns_fast_answers_flag(
                        nrr_service_runtime::dns_resolver::global_dns_fast_answers(),
                    )
                    // Fake-IP UDP relay — unlike the flag-only toggles above,
                    // this changes the emitted `ks-fakeip-pool` WFP filters, so
                    // the hook both stores the new value into the shared live
                    // flag the per-SID codegen reads AND replans the active
                    // SIDs, reusing the same `fake_ip_replan` closure the
                    // fake-IP toggle drives above. Offloaded to a thread so
                    // the (possibly multi-SID) WFP recompute never stalls this
                    // IPC reply.
                    .with_udp_relay_apply({
                        let replan = Arc::clone(&fake_ip_replan);
                        Arc::new(move |desired: bool| {
                            nrr_service_runtime::fake_ip::global_udp_relay_enabled()
                                .store(desired, std::sync::atomic::Ordering::Relaxed);
                            let replan = Arc::clone(&replan);
                            std::thread::spawn(move || replan());
                        })
                    })
                    // Fake-IP instant reset — the dial path reads this flag
                    // fresh per dial and it never feeds WFP filter
                    // generation, so (unlike UDP relay above) storing the new
                    // value IS the whole live apply: no replan thread needed.
                    .with_instant_rst_flag(
                        nrr_service_runtime::fake_ip::global_instant_rst_enabled(),
                    )
                    // Same lightweight contract; same singleton the engine
                    // above reads.
                    .with_isp_block_candidates_flag(
                        nrr_service_runtime::auto_rules::global_isp_block_candidates_enabled(),
                    );
                // The writer also flips the LIVE tracing filter on
                // a `verbose_logging` change, without a restart. `None` on a
                // degraded boot (no log writer at startup) — the value still
                // persists and takes effect next restart, same as before.
                if let Some(handle) = verbosity_handle {
                    writer = writer
                        .with_verbosity_control(Arc::new(handle) as Arc<dyn VerbosityControl>);
                }
                writer
            }) as Arc<dyn ServiceStabilityConfigWriter>,
        )
        // Archive directory + app version for the
        // diagnostics export handler. Archives directory is a
        // sibling of `logs/` and `audit/` under `data_dir`.
        .with_archives_config(
            artifacts.topology.data_dir.join("archives"),
            env!("CARGO_PKG_VERSION").to_string(),
        )
        // Collect host system info (OS/CPU/RAM) once at the
        // composition root (only here, in the Windows binary, can we call the
        // Windows collector) so the diagnostic archive's system_info.json can
        // identify the reporting host.
        .with_system_info(nrr_platform_windows::system_info::collect())
        // Attach the state-schema
        // version read above (same `conn`) for `health.json`.
        .with_state_schema_version(state_schema_version)
        // Fail-Closed probe wired against the same
        // settings DB connection. Reads per-SID `route_bindings`
        // every call (no caching) so policy changes reflected in
        // subsequent SnapshotInterfacesGet responses without restart.
        .with_fail_closed_probe(
            Arc::new(nrr_service_runtime::ProductionFailClosedProbe::new(
                Arc::clone(conn),
            ))
                as Arc<dyn nrr_service_runtime::ipc_handlers::providers::FailClosedStateProbe>,
        )
        // Preset export source reads the active
        // revision via `RevisionsRepository` and projects it to
        // canonical rules-file txt bytes for the
        // `preset.export.get` IPC op.
        .with_preset_export_source(Arc::new(
            nrr_service_runtime::production_preset_exporter::ProductionPresetExporter::new(
                Arc::clone(conn),
            ),
        )
            as Arc<dyn nrr_service_runtime::production_preset_exporter::PresetExportSource>)
        // Merge-preview source reconciles the caller's linked
        // rules-file text with their active revision (per-SID read-through)
        // for the `rules.merge-preview` IPC op. Reuses the same state DB
        // connection as the preset exporter.
        .with_merge_preview_source(Arc::new(
            nrr_service_runtime::production_merge_preview::ProductionMergePreviewSource::new(
                Arc::clone(conn),
            ),
        )
            as Arc<dyn nrr_service_runtime::production_merge_preview::MergePreviewSource>)
        // Settings export source reads per-SID
        // `route_bindings` + behavior mode and emits docs/en/rules-file-format.md Settings Export Format
        // YAML for the `settings.export.full` IPC op. Clock stamps
        // the `exported_at` field.
        .with_settings_export_source(
            Arc::new(
                nrr_service_runtime::production_settings_exporter::ProductionSettingsExporter::new(
                    Arc::clone(conn),
                ),
            )
                as Arc<dyn nrr_service_runtime::production_settings_exporter::SettingsExportSource>,
            Arc::new(SystemClock) as Arc<dyn nrr_service_runtime::activation_coordinator::Clock>,
        )
        // Share the same status the per-SID orchestrator
        // publishes unresolved app rules into, so SnapshotInitial can surface
        // them to the GUI as a banner.
        .with_app_enforcement_status(app_enforcement.clone())
        // Same split for the smart-kill-switch shared-IP count.
        .with_shared_ip_exemption_status(shared_ip_exemptions.clone())
        // Same split for the block-all posture banner flag.
        .with_block_all_posture_status(block_all_posture.clone());
        // Wire the post-write recompile hook
        // so a routing-active user's `route.policy.update` recompiles their
        // WFP filters mid-session. Only when the orchestrator exists (WFP available); otherwise the
        // update stays persist-only and applies on the next tray connect.
        if let Some(orch) = per_sid_orchestrator.as_ref() {
            let trigger = build_apply_trigger(
                orch,
                &sid_registry,
                route_coordinator.as_ref(),
                pause_coordinator.as_ref(),
            );
            deps = deps.with_route_policy_apply_trigger(trigger);
        }
        // Wire the per-SID link-provider app writer so
        // `route.link-provider.set` resolves to the real handler (same
        // state-DB-backed impl as the route-policy writer).
        deps = deps.with_link_provider_writer(Arc::new(ProductionRoutePolicyWriter::new(
            Arc::clone(conn),
        ))
            as Arc<dyn nrr_service_runtime::ipc_handlers::providers::LinkProviderWriter>);
        // Wire the full-reset auxiliary-state purger, same shape as the
        // route-policy writer above.
        deps = deps.with_principal_data_purger(Arc::new(
            nrr_service_runtime::production_handlers_misc::ProductionPrincipalDataPurger::new(
                Arc::clone(conn),
            ),
        )
            as Arc<dyn nrr_service_runtime::ipc_handlers::providers::PrincipalDataPurger>);
        // Wire the shared DoH resolver baseline store so
        // `doh.resolvers.get` / `doh.resolvers.set` resolve to real handlers.
        deps = deps.with_doh_resolver_store(Arc::new(
            nrr_service_runtime::production_handlers_misc::ProductionDohResolverListStore::new(
                Arc::clone(conn),
            ),
        )
            as Arc<dyn nrr_service_runtime::ipc_handlers::doh_resolvers::DohResolverListStore>);
        // Wire the FQDN/IP cache repository so the
        // `cache.clear` IPC op can clear it. Only when the cache DB opened.
        if let Some(cache) = cache_store.clone() {
            deps = deps.with_cache_repository(cache);
        }
        // Wire the opt-in browser-history seeder so
        // `diagnostics.seed-from-browser-history` resolves to the real handler.
        // Only when the cache DB opened (nothing to cache into otherwise). The
        // seeded entries are picked up by the next periodic reconcile (like the
        // OS-cache seed), so no recompute hook is threaded here.
        if let Some(cache) = cache_store.clone() {
            let history: Arc<dyn nrr_platform_api::browser_history::BrowserHistoryReadPort> = {
                #[cfg(target_os = "windows")]
                {
                    Arc::new(nrr_platform_windows::WindowsBrowserHistoryRead::new())
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Arc::new(nrr_platform_api::browser_history::NoopBrowserHistoryRead)
                }
            };
            let rules: Arc<dyn RulesProvider> =
                Arc::new(ProductionRulesProvider::new(Arc::clone(conn)));
            let active_sid: nrr_service_runtime::dns_observation_consumer::ActiveSidFn = {
                let reg = Arc::clone(&sid_registry);
                let coord = route_coordinator.clone();
                Arc::new(move || {
                    coord
                        .as_ref()
                        .and_then(|c| c.effective_routing_sid(&reg.active_sids()))
                })
            };
            let resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort> =
                Arc::new(WindowsDnsResolver::new());
            let seeder = Arc::new(
                nrr_service_runtime::browser_history_seeder::BrowserHistorySeeder::new(
                    history,
                    rules,
                    Arc::clone(&active_sid),
                    resolver,
                    cache,
                ),
            );
            deps = deps.with_browser_history_seeder(Arc::clone(&seeder));
            // Opt-in AUTOMATIC seed at boot: when the active
            // SID's stored policy has `browser_history_auto_seed`, run ONE seed
            // pass without the manual button. Detached worker with a bounded
            // retry: the active SID resolves only once the session roster and
            // route coordinator settle after service start. Never elevates
            // above the manual path — same seeder, same rule gate.
            {
                let seeder = Arc::clone(&seeder);
                let policy_conn = Arc::clone(conn);
                let spawned = std::thread::Builder::new()
                    .name("nrr-bh-autoseed".into())
                    .spawn(move || {
                        for _ in 0..12 {
                            std::thread::sleep(std::time::Duration::from_secs(5));
                            let Some(sid) = active_sid() else { continue };
                            let enabled = policy_conn
                                .lock()
                                .ok()
                                .and_then(|guard| {
                                    nrr_storage::route_bindings::RouteBindingsRepository::new(
                                        &guard,
                                    )
                                    .load_for_sid(&sid)
                                    .ok()
                                })
                                .map(|r| r.browser_history_auto_seed)
                                .unwrap_or(false);
                            if enabled {
                                tracing::info!(
                                    target: "nrr::browser-history",
                                    "auto-seed opt-in enabled — running boot browser-history seed",
                                );
                                let _ = seeder.seed(std::time::SystemTime::now());
                            }
                            // SID resolved and the opt-in was consulted — done
                            // either way (one boot pass, not a periodic loop).
                            break;
                        }
                    });
                if let Err(e) = spawned {
                    tracing::warn!(
                        target: "nrr::browser-history",
                        error = %e,
                        "could not spawn boot browser-history auto-seed worker",
                    );
                }
            }
        }
        // Wire the OS resolver-cache flush port so the GUI's split
        // "clear OS DNS cache" button flushes the real OS cache (same
        // mechanism as the boot / block-all-edge flushes).
        deps = deps
            .with_dns_cache_control(Arc::new(nrr_platform_windows::WindowsDnsCacheControl::new()));
        // Wire the third-party binary inspector so the GUI
        // can show the user WHERE the shipped Wintun driver is, its SHA-256 and
        // who signed it, rather than only asserting that it is genuine.
        deps = deps.with_third_party_integrity(Arc::new(
            nrr_platform_windows::fake_ip::WindowsThirdPartyIntegrity::new(),
        ));
        // Wire the connection-trace ring so `conn-trace.entries.list`
        // serves recent observed connections (same Arc the observer feeds).
        if let Some(ring) = conn_trace_ring.clone() {
            deps = deps.with_conn_trace_ring(ring);
        }
        // Wire the sampler-backed traffic-counter provider + writer.
        if let Some(ts) = traffic_stats.as_ref() {
            deps = deps.with_traffic_stats(
                Arc::clone(ts) as Arc<dyn nrr_service_runtime::TrafficStatsProvider>,
                Arc::clone(ts) as Arc<dyn nrr_service_runtime::TrafficStatsWriter>,
            );
        }
        // Expected-route inputs for the conn-trace viewer: rules +
        // FQDN cache + routing-active SID. Each row then carries where policy
        // EXPECTS it to egress, so the GUI can flag a secondary-expected flow
        // that actually left over the primary.
        if let (Some(state_conn), Some(cache_arc)) = (settings_conn.as_ref(), cache_store.as_ref())
        {
            let rules: Arc<dyn nrr_service_runtime::per_sid_orchestrator::RulesProvider> =
                Arc::new(ProductionRulesProvider::new(Arc::clone(state_conn)));
            let fqdn: Arc<dyn FqdnCacheLookup> = Arc::new(SqliteFqdnCacheLookup::new(
                Arc::clone(cache_arc),
                FreshnessThresholds::default_production(),
            ));
            let active_sid: nrr_service_runtime::dns_observation_consumer::ActiveSidFn = {
                let reg = Arc::clone(&sid_registry);
                let coord = route_coordinator.clone();
                Arc::new(move || match coord.as_ref() {
                    Some(c) => c.effective_routing_sid(&reg.active_sids()),
                    None => reg.active_sids().first().cloned(),
                })
            };
            deps = deps.with_conn_trace_expectation(rules, fqdn, active_sid);
        }
        // Share the ONE assembly's read-only binding view so
        // the cache viewer and the synthetic explain probe surface the virtual
        // address a host currently resolves to. Same Arc the resolver / relay
        // draw from, so the address shown matches what is served.
        deps = deps.with_fake_ip_bindings(fake_ip_assembly.binding_view());
        // Live fake-IP datapath probe for `service.health.get` /
        // `snapshot.initial.get`, so the GUI can show "fake-IP is ON but the
        // datapath is down" instead of staying silent through an outage.
        // `datapath_status` takes only the controller's short-lived mutex —
        // cheap enough for the health side channel.
        deps = deps.with_fake_ip_datapath_probe({
            let controller = Arc::clone(&fake_ip_controller);
            Arc::new(move || controller.datapath_status())
        });
        // The SAME companion-discovery engine the observation feed
        // writes into and the proposal tick drives, so the tray's list/accept/
        // dismiss act on exactly the suggestions the service parked.
        if let Some(engine) = auto_rules_engine.as_ref() {
            deps = deps.with_auto_rules(Arc::clone(engine));
        }
        // Block-notice mutes: the durable store plus the SAME
        // `block_notice_center` the connection observer feeds, so a mute set
        // through IPC silences the very next matching episode.
        if let Some(store) = block_notice_mute_store.clone() {
            deps = deps.with_block_notice_mutes(store, Arc::clone(&block_notice_center));
        }
        // "Route this blocked host" — the SAME author the companion-domain
        // engine's accept path uses.
        if let Some(author) = block_notice_rule_author.clone() {
            deps = deps.with_block_notice_author(author);
        }
        register_production_handlers(&mut registry, Arc::new(deps));
    }
    // If the settings DB couldn't be opened (e.g. recovery path), the
    // registry stays empty — the supervisor will not transition to
    // `Running` because bootstrap was Blocking.

    let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
    let router = Arc::new(IpcRouter::new(
        registry,
        Arc::clone(&audit),
        MUTATION_QUEUE_CAPACITY,
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
            Arc::new(move || {
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
                if let Err(e) = coord.recompute_active(&tray_active) {
                    tracing::error!(
                        target: "nrr::route-coordinator",
                        "route recompute after DNS warm-up failed: {e:?}",
                    );
                }
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
                // Mode-B resolver watchdog (see above): re-arm the
                // resolver if it is enabled but its serve thread has died.
                dns_ctl.tick();
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
                    // it so future lookups are observable. Best-effort.
                    let seeded = consumer.seed_from_os_cache(std::time::SystemTime::now());
                    if seeded.matched > 0 {
                        tracing::info!(
                            target: "nrr::dns-observe",
                            matched = seeded.matched,
                            "boot seed from OS resolver cache before flush",
                        );
                    }
                    // The observer only sees WIRE
                    // queries; anything the OS resolver cached before this
                    // service start would stay invisible until its TTL
                    // expires (a name resolved pre-start would otherwise be
                    // absent from the FQDN cache and its zone→primary permit
                    // never built). Flush once at boot, right after the ETW session
                    // is live, so every next lookup re-queries observably.
                    use nrr_platform_windows::DnsCacheControlPort as _;
                    match nrr_platform_windows::WindowsDnsCacheControl::new().flush_resolver_cache()
                    {
                        Ok(()) => tracing::info!(
                            target: "nrr::dns-observe",
                            "flushed OS DNS resolver cache at observer start — pre-boot cached names will re-query and become observable",
                        ),
                        Err(e) => tracing::warn!(
                            target: "nrr::dns-observe",
                            error = ?e,
                            "OS DNS resolver cache flush at observer start failed — names cached before boot stay invisible until their TTL expires",
                        ),
                    }
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
        fcrdns_hook,
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
    if let Err(e) = nrr_platform_windows::dns_redirect::clear_orphan_redirect(
        &nrr_platform_windows::dns_redirect::PowerShellRunner,
    ) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            "Mode B: orphan NRPT cleanup at boot failed ({e})",
        );
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
    if let Some(stack_factory) = build_fake_ip_stack_factory(
        Arc::clone(&fake_ip_assembly),
        cache_store.as_ref(),
        settings_conn.as_ref(),
        active_routing_sid.as_ref(),
        route_coordinator.as_ref(),
        auto_rules_engine.as_ref(),
    ) {
        fake_ip_controller.set_factory(stack_factory);
    }
    // Relay datapath watchdog: guards against the stack thread staying
    // alive while the TUN below it silently stops delivering packets —
    // under block-all the relay is the machine's only escape hatch. The
    // controller compares the shared answers/ingress pulse every tick and
    // rebuilds the stack when answers keep flowing with zero ingress; after a
    // rebuild this worker re-runs the same replan + OS-cache flush a boot
    // bring-up does, so the pool permit and client caches match the fresh
    // adapter.
    fake_ip_controller.set_health(fake_ip_assembly.health());
    {
        let controller = Arc::clone(&fake_ip_controller);
        let replan = Arc::clone(&fake_ip_replan);
        let spawned = std::thread::Builder::new()
            .name("nrr-fakeip-watchdog".into())
            .spawn(move || {
                use nrr_platform_api::DnsCacheControlPort;
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    if controller.is_shut_down() {
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
        Some(Arc::clone(&fake_ip_assembly)),
        Some(Arc::clone(&fake_ip_running)),
        dns_egress_policy,
        auto_rules_engine.clone(),
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
    // Bring-up runs on its own thread so a slow driver never delays boot; the
    // fail-open gate keeps traffic on real addresses if it fails.
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
        stability: stability_config,
        // Audit files share `logs_dir`; clone before `logs_dir` moves.
        audit_dir: logs_dir.clone(),
        audit_retention,
        logs_dir,
        log_retention,
        cleanup_scope,
        state_db_conn: settings_conn,
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
        rebind_requests: Some(rebind_requests),
        secondary_liveness_hook,
        secondary_external_address,
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
    use nrr_platform_windows::ErrorClass;

    let api: Arc<dyn WindowsApiPort> = Arc::new(ProductionWindowsApi);

    // ── WFP filter sweep (the lockout risk) ────────────────────────────
    let session = match WfpSession::open(Arc::clone(&api)) {
        Ok(s) => s,
        Err(e) if e.classify() == ErrorClass::PrivilegeRequired => {
            eprintln!(
                "cleanup: access denied opening the WFP engine. Re-run from an elevated \
                 (Administrator) console (the `scripts/reset-network.ps1` wrapper \
                 self-elevates via UAC)."
            );
            return std::process::ExitCode::from(1);
        }
        Err(e) => {
            eprintln!("cleanup: could not open the WFP engine: {e:?}");
            return std::process::ExitCode::from(1);
        }
    };
    // `cleanup_all` enumerates every filter under the NRR provider GUID and
    // deletes it in one transaction (block AND permit) — the same sweep the
    // orchestrator's `cleanup_wfp` runs, minus the in-memory tracked-id pass
    // (there is no live orchestrator state to consult offline).
    let filters_removed = match session.cleanup_all() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("cleanup: WFP filter sweep failed: {e:?}");
            return std::process::ExitCode::from(1);
        }
    };
    // Release the engine handle before the route sweep (independent surface).
    drop(session);

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
                        Arc::clone(&api),
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
        &nrr_platform_windows::dns_redirect::PowerShellRunner,
    ) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "cleanup: NRPT/DNS-redirect sweep failed ({e:?}); if DNS is broken, remove the \
                 rule manually (`Get-DnsClientNrptRule | Where Comment -eq \
                 'NetRuleRouter-ModeB-DnsRedirect' | Remove-DnsClientNrptRule -Force`) or reboot."
            );
            false
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
        true => println!("  DNS redirect (NRPT) rules: cleared"),
        false => println!("  DNS redirect (NRPT) rules: <sweep failed — see above>"),
    }
    println!("Reboot to fully clear any remainder.");
    std::process::ExitCode::SUCCESS
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
    use nrr_platform_windows::dns_redirect::{capture_upstream_dns_v4, PowerShellRunner};
    use nrr_service_runtime::dns_resolver_ports::{
        ConsumerConfirmedHostSink, FcrdnsUpstreamResolver,
    };
    use nrr_service_runtime::fcrdns_learner::{LearnOutcome, ReverseDnsLearner};
    use std::time::{Duration, Instant};

    // Cap distinct IPs named per service run — a backstop against a drop storm
    // turning into a PTR/A query flood (each IP is attempted at most once anyway).
    const MAX_ATTEMPTS_PER_SESSION: usize = 512;

    type CapturedUpstream = Option<(Instant, Option<std::net::Ipv4Addr>)>;
    let captured: Mutex<CapturedUpstream> = Mutex::new(None);
    let upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync> =
        Arc::new(move || {
            let mut guard = captured.lock().unwrap_or_else(|p| p.into_inner());
            let fresh = matches!(&*guard, Some((at, _)) if at.elapsed() < Duration::from_secs(300));
            if !fresh {
                *guard = Some((Instant::now(), capture_upstream_dns_v4(&PowerShellRunner)));
            }
            guard
                .as_ref()
                .and_then(|(_, ip)| *ip)
                .map(|ip| std::net::SocketAddr::from((ip, 53)))
        });

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

fn build_conn_trace_pair(
    api: &Arc<dyn WindowsApiPort>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    ndjson_on: bool,
    trace_ring: Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>>,
    // When the FCrDNS worker is active, this
    // sender is the drop hook: OUR block of a routable V4 enqueues the IP for the
    // worker to name + forward-confirm. `None` disables reverse-learning.
    reverse_dns_learner_tx: Option<std::sync::mpsc::SyncSender<(std::net::Ipv4Addr, bool)>>,
    vpn_learning: VpnLearningDeps<'_>,
) -> (
    Option<Arc<dyn nrr_platform_windows::conn_observe::ConnectionObservationSource>>,
    Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionObservationConsumer>>,
) {
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
            Arc::clone(api),
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
    // Feed the connection-trace ring so the Diagnostics panel can read
    // recent connections (only wired when the GUI stream is on → ring is Some).
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
        consumer_builder = consumer_builder.with_vpn_endpoint_learner(learner);
        let registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        consumer_builder =
            consumer_builder.with_killswitch_drop_check(Arc::new(move |id| registry.contains(id)));
        // The same registry classifies the drop's blocking scope,
        // so the scope-bug detector can tell an app pin's expected first
        // contact from a destination pin that outran its route.
        let scope_registry = Arc::clone(vpn_learning.killswitch_drop_registry);
        consumer_builder = consumer_builder
            .with_killswitch_app_scope_check(Arc::new(move |id| scope_registry.is_app_scoped(id)));
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
        consumer_builder =
            consumer_builder.with_companion_primary_health(Arc::new(move |hostname, stalled| {
                let Some(sid) = sid_for_health() else {
                    return;
                };
                let event = if stalled {
                    nrr_domain::companion_affinity::PrimaryHealthEvent::Stalled
                } else {
                    nrr_domain::companion_affinity::PrimaryHealthEvent::Completed
                };
                engine_health.note_primary_health(&sid, hostname, event);
            }));
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

// ── Degraded policy manager ──────────────────────────────────────────────────

/// Fallback `PolicyManager` for the recovery-blocked path
/// (state DB couldn't be opened). All methods return safe defaults so
/// the snapshot/health handlers don't crash. Production startup with a
/// healthy DB always uses [`CoordinatorPolicyManager`] instead.
struct DegradedPolicyManager;

impl PolicyManager for DegradedPolicyManager {
    fn load_active(&self) -> nrr_service_runtime::state::ServicePolicyState {
        nrr_service_runtime::state::ServicePolicyState::RecoveryRequired
    }
    fn current_revision(&self) -> Option<nrr_service_runtime::state::ActiveRevisionState> {
        None
    }
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

    let conn = match Connection::open(path) {
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

    // Rebuildable ledger — any first-attempt open/migration failure (structural
    // corruption, stale migration checksum) deletes the DB with its WAL
    // sidecars and recreates it once inside the storage helper.
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
    match Connection::open(path) {
        Ok(conn) => {
            // Match the storage-layer baseline so concurrent reads with
            // `SqliteStateStore`'s connection don't race.
            let _: rusqlite::Result<()> =
                conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
            Some(Arc::new(Mutex::new(conn)))
        }
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
    // The shared fake-IP assembly + the "stack running?"
    // gate. Both absent leaves Mode B exactly as before fake-IP.
    fake_assembly: Option<Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>>,
    fake_ip_running: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    // DNS-over-secondary policy. `None` (no route coordinator) leaves every
    // query on the captured primary upstream, exactly as before.
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
    // Parked companion suggestions. Absent leaves the collateral rescue
    // unvetoed, exactly as before the port existed.
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
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
                fake_assembly.as_ref(),
                fake_ip_running.clone(),
                egress.clone(),
                auto_rules.clone(),
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
/// longer starve a rule of its routable public IP. The upstream capture runs
/// PowerShell, so it is memoized for 5 minutes per resolver instance. Missing
/// settings DB / no active user read as the DEFAULT posture (bypass ON).
fn build_hosts_bypass_resolver(
    settings_conn: Option<Arc<Mutex<Connection>>>,
    active_sid: Option<nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
) -> Arc<dyn nrr_platform_windows::dns::DnsResolverPort> {
    use nrr_platform_windows::dns_redirect::{capture_upstream_dns_v4, PowerShellRunner};
    use std::time::{Duration, Instant};

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
    type CapturedUpstream = Option<(Instant, Option<std::net::Ipv4Addr>)>;
    let captured: Arc<Mutex<CapturedUpstream>> = Arc::new(Mutex::new(None));
    let upstream: Arc<dyn Fn() -> Option<std::net::SocketAddr> + Send + Sync> =
        Arc::new(move || {
            let mut guard = captured.lock().unwrap_or_else(|p| p.into_inner());
            let fresh = matches!(&*guard, Some((at, _)) if at.elapsed() < Duration::from_secs(300));
            if !fresh {
                *guard = Some((Instant::now(), capture_upstream_dns_v4(&PowerShellRunner)));
            }
            guard
                .as_ref()
                .and_then(|(_, ip)| *ip)
                .map(|ip| std::net::SocketAddr::from((ip, 53)))
        });
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

/// Adapts the engine to `BlockedHostSinkFn` — a plain closure, since the
/// learner has no observer trait of its own.
fn isp_block_page_sink(
    engine: Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
) -> nrr_service_runtime::isp_block_page_learner::BlockedHostSinkFn {
    Arc::new(move |blocked: &str, _notice_page: &str| {
        let Some(sid) = active_sid() else {
            return;
        };
        engine.note_isp_blocked_host(&sid, blocked, std::time::SystemTime::now());
    })
}

#[allow(clippy::too_many_arguments)]
fn build_dns_resolver_instance(
    settings_conn: &Arc<Mutex<Connection>>,
    cache: &Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    active_sid: &nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
    hook: &nrr_service_runtime::supervised_runtime::RouteRecomputeHook,
    known_direct: Option<&Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    block_all_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fake_assembly: Option<&Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>>,
    fake_ip_running: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
) -> Option<nrr_service_runtime::dns_resolver_service::DnsResolverService> {
    use nrr_platform_windows::dns_redirect::{
        capture_upstream_dns_v4, NrptDnsRedirect, PowerShellRunner, SystemDnsRedirectPort,
    };
    use nrr_service_runtime::dns_listener::DnsInterceptListener;
    use nrr_service_runtime::dns_resolver_ports::{
        ActiveRuleHostOracle, CacheFactSink, DirectUdpUpstreamResolver, HookSyncReconciler,
    };
    use nrr_service_runtime::dns_resolver_service::DnsResolverService;
    use std::net::SocketAddr;
    use std::time::Duration;

    // Capture the real upstream DNS BEFORE redirecting. Without it the forward
    // path for non-rule queries would break general DNS — so refuse to arm.
    let upstream_ip = match capture_upstream_dns_v4(&PowerShellRunner) {
        Some(ip) => ip,
        None => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                "Mode B requested but no upstream IPv4 DNS could be captured; staying reactive",
            );
            return None;
        }
    };
    let upstream_dns = SocketAddr::from((upstream_ip, 53));

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
        DirectUdpUpstreamResolver::new(upstream_dns, Duration::from_millis(1500), 2);
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
    let upstream = Arc::new(poison_fallback);
    let sink = Arc::new(CacheFactSink::new(Arc::clone(cache)));
    let reconciler = Arc::new(HookSyncReconciler::new(hook.clone()));
    // Direct-answer steering: replies for non-rule
    // hosts are filtered against the secondary-pinned set so a shared-CDN host
    // (www.google.com vs gemini/youtube) gets clean addresses that stay on the
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

    let mut listener = DnsInterceptListener::new(
        oracle,
        upstream,
        sink,
        Arc::clone(&reconciler) as Arc<dyn nrr_service_runtime::dns_resolver::SyncReconciler>,
        upstream_dns,
        // Latency budget → fail-open on slow reconcile. Measured on real
        // hardware, the reconcile hook takes roughly 150-900 ms; a smaller
        // budget fails open on most rule-host answers — every first-seen
        // host's first connect races ahead of its route and egresses the
        // wrong link. 900 ms matches the direct-gate budget below and stalls
        // only the querying host's own answer.
        Duration::from_millis(900),
        Duration::from_millis(2000), // forward timeout for non-intercepted queries
    )
    .with_direct_answer_steering(secondary_owned);
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
        let answerer: Arc<dyn nrr_service_runtime::dns_resolver::FakeIpAnswerer> =
            Arc::new(nrr_service_runtime::dns_resolver::GatedFakeIpAnswerer::new(
                Arc::new(assembly.answerer()),
                Arc::clone(&running),
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
    // The learner always observes (diagnostics-only); with an engine wired,
    // a blocked host also reaches it as an auto-rules candidate.
    {
        let mut observer =
            nrr_service_runtime::isp_block_page_learner::LearningResolutionObserver::new(
                nrr_service_runtime::isp_block_page_learner::global_isp_block_page_learner(),
            );
        if let Some(engine) = auto_rules.as_ref() {
            observer = observer.with_blocked_host_sink(isp_block_page_sink(
                Arc::clone(engine),
                Arc::clone(active_sid),
            ));
        }
        listener = listener.with_resolution_observer(Arc::new(observer));
    }
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
    let redirect: Arc<dyn SystemDnsRedirectPort> = Arc::new(NrptDnsRedirect::new(PowerShellRunner));
    let listen_addr = SocketAddr::from(([127, 0, 0, 1], 53));
    tracing::info!(
        target: "nrr::dns-resolver",
        upstream = %upstream_dns,
        "Mode B armed: local DNS resolver will bind 127.0.0.1:53 and forward non-rule \
         queries to the captured upstream",
    );
    Some(DnsResolverService::new(listener, redirect, listen_addr))
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

//! Linux counterpart of `windows-service/runtime_deps.rs`: assembles the
//! [`SupervisedRuntimeDeps`] the shared supervised runtime consumes.
//!
//! The runtime body itself is OS-neutral and already used by Windows; what was
//! missing on Linux was this wiring, which is why the daemon sat in an idle
//! watchdog loop. With it, Linux gets the same supervisor, the same health
//! aggregation, the same IPC accept task and the same retention jobs.
//!
//! ## What is wired and what is honestly absent
//!
//! Wired: health, IPC, adapter monitoring, operation-status GC, log and audit
//! retention, and the enforcement cycle — logind names who is present, the
//! per-principal store supplies their rules, nftables applies the lot in one
//! pass.
//!
//! The recompute hook is the enforcement cycle's own pass, so every neutral
//! caller that knows a re-arm is due — the adapter monitor, the safety tick, the
//! netlink change observer, the resume watchdog — drives the SAME pass the timer
//! drives, and a tunnel coming up is enforced in the debounce window rather than
//! at the next ten-second tick. Graceful stop tears the policy back out through
//! the same object.
//!
//! Absent, with `None` rather than a stub: DNS refresh (no Linux resolver
//! mechanism yet), the observation consumers, and the power observer (the
//! neutral resume watchdog covers a wake a few seconds later). What that costs
//! is concrete rather than abstract: rules naming a domain are enforced only for
//! addresses already in the FQDN cache, and the catch-all kill-switch is NOT
//! part of the plan yet — the daemon states both on every apply instead of
//! implying full coverage.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::Arc;

use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
use nrr_domain::enforcement_mode::EnforcementMode;
use nrr_platform_api::adapters::AdapterMonitor;
use nrr_platform_api::network_change::NetworkChangeObserver;
use nrr_platform_linux::network_change::LinuxNetworkChangeObserver;
use nrr_service_runtime::bootstrap::BootstrapArtifacts;
use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
use nrr_service_runtime::service_stability::ServiceStabilityConfig;
use nrr_service_runtime::service_tasks::{AppObservationWiring, DnsObservationWiring};
use nrr_service_runtime::supervised_runtime::{RouteRecomputeHook, SupervisedRuntimeDeps};
use nrr_service_runtime::{HealthAggregator, IpcServer};

use crate::unix_socket_server::UnixDomainSocketServer;

use nrr_platform_api::enforcement::{EgressBindingSource, PolicyEnforcer};
use nrr_platform_linux::logind::LogindActivePrincipals;
use nrr_platform_linux::nft_policy_enforcer::NftPolicyEnforcer;
use nrr_service_runtime::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use nrr_service_runtime::dns_observation_consumer::DnsObservationConsumer;
use nrr_service_runtime::per_sid_orchestrator::{RoutePolicySource, RulesProvider};
use nrr_service_runtime::principal_enforcement::{PrincipalEnforcementCycle, PrincipalPlanSource};
use nrr_service_runtime::production_handlers_misc::ProductionRoutePolicySource;
use nrr_service_runtime::production_principal_plan::{
    cache_lookup_over, open_cache_store, open_state_connection, ProductionPrincipalPlanSource,
    StoredEgressBindings,
};
use nrr_service_runtime::production_rules_provider::ProductionRulesProvider;
use nrr_service_runtime::route_apply::PlannedRouteApplier;
use nrr_service_runtime::rule_hostname_seeder::RuleHostnameSeeder;
use nrr_service_runtime::secondary_liveness::SecondaryLivenessTracker;

/// Debounce for adapter state changes, in milliseconds. Matches the Windows
/// wiring: a link that flaps must not produce a burst of recomputes.
const ADAPTER_DEBOUNCE_MS: u64 = 500;

/// Build the dependency bundle for the Linux daemon.
///
/// `health` is passed in rather than created here so the IPC health handler and
/// the supervisor share ONE aggregator. Two instances is a bug the Windows side
/// already paid for: IPC reported `starting` with no components forever, because
/// the aggregator being filled was not the one being read.
pub(crate) fn build_runtime_deps(
    artifacts: &BootstrapArtifacts,
    health: Arc<HealthAggregator>,
    ipc_server: Arc<dyn IpcServer>,
    event_bus: Arc<EventBus>,
    policy: Option<PolicyStack>,
    dns_observation: Option<DnsObservationWiring>,
    adapter_source: Arc<nrr_platform_linux::adapters::LinuxAdapterSource>,
) -> SupervisedRuntimeDeps {
    // The policy layer arrives whole rather than field by field: every piece of
    // it is present or absent together, and splitting it into arguments invited
    // a caller to pass half of one.
    let (
        enforcement,
        app_observations,
        cache_store,
        rule_seeder,
        state_conn,
        liveness,
        rules_provider,
        auto_rules,
    ) = match policy {
        Some(stack) => (
            Some(stack.cycle),
            Some(stack.app_observations),
            Some(stack.cache_store),
            Some(stack.rule_seeder),
            Some(stack.state_conn),
            Some(stack.liveness),
            Some(stack.rules),
            Some(stack.auto_rules),
        ),
        None => (None, None, None, None, None, None, None, None),
    };
    // One source, two readers: the monitor that reports link changes and the
    // enforcer that resolves bindings against them. Two enumerations would let
    // the pair disagree about the same machine.
    let adapter_monitor = Arc::new(AdapterMonitor::new(
        Arc::clone(&adapter_source) as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
        ADAPTER_DEBOUNCE_MS,
    ));

    // One pass, many callers. The hook is the cycle's own tick, so a link
    // change, a wake and the safety tick all converge on the object that
    // serialises passes rather than each recomputing its own view.
    let recompute_hook: Option<RouteRecomputeHook> = enforcement.as_ref().map(|cycle| {
        let cycle = Arc::clone(cycle);
        Arc::new(move || {
            cycle.tick_logged("recompute");
        }) as RouteRecomputeHook
    });
    // Stopping must restore the machine: policy left in the kernel by an exited
    // daemon is policy nothing maintains, and its leak-guard `drop` would
    // outlive the service that could explain it.
    let teardown_hook: Option<RouteRecomputeHook> = enforcement.as_ref().map(|cycle| {
        let cycle = Arc::clone(cycle);
        Arc::new(move || {
            if let Err(reason) = cycle.teardown() {
                tracing::error!(
                    target: "nrr::enforcement",
                    reason = %reason,
                    "policy could NOT be removed on stop: the machine may still be enforcing rules no service is maintaining",
                );
            } else {
                tracing::info!(
                    target: "nrr::enforcement",
                    "policy removed on stop: filters and owned routes are gone",
                );
            }
        }) as RouteRecomputeHook
    });

    let logs_dir: PathBuf = artifacts.topology.logs_dir.clone();
    // On Linux the two diverge, unlike Windows where both sit under the data
    // root: logs follow FHS into /var/log, while the audit trail stays under
    // /var/lib with the state it attests to — deliberately out of reach of a
    // logrotate config scoped to /var/log.
    let audit_dir: PathBuf = artifacts.topology.data_dir.join("audit");

    SupervisedRuntimeDeps {
        health,
        ipc_server,
        adapter_monitor,
        operation_results: Arc::default(),
        stability: ServiceStabilityConfig::default(),
        logs_dir,
        log_retention: LogRetentionPolicy::default(),
        // Operational logs only: the cleanup job must never touch the audit
        // trail or exported archives, and saying so explicitly beats relying on
        // a default that could change.
        cleanup_scope: ManualCleanupScope {
            operational_logs: true,
            diagnostic_temp_data: false,
            exported_archives: false,
        },
        audit_dir,
        audit_retention: AuditRetentionPolicy::default(),
        state_db_conn: None,
        principal_enforcement: enforcement,
        // Counting octets per interface: the mechanism has existed since the
        // adapter port landed and was simply never called here, so the traffic
        // page had nothing to show on Linux.
        traffic_tick: traffic_tick(artifacts, state_conn.as_ref()),
        activation_coordinator: None,
        // Domain rules are only as current as the addresses behind them: without
        // this the cache never refreshes, and a rule naming a domain enforces
        // whatever addresses happened to be known when they were first learnt.
        dns_refresh_orchestrator: cache_store.map(|store| {
            Arc::new(
                nrr_service_runtime::dns_refresh::DnsRefreshOrchestrator::new(
                    Arc::new(nrr_platform_linux::dns_resolver::LinuxDnsResolver::new()),
                    store,
                ),
            )
        }),
        route_recompute_hook: recompute_hook.clone(),
        route_teardown_hook: teardown_hook,
        // Both need the per-principal orchestrator's seeding path, which is not
        // ported. `None` skips the task; a stub would have the daemon claim work
        // it does not do.
        rule_hostname_seeder: rule_seeder,
        // Windows names ONE console user here; on Linux the answer is a list, so
        // the neutral tasks read `present_principals` below instead.
        active_routing_sid: None,
        dns_observation_source: None,
        dns_observation_consumer: None,
        conn_observation_source: None,
        conn_observation_consumer: None,
        // The same engine the observation consumer feeds, so the slow proposal
        // tick and anything reading suggestions see one state rather than two.
        auto_rules_engine: auto_rules,
        secondary_external_address: None,
        dns_resolver_controller: None,
        // Reactive: the local resolver is a Windows mechanism today, so booting
        // in `Resolver` mode would arm something that does not exist here.
        dns_resolver_boot_mode: EnforcementMode::default(),
        // Same bus the socket server drains, so the adapter monitor's
        // `AdaptersChanged` actually reaches a subscribed GUI instead of being
        // published into nothing.
        event_bus: Some(event_bus),
        // The kernel's own change feed: a tunnel coming up re-arms policy in
        // the debounce window instead of waiting out the tick.
        network_change_observer: recompute_hook
            .is_some()
            .then(|| Arc::new(LinuxNetworkChangeObserver) as Arc<dyn NetworkChangeObserver>),
        // An `Up` interface says nothing about the path behind it: a tunnel whose
        // peer is gone still presents one. The probe asks the tunnel's own next
        // hop and feeds the tracker the enforcer reads.
        secondary_liveness_hook: match (state_conn.as_ref(), liveness) {
            (Some(conn), Some(tracker)) => Some(secondary_liveness_hook(
                conn,
                Arc::clone(&adapter_source)
                    as Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
                tracker,
            )),
            _ => None,
        },
        // No Linux suspend/resume mechanism yet. The neutral resume watchdog
        // below still recovers from a wake — just a few seconds later.
        power_event_observer: None,
        rebind_requests: recompute_hook
            .is_some()
            .then(|| Arc::new(nrr_service_runtime::power_resume::RebindRequests::new())),
        // Application rules learn their destinations from the connections the
        // programs make: procfs lists the sockets, and the store is the same one
        // the planner reads.
        app_observation: app_observations.as_ref().map(|store| AppObservationWiring {
            source: Arc::new(nrr_platform_linux::conn_observe::ProcfsConnectionObserver::new()),
            store: Arc::clone(store),
        }),
        // What those applications talked to LAST session. Without it every
        // restart starts cold, and an app rule enforces nothing until the
        // program happens to connect again.
        app_destination_memory: match (app_observations, state_conn.as_ref(), rules_provider) {
            (Some(store), Some(conn), Some(rules)) => {
                Some(app_destination_memory(store, rules, conn))
            }
            _ => None,
        },
        dns_observation,
        // logind is the authority on who is logged in, and every per-user task
        // acts for all of them rather than for whoever happens to be first.
        present_principals: Some(Arc::new(LogindActivePrincipals)),
    }
}

/// Build the production IPC server for the daemon.
///
/// With the policy layer present the socket answers the FULL operation set;
/// without it (no state database) it falls back to the handshake trio, because
/// a registry whose providers cannot read anything would answer every question
/// with a plausible-looking blank.
pub(crate) fn build_ipc_server(
    artifacts: &BootstrapArtifacts,
    health: Arc<HealthAggregator>,
    event_bus: Arc<EventBus>,
    stack: Option<&PolicyStack>,
) -> Arc<dyn IpcServer> {
    let registry = match stack {
        Some(stack) => {
            let surface = crate::ipc_deps::build_ipc_surface(
                Arc::clone(&stack.state_conn),
                open_state_connection(&artifacts.topology.cache_db_path),
                artifacts.topology.data_dir.clone(),
                artifacts.topology.logs_dir.clone(),
                artifacts.topology.data_dir.join("audit"),
                artifacts.topology.state_db_path.clone(),
                artifacts.topology.cache_db_path.clone(),
                artifacts.audit_writer.clone(),
                Arc::new(nrr_platform_linux::LinuxApi),
                Arc::clone(&stack.cycle),
                Arc::clone(&health),
                Arc::clone(&event_bus),
                gui_binary_path(),
                Some(Arc::clone(&stack.auto_rules)),
            );
            let mut registry = nrr_service_runtime::IpcHandlerRegistry::new();
            nrr_service_runtime::ipc_handlers::register_production_handlers(
                &mut registry,
                surface.deps,
            );
            registry
        }
        None => {
            tracing::error!(
                target: "nrr::ipc",
                "no state database: only the handshake, subscription and health operations \
                 are served — the GUI will show the service as needing recovery",
            );
            crate::run::serving_registry_with(health, Arc::clone(&event_bus))
        }
    };
    // polkit answers "may this user do this" for callers who cannot elevate
    // themselves — which on this platform is everyone but root. Without it a
    // privileged operation from a normal desktop session has no path at all.
    let router = Arc::new(
        nrr_service_runtime::IpcRouter::new(
            registry,
            Arc::new(nrr_service_runtime::NoopIpcAuditEmitter),
            1,
        )
        .with_authority(Arc::new(nrr_platform_linux::polkit::PolkitAuthority)),
    );
    Arc::new(UnixDomainSocketServer::new(router).with_event_bus(event_bus))
}

/// Remember what routed applications talked to, so the next session's routes
/// exist before those applications connect again.
///
/// Warm-loaded here, before the first pass: the whole point is that the routes
/// are already in place when the program dials, and a load that happened after
/// the first apply would be one session late every time.
fn app_destination_memory(
    observations: Arc<AppObservationStore>,
    rules: Arc<dyn RulesProvider>,
    state_conn: &Arc<std::sync::Mutex<rusqlite::Connection>>,
) -> Arc<nrr_service_runtime::app_destination_memory::AppDestinationMemory> {
    use nrr_platform_api::active_principals::ActivePrincipalSource;
    use nrr_storage::app_destinations::AppDestinationsRepository;

    let unix_millis = |at: std::time::SystemTime| {
        at.duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    };
    let memory = Arc::new(
        nrr_service_runtime::app_destination_memory::AppDestinationMemory::new(
            observations,
            rules,
            Arc::new(|| match LogindActivePrincipals.active_principals() {
                Ok(principals) => principals
                    .iter()
                    .map(|p| p.as_stored().to_owned())
                    .collect(),
                Err(_) => Vec::new(),
            }),
            {
                let conn = Arc::clone(state_conn);
                Arc::new(move |app: &str, ips: &[std::net::Ipv4Addr], now| {
                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                    if let Err(e) =
                        AppDestinationsRepository::new(&guard).upsert(app, ips, unix_millis(now))
                    {
                        tracing::warn!(
                            target: "nrr::app-routing",
                            error = %e,
                            "application destinations could not be persisted — continuing",
                        );
                    }
                })
            },
            {
                let conn = Arc::clone(state_conn);
                Arc::new(move |cutoff| {
                    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                    let repo = AppDestinationsRepository::new(&guard);
                    let cutoff = unix_millis(cutoff);
                    // Rows past the window can never be enforced again, so the
                    // read is also where they go — no retention task of its own.
                    let _ = repo.prune_before(cutoff);
                    repo.load_confirmed_since(cutoff).unwrap_or_default()
                })
            },
        ),
    );
    let admitted = memory.warm_load(std::time::SystemTime::now());
    if admitted > 0 {
        tracing::info!(
            target: "nrr::app-routing",
            admitted,
            "application destinations restored from the previous session",
        );
    }
    memory
}

/// The liveness probe: ask each present principal's tunnel whether it is still
/// there, and feed the answer to the tracker.
///
/// Probing the tunnel's own next hop, not a public address: the question is
/// whether the path through this link works, and a public target would also fail
/// when the far side's internet is down — a different fault with a different
/// remedy. An interface with no gateway (the usual point-to-point tunnel) has no
/// next hop to ask, so it is left unprobed rather than guessed at.
fn secondary_liveness_hook(
    state_conn: &Arc<std::sync::Mutex<rusqlite::Connection>>,
    adapters: Arc<dyn nrr_platform_api::adapters::AdapterEventSource>,
    tracker: Arc<SecondaryLivenessTracker>,
) -> RouteRecomputeHook {
    use nrr_platform_api::active_principals::ActivePrincipalSource;
    use nrr_platform_api::reachability::ReachabilityProbe;

    let conn = Arc::clone(state_conn);
    Arc::new(move || {
        // Nothing to decide while the feature is off; the probe stays silent
        // rather than filling the tracker with evidence nobody reads.
        if tracker.window_secs() == 0 {
            return;
        }
        let Ok(principals) = LogindActivePrincipals.active_principals() else {
            return;
        };
        let Ok(links) = adapters.enumerate_all() else {
            return;
        };
        let probe = nrr_platform_linux::reachability::LinuxIcmpProbe;
        let mut probed: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for principal in principals {
            let bound = {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                nrr_storage::RouteBindingsRepository::new(&guard)
                    .load_for_sid(principal.as_stored())
                    .ok()
                    .and_then(|policy| policy.secondary.map(|b| b.display_name))
            };
            let Some(name) = bound else { continue };
            let Some(link) = links
                .iter()
                .find(|a| a.friendly_name == name || a.adapter_name == name)
            else {
                continue;
            };
            // Two users on one tunnel ask once: the answer is about the link.
            if !probed.insert(link.index) {
                continue;
            }
            let Some(next_hop) = link.gateways.first().copied() else {
                continue;
            };
            let reachable = probe.is_reachable(next_hop, LIVENESS_PROBE_TIMEOUT);
            tracker.record(link.index, reachable, std::time::Instant::now());
        }
    })
}

/// How long the tunnel's next hop gets to answer. Short: the tick runs every few
/// seconds, and a probe that outlives its own interval measures nothing.
const LIVENESS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(800);

/// Assemble the traffic-counter tick, or `None` when there is nothing to count
/// into.
///
/// The role resolver reads the bindings of the FIRST principal logind reports.
/// The ledger counts a machine's interfaces, and a role is a per-user idea: with
/// two users bound to different additional links the same interface would carry
/// two roles at once. Naming the first present user keeps the figures readable
/// and matches the single-user shape the free tier is built around; a
/// multi-user ledger is a product decision, not a wiring one.
fn traffic_tick(
    artifacts: &BootstrapArtifacts,
    state_conn: Option<&Arc<std::sync::Mutex<rusqlite::Connection>>>,
) -> Option<nrr_service_runtime::TrafficTickDeps> {
    use nrr_platform_api::active_principals::ActivePrincipalSource;

    let state_conn = state_conn?;
    let sampler = open_traffic_sampler(&artifacts.topology.traffic_db_path)?;

    let roles: nrr_service_runtime::TrafficRoleResolver = {
        let conn = Arc::clone(state_conn);
        Arc::new(move || {
            let Ok(principals) = LogindActivePrincipals.active_principals() else {
                return (None, None);
            };
            let Some(principal) = principals.first() else {
                return (None, None);
            };
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            match nrr_storage::RouteBindingsRepository::new(&guard)
                .load_for_sid(principal.as_stored())
            {
                Ok(policy) => (
                    policy.primary.map(|b| b.display_name),
                    policy.secondary.map(|b| b.display_name),
                ),
                Err(_) => (None, None),
            }
        })
    };
    let settings: nrr_service_runtime::TrafficSettingsResolver = {
        let access = nrr_service_runtime::production_traffic::ProductionTrafficSettings::new(
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
        sampler,
        roles,
        settings,
        timezone: Arc::new(nrr_platform_linux::local_time::LinuxTimeZone),
    })
}

/// Open the rebuildable traffic ledger and prime a sampler over the Linux
/// interface counters.
///
/// `None` disables the counter rather than failing the daemon: a machine with a
/// broken ledger still routes, and traffic figures are the one thing here that
/// can be recomputed by simply counting again.
fn open_traffic_sampler(
    path: &std::path::Path,
) -> Option<Arc<std::sync::Mutex<nrr_service_runtime::traffic_sampler::TrafficSampler>>> {
    use nrr_platform_linux::interface_traffic::LinuxInterfaceCounterSource;
    use nrr_service_runtime::traffic_sampler::TrafficSampler;
    use nrr_storage::SqliteTrafficStore;

    let opened = match nrr_storage::open_traffic_connection_or_rebuild(path) {
        Ok(opened) => opened,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                path = %path.display(),
                "traffic-stats DB unavailable; the traffic counter is off",
            );
            return None;
        }
    };
    if let Some(reason) = &opened.rebuilt_reason {
        tracing::info!(
            target: "nrr::runtime",
            path = %path.display(),
            reason = %reason,
            "traffic-stats DB was recreated after an open/migration failure",
        );
    }
    let source = Arc::new(LinuxInterfaceCounterSource::new())
        as Arc<dyn nrr_platform_api::InterfaceCounterSource>;
    match TrafficSampler::new(source, SqliteTrafficStore::new(opened.connection)) {
        Ok(sampler) => Some(Arc::new(std::sync::Mutex::new(sampler))),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                error = %e,
                "traffic sampler could not be primed; the traffic counter is off",
            );
            None
        }
    }
}

/// The GUI binary an autostart entry should point at.
///
/// Derived from the product identity rather than typed here, and resolved next
/// to the daemon: a packaged install puts the two side by side, and pointing an
/// autostart entry at a path nobody ships is worse than declining to write one.
fn gui_binary_path() -> std::path::PathBuf {
    let leaf = nrr_shared::product_identity::BinaryRole::Gui.host_file_name();
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(leaf)))
        .unwrap_or_else(|| std::path::PathBuf::from(leaf))
}

/// The policy layer, built once and shared by everything that acts on it.
///
/// One connection and one cycle, deliberately: the timer pass and the pass the
/// GUI triggers on apply must be the same object, or the two would race to
/// replace the same table with plans read at different moments.
pub(crate) struct PolicyStack {
    pub state_conn: Arc<std::sync::Mutex<rusqlite::Connection>>,
    /// Resolutions behind domain rules: the planner reads it, the DNS refresher
    /// keeps it current.
    pub cache_store: Arc<std::sync::Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    /// What applications have been seen connecting to — the expression of an
    /// application rule on a platform whose filter engine has no app context.
    pub app_observations: Arc<AppObservationStore>,
    /// The per-principal rule book, shared with everything that needs to know
    /// which applications are routed where.
    pub rules: Arc<dyn RulesProvider>,
    /// Companion-domain discovery: what the observed resolutions suggest the
    /// user might want a rule for. Suggests only — the mode decides whether
    /// anything is ever authored.
    pub auto_rules: Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    /// Verdict on whether each bound tunnel is still carrying traffic. Written
    /// by the liveness tick, read by the enforcer when it decides whether the
    /// additional link is available.
    pub liveness: Arc<SecondaryLivenessTracker>,
    /// Resolves the hostnames of a principal's rules into the cache before
    /// anything connects to them — without it a domain rule enforces nothing
    /// until something else happens to resolve the name.
    pub rule_seeder: Arc<RuleHostnameSeeder>,
    /// Folds observed resolutions into the cache, on behalf of whichever
    /// principal the caller names.
    pub dns_consumer: Arc<DnsObservationConsumer>,
    /// Which principal the consumer is acting for. Set immediately before each
    /// call: a resolution belongs to the machine, and every present user's rules
    /// get a look at it.
    pub dns_consumer_subject: Arc<std::sync::Mutex<Option<String>>>,
    pub cycle: Arc<PrincipalEnforcementCycle>,
}

/// Assemble the policy stack, or explain why the daemon cannot enforce.
///
/// `None` is returned only when the state database is unreachable — without it
/// there are no rules to apply, and a cycle over an empty store would flush the
/// table on every tick, which is a policy decision nobody made.
pub(crate) fn build_policy_stack(
    artifacts: &BootstrapArtifacts,
    adapters: Arc<nrr_platform_linux::adapters::LinuxAdapterSource>,
) -> Option<PolicyStack> {
    let conn = open_state_connection(&artifacts.topology.state_db_path)?;
    let state_conn = Arc::clone(&conn);
    let conn_for_stability = Arc::clone(&conn);

    let policy: Arc<dyn RoutePolicySource> =
        Arc::new(ProductionRoutePolicySource::new(Arc::clone(&conn)));
    let rules: Arc<dyn RulesProvider> = Arc::new(ProductionRulesProvider::new(conn));
    let rules_for_stack = Arc::clone(&rules);

    // No cache means domain rules resolve to nothing. Said out loud here,
    // because the plans that follow would otherwise look complete while
    // silently covering only the literal-IP rules.
    // One store, two users: the planner reads resolutions out of it and the
    // refresher writes them in. Two connections would be two writers of one
    // SQLite file.
    let cache_store = match open_cache_store(&artifacts.topology.cache_db_path) {
        Some(store) => store,
        None => {
            tracing::error!(
                target: "nrr::enforcement",
                "no FQDN cache: rules naming a domain will be enforced for NO addresses",
            );
            return None;
        }
    };
    let fqdn_cache = cache_lookup_over(Arc::clone(&cache_store));

    // The same resolver the refresh task uses, pointed at the rule book instead
    // of at expiring cache rows: one asks "what is this name now", the other
    // "what are the names my rules mention".
    let rule_seeder = Arc::new(RuleHostnameSeeder::new(
        Arc::new(nrr_platform_linux::dns_resolver::LinuxDnsResolver::new()),
        Arc::clone(&cache_store),
        Arc::clone(&fqdn_cache),
        Arc::clone(&rules),
    ));

    // The consumer matches an observed name against a principal's rules, and asks
    // WHICH principal through a callback. With several users present the answer
    // differs per call, so the subject is a slot the caller sets rather than a
    // choice made once here.
    let dns_consumer_subject: Arc<std::sync::Mutex<Option<String>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Discovery reads the SAME observations the cache does: a suggestion the
    // user sees must come from the resolutions that actually happened, not from
    // a second, differently-filtered stream.
    let auto_rules = Arc::new(nrr_service_runtime::auto_rules::AutoRulesEngine::new(
        Arc::clone(&rules),
        {
            let conn = Arc::clone(&state_conn);
            Arc::new(move |sid: &str| {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
                    .load_for_sid(sid)
                    .map(|record| record.auto_rules_mode)
                    // A read failure must not widen what the service may do
                    // on the user's behalf: the default suggests and applies
                    // nothing.
                    .unwrap_or_default()
            })
        },
        Arc::new(nrr_service_runtime::auto_rules::SqliteDismissalStore::new(
            Arc::clone(&state_conn),
        )),
        Arc::new(nrr_service_runtime::auto_rules::SqlitePendingStore::new(
            Arc::clone(&state_conn),
        )),
        std::time::SystemTime::now(),
    ));

    let dns_consumer = {
        let subject = Arc::clone(&dns_consumer_subject);
        Arc::new(
            DnsObservationConsumer::new(
                Arc::clone(&rules),
                Arc::clone(&cache_store),
                Arc::clone(&fqdn_cache),
                Arc::new(move || subject.lock().unwrap_or_else(|p| p.into_inner()).clone()),
            )
            .with_auto_rules(Arc::clone(&auto_rules)),
        )
    };

    let bindings: Arc<dyn EgressBindingSource> =
        Arc::new(StoredEgressBindings::new(Arc::clone(&policy)));
    // One source object behind every reader — the filter path, the route path
    // and the exemption reader must see the same machine.
    let adapter_port: Arc<dyn nrr_platform_api::adapters::AdapterEventSource> = adapters;

    // One store, two readers: the tick that learns destinations and the planner
    // that turns them into flows. Two would mean the planner reading a memory
    // nobody fills — which is what "app rules do nothing" looked like.
    let app_observations = Arc::new(AppObservationStore::new());
    let plans: Arc<dyn PrincipalPlanSource> = Arc::new(
        ProductionPrincipalPlanSource::new(
            rules,
            Arc::clone(&policy),
            fqdn_cache,
            Arc::new(nrr_platform_linux::app_path_resolver::LinuxAppPathResolver),
            Arc::clone(&app_observations) as Arc<dyn AppObservationLookup>,
        )
        // The blanket block's exemptions: the tunnel-server host routes and the
        // attached subnets, read from the same rtnetlink table the route applier
        // writes to.
        .with_machine_facts(
            Arc::new(nrr_platform_linux::LinuxApi),
            Arc::clone(&adapter_port),
        ),
    );
    // The tracker turns a stream of probe results into a verdict with
    // hysteresis; the enforcer only ever asks it for the verdict. A tunnel that
    // has never answered a probe is unprobeable, not dead — that rule lives in
    // the tracker, not here.
    // Window 0 = the probe records evidence but never declares anything dead.
    // The saved setting is applied below, so an operator who never opted in
    // keeps the interface-state-only behaviour they had.
    let liveness = Arc::new(SecondaryLivenessTracker::new(0));
    let enforcer: Arc<dyn PolicyEnforcer> = Arc::new(
        NftPolicyEnforcer::new(Arc::clone(&bindings), Arc::clone(&adapter_port)).with_liveness({
            let liveness = Arc::clone(&liveness);
            Arc::new(move |ifindex| !liveness.is_dead(ifindex, std::time::Instant::now()))
        }),
    );

    // The other half of enforcement: rtnetlink puts the /32s in the table so the
    // traffic the filters permit on the tunnel actually goes there. Without it a
    // route-to-secondary rule reads as a block — the packet takes the default
    // path and meets its own leak-guard drop.
    let routes = Arc::new(PlannedRouteApplier::new(
        Arc::new(nrr_platform_linux::LinuxApi),
        adapter_port,
        bindings,
    ));

    // The persisted window, if the operator set one. Read once at build: a live
    // change reaches the tracker through the settings writer, exactly as on the
    // other platform.
    if let Ok(guard) = conn_for_stability.lock() {
        if let Ok(config) =
            nrr_storage::service_stability_config::ServiceStabilityConfigRepository::new(&guard)
                .get_or_default()
        {
            liveness.set_window_secs(u64::from(config.secondary_liveness_window_secs));
        }
    }

    Some(PolicyStack {
        state_conn,
        cache_store,
        app_observations,
        rules: rules_for_stack,
        auto_rules,
        liveness,
        rule_seeder,
        dns_consumer,
        dns_consumer_subject,
        cycle: Arc::new(
            PrincipalEnforcementCycle::new(Arc::new(LogindActivePrincipals), plans, enforcer)
                .with_routes(routes),
        ),
    })
}

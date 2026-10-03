//! The daemon's IPC surface: the real handler registry, not a handshake.
//!
//! Until this landed the socket answered three operations — negotiate,
//! subscribe, health — and everything else came back "unhandled", which a
//! client cannot tell apart from a broken transport. The registry itself is
//! neutral (`register_production_handlers`); what was missing on Linux was the
//! bundle of providers it reads through, and every one of those already existed
//! as OS-neutral code over the state database.
//!
//! ## Applying rules from the GUI
//!
//! The activation coordinator takes a `RulesApplyDispatcher` TRAIT, so nothing
//! about approving a revision is Windows-bound. The Linux dispatcher hands the
//! work to the enforcement cycle: the coordinator has already written the
//! revision, so one pass reads it back and reconciles it. Doing it inline rather
//! than waiting for the next tick is what lets the GUI report the truth instead
//! of "submitted, probably".
//!
//! ## Signed revisions
//!
//! The coordinator signs every revision it writes with the key kept beside the
//! state database, and the rows a previous run left are checked before the first
//! enforcement pass reads them: the neutral `revision_signing` sequence, with the
//! key store as the only part this platform supplies.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::SecurityAlertsRepository;
use nrr_platform_api::key_store::KeyStore;
use nrr_service_runtime::activation_coordinator::{
    ActivationCoordinator, DispatchFailure, PreFlightWarning, RulesApplyDispatcher,
    SidActionPlanSummary,
};
use nrr_service_runtime::boot_integrity::AuditTrail;
use nrr_service_runtime::browser_history_seeder::BrowserHistorySeeder;
use nrr_service_runtime::ipc_handlers::event_bus::EventBus;
use nrr_service_runtime::ipc_handlers::IpcHandlerDeps;
use nrr_service_runtime::principal_enforcement::{CycleOutcome, PrincipalEnforcementCycle};
use nrr_service_runtime::production_coordinator::{
    ProductionActivationAuditEmitter, ProductionApplyMarkerStore, ProductionIdGenerator,
};
use nrr_service_runtime::production_diagnostics::ProductionDiagnosticsFacade;
use nrr_service_runtime::production_handlers_misc::{
    MonitoredAdaptersSnapshotProvider, ProductionDohResolverListStore,
    ProductionMigrationCompletionWriter, ProductionMigrationStatusProvider,
    ProductionPrincipalDataPurger, ProductionRoutePolicyProvider, ProductionRoutePolicyWriter,
    ProductionRulesSnapshotProvider,
};
use nrr_service_runtime::production_merge_preview::{
    MergePreviewSource, ProductionMergePreviewSource,
};
use nrr_service_runtime::production_mutation_executor::ProductionMutationExecutor;
use nrr_service_runtime::production_policy_manager::CoordinatorPolicyManager;
use nrr_service_runtime::production_preset_exporter::{
    PresetExportSource, ProductionPresetExporter,
};
use nrr_service_runtime::production_rules_provider::ProductionRulesProvider;
use nrr_service_runtime::production_security_alerts::ProductionSecurityAlertsRepository;
use nrr_service_runtime::production_settings::{
    ProductionApplyFailurePolicy, ProductionAutostart, ProductionLogRetentionConfig,
    ProductionRetentionSettings, ProductionRoutingPause, ProductionServiceStability,
    ProductionStorageUsage,
};
use nrr_service_runtime::production_settings_exporter::{
    ProductionSettingsExporter, SettingsExportSource,
};
use nrr_service_runtime::revision_signing::RevisionSigning;
use nrr_service_runtime::revision_watch::RevisionWatch;
use nrr_service_runtime::routing_pause::{
    NoopRoutingPauseAudit, PauseDispatcher, RoutingPauseCoordinator,
};
use nrr_service_runtime::{
    ActiveSidRegistry, IpcAuditEmitter, MutationTokenStore, NoopIpcAuditEmitter,
};

/// Everything the daemon needs to answer the full IPC surface.
pub(crate) struct IpcSurface {
    pub deps: Arc<IpcHandlerDeps>,
    /// The dry-run token store the surface actually uses. Handed back so the
    /// housekeeping tick can collect expired tokens: a dry-run needs no
    /// elevation and skips the mutation queue, so its payload parks here until
    /// confirmed or expired, and nothing else would ever sweep it.
    pub mutation_tokens: Arc<MutationTokenStore>,
    /// The audit emitter the router must share with the handlers. The router
    /// refuses a privileged mutation whose record cannot be written; with a
    /// no-op emitter that safeguard can never fire.
    pub audit: Arc<dyn IpcAuditEmitter>,
    /// The one coordinator every rule change goes through, signing what it
    /// writes; the runtime holds it for the life of the daemon.
    pub coordinator: Arc<ActivationCoordinator>,
    /// The recheck after an outside write to the state database. `None`
    /// without a signing key.
    pub revision_watch: Option<RevisionWatch>,
    /// The automatic main-link pass over the SAME runner the button uses, so
    /// both share one repeat suppression. `None` without the suggestions engine.
    pub auto_probe: Option<nrr_service_runtime::service_tasks::AutoProbeWiring>,
}

/// Turns an approved revision into kernel state by running one enforcement pass.
///
/// The pass reads rules through the provider, which serves the revision being
/// applied for the whole activation window (the stored pointer commits only
/// after this returns) and the stored one again by revert time. What the
/// dispatcher adds is timing — the change takes effect now rather than at the
/// next tick, which is the difference between the GUI reporting a result and
/// reporting a hope.
struct CycleApplyDispatcher {
    cycle: Arc<PrincipalEnforcementCycle>,
}

impl RulesApplyDispatcher for CycleApplyDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        // Zeroes because this platform does not compute the id-level diff yet,
        // and inventing counts would be worse than admitting none: the GUI
        // renders them as "what will change".
        tracing::debug!(
            target: "nrr::enforcement",
            sid,
            "dry-run on this platform reports no counts: the per-rule diff is not computed here",
        );
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 0,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        _sid: &str,
        _rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        Ok(Vec::new())
    }

    fn apply_for_sid(&self, sid: &str, _rules_json: &str) -> Result<(), DispatchFailure> {
        self.run_pass(sid)
    }

    fn revert_for_sid(&self, sid: &str, _previous_rules_json: &str) -> Result<(), DispatchFailure> {
        // Revert is the same primitive: the overlay is withdrawn by now, so
        // the pass reads the stored revision, which never moved.
        self.run_pass(sid)
    }
}

impl CycleApplyDispatcher {
    fn run_pass(&self, sid: &str) -> Result<(), DispatchFailure> {
        // An apply the user asked for is attempted even with plans refused
        // before: the fix may be one the plans do not show.
        self.cycle.request_retry();
        match self.cycle.tick_logged("apply") {
            CycleOutcome::Applied { .. } | CycleOutcome::Unchanged => Ok(()),
            // Every other outcome means the machine does NOT match the
            // revision that was just approved. Reporting success here would
            // leave the user believing rules are in force that are not.
            CycleOutcome::EnforcementFailed { reason, .. }
            | CycleOutcome::RefusalStands { reason } => Err(DispatchFailure {
                sid: sid.to_string(),
                message: reason,
            }),
            CycleOutcome::AuthorityUnavailable { reason } => Err(DispatchFailure {
                sid: sid.to_string(),
                message: format!("could not determine who is logged in: {reason}"),
            }),
            CycleOutcome::Stopped => Err(DispatchFailure {
                sid: sid.to_string(),
                message: "the service is stopping; the rules were saved but not applied".to_owned(),
            }),
        }
    }
}

/// Routing pause on this platform is not wired to a mechanism yet.
///
/// It refuses instead of pretending: a pause that reports success while traffic
/// keeps following the rules is the exact failure a pause exists to prevent.
struct UnsupportedPauseDispatcher;

impl PauseDispatcher for UnsupportedPauseDispatcher {
    fn install_for_sid(&self, _sid: &str) -> Result<(), String> {
        Err("routing pause is not available on this platform yet".to_owned())
    }

    fn remove_for_sid(&self, _sid: &str) -> Result<(), String> {
        Err("routing pause is not available on this platform yet".to_owned())
    }
}

/// The IPC audit emitter this daemon serves with: the real one when there is a
/// writer to record into, the no-op when there is not.
///
/// The choice is load-bearing rather than cosmetic. The router REFUSES a
/// privileged mutation whose audit record cannot be written — an operation that
/// cannot be accounted for does not happen — so with the no-op that safeguard
/// can never fire, and the trail stays empty while everything looks healthy.
/// Bootstrap has already reported why a writer is missing, so this stays quiet.
fn ipc_audit_emitter(
    audit_writer: Option<&Arc<nrr_diagnostics::AuditWriter>>,
) -> Arc<dyn IpcAuditEmitter> {
    match audit_writer {
        Some(writer) => Arc::new(
            nrr_service_runtime::production_ipc_audit::ProductionIpcAuditEmitter::new(Arc::clone(
                writer,
            )),
        ),
        None => Arc::new(NoopIpcAuditEmitter),
    }
}

/// Assemble the full IPC surface over the open state database.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_ipc_surface(
    state_conn: Arc<Mutex<rusqlite::Connection>>,
    cache_conn: Option<Arc<Mutex<rusqlite::Connection>>>,
    data_dir: PathBuf,
    logs_dir: PathBuf,
    audit_dir: PathBuf,
    state_db_path: PathBuf,
    cache_db_path: PathBuf,
    audit_writer: Option<Arc<nrr_diagnostics::AuditWriter>>,
    log_writer: Option<Arc<nrr_diagnostics::LogWriter>>,
    route_table: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
    cycle: Arc<PrincipalEnforcementCycle>,
    health: Arc<nrr_service_runtime::HealthAggregator>,
    event_bus: Arc<EventBus>,
    gui_binary: PathBuf,
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    traffic_sampler: Option<crate::runtime_deps::TrafficSamplerHandle>,
    cache_store: Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    conn_trace_ring: Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>,
    app_enforcement: nrr_service_runtime::app_enforcement_status::AppEnforcementStatus,
    conn_trace_log_apply: Arc<dyn Fn(bool) + Send + Sync>,
    verbosity: Option<nrr_service_runtime::TracingVerbosityHandle>,
    key_store: Arc<dyn KeyStore>,
    // The daemon's own resolver: under the DNS redirect `/etc/resolv.conf`
    // leads back into our listener.
    dns_resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort>,
) -> IpcSurface {
    // Cloned before the facade takes ownership: storage usage counts the same
    // log directory the diagnostics reader serves from, and on Linux that lives
    // outside the data root.
    let usage_logs_dir = logs_dir.clone();
    // Held back from the deps builder below, which consumes the connection.
    let stats_state_conn = Arc::clone(&state_conn);
    let ids = Arc::new(ProductionIdGenerator::new());
    // Bound here rather than inline at the call below, so the caller can hand it
    // to the housekeeping tick — the same wiring the Windows surface has.
    let mutation_tokens: Arc<MutationTokenStore> = Arc::default();
    let audit = ipc_audit_emitter(audit_writer.as_ref());
    let alerts_repo: Arc<dyn SecurityAlertsRepository> = Arc::new(
        ProductionSecurityAlertsRepository::new(Arc::clone(&state_conn)),
    );

    // Before the coordinator exists and before the socket listens: the check
    // has to see the rows exactly as the previous run signed them. The same
    // sequence the Windows service runs; only the key store is ours.
    let signing = RevisionSigning::bootstrap(
        &state_conn,
        key_store,
        Arc::clone(&alerts_repo),
        audit_writer
            .as_ref()
            .map(|w| Arc::clone(w) as Arc<AuditTrail>),
        Arc::clone(&health),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
    );

    // Without an audit writer the coordinator still runs, but its trail is not
    // persisted. Bootstrap already reported why, so this stays silent about the
    // cause and only picks the emitter.
    let activation_audit: Arc<
        dyn nrr_service_runtime::activation_coordinator::ActivationAuditEmitter,
    > = match audit_writer.as_ref() {
        Some(writer) => Arc::new(
            ProductionActivationAuditEmitter::new(Arc::clone(writer), Arc::clone(&ids))
                .with_event_bus(Arc::clone(&event_bus)),
        ),
        None => Arc::new(nrr_service_runtime::activation_coordinator::NoopActivationAudit),
    };

    let sid_registry = Arc::new(ActiveSidRegistry::new());
    let coordinator = ActivationCoordinator::new(
        Arc::clone(&state_conn),
        Arc::clone(&sid_registry),
        Arc::new(CycleApplyDispatcher {
            cycle: Arc::clone(&cycle),
        }),
        Arc::new(ProductionApplyMarkerStore::new(&data_dir)),
        activation_audit,
        Arc::new(nrr_service_runtime::production_settings::SystemClock),
        ids,
        nrr_service_runtime::activation_coordinator::ApplyFailurePolicy::AllOrNothing,
    );
    let coordinator = Arc::new(signing.sign(coordinator));
    // Before the first enforcement pass reads the rules.
    let revision_watch = signing.enforce_and_watch(Some(&coordinator));

    let pause_coordinator = Arc::new(RoutingPauseCoordinator::new(
        Arc::clone(&state_conn),
        sid_registry,
        Arc::new(UnsupportedPauseDispatcher),
        Arc::new(NoopRoutingPauseAudit),
        Arc::new(nrr_service_runtime::production_settings::SystemClock),
    ));

    // Every rule change the GUI makes — preset import, table edits, rollback —
    // lands here; without it a preview came back empty and read as "nothing to
    // apply". The coordinator's dispatcher is what makes an approval take effect.
    let mut mutation_executor = ProductionMutationExecutor::new(Arc::clone(&coordinator))
        .with_alerts_repo(Arc::clone(&alerts_repo))
        .with_state_conn(Arc::clone(&state_conn))
        .with_event_bus(Arc::clone(&event_bus))
        .with_pause_coordinator(Arc::clone(&pause_coordinator))
        .with_stability_provider(Arc::new(ProductionServiceStability::new(Arc::clone(
            &state_conn,
        ))));
    // An alert acknowledgement the trail cannot point at would be recorded
    // as having happened nowhere; the chain restart needs the trail too.
    if let Some(writer) = audit_writer.as_ref() {
        mutation_executor = mutation_executor.with_audit_writer(Arc::clone(writer));
    }

    // Wired but shadowed: the launcher answers `autostart.*` before the socket
    // hop because autostart is per-user and this daemon runs as root, where
    // `$HOME` is `/root` — an entry written here is one no session ever reads.
    // A missing XDG autostart directory is not a reason to refuse service: the
    // registry falls back to the standard location, and the write itself is what
    // reports a real failure to the user.
    let registry =
        nrr_platform_linux::autostart::XdgAutostartRegistry::new().unwrap_or_else(|_| {
            nrr_platform_linux::autostart::XdgAutostartRegistry::with_autostart_dir(
                default_autostart_dir(),
            )
        });
    let autostart_helper = Arc::new(nrr_platform_api::autostart::AutostartHelper::new(registry));

    // The main-link check writes its verdicts here; the rules table reads them.
    let main_route_verdicts =
        Arc::new(nrr_service_runtime::main_route_verdicts::MainRouteVerdicts::new());
    let probe_route_table = Arc::clone(&route_table);
    let seed_cache = Arc::clone(&cache_store);
    let probe_cache = Arc::clone(&cache_store);

    let deps = IpcHandlerDeps::new(
        Arc::clone(&audit),
        health,
        Arc::new(CoordinatorPolicyManager::new(
            Arc::clone(&coordinator),
            Arc::clone(&state_conn),
        )),
        Arc::new(MonitoredAdaptersSnapshotProvider::new(
            route_table,
            Arc::new(nrr_platform_linux::interface_rows::LinuxInterfaceRows),
        )),
        Arc::new(
            ProductionRulesSnapshotProvider::new(Arc::clone(&state_conn))
                .with_main_route_verdicts(Arc::clone(&main_route_verdicts)),
        ),
        Arc::new(
            ProductionDiagnosticsFacade::new(
                logs_dir,
                audit_dir,
                cache_conn,
                Arc::clone(&alerts_repo),
                Some(Arc::clone(&state_conn)),
            )
            .with_log_writer(log_writer)
            // Restarts the service sealed are honoured; any other is an event.
            .with_chain_restart_key(coordinator.audit_restart_key()),
        ),
        Arc::new(mutation_executor),
        Arc::clone(&mutation_tokens),
        Arc::default(),
        Arc::clone(&event_bus),
        Arc::new(ProductionRoutePolicyProvider::new(Arc::clone(&state_conn))),
        Arc::new(ProductionRoutePolicyWriter::new(Arc::clone(&state_conn))),
        Arc::new(ProductionMigrationStatusProvider::new(Arc::clone(
            &state_conn,
        ))),
        Arc::new(ProductionMigrationCompletionWriter::new(Arc::clone(
            &state_conn,
        ))),
        Arc::new(ProductionRetentionSettings::new(Arc::clone(&state_conn))),
        Arc::new(ProductionRetentionSettings::new(Arc::clone(&state_conn))),
        Arc::new(ProductionLogRetentionConfig::new(Arc::clone(&state_conn))),
        Arc::new(ProductionLogRetentionConfig::new(Arc::clone(&state_conn))),
        Arc::new(ProductionApplyFailurePolicy::new(Arc::clone(&state_conn))),
        Arc::new(ProductionApplyFailurePolicy::new(Arc::clone(&state_conn))),
        Arc::new(ProductionStorageUsage::new(
            state_db_path,
            cache_db_path,
            usage_logs_dir,
        )),
        Arc::new(ProductionRoutingPause::new(
            Arc::clone(&state_conn),
            Arc::clone(&pause_coordinator),
        )),
        Arc::new(
            ProductionRoutingPause::new(Arc::clone(&state_conn), pause_coordinator)
                .with_event_bus(Arc::clone(&event_bus)),
        ),
        Arc::new(ProductionAutostart::new(
            Arc::clone(&state_conn),
            Arc::clone(&autostart_helper),
            gui_binary.clone(),
        )),
        Arc::new(
            ProductionAutostart::new(state_conn, autostart_helper, gui_binary)
                .with_event_bus(event_bus),
        ),
    );
    // Archives go under the runtime directory: the state tree is `0700`, and a
    // user cannot open a file below a directory they cannot traverse.
    let deps = deps
        // The tamper gate at the socket, and the elevation an acknowledgement
        // needs once it would adopt another user's rows.
        .with_alerts_repo(alerts_repo)
        .with_other_principals_reader(
            nrr_service_runtime::revision_signing::other_principals_hold_revisions(Arc::clone(
                &stats_state_conn,
            )),
        )
        .with_cache_repository(cache_store)
        .with_archives_config(
            nrr_platform_linux::systemd::runtime_dir().join("archives"),
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .with_system_info(nrr_platform_linux::system_info::collect())
        .with_file_handoff(Arc::new(nrr_platform_linux::file_handoff::ChownFileHandoff))
        .with_conn_trace_ring(conn_trace_ring)
        // The same status the planner publishes rule conflicts into.
        .with_app_enforcement_status(app_enforcement)
        .with_state_schema_version(
            stats_state_conn
                .lock()
                .ok()
                .and_then(|guard| nrr_storage::migration::read_schema_version(&guard).ok()),
        );
    // OS-neutral handlers over the state database. Left unwired, "Save to
    // file", the drift merge, the full settings export, the full reset and the
    // DoH list each came back as an unimplemented operation.
    let deps = deps
        .with_preset_export_source(Arc::new(ProductionPresetExporter::new(Arc::clone(
            &stats_state_conn,
        ))) as Arc<dyn PresetExportSource>)
        .with_merge_preview_source(Arc::new(ProductionMergePreviewSource::new(Arc::clone(
            &stats_state_conn,
        ))) as Arc<dyn MergePreviewSource>)
        .with_settings_export_source(
            Arc::new(ProductionSettingsExporter::new(Arc::clone(
                &stats_state_conn,
            ))) as Arc<dyn SettingsExportSource>,
            Arc::new(nrr_service_runtime::production_settings::SystemClock)
                as Arc<dyn nrr_service_runtime::activation_coordinator::Clock>,
        )
        .with_link_provider_writer(Arc::new(ProductionRoutePolicyWriter::new(Arc::clone(
            &stats_state_conn,
        )))
            as Arc<dyn nrr_service_runtime::ipc_handlers::providers::LinkProviderWriter>)
        .with_principal_data_purger(Arc::new(ProductionPrincipalDataPurger::new(Arc::clone(
            &stats_state_conn,
        )))
            as Arc<dyn nrr_service_runtime::ipc_handlers::providers::PrincipalDataPurger>)
        // The planner reads this list for the DoH lockdown on this OS too.
        .with_doh_resolver_store(Arc::new(ProductionDohResolverListStore::new(Arc::clone(
            &stats_state_conn,
        )))
            as Arc<
                dyn nrr_service_runtime::ipc_handlers::doh_resolvers::DohResolverListStore,
            >);
    // The stability fields this daemon applies live are the verbose window,
    // resumed here from the stored deadline, and the connection trace's log
    // switch; the rest of the row is stored and not read.
    let stability = {
        let writer = ProductionServiceStability::new(Arc::clone(&stats_state_conn))
            .with_conn_trace_ndjson_apply(conn_trace_log_apply);
        Arc::new(match verbosity {
            Some(handle) => writer.with_verbosity_control(Arc::new(handle)
                as Arc<dyn nrr_service_runtime::verbosity_control::VerbosityControl>),
            None => writer,
        })
    };
    let deps = deps.with_service_stability(
        Arc::clone(&stability) as Arc<dyn nrr_service_runtime::ServiceStabilityConfigProvider>,
        stability as Arc<dyn nrr_service_runtime::ServiceStabilityConfigWriter>,
    );
    // The user's own history, read only on their request or opt-in.
    let seeder = browser_history_seeder(
        Arc::clone(&stats_state_conn),
        seed_cache,
        data_dir.join("browser-history"),
        dns_resolver,
    );
    spawn_boot_auto_seed(Arc::clone(&seeder), Arc::clone(&stats_state_conn));
    let deps = deps
        .with_browser_history_seeder(seeder)
        // "This site refuses main-link addresses": a fact only the user knows.
        .with_refusing_anchors(Arc::new(
            nrr_service_runtime::production_local_networks::ProductionRefusingAnchors::new(
                Arc::clone(&stats_state_conn),
            ),
        ));
    // The SAME engine the observation consumer feeds. Without it the
    // `autorules.candidates.*` operations stay registered as unimplemented and
    // the GUI's suggestions page has nothing to read.
    let mut auto_probe = None;
    let deps = match auto_rules {
        Some(engine) => {
            let runner = main_link_probe(
                Arc::clone(&engine),
                probe_cache,
                Arc::clone(&stats_state_conn),
                probe_route_table,
                main_route_verdicts,
            );
            auto_probe = Some(nrr_service_runtime::service_tasks::AutoProbeWiring {
                runner: Arc::clone(&runner),
                cadence: nrr_service_runtime::service_tasks::stored_auto_probe_cadence(Arc::clone(
                    &stats_state_conn,
                )),
            });
            deps.with_auto_rule_probe(runner).with_auto_rules(engine)
        }
        None => deps,
    };
    // The SAME sampler the housekeeping tick counts into, so the traffic page
    // reports the ledger that is actually being written. Without it the
    // `traffic-stats.*` operations stay unimplemented and the GUI polls a
    // refusal every minute.
    let deps = match traffic_sampler {
        Some(sampler) => {
            let settings = Arc::new(
                nrr_service_runtime::production_traffic::ProductionTrafficSettings::new(
                    Arc::clone(&stats_state_conn),
                ),
            )
                as Arc<dyn nrr_service_runtime::production_traffic::TrafficSettingsAccess>;
            let stats = Arc::new(
                nrr_service_runtime::production_traffic::ProductionTrafficStats::new(
                    sampler, settings,
                ),
            );
            deps.with_traffic_stats(
                Arc::clone(&stats) as Arc<dyn nrr_service_runtime::TrafficStatsProvider>,
                stats as Arc<dyn nrr_service_runtime::TrafficStatsWriter>,
            )
        }
        None => deps,
    };

    IpcSurface {
        deps: Arc::new(deps),
        mutation_tokens,
        audit,
        coordinator,
        revision_watch,
        auto_probe,
    }
}

/// The opt-in browser-history import: the user's own profiles, their own rules,
/// the cache the planner reads.
fn browser_history_seeder(
    state_conn: Arc<Mutex<rusqlite::Connection>>,
    cache: Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    copy_dir: PathBuf,
    dns_resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort>,
) -> Arc<BrowserHistorySeeder> {
    let resolver: Arc<dyn nrr_platform_api::dns::DnsResolverPort> = Arc::new(
        nrr_platform_api::dns_budget::BudgetedDnsResolver::new(dns_resolver),
    );
    Arc::new(BrowserHistorySeeder::new(
        Arc::new(nrr_platform_linux::browser_history::LinuxBrowserHistoryRead::new(copy_dir)),
        Arc::new(ProductionRulesProvider::new(state_conn)),
        resolver,
        cache,
    ))
}

/// One seed pass at start for each signed-in user who opted in, retried while
/// logind reports nobody: sessions come up after the daemon.
fn spawn_boot_auto_seed(
    seeder: Arc<BrowserHistorySeeder>,
    state_conn: Arc<Mutex<rusqlite::Connection>>,
) {
    use nrr_platform_api::active_principals::ActivePrincipalSource;

    let spawned = std::thread::Builder::new()
        .name("nrr-bh-autoseed".into())
        .spawn(move || {
            for _ in 0..12 {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let principals = nrr_platform_linux::logind::LogindActivePrincipals
                    .active_principals()
                    .unwrap_or_default();
                if principals.is_empty() {
                    continue;
                }
                for principal in principals {
                    let sid = principal.as_stored();
                    let opted_in = state_conn
                        .lock()
                        .ok()
                        .and_then(|guard| {
                            nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
                                .load_for_sid(sid)
                                .ok()
                        })
                        .is_some_and(|record| record.browser_history_auto_seed);
                    if !opted_in {
                        continue;
                    }
                    tracing::info!(
                        target: "nrr::browser-history",
                        msg_key = "svc-ipc-browser-history-autoseed-run",
                        "auto-seed opt-in enabled — running boot browser-history seed",
                    );
                    // A manual import already running covers it.
                    if let Some(run) = seeder.try_begin(sid) {
                        let _ = run.run(std::time::SystemTime::now());
                    }
                }
                break;
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(
            target: "nrr::browser-history",
            msg_key = "svc-ipc-browser-history-autoseed-spawn-failed",
            error = %e,
            "could not spawn boot browser-history auto-seed worker",
        );
    }
}

/// The "does it answer on the main link?" pass. The main link is the user's
/// bound one, or the default route when none is bound.
fn main_link_probe(
    engine: Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    cache: Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    state_conn: Arc<Mutex<rusqlite::Connection>>,
    route_table: Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
    verdicts: Arc<nrr_service_runtime::main_route_verdicts::MainRouteVerdicts>,
) -> Arc<dyn nrr_service_runtime::ipc_handlers::providers::AutoRuleProbeRunner> {
    use nrr_service_runtime::path_probe::{PathProber, ProbeLimits};
    use nrr_service_runtime::production_auto_rule_probe::{
        ProductionAutoRuleProbe, StoredBindingEgress,
    };

    let egress = Arc::new(StoredBindingEgress::new(
        Arc::new(
            nrr_service_runtime::production_handlers_misc::ProductionRoutePolicySource::new(
                Arc::clone(&state_conn),
            ),
        ),
        route_table,
    ));
    // The user's own bounds, clamped by `ProbeLimits::new`.
    let limits_for = Arc::new(move |sid: &str| {
        let guard = state_conn.lock().unwrap_or_else(|p| p.into_inner());
        match nrr_storage::route_bindings::RouteBindingsRepository::new(&guard).load_for_sid(sid) {
            Ok(record) => ProbeLimits::new(
                std::time::Duration::from_millis(u64::from(record.primary_probe_timeout_ms)),
                record.primary_probe_max_targets as usize,
                std::time::Duration::from_secs(u64::from(record.primary_probe_repeat_secs)),
            ),
            Err(_) => ProbeLimits::default(),
        }
    });
    Arc::new(
        ProductionAutoRuleProbe::over(
            engine,
            nrr_service_runtime::production_principal_plan::cache_lookup_over(cache),
            egress,
            Arc::new(PathProber::new(Arc::new(LinkBoundPathProbe))),
            limits_for,
        )
        .with_verdicts(verdicts)
        // Its own prober: repeat-suppression is per instance.
        .with_secondary_prober(Arc::new(PathProber::new(Arc::new(LinkBoundPathProbe))))
        .with_observed_names(
            nrr_service_runtime::observed_host_names::global_observed_host_names(),
        ),
    )
}

/// The neutral probe over a socket pinned to the link that carries the source
/// address.
struct LinkBoundPathProbe;

impl nrr_service_runtime::path_probe::PathProbe for LinkBoundPathProbe {
    fn probe(
        &self,
        target: std::net::Ipv4Addr,
        port: u16,
        source: Option<std::net::Ipv4Addr>,
        timeout: std::time::Duration,
    ) -> nrr_service_runtime::path_probe::PathVerdict {
        use nrr_platform_linux::link_probe::{connect_over_link, LinkProbeOutcome};
        use nrr_service_runtime::path_probe::PathVerdict;

        // Unpinned, the kernel routes by destination, through the tunnel for a
        // routed host, and the answer would be about the wrong link.
        let Some(source) = source else {
            return PathVerdict::Indeterminate;
        };
        match connect_over_link(target, port, source, timeout) {
            LinkProbeOutcome::Connected => PathVerdict::Answered,
            LinkProbeOutcome::NoAnswer => PathVerdict::Silent,
            LinkProbeOutcome::NotRun => PathVerdict::Indeterminate,
        }
    }
}

/// Where XDG says per-user autostart entries live, when the environment does
/// not say otherwise.
fn default_autostart_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc/xdg"))
        .join("autostart")
}

#[cfg(test)]
mod integrity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_service_runtime::{IpcRequestContext, IpcRequestEnvelope};

    fn envelope() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: nrr_service_runtime::IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: nrr_shared::ipc::IpcOperationName::MutationSubmit,
            operation_class: nrr_service_runtime::ipc::IpcOperationClass::MutationRequest,
            confirmation_token: Some("tok".into()),
            payload: serde_json::json!({ "mutation-kind": "rules-update" }),
        }
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: nrr_shared::ipc::IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
            caller_pid: None,
        }
    }

    /// With a writer the daemon must record for real. The router refuses a
    /// privileged mutation whose record cannot be written, and that refusal is
    /// the only thing standing between "audited" and "silently unaudited" — so
    /// the wiring is checked by what reaches the disk, not by what was passed.
    #[test]
    fn a_writer_gives_an_emitter_that_actually_records() {
        let dir = std::env::temp_dir().join(format!("nrr-ipc-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp audit dir");

        let writer = Arc::new(nrr_diagnostics::AuditWriter::open(
            nrr_diagnostics::AuditWriterConfig::new(dir.clone()),
        ));
        ipc_audit_emitter(Some(&writer))
            .record_request(&envelope(), &ctx())
            .expect("the record is written");

        let wrote_something = std::fs::read_dir(&dir)
            .expect("read temp audit dir")
            .filter_map(Result::ok)
            .any(|e| e.metadata().map(|m| m.len() > 0).unwrap_or(false));
        assert!(wrote_something, "an audit record must reach the trail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without a writer the emitter must still SUCCEED, not fail: reporting an
    /// error here would make the router refuse every privileged mutation on a
    /// daemon whose audit storage is merely unavailable.
    #[test]
    fn no_writer_gives_a_silent_emitter_that_does_not_refuse() {
        ipc_audit_emitter(None)
            .record_request(&envelope(), &ctx())
            .expect("the no-op reports success");
    }
}

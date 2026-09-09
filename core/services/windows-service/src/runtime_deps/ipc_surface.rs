//! Assembly of the IPC handler surface, carved out of
//! [`super::build_supervised_runtime_deps`].
//!
//! Thirty values in and four out, and that ratio is the finding rather than an
//! accident of the split: the IPC surface is where nearly the whole dependency
//! graph is finally read. Inline, that fact was spread over eight hundred lines
//! and could not be seen; as a parameter list it is stated once.
//!
//! What deliberately did NOT move: the audit emitter, the router and the named
//! pipe server. They consume the registry this builds, and pipe-server
//! construction is the Windows-specific reason `runtime_deps` exists at all.
//!
//! Behaviour is unchanged: the same statements in the same order.

use super::*;

/// Everything the handler surface reads.
pub(super) struct IpcSurfaceInputs<'a> {
    pub artifacts: &'a BootstrapArtifacts,
    pub activation_coordinator: Option<Arc<ActivationCoordinator>>,
    pub api: Arc<dyn WindowsApiPort>,
    pub app_enforcement: nrr_service_runtime::app_enforcement_status::AppEnforcementStatus,
    pub auto_rules_engine: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    pub autostart_helper: Arc<AutostartHelper<ProductionAutostartRegistry>>,
    pub block_all_posture: nrr_service_runtime::app_enforcement_status::BlockAllPostureStatus,
    pub block_notice_center: Arc<nrr_service_runtime::block_notice_center::BlockNoticeCenter>,
    pub block_notice_journal_store:
        Option<Arc<dyn nrr_service_runtime::block_notice_journal_store::BlockNoticeJournalStore>>,
    pub block_notice_mute_store:
        Option<Arc<dyn nrr_service_runtime::block_notice_mute_store::BlockNoticeMuteStore>>,
    pub block_notice_rule_author: Option<Arc<dyn nrr_service_runtime::auto_rules::AutoRuleAuthor>>,
    pub cache_store: Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    pub dns_resolver_controller:
        Arc<nrr_service_runtime::dns_resolver_service::DnsResolverController>,
    pub event_bus: Arc<EventBus>,
    pub fake_ip_assembly: Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>,
    pub fake_ip_controller: Arc<nrr_service_runtime::fake_ip::FakeIpController>,
    pub fake_ip_replan: Arc<dyn Fn() + Send + Sync>,
    pub health_agg: Arc<HealthAggregator>,
    pub liveness_tracker: Arc<nrr_service_runtime::secondary_liveness::SecondaryLivenessTracker>,
    pub main_route_verdicts: Arc<nrr_service_runtime::main_route_verdicts::MainRouteVerdicts>,
    pub mutation_tokens: Arc<MutationTokenStore>,
    pub pause_coordinator: Option<Arc<RoutingPauseCoordinator>>,
    pub per_sid_orchestrator: Option<Arc<PerSidApplyOrchestrator>>,
    pub recovery_audit_sink: Option<Arc<dyn RecoveryAuditSink>>,
    pub route_coordinator:
        Option<Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>>,
    pub settings_conn: Option<Arc<Mutex<Connection>>>,
    pub shared_ip_exemptions: nrr_service_runtime::app_enforcement_status::SharedIpExemptionStatus,
    pub sid_registry: Arc<ActiveSidRegistry>,
    pub traffic_sampler: Option<Arc<Mutex<nrr_service_runtime::traffic_sampler::TrafficSampler>>>,
    pub tray_path: PathBuf,
    /// Moved in, not borrowed: the writer below takes ownership so a
    /// mid-session "Verbose service logging" save takes effect live.
    pub verbosity_handle: Option<TracingVerbosityHandle>,
}

/// What the assembly hands back.
pub(super) struct IpcSurface {
    /// Whether the on-disk connection-trace NDJSON sink is enabled. The ring
    /// below is always built; only the persisted sink is opt-in.
    pub conn_trace_persisted_ndjson: bool,
    pub conn_trace_ring:
        Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>>,
    /// Filled while the handlers are wired (the probe runner is built there)
    /// and read when the supervised tasks are assembled.
    pub auto_probe_wiring: Option<nrr_service_runtime::service_tasks::AutoProbeWiring>,
    pub registry: IpcHandlerRegistry,
}

pub(super) fn build(inputs: IpcSurfaceInputs<'_>) -> IpcSurface {
    // Destructured so the moved body reads exactly as it did inline.
    let IpcSurfaceInputs {
        artifacts,
        activation_coordinator,
        api,
        app_enforcement,
        auto_rules_engine,
        autostart_helper,
        block_all_posture,
        block_notice_center,
        block_notice_journal_store,
        block_notice_mute_store,
        block_notice_rule_author,
        cache_store,
        dns_resolver_controller,
        event_bus,
        fake_ip_assembly,
        fake_ip_controller,
        fake_ip_replan,
        health_agg,
        liveness_tracker,
        main_route_verdicts,
        mutation_tokens,
        pause_coordinator,
        per_sid_orchestrator,
        recovery_audit_sink,
        route_coordinator,
        settings_conn,
        shared_ip_exemptions,
        sid_registry,
        traffic_sampler,
        tray_path,
        verbosity_handle,
    } = inputs;

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

    // Filled while the IPC handlers are wired (the probe runner is built
    // there) and read when the supervised tasks are assembled below.
    let mut auto_probe_wiring: Option<nrr_service_runtime::service_tasks::AutoProbeWiring> = None;
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
            None => Arc::new(nrr_service_runtime::ipc_handlers::stub::DegradedPolicyManager),
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
            match nrr_storage::migration::open_connection(path) {
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
        let diagnostics: Arc<dyn DiagnosticsFacade> = Arc::new(
            ProductionDiagnosticsFacade::new(
                artifacts.topology.logs_dir.clone(),
                artifacts.topology.data_dir.join("audit"),
                diagnostics_cache_conn,
                Arc::clone(&alerts_repo),
                Some(Arc::clone(conn)),
            )
            .with_log_writer(artifacts.log_writer.clone())
            // "Did the service slow my boot" is the standing suspicion of every
            // background service. The card answers it with the two moments
            // measured — the host log's sign-in phase, and this process's own
            // start — rather than with a reassurance.
            .with_boot_timing(
                std::sync::Arc::new(nrr_platform_windows::event_log::WindowsEventLog::new()),
                nrr_service_runtime::process_started_at_ms(),
            ),
        );

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
        let mut adapters_snapshot_provider = MonitoredAdaptersSnapshotProvider::new(
            Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
        );
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
            Arc::new(
                ProductionRulesSnapshotProvider::new(Arc::clone(conn))
                    .with_main_route_verdicts(Arc::clone(&main_route_verdicts))
                    // So an application rule can show what it is holding: the
                    // same store the codegen turns into host routes.
                    .with_app_observations(
                        nrr_service_runtime::app_observation_lookup::global_app_observations(),
                    ),
            )
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
            Arc::clone(&mutation_tokens),
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
        // Clearing a blocking integrity alert re-signs every revision row, so
        // it speaks for whoever owns them. Asked live, per acknowledgement: on
        // the ordinary single-user machine the answer is "nobody else" and the
        // user clears their own alert unaided.
        .with_other_principals_reader({
            let conn = Arc::clone(conn);
            Arc::new(move |caller: &str| {
                let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                nrr_storage::revisions::RevisionsRepository::new(&guard)
                    .distinct_principals()
                    .map(|principals| {
                        principals.iter().any(|p| {
                            p != caller && p != nrr_storage::BASELINE_PRINCIPAL
                        })
                    })
                    // Unreadable is not consent to speak for others.
                    .unwrap_or(true)
            })
        })
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
        // Hand a finished archive to the user who asked for it. The service
        // tree is closed to ordinary accounts, so without this the export is a
        // file its requester cannot open.
        .with_file_handoff(Arc::new(
            nrr_platform_windows::file_handoff::IcaclsFileHandoff,
        ))
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
        // Local networks under the kill-switch: the same coordinator that
        // computes the exemptions also answers what it discovered, so the list
        // the user ticks and the set the enforcement applies cannot drift.
        // "Does this address answer on the main link?" — asked when the user
        // presses Check, and on the auto-rules tick when they opted in.
        // Bounded by their own limits; the verdicts travel the same health
        // channel observed traffic uses.
        if let (Some(engine), Some(coord), Some(cache_arc), Some(conn_for_probe)) = (
            auto_rules_engine.as_ref(),
            route_coordinator.as_ref(),
            cache_store.as_ref(),
            settings_conn.as_ref(),
        ) {
            let fqdn_for_probe: Arc<dyn FqdnCacheLookup> = Arc::new(SqliteFqdnCacheLookup::new(
                Arc::clone(cache_arc),
                FreshnessThresholds::default_production(),
            ));
            let probe_runner = Arc::new(
                nrr_service_runtime::production_auto_rule_probe::ProductionAutoRuleProbe::new(
                    Arc::clone(engine),
                    fqdn_for_probe,
                    Arc::clone(coord),
                    Arc::new(nrr_service_runtime::path_probe::PathProber::new(Arc::new(
                        nrr_service_runtime::path_probe::SystemPathProbe,
                    ))),
                    {
                        // The user's own bounds, clamped by `ProbeLimits::new`
                        // — a stored value can widen nothing.
                        let conn = Arc::clone(conn_for_probe);
                        Arc::new(move |sid: &str| {
                            use nrr_service_runtime::path_probe::ProbeLimits;
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            let repo =
                                nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
                            match repo.load_for_sid(sid) {
                                Ok(record) => ProbeLimits::new(
                                    std::time::Duration::from_millis(u64::from(
                                        record.primary_probe_timeout_ms,
                                    )),
                                    record.primary_probe_max_targets as usize,
                                    std::time::Duration::from_secs(u64::from(
                                        record.primary_probe_repeat_secs,
                                    )),
                                ),
                                Err(_) => ProbeLimits::default(),
                            }
                        })
                    },
                )
                .with_verdicts(Arc::clone(&main_route_verdicts))
                // Its own prober: the repeat-suppression is per instance, and a
                // shared one would skip every host the main-link pass had just
                // asked about.
                .with_secondary_prober(Arc::new(
                    nrr_service_runtime::path_probe::PathProber::new(Arc::new(
                        nrr_service_runtime::path_probe::SystemPathProbe,
                    )),
                )),
            );
            // The user's own opt-in decides whether the tick runs the pass; the
            // stored repeat window is what keeps it a check rather than a
            // stream of connections.
            let cadence_conn = Arc::clone(conn_for_probe);
            auto_probe_wiring = Some(nrr_service_runtime::service_tasks::AutoProbeWiring {
                runner: Arc::clone(&probe_runner)
                    as Arc<dyn nrr_service_runtime::ipc_handlers::providers::AutoRuleProbeRunner>,
                cadence: Arc::new(move |sid: &str| {
                    use nrr_service_runtime::service_tasks::AutoProbeCadence;
                    let guard = cadence_conn.lock().unwrap_or_else(|p| p.into_inner());
                    let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
                    match repo.load_for_sid(sid) {
                        Ok(record) => AutoProbeCadence {
                            enabled: record.primary_probe_auto,
                            repeat: std::time::Duration::from_secs(u64::from(
                                record.primary_probe_repeat_secs,
                            )),
                        },
                        // Unreadable policy is not consent.
                        Err(_) => AutoProbeCadence {
                            enabled: false,
                            repeat: std::time::Duration::from_secs(300),
                        },
                    }
                }),
            });
            deps = deps.with_auto_rule_probe(probe_runner);
        }
        // The one fact about a routed site nothing here can measure: the user
        // says it, and it only ever un-quietens that site's companions.
        if let Some(conn) = settings_conn.as_ref() {
            deps = deps.with_refusing_anchors(Arc::new(
                nrr_service_runtime::production_local_networks::ProductionRefusingAnchors::new(
                    Arc::clone(conn),
                ),
            ));
        }
        if let (Some(conn), Some(coord)) = (settings_conn.as_ref(), route_coordinator.as_ref()) {
            deps = deps.with_local_networks(Arc::new(
                nrr_service_runtime::production_local_networks::ProductionLocalNetworks::new(
                    Arc::clone(coord),
                    Arc::clone(conn),
                ),
            ));
        }
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
        // The SAME backlog the centre appends to, so a surface reads what the
        // drop path recorded.
        if let Some(store) = block_notice_journal_store.clone() {
            deps = deps.with_block_notice_journal(store);
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

    IpcSurface {
        conn_trace_persisted_ndjson,
        conn_trace_ring,
        auto_probe_wiring,
        registry,
    }
}

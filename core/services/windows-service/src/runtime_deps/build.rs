//! Assembles the production `SupervisedRuntimeDeps` bundle — the top-level
//! function that calls every other submodule in this tree.

use super::*;

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

    // Filled once the recompute hook exists: work that outlives its caller (a
    // seed past its wait, a background disk walk) calls back into the hook.
    let recompute_slot: Arc<std::sync::OnceLock<std::sync::Weak<dyn Fn() + Send + Sync>>> =
        Arc::new(std::sync::OnceLock::new());
    let recompute_later: Arc<dyn Fn() + Send + Sync> = {
        let slot = Arc::clone(&recompute_slot);
        Arc::new(move || {
            if let Some(hook) = slot.get().and_then(std::sync::Weak::upgrade) {
                hook();
            }
        })
    };

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
        app_walk_found: Arc::clone(&recompute_later),
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
            let namespace_recheck = Arc::clone(namespace_recheck());
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
            // Seed rule hostnames BEFORE recompute: the /32 set gates both the
            // secondary route and the fail-closed block, and after boot a rule
            // host with no /32 leaked to the primary. The wait is bounded — a
            // seed that outlives it recomputes again when it lands.
            let seeder = rule_hostname_seeder.clone();
            let late_recompute = Arc::clone(&recompute_later);
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
                // This hook fires on the adapter monitor, so a link that just
                // appeared may have brought a claimed namespace with it. Wake
                // the DNS guard instead of leaving its names to us for up to a
                // guard interval.
                namespace_recheck.store(true, std::sync::atomic::Ordering::SeqCst);
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
                    seeder.seed_within(
                        active.clone(),
                        nrr_service_runtime::rule_hostname_seeder::SEED_WAIT_BUDGET,
                        Arc::clone(&late_recompute),
                    );
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
                timings.mark("leak-guard");
                // A new link usually means a new resolver. Re-selection probes
                // each dead server up to a timeout, so it runs beside the pass;
                // an upstream it finds clears the re-arm backoff and re-ticks
                // the watchdog at once rather than on the next pass.
                {
                    let dns_ctl = Arc::clone(&dns_ctl);
                    upstream_dns_pool().note_network_change_in_background(move |upstream| {
                        dns_ctl.note_upstream_present(upstream.is_some());
                        dns_ctl.tick();
                    });
                }
                // Mode-B resolver watchdog (see above): re-arm the
                // resolver if it is enabled but its serve thread has died.
                dns_ctl.tick();
                timings.mark("dns-watchdog");
                report_recompute_cost(&timings);
            }) as nrr_service_runtime::supervised_runtime::RouteRecomputeHook
        });
    let route_recompute_hook =
        route_recompute_hook.map(nrr_service_runtime::recompute_coalescer::coalesce);
    if let Some(hook) = route_recompute_hook.as_ref() {
        let _ = recompute_slot.set(Arc::downgrade(hook));
    }

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
    let (fcrdns_tx, fcrdns_rx) = std::sync::mpsc::sync_channel::<(
        std::net::Ipv4Addr,
        bool,
        nrr_service_runtime::conn_observation_consumer::ReverseLearnOrigin,
    )>(256);
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
    let (conn_observation_source, conn_observation_consumer, conn_observer_shutdown) =
        build_conn_trace_pair(
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
        route_coordinator.clone(),
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
        conn_observer_shutdown,
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
        // The consumers above see a connection when it opens; this keeps the
        // destinations of connections still open from ageing out under them.
        live_connection_refresh: Some(
            nrr_service_runtime::service_tasks::LiveConnectionRefreshWiring {
                source: Arc::new(
                    nrr_platform_windows::conn_observe::live::WindowsLiveConnections::new(),
                ),
                store: nrr_service_runtime::app_observation_lookup::global_app_observations(),
            },
        ),
        dns_observation: None,
        // One console user at a time here, so the per-user tasks keep reading
        // `active_routing_sid`. The list form exists for platforms where several
        // people are logged in at once.
        present_principals: None,
    }
}

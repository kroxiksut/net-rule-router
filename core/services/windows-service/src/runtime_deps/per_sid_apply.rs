//! The per-SID apply stack, carved out of [`super::build_supervised_runtime_deps`].
//!
//! It was 1163 lines in the middle of one 3300-line function, and the reason it
//! can move at all is that its interface is narrow: eleven values in, fourteen
//! out, and nothing else crosses. Both of those were invisible while the block
//! sat inline — that is the whole point of the split, not the line count.
//!
//! Behaviour is unchanged: the body is the same statements in the same order.

// Carved out of the parent, so it reads the parent's imports rather than
// restating sixty `use` lines that would then drift.
use super::*;

/// What the stack needs from the boot bundle.
///
/// Owned clones (every field is an `Arc` or a `Copy`) rather than borrows, so
/// the moved body keeps using `Arc::clone(&x)` exactly as it did inline.
pub(super) struct PerSidApplyInputs<'a> {
    pub artifacts: &'a BootstrapArtifacts,
    pub cache_refresh_secs: u32,
    pub cache_store: Option<Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    pub event_bus: Arc<EventBus>,
    pub fake_ip_controller: Arc<nrr_service_runtime::fake_ip::FakeIpController>,
    pub health_agg: Arc<HealthAggregator>,
    pub id_generator: Arc<ProductionIdGenerator>,
    pub liveness_tracker: Arc<nrr_service_runtime::secondary_liveness::SecondaryLivenessTracker>,
    pub reachability_probe: Arc<dyn nrr_platform_windows::reachability::ReachabilityProbe>,
    pub rebind_requests: Arc<nrr_service_runtime::power_resume::RebindRequests>,
    pub settings_conn: Option<Arc<Mutex<Connection>>>,
    pub sid_registry: Arc<ActiveSidRegistry>,
}

/// What it hands back to the rest of the bundle.
///
/// Fourteen fields because fourteen values were read after the block; naming
/// them is the point. `pause_coordinator` and the block-notice stores stay
/// `Option` for the same reason they always were: a degraded boot with no
/// settings DB still has to come up.
pub(super) struct PerSidApplyStack {
    pub api: Arc<dyn WindowsApiPort>,
    pub app_enforcement: nrr_service_runtime::app_enforcement_status::AppEnforcementStatus,
    pub shared_ip_exemptions: nrr_service_runtime::app_enforcement_status::SharedIpExemptionStatus,
    pub block_all_posture: nrr_service_runtime::app_enforcement_status::BlockAllPostureStatus,
    pub learned_vpn_endpoints: Arc<nrr_service_runtime::vpn_endpoint_learning::LearnedVpnEndpoints>,
    pub learned_vpn_client_apps:
        Arc<nrr_service_runtime::vpn_client_registry::LearnedVpnClientApps>,
    pub killswitch_drop_registry:
        Arc<nrr_service_runtime::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    pub main_route_verdicts: Arc<nrr_service_runtime::main_route_verdicts::MainRouteVerdicts>,
    pub dns_resolve_now_slot: Arc<std::sync::OnceLock<Arc<DnsRefreshOrchestrator>>>,
    pub block_notice_mute_store:
        Option<Arc<dyn nrr_service_runtime::block_notice_mute_store::BlockNoticeMuteStore>>,
    pub block_notice_journal_store:
        Option<Arc<dyn nrr_service_runtime::block_notice_journal_store::BlockNoticeJournalStore>>,
    pub block_notice_center: Arc<nrr_service_runtime::block_notice_center::BlockNoticeCenter>,
    pub pause_coordinator: Option<Arc<RoutingPauseCoordinator>>,
    pub fake_ip_replan: Arc<dyn Fn() + Send + Sync>,
    /// The seven values the WFP-session branch produces, all `None` together
    /// when no session could be acquired — that is what makes the degraded
    /// boot a single state instead of seven independent ones.
    pub route_path: RoutePathBundle,
}

pub(super) fn build(inputs: PerSidApplyInputs<'_>) -> PerSidApplyStack {
    // Destructured rather than read through `inputs.x`, so the body below is
    // the same text it was inline and the diff shows a move, not a rewrite.
    let PerSidApplyInputs {
        artifacts,
        cache_refresh_secs,
        cache_store,
        event_bus,
        fake_ip_controller,
        health_agg,
        id_generator,
        liveness_tracker,
        reachability_probe,
        rebind_requests,
        settings_conn,
        sid_registry,
    } = inputs;

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
    // Shared "guard blocking, additional link unresolved" flag. Wider than the
    // block-all one above and read by the two places that must not treat a rule
    // host as covered while it is armed: the DNS handler and the rule-hostname
    // seeder. Created here because the seeder is built before the orchestrator
    // that writes it.
    let fail_closed_posture =
        nrr_service_runtime::app_enforcement_status::FailClosedPostureStatus::new();
    let seed_leak_guard: Arc<dyn nrr_service_runtime::dns_resolver::LeakGuardPosture> = {
        let posture = fail_closed_posture.clone();
        Arc::new(move || posture.armed())
    };
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
    // What the user's last "check the main route" pass found for their own
    // rules. Written by the probe runner, read back by the rules snapshot.
    let main_route_verdicts =
        Arc::new(nrr_service_runtime::main_route_verdicts::MainRouteVerdicts::new());
    // Filled once the DNS refresher exists; the apply path holds only this
    // slot, so a rule naming an unresolved host can ask for a resolution
    // without the two construction orders having to meet.
    let dns_resolve_now_slot: Arc<std::sync::OnceLock<Arc<DnsRefreshOrchestrator>>> =
        Arc::new(std::sync::OnceLock::new());
    // One resolve pass at a time: applies can arrive in bursts (import, review,
    // activation) and each pass is a run of live DNS round-trips.
    let dns_resolve_now_busy = Arc::new(std::sync::atomic::AtomicBool::new(false));
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
    // Backlog for notices raised with no surface subscribed — the shape a user
    // gets by running the service without the tray. Same connection again.
    let block_notice_journal_store: Option<
        Arc<dyn nrr_service_runtime::block_notice_journal_store::BlockNoticeJournalStore>,
    > = settings_conn.as_ref().map(|conn| {
        Arc::new(
            nrr_service_runtime::block_notice_journal_store::SqliteBlockNoticeJournalStore::new(
                Arc::clone(conn),
            ),
        )
            as Arc<dyn nrr_service_runtime::block_notice_journal_store::BlockNoticeJournalStore>
    });
    let block_notice_center = {
        let mut center = nrr_service_runtime::block_notice_center::BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&event_bus));
        if let Some(journal) = block_notice_journal_store.clone() {
            center = center.with_journal(journal);
        }
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
                // Remember the MAC of an adapter a binding resolved to, so the
                // binding survives a GUID + ifindex change (Wi-Fi or Bluetooth
                // after sleep). Widens the identity set only — never moves the
                // binding — hence a callback of its own.
                let binding_anchor_persist: nrr_service_runtime::route_coordinator::BindingAnchorPersistFn = {
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str, role: &str, anchor_id: &str| {
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0);
                            if let Err(e) = repo.remember_stable_id(sid, role, anchor_id, now) {
                                tracing::warn!(target: "nrr::route-coordinator", sid = %sid, error = %e, "MAC anchor persist failed");
                            }
                        })
                    };
                // The user's own answers about local networks: which segments
                // stay reachable while the kill-switch blocks everything else.
                // Read per resolve so a change in Settings lands on the next
                // reconcile; unreadable rows degrade to "no stored decisions",
                // never to a wider exemption.
                let local_network_policy: nrr_service_runtime::route_coordinator::LocalNetworkPolicyFn = {
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str| {
                            use nrr_domain::ipv4_network::Ipv4Network;
                            let mut policy = nrr_service_runtime::route_coordinator::LocalNetworkPolicy::default();
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            let repo = nrr_storage::local_network_rules::LocalNetworkRulesRepository::new(&guard);
                            let Ok(rules) = repo.list_for_sid(sid) else {
                                return policy;
                            };
                            for rule in rules {
                                // The adapter half is what survives a
                                // hypervisor switch renumbering its segment;
                                // the coordinator resolves it against the
                                // adapters that exist at reconcile time.
                                if !rule.adapter.is_empty() {
                                    policy
                                        .adapter_answers
                                        .push((rule.adapter.clone(), rule.allow));
                                }
                                let Some(network) = Ipv4Network::parse(&rule.cidr) else {
                                    continue;
                                };
                                if rule.allow {
                                    policy.allowed.push(network);
                                } else {
                                    policy.refused.push(network);
                                }
                            }
                            policy
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
                        Arc::clone(&api) as Arc<dyn nrr_platform_api::route_table::RouteTablePort>,
                        Arc::clone(&rules_provider),
                        Arc::clone(&route_source),
                        Arc::clone(&fqdn_cache),
                        rule_scope_provider,
                    )
                    .with_binding_heal_persist(binding_heal_persist)
                    .with_binding_anchor_persist(binding_anchor_persist)
                    .with_local_network_policy(local_network_policy)
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
                    .with_learned_vpn_endpoints(Arc::clone(&learned_vpn_endpoints))
                    // So "your rules are not in force, and here is why" reaches
                    // the GUI banner and the tray instead of only the log.
                    .with_event_bus(Arc::clone(&event_bus)),
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
                    )
                    // While the guard blocks an unresolved link, a rule host
                    // with no cached address is an unprotected one — retry in
                    // seconds instead of minutes until it has one.
                    .with_leak_guard_posture(Arc::clone(&seed_leak_guard)),
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
                            {
                                // One console user here; the neutral type takes
                                // a list because other platforms have several.
                                let active = Arc::clone(&seeder_active_sid);
                                Arc::new(move || active().into_iter().collect())
                            },
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
                    )
                    // Suggestions wait for the additional route: with it down
                    // every address already travels the main link, so there is
                    // no half-loaded page to offer a fix for. Same resolve the
                    // reconcile does, once per 10 s tick.
                    .with_refusing_anchors({
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str| {
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            nrr_storage::refusing_anchors::RefusingAnchorsRepository::new(&guard)
                                .list_for_sid(sid)
                                .unwrap_or_default()
                        })
                    })
                    // A third-party host is only worth a question once the
                    // main link has answered for it, so the offer waits while
                    // an answer can still arrive. Read live: switching the pass
                    // off releases the held questions on the next tick.
                    .with_main_link_pass_enabled({
                        let conn = Arc::clone(state_conn);
                        Arc::new(move |sid: &str| {
                            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
                            nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
                                .load_for_sid(sid)
                                .map(|record| record.primary_probe_auto)
                                .unwrap_or(false)
                        })
                    })
                    .with_secondary_ready({
                        let coord = Arc::clone(&route_coord);
                        Arc::new(move |sid: &str| coord.resolve_egress_ifindexes(sid).1.is_some())
                    }),
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
                // The DNS refresher is built much further down (it needs the
                // cache and the egress policy), so the apply path reaches it
                // through a slot filled once that construction lands.
                let dns_resolve_slot = Arc::clone(&dns_resolve_now_slot);
                let dns_resolve_busy = Arc::clone(&dns_resolve_now_busy);
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
                        // Publish the wider fail-closed posture the DNS handler
                        // and the seeder key on.
                        .with_fail_closed_posture_status(fail_closed_posture.clone())
                        // Tell the OTHER logged-in principals when somebody
                        // arms a cut the WFP packet layers cannot scope to one
                        // user — their ICMP and IPv6 go with it.
                        .with_events(Arc::clone(&event_bus))
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
                        // Break the connections a newly enforced destination
                        // inherited: a socket opened before the rule keeps its
                        // interface for life, so the page the user just added a
                        // rule for would otherwise finish over the old link.
                        .with_stale_flow_reset(Arc::new(
                            nrr_platform_windows::stale_flows::WindowsStaleFlowReset::new(),
                        ))
                        // Proactive VPN-client exemption: fold
                        // the verified client paths into the block-all app
                        // exemption set on every compute, so a known client is
                        // permitted BEFORE its first drop of the session.
                        .with_vpn_client_apps_provider({
                            let registry = Arc::clone(&learned_vpn_client_apps);
                            Arc::new(move || registry.current())
                        })
                        // A rule can name a host nothing has resolved yet — the
                        // browser tab that prompted it is sitting on an
                        // established socket and will never ask DNS again. Ask
                        // for those names ourselves, off this thread: the
                        // addresses land in the cache, the next reconcile builds
                        // the pins, and its teardown breaks the stale sockets.
                        .with_unresolved_hosts_sink({
                            let slot = Arc::clone(&dns_resolve_slot);
                            let busy = Arc::clone(&dns_resolve_busy);
                            Arc::new(move |hosts: Vec<String>| {
                                let Some(refresher) = slot.get().map(Arc::clone) else {
                                    return;
                                };
                                if busy
                                    .compare_exchange(
                                        false,
                                        true,
                                        std::sync::atomic::Ordering::AcqRel,
                                        std::sync::atomic::Ordering::Acquire,
                                    )
                                    .is_err()
                                {
                                    return;
                                }
                                let busy_done = Arc::clone(&busy);
                                let spawned = std::thread::Builder::new()
                                    .name("nrr-rule-host-resolve".to_string())
                                    .spawn(move || {
                                        let summary = refresher
                                            .resolve_now(&hosts, std::time::SystemTime::now());
                                        tracing::info!(
                                            target: "nrr::dns",
                                            attempted = summary.attempted,
                                            succeeded = summary.succeeded,
                                            "resolved rule hosts that had no confirmed address — enforcement picks them up on the next reconcile",
                                        );
                                        busy_done
                                            .store(false, std::sync::atomic::Ordering::Release);
                                    });
                                if spawned.is_err() {
                                    busy.store(false, std::sync::atomic::Ordering::Release);
                                }
                            })
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

    PerSidApplyStack {
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
        route_path: (
            per_sid_orchestrator,
            route_coordinator,
            rule_hostname_seeder,
            dns_observation_consumer,
            known_direct_registry,
            auto_rules_engine,
            app_destination_memory,
        ),
    }
}

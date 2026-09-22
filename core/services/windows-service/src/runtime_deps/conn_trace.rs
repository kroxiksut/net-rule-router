//! Connection-observation wiring: the two observers, the consumer they feed,
//! and the learners that hang off it.
//!
//! Everything here is `pub(super)` for one reason — it is called from
//! `build_supervised_runtime_deps` next door. Nothing is public beyond the
//! module tree of the boot wiring.

use super::*;

/// Spawn the FCrDNS learner worker. Owns the
/// `ReverseDnsLearner` (PTR + forward-confirm against the CURRENT captured
/// upstream, re-captured on a 5-min TTL like the hosts-bypass resolver) and the
/// rule-gated cache sink (the DNS-observation consumer's `learn_reverse_confirmed`
/// keep-logic), draining the named IPs off the observe-tick hot path. The thread
/// ends when the sender (held by the conn-trace consumer) is dropped at shutdown.
pub(super) fn spawn_fcrdns_learner_worker(
    rx: std::sync::mpsc::Receiver<(std::net::Ipv4Addr, bool, ReverseLearnOrigin)>,
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
            for (ip, allow_direct, origin) in rx {
                // The two feeds mean different things; only one of them is a
                // drop. Naming the wrong one costs the next reader a hunt for
                // a filter that never fired.
                let what = match origin {
                    ReverseLearnOrigin::EnforcementDrop => "dropped destination",
                    ReverseLearnOrigin::PrimaryEgress => {
                        "destination that left over the main link"
                    }
                };
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
                            what,
                            "matched a recent answer for a rule host — permit compiles on the next reconcile",
                        );
                        continue;
                    }
                }
                match learner.learn_scoped(ip, allow_direct) {
                    LearnOutcome::Learned => tracing::info!(
                        target: "nrr::fcrdns",
                        ip = %ip,
                        what,
                        "reverse-confirmed into a rule host — permit compiles on the next reconcile",
                    ),
                    // Forward-confirmed but matches NO rule: a
                    // positively-direct destination the block-all was cutting.
                    LearnOutcome::LearnedDirect => tracing::info!(
                        target: "nrr::fcrdns",
                        ip = %ip,
                        what,
                        "reverse-confirmed into a DIRECT host — block-all exemption compiles on the next reconcile",
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
pub(super) struct VpnLearningDeps<'a> {
    pub(super) learned_vpn_endpoints:
        &'a Arc<nrr_service_runtime::vpn_endpoint_learning::LearnedVpnEndpoints>,
    pub(super) killswitch_drop_registry:
        &'a Arc<nrr_service_runtime::killswitch_drop_registry::KillswitchBlockFilterRegistry>,
    /// Proactive VPN-client learning: the verified-client
    /// registry the app sink writes into (the same one the per-SID
    /// orchestrator reads for the block-all app exemption).
    pub(super) learned_vpn_client_apps:
        &'a Arc<nrr_service_runtime::vpn_client_registry::LearnedVpnClientApps>,
    /// Best-effort persistence for a newly-learned client path (state DB
    /// `vpn_client_apps`). `None` when the state DB is unavailable — the
    /// registry then stays session-scoped.
    pub(super) vpn_client_app_persist: Option<VpnClientAppPersistFn>,
    /// Companion discovery, fed from the same observations: a flow leaving
    /// over the primary while a routed site is open names an address that
    /// site needed and did not get. `None` keeps the observer diagnostic.
    pub(super) auto_rules_engine: Option<&'a Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    /// Block-notice reporting — unrelated to VPN learning, bundled here for
    /// the same "keep the argument count sane" reason as `auto_rules_engine`
    /// above. Always wired (unlike the VPN learners, it needs no gate).
    pub(super) block_notice_center:
        &'a Arc<nrr_service_runtime::block_notice_center::BlockNoticeCenter>,
    /// The live fail-closed posture, read when a drop is explained: during an
    /// outage window the outage is the reason, whichever filter caught it.
    pub(super) block_all_posture:
        &'a nrr_service_runtime::app_enforcement_status::BlockAllPostureStatus,
}

/// Best-effort write-through of one learned VPN client exe path.
pub(super) type VpnClientAppPersistFn = Arc<dyn Fn(&str) + Send + Sync>;

/// What the FCrDNS worker needs to report a reverse-named non-rule host to
/// companion discovery: the engine to tell, and whose session it belongs to.
pub(super) struct CompanionFromReverseDeps<'a> {
    pub(super) engine: &'a Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>,
    pub(super) active_sid: &'a nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
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
pub(super) struct ObservationSinks {
    /// When the FCrDNS worker is active, this sender is the naming hook: a
    /// routable V4 OUR block dropped, or one that left over the main link
    /// beside routed traffic, is enqueued for the worker to name +
    /// forward-confirm. `None` disables reverse-learning.
    pub(super) reverse_dns_learner_tx:
        Option<std::sync::mpsc::SyncSender<(std::net::Ipv4Addr, bool, ReverseLearnOrigin)>>,
    /// Deletes one remembered application destination. Wired when the state DB
    /// is open: a destination withdrawn for moving another process's traffic
    /// must not be re-seeded from disk at the next start.
    pub(super) app_destination_forget:
        Option<nrr_service_runtime::conn_observation_consumer::AppDestinationForgetFn>,
    /// The rule book's routed application patterns. Without it the collateral
    /// check cannot tell a pin from an ordinary observation and stays silent.
    pub(super) routed_apps: Option<nrr_service_runtime::conn_observation_consumer::RoutedAppsFn>,
}

/// What the connection-trace wiring hands back: the merged observation source,
/// the consumer fed from it, and the call that stops the observers.
pub(super) type ConnTraceWiring = (
    Option<Arc<dyn nrr_platform_windows::conn_observe::ConnectionObservationSource>>,
    Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionObservationConsumer>>,
    Option<Arc<dyn Fn() + Send + Sync>>,
);

/// Build the opt-in connection-egress trace source+consumer pair. Returns
/// `(None, None)` unless the trace is requested ([`conn_trace_requested`]) AND
/// the route path
/// (coordinator + active-SID resolver) is available. The WFP net-event source
/// is started here; failure to start degrades to no trace (a WARN only), the
/// same graceful-degradation contract as the DNS-Client observer.
pub(super) fn build_conn_trace_pair(
    api: &Arc<dyn WindowsApiPort>,
    route_coordinator: Option<
        &Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    ndjson_on: bool,
    trace_ring: Option<Arc<nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing>>,
    sinks: ObservationSinks,
    vpn_learning: VpnLearningDeps<'_>,
) -> ConnTraceWiring {
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
        return (None, None, None);
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
            move |ip: std::net::Ipv4Addr, allow_direct: bool, origin: ReverseLearnOrigin| {
                let _ = tx.try_send((ip, allow_direct, origin));
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
        let engine_app = Arc::clone(engine);
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
                    let reached = nrr_service_runtime::navigation_registry::global_navigation()
                        .counts_of(hostname);
                    nrr_service_runtime::navigation_registry::log_counts(hostname, &reached);
                    engine_health.note_main_link_blocked_host(
                        &sid,
                        hostname,
                        reached,
                        std::time::SystemTime::now(),
                    );
                }
            }));
        // Programs the main link carries none of: offered whole, and withdrawn
        // the moment one of their connections completes there.
        {
            let sid_for_app = Arc::clone(active_sid);
            let reach = nrr_service_runtime::app_main_link_reach::global_app_main_link_reach();
            consumer_builder = consumer_builder.with_app_main_link(Arc::new(
                move |program: &str, remote: std::net::IpAddr, stalled: bool, named: bool| {
                    let at_ms = nrr_service_runtime::conn_observation_consumer::now_unix_ms();
                    let Some(verdict) = reach.note(program, remote, stalled, named, at_ms) else {
                        return;
                    };
                    let Some(sid) = sid_for_app() else {
                        return;
                    };
                    let now = std::time::SystemTime::now();
                    match verdict {
                        nrr_service_runtime::app_main_link_reach::AppVerdict::NotCarried(
                            addresses,
                        ) => {
                            engine_app.note_app_main_link_blocked(&sid, program, &addresses, now);
                        }
                        nrr_service_runtime::app_main_link_reach::AppVerdict::Carried => {
                            engine_app.withdraw_app_offer(&sid, program, now);
                        }
                    }
                },
            ));
        }
        // Did the user go to this host, or did a page take them there? The
        // counts gate the main-link offer above; the distribution is logged so
        // the thresholds can be picked from real traffic.
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
    // Each backend hands back the call that stops it. `Drop` cannot do this
    // job: the observation task holds its own `Arc` to the source, and a task
    // the supervisor had to detach never releases it — so an ETW session and a
    // WFP subscription would outlive the process that owns them.
    type StopFn = Arc<dyn Fn() + Send + Sync>;
    let start_etw = || -> Result<(DynSource, StopFn), nrr_platform_windows::PlatformError> {
        let obs = Arc::new(
            nrr_platform_windows::conn_observe::etw_tcpip::EtwKernelNetworkObserver::start()?,
        );
        let stop = {
            let obs = Arc::clone(&obs);
            Arc::new(move || obs.shutdown()) as StopFn
        };
        Ok((obs as DynSource, stop))
    };
    // Ask BFE for allow events only when nothing else reports connections: the
    // allow half costs one machine-wide event per PERMITTED classify of every
    // process on the host, and where ETW is also running it already reports
    // every connect, with its pid. Drops arrive either way.
    use nrr_platform_windows::conn_observe::wfp_events::NetEventScope;
    let start_wfp =
        |scope: NetEventScope| -> Result<(DynSource, StopFn), nrr_platform_windows::PlatformError> {
            // Subscribing goes into the filtering engine, and a wedged engine never
            // answers: on Win11 this is where a boot stopped for good. The trace is
            // a diagnostic, so it gets a budget and the service starts without it.
            let obs = with_budget(
                "WFP net-event observer start",
                CONN_OBSERVER_START_BUDGET,
                move || {
                    nrr_platform_windows::conn_observe::wfp_events::WfpConnectionObserver::start(
                        scope,
                    )
                    .map(Arc::new)
                },
            )?;
            let stop = {
                let obs = Arc::clone(&obs);
                Arc::new(move || obs.shutdown()) as StopFn
            };
            Ok((obs as DynSource, stop))
        };
    let started: Result<(DynSource, Vec<StopFn>), nrr_platform_windows::PlatformError> =
        match backend {
            ConnTraceBackend::Etw => start_etw().map(|(s, stop)| (s, vec![stop])),
            ConnTraceBackend::Wfp => {
                start_wfp(NetEventScope::DropsAndAllows).map(|(s, stop)| (s, vec![stop]))
            }
            // Default: run BOTH and merge. ETW captures
            // every TCP connect (so codex/browser connects appear), WFP adds the
            // allow/block verdict (notably drops). Degrade gracefully to whichever
            // single backend starts; error only if BOTH fail. Merging is pure
            // fan-in over `drain()` — it adds NO observe-filter to the live WFP
            // filter set, so there is no lockout risk.
            ConnTraceBackend::Both => {
                let mut live: Vec<DynSource> = Vec::new();
                let mut stops: Vec<StopFn> = Vec::new();
                match start_etw() {
                    Ok((s, stop)) => {
                        live.push(s);
                        stops.push(stop);
                    }
                    Err(e) => tracing::warn!(
                        target: "nrr::conn-trace",
                        "ETW connection observer unavailable (merged mode) — continuing with WFP only: {e}",
                    ),
                }
                // ETW down in merged mode leaves WFP as the only source of
                // "a connection happened", so it has to carry the allow half.
                let scope = if live.is_empty() {
                    NetEventScope::DropsAndAllows
                } else {
                    NetEventScope::DropsOnly
                };
                match start_wfp(scope) {
                    Ok((s, stop)) => {
                        live.push(s);
                        stops.push(stop);
                    }
                    Err(e) => tracing::warn!(
                        target: "nrr::conn-trace",
                        "WFP connection observer unavailable (merged mode) — continuing with ETW only: {e}",
                    ),
                }
                if live.len() >= 2 {
                    Ok((
                        Arc::new(
                            nrr_platform_windows::conn_observe::MergedConnectionObservationSource::new(
                                live,
                            ),
                        ) as DynSource,
                        stops,
                    ))
                } else {
                    match live.into_iter().next() {
                        Some(one) => Ok((one, stops)),
                        None => Err(nrr_platform_windows::PlatformError::Transient {
                            operation: "conn-trace start (both backends)",
                            detail: "neither the ETW nor the WFP connection observer could start"
                                .to_string(),
                        }),
                    }
                }
            }
        };
    match started {
        Ok((source, stops)) => {
            tracing::info!(
                target: "nrr::conn-trace",
                backend = backend.slug(),
                "connection trace enabled",
            );
            // Only now is the ring actually being fed: the panel may say so.
            if let Some(ring) = trace_ring_flag {
                ring.mark_observer_active();
            }
            let shutdown: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                for stop in &stops {
                    stop();
                }
            });
            (Some(source), Some(consumer), Some(shutdown))
        }
        Err(e) => {
            tracing::warn!(
                target: "nrr::conn-trace",
                backend = backend.slug(),
                "connection observer unavailable; connection trace disabled: {e}",
            );
            (None, None, None)
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

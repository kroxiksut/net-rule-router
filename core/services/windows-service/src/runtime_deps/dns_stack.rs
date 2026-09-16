//! Factories for the DNS half of the datapath: the Mode-B resolver, the
//! fake-IP stack, the egress policy and the hosts-bypass resolver.
//!
//! They are factories rather than values because Mode B re-arms: the resolver
//! is rebuilt on every start so it re-captures the CURRENT upstream after a
//! network change. `pub(super)` — the caller is `build_supervised_runtime_deps`.

use super::*;

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
pub(super) fn build_dns_resolver_factory(
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
    // Routes a rule host's never-seen addresses before its answer goes out.
    // Absent leaves the first connect racing the full recompute, as before.
    route_coordinator: Option<
        Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
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
                route_coordinator.clone(),
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
pub(super) struct CoordinatorRelaySourceAddrs {
    pub(super) coordinator: Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    pub(super) active_sid: nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn,
    pub(super) cache: RelaySourceAddrCache,
}

type ResolvedSourceIps = (Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>);
type RelaySourceAddrCache = Mutex<Option<(std::time::Instant, ResolvedSourceIps)>>;

/// How long one adapter-source resolution serves relay dials before a fresh
/// look at the live adapters. Short enough to track a VPN reconnect promptly,
/// long enough that a burst of new flows costs one resolution.
const RELAY_SOURCE_ADDR_TTL: std::time::Duration = std::time::Duration::from_secs(3);

impl CoordinatorRelaySourceAddrs {
    pub(super) fn current(&self) -> ResolvedSourceIps {
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
pub(super) fn build_dns_egress_policy(
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

pub(super) fn build_fake_ip_stack_factory(
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
        let mut dialer = SystemRelayDialer::new()
            .with_icmp_echo(Arc::new(nrr_platform_windows::icmp_echo::WindowsIcmpEcho));
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
pub(super) fn build_hosts_bypass_resolver(
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
pub(super) fn upstream_dns_pool() -> Arc<nrr_service_runtime::dns_upstream::UpstreamDnsPool> {
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
    route_coordinator: Option<
        Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
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
    let mut reconciler = HookSyncReconciler::new(hook.clone());
    // A rule host's never-seen addresses get their routes before the answer
    // goes out; the full run that brings their filters takes seconds.
    if let Some(coordinator) = route_coordinator {
        let sid = Arc::clone(active_sid);
        reconciler =
            reconciler.with_first_contact(Arc::new(move |addresses: &[std::net::Ipv4Addr]| {
                sid().map_or(0, |sid| coordinator.route_first_contact(&sid, addresses))
            }));
    }
    let reconciler = Arc::new(reconciler);
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
    // What the routing principal's links carry decides a rule host's AAAA. The
    // plan pass publishes it, so nothing enumerates adapters per query.
    listener = listener.with_ipv6_disposition({
        let sid = Arc::clone(active_sid);
        Arc::new(move || {
            sid().map_or(
                nrr_service_runtime::enforcement_planner::Ipv6Guard::Off,
                |sid| nrr_service_runtime::ipv6_disposition::global_ipv6_dispositions().of(&sid),
            )
        })
    });
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
            .with_namespace_exemptions(Arc::new(claimed_namespaces))
            // A VPN that connects mid-session claims its namespace the moment
            // its link appears; waiting for the guard tick leaves its names
            // resolving through us for up to half a minute, and the client then
            // caches that answer on top.
            .with_namespace_recheck(Arc::clone(namespace_recheck())),
    )
}

/// One process-wide fact — "the set of links just changed" — shared by the
/// adapter monitor that observes it and the DNS guard that must act on it.
///
/// A static rather than a threaded parameter because the two live in different
/// construction paths that never meet: the resolver is built by its factory,
/// the monitor hook by the supervisor wiring. Threading a flag between them
/// would mean a parameter on everything in between, all of it to carry one bit
/// neither cares about.
pub(super) fn namespace_recheck(
) -> &'static nrr_service_runtime::dns_resolver_service::NamespaceRecheck {
    static FLAG: std::sync::OnceLock<nrr_service_runtime::dns_resolver_service::NamespaceRecheck> =
        std::sync::OnceLock::new();
    FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
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

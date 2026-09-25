//! Factories for the DNS half of the datapath: the Mode-B resolver, the
//! fake-IP stack, the egress policy and the hosts-bypass resolver.
//!
//! They are factories rather than values because Mode B re-arms: the resolver
//! is rebuilt on every start so it re-captures the CURRENT upstream after a
//! network change. `pub(super)` — the caller is `build_supervised_runtime_deps`.

use super::*;

/// The Mode-B resolver factory: the neutral assembly
/// (`nrr_service_runtime::dns_stack`) over the Windows mechanisms — NRPT, the
/// adapters' DNS servers and the namespaces connections claim. `None` if a
/// required input is missing; the controller then never arms (fail-safe).
#[allow(clippy::too_many_arguments)]
pub(super) fn build_dns_resolver_factory(
    settings_conn: Option<&Arc<Mutex<Connection>>>,
    cache_store: Option<&Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    active_routing_sid: Option<&nrr_service_runtime::supervised_runtime::ActiveRoutingSidFn>,
    route_recompute_hook: Option<&nrr_service_runtime::supervised_runtime::RouteRecomputeHook>,
    known_direct: Option<&Arc<nrr_service_runtime::known_direct::KnownDirectRegistry>>,
    block_all_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fail_closed_armed: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fake_assembly: Option<Arc<nrr_service_runtime::fake_ip::FakeIpAssembly>>,
    fake_ip_running: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    fake_ip_secondary_ready: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    egress: Option<Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>>,
    auto_rules: Option<Arc<nrr_service_runtime::auto_rules::AutoRulesEngine>>,
    signed_in: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    route_coordinator: Option<
        Arc<nrr_service_runtime::route_coordinator::SecondaryRouteCoordinator>,
    >,
) -> Option<nrr_service_runtime::dns_resolver_service::DnsResolverFactory> {
    use nrr_platform_windows::dns_redirect::{
        NrptDnsRedirect, PowerShellRunner, TransactedNrptStore, WindowsSystemDnsServers,
    };
    use nrr_service_runtime::dns_stack::{DnsStackInputs, DnsStackPlatform};

    let inputs = DnsStackInputs {
        settings_conn: Arc::clone(settings_conn?),
        cache: Arc::clone(cache_store?),
        active_sid: Arc::clone(active_routing_sid?),
        recompute_hook: route_recompute_hook?.clone(),
        known_direct: known_direct.map(Arc::clone),
        block_all_armed,
        fail_closed_armed,
        fake_assembly,
        fake_ip_running,
        fake_ip_secondary_ready,
        egress,
        auto_rules,
        signed_in,
        route_coordinator,
    };
    let platform = DnsStackPlatform {
        system_dns: Arc::new(WindowsSystemDnsServers),
        upstream_pool: upstream_dns_pool(),
        redirect: Arc::new(NrptDnsRedirect::new(PowerShellRunner, TransactedNrptStore)),
        listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 53)),
        claimed_namespaces: Arc::new(claimed_namespaces),
    };
    Some(nrr_service_runtime::dns_stack::build_dns_resolver_factory(
        inputs, platform,
    ))
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
    // `DnsQuery_W` answers when the OS is done with it; on the datapath the
    // caller cannot wait that long, so the system fallback gets a budget.
    let mut resolver = nrr_service_runtime::dns_resolver_ports::HostsBypassDnsResolver::new(
        Arc::new(nrr_platform_api::dns_budget::BudgetedDnsResolver::new(
            Arc::new(WindowsDnsResolver::new()),
        )),
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

pub(super) use nrr_service_runtime::dns_stack::namespace_recheck;

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

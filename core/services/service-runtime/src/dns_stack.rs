//! Assembly of the local DNS resolver: the listener, its upstream chain and the
//! gates around it, wired to whatever the OS supplies for the four things that
//! differ per platform — see [`DnsStackPlatform`].
//!
//! A factory rather than a value because the resolver re-arms: it is rebuilt on
//! every start so it captures the upstream that is current after a network
//! change.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_platform_api::dns::SystemDnsServersPort;
use nrr_platform_api::dns_redirect::{DnsNamespaceExemption, SystemDnsRedirectPort};
use rusqlite::Connection;

use crate::dns_resolver_service::{DnsResolverFactory, DnsResolverService, NamespaceRecheck};
use crate::dns_upstream::UpstreamDnsPool;
use crate::production_rules_provider::ProductionRulesProvider;

type Flag = Arc<dyn Fn() -> bool + Send + Sync>;

/// What the OS supplies. Everything else about the resolver is the same on
/// every platform.
#[derive(Clone)]
pub struct DnsStackPlatform {
    /// The machine's own resolvers, read before the redirect takes them over.
    pub system_dns: Arc<dyn SystemDnsServersPort>,
    /// The shared upstream choice; outlives resolver restarts.
    pub upstream_pool: Arc<UpstreamDnsPool>,
    /// Points the OS at the listener and takes it back.
    pub redirect: Arc<dyn SystemDnsRedirectPort>,
    /// Where the listener binds — the address the redirect points the OS at.
    pub listen_addr: SocketAddr,
    /// Namespaces other connections claim, read fresh on every call.
    pub claimed_namespaces: Arc<dyn Fn() -> Vec<DnsNamespaceExemption> + Send + Sync>,
}

/// The product-side inputs. Every optional one, when absent, leaves the
/// behaviour it would add off.
#[derive(Clone)]
pub struct DnsStackInputs {
    pub settings_conn: Arc<Mutex<Connection>>,
    pub cache: Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    pub active_sid: crate::supervised_runtime::ActiveRoutingSidFn,
    pub recompute_hook: crate::supervised_runtime::RouteRecomputeHook,
    pub known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
    pub block_all_armed: Option<Flag>,
    /// "Is the guard blocking an unresolved additional link?" — wider than
    /// `block_all_armed`. Absent keeps the fail-open on a missed deadline.
    pub fail_closed_armed: Option<Flag>,
    pub fake_assembly: Option<Arc<crate::fake_ip::FakeIpAssembly>>,
    pub fake_ip_running: Option<Flag>,
    /// "Can the relay carry a scope host right now?"
    pub fake_ip_secondary_ready: Option<Flag>,
    pub egress: Option<Arc<dyn crate::dns_egress::DnsEgressPolicy>>,
    pub auto_rules: Option<Arc<crate::auto_rules::AutoRulesEngine>>,
    /// "Is anyone signed in?" Absent leaves the arm ungated (test profiles).
    pub signed_in: Option<Flag>,
    /// Routes a rule host's never-seen addresses before its answer goes out.
    pub route_coordinator: Option<Arc<crate::route_coordinator::SecondaryRouteCoordinator>>,
}

/// The factory the [`DnsResolverController`] calls on each start. The
/// enforcement-mode gate lives in the controller: the factory always tries to
/// build when asked.
///
/// [`DnsResolverController`]: crate::dns_resolver_service::DnsResolverController
pub fn build_dns_resolver_factory(
    inputs: DnsStackInputs,
    platform: DnsStackPlatform,
) -> DnsResolverFactory {
    Arc::new(move || build_dns_resolver_instance(&inputs, &platform))
}

/// One process-wide fact — "the set of links just changed" — shared by the
/// adapter monitor that observes it and the DNS guard that must act on it.
/// A static because the two are built on paths that never meet.
pub fn namespace_recheck() -> &'static NamespaceRecheck {
    static FLAG: std::sync::OnceLock<NamespaceRecheck> = std::sync::OnceLock::new();
    FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
}

/// Adapts the auto-rules engine to the resolver's companion-candidate port.
struct PendingCompanionCandidates(Arc<crate::auto_rules::AutoRulesEngine>);

impl crate::dns_resolver::CompanionCandidateLookup for PendingCompanionCandidates {
    fn is_pending_secondary_companion(&self, hostname: &str) -> bool {
        self.0.covers_pending_secondary_host(hostname)
    }
}

/// Reports a collateral host to the engine under its own name.
struct RescuedCompanions {
    engine: Arc<crate::auto_rules::AutoRulesEngine>,
    active_sid: crate::supervised_runtime::ActiveRoutingSidFn,
}

impl crate::dns_resolver::CompanionRescueObserver for RescuedCompanions {
    fn note_rescued_companion(&self, hostname: &str) {
        let Some(sid) = (self.active_sid)() else {
            return;
        };
        self.engine
            .note_candidate_in_use(&sid, hostname, std::time::SystemTime::now());
    }
}

/// Build ONE resolver instance. `None` when nobody is signed in or no upstream
/// answers a probe: redirecting the OS to a resolver that cannot forward would
/// black-hole every name.
fn build_dns_resolver_instance(
    inputs: &DnsStackInputs,
    platform: &DnsStackPlatform,
) -> Option<DnsResolverService> {
    use crate::dns_listener::DnsInterceptListener;
    use crate::dns_resolver_ports::{
        ActiveRuleHostOracle, CacheFactSink, DirectUdpUpstreamResolver, HookSyncReconciler,
    };

    let active_sid = &inputs.active_sid;
    // With nobody signed in there are no rules to apply, and rewriting
    // machine-wide resolution inside the logon phase costs a frozen screen.
    // The question is "is anyone signed in", not "who do we route for": the
    // latter can be `None` while a user is right there.
    if let Some(signed_in) = inputs.signed_in.as_ref() {
        if !signed_in() {
            tracing::info!(
                target: "nrr::dns-resolver",
                "Mode B: no signed-in user yet — staying reactive until sign-in",
            );
            return None;
        }
    }

    // Settle the upstream BEFORE redirecting: once the OS points at the
    // listener, an upstream that does not answer takes every name with it.
    // The pool refuses a server that is merely configured.
    let upstream_pool = &platform.upstream_pool;
    let Some(upstream_dns) = upstream_pool.refresh() else {
        tracing::warn!(
            target: "nrr::dns-resolver",
            "Mode B requested but no upstream IPv4 DNS answered a probe; staying reactive",
        );
        return None;
    };

    let rules = || {
        Arc::new(ProductionRulesProvider::new(Arc::clone(
            &inputs.settings_conn,
        )))
    };
    let oracle = Arc::new(ActiveRuleHostOracle::new(rules(), Arc::clone(active_sid)));
    // Rule hosts go straight to the upstream over a raw socket: the system
    // resolver would honour the very redirect installed here and loop back.
    let mut direct_upstream =
        DirectUdpUpstreamResolver::new(upstream_dns, Duration::from_millis(1500), 2)
            .with_upstream_pool(Arc::clone(upstream_pool));
    if let Some(policy) = inputs.egress.clone() {
        direct_upstream = direct_upstream.with_egress(policy);
    }
    // A filtering provider answers rule hosts with a placeholder; an unusable
    // answer is re-asked of the public resolvers.
    let mut poison_fallback =
        crate::dns_resolver_ports::PoisonFallbackUpstreamResolver::new(Arc::new(direct_upstream))
            .with_recent_addresses(crate::recent_rule_addresses::global_recent_rule_addresses());
    if let Some(policy) = inputs.egress.clone() {
        poison_fallback = poison_fallback.with_egress(policy);
    }
    // Last stop before "no such name": the machine's own private resolvers,
    // the only ones that can hold a namespace the internet never heard of.
    let upstream = Arc::new(
        crate::local_namespace_fallback::LocalNamespaceFallbackResolver::new(
            Arc::new(poison_fallback),
            Arc::clone(&platform.system_dns),
            Duration::from_millis(700),
        )
        .already_asked(match upstream_dns.ip() {
            std::net::IpAddr::V4(v4) => vec![v4],
            std::net::IpAddr::V6(_) => Vec::new(),
        }),
    );
    let sink = Arc::new(CacheFactSink::new(Arc::clone(&inputs.cache)));
    let mut reconciler = HookSyncReconciler::new(inputs.recompute_hook.clone());
    if let Some(coordinator) = inputs.route_coordinator.clone() {
        let sid = Arc::clone(active_sid);
        reconciler =
            reconciler.with_first_contact(Arc::new(move |addresses: &[std::net::Ipv4Addr]| {
                sid().map_or(0, |sid| coordinator.route_first_contact(&sid, addresses))
            }));
    }
    let reconciler = Arc::new(reconciler);
    // Replies for non-rule hosts are filtered against the secondary-pinned set,
    // so a shared-CDN host gets addresses that stay on the primary path.
    let secondary_owned = Arc::new(crate::dns_resolver_ports::ActiveSecondaryOwnedIps::new(
        rules(),
        Arc::clone(active_sid),
        Arc::new(crate::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
            Arc::clone(&inputs.cache),
            nrr_domain::decision_lookup::FreshnessThresholds::default_production(),
        )),
    ));

    // A name one server calls non-existent is re-asked of the machine's
    // private resolvers: a corporate host and a LAN machine stopped resolving
    // once the whole system pointed at us.
    let private_resolvers: crate::dns_listener::PrivateResolversFn = {
        let system_dns = Arc::clone(&platform.system_dns);
        Arc::new(move || {
            system_dns
                .upstream_candidates_v4()
                .into_iter()
                .map(|c| c.server)
                .filter(|s| crate::local_namespace_fallback::is_private_resolver(*s))
                .collect()
        })
    };
    let mut listener = DnsInterceptListener::new(
        oracle,
        upstream,
        sink,
        Arc::clone(&reconciler) as Arc<dyn crate::dns_resolver::SyncReconciler>,
        upstream_dns,
        // Rule-host reconcile budget; it stalls only the querying host's answer.
        Duration::from_millis(900),
        Duration::from_millis(2000),
    )
    .with_upstream_pool(Arc::clone(upstream_pool))
    .with_direct_answer_steering(secondary_owned)
    // What the machine actually enforces, so the answer gate stops reading the
    // FQDN cache as proof that an address is carried.
    .with_enforced_view(Arc::new(
        crate::dns_resolver_ports::ActiveSidEnforcedAddresses::new(Arc::clone(active_sid)),
    ));
    listener = listener.with_private_resolvers(private_resolvers);
    listener = listener.with_ipv6_disposition({
        let sid = Arc::clone(active_sid);
        Arc::new(move || {
            sid().map_or(crate::enforcement_planner::Ipv6Guard::Off, |sid| {
                crate::ipv6_disposition::global_ipv6_dispositions().of(&sid)
            })
        })
    });
    // Withhold a rule-host answer whose enforcement missed its deadline while
    // the guard blocks an unresolved link — handing it over is the leak.
    if let Some(armed) = inputs.fail_closed_armed.clone() {
        listener = listener.with_leak_guard_posture(Arc::new(move || armed()));
    }
    // Fake-IP is wired regardless of its toggle: the live `running` gate, not a
    // resolver rebuild, turns it on and off.
    if let Some(assembly) = inputs.fake_assembly.as_ref() {
        let running = inputs
            .fake_ip_running
            .clone()
            .unwrap_or_else(|| Arc::new(|| false) as Flag);
        let scope_gate: Flag = match inputs.fake_ip_secondary_ready.clone() {
            Some(ready) => {
                let running_for_scope = Arc::clone(&running);
                Arc::new(move || running_for_scope() && ready())
            }
            None => Arc::clone(&running),
        };
        let answerer: Arc<dyn crate::dns_resolver::FakeIpAnswerer> =
            Arc::new(crate::dns_resolver::GatedFakeIpAnswerer::new(
                Arc::new(assembly.answerer()),
                scope_gate,
            ));
        listener = listener.with_fake_ip(answerer);
        if let Some(block_armed) = inputs.block_all_armed.clone() {
            let running_for_direct = Arc::clone(&running);
            let armed: Flag = Arc::new(move || block_armed() && running_for_direct());
            listener = listener.with_direct_fake_ip(Arc::new(assembly.direct_answerer(armed)));
        }
        // Collateral rescue is live whenever the stack is: the collateral
        // egresses the wrong link in every posture.
        listener = listener
            .with_collateral_fake_ip(Arc::new(assembly.direct_answerer(Arc::clone(&running))));
    }
    // …but never for a host parked as a suggestion for the additional route:
    // the rescue would push it onto the primary and break the page.
    if let Some(engine) = inputs.auto_rules.as_ref() {
        listener = listener
            .with_companion_candidates(Arc::new(PendingCompanionCandidates(Arc::clone(engine))));
        listener = listener.with_companion_rescue_observer(Arc::new(RescuedCompanions {
            engine: Arc::clone(engine),
            active_sid: Arc::clone(active_sid),
        }));
    }
    // Under the armed block-all a direct host's steered answer drives a bounded
    // reconcile before it is sent, so its first connect is not cut by the
    // catch-all. 900 ms covers the measured reconcile distribution.
    if let (Some(registry), Some(armed)) =
        (inputs.known_direct.as_ref(), inputs.block_all_armed.clone())
    {
        listener = listener.with_direct_answer_gate(Arc::new(
            crate::dns_resolver_ports::ReconcilingDirectAnswerGate::new(
                Arc::clone(registry),
                reconciler,
                armed,
                Duration::from_millis(900),
            ),
        ));
    }
    tracing::info!(
        target: "nrr::dns-resolver",
        upstream = %upstream_dns,
        listener = %platform.listen_addr,
        "Mode B armed: the local DNS resolver forwards non-rule queries to an upstream that answered a probe",
    );
    Some(
        DnsResolverService::new(
            listener,
            Arc::clone(&platform.redirect),
            platform.listen_addr,
        )
        // A corporate VPN announces its domain and servers; the product stays
        // out of names it has no business answering.
        .with_namespace_exemptions(Arc::clone(&platform.claimed_namespaces))
        // A VPN connecting mid-session claims its namespace the moment its link
        // appears, not on the next guard tick.
        .with_namespace_recheck(Arc::clone(namespace_recheck())),
    )
}

/// The persisted enforcement mode. The default on a lock or read failure, like
/// every other boot-time setting read.
pub fn read_enforcement_mode(
    conn: &Arc<Mutex<Connection>>,
) -> nrr_domain::enforcement_mode::EnforcementMode {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let Ok(guard) = conn.lock() else {
        return nrr_domain::enforcement_mode::EnforcementMode::default();
    };
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .map(|record| record.enforcement_mode)
        .unwrap_or_default()
}

/// How long one answer about who is signed in serves DNS queries. A query
/// carries no user, and asking the session manager per query would put a
/// process spawn on every name.
const ROUTING_PRINCIPAL_TTL: Duration = Duration::from_secs(3);

/// Whose rules the resolver applies: the first principal `source` reports.
/// A query reaches the listener with no trace of the user who asked, so on a
/// machine with several users signed in only one rule book can speak for DNS.
pub fn routing_principal_from(
    source: Arc<dyn nrr_platform_api::active_principals::ActivePrincipalSource>,
) -> crate::supervised_runtime::ActiveRoutingSidFn {
    type Cached = Option<(std::time::Instant, Option<String>)>;
    let cache: Arc<Mutex<Cached>> = Arc::new(Mutex::new(None));
    Arc::new(move || {
        let mut cached = cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, principal)) = cached.as_ref() {
            if at.elapsed() < ROUTING_PRINCIPAL_TTL {
                return principal.clone();
            }
        }
        let principal = source
            .active_principals()
            .ok()
            .and_then(|all| all.into_iter().next())
            .map(|p| p.as_stored().to_string());
        *cached = Some((std::time::Instant::now(), principal.clone()));
        principal
    })
}

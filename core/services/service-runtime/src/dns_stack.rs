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
use nrr_platform_api::dns_config_change::DnsConfigChangeObserver;
use nrr_platform_api::dns_redirect::{DnsNamespaceExemption, SystemDnsRedirectPort};
use nrr_platform_api::dns_servers_cache::NetworkChangeCachedDnsServers;
use nrr_platform_api::network_change::{NetworkChangeObserver, NetworkChangeSubscription};
use rusqlite::Connection;

use crate::dns_resolver_service::{
    DnsResolverFactory, DnsResolverService, NamespaceRecheck, CLAIMS_SAFETY_RECHECK_INTERVAL,
};
use crate::dns_upstream::UpstreamDnsPool;
use crate::production_rules_provider::ProductionRulesProvider;

type Flag = Arc<dyn Fn() -> bool + Send + Sync>;

/// What the OS supplies. Everything else about the resolver is the same on
/// every platform.
#[derive(Clone)]
pub struct DnsStackPlatform {
    /// The machine's own resolvers, read before the redirect takes them over.
    /// Read on the answer path: pass it through [`cached_system_dns`].
    pub system_dns: Arc<dyn SystemDnsServersPort>,
    /// The shared upstream choice; outlives resolver restarts.
    pub upstream_pool: Arc<UpstreamDnsPool>,
    /// Points the OS at the listener and takes it back.
    pub redirect: Arc<dyn SystemDnsRedirectPort>,
    /// Where the listener binds — the address the redirect points the OS at.
    pub listen_addr: SocketAddr,
    /// Namespaces other connections claim, read fresh on every call. Called
    /// on the arm, on a change the two feeds below report and once per safety
    /// interval — never per query.
    pub claimed_namespaces: Arc<dyn Fn() -> Vec<DnsNamespaceExemption> + Send + Sync>,
    /// Link and route changes.
    pub network_changes: Arc<dyn NetworkChangeObserver>,
    /// DNS settings changes that move no link or route.
    pub dns_config_changes: Arc<dyn DnsConfigChangeObserver>,
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
    let watch = watch_dns_changes(
        platform.network_changes.as_ref(),
        platform.dns_config_changes.as_ref(),
        namespace_recheck(),
    );
    let fed = watch.is_some();
    Arc::new(move || {
        // Subscribed for as long as a resolver can be built on it.
        let _subscribed = &watch;
        build_dns_resolver_instance(&inputs, &platform, fed)
    })
}

/// One process-wide fact — "what the DNS guard reads may have changed" —
/// shared by the change feeds, the settings writer and the guard that acts on
/// it. A static because they are built on paths that never meet.
pub fn namespace_recheck() -> &'static NamespaceRecheck {
    static FLAG: std::sync::OnceLock<NamespaceRecheck> = std::sync::OnceLock::new();
    FLAG.get_or_init(|| Arc::new(std::sync::atomic::AtomicBool::new(false)))
}

/// The subscriptions that raise the recheck flag; dropping it ends them.
pub(crate) struct DnsChangeWatch {
    _network: NetworkChangeSubscription,
    _dns_config: NetworkChangeSubscription,
}

/// Raise `flag` on every link, route or DNS settings change. `None` when
/// either feed cannot be subscribed: the guard then reads on every tick, as it
/// must with nothing to say what changed.
pub(crate) fn watch_dns_changes(
    network: &dyn NetworkChangeObserver,
    dns_config: &dyn DnsConfigChangeObserver,
    flag: &NamespaceRecheck,
) -> Option<DnsChangeWatch> {
    let raise =
        |flag: &NamespaceRecheck| -> nrr_platform_api::network_change::NetworkChangeCallback {
            let flag = Arc::clone(flag);
            Arc::new(move || flag.store(true, std::sync::atomic::Ordering::SeqCst))
        };
    let subscribed = network
        .subscribe(raise(flag))
        .and_then(|net| Ok((net, dns_config.subscribe(raise(flag))?)));
    match subscribed {
        Ok((network, dns_config)) => Some(DnsChangeWatch {
            _network: network,
            _dns_config: dns_config,
        }),
        Err(e) => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-stack-changes-unwatched",
                error = %e,
                "network or DNS settings changes cannot be watched; the local resolver re-reads the connections' DNS domains on every check",
            );
            None
        }
    }
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
    fed: bool,
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
                msg_key = "dns-stack-modeb-no-signed-in-user",
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
            msg_key = "dns-stack-modeb-no-upstream-answered",
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

    let private_resolvers = private_resolvers_from(Arc::clone(&platform.system_dns));
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
    let suffixes = crate::short_name_suffixes::global_user_short_name_suffixes();
    {
        let conn = inputs
            .settings_conn
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Err(e) = suffixes.reload(&conn) {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-stack-short-name-suffixes-unread",
                error = %e,
                "the short-name domains could not be read; the ones read before stay in use",
            );
        }
    }
    let user_suffix = short_name_suffix(suffixes, Arc::clone(active_sid));
    listener = listener.with_short_name_suffix(Arc::clone(&user_suffix));
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
        msg_key = "dns-stack-modeb-armed",
        upstream = %upstream_dns,
        listener = %platform.listen_addr,
        "Mode B armed: the local DNS resolver forwards non-rule queries to an upstream that answered a probe",
    );
    let service = DnsResolverService::new(
        listener,
        Arc::clone(&platform.redirect),
        platform.listen_addr,
    )
    // A corporate VPN announces its domain and servers; the product stays out
    // of names it has no business answering.
    .with_namespace_exemptions(Arc::clone(&platform.claimed_namespaces))
    // The OS completes a short name before it asks anyone, and the redirect
    // can cost it the suffixes to complete with.
    .with_short_name_suffixes(Arc::new(move || user_suffix().into_iter().collect()));
    // A VPN connecting mid-session claims its namespace the moment its link
    // appears, and a quiet machine costs the guard no read at all.
    Some(if fed {
        service.with_change_feed(
            Arc::clone(namespace_recheck()),
            CLAIMS_SAFETY_RECHECK_INTERVAL,
        )
    } else {
        service
    })
}

/// The routing principal's short-name domain, from the snapshot the settings
/// writer publishes: asked on every unanswered bare label and, on a platform
/// that writes it into the OS search list, whenever the guard reads the claims.
fn short_name_suffix(
    suffixes: &'static crate::short_name_suffixes::UserShortNameSuffixes,
    active_sid: crate::supervised_runtime::ActiveRoutingSidFn,
) -> crate::dns_listener::ShortNameSuffixFn {
    Arc::new(move || suffixes.of(&active_sid()?))
}

/// A name one server calls non-existent is re-asked of the machine's private
/// resolvers: a corporate host and a LAN machine stopped resolving once the
/// whole system pointed at us. Asked per NXDOMAIN, so `system_dns` must not
/// enumerate per call — see [`cached_system_dns`].
pub(crate) fn private_resolvers_from(
    system_dns: Arc<dyn SystemDnsServersPort>,
) -> crate::dns_listener::PrivateResolversFn {
    Arc::new(move |budget| {
        system_dns
            .upstream_candidates_v4_within(budget)
            .into_iter()
            .map(|c| c.server)
            .filter(|s| crate::local_namespace_fallback::is_private_resolver(*s))
            .collect()
    })
}

/// `servers`, enumerated once per network change or DNS-configuration change,
/// for [`DnsStackPlatform::system_dns`]. The answer path reads it on every
/// NXDOMAIN and one enumeration can be a child process, so either feed
/// re-reads it in the background and an answer waits for that read only
/// within its own budget. A DHCP-pushed domain or a VPN client's own
/// namespace moves no link or route, which is why the DNS-config feed sits
/// beside the network-change one rather than replacing it. Without the
/// network-change feed a cached list could never refresh, so the port is then
/// used as is; a DNS-config feed that cannot be watched just leaves the
/// network-change-only cache in place.
pub fn cached_system_dns(
    servers: Arc<dyn SystemDnsServersPort>,
    network: &dyn NetworkChangeObserver,
    dns_config: &dyn DnsConfigChangeObserver,
) -> Arc<dyn SystemDnsServersPort> {
    match NetworkChangeCachedDnsServers::new(Arc::clone(&servers), network) {
        Ok(cached) => Arc::new(cached.also_reading_on_dns_config_change(dns_config)),
        Err(e) => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "dns-stack-servers-uncached",
                error = %e,
                "network changes cannot be watched; every unanswered name re-reads the machine's DNS servers",
            );
            servers
        }
    }
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

/// [`read_enforcement_mode`] at call time, so a later reader sees what the
/// settings writer stored since boot. No database: the default, as at boot.
pub fn persisted_enforcement_mode(
    conn: Option<Arc<Mutex<Connection>>>,
) -> crate::supervised_runtime::EnforcementModeSource {
    Arc::new(move || conn.as_ref().map(read_enforcement_mode).unwrap_or_default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::short_name_suffixes::UserShortNameSuffixes;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::route_bindings::{BindingSource, RouteBindingsRepository, RoutePolicyRecord};

    const SID: &str = "S-1-5-21-0-0-0-1001";

    fn settings_with(
        completion: bool,
        suffix: &str,
    ) -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = SqliteMigrationRunner::for_state_db(
            open_connection(&dir.path().join("state.db")).expect("open"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let mut policy = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        policy.short_name_completion = completion;
        policy.short_name_suffix = suffix.to_string();
        RouteBindingsRepository::new(&conn)
            .update_for_sid(SID, &policy, 0)
            .expect("write policy");
        (dir, Arc::new(Mutex::new(conn)))
    }

    /// A snapshot of its own, so no other test's writes reach it.
    fn loaded_from(conn: &Arc<Mutex<Connection>>) -> &'static UserShortNameSuffixes {
        let suffixes: &'static UserShortNameSuffixes = Box::leak(Box::default());
        suffixes
            .reload(&conn.lock().expect("settings"))
            .expect("reload");
        suffixes
    }

    fn suffix_for(
        suffixes: &'static UserShortNameSuffixes,
        sid: Option<&'static str>,
    ) -> Option<String> {
        short_name_suffix(suffixes, Arc::new(move || sid.map(str::to_string)))()
    }

    #[test]
    fn the_listener_reads_the_routing_users_short_name_domain() {
        let (_dir, conn) = settings_with(true, "corp.example");
        let suffixes = loaded_from(&conn);
        assert_eq!(
            suffix_for(suffixes, Some(SID)).as_deref(),
            Some("corp.example")
        );
        assert_eq!(
            suffix_for(suffixes, None),
            None,
            "nobody routed, nothing named"
        );

        let (_dir, off) = settings_with(false, "corp.example");
        assert_eq!(
            suffix_for(loaded_from(&off), Some(SID)),
            None,
            "the switch is off"
        );
    }

    #[test]
    fn nothing_published_means_no_short_name_domain() {
        let (_dir, _conn) = settings_with(true, "corp.example");
        let unpublished: &'static UserShortNameSuffixes = Box::leak(Box::default());

        assert_eq!(suffix_for(unpublished, Some(SID)), None);
    }

    /// The answer path never touches the settings database: a row changed
    /// behind the snapshot's back is invisible to any number of answers.
    #[test]
    fn short_name_answers_read_no_settings() {
        let (_dir, conn) = settings_with(true, "corp.example");
        let suffixes = loaded_from(&conn);
        let mut policy = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        policy.short_name_completion = true;
        policy.short_name_suffix = "other.example".to_string();
        RouteBindingsRepository::new(&conn.lock().expect("settings"))
            .update_for_sid(SID, &policy, 1)
            .expect("write behind the snapshot");

        for _ in 0..100 {
            assert_eq!(
                suffix_for(suffixes, Some(SID)).as_deref(),
                Some("corp.example")
            );
        }
    }

    /// Positive control for the one above: the service's own settings write
    /// reaches the very next answer.
    #[test]
    fn a_settings_write_reaches_the_next_short_name_answer() {
        use crate::ipc_handlers::providers::RoutePolicyWriter;
        const WRITER_SID: &str = "S-1-5-21-0-0-0-1077";
        let (_dir, conn) = settings_with(false, "");
        let writer =
            crate::production_handlers_misc::ProductionRoutePolicyWriter::new(Arc::clone(&conn));
        let suffixes = crate::short_name_suffixes::global_user_short_name_suffixes();
        let request = |completion: bool, suffix: &str| {
            serde_json::from_value::<crate::ipc_handlers::payloads::RoutePolicyUpdateRequest>(
                serde_json::json!({
                    "mode": "prefer-primary",
                    "block-secondary-when-unavailable": true,
                    "kill-switch-block-all": false,
                    "kill-switch-enabled": true,
                    "doh-lockdown-enabled": false,
                    "kill-switch-strict-shared-ips": false,
                    "binding-source": "user-assigned",
                    "short-name-completion": completion,
                    "short-name-suffix": suffix,
                }),
            )
            .expect("request")
        };
        assert_eq!(suffix_for(suffixes, Some(WRITER_SID)), None);

        writer
            .update_for_sid(WRITER_SID, &request(true, "corp.example"))
            .expect("write");
        assert_eq!(
            suffix_for(suffixes, Some(WRITER_SID)).as_deref(),
            Some("corp.example")
        );

        writer
            .update_for_sid(WRITER_SID, &request(false, "corp.example"))
            .expect("write");
        assert_eq!(suffix_for(suffixes, Some(WRITER_SID)), None);
    }

    struct CountingServers {
        calls: std::sync::atomic::AtomicUsize,
        answer: Vec<nrr_platform_api::dns::UpstreamDnsCandidate>,
    }

    impl CountingServers {
        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SystemDnsServersPort for CountingServers {
        fn upstream_candidates_v4(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsCandidate> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.answer.clone()
        }
    }

    /// Hands the test the callback the OS would call.
    #[derive(Default)]
    struct ManualObserver(Mutex<Option<nrr_platform_api::network_change::NetworkChangeCallback>>);

    impl ManualObserver {
        fn fire(&self) {
            let callback = self.0.lock().expect("observer").clone();
            if let Some(callback) = callback {
                callback();
            }
        }
    }

    impl NetworkChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: nrr_platform_api::network_change::NetworkChangeCallback,
        ) -> Result<
            nrr_platform_api::network_change::NetworkChangeSubscription,
            nrr_platform_api::error::PlatformError,
        > {
            *self.0.lock().expect("observer") = Some(on_change);
            Ok(nrr_platform_api::network_change::NetworkChangeSubscription::inert())
        }
    }

    impl DnsConfigChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: nrr_platform_api::network_change::NetworkChangeCallback,
        ) -> Result<
            nrr_platform_api::network_change::NetworkChangeSubscription,
            nrr_platform_api::error::PlatformError,
        > {
            NetworkChangeObserver::subscribe(self, on_change)
        }
    }

    struct Refusing;

    impl DnsConfigChangeObserver for Refusing {
        fn subscribe(
            &self,
            _on_change: nrr_platform_api::network_change::NetworkChangeCallback,
        ) -> Result<
            nrr_platform_api::network_change::NetworkChangeSubscription,
            nrr_platform_api::error::PlatformError,
        > {
            Err(nrr_platform_api::error::PlatformError::NotSupported {
                reason: "no DNS settings notification",
            })
        }
    }

    /// A link change and a DNS settings change each tell the guard to read.
    #[test]
    fn either_feed_raises_the_recheck() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        let (network, dns_config) = (ManualObserver::default(), ManualObserver::default());
        let watch = watch_dns_changes(&network, &dns_config, &flag);
        assert!(watch.is_some());
        assert!(!flag.load(Ordering::SeqCst), "nothing happened yet");

        network.fire();
        assert!(flag.swap(false, Ordering::SeqCst), "a link change");
        dns_config.fire();
        assert!(flag.swap(false, Ordering::SeqCst), "a DNS settings change");
    }

    /// With either feed missing nothing could say what changed, so the
    /// resolver is built without a feed and its guard reads on every tick.
    #[test]
    fn a_feed_that_cannot_be_watched_means_no_feed() {
        use std::sync::atomic::AtomicBool;
        let flag: NamespaceRecheck = Arc::new(AtomicBool::new(false));
        assert!(watch_dns_changes(&ManualObserver::default(), &Refusing, &flag).is_none());
    }

    struct NoSuchName;

    impl crate::dns_resolver::UpstreamResolver for NoSuchName {
        fn resolve_within(
            &self,
            _hostname: &str,
            _family: nrr_platform_api::dns::AddressFamily,
            _budget: Duration,
        ) -> Result<crate::dns_resolver::ResolvedAddresses, crate::dns_resolver::ResolveError>
        {
            Err(crate::dns_resolver::ResolveError::NoRecords)
        }
    }

    /// Both answer-path readers of the machine's resolvers — the listener's
    /// private-resolver list and the rule-host fallback — share one
    /// enumeration per network change.
    #[test]
    fn nxdomain_answers_enumerate_the_resolvers_once_per_network_change() {
        let inner = Arc::new(CountingServers {
            calls: Default::default(),
            // Public only: nothing to ask, so the loop measures the reads alone.
            answer: vec![nrr_platform_api::dns::UpstreamDnsCandidate::new(
                Some(2),
                std::net::Ipv4Addr::new(192, 0, 2, 53),
            )],
        });
        let observer = ManualObserver::default();
        let servers = cached_system_dns(Arc::clone(&inner) as _, &observer, &observer);
        let private = private_resolvers_from(Arc::clone(&servers));
        let fallback = crate::local_namespace_fallback::LocalNamespaceFallbackResolver::new(
            Arc::new(NoSuchName),
            servers,
            Duration::from_millis(50),
        );
        let answer_many = || {
            for _ in 0..100 {
                assert!(private(Duration::from_millis(50)).is_empty());
                let nx = crate::dns_resolver::UpstreamResolver::resolve_within(
                    &fallback,
                    "host.corp.example",
                    nrr_platform_api::dns::AddressFamily::Ipv4,
                    Duration::from_millis(50),
                );
                assert!(matches!(
                    nx,
                    Err(crate::dns_resolver::ResolveError::NoRecords)
                ));
            }
        };

        answer_many();
        assert_eq!(inner.calls(), 1, "one warm-up enumeration");

        observer.fire();
        answer_many();
        assert_eq!(inner.calls(), 2, "one more after the network changed");
    }

    /// The same cache also answers to a DNS-configuration change on its own
    /// feed — a DHCP-pushed domain or a VPN client's namespace reaches the
    /// same warm-up worker without a link or route event, and a burst that
    /// touches both feeds together still costs one enumeration.
    #[test]
    fn nxdomain_answers_enumerate_once_per_dns_config_change_and_once_per_burst() {
        let inner = Arc::new(CountingServers {
            calls: Default::default(),
            answer: vec![nrr_platform_api::dns::UpstreamDnsCandidate::new(
                Some(2),
                std::net::Ipv4Addr::new(192, 0, 2, 53),
            )],
        });
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let servers = cached_system_dns(Arc::clone(&inner) as _, &network, &dns_config);
        let private = private_resolvers_from(Arc::clone(&servers));
        assert!(private(Duration::from_millis(50)).is_empty());
        assert_eq!(inner.calls(), 1, "one warm-up enumeration");

        dns_config.fire();
        assert!(private(Duration::from_secs(2)).is_empty());
        assert_eq!(inner.calls(), 2, "the DNS-config feed alone re-read it");

        for _ in 0..5 {
            network.fire();
            dns_config.fire();
        }
        assert!(private(Duration::from_secs(2)).is_empty());
        assert_eq!(inner.calls(), 3, "a burst on both feeds is one more read");
    }

    /// Enumerates as slowly as a PowerShell run.
    struct SlowServers {
        calls: std::sync::atomic::AtomicUsize,
        took: Duration,
    }

    impl SystemDnsServersPort for SlowServers {
        fn upstream_candidates_v4(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsCandidate> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(self.took);
            vec![nrr_platform_api::dns::UpstreamDnsCandidate::new(
                Some(2),
                std::net::Ipv4Addr::new(10, 0, 0, 53),
            )]
        }
    }

    /// NXDOMAIN answers arriving while a change re-reads the resolvers keep to
    /// their own budget and start no enumeration of their own; the next ones
    /// find the list the change read.
    #[test]
    fn nxdomain_answers_during_a_re_read_keep_their_budget() {
        let inner = Arc::new(SlowServers {
            calls: Default::default(),
            took: Duration::from_millis(600),
        });
        let observer = ManualObserver::default();
        let servers = cached_system_dns(Arc::clone(&inner) as _, &observer, &observer);
        let private = private_resolvers_from(servers);
        let calls = || inner.calls.load(std::sync::atomic::Ordering::SeqCst);
        let wanted = vec![std::net::Ipv4Addr::new(10, 0, 0, 53)];
        assert_eq!(private(Duration::from_secs(10)), wanted);

        observer.fire();
        for _ in 0..5 {
            let started = std::time::Instant::now();
            assert!(private(Duration::from_millis(20)).is_empty());
            assert!(started.elapsed() < Duration::from_millis(400));
        }
        assert!(calls() <= 2, "the answers started no enumeration");

        assert_eq!(private(Duration::from_secs(10)), wanted);
        assert_eq!(calls(), 2);
        for _ in 0..50 {
            assert_eq!(private(Duration::ZERO), wanted);
        }
        assert_eq!(calls(), 2);
    }
}

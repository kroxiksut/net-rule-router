//! Production adapters wiring the neutral relay ports to real data sources.
//!
//! The relay ([`super::relay`]) decides each flow over two injected ports:
//! [`UpstreamAddressResolver`] (where does this hostname really live?) and
//! [`RouteSelector`] (which link must its traffic leave over?). In tests those
//! are fixtures; in the running service they read the FQDN cache and the active
//! rule book — the SAME sources the WFP codegen and the DNS observer already use.
//! So a hostname answered with a fake address is relayed to exactly the real
//! addresses the cache learned, over exactly the link its rule selected, with no
//! second copy of that policy to drift out of sync.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_platform_api::dns::DnsResolverPort;
use nrr_shared::RouteRole;
use nrr_storage::repository::CacheRepository;

use crate::dns_observation_consumer::rule_covers;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::RulesProvider;
use crate::service_tasks::ServiceTaskKind;
use crate::task_liveness::{TaskLiveness, ThreadExit, ThreadLease, Watch};

use super::dialer::RelayNameResolver;
use super::relay::{FlowOwner, FlowOwners, RouteSelector, UpstreamAddressResolver};
use nrr_platform_api::dns::AddressFamily;
use nrr_platform_api::fake_ip::{FlowOwnerLookup, FlowTransport};

/// [`UpstreamAddressResolver`] over the FQDN cache.
///
/// The relay dials the real addresses the cache already holds for the hostname.
/// They are warm by construction: the resolver records the real answer into the
/// cache immediately before handing the application the fake address (see
/// `dns_resolver::handle_a_query`), so the address is present by the time the
/// application's first packet reaches the TUN.
pub struct CacheUpstreamResolver {
    cache: Arc<dyn FqdnCacheLookup>,
}

impl CacheUpstreamResolver {
    #[must_use]
    pub fn new(cache: Arc<dyn FqdnCacheLookup>) -> Self {
        Self { cache }
    }
}

impl UpstreamAddressResolver for CacheUpstreamResolver {
    fn addresses_for(&self, hostname: &str) -> Vec<IpAddr> {
        // IPv4 only today, as is the whole resolver path; when the cache begins
        // learning AAAA a v6 arm widens this without touching the relay.
        self.cache.ips_for_hostname(hostname)
    }
}

/// [`RelayNameResolver`] over the same confirmed resolver the rest of the
/// service uses, with the answer written back to the FQDN cache.
///
/// This runs on a dial thread, once per hostname the cache did not know. The
/// short memo is what keeps it that way: a page opens dozens of connections to
/// the same host within a second, and without it each one would repeat the
/// lookup while the cache write is still in flight.
pub struct ConfirmedNameResolver {
    resolver: Arc<dyn DnsResolverPort>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    memo: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

/// How long a dial-time answer is reused before asking again. Long enough to
/// cover one page load, short enough that it is the FQDN cache — refreshed on
/// its own schedule — that owns the durable answer.
const NAME_MEMO_TTL: Duration = Duration::from_secs(30);

/// Cap on memo entries, so a scan of many names cannot grow it without bound.
const NAME_MEMO_CAP: usize = 256;

impl ConfirmedNameResolver {
    #[must_use]
    pub fn new(
        resolver: Arc<dyn DnsResolverPort>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
    ) -> Self {
        Self {
            resolver,
            cache,
            memo: Mutex::new(HashMap::new()),
        }
    }

    fn remembered(&self, hostname: &str) -> Option<Vec<IpAddr>> {
        let memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        memo.get(hostname)
            .filter(|(_, at)| at.elapsed() < NAME_MEMO_TTL)
            .map(|(ips, _)| ips.clone())
    }

    fn remember(&self, hostname: &str, addresses: &[IpAddr]) {
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if memo.len() >= NAME_MEMO_CAP {
            memo.clear();
        }
        memo.insert(hostname.to_string(), (addresses.to_vec(), Instant::now()));
    }
}

impl RelayNameResolver for ConfirmedNameResolver {
    fn resolve(&self, hostname: &str) -> Vec<IpAddr> {
        if let Some(known) = self.remembered(hostname) {
            return known;
        }
        let Ok(record) = self.resolver.resolve(hostname, AddressFamily::Ipv4) else {
            // Remember nothing on failure: the next connection attempt — often
            // the browser's own retry a second later — should try again.
            return Vec::new();
        };
        let addresses = record.addresses.clone();
        if addresses.is_empty() {
            return addresses;
        }
        self.remember(hostname, &addresses);
        // Write it where every other surface reads from, so the routes and
        // filters for this host stop being empty as well — the relay carrying
        // the flow is only half the job.
        if let Ok(cache) = self.cache.lock() {
            if let Err(error) = cache.upsert_resolution(nrr_storage::dto::ResolutionEntry {
                canonical_hostname: record.canonical_hostname.clone(),
                raw_hostname_sample: None,
                resolved_ips: record.addresses.clone(),
                ttl_seconds: record.ttl_seconds,
                source: nrr_storage::resolution_source::StorageResolutionSource::Dns,
                resolved_at: std::time::SystemTime::now(),
                active_revision_id: None,
            }) {
                tracing::debug!(
                    target: "nrr::fake_ip",
                    hostname = %hostname,
                    error = %error,
                    "resolved at dial time but could not cache it — the flow still goes through",
                );
            }
        }
        addresses
    }
}

/// How many un-processed flow notices may wait before new ones are dropped.
///
/// Deep enough that an ordinary page load (dozens of hosts at once) never
/// touches it, shallow enough that a stalled worker cannot grow without bound.
const FLOW_NOTICE_QUEUE_DEPTH: usize = 256;

/// One notice held longer than this is a worker stuck behind the ledger lock.
const FLOW_NOTICE_WORK_DEADLINE: Duration = Duration::from_secs(60);

/// Feeds relayed flows to companion discovery as activity.
///
/// The learner opens a window when it is told a routed site is in use, and its
/// only source for that was DNS. A browser answering from its own cache — or
/// over DoH, where we see nothing at all — left the window shut while the user
/// was on the page, so the CDN hosts loading beside it had no anchor to attach
/// to and were never proposed. A relayed flow is the same fact, arriving from a
/// channel nothing can cache away.
///
/// **`on_flow_opened` runs on the stack's poll thread while a TCP connection is
/// being established, so it must be prompt.** SID resolution and rule-set
/// matching take the GLOBAL ledger mutex — the same mutex the discovery tick
/// holds while it qualifies up to tens of thousands of candidate pairs — so
/// that work runs on this observer's own worker thread instead. The hot path
/// only hands over the hostname and the instant; the queue is bounded and a
/// full queue DROPS the notice, because an observation is optional and a
/// connection is not.
/// A relayed flow's hostname, owner (`None` = the routing user) and time.
type FlowNotice = (String, Option<String>, SystemTime);

pub struct FlowActivityObserver {
    notices: std::sync::mpsc::SyncSender<FlowNotice>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl FlowActivityObserver {
    #[must_use]
    pub fn new(
        engine: Arc<crate::auto_rules::AutoRulesEngine>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        liveness: Option<Arc<TaskLiveness>>,
    ) -> Self {
        let (notices, inbox) = std::sync::mpsc::sync_channel::<FlowNotice>(FLOW_NOTICE_QUEUE_DEPTH);
        // The worker ends when the sender goes — i.e. when the stack drops this
        // observer during teardown. No stop token to keep in sync.
        let spawned = std::thread::Builder::new()
            .name("nrr-flow-observer".to_owned())
            .spawn(move || {
                let lease = liveness.as_ref().map(|l| {
                    l.lease(
                        ServiceTaskKind::FakeIpFlowObserver,
                        None,
                        Watch::Work(FLOW_NOTICE_WORK_DEADLINE),
                    )
                });
                while let Ok((hostname, owner, at)) = inbox.recv() {
                    let _notice = lease.as_ref().map(ThreadLease::work);
                    // Another served user's flow teaches their book, not the
                    // routing user's.
                    if let Some(sid) = owner.or_else(|| active_sid()) {
                        engine.note_flow(&sid, &hostname, at);
                    }
                }
                if let Some(lease) = lease {
                    lease.finish(ThreadExit::Stopped);
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(
                target: "nrr::fake-ip",
                msg_key = "fakeip-flow-worker-start-failed",
                %error,
                "could not start the flow-activity worker — companion discovery will not see relayed flows",
            );
        }
        Self {
            notices,
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

impl super::stack::FlowObserver for FlowActivityObserver {
    fn on_flow_opened(
        &self,
        _client: SocketAddr,
        _fake: SocketAddr,
        hostname: &str,
        owner: Option<&str>,
    ) {
        if hostname.is_empty() {
            return;
        }
        if self
            .notices
            .try_send((
                hostname.to_owned(),
                owner.map(str::to_owned),
                SystemTime::now(),
            ))
            .is_err()
        {
            // Full, or the worker is gone. Either way the connection continues;
            // the count is logged sparsely so a persistent stall is visible
            // without a line per dropped flow.
            let n = self
                .dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            if n == 1 || n.is_multiple_of(512) {
                tracing::warn!(
                    target: "nrr::fake-ip",
                    msg_key = "fakeip-flow-notices-dropped",
                    dropped = n,
                    "flow-activity notices are being dropped — companion discovery is behind",
                );
            }
        }
    }
}

/// Fans one flow notification out to several observers.
///
/// The stack holds exactly one; self-heal and companion discovery both need it,
/// and neither should have to know the other exists.
pub struct CompositeFlowObserver {
    observers: Vec<Arc<dyn super::stack::FlowObserver>>,
}

impl CompositeFlowObserver {
    #[must_use]
    pub fn new(observers: Vec<Arc<dyn super::stack::FlowObserver>>) -> Self {
        Self { observers }
    }
}

impl super::stack::FlowObserver for CompositeFlowObserver {
    fn on_flow_opened(
        &self,
        client: SocketAddr,
        fake: SocketAddr,
        hostname: &str,
        owner: Option<&str>,
    ) {
        for observer in &self.observers {
            observer.on_flow_opened(client, fake, hostname, owner);
        }
    }
}

/// [`RouteSelector`] over the active rule book.
///
/// A hostname that matches an enabled **secondary** rule for the routing-active
/// principal leaves over the secondary link; everything else takes the primary.
/// Hosts are matched by the same `rule_covers` the DNS oracle and the observer
/// use, so fake-IP steers a host to the link the filters do — which is also why
/// a rule enforcement skips for its shape is left out.
pub struct RuleBookRouteSelector {
    rules_provider: Arc<dyn RulesProvider>,
    active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl RuleBookRouteSelector {
    #[must_use]
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        Self {
            rules_provider,
            active_sid,
        }
    }
}

/// A rule enforcement skips for its shape steers and blocks nothing here
/// either.
fn steers(rule: &nrr_domain::canonical::CanonicalRule) -> bool {
    rule.enabled && crate::wfp_codegen::rule_shape_enforced(rule)
}

fn secondary_covers(book: &nrr_domain::canonical::CanonicalRuleBook, hostname: &str) -> bool {
    book.secondary
        .rules()
        .iter()
        .any(|r| steers(r) && rule_covers(r, hostname))
}

/// Whether the narrowest name rule claiming `hostname` in `book` is a block.
/// A block and a route equally narrow leave it blocked.
fn book_blocks(book: &nrr_domain::canonical::CanonicalRuleBook, hostname: &str) -> bool {
    use nrr_domain::rule_specificity::rule_match_specificity;
    let mut block = None;
    let mut route = None;
    for rule in book
        .primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .filter(|r| steers(r) && r.app_match.is_none())
    {
        let claim = rule_match_specificity(hostname, rule);
        match rule.action {
            nrr_domain::RuleAction::Block => block = block.max(claim),
            nrr_domain::RuleAction::Route | nrr_domain::RuleAction::Verify => {
                route = route.max(claim)
            }
        }
    }
    block.is_some() && block >= route
}

impl RouteSelector for RuleBookRouteSelector {
    fn route_for(&self, hostname: &str) -> RouteRole {
        let is_secondary = (self.active_sid)()
            .and_then(|sid| self.rules_provider.active_rules_for(&sid))
            .is_some_and(|snapshot| secondary_covers(&snapshot.rule_book, hostname));
        if is_secondary {
            RouteRole::Secondary
        } else {
            RouteRole::Primary
        }
    }

    /// The shared DNS answer was given by the routing user's book, so a host
    /// this user blocks can arrive here: their own filters never see the
    /// relay's dial, and the block is honoured here instead.
    fn route_for_principal(&self, principal: &str, hostname: &str) -> Option<RouteRole> {
        let Some(snapshot) = self.rules_provider.active_rules_for(principal) else {
            return Some(RouteRole::Primary);
        };
        if book_blocks(&snapshot.rule_book, hostname) {
            return None;
        }
        Some(if secondary_covers(&snapshot.rule_book, hostname) {
            RouteRole::Secondary
        } else {
            RouteRole::Primary
        })
    }
}

/// The served users, longest-served first.
pub type ServedPrincipalsFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// [`FlowOwners`] for the running service: nobody is looked up while one
/// user is served, so a single-user machine pays nothing; with two or more,
/// each new flow's owner is read from the connection table, and a flow whose
/// owner is unknown or not served is refused.
pub struct ServedFlowOwners {
    lookup: Arc<dyn FlowOwnerLookup>,
    served: ServedPrincipalsFn,
    routing: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl ServedFlowOwners {
    #[must_use]
    pub fn new(
        lookup: Arc<dyn FlowOwnerLookup>,
        served: ServedPrincipalsFn,
        routing: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        Self {
            lookup,
            served,
            routing,
        }
    }
}

/// A machine account (LocalSystem, LocalService, NetworkService, a per-service
/// SID): its traffic follows the route-table owner, as the leak guard has it.
fn is_service_account(principal: &str) -> bool {
    nrr_platform_api::types::is_service_account_sid(principal)
}

impl FlowOwners for ServedFlowOwners {
    fn owner_of(
        &self,
        client: SocketAddr,
        destination: SocketAddr,
        transport: Option<FlowTransport>,
    ) -> FlowOwner {
        let served = (self.served)();
        if served.len() < 2 {
            return FlowOwner::RoutingUser;
        }
        let Some(transport) = transport else {
            return FlowOwner::Refused("owner-unreadable");
        };
        let Some(owner) = self.lookup.owner_principal(client, destination, transport) else {
            return FlowOwner::Refused("owner-unknown");
        };
        if is_service_account(&owner) {
            return FlowOwner::RoutingUser;
        }
        let Some(principal) = served
            .into_iter()
            .find(|sid| sid.eq_ignore_ascii_case(&owner))
        else {
            return FlowOwner::Refused("owner-not-served");
        };
        if (self.routing)().is_some_and(|routing| routing == principal) {
            FlowOwner::RoutingUser
        } else {
            FlowOwner::Principal(principal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::RuleId;
    use std::net::Ipv4Addr;

    /// `on_flow_opened` runs while a TCP connection is being established, so it
    /// must hand the fact over and return without waiting on SID resolution or
    /// the global ledger mutex — the same mutex the discovery tick holds through
    /// tens of thousands of qualify calls. A backlog must cost observations,
    /// never connections.
    #[test]
    fn a_flow_notice_never_waits_on_the_worker() {
        use super::super::stack::FlowObserver;
        use crate::auto_rules::{AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore};
        use crate::per_sid_orchestrator::{NoopRulesProvider, RulesProvider};
        use nrr_storage::auto_rules::AutoRulesMode;
        use std::sync::atomic::Ordering;
        use std::time::{Duration, Instant};

        let engine = Arc::new(AutoRulesEngine::new(
            Arc::new(NoopRulesProvider) as Arc<dyn RulesProvider>,
            Arc::new(|_: &str| AutoRulesMode::Off),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::UNIX_EPOCH,
        ));

        // A slow worker, not a stuck one: a regression here has to FAIL the
        // time assertion below, not hang the suite waiting for a lock.
        let active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync> = Arc::new(|| {
            std::thread::sleep(Duration::from_millis(20));
            Some("S-1-5-21-test".to_owned())
        });
        let observer = FlowActivityObserver::new(engine, active_sid, None);

        let addr: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let notices = FLOW_NOTICE_QUEUE_DEPTH * 2;
        let started = Instant::now();
        for _ in 0..notices {
            observer.on_flow_opened(addr, addr, "cdn.example.net", None);
        }
        let elapsed = started.elapsed();

        // Doing the work inline would have cost `notices * 20 ms` — ten seconds
        // of connection latency for this many flows.
        assert!(
            elapsed < Duration::from_secs(2),
            "the connection path blocked for {elapsed:?} behind a slow observer",
        );
        assert!(
            observer.dropped.load(Ordering::Relaxed) > 0,
            "a full queue must drop notices, not wait",
        );
    }

    #[test]
    fn cache_resolver_returns_cached_v4_addresses() {
        let cache = Arc::new(MockFqdnCacheLookup::new());
        cache.set_ips(
            "assistant.example",
            vec![
                Ipv4Addr::new(203, 0, 113, 140),
                Ipv4Addr::new(203, 0, 113, 141),
            ],
        );
        let resolver = CacheUpstreamResolver::new(cache);
        assert_eq!(
            resolver.addresses_for("assistant.example"),
            vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 140)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 141)),
            ]
        );
        // An un-cached host yields nothing — the relay then fails the flow closed
        // rather than dialling a guess.
        assert!(resolver.addresses_for("unknown.example").is_empty());
    }

    struct FakeRules {
        primary: CanonicalRuleSet,
        secondary: CanonicalRuleSet,
    }
    impl RulesProvider for FakeRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: self.primary.clone(),
                    secondary: self.secondary.clone(),
                },
            })
        }
    }

    fn exact_rule(id: &str, host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn selector_for(secondary_host: &str, sid: Option<&'static str>) -> RuleBookRouteSelector {
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![exact_rule("r-p", "primary.example")]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", secondary_host)]),
        });
        RuleBookRouteSelector::new(rules, Arc::new(move || sid.map(str::to_string)))
    }

    #[test]
    fn route_selector_steers_secondary_hosts_and_defaults_others_to_primary() {
        let selector = selector_for("assistant.example", Some("S-1-5-21-1"));
        assert_eq!(
            selector.route_for("assistant.example"),
            RouteRole::Secondary
        );
        // A primary-only rule host, and an unmatched host, both take the primary.
        assert_eq!(selector.route_for("primary.example"), RouteRole::Primary);
        assert_eq!(selector.route_for("random.example.net"), RouteRole::Primary);
    }

    #[test]
    fn route_selector_defaults_to_primary_with_no_active_principal() {
        let selector = selector_for("assistant.example", None);
        assert_eq!(selector.route_for("assistant.example"), RouteRole::Primary);
    }

    fn suffix_rule(id: &str, suffix: &str, action: nrr_domain::RuleAction) -> CanonicalRule {
        CanonicalRule {
            address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix.into())),
            action,
            ..exact_rule(id, "unused.example")
        }
    }

    /// Each served user's flow takes that user's book: the blocks in it hold
    /// even though the relay's own dial passes every user's filters, and the
    /// narrower rule still beats the wider block.
    #[test]
    fn another_users_book_routes_and_blocks_their_flow() {
        let mut blocked = exact_rule("r-b", "blocked.example");
        blocked.action = nrr_domain::RuleAction::Block;
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![
                blocked,
                suffix_rule("r-w", "wide.example", nrr_domain::RuleAction::Block),
                exact_rule("r-n", "open.wide.example"),
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![exact_rule("r-s", "tunnel.example")]),
        });
        let selector = RuleBookRouteSelector::new(rules, Arc::new(|| None::<String>));

        let route = |host| selector.route_for_principal("S-1-5-21-2", host);
        assert_eq!(route("tunnel.example"), Some(RouteRole::Secondary));
        assert_eq!(route("blocked.example"), None);
        assert_eq!(route("deep.wide.example"), None);
        assert_eq!(route("open.wide.example"), Some(RouteRole::Primary));
        assert_eq!(route("elsewhere.example"), Some(RouteRole::Primary));
    }

    fn owners(
        served: &'static [&'static str],
        lookup: Arc<MockFlowOwnerLookup>,
    ) -> ServedFlowOwners {
        ServedFlowOwners::new(
            lookup,
            Arc::new(move || served.iter().map(|s| s.to_string()).collect()),
            Arc::new(move || served.first().map(|s| s.to_string())),
        )
    }

    use nrr_platform_api::MockFlowOwnerLookup;

    /// With two users served, a flow is carried for its own owner, a service
    /// account follows the routing user, and a flow nobody can be named for
    /// is refused rather than carried by somebody else's rules.
    #[test]
    fn a_flow_is_carried_for_its_owner_when_two_users_are_served() {
        let fake: SocketAddr = "198.18.0.9:443".parse().expect("addr");
        let a: SocketAddr = "10.0.0.2:50001".parse().expect("addr");
        let b: SocketAddr = "10.0.0.2:50002".parse().expect("addr");
        let svc: SocketAddr = "10.0.0.2:50003".parse().expect("addr");
        let ghost: SocketAddr = "10.0.0.2:50004".parse().expect("addr");
        let stranger: SocketAddr = "10.0.0.2:50005".parse().expect("addr");
        let lookup = Arc::new(MockFlowOwnerLookup::new());
        lookup.set_principal(a, FlowTransport::Tcp, "S-1-5-21-1");
        lookup.set_principal(b, FlowTransport::Tcp, "S-1-5-21-2");
        lookup.set_principal(svc, FlowTransport::Tcp, "S-1-5-18");
        lookup.set_principal(stranger, FlowTransport::Tcp, "S-1-5-21-9");
        let owners = owners(&["S-1-5-21-1", "S-1-5-21-2"], lookup);

        let tcp = Some(FlowTransport::Tcp);
        assert_eq!(owners.owner_of(a, fake, tcp), FlowOwner::RoutingUser);
        assert_eq!(
            owners.owner_of(b, fake, tcp),
            FlowOwner::Principal("S-1-5-21-2".into())
        );
        assert_eq!(owners.owner_of(svc, fake, tcp), FlowOwner::RoutingUser);
        assert!(matches!(
            owners.owner_of(ghost, fake, tcp),
            FlowOwner::Refused(_)
        ));
        assert!(matches!(
            owners.owner_of(stranger, fake, tcp),
            FlowOwner::Refused(_)
        ));
        assert!(matches!(
            owners.owner_of(b, fake, None),
            FlowOwner::Refused(_)
        ));
    }

    /// One user served: no lookup at all, whatever the table would say.
    #[test]
    fn a_single_user_machine_never_looks_an_owner_up() {
        let lookup = Arc::new(MockFlowOwnerLookup::new());
        let owners = owners(&["S-1-5-21-1"], Arc::clone(&lookup));
        let any: SocketAddr = "10.0.0.2:50001".parse().expect("addr");
        assert_eq!(owners.owner_of(any, any, None), FlowOwner::RoutingUser);
        assert_eq!(lookup.call_count(), 0);
    }
}

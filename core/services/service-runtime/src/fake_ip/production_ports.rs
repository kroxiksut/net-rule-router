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

use crate::dns_observation_consumer::rule_set_matches;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::per_sid_orchestrator::RulesProvider;

use super::dialer::RelayNameResolver;
use super::relay::{RouteSelector, UpstreamAddressResolver};

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
        self.cache
            .ips_for_hostname(hostname)
            .into_iter()
            .map(IpAddr::V4)
            .collect()
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
        let Ok(record) = self.resolver.resolve_a(hostname) else {
            // Remember nothing on failure: the next connection attempt — often
            // the browser's own retry a second later — should try again.
            return Vec::new();
        };
        let addresses: Vec<IpAddr> = record.addresses.iter().copied().map(IpAddr::V4).collect();
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
                    error = ?error,
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
/// being established.** Its contract there is to be prompt, and it was not:
/// resolving the active SID walks the session registry, and `note_flow` then
/// matches the hostname against both rule sets and takes the GLOBAL ledger
/// mutex — the same mutex the discovery tick holds while it qualifies up to
/// tens of thousands of candidate pairs. A user's connection waited on that.
///
/// So the hot path now only hands over the hostname and the instant. Everything
/// else happens on this observer's own thread. The queue is bounded and a full
/// queue DROPS the notice: an observation is optional and a connection is not.
/// The SID is resolved by the worker rather than at the call, which is a
/// sub-millisecond difference in attribution and takes a registry walk off the
/// connection path.
pub struct FlowActivityObserver {
    notices: std::sync::mpsc::SyncSender<(String, SystemTime)>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl FlowActivityObserver {
    #[must_use]
    pub fn new(
        engine: Arc<crate::auto_rules::AutoRulesEngine>,
        active_sid: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        let (notices, inbox) =
            std::sync::mpsc::sync_channel::<(String, SystemTime)>(FLOW_NOTICE_QUEUE_DEPTH);
        // The worker ends when the sender goes — i.e. when the stack drops this
        // observer during teardown. No stop token to keep in sync.
        let spawned = std::thread::Builder::new()
            .name("nrr-flow-observer".to_owned())
            .spawn(move || {
                while let Ok((hostname, at)) = inbox.recv() {
                    if let Some(sid) = active_sid() {
                        engine.note_flow(&sid, &hostname, at);
                    }
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(
                target: "nrr::fake-ip",
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
    fn on_flow_opened(&self, _client: SocketAddr, _fake: SocketAddr, hostname: &str) {
        if hostname.is_empty() {
            return;
        }
        if self
            .notices
            .try_send((hostname.to_owned(), SystemTime::now()))
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
    fn on_flow_opened(&self, client: SocketAddr, fake: SocketAddr, hostname: &str) {
        for observer in &self.observers {
            observer.on_flow_opened(client, fake, hostname);
        }
    }
}

/// [`RouteSelector`] over the active rule book.
///
/// A hostname that matches an enabled **secondary** rule for the routing-active
/// principal leaves over the secondary link; everything else takes the primary.
/// This is the same `rule_set_matches` gate the DNS oracle and the observer use
/// (single source of truth), so fake-IP steers a host to the same link every
/// other surface would.
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

impl RouteSelector for RuleBookRouteSelector {
    fn route_for(&self, hostname: &str) -> RouteRole {
        let is_secondary = (self.active_sid)()
            .and_then(|sid| self.rules_provider.active_rules_for(&sid))
            .is_some_and(|snapshot| rule_set_matches(hostname, &snapshot.rule_book.secondary));
        if is_secondary {
            RouteRole::Secondary
        } else {
            RouteRole::Primary
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
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use std::net::Ipv4Addr;

    /// `on_flow_opened` runs while a TCP connection is being established. It
    /// used to resolve the SID and then take the global ledger mutex — the one
    /// the discovery tick holds through tens of thousands of qualify calls — so
    /// a user's connection waited on a background computation. The hot path
    /// must hand the fact over and return, and a backlog must cost observations
    /// rather than connections.
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
        let observer = FlowActivityObserver::new(engine, active_sid);

        let addr: SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let notices = FLOW_NOTICE_QUEUE_DEPTH * 2;
        let started = Instant::now();
        for _ in 0..notices {
            observer.on_flow_opened(addr, addr, "cdn.example.net");
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
                Ipv4Addr::new(23, 10, 20, 140),
                Ipv4Addr::new(23, 10, 20, 141),
            ],
        );
        let resolver = CacheUpstreamResolver::new(cache);
        assert_eq!(
            resolver.addresses_for("assistant.example"),
            vec![
                IpAddr::V4(Ipv4Addr::new(23, 10, 20, 140)),
                IpAddr::V4(Ipv4Addr::new(23, 10, 20, 141)),
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
                behavior_mode: RouteBehaviorMode::PreferPrimary,
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
        assert_eq!(selector.route_for("random.net"), RouteRole::Primary);
    }

    #[test]
    fn route_selector_defaults_to_primary_with_no_active_principal() {
        let selector = selector_for("assistant.example", None);
        assert_eq!(selector.route_for("assistant.example"), RouteRole::Primary);
    }
}

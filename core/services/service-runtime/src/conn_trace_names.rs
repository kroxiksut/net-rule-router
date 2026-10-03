//! Names for a traced connection's remote address: the hostnames the service's
//! own DNS observation saw resolve to it, or the one a virtual (fake-IP)
//! address stands for.
//!
//! Diagnostic only. A name here says "this address was answered for this
//! host", never that the connection went there for that host: several names
//! can share one address, which is why the whole list travels with the row.
//!
//! Resolved once, when the trace row is recorded, and memoised per address: a
//! busy page reconnects to the same few addresses constantly, so the stores
//! behind it are asked about each new address once a minute at most. It runs on
//! the observer's drain tick, never on the traffic path.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_storage::repository::CacheRepository;

use crate::fake_ip::FakeIpBindingView;
use crate::observed_host_names::ObservedHostNames;
use crate::recent_rule_addresses::RecentRuleAddressIndex;

/// Names kept per row. The count beside them stays exact past this.
pub const MAX_NAMES_PER_ADDRESS: usize = 8;

/// How long a known name is reused before the stores are asked again.
const NAMED_TTL: Duration = Duration::from_secs(60);
/// Shorter, because the DNS drain can trail the connection drain by a tick:
/// an address nobody named yet is likely to be named a moment later.
const UNNAMED_TTL: Duration = Duration::from_secs(5);
/// Bound on memoised addresses; past it the expired ones go, then all of them.
const MEMO_CAP: usize = 4096;

/// The names one address was seen answering for, most recent first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteNames {
    /// At most [`MAX_NAMES_PER_ADDRESS`]; the first one is the name shown.
    pub names: Vec<String>,
    /// Distinct names in all, including any the cap left out.
    pub total: u32,
    /// The address is a virtual one from the fake-IP pool. The pool is then the
    /// only truth: `names` is empty once its binding was recycled.
    pub fake_ip: bool,
}

/// One place names for an address come from.
pub trait AddressNameSource: Send + Sync {
    /// Names for `ip`, most recently seen first, at most `limit`.
    fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames;
}

/// The FQDN cache: every host whose answer contained the address within
/// `freshness`, plus the direct hosts recorded as sharing it.
pub struct CacheAddressNames {
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    freshness: Duration,
}

impl CacheAddressNames {
    /// The cache keeps rows for weeks; an address not re-confirmed within
    /// `freshness` has likely been handed to another tenant since, and naming a
    /// connection after that tenant's predecessor would mislead.
    pub fn new(cache: Arc<Mutex<dyn CacheRepository + Send>>, freshness: Duration) -> Self {
        Self { cache, freshness }
    }
}

impl AddressNameSource for CacheAddressNames {
    fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames {
        let since = SystemTime::now()
            .checked_sub(self.freshness)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let Ok(guard) = self.cache.lock() else {
            return RemoteNames::default();
        };
        match guard.names_for_address(ip, since, limit) {
            Ok(found) => RemoteNames {
                names: found.names,
                total: found.total,
                fake_ip: false,
            },
            Err(e) => {
                tracing::debug!(
                    target: "nrr::conn-trace",
                    error = %e,
                    "naming a traced address from the cache failed; the row keeps the address only",
                );
                RemoteNames::default()
            }
        }
    }
}

/// The rule host whose answer most recently held the address, including the
/// pool members our resolver chose not to hand out.
impl AddressNameSource for RecentRuleAddressIndex {
    fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames {
        single_v4_name(ip, limit, |v4| self.lookup(v4))
    }
}

/// The rule-less host whose answer most recently held the address — the bulk
/// of ordinary traffic, which the cache never stores.
impl AddressNameSource for ObservedHostNames {
    fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames {
        single_v4_name(ip, limit, |v4| self.lookup(v4))
    }
}

/// The live fake-IP pool: exact, because the service itself dealt the address.
impl AddressNameSource for FakeIpBindingView {
    fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames {
        match self.domain_for_address(ip) {
            None => RemoteNames::default(),
            Some(domain) => {
                let names: Vec<String> = domain.into_iter().take(limit).collect();
                RemoteNames {
                    total: names.len() as u32,
                    names,
                    fake_ip: true,
                }
            }
        }
    }
}

fn single_v4_name(
    ip: IpAddr,
    limit: usize,
    lookup: impl FnOnce(Ipv4Addr) -> Option<String>,
) -> RemoteNames {
    match ip {
        IpAddr::V4(v4) if limit > 0 => lookup(v4)
            .map(|name| RemoteNames {
                names: vec![name],
                total: 1,
                fake_ip: false,
            })
            .unwrap_or_default(),
        _ => RemoteNames::default(),
    }
}

struct Memo {
    expires: Instant,
    names: Option<Arc<RemoteNames>>,
}

/// Names a remote address from several sources, in priority order, memoised.
pub struct ConnTraceNamer {
    sources: Vec<Arc<dyn AddressNameSource>>,
    memo: Mutex<HashMap<IpAddr, Memo>>,
}

impl ConnTraceNamer {
    /// Earlier sources win the shown name; later ones only add names the
    /// earlier ones did not list.
    pub fn new(sources: Vec<Arc<dyn AddressNameSource>>) -> Self {
        Self {
            sources,
            memo: Mutex::new(HashMap::new()),
        }
    }

    /// The production order: the cache the Cache screen shows, then the rule
    /// hosts' recent answers, then everything else the DNS observer saw.
    pub fn production(cache: Arc<Mutex<dyn CacheRepository + Send>>) -> Self {
        Self::new(vec![
            Arc::new(CacheAddressNames::new(
                cache,
                crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW,
            )) as Arc<dyn AddressNameSource>,
            crate::recent_rule_addresses::global_recent_rule_addresses(),
            crate::observed_host_names::global_observed_host_names(),
        ])
    }

    /// Ask the fake-IP pool first. An address inside it means nothing to the
    /// other sources: whatever they recorded for it is a stale binding.
    #[must_use]
    pub fn with_fake_ip_pool(mut self, pool: FakeIpBindingView) -> Self {
        self.sources.insert(0, Arc::new(pool));
        self
    }

    /// Names for `ip`, or `None` when nothing named it and it is no virtual
    /// address.
    pub fn name(&self, ip: IpAddr) -> Option<Arc<RemoteNames>> {
        self.name_at(ip, Instant::now())
    }

    fn name_at(&self, ip: IpAddr, now: Instant) -> Option<Arc<RemoteNames>> {
        if !is_nameable(ip) {
            return None;
        }
        {
            let memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(hit) = memo.get(&ip).filter(|m| m.expires > now) {
                return hit.names.clone();
            }
        }
        // Asked outside the memo lock: a slow store must not stall a reader of
        // an address that is already known.
        let names = self.resolve(ip).map(Arc::new);
        let ttl = if names.is_some() {
            NAMED_TTL
        } else {
            UNNAMED_TTL
        };
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if memo.len() >= MEMO_CAP {
            memo.retain(|_, m| m.expires > now);
            if memo.len() >= MEMO_CAP {
                memo.clear();
            }
        }
        memo.insert(
            ip,
            Memo {
                expires: now + ttl,
                names: names.clone(),
            },
        );
        names
    }

    fn resolve(&self, ip: IpAddr) -> Option<RemoteNames> {
        let mut merged = RemoteNames::default();
        for source in &self.sources {
            let room = MAX_NAMES_PER_ADDRESS - merged.names.len();
            let found = source.names_for(ip, room);
            if found.fake_ip {
                return Some(found);
            }
            if merged.names.is_empty() {
                merged = found;
                continue;
            }
            // A full list means the earlier source already counted more names
            // than it listed, and a later name may be one of those: adding it
            // would count it twice.
            if room == 0 {
                break;
            }
            for name in found.names {
                if merged.names.len() >= MAX_NAMES_PER_ADDRESS {
                    break;
                }
                if !merged.names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    merged.names.push(name);
                    merged.total = merged.total.saturating_add(1);
                }
            }
        }
        merged.names.truncate(MAX_NAMES_PER_ADDRESS);
        // A source that counted names it did not list still leaves the count
        // at least as long as the list.
        merged.total = merged.total.max(merged.names.len() as u32);
        (!merged.names.is_empty()).then_some(merged)
    }
}

/// Loopback, unspecified and multicast destinations are never answered by DNS.
fn is_nameable(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fixed answer per address, counting how often it is asked.
    #[derive(Default)]
    struct Fixed {
        answers: HashMap<IpAddr, Vec<&'static str>>,
        asked: AtomicUsize,
    }

    impl Fixed {
        fn with(mut self, ip: IpAddr, names: &[&'static str]) -> Self {
            self.answers.insert(ip, names.to_vec());
            self
        }
    }

    impl AddressNameSource for Fixed {
        fn names_for(&self, ip: IpAddr, limit: usize) -> RemoteNames {
            self.asked.fetch_add(1, Ordering::Relaxed);
            let all = self.answers.get(&ip).cloned().unwrap_or_default();
            RemoteNames {
                names: all.iter().take(limit).map(|s| s.to_string()).collect(),
                total: all.len() as u32,
                fake_ip: false,
            }
        }
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn namer(sources: Vec<Arc<Fixed>>) -> ConnTraceNamer {
        ConnTraceNamer::new(
            sources
                .into_iter()
                .map(|s| s as Arc<dyn AddressNameSource>)
                .collect(),
        )
    }

    #[test]
    fn a_single_name_is_shown_with_nothing_else() {
        let n = namer(vec![Arc::new(
            Fixed::default().with(v4(1), &["www.example"]),
        )]);
        let named = n.name(v4(1)).expect("named");
        assert_eq!(named.names, vec!["www.example"]);
        assert_eq!(named.total, 1);
    }

    #[test]
    fn a_shared_address_keeps_every_name_and_the_first_source_leads() {
        let cache = Arc::new(Fixed::default().with(v4(2), &["b.example", "a.example"]));
        let observed = Arc::new(Fixed::default().with(v4(2), &["c.example"]));
        let named = namer(vec![cache, observed]).name(v4(2)).expect("named");
        assert_eq!(named.names, vec!["b.example", "a.example", "c.example"]);
        assert_eq!(named.total, 3, "shown as «b.example (+2)»");
    }

    #[test]
    fn a_later_source_repeating_a_name_does_not_count_it_twice() {
        let cache = Arc::new(Fixed::default().with(v4(3), &["Www.Example"]));
        let recent = Arc::new(Fixed::default().with(v4(3), &["www.example"]));
        let named = namer(vec![cache, recent]).name(v4(3)).expect("named");
        assert_eq!(named.names, vec!["Www.Example"]);
        assert_eq!(named.total, 1);
    }

    #[test]
    fn a_later_source_names_what_the_cache_does_not_know() {
        let cache = Arc::new(Fixed::default());
        let observed = Arc::new(Fixed::default().with(v4(4), &["unruled.example"]));
        let named = namer(vec![cache, observed]).name(v4(4)).expect("named");
        assert_eq!(named.names, vec!["unruled.example"]);
        assert_eq!(named.total, 1);
    }

    #[test]
    fn the_list_is_capped_but_the_count_is_not() {
        let many: Vec<&'static str> = vec![
            "n01.example",
            "n02.example",
            "n03.example",
            "n04.example",
            "n05.example",
            "n06.example",
            "n07.example",
            "n08.example",
            "n09.example",
            "n10.example",
        ];
        let cache = Arc::new(Fixed::default().with(v4(5), &many));
        let observed = Arc::new(Fixed::default().with(v4(5), &["other.example"]));
        let named = namer(vec![cache, observed]).name(v4(5)).expect("named");
        assert_eq!(named.names.len(), MAX_NAMES_PER_ADDRESS);
        assert_eq!(
            named.total, 10,
            "a full list stops later sources: their name may be one of the unlisted"
        );
    }

    #[test]
    fn an_address_nobody_named_stays_bare_and_local_ones_are_not_asked() {
        let source = Arc::new(Fixed::default());
        let n = namer(vec![Arc::clone(&source)]);
        assert!(n.name(v4(6)).is_none());
        assert!(n.name(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
        assert!(n.name("::1".parse().expect("v6")).is_none());
        assert_eq!(
            source.asked.load(Ordering::Relaxed),
            1,
            "only the routable one"
        );
    }

    #[test]
    fn a_known_address_is_asked_once_a_minute_and_an_unknown_one_soon_again() {
        let source = Arc::new(Fixed::default().with(v4(7), &["www.example"]));
        let n = namer(vec![Arc::clone(&source)]);
        let t0 = Instant::now();
        for s in 0..30 {
            assert!(n.name_at(v4(7), t0 + Duration::from_secs(s)).is_some());
        }
        assert_eq!(source.asked.load(Ordering::Relaxed), 1);
        assert!(n
            .name_at(v4(7), t0 + NAMED_TTL + Duration::from_secs(1))
            .is_some());
        assert_eq!(source.asked.load(Ordering::Relaxed), 2);

        // Unnamed now, named by the next DNS drain: the miss must not stick.
        assert!(n.name_at(v4(8), t0).is_none());
        assert!(n.name_at(v4(8), t0 + Duration::from_secs(1)).is_none());
        assert_eq!(source.asked.load(Ordering::Relaxed), 3);
        assert!(n
            .name_at(v4(8), t0 + UNNAMED_TTL + Duration::from_secs(1))
            .is_none());
        assert_eq!(source.asked.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn the_in_memory_indexes_name_v4_only() {
        let recent = RecentRuleAddressIndex::new();
        recent.record("rule.example", &[Ipv4Addr::new(198, 51, 100, 1)]);
        let named = recent.names_for(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 8);
        assert_eq!(named.names, vec!["rule.example"]);
        assert!(recent
            .names_for("2001:db8::1".parse().expect("v6"), 8)
            .names
            .is_empty());
        assert!(recent
            .names_for(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 0)
            .names
            .is_empty());
    }

    fn fake_pool() -> (crate::fake_ip::FakeIpAssembly, IpAddr) {
        use crate::dns_resolver::FakeIpAnswerer;
        use nrr_platform_api::fake_ip::{FakeIpPoolConfig, FakeIpScope};
        let assembly = crate::fake_ip::FakeIpAssembly::new(
            FakeIpScope::enabled(Vec::<String>::new()),
            FakeIpPoolConfig::default(),
        );
        let fake = assembly
            .answerer()
            .fake_answer("app.example")
            .expect("in scope")[0];
        (assembly, IpAddr::V4(fake))
    }

    #[test]
    fn a_virtual_address_is_named_by_the_pool_alone() {
        let (assembly, fake) = fake_pool();
        // A stale record of the same address elsewhere must not leak in.
        let observed = Arc::new(Fixed::default().with(fake, &["stale.example"]));
        let n = namer(vec![observed]).with_fake_ip_pool(assembly.binding_view());
        let named = n.name(fake).expect("named");
        assert_eq!(named.names, vec!["app.example"]);
        assert_eq!(named.total, 1);
        assert!(named.fake_ip);
    }

    #[test]
    fn a_recycled_virtual_address_is_marked_but_unnamed() {
        let (assembly, fake) = fake_pool();
        let IpAddr::V4(v4) = fake else {
            unreachable!("the pool answered v4")
        };
        let unbound = IpAddr::V4(Ipv4Addr::from(u32::from(v4) + 1));
        let observed = Arc::new(Fixed::default().with(unbound, &["stale.example"]));
        let n = namer(vec![observed]).with_fake_ip_pool(assembly.binding_view());
        let marked = n.name(unbound).expect("marked");
        assert!(marked.names.is_empty());
        assert!(marked.fake_ip);
    }

    #[test]
    fn a_real_address_passes_the_pool_by() {
        let (assembly, _) = fake_pool();
        let observed = Arc::new(Fixed::default().with(v4(10), &["real.example"]));
        let n = namer(vec![observed]).with_fake_ip_pool(assembly.binding_view());
        let named = n.name(v4(10)).expect("named");
        assert_eq!(named.names, vec!["real.example"]);
        assert!(!named.fake_ip);
    }

    #[test]
    fn the_cache_source_reads_the_fqdn_cache() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::resolution_source::StorageResolutionSource;
        use nrr_storage::store::SqliteCacheStore;

        let conn = rusqlite::Connection::open_in_memory().expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            nrr_domain::decision_lookup::FreshnessThresholds::default_production(),
        );
        let now = SystemTime::now();
        for (host, age) in [
            ("cdn-a.example", 30),
            ("cdn-b.example", 5),
            ("aged.example", 7_200),
        ] {
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: host.into(),
                    raw_hostname_sample: None,
                    resolved_ips: vec![v4(9)],
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: now - Duration::from_secs(age),
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let source = CacheAddressNames::new(cache, Duration::from_secs(3_600));
        let named = source.names_for(v4(9), 8);
        assert_eq!(
            named.names,
            vec!["cdn-b.example", "cdn-a.example"],
            "most recent first; a name past the freshness window is dropped"
        );
        assert_eq!(named.total, 2);
    }
}

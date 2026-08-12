//! fake-IP for DIRECT hosts under the armed block-all.
//!
//! A gate-based exemption path is structurally racy: installing a WFP
//! exemption is a full reconcile, and a fast first connect can lose that race
//! against the catch-all block. This module removes the race for the fake-IP
//! posture: a DIRECT host's answer becomes a virtual address (nothing
//! compiles on the answer path — the static pool permit already covers it),
//! and the relay dials the real address out the primary while the client
//! waits inside its handshake.
//!
//! Two pieces:
//!
//! - [`DirectRealIpMap`] — session-scoped, in-memory `hostname → real IPs`.
//!   DIRECT hosts are deliberately NOT written to the FQDN cache (it persists
//!   rule-matching hosts only; recording every site the user visits would turn
//!   it into a browsing log). The relay's upstream lookup reads this map first.
//! - [`ArmedDirectFakeIpAnswerer`] — the production
//!   [`DirectFakeIpAnswerer`]: armed-latch gate, scope exclusions, record real
//!   addresses, allocate the stable fake.
//!
//! [`DirectAwareUpstreamResolver`] composes the map over the FQDN-cache
//! resolver so one [`UpstreamAddressResolver`] serves both host kinds.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use nrr_platform_api::fake_ip::{FakeIpAllocator, FakeIpScope};

use crate::dns_resolver::DirectFakeIpAnswerer;

use super::relay::UpstreamAddressResolver;

/// Hosts the map holds before evicting the least-recently-touched entry. A
/// browsing session touches a few hundred distinct direct hosts; 4096 leaves
/// generous headroom while bounding memory (the fake pool itself is far
/// larger, so the map — not the pool — is the effective direct-host bound).
pub const DIRECT_MAP_CAPACITY: usize = 4096;

#[derive(Default)]
struct DirectMapInner {
    entries: HashMap<String, DirectEntry>,
    /// Monotonic touch counter — O(1) touch, O(n) eviction scan only when full
    /// (same discipline as the allocator's LRU).
    tick: u64,
}

struct DirectEntry {
    ips: Vec<Ipv4Addr>,
    touched: u64,
}

/// Session-scoped `hostname → real IPv4 addresses` for DIRECT hosts answered
/// with a fake address. In-memory only, by design (privacy: direct hosts are
/// the user's browsing, and the flows die with the service anyway).
#[derive(Default)]
pub struct DirectRealIpMap {
    inner: Mutex<DirectMapInner>,
}

impl DirectRealIpMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the latest answer for `hostname`, REPLACING any previous set —
    /// CDN answers rotate, and the freshest set is what the client was just
    /// told, so it is what the relay must dial. Evicts the least-recently
    /// touched entry when full.
    pub fn record(&self, hostname: &str, ips: &[Ipv4Addr]) {
        if ips.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.tick += 1;
        let tick = inner.tick;
        if !inner.entries.contains_key(hostname) && inner.entries.len() >= DIRECT_MAP_CAPACITY {
            if let Some(coldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, e)| e.touched)
                .map(|(host, _)| host.clone())
            {
                inner.entries.remove(&coldest);
            }
        }
        inner.entries.insert(
            hostname.to_string(),
            DirectEntry {
                ips: ips.to_vec(),
                touched: tick,
            },
        );
    }

    /// The real addresses recorded for `hostname` (empty when unknown).
    /// Touches the entry so hosts with live flows stay resident.
    #[must_use]
    pub fn ips_for(&self, hostname: &str) -> Vec<Ipv4Addr> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.tick += 1;
        let tick = inner.tick;
        match inner.entries.get_mut(hostname) {
            Some(entry) => {
                entry.touched = tick;
                entry.ips.clone()
            }
            None => Vec::new(),
        }
    }
}

/// Production [`DirectFakeIpAnswerer`]: while `armed` reads true, a DIRECT
/// host inside the fake-IP scope records its real addresses into the
/// [`DirectRealIpMap`] and is answered with its stable fake address from the
/// SAME allocator the rule-host answerer and the relay share.
///
/// Order matters: the real addresses are recorded BEFORE the fake address is
/// returned — the client's first packet may hit the TUN immediately, and the
/// relay must already be able to resolve the upstream.
///
/// Disarm behaviour: new queries fall back to real answers (`None`), while
/// flows already opened against a fake address keep relaying — the allocator
/// binding and the map entry survive, so nothing severs mid-download.
pub struct ArmedDirectFakeIpAnswerer {
    scope: FakeIpScope,
    allocator: Arc<Mutex<FakeIpAllocator>>,
    map: Arc<DirectRealIpMap>,
    armed: Arc<dyn Fn() -> bool + Send + Sync>,
    runtime_exclusions: Arc<super::self_heal::RuntimeHostExclusions>,
    health: Arc<super::health::FakeIpHealth>,
}

impl ArmedDirectFakeIpAnswerer {
    #[must_use]
    pub fn new(
        scope: FakeIpScope,
        allocator: Arc<Mutex<FakeIpAllocator>>,
        map: Arc<DirectRealIpMap>,
        armed: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self {
            scope,
            allocator,
            map,
            armed,
            runtime_exclusions: Arc::new(super::self_heal::RuntimeHostExclusions::new()),
            health: Arc::new(super::health::FakeIpHealth::new()),
        }
    }

    /// Share a runtime exclusion set (VPN self-heal): a host it names keeps its
    /// real address. Builder-style; default is an empty set.
    #[must_use]
    pub fn with_runtime_exclusions(
        mut self,
        exclusions: Arc<super::self_heal::RuntimeHostExclusions>,
    ) -> Self {
        self.runtime_exclusions = exclusions;
        self
    }

    /// Share the datapath-health counters (relay watchdog). Builder-style;
    /// default is a private counter nobody reads.
    #[must_use]
    pub fn with_health(mut self, health: Arc<super::health::FakeIpHealth>) -> Self {
        self.health = health;
        self
    }
}

impl DirectFakeIpAnswerer for ArmedDirectFakeIpAnswerer {
    fn fake_direct_answer(&self, hostname: &str, real: &[Ipv4Addr]) -> Option<Vec<Ipv4Addr>> {
        if real.is_empty() || !(self.armed)() {
            return None;
        }
        // Honour a VPN self-heal exclusion: keep the real address.
        if self.runtime_exclusions.contains(hostname) {
            return None;
        }
        // Same scope the relay re-checks per flow: literal/non-routable/user
        // exclusions keep their real answers. (The P2P app-group exclusion
        // cannot fire on a DNS query — no process attribution — matching the
        // rule-host answerer's documented posture.)
        if !self.scope.decide(hostname, None).is_fake_ip() {
            return None;
        }
        self.map.record(hostname, real);
        let mut allocator = self.allocator.lock().unwrap_or_else(|p| p.into_inner());
        match allocator.allocate(hostname) {
            Ok(binding) => {
                self.health.record_answer();
                Some(vec![binding.v4])
            }
            // Pool exhausted and un-recyclable → decline; the caller falls
            // back to the gate + real-answer path rather than failing DNS.
            Err(_) => None,
        }
    }
}

/// [`UpstreamAddressResolver`] that consults the direct-host map first and
/// falls back to the inner (FQDN-cache) resolver for rule hosts. One resolver
/// instance then serves every fake-addressed flow, whichever side allocated it.
pub struct DirectAwareUpstreamResolver {
    direct: Arc<DirectRealIpMap>,
    inner: Arc<dyn UpstreamAddressResolver>,
}

impl DirectAwareUpstreamResolver {
    #[must_use]
    pub fn new(direct: Arc<DirectRealIpMap>, inner: Arc<dyn UpstreamAddressResolver>) -> Self {
        Self { direct, inner }
    }
}

impl UpstreamAddressResolver for DirectAwareUpstreamResolver {
    fn addresses_for(&self, hostname: &str) -> Vec<IpAddr> {
        let direct = self.direct.ips_for(hostname);
        if !direct.is_empty() {
            return direct.into_iter().map(IpAddr::V4).collect();
        }
        self.inner.addresses_for(hostname)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_ip::relay::StaticUpstreamResolver;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn answerer(armed: Arc<AtomicBool>) -> (ArmedDirectFakeIpAnswerer, Arc<DirectRealIpMap>) {
        let map = Arc::new(DirectRealIpMap::new());
        let a = ArmedDirectFakeIpAnswerer::new(
            FakeIpScope::enabled(Vec::<String>::new()),
            Arc::new(Mutex::new(FakeIpAllocator::default())),
            Arc::clone(&map),
            Arc::new(move || armed.load(Ordering::SeqCst)),
        );
        (a, map)
    }

    #[test]
    fn map_replaces_on_record_and_touches_on_lookup() {
        let map = DirectRealIpMap::new();
        map.record("gosuslugi.ru", &[ip(95, 173, 128, 10)]);
        map.record(
            "gosuslugi.ru",
            &[ip(95, 173, 128, 20), ip(95, 173, 128, 21)],
        );
        // Latest answer wins wholesale — the client was just told THIS set.
        assert_eq!(
            map.ips_for("gosuslugi.ru"),
            vec![ip(95, 173, 128, 20), ip(95, 173, 128, 21)]
        );
        assert!(map.ips_for("unknown.example").is_empty());
    }

    #[test]
    fn map_evicts_the_coldest_entry_when_full() {
        let map = DirectRealIpMap::new();
        for i in 0..DIRECT_MAP_CAPACITY {
            map.record(&format!("host-{i}.example"), &[ip(10, 0, 0, 1)]);
        }
        // Touch the oldest entry so it is no longer the eviction candidate.
        assert!(!map.ips_for("host-0.example").is_empty());
        map.record("newcomer.example", &[ip(10, 0, 0, 2)]);
        // host-0 survived (recently touched); host-1 was the coldest and left.
        assert!(!map.ips_for("host-0.example").is_empty());
        assert!(map.ips_for("host-1.example").is_empty());
        assert_eq!(map.ips_for("newcomer.example"), vec![ip(10, 0, 0, 2)]);
    }

    #[test]
    fn armed_answerer_records_real_then_hands_out_a_stable_fake() {
        let (answerer, map) = answerer(Arc::new(AtomicBool::new(true)));
        let real = [ip(178, 248, 237, 68)];
        let fake = answerer
            .fake_direct_answer("habr.com", &real)
            .expect("armed + in scope");
        assert_eq!(fake.len(), 1);
        assert!(fake[0].to_string().starts_with("198.18."));
        // The real set was registered for the relay BEFORE the fake went out.
        assert_eq!(map.ips_for("habr.com"), real.to_vec());
        // Stable: the same host keeps its fake address across re-queries.
        assert_eq!(answerer.fake_direct_answer("habr.com", &real), Some(fake));
    }

    #[test]
    fn disarmed_or_excluded_hosts_decline_to_the_real_path() {
        // Disarmed → None even for an in-scope host.
        let (disarmed, map) = answerer(Arc::new(AtomicBool::new(false)));
        assert_eq!(
            disarmed.fake_direct_answer("habr.com", &[ip(178, 248, 237, 68)]),
            None
        );
        assert!(map.ips_for("habr.com").is_empty(), "nothing recorded");
        // Armed, but the name is excluded by scope (non-routable / literal).
        let (armed, _) = answerer(Arc::new(AtomicBool::new(true)));
        assert_eq!(
            armed.fake_direct_answer("localhost", &[ip(127, 0, 0, 1)]),
            None
        );
        assert_eq!(
            armed.fake_direct_answer("10.1.2.3", &[ip(10, 1, 2, 3)]),
            None
        );
        // An empty answer set is never claimed.
        assert_eq!(armed.fake_direct_answer("habr.com", &[]), None);
    }

    #[test]
    fn direct_aware_resolver_prefers_the_map_and_falls_back_to_the_cache() {
        let map = Arc::new(DirectRealIpMap::new());
        map.record("habr.com", &[ip(178, 248, 237, 68)]);
        let inner = Arc::new(
            StaticUpstreamResolver::new().with("chatgpt.com", &[IpAddr::V4(ip(104, 18, 32, 47))]),
        );
        let resolver = DirectAwareUpstreamResolver::new(map, inner);
        // Direct host → map.
        assert_eq!(
            resolver.addresses_for("habr.com"),
            vec![IpAddr::V4(ip(178, 248, 237, 68))]
        );
        // Rule host → inner (FQDN cache in production).
        assert_eq!(
            resolver.addresses_for("chatgpt.com"),
            vec![IpAddr::V4(ip(104, 18, 32, 47))]
        );
        assert!(resolver.addresses_for("nowhere.example").is_empty());
    }
}

//! Tearing down the connections a freshly applied rule left on the old path.
//!
//! # The problem this solves
//!
//! A rule only decides where a connection goes while that connection is being
//! established. Sockets opened before the rule existed keep running over the
//! route they were opened on, and nothing tells the application otherwise: the
//! page is already loaded, its images already have their sockets, so the user
//! adds the rule and sees no change until they press refresh. Worse, the
//! browser holds a DNS answer of its own, so even a new socket can go to the
//! old address for another minute.
//!
//! Tearing those sockets down is what turns the rule into something the user
//! can see. The application reconnects on its next request and that connection
//! is established under the new rule.
//!
//! Two sets of addresses are worth tearing down, and they close different
//! halves of the problem:
//!
//! - the **hosts the new rule routes** — whatever is being fetched right now
//!   moves onto the new path;
//! - the **anchor**, the site the suggestion was made next to — a page that
//!   keeps a channel open re-opens it and asks for its resources again, which
//!   is what makes the images appear without a manual refresh.
//!
//! # Cost and blast radius
//!
//! Nothing here sits on the data path: one pass over the connection table per
//! accepted suggestion, never per packet or per observation. Only established
//! TCP connections to the exact addresses behind those hostnames are torn
//! down — connections whose route just changed under them anyway. Both the
//! address count and the per-suffix expansion are capped so a broad rule over a
//! warm cache cannot turn into an unbounded sweep.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use nrr_platform_api::fake_ip::stale_flows::{StaleFlowReset, StaleFlowSweep};

use crate::fqdn_cache_lookup::FqdnCacheLookup;

/// Addresses torn down in one pass. Reached only by a suffix rule over a warm
/// cache; past this point the user has bigger changes in flight than one page's
/// sockets, and a bounded pass is worth more than a complete one.
const MAX_ADDRESSES_PER_PASS: usize = 256;

/// Hostnames one suffix rule expands to. The cache can hold thousands under a
/// popular suffix, and the ones worth tearing down are the handful the browser
/// is actually talking to.
const MAX_HOSTS_PER_SUFFIX: usize = 64;

/// A hostname that a just-applied rule now routes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutedHost {
    /// One name, matched exactly.
    Exact(String),
    /// A domain and everything under it.
    Suffix(String),
}

/// Tears down established connections to hosts whose route just changed.
pub struct RoutedHostFlowRefresh {
    cache: Arc<dyn FqdnCacheLookup>,
    reset: Arc<dyn StaleFlowReset>,
}

impl RoutedHostFlowRefresh {
    #[must_use]
    pub fn new(cache: Arc<dyn FqdnCacheLookup>, reset: Arc<dyn StaleFlowReset>) -> Self {
        Self { cache, reset }
    }

    /// Tear down every established connection aimed at an address behind
    /// `hosts`. Best-effort by contract: the worst case is the old behaviour,
    /// an application sitting on a socket over the previous route.
    ///
    /// Call this only once the rule is applied. Tearing down first would have
    /// the application reconnect over the route that is still in force.
    pub fn refresh(&self, hosts: &[RoutedHost]) -> StaleFlowSweep {
        let addresses = self.addresses_behind(hosts);
        let mut total = StaleFlowSweep::default();
        for address in &addresses {
            let sweep = self.reset.reset_flows_to(*address, 32);
            total.found = total.found.saturating_add(sweep.found);
            total.torn_down = total.torn_down.saturating_add(sweep.torn_down);
        }
        if total.found > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                addresses = addresses.len(),
                found = total.found,
                torn_down = total.torn_down,
                "tore down connections still running over the previous route — \
                 the application reconnects under the new rule",
            );
        } else {
            tracing::debug!(
                target: "nrr::auto-rules",
                addresses = addresses.len(),
                "no connection was left on the previous route",
            );
        }
        total
    }

    /// Cached addresses behind `hosts`, deduplicated and capped. Sorted because
    /// `BTreeSet` makes the pass order deterministic, which keeps a log line
    /// from one run comparable with the next.
    fn addresses_behind(&self, hosts: &[RoutedHost]) -> Vec<Ipv4Addr> {
        let mut addresses = BTreeSet::new();
        for host in hosts {
            match host {
                RoutedHost::Exact(name) => {
                    self.collect_into(&mut addresses, name);
                }
                RoutedHost::Suffix(label) => {
                    // The expansion helper is the same one enforcement uses, so
                    // the set torn down cannot drift from the set routed.
                    for name in self
                        .cache
                        .hostnames_for_suffix_domain(label, MAX_HOSTS_PER_SUFFIX)
                    {
                        self.collect_into(&mut addresses, &name);
                    }
                }
            }
            if addresses.len() >= MAX_ADDRESSES_PER_PASS {
                break;
            }
        }
        addresses.into_iter().take(MAX_ADDRESSES_PER_PASS).collect()
    }

    fn collect_into(&self, addresses: &mut BTreeSet<Ipv4Addr>, hostname: &str) {
        for address in self.cache.ips_for_hostname(hostname) {
            addresses.insert(address);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nrr_platform_api::fake_ip::MockStaleFlowReset;

    use super::*;

    #[derive(Default)]
    struct FakeCache {
        addresses: HashMap<String, Vec<Ipv4Addr>>,
        under_suffix: HashMap<String, Vec<String>>,
    }

    impl FqdnCacheLookup for FakeCache {
        fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
            self.addresses.get(hostname).cloned().unwrap_or_default()
        }

        fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
            let mut hosts = self.under_suffix.get(suffix).cloned().unwrap_or_default();
            hosts.truncate(limit);
            hosts
        }
    }

    fn cache_with(rows: &[(&str, &str)]) -> FakeCache {
        let mut cache = FakeCache::default();
        for (host, address) in rows {
            cache
                .addresses
                .entry((*host).to_string())
                .or_default()
                .push(address.parse().expect("test address"));
        }
        cache
    }

    fn refresh_with(cache: FakeCache, hosts: &[RoutedHost]) -> (StaleFlowSweep, Vec<Ipv4Addr>) {
        let reset = Arc::new(MockStaleFlowReset::new());
        let refresher = RoutedHostFlowRefresh::new(
            Arc::new(cache),
            Arc::clone(&reset) as Arc<dyn StaleFlowReset>,
        );
        let sweep = refresher.refresh(hosts);
        let swept = reset.calls().into_iter().map(|(base, _)| base).collect();
        (sweep, swept)
    }

    #[test]
    fn every_address_behind_the_named_hosts_is_swept_once() {
        let cache = cache_with(&[
            ("cdn.example", "203.0.113.10"),
            ("cdn.example", "203.0.113.11"),
            ("site.example", "203.0.113.20"),
        ]);
        let (_, swept) = refresh_with(
            cache,
            &[
                RoutedHost::Exact("cdn.example".into()),
                RoutedHost::Exact("site.example".into()),
            ],
        );
        assert_eq!(
            swept,
            vec![
                "203.0.113.10".parse::<Ipv4Addr>().expect("addr"),
                "203.0.113.11".parse().expect("addr"),
                "203.0.113.20".parse().expect("addr"),
            ]
        );
    }

    #[test]
    fn an_address_shared_by_two_hosts_is_swept_once() {
        let cache = cache_with(&[
            ("cdn.example", "203.0.113.10"),
            ("site.example", "203.0.113.10"),
        ]);
        let (_, swept) = refresh_with(
            cache,
            &[
                RoutedHost::Exact("cdn.example".into()),
                RoutedHost::Exact("site.example".into()),
            ],
        );
        assert_eq!(swept.len(), 1);
    }

    #[test]
    fn a_suffix_sweeps_the_hosts_it_covers() {
        let mut cache = cache_with(&[
            ("img.site.example", "203.0.113.30"),
            ("api.site.example", "203.0.113.31"),
            ("elsewhere.example", "203.0.113.99"),
        ]);
        cache.under_suffix.insert(
            "site.example".to_string(),
            vec!["api.site.example".into(), "img.site.example".into()],
        );
        let (_, swept) = refresh_with(cache, &[RoutedHost::Suffix("site.example".into())]);
        assert_eq!(swept.len(), 2);
        assert!(!swept.contains(&"203.0.113.99".parse().expect("addr")));
    }

    #[test]
    fn a_host_the_cache_never_saw_sweeps_nothing() {
        let (sweep, swept) = refresh_with(
            FakeCache::default(),
            &[RoutedHost::Exact("unknown.example".into())],
        );
        assert!(swept.is_empty());
        assert_eq!(sweep, StaleFlowSweep::default());
    }
}

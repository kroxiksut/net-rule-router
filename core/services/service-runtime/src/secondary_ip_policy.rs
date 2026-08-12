//! Shared-IP policy enforcement bridge.
//!
//! Computes the set of secondary IPs to EXCLUDE from secondary routing /
//! protection under the user's [`SharedIpPolicy`]. The pure decision lives in
//! [`nrr_domain::shared_ip::commit_shared_ip`]; this module supplies the census
//! counts (`rule_on_ip` / `total_rule` from the secondary rules × FQDN cache,
//! `direct_on_ip` from the observed shared-IP census) and returns a denylist the
//! WFP codegen ([`crate::wfp_codegen`]) and the route codegen
//! ([`crate::route_codegen`]) both filter against — so a shared IP that the
//! policy declines is dropped from BOTH the `/32` route and the kill-switch set
//! consistently (a route without a matching WFP entry, or vice-versa, would be
//! an incoherent partial commit).
//!
//! Only NAME-derived IPs are considered: `ExactIp` rules name an address
//! outright, so they are always honoured (never denied) regardless of sharing.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use nrr_domain::shared_ip::{commit_shared_ip, SharedIpPolicy};
use nrr_domain::RuleAction;

use crate::fqdn_cache_lookup::FqdnCacheLookup;

/// Cap on suffix/zone fan-out when expanding rules to their cached hostnames —
/// mirrors the codegen's own bound so the two views stay consistent.
const SUFFIX_FANOUT_LIMIT: usize = 1024;

/// The secondary IPs to EXCLUDE from secondary routing/protection under
/// `policy`. Empty when the policy is [`SharedIpPolicy::AnyRuleDomain`] (it
/// never declines) or when no shared IP loses its majority test — so the
/// default, collateral-free case produces an empty denylist and leaves routing
/// exactly as before this feature existed.
pub fn secondary_ip_denylist(
    secondary: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
    policy: SharedIpPolicy,
) -> HashSet<Ipv4Addr> {
    // AnyRuleDomain commits every shared IP → skip the census work entirely.
    if policy == SharedIpPolicy::AnyRuleDomain {
        return HashSet::new();
    }

    // Expand every enabled, routable, NAME-based secondary rule into
    // `ip → {owning rule hostnames}`, and the global set of rule hostnames.
    let mut ip_rule_hosts: HashMap<Ipv4Addr, HashSet<String>> = HashMap::new();
    let mut rule_hosts: HashSet<String> = HashSet::new();
    for rule in secondary.rules().iter().filter(|r| r.enabled) {
        // App rules and block rules do not put a destination IP on the secondary
        // link (block = dropped; app routing is Pro), so they never contribute a
        // committable shared IP.
        if rule.app_match.is_some() || matches!(rule.action, RuleAction::Block) {
            continue;
        }
        match &rule.address_match {
            // Explicit IPs are the user's direct choice — always honoured, never
            // subject to the shared-IP heuristic.
            Some(CanonicalAddressMatch::ExactIp(_)) | None => {}
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                rule_hosts.insert(host.clone());
                for ip in cache.ips_for_hostname(host) {
                    ip_rule_hosts.entry(ip).or_default().insert(host.clone());
                }
            }
            // `*.suffix` covers its apex, a zone does not — the census must see
            // the same host set the codegens enforce, or a shared-IP decision
            // would be taken on a different population than it is applied to.
            Some(CanonicalAddressMatch::SuffixDomain(s)) => {
                collect_suffix_hosts(
                    &cache.hostnames_for_suffix_domain(s, SUFFIX_FANOUT_LIMIT),
                    cache,
                    &mut ip_rule_hosts,
                    &mut rule_hosts,
                );
            }
            Some(CanonicalAddressMatch::Zone(z)) => {
                collect_suffix_hosts(
                    &cache.hostnames_under_suffix(z, SUFFIX_FANOUT_LIMIT),
                    cache,
                    &mut ip_rule_hosts,
                    &mut rule_hosts,
                );
            }
        }
    }

    let total_rule = rule_hosts.len() as u32;
    let mut denied = HashSet::new();
    for (ip, hosts) in &ip_rule_hosts {
        let direct_on_ip = cache.direct_host_count_for_ip(*ip);
        let rule_on_ip = hosts.len() as u32;
        if !commit_shared_ip(policy, rule_on_ip, direct_on_ip, total_rule) {
            denied.insert(*ip);
        }
    }
    denied
}

/// Record a suffix/zone rule's expanded host list into the census maps.
fn collect_suffix_hosts(
    hosts: &[String],
    cache: &dyn FqdnCacheLookup,
    ip_rule_hosts: &mut HashMap<Ipv4Addr, HashSet<String>>,
    rule_hosts: &mut HashSet<String>,
) {
    for h in hosts {
        for ip in cache.ips_for_hostname(h) {
            ip_rule_hosts.entry(ip).or_default().insert(h.clone());
        }
        rule_hosts.insert(h.clone());
    }
}

/// A [`FqdnCacheLookup`] view that hides denied IPs from `ips_for_hostname`,
/// so a codegen fed this view over the SECONDARY rule set emits neither a `/32`
/// route nor a WFP permit for a shared IP the policy declined — while
/// `ExactIp` filters (which read the address directly, not via the cache) are
/// untouched. Wrapping the cache keeps the deep per-IP emit helpers unchanged.
pub struct DenylistFilteredCache<'a> {
    inner: &'a dyn FqdnCacheLookup,
    denied: &'a HashSet<Ipv4Addr>,
}

impl<'a> DenylistFilteredCache<'a> {
    pub fn new(inner: &'a dyn FqdnCacheLookup, denied: &'a HashSet<Ipv4Addr>) -> Self {
        Self { inner, denied }
    }
}

impl FqdnCacheLookup for DenylistFilteredCache<'_> {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
        self.inner
            .ips_for_hostname(hostname)
            .into_iter()
            .filter(|ip| !self.denied.contains(ip))
            .collect()
    }

    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        // Hostnames are unchanged — the per-hostname IP set is filtered when the
        // codegen calls `ips_for_hostname` on each.
        self.inner.hostnames_under_suffix(suffix, limit)
    }

    fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.inner.direct_host_count_for_ip(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
    use nrr_domain::RuleId;

    /// A mock that also answers `direct_host_count_for_ip` from a fixed map.
    struct CensusMock {
        inner: MockFqdnCacheLookup,
        direct: HashMap<Ipv4Addr, u32>,
    }
    impl FqdnCacheLookup for CensusMock {
        fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
            self.inner.ips_for_hostname(hostname)
        }
        fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
            self.inner.hostnames_under_suffix(suffix, limit)
        }
        fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
            self.direct.get(&ip).copied().unwrap_or(0)
        }
    }

    fn fqdn_rule(id: &str, host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn any_rule_domain_never_denies() {
        let inner = MockFqdnCacheLookup::new();
        inner.set_ips("chatgpt.com", vec![Ipv4Addr::new(8, 6, 112, 0)]);
        let mut direct = HashMap::new();
        direct.insert(Ipv4Addr::new(8, 6, 112, 0), 9); // heavily shared
        let cache = CensusMock { inner, direct };
        let secondary = CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "chatgpt.com")]);
        let denied = secondary_ip_denylist(&secondary, &cache, SharedIpPolicy::AnyRuleDomain);
        assert!(denied.is_empty());
    }

    #[test]
    fn majority_of_ip_denies_a_minority_shared_ip() {
        let inner = MockFqdnCacheLookup::new();
        let shared = Ipv4Addr::new(8, 6, 112, 0);
        inner.set_ips("chatgpt.com", vec![shared]);
        let mut direct = HashMap::new();
        direct.insert(shared, 3); // 1 rule host vs 3 innocents → minority
        let cache = CensusMock { inner, direct };
        let secondary = CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "chatgpt.com")]);
        let denied = secondary_ip_denylist(&secondary, &cache, SharedIpPolicy::MajorityOfIp);
        assert!(denied.contains(&shared));
    }

    #[test]
    fn non_shared_ip_is_never_denied() {
        let inner = MockFqdnCacheLookup::new();
        let solo = Ipv4Addr::new(1, 2, 3, 4);
        inner.set_ips("example.com", vec![solo]);
        // No direct hosts recorded → direct_on_ip == 0 → committed.
        let cache = CensusMock {
            inner,
            direct: HashMap::new(),
        };
        let secondary = CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "example.com")]);
        let denied = secondary_ip_denylist(&secondary, &cache, SharedIpPolicy::MajorityOfRules);
        assert!(denied.is_empty());
    }
}

//! Neutral fake-IP enforcement policy: which real IPs of fake-routed hosts lose
//! their direct `/32` permit.
//!
//! When fake-IP is on, a scope host's traffic normally goes app -> fake address
//! -> TUN -> relay. An app that kept the real address (own cache, in-app DoH)
//! never sees the virtual answer, so the plan has to say what happens to it.
//! The census splits the answer in two, and only the shared half is special:
//!
//! - **Shared with a directly-routed host** -> suppress the `/32` permit. Pinning
//!   it to the tunnel would drag the direct co-tenant along, which is the
//!   shared-CDN collateral fake-IP exists to avoid. The co-tenant's own answer
//!   gates these addresses for the primary link instead.
//! - **Not shared** -> leave the `/32` permit and route alone. The address belongs
//!   to one host, whose rule already says "tunnel", so routing it there directly
//!   lands it exactly where the relay would have. Suppressing it bought nothing
//!   and cost a dead destination for every app holding the real address.
//!
//! Pure over injected ports (scope, rule set, FQDN cache, census), so every
//! branch is a unit test — no WFP, no network.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use nrr_platform_api::fake_ip::{FakeIpPoolConfig, FakeIpScope};
use nrr_platform_api::types::WfpFilterSpec;

use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::wfp_codegen::{PER_HOSTNAME_IP_CAP, SUFFIX_FANOUT_BACKSTOP};

/// Answers "is this IP shared with a directly-routed host?" — the gate that
/// decides whether fake-IP may take the address away from the direct host.
/// Production wraps the `shared_ip_direct_hosts` census.
pub trait SharedIpCensus: Send + Sync {
    fn is_shared_with_direct(&self, ip: Ipv4Addr) -> bool;
}

/// No IP is shared — nothing is suppressed. The default where no census is
/// available.
pub struct NoSharedIps;

impl SharedIpCensus for NoSharedIps {
    fn is_shared_with_direct(&self, _ip: Ipv4Addr) -> bool {
        false
    }
}

/// The production census: an IP present in this set is one the shared-IP policy
/// already declined for the secondary because it is shared with a directly
/// routed host — exactly the set fake-IP must NOT block. The orchestrator passes
/// the `secondary_ip_denylist` it already computes from the same rule book and
/// cache, so routing and fake-IP blocking gate on one coherent shared-IP view.
impl SharedIpCensus for std::collections::HashSet<Ipv4Addr> {
    fn is_shared_with_direct(&self, ip: Ipv4Addr) -> bool {
        self.contains(&ip)
    }
}

/// The fake-IP additions to a principal's enforcement plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeIpEnforcementPlan {
    /// Real IPs of fake-routed hosts whose `/32` permit must be SUPPRESSED:
    /// those a directly-routed host also uses. Union into the secondary
    /// denylist. An address only this host uses keeps its permit and route.
    pub suppress_ips: Vec<Ipv4Addr>,
}

/// Compute the fake-IP additions for the active principal's SECONDARY rules.
///
/// Empty when fake-IP is disabled. For every enabled secondary rule whose host
/// is in fake-IP scope, the host's cached real IPs are collected and the
/// census-shared ones suppressed. Order is deterministic (rule order, then the
/// cache's IP order), deduplicated.
#[must_use]
pub fn plan_fake_ip_enforcement(
    scope: &FakeIpScope,
    secondary: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
    census: &dyn SharedIpCensus,
) -> FakeIpEnforcementPlan {
    if !scope.is_enabled() {
        return FakeIpEnforcementPlan::default();
    }

    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let mut scope_ips: Vec<Ipv4Addr> = Vec::new();

    for rule in secondary.rules().iter().filter(|r| r.enabled) {
        let Some(addr) = &rule.address_match else {
            continue;
        };
        let hosts: Vec<String> = match addr {
            CanonicalAddressMatch::ExactFqdn(host) => vec![host.clone()],
            // `*.suffix` covers the apex host too; a zone never covers its bare
            // label. Same split the WFP/route codegens make.
            CanonicalAddressMatch::SuffixDomain(suffix) => {
                cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
            }
            CanonicalAddressMatch::Zone(zone) => {
                cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP)
            }
            // Literal IPs (and app rules, carried on a separate field) have no
            // name to hand a fake address, so fake-IP does not apply.
            CanonicalAddressMatch::ExactIp(_) => Vec::new(),
        };
        for host in hosts {
            if !scope.decide(&host, None).is_fake_ip() {
                continue;
            }
            for ip in cache
                .ips_for_hostname(&host)
                .into_iter()
                .take(PER_HOSTNAME_IP_CAP)
            {
                if seen.insert(ip) {
                    scope_ips.push(ip);
                }
            }
        }
    }

    let suppress_ips = scope_ips
        .into_iter()
        .filter(|ip| census.is_shared_with_direct(*ip))
        .collect();

    FakeIpEnforcementPlan { suppress_ips }
}

/// What the per-SID orchestrator needs to fold fake-IP into a filter plan: the
/// scope (who is fake-routed) and the pool (the addresses to permit). A disabled
/// scope makes every use below a no-op, so the orchestrator can hold this
/// unconditionally and let the setting decide.
#[derive(Clone, Debug)]
pub struct FakeIpEnforcementContext {
    pub scope: FakeIpScope,
    pub pool: FakeIpPoolConfig,
}

/// The additions fake-IP makes to a per-SID WFP plan.
#[derive(Clone, Debug, Default)]
pub struct FakeIpAugmentation {
    /// Real IPs to add to the secondary denylist — suppresses the `/32` permits
    /// of addresses a directly-routed host shares with a fake-routed one.
    pub denylist_additions: Vec<Ipv4Addr>,
    /// Filters to append: the fake-pool permit.
    pub extra_filters: Vec<WfpFilterSpec>,
}

/// Fold fake-IP into a per-SID plan: given the base secondary denylist (used as
/// the shared-IP census), return the denylist additions and the extra filters.
/// Empty when fake-IP is off.
///
/// `udp_relay_enabled` gates the pool permit's UDP handling (see
/// [`crate::killswitch_codegen::fake_ip_pool_permit_filters`]): `false` (the
/// default) keeps UDP hard-blocked into the pool; `true` lets QUIC/HTTP-3 ride
/// the relay's TUN stack like TCP already does.
///
/// Ordering the caller must honour: compute this against the ORIGINAL denylist
/// (before adding `denylist_additions`), THEN extend the denylist and generate,
/// THEN append `extra_filters`.
#[must_use]
pub fn augment_codegen_for_fake_ip(
    sid: &str,
    ctx: &FakeIpEnforcementContext,
    secondary: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
    base_denylist: &HashSet<Ipv4Addr>,
    udp_relay_enabled: bool,
) -> FakeIpAugmentation {
    if !ctx.scope.is_enabled() {
        return FakeIpAugmentation::default();
    }
    let plan = plan_fake_ip_enforcement(&ctx.scope, secondary, cache, base_denylist);
    let extra_filters =
        crate::killswitch_codegen::fake_ip_pool_permit_filters(sid, &ctx.pool, udp_relay_enabled);
    FakeIpAugmentation {
        denylist_additions: plan.suppress_ips,
        extra_filters,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::CanonicalRule;
    use nrr_domain::RuleId;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn fqdn_rule(host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(format!("r-{host}")),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule(suffix: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(format!("r-{suffix}")),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    struct SharedSet(Vec<Ipv4Addr>);
    impl SharedIpCensus for SharedSet {
        fn is_shared_with_direct(&self, ip: Ipv4Addr) -> bool {
            self.0.contains(&ip)
        }
    }

    #[test]
    fn disabled_scope_yields_an_empty_plan() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("chatgpt.com", vec![ip(104, 18, 32, 47)]);
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::disabled(),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &NoSharedIps,
        );
        assert_eq!(plan, FakeIpEnforcementPlan::default());
    }

    #[test]
    fn an_unshared_scope_ip_keeps_its_permit() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "chatgpt.com",
            vec![ip(104, 18, 32, 47), ip(104, 18, 33, 47)],
        );
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::enabled(Vec::<String>::new()),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &NoSharedIps,
        );
        // One host owns both addresses and its rule says "tunnel", so routing
        // them there directly lands them where the relay would have.
        assert!(plan.suppress_ips.is_empty());
    }

    #[test]
    fn only_the_ip_a_direct_host_shares_is_suppressed() {
        let cache = MockFqdnCacheLookup::new();
        // .32 is shared with a direct host (a non-scope host on the same CDN IP);
        // .33 is unique to chatgpt.
        cache.set_ips(
            "chatgpt.com",
            vec![ip(104, 18, 32, 47), ip(104, 18, 33, 47)],
        );
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::enabled(Vec::<String>::new()),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &SharedSet(vec![ip(104, 18, 32, 47)]),
        );
        // Pinning the shared one would drag its direct co-tenant into the
        // tunnel; the unshared one has no co-tenant to drag.
        assert_eq!(plan.suppress_ips, vec![ip(104, 18, 32, 47)]);
    }

    /// The 0719 breakage in one assertion: an address a direct host also uses
    /// must never keep a secondary `/32` permit, however many fake-routed hosts
    /// claim it. Pinning it would carry the direct co-tenant into the tunnel.
    #[test]
    fn a_shared_ip_is_never_left_pinnable_to_the_tunnel() {
        let cache = MockFqdnCacheLookup::new();
        let shared = ip(142, 251, 154, 119);
        cache.set_ips("gemini.google.com", vec![shared]);
        cache.set_ips("aistudio.google.com", vec![shared, ip(216, 58, 198, 46)]);
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::enabled(Vec::<String>::new()),
            &CanonicalRuleSet::from_rules(vec![
                fqdn_rule("gemini.google.com"),
                fqdn_rule("aistudio.google.com"),
            ]),
            &cache,
            &SharedSet(vec![shared]),
        );
        assert_eq!(plan.suppress_ips, vec![shared], "deduplicated, shared only");
    }

    #[test]
    fn a_user_excluded_host_is_not_suppressed() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("torrent.example", vec![ip(203, 0, 113, 5)]);
        let plan = plan_fake_ip_enforcement(
            // The host is excluded from fake-IP → it keeps its real /32 path.
            &FakeIpScope::enabled(["torrent.example"]),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("torrent.example")]),
            &cache,
            &NoSharedIps,
        );
        assert!(plan.suppress_ips.is_empty());
    }

    #[test]
    fn a_suffix_rule_enumerates_cached_subhosts() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.openai.com", vec![ip(104, 18, 0, 1)]);
        cache.set_ips("cdn.openai.com", vec![ip(104, 18, 0, 2)]);
        // Both shared, so the suffix fan-out itself is what is under test here.
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::enabled(Vec::<String>::new()),
            &CanonicalRuleSet::from_rules(vec![suffix_rule("openai.com")]),
            &cache,
            &SharedSet(vec![ip(104, 18, 0, 1), ip(104, 18, 0, 2)]),
        );
        let mut got = plan.suppress_ips;
        got.sort();
        assert_eq!(got, vec![ip(104, 18, 0, 1), ip(104, 18, 0, 2)]);
    }

    fn ctx(enabled: bool) -> FakeIpEnforcementContext {
        FakeIpEnforcementContext {
            scope: if enabled {
                FakeIpScope::enabled(Vec::<String>::new())
            } else {
                FakeIpScope::disabled()
            },
            pool: nrr_platform_api::fake_ip::FakeIpPoolConfig::default(),
        }
    }

    #[test]
    fn augmentation_is_empty_when_fake_ip_is_off() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("chatgpt.com", vec![ip(104, 18, 32, 47)]);
        let aug = augment_codegen_for_fake_ip(
            "S",
            &ctx(false),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &HashSet::new(),
            false,
        );
        assert!(aug.denylist_additions.is_empty());
        assert!(aug.extra_filters.is_empty());
    }

    #[test]
    fn augmentation_suppresses_only_the_shared_ip_and_permits_pool() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "chatgpt.com",
            vec![ip(104, 18, 32, 47), ip(104, 18, 33, 47)],
        );
        // .32 is shared with a direct host (in the base denylist).
        let mut base = HashSet::new();
        base.insert(ip(104, 18, 32, 47));
        let aug = augment_codegen_for_fake_ip(
            "S-1-5-21-3",
            &ctx(true),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &base,
            false,
        );
        // Only the shared .32 loses its /32 permit; .33 belongs to chatgpt
        // alone and keeps the route its rule already implies.
        assert_eq!(aug.denylist_additions, vec![ip(104, 18, 32, 47)]);
        // A real address is never blocked outright: the shared one would take
        // its direct co-tenant down with it, the unshared one is simply routed.
        assert!(
            !aug.extra_filters.iter().any(|f| {
                f.action == nrr_platform_api::types::WfpAction::Block && f.remote_ip.is_some()
            }),
            "no per-IP block of a real address"
        );
        let permits = aug
            .extra_filters
            .iter()
            .filter(|f| f.action == nrr_platform_api::types::WfpAction::Permit)
            .count();
        assert!(permits >= 1, "the fake pool is permitted");
    }

    #[test]
    fn udp_relay_enabled_drops_pool_udp_blocks() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("chatgpt.com", vec![ip(104, 18, 32, 47)]);
        let aug = augment_codegen_for_fake_ip(
            "S-1-5-21-3",
            &ctx(true),
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("chatgpt.com")]),
            &cache,
            &HashSet::new(),
            true,
        );
        assert!(
            aug.extra_filters
                .iter()
                .filter(|f| f.remote_ip.is_none())
                .all(|f| f.ip_protocol.is_none()),
            "the pool permit(s) must stay protocol-agnostic when the UDP relay is enabled"
        );
    }

    #[test]
    fn a_literal_ip_rule_never_contributes() {
        let cache = MockFqdnCacheLookup::new();
        let literal = CanonicalRule {
            id: RuleId("r-ip".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(ip(198, 51, 100, 7))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        let plan = plan_fake_ip_enforcement(
            &FakeIpScope::enabled(Vec::<String>::new()),
            &CanonicalRuleSet::from_rules(vec![literal]),
            &cache,
            &NoSharedIps,
        );
        assert!(plan.suppress_ips.is_empty());
    }
}

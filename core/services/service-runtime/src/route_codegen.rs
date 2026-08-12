//! route-table codegen for **interface routing**.
//!
//! The sibling of [`crate::wfp_codegen`]: where `wfp_codegen` emits WFP
//! ALE permit/block filters (the security / fail-closed kill-switch),
//! this module emits [`RouteEntry`] entries for the **system route
//! table** — the mechanism that actually sends secondary-bound traffic
//! out the secondary adapter (`strategy.rs`: "Route table for routing;
//! WFP ALE for blocking").
//!
//! For each enabled rule bound to the secondary route it resolves the
//! rule's address condition to IPv4 addresses and emits a `/32` host
//! route via the secondary gateway:
//!
//! | Rule kind | Routes |
//! |---|---|
//! | `ExactIp(addr)` | 1 route to `addr`. |
//! | `ExactFqdn(name)` | one route per cached resolved IPv4 (cold cache → 0 + diagnostic). |
//! | `SuffixDomain(s)` | fan-out: the apex plus each cached sub-hostname under the suffix × its cached IPv4 set (cold cache → 0 + diagnostic). |
//! | `Zone(z)` | same fan-out minus the apex — the bare zone label is not a member of its zone. |
//! | app-only rule (no address) | one route per destination the app has been observed connecting to (none observed yet → 0 + diagnostic). |
//! | app + address rule | **0** — the two conditions match as AND and a route cannot be scoped to a process, so routing the address would over-route. |
//!
//! Tier boundary (`strategy.rs`): IPv4 IP/FQDN/domain-suffix/zone routing
//! is **Free**. IP-subnet/CIDR zones are **Pro** (they do not exist in the
//! canonical model today — `Zone` is always a *domain* suffix). Application
//! rules route by destination, learned from observation: a route entry itself
//! is never process-scoped (no route table is), so what the table carries is
//! "this destination goes over that link" — precise per-PROCESS routing, where
//! two processes reaching the same address take different links, still needs
//! the Pro callout driver. The system route table is machine-wide, so precise
//! per-user routing is likewise a Pro/callout feature; the caller decides whose
//! effective rules drive the global table (block 16.18 wiring).

use std::collections::{BTreeSet, HashSet};
use std::net::Ipv4Addr;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppPattern, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::{RouteBehaviorMode, RuleAction};
use nrr_platform_api::RouteEntry;

use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::net_filter::is_non_routable_v4;
use crate::wfp_codegen::{PER_HOSTNAME_IP_CAP, SUFFIX_FANOUT_BACKSTOP};

/// Upper bound on routes emitted for a single rule, so a pathological
/// suffix fan-out cannot flood the route table.  — raised 256 →
/// 4096 in step with `wfp_codegen::SUFFIX_FANOUT_BACKSTOP`: a busy zone rule
/// overflowed 256 in normal use, and a host that keeps its WFP permit but
/// loses its `/32` would silently ride the wrong link. A runaway guard, not
/// a product limit.
pub const MAX_ROUTES_PER_RULE: usize = 4096;

/// Metric for our secondary routes. Low = preferred over the default
/// route, but we never touch the system default itself (`is_ours = true`
/// only). A VPN may still install a lower-metric route for the same
/// destination — documented in `strategy.rs`'s risk matrix.
pub const SECONDARY_ROUTE_METRIC: u32 = 5;

/// the two split-default halves. Together they cover all of
/// IPv4 and, being more specific (`/1`) than the OS default `0.0.0.0/0`, win
/// over it WITHOUT our ever touching the fail-safe default itself. In mode B we
/// own this pair (pointing at the secondary/VPN) so *everything* travels the
/// tunnel; the same shape is what a `redirect-gateway`-style VPN installs.
pub const OVERLAY_LOW: (Ipv4Addr, u8) = (Ipv4Addr::new(0, 0, 0, 0), 1); // 0.0.0.0/1
pub const OVERLAY_HIGH: (Ipv4Addr, u8) = (Ipv4Addr::new(128, 0, 0, 0), 1); // 128.0.0.0/1

/// mode-A counter-overlay: four `/2` blocks that together
/// cover all of IPv4 and are MORE specific than a redirect VPN's `/1` pair, so
/// non-rule traffic falls back to the **primary** by longest-prefix WITHOUT our
/// removing the VPN's own routes (removing them destabilises the client — see
/// the dormant `route_reconciler::strip_foreign_overlay`). Secondary `/32`
/// rules stay more specific still → those keep going via the secondary.
pub const COUNTER_OVERLAY: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(0, 0, 0, 0), 2),   // 0.0.0.0/2
    (Ipv4Addr::new(64, 0, 0, 0), 2),  // 64.0.0.0/2
    (Ipv4Addr::new(128, 0, 0, 0), 2), // 128.0.0.0/2
    (Ipv4Addr::new(192, 0, 0, 0), 2), // 192.0.0.0/2
];

/// Where matched traffic is sent: an adapter's gateway + interface index,
/// resolved by the caller from the active route binding. Used for the
/// secondary (VPN) target and — in mode B (block 16.18.vpn) — for the primary
/// NIC too, when pulling exception routes back off the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondaryRouteTarget {
    pub gateway: Ipv4Addr,
    pub interface_index: u32,
}

/// Non-fatal codegen observations surfaced to diagnostics/health so the
/// GUI can explain "no routes yet — DNS warm-up pending" or "app routing
/// needs Pro".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteCodegenDiagnostic {
    /// An `ExactFqdn` rule had no cached IPs (cold DNS cache).
    HostnameUnresolved { rule_id: String, hostname: String },
    /// A `SuffixDomain` rule had no cached sub-hostnames yet.
    SuffixEmpty { rule_id: String, suffix: String },
    /// A `Zone` rule had no cached sub-hostnames yet.
    ZoneEmpty { rule_id: String, zone: String },
    /// The rule carries BOTH an application and an address condition, so it is
    /// **not** routed here: the two match as AND, and a route cannot be scoped
    /// to a process — routing the address would ignore the app half and
    /// over-route every other process. Informational, not an error: the rule
    /// still takes effect through the filter layer (`wfp_codegen`). An
    /// app-ONLY rule is routed, by observed destination.
    AppRuleRoutingProOnly { rule_id: String },
    /// An application rule has no observed destinations yet (cold start, or
    /// the app has not connected since the service came up), so it produced no
    /// route. Self-clearing: the first observed connection installs one.
    AppRuleUnobserved { rule_id: String, app: String },
    /// a mode wanted to send some traffic to the **primary**
    /// NIC but no usable primary target is bound: in mode B the per-rule
    /// exceptions can't be carved back off the tunnel; in mode A the `/2`
    /// counter-overlay can't be installed, so non-rule traffic stays on whatever
    /// the VPN's own redirect does. Bind a primary adapter to enable it.
    PrimaryExceptionsUnavailable,
}

#[derive(Debug, Default)]
pub struct RouteCodegenOutput {
    pub routes: Vec<RouteEntry>,
    pub diagnostics: Vec<RouteCodegenDiagnostic>,
}

/// Build the secondary route set for `secondary_rules` (the rules bound
/// to the secondary route role). Pure: no I/O beyond the injected FQDN
/// cache reader. Routes are de-duplicated by destination across rules.
pub fn generate_secondary_routes(
    secondary_rules: &CanonicalRuleSet,
    target: &SecondaryRouteTarget,
    cache: &dyn FqdnCacheLookup,
    app_observations: &dyn AppObservationLookup,
    denied: &HashSet<Ipv4Addr>,
) -> RouteCodegenOutput {
    let mut out = RouteCodegenOutput::default();
    let mut seen: BTreeSet<Ipv4Addr> = BTreeSet::new();

    for rule in secondary_rules.rules() {
        if !rule.enabled {
            continue;
        }
        // A Block-action rule drops its destination — it must never get a /32
        // route. The WFP codegen layer emits a hard FWP_ACTION_BLOCK filter
        // instead. Skip before any address resolution. (This also covers the
        // mode-B primary-exception carving, which reuses this function.)
        if matches!(rule.action, RuleAction::Block) {
            continue;
        }
        // A rule carrying BOTH an application and an address condition still
        // produces no route: the two match as AND, and the system route table
        // cannot scope a route to a process, so routing the address globally
        // would ignore the app half and over-route every other process. The
        // user adds a separate address-only rule to route that destination.
        if rule.app_match.is_some() && rule.address_match.is_some() {
            out.diagnostics
                .push(RouteCodegenDiagnostic::AppRuleRoutingProOnly {
                    rule_id: rule.id.as_str().to_string(),
                });
            continue;
        }
        // App-only rule: route the destinations this app has actually been
        // observed connecting to, the same way an `ExactFqdn` rule routes its
        // resolved addresses.
        //
        // Without this an app that never asks DNS anything — a messenger with
        // hardcoded server addresses is the canonical case — got its per-app
        // permit filter but no route: the packet left over the main link, the
        // permit is conditional on leaving the additional link, so the
        // catch-all dropped it and the app was dead for as long as the
        // additional link was up. The permit and the route have to agree on
        // which interface the traffic uses.
        //
        // The route itself is not app-scoped (no route table is), so it also
        // moves other processes talking to the very same address. That is the
        // same trade-off address rules already make, bounded by the observation
        // store's own per-app cap and the shared-address policy below.
        if let Some(app) = rule.app_match.as_ref() {
            let pattern = match &app.pattern {
                CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.as_str(),
            };
            let observed = app_observations.ips_for_app(pattern);
            if observed.is_empty() {
                out.diagnostics
                    .push(RouteCodegenDiagnostic::AppRuleUnobserved {
                        rule_id: rule.id.as_str().to_string(),
                        app: pattern.to_string(),
                    });
                continue;
            }
            let mut per_rule = 0usize;
            for ip in observed {
                // Shared with a direct destination and declined by policy —
                // dropped from the route exactly as it is from the filter set.
                if denied.contains(&ip) {
                    continue;
                }
                if !push_route(ip, target, &mut seen, &mut out, &mut per_rule) {
                    break;
                }
            }
            continue;
        }
        let mut per_rule = 0usize;
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                push_route(*ip, target, &mut seen, &mut out, &mut per_rule);
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                let ips = cache.ips_for_hostname(host);
                if ips.is_empty() {
                    out.diagnostics
                        .push(RouteCodegenDiagnostic::HostnameUnresolved {
                            rule_id: rule.id.as_str().to_string(),
                            hostname: host.clone(),
                        });
                    continue;
                }
                for ip in ips.into_iter().take(PER_HOSTNAME_IP_CAP) {
                    if !push_route(ip, target, &mut seen, &mut out, &mut per_rule) {
                        break;
                    }
                }
            }
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                let had_subhosts = fanout_suffix(
                    suffix,
                    true,
                    target,
                    cache,
                    &mut seen,
                    &mut out,
                    &mut per_rule,
                );
                if !had_subhosts {
                    out.diagnostics.push(RouteCodegenDiagnostic::SuffixEmpty {
                        rule_id: rule.id.as_str().to_string(),
                        suffix: suffix.clone(),
                    });
                }
            }
            Some(CanonicalAddressMatch::Zone(zone)) => {
                let had_subhosts = fanout_suffix(
                    zone,
                    false,
                    target,
                    cache,
                    &mut seen,
                    &mut out,
                    &mut per_rule,
                );
                if !had_subhosts {
                    out.diagnostics.push(RouteCodegenDiagnostic::ZoneEmpty {
                        rule_id: rule.id.as_str().to_string(),
                        zone: zone.clone(),
                    });
                }
            }
            None => {
                // A rule with neither an address nor an app condition has
                // nothing to route — ignored. (App rules were handled by
                // the `app_match` guard above.)
            }
        }
    }

    out
}

/// Mode-aware route generation (block 16.18.vpn). The desired route set
/// depends on the active [`RouteBehaviorMode`]:
///
/// - **`PreferPrimary`** (mode A): secondary-bound rules → `/32` via the
///   secondary (VPN); with a primary target, a `/2` counter-overlay
///   ([`COUNTER_OVERLAY`]) via primary out-specifics a redirect VPN's `/1`, so
///   all non-rule traffic rides the primary — additive, the VPN's own routes
///   are never removed.
/// - **`PreferSecondaryWhenAvailable` / `StrictSecondaryFailClosed`**
///   (mode B): NetRuleRouter owns a split-default overlay
///   ([`OVERLAY_LOW`] + [`OVERLAY_HIGH`]) via the secondary so *everything*
///   travels the tunnel, and primary-bound rules are pulled back to the
///   primary NIC as `/32` exceptions.
///
/// The OS default `0.0.0.0/0` is never emitted or touched — it stays the
/// fail-safe anchor on primary. `primary_target` is needed to send traffic to
/// the primary NIC (the mode-A counter-overlay and the mode-B exceptions);
/// `None` records [`RouteCodegenDiagnostic::PrimaryExceptionsUnavailable`] and
/// skips that part. Pure: no I/O beyond the injected FQDN cache reader.
pub fn generate_routes(
    mode: RouteBehaviorMode,
    rule_book: &CanonicalRuleBook,
    primary_target: Option<&SecondaryRouteTarget>,
    secondary_target: &SecondaryRouteTarget,
    cache: &dyn FqdnCacheLookup,
    app_observations: &dyn AppObservationLookup,
    // secondary IPs the shared-IP policy declined. Applied to
    // the mode-A secondary `/32` fan-out ONLY; the same set the WFP codegen uses,
    // so a declined shared IP is dropped from BOTH the route and the kill-switch.
    denied: &HashSet<Ipv4Addr>,
) -> RouteCodegenOutput {
    match mode {
        RouteBehaviorMode::PreferPrimary => {
            // Secondary-bound rules → /32 via the secondary (VPN), minus any
            // shared IP the policy declined (fed via a filtered cache view).
            let secondary_cache =
                crate::secondary_ip_policy::DenylistFilteredCache::new(cache, denied);
            let mut out = generate_secondary_routes(
                &rule_book.secondary,
                secondary_target,
                &secondary_cache,
                app_observations,
                denied,
            );
            // Mode-A selectivity over a redirect VPN: a /2 counter-overlay via
            // primary out-specifics the VPN's /1, so all non-rule traffic falls
            // back to primary WITHOUT removing the VPN's own routes (additive →
            // the tunnel is not disturbed). Secondary /32 rules stay more
            // specific → still via the secondary. Needs a usable primary target.
            match primary_target {
                Some(pt) => {
                    for half in COUNTER_OVERLAY {
                        out.routes.push(overlay_route(half, pt));
                    }
                }
                None => out
                    .diagnostics
                    .push(RouteCodegenDiagnostic::PrimaryExceptionsUnavailable),
            }
            out
        }
        RouteBehaviorMode::PreferSecondaryWhenAvailable
        | RouteBehaviorMode::StrictSecondaryFailClosed => {
            let mut out = RouteCodegenOutput::default();
            // Own the split-default overlay → all traffic to the tunnel.
            out.routes
                .push(overlay_route(OVERLAY_LOW, secondary_target));
            out.routes
                .push(overlay_route(OVERLAY_HIGH, secondary_target));
            // Carve primary-bound rules back onto the primary NIC as /32
            // exceptions. Reuse the host-route codegen, just aimed at primary.
            match primary_target {
                Some(pt) => {
                    // Primary-bound exceptions are carved out of the tunnel, so
                    // the shared-address denylist (which only ever removes
                    // destinations from the tunnel) does not apply here.
                    let exceptions = generate_secondary_routes(
                        &rule_book.primary,
                        pt,
                        cache,
                        app_observations,
                        &HashSet::new(),
                    );
                    out.routes.extend(exceptions.routes);
                    out.diagnostics.extend(exceptions.diagnostics);
                }
                None => out
                    .diagnostics
                    .push(RouteCodegenDiagnostic::PrimaryExceptionsUnavailable),
            }
            out
        }
    }
}

/// `/32` routes that send the service's own DNS queries out the secondary link
/// (the route half of the DNS-over-secondary setting).
///
/// Source-binding a query socket to the tunnel address is not enough on its
/// own: the route table still picks the outgoing interface by DESTINATION, so
/// without these the packet would leave over the primary link carrying a tunnel
/// source address — traffic the provider drops as spoofed. Pure; the caller
/// decides whether the setting is on and appends the result to the rule routes.
///
/// Deduplication against the rule routes is the reconciler's job (a public
/// resolver address that some rule already routes is simply the same entry).
pub fn dns_via_secondary_routes(
    servers: &[Ipv4Addr],
    target: &SecondaryRouteTarget,
) -> Vec<RouteEntry> {
    servers
        .iter()
        .copied()
        .filter(|ip| !is_non_routable_v4(ip))
        .map(|ip| RouteEntry {
            destination: ip,
            prefix_length: 32,
            next_hop: target.gateway,
            interface_index: target.interface_index,
            metric: SECONDARY_ROUTE_METRIC,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        })
        .collect()
}

/// Build one overlay route (`0.0.0.0/1` or `128.0.0.0/1`) via `target`.
fn overlay_route((dest, prefix): (Ipv4Addr, u8), target: &SecondaryRouteTarget) -> RouteEntry {
    RouteEntry {
        destination: dest,
        prefix_length: prefix,
        next_hop: target.gateway,
        interface_index: target.interface_index,
        metric: SECONDARY_ROUTE_METRIC,
        is_ours: true,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

/// Append a `/32` route for `ip` (deduped by destination, capped per
/// rule). Returns `false` only when the per-rule cap is hit so the caller
/// stops fanning out.
fn push_route(
    ip: Ipv4Addr,
    target: &SecondaryRouteTarget,
    seen: &mut BTreeSet<Ipv4Addr>,
    out: &mut RouteCodegenOutput,
    per_rule: &mut usize,
) -> bool {
    if *per_rule >= MAX_ROUTES_PER_RULE {
        return false;
    }
    // Never route a non-routable destination. An ad-blocking hosts file
    // pins domains to loopback/unspecified (e.g. `musical.ly 127.0.0.1`);
    // routing that out the secondary (VPN) link is nonsensical — loopback
    // never leaves the box. Skip WITHOUT signalling a cap hit so the caller
    // keeps scanning this rule's remaining (routable) IPs.
    if is_non_routable_v4(&ip) {
        tracing::debug!(
            target: "nrr::route-codegen",
            ip = %ip,
            "destination pinned to loopback/unspecified (hosts file?) — not routed",
        );
        return true;
    }
    // Already routed by an earlier rule → not a new route, but not a cap
    // hit either: keep scanning this rule.
    if !seen.insert(ip) {
        return true;
    }
    out.routes.push(RouteEntry {
        destination: ip,
        prefix_length: 32,
        next_hop: target.gateway,
        interface_index: target.interface_index,
        metric: SECONDARY_ROUTE_METRIC,
        is_ours: true,
        table: nrr_platform_api::RouteTableRef::Main,
    });
    *per_rule += 1;
    true
}

/// Fan a domain suffix / zone out to the cached sub-hostnames' IPs and
/// emit a route per IP. Returns `true` if the suffix had ANY cached
/// sub-hostname (so the caller can distinguish a cold-cache suffix —
/// which deserves a "DNS warm-up pending" diagnostic — from one that
/// simply resolved to already-routed IPs).
/// Fan a suffix-shaped rule out to `/32` routes.
///
/// `include_apex` splits the two forms: a `SuffixDomain` rule covers its apex
///  while a `Zone` rule never covers the bare zone label.
fn fanout_suffix(
    suffix: &str,
    include_apex: bool,
    target: &SecondaryRouteTarget,
    cache: &dyn FqdnCacheLookup,
    seen: &mut BTreeSet<Ipv4Addr>,
    out: &mut RouteCodegenOutput,
    per_rule: &mut usize,
) -> bool {
    let subhosts = if include_apex {
        cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
    } else {
        cache.hostnames_under_suffix(suffix, SUFFIX_FANOUT_BACKSTOP)
    };
    let had_subhosts = !subhosts.is_empty();
    for sub in subhosts {
        for ip in cache
            .ips_for_hostname(&sub)
            .into_iter()
            .take(PER_HOSTNAME_IP_CAP)
        {
            if !push_route(ip, target, seen, out, per_rule) {
                return had_subhosts;
            }
        }
    }
    had_subhosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_observation_lookup::MockAppObservationLookup;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalAppMatch, CanonicalRule};
    use nrr_domain::RuleId;

    /// No application has been observed connecting anywhere — the state every
    /// address-rule test runs in.
    fn no_apps() -> MockAppObservationLookup {
        MockAppObservationLookup::new()
    }

    fn app_rule(id: &str, pattern: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(pattern.to_string()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn app_only_rule_routes_every_observed_destination() {
        let cache = MockFqdnCacheLookup::new();
        let apps = MockAppObservationLookup::new();
        apps.set_ips(
            "telegram.exe",
            vec![ip(149, 154, 167, 50), ip(91, 108, 56, 104)],
        );
        let rs = ruleset(vec![app_rule("R-app", "telegram.exe")]);

        let out = generate_secondary_routes(&rs, &target(), &cache, &apps, &HashSet::new());

        let mut dests: Vec<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        dests.sort();
        assert_eq!(dests, vec![ip(91, 108, 56, 104), ip(149, 154, 167, 50)]);
        assert!(out
            .routes
            .iter()
            .all(|r| r.prefix_length == 32 && r.interface_index == target().interface_index));
        assert!(out.diagnostics.is_empty());
    }

    #[test]
    fn app_only_rule_without_observations_diagnoses_and_routes_nothing() {
        let cache = MockFqdnCacheLookup::new();
        let rs = ruleset(vec![app_rule("R-app", "telegram.exe")]);

        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());

        assert!(out.routes.is_empty());
        assert!(matches!(
            out.diagnostics.as_slice(),
            [RouteCodegenDiagnostic::AppRuleUnobserved { app, .. }] if app == "telegram.exe"
        ));
    }

    #[test]
    fn app_only_rule_skips_destinations_the_shared_address_policy_declined() {
        let cache = MockFqdnCacheLookup::new();
        let apps = MockAppObservationLookup::new();
        apps.set_ips("telegram.exe", vec![ip(8, 8, 8, 8), ip(91, 108, 56, 104)]);
        let rs = ruleset(vec![app_rule("R-app", "telegram.exe")]);
        let denied: HashSet<Ipv4Addr> = [ip(8, 8, 8, 8)].into_iter().collect();

        let out = generate_secondary_routes(&rs, &target(), &cache, &apps, &denied);

        let dests: Vec<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        assert_eq!(dests, vec![ip(91, 108, 56, 104)]);
    }

    fn target() -> SecondaryRouteTarget {
        SecondaryRouteTarget {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface_index: 7,
        }
    }

    fn rule(id: &str, enabled: bool, m: CanonicalAddressMatch) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn ruleset(rules: Vec<CanonicalRule>) -> CanonicalRuleSet {
        CanonicalRuleSet::from_rules(rules)
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn exact_ip_emits_one_host_route_via_secondary() {
        let cache = MockFqdnCacheLookup::new();
        let rs = ruleset(vec![rule(
            "r-ip",
            true,
            CanonicalAddressMatch::ExactIp(ip(93, 184, 216, 34)),
        )]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        assert_eq!(out.routes.len(), 1);
        let r = &out.routes[0];
        assert_eq!(r.destination, ip(93, 184, 216, 34));
        assert_eq!(r.prefix_length, 32);
        assert_eq!(r.next_hop, ip(10, 0, 0, 1));
        assert_eq!(r.interface_index, 7);
        assert!(r.is_ours);
        assert!(out.diagnostics.is_empty());
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let cache = MockFqdnCacheLookup::new();
        let rs = ruleset(vec![rule(
            "r-off",
            false,
            CanonicalAddressMatch::ExactIp(ip(1, 1, 1, 1)),
        )]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        assert!(out.routes.is_empty());
    }

    #[test]
    fn block_action_rule_produces_no_route() {
        let cache = MockFqdnCacheLookup::new();
        let mut blocked = rule(
            "r-block",
            true,
            CanonicalAddressMatch::ExactIp(ip(203, 0, 113, 5)),
        );
        blocked.action = nrr_domain::RuleAction::Block;
        let rs = ruleset(vec![blocked]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        // A dropped destination gets no /32 route — the WFP block enforces it.
        assert!(out.routes.is_empty());
    }

    #[test]
    fn exact_fqdn_warm_cache_routes_each_ip_cold_cache_diagnoses() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![ip(20, 0, 0, 1), ip(20, 0, 0, 2)]);
        let rs = ruleset(vec![
            rule(
                "r-warm",
                true,
                CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
            ),
            rule(
                "r-cold",
                true,
                CanonicalAddressMatch::ExactFqdn("cold.example.com".into()),
            ),
        ]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        let dests: BTreeSet<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        assert_eq!(dests, BTreeSet::from([ip(20, 0, 0, 1), ip(20, 0, 0, 2)]));
        assert!(out
            .diagnostics
            .iter()
            .any(|d| matches!(d, RouteCodegenDiagnostic::HostnameUnresolved { hostname, .. } if hostname == "cold.example.com")));
    }

    #[test]
    fn suffix_and_zone_fan_out_to_cached_subdomain_ips() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("a.corp.example", vec![ip(30, 0, 0, 1)]);
        cache.set_ips("b.corp.example", vec![ip(30, 0, 0, 2)]);
        // A host under a different suffix must NOT leak in.
        cache.set_ips("x.other.example", vec![ip(99, 0, 0, 9)]);

        let suffix_rules = ruleset(vec![rule(
            "r-suffix",
            true,
            CanonicalAddressMatch::SuffixDomain("corp.example".into()),
        )]);
        let out = generate_secondary_routes(
            &suffix_rules,
            &target(),
            &cache,
            &no_apps(),
            &HashSet::new(),
        );
        let dests: BTreeSet<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        assert_eq!(dests, BTreeSet::from([ip(30, 0, 0, 1), ip(30, 0, 0, 2)]));

        // Zone uses the same fan-out.
        let zone_rules = ruleset(vec![rule(
            "r-zone",
            true,
            CanonicalAddressMatch::Zone("example".into()),
        )]);
        let out2 =
            generate_secondary_routes(&zone_rules, &target(), &cache, &no_apps(), &HashSet::new());
        assert!(out2.routes.iter().any(|r| r.destination == ip(99, 0, 0, 9)));
    }

    #[test]
    fn suffix_routes_its_apex_while_a_zone_never_routes_its_bare_label() {
        //  — `*.corp.example` covers "corp.example" itself, so the
        // apex gets a `/32`. A zone rule keeps ignoring its own bare label,
        // otherwise a host literally named "example" would be swept in.
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("corp.example", vec![ip(30, 0, 0, 7)]);
        cache.set_ips("a.corp.example", vec![ip(30, 0, 0, 1)]);
        cache.set_ips("example", vec![ip(88, 0, 0, 8)]);

        let suffix_rules = ruleset(vec![rule(
            "r-suffix",
            true,
            CanonicalAddressMatch::SuffixDomain("corp.example".into()),
        )]);
        let out = generate_secondary_routes(
            &suffix_rules,
            &target(),
            &cache,
            &no_apps(),
            &HashSet::new(),
        );
        let dests: BTreeSet<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        assert_eq!(dests, BTreeSet::from([ip(30, 0, 0, 7), ip(30, 0, 0, 1)]));

        let zone_rules = ruleset(vec![rule(
            "r-zone",
            true,
            CanonicalAddressMatch::Zone("example".into()),
        )]);
        let out2 =
            generate_secondary_routes(&zone_rules, &target(), &cache, &no_apps(), &HashSet::new());
        assert!(
            !out2.routes.iter().any(|r| r.destination == ip(88, 0, 0, 8)),
            "the bare zone label must not be routed"
        );
    }

    #[test]
    fn empty_suffix_emits_diagnostic_no_route() {
        let cache = MockFqdnCacheLookup::new();
        let rs = ruleset(vec![rule(
            "r-empty",
            true,
            CanonicalAddressMatch::SuffixDomain("nothing.cached".into()),
        )]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        assert!(out.routes.is_empty());
        assert!(out
            .diagnostics
            .iter()
            .any(|d| matches!(d, RouteCodegenDiagnostic::SuffixEmpty { .. })));
    }

    #[test]
    fn loopback_and_unspecified_destinations_are_not_routed() {
        let cache = MockFqdnCacheLookup::new();
        // An ad-blocking hosts file pins the domain to loopback → the cache
        // holds only 127.0.0.1, so the ExactFqdn rule must produce NO route.
        cache.set_ips("musical.ly", vec![ip(127, 0, 0, 1)]);
        // A mixed resolution (loopback + a real public IP) must route ONLY
        // the routable IP.
        cache.set_ips(
            "mixed.example.com",
            vec![ip(127, 0, 0, 1), ip(93, 184, 216, 34)],
        );
        let rs = ruleset(vec![
            rule(
                "r-loop-ip",
                true,
                CanonicalAddressMatch::ExactIp(ip(127, 0, 0, 1)),
            ),
            rule(
                "r-unspec-ip",
                true,
                CanonicalAddressMatch::ExactIp(ip(0, 0, 0, 0)),
            ),
            rule(
                "r-loop-fqdn",
                true,
                CanonicalAddressMatch::ExactFqdn("musical.ly".into()),
            ),
            rule(
                "r-mixed",
                true,
                CanonicalAddressMatch::ExactFqdn("mixed.example.com".into()),
            ),
        ]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        // Only the public IP survives; loopback + unspecified are dropped and
        // the loopback-only FQDN yields nothing.
        let dests: BTreeSet<Ipv4Addr> = out.routes.iter().map(|r| r.destination).collect();
        assert_eq!(dests, BTreeSet::from([ip(93, 184, 216, 34)]));
    }

    #[test]
    fn duplicate_destination_across_rules_is_routed_once() {
        let cache = MockFqdnCacheLookup::new();
        let rs = ruleset(vec![
            rule("r1", true, CanonicalAddressMatch::ExactIp(ip(40, 0, 0, 1))),
            rule("r2", true, CanonicalAddressMatch::ExactIp(ip(40, 0, 0, 1))),
        ]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        assert_eq!(out.routes.len(), 1, "same destination must route once");
    }

    #[test]
    fn combined_app_and_address_rule_is_not_routed_in_free() {
        // A rule with BOTH an app condition and an address is block-only in
        // Free — it must NOT produce a route (routing the address would
        // ignore the app scoping and over-route every process).
        use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern};
        let cache = MockFqdnCacheLookup::new();
        let combined = CanonicalRule {
            id: RuleId("r-app-ip".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(ip(50, 0, 0, 1))),
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("chrome.exe".into()),
                include_child_processes: true,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        let rs = ruleset(vec![combined]);
        let out = generate_secondary_routes(&rs, &target(), &cache, &no_apps(), &HashSet::new());
        assert!(
            out.routes.is_empty(),
            "combined app+address rule must not route the address globally"
        );
        assert!(out
            .diagnostics
            .iter()
            .any(|d| matches!(d, RouteCodegenDiagnostic::AppRuleRoutingProOnly { .. })));
    }

    // ── mode-aware generate_routes (block 16.18.vpn) ──

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    #[test]
    fn mode_a_prefer_primary_emits_secondary_host_routes_no_overlay() {
        let cache = MockFqdnCacheLookup::new();
        let rb = book(
            vec![rule(
                "p",
                true,
                CanonicalAddressMatch::ExactIp(ip(8, 8, 8, 8)),
            )],
            vec![rule(
                "s",
                true,
                CanonicalAddressMatch::ExactIp(ip(1, 1, 1, 1)),
            )],
        );
        let out = generate_routes(
            RouteBehaviorMode::PreferPrimary,
            &rb,
            None,
            &target(),
            &cache,
            &no_apps(),
            &std::collections::HashSet::new(),
        );
        // No /1 overlay in mode A; only the secondary rule's /32 (primary rule
        // is irrelevant — default already rides primary).
        assert_eq!(out.routes.len(), 1);
        assert_eq!(out.routes[0].destination, ip(1, 1, 1, 1));
        assert_eq!(out.routes[0].prefix_length, 32);
        assert_eq!(out.routes[0].interface_index, 7); // secondary ifindex
    }

    #[test]
    fn mode_a_with_primary_adds_counter_overlay_via_primary() {
        let cache = MockFqdnCacheLookup::new();
        let rb = book(
            vec![], // primary rules irrelevant — the /2 counter-overlay covers all non-secondary
            vec![rule(
                "s",
                true,
                CanonicalAddressMatch::ExactIp(ip(1, 1, 1, 1)),
            )], // foreign → secondary
        );
        let primary = SecondaryRouteTarget {
            gateway: ip(192, 168, 1, 1),
            interface_index: 12,
        };
        let out = generate_routes(
            RouteBehaviorMode::PreferPrimary,
            &rb,
            Some(&primary),
            &target(),
            &cache,
            &no_apps(),
            &std::collections::HashSet::new(),
        );
        // Counter-overlay: four /2 via the primary NIC (ifindex 12) — these
        // out-specific a redirect VPN's /1 so non-rule traffic rides primary.
        let co: Vec<_> = out.routes.iter().filter(|r| r.prefix_length == 2).collect();
        assert_eq!(co.len(), 4);
        assert!(co
            .iter()
            .all(|r| r.interface_index == 12 && r.next_hop == ip(192, 168, 1, 1)));
        let dests: BTreeSet<Ipv4Addr> = co.iter().map(|r| r.destination).collect();
        assert_eq!(
            dests,
            BTreeSet::from([
                ip(0, 0, 0, 0),
                ip(64, 0, 0, 0),
                ip(128, 0, 0, 0),
                ip(192, 0, 0, 0)
            ])
        );
        // Foreign /32 stays via the secondary (VPN, ifindex 7) — more specific
        // than the /2, so it wins by longest-prefix.
        let f = out
            .routes
            .iter()
            .find(|r| r.destination == ip(1, 1, 1, 1))
            .expect("secondary /32 route");
        assert_eq!(f.prefix_length, 32);
        assert_eq!(f.interface_index, 7);
        // No /1 overlay in mode A.
        assert!(!out.routes.iter().any(|r| r.prefix_length == 1));
    }

    #[test]
    fn mode_b_owns_overlay_via_secondary_and_pulls_primary_exceptions() {
        let cache = MockFqdnCacheLookup::new();
        let rb = book(
            vec![rule(
                "p",
                true,
                CanonicalAddressMatch::ExactIp(ip(8, 8, 8, 8)),
            )],
            vec![],
        );
        let primary = SecondaryRouteTarget {
            gateway: ip(192, 168, 1, 1),
            interface_index: 12,
        };
        let out = generate_routes(
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
            &rb,
            Some(&primary),
            &target(),
            &cache,
            &no_apps(),
            &std::collections::HashSet::new(),
        );
        // Overlay 0.0.0.0/1 + 128.0.0.0/1 via the secondary (ifindex 7).
        let overlay: Vec<_> = out.routes.iter().filter(|r| r.prefix_length == 1).collect();
        assert_eq!(overlay.len(), 2);
        assert!(overlay.iter().all(|r| r.interface_index == 7));
        assert!(overlay.iter().any(|r| r.destination == ip(0, 0, 0, 0)));
        assert!(overlay.iter().any(|r| r.destination == ip(128, 0, 0, 0)));
        // Exception: primary rule 8.8.8.8/32 via the PRIMARY NIC (ifindex 12).
        let exc = out
            .routes
            .iter()
            .find(|r| r.destination == ip(8, 8, 8, 8))
            .expect("primary exception route");
        assert_eq!(exc.prefix_length, 32);
        assert_eq!(exc.interface_index, 12);
        assert_eq!(exc.next_hop, ip(192, 168, 1, 1));
    }

    #[test]
    fn mode_b_without_primary_target_keeps_overlay_and_diagnoses() {
        let cache = MockFqdnCacheLookup::new();
        let rb = book(
            vec![rule(
                "p",
                true,
                CanonicalAddressMatch::ExactIp(ip(8, 8, 8, 8)),
            )],
            vec![],
        );
        let out = generate_routes(
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &rb,
            None,
            &target(),
            &cache,
            &no_apps(),
            &std::collections::HashSet::new(),
        );
        // Only the overlay survives (no exceptions without a primary target).
        assert_eq!(out.routes.len(), 2);
        assert!(out.routes.iter().all(|r| r.prefix_length == 1));
        assert!(out
            .diagnostics
            .iter()
            .any(|d| matches!(d, RouteCodegenDiagnostic::PrimaryExceptionsUnavailable)));
    }

    #[test]
    fn dns_via_secondary_routes_pin_each_resolver_to_the_secondary() {
        let servers = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
        let routes = dns_via_secondary_routes(&servers, &target());
        assert_eq!(routes.len(), 2);
        for (route, expected) in routes.iter().zip(servers.iter()) {
            assert_eq!(route.destination, *expected);
            // A /32 is what makes the source-bound query socket actually leave
            // over the tunnel; anything wider would not out-specific the
            // default route.
            assert_eq!(route.prefix_length, 32);
            assert_eq!(route.interface_index, target().interface_index);
            assert_eq!(route.next_hop, target().gateway);
            assert!(route.is_ours);
        }
    }

    #[test]
    fn dns_via_secondary_routes_skip_non_routable_servers() {
        let servers = [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED];
        assert!(dns_via_secondary_routes(&servers, &target()).is_empty());
    }
}

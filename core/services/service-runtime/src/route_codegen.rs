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
//! Scope: IPv4 IP/FQDN/domain-suffix/zone routing. IP-subnet/CIDR zones do not
//! exist in the canonical model — `Zone` is always a *domain* suffix.
//! Application rules route by destination, learned from observation: a route
//! entry is never process-scoped (no route table is), so what the table carries
//! is "this destination goes over that link". Precise per-PROCESS routing,
//! where two processes reaching the same address take different links, cannot
//! be expressed this way at all; neither can per-user routing, the system route
//! table being machine-wide. The caller decides whose effective rules drive the
//! global table.

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppPattern, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::{RouteBehaviorMode, RuleAction};
use nrr_platform_api::RouteEntry;

use crate::address_ownership::AppDestinationRefusal;
use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::net_filter::is_non_routable_v4;
use crate::wfp_codegen::SUFFIX_FANOUT_BACKSTOP;

/// Upper bound on routes emitted for a single rule, so a pathological
/// suffix fan-out cannot flood the route table. Matches
/// `wfp_codegen::SUFFIX_FANOUT_BACKSTOP`: a busy zone rule can overflow a
/// smaller cap in normal use, and a host that keeps its WFP permit but loses
/// its `/32` would silently ride the wrong link. A runaway guard, not a
/// product limit.
pub const MAX_ROUTES_PER_RULE: usize = 4096;

/// Prefix length of a host route — the shape every address rule fans out to.
pub const HOST_PREFIX: u8 = 32;

/// The same shape in IPv6.
pub const HOST_PREFIX_V6: u8 = 128;

/// Whether `prefix_length` is a shape THIS codegen emits.
///
/// Startup orphan adoption identifies our leftovers by metric plus shape.
/// Derived from the overlay constants rather than kept as a separate list: a
/// hardcoded list goes stale the moment a mode grows a shape it does not
/// know, leaving a crashed-and-recovered pair unadopted so every packet keeps
/// steering into a tunnel that is no longer there. Pinned by a test that
/// generates every mode and asserts each emitted shape is recognised here.
///
/// The FAMILY is part of the shape. `/32` in IPv6 is a prefix, not a host
/// route, so a family-blind answer adopts a stranger and hands the reconciler
/// a route to delete that was never ours. Only host routes are emitted over
/// IPv6 — the overlay halves and the counter-overlay are IPv4 mechanisms.
#[must_use]
pub fn is_owned_shape(destination: IpAddr, prefix_length: u8) -> bool {
    match destination {
        IpAddr::V4(_) => {
            prefix_length == HOST_PREFIX
                || prefix_length == OVERLAY_LOW.1
                || prefix_length == OVERLAY_HIGH.1
                || COUNTER_OVERLAY.iter().any(|(_, p)| *p == prefix_length)
        }
        IpAddr::V6(_) => prefix_length == HOST_PREFIX_V6,
    }
}

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
/// removing the VPN's own routes — hardware testing showed that removing them
/// makes the client treat it as a fault and reconnect. Secondary `/32` rules
/// stay more specific still → those keep going via the secondary.
pub const COUNTER_OVERLAY: [(Ipv4Addr, u8); 4] = [
    (Ipv4Addr::new(0, 0, 0, 0), 2),   // 0.0.0.0/2
    (Ipv4Addr::new(64, 0, 0, 0), 2),  // 64.0.0.0/2
    (Ipv4Addr::new(128, 0, 0, 0), 2), // 128.0.0.0/2
    (Ipv4Addr::new(192, 0, 0, 0), 2), // 192.0.0.0/2
];

/// The counter-overlay that actually out-specifics THIS tunnel.
///
/// The fixed `/2` set assumes the VPN redirects with a `/1` pair. A Wintun
/// client (swiftvpn over WireGuard) instead covers the internet with a
/// redirect SET — `0.0.0.0/5`, `8.0.0.0/7`, `16.0.0.0/4`, …, `128.0.0.0/2`,
/// `192.0.0.0/9` — and against that the `/2`s lose: same length at a better
/// metric, or shorter outright. Every non-rule connection then rode the
/// tunnel, `.ru` sites included, and a Russian shop that refuses foreign
/// addresses stopped opening.
///
/// So the counter-overlay is derived from the tunnel's own catch-all
/// prefixes: each `P/N` the tunnel installs is answered by its two `/(N+1)`
/// halves via the primary — one bit longer, so longest-prefix picks the
/// primary regardless of metric, and nothing the tunnel installed is
/// touched. A `/1` pair yields exactly the classic four `/2`s; an empty list
/// (the tunnel's catch-alls are not visible, or were stripped) falls back to
/// them as well. Rule `/32`s stay longer than anything here, so they keep
/// riding the tunnel. Deduplicated and sorted for a stable reconcile.
pub fn counter_overlay_for(tunnel_catch_alls: &[(Ipv4Addr, u8)]) -> Vec<(Ipv4Addr, u8)> {
    let mut halves: Vec<(Ipv4Addr, u8)> = tunnel_catch_alls
        .iter()
        .filter(|(_, n)| *n < 31)
        .flat_map(|&(dest, n)| {
            let base = u32::from(dest) & prefix_mask(n);
            let half = 1u32 << (31 - u32::from(n));
            [
                (Ipv4Addr::from(base), n + 1),
                (Ipv4Addr::from(base | half), n + 1),
            ]
        })
        .collect();
    if halves.is_empty() {
        return COUNTER_OVERLAY.to_vec();
    }
    halves.sort_unstable_by_key(|&(d, n)| (u32::from(d), n));
    halves.dedup();
    halves
}

fn prefix_mask(n: u8) -> u32 {
    if n == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(n))
    }
}

/// The on-link and peer routes a tunnel client installs to steer the internet
/// into itself — the set [`counter_overlay_for`] has to out-specific. Wide
/// unicast prefixes on `ifindex` only: host routes are the tunnel's own
/// address, and the multicast block is on every interface.
pub fn tunnel_catch_all_prefixes(routes: &[RouteEntry], ifindex: u32) -> Vec<(Ipv4Addr, u8)> {
    let mut out: Vec<(Ipv4Addr, u8)> = routes
        .iter()
        .filter_map(|r| match r.destination {
            // The tunnel catch-all it feeds is an IPv4 construction
            // (`0.0.0.0/1` + `128.0.0.0/1`), so only v4 rows inform it.
            IpAddr::V4(d) => Some((r, d)),
            IpAddr::V6(_) => None,
        })
        .filter(|(r, d)| {
            r.interface_index == ifindex
                && !r.is_ours
                && r.prefix_length <= TUNNEL_CATCH_ALL_MAX_PREFIX
                && d.octets()[0] < 224
        })
        .map(|(r, d)| (d, r.prefix_length))
        .collect();
    out.sort_unstable_by_key(|&(d, n)| (u32::from(d), n));
    out.dedup();
    out
}

/// Longest prefix that still reads as "steer a chunk of the internet" rather
/// than "reach one network": swiftvpn's set bottoms out at `/9`, a corporate
/// split tunnel names `/16`s and narrower, which are its business, not ours.
const TUNNEL_CATCH_ALL_MAX_PREFIX: u8 = 12;

/// Where matched traffic is sent: an adapter's gateway + interface index,
/// resolved by the caller from the active route binding. Used for the
/// secondary (VPN) target and — in mode B — for the primary NIC too, when
/// pulling exception routes back off the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondaryRouteTarget {
    pub gateway: Ipv4Addr,
    /// The IPv6 next hop out of the same interface, when it has one.
    ///
    /// `None` means this link carries no IPv6 forwarding path, and it is what
    /// keeps a `/128` out of the table: a host route through a link that
    /// cannot deliver the family is a black hole, which the user reads as a
    /// hung site rather than as protection. `Some(::)` is the on-link form a
    /// peerless tunnel uses, exactly as `0.0.0.0` is on the IPv4 side.
    pub gateway_v6: Option<Ipv6Addr>,
    pub interface_index: u32,
}

/// Non-fatal codegen observations surfaced to diagnostics/health so the
/// GUI can explain "no routes yet — DNS warm-up pending" or "this rule
/// cannot be routed".
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
    AppRuleAddressAndAppNotRouted { rule_id: String },
    /// An application rule has no observed destinations yet (cold start, or
    /// the app has not connected since the service came up), so it produced no
    /// route. Self-clearing: the first observed connection installs one.
    AppRuleUnobserved { rule_id: String, app: String },
    /// An application rule's observed destination is an address the MAIN
    /// link's own rules claim, so it was not routed to the additional link. A
    /// route is machine-wide, so pinning it would have taken the address away
    /// from every other process — including the browser the user wrote that
    /// main-link rule for. Address rules outrank application rules, and this is
    /// where that order is kept.
    AppRuleDestinationClaimedByMainLink {
        rule_id: String,
        app: String,
        ip: Ipv4Addr,
    },
    /// An application rule's observed destination is already in use by a
    /// process no application rule names, so it was not routed to the
    /// additional link. A host route moves every process that talks to the
    /// address; claiming one somebody else is using would take their traffic
    /// with it. Two application rules sharing a destination is NOT this case —
    /// a route serves them both the same way.
    AppRuleDestinationUsedByOtherProcess {
        rule_id: String,
        app: String,
        ip: Ipv4Addr,
    },
    /// An ADDRESS rule on the additional link named an address the MAIN link's
    /// rules also name, so it was not pinned into the tunnel. Rules name hosts,
    /// routes move addresses, and one address carries many hosts: pinning it
    /// would take the main link's hosts along, and they would then work only
    /// while the tunnel is up. Aggregated per rule — `ip` is one example and
    /// `count` is how many that rule lost, because a suffix rule can hold back
    /// hundreds and a line each would bury the log.
    AddressClaimedByMainLink {
        rule_id: String,
        ip: IpAddr,
        count: usize,
    },
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
    // Addresses the OTHER link's own rules claim. Subtracted from the
    // app-observation fan-out only — see the app branch for why.
    ownership: &crate::address_ownership::AddressOwnership,
    // Which link these rules route to, so the arbiter can tell "the other
    // link's address rule names this" from "our own does".
    link: crate::address_ownership::Link,
) -> RouteCodegenOutput {
    let mut out = RouteCodegenOutput::default();
    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    // Ownership and the outside-use census are asked as one question, through
    // the one gate every mechanism shares.
    let gate = crate::address_ownership::AppDestinationGate::for_rule_set(
        ownership,
        app_observations,
        secondary_rules,
    );

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
                .push(RouteCodegenDiagnostic::AppRuleAddressAndAppNotRouted {
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
            let destinations = gate.admit(pattern, link);
            if destinations.admitted.is_empty() && destinations.refused.is_empty() {
                out.diagnostics
                    .push(RouteCodegenDiagnostic::AppRuleUnobserved {
                        rule_id: rule.id.as_str().to_string(),
                        app: pattern.to_string(),
                    });
                continue;
            }
            for (ip, reason) in destinations.refused {
                // Declined by the shared-address policy is reported by that
                // policy, not here.
                if denied.contains(&ip) {
                    continue;
                }
                out.diagnostics.push(match reason {
                    // The other link's rules already claim this address, by
                    // name or by literal. An app rule learns its destinations
                    // by watching the app, so anything the app happens to touch
                    // would otherwise be pinned — machine-wide — over an
                    // explicit rule the user wrote for that very host. Address
                    // beats application in the evaluation order, and a route
                    // cannot be process-scoped, so the only way to honour the
                    // order is to not emit it.
                    AppDestinationRefusal::ClaimedByAddressRule => {
                        RouteCodegenDiagnostic::AppRuleDestinationClaimedByMainLink {
                            rule_id: rule.id.as_str().to_string(),
                            app: pattern.to_string(),
                            ip,
                        }
                    }
                    // Somebody the rule set never named is already using this
                    // address. Pinning it would move their traffic too — the
                    // browser reaching the same site is the case that matters —
                    // and the rule is not worth that.
                    AppDestinationRefusal::UsedByOtherProcess => {
                        RouteCodegenDiagnostic::AppRuleDestinationUsedByOtherProcess {
                            rule_id: rule.id.as_str().to_string(),
                            app: pattern.to_string(),
                            ip,
                        }
                    }
                });
            }
            let mut per_rule = 0usize;
            for ip in destinations.admitted {
                // Shared with a direct destination and declined by policy —
                // dropped from the route exactly as it is from the filter set.
                if denied.contains(&ip) {
                    continue;
                }
                // App observations are IPv4: nothing records a v6 destination
                // for a process yet.
                if !push_route(IpAddr::V4(ip), target, &mut seen, &mut out, &mut per_rule) {
                    break;
                }
            }
            continue;
        }
        let mut per_rule = 0usize;
        // An address this rule may not steer — the other link's address rules
        // name it too. Held back rather than pinned, reported once per rule.
        let mut held: Option<(IpAddr, usize)> = None;
        let steerable = |ip: IpAddr| ownership.address_rule_may_steer(ip, link);
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                let ip = *ip;
                if steerable(ip) {
                    push_route(ip, target, &mut seen, &mut out, &mut per_rule);
                } else {
                    note_held(&mut held, ip);
                }
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                if cache.ips_for_hostname(host).is_empty() {
                    out.diagnostics
                        .push(RouteCodegenDiagnostic::HostnameUnresolved {
                            rule_id: rule.id.as_str().to_string(),
                            hostname: host.clone(),
                        });
                    continue;
                }
                // Both families, capped per family — the same view of the host
                // the filter codegen pins. The family GATE is not asked here:
                // whether a route may be installed is a question about the
                // link, and `push_route` answers it from the link's own next
                // hop. Asking the guard as well would be two answers to one
                // question, and they could disagree.
                for ip in crate::enforcement_planner::capped_for_host(
                    cache,
                    host,
                    crate::enforcement_planner::FamilyScope::Both,
                ) {
                    if !steerable(ip) {
                        note_held(&mut held, ip);
                        continue;
                    }
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
                    &steerable,
                    &mut held,
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
                    &steerable,
                    &mut held,
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
        if let Some((ip, count)) = held {
            out.diagnostics
                .push(RouteCodegenDiagnostic::AddressClaimedByMainLink {
                    rule_id: rule.id.as_str().to_string(),
                    ip,
                    count,
                });
        }
    }

    out
}

/// Record one held-back address: the first is kept as the example, all of them
/// count.
fn note_held(held: &mut Option<(IpAddr, usize)>, ip: IpAddr) {
    match held {
        Some((_, count)) => *count += 1,
        None => *held = Some((ip, 1)),
    }
}

/// Mode-aware route generation. The desired route set
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
// Eight positional arguments, one over the lint's taste. Grouping them into a
// struct would be a second shape of the same call for the ten call sites to
// keep in step, and the last one is what this function is FOR: the arbitration
// order every mechanism must share.
#[allow(clippy::too_many_arguments)]
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
    // Where an exact-address rule sits against a zone rule, from the
    // principal's `zone_priority_over_ip`. The two can only contest the same
    // address in the ownership arbiter, so this is the whole of its reach here.
    order: crate::address_ownership::ZoneVsIpOrder,
    // The tunnel's own catch-all prefixes (see [`tunnel_catch_all_prefixes`]);
    // mode A's counter-overlay is shaped to out-specific exactly these.
    tunnel_catch_alls: &[(Ipv4Addr, u8)],
) -> RouteCodegenOutput {
    match mode {
        RouteBehaviorMode::PreferPrimary => {
            // Secondary-bound rules → /32 via the secondary (VPN), minus any
            // shared IP the policy declined (fed via a filtered cache view).
            let secondary_cache =
                crate::secondary_ip_policy::DenylistFilteredCache::new(cache, denied);
            // Read from the UNFILTERED cache: the denylist view exists to
            // trim what goes to the tunnel, and using it here would understate
            // what the main link claims.
            let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
                rule_book, cache, order,
            );
            let mut out = generate_secondary_routes(
                &rule_book.secondary,
                secondary_target,
                &secondary_cache,
                app_observations,
                denied,
                &ownership,
                crate::address_ownership::Link::Additional,
            );
            // Mode-A selectivity over a redirect VPN: a /2 counter-overlay via
            // primary out-specifics the VPN's /1, so all non-rule traffic falls
            // back to primary WITHOUT removing the VPN's own routes (additive →
            // the tunnel is not disturbed). Secondary /32 rules stay more
            // specific → still via the secondary. Needs a usable primary target.
            match primary_target {
                Some(pt) => {
                    for half in counter_overlay_for(tunnel_catch_alls) {
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
                    // In the always-on modes the tunnel carries everything, so
                    // these are the main link's own carve-outs. The arbiter is
                    // still consulted: an app rule here must not take an address
                    // the ADDITIONAL link's rules name, or a host the user
                    // deliberately tunnels would follow a program out onto the
                    // open link.
                    let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
                        rule_book, cache, order,
                    );
                    let exceptions = generate_secondary_routes(
                        &rule_book.primary,
                        pt,
                        cache,
                        app_observations,
                        &HashSet::new(),
                        &ownership,
                        crate::address_ownership::Link::Main,
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
            destination: IpAddr::V4(ip),
            prefix_length: 32,
            next_hop: IpAddr::V4(target.gateway),
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
        destination: IpAddr::V4(dest),
        prefix_length: prefix,
        next_hop: IpAddr::V4(target.gateway),
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
    ip: IpAddr,
    target: &SecondaryRouteTarget,
    seen: &mut BTreeSet<IpAddr>,
    out: &mut RouteCodegenOutput,
    per_rule: &mut usize,
) -> bool {
    if *per_rule >= MAX_ROUTES_PER_RULE {
        return false;
    }
    // Never route a non-routable destination. An ad-blocking hosts file
    // pins domains to loopback/unspecified (e.g. `app.example 127.0.0.1`);
    // routing that out the secondary (VPN) link is nonsensical — loopback
    // never leaves the box. Skip WITHOUT signalling a cap hit so the caller
    // keeps scanning this rule's remaining (routable) IPs.
    if is_non_routable(ip) {
        tracing::debug!(
            target: "nrr::route-codegen",
            ip = %ip,
            "destination pinned to loopback/unspecified (hosts file?) — not routed",
        );
        return true;
    }
    // The next hop this link offers for the address's own family. `None` means
    // the link has no way out for it, and a host route through such a link is a
    // black hole: the user reads a hang, not protection. Not a cap hit — the
    // rule's other addresses may well be routable.
    let Some(next_hop) = next_hop_for(ip, target) else {
        return true;
    };
    // Already routed by an earlier rule → not a new route, but not a cap
    // hit either: keep scanning this rule.
    if !seen.insert(ip) {
        return true;
    }
    out.routes.push(RouteEntry {
        destination: ip,
        prefix_length: host_prefix_for(ip),
        next_hop,
        interface_index: target.interface_index,
        metric: SECONDARY_ROUTE_METRIC,
        is_ours: true,
        table: nrr_platform_api::RouteTableRef::Main,
    });
    *per_rule += 1;
    true
}

/// The next hop `target` offers for `ip`'s family, if it has one.
fn next_hop_for(ip: IpAddr, target: &SecondaryRouteTarget) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(_) => Some(IpAddr::V4(target.gateway)),
        IpAddr::V6(_) => target.gateway_v6.map(IpAddr::V6),
    }
}

/// The single-host prefix for an address's family.
fn host_prefix_for(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// `true` for a destination no route should ever be installed for, in either
/// family: loopback, the unspecified address, and (v6) the link-local and
/// multicast scopes, which never leave the link they are on.
fn is_non_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_routable_v4(&v4),
        IpAddr::V6(v6) => {
            let head = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (head & 0xffc0) == 0xfe80
                || (head & 0xff00) == 0xff00
        }
    }
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
// The one definition of "this address is spoken for" lives in
// `address_ownership`: the route side, the filter side and the kill-switch all
// read it from there, because two definitions of one fact is exactly how the
// halves came to disagree.
pub use crate::address_ownership::address_rule_ips;

#[allow(clippy::too_many_arguments)]
fn fanout_suffix(
    suffix: &str,
    include_apex: bool,
    target: &SecondaryRouteTarget,
    cache: &dyn FqdnCacheLookup,
    steerable: &dyn Fn(IpAddr) -> bool,
    held: &mut Option<(IpAddr, usize)>,
    seen: &mut BTreeSet<IpAddr>,
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
        for ip in crate::enforcement_planner::capped_for_host(
            cache,
            &sub,
            crate::enforcement_planner::FamilyScope::Both,
        ) {
            if !steerable(ip) {
                note_held(held, ip);
                continue;
            }
            if !push_route(ip, target, seen, out, per_rule) {
                return had_subhosts;
            }
        }
    }
    had_subhosts
}

#[cfg(test)]
mod tests;

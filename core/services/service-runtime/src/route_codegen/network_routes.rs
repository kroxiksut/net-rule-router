//! Network rules as routes.
//!
//! A host rule is one host route. A network rule is one route per block, and
//! the OS picks routes by longest prefix, so each block has to out-specific
//! whatever would carry its addresses over the other link — the tunnel's own
//! routes above all — while everything narrower than the rule keeps beating
//! it. The work is per block and per competing route; no address inside a
//! network is ever walked.
//!
//! The Windows codegen and the neutral planner both lower [`plan_network_routes`],
//! so the two cannot disagree about a network.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_domain::canonical::{CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::ip_network_policy::wider_than_rule_allows;
use nrr_domain::rule_shape::{rule_verdict, RuleShapeSupport};
use nrr_domain::{RouteBehaviorMode, RuleAction};
use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::{RouteEntry, RouteTableRef};
use nrr_shared::ip_block::IpBlock;

use super::{
    counter_overlay_for, is_owned_route, RouteCodegenDiagnostic, MAX_ROUTES_PER_RULE, OVERLAY_HIGH,
    OVERLAY_LOW,
};
use crate::address_ownership::{AddressOwnership, Link};

/// What the machine says about the links a network route must respect.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkRouteFacts {
    /// Routes the additional link's own client installed. A main-link network
    /// out-specifics each one inside it, so the tunnel keeps what lies outside.
    pub tunnel_routes: Vec<IpBlock>,
    /// Networks an interface of this machine is attached to, the tunnel's own
    /// interior included. A rule never takes one away from its interface.
    pub local_networks: Vec<IpBlock>,
    /// The tunnel's server endpoints: routed into the tunnel, they seal its
    /// own reconnect.
    pub tunnel_servers: Vec<IpAddr>,
}

impl NetworkRouteFacts {
    /// Only the tunnel's catch-alls are known — all a caller without a wider
    /// reading of the machine can say.
    #[must_use]
    pub fn from_catch_alls(catch_alls: &[(Ipv4Addr, u8)]) -> Self {
        Self {
            tunnel_routes: catch_alls
                .iter()
                .filter_map(|&(net, prefix)| IpBlock::new(IpAddr::V4(net), prefix))
                .collect(),
            ..Self::default()
        }
    }

    /// Read from one enumeration of the route table and the adapters.
    ///
    /// `tunnel` is the additional link's interface index; `servers` the tunnel
    /// endpoints the caller knows, live or remembered.
    #[must_use]
    pub fn read(
        routes: &[RouteEntry],
        adapters: &[AdapterInfo],
        tunnel: Option<u32>,
        servers: Vec<IpAddr>,
    ) -> Self {
        let local_networks = attached_networks(routes, adapters);
        let mut tunnel_routes: Vec<IpBlock> = routes
            .iter()
            .filter(|r| Some(r.interface_index) == tunnel && is_foreign_main(r))
            .filter_map(|r| IpBlock::new(r.destination, r.prefix_length))
            .filter(|b| {
                b.prefix_len() > 0
                    && !b.is_single_address()
                    && is_unicast(*b)
                    && !local_networks.contains(b)
            })
            .collect();
        tunnel_routes.sort_unstable();
        tunnel_routes.dedup();
        let mut tunnel_servers = servers;
        tunnel_servers.sort_unstable();
        tunnel_servers.dedup();
        Self {
            tunnel_routes,
            local_networks,
            tunnel_servers,
        }
    }
}

/// A route the system or another program installed in the main table.
fn is_foreign_main(route: &RouteEntry) -> bool {
    route.table == RouteTableRef::Main && !route.is_ours && !is_owned_route(route)
}

/// For each own address of each adapter, the narrowest on-link route holding
/// it — the segment the address sits on.
///
/// Routes wider than a rule may be are not segments: a tunnel that steers the
/// internet on-link (`0.0.0.0/1` and the like) holds its own address too, and
/// taking that for a LAN would refuse every network inside the internet.
fn attached_networks(routes: &[RouteEntry], adapters: &[AdapterInfo]) -> Vec<IpBlock> {
    let mut out = BTreeSet::new();
    for adapter in adapters {
        let on_link: Vec<IpBlock> = routes
            .iter()
            .filter(|r| {
                r.interface_index == adapter.index
                    && r.next_hop.is_unspecified()
                    && is_foreign_main(r)
            })
            .filter_map(|r| IpBlock::new(r.destination, r.prefix_length))
            .filter(|b| !wider_than_rule_allows(*b) && !b.is_single_address())
            .collect();
        let own = adapter
            .ipv4_addresses
            .iter()
            .map(|a| IpAddr::V4(*a))
            .chain(adapter.ipv6_addresses.iter().map(|a| IpAddr::V6(*a)))
            .filter(|a| is_segment_address(*a));
        for address in own {
            if let Some(segment) = on_link
                .iter()
                .filter(|b| b.contains(address))
                .max_by_key(|b| b.prefix_len())
            {
                out.insert(*segment);
            }
        }
    }
    out.into_iter().collect()
}

/// An address that numbers a segment. IPv6 link-local sits on every link and
/// is no rule's business; loopback and unspecified are not on a link at all.
fn is_segment_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => !a.is_unspecified() && !a.is_loopback(),
        IpAddr::V6(a) => {
            !a.is_unspecified() && !a.is_loopback() && (a.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Not a multicast or link-local scope — the routes every interface carries.
fn is_unicast(block: IpBlock) -> bool {
    const SCOPES: [&str; 4] = ["224.0.0.0/4", "169.254.0.0/16", "ff00::/8", "fe80::/10"];
    !SCOPES
        .iter()
        .filter_map(|s| IpBlock::parse(s))
        .any(|scope| scope.covers(block))
}

/// Why a network cannot be routed as written on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkLinkConflict {
    /// The network holds the tunnel's server.
    CoversTunnelServer(IpAddr),
    /// The network shares addresses with a network this machine is attached to.
    OverlapsLocalNetwork(IpBlock),
}

/// The submission check: `None` when `network` can be routed without taking
/// the tunnel's server or an attached network off its own link.
///
/// Link-agnostic on purpose: the rule may move between links later, and the
/// enforcement side only routes around these facts, it never refuses.
#[must_use]
pub fn network_conflicts_with_links(
    network: IpBlock,
    facts: &NetworkRouteFacts,
) -> Option<NetworkLinkConflict> {
    if let Some(server) = facts.tunnel_servers.iter().find(|s| network.contains(**s)) {
        return Some(NetworkLinkConflict::CoversTunnelServer(*server));
    }
    facts
        .local_networks
        .iter()
        .find(|local| local.overlaps(network))
        .map(|local| NetworkLinkConflict::OverlapsLocalNetwork(*local))
}

/// Whether `book` has a network rule to route under `support` — the gate that
/// keeps the machine reading off the recompute when nothing would use it.
#[must_use]
pub fn names_networks(book: &CanonicalRuleBook, support: RuleShapeSupport) -> bool {
    [&book.primary, &book.secondary]
        .into_iter()
        .any(|rules| network_rules(rules, support).next().is_some())
}

/// Enabled route rules naming networks, each with its blocks.
fn network_rules(
    rules: &CanonicalRuleSet,
    support: RuleShapeSupport,
) -> impl Iterator<Item = (&nrr_domain::canonical::CanonicalRule, &[IpBlock])> {
    rules.rules().iter().filter_map(move |rule| {
        // A Block drops, it does not steer; an app-scoped network is a shape no
        // route can carry (a route is machine-wide).
        if !rule.enabled
            || matches!(rule.action, RuleAction::Block)
            || rule.app_match.is_some()
            || !rule_verdict(rule, support).is_supported()
        {
            return None;
        }
        Some((rule, rule.address_match.as_ref()?.ip_blocks()?))
    })
}

/// The network half of a route plan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NetworkRoutePlan {
    /// One route per piece, in rule order, never repeated on a link.
    pub networks: Vec<(Link, IpBlock)>,
    /// Host routes keeping a narrower rule's address on its own link where the
    /// other link's network would otherwise carry it — the hosts of the link
    /// whose host rules this mode does not route at all.
    pub hosts: Vec<(Link, IpAddr)>,
    pub diagnostics: Vec<RouteCodegenDiagnostic>,
}

/// Plan the routes `rule_book`'s networks need under `mode`.
///
/// Every network is routed over its own link in every mode: a mode's fallback
/// (the default route, an overlay) is wider than any rule, so a network
/// narrower than a network of the other link is lost without its own route.
/// `has_primary` says whether the main link can be routed to at all.
#[must_use]
pub fn plan_network_routes(
    mode: RouteBehaviorMode,
    rule_book: &CanonicalRuleBook,
    has_primary: bool,
    ownership: &AddressOwnership,
    facts: &NetworkRouteFacts,
    tunnel_catch_alls: &[(Ipv4Addr, u8)],
    support: RuleShapeSupport,
) -> NetworkRoutePlan {
    let mut plan = NetworkRoutePlan::default();
    let mode_b = !matches!(mode, RouteBehaviorMode::PreferPrimary);
    // What carries a link's network over the OTHER link unless out-specified:
    // the tunnel's routes and our mode-B overlay for the main link, our mode-A
    // counter-overlay for the additional one.
    let v4_blocks = |set: &[(Ipv4Addr, u8)]| -> Vec<IpBlock> {
        set.iter()
            .filter_map(|&(net, prefix)| IpBlock::new(IpAddr::V4(net), prefix))
            .collect()
    };
    let mut main_competitors = facts.tunnel_routes.clone();
    let mut additional_competitors = Vec::new();
    if mode_b {
        main_competitors.extend(v4_blocks(&[OVERLAY_LOW, OVERLAY_HIGH]));
    } else if has_primary {
        additional_competitors = v4_blocks(&counter_overlay_for(tunnel_catch_alls));
    }

    let mut emitted: BTreeSet<(bool, IpBlock)> = BTreeSet::new();
    for (rules, link, competitors) in [
        (&rule_book.primary, Link::Main, &main_competitors),
        (
            &rule_book.secondary,
            Link::Additional,
            &additional_competitors,
        ),
    ] {
        if link == Link::Main && !has_primary {
            continue;
        }
        for (rule, blocks) in network_rules(rules, support) {
            let rule_id = rule.id.as_str();
            let mut pieces: Vec<IpBlock> = Vec::new();
            for &block in blocks {
                pieces.extend(pieces_for(
                    rule_id,
                    block,
                    link,
                    competitors,
                    ownership,
                    facts,
                    &mut plan.diagnostics,
                ));
            }
            if pieces.len() > MAX_ROUTES_PER_RULE {
                // Widest first: what is cut is the deepest split, which costs a
                // corner of a tunnel route rather than the network itself.
                pieces.sort_unstable_by_key(|p| (p.prefix_len(), *p));
                pieces.truncate(MAX_ROUTES_PER_RULE);
                plan.diagnostics
                    .push(RouteCodegenDiagnostic::NetworkRoutesCapped {
                        rule_id: rule_id.to_string(),
                        cap: MAX_ROUTES_PER_RULE,
                    });
            }
            for piece in pieces {
                if emitted.insert((link == Link::Main, piece)) {
                    plan.networks.push((link, piece));
                }
            }
        }
    }

    // The link whose host rules this mode leaves to a wide fallback: mode A
    // routes no main-link host, mode B no additional-link host.
    let carve_link = if mode_b { Link::Additional } else { Link::Main };
    if carve_link == Link::Main && !has_primary {
        return plan;
    }
    let mut hosts = BTreeSet::new();
    for &(link, piece) in &plan.networks {
        if link == carve_link {
            continue;
        }
        for &ip in ownership.explicit_inside(piece) {
            if ownership.owner_of(ip) == Some(carve_link)
                && narrowest_holder(&plan.networks, ip) != Some(carve_link)
            {
                hosts.insert(ip);
            }
        }
    }
    plan.hosts = hosts.into_iter().map(|ip| (carve_link, ip)).collect();
    plan
}

/// The link of the narrowest planned network holding `ip`.
fn narrowest_holder(networks: &[(Link, IpBlock)], ip: IpAddr) -> Option<Link> {
    networks
        .iter()
        .filter(|(_, b)| b.contains(ip))
        .max_by_key(|(_, b)| b.prefix_len())
        .map(|(link, _)| *link)
}

/// The routes one block of a rule on `link` becomes.
fn pieces_for(
    rule_id: &str,
    block: IpBlock,
    link: Link,
    competitors: &[IpBlock],
    ownership: &AddressOwnership,
    facts: &NetworkRouteFacts,
    diagnostics: &mut Vec<RouteCodegenDiagnostic>,
) -> Vec<IpBlock> {
    // The same network on both links stays on the main one, the tie-break
    // every other mechanism applies.
    if link == Link::Additional && ownership.networks(Link::Main).any(|n| n == block) {
        diagnostics.push(RouteCodegenDiagnostic::NetworkClaimedByMainLink {
            rule_id: rule_id.to_string(),
            network: block,
        });
        return Vec::new();
    }
    let mut pieces = split_against(block, competitors);
    if link == Link::Additional {
        for &server in &facts.tunnel_servers {
            let Some(hole) = IpBlock::new(server, if server.is_ipv4() { 32 } else { 128 }) else {
                continue;
            };
            if !block.covers(hole) {
                continue;
            }
            pieces = pieces.into_iter().flat_map(|p| without(p, hole)).collect();
            diagnostics.push(RouteCodegenDiagnostic::NetworkRoutedAroundTunnelServer {
                rule_id: rule_id.to_string(),
                network: block,
                server,
            });
        }
    }
    // A piece inside an attached network would take that segment off its
    // interface; one around it loses to the segment's own longer route anyway.
    let mut yielded: Option<IpBlock> = None;
    pieces.retain(
        |p| match facts.local_networks.iter().find(|l| l.covers(*p)) {
            Some(local) => {
                yielded.get_or_insert(*local);
                false
            }
            None => true,
        },
    );
    if let Some(local) = yielded {
        diagnostics.push(RouteCodegenDiagnostic::NetworkYieldsToLocalNetwork {
            rule_id: rule_id.to_string(),
            network: block,
            local,
        });
    }
    // A narrower network of the other link wins inside itself; a piece of ours
    // as narrow as it would tie.
    let narrower: Vec<IpBlock> = ownership
        .networks_inside(block)
        .filter(|(_, winner)| *winner != link)
        .map(|(net, _)| net)
        .collect();
    pieces.retain(|p| !narrower.iter().any(|n| n.covers(*p)));
    pieces
}

/// `block` plus the pieces that out-specific every competitor inside it.
///
/// A competitor inside the block is answered by its two halves, one bit longer,
/// so longest-prefix match picks ours whatever the metrics; outside every
/// competitor the block itself is the longest route. A competitor equal to
/// the block replaces it with its halves; a host competitor cannot be
/// out-specified and keeps its address. A competitor wider than the block
/// needs nothing.
#[must_use]
pub fn split_against(block: IpBlock, competitors: &[IpBlock]) -> Vec<IpBlock> {
    let mut out = BTreeSet::new();
    let mut whole = true;
    for &competitor in competitors {
        if !block.covers(competitor) {
            continue;
        }
        if competitor == block {
            whole = false;
        }
        if let Some([low, high]) = halves(competitor) {
            out.insert(low);
            out.insert(high);
        }
    }
    if whole {
        out.insert(block);
    }
    out.into_iter().collect()
}

/// `block` without `hole`: the siblings along the path down to it.
#[must_use]
pub fn without(block: IpBlock, hole: IpBlock) -> Vec<IpBlock> {
    if !block.overlaps(hole) {
        return vec![block];
    }
    if hole.covers(block) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = block;
    while current != hole {
        let Some([low, high]) = halves(current) else {
            break;
        };
        if low.covers(hole) {
            out.push(high);
            current = low;
        } else {
            out.push(low);
            current = high;
        }
    }
    out
}

/// The two blocks one bit longer than `block`; `None` for a single address.
fn halves(block: IpBlock) -> Option<[IpBlock; 2]> {
    if block.is_single_address() {
        return None;
    }
    let len = block.prefix_len() + 1;
    let bit = 1u128 << (block.max_prefix_len() - len);
    let high = with_bits(block.network(), bits(block.network()) | bit);
    Some([
        IpBlock::new(block.network(), len)?,
        IpBlock::new(high, len)?,
    ])
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// `value` as an address of `like`'s family; a v4 value always fits in 32 bits.
fn with_bits(like: IpAddr, value: u128) -> IpAddr {
    match like {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::try_from(value).unwrap_or(u32::MAX))),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

#[cfg(test)]
mod tests;

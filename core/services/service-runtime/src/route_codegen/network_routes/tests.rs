use std::collections::HashSet;

use super::*;
use crate::address_ownership::ZoneVsIpOrder;
use crate::app_observation_lookup::MockAppObservationLookup;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use crate::route_codegen::{
    generate_routes, generate_routes_with, is_overlay_route, tunnel_catch_all_prefixes,
    SecondaryRouteTarget, NETWORK_ROUTE_METRIC,
};
use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
use nrr_domain::RuleId;
use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
use nrr_shared::ip_block::IpRange;

const NETWORKS: RuleShapeSupport = RuleShapeSupport {
    network_destination: true,
    ..RuleShapeSupport::NONE
};

fn net(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("network literal")
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("address literal")
}

fn rule(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn subnet(id: &str, text: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::Subnet(net(text)))
}

fn exact(id: &str, text: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::ExactIp(addr(text)))
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

fn ownership(book: &CanonicalRuleBook) -> AddressOwnership {
    AddressOwnership::resolve_with_support(
        book,
        &MockFqdnCacheLookup::new(),
        ZoneVsIpOrder::default(),
        NETWORKS,
    )
}

fn plan(
    mode: RouteBehaviorMode,
    book: &CanonicalRuleBook,
    facts: &NetworkRouteFacts,
    catch_alls: &[(Ipv4Addr, u8)],
) -> NetworkRoutePlan {
    plan_network_routes(
        mode,
        book,
        true,
        &ownership(book),
        facts,
        catch_alls,
        NETWORKS,
    )
}

fn tunnel_facts(routes: &[&str]) -> NetworkRouteFacts {
    NetworkRouteFacts {
        tunnel_routes: routes.iter().map(|r| net(r)).collect(),
        ..NetworkRouteFacts::default()
    }
}

fn on(link: Link, plan: &NetworkRoutePlan) -> Vec<IpBlock> {
    plan.networks
        .iter()
        .filter(|(l, _)| *l == link)
        .map(|(_, b)| *b)
        .collect()
}

/// The route the OS picks for `ip`: longest prefix; `None` on a tie between
/// different owners, which is exactly what splitting must never leave.
fn pick<'a>(table: &'a [(IpBlock, &'a str)], ip: IpAddr) -> Option<&'a str> {
    let best = table
        .iter()
        .filter(|(b, _)| b.contains(ip))
        .map(|(b, _)| b.prefix_len())
        .max()?;
    let owners: HashSet<&str> = table
        .iter()
        .filter(|(b, _)| b.contains(ip) && b.prefix_len() == best)
        .map(|(_, o)| *o)
        .collect();
    (owners.len() == 1).then(|| owners.into_iter().next().unwrap_or_default())
}

/// Addresses spread over `block`, its edges and every competitor's edges.
fn samples(block: IpBlock, competitors: &[IpBlock]) -> Vec<IpAddr> {
    let mut out = vec![block.network(), block.last()];
    for c in competitors.iter().filter(|c| block.covers(**c)) {
        out.push(c.network());
        out.push(c.last());
        if let Some([low, high]) = halves(*c) {
            out.push(low.last());
            out.push(high.network());
        }
    }
    let step = 1u128 << (block.max_prefix_len() - block.prefix_len()).saturating_sub(6);
    for i in 0..64u128 {
        out.push(with_bits(block.network(), bits(block.network()) + i * step));
    }
    out
}

// ── Splitting ─────────────────────────────────────────────────────────────

/// The owner's example: corporate `10.0.0.0/8` on the main link against the
/// tunnel's own `10.88.0.0/13`.
#[test]
fn a_wide_rule_out_specifics_a_narrower_tunnel_route_with_three_routes() {
    let pieces = split_against(net("10.0.0.0/8"), &[net("10.88.0.0/13")]);
    assert_eq!(
        pieces,
        vec![net("10.0.0.0/8"), net("10.88.0.0/14"), net("10.92.0.0/14")]
    );
}

#[test]
fn every_address_of_the_rule_is_won_by_the_rule_whatever_the_tunnel_nests() {
    let rule = net("10.0.0.0/8");
    let tunnel = [
        net("0.0.0.0/1"),
        net("10.0.0.0/8"),
        net("10.88.0.0/13"),
        net("10.88.0.0/14"),
        net("10.90.1.0/24"),
        net("10.200.0.0/31"),
        net("172.16.0.0/12"),
    ];
    let mut table: Vec<(IpBlock, &str)> = tunnel.iter().map(|b| (*b, "tunnel")).collect();
    table.extend(
        split_against(rule, &tunnel)
            .into_iter()
            .map(|b| (b, "rule")),
    );
    for ip in samples(rule, &tunnel) {
        assert_eq!(pick(&table, ip), Some("rule"), "{ip} must ride the rule");
    }
    // Outside the rule the tunnel keeps what it had.
    assert_eq!(pick(&table, addr("172.16.1.1")), Some("tunnel"));
    assert_eq!(pick(&table, addr("11.0.0.1")), Some("tunnel"));
}

#[test]
fn a_tunnel_route_wider_than_the_rule_needs_nothing() {
    assert_eq!(
        split_against(net("10.1.0.0/16"), &[net("10.0.0.0/8"), net("0.0.0.0/1")]),
        vec![net("10.1.0.0/16")]
    );
}

#[test]
fn a_tunnel_route_equal_to_the_rule_is_answered_by_its_halves_alone() {
    assert_eq!(
        split_against(net("10.88.0.0/13"), &[net("10.88.0.0/13")]),
        vec![net("10.88.0.0/14"), net("10.92.0.0/14")]
    );
}

/// A host route cannot be out-specified; it keeps its one address.
#[test]
fn a_tunnel_host_route_inside_the_rule_keeps_its_address() {
    let rule = net("10.0.0.0/8");
    let host = net("10.1.2.3/32");
    assert_eq!(split_against(rule, &[host]), vec![rule]);
}

#[test]
fn splitting_works_on_ipv6_too() {
    let pieces = split_against(net("2001:db8::/32"), &[net("2001:db8:8000::/33")]);
    assert_eq!(
        pieces,
        vec![
            net("2001:db8::/32"),
            net("2001:db8:8000::/34"),
            net("2001:db8:c000::/34")
        ]
    );
}

/// Speed: a tunnel pushing fifty `/16`s into a corporate `/8` costs one route
/// per pushed route and a half, never per address.
#[test]
fn a_slash_8_against_fifty_pushed_routes_is_a_hundred_and_one_routes() {
    let tunnel: Vec<IpBlock> = (0..50u8)
        .map(|i| IpBlock::new(IpAddr::V4(Ipv4Addr::new(10, i, 0, 0)), 16).expect("block"))
        .collect();
    assert_eq!(split_against(net("10.0.0.0/8"), &tunnel).len(), 101);
}

// ── Cutting out ───────────────────────────────────────────────────────────

#[test]
fn without_a_host_leaves_the_rest_and_never_the_host() {
    let block = net("10.0.0.0/8");
    let hole = net("10.1.2.3/32");
    let pieces = without(block, hole);
    assert_eq!(pieces.len(), 24, "one sibling per bit below /8");
    assert!(pieces.iter().all(|p| !p.contains(hole.network())));
    for ip in samples(block, &[]) {
        if ip != hole.network() {
            assert_eq!(pieces.iter().filter(|p| p.contains(ip)).count(), 1, "{ip}");
        }
    }
}

#[test]
fn without_disjoint_or_covering_holes() {
    assert_eq!(
        without(net("10.0.0.0/8"), net("192.0.2.0/24")),
        vec![net("10.0.0.0/8")]
    );
    assert!(without(net("10.1.0.0/16"), net("10.0.0.0/8")).is_empty());
}

// ── Machine facts ─────────────────────────────────────────────────────────

fn row(dest: &str, len: u8, hop: &str, ifx: u32, metric: u32) -> RouteEntry {
    RouteEntry {
        destination: addr(dest),
        prefix_length: len,
        next_hop: addr(hop),
        interface_index: ifx,
        metric,
        is_ours: false,
        table: RouteTableRef::Main,
    }
}

fn adapter(index: u32, v4: &[&str], v6: &[&str]) -> AdapterInfo {
    AdapterInfo {
        index,
        adapter_name: format!("if{index}"),
        description: String::new(),
        friendly_name: String::new(),
        mac: None,
        interface_type: InterfaceType::Ethernet,
        oper_status: IfOperStatus::Up,
        ipv4_addresses: v4.iter().map(|a| a.parse().expect("v4")).collect(),
        ipv6_addresses: v6.iter().map(|a| a.parse().expect("v6")).collect(),
        gateways: Vec::new(),
    }
}

/// LAN on 12, an OpenVPN-style tunnel on 7 (interior, a pushed route via the
/// peer, the redirect pair), a Wintun-style tunnel on 9 holding only its own
/// address and steering the internet on-link.
fn machine() -> (Vec<RouteEntry>, Vec<AdapterInfo>) {
    let routes = vec![
        row("0.0.0.0", 0, "192.168.1.1", 12, 25),
        row("192.168.1.0", 24, "0.0.0.0", 12, 256),
        row("192.168.1.50", 32, "0.0.0.0", 12, 256),
        row("224.0.0.0", 4, "0.0.0.0", 12, 256),
        row("2001:db8:1::", 64, "::", 12, 256),
        row("fe80::", 64, "::", 12, 256),
        row("10.8.0.0", 24, "0.0.0.0", 7, 1),
        row("10.88.0.0", 13, "10.8.0.1", 7, 1),
        row("0.0.0.0", 1, "10.8.0.1", 7, 1),
        row("128.0.0.0", 1, "10.8.0.1", 7, 1),
        row("203.0.113.7", 32, "192.168.1.1", 12, 1),
        // One of ours: never a tunnel route, whatever its shape.
        row("10.0.0.0", 8, "10.8.0.1", 7, NETWORK_ROUTE_METRIC),
        row("0.0.0.0", 1, "0.0.0.0", 9, 0),
        row("100.64.0.9", 32, "0.0.0.0", 9, 0),
    ];
    let adapters = vec![
        adapter(12, &["192.168.1.50"], &["2001:db8:1::50", "fe80::50"]),
        adapter(7, &["10.8.0.6"], &[]),
        adapter(9, &["100.64.0.9"], &[]),
    ];
    (routes, adapters)
}

#[test]
fn facts_read_the_segments_by_the_addresses_on_them() {
    let (routes, adapters) = machine();
    let facts = NetworkRouteFacts::read(&routes, &adapters, Some(7), vec![addr("203.0.113.7")]);
    assert_eq!(
        facts.local_networks,
        vec![
            net("10.8.0.0/24"),
            net("192.168.1.0/24"),
            net("2001:db8:1::/64")
        ],
        "a catch-all holding a tunnel's own address is no segment"
    );
    assert_eq!(
        facts.tunnel_routes,
        vec![net("0.0.0.0/1"), net("10.88.0.0/13"), net("128.0.0.0/1")],
        "the interior, our own route and other links stay out"
    );
    assert_eq!(facts.tunnel_servers, vec![addr("203.0.113.7")]);
}

#[test]
fn the_submission_check_names_what_a_network_would_take() {
    let (routes, adapters) = machine();
    let facts = NetworkRouteFacts::read(&routes, &adapters, Some(7), vec![addr("203.0.113.7")]);
    assert_eq!(
        network_conflicts_with_links(net("203.0.113.0/24"), &facts),
        Some(NetworkLinkConflict::CoversTunnelServer(addr("203.0.113.7")))
    );
    assert_eq!(
        network_conflicts_with_links(net("192.168.0.0/16"), &facts),
        Some(NetworkLinkConflict::OverlapsLocalNetwork(net(
            "192.168.1.0/24"
        )))
    );
    assert_eq!(
        network_conflicts_with_links(net("192.168.1.128/25"), &facts),
        Some(NetworkLinkConflict::OverlapsLocalNetwork(net(
            "192.168.1.0/24"
        ))),
        "inside the LAN is taking part of it"
    );
    assert_eq!(
        network_conflicts_with_links(net("10.0.0.0/8"), &facts),
        Some(NetworkLinkConflict::OverlapsLocalNetwork(net(
            "10.8.0.0/24"
        ))),
        "the tunnel's interior is a segment too"
    );
    assert_eq!(
        network_conflicts_with_links(net("10.88.0.0/13"), &facts),
        None
    );
    assert_eq!(
        network_conflicts_with_links(net("198.51.100.0/24"), &facts),
        None
    );
}

// ── The plan ──────────────────────────────────────────────────────────────

#[test]
fn shape_support_off_plans_nothing() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![subnet("a", "198.51.100.0/24")],
    );
    let got = plan_network_routes(
        RouteBehaviorMode::PreferPrimary,
        &b,
        true,
        &ownership(&b),
        &tunnel_facts(&["10.88.0.0/13"]),
        &[],
        RuleShapeSupport::NONE,
    );
    assert_eq!(got, NetworkRoutePlan::default());
    assert!(!names_networks(&b, RuleShapeSupport::NONE));
    assert!(names_networks(&b, NETWORKS));
}

#[test]
fn every_mode_routes_each_network_over_its_own_link() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![subnet("a", "198.51.100.0/24")],
    );
    for mode in [
        RouteBehaviorMode::PreferPrimary,
        RouteBehaviorMode::PreferSecondaryWhenAvailable,
        RouteBehaviorMode::StrictSecondaryFailClosed,
    ] {
        let got = plan(mode, &b, &tunnel_facts(&["10.88.0.0/13"]), &[]);
        assert_eq!(
            on(Link::Main, &got),
            vec![net("10.0.0.0/8"), net("10.88.0.0/14"), net("10.92.0.0/14")],
            "{mode:?}"
        );
        assert_eq!(
            on(Link::Additional, &got),
            vec![net("198.51.100.0/24")],
            "{mode:?}"
        );
    }
}

#[test]
fn without_a_main_target_a_main_network_is_not_planned() {
    let b = book(vec![subnet("m", "10.0.0.0/8")], vec![]);
    let got = plan_network_routes(
        RouteBehaviorMode::PreferPrimary,
        &b,
        false,
        &ownership(&b),
        &NetworkRouteFacts::default(),
        &[],
        NETWORKS,
    );
    assert!(got.networks.is_empty());
}

#[test]
fn block_and_disabled_network_rules_route_nothing() {
    let mut blocked = subnet("b", "10.0.0.0/8");
    blocked.action = RuleAction::Block;
    let mut off = subnet("o", "172.16.0.0/12");
    off.enabled = false;
    let b = book(vec![], vec![blocked, off]);
    assert!(plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[]
    )
    .networks
    .is_empty());
}

#[test]
fn a_range_routes_its_blocks() {
    let range = IpRange::new(addr("198.51.100.0"), addr("198.51.100.191")).expect("range");
    let b = book(
        vec![],
        vec![rule("r", CanonicalAddressMatch::ip_range(range))],
    );
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[],
    );
    assert_eq!(
        on(Link::Additional, &got),
        vec![net("198.51.100.0/25"), net("198.51.100.128/26")]
    );
}

/// Mode A's counter-overlay is wider than nothing a rule names by accident: a
/// Wintun set's `8.0.0.0/7` is answered with `9.0.0.0/8` via the main link,
/// which a `9.0.0.0/8` tunnel rule must beat rather than tie.
#[test]
fn an_additional_network_out_specifics_the_counter_overlay() {
    let b = book(vec![], vec![subnet("a", "9.0.0.0/8")]);
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[(Ipv4Addr::new(8, 0, 0, 0), 7)],
    );
    assert_eq!(
        on(Link::Additional, &got),
        vec![net("9.0.0.0/9"), net("9.128.0.0/9")]
    );
}

#[test]
fn a_tunnel_network_is_routed_around_the_tunnel_server() {
    let b = book(vec![], vec![subnet("a", "10.0.0.0/8")]);
    let facts = NetworkRouteFacts {
        tunnel_servers: vec![addr("10.1.2.3"), addr("192.0.2.1")],
        ..NetworkRouteFacts::default()
    };
    let got = plan(RouteBehaviorMode::PreferPrimary, &b, &facts, &[]);
    let pieces = on(Link::Additional, &got);
    assert_eq!(pieces.len(), 24);
    assert!(pieces.iter().all(|p| !p.contains(addr("10.1.2.3"))));
    assert_eq!(
        got.diagnostics,
        vec![RouteCodegenDiagnostic::NetworkRoutedAroundTunnelServer {
            rule_id: "a".into(),
            network: net("10.0.0.0/8"),
            server: addr("10.1.2.3"),
        }]
    );
}

/// The server rides the main link anyway, so a main-link network keeps it.
#[test]
fn a_main_network_is_not_cut_around_the_server() {
    let b = book(vec![subnet("m", "10.0.0.0/8")], vec![]);
    let facts = NetworkRouteFacts {
        tunnel_servers: vec![addr("10.1.2.3")],
        ..NetworkRouteFacts::default()
    };
    let got = plan(RouteBehaviorMode::PreferPrimary, &b, &facts, &[]);
    assert_eq!(on(Link::Main, &got), vec![net("10.0.0.0/8")]);
}

#[test]
fn a_network_never_takes_a_segment_off_its_interface() {
    let facts = NetworkRouteFacts {
        local_networks: vec![net("192.168.1.0/24")],
        ..NetworkRouteFacts::default()
    };
    // Around the LAN: the LAN's own longer route keeps it, nothing to drop.
    let around = book(vec![], vec![subnet("a", "192.168.0.0/16")]);
    let got = plan(RouteBehaviorMode::PreferPrimary, &around, &facts, &[]);
    assert_eq!(on(Link::Additional, &got), vec![net("192.168.0.0/16")]);
    assert!(got.diagnostics.is_empty());
    // Inside the LAN: the route would win, so it is not installed.
    let inside = book(vec![], vec![subnet("a", "192.168.1.128/25")]);
    let got = plan(RouteBehaviorMode::PreferPrimary, &inside, &facts, &[]);
    assert!(got.networks.is_empty());
    assert_eq!(
        got.diagnostics,
        vec![RouteCodegenDiagnostic::NetworkYieldsToLocalNetwork {
            rule_id: "a".into(),
            network: net("192.168.1.128/25"),
            local: net("192.168.1.0/24"),
        }]
    );
}

/// A tunnel route equal to a LAN is not one to beat: its halves would sit
/// inside the LAN.
#[test]
fn halves_landing_inside_a_segment_are_dropped() {
    let facts = NetworkRouteFacts {
        tunnel_routes: vec![net("192.168.1.0/24")],
        local_networks: vec![net("192.168.1.0/24")],
        ..NetworkRouteFacts::default()
    };
    let b = book(vec![subnet("m", "192.168.0.0/16")], vec![]);
    let got = plan(RouteBehaviorMode::PreferPrimary, &b, &facts, &[]);
    assert_eq!(on(Link::Main, &got), vec![net("192.168.0.0/16")]);
}

#[test]
fn the_same_network_on_both_links_stays_on_the_main_one() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![subnet("a", "10.0.0.0/8")],
    );
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[],
    );
    assert_eq!(on(Link::Main, &got), vec![net("10.0.0.0/8")]);
    assert!(on(Link::Additional, &got).is_empty());
    assert!(got
        .diagnostics
        .contains(&RouteCodegenDiagnostic::NetworkClaimedByMainLink {
            rule_id: "a".into(),
            network: net("10.0.0.0/8"),
        }));
}

/// A narrower network of the other link wins inside itself: a split piece of
/// ours exactly as narrow would tie it.
#[test]
fn split_pieces_yield_to_a_narrower_network_of_the_other_link() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![subnet("a", "10.1.0.0/17")],
    );
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &tunnel_facts(&["10.1.0.0/16"]),
        &[],
    );
    assert_eq!(
        on(Link::Main, &got),
        vec![net("10.0.0.0/8"), net("10.1.128.0/17")]
    );
    assert_eq!(on(Link::Additional, &got), vec![net("10.1.0.0/17")]);
}

/// Narrower wins inside networks: in mode A no main-link host is routed, so a
/// main exact IP inside a tunnel network needs a host route of its own.
#[test]
fn mode_a_keeps_a_main_host_inside_a_tunnel_network_on_the_main_link() {
    let b = book(
        vec![exact("m", "10.1.1.1")],
        vec![subnet("a", "10.0.0.0/8")],
    );
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[],
    );
    assert_eq!(got.hosts, vec![(Link::Main, addr("10.1.1.1"))]);
}

#[test]
fn mode_b_keeps_a_tunnel_host_inside_a_main_network_in_the_tunnel() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![exact("a", "10.1.1.1")],
    );
    let got = plan(
        RouteBehaviorMode::PreferSecondaryWhenAvailable,
        &b,
        &NetworkRouteFacts::default(),
        &[],
    );
    assert_eq!(got.hosts, vec![(Link::Additional, addr("10.1.1.1"))]);
}

/// A host already inside a network of its own link needs no host route.
#[test]
fn a_host_inside_its_own_links_narrower_network_needs_no_host_route() {
    let b = book(
        vec![exact("m", "10.1.1.1"), subnet("m2", "10.1.0.0/16")],
        vec![subnet("a", "10.0.0.0/8")],
    );
    let got = plan(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        &[],
    );
    assert!(got.hosts.is_empty());
}

// ── Windows lowering ──────────────────────────────────────────────────────

fn tunnel_target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 8, 0, 1),
        gateway_v6: None,
        interface_index: 7,
    }
}

fn main_target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        gateway_v6: Some("fe80::1".parse().expect("v6")),
        interface_index: 12,
    }
}

fn windows(
    mode: RouteBehaviorMode,
    b: &CanonicalRuleBook,
    facts: &NetworkRouteFacts,
    support: RuleShapeSupport,
) -> crate::route_codegen::RouteCodegenOutput {
    generate_routes_with(
        mode,
        b,
        Some(&main_target()),
        &tunnel_target(),
        &MockFqdnCacheLookup::new(),
        &MockAppObservationLookup::new(),
        &HashSet::new(),
        ZoneVsIpOrder::default(),
        &[],
        facts,
        support,
    )
}

#[test]
fn windows_codegen_emits_network_routes_at_their_own_metric() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![subnet("a", "198.51.100.0/24"), exact("x", "10.1.1.1")],
    );
    let out = windows(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &tunnel_facts(&["10.88.0.0/13"]),
        NETWORKS,
    );
    let networks: Vec<(IpAddr, u8, u32)> = out
        .routes
        .iter()
        .filter(|r| r.metric == NETWORK_ROUTE_METRIC)
        .map(|r| (r.destination, r.prefix_length, r.interface_index))
        .collect();
    assert_eq!(
        networks,
        vec![
            (addr("10.0.0.0"), 8, 12),
            (addr("10.88.0.0"), 14, 12),
            (addr("10.92.0.0"), 14, 12),
            (addr("198.51.100.0"), 24, 7),
        ]
    );
    // The tunnel's exact host inside the main network keeps its own route.
    assert!(out.routes.iter().any(|r| r.destination == addr("10.1.1.1")
        && r.prefix_length == 32
        && r.interface_index == 7));
    for r in &out.routes {
        assert!(
            crate::route_codegen::is_owned_route(r),
            "{r:?} unrecognised after a crash"
        );
        assert_eq!(
            is_overlay_route(r),
            r.metric != NETWORK_ROUTE_METRIC && r.prefix_length < 32,
            "{r:?}"
        );
    }
}

#[test]
fn the_plain_entry_point_follows_the_shipped_shape_support() {
    let b = book(vec![], vec![subnet("a", "198.51.100.0/24")]);
    let plain = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &b,
        Some(&main_target()),
        &tunnel_target(),
        &MockFqdnCacheLookup::new(),
        &MockAppObservationLookup::new(),
        &HashSet::new(),
        ZoneVsIpOrder::default(),
        &[],
    );
    let explicit = windows(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        crate::wfp_codegen::current_rule_shape_support(),
    );
    assert_eq!(plain.routes, explicit.routes);
}

#[test]
fn a_v6_network_needs_a_v6_next_hop() {
    let b = book(
        vec![subnet("m", "2001:db8::/32")],
        vec![subnet("a", "2001:db8:1::/48")],
    );
    let out = windows(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &NetworkRouteFacts::default(),
        NETWORKS,
    );
    let v6: Vec<(u8, u32)> = out
        .routes
        .iter()
        .filter(|r| r.destination.is_ipv6())
        .map(|r| (r.prefix_length, r.interface_index))
        .collect();
    assert_eq!(v6, vec![(32, 12)], "the tunnel carries no IPv6 here");
}

/// Mode A over a split tunnel, end to end through longest-prefix match: the
/// rule beats the tunnel inside, the tunnel keeps what lies outside, the
/// narrower tunnel host keeps its address.
#[test]
fn the_installed_table_sends_the_rule_network_where_the_rule_says() {
    let b = book(
        vec![subnet("m", "10.0.0.0/8")],
        vec![exact("x", "10.90.0.5")],
    );
    let tunnel = ["10.88.0.0/13", "10.90.0.0/16", "172.16.0.0/12"];
    let out = windows(
        RouteBehaviorMode::PreferPrimary,
        &b,
        &tunnel_facts(&tunnel),
        NETWORKS,
    );
    let mut table: Vec<(IpBlock, &str)> = tunnel.iter().map(|t| (net(t), "tunnel")).collect();
    for r in &out.routes {
        let owner = if r.interface_index == 12 {
            "main"
        } else {
            "tunnel"
        };
        table.push((
            IpBlock::new(r.destination, r.prefix_length).expect("block"),
            owner,
        ));
    }
    for (ip, want) in [
        ("10.0.0.1", "main"),
        ("10.88.0.1", "main"),
        ("10.90.200.1", "main"),
        ("10.95.255.254", "main"),
        ("10.90.0.5", "tunnel"),
        ("172.16.0.1", "tunnel"),
    ] {
        assert_eq!(pick(&table, addr(ip)), Some(want), "{ip}");
    }
}

/// Our own network route on the tunnel's interface must not pass for one of
/// the tunnel's catch-alls: the counter-overlay would answer it with halves
/// via the main link and take the rule's traffic back.
#[test]
fn our_network_route_is_never_read_back_as_a_tunnel_catch_all() {
    let ours = row("10.0.0.0", 8, "10.8.0.1", 7, NETWORK_ROUTE_METRIC);
    let stamped = RouteEntry {
        is_ours: ours.is_ours || crate::route_codegen::is_owned_route(&ours),
        ..ours
    };
    assert!(tunnel_catch_all_prefixes(&[stamped], 7).is_empty());
}

#[test]
fn a_rule_network_and_an_overlay_half_of_one_length_are_told_apart() {
    let half = row(
        "0.0.0.0",
        9,
        "192.168.1.1",
        12,
        crate::route_codegen::SECONDARY_ROUTE_METRIC,
    );
    let rule = row("10.0.0.0", 9, "192.168.1.1", 12, NETWORK_ROUTE_METRIC);
    assert!(crate::route_codegen::is_owned_route(&half) && is_overlay_route(&half));
    assert!(crate::route_codegen::is_owned_route(&rule) && !is_overlay_route(&rule));
    // Wider than a rule may be is never a rule's route.
    let wide = row("0.0.0.0", 2, "192.168.1.1", 12, NETWORK_ROUTE_METRIC);
    assert!(!crate::route_codegen::is_owned_route(&wide));
    let v6 = row("2001:db8::", 32, "fe80::1", 12, NETWORK_ROUTE_METRIC);
    assert!(crate::route_codegen::is_owned_route(&v6));
}

/// Linux installs the neutral plan, Windows its own codegen: for the same
/// machine and book, the two must put the same rows in the table.
#[test]
fn the_neutral_plan_lowers_to_the_windows_routes() {
    use crate::enforcement_planner::{plan_routes_with, FamilyScope};
    use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};
    use nrr_platform_api::route_lowering::{lower_routes, RouteTarget};

    let (routes, adapters) = machine();
    let facts = NetworkRouteFacts::read(
        &routes,
        &adapters,
        Some(7),
        vec![addr("203.0.113.7"), addr("10.1.2.3")],
    );
    let b = book(
        vec![subnet("m", "10.0.0.0/8"), exact("m-host", "198.51.100.77")],
        vec![
            subnet("a", "198.51.100.0/24"),
            subnet("lan", "192.168.0.0/16"),
            subnet("srv", "203.0.113.0/24"),
            exact("x", "10.1.1.1"),
        ],
    );
    let catch_alls = [
        (Ipv4Addr::new(0, 0, 0, 0), 1),
        (Ipv4Addr::new(128, 0, 0, 0), 1),
    ];
    let lowered_target = |t: &SecondaryRouteTarget| RouteTarget {
        gateway: t.gateway,
        gateway_v6: t.gateway_v6.unwrap_or(std::net::Ipv6Addr::UNSPECIFIED),
        interface_index: t.interface_index,
    };
    let cache = MockFqdnCacheLookup::new();
    let apps = MockAppObservationLookup::new();
    for mode in [
        RouteBehaviorMode::PreferPrimary,
        RouteBehaviorMode::PreferSecondaryWhenAvailable,
        RouteBehaviorMode::StrictSecondaryFailClosed,
    ] {
        for has_primary in [true, false] {
            let main = main_target();
            let windows = generate_routes_with(
                mode,
                &b,
                has_primary.then_some(&main),
                &tunnel_target(),
                &cache,
                &apps,
                &HashSet::new(),
                ZoneVsIpOrder::default(),
                &catch_alls,
                &facts,
                NETWORKS,
            )
            .routes;
            let plan = EnforcementPlan {
                principal: UserPrincipal::from_linux_uid(1000),
                flows: Vec::new(),
                routes: plan_routes_with(
                    mode,
                    &b,
                    has_primary,
                    &cache,
                    &apps,
                    &HashSet::new(),
                    FamilyScope::V4Only,
                    ZoneVsIpOrder::default(),
                    &catch_alls,
                    &facts,
                    NETWORKS,
                ),
                policy_rules: Vec::new(),
            };
            let neutral = lower_routes(
                &plan,
                lowered_target(&tunnel_target()),
                has_primary.then(|| lowered_target(&main)),
            );
            assert!(
                windows.iter().any(|r| r.metric == NETWORK_ROUTE_METRIC),
                "fixture guard: {mode:?}"
            );
            assert_eq!(windows.len(), neutral.len(), "{mode:?}, {has_primary}");
            assert!(
                windows.iter().all(|r| neutral.contains(r)),
                "{mode:?}, {has_primary}\nwindows: {windows:#?}\nneutral: {neutral:#?}"
            );
        }
    }
}

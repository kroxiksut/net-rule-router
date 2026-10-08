//! Network rules (subnets and ranges) in the filter codegen.

use super::*;
use crate::app_observation_lookup::MockAppObservationLookup;
use crate::enforcement_planner::FamilyScope;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_domain::canonical::CanonicalRuleSet;
use nrr_domain::RuleId;
use nrr_platform_api::NoopAppPathResolver;
use nrr_shared::ip_block::IpRange;

const SID: &str = "S-1-5-21-A";

/// What enforcement will carry once routes and Fail-Closed do too.
const NETWORKS: RuleShapeSupport = RuleShapeSupport {
    app_scoped_destination_block: false,
    app_scoped_destination_route: false,
    network_destination: true,
};

fn rule(id: &str, m: CanonicalAddressMatch, action: RuleAction) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action,
        origin: None,
    }
}

fn subnet(id: &str, text: &str, action: RuleAction) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::Subnet(IpBlock::parse(text).expect("valid subnet")),
        action,
    )
}

fn range(id: &str, first: &str, last: &str) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::ip_range(
            IpRange::new(
                first.parse().expect("valid address"),
                last.parse().expect("valid address"),
            )
            .expect("valid range"),
        ),
        RuleAction::Route,
    )
}

fn exact(id: &str, ip: &str) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::ExactIp(ip.parse().expect("valid address")),
        RuleAction::Route,
    )
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

fn generate_in(
    rule_book: &CanonicalRuleBook,
    cache: &MockFqdnCacheLookup,
    families: FamilyScope,
    shapes: RuleShapeSupport,
) -> CodegenOutput {
    generate_filters_with_shapes(
        CodegenInput {
            sid: SID,
            rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
            zone_priority_over_ip: false,
            families,
            packet_blocks: true,
        },
        shapes,
    )
}

fn generate(rule_book: &CanonicalRuleBook) -> CodegenOutput {
    generate_in(
        rule_book,
        &MockFqdnCacheLookup::new(),
        FamilyScope::V4Only,
        NETWORKS,
    )
}

fn block(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("valid block")
}

/// The filter that decides `ip` at the connect layer: the highest weight
/// covering it.
fn winner(filters: &[WfpFilterSpec], ip: IpAddr) -> Option<&WfpFilterSpec> {
    filters
        .iter()
        .filter(|f| {
            matches!(
                f.layer,
                WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
            )
        })
        .filter(|f| covers(f, ip))
        .max_by_key(|f| f.weight)
}

fn covers(f: &WfpFilterSpec, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            f.covers_v4(v4)
                || f.remote_subnet
                    .and_then(|(net, len)| IpBlock::new(IpAddr::V4(net), len))
                    .is_some_and(|b| b.contains(ip))
        }
        IpAddr::V6(v6) => {
            f.covers_v6(v6)
                || f.remote_subnet_v6
                    .and_then(|(net, len)| IpBlock::new(IpAddr::V6(net), len))
                    .is_some_and(|b| b.contains(ip))
        }
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("valid address")
}

#[test]
fn a_subnet_route_is_one_subnet_filter_never_per_address() {
    let out = generate(&book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        vec![],
    ));
    assert_eq!(out.filters.len(), 1, "{:?}", out.filters);
    let f = &out.filters[0];
    assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(f.action, WfpAction::Permit);
    assert_eq!(f.remote_subnet, Some((Ipv4Addr::new(10, 0, 0, 0), 8)));
    assert!(f.remote_ip.is_none() && f.remote_ip_set.is_empty());
    assert_eq!(f.weight, BASE_PRIMARY);
    assert_eq!(f.user_sid.as_deref(), Some(SID));
    assert!(f.validate_layer_conditions().is_ok());
    assert_eq!(out.primary_dest_networks, vec![block("10.0.0.0/8")]);
    // Hosts are what the per-address guards read; a network is not one.
    assert!(out.primary_dest_ips.is_empty());
    assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
}

#[test]
fn the_shape_gate_lets_networks_into_the_service() {
    let rule_book = book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        vec![],
    );
    let out = generate_filters(CodegenInput {
        sid: SID,
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &MockFqdnCacheLookup::new(),
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: FamilyScope::V4Only,
        packet_blocks: true,
    });
    assert!(out
        .filters
        .iter()
        .any(|f| f.remote_subnet == Some((std::net::Ipv4Addr::new(10, 0, 0, 0), 8))));
    assert!(!out
        .diagnostics
        .iter()
        .any(|d| matches!(d, CodegenDiagnostic::UnsupportedRuleShape { .. })));
}

#[test]
fn a_range_is_one_filter_per_block_of_its_decomposition() {
    let r = range("s-range", "10.0.0.5", "10.0.0.40");
    let blocks = r
        .address_match
        .as_ref()
        .and_then(|m| m.ip_blocks())
        .expect("a range has blocks")
        .to_vec();
    let out = generate(&book(vec![], vec![r]));
    assert_eq!(out.filters.len(), blocks.len());
    assert_eq!(out.secondary_dest_networks, blocks);
    for (idx, f) in out.filters.iter().enumerate() {
        assert_eq!(f.weight, BASE_SECONDARY + idx as u64, "one slot per piece");
    }
}

#[test]
fn a_network_block_is_dropped_at_both_layers() {
    let out = generate(&book(
        vec![],
        vec![subnet("b-net", "203.0.113.0/24", RuleAction::Block)],
    ));
    assert_eq!(out.filters.len(), 2, "{:?}", out.filters);
    let ale = &out.filters[0];
    let pkt = &out.filters[1];
    assert_eq!(ale.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(pkt.layer, WfpLayerKey::OutboundIpPacketV4);
    for f in [ale, pkt] {
        assert_eq!(f.action, WfpAction::Block);
        assert_eq!(f.remote_subnet, Some((Ipv4Addr::new(203, 0, 113, 0), 24)));
        assert_eq!(f.weight, BASE_BLOCK);
        assert!(f.validate_layer_conditions().is_ok());
    }
    assert_eq!(ale.user_sid.as_deref(), Some(SID));
    // The packet layer has no user condition.
    assert!(pkt.user_sid.is_none());
    assert_ne!(ale.id, pkt.id);
    // A dropped network is not a destination anybody routes.
    assert!(out.secondary_dest_networks.is_empty());
}

#[test]
fn an_ipv6_network_waits_for_a_link_that_carries_the_family() {
    let rule_book = book(
        vec![subnet("p-v6", "2001:db8::/32", RuleAction::Route)],
        vec![],
    );
    let cache = MockFqdnCacheLookup::new();
    assert!(
        generate_in(&rule_book, &cache, FamilyScope::V4Only, NETWORKS)
            .filters
            .is_empty()
    );
    let out = generate_in(&rule_book, &cache, FamilyScope::Both, NETWORKS);
    assert_eq!(out.filters.len(), 1);
    assert_eq!(out.filters[0].layer, WfpLayerKey::AleAuthConnectV6);
    assert_eq!(
        out.filters[0].remote_subnet_v6,
        Some(("2001:db8::".parse().expect("v6"), 32))
    );
    assert!(out.filters[0].validate_layer_conditions().is_ok());
}

#[test]
fn a_main_network_leaves_out_a_tunnel_address_inside_it() {
    let out = generate(&book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        vec![exact("s-ip", "10.1.2.3")],
    ));
    // 10.0.0.0/8 minus one address is 24 pieces, none of which holds it.
    assert_eq!(out.primary_dest_networks.len(), 24);
    assert!(!out
        .primary_dest_networks
        .iter()
        .any(|b| b.contains(ip("10.1.2.3"))));
    let w = winner(&out.filters, ip("10.1.2.3")).expect("the tunnel host has a filter");
    assert_eq!(
        w.weight, BASE_SECONDARY,
        "the tunnel host's own filter decides it"
    );
    let w = winner(&out.filters, ip("10.1.2.4")).expect("the rest is the network's");
    assert!(w.remote_subnet.is_some() && w.weight >= BASE_PRIMARY);
}

#[test]
fn a_tunnel_network_leaves_out_a_main_address_inside_it() {
    let out = generate(&book(
        vec![exact("p-ip", "10.1.2.3")],
        vec![subnet("s-net", "10.0.0.0/8", RuleAction::Route)],
    ));
    assert!(!out
        .secondary_dest_networks
        .iter()
        .any(|b| b.contains(ip("10.1.2.3"))));
    assert_eq!(out.secondary_dest_networks.len(), 24);
}

#[test]
fn a_longer_prefix_on_the_other_link_is_carved_out_whichever_link_is_wider() {
    for wide_on_main in [true, false] {
        let wide = subnet("wide", "10.1.0.0/16", RuleAction::Route);
        let narrow = subnet("narrow", "10.1.2.0/24", RuleAction::Route);
        let rule_book = if wide_on_main {
            book(vec![wide], vec![narrow])
        } else {
            book(vec![narrow], vec![wide])
        };
        let out = generate(&rule_book);
        let (wide_pieces, narrow_pieces) = if wide_on_main {
            (&out.primary_dest_networks, &out.secondary_dest_networks)
        } else {
            (&out.secondary_dest_networks, &out.primary_dest_networks)
        };
        assert_eq!(narrow_pieces, &vec![block("10.1.2.0/24")]);
        assert_eq!(wide_pieces.len(), 8, "a /16 minus a /24 is eight blocks");
        assert!(!wide_pieces.iter().any(|b| b.overlaps(block("10.1.2.0/24"))));
    }
}

#[test]
fn a_same_link_network_inside_another_is_not_carved() {
    let out = generate(&book(
        vec![
            subnet("p-wide", "10.0.0.0/8", RuleAction::Route),
            subnet("p-narrow", "10.1.0.0/16", RuleAction::Route),
        ],
        vec![],
    ));
    assert_eq!(
        out.primary_dest_networks,
        vec![block("10.0.0.0/8"), block("10.1.0.0/16")]
    );
}

#[test]
fn a_network_block_leaves_out_the_hosts_a_narrower_route_names() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("a.example", vec![Ipv4Addr::new(192, 0, 2, 10)]);
    for block_on_main in [true, false] {
        let blocked = subnet("b-net", "192.0.2.0/24", RuleAction::Block);
        let named = rule(
            "r-name",
            CanonicalAddressMatch::ExactFqdn("a.example".into()),
            RuleAction::Route,
        );
        let rule_book = if block_on_main {
            book(vec![blocked], vec![named])
        } else {
            book(vec![named], vec![blocked])
        };
        let out = generate_in(&rule_book, &cache, FamilyScope::V4Only, NETWORKS);
        let w = winner(&out.filters, ip("192.0.2.10")).expect("the named host has a filter");
        assert_eq!(
            w.action,
            WfpAction::Permit,
            "the name inside the blocked network keeps its route"
        );
        let w = winner(&out.filters, ip("192.0.2.11")).expect("the rest is blocked");
        assert_eq!(w.action, WfpAction::Block);
        // The packet layer leaves it out as well.
        assert!(!out.filters.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundIpPacketV4 && covers(f, ip("192.0.2.10"))
        }));
    }
}

#[test]
fn a_zone_inside_a_blocked_network_stays_blocked() {
    // The network is narrower than a zone, so its Block wins.
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("b.example", vec![Ipv4Addr::new(192, 0, 2, 20)]);
    let out = generate_in(
        &book(
            vec![subnet("b-net", "192.0.2.0/24", RuleAction::Block)],
            vec![rule(
                "r-zone",
                CanonicalAddressMatch::Zone("example".into()),
                RuleAction::Route,
            )],
        ),
        &cache,
        FamilyScope::V4Only,
        NETWORKS,
    );
    let w = winner(&out.filters, ip("192.0.2.20")).expect("covered");
    assert_eq!(w.action, WfpAction::Block);
}

#[test]
fn a_narrower_network_block_inside_a_route_network_wins_by_band() {
    let out = generate(&book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        vec![subnet("b-net", "10.1.0.0/16", RuleAction::Block)],
    ));
    assert_eq!(out.primary_dest_networks, vec![block("10.0.0.0/8")]);
    let w = winner(&out.filters, ip("10.1.0.1")).expect("covered");
    assert_eq!(w.action, WfpAction::Block);
}

#[test]
fn a_network_block_and_an_equal_route_network_go_to_the_block() {
    let out = generate(&book(
        vec![subnet("p-net", "10.1.0.0/16", RuleAction::Route)],
        vec![subnet("b-net", "10.1.0.0/16", RuleAction::Block)],
    ));
    let w = winner(&out.filters, ip("10.1.0.1")).expect("covered");
    assert_eq!(w.action, WfpAction::Block);
}

#[test]
fn carving_past_the_cap_falls_back_to_the_bare_network_and_says_so() {
    // Twenty addresses inside a /8 would carve it into ~480 pieces.
    let inside: Vec<CanonicalRule> = (0..20u8)
        .map(|i| exact(&format!("s-{i}"), &format!("10.{i}.0.1")))
        .collect();
    let out = generate(&book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        inside,
    ));
    assert_eq!(out.primary_dest_networks, vec![block("10.0.0.0/8")]);
    assert!(
        out.diagnostics.iter().any(|d| matches!(
            d,
            CodegenDiagnostic::NetworkCarvingOverCap { rule_id, cap, pieces }
                if rule_id == "p-net"
                    && *cap == crate::enforcement_planner::NETWORK_PIECE_CAP
                    && *pieces > *cap
        )),
        "{:?}",
        out.diagnostics
    );
}

/// The speed budget, stated as numbers: a network never costs a filter per
/// address, and the widest rule validation admits is one filter.
#[test]
fn filter_counts_stay_bounded() {
    let slash8 = generate(&book(
        vec![subnet("p", "10.0.0.0/8", RuleAction::Route)],
        vec![],
    ));
    assert_eq!(slash8.filters.len(), 1);
    let slash8_block = generate(&book(
        vec![subnet("b", "10.0.0.0/8", RuleAction::Block)],
        vec![],
    ));
    assert_eq!(slash8_block.filters.len(), 2);

    // The worst-aligned range of a /8's width: one address short at each end.
    let worst = range("w", "10.0.0.1", "10.255.255.254");
    let pieces = worst
        .address_match
        .as_ref()
        .and_then(|m| m.ip_blocks())
        .map_or(0, <[IpBlock]>::len);
    let out = generate(&book(vec![], vec![worst]));
    assert_eq!(out.filters.len(), pieces);
    assert_eq!(pieces, 46);
}

#[test]
fn filter_ids_are_stable_and_distinct_per_piece() {
    let rule_book = book(
        vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
        vec![exact("s-ip", "10.1.2.3")],
    );
    let first = generate(&rule_book);
    let second = generate(&rule_book);
    assert_eq!(first.filters, second.filters);
    let ids: std::collections::HashSet<u64> = first.filters.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids.len(), first.filters.len());
}

/// A user's own Block holds for that user only: the connect layer carries
/// their SID, and nothing lands on the packet layer, which has no user
/// condition and would cut every other account. The baseline's Block keeps
/// its packet-layer mirror.
#[test]
fn only_the_baseline_block_reaches_the_packet_layer() {
    let mut rb = book(
        Vec::new(),
        vec![
            subnet("b-net", "10.1.0.0/16", RuleAction::Block),
            exact("b-ip", "192.0.2.9"),
        ],
    );
    let blocked: Vec<CanonicalRule> = rb
        .secondary
        .rules()
        .iter()
        .cloned()
        .map(|mut r| {
            r.action = RuleAction::Block;
            r
        })
        .collect();
    rb.secondary = CanonicalRuleSet::from_rules(blocked);
    let generate_for = |packet_blocks: bool| {
        generate_filters_with_shapes(
            CodegenInput {
                sid: SID,
                rule_book: &rb,
                behavior_mode: RouteBehaviorMode::PreferPrimary,
                fqdn_cache: &MockFqdnCacheLookup::new(),
                app_observations: &MockAppObservationLookup::new(),
                app_resolver: &NoopAppPathResolver,
                secondary_ip_denylist: &std::collections::HashSet::new(),
                zone_priority_over_ip: false,
                families: FamilyScope::V4Only,
                packet_blocks,
            },
            NETWORKS,
        )
    };
    let packet = |out: &CodegenOutput| {
        out.filters
            .iter()
            .filter(|f| {
                matches!(
                    f.layer,
                    WfpLayerKey::OutboundIpPacketV4 | WfpLayerKey::OutboundIpPacketV6
                )
            })
            .count()
    };

    let own = generate_for(false);
    assert_eq!(packet(&own), 0, "{:?}", own.filters);
    let connect: Vec<&WfpFilterSpec> = own
        .filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    assert!(connect.len() >= 2, "{connect:?}");
    assert!(connect.iter().all(|f| f.user_sid.as_deref() == Some(SID)));

    let baseline = generate_for(true);
    assert!(packet(&baseline) >= 2, "{:?}", baseline.filters);
}

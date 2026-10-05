//! Network rules in the neutral planner.

use super::*;
use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
use nrr_domain::rule_shape::RuleShapeSupport;
use nrr_domain::RuleId;
use nrr_shared::ip_block::{IpBlock, IpRange};

const SID: &str = "S-1-5-21-1-2-3-1001";

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

struct NoCache;
impl FqdnCacheLookup for NoCache {
    fn ips_for_hostname(&self, _: &str) -> Vec<IpAddr> {
        Vec::new()
    }
    fn hostnames_under_suffix(&self, _: &str, _: usize) -> Vec<String> {
        Vec::new()
    }
}

struct NoApps;
impl AppPathResolver for NoApps {
    fn resolve(&self, _: &str) -> Vec<PathBuf> {
        Vec::new()
    }
}
impl AppObservationLookup for NoApps {
    fn ips_for_app(&self, _: &str) -> Vec<Ipv4Addr> {
        Vec::new()
    }
}

fn plan(rule_book: &CanonicalRuleBook, ipv6: Ipv6Guard) -> Vec<FlowRule> {
    let denylist = HashSet::new();
    plan_route_rules_with_shapes(
        rule_book,
        SID,
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            fqdn_cache: &NoCache,
            app_resolver: &NoApps,
            app_observations: &NoApps,
            zone_priority_over_ip: false,
            secondary_ip_denylist: &denylist,
            ipv6,
        },
        NETWORKS,
    )
    .0
}

fn block(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("valid block")
}

#[test]
fn a_network_is_planned_as_subnet_flows_never_as_hosts() {
    let flows = plan(
        &book(
            vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
            vec![subnet("b-net", "203.0.113.0/24", RuleAction::Block)],
        ),
        Ipv6Guard::Off,
    );
    assert_eq!(flows.len(), 2, "{flows:?}");
    assert_eq!(
        flows[0].flow.dst,
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8
        }
    );
    assert_eq!(flows[0].verdict, Verdict::Permit);
    assert_eq!(
        flows[0].precedence.class,
        PrecedenceClass::RouteRule(RouteRole::Primary)
    );
    assert_eq!(flows[0].coverage, Coverage::ConnectOnly);
    assert_eq!(flows[1].verdict, Verdict::Block);
    assert_eq!(flows[1].precedence.class, PrecedenceClass::HardBlock);
    assert_eq!(flows[1].coverage, Coverage::AllPackets);
    assert!(flows.iter().all(|f| f.principal.0.is_some()));
    // Hosts are what the per-address guards read; a network adds none.
    assert!(route_destinations(&flows, RouteRole::Primary).is_empty());
    assert_eq!(
        route_networks(&flows, RouteRole::Primary),
        vec![block("10.0.0.0/8")]
    );
}

#[test]
fn the_service_shape_gate_lets_networks_through() {
    let denylist = HashSet::new();
    let (flows, report) = plan_route_rules(
        &book(
            vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
            vec![],
        ),
        SID,
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            fqdn_cache: &NoCache,
            app_resolver: &NoApps,
            app_observations: &NoApps,
            zone_priority_over_ip: false,
            secondary_ip_denylist: &denylist,
            ipv6: Ipv6Guard::Off,
        },
    );
    assert!(report.unsupported_shapes().is_empty());
    assert_eq!(
        route_networks(&flows, RouteRole::Primary),
        vec![IpBlock::parse("10.0.0.0/8").expect("block")]
    );
}

#[test]
fn a_range_plans_one_flow_per_block_at_consecutive_ordinals() {
    let r = IpRange::new(
        "10.0.0.5".parse().expect("ip"),
        "10.0.0.40".parse().expect("ip"),
    )
    .expect("range");
    let blocks = r.blocks().to_vec();
    let flows = plan(
        &book(
            vec![exact("p-ip", "192.0.2.1")],
            vec![
                exact("s-ip", "192.0.2.2"),
                rule(
                    "s-range",
                    CanonicalAddressMatch::ip_range(r),
                    RuleAction::Route,
                ),
            ],
        ),
        Ipv6Guard::Off,
    );
    let range_flows: Vec<&FlowRule> = flows
        .iter()
        .filter(|f| matches!(f.flow.dst, DstMatch::SubnetV4 { .. }))
        .collect();
    assert_eq!(range_flows.len(), blocks.len());
    for (idx, f) in range_flows.iter().enumerate() {
        assert_eq!(f.precedence.ordinal, SLOTS_PER_RULE + idx as u32);
    }
    assert_eq!(route_networks(&flows, RouteRole::Secondary), blocks);
}

#[test]
fn the_planner_carves_what_the_other_link_names_inside_a_network() {
    let flows = plan(
        &book(
            vec![subnet("p-net", "10.0.0.0/8", RuleAction::Route)],
            vec![
                exact("s-ip", "10.1.2.3"),
                subnet("s-net", "10.2.0.0/16", RuleAction::Route),
            ],
        ),
        Ipv6Guard::Off,
    );
    let main = route_networks(&flows, RouteRole::Primary);
    assert!(!main
        .iter()
        .any(|b| b.contains("10.1.2.3".parse().expect("ip"))));
    assert!(!main.iter().any(|b| b.overlaps(block("10.2.0.0/16"))));
    assert!(main
        .iter()
        .any(|b| b.contains("10.1.2.4".parse().expect("ip"))));
    assert_eq!(
        route_networks(&flows, RouteRole::Secondary),
        vec![block("10.2.0.0/16")]
    );
}

#[test]
fn an_ipv6_network_is_planned_only_when_a_link_carries_the_family() {
    let rule_book = book(
        vec![subnet("p-v6", "2001:db8::/32", RuleAction::Route)],
        vec![],
    );
    assert!(plan(&rule_book, Ipv6Guard::Off).is_empty());
    let flows = plan(&rule_book, Ipv6Guard::FiltersOnly);
    assert_eq!(
        flows[0].flow.dst,
        DstMatch::SubnetV6 {
            net: "2001:db8::".parse().expect("v6"),
            prefix: 32
        }
    );
}

/// The shadow comparison on Windows holds the neutral pipeline to the codegen;
/// networks must not be where the two drift apart.
#[cfg(windows)]
#[test]
fn network_rules_lower_to_the_filters_the_codegen_emits() {
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::wfp_codegen::{generate_filters_with_shapes, CodegenInput};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("a.example", vec![Ipv4Addr::new(192, 0, 2, 10)]);
    let rule_book = book(
        vec![
            subnet("p-net", "10.0.0.0/8", RuleAction::Route),
            subnet("p-v6", "2001:db8::/32", RuleAction::Route),
            subnet("b-net", "192.0.2.0/24", RuleAction::Block),
        ],
        vec![
            exact("s-ip", "10.1.2.3"),
            rule(
                "s-name",
                CanonicalAddressMatch::ExactFqdn("a.example".into()),
                RuleAction::Route,
            ),
            rule(
                "s-range",
                CanonicalAddressMatch::ip_range(
                    IpRange::new(
                        "10.9.0.5".parse().expect("ip"),
                        "10.9.0.40".parse().expect("ip"),
                    )
                    .expect("range"),
                ),
                RuleAction::Route,
            ),
            exact("s-ip6", "2001:db8::1"),
        ],
    );
    let denylist = HashSet::new();
    let codegen = generate_filters_with_shapes(
        CodegenInput {
            sid: SID,
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &NoApps,
            app_resolver: &NoApps,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
            families: FamilyScope::Both,
        },
        NETWORKS,
    );
    let flows = plan_route_rules_with_shapes(
        &rule_book,
        SID,
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            fqdn_cache: &cache,
            app_resolver: &NoApps,
            app_observations: &NoApps,
            zone_priority_over_ip: false,
            secondary_ip_denylist: &denylist,
            ipv6: Ipv6Guard::FiltersAndRoutes,
        },
        NETWORKS,
    )
    .0;
    let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(SID)
            .expect("valid sid"),
        flows,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    });
    assert!(codegen.filters.iter().any(|f| f.remote_subnet.is_some()));
    assert!(codegen.filters.iter().any(|f| f.remote_subnet_v6.is_some()));
    assert!(
        behaviorally_equivalent(&codegen.filters, &lowered),
        "{:?}",
        nrr_platform_api::wfp_behavioral::behavioral_difference(&codegen.filters, &lowered)
    );
    assert!(arbitration_order_preserved(&codegen.filters, &lowered));
}

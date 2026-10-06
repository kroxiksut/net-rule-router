use super::*;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_domain::canonical::CanonicalRule;
use nrr_domain::RuleId;
use nrr_shared::ip_block::IpRange;

fn rule(id: &str, address: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(address),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn subnet(id: &str, net: &str) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::Subnet(IpBlock::parse(net).expect("test network literal")),
    )
}

fn range(id: &str, text: &str) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::ip_range(IpRange::parse(text).expect("test range literal")),
    )
}

fn exact_ip(id: &str, ip: &str) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::ExactIp(ip.parse().expect("test address literal")),
    )
}

fn host(id: &str, name: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::ExactFqdn(name.into()))
}

fn zone(id: &str, name: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::Zone(name.into()))
}

fn with_networks() -> RuleShapeSupport {
    RuleShapeSupport {
        network_destination: true,
        ..crate::wfp_codegen::current_rule_shape_support()
    }
}

fn owners(
    primary: Vec<CanonicalRule>,
    secondary: Vec<CanonicalRule>,
    fqdn: &MockFqdnCacheLookup,
) -> SecondaryAddressOwners {
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    };
    SecondaryAddressOwners::build_with_support(&book, fqdn, with_networks())
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn owner(owners: &SecondaryAddressOwners, ip: IpAddr) -> Option<String> {
    owners.owner_of(ip).map(Cow::into_owned)
}

#[test]
fn an_address_inside_a_secondary_subnet_is_expected_on_the_secondary() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(Vec::new(), vec![subnet("s", "10.0.0.0/8")], &fqdn);
    assert_eq!(owner(&o, v4(10, 1, 2, 3)).as_deref(), Some("10.0.0.0/8"));
    assert!(o.contains(&Ipv4Addr::new(10, 1, 2, 3)));
    assert!(o.owned_by_network_only(&Ipv4Addr::new(10, 1, 2, 3)));
    assert_eq!(owner(&o, v4(192, 0, 2, 1)), None);
}

#[test]
fn an_exact_primary_address_inside_a_secondary_subnet_stays_primary() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(
        vec![exact_ip("p", "10.1.2.3")],
        vec![subnet("s", "10.0.0.0/8")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 1, 2, 3)), None);
    assert!(o.contains(&Ipv4Addr::new(10, 1, 2, 4)));
}

#[test]
fn a_primary_host_inside_a_secondary_subnet_stays_primary_but_a_zone_does_not() {
    let fqdn = MockFqdnCacheLookup::new();
    fqdn.set_ips("intranet.corp.example", vec![Ipv4Addr::new(10, 1, 0, 1)]);
    fqdn.set_ips("wiki.zone.example", vec![Ipv4Addr::new(10, 1, 0, 2)]);
    let o = owners(
        vec![
            host("p-host", "intranet.corp.example"),
            zone("p-zone", "zone.example"),
        ],
        vec![subnet("s", "10.0.0.0/8")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 1, 0, 1)), None, "a name beats a network");
    assert_eq!(
        owner(&o, v4(10, 1, 0, 2)).as_deref(),
        Some("10.0.0.0/8"),
        "a network beats a zone"
    );
}

#[test]
fn a_longer_primary_prefix_inside_a_shorter_secondary_one_wins() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(
        vec![subnet("p", "10.5.0.0/16")],
        vec![subnet("s", "10.0.0.0/8"), subnet("s-inner", "10.5.7.0/24")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 5, 0, 1)), None);
    assert_eq!(owner(&o, v4(10, 9, 0, 1)).as_deref(), Some("10.0.0.0/8"));
    // A secondary network narrower still takes its piece back.
    assert_eq!(owner(&o, v4(10, 5, 7, 1)).as_deref(), Some("10.5.7.0/24"));
}

#[test]
fn the_same_network_on_both_links_stays_primary() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(
        vec![subnet("p", "10.0.0.0/8")],
        vec![subnet("s", "10.0.0.0/8")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 1, 2, 3)), None);
}

#[test]
fn a_range_rule_is_named_as_written() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(Vec::new(), vec![range("s", "192.0.2.10-192.0.2.20")], &fqdn);
    assert_eq!(
        owner(&o, v4(192, 0, 2, 15)).as_deref(),
        Some("192.0.2.10-192.0.2.20")
    );
    assert_eq!(owner(&o, v4(192, 0, 2, 9)), None);
    assert_eq!(owner(&o, v4(192, 0, 2, 21)), None);
}

#[test]
fn disabled_and_block_networks_send_nothing() {
    let fqdn = MockFqdnCacheLookup::new();
    let mut disabled = subnet("s-off", "10.0.0.0/8");
    disabled.enabled = false;
    let mut block = subnet("s-block", "172.16.0.0/12");
    block.action = RuleAction::Block;
    let o = owners(Vec::new(), vec![disabled, block], &fqdn);
    assert!(o.is_empty());
    assert_eq!(owner(&o, v4(10, 1, 2, 3)), None);
    assert_eq!(owner(&o, v4(172, 16, 0, 1)), None);
}

#[test]
fn a_network_enforcement_cannot_carry_is_not_expected() {
    let fqdn = MockFqdnCacheLookup::new();
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(Vec::new()),
        secondary: CanonicalRuleSet::from_rules(vec![subnet("s", "10.0.0.0/8")]),
    };
    let o = SecondaryAddressOwners::build_with_support(&book, &fqdn, RuleShapeSupport::NONE);
    assert_eq!(owner(&o, v4(10, 1, 2, 3)), None);
}

#[test]
fn host_claims_keep_their_owner_and_beat_a_primary_network() {
    let fqdn = MockFqdnCacheLookup::new();
    fqdn.set_ips("video.example", vec![Ipv4Addr::new(10, 5, 0, 9)]);
    let o = owners(
        vec![subnet("p", "10.5.0.0/16")],
        vec![host("s-host", "video.example")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 5, 0, 9)).as_deref(), Some("video.example"));
    assert!(!o.owned_by_network_only(&Ipv4Addr::new(10, 5, 0, 9)));
}

#[test]
fn a_secondary_zone_host_inside_a_primary_network_goes_primary() {
    let fqdn = MockFqdnCacheLookup::new();
    fqdn.set_ips("cdn.zone.example", vec![Ipv4Addr::new(10, 5, 0, 9)]);
    fqdn.set_ips("www.zone.example", vec![Ipv4Addr::new(198, 51, 100, 9)]);
    let o = owners(
        vec![subnet("p", "10.5.0.0/16")],
        vec![zone("s-zone", "zone.example")],
        &fqdn,
    );
    assert_eq!(owner(&o, v4(10, 5, 0, 9)), None);
    assert_eq!(
        owner(&o, v4(198, 51, 100, 9)).as_deref(),
        Some("www.zone.example")
    );
}

#[test]
fn an_ipv6_secondary_network_is_expected_when_enforced() {
    let fqdn = MockFqdnCacheLookup::new();
    let o = owners(Vec::new(), vec![subnet("s", "2001:db8::/32")], &fqdn);
    let inside: IpAddr = "2001:db8::1".parse().expect("test address literal");
    let outside: IpAddr = "2001:db9::1".parse().expect("test address literal");
    assert_eq!(owner(&o, inside).as_deref(), Some("2001:db8::/32"));
    assert_eq!(owner(&o, outside), None);
}

#[test]
fn from_named_answers_like_the_plain_set() {
    let o = SecondaryAddressOwners::from_named([Ipv4Addr::new(100, 64, 0, 1)]);
    assert!(o.contains(&Ipv4Addr::new(100, 64, 0, 1)));
    assert!(!o.contains(&Ipv4Addr::new(100, 64, 0, 2)));
    assert!(!o.owned_by_network_only(&Ipv4Addr::new(100, 64, 0, 1)));
    assert!(SecondaryAddressOwners::default().is_empty());
}

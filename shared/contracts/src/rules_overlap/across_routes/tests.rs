use super::*;
use crate::rules_json::{AppMatchDto, AppPatternDto, RuleAction, RULES_JSON_SCHEMA_VERSION};

fn rule(id: &str, address_match: AddressMatchDto) -> RuleDto {
    RuleDto {
        id: id.to_string(),
        enabled: true,
        address_match: Some(address_match),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn exact(id: &str, value: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::ExactFqdn {
            value: value.into(),
        },
    )
}

fn suffix(id: &str, suffix: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::SuffixDomain {
            suffix: suffix.into(),
        },
    )
}

fn zone(id: &str, name: &str) -> RuleDto {
    rule(id, AddressMatchDto::Zone { name: name.into() })
}

fn book(primary: Vec<RuleDto>, secondary: Vec<RuleDto>) -> CanonicalRulesJsonV1 {
    CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary,
        secondary,
    }
}

fn overlaps(dto: &CanonicalRulesJsonV1) -> Vec<RouteOverlap> {
    find_route_overlaps(dto, false)
}

#[test]
fn a_host_named_inside_the_other_routes_zone_wins_over_the_zone() {
    let found = overlaps(&book(
        vec![zone("P1", "example")],
        vec![exact("S1", "www.site.example")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Nested);
    assert_eq!(found[0].winner.rule_id, "S1");
    assert_eq!(found[0].winner.route, "secondary");
    assert_eq!(found[0].loser.rule_id, "P1");
    assert_eq!(found[0].loser.rule_type, "zone");
}

#[test]
fn the_longer_suffix_wins_whichever_route_holds_it() {
    let found = overlaps(&book(
        vec![suffix("P1", "ai.search.example")],
        vec![suffix("S1", "search.example")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].winner.rule_id, "P1");
    assert_eq!(found[0].loser.rule_id, "S1");
}

#[test]
fn a_suffix_beats_the_zone_of_the_same_name() {
    let found = overlaps(&book(
        vec![zone("P1", "example")],
        vec![suffix("S1", "example")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].winner.rule_id, "S1");
}

#[test]
fn a_zone_never_covers_its_own_name() {
    assert!(overlaps(&book(
        vec![zone("P1", "example")],
        vec![exact("S1", "example")]
    ))
    .is_empty());
}

#[test]
fn an_exact_name_covers_its_subdomains_only_under_coverage() {
    let rules = book(
        vec![exact("P1", "site.example")],
        vec![exact("S1", "www.site.example")],
    );
    assert!(overlaps(&rules).is_empty());
    let covered = find_route_overlaps(&rules, true);
    assert_eq!(covered.len(), 1, "{covered:?}");
    assert_eq!(covered[0].winner.rule_id, "S1");
}

#[test]
fn the_same_rule_on_both_routes_is_a_duplicate_the_main_route_wins() {
    let found = overlaps(&book(
        vec![exact("P1", "site.example")],
        vec![exact("S1", "site.example")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Duplicate);
    assert_eq!(found[0].winner.route, "primary");
}

#[test]
fn a_name_and_its_suffix_are_one_rule_under_coverage() {
    let found = find_route_overlaps(
        &book(
            vec![suffix("P1", "site.example")],
            vec![exact("S1", "site.example")],
        ),
        true,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Duplicate);
}

#[test]
fn rules_on_one_route_do_not_overlap_each_other() {
    assert!(overlaps(&book(
        vec![zone("P1", "example"), exact("P2", "www.site.example")],
        vec![exact("S1", "other.test")],
    ))
    .is_empty());
}

#[test]
fn disabled_app_scoped_and_address_rules_are_left_out() {
    let mut disabled = exact("S1", "a.example");
    disabled.enabled = false;
    let mut app_scoped = exact("S2", "b.example");
    app_scoped.app_match = Some(AppMatchDto {
        pattern: AppPatternDto::Exact {
            value: "browser.exe".into(),
        },
        include_child_processes: false,
    });
    let ip = rule(
        "S3",
        AddressMatchDto::ExactIpv4 {
            address: "192.0.2.1".into(),
        },
    );
    assert!(overlaps(&book(
        vec![zone("P1", "example")],
        vec![disabled, app_scoped, ip]
    ))
    .is_empty());
}

#[test]
fn a_label_ending_in_the_parent_text_is_not_below_it() {
    assert!(overlaps(&book(
        vec![suffix("P1", "example.test")],
        vec![exact("S1", "notexample.test")]
    ))
    .is_empty());
}

#[test]
fn values_not_yet_canonical_on_screen_still_pair() {
    let found = overlaps(&book(
        vec![zone("P1", ".Example")],
        vec![exact("S1", "WWW.Site.Example.")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].winner.value, "WWW.Site.Example.",
        "shown as written"
    );
}

#[test]
fn each_pair_is_reported_once_with_a_key_naming_both_routes() {
    let found = overlaps(&book(
        vec![
            suffix("P1", "search.example"),
            exact("P2", "x.ai.search.example"),
        ],
        vec![suffix("S1", "ai.search.example")],
    ));
    assert_eq!(found.len(), 2, "{found:?}");
    let keys: std::collections::BTreeSet<_> = found.iter().map(|o| &o.key).collect();
    assert_eq!(keys.len(), 2);
    assert!(found
        .iter()
        .all(|o| o.key.contains("primary:") && o.key.contains("secondary:")));
}

fn blocking(mut rule: RuleDto) -> RuleDto {
    rule.action = RuleAction::Block;
    rule
}

#[test]
fn a_block_wins_a_tie_against_a_route_on_either_set() {
    for block_on_main in [true, false] {
        let block = blocking(exact("B1", "a.example"));
        let route = exact("R1", "a.example");
        let dto = if block_on_main {
            book(vec![block], vec![route])
        } else {
            book(vec![route], vec![block])
        };
        let found = overlaps(&dto);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].kind, RouteOverlapKind::Duplicate);
        assert_eq!(
            found[0].winner.rule_id, "B1",
            "block on main: {block_on_main}"
        );
        assert_eq!(found[0].loser.rule_id, "R1");
        assert!(found[0].block_wins_tie);
    }
}

#[test]
fn only_a_block_against_a_route_raises_the_tie_warning() {
    let routes = overlaps(&book(
        vec![exact("P1", "a.example")],
        vec![exact("S1", "a.example")],
    ));
    assert_eq!(routes[0].winner.rule_id, "P1");
    assert!(!routes[0].block_wins_tie);

    let blocks = overlaps(&book(
        vec![blocking(exact("P1", "a.example"))],
        vec![blocking(exact("S1", "a.example"))],
    ));
    assert!(!blocks[0].block_wins_tie);

    // A narrower route over a wider block is a plain nesting, no warning.
    let nested = overlaps(&book(
        vec![exact("P1", "a.example")],
        vec![blocking(zone("S1", "example"))],
    ));
    assert_eq!(nested[0].winner.rule_id, "P1");
    assert_eq!(nested[0].kind, RouteOverlapKind::Nested);
    assert!(!nested[0].block_wins_tie);
}

// ── address rules ─────────────────────────────────────────────────────────

fn ip(id: &str, address: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::ExactIpv4 {
            address: address.into(),
        },
    )
}

fn subnet(id: &str, network: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::Subnet {
            network: network.into(),
        },
    )
}

fn range(id: &str, first: &str, last: &str) -> RuleDto {
    rule(
        id,
        AddressMatchDto::IpRange {
            first: first.into(),
            last: last.into(),
        },
    )
}

#[test]
fn an_address_inside_the_other_routes_subnet_wins_over_it() {
    let found = overlaps(&book(
        vec![subnet("P1", "10.20.0.0/16")],
        vec![ip("S1", "10.20.3.4")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Nested);
    assert_eq!(found[0].winner.rule_id, "S1");
    assert_eq!(found[0].winner.rule_type, "exact-ip");
    assert_eq!(found[0].loser.rule_type, "subnet");
}

#[test]
fn the_longer_prefix_wins_and_disjoint_networks_are_not_paired() {
    let found = overlaps(&book(
        vec![subnet("P1", "10.0.0.0/8"), subnet("P2", "192.168.0.0/16")],
        vec![subnet("S1", "10.20.0.0/24")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].winner.rule_id, "S1");
    assert_eq!(found[0].loser.rule_id, "P1");
}

#[test]
fn the_same_network_on_both_routes_is_a_duplicate_the_main_route_wins() {
    let found = overlaps(&book(
        vec![subnet("P1", "10.20.0.0/24")],
        vec![range("S1", "10.20.0.0", "10.20.0.255")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Duplicate);
    assert_eq!(found[0].winner.rule_id, "P1");
}

#[test]
fn a_blocked_network_wins_a_tie() {
    let mut blocked = subnet("S1", "10.20.0.0/24");
    blocked.action = RuleAction::Block;
    let found = overlaps(&book(vec![subnet("P1", "10.20.0.0/24")], vec![blocked]));
    assert_eq!(found[0].winner.rule_id, "S1");
    assert!(found[0].block_wins_tie);
}

#[test]
fn ranges_that_share_part_of_their_addresses_intersect() {
    let found = overlaps(&book(
        vec![range("P1", "10.0.0.0", "10.0.0.99")],
        vec![range("S1", "10.0.0.50", "10.0.0.200")],
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, RouteOverlapKind::Intersecting);
}

#[test]
fn names_are_never_paired_with_addresses() {
    let found = overlaps(&book(
        vec![subnet("P1", "10.0.0.0/8")],
        vec![exact("S1", "host.example")],
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_main_address_inside_the_additional_network_stays_on_the_main_link() {
    for primary in [ip("P1", "10.20.3.4"), subnet("P1", "10.20.3.0/24")] {
        let found = overlaps(&book(vec![primary], vec![subnet("S1", "10.20.0.0/16")]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].winner.rule_id, "P1");
        assert!(found[0].main_stays_when_additional_down, "{found:?}");
    }
    let found = overlaps(&book(
        vec![ip("P1", "10.0.0.7")],
        vec![range("S1", "10.0.0.0", "10.0.0.99")],
    ));
    assert!(found[0].main_stays_when_additional_down, "{found:?}");
}

#[test]
fn the_note_is_only_for_a_main_address_inside_an_additional_network() {
    // The additional route's address inside the main route's network.
    let found = overlaps(&book(
        vec![subnet("P1", "10.20.0.0/16")],
        vec![ip("S1", "10.20.3.4")],
    ));
    assert!(!found[0].main_stays_when_additional_down, "{found:?}");
    // A blocked main address is not "staying" anywhere.
    let found = overlaps(&book(
        vec![blocking(ip("P1", "10.20.3.4"))],
        vec![subnet("S1", "10.20.0.0/16")],
    ));
    assert!(!found[0].main_stays_when_additional_down, "{found:?}");
    // The same network on both routes is a duplicate, not a nesting.
    let found = overlaps(&book(
        vec![subnet("P1", "10.20.0.0/24")],
        vec![subnet("S1", "10.20.0.0/24")],
    ));
    assert!(!found[0].main_stays_when_additional_down, "{found:?}");
    // Names carry no such note.
    let found = overlaps(&book(
        vec![exact("P1", "a.example")],
        vec![suffix("S1", "example")],
    ));
    assert!(!found[0].main_stays_when_additional_down, "{found:?}");
}

#[test]
fn an_older_overlap_without_the_note_still_reads() {
    let json = serde_json::json!({
        "key": "k", "kind": "nested",
        "winner": { "rule-id": "a", "route": "primary", "rule-type": "exact-ip", "value": "10.0.0.1" },
        "loser": { "rule-id": "b", "route": "secondary", "rule-type": "subnet", "value": "10.0.0.0/8" },
    });
    let overlap: RouteOverlap = serde_json::from_value(json).expect("older overlap");
    assert!(!overlap.main_stays_when_additional_down);
}

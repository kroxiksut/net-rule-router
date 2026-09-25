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

//! `name.*` — a site in every zone, and a rule naming the zone beats it.

#![allow(clippy::expect_used, clippy::panic)]

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::decision_engine_input::match_sample;
use nrr_domain::decision_matching::{
    match_any_zone_domain, RequestedRouteDecision, ZonePriorityPolicy,
};
use nrr_domain::preset_canonicalize::canonicalize_preset_rules;
use nrr_domain::rules_file::HostPlatform;
use nrr_domain::rules_file::{
    canonical_rule_set_to_rules_file_parsed, parse_rules_file, RulesFileSection,
};
use nrr_domain::{RouteBehaviorMode, RouteRole, RuleAction, RuleId};

fn rules(text: &str) -> CanonicalRuleSet {
    let parsed = parse_rules_file(text);
    canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false)
        .rule_set()
        .cloned()
        .unwrap_or_else(|| panic!("`{text}` refused"))
}

fn refused(text: &str) -> bool {
    let parsed = parse_rules_file(text);
    canonicalize_preset_rules(&parsed, RouteRole::Primary, HostPlatform::Windows, false)
        .rule_set()
        .is_none_or(|set| set.is_empty())
}

fn rule(id: &str, address: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: Some(address),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

fn any_zone(id: &str, base: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::AnyZoneDomain(base.into()))
}

fn suffix(id: &str, name: &str) -> CanonicalRule {
    rule(id, CanonicalAddressMatch::SuffixDomain(name.into()))
}

/// The route the engine picks for `host`, `None` for the default.
fn route_of(book: &CanonicalRuleBook, host: &str) -> Option<RouteRole> {
    match match_sample(
        book,
        Some(host),
        None,
        None,
        ZonePriorityPolicy::default(),
        RouteBehaviorMode::PreferPrimary,
    ) {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.route_role),
        RequestedRouteDecision::DefaultRoute { .. } => None,
    }
}

#[test]
fn both_spellings_read_as_one_rule_and_write_back_short() {
    for written in ["autodesk.*", "*.autodesk.*", "AutoDesk.*"] {
        let set = rules(&format!("--- Domains\n{written}\n"));
        assert_eq!(
            set.rules()[0].address_match,
            Some(CanonicalAddressMatch::AnyZoneDomain("autodesk".into())),
            "{written}"
        );
        let file = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(file.sections[0].entries[0].match_value, "autodesk.*");
    }
}

#[test]
fn a_bare_wildcard_is_not_a_site() {
    for written in ["*.*", ".*", "*", "auto*desk.*", "192.0.2.1.*"] {
        assert!(refused(&format!("--- Domains\n{written}\n")), "{written}");
    }
}

#[test]
fn the_zone_is_the_public_suffix_of_the_host() {
    let m = |host| match_any_zone_domain(host, "autodesk");
    assert_eq!(m("autodesk.com"), Some("autodesk.com"));
    assert_eq!(m("autodesk.net"), Some("autodesk.net"));
    assert_eq!(m("webpub.autodesk.com"), Some("autodesk.com"));
    assert_eq!(m("www.autodesk.co.uk"), Some("autodesk.co.uk"));
    assert_eq!(m("autodesk.com.attacker.net"), None);
    assert_eq!(m("autodesk.attacker.net"), None);
    assert_eq!(m("myautodesk.com"), None);
    assert_eq!(m("autodesk"), None);
    assert_eq!(m("co.uk"), None);
}

#[test]
fn a_rule_naming_the_zone_beats_the_any_zone_rule() {
    let rules = book(
        vec![suffix("p", "autodesk.by")],
        vec![any_zone("s", "autodesk")],
    );
    assert_eq!(route_of(&rules, "autodesk.by"), Some(RouteRole::Primary));
    assert_eq!(
        route_of(&rules, "www.autodesk.by"),
        Some(RouteRole::Primary)
    );
    assert_eq!(route_of(&rules, "autodesk.com"), Some(RouteRole::Secondary));
    assert_eq!(
        route_of(&rules, "cdn.autodesk.net"),
        Some(RouteRole::Secondary)
    );

    // The other way round too: the explicit rule wins whichever set holds it.
    let flipped = book(
        vec![any_zone("p", "autodesk")],
        vec![suffix("s", "autodesk.by")],
    );
    assert_eq!(
        route_of(&flipped, "autodesk.by"),
        Some(RouteRole::Secondary)
    );
    assert_eq!(route_of(&flipped, "autodesk.com"), Some(RouteRole::Primary));
}

#[test]
fn an_exact_rule_in_the_zone_wins_for_its_host_only() {
    let rules = book(
        vec![rule(
            "p",
            CanonicalAddressMatch::ExactFqdn("autodesk.by".into()),
        )],
        vec![any_zone("s", "autodesk")],
    );
    assert_eq!(route_of(&rules, "autodesk.by"), Some(RouteRole::Primary));
    assert_eq!(
        route_of(&rules, "www.autodesk.by"),
        Some(RouteRole::Secondary)
    );
    // Subdomain coverage gives the exact rule its `*.` twin, which names the
    // zone outright.
    let covered = rules.with_subdomain_coverage();
    assert_eq!(
        route_of(&covered, "www.autodesk.by"),
        Some(RouteRole::Primary)
    );
}

#[test]
fn the_longer_name_wins_between_any_zone_rules_and_over_zones() {
    let rules = book(
        vec![
            any_zone("p", "webpub.autodesk"),
            rule("z", CanonicalAddressMatch::Zone("com".into())),
        ],
        vec![any_zone("s", "autodesk")],
    );
    assert_eq!(
        route_of(&rules, "webpub.autodesk.com"),
        Some(RouteRole::Primary)
    );
    assert_eq!(
        route_of(&rules, "www.autodesk.com"),
        Some(RouteRole::Secondary)
    );
    assert_eq!(route_of(&rules, "other.com"), Some(RouteRole::Primary));
    // A wider suffix spelled with its zone is still the wider rule.
    let wide = book(vec![suffix("p", "com")], vec![any_zone("s", "autodesk")]);
    assert_eq!(route_of(&wide, "autodesk.com"), Some(RouteRole::Secondary));
}

#[test]
fn enforcement_sees_a_suffix_twin_per_zone_seen_except_one_named_outright() {
    let rules = book(
        vec![suffix("p", "autodesk.by")],
        vec![any_zone("s", "autodesk")],
    );
    let seen = |base: &str| {
        assert_eq!(base, "autodesk");
        vec![
            "autodesk.com".to_string(),
            "autodesk.by".to_string(),
            "autodesk.com".to_string(),
        ]
    };
    let expanded = rules.with_any_zone_sites(seen);
    let secondary: Vec<_> = expanded
        .secondary
        .rules()
        .iter()
        .filter_map(|r| r.address_match.clone())
        .collect();
    assert_eq!(
        secondary,
        [
            CanonicalAddressMatch::SuffixDomain("autodesk.com".into()),
            CanonicalAddressMatch::AnyZoneDomain("autodesk".into()),
        ]
    );
    assert_eq!(expanded.primary, rules.primary);
    // The twins decide exactly what the rule itself decides.
    for host in [
        "autodesk.com",
        "a.autodesk.com",
        "autodesk.by",
        "x.autodesk.by",
    ] {
        assert_eq!(route_of(&expanded, host), route_of(&rules, host), "{host}");
    }
    // A book without `name.*` rules is handed back untouched.
    let plain = book(vec![suffix("p", "example.com")], Vec::new());
    assert_eq!(plain.with_any_zone_sites(|_| panic!("not asked")), plain);
}

#[test]
fn a_companion_in_another_zone_of_the_same_site_names_that_site() {
    use nrr_domain::companion_affinity::site_shared_across_zones;
    assert_eq!(
        site_shared_across_zones("webpub.example.com", "example.net"),
        Some("example")
    );
    assert_eq!(
        site_shared_across_zones("www.example.co.uk", "cdn.example.com"),
        Some("example")
    );
    assert_eq!(
        site_shared_across_zones("example.com", "cdn.example.com"),
        None,
        "same zone"
    );
    assert_eq!(
        site_shared_across_zones("t.co", "t.me"),
        None,
        "too short to be one site"
    );
    assert_eq!(site_shared_across_zones("example.com", "other.net"), None);
    assert_eq!(site_shared_across_zones("localhost", "example.net"), None);
}

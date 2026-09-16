use super::*;

// ── canonical_rule_set_to_rules_file_parsed ──────────────────────────────

use crate::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleSet,
};
use crate::RuleId;
use std::net::{IpAddr, Ipv4Addr};

fn rule_with_app(
    id: &str,
    enabled: bool,
    pattern: CanonicalAppPattern,
    comment: &str,
) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern,
            include_child_processes: false,
        }),
        comment: comment.to_string(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

#[test]
fn canonical_to_rules_file_maps_exact_fqdn_to_domains() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections.len(), 1);
    assert_eq!(parsed.sections[0].section, RulesFileSection::Domains);
    assert_eq!(parsed.sections[0].entries[0].match_value, "example.com");
    assert!(parsed.sections[0].entries[0].enabled);
    assert!(parsed.sections[0].entries[0].inline_comment.is_none());
}

#[test]
fn canonical_to_rules_file_maps_suffix_domain_with_star_prefix() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::SuffixDomain("example.com".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections[0].entries[0].match_value, "*.example.com");
}

#[test]
fn canonical_to_rules_file_maps_zone_to_zones_section() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::Zone("ru".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections[0].section, RulesFileSection::Zones);
    assert_eq!(parsed.sections[0].entries[0].match_value, "ru");
}

#[test]
fn canonical_to_rules_file_maps_exact_ip_to_ip_section() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections[0].section, RulesFileSection::Ip);
    assert_eq!(parsed.sections[0].entries[0].match_value, "203.0.113.7");
}

#[test]
fn canonical_to_rules_file_maps_app_match_to_host_section() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_app(
        "r-1",
        true,
        CanonicalAppPattern::Exact("chrome.exe".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(parsed.sections[0].section, RulesFileSection::Windows);
    assert_eq!(parsed.sections[0].entries[0].match_value, "chrome.exe");
}

#[test]
fn canonical_to_rules_file_preserves_inline_comment() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
        "vendor updates",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert_eq!(
        parsed.sections[0].entries[0].inline_comment.as_deref(),
        Some("vendor updates")
    );
}

#[test]
fn canonical_to_rules_file_preserves_disabled_state() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        false,
        CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    assert!(!parsed.sections[0].entries[0].enabled);
}

#[test]
fn canonical_to_rules_file_emits_sections_in_canonical_order() {
    let set = CanonicalRuleSet::from_rules(vec![
        rule_with_app(
            "r-1",
            true,
            CanonicalAppPattern::Exact("chrome.exe".to_string()),
            "",
        ),
        rule_with_address(
            "r-2",
            true,
            CanonicalAddressMatch::Zone("ru".to_string()),
            "",
        ),
        rule_with_address(
            "r-3",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        ),
    ]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    let order: Vec<RulesFileSection> = parsed.sections.iter().map(|s| s.section).collect();
    // Canonical order: Zones → Domains → (IP omitted) → Windows.
    assert_eq!(
        order,
        vec![
            RulesFileSection::Zones,
            RulesFileSection::Domains,
            RulesFileSection::Windows,
        ]
    );
}

#[test]
fn canonical_to_rules_file_omits_empty_sections() {
    let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
        "r-1",
        true,
        CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
        "",
    )]);
    let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
    // Only Domains is present; Zones/IP/Windows are not emitted.
    assert_eq!(parsed.sections.len(), 1);
}

#[test]
fn canonical_to_rules_file_full_round_trip_via_writer() {
    // CanonicalRuleSet → RulesFileParsed → text → parse →
    // rules_file_to_route_rule_set → CanonicalRuleSet (via from_rules).
    let original_rules = vec![
        rule_with_address(
            "r-a",
            true,
            CanonicalAddressMatch::Zone("ru".to_string()),
            "",
        ),
        rule_with_address(
            "r-b",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        ),
        rule_with_address(
            "r-c",
            true,
            CanonicalAddressMatch::SuffixDomain("corp.example.net".to_string()),
            "all subdomains",
        ),
        rule_with_address(
            "r-d",
            false,
            CanonicalAddressMatch::ExactFqdn("old.example.com".to_string()),
            "decommissioned",
        ),
        rule_with_address(
            "r-e",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            "",
        ),
        rule_with_app(
            "r-f",
            true,
            CanonicalAppPattern::Exact("chrome.exe".to_string()),
            "",
        ),
    ];
    let original_set = CanonicalRuleSet::from_rules(original_rules);
    let parsed = canonical_rule_set_to_rules_file_parsed(&original_set, RulesFileSection::Windows);
    let written = write_rules_file(&parsed, &[], None);
    // Round-trip through the parser.
    let reparse = parse_rules_file(&written).parsed;
    let route_rule_set = rules_file_to_route_rule_set(&reparse, HostPlatform::Windows, false);
    // Build a CanonicalRuleSet from the round-tripped RouteRuleSet
    // by promoting each Rule into a CanonicalRule with the same
    // address_match / app_match / enabled / comment. Then compare
    // **the match-value content**, not the rule_ids (which the
    // parser regenerates).
    // Compare as sorted sets: file-order (Zones→Domains→IP→Windows)
    // differs from canonical-sort-order (ExactFqdn→SuffixDomain→Zone→
    // ExactIp→Application), so element-by-element equality is the
    // wrong invariant. Sorted-vec equality captures the round-trip
    // guarantee.
    let mut written_values: Vec<(bool, Option<String>, Option<String>, String)> = route_rule_set
        .rules
        .iter()
        .map(|r| {
            (
                r.enabled,
                r.address_match.as_ref().map(|a| match a {
                    crate::AddressMatch::ExactFqdn(s)
                    | crate::AddressMatch::SuffixDomain(s)
                    | crate::AddressMatch::Zone(s) => s.clone(),
                    crate::AddressMatch::ExactIp(ip) => ip.to_string(),
                }),
                r.app_match.as_ref().map(|app| match &app.pattern {
                    crate::AppMatchPattern::Exact(s) | crate::AppMatchPattern::Glob(s) => s.clone(),
                }),
                r.comment.clone(),
            )
        })
        .collect();
    let mut original_values: Vec<(bool, Option<String>, Option<String>, String)> = original_set
        .rules()
        .iter()
        .map(|r| {
            (
                r.enabled,
                r.address_match.as_ref().map(|a| match a {
                    CanonicalAddressMatch::ExactFqdn(s)
                    | CanonicalAddressMatch::SuffixDomain(s)
                    | CanonicalAddressMatch::Zone(s) => s.clone(),
                    CanonicalAddressMatch::ExactIp(ip) => ip.to_string(),
                }),
                r.app_match.as_ref().map(|app| match &app.pattern {
                    CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
                }),
                r.comment.clone(),
            )
        })
        .collect();
    written_values.sort();
    original_values.sort();
    assert_eq!(
        written_values, original_values,
        "round-trip values diverged (set comparison):\nwritten=\n{written}"
    );
}

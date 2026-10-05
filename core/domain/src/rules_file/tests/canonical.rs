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
                    | crate::AddressMatch::Zone(s)
                    | crate::AddressMatch::ExactIp(s)
                    | crate::AddressMatch::Subnet(s)
                    | crate::AddressMatch::IpRange(s) => s.clone(),
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
                    other => other.to_display_string(),
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

/// Networks and ranges travel through their own sections and come back out of
/// them, canonical.
#[test]
fn network_sections_round_trip_through_the_canonical_set() {
    let input = "--- CIDR\n10.0.2.7/24\n2001:db8::/32  # lab\n--- Ranges\n10.0.0.5 - 10.0.0.40\n";
    let set = canonical_set(input);
    let written = write_rules_file(
        &canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows),
        &[],
        None,
    );
    assert!(
        written.contains("--- CIDR\n10.0.2.0/24\n2001:db8::/32"),
        "{written}"
    );
    assert!(
        written.contains("--- Ranges\n10.0.0.5-10.0.0.40\n"),
        "{written}"
    );
    assert_eq!(canonical_set(&written), set);
}

/// Section is type: a network under `--- IP` is a line error naming the
/// section it belongs in, never silently re-filed.
#[test]
fn a_value_under_the_wrong_network_heading_is_refused_with_the_right_one() {
    use crate::ip_network_policy::IpValueKind;
    use crate::validation::ValidationError;
    for (input, belongs_in) in [
        ("--- IP\n10.0.0.0/8\n", IpValueKind::Subnet),
        ("--- IP\n10.0.0.1-10.0.0.9\n", IpValueKind::Range),
        ("--- CIDR\n10.0.0.1\n", IpValueKind::Address),
        ("--- Ranges\n10.0.0.0/24\n", IpValueKind::Subnet),
    ] {
        let errors = canonical_errors(input);
        assert!(
            matches!(
                errors.as_slice(),
                [ValidationError::WrongAddressSection { belongs_in: b, .. }] if *b == belongs_in
            ),
            "{input:?}: {errors:?}"
        );
    }
}

fn canonicalized(input: &str) -> crate::preset_canonicalize::PresetRulesCanonicalizeOutcome {
    crate::preset_canonicalize::canonicalize_preset_rules(
        &parse_rules_file(input),
        nrr_shared::RouteRole::Primary,
        HostPlatform::Windows,
        false,
    )
}

fn canonical_set(input: &str) -> CanonicalRuleSet {
    canonicalized(input)
        .rule_set()
        .cloned()
        .unwrap_or_else(|| panic!("{input:?} must be accepted"))
}

fn canonical_errors(input: &str) -> Vec<crate::validation::ValidationError> {
    match canonicalized(input) {
        crate::preset_canonicalize::PresetRulesCanonicalizeOutcome::Rejected { errors } => errors,
        other => panic!("{input:?} accepted as {other:?}"),
    }
}

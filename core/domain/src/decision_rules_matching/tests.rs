use std::net::{IpAddr, Ipv4Addr};

use nrr_shared::{RouteBehaviorMode, RouteRole};

use super::*;
use crate::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, CanonicalRuleSet,
};
use crate::decision_engine_input::normalize_runtime_input;
use crate::decision_engine_input::test_support::{empty_lookup, runtime_input_for};
use crate::decision_lookup::{
    CacheEntryState, LookupExplainData, LookupExtendedMetadata, LookupResult, LookupSource,
    LookupStandardSignals, ResolvedAddressEntry,
};
use crate::decision_matching::{
    ConflictMarker, MatchClass, NoMatchReason, RequestedRouteDecision, SpecificityScore,
    ZonePriorityPolicy,
};
use crate::RuleId;

// ── Test helpers ──────────────────────────────────────────────────────────

fn rule(
    id: &str,
    addr: Option<CanonicalAddressMatch>,
    app: Option<CanonicalAppMatch>,
) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_owned()),
        enabled: true,
        address_match: addr,
        app_match: app,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

fn disabled_rule(id: &str, addr: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_owned()),
        enabled: false,
        address_match: Some(addr),
        app_match: None,
        comment: String::new(),
        action: crate::canonical::RuleAction::Route,
        origin: None,
    }
}

fn exact_fqdn(label: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::ExactFqdn(label.to_owned())
}

fn suffix_domain(label: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::SuffixDomain(label.to_owned())
}

fn zone(name: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::Zone(name.to_owned())
}

fn exact_ip(a: u8, b: u8, c: u8, d: u8) -> CanonicalAddressMatch {
    CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

fn app_exact(name: &str) -> CanonicalAppMatch {
    CanonicalAppMatch {
        pattern: CanonicalAppPattern::Exact(name.to_owned()),
        include_child_processes: false,
    }
}

fn app_glob(pattern: &str) -> CanonicalAppMatch {
    CanonicalAppMatch {
        pattern: CanonicalAppPattern::Glob(pattern.to_owned()),
        include_child_processes: false,
    }
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

fn input_hostname(hostname: &str) -> NormalizedDecisionInput {
    normalize_runtime_input(&runtime_input_for(hostname, None, None))
}

fn input_ip(ip: Ipv4Addr) -> NormalizedDecisionInput {
    normalize_runtime_input(&runtime_input_for("", Some(IpAddr::V4(ip)), None))
}

fn input_full(hostname: &str, ip: Ipv4Addr, process: &str) -> NormalizedDecisionInput {
    normalize_runtime_input(&runtime_input_for(
        hostname,
        Some(IpAddr::V4(ip)),
        Some(process),
    ))
}

fn lookup_fresh_ip(a: u8, b: u8, c: u8, d: u8) -> LookupResult {
    LookupResult {
        selected_ip: Some(ResolvedAddressEntry {
            addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            cache_state: CacheEntryState::Fresh,
            source: LookupSource::CacheHit,
            resolved_at: None,
            ttl_seconds: None,
        }),
        is_multi_ip: false,
        explain_data: LookupExplainData {
            standard: LookupStandardSignals {
                cache_hit: true,
                freshness: Some(CacheEntryState::Fresh),
                source: Some(LookupSource::CacheHit),
                errors: vec![],
            },
            extended: LookupExtendedMetadata {
                all_resolved_ips: vec![],
                selected_entry_ttl_secs: None,
                selected_entry_resolved_at: None,
            },
        },
    }
}

fn lookup_stale_not_usable() -> LookupResult {
    LookupResult {
        selected_ip: Some(ResolvedAddressEntry {
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)),
            cache_state: CacheEntryState::StaleNotUsable,
            source: LookupSource::CacheHit,
            resolved_at: None,
            ttl_seconds: None,
        }),
        is_multi_ip: false,
        explain_data: LookupExplainData {
            standard: LookupStandardSignals {
                cache_hit: true,
                freshness: Some(CacheEntryState::StaleNotUsable),
                source: Some(LookupSource::CacheHit),
                errors: vec![],
            },
            extended: LookupExtendedMetadata {
                all_resolved_ips: vec![],
                selected_entry_ttl_secs: None,
                selected_entry_resolved_at: None,
            },
        },
    }
}

fn prefer_primary() -> RouteBehaviorMode {
    RouteBehaviorMode::PreferPrimary
}
fn default_zone_policy() -> ZonePriorityPolicy {
    ZonePriorityPolicy::default()
}

fn matched_class(decision: &RequestedRouteDecision) -> Option<MatchClass> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.match_class),
        _ => None,
    }
}

fn matched_role(decision: &RequestedRouteDecision) -> Option<RouteRole> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.route_role),
        _ => None,
    }
}

fn matched_rule_id(decision: &RequestedRouteDecision) -> Option<&str> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.rule_id.as_str()),
        _ => None,
    }
}

fn matched_specificity(decision: &RequestedRouteDecision) -> Option<SpecificityScore> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.specificity),
        _ => None,
    }
}

fn matched_conflict(decision: &RequestedRouteDecision) -> Option<ConflictMarker> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.conflict),
        _ => None,
    }
}

// ── app_pattern_matches (glob) ───────────────────────────────────────────

fn glob_names(pattern: &str, process: &str) -> bool {
    app_pattern_matches(&CanonicalAppPattern::Glob(pattern.to_owned()), process)
}

#[test]
fn glob_exact_no_wildcard() {
    assert!(glob_names("chrome.exe", "chrome.exe"));
    assert!(!glob_names("chrome.exe", "firefox.exe"));
}

#[test]
fn glob_star_prefix() {
    assert!(glob_names("*vpn*.exe", "foovpnbar.exe"));
    assert!(glob_names("*vpn*.exe", "vpn.exe"));
    assert!(!glob_names("*vpn*.exe", "chrome.exe"));
}

#[test]
fn glob_star_suffix() {
    assert!(glob_names("chrome*", "chrome.exe"));
    assert!(glob_names("chrome*", "chrome"));
    assert!(!glob_names("chrome*", "firefox.exe"));
}

#[test]
fn glob_star_only_matches_everything() {
    assert!(glob_names("*", ""));
    assert!(glob_names("*", "anything.exe"));
}

#[test]
fn glob_multiple_stars() {
    assert!(glob_names("*foo*bar*", "xfooyybarz"));
    assert!(!glob_names("*foo*bar*", "xfoobaz"));
}

#[test]
fn glob_question_mark_is_a_literal_to_the_rule_engine() {
    assert!(glob_names("vk?*", "vk?x.exe"));
    assert!(!glob_names("vk?*", "vk1x.exe"));
}

#[test]
fn glob_pathological_pattern_returns_promptly() {
    let pattern = format!("{}b.exe", "*a".repeat(60));
    let started = std::time::Instant::now();
    assert!(!glob_names(&pattern, &"a".repeat(250)));
    assert!(started.elapsed() < std::time::Duration::from_millis(100));
}

// ── Tier 1: ExactFqdn ─────────────────────────────────────────────────────

#[test]
fn exact_fqdn_primary_matches() {
    let rb = book(
        vec![rule("r1", Some(exact_fqdn("example.com")), None)],
        vec![],
    );
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
    assert_eq!(matched_rule_id(&d), Some("r1"));
}

#[test]
fn exact_fqdn_secondary_matches() {
    let rb = book(vec![], vec![rule("r1", Some(exact_fqdn("api.corp")), None)]);
    let input = input_hostname("api.corp");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_role(&d), Some(RouteRole::Secondary));
}

#[test]
fn exact_fqdn_no_match_for_subdomain() {
    // ExactFqdn("example.com") must NOT match "sub.example.com"
    let rb = book(
        vec![rule("r1", Some(exact_fqdn("example.com")), None)],
        vec![],
    );
    let input = input_hostname("sub.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

#[test]
fn exact_fqdn_specificity_is_label_count() {
    let rb = book(
        vec![rule("r1", Some(exact_fqdn("mail.example.com")), None)],
        vec![],
    );
    let input = input_hostname("mail.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_specificity(&d), Some(SpecificityScore(3)));
}

// ── Tier 2: SuffixDomain ──────────────────────────────────────────────────

#[test]
fn suffix_domain_matches_subdomain() {
    let rb = book(
        vec![rule("r1", Some(suffix_domain("example.com")), None)],
        vec![],
    );
    let input = input_hostname("sub.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::SuffixDomain));
}

#[test]
fn suffix_domain_matches_deep_subdomain() {
    let rb = book(
        vec![rule("r1", Some(suffix_domain("example.com")), None)],
        vec![],
    );
    let input = input_hostname("a.b.c.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::SuffixDomain));
}

#[test]
fn suffix_domain_matches_apex() {
    // `*.example.com` covers "example.com" itself, not just subdomains —
    // see the apex-coverage rationale on `match_suffix_domain`.
    let rb = book(
        vec![rule("r1", Some(suffix_domain("example.com")), None)],
        vec![],
    );
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::SuffixDomain));
    assert_eq!(matched_rule_id(&d), Some("r1"));
}

#[test]
fn suffix_domain_apex_does_not_leak_across_the_label_boundary() {
    // "notexample.com" shares the tail but not the label boundary.
    let rb = book(
        vec![rule("r1", Some(suffix_domain("example.com")), None)],
        vec![],
    );
    let input = input_hostname("notexample.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

#[test]
fn suffix_domain_at_depth_covers_its_own_apex_only() {
    // A multi-label suffix `*.sub.example.com` covers the apex of THAT
    // suffix and anything under it — never its parent or a sibling.
    let rb = book(
        vec![rule("r1", Some(suffix_domain("sub.example.com")), None)],
        vec![],
    );
    for covered in [
        "sub.example.com",
        "a.sub.example.com",
        "x.y.sub.example.com",
    ] {
        let d = match_rules(
            &input_hostname(covered),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert_eq!(
            matched_class(&d),
            Some(MatchClass::SuffixDomain),
            "{covered} must be covered by *.sub.example.com"
        );
    }
    for uncovered in ["example.com", "other.example.com", "notsub.example.com"] {
        let d = match_rules(
            &input_hostname(uncovered),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert!(
            matches!(d, RequestedRouteDecision::DefaultRoute { .. }),
            "{uncovered} must NOT be covered by *.sub.example.com"
        );
    }
}

#[test]
fn suffix_domain_longest_wins_when_the_longer_one_matches_via_its_apex() {
    // The regression this guards: "sub.example.com" is now matched by BOTH
    // `*.example.com` (as a subdomain) and `*.sub.example.com` (as its
    // apex). Apex coverage must not demote the more specific rule — the
    // specificity score is still the suffix's label count, so the longer
    // suffix wins regardless of which way it matched. Getting this wrong
    // would route a host by the broader rule and be invisible in the GUI.
    let rb = book(
        vec![rule("r-short", Some(suffix_domain("example.com")), None)],
        vec![rule("r-long", Some(suffix_domain("sub.example.com")), None)],
    );
    let d = match_rules(
        &input_hostname("sub.example.com"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-long"));
    assert_eq!(matched_role(&d), Some(RouteRole::Secondary));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore(3)));
}

#[test]
fn exact_fqdn_on_the_apex_beats_both_suffix_rules() {
    // "subdomains here, apex elsewhere" stays expressible: the exact rule
    // is tier 1 and wins over every SuffixDomain candidate, however deep.
    let rb = book(
        vec![rule("r-exact", Some(exact_fqdn("sub.example.com")), None)],
        vec![
            rule("r-short", Some(suffix_domain("example.com")), None),
            rule("r-long", Some(suffix_domain("sub.example.com")), None),
        ],
    );
    let d = match_rules(
        &input_hostname("sub.example.com"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
    assert_eq!(matched_rule_id(&d), Some("r-exact"));
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
}

#[test]
fn exact_fqdn_on_the_apex_wins_over_the_suffix_rule_covering_it() {
    // The escape hatch for the apex itself: `*.example.com` on secondary,
    // `example.com` exact on primary → the apex takes the primary route.
    let rb = book(
        vec![rule("r-exact", Some(exact_fqdn("example.com")), None)],
        vec![rule("r-suffix", Some(suffix_domain("example.com")), None)],
    );
    let d = match_rules(
        &input_hostname("example.com"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
}

#[test]
fn zone_rule_still_does_not_match_the_bare_zone_label() {
    // Zone semantics are deliberately unchanged by apex coverage: a rule on
    // the zone `intra` must not match the bare host "intra".
    let rb = book(vec![rule("r1", Some(zone("intra")), None)], vec![]);
    let d = match_rules(
        &input_hostname("intra"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
    // …while a host inside the zone still matches.
    let d = match_rules(
        &input_hostname("host.intra"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Zone));
}

/// The same traffic named on both routes is the user's own ambiguity — but
/// the answer must still be the one the service will enforce, and there the
/// main route's weight band wins. Before this it was whichever rule id
/// sorted first, so the probe could promise the additional route for a
/// connection the service sends down the main one.
#[test]
fn a_tie_between_the_two_routes_goes_to_the_main_one_and_is_marked() {
    let rb = book(
        vec![rule("z-primary", Some(zone("intra")), None)],
        vec![rule("a-secondary", Some(zone("intra")), None)],
    );
    let d = match_rules(
        &input_hostname("host.intra"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
    assert_eq!(matched_rule_id(&d), Some("z-primary"));
    assert_eq!(
        matched_conflict(&d),
        Some(ConflictMarker::Detected),
        "naming the same traffic twice is still reported"
    );
}

/// A rule naming the address the connection ACTUALLY goes to must apply,
/// even when the cache remembers a different one for the same host. The
/// two disagree routinely — CDN rotation, an entry that is stale but still
/// "usable" — and before this the cached address silently won, so the rule
/// the user wrote for the live address did nothing.
#[test]
fn a_rule_on_the_observed_address_matches_even_when_the_cache_says_another() {
    let rb = book(
        vec![rule(
            "r-observed",
            Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
                203, 0, 113, 9,
            )))),
            None,
        )],
        vec![],
    );
    let input = input_full("example.com", Ipv4Addr::new(203, 0, 113, 9), "curl");
    // The cache holds a DIFFERENT, perfectly fresh address for that host.
    let d = match_rules(
        &input,
        &lookup_fresh_ip(192, 0, 2, 4),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactIp));
    assert_eq!(matched_rule_id(&d), Some("r-observed"));

    // And the cached address still matches its own rule, unchanged.
    let rb = book(
        vec![rule(
            "r-cached",
            Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 4,
            )))),
            None,
        )],
        vec![],
    );
    let d = match_rules(
        &input,
        &lookup_fresh_ip(192, 0, 2, 4),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-cached"));
}

/// The product rule is that the narrower rule wins. Two zones over the same
/// host are the one place that could not express it: every zone scored the
/// same, so the winner fell to whichever `rule_id` sorted first — and
/// `intra` could take traffic the user had assigned to `corp.intra`.
#[test]
fn the_narrower_zone_wins_over_the_wider_one_it_sits_inside() {
    // `z-wide` sorts BEFORE `a-narrow`? No — deliberately the other way
    // round, so a lexicographic tie-break would pick the wide one and the
    // test would fail for the reason it exists.
    let rb = book(
        vec![
            rule("a-wide", Some(zone("intra")), None),
            rule("z-narrow", Some(zone("corp.intra")), None),
        ],
        vec![],
    );
    let d = match_rules(
        &input_hostname("db.corp.intra"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Zone));
    assert_eq!(
        matched_rule_id(&d),
        Some("z-narrow"),
        "the more specific zone must win regardless of rule id order"
    );

    // A host outside the narrow zone still belongs to the wide one.
    let d = match_rules(
        &input_hostname("db.other.intra"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("a-wide"));
}

#[test]
fn suffix_domain_apex_matching_is_case_and_trailing_dot_insensitive() {
    // Normalisation happens before matching; apex coverage must ride on the
    // same normalised form as subdomain coverage.
    let rb = book(
        vec![rule("r1", Some(suffix_domain("example.com")), None)],
        vec![],
    );
    for raw in ["EXAMPLE.COM", "Example.Com.", "example.com."] {
        let d = match_rules(
            &input_hostname(raw),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert_eq!(
            matched_class(&d),
            Some(MatchClass::SuffixDomain),
            "{raw} must normalise onto the apex"
        );
    }
}

#[test]
fn suffix_domain_apex_matching_works_on_punycode_labels() {
    // IDN rules are stored punycode-encoded; the apex is matched on that
    // same encoded form, exactly like subdomains.
    let rb = book(
        vec![rule(
            "r1",
            Some(suffix_domain("xn--e1afmkfd.xn--p1ai")),
            None,
        )],
        vec![],
    );
    for host in ["xn--e1afmkfd.xn--p1ai", "www.xn--e1afmkfd.xn--p1ai"] {
        let d = match_rules(
            &input_hostname(host),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert_eq!(matched_class(&d), Some(MatchClass::SuffixDomain), "{host}");
    }
}

#[test]
fn suffix_domain_longest_wins() {
    // "sub.example.com" matches both "example.com" (2 labels) and "sub.example.com" (3 labels)
    let rb = book(
        vec![
            rule("r-short", Some(suffix_domain("example.com")), None),
            rule("r-long", Some(suffix_domain("sub.example.com")), None),
        ],
        vec![],
    );
    let input = input_hostname("a.sub.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    // "sub.example.com" has more labels → wins
    assert_eq!(matched_rule_id(&d), Some("r-long"));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore(3)));
}

// ── ExactFqdn beats SuffixDomain ─────────────────────────────────────────

#[test]
fn exact_fqdn_beats_suffix_domain_for_same_hostname() {
    let rb = book(
        vec![
            rule("r-fqdn", Some(exact_fqdn("api.example.com")), None),
            rule("r-suffix", Some(suffix_domain("example.com")), None),
        ],
        vec![],
    );
    let input = input_hostname("api.example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
    assert_eq!(matched_rule_id(&d), Some("r-fqdn"));
}

// ── Tier 3a: ExactIp ──────────────────────────────────────────────────────

#[test]
fn exact_ip_matches_observed_ip() {
    let rb = book(vec![rule("r1", Some(exact_ip(192, 0, 2, 4)), None)], vec![]);
    let input = input_ip(Ipv4Addr::new(192, 0, 2, 4));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactIp));
}

#[test]
fn exact_ip_uses_lookup_over_observed_ip() {
    // Observed IP = 192.0.2.4 but lookup resolved 198.51.100.8 → rule for 198.51.100.8 wins
    let rb = book(
        vec![
            rule("r-obs", Some(exact_ip(192, 0, 2, 4)), None),
            rule("r-lookup", Some(exact_ip(198, 51, 100, 8)), None),
        ],
        vec![],
    );
    let input = input_ip(Ipv4Addr::new(192, 0, 2, 4));
    let lookup = lookup_fresh_ip(198, 51, 100, 8);
    let d = match_rules(
        &input,
        &lookup,
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-lookup"));
}

#[test]
fn exact_ip_falls_back_to_observed_when_lookup_stale_not_usable() {
    let rb = book(vec![rule("r1", Some(exact_ip(192, 0, 2, 4)), None)], vec![]);
    let input = input_ip(Ipv4Addr::new(192, 0, 2, 4));
    let lookup = lookup_stale_not_usable(); // stale-not-usable → ignored
    let d = match_rules(
        &input,
        &lookup,
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r1"));
}

#[test]
fn exact_ip_no_match_different_ip() {
    let rb = book(
        vec![rule("r1", Some(exact_ip(203, 0, 113, 9)), None)],
        vec![],
    );
    let input = input_ip(Ipv4Addr::new(192, 0, 2, 4));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

// ── Tier 3b: Zone ────────────────────────────────────────────────────────

#[test]
fn zone_matches_hostname() {
    let rb = book(vec![rule("r1", Some(zone("ru")), None)], vec![]);
    let input = input_hostname("example.ru");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    // Default policy: ExactIp first, then Zone. No IP rule → falls through to Zone.
    assert_eq!(matched_class(&d), Some(MatchClass::Zone));
}

#[test]
fn zone_skipped_when_hostname_unavailable() {
    let rb = book(vec![rule("r1", Some(zone("ru")), None)], vec![]);
    // No hostname in input — only IP
    let input = input_ip(Ipv4Addr::new(192, 0, 2, 4));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

// ── ZonePriorityPolicy ────────────────────────────────────────────────────

#[test]
fn zone_policy_default_ip_beats_zone() {
    // Both ExactIp(192.0.2.4) and Zone("ru") rules present for hostname "example.ru"
    // Default policy (prefer_ip = true): ExactIp is evaluated first → wins
    let rb = book(
        vec![
            rule("r-ip", Some(exact_ip(192, 0, 2, 4)), None),
            rule("r-zone", Some(zone("ru")), None),
        ],
        vec![],
    );
    let input = input_full("example.ru", Ipv4Addr::new(192, 0, 2, 4), "chrome.exe");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactIp));
    assert_eq!(matched_rule_id(&d), Some("r-ip"));
}

#[test]
fn zone_policy_prefer_zone_beats_ip() {
    let rb = book(
        vec![
            rule("r-ip", Some(exact_ip(192, 0, 2, 4)), None),
            rule("r-zone", Some(zone("ru")), None),
        ],
        vec![],
    );
    let input = input_full("example.ru", Ipv4Addr::new(192, 0, 2, 4), "chrome.exe");
    let zone_first = ZonePriorityPolicy { prefer_ip: false };
    let d = match_rules(&input, &empty_lookup(), &rb, zone_first, prefer_primary());
    assert_eq!(matched_class(&d), Some(MatchClass::Zone));
    assert_eq!(matched_rule_id(&d), Some("r-zone"));
}

// ── Tier 4: Application ───────────────────────────────────────────────────

#[test]
fn application_exact_match() {
    let rb = book(
        vec![rule("r1", None, Some(app_exact("firefox.exe")))],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Application));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore::APP_EXACT));
}

#[test]
fn application_glob_match() {
    let rb = book(vec![rule("r1", None, Some(app_glob("*vpn*.exe")))], vec![]);
    let input = normalize_runtime_input(&runtime_input_for(
        "example.com",
        None,
        Some("myvpnclient.exe"),
    ));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Application));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore::APP_GLOB));
}

/// The observed name always carries `.exe`; a glob never gets one added.
#[test]
fn a_glob_without_the_suffix_still_names_the_process() {
    let rb = book(vec![rule("r1", None, Some(app_glob("*torrent")))], vec![]);
    let input = normalize_runtime_input(&runtime_input_for(
        "example.com",
        None,
        Some("exampletorrent.exe"),
    ));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Application));
}

/// A Linux process has no suffix; a rule may still be stored with one.
#[test]
fn an_exact_rule_matches_a_process_spelled_without_the_suffix() {
    let rb = book(
        vec![rule("r1", None, Some(app_exact("firefox.exe")))],
        vec![],
    );
    let input = normalize_runtime_input(&runtime_input_for(
        "example.com",
        None,
        Some("/usr/bin/firefox"),
    ));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Application));
}

#[test]
fn application_exact_beats_glob() {
    let rb = book(
        vec![
            rule("r-glob", None, Some(app_glob("chrome*"))),
            rule("r-exact", None, Some(app_exact("chrome.exe"))),
        ],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("chrome.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-exact"));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore::APP_EXACT));
}

#[test]
fn application_skipped_when_address_rule_matched() {
    // ExactFqdn rule matches → application rule must NOT override it
    let rb = book(
        vec![
            rule("r-fqdn", Some(exact_fqdn("example.com")), None),
            rule("r-app", None, Some(app_exact("firefox.exe"))),
        ],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
    assert_eq!(matched_rule_id(&d), Some("r-fqdn"));
}

#[test]
fn application_not_matched_falls_to_default() {
    let rb = book(
        vec![rule("r1", None, Some(app_exact("notepad.exe")))],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

// ── App filter on address rules (AND semantics) ───────────────────────────

#[test]
fn address_rule_with_app_filter_both_must_match() {
    let rb = book(
        vec![rule(
            "r1",
            Some(exact_fqdn("example.com")),
            Some(app_exact("firefox.exe")),
        )],
        vec![],
    );
    // Address matches, app doesn't → no match
    let wrong_app =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("chrome.exe")));
    let d = match_rules(
        &wrong_app,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

#[test]
fn address_rule_with_app_filter_both_match() {
    let rb = book(
        vec![rule(
            "r1",
            Some(exact_fqdn("example.com")),
            Some(app_exact("firefox.exe")),
        )],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
}

// ── Disabled rules ────────────────────────────────────────────────────────

#[test]
fn disabled_rule_is_skipped() {
    let rb = book(vec![disabled_rule("r1", exact_fqdn("example.com"))], vec![]);
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(d, RequestedRouteDecision::DefaultRoute { .. }));
}

// ── Default route variants ────────────────────────────────────────────────

#[test]
fn default_empty_rule_book() {
    let rb = book(vec![], vec![]);
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(
        d,
        RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::EmptyRuleBook,
            ..
        }
    ));
}

#[test]
fn default_no_match_found() {
    let rb = book(
        vec![rule("r1", Some(exact_fqdn("other.com")), None)],
        vec![],
    );
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(
        d,
        RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::NoMatchFound,
            ..
        }
    ));
}

#[test]
fn default_carries_behavior_mode() {
    let rb = book(vec![], vec![]);
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        RouteBehaviorMode::StrictSecondaryFailClosed,
    );
    if let RequestedRouteDecision::DefaultRoute { behavior_mode, .. } = d {
        assert_eq!(behavior_mode, RouteBehaviorMode::StrictSecondaryFailClosed);
    } else {
        panic!("expected DefaultRoute");
    }
}

// ── Conflict detection ────────────────────────────────────────────────────

#[test]
fn conflict_detected_same_specificity_different_roles() {
    // Two ExactFqdn rules with identical hostname — one primary, one secondary
    let rb = book(
        vec![rule("r-pri", Some(exact_fqdn("example.com")), None)],
        vec![rule("r-sec", Some(exact_fqdn("example.com")), None)],
    );
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_conflict(&d), Some(ConflictMarker::Detected));
}

#[test]
fn no_conflict_when_same_role() {
    // Two ExactFqdn rules for same hostname, both primary — tie-break by rule_id, no conflict
    let rb = book(
        vec![
            rule("r-a", Some(exact_fqdn("example.com")), None),
            rule("r-b", Some(exact_fqdn("example.com")), None),
        ],
        vec![],
    );
    let input = input_hostname("example.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    // Both primary → no conflict; "r-a" wins (lexicographically smaller)
    assert_eq!(matched_conflict(&d), Some(ConflictMarker::None));
    assert_eq!(matched_rule_id(&d), Some("r-a"));
}

#[test]
fn conflict_winner_is_primary_rule_when_tied() {
    // Conflict scenario: primary rule wins (lower rule_id wins the tie)
    let rb = book(
        vec![rule("r-aaa", Some(exact_fqdn("conflict.com")), None)],
        vec![rule("r-zzz", Some(exact_fqdn("conflict.com")), None)],
    );
    let input = input_hostname("conflict.com");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_conflict(&d), Some(ConflictMarker::Detected));
    // "r-aaa" < "r-zzz" lexicographically → "r-aaa" (primary) wins
    assert_eq!(matched_rule_id(&d), Some("r-aaa"));
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
}

// ── Tier precedence chain ─────────────────────────────────────────────────

#[test]
fn exact_fqdn_beats_zone() {
    let rb = book(
        vec![
            rule("r-fqdn", Some(exact_fqdn("api.corp.ru")), None),
            rule("r-zone", Some(zone("ru")), None),
        ],
        vec![],
    );
    let input = input_hostname("api.corp.ru");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::ExactFqdn));
}

#[test]
fn suffix_domain_beats_zone() {
    let rb = book(
        vec![
            rule("r-suffix", Some(suffix_domain("corp.ru")), None),
            rule("r-zone", Some(zone("ru")), None),
        ],
        vec![],
    );
    let input = input_hostname("api.corp.ru");
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::SuffixDomain));
}

#[test]
fn address_tier_beats_application() {
    let rb = book(
        vec![
            rule("r-zone", Some(zone("ru")), None),
            rule("r-app", None, Some(app_exact("firefox.exe"))),
        ],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.ru", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_class(&d), Some(MatchClass::Zone));
}

// ── select_winner with all ineligible ─────────────────────────────────────

#[test]
fn address_and_app_filter_discard_both_falls_to_default() {
    // ExactFqdn rule matches address but not app → ineligible → falls to default
    let rb = book(
        vec![rule(
            "r1",
            Some(exact_fqdn("example.com")),
            Some(app_exact("notepad.exe")),
        )],
        vec![],
    );
    let input =
        normalize_runtime_input(&runtime_input_for("example.com", None, Some("firefox.exe")));
    let d = match_rules(
        &input,
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert!(matches!(
        d,
        RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::NoMatchFound,
            ..
        }
    ));
}

// ── Block veto and Block-vs-route ties ────────────────────────────────────

fn blocking(id: &str, addr: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        action: crate::canonical::RuleAction::Block,
        ..rule(id, Some(addr), None)
    }
}

fn matched_action(decision: &RequestedRouteDecision) -> Option<crate::canonical::RuleAction> {
    match decision {
        RequestedRouteDecision::MatchedRoute { candidate } => Some(candidate.action),
        RequestedRouteDecision::DefaultRoute { .. } => None,
    }
}

/// A literal-IP Block drops the address in enforcement whatever name rule a
/// tenant of it carries, so the engine must not answer "routed" for it.
#[test]
fn a_literal_ip_block_vetoes_a_narrower_name_rule_on_either_set() {
    for block_on_main in [true, false] {
        let block = blocking("b-ip", exact_ip(192, 0, 2, 10));
        let route = rule("r-exact", Some(exact_fqdn("a.example")), None);
        let rb = if block_on_main {
            book(vec![block], vec![route])
        } else {
            book(vec![route], vec![block])
        };
        let d = match_rules(
            &input_full("a.example", Ipv4Addr::new(192, 0, 2, 10), "curl.exe"),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert_eq!(
            matched_rule_id(&d),
            Some("b-ip"),
            "block on main: {block_on_main}"
        );
        assert_eq!(
            matched_action(&d),
            Some(crate::canonical::RuleAction::Block)
        );
        assert_eq!(matched_class(&d), Some(MatchClass::ExactIp));

        // Another address of the same host is not vetoed.
        let d = match_rules(
            &input_full("a.example", Ipv4Addr::new(192, 0, 2, 11), "curl.exe"),
            &empty_lookup(),
            &rb,
            default_zone_policy(),
            prefer_primary(),
        );
        assert_eq!(matched_rule_id(&d), Some("r-exact"));
    }
}

/// The veto is about Blocks only: a literal ROUTE on the address still waits
/// for its tier, so the narrower name rule keeps winning.
#[test]
fn a_literal_ip_route_does_not_jump_the_tier_order() {
    let rb = book(
        vec![rule("r-exact", Some(exact_fqdn("a.example")), None)],
        vec![rule("r-ip", Some(exact_ip(192, 0, 2, 10)), None)],
    );
    let d = match_rules(
        &input_full("a.example", Ipv4Addr::new(192, 0, 2, 10), "curl.exe"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-exact"));
}

/// A disabled literal Block vetoes nothing.
#[test]
fn a_disabled_literal_ip_block_does_not_veto() {
    let mut block = blocking("b-ip", exact_ip(192, 0, 2, 10));
    block.enabled = false;
    let rb = book(
        vec![rule("r-exact", Some(exact_fqdn("a.example")), None)],
        vec![block],
    );
    let d = match_rules(
        &input_full("a.example", Ipv4Addr::new(192, 0, 2, 10), "curl.exe"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-exact"));
}

/// A Block and a route of identical specificity: the Block wins on whichever
/// set either sits, as enforcement does.
#[test]
fn a_block_beats_a_route_of_equal_specificity_on_either_set() {
    let shapes = [
        (exact_fqdn("a.example"), "a.example"),
        (suffix_domain("a.example"), "x.a.example"),
        (zone("example"), "x.example"),
    ];
    for (addr, host) in shapes {
        for block_on_main in [true, false] {
            let block = blocking("b-1", addr.clone());
            let route = rule("r-1", Some(addr.clone()), None);
            let rb = if block_on_main {
                book(vec![block], vec![route])
            } else {
                book(vec![route], vec![block])
            };
            let d = match_rules(
                &input_hostname(host),
                &empty_lookup(),
                &rb,
                default_zone_policy(),
                prefer_primary(),
            );
            assert_eq!(
                matched_rule_id(&d),
                Some("b-1"),
                "{host}, block on main: {block_on_main}"
            );
            assert_eq!(
                matched_conflict(&d),
                Some(ConflictMarker::Detected),
                "{host}: the two sets still disagree"
            );
        }
    }
}

/// The tie-break does not lift a Block above a NARROWER route.
#[test]
fn a_narrower_route_still_beats_a_wider_block() {
    let rb = book(
        vec![rule("r-exact", Some(exact_fqdn("a.example")), None)],
        vec![blocking("b-suffix", suffix_domain("example"))],
    );
    let d = match_rules(
        &input_hostname("a.example"),
        &empty_lookup(),
        &rb,
        default_zone_policy(),
        prefer_primary(),
    );
    assert_eq!(matched_rule_id(&d), Some("r-exact"));
}

// ── Subnets and ranges ────────────────────────────────────────────────────

fn subnet(text: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::Subnet(nrr_shared::ip_block::IpBlock::parse(text).expect("subnet"))
}

fn ip_range(text: &str) -> CanonicalAddressMatch {
    CanonicalAddressMatch::ip_range(nrr_shared::ip_block::IpRange::parse(text).expect("range"))
}

fn blocked(mut r: CanonicalRule) -> CanonicalRule {
    r.action = crate::canonical::RuleAction::Block;
    r
}

fn decide(input: &NormalizedDecisionInput, rules: &CanonicalRuleBook) -> RequestedRouteDecision {
    match_rules(
        input,
        &empty_lookup(),
        rules,
        default_zone_policy(),
        prefer_primary(),
    )
}

#[test]
fn an_address_inside_a_subnet_follows_the_subnet() {
    let rules = book(vec![], vec![rule("s", Some(subnet("10.20.0.0/16")), None)]);
    let d = decide(&input_ip(Ipv4Addr::new(10, 20, 3, 4)), &rules);
    assert_eq!(matched_class(&d), Some(MatchClass::Subnet));
    assert_eq!(matched_role(&d), Some(RouteRole::Secondary));
    assert_eq!(matched_specificity(&d), Some(SpecificityScore(16)));
    let outside = decide(&input_ip(Ipv4Addr::new(10, 21, 0, 1)), &rules);
    assert_eq!(matched_class(&outside), None);
}

#[test]
fn an_exact_address_beats_the_subnet_it_sits_in() {
    let rules = book(
        vec![rule("ip", Some(exact_ip(10, 20, 3, 4)), None)],
        vec![rule("s", Some(subnet("10.20.0.0/16")), None)],
    );
    let d = decide(&input_ip(Ipv4Addr::new(10, 20, 3, 4)), &rules);
    assert_eq!(matched_rule_id(&d), Some("ip"));
    assert_eq!(matched_role(&d), Some(RouteRole::Primary));
}

#[test]
fn the_longer_prefix_wins() {
    let rules = book(
        vec![rule("wide", Some(subnet("10.0.0.0/8")), None)],
        vec![rule("narrow", Some(subnet("10.20.0.0/24")), None)],
    );
    let d = decide(&input_ip(Ipv4Addr::new(10, 20, 0, 9)), &rules);
    assert_eq!(matched_rule_id(&d), Some("narrow"));
    let d = decide(&input_ip(Ipv4Addr::new(10, 30, 0, 9)), &rules);
    assert_eq!(matched_rule_id(&d), Some("wide"));
}

#[test]
fn a_range_is_as_narrow_as_its_piece_around_the_address() {
    let rules = book(
        vec![rule("net", Some(subnet("10.0.0.0/24")), None)],
        vec![rule("range", Some(ip_range("10.0.0.5-10.0.0.40")), None)],
    );
    let inside = decide(&input_ip(Ipv4Addr::new(10, 0, 0, 9)), &rules);
    assert_eq!(
        matched_rule_id(&inside),
        Some("range"),
        "10.0.0.8/29 beats /24"
    );
    let outside = decide(&input_ip(Ipv4Addr::new(10, 0, 0, 41)), &rules);
    assert_eq!(matched_rule_id(&outside), Some("net"));
}

#[test]
fn a_name_beats_the_subnet_its_address_sits_in() {
    let rules = book(
        vec![rule("name", Some(exact_fqdn("app.corp.example")), None)],
        vec![rule("s", Some(subnet("10.20.0.0/16")), None)],
    );
    let d = decide(
        &input_full("app.corp.example", Ipv4Addr::new(10, 20, 3, 4), "x.exe"),
        &rules,
    );
    assert_eq!(matched_rule_id(&d), Some("name"));
}

#[test]
fn a_subnet_beats_a_zone() {
    let rules = book(
        vec![rule("zone", Some(zone("example")), None)],
        vec![rule("s", Some(subnet("10.20.0.0/16")), None)],
    );
    let d = decide(
        &input_full("app.corp.example", Ipv4Addr::new(10, 20, 3, 4), "x.exe"),
        &rules,
    );
    assert_eq!(matched_rule_id(&d), Some("s"));
}

#[test]
fn a_blocked_subnet_does_not_veto_a_name_inside_it() {
    let rules = book(
        vec![rule("name", Some(exact_fqdn("app.corp.example")), None)],
        vec![blocked(rule("s", Some(subnet("10.20.0.0/16")), None))],
    );
    let d = decide(
        &input_full("app.corp.example", Ipv4Addr::new(10, 20, 3, 4), "x.exe"),
        &rules,
    );
    assert_eq!(matched_rule_id(&d), Some("name"), "the narrower rule wins");
    let bare = decide(&input_ip(Ipv4Addr::new(10, 20, 3, 4)), &rules);
    assert_eq!(matched_rule_id(&bare), Some("s"));
}

#[test]
fn ipv6_subnets_match_their_own_family_only() {
    let rules = book(
        vec![],
        vec![rule("s6", Some(subnet("2001:db8::/32")), None)],
    );
    let v6 = normalize_runtime_input(&runtime_input_for(
        "",
        Some("2001:db8::7".parse().expect("v6")),
        None,
    ));
    assert_eq!(matched_rule_id(&decide(&v6, &rules)), Some("s6"));
    assert_eq!(
        matched_class(&decide(&input_ip(Ipv4Addr::new(32, 1, 13, 184)), &rules)),
        None
    );
}

//! Rule matching implementation.
//!
//! Five-tier matching algorithm:
//! 1. ExactFqdn — exact hostname (always before SuffixDomain for the same hostname)
//! 2. SuffixDomain — longest suffix domain (`*.label`); covers the apex `label`
//!    itself and every subdomain of it — see [`match_suffix_domain`]
//! 3. ExactIp / Zone (tiers 3a/3b) — order per [`ZonePriorityPolicy`] (default: ExactIp first)
//! 4. Application — process name / glob (address-less rules only)
//! 5. Default — behavior-mode fallback, no rule matched
//!
//! Public entry point: [`match_rules`].
//!
//! # AND semantics for address + app filter
//!
//! When a rule carries both an `address_match` and an `app_match`, **both**
//! must match. A rule that matches the address but fails the app filter is
//! discarded by [`select_winner`] before specificity selection.
//!
//! # Determinism
//!
//! Tie-breaking within a tier is deterministic: highest [`SpecificityScore`]
//! wins; among equal scores, the lexicographically smallest `rule_id` wins.
//! A [`ConflictMarker::Detected`] is attached when two candidates have equal
//! specificity but belong to different route roles.

use std::net::Ipv4Addr;

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::canonical::{
    CanonicalAddressMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleBook, RuleAction,
};
use crate::decision_lookup::LookupResult;
use crate::decision_matching::{
    match_suffix_domain, match_zone, AppFilterResult, ConflictMarker, MatchClass, NoMatchReason,
    RequestedRouteDecision, RuleMatchCandidate, SpecificityScore, ZonePriorityPolicy,
};
use crate::decision_normalization::{
    NormalizedAppIdentity, NormalizedDecisionInput, NormalizedHostname, NormalizedIp,
};
use crate::RuleId;

// ── Public entry point ────────────────────────────────────────────────────────

/// Evaluates all routing rules against the normalised input and returns the
/// requested route decision.
///
/// The function is pure and deterministic — identical inputs always produce
/// identical outputs. It does not perform I/O, DNS resolution, or any
/// side-effecting operation.
pub fn match_rules(
    input: &NormalizedDecisionInput,
    lookup: &LookupResult,
    rule_book: &CanonicalRuleBook,
    zone_policy: ZonePriorityPolicy,
    behavior_mode: RouteBehaviorMode,
) -> RequestedRouteDecision {
    let avail = &input.match_class_availability;

    // Tier 1: ExactFqdn
    if avail.exact_fqdn.is_none() {
        if let NormalizedHostname::Valid(hostname) = &input.hostname {
            let candidates = collect_exact_fqdn(rule_book, hostname, &input.app_identity);
            if let Some(winner) = select_winner(candidates) {
                return RequestedRouteDecision::MatchedRoute { candidate: winner };
            }
        }
    }

    // Tier 2: SuffixDomain
    if avail.suffix_domain.is_none() {
        if let NormalizedHostname::Valid(hostname) = &input.hostname {
            let candidates = collect_suffix_domain(rule_book, hostname, &input.app_identity);
            if let Some(winner) = select_winner(candidates) {
                return RequestedRouteDecision::MatchedRoute { candidate: winner };
            }
        }
    }

    // Tier 3: Zone/ExactIp — order per ZonePriorityPolicy
    let effective_ip = effective_ip_for_matching(input, lookup);
    for tier3_class in zone_policy.tier3_order() {
        let maybe_winner = match tier3_class {
            MatchClass::Zone => {
                if avail.zone.is_none() {
                    if let NormalizedHostname::Valid(hostname) = &input.hostname {
                        select_winner(collect_zone(rule_book, hostname, &input.app_identity))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            MatchClass::ExactIp => {
                if avail.exact_ip.is_none() {
                    effective_ip.and_then(|ip| {
                        select_winner(collect_exact_ip(rule_book, ip, &input.app_identity))
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(winner) = maybe_winner {
            return RequestedRouteDecision::MatchedRoute { candidate: winner };
        }
    }

    // Tier 4: Application (address-less rules only)
    if avail.application.is_none() {
        if let Some(app_identity) = &input.app_identity {
            let candidates = collect_application(rule_book, app_identity);
            if let Some(winner) = select_winner(candidates) {
                return RequestedRouteDecision::MatchedRoute { candidate: winner };
            }
        }
    }

    // Tier 5: Default — behavior-mode fallback
    let reason = if avail.nothing_available() {
        NoMatchReason::AllClassesBlocked
    } else if rule_book.total_enabled_count() == 0 {
        NoMatchReason::EmptyRuleBook
    } else {
        NoMatchReason::NoMatchFound
    };
    RequestedRouteDecision::DefaultRoute {
        reason,
        behavior_mode,
    }
}

// ── Candidate collection ──────────────────────────────────────────────────────

fn collect_exact_fqdn(
    rule_book: &CanonicalRuleBook,
    hostname: &str,
    app_identity: &Option<NormalizedAppIdentity>,
) -> Vec<RuleMatchCandidate> {
    let mut out = Vec::new();
    for role in [RouteRole::Primary, RouteRole::Secondary] {
        for rule in rule_book.set_for(role).rules() {
            if !rule.enabled {
                continue;
            }
            if let Some(CanonicalAddressMatch::ExactFqdn(label)) = &rule.address_match {
                if label == hostname {
                    out.push(make_candidate(
                        &rule.id,
                        role,
                        MatchClass::ExactFqdn,
                        SpecificityScore::label_count(label),
                        eval_app_filter(rule, app_identity),
                        rule.action,
                    ));
                }
            }
        }
    }
    out
}

fn collect_suffix_domain(
    rule_book: &CanonicalRuleBook,
    hostname: &str,
    app_identity: &Option<NormalizedAppIdentity>,
) -> Vec<RuleMatchCandidate> {
    let mut out = Vec::new();
    for role in [RouteRole::Primary, RouteRole::Secondary] {
        for rule in rule_book.set_for(role).rules() {
            if !rule.enabled {
                continue;
            }
            if let Some(CanonicalAddressMatch::SuffixDomain(label)) = &rule.address_match {
                // The apex `label` itself and every subdomain of it. Specificity
                // stays the label count, so a longer suffix still wins within
                // the tier, and ExactFqdn (tier 1) still wins over any of them.
                if match_suffix_domain(hostname, label) {
                    out.push(make_candidate(
                        &rule.id,
                        role,
                        MatchClass::SuffixDomain,
                        SpecificityScore::label_count(label),
                        eval_app_filter(rule, app_identity),
                        rule.action,
                    ));
                }
            }
        }
    }
    out
}

fn collect_zone(
    rule_book: &CanonicalRuleBook,
    hostname: &str,
    app_identity: &Option<NormalizedAppIdentity>,
) -> Vec<RuleMatchCandidate> {
    let mut out = Vec::new();
    for role in [RouteRole::Primary, RouteRole::Secondary] {
        for rule in rule_book.set_for(role).rules() {
            if !rule.enabled {
                continue;
            }
            if let Some(CanonicalAddressMatch::Zone(zone_name)) = &rule.address_match {
                if match_zone(hostname, zone_name) {
                    out.push(make_candidate(
                        &rule.id,
                        role,
                        MatchClass::Zone,
                        SpecificityScore::SINGLE,
                        eval_app_filter(rule, app_identity),
                        rule.action,
                    ));
                }
            }
        }
    }
    out
}

fn collect_exact_ip(
    rule_book: &CanonicalRuleBook,
    ip: Ipv4Addr,
    app_identity: &Option<NormalizedAppIdentity>,
) -> Vec<RuleMatchCandidate> {
    let mut out = Vec::new();
    for role in [RouteRole::Primary, RouteRole::Secondary] {
        for rule in rule_book.set_for(role).rules() {
            if !rule.enabled {
                continue;
            }
            if let Some(CanonicalAddressMatch::ExactIp(rule_ip)) = &rule.address_match {
                if *rule_ip == ip {
                    out.push(make_candidate(
                        &rule.id,
                        role,
                        MatchClass::ExactIp,
                        SpecificityScore::SINGLE,
                        eval_app_filter(rule, app_identity),
                        rule.action,
                    ));
                }
            }
        }
    }
    out
}

fn collect_application(
    rule_book: &CanonicalRuleBook,
    app_identity: &NormalizedAppIdentity,
) -> Vec<RuleMatchCandidate> {
    let mut out = Vec::new();
    for role in [RouteRole::Primary, RouteRole::Secondary] {
        for rule in rule_book.set_for(role).rules() {
            if !rule.enabled {
                continue;
            }
            if rule.address_match.is_some() {
                continue; // address rules are handled by tiers 1–4
            }
            let Some(app_match) = &rule.app_match else {
                continue; // invariant: at least one of address_match/app_match is Some
            };
            let (matched, specificity) = match &app_match.pattern {
                CanonicalAppPattern::Exact(pattern) => (
                    *pattern == app_identity.process_name,
                    SpecificityScore::APP_EXACT,
                ),
                CanonicalAppPattern::Glob(pattern) => (
                    glob_matches(pattern, &app_identity.process_name),
                    SpecificityScore::APP_GLOB,
                ),
            };
            // TODO: `include_child_processes` requires a process tree
            // snapshot (parent PID → process name mapping) that is not
            // available in `DecisionRequest`. The pure-domain layer can't
            // synthesise it; the service-runtime adapter must wire a
            // process-tree probe before this branch fires. Today only
            // the current process identity is matched.
            if matched {
                out.push(make_candidate(
                    &rule.id,
                    role,
                    MatchClass::Application,
                    specificity,
                    AppFilterResult::Matched,
                    rule.action,
                ));
            }
        }
    }
    out
}

// ── Winner selection ──────────────────────────────────────────────────────────

/// Selects the highest-specificity eligible candidate and records any conflict.
///
/// Ineligible candidates (`AppFilterResult::NotMatched`) are discarded first.
/// Among eligible candidates, the one with the highest [`SpecificityScore`]
/// wins. Ties are broken by ascending `rule_id` (lexicographic). When the
/// winner ties with a candidate from a **different** route role, a
/// [`ConflictMarker::Detected`] is attached to the winner.
fn select_winner(mut candidates: Vec<RuleMatchCandidate>) -> Option<RuleMatchCandidate> {
    candidates.retain(|c| c.app_filter_result.is_eligible());
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(|a, b| {
        b.specificity
            .cmp(&a.specificity)
            .then_with(|| a.rule_id.as_str().cmp(b.rule_id.as_str()))
    });
    let top_specificity = candidates[0].specificity;
    let top_role = candidates[0].route_role;
    let conflict = candidates[1..]
        .iter()
        .any(|c| c.specificity == top_specificity && c.route_role != top_role);
    let mut winner = candidates.remove(0);
    winner.conflict = if conflict {
        ConflictMarker::Detected
    } else {
        ConflictMarker::None
    };
    Some(winner)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns the IPv4 address to use for `ExactIp` matching.
///
/// Prefers `lookup.selected_ip` (the authoritative resolution from the
/// lookup stage) when usable (`Fresh` or `StaleUsable`); falls back to the
/// observed IPv4 from input.
fn effective_ip_for_matching(
    input: &NormalizedDecisionInput,
    lookup: &LookupResult,
) -> Option<Ipv4Addr> {
    if let Some(selected) = &lookup.selected_ip {
        if selected.cache_state.is_usable_for_matching() {
            return Some(selected.addr);
        }
    }
    if let NormalizedIp::ValidIpv4(addr) = &input.ip {
        return Some(*addr);
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn make_candidate(
    rule_id: &RuleId,
    route_role: RouteRole,
    match_class: MatchClass,
    specificity: SpecificityScore,
    app_filter_result: AppFilterResult,
    action: RuleAction,
) -> RuleMatchCandidate {
    RuleMatchCandidate {
        rule_id: rule_id.clone(),
        route_role,
        match_class,
        specificity,
        app_filter_result,
        conflict: ConflictMarker::None,
        action,
    }
}

/// Evaluates the optional app filter on an address rule.
fn eval_app_filter(
    rule: &CanonicalRule,
    app_identity: &Option<NormalizedAppIdentity>,
) -> AppFilterResult {
    let Some(app_match) = &rule.app_match else {
        return AppFilterResult::NoFilter;
    };
    let Some(identity) = app_identity else {
        return AppFilterResult::NotMatched;
    };
    let matched = match &app_match.pattern {
        CanonicalAppPattern::Exact(pattern) => *pattern == identity.process_name,
        CanonicalAppPattern::Glob(pattern) => glob_matches(pattern, &identity.process_name),
    };
    if matched {
        AppFilterResult::Matched
    } else {
        AppFilterResult::NotMatched
    }
}

/// Glob match where `*` matches zero or more characters (lowercase inputs only).
fn glob_matches(pattern: &str, text: &str) -> bool {
    glob_bytes(pattern.as_bytes(), text.as_bytes())
}

fn glob_bytes(pat: &[u8], txt: &[u8]) -> bool {
    match pat.first() {
        None => txt.is_empty(),
        Some(b'*') => (0..=txt.len()).any(|i| glob_bytes(&pat[1..], &txt[i..])),
        Some(&pc) => txt
            .first()
            .is_some_and(|&tc| tc == pc && glob_bytes(&pat[1..], &txt[1..])),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        CanonicalAddressMatch::ExactIp(Ipv4Addr::new(a, b, c, d))
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
                addr: Ipv4Addr::new(a, b, c, d),
                cache_state: CacheEntryState::Fresh,
                source: LookupSource::CacheHit,
                resolved_at: None,
                ttl_seconds: None,
            }),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: true,
                    freshness: Some(CacheEntryState::Fresh),
                    source: Some(LookupSource::CacheHit),
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        }
    }

    fn lookup_stale_not_usable() -> LookupResult {
        LookupResult {
            selected_ip: Some(ResolvedAddressEntry {
                addr: Ipv4Addr::new(1, 2, 3, 4),
                cache_state: CacheEntryState::StaleNotUsable,
                source: LookupSource::CacheHit,
                resolved_at: None,
                ttl_seconds: None,
            }),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: true,
                    freshness: Some(CacheEntryState::StaleNotUsable),
                    source: Some(LookupSource::CacheHit),
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
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

    // ── glob_matches ──────────────────────────────────────────────────────────

    #[test]
    fn glob_exact_no_wildcard() {
        assert!(glob_matches("chrome.exe", "chrome.exe"));
        assert!(!glob_matches("chrome.exe", "firefox.exe"));
    }

    #[test]
    fn glob_star_prefix() {
        assert!(glob_matches("*vpn*.exe", "foovpnbar.exe"));
        assert!(glob_matches("*vpn*.exe", "vpn.exe"));
        assert!(!glob_matches("*vpn*.exe", "chrome.exe"));
    }

    #[test]
    fn glob_star_suffix() {
        assert!(glob_matches("chrome*", "chrome.exe"));
        assert!(glob_matches("chrome*", "chrome"));
        assert!(!glob_matches("chrome*", "firefox.exe"));
    }

    #[test]
    fn glob_star_only_matches_everything() {
        assert!(glob_matches("*", ""));
        assert!(glob_matches("*", "anything.exe"));
    }

    #[test]
    fn glob_empty_pattern_matches_only_empty() {
        assert!(glob_matches("", ""));
        assert!(!glob_matches("", "nonempty"));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(glob_matches("*foo*bar*", "xfooyybarz"));
        assert!(!glob_matches("*foo*bar*", "xfoobaz"));
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
        let rb = book(vec![rule("r1", Some(exact_ip(1, 2, 3, 4)), None)], vec![]);
        let input = input_ip(Ipv4Addr::new(1, 2, 3, 4));
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
        // Observed IP = 1.2.3.4 but lookup resolved 5.6.7.8 → rule for 5.6.7.8 wins
        let rb = book(
            vec![
                rule("r-obs", Some(exact_ip(1, 2, 3, 4)), None),
                rule("r-lookup", Some(exact_ip(5, 6, 7, 8)), None),
            ],
            vec![],
        );
        let input = input_ip(Ipv4Addr::new(1, 2, 3, 4));
        let lookup = lookup_fresh_ip(5, 6, 7, 8);
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
        let rb = book(vec![rule("r1", Some(exact_ip(1, 2, 3, 4)), None)], vec![]);
        let input = input_ip(Ipv4Addr::new(1, 2, 3, 4));
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
        let rb = book(vec![rule("r1", Some(exact_ip(9, 9, 9, 9)), None)], vec![]);
        let input = input_ip(Ipv4Addr::new(1, 2, 3, 4));
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
        let input = input_ip(Ipv4Addr::new(1, 2, 3, 4));
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
        // Both ExactIp(1.2.3.4) and Zone("ru") rules present for hostname "example.ru"
        // Default policy (prefer_ip = true): ExactIp is evaluated first → wins
        let rb = book(
            vec![
                rule("r-ip", Some(exact_ip(1, 2, 3, 4)), None),
                rule("r-zone", Some(zone("ru")), None),
            ],
            vec![],
        );
        let input = input_full("example.ru", Ipv4Addr::new(1, 2, 3, 4), "chrome.exe");
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
                rule("r-ip", Some(exact_ip(1, 2, 3, 4)), None),
                rule("r-zone", Some(zone("ru")), None),
            ],
            vec![],
        );
        let input = input_full("example.ru", Ipv4Addr::new(1, 2, 3, 4), "chrome.exe");
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
}

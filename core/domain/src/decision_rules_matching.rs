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

use std::net::IpAddr;

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
    let effective_ips = effective_ips_for_matching(input, lookup);
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
                    let candidates: Vec<_> = effective_ips
                        .iter()
                        .flat_map(|ip| collect_exact_ip(rule_book, *ip, &input.app_identity))
                        .collect();
                    select_winner(candidates)
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
                        // By label count, not a flat 1: `corp.intra` is
                        // narrower than `intra` and must beat it, the same way
                        // an exact host beats the suffix it sits under.
                        SpecificityScore::label_count(zone_name),
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
    ip: IpAddr,
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
            let specificity = match &app_match.pattern {
                CanonicalAppPattern::Exact(_) => SpecificityScore::APP_EXACT,
                CanonicalAppPattern::Glob(_) => SpecificityScore::APP_GLOB,
            };
            let matched = app_pattern_matches(&app_match.pattern, &app_identity.process_name);
            // TODO: `include_child_processes` requires a process-tree
            // snapshot (parent PID -> process name) that the matcher is never
            // given. The pure-domain layer cannot synthesise it; the caller
            // must supply it before this branch can fire. Today only the
            // current process identity is matched.
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
/// Among eligible candidates the highest [`SpecificityScore`] wins.
///
/// A tie between the two route sets is broken by ROLE — the main route wins —
/// because that is what the enforcement layer does with the same tie: its
/// primary weight band sits above the secondary one, so a filter for the main
/// route is the one that fires. Breaking it by `rule_id` here made this
/// matcher answer "additional route" for a case the service would route down
/// the main one, purely because a name sorted first; an explain probe that
/// disagrees with enforcement is worse than no probe. The tie is still marked
/// [`ConflictMarker::Detected`] — the user named the same traffic twice, and
/// only they can say which they meant. `rule_id` remains the last resort so
/// the answer stays deterministic.
fn select_winner(mut candidates: Vec<RuleMatchCandidate>) -> Option<RuleMatchCandidate> {
    candidates.retain(|c| c.app_filter_result.is_eligible());
    if candidates.is_empty() {
        return None;
    }
    candidates.sort_by(|a, b| {
        b.specificity
            .cmp(&a.specificity)
            .then_with(|| role_rank(a.route_role).cmp(&role_rank(b.route_role)))
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

/// Tie-break order between the two route sets: the main route first, matching
/// the weight bands the enforcement layer assigns.
fn role_rank(role: RouteRole) -> u8 {
    match role {
        RouteRole::Primary => 0,
        RouteRole::Secondary => 1,
    }
}

/// The IPv4 addresses an `ExactIp` rule may be matched against: the resolved
/// one, the observed one, or both when they disagree.
///
/// The lookup stage's `selected_ip` is the authoritative resolution and comes
/// first. The observed address used to be consulted only when there was no
/// usable cache entry — so a rule naming the address the connection ACTUALLY
/// goes to did not apply whenever the cache happened to hold a different one,
/// silently, with the doc claiming the two were cross-checked. They are not
/// always the same thing (CDN rotation, a stale entry that is still "usable"),
/// and the address the traffic is going to is a fact, not a memory. Both are
/// offered; if they name different rules, the equal-specificity conflict marker
/// already says the pipeline saw an ambiguity.
fn effective_ips_for_matching(
    input: &NormalizedDecisionInput,
    lookup: &LookupResult,
) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Some(selected) = &lookup.selected_ip {
        if selected.cache_state.is_usable_for_matching() {
            out.push(selected.addr);
        }
    }
    let observed = match input.ip {
        NormalizedIp::ValidIpv4(v4) => Some(IpAddr::V4(v4)),
        NormalizedIp::ValidIpv6(v6) => Some(IpAddr::V6(v6)),
        NormalizedIp::Unavailable => None,
    };
    if let Some(ip) = observed {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
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
    let matched = app_pattern_matches(&app_match.pattern, &identity.process_name);
    if matched {
        AppFilterResult::Matched
    } else {
        AppFilterResult::NotMatched
    }
}

/// Does `pattern` name the observed process?
///
/// Both sides go through the one match key, so the `.exe` spelling — appended
/// to the observed name on every OS, appended to an exact rule but never to a
/// glob — cannot decide the answer: `*torrent` names `qbittorrent.exe`, and an
/// exact rule matches a Linux process that has no suffix at all.
fn app_pattern_matches(pattern: &CanonicalAppPattern, process_name: &str) -> bool {
    let observed = nrr_shared::app_identity::app_match_key(process_name);
    match pattern {
        CanonicalAppPattern::Exact(p) => nrr_shared::app_identity::app_match_key(p) == observed,
        CanonicalAppPattern::Glob(p) => {
            glob_matches(&nrr_shared::app_identity::app_match_key(p), &observed)
        }
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
mod tests;

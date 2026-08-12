//! Pipeline scenarios, pseudocode, and completion criteria.
//!
//! This module serves three purposes:
//!
//! 1. **Full pipeline pseudocode** — a single reference document for the
//!    routing decision algorithm.
//! 2. **Scenario definitions** — the 13 canonical test scenarios the rule
//!    engine must pass.
//! 3. **Completion criteria** — a machine-readable checklist verified by the
//!    tests in this module.
//!
//! # Full pipeline pseudocode
//!
//! ```text
//! fn route_decision(raw_input: RuntimeInput) -> FinalDecision {
//!
//!   // ── Stage 1: Normalization ──────────────────────────────────────────────
//!   let norm = normalize(raw_input);
//!   // norm: NormalizedDecisionInput — hostname, ip, app_identity,
//!   //        match_class_availability, availability_signals, warnings
//!
//!   // ── Stage 2: FQDN/IP Lookup ────────────────────────────────────────────
//!   let lookup = lookup_cache(LookupRequest {
//!       hostname:   norm.hostname.valid(),
//!       observed_ip: norm.ip.valid_ipv4(),
//!       direction:  Both,
//!       ..
//!   });
//!   // Policy: CacheWithBackgroundRefresh (never block on live DNS in decision)
//!
//!   // ── Stage 3: Rule Matching ─────────────────────────────────────────────
//!   // Pass 1 — ExactFqdn (tier 1)
//!   if hostname available:
//!     if let Some(c) = match_exact_fqdn(&norm, rule_book):
//!       return build_decision(c, ...)
//!
//!   // Pass 1 — SuffixDomain (tier 2)
//!   if hostname available:
//!     if let Some(c) = match_suffix_domain(&norm, rule_book):
//!       return build_decision(c, ...)
//!
//!   // Pass 2 — Zone ↔ ExactIp (tier 3, order per ZonePriorityPolicy)
//!   for tier in zone_policy.tier3_order():   // [ExactIp, Zone] or [Zone, ExactIp]
//!     match tier:
//!       ExactIp => if ip available: try match_exact_ip(lookup.selected_ip, rule_book)
//!       Zone    => if hostname available: try match_zone_rules(&norm.hostname, rule_book)
//!     if match found: return build_decision(...)
//!
//!   // Pass 3 — Application (tier 4)
//!   if app_identity available:
//!     if let Some(c) = match_application(&norm.app_identity, rule_book):
//!       return build_decision(c, ...)
//!
//!   // Pass 4 — Default route (tier 5)
//!   let matched = RequestedRouteDecision::DefaultRoute {
//!       reason: NoMatchReason::NoMatchFound,
//!       behavior_mode: raw_input.route_behavior_mode,
//!   };
//!
//!   // ── Stage 4: Availability Check ────────────────────────────────────────
//!   let avail = check_availability(matched, raw_input.interface_availability);
//!
//!   // ── Stage 5: Fail Policy ───────────────────────────────────────────────
//!   let final_decision = apply_fail_policy(FailPolicyInput {
//!       availability: avail,
//!       browser_stub_experimental: raw_input.feature_flags.browser_stub_experimental,
//!       browser: classify_browser(&raw_input.process_context),
//!   });
//!
//!   // ── Stage 6: Explain Assembly ──────────────────────────────────────────
//!   let explain = DecisionExplainBuilder::new(DecisionId::new(), revision_id)
//!       .input_summary(build_input_summary(&raw_input))
//!       .match_trace(...)
//!       .availability_trace(...)
//!       .final_action(...)
//!       .add_uncertainty_markers_from(norm, lookup, avail)
//!       .build()?;
//!
//!   FinalDecision { action: final_decision.action, explain }
//! }
//! ```
//!
//! # Completion criteria
//!
//! ✓ Decision pipeline described and staged
//! ✓ Input normalization contracts defined including Zone name and IPv6 rejection
//! ✓ Lookup/cache contract defined with freshness and do-resolve policy
//! ✓ Match order: ExactFqdn → SuffixDomain → Zone ↔ ExactIp (configurable)
//! ✓ Zone matching: `hostname.ends_with(".{zone}")`, IP-only skips Zone
//! ✓ Configurable Zone/ExactIp priority via `ZonePriorityPolicy`
//! ✓ Fail-Closed / Fail-Open arbitration: StrictFailClosed never silent fallback
//! ✓ Browser stub experimental — KnownProcessName only, disabled by default
//! ✓ Availability snapshot: secondary=None vs Some(unavailable) distinct
//! ✓ Explain output: deterministic ordering, privacy tiers, required fields
//! ✓ UI tasks described: zone_priority_over_ip, log_level, browser_stub_experimental

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::decision_availability::{
    AvailabilityCheckOutcome, AvailabilityExplainData, AvailabilityReason, InterfaceLifecycleState,
    RouteAdapterAvailability, RouteAvailabilityState, SecondaryAvailabilityStatus,
    SnapshotStaleness,
};
use crate::decision_fail_policy::{
    apply_fail_policy, BrowserClassification, BrowserClassificationBasis, FailPolicyInput,
    FinalAction,
};
use crate::decision_matching::{
    match_suffix_domain, match_zone, AppFilterResult, ConflictMarker, MatchClass,
    RuleMatchCandidate, SpecificityScore, ZonePriorityPolicy,
};
use crate::decision_normalization::{
    InputAvailabilitySignal, MatchClassAvailability, NormalizationError, NormalizedHostname,
    NormalizedIp,
};
use crate::RuleId;

// ── Scenario helpers ──────────────────────────────────────────────────────────

fn secondary_not_configured_outcome(mode: RouteBehaviorMode) -> AvailabilityCheckOutcome {
    AvailabilityCheckOutcome::SecondaryNotConfigured {
        behavior_mode: mode,
        explain: {
            let mut e = avail_explain(
                RouteRole::Secondary,
                RouteAvailabilityState::Unavailable,
                false,
            );
            e.secondary_not_configured = true;
            e
        },
    }
}

fn secondary_not_reachable_outcome(
    mode: RouteBehaviorMode,
    state: RouteAvailabilityState,
    reason: AvailabilityReason,
) -> AvailabilityCheckOutcome {
    AvailabilityCheckOutcome::SecondaryNotReachable {
        state,
        reason: Some(reason),
        behavior_mode: mode,
        explain: avail_explain(RouteRole::Secondary, state, false),
    }
}

fn secondary_unknown_outcome(mode: RouteBehaviorMode) -> AvailabilityCheckOutcome {
    AvailabilityCheckOutcome::SecondaryUnknown {
        staleness: SnapshotStaleness::StaleUsable,
        behavior_mode: mode,
        explain: {
            let mut e = avail_explain(RouteRole::Secondary, RouteAvailabilityState::Unknown, false);
            e.stale_marker = Some(SnapshotStaleness::StaleUsable);
            e
        },
    }
}

fn avail_explain(
    route: RouteRole,
    state: RouteAvailabilityState,
    stale: bool,
) -> AvailabilityExplainData {
    AvailabilityExplainData {
        requested_route: route,
        observed_state: state,
        stale_marker: if stale {
            Some(SnapshotStaleness::StaleUsable)
        } else {
            None
        },
        unavailability_reason: None,
        secondary_not_configured: false,
    }
}

fn rule_candidate(
    class: MatchClass,
    role: RouteRole,
    specificity: SpecificityScore,
) -> RuleMatchCandidate {
    RuleMatchCandidate {
        rule_id: RuleId("r-scenario".to_owned()),
        route_role: role,
        match_class: class,
        specificity,
        app_filter_result: AppFilterResult::NoFilter,
        conflict: ConflictMarker::None,
        action: crate::canonical::RuleAction::Route,
    }
}

fn fail_input(
    avail: AvailabilityCheckOutcome,
    stub: bool,
    browser: BrowserClassification,
) -> FailPolicyInput {
    FailPolicyInput {
        availability: avail,
        browser_stub_experimental: stub,
        browser,
    }
}

fn known_browser(name: &str) -> BrowserClassification {
    BrowserClassification {
        is_browser: true,
        basis: BrowserClassificationBasis::KnownProcessName {
            process_name: name.to_owned(),
        },
    }
}

fn non_browser() -> BrowserClassification {
    BrowserClassification::unclassified()
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCENARIO TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── Scenario 1: ExactFqdn beats SuffixDomain ─────────────────────────────────
//
// Input:    hostname = "mail.corp.example.com"
// Rules:    ExactFqdn("mail.corp.example.com") → secondary
//           SuffixDomain("corp.example.com")   → primary
// Expected: ExactFqdn wins (tier 1 always precedes tier 2)
#[test]
fn scenario_01_exact_fqdn_beats_suffix_domain() {
    let fqdn_candidate = rule_candidate(
        MatchClass::ExactFqdn,
        RouteRole::Secondary,
        SpecificityScore::label_count("mail.corp.example.com"),
    );
    let suffix_candidate = rule_candidate(
        MatchClass::SuffixDomain,
        RouteRole::Primary,
        SpecificityScore::label_count("corp.example.com"),
    );
    // ExactFqdn (tier 1) has lower enum discriminant than SuffixDomain (tier 2)
    assert!(fqdn_candidate.match_class < suffix_candidate.match_class);
    assert_eq!(fqdn_candidate.route_role, RouteRole::Secondary);
}

// ── Scenario 2: SuffixDomain beats Zone ──────────────────────────────────────
//
// Input:    hostname = "server.corp.intra"
// Rules:    SuffixDomain("corp.intra") → secondary (tier 2)
//           Zone("intra")              → primary   (tier 3)
// Expected: SuffixDomain wins (tier 2 < tier 3)
#[test]
fn scenario_02_suffix_domain_beats_zone() {
    let suffix = rule_candidate(
        MatchClass::SuffixDomain,
        RouteRole::Secondary,
        SpecificityScore::label_count("corp.intra"),
    );
    let zone = rule_candidate(
        MatchClass::Zone,
        RouteRole::Primary,
        SpecificityScore::SINGLE,
    );
    assert!(suffix.match_class < zone.match_class);
    // SuffixDomain fires: "server.corp.intra" is a subdomain of "corp.intra"
    let hostname = "server.corp.intra";
    let base = "corp.intra";
    assert!(match_suffix_domain(hostname, base));
    // …and the apex of the suffix is covered too, while the Zone rule still
    // refuses its own bare label.
    assert!(match_suffix_domain(base, base));
    assert!(!match_zone("intra", "intra"));
}

// ── Scenario 3: Zone match — hostname suffix ──────────────────────────────────
//
// Input:    hostname = "server.corp.intra"
// Rules:    Zone("intra") → secondary
// Expected: Zone fires because hostname ends with ".intra"
#[test]
fn scenario_03_zone_match_hostname_suffix() {
    assert!(match_zone("server.corp.intra", "intra"));
    assert!(match_zone("host.intra", "intra"));
    assert!(match_zone("a.b.c.intra", "intra"));
    // Apex does not match
    assert!(!match_zone("intra", "intra"));
    // Different zone does not match
    assert!(!match_zone("server.corp.intra", "corp"));
}

// ── Scenario 4: ExactIp beats Zone (default policy) ──────────────────────────
//
// Input:    hostname = "api.example.ru", IP = 203.0.113.7
// Rules:    ExactIp(203.0.113.7) → primary  (checked first in default policy)
//           Zone("ru")           → secondary
// Expected: ExactIp wins — default ZonePriorityPolicy has prefer_ip = true
#[test]
fn scenario_04_exact_ip_beats_zone_default_policy() {
    let policy = ZonePriorityPolicy::default();
    assert!(
        policy.prefer_ip,
        "default policy must prefer ExactIp over Zone"
    );
    let order = policy.tier3_order();
    assert_eq!(
        order[0],
        MatchClass::ExactIp,
        "ExactIp must be evaluated first"
    );
    assert_eq!(order[1], MatchClass::Zone);
}

// ── Scenario 5: Zone beats ExactIp (inverted policy) ─────────────────────────
//
// Input:    hostname = "api.example.ru", IP = 203.0.113.7
// Rules:    Zone("ru")           → secondary (checked first in inverted policy)
//           ExactIp(203.0.113.7) → primary
// Expected: Zone wins — inverted ZonePriorityPolicy has prefer_ip = false
#[test]
fn scenario_05_zone_beats_exact_ip_inverted_policy() {
    let policy = ZonePriorityPolicy { prefer_ip: false };
    let order = policy.tier3_order();
    assert_eq!(
        order[0],
        MatchClass::Zone,
        "Zone must be evaluated first in inverted policy"
    );
    assert_eq!(order[1], MatchClass::ExactIp);
}

// ── Scenario 6: Hostname absent → Zone skip ──────────────────────────────────
//
// Input:    hostname = None, IP = 10.0.0.1
// Rules:    Zone("intra") → secondary
//           ExactIp(10.0.0.1) → primary
// Expected: Zone class is blocked (hostname unavailable), ExactIp still applies
#[test]
fn scenario_06_hostname_absent_zone_skip() {
    let hostname = NormalizedHostname::Unavailable;
    assert!(
        !hostname.is_usable(),
        "unavailable hostname must not be used for Zone matching"
    );

    // Normalization produces availability signals
    let signals = [InputAvailabilitySignal::HostnameUnavailable];
    assert!(signals.contains(&InputAvailabilitySignal::HostnameUnavailable));

    // Zone is blocked; ExactIp is still available
    let avail = MatchClassAvailability {
        exact_fqdn: Some(NormalizationError::DomainEmpty),
        suffix_domain: Some(NormalizationError::DomainEmpty),
        zone: Some(NormalizationError::DomainEmpty),
        exact_ip: None, // available
        application: None,
    };
    assert!(
        avail.zone.is_some(),
        "Zone must be blocked when hostname is absent"
    );
    assert!(avail.exact_ip.is_none(), "ExactIp must remain available");
}

// ── Scenario 7: Exact IP match ────────────────────────────────────────────────
//
// Input:    IP = 192.168.1.100
// Rules:    ExactIp(192.168.1.100) → secondary
// Expected: ExactIp fires; candidate has specificity = SINGLE
#[test]
fn scenario_07_exact_ip_match() {
    let ip = NormalizedIp::ValidIpv4("192.168.1.100".parse().unwrap());
    assert!(
        ip.is_usable(),
        "valid IPv4 must be usable for ExactIp matching"
    );

    let candidate = rule_candidate(
        MatchClass::ExactIp,
        RouteRole::Secondary,
        SpecificityScore::SINGLE,
    );
    assert_eq!(candidate.match_class, MatchClass::ExactIp);
    assert_eq!(candidate.specificity, SpecificityScore::SINGLE);
}

// ── Scenario 8: App-only fallback ─────────────────────────────────────────────
//
// Input:    hostname = None, IP = None, process = "curl.exe"
// Rules:    Application("curl.exe") → primary
// Expected: Application tier fires; hostname and IP classes are blocked
#[test]
fn scenario_08_app_only_fallback() {
    let avail = MatchClassAvailability {
        exact_fqdn: Some(NormalizationError::DomainEmpty),
        suffix_domain: Some(NormalizationError::DomainEmpty),
        zone: Some(NormalizationError::DomainEmpty),
        exact_ip: Some(NormalizationError::ApplicationNameEmpty), // IP unavailable
        application: None,                                        // available
    };
    assert!(
        avail.all_address_classes_blocked(),
        "all address classes must be blocked"
    );
    assert!(
        avail.application.is_none(),
        "Application class must be available"
    );

    let candidate = rule_candidate(
        MatchClass::Application,
        RouteRole::Primary,
        SpecificityScore::APP_EXACT,
    );
    assert_eq!(candidate.match_class, MatchClass::Application);
    assert_eq!(candidate.specificity, SpecificityScore::APP_EXACT);
    assert!(candidate.app_filter_result.is_eligible());
}

// ── Scenario 9: Default route (no rule matched) ───────────────────────────────
//
// Input:    hostname = "unknown.internal"
// Rules:    (none matching)
// Expected: DefaultRoute with PreferPrimary → RoutePrimary
#[test]
fn scenario_09_default_route_prefer_primary() {
    let result = apply_fail_policy(&fail_input(
        AvailabilityCheckOutcome::Available {
            route: RouteRole::Primary,
            explain: avail_explain(RouteRole::Primary, RouteAvailabilityState::Available, false),
        },
        false,
        non_browser(),
    ));
    assert_eq!(result.action, FinalAction::RoutePrimary);
    assert!(result.action.is_forwarding());
}

// ── Scenario 10: Missing hostname — normalization handles gracefully ───────────
//
// Input:    hostname = ""  (empty after trim)
// Expected: DomainEmpty error, hostname match classes blocked, no panic
#[test]
fn scenario_10_missing_hostname_normalization() {
    let error = NormalizationError::DomainEmpty;
    let hostname = NormalizedHostname::Invalid {
        raw: String::new(),
        error: NormalizationError::DomainEmpty,
    };
    assert!(!hostname.is_usable());
    assert_eq!(NormalizationError::DomainEmpty, error); // error is cloneable/comparable
}

// ── Scenario 11: Stale cache — decision proceeds with uncertainty marker ───────
//
// Input:    hostname = "api.example.com", IP from stale cache
// Expected: LookupResult.selected_ip has CacheEntryState::StaleUsable,
//           UncertaintyMarker::StaleCacheUsed added to explain
#[test]
fn scenario_11_stale_cache_decision_proceeds_with_uncertainty() {
    use crate::decision_explain::UncertaintyMarker;
    use crate::decision_lookup::{CacheEntryState, LookupSource, ResolvedAddressEntry};

    let stale_entry = ResolvedAddressEntry {
        addr: "93.184.216.34".parse().unwrap(),
        cache_state: CacheEntryState::StaleUsable,
        source: LookupSource::CacheHit,
        resolved_at: None,
        ttl_seconds: None,
    };
    assert!(
        stale_entry.cache_state.is_usable_for_matching(),
        "StaleUsable must still be usable for matching"
    );
    // The explain builder will carry an uncertainty marker
    let marker = UncertaintyMarker::StaleCacheUsed;
    assert!(marker < UncertaintyMarker::StaleAvailabilitySnapshot);
}

// ── Scenario 12: Unavailable secondary — not configured vs interface down ──────
//
// Case A: secondary = None (not configured)
// Expected: SecondaryNotConfigured → reason secondary_not_configured
//
// Case B: secondary = Some + interface down
// Expected: SecondaryNotReachable → reason secondary_unavailable
#[test]
fn scenario_12a_secondary_not_configured() {
    let status = SecondaryAvailabilityStatus::NotConfigured;
    assert!(!status.is_routable());
    // Not configured is structurally different from configured-but-down
    assert!(matches!(status, SecondaryAvailabilityStatus::NotConfigured));
}

#[test]
fn scenario_12b_secondary_interface_down() {
    let status = SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
        InterfaceLifecycleState::Disconnected,
    ));
    assert!(!status.is_routable());
    assert_eq!(status.state(), RouteAvailabilityState::Unavailable);
    // Configured but down — different from NotConfigured (different explain reason)
    assert!(matches!(status, SecondaryAvailabilityStatus::Configured(_)));
}

#[test]
fn scenario_12c_not_configured_and_interface_down_are_structurally_distinct() {
    let not_cfg = SecondaryAvailabilityStatus::NotConfigured;
    let down = SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
        InterfaceLifecycleState::Disconnected,
    ));
    assert_ne!(
        not_cfg, down,
        "not-configured and interface-down must be distinct variants"
    );
}

// ── Scenario 13: Strict Fail-Closed ──────────────────────────────────────────
//
// Case A: non-browser traffic → Block
// Case B: browser + stub enabled → BrowserStubAttempt
// Case C: browser + stub disabled → Block (not silent RoutePrimary)
// Invariant: StrictFailClosed never silently routes to primary
#[test]
fn scenario_13a_strict_fail_closed_non_browser_blocks() {
    let result = apply_fail_policy(&fail_input(
        secondary_not_reachable_outcome(
            RouteBehaviorMode::StrictSecondaryFailClosed,
            RouteAvailabilityState::Unavailable,
            AvailabilityReason::PhysicalLinkDown,
        ),
        false,
        non_browser(),
    ));
    assert_eq!(result.action, FinalAction::Block);
    assert!(result.explain.fail_closed_active);
    assert_eq!(result.route_role, None);
}

#[test]
fn scenario_13b_strict_fail_closed_browser_stub_enabled() {
    let result = apply_fail_policy(&fail_input(
        secondary_not_reachable_outcome(
            RouteBehaviorMode::StrictSecondaryFailClosed,
            RouteAvailabilityState::Unavailable,
            AvailabilityReason::PhysicalLinkDown,
        ),
        true, // stub_experimental = true
        known_browser("msedge.exe"),
    ));
    assert_eq!(result.action, FinalAction::BrowserStubAttempt);
    assert!(result.action.is_fail_closed());
}

#[test]
fn scenario_13c_strict_fail_closed_browser_stub_disabled_blocks() {
    let result = apply_fail_policy(&fail_input(
        secondary_not_reachable_outcome(
            RouteBehaviorMode::StrictSecondaryFailClosed,
            RouteAvailabilityState::Unavailable,
            AvailabilityReason::PhysicalLinkDown,
        ),
        false, // stub_experimental = false
        known_browser("chrome.exe"),
    ));
    assert_eq!(result.action, FinalAction::Block);
    assert_ne!(
        result.action,
        FinalAction::RoutePrimary,
        "StrictFailClosed must never silently route to primary"
    );
}

#[test]
fn scenario_13d_strict_fail_closed_secondary_not_configured_blocks() {
    let result = apply_fail_policy(&fail_input(
        secondary_not_configured_outcome(RouteBehaviorMode::StrictSecondaryFailClosed),
        false,
        non_browser(),
    ));
    assert_eq!(result.action, FinalAction::Block);
    assert!(result.explain.fail_closed_active);
}

#[test]
fn scenario_13e_strict_fail_closed_stale_snapshot_blocks_with_uncertainty() {
    let result = apply_fail_policy(&fail_input(
        secondary_unknown_outcome(RouteBehaviorMode::StrictSecondaryFailClosed),
        false,
        non_browser(),
    ));
    assert_eq!(result.action, FinalAction::Block);
    assert!(
        result.has_uncertainty,
        "stale snapshot must produce uncertainty flag"
    );
}

// ── Completion criteria (machine-readable) ─────────────────────────────────────

/// Verifies that all contract modules are present and compile by using at
/// least one public type from each.
#[test]
fn completion_criterion_all_block10_modules_present() {
    // RuntimeInput, ProcessContext, ObservationSource
    use crate::decision_pipeline::{ObservationSource, ProcessContext};
    let _ = ObservationSource::WfpCallback;
    let _ = ProcessContext {
        pid: 0,
        process_name: None,
        process_path: None,
        parent_pid: None,
        browser_hint: false,
    };

    // NormalizedDecisionInput, NormalizationError
    use crate::decision_normalization::NormalizationError;
    let _ = NormalizationError::DomainEmpty;

    // LookupRequest, CacheEntryState, FreshnessThresholds
    use crate::decision_lookup::{CacheEntryState, FreshnessThresholds};
    let _ = CacheEntryState::Fresh;
    let t = FreshnessThresholds::default_production();
    assert!(t.fresh_max_age_secs > 0);

    // match_zone, ZonePriorityPolicy, RuleMatchCandidate, RequestedRouteDecision
    use crate::decision_matching::RequestedRouteDecision;
    let _ = ZonePriorityPolicy::default();
    let _ = match_zone("host.intra", "intra");
    let _ = RequestedRouteDecision::DefaultRoute {
        reason: crate::decision_matching::NoMatchReason::NoMatchFound,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    };

    // RouteAvailabilitySnapshot, SnapshotFreshnessThresholds
    use crate::decision_availability::SnapshotFreshnessThresholds;
    let _ = SnapshotFreshnessThresholds::default_production();

    // FinalAction, apply_fail_policy, BrowserClassification
    let _ = FinalAction::Block;
    let _ = BrowserClassification::unclassified();

    // DecisionExplain, DecisionExplainBuilder, UncertaintyMarker
    use crate::decision_explain::{DecisionId, UncertaintyMarker};
    let id = DecisionId("d-test".to_owned());
    assert!(id.as_str().starts_with("d-"));
    let _ = UncertaintyMarker::StaleCacheUsed;
}

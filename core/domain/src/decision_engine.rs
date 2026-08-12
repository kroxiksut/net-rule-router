//! Rule engine public API.
//!
//! This module provides the single public entrypoint [`decide_route`] and the
//! input/output types that form the rule engine's public contract.
//!
//! # Design contract
//!
//! - The engine is **pure and deterministic**: identical inputs always produce
//!   identical outputs and identical ordered traces.
//! - The engine **never** performs I/O, DNS resolution, SQLite reads, OS route
//!   manipulation, or any other side-effecting operation.  All data is injected
//!   by the caller via [`DecisionRequest`].
//! - Errors in input data are converted to [`DecisionWarning`] entries and
//!   produce safe fallback decisions — the engine never panics on bad input.
//!
//! # Pipeline stages
//!
//! ```text
//! DecisionRequest
//!   └─ NormalizedDecisionInput  (pre-normalized by caller)
//!     │
//!     ▼  collect_input_warnings
//!     │
//!     ▼  match_rules → RequestedRouteDecision
//!     │
//!     ▼  resolve_final_action → FinalDecision
//!     │
//!     ▼  build_explain → DecisionExplain
//!     │
//!     ▼  DecisionOutcome
//! ```
//!
//! Each stage lives in its own module: input normalization/adapter support,
//! `match_rules()` for all five tiers, `resolve_final_action()` wiring, and
//! the `DecisionExplainBuilder` wiring in this module.

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::canonical::CanonicalProfile;
use crate::decision_availability::{
    RouteAvailabilitySnapshot, RouteAvailabilityState, SecondaryAvailabilityStatus,
    SnapshotStaleness,
};
use crate::decision_engine_input::collect_input_warnings;
use crate::decision_explain::{
    AvailabilityTraceSummary, DecisionExplain, DecisionExplainBuilder, DecisionId,
    ExplainBuildError, ExplainConflictMarker, ExplainWarning, FinalActionSummary, InputSummary,
    MatchTraceSummary, ObservationSourceLabel, UncertaintyMarker,
};
use crate::decision_fail_policy::{FinalAction, FinalActionReason, FinalDecision};
use crate::decision_final_action::resolve_final_action;
use crate::decision_lookup::LookupResult;
use crate::decision_matching::{
    ConflictMarker, MatchClass, NoMatchReason, RequestedRouteDecision, ZonePriorityPolicy,
};
use crate::decision_normalization::{NormalizedDecisionInput, NormalizedHostname, NormalizedIp};
use crate::decision_pipeline::{DecisionFeatureFlags, ObservationSource, ProcessContext};
use crate::decision_rules_matching::match_rules;
use crate::revision::RevisionId;

// ── DecisionWarning ───────────────────────────────────────────────────────────

/// Engine-level warning emitted during a routing decision.
///
/// Collected in [`DecisionOutcome::warnings`] and also reflected in
/// [`DecisionExplain`] for the operator/UI diagnostics layer.  Warnings
/// describe conditions that did not prevent a decision but are significant
/// enough to surface to the user or operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionWarning {
    /// Hostname was not available; hostname-based tiers (ExactFqdn, SuffixDomain,
    /// Zone) were skipped.
    HostnameUnavailable,
    /// Resolved IP was not available; the `ExactIp` tier was skipped.
    IpUnavailable,
    /// Process/app identity was not available; application-only rules were
    /// skipped.
    AppContextUnavailable,
    /// The lookup result is stale; matching may use outdated resolution data.
    LookupStale,
    /// The availability snapshot is stale; route status may be outdated.
    AvailabilityStale,
    /// Two rules of equal specificity but different route roles were detected.
    /// The pipeline selected the primary-route rule deterministically.
    ConflictDetected,
    /// A rule of an unsupported type was encountered in the active rule book
    /// and was skipped; the pipeline continued with remaining rules.
    UnsupportedRuleSkipped,
    /// An application rule matched using only a weak process identity signal
    /// (filename only, no path or signature).
    WeakAppIdentityMatch,
    /// Route availability state is unknown (stale snapshot or probe failed);
    /// the pipeline applied conservative policy.
    AvailabilityUnknown,
}

// ── DecisionDiagnosticId ──────────────────────────────────────────────────────

/// An opaque correlation identifier attached to a routing decision for
/// diagnostics and log correlation.
///
/// Format: `"d-<uuid>"` — the same scheme used by [`DecisionId`], but
/// diagnostic IDs link *specific events within* a decision to log entries
/// rather than identifying the decision as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecisionDiagnosticId(pub String);

// ── DecisionRequest ───────────────────────────────────────────────────────────

/// All inputs required to make a single routing decision.
///
/// The caller assembles this struct from:
/// - a caller-provided [`DecisionId`] (the service layer generates the ID;
///   the engine never creates random values),
/// - the active [`CanonicalProfile`] (rule book from the active revision),
/// - a [`NormalizedDecisionInput`] (output of the normalization stage),
/// - a [`LookupResult`] injected by the service/cache layer — the engine
///   never resolves DNS or reads SQLite directly,
/// - a [`RouteAvailabilitySnapshot`] injected by the service layer,
/// - the active [`ZonePriorityPolicy`] (from `UiPreferences`),
/// - the active [`DecisionFeatureFlags`] (from `UiPreferences`),
/// - the [`ProcessContext`] for browser classification and explain assembly,
/// - the [`ObservationSource`] for explain output provenance.
///
/// The engine reads this struct once and produces a [`DecisionOutcome`].
/// It does not cache or mutate `DecisionRequest`.
#[derive(Debug)]
pub struct DecisionRequest {
    /// Stable identifier for this decision, provided by the caller.
    ///
    /// The service layer generates a UUID v4 per invocation.  Test code uses
    /// a fixed deterministic string.  The engine never generates IDs
    /// internally — that would break pure/deterministic semantics.
    pub decision_id: DecisionId,
    /// ID of the active policy revision this decision is evaluated against.
    pub revision_id: RevisionId,
    /// The canonical rule book and route bindings for the active revision.
    pub profile: CanonicalProfile,
    /// Normalised destination and process identity.
    pub input: NormalizedDecisionInput,
    /// FQDN/IP lookup result — pre-computed by the service/cache layer.
    pub lookup: LookupResult,
    /// Adapter availability snapshot — pre-computed by the service layer.
    pub availability: RouteAvailabilitySnapshot,
    /// Whether Zone or ExactIp is evaluated first in tier 3 of matching.
    pub zone_policy: ZonePriorityPolicy,
    /// Feature flags for experimental routing paths (e.g. browser stub).
    pub feature_flags: DecisionFeatureFlags,
    /// Identity and context of the originating process (browser hint, paths).
    pub process_context: ProcessContext,
    /// Source of this observation — used for explain output provenance.
    pub observation_source: ObservationSource,
}

// ── DecisionOutcome ───────────────────────────────────────────────────────────

/// The complete output of a single routing decision.
///
/// Produced by [`decide_route`] and consumed by:
/// - the service layer — to apply `final_action` via the platform adapter,
/// - the IPC/DTO layer — to propagate the outcome to GUI/tray,
/// - the diagnostics layer — via `decision_id` and `diagnostic_ids` for log
///   correlation and audit trails.
#[derive(Debug)]
pub struct DecisionOutcome {
    /// Stable identifier for this decision instance.  Format: `"d-<uuid>"`.
    pub decision_id: DecisionId,
    /// What route the rule matching stage requested.
    pub requested_route: RequestedRouteDecision,
    /// The final routing action after availability and fail-policy arbitration.
    pub final_action: FinalAction,
    /// Why the final action was chosen.
    pub final_action_reason: FinalActionReason,
    /// Full explain payload for UI diagnostics and operator tooling.
    pub explain: DecisionExplain,
    /// Engine-level warnings collected during this decision.
    pub warnings: Vec<DecisionWarning>,
    /// Correlation IDs linking decision events to log/audit entries.
    pub diagnostic_ids: Vec<DecisionDiagnosticId>,
}

// ── decide_route ──────────────────────────────────────────────────────────────

/// Make a single routing decision for the given request.
///
/// This is the sole public entrypoint of the rule engine.  It is pure and
/// deterministic: identical inputs always produce identical outputs and
/// identical ordered traces.
///
/// # Panics
///
/// Panics only on an internal invariant violation in the explain builder
/// (missing required fields).  Valid callers — those who construct
/// `DecisionRequest` via the normal builder — will never trigger a panic.
pub fn decide_route(request: DecisionRequest) -> DecisionOutcome {
    let behavior_mode = request.profile.behavior_mode;

    // Stage 1: collect input warnings
    let warnings = collect_input_warnings(&request.input, &request.lookup, &request.availability);

    // Stage 2: rule matching across all five tiers
    let match_result = match_rules(
        &request.input,
        &request.lookup,
        &request.profile.rule_book,
        request.zone_policy,
        behavior_mode,
    );

    // Stage 3: availability check + fail-policy arbitration
    let final_decision = resolve_final_action(
        &match_result,
        &request.availability,
        behavior_mode,
        &request.feature_flags,
        &request.process_context,
        &request.input.app_identity,
    );

    // Stage 4: explain assembly
    let decision_id = request.decision_id.clone();
    let explain = build_explain(&request, &match_result, &final_decision, &warnings)
        .unwrap_or_else(|e| panic!("DecisionExplainBuilder invariant violated: {e:?}"));

    DecisionOutcome {
        decision_id,
        requested_route: match_result,
        final_action: final_decision.action,
        final_action_reason: final_decision.reason,
        explain,
        warnings,
        // TODO: populate `diagnostic_ids` from the audit log lookup once
        // `decide_route` is invoked from the production service path.
        // Currently per-packet decisions are kernel-side WFP, so no
        // `DecisionOutcome` producer exists yet.
        diagnostic_ids: Vec::new(),
    }
}

// ── Internal explain assembly ─────────────────────────────────────────────────

/// Assembles a [`DecisionExplain`] from all stage outputs.
///
/// This is the explain-builder wiring.  It maps raw stage data (rule match
/// candidate, availability snapshot, fail-policy result) to the builder API
/// without embedding UI text in the matching or policy stages.
fn build_explain(
    request: &DecisionRequest,
    match_result: &RequestedRouteDecision,
    final_decision: &FinalDecision,
    warnings: &[DecisionWarning],
) -> Result<DecisionExplain, ExplainBuildError> {
    let behavior_mode = request.profile.behavior_mode;
    let input_summary = build_input_summary(
        &request.input,
        &request.process_context,
        &request.observation_source,
    );
    let match_trace = build_match_trace(match_result, behavior_mode);
    let avail_trace = build_avail_trace(match_result, &request.availability, behavior_mode);
    let final_summary = build_final_action_summary(final_decision);

    let mut b =
        DecisionExplainBuilder::new(request.decision_id.clone(), request.revision_id.as_str())
            .input_summary(input_summary)
            .match_trace(match_trace)
            .availability_trace(avail_trace)
            .final_action(final_summary);

    // Propagate markers and warnings from input/lookup/availability warnings
    for w in warnings {
        b = propagate_warning(b, w);
    }

    // Stale uncertainty from final_decision (fail-policy stage may set it)
    if final_decision.has_uncertainty {
        b = b.add_uncertainty(UncertaintyMarker::StaleAvailabilitySnapshot);
    }

    // Conflict from the match result
    if let RequestedRouteDecision::MatchedRoute { candidate } = match_result {
        if matches!(candidate.conflict, ConflictMarker::Detected) {
            b = b
                .add_conflict(ExplainConflictMarker::DuplicateConflictingRules)
                .add_warning(ExplainWarning::MatchConflictResolved);
        }
    }

    // Used signals (what data drove the decision)
    b = b.add_signal(match_signal_label(match_result));
    if matches!(request.input.hostname, NormalizedHostname::Valid(_)) {
        b = b.add_signal("hostname");
    }
    if matches!(request.input.ip, NormalizedIp::ValidIpv4(_)) {
        b = b.add_signal("ip");
    }
    if request.input.app_identity.is_some() {
        b = b.add_signal("process_name");
    }

    b.build()
}

fn build_input_summary(
    input: &NormalizedDecisionInput,
    process_context: &ProcessContext,
    observation_source: &ObservationSource,
) -> InputSummary {
    let destination_hostname = match &input.hostname {
        NormalizedHostname::Valid(h) => Some(h.clone()),
        NormalizedHostname::Invalid { raw, .. } => Some(raw.clone()),
        NormalizedHostname::Unavailable => None,
    };
    InputSummary {
        destination_hostname,
        destination_ip_present: matches!(input.ip, NormalizedIp::ValidIpv4(_)),
        process_name: input.app_identity.as_ref().map(|a| a.process_name.clone()),
        process_path_extended: process_context.process_path.clone(),
        observation_source: match observation_source {
            ObservationSource::WfpCallback => ObservationSourceLabel::WfpCallback,
            ObservationSource::TestHarness => ObservationSourceLabel::TestHarness,
        },
    }
}

fn build_match_trace(
    match_result: &RequestedRouteDecision,
    behavior_mode: RouteBehaviorMode,
) -> MatchTraceSummary {
    match match_result {
        RequestedRouteDecision::MatchedRoute { candidate } => MatchTraceSummary::RuleMatched {
            rule_id: candidate.rule_id.clone(),
            match_class_label: match_class_label(candidate.match_class),
            route_role: candidate.route_role,
            conflict_resolved: matches!(candidate.conflict, ConflictMarker::Detected),
        },
        RequestedRouteDecision::DefaultRoute { reason, .. } => MatchTraceSummary::DefaultRoute {
            reason_label: no_match_reason_label(*reason),
            behavior_mode_label: behavior_mode_label(behavior_mode),
        },
    }
}

fn build_avail_trace(
    match_result: &RequestedRouteDecision,
    snapshot: &RouteAvailabilitySnapshot,
    behavior_mode: RouteBehaviorMode,
) -> AvailabilityTraceSummary {
    let requested_route = match match_result {
        RequestedRouteDecision::MatchedRoute { candidate } => candidate.route_role,
        RequestedRouteDecision::DefaultRoute { .. } => behavior_mode.default_route_role(),
    };
    let effective_state = snapshot.effective_state(requested_route);
    let snapshot_stale = !matches!(snapshot.staleness, SnapshotStaleness::Fresh);
    let secondary_not_configured = requested_route == RouteRole::Secondary
        && matches!(
            snapshot.secondary,
            SecondaryAvailabilityStatus::NotConfigured
        );

    AvailabilityTraceSummary {
        requested_route,
        observed_state_label: avail_state_label(effective_state),
        secondary_not_configured,
        snapshot_stale,
    }
}

fn build_final_action_summary(decision: &FinalDecision) -> FinalActionSummary {
    FinalActionSummary {
        action: decision.action,
        route_role: decision.route_role,
        reason_label: final_action_reason_label(decision.reason),
        stub_considered_but_rejected: decision.explain.stub_considered_but_rejected,
    }
}

/// Maps a [`DecisionWarning`] to the appropriate builder calls.
fn propagate_warning(b: DecisionExplainBuilder, w: &DecisionWarning) -> DecisionExplainBuilder {
    match w {
        DecisionWarning::HostnameUnavailable => {
            b.add_uncertainty(UncertaintyMarker::HostnameUnavailable)
        }
        DecisionWarning::IpUnavailable => b,
        DecisionWarning::AppContextUnavailable => {
            b.add_uncertainty(UncertaintyMarker::AppContextUnavailable)
        }
        DecisionWarning::LookupStale => b
            .add_uncertainty(UncertaintyMarker::StaleCacheUsed)
            .add_warning(ExplainWarning::LookupStaleCacheUsed),
        DecisionWarning::AvailabilityStale => b
            .add_uncertainty(UncertaintyMarker::StaleAvailabilitySnapshot)
            .add_warning(ExplainWarning::AvailabilitySnapshotStale),
        DecisionWarning::AvailabilityUnknown => {
            b.add_uncertainty(UncertaintyMarker::UnknownSecondaryState)
        }
        DecisionWarning::ConflictDetected => b
            .add_conflict(ExplainConflictMarker::DuplicateConflictingRules)
            .add_warning(ExplainWarning::MatchConflictResolved),
        DecisionWarning::WeakAppIdentityMatch => b.add_warning(ExplainWarning::WeakProcessIdentity),
        DecisionWarning::UnsupportedRuleSkipped => {
            b.add_conflict(ExplainConflictMarker::UnsupportedRuleTypeEncountered)
        }
    }
}

// ── Label helpers ─────────────────────────────────────────────────────────────

fn match_signal_label(match_result: &RequestedRouteDecision) -> &'static str {
    match match_result {
        RequestedRouteDecision::MatchedRoute { candidate } => match candidate.match_class {
            MatchClass::ExactFqdn => "hostname_exact",
            MatchClass::SuffixDomain => "hostname_suffix",
            MatchClass::Zone => "hostname_zone",
            MatchClass::ExactIp => "ip_exact",
            MatchClass::Application => "app_name",
            MatchClass::Default => "default_route",
        },
        RequestedRouteDecision::DefaultRoute { .. } => "default_route",
    }
}

fn match_class_label(class: MatchClass) -> String {
    match class {
        MatchClass::ExactFqdn => "ExactFqdn",
        MatchClass::SuffixDomain => "SuffixDomain",
        MatchClass::ExactIp => "ExactIp",
        MatchClass::Zone => "Zone",
        MatchClass::Application => "Application",
        MatchClass::Default => "Default",
    }
    .to_owned()
}

fn no_match_reason_label(reason: NoMatchReason) -> String {
    match reason {
        NoMatchReason::AllClassesBlocked => "all_classes_blocked",
        NoMatchReason::EmptyRuleBook => "empty_rule_book",
        NoMatchReason::NoMatchFound => "no_match_found",
    }
    .to_owned()
}

fn behavior_mode_label(mode: RouteBehaviorMode) -> String {
    match mode {
        RouteBehaviorMode::PreferPrimary => "prefer_primary",
        RouteBehaviorMode::PreferSecondaryWhenAvailable => "prefer_secondary_when_available",
        RouteBehaviorMode::StrictSecondaryFailClosed => "strict_secondary_fail_closed",
    }
    .to_owned()
}

fn avail_state_label(state: RouteAvailabilityState) -> String {
    match state {
        RouteAvailabilityState::Available => "available",
        RouteAvailabilityState::Degraded => "degraded",
        RouteAvailabilityState::Unavailable => "unavailable",
        RouteAvailabilityState::Unknown => "unknown",
    }
    .to_owned()
}

fn final_action_reason_label(reason: FinalActionReason) -> String {
    match reason {
        FinalActionReason::SecondaryAvailable => "secondary_available",
        FinalActionReason::SecondaryUnavailableFailClosed => "secondary_unavailable_fail_closed",
        FinalActionReason::SecondaryUnavailableFailOpen => "secondary_unavailable_fail_open",
        FinalActionReason::SecondaryNotConfiguredFailOpen => "secondary_not_configured_fail_open",
        FinalActionReason::SecondaryNotConfiguredFailClosed => {
            "secondary_not_configured_fail_closed"
        }
        FinalActionReason::PrimaryRequested => "primary_requested",
        FinalActionReason::PrimaryDefault => "primary_default",
        FinalActionReason::PrimaryOnlyRoute => "primary_only_route",
        FinalActionReason::BrowserStubEnabled => "browser_stub_enabled",
        FinalActionReason::BrowserStubNotPossible => "browser_stub_not_possible",
        FinalActionReason::StaleAvailabilityUsed => "stale_availability_used",
        FinalActionReason::RevisionNotReady => "revision_not_ready",
        FinalActionReason::RuleBlocked => "rule_blocked",
    }
    .to_owned()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use nrr_shared::{RouteBehaviorMode, RouteRole};

    use super::*;
    use crate::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
        CanonicalRuleBook, CanonicalRuleSet,
    };
    use crate::decision_availability::{
        AvailabilityCheckSource, InterfaceLifecycleState, RouteAdapterAvailability,
        RouteAvailabilityState, SecondaryAvailabilityStatus, SnapshotStaleness,
    };
    use crate::decision_engine_input::test_support::{
        both_available_snapshot, dual_route_profile, minimal_profile, primary_available_snapshot,
        runtime_input_for, secondary_no_ip_snapshot, stale_snapshot, DecisionRequestBuilder,
    };
    use crate::decision_explain::{ExplainConflictMarker, UncertaintyMarker};
    use crate::decision_pipeline::{DecisionFeatureFlags, ObservationSource, ProcessContext};
    use crate::revision::RevisionId;
    use crate::{AdapterIdentity, BindingSource, RouteBinding, RuleId};

    // ── Test ID ───────────────────────────────────────────────────────────────

    fn test_id() -> DecisionId {
        DecisionId("d-11111111-1111-1111-1111-111111111111".to_owned())
    }

    // ── Profile helpers ───────────────────────────────────────────────────────

    fn secondary_fail_closed_profile() -> crate::canonical::CanonicalProfile {
        crate::canonical::CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "eth0".to_owned(),
                    display_name: "Ethernet".to_owned(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: Some(RouteBinding {
                role: RouteRole::Secondary,
                adapter: AdapterIdentity {
                    stable_id: "vpn0".to_owned(),
                    display_name: "VPN".to_owned(),
                },
                source: BindingSource::UserAssigned,
            }),
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            rule_book: CanonicalRuleBook::default(),
        }
    }

    fn rule_book_with_secondary(rules: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(rules),
        }
    }

    fn exact_fqdn_rule_secondary(id: &str, fqdn: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(fqdn.to_owned())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule_secondary(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(label.to_owned())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn zone_rule_secondary(id: &str, zone: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(zone.to_owned())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn ip_rule_secondary(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(addr)),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn app_rule_secondary(id: &str, name: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_owned()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(name.to_owned()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    // ── Snapshot helpers ──────────────────────────────────────────────────────

    fn secondary_unavailable_snapshot() -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability {
                state: RouteAvailabilityState::Unavailable,
                lifecycle: InterfaceLifecycleState::Disconnected,
                reason: None,
            }),
            taken_at: std::time::SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    fn build_request(
        profile: crate::canonical::CanonicalProfile,
        hostname: Option<&str>,
        ip: Option<std::net::IpAddr>,
        process_name: Option<&str>,
        browser_hint: bool,
        availability: RouteAvailabilitySnapshot,
        feature_flags: DecisionFeatureFlags,
    ) -> DecisionRequest {
        use crate::decision_engine_input::normalize_runtime_input;
        use crate::decision_engine_input::test_support::empty_lookup;
        use crate::decision_pipeline::{ProtocolHints, RuntimeInput};

        let ri = RuntimeInput {
            process_context: ProcessContext {
                pid: 1,
                process_name: process_name.map(str::to_owned),
                process_path: None,
                parent_pid: None,
                browser_hint,
            },
            destination_hostname: hostname.map(str::to_owned),
            destination_ip: ip,
            protocol_hints: ProtocolHints {
                ip_protocol: None,
                destination_port: None,
            },
            active_revision_id: RevisionId::from_prefixed_string("rev-test-001".to_owned())
                .unwrap_or_else(|e| panic!("bad rev id: {e}")),
            route_behavior_mode: profile.behavior_mode,
            interface_availability: crate::decision_pipeline::InterfaceAvailabilitySnapshot {
                primary: crate::decision_pipeline::AdapterAvailability::Available,
                secondary: None,
            },
            observed_at: std::time::SystemTime::UNIX_EPOCH,
            observation_source: ObservationSource::TestHarness,
            feature_flags: feature_flags.clone(),
        };

        DecisionRequest {
            decision_id: test_id(),
            revision_id: RevisionId::from_prefixed_string("rev-test-001".to_owned())
                .unwrap_or_else(|e| panic!("bad rev id: {e}")),
            profile,
            input: normalize_runtime_input(&ri),
            lookup: empty_lookup(),
            availability,
            zone_policy: crate::decision_matching::ZonePriorityPolicy::default(),
            feature_flags,
            process_context: ri.process_context,
            observation_source: ObservationSource::TestHarness,
        }
    }

    // ── ExactFqdn match ───────────────────────────────────────────────────────

    #[test]
    fn exact_fqdn_match_routes_to_secondary_when_available() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-001", "example.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert_eq!(
            outcome.final_action_reason,
            FinalActionReason::SecondaryAvailable
        );
        assert!(outcome.explain.is_complete_for(FinalAction::RouteSecondary));
        assert_eq!(
            outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched {
                rule_id: RuleId("r-001".to_owned()),
                match_class_label: "ExactFqdn".to_owned(),
                route_role: RouteRole::Secondary,
                conflict_resolved: false,
            })
        );
        assert!(outcome
            .explain
            .used_signals
            .contains(&"hostname_exact".to_owned()));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"hostname".to_owned()));
    }

    // ── SuffixDomain match ────────────────────────────────────────────────────

    #[test]
    fn suffix_domain_match_routes_sub_to_secondary() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![suffix_rule_secondary("r-002", "example.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("sub.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "SuffixDomain"
        ));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"hostname_suffix".to_owned()));
    }

    // ── Zone match ────────────────────────────────────────────────────────────

    #[test]
    fn zone_match_routes_hostname_in_zone_to_secondary() {
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![zone_rule_secondary("r-003", "ru")]);

        let outcome = decide_route(build_request(
            profile,
            Some("news.example.ru"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "Zone"
        ));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"hostname_zone".to_owned()));
    }

    // ── ExactIp match ─────────────────────────────────────────────────────────

    #[test]
    fn exact_ip_match_routes_to_secondary() {
        use std::net::IpAddr;
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![ip_rule_secondary("r-004", ip)]);

        let outcome = decide_route(build_request(
            profile,
            None,
            Some(IpAddr::V4(ip)),
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "ExactIp"
        ));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"ip_exact".to_owned()));
        assert!(outcome.explain.used_signals.contains(&"ip".to_owned()));
    }

    // ── Application fallback ──────────────────────────────────────────────────

    #[test]
    fn app_rule_matches_when_no_address_matches() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![app_rule_secondary("r-005", "myvpnclient.exe")]);

        let outcome = decide_route(build_request(
            profile,
            None,
            None,
            Some("myvpnclient.exe"),
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "Application"
        ));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"app_name".to_owned()));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"process_name".to_owned()));
    }

    // ── Default route ─────────────────────────────────────────────────────────

    #[test]
    fn default_route_prefer_primary_returns_primary() {
        // Use a profile with a rule for a different hostname so "no_match_found" fires
        let mut profile = minimal_profile();
        profile.rule_book.secondary =
            CanonicalRuleSet::from_rules(vec![exact_fqdn_rule_secondary(
                "r-no-match",
                "other.com",
            )]);

        let outcome = decide_route(build_request(
            profile,
            Some("anything.com"),
            None,
            None,
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::DefaultRoute { reason_label, .. })
            if reason_label == "no_match_found"
        ));
        assert!(outcome
            .explain
            .used_signals
            .contains(&"default_route".to_owned()));
    }

    #[test]
    fn default_route_empty_rule_book_produces_empty_rule_book_reason() {
        let outcome = decide_route(build_request(
            minimal_profile(),
            None,
            None,
            None,
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::DefaultRoute { reason_label, .. })
            if reason_label == "empty_rule_book"
        ));
    }

    // ── Fail-open fallback ────────────────────────────────────────────────────

    #[test]
    fn fail_open_secondary_unavailable_routes_to_primary() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-006", "test.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("test.com"),
            None,
            None,
            false,
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert_eq!(
            outcome.final_action_reason,
            FinalActionReason::SecondaryUnavailableFailOpen
        );
        assert_eq!(
            outcome.explain.availability_trace.observed_state_label,
            "unavailable"
        );
    }

    // ── Fail-closed block ─────────────────────────────────────────────────────

    #[test]
    fn fail_closed_secondary_unavailable_blocks() {
        let mut profile = secondary_fail_closed_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-007", "secret.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("secret.com"),
            None,
            None,
            false,
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.final_action, FinalAction::Block);
        assert_eq!(
            outcome.final_action_reason,
            FinalActionReason::SecondaryUnavailableFailClosed
        );
        assert!(outcome.explain.is_blocked());
        assert_eq!(
            outcome.explain.final_action_summary.reason_label,
            "secondary_unavailable_fail_closed"
        );
    }

    // ── Browser stub attempt ──────────────────────────────────────────────────

    #[test]
    fn fail_closed_known_browser_with_stub_enabled_returns_browser_stub_attempt() {
        let mut profile = secondary_fail_closed_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-008", "vpn.example.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("vpn.example.com"),
            None,
            Some("chrome.exe"),
            true, // browser_hint
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags {
                browser_stub_experimental: true,
            },
        ));

        assert_eq!(outcome.final_action, FinalAction::BrowserStubAttempt);
        assert_eq!(
            outcome.final_action_reason,
            FinalActionReason::BrowserStubEnabled
        );
    }

    // ── Explain trace completeness ────────────────────────────────────────────

    #[test]
    fn explain_is_complete_for_all_actions() {
        let mut profile = secondary_fail_closed_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-009", "corp.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("corp.com"),
            None,
            None,
            false,
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert!(outcome.explain.is_complete_for(outcome.final_action));
    }

    #[test]
    fn explain_decision_id_matches_request_id() {
        let outcome = decide_route(build_request(
            minimal_profile(),
            Some("test.com"),
            None,
            None,
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert_eq!(outcome.explain.id(), test_id().as_str());
        assert_eq!(outcome.decision_id, test_id());
    }

    // ── Stale snapshot → uncertainty markers ─────────────────────────────────

    #[test]
    fn stale_snapshot_produces_uncertainty_markers() {
        let outcome = decide_route(build_request(
            minimal_profile(),
            Some("test.com"),
            None,
            None,
            false,
            stale_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert!(outcome.explain.has_uncertainty());
        assert!(outcome
            .explain
            .uncertainty_markers
            .contains(&UncertaintyMarker::StaleAvailabilitySnapshot));
        assert!(outcome
            .explain
            .uncertainty_markers
            .contains(&UncertaintyMarker::UnknownSecondaryState));
    }

    // ── Conflict detection ────────────────────────────────────────────────────

    #[test]
    fn conflict_between_equal_specificity_rules_is_recorded_in_explain() {
        // Two rules with same ExactFqdn "conflict.com" — one in each route set
        let primary_rule = CanonicalRule {
            id: RuleId("r-p".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn("conflict.com".to_owned())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let secondary_rule = CanonicalRule {
            id: RuleId("r-s".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn("conflict.com".to_owned())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };

        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![primary_rule]),
            secondary: CanonicalRuleSet::from_rules(vec![secondary_rule]),
        };

        let outcome = decide_route(build_request(
            profile,
            Some("conflict.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert!(outcome.explain.has_conflicts());
        assert!(outcome
            .explain
            .conflict_markers
            .contains(&ExplainConflictMarker::DuplicateConflictingRules));
    }

    // ── Hostname unavailable ──────────────────────────────────────────────────

    #[test]
    fn hostname_unavailable_produces_uncertainty_marker() {
        let outcome = decide_route(build_request(
            minimal_profile(),
            None, // no hostname
            None,
            None,
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        assert!(outcome
            .warnings
            .contains(&DecisionWarning::HostnameUnavailable));
        assert!(outcome
            .explain
            .uncertainty_markers
            .contains(&UncertaintyMarker::HostnameUnavailable));
    }

    // ── Compact summary ───────────────────────────────────────────────────────

    #[test]
    fn compact_summary_contains_action_and_hostname() {
        let outcome = decide_route(build_request(
            minimal_profile(),
            Some("example.com"),
            None,
            None,
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        let summary = outcome.explain.compact_summary();
        assert!(summary.contains("route:primary"));
        assert!(summary.contains("example.com"));
    }

    // ── Deterministic ordering ────────────────────────────────────────────────

    #[test]
    fn explain_used_signals_are_sorted_alphabetically() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r-z", "sort.example.com")]);

        let outcome = decide_route(build_request(
            profile,
            Some("sort.example.com"),
            None,
            Some("firefox.exe"),
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));

        let signals = &outcome.explain.used_signals;
        let mut sorted = signals.clone();
        sorted.sort();
        assert_eq!(
            *signals, sorted,
            "used_signals must be sorted alphabetically"
        );
    }

    // ── DecisionWarning unit tests ────────────────────────────────────────────

    #[test]
    fn decision_warning_clone_and_eq() {
        let w = DecisionWarning::HostnameUnavailable;
        assert_eq!(w.clone(), DecisionWarning::HostnameUnavailable);
        assert_ne!(w, DecisionWarning::IpUnavailable);
    }

    #[test]
    fn decision_warning_all_variants_are_distinct() {
        let variants = [
            DecisionWarning::HostnameUnavailable,
            DecisionWarning::IpUnavailable,
            DecisionWarning::AppContextUnavailable,
            DecisionWarning::LookupStale,
            DecisionWarning::AvailabilityStale,
            DecisionWarning::ConflictDetected,
            DecisionWarning::UnsupportedRuleSkipped,
            DecisionWarning::WeakAppIdentityMatch,
            DecisionWarning::AvailabilityUnknown,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn decision_diagnostic_id_wraps_string() {
        let id = DecisionDiagnosticId("d-abc-123".to_owned());
        assert_eq!(id.0, "d-abc-123");
        assert_eq!(id.clone(), id);
    }

    #[test]
    fn decision_diagnostic_id_hash_consistency() {
        use std::collections::HashSet;
        let a = DecisionDiagnosticId("d-aaa".to_owned());
        let b = DecisionDiagnosticId("d-aaa".to_owned());
        let c = DecisionDiagnosticId("d-bbb".to_owned());
        let mut set = HashSet::new();
        set.insert(a.clone());
        set.insert(b.clone());
        set.insert(c.clone());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&a));
        assert!(set.contains(&c));
    }

    // ── Match priority order ─────────────────────────────────────

    #[test]
    fn match_order_exact_fqdn_always_beats_suffix_for_same_hostname() {
        // ExactFqdn and SuffixDomain both match "api.example.com" — ExactFqdn wins.
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![
                exact_fqdn_rule_secondary("fqdn", "api.example.com"),
                suffix_rule_secondary("suffix", "example.com"),
            ]),
        };
        let outcome = decide_route(build_request(
            profile,
            Some("api.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, rule_id, .. })
            if match_class_label == "ExactFqdn" && rule_id.0 == "fqdn"
        ));
    }

    #[test]
    fn match_order_suffix_domain_beats_zone_for_same_hostname() {
        // SuffixDomain("example.ru") and Zone("ru") both match "test.example.ru" — SuffixDomain wins.
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![
            suffix_rule_secondary("suffix", "example.ru"),
            zone_rule_secondary("zone", "ru"),
        ]);
        let outcome = decide_route(build_request(
            profile,
            Some("test.example.ru"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, rule_id, .. })
            if match_class_label == "SuffixDomain" && rule_id.0 == "suffix"
        ));
    }

    #[test]
    fn match_order_zone_beats_app_for_zone_hostname() {
        // Zone("ru") and Application("myapp.exe") — Zone wins when hostname is in zone.
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![
            zone_rule_secondary("zone", "ru"),
            app_rule_secondary("app", "myapp.exe"),
        ]);
        let outcome = decide_route(build_request(
            profile,
            Some("news.example.ru"),
            None,
            Some("myapp.exe"),
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, rule_id, .. })
            if match_class_label == "Zone" && rule_id.0 == "zone"
        ));
    }

    // ── Zone matching ─────────────────────────────────────────────

    #[test]
    fn zone_does_not_match_ip_only_traffic_without_hostname() {
        // Zone rule "ru" — no hostname in input → zone tier is skipped → DefaultRoute.
        use std::net::IpAddr;
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![zone_rule_secondary("zone", "ru")]);
        let outcome = decide_route(build_request(
            profile,
            None,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert!(
            matches!(
                &outcome.explain.match_trace,
                Some(MatchTraceSummary::DefaultRoute { .. })
            ),
            "zone must not match when hostname is unavailable"
        );
        assert!(outcome
            .warnings
            .contains(&DecisionWarning::HostnameUnavailable));
    }

    #[test]
    fn zone_idn_punycode_zone_matches_unicode_hostname() {
        // The validation pipeline canonicalizes zone "рф" to "xn--p1ai"
        // (see `validation::zone_unicode_normalized_to_punycode`), and
        // `normalize_runtime_input` punycode-encodes Unicode hostnames, so
        // the two sides meet on ASCII: "пример.рф" must match the zone.
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![zone_rule_secondary("zone-rf", "xn--p1ai")]);
        let outcome = decide_route(build_request(
            profile,
            Some("пример.рф"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, rule_id, .. })
            if match_class_label == "Zone" && rule_id.0 == "zone-rf"
        ));
    }

    #[test]
    fn zone_priority_ip_first_ip_beats_zone_when_both_match() {
        // Default policy (prefer_ip=true): ExactIp rule (primary) beats Zone rule (secondary).
        use std::net::IpAddr;
        let ip_addr = Ipv4Addr::new(10, 20, 30, 40);
        let ip_rule_primary = CanonicalRule {
            id: RuleId("ip-p".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(ip_addr)),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![ip_rule_primary]),
            secondary: CanonicalRuleSet::from_rules(vec![zone_rule_secondary("zone-s", "ru")]),
        };
        let outcome = decide_route(build_request(
            profile,
            Some("site.example.ru"),
            Some(IpAddr::V4(ip_addr)),
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "ExactIp"
        ));
    }

    #[test]
    fn zone_priority_zone_first_zone_beats_ip_when_both_match() {
        // Override policy (prefer_ip=false): Zone rule (secondary) beats ExactIp rule (primary).
        use std::net::IpAddr;
        let ip_addr = Ipv4Addr::new(10, 20, 30, 40);
        let ip_rule_primary = CanonicalRule {
            id: RuleId("ip-p".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(ip_addr)),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![ip_rule_primary]),
            secondary: CanonicalRuleSet::from_rules(vec![zone_rule_secondary("zone-s", "ru")]),
        };
        let outcome = decide_route(
            DecisionRequestBuilder::new()
                .profile(profile)
                .runtime_input(runtime_input_for(
                    "site.example.ru",
                    Some(IpAddr::V4(ip_addr)),
                    None,
                ))
                .availability(both_available_snapshot())
                .zone_policy(ZonePriorityPolicy { prefer_ip: false })
                .build(),
        );
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { match_class_label, .. })
            if match_class_label == "Zone"
        ));
    }

    // ── SuffixDomain longest-match ────────────────────────────────

    #[test]
    fn suffix_longest_label_wins_over_shorter_label() {
        // SuffixDomain("api.example.com") secondary (more specific) vs
        // SuffixDomain("example.com") primary (less specific).
        // Hostname "sub.api.example.com" matches both; longer label wins → secondary.
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("short".to_owned()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::SuffixDomain(
                    "example.com".to_owned(),
                )),
                app_match: None,
                comment: String::new(),
                action: crate::canonical::RuleAction::Route,
                origin: None,
            }]),
            secondary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("long".to_owned()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::SuffixDomain(
                    "api.example.com".to_owned(),
                )),
                app_match: None,
                comment: String::new(),
                action: crate::canonical::RuleAction::Route,
                origin: None,
            }]),
        };
        let outcome = decide_route(build_request(
            profile,
            Some("sub.api.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, match_class_label, .. })
            if rule_id.0 == "long" && match_class_label == "SuffixDomain"
        ));
    }

    #[test]
    fn suffix_short_label_still_matches_deep_subdomain() {
        // SuffixDomain("example.com") matches a deeply nested hostname.
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![suffix_rule_secondary("root", "example.com")]);
        let outcome = decide_route(build_request(
            profile,
            Some("deep.sub.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, match_class_label, .. })
            if rule_id.0 == "root" && match_class_label == "SuffixDomain"
        ));
    }

    // ── Suffix-domain apex coverage ────────────────────────────────────────────

    #[test]
    fn suffix_rule_routes_its_own_apex() {
        // `*.example.com` covers "example.com" itself. The rule book is built
        // explicitly here — no `include_subdomains` expansion is involved, so
        // this proves SuffixDomain semantics and nothing else.
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![suffix_rule_secondary("apex", "example.com")]);
        let outcome = decide_route(build_request(
            profile,
            Some("example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, match_class_label, .. })
            if rule_id.0 == "apex" && match_class_label == "SuffixDomain"
        ));
    }

    #[test]
    fn deeper_suffix_wins_when_matched_through_its_apex() {
        // "sub.example.com" is matched by `*.example.com` as a subdomain AND by
        // `*.sub.example.com` as its apex. The deeper suffix must still win —
        // apex coverage must not flatten longest-match within the tier.
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: RuleId("short".to_owned()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::SuffixDomain(
                    "example.com".to_owned(),
                )),
                app_match: None,
                comment: String::new(),
                action: crate::canonical::RuleAction::Route,
                origin: None,
            }]),
            secondary: CanonicalRuleSet::from_rules(vec![suffix_rule_secondary(
                "long",
                "sub.example.com",
            )]),
        };
        let outcome = decide_route(build_request(
            profile,
            Some("sub.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, match_class_label, .. })
            if rule_id.0 == "long" && match_class_label == "SuffixDomain"
        ));
    }

    #[test]
    fn exact_apex_rule_overrides_the_suffix_rule_that_now_covers_it() {
        // The explicit escape hatch for "subdomains here, apex elsewhere":
        // ExactFqdn is tier 1, so the primary-bound apex rule wins.
        let mut profile = dual_route_profile();
        profile.rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![exact_fqdn_rule_secondary(
                "apex-exact",
                "example.com",
            )]),
            secondary: CanonicalRuleSet::from_rules(vec![suffix_rule_secondary(
                "sub-wildcard",
                "example.com",
            )]),
        };
        let outcome = decide_route(build_request(
            profile,
            Some("example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, match_class_label, .. })
            if rule_id.0 == "apex-exact" && match_class_label == "ExactFqdn"
        ));
    }

    #[test]
    fn zone_rule_does_not_route_the_bare_zone_label() {
        // Zone keeps apex-excluded semantics: a `ru` zone rule must not capture
        // a host literally named "ru".
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![zone_rule_secondary("z", "ru")]);
        let outcome = decide_route(build_request(
            profile,
            Some("ru"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        // No rule may claim it — whatever the behavior-mode default then does
        // with the connection is a separate concern.
        assert!(
            !matches!(
                &outcome.explain.match_trace,
                Some(MatchTraceSummary::RuleMatched { .. })
            ),
            "a zone rule must not match its own bare label: {:?}",
            outcome.explain.match_trace
        );
    }

    // ── App-filter AND semantics ──────────────────────────────────

    #[test]
    fn app_filter_on_address_rule_requires_both_conditions_to_match() {
        // ExactFqdn("corp.com") AND app=Exact("corp.exe"): both must match → secondary.
        let rule_with_filter = CanonicalRule {
            id: RuleId("addr-app".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn("corp.com".to_owned())),
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("corp.exe".to_owned()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![rule_with_filter]);
        let outcome = decide_route(build_request(
            profile,
            Some("corp.com"),
            None,
            Some("corp.exe"),
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::RuleMatched { rule_id, .. })
            if rule_id.0 == "addr-app"
        ));
    }

    #[test]
    fn app_filter_on_address_rule_no_match_when_app_differs() {
        // ExactFqdn matches but app_filter fails → rule discarded → DefaultRoute.
        let rule_with_filter = CanonicalRule {
            id: RuleId("addr-app".to_owned()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn("corp.com".to_owned())),
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("corp.exe".to_owned()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let mut profile = dual_route_profile();
        profile.rule_book = rule_book_with_secondary(vec![rule_with_filter]);
        let outcome = decide_route(build_request(
            profile,
            Some("corp.com"),
            None,
            Some("other.exe"),
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert!(
            matches!(
                &outcome.explain.match_trace,
                Some(MatchTraceSummary::DefaultRoute { .. })
            ),
            "address rule with non-matching app filter must fall through to default route"
        );
    }

    // ── Behavior modes ────────────────────────────────────────────

    #[test]
    fn behavior_prefer_secondary_no_match_secondary_available_routes_secondary() {
        // PreferSecondaryWhenAvailable + no rules + secondary available → secondary default.
        let outcome = decide_route(build_request(
            dual_route_profile(),
            Some("no-match.example.com"),
            None,
            None,
            false,
            both_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RouteSecondary);
        assert!(matches!(
            &outcome.explain.match_trace,
            Some(MatchTraceSummary::DefaultRoute { behavior_mode_label, .. })
            if behavior_mode_label == "prefer_secondary_when_available"
        ));
    }

    #[test]
    fn behavior_prefer_secondary_degraded_secondary_routes_primary_fail_open() {
        // PreferSecondaryWhenAvailable + secondary degraded → fail-open → primary.
        let outcome = decide_route(build_request(
            dual_route_profile(),
            Some("no-match.example.com"),
            None,
            None,
            false,
            secondary_no_ip_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert_eq!(
            outcome.explain.availability_trace.observed_state_label,
            "degraded"
        );
    }

    #[test]
    fn behavior_strict_fail_closed_degraded_secondary_blocks() {
        // StrictSecondaryFailClosed + secondary degraded → block.
        let outcome = decide_route(build_request(
            secondary_fail_closed_profile(),
            Some("no-match.example.com"),
            None,
            None,
            false,
            secondary_no_ip_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::Block);
        assert_eq!(
            outcome.explain.availability_trace.observed_state_label,
            "degraded"
        );
    }

    // ── Stale lookup ──────────────────────────────────────────────

    #[test]
    fn stale_lookup_produces_warning_and_stale_cache_uncertainty_marker() {
        use crate::decision_lookup::{
            CacheEntryState, LookupExplainData, LookupExtendedMetadata, LookupStandardSignals,
        };
        let stale = LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit: true,
                    freshness: Some(CacheEntryState::StaleUsable),
                    source: None,
                    errors: vec![],
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: vec![],
                    reverse_hostnames: vec![],
                    selected_entry_ttl_secs: None,
                    selected_entry_resolved_at: None,
                },
            },
        };
        let outcome = decide_route(
            DecisionRequestBuilder::new()
                .lookup(stale)
                .availability(primary_available_snapshot())
                .build(),
        );
        assert!(outcome.warnings.contains(&DecisionWarning::LookupStale));
        assert!(outcome
            .explain
            .uncertainty_markers
            .contains(&UncertaintyMarker::StaleCacheUsed));
    }

    // ── Availability trace ───────────────────────────────────────

    #[test]
    fn avail_trace_secondary_not_configured_has_flag() {
        // PreferSecondaryWhenAvailable + snapshot secondary = NotConfigured → flag set in trace.
        let outcome = decide_route(build_request(
            dual_route_profile(),
            Some("anything.example.com"),
            None,
            None,
            false,
            primary_available_snapshot(), // secondary = NotConfigured
            DecisionFeatureFlags::default(),
        ));
        assert!(
            outcome.explain.availability_trace.secondary_not_configured,
            "secondary_not_configured flag must be set when snapshot has no secondary"
        );
    }

    #[test]
    fn avail_trace_degraded_secondary_shows_degraded_state() {
        let mut profile = dual_route_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r", "target.com")]);
        let outcome = decide_route(build_request(
            profile,
            Some("target.com"),
            None,
            None,
            false,
            secondary_no_ip_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(
            outcome.explain.availability_trace.observed_state_label,
            "degraded"
        );
    }

    // ── Browser / Fail-Closed matrix ──────────────────────────────

    #[test]
    fn fail_closed_non_browser_process_stub_enabled_still_blocks() {
        // Non-browser process + stub enabled → stub not applicable → block.
        let mut profile = secondary_fail_closed_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r", "secret.com")]);
        let outcome = decide_route(build_request(
            profile,
            Some("secret.com"),
            None,
            Some("notepad.exe"),
            false, // no browser_hint
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags {
                browser_stub_experimental: true,
            },
        ));
        assert_eq!(outcome.final_action, FinalAction::Block);
        assert_eq!(
            outcome.final_action_reason,
            FinalActionReason::SecondaryUnavailableFailClosed
        );
    }

    #[test]
    fn fail_closed_no_app_identity_stub_enabled_blocks() {
        // No app identity → browser classification unknown → stub not applicable → block.
        let mut profile = secondary_fail_closed_profile();
        profile.rule_book =
            rule_book_with_secondary(vec![exact_fqdn_rule_secondary("r", "secret.com")]);
        let outcome = decide_route(build_request(
            profile,
            Some("secret.com"),
            None,
            None, // no process
            false,
            secondary_unavailable_snapshot(),
            DecisionFeatureFlags {
                browser_stub_experimental: true,
            },
        ));
        assert_eq!(outcome.final_action, FinalAction::Block);
    }

    // ── Determinism ───────────────────────────────────────────────

    #[test]
    fn decide_route_is_deterministic_for_identical_inputs() {
        let make = || {
            let mut profile = dual_route_profile();
            profile.rule_book = rule_book_with_secondary(vec![exact_fqdn_rule_secondary(
                "r-det",
                "det.example.com",
            )]);
            build_request(
                profile,
                Some("det.example.com"),
                None,
                None,
                false,
                both_available_snapshot(),
                DecisionFeatureFlags::default(),
            )
        };
        let o1 = decide_route(make());
        let o2 = decide_route(make());
        assert_eq!(o1.final_action, o2.final_action);
        assert_eq!(o1.final_action_reason, o2.final_action_reason);
        assert_eq!(o1.warnings, o2.warnings);
        assert_eq!(o1.explain.compact_summary(), o2.explain.compact_summary());
        assert_eq!(o1.explain.used_signals, o2.explain.used_signals);
    }

    // ── Incomplete input ─────────────────────────────────────────

    #[test]
    fn all_inputs_missing_produces_primary_route_with_unavailable_warnings() {
        // No hostname, no IP, no app identity — all input classes unavailable.
        let outcome = decide_route(build_request(
            minimal_profile(),
            None, // no hostname
            None, // no IP
            None, // no process
            false,
            primary_available_snapshot(),
            DecisionFeatureFlags::default(),
        ));
        assert_eq!(outcome.final_action, FinalAction::RoutePrimary);
        assert!(outcome
            .warnings
            .contains(&DecisionWarning::HostnameUnavailable));
        assert!(outcome.warnings.contains(&DecisionWarning::IpUnavailable));
        assert!(outcome
            .warnings
            .contains(&DecisionWarning::AppContextUnavailable));
        assert!(outcome.explain.has_uncertainty());
    }
}

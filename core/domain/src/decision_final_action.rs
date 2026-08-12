//! Availability check and fail-policy wiring.
//!
//! This module wires two pipeline stages together:
//!
//! 1. **Availability check** ([`check_availability`]) — converts a
//!    [`RequestedRouteDecision`] + [`RouteAvailabilitySnapshot`] into an
//!    [`AvailabilityCheckOutcome`] that describes whether the requested route
//!    is reachable right now.
//!
//! 2. **Fail-policy arbitration** — calls the existing [`apply_fail_policy`]
//!    with the outcome to produce the [`FinalDecision`].
//!
//! Public entry point: [`resolve_final_action`].
//!
//! # Invariants
//!
//! - `StrictSecondaryFailClosed` never silently routes to primary.
//! - Browser stub is attempted only when `browser_stub_experimental == true`,
//!   the process is a confirmed known browser, and Fail-Closed is active.
//! - `PreferPrimary` and `PreferSecondaryWhenAvailable` never block.

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::decision_availability::{
    AvailabilityCheckOutcome, AvailabilityExplainData, AvailabilityReason,
    RouteAdapterAvailability, RouteAvailabilitySnapshot, RouteAvailabilityState,
    SecondaryAvailabilityStatus, SnapshotStaleness,
};
use crate::decision_fail_policy::{
    apply_fail_policy, BrowserClassification, BrowserClassificationBasis, FailPolicyInput,
    FinalDecision,
};
use crate::decision_matching::RequestedRouteDecision;
use crate::decision_normalization::NormalizedAppIdentity;
use crate::decision_pipeline::{DecisionFeatureFlags, ProcessContext};
use crate::RuleAction;

// ── Known browser process names ───────────────────────────────────────────────

/// Normalized lowercase process names that are recognised as browser executables.
///
/// Matching is exact — process names are already normalised to lowercase `.exe`
/// before reaching this check.
const KNOWN_BROWSER_NAMES: &[&str] = &[
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
    "waterfox.exe",
    "seamonkey.exe",
    "opera_autoupdate.exe", // intentionally not a browser for stub purposes
];

// ── Public entry point ────────────────────────────────────────────────────────

/// Converts a [`RequestedRouteDecision`] into a [`FinalDecision`] by running
/// the availability check (stage 4) and Fail-Closed / Fail-Open arbitration
/// (stage 5).
///
/// This wiring function does not perform I/O — it reads only the
/// pre-computed `snapshot`, normalised `app_identity`, and `process_context`.
pub fn resolve_final_action(
    requested: &RequestedRouteDecision,
    snapshot: &RouteAvailabilitySnapshot,
    behavior_mode: RouteBehaviorMode,
    feature_flags: &DecisionFeatureFlags,
    process_context: &ProcessContext,
    app_identity: &Option<NormalizedAppIdentity>,
) -> FinalDecision {
    // A rule-level Block short-circuits ALL availability / fail-policy
    // arbitration: the destination is dropped regardless of route role,
    // reachability, or behavior mode. This mirrors the WFP codegen layer,
    // which emits a hard `FWP_ACTION_BLOCK` filter and installs no route.
    if let RequestedRouteDecision::MatchedRoute { candidate } = requested {
        if candidate.action == RuleAction::Block {
            return FinalDecision::rule_blocked();
        }
    }

    let availability = check_availability(requested, snapshot, behavior_mode);
    let browser = classify_browser(process_context, app_identity);
    let policy_input = FailPolicyInput {
        availability,
        browser_stub_experimental: feature_flags.browser_stub_experimental,
        browser,
    };
    apply_fail_policy(&policy_input)
}

// ── Availability check ────────────────────────────────────────────────────────

/// Maps `RequestedRouteDecision + snapshot + behavior_mode` to an
/// [`AvailabilityCheckOutcome`] for the fail-policy stage.
///
/// For `MatchedRoute`, the requested route role comes from the winning candidate.
/// For `DefaultRoute`, it is derived from `behavior_mode`:
/// - `PreferPrimary` → check primary availability.
/// - `PreferSecondaryWhenAvailable` / `StrictSecondaryFailClosed` → check
///   secondary availability (the fail-policy stage handles fallback / block).
fn check_availability(
    requested: &RequestedRouteDecision,
    snapshot: &RouteAvailabilitySnapshot,
    behavior_mode: RouteBehaviorMode,
) -> AvailabilityCheckOutcome {
    let requested_role = match requested {
        RequestedRouteDecision::MatchedRoute { candidate } => candidate.route_role,
        RequestedRouteDecision::DefaultRoute { .. } => behavior_mode.default_route_role(),
    };

    match requested_role {
        RouteRole::Primary => check_primary(snapshot),
        RouteRole::Secondary => check_secondary(snapshot, behavior_mode),
    }
}

fn check_primary(snapshot: &RouteAvailabilitySnapshot) -> AvailabilityCheckOutcome {
    let effective = snapshot.effective_state(RouteRole::Primary);
    let stale_marker = snapshot_stale_marker(snapshot);
    let explain = AvailabilityExplainData {
        requested_route: RouteRole::Primary,
        observed_state: effective,
        stale_marker,
        unavailability_reason: if snapshot.staleness != SnapshotStaleness::StaleNotUsable {
            snapshot.primary.reason
        } else {
            None
        },
        secondary_not_configured: false,
    };
    match effective {
        RouteAvailabilityState::Available => AvailabilityCheckOutcome::Available {
            route: RouteRole::Primary,
            explain,
        },
        _ => AvailabilityCheckOutcome::PrimaryDegraded {
            state: effective,
            reason: snapshot.primary.reason,
            explain,
        },
    }
}

fn check_secondary(
    snapshot: &RouteAvailabilitySnapshot,
    behavior_mode: RouteBehaviorMode,
) -> AvailabilityCheckOutcome {
    match &snapshot.secondary {
        SecondaryAvailabilityStatus::NotConfigured => {
            let explain = AvailabilityExplainData {
                requested_route: RouteRole::Secondary,
                observed_state: RouteAvailabilityState::Unavailable,
                stale_marker: None,
                unavailability_reason: Some(AvailabilityReason::NotConfigured),
                secondary_not_configured: true,
            };
            AvailabilityCheckOutcome::SecondaryNotConfigured {
                behavior_mode,
                explain,
            }
        }
        SecondaryAvailabilityStatus::Configured(adapter) => {
            check_secondary_configured(snapshot, adapter, behavior_mode)
        }
    }
}

fn check_secondary_configured(
    snapshot: &RouteAvailabilitySnapshot,
    adapter: &RouteAdapterAvailability,
    behavior_mode: RouteBehaviorMode,
) -> AvailabilityCheckOutcome {
    let effective = snapshot.effective_state(RouteRole::Secondary);
    let stale_marker = snapshot_stale_marker(snapshot);
    let unavailability_reason = if snapshot.staleness != SnapshotStaleness::StaleNotUsable {
        adapter.reason
    } else {
        None
    };
    let explain = AvailabilityExplainData {
        requested_route: RouteRole::Secondary,
        observed_state: effective,
        stale_marker,
        unavailability_reason,
        secondary_not_configured: false,
    };
    match effective {
        RouteAvailabilityState::Available => AvailabilityCheckOutcome::Available {
            route: RouteRole::Secondary,
            explain,
        },
        RouteAvailabilityState::Unknown => AvailabilityCheckOutcome::SecondaryUnknown {
            staleness: snapshot.staleness,
            behavior_mode,
            explain,
        },
        _ => AvailabilityCheckOutcome::SecondaryNotReachable {
            state: effective,
            reason: unavailability_reason,
            behavior_mode,
            explain,
        },
    }
}

fn snapshot_stale_marker(snapshot: &RouteAvailabilitySnapshot) -> Option<SnapshotStaleness> {
    match snapshot.staleness {
        SnapshotStaleness::Fresh => None,
        s => Some(s),
    }
}

// ── Browser classification ────────────────────────────────────────────────────

/// Classifies the process as a browser for browser-stub policy decisions.
///
/// Returns a confirmed `KnownProcessName` classification only for processes
/// whose name appears in [`KNOWN_BROWSER_NAMES`]. `browser_hint = true` with
/// an unknown name produces a `WeakHint` (not stub-eligible).
fn classify_browser(
    process_context: &ProcessContext,
    app_identity: &Option<NormalizedAppIdentity>,
) -> BrowserClassification {
    let Some(identity) = app_identity else {
        return BrowserClassification::unclassified();
    };
    let name = &identity.process_name;
    if KNOWN_BROWSER_NAMES.contains(&name.as_str()) {
        return BrowserClassification {
            is_browser: true,
            basis: BrowserClassificationBasis::KnownProcessName {
                process_name: name.clone(),
            },
        };
    }
    if process_context.browser_hint {
        return BrowserClassification {
            is_browser: false,
            basis: BrowserClassificationBasis::WeakHint {
                process_name: name.clone(),
            },
        };
    }
    BrowserClassification::unclassified()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use nrr_shared::{RouteBehaviorMode, RouteRole};

    use super::*;
    use crate::decision_availability::{
        AvailabilityCheckSource, InterfaceLifecycleState, RouteAdapterAvailability,
        RouteAvailabilitySnapshot, RouteAvailabilityState, SecondaryAvailabilityStatus,
        SnapshotStaleness,
    };
    use crate::decision_fail_policy::{FinalAction, FinalActionReason};
    use crate::decision_matching::{
        AppFilterResult, ConflictMarker, MatchClass, NoMatchReason, RequestedRouteDecision,
        RuleMatchCandidate, SpecificityScore,
    };
    use crate::decision_normalization::NormalizedAppIdentity;
    use crate::decision_pipeline::{DecisionFeatureFlags, ProcessContext};
    use crate::RuleId;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn primary_active() -> RouteAdapterAvailability {
        RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentActive)
    }

    fn primary_no_ip() -> RouteAdapterAvailability {
        RouteAdapterAvailability::from_lifecycle(InterfaceLifecycleState::PresentNoIp)
    }

    fn snapshot(
        primary: RouteAdapterAvailability,
        secondary: SecondaryAvailabilityStatus,
        staleness: SnapshotStaleness,
    ) -> RouteAvailabilitySnapshot {
        RouteAvailabilitySnapshot {
            primary,
            secondary,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    fn fresh_primary_only() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::NotConfigured,
            SnapshotStaleness::Fresh,
        )
    }

    fn fresh_both_available() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentActive,
            )),
            SnapshotStaleness::Fresh,
        )
    }

    fn fresh_secondary_no_ip() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentNoIp,
            )),
            SnapshotStaleness::Fresh,
        )
    }

    fn fresh_secondary_disconnected() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::Disconnected,
            )),
            SnapshotStaleness::Fresh,
        )
    }

    fn stale_usable_both() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentActive,
            )),
            SnapshotStaleness::StaleUsable,
        )
    }

    fn stale_not_usable_both() -> RouteAvailabilitySnapshot {
        snapshot(
            primary_active(),
            SecondaryAvailabilityStatus::Configured(RouteAdapterAvailability::from_lifecycle(
                InterfaceLifecycleState::PresentActive,
            )),
            SnapshotStaleness::StaleNotUsable,
        )
    }

    fn matched(role: RouteRole) -> RequestedRouteDecision {
        RequestedRouteDecision::MatchedRoute {
            candidate: RuleMatchCandidate {
                rule_id: RuleId("r-test".to_owned()),
                route_role: role,
                match_class: MatchClass::ExactFqdn,
                specificity: SpecificityScore::SINGLE,
                app_filter_result: AppFilterResult::NoFilter,
                conflict: ConflictMarker::None,
                action: crate::canonical::RuleAction::Route,
            },
        }
    }

    fn default_route(mode: RouteBehaviorMode) -> RequestedRouteDecision {
        RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::NoMatchFound,
            behavior_mode: mode,
        }
    }

    fn no_flags() -> DecisionFeatureFlags {
        DecisionFeatureFlags::default()
    }
    fn stub_flags() -> DecisionFeatureFlags {
        DecisionFeatureFlags {
            browser_stub_experimental: true,
        }
    }

    fn plain_process(name: &str) -> ProcessContext {
        ProcessContext {
            pid: 1,
            process_name: Some(name.to_owned()),
            process_path: None,
            parent_pid: None,
            browser_hint: false,
        }
    }

    fn browser_hint_process(name: &str) -> ProcessContext {
        ProcessContext {
            pid: 1,
            process_name: Some(name.to_owned()),
            process_path: None,
            parent_pid: None,
            browser_hint: true,
        }
    }

    fn app_identity(name: &str) -> Option<NormalizedAppIdentity> {
        Some(NormalizedAppIdentity {
            process_name: name.to_owned(),
            original_path: None,
            warnings: vec![],
        })
    }

    // ── check_availability — primary ──────────────────────────────────────────

    #[test]
    fn matched_primary_available_gives_available_outcome() {
        let outcome = check_availability(
            &matched(RouteRole::Primary),
            &fresh_primary_only(),
            RouteBehaviorMode::PreferPrimary,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::Available {
                route: RouteRole::Primary,
                ..
            }
        ));
    }

    #[test]
    fn matched_primary_degraded_gives_primary_degraded_outcome() {
        let snap = snapshot(
            primary_no_ip(),
            SecondaryAvailabilityStatus::NotConfigured,
            SnapshotStaleness::Fresh,
        );
        let outcome = check_availability(
            &matched(RouteRole::Primary),
            &snap,
            RouteBehaviorMode::PreferPrimary,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::PrimaryDegraded { .. }
        ));
    }

    // ── check_availability — secondary ────────────────────────────────────────

    #[test]
    fn matched_secondary_available_gives_available_outcome() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &fresh_both_available(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::Available {
                route: RouteRole::Secondary,
                ..
            }
        ));
    }

    #[test]
    fn matched_secondary_not_configured_gives_not_configured() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &fresh_primary_only(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryNotConfigured { .. }
        ));
    }

    #[test]
    fn matched_secondary_no_ip_gives_not_reachable() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &fresh_secondary_no_ip(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryNotReachable {
                state: RouteAvailabilityState::Degraded,
                ..
            }
        ));
    }

    #[test]
    fn matched_secondary_disconnected_gives_not_reachable_unavailable() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &fresh_secondary_disconnected(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryNotReachable {
                state: RouteAvailabilityState::Unavailable,
                ..
            }
        ));
    }

    #[test]
    fn stale_not_usable_secondary_gives_unknown_outcome() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &stale_not_usable_both(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryUnknown { .. }
        ));
    }

    #[test]
    fn stale_usable_secondary_available_is_still_available() {
        // StaleUsable does not downgrade the state — secondary remains Available
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &stale_usable_both(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::Available {
                route: RouteRole::Secondary,
                ..
            }
        ));
    }

    #[test]
    fn stale_marker_present_for_stale_usable_snapshot() {
        let outcome = check_availability(
            &matched(RouteRole::Secondary),
            &stale_usable_both(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        if let AvailabilityCheckOutcome::Available { explain, .. } = outcome {
            assert_eq!(explain.stale_marker, Some(SnapshotStaleness::StaleUsable));
        } else {
            panic!("expected Available");
        }
    }

    // ── DefaultRoute behavior_mode → requested_role mapping ──────────────────

    #[test]
    fn default_route_prefer_primary_checks_primary() {
        let outcome = check_availability(
            &default_route(RouteBehaviorMode::PreferPrimary),
            &fresh_primary_only(),
            RouteBehaviorMode::PreferPrimary,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::Available {
                route: RouteRole::Primary,
                ..
            }
        ));
    }

    #[test]
    fn default_route_prefer_secondary_checks_secondary() {
        let outcome = check_availability(
            &default_route(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            &fresh_primary_only(), // secondary not configured
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryNotConfigured { .. }
        ));
    }

    #[test]
    fn default_route_strict_checks_secondary() {
        let outcome = check_availability(
            &default_route(RouteBehaviorMode::StrictSecondaryFailClosed),
            &fresh_primary_only(), // secondary not configured
            RouteBehaviorMode::StrictSecondaryFailClosed,
        );
        assert!(matches!(
            outcome,
            AvailabilityCheckOutcome::SecondaryNotConfigured { .. }
        ));
    }

    // ── classify_browser ──────────────────────────────────────────────────────

    #[test]
    fn known_browser_chrome_is_stub_eligible() {
        let bc = classify_browser(&plain_process("chrome.exe"), &app_identity("chrome.exe"));
        assert!(bc.is_browser);
        assert!(bc.stub_eligible());
        assert!(matches!(
            bc.basis,
            BrowserClassificationBasis::KnownProcessName { .. }
        ));
    }

    #[test]
    fn known_browser_firefox_is_stub_eligible() {
        let bc = classify_browser(&plain_process("firefox.exe"), &app_identity("firefox.exe"));
        assert!(bc.stub_eligible());
    }

    #[test]
    fn unknown_process_no_hint_is_unclassified() {
        let bc = classify_browser(&plain_process("notepad.exe"), &app_identity("notepad.exe"));
        assert!(!bc.is_browser);
        assert!(!bc.stub_eligible());
        assert!(matches!(bc.basis, BrowserClassificationBasis::Unclassified));
    }

    #[test]
    fn unknown_process_with_browser_hint_is_weak() {
        let bc = classify_browser(
            &browser_hint_process("custom-browser.exe"),
            &app_identity("custom-browser.exe"),
        );
        assert!(!bc.is_browser); // WeakHint is not is_browser
        assert!(!bc.stub_eligible());
        assert!(matches!(
            bc.basis,
            BrowserClassificationBasis::WeakHint { .. }
        ));
    }

    #[test]
    fn no_app_identity_is_unclassified() {
        let bc = classify_browser(&plain_process("chrome.exe"), &None);
        assert!(!bc.stub_eligible());
    }

    // ── resolve_final_action — full pipeline ──────────────────────────────────

    #[test]
    fn matched_primary_available_routes_primary() {
        let d = resolve_final_action(
            &matched(RouteRole::Primary),
            &fresh_primary_only(),
            RouteBehaviorMode::PreferPrimary,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::RoutePrimary);
    }

    #[test]
    fn matched_block_short_circuits_to_drop_even_when_route_available() {
        // A Block-action match drops regardless of route reachability or mode.
        let mut requested = matched(RouteRole::Primary);
        if let RequestedRouteDecision::MatchedRoute { candidate } = &mut requested {
            candidate.action = crate::canonical::RuleAction::Block;
        }
        let d = resolve_final_action(
            &requested,
            &fresh_both_available(),
            RouteBehaviorMode::PreferPrimary,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(d.reason, FinalActionReason::RuleBlocked);
        assert_eq!(d.route_role, None);
    }

    #[test]
    fn matched_secondary_available_routes_secondary() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_both_available(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::RouteSecondary);
        assert_eq!(d.reason, FinalActionReason::SecondaryAvailable);
    }

    #[test]
    fn matched_secondary_no_ip_prefer_secondary_falls_back() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_secondary_no_ip(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert_eq!(d.reason, FinalActionReason::SecondaryUnavailableFailOpen);
    }

    #[test]
    fn matched_secondary_not_configured_strict_blocks() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_primary_only(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(
            d.reason,
            FinalActionReason::SecondaryNotConfiguredFailClosed
        );
    }

    #[test]
    fn matched_secondary_no_ip_strict_blocks() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_secondary_no_ip(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(d.reason, FinalActionReason::SecondaryUnavailableFailClosed);
    }

    #[test]
    fn strict_browser_stub_enabled_attempts_stub() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_secondary_disconnected(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &stub_flags(),
            &plain_process("firefox.exe"),
            &app_identity("firefox.exe"),
        );
        assert_eq!(d.action, FinalAction::BrowserStubAttempt);
        assert_eq!(d.reason, FinalActionReason::BrowserStubEnabled);
    }

    #[test]
    fn strict_browser_stub_disabled_blocks_even_for_known_browser() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &fresh_secondary_disconnected(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &no_flags(), // stub disabled
            &plain_process("chrome.exe"),
            &app_identity("chrome.exe"),
        );
        assert_eq!(d.action, FinalAction::Block);
        // stub was considered but rejected (known browser, feature disabled)
        assert!(d.explain.stub_considered_but_rejected);
    }

    #[test]
    fn stale_not_usable_strict_blocks_with_no_uncertainty_marker() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &stale_not_usable_both(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        // StaleNotUsable → Unknown → strict blocks; uncertainty=false (StaleNotUsable.is_usable()==false)
        assert_eq!(d.action, FinalAction::Block);
        assert!(!d.has_uncertainty);
    }

    #[test]
    fn stale_usable_prefer_secondary_falls_back_with_uncertainty() {
        let d = resolve_final_action(
            &matched(RouteRole::Secondary),
            &stale_not_usable_both(),
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        // StaleNotUsable → Unknown → prefer secondary → fallback primary, uncertainty=false
        assert_eq!(d.action, FinalAction::RoutePrimary);
    }

    #[test]
    fn default_route_prefer_primary_routes_primary() {
        let d = resolve_final_action(
            &default_route(RouteBehaviorMode::PreferPrimary),
            &fresh_primary_only(),
            RouteBehaviorMode::PreferPrimary,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::RoutePrimary);
    }

    #[test]
    fn default_route_strict_no_secondary_blocks() {
        let d = resolve_final_action(
            &default_route(RouteBehaviorMode::StrictSecondaryFailClosed),
            &fresh_primary_only(),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &no_flags(),
            &plain_process("notepad.exe"),
            &app_identity("notepad.exe"),
        );
        assert_eq!(d.action, FinalAction::Block);
    }

    #[test]
    fn strict_never_routes_primary_when_secondary_unavailable() {
        for snap in [
            fresh_primary_only(),
            fresh_secondary_no_ip(),
            fresh_secondary_disconnected(),
            stale_not_usable_both(),
        ] {
            let d = resolve_final_action(
                &matched(RouteRole::Secondary),
                &snap,
                RouteBehaviorMode::StrictSecondaryFailClosed,
                &no_flags(),
                &plain_process("notepad.exe"),
                &app_identity("notepad.exe"),
            );
            assert_ne!(
                d.action,
                FinalAction::RoutePrimary,
                "StrictSecondaryFailClosed must never silently route to primary"
            );
        }
    }
}

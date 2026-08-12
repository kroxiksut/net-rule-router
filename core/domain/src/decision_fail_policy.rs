//! Fail-Closed / Fail-Open arbitration contracts.
//!
//! This module formalises the **fail policy stage**: the fifth step of the
//! routing decision pipeline that converts an [`AvailabilityCheckOutcome`]
//! into a concrete [`FinalAction`].
//!
//! # Final action model
//!
//! | Variant             | Meaning                                                   |
//! |---------------------|-----------------------------------------------------------|
//! | `RoutePrimary`      | Forward traffic via the primary route adapter             |
//! | `RouteSecondary`    | Forward traffic via the secondary route adapter           |
//! | `Block`             | Block the connection locally (Fail-Closed)                |
//! | `BrowserStubAttempt`| Attempt to serve a local stub page (experimental)        |
//! | `Defer`             | Decision cannot be made; apply safe fallback at call site |
//!
//! # Policy matrix
//!
//! ```text
//! Availability outcome         BehaviorMode                   Browser / stub  FinalAction
//! ───────────────────────────  ─────────────────────────────  ──────────────  ──────────────────────────
//! Available(Primary)           any                            any             RoutePrimary
//! Available(Secondary)         any                            any             RouteSecondary
//! PrimaryDegraded              any                            any             RoutePrimary  (+warn)
//! SecondaryNotConfigured       PreferPrimary                  any             RoutePrimary  (fail-open)
//! SecondaryNotConfigured       PreferSecondaryWhenAvailable   any             RoutePrimary  (fail-open)
//! SecondaryNotConfigured       StrictSecondaryFailClosed      non-browser     Block
//! SecondaryNotConfigured       StrictSecondaryFailClosed      browser+stub    BrowserStubAttempt
//! SecondaryNotConfigured       StrictSecondaryFailClosed      browser-stub    Block
//! SecondaryNotReachable        PreferSecondaryWhenAvailable   any             RoutePrimary  (fail-open)
//! SecondaryNotReachable        StrictSecondaryFailClosed      non-browser     Block
//! SecondaryNotReachable        StrictSecondaryFailClosed      browser+stub    BrowserStubAttempt
//! SecondaryNotReachable        StrictSecondaryFailClosed      browser-stub    Block
//! SecondaryUnknown(usable)     PreferSecondaryWhenAvailable   any             RoutePrimary  (+uncertainty)
//! SecondaryUnknown(usable)     StrictSecondaryFailClosed      non-browser     Block         (+uncertainty)
//! SecondaryUnknown(usable)     StrictSecondaryFailClosed      browser+stub    BrowserStubAttempt (+uncertainty)
//! SecondaryUnknown(usable)     StrictSecondaryFailClosed      browser-stub    Block         (+uncertainty)
//! ```
//!
//! `browser+stub` = `browser_hint == true && browser_stub_experimental == true`
//! `browser-stub` = `browser_hint == true && browser_stub_experimental == false`
//!
//! # `StrictSecondaryFailClosed` never silently falls back to primary
//!
//! When `StrictSecondaryFailClosed` is active and secondary is unavailable,
//! the pipeline **must not** silently route via primary.  The only valid
//! non-block outcome for browser traffic is `BrowserStubAttempt` (experimental).
//!
//! # `PreferSecondaryWhenAvailable` explicitly allows fail-open
//!
//! When `PreferSecondaryWhenAvailable` is active and secondary is unavailable,
//! the pipeline falls back to primary.  This is intentional and documented in
//! the reason code `SecondaryUnavailableFailOpen`.
//!
//! # Browser stub — experimental, not a universal HTTPS replacement
//!
//! `BrowserStubAttempt` is attempted only when:
//! 1. `DecisionFeatureFlags::browser_stub_experimental == true`.
//! 2. `ProcessContext::browser_hint == true`.
//! 3. The connection is being blocked by a Fail-Closed policy.
//!
//! The stub is **not** a guarantee — it may fail at the platform layer.
//! If the stub cannot be served, the outcome degrades to `Block`.
//! The stub must never be attempted for non-browser traffic.
//! The stub does **not** support universal HTTPS interception.

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::decision_availability::AvailabilityCheckOutcome;

// ── FinalAction ───────────────────────────────────────────────────────────────

/// The concrete routing action produced at the end of the decision pipeline.
///
/// This value is passed to the platform layer to apply the route, and is
/// embedded in [`FinalDecision`] alongside the explain trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalAction {
    /// Route traffic via the primary adapter.
    RoutePrimary,
    /// Route traffic via the secondary adapter.
    RouteSecondary,
    /// Block the connection locally (Fail-Closed policy enforced).
    Block,
    /// Attempt to serve a local browser stub page (experimental).
    ///
    /// This is a best-effort action — the platform layer may still fall back
    /// to `Block` if the stub cannot be served.
    BrowserStubAttempt,
    /// Decision cannot be made at this time (revision loading, timeout).
    /// The call site must apply a safe fallback (typically `Block` for strict
    /// policies, or `RoutePrimary` for permissive policies).
    Defer,
}

impl FinalAction {
    /// Returns `true` if traffic will be forwarded (not blocked or deferred).
    pub fn is_forwarding(self) -> bool {
        matches!(self, Self::RoutePrimary | Self::RouteSecondary)
    }

    /// Returns `true` if this action enforces Fail-Closed semantics.
    pub fn is_fail_closed(self) -> bool {
        matches!(self, Self::Block | Self::BrowserStubAttempt)
    }
}

// ── FinalActionReason ─────────────────────────────────────────────────────────

/// Reason code explaining why a specific [`FinalAction`] was chosen.
///
/// These codes are surfaced in explain output and logs.  They distinguish
/// cases that have the same `FinalAction` but different root causes
/// (e.g., two different ways to arrive at `RoutePrimary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalActionReason {
    /// Secondary was available and the rule / behavior mode requested it.
    SecondaryAvailable,
    /// Secondary was unavailable; Fail-Closed policy blocked the connection.
    SecondaryUnavailableFailClosed,
    /// Secondary was unavailable; behavior mode allowed fail-open to primary.
    SecondaryUnavailableFailOpen,
    /// Secondary was not configured; fell back to primary (non-strict mode).
    SecondaryNotConfiguredFailOpen,
    /// Secondary was not configured; Fail-Closed policy blocked the connection.
    SecondaryNotConfiguredFailClosed,
    /// Primary was the explicit target of the matched rule or behavior mode.
    PrimaryRequested,
    /// Primary was chosen as the default (PreferPrimary behavior mode).
    PrimaryDefault,
    /// Primary was chosen because primary was the only configured route.
    PrimaryOnlyRoute,
    /// Browser stub was attempted (experimental feature enabled).
    BrowserStubEnabled,
    /// Browser stub was not possible (feature disabled or non-browser traffic).
    BrowserStubNotPossible,
    /// Availability snapshot was stale; decision carries an uncertainty marker.
    StaleAvailabilityUsed,
    /// Decision was deferred because the active revision is not yet loaded.
    RevisionNotReady,
    /// The winning rule carries a [`crate::RuleAction::Block`] action: traffic
    /// is dropped by explicit user request, independent of the fail policy.
    RuleBlocked,
}

// ── BrowserClassificationBasis ────────────────────────────────────────────────

/// How a process was identified (or not) as a browser.
///
/// Classification is based on the process name from [`ProcessContext`].
/// A bare process name (without path) is a weak identity signal — any process
/// could adopt a browser's name.  A missing process name means the connection
/// cannot be classified.
///
/// The actual list of known browser process names is maintained by the
/// platform layer and is not part of this contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrowserClassificationBasis {
    /// Process name matched a static list of known browser executables
    /// (e.g. `chrome.exe`, `firefox.exe`, `msedge.exe`, `brave.exe`, `opera.exe`).
    KnownProcessName { process_name: String },
    /// `ProcessContext::browser_hint` was `true` but the process name did not
    /// appear in the known browser list (e.g. a custom build or wrapper).
    WeakHint { process_name: String },
    /// Process name was absent or could not be matched.  Treated as
    /// non-browser for all routing and stub purposes.
    Unclassified,
}

/// Browser classification signal for a single connection.
///
/// Used by the fail policy stage to decide whether `BrowserStubAttempt` is
/// eligible when Fail-Closed is active.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserClassification {
    /// Whether this connection is treated as browser traffic for policy purposes.
    ///
    /// `true` only for `KnownProcessName` basis — `WeakHint` and `Unclassified`
    /// are treated as non-browser to avoid false positives.
    pub is_browser: bool,
    /// How the classification was determined.
    pub basis: BrowserClassificationBasis,
}

impl BrowserClassification {
    /// Classification for an unidentified or non-browser process.
    pub fn unclassified() -> Self {
        Self {
            is_browser: false,
            basis: BrowserClassificationBasis::Unclassified,
        }
    }

    /// Returns `true` if the browser stub is eligible for this connection.
    ///
    /// Eligibility requires a known browser process — weak hints are not
    /// sufficient to justify an experimental stub attempt.
    pub fn stub_eligible(&self) -> bool {
        self.is_browser
            && matches!(
                self.basis,
                BrowserClassificationBasis::KnownProcessName { .. }
            )
    }
}

// ── FailPolicyInput ───────────────────────────────────────────────────────────

/// Inputs to the fail policy arbitration stage.
///
/// Assembled by the pipeline orchestrator from prior stage outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailPolicyInput {
    /// Result of the availability check stage.
    pub availability: AvailabilityCheckOutcome,
    /// Whether the experimental browser stub feature is enabled.
    pub browser_stub_experimental: bool,
    /// Browser classification for the current connection.
    pub browser: BrowserClassification,
}

// ── FailPolicyExplainData ─────────────────────────────────────────────────────

/// Explain data produced by the fail policy stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailPolicyExplainData {
    /// The final action chosen.
    pub final_action: FinalAction,
    /// Reason code for the chosen action.
    pub reason: FinalActionReason,
    /// Whether an uncertainty marker was attached (stale snapshot).
    pub uncertainty: bool,
    /// Whether `StrictSecondaryFailClosed` was the active policy.
    pub fail_closed_active: bool,
    /// Whether `BrowserStubAttempt` was considered but rejected.
    pub stub_considered_but_rejected: bool,
}

// ── FinalDecision ─────────────────────────────────────────────────────────────

/// Output of the fail policy stage — the complete routing decision ready for
/// the explain assembly stage and the platform apply layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalDecision {
    /// The concrete action to take.
    pub action: FinalAction,
    /// Reason code for the action.
    pub reason: FinalActionReason,
    /// Route role that the action targets, if applicable.
    /// `None` for `Block`, `Defer`, and `BrowserStubAttempt`.
    pub route_role: Option<RouteRole>,
    /// Whether the decision carries an uncertainty flag (stale availability).
    pub has_uncertainty: bool,
    /// Explain data for this stage.
    pub explain: FailPolicyExplainData,
}

impl FinalDecision {
    fn build(
        action: FinalAction,
        reason: FinalActionReason,
        route_role: Option<RouteRole>,
        has_uncertainty: bool,
        fail_closed_active: bool,
        stub_considered_but_rejected: bool,
    ) -> Self {
        Self {
            action,
            reason,
            route_role,
            has_uncertainty,
            explain: FailPolicyExplainData {
                final_action: action,
                reason,
                uncertainty: has_uncertainty,
                fail_closed_active,
                stub_considered_but_rejected,
            },
        }
    }

    /// Constructs the terminal decision for a rule-level
    /// [`crate::RuleAction::Block`] match: a hard drop requested by the user,
    /// distinct from a fail-closed policy block. Carries no route role.
    pub fn rule_blocked() -> Self {
        Self::build(
            FinalAction::Block,
            FinalActionReason::RuleBlocked,
            None,
            false,
            false,
            false,
        )
    }
}

// ── apply_fail_policy ─────────────────────────────────────────────────────────

/// Applies the Fail-Closed / Fail-Open policy to produce a [`FinalDecision`].
///
/// This is the canonical policy arbitration function, called as part of the
/// decision pipeline.
///
/// # Invariants
///
/// - `StrictSecondaryFailClosed` never silently falls back to primary.
/// - Browser stub is attempted only when all three conditions hold:
///   `browser_stub_experimental == true`, `browser.stub_eligible() == true`,
///   and the connection is being Fail-Closed blocked.
/// - `PreferPrimary` and `PreferSecondaryWhenAvailable` never block.
pub fn apply_fail_policy(input: &FailPolicyInput) -> FinalDecision {
    let stub_possible = input.browser_stub_experimental && input.browser.stub_eligible();

    match &input.availability {
        // ── Route is available — forward directly ─────────────────────────────
        AvailabilityCheckOutcome::Available { route, .. } => FinalDecision::build(
            match route {
                RouteRole::Primary => FinalAction::RoutePrimary,
                RouteRole::Secondary => FinalAction::RouteSecondary,
            },
            match route {
                RouteRole::Primary => FinalActionReason::PrimaryRequested,
                RouteRole::Secondary => FinalActionReason::SecondaryAvailable,
            },
            Some(*route),
            false,
            false,
            false,
        ),

        // ── Primary is degraded — note but forward anyway ─────────────────────
        AvailabilityCheckOutcome::PrimaryDegraded { .. } => FinalDecision::build(
            FinalAction::RoutePrimary,
            FinalActionReason::PrimaryRequested,
            Some(RouteRole::Primary),
            false,
            false,
            false,
        ),

        // ── Secondary not configured ──────────────────────────────────────────
        AvailabilityCheckOutcome::SecondaryNotConfigured { behavior_mode, .. } => {
            apply_secondary_fail(*behavior_mode, stub_possible, true, false)
        }

        // ── Secondary configured but not reachable ────────────────────────────
        AvailabilityCheckOutcome::SecondaryNotReachable { behavior_mode, .. } => {
            apply_secondary_fail(*behavior_mode, stub_possible, false, false)
        }

        // ── Secondary availability unknown (stale snapshot) ───────────────────
        AvailabilityCheckOutcome::SecondaryUnknown {
            behavior_mode,
            staleness,
            ..
        } => {
            let uncertainty = staleness.is_usable(); // true when StaleUsable
            apply_secondary_fail(*behavior_mode, stub_possible, true, uncertainty)
        }
    }
}

/// Shared logic for all "secondary not available" cases.
fn apply_secondary_fail(
    behavior_mode: RouteBehaviorMode,
    stub_possible: bool,
    is_not_configured: bool,
    has_uncertainty: bool,
) -> FinalDecision {
    match behavior_mode {
        // PreferPrimary — secondary was a default preference, always fail-open
        RouteBehaviorMode::PreferPrimary => FinalDecision::build(
            FinalAction::RoutePrimary,
            FinalActionReason::PrimaryDefault,
            Some(RouteRole::Primary),
            has_uncertainty,
            false,
            false,
        ),

        // PreferSecondaryWhenAvailable — explicit fail-open to primary
        RouteBehaviorMode::PreferSecondaryWhenAvailable => FinalDecision::build(
            FinalAction::RoutePrimary,
            if is_not_configured {
                FinalActionReason::SecondaryNotConfiguredFailOpen
            } else {
                FinalActionReason::SecondaryUnavailableFailOpen
            },
            Some(RouteRole::Primary),
            has_uncertainty,
            false,
            false,
        ),

        // StrictSecondaryFailClosed — never fall back to primary silently
        RouteBehaviorMode::StrictSecondaryFailClosed => {
            if stub_possible {
                FinalDecision::build(
                    FinalAction::BrowserStubAttempt,
                    FinalActionReason::BrowserStubEnabled,
                    None,
                    has_uncertainty,
                    true,
                    false,
                )
            } else {
                FinalDecision::build(
                    FinalAction::Block,
                    if is_not_configured {
                        FinalActionReason::SecondaryNotConfiguredFailClosed
                    } else {
                        FinalActionReason::SecondaryUnavailableFailClosed
                    },
                    None,
                    has_uncertainty,
                    true,
                    // stub was considered if browser traffic but feature disabled
                    !stub_possible,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_availability::{
        AvailabilityExplainData, AvailabilityReason, RouteAvailabilityState, SnapshotStaleness,
    };

    fn explain_for(route: RouteRole, state: RouteAvailabilityState) -> AvailabilityExplainData {
        AvailabilityExplainData {
            requested_route: route,
            observed_state: state,
            stale_marker: None,
            unavailability_reason: None,
            secondary_not_configured: false,
        }
    }

    fn available_secondary() -> AvailabilityCheckOutcome {
        AvailabilityCheckOutcome::Available {
            route: RouteRole::Secondary,
            explain: explain_for(RouteRole::Secondary, RouteAvailabilityState::Available),
        }
    }

    fn available_primary() -> AvailabilityCheckOutcome {
        AvailabilityCheckOutcome::Available {
            route: RouteRole::Primary,
            explain: explain_for(RouteRole::Primary, RouteAvailabilityState::Available),
        }
    }

    fn secondary_not_configured(mode: RouteBehaviorMode) -> AvailabilityCheckOutcome {
        AvailabilityCheckOutcome::SecondaryNotConfigured {
            behavior_mode: mode,
            explain: {
                let mut e = explain_for(RouteRole::Secondary, RouteAvailabilityState::Unavailable);
                e.secondary_not_configured = true;
                e
            },
        }
    }

    fn secondary_not_reachable(mode: RouteBehaviorMode) -> AvailabilityCheckOutcome {
        AvailabilityCheckOutcome::SecondaryNotReachable {
            state: RouteAvailabilityState::Degraded,
            reason: Some(AvailabilityReason::NoIpAddress),
            behavior_mode: mode,
            explain: explain_for(RouteRole::Secondary, RouteAvailabilityState::Degraded),
        }
    }

    fn secondary_unknown(mode: RouteBehaviorMode) -> AvailabilityCheckOutcome {
        AvailabilityCheckOutcome::SecondaryUnknown {
            staleness: SnapshotStaleness::StaleUsable,
            behavior_mode: mode,
            explain: {
                let mut e = explain_for(RouteRole::Secondary, RouteAvailabilityState::Unknown);
                e.stale_marker = Some(SnapshotStaleness::StaleUsable);
                e
            },
        }
    }

    fn browser_known(name: &str) -> BrowserClassification {
        BrowserClassification {
            is_browser: true,
            basis: BrowserClassificationBasis::KnownProcessName {
                process_name: name.to_owned(),
            },
        }
    }

    fn input(
        availability: AvailabilityCheckOutcome,
        stub_experimental: bool,
        browser: BrowserClassification,
    ) -> FailPolicyInput {
        FailPolicyInput {
            availability,
            browser_stub_experimental: stub_experimental,
            browser,
        }
    }

    // ── Available cases ───────────────────────────────────────────────────────

    #[test]
    fn available_secondary_routes_secondary() {
        let d = apply_fail_policy(&input(
            available_secondary(),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RouteSecondary);
        assert_eq!(d.route_role, Some(RouteRole::Secondary));
        assert_eq!(d.reason, FinalActionReason::SecondaryAvailable);
        assert!(!d.has_uncertainty);
    }

    #[test]
    fn available_primary_routes_primary() {
        let d = apply_fail_policy(&input(
            available_primary(),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert_eq!(d.route_role, Some(RouteRole::Primary));
        assert!(!d.has_uncertainty);
    }

    #[test]
    fn primary_degraded_still_routes_primary() {
        let outcome = AvailabilityCheckOutcome::PrimaryDegraded {
            state: RouteAvailabilityState::Degraded,
            reason: Some(AvailabilityReason::NoIpAddress),
            explain: explain_for(RouteRole::Primary, RouteAvailabilityState::Degraded),
        };
        let d = apply_fail_policy(&input(
            outcome,
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert!(!d.explain.fail_closed_active);
    }

    // ── PreferPrimary — always fail-open ──────────────────────────────────────

    #[test]
    fn prefer_primary_secondary_not_configured_routes_primary() {
        let d = apply_fail_policy(&input(
            secondary_not_configured(RouteBehaviorMode::PreferPrimary),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert_eq!(d.reason, FinalActionReason::PrimaryDefault);
        assert!(!d.explain.fail_closed_active);
    }

    // ── PreferSecondaryWhenAvailable — explicit fail-open ─────────────────────

    #[test]
    fn prefer_secondary_not_configured_falls_back_to_primary() {
        let d = apply_fail_policy(&input(
            secondary_not_configured(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert_eq!(d.reason, FinalActionReason::SecondaryNotConfiguredFailOpen);
        assert!(!d.explain.fail_closed_active);
    }

    #[test]
    fn prefer_secondary_not_reachable_falls_back_to_primary() {
        let d = apply_fail_policy(&input(
            secondary_not_reachable(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert_eq!(d.reason, FinalActionReason::SecondaryUnavailableFailOpen);
        assert!(!d.explain.fail_closed_active);
    }

    #[test]
    fn prefer_secondary_unknown_falls_back_to_primary_with_uncertainty() {
        let d = apply_fail_policy(&input(
            secondary_unknown(RouteBehaviorMode::PreferSecondaryWhenAvailable),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::RoutePrimary);
        assert!(d.has_uncertainty);
        assert!(!d.explain.fail_closed_active);
    }

    // ── StrictSecondaryFailClosed — non-browser: always Block ─────────────────

    #[test]
    fn strict_fail_closed_non_browser_not_configured_blocks() {
        let d = apply_fail_policy(&input(
            secondary_not_configured(RouteBehaviorMode::StrictSecondaryFailClosed),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(
            d.reason,
            FinalActionReason::SecondaryNotConfiguredFailClosed
        );
        assert!(d.explain.fail_closed_active);
        assert_eq!(d.route_role, None);
    }

    #[test]
    fn strict_fail_closed_non_browser_not_reachable_blocks() {
        let d = apply_fail_policy(&input(
            secondary_not_reachable(RouteBehaviorMode::StrictSecondaryFailClosed),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(d.reason, FinalActionReason::SecondaryUnavailableFailClosed);
        assert!(d.explain.fail_closed_active);
    }

    #[test]
    fn strict_fail_closed_non_browser_unknown_blocks_with_uncertainty() {
        let d = apply_fail_policy(&input(
            secondary_unknown(RouteBehaviorMode::StrictSecondaryFailClosed),
            false,
            BrowserClassification::unclassified(),
        ));
        assert_eq!(d.action, FinalAction::Block);
        assert!(d.has_uncertainty);
        assert!(d.explain.fail_closed_active);
    }

    // ── StrictSecondaryFailClosed — browser + stub enabled: BrowserStubAttempt

    #[test]
    fn strict_fail_closed_browser_stub_enabled_attempts_stub() {
        let d = apply_fail_policy(&input(
            secondary_not_reachable(RouteBehaviorMode::StrictSecondaryFailClosed),
            true, // stub_experimental = true
            browser_known("firefox.exe"),
        ));
        assert_eq!(d.action, FinalAction::BrowserStubAttempt);
        assert_eq!(d.reason, FinalActionReason::BrowserStubEnabled);
        assert!(d.explain.fail_closed_active);
        assert_eq!(d.route_role, None);
    }

    #[test]
    fn strict_fail_closed_browser_stub_disabled_blocks() {
        let d = apply_fail_policy(&input(
            secondary_not_reachable(RouteBehaviorMode::StrictSecondaryFailClosed),
            false, // stub_experimental = false
            browser_known("chrome.exe"),
        ));
        assert_eq!(d.action, FinalAction::Block);
        assert_eq!(d.reason, FinalActionReason::SecondaryUnavailableFailClosed);
        // stub was considered (browser traffic) but rejected (feature disabled)
        assert!(d.explain.stub_considered_but_rejected);
    }

    #[test]
    fn strict_fail_closed_weak_browser_hint_blocks_not_stub() {
        // WeakHint is not considered a confirmed browser — stub not eligible
        let weak = BrowserClassification {
            is_browser: false,
            basis: BrowserClassificationBasis::WeakHint {
                process_name: "custom-browser.exe".to_owned(),
            },
        };
        let d = apply_fail_policy(&input(
            secondary_not_reachable(RouteBehaviorMode::StrictSecondaryFailClosed),
            true,
            weak,
        ));
        assert_eq!(d.action, FinalAction::Block);
        assert!(d.explain.fail_closed_active);
    }

    // ── BrowserClassification helpers ─────────────────────────────────────────

    #[test]
    fn browser_classification_unclassified_is_not_stub_eligible() {
        assert!(!BrowserClassification::unclassified().stub_eligible());
    }

    #[test]
    fn browser_classification_known_name_is_stub_eligible() {
        assert!(browser_known("msedge.exe").stub_eligible());
    }

    #[test]
    fn browser_classification_weak_hint_is_not_stub_eligible() {
        let weak = BrowserClassification {
            is_browser: false,
            basis: BrowserClassificationBasis::WeakHint {
                process_name: "chromium-fork.exe".to_owned(),
            },
        };
        assert!(!weak.stub_eligible());
    }

    // ── FinalAction helpers ───────────────────────────────────────────────────

    #[test]
    fn final_action_is_forwarding() {
        assert!(FinalAction::RoutePrimary.is_forwarding());
        assert!(FinalAction::RouteSecondary.is_forwarding());
        assert!(!FinalAction::Block.is_forwarding());
        assert!(!FinalAction::BrowserStubAttempt.is_forwarding());
        assert!(!FinalAction::Defer.is_forwarding());
    }

    #[test]
    fn final_action_is_fail_closed() {
        assert!(!FinalAction::RoutePrimary.is_fail_closed());
        assert!(!FinalAction::RouteSecondary.is_fail_closed());
        assert!(FinalAction::Block.is_fail_closed());
        assert!(FinalAction::BrowserStubAttempt.is_fail_closed());
        assert!(!FinalAction::Defer.is_fail_closed());
    }

    // ── Strict policy never silently falls back to primary ────────────────────

    #[test]
    fn strict_fail_closed_never_routes_primary_when_secondary_unavailable() {
        for availability in [
            secondary_not_configured(RouteBehaviorMode::StrictSecondaryFailClosed),
            secondary_not_reachable(RouteBehaviorMode::StrictSecondaryFailClosed),
            secondary_unknown(RouteBehaviorMode::StrictSecondaryFailClosed),
        ] {
            let d = apply_fail_policy(&input(
                availability,
                false,
                BrowserClassification::unclassified(),
            ));
            assert_ne!(
                d.action,
                FinalAction::RoutePrimary,
                "StrictSecondaryFailClosed must never silently route to primary"
            );
        }
    }
}

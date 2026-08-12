//! Explain output contracts for the routing decision pipeline.
//!
//! This module formalises the **explain assembly stage**: the sixth and final
//! step of the routing decision pipeline that assembles a [`DecisionExplain`]
//! from all prior stage outputs.
//!
//! # What explain output is
//!
//! `DecisionExplain` is the authoritative record of **why** a routing decision
//! was made.  It is:
//! - Shown in the GUI explain panel (compact form).
//! - Written to the audit log (filtered form — no raw sensitive payload).
//! - Used by integration tests for deterministic trace comparison.
//!
//! # Detail levels
//!
//! | Level              | Audience               | Content                              |
//! |--------------------|------------------------|--------------------------------------|
//! | `CompactUi`        | End user               | Action, rule label, secondary status |
//! | `Diagnostics`      | Power user / support   | + normalized inputs, cache, warnings |
//! | `DeveloperTrace`   | Developer / test       | + full stage trace, timestamps, IDs  |
//!
//! # Privacy filtering
//!
//! The standard UI (`CompactUi`) must **not** expose:
//! - Full executable path (show only the filename).
//! - Full resolved IP list (show only whether IP matching occurred).
//! - Exact resolution timestamps.
//! - Reverse DNS hostnames.
//!
//! These details are available only in `Diagnostics` and `DeveloperTrace`
//! levels, accessible via an explicit user action.
//!
//! # Deterministic ordering
//!
//! All `Vec` fields in `DecisionExplain` are **sorted deterministically** so
//! that unit and integration tests can compare expected traces by equality:
//! - `uncertainty_markers` — sorted by enum discriminant (ascending).
//! - `conflict_markers` — sorted by enum discriminant (ascending).
//! - `warnings` — sorted by source stage, then by message.
//! - `used_signals` — sorted alphabetically.
//!
//! # Decision ID format
//!
//! `DecisionId` uses the format `"d-{uuid_v4}"` — the `d-` prefix distinguishes
//! decision IDs from rule IDs (`r-`) and event IDs (`evt-`) in logs and audit.
//!
//! # Relationship to `ExplainSampleDto`
//!
//! `ExplainSampleDto` in `nrr-shared` is the compact IPC/UI representation,
//! derived from `DecisionExplain::compact_summary()`.
//!
//! # Required fields by final action
//!
//! | `FinalAction`        | Required explain fields                                         |
//! |----------------------|-----------------------------------------------------------------|
//! | `RoutePrimary`       | input_summary, decision_id, revision_id, match_trace, avail_trace |
//! | `RouteSecondary`     | same + secondary availability confirmation in avail_trace       |
//! | `Block`              | same + fail_closed_reason, secondary state in avail_trace       |
//! | `BrowserStubAttempt` | same + browser_classification, stub_eligibility in match_trace  |
//! | `Defer`              | decision_id, revision_id, defer_reason                          |

use std::time::SystemTime;

use nrr_shared::RouteRole;

use crate::decision_fail_policy::FinalAction;
use crate::RuleId;

// ── DecisionId ────────────────────────────────────────────────────────────────

/// Stable, unique identifier for a single routing decision.
///
/// Format: `"d-{uuid_v4}"` — the `d-` prefix distinguishes decision IDs from
/// rule IDs (`r-`), event IDs (`evt-`), and revision IDs in logs and audit.
///
/// Generated fresh for every decision invocation; never reused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DecisionId(pub String);

impl DecisionId {
    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DecisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ExplainDetailLevel ────────────────────────────────────────────────────────

/// Level of detail requested when rendering explain output.
///
/// The pipeline always produces a full [`DecisionExplain`]; the rendering
/// layer filters fields based on the requested level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExplainDetailLevel {
    /// Compact, privacy-safe summary for the end-user explain panel.
    CompactUi,
    /// Extended diagnostics for power users or support — includes normalized
    /// inputs, cache state, and non-sensitive warnings.
    Diagnostics,
    /// Full trace for developer and integration-test use — includes all stage
    /// outputs, timestamps, and internal IDs.
    DeveloperTrace,
}

// ── UncertaintyMarker ─────────────────────────────────────────────────────────

/// Marker indicating that the decision was made with incomplete or uncertain
/// data.  Does not invalidate the decision — it is a diagnostic annotation.
///
/// Markers are **sorted by discriminant order** in `DecisionExplain::uncertainty_markers`
/// to guarantee deterministic output for testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UncertaintyMarker {
    /// Destination hostname was not available; hostname-based matching skipped.
    HostnameUnavailable,
    /// Process identity was not available; application matching skipped.
    AppContextUnavailable,
    /// FQDN/IP cache entry was stale but still used for matching.
    StaleCacheUsed,
    /// Multiple IPs resolved for the hostname; the selected IP may not be
    /// the one the connection actually used.
    AmbiguousLookup,
    /// Route availability snapshot was stale; availability assessment uncertain.
    StaleAvailabilitySnapshot,
    /// Secondary adapter state was unknown at decision time.
    UnknownSecondaryState,
    /// Destination IP was native IPv6 (Pro-only); ExactIp matching was skipped.
    Ipv6DestinationProOnly,
}

// ── ExplainConflictMarker ─────────────────────────────────────────────────────

/// Marker indicating a detected conflict or inconsistency in the rule book,
/// revision, or adapter bindings at the time of the decision.
///
/// Conflicts should be surfaced to the user via the diagnostics panel so they
/// can be investigated and resolved.  They do not abort the pipeline — a
/// deterministic winner is still chosen.
///
/// Sorted by discriminant order in `DecisionExplain::conflict_markers`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExplainConflictMarker {
    /// Two rules with equal specificity pointed to different route sets.
    /// The pipeline chose deterministically (lowest rule_id wins).
    DuplicateConflictingRules,
    /// The active revision has not been confirmed as current by the service.
    /// The decision was made against a potentially outdated rule book.
    StaleActiveRevision,
    /// The adapter assigned to a route role is no longer present in the OS.
    RouteBindingMissing,
    /// A rule in the operational store uses a type unsupported in Free edition
    /// (e.g., `AddressMatch::ExactIp(V6)`) — it was skipped during matching.
    UnsupportedRuleTypeEncountered,
}

// ── ExplainWarning ────────────────────────────────────────────────────────────

/// Non-fatal diagnostic warning attached to an explain output.
///
/// Warnings are sourced from normalization, lookup, matching, and availability
/// stages.  They are shown in `Diagnostics` and `DeveloperTrace` levels.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExplainWarning {
    // ── Normalization ─────────────────────────────────────────────────────────
    /// IPv4-mapped IPv6 was normalised to IPv4.
    Ipv4MappedNormalised,
    /// Process name is a bare name without path — weak identity.
    WeakProcessIdentity,
    /// Application exe suffix was added during normalisation.
    AppExeSuffixAdded,
    /// Trailing dot was removed from the hostname.
    DomainTrailingDotRemoved,
    // ── Lookup ────────────────────────────────────────────────────────────────
    /// Lookup used a stale cache entry.
    LookupStaleCacheUsed,
    /// Lookup timed out; only observed IP was used.
    LookupTimeout,
    /// Multiple IPs resolved; the selected one is noted in diagnostics.
    LookupMultipleIpsResolved,
    // ── Matching ─────────────────────────────────────────────────────────────
    /// A rule conflict was resolved deterministically.
    MatchConflictResolved,
    // ── Availability ─────────────────────────────────────────────────────────
    /// Primary adapter is degraded (no IP), but routing proceeded.
    PrimaryAdapterDegraded,
    /// Availability snapshot was stale; decision carries uncertainty.
    AvailabilitySnapshotStale,
}

// ── InputSummary ──────────────────────────────────────────────────────────────

/// Privacy-filtered summary of the raw `RuntimeInput`.
///
/// Shown at all detail levels.  Fields that could expose sensitive information
/// (full path, exact IP) are omitted at `CompactUi` level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSummary {
    /// Destination hostname as observed (not normalised), if available.
    /// Shown at all levels.
    pub destination_hostname: Option<String>,
    /// Whether a destination IP was observed (omits the actual address at
    /// `CompactUi` level to avoid exposing network topology).
    pub destination_ip_present: bool,
    /// Process filename only (path stripped) — shown at all levels.
    pub process_name: Option<String>,
    /// Full process path — shown only at `Diagnostics` / `DeveloperTrace`.
    pub process_path_extended: Option<String>,
    /// Source of the observation.
    pub observation_source: ObservationSourceLabel,
}

/// Label for the observation source, safe to include in all explain levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationSourceLabel {
    WfpCallback,
    TestHarness,
}

// ── MatchTraceSummary ─────────────────────────────────────────────────────────

/// Summary of the rule matching stage outcome for explain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchTraceSummary {
    /// A rule was matched.
    RuleMatched {
        /// Stable ID of the winning rule.
        rule_id: RuleId,
        /// Match class that produced the winner.
        match_class_label: String,
        /// Route role the winning rule belongs to.
        route_role: RouteRole,
        /// Whether a same-tier conflict was detected and resolved.
        conflict_resolved: bool,
    },
    /// No rule matched; behavior-mode default was applied.
    DefaultRoute {
        /// Human-readable reason why no rule matched.
        reason_label: String,
        /// The behavior mode that determined the default route.
        behavior_mode_label: String,
    },
}

// ── AvailabilityTraceSummary ──────────────────────────────────────────────────

/// Summary of the availability check stage outcome for explain output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityTraceSummary {
    /// Which route was requested by the match stage.
    pub requested_route: RouteRole,
    /// Availability state observed for the requested route.
    pub observed_state_label: String,
    /// Whether secondary was not configured (vs configured but down).
    pub secondary_not_configured: bool,
    /// Whether the snapshot was stale.
    pub snapshot_stale: bool,
}

// ── FinalActionSummary ────────────────────────────────────────────────────────

/// Summary of the final action chosen by the fail policy stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalActionSummary {
    /// The final action taken.
    pub action: FinalAction,
    /// Route role that was applied (None for Block / BrowserStubAttempt / Defer).
    pub route_role: Option<RouteRole>,
    /// Human-readable reason code label.
    pub reason_label: String,
    /// Whether the browser stub was considered but rejected.
    pub stub_considered_but_rejected: bool,
}

// ── DecisionExplain ───────────────────────────────────────────────────────────

/// Full explain record for a single routing decision.
///
/// Assembled at the end of the pipeline from all stage outputs.  The rendering
/// layer filters fields based on [`ExplainDetailLevel`].
///
/// # Invariants for deterministic testing
///
/// - `uncertainty_markers` is always sorted by `UncertaintyMarker` discriminant.
/// - `conflict_markers` is always sorted by `ExplainConflictMarker` discriminant.
/// - `warnings` is always sorted by `ExplainWarning` discriminant.
/// - `used_signals` is always sorted alphabetically.
///
/// These invariants must be ensured when building `DecisionExplain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionExplain {
    // ── Identity fields (all levels) ─────────────────────────────────────────
    /// Unique ID for this decision.  Format: `"d-{uuid_v4}"`.
    pub decision_id: DecisionId,
    /// Active revision ID this decision was evaluated against.
    pub active_revision_id: String,
    /// Wall-clock time of the decision.  `DeveloperTrace` only.
    pub decided_at: Option<SystemTime>,

    // ── Input summary (all levels) ────────────────────────────────────────────
    /// Privacy-filtered summary of the raw input.
    pub input_summary: InputSummary,

    // ── Stage traces ─────────────────────────────────────────────────────────
    /// Match stage outcome.  Required for all actions except `Defer`.
    pub match_trace: Option<MatchTraceSummary>,
    /// Availability check outcome.  Required for all actions.
    pub availability_trace: AvailabilityTraceSummary,
    /// Final action chosen by the fail policy stage.
    pub final_action_summary: FinalActionSummary,

    // ── Markers and warnings ──────────────────────────────────────────────────
    /// Uncertainty markers (sorted deterministically).  `Diagnostics`+.
    pub uncertainty_markers: Vec<UncertaintyMarker>,
    /// Conflict markers (sorted deterministically).  `Diagnostics`+.
    pub conflict_markers: Vec<ExplainConflictMarker>,
    /// Non-fatal warnings from all stages (sorted deterministically).
    /// `Diagnostics`+.
    pub warnings: Vec<ExplainWarning>,
    /// Signal labels used to reach the decision (sorted alphabetically).
    /// Shown at all levels.
    pub used_signals: Vec<String>,

    // ── Audit / correlation ───────────────────────────────────────────────────
    /// Correlation ID linking this decision to an external trace or session.
    /// `DeveloperTrace` only.  Never included in default audit output.
    pub correlation_id: Option<String>,
}

impl DecisionExplain {
    /// Returns the decision ID string.
    pub fn id(&self) -> &str {
        self.decision_id.as_str()
    }

    /// Returns `true` if any uncertainty markers are present.
    pub fn has_uncertainty(&self) -> bool {
        !self.uncertainty_markers.is_empty()
    }

    /// Returns `true` if any conflict markers are present.
    pub fn has_conflicts(&self) -> bool {
        !self.conflict_markers.is_empty()
    }

    /// Returns the final action.
    pub fn action(&self) -> FinalAction {
        self.final_action_summary.action
    }

    /// Returns `true` if routing was ultimately blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(
            self.final_action_summary.action,
            FinalAction::Block | FinalAction::Defer
        )
    }

    /// Returns `true` when this explain carries all required fields for the
    /// given final action.
    ///
    /// Used in tests to assert that the explain builder did not omit required
    /// data.
    pub fn is_complete_for(&self, action: FinalAction) -> bool {
        match action {
            FinalAction::RoutePrimary | FinalAction::RouteSecondary => self.match_trace.is_some(),
            FinalAction::Block => self.match_trace.is_some(),
            FinalAction::BrowserStubAttempt => self.match_trace.is_some(),
            FinalAction::Defer => {
                // Defer only requires decision_id and revision_id
                true
            }
        }
    }

    /// Produces a compact string summary suitable for `ExplainSampleDto`.
    /// Does not include privacy-sensitive fields.
    pub fn compact_summary(&self) -> String {
        let action_label = match self.final_action_summary.action {
            FinalAction::RoutePrimary => "route:primary",
            FinalAction::RouteSecondary => "route:secondary",
            FinalAction::Block => "block",
            FinalAction::BrowserStubAttempt => "browser_stub",
            FinalAction::Defer => "defer",
        };
        let hostname = self
            .input_summary
            .destination_hostname
            .as_deref()
            .unwrap_or("<no-hostname>");
        format!(
            "{action_label} | {hostname} | {}",
            self.final_action_summary.reason_label
        )
    }
}

// ── DecisionExplainBuilder ────────────────────────────────────────────────────

/// Incrementally builds a [`DecisionExplain`], enforcing deterministic
/// ordering invariants at `build()` time.
///
/// The rule engine uses this builder to assemble the explain trace as each
/// pipeline stage completes.
#[derive(Debug)]
pub struct DecisionExplainBuilder {
    decision_id: DecisionId,
    active_revision_id: String,
    decided_at: Option<SystemTime>,
    input_summary: Option<InputSummary>,
    match_trace: Option<MatchTraceSummary>,
    availability_trace: Option<AvailabilityTraceSummary>,
    final_action_summary: Option<FinalActionSummary>,
    uncertainty_markers: Vec<UncertaintyMarker>,
    conflict_markers: Vec<ExplainConflictMarker>,
    warnings: Vec<ExplainWarning>,
    used_signals: Vec<String>,
    correlation_id: Option<String>,
}

impl DecisionExplainBuilder {
    /// Creates a new builder for a decision with the given IDs.
    pub fn new(decision_id: DecisionId, active_revision_id: impl Into<String>) -> Self {
        Self {
            decision_id,
            active_revision_id: active_revision_id.into(),
            decided_at: None,
            input_summary: None,
            match_trace: None,
            availability_trace: None,
            final_action_summary: None,
            uncertainty_markers: Vec::new(),
            conflict_markers: Vec::new(),
            warnings: Vec::new(),
            used_signals: Vec::new(),
            correlation_id: None,
        }
    }

    pub fn decided_at(mut self, t: SystemTime) -> Self {
        self.decided_at = Some(t);
        self
    }

    pub fn input_summary(mut self, s: InputSummary) -> Self {
        self.input_summary = Some(s);
        self
    }

    pub fn match_trace(mut self, t: MatchTraceSummary) -> Self {
        self.match_trace = Some(t);
        self
    }

    pub fn availability_trace(mut self, t: AvailabilityTraceSummary) -> Self {
        self.availability_trace = Some(t);
        self
    }

    pub fn final_action(mut self, s: FinalActionSummary) -> Self {
        self.final_action_summary = Some(s);
        self
    }

    pub fn add_uncertainty(mut self, m: UncertaintyMarker) -> Self {
        if !self.uncertainty_markers.contains(&m) {
            self.uncertainty_markers.push(m);
        }
        self
    }

    pub fn add_conflict(mut self, m: ExplainConflictMarker) -> Self {
        if !self.conflict_markers.contains(&m) {
            self.conflict_markers.push(m);
        }
        self
    }

    pub fn add_warning(mut self, w: ExplainWarning) -> Self {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
        self
    }

    pub fn add_signal(mut self, s: impl Into<String>) -> Self {
        let s = s.into();
        if !self.used_signals.contains(&s) {
            self.used_signals.push(s);
        }
        self
    }

    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Builds the [`DecisionExplain`], sorting all marker and warning vecs
    /// deterministically.
    ///
    /// Returns `Err` if required fields (input_summary, availability_trace,
    /// final_action_summary) are absent.
    pub fn build(mut self) -> Result<DecisionExplain, ExplainBuildError> {
        let input_summary = self
            .input_summary
            .ok_or(ExplainBuildError::MissingInputSummary)?;
        let availability_trace = self
            .availability_trace
            .ok_or(ExplainBuildError::MissingAvailabilityTrace)?;
        let final_action_summary = self
            .final_action_summary
            .ok_or(ExplainBuildError::MissingFinalAction)?;

        // Enforce deterministic ordering
        self.uncertainty_markers.sort();
        self.conflict_markers.sort();
        self.warnings.sort();
        self.used_signals.sort();

        Ok(DecisionExplain {
            decision_id: self.decision_id,
            active_revision_id: self.active_revision_id,
            decided_at: self.decided_at,
            input_summary,
            match_trace: self.match_trace,
            availability_trace,
            final_action_summary,
            uncertainty_markers: self.uncertainty_markers,
            conflict_markers: self.conflict_markers,
            warnings: self.warnings,
            used_signals: self.used_signals,
            correlation_id: self.correlation_id,
        })
    }
}

/// Error returned when [`DecisionExplainBuilder::build`] is called with
/// missing required fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainBuildError {
    MissingInputSummary,
    MissingAvailabilityTrace,
    MissingFinalAction,
}

// ── Scenario examples (doc-tested via unit tests) ─────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::RouteRole;

    fn test_decision_id() -> DecisionId {
        DecisionId("d-00000000-0000-0000-0000-000000000001".to_owned())
    }

    fn minimal_input() -> InputSummary {
        InputSummary {
            destination_hostname: Some("example.com".to_owned()),
            destination_ip_present: true,
            process_name: Some("firefox.exe".to_owned()),
            process_path_extended: None,
            observation_source: ObservationSourceLabel::WfpCallback,
        }
    }

    fn availability_trace(route: RouteRole) -> AvailabilityTraceSummary {
        AvailabilityTraceSummary {
            requested_route: route,
            observed_state_label: "available".to_owned(),
            secondary_not_configured: false,
            snapshot_stale: false,
        }
    }

    fn final_action(
        action: FinalAction,
        role: Option<RouteRole>,
        reason: &str,
    ) -> FinalActionSummary {
        FinalActionSummary {
            action,
            route_role: role,
            reason_label: reason.to_owned(),
            stub_considered_but_rejected: false,
        }
    }

    // ── Builder happy path ────────────────────────────────────────────────────

    #[test]
    fn builder_builds_domain_match_explain() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .match_trace(MatchTraceSummary::RuleMatched {
                rule_id: RuleId("r-abc".to_owned()),
                match_class_label: "ExactFqdn".to_owned(),
                route_role: RouteRole::Secondary,
                conflict_resolved: false,
            })
            .availability_trace(availability_trace(RouteRole::Secondary))
            .final_action(final_action(
                FinalAction::RouteSecondary,
                Some(RouteRole::Secondary),
                "secondary_available",
            ))
            .add_signal("hostname_match")
            .build()
            .unwrap();

        assert_eq!(explain.action(), FinalAction::RouteSecondary);
        assert!(!explain.has_uncertainty());
        assert!(!explain.has_conflicts());
        assert!(explain.is_complete_for(FinalAction::RouteSecondary));
        assert!(explain.used_signals.contains(&"hostname_match".to_owned()));
    }

    #[test]
    fn builder_builds_fail_closed_block_explain() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .match_trace(MatchTraceSummary::DefaultRoute {
                reason_label: "no_rule_matched".to_owned(),
                behavior_mode_label: "strict_secondary_fail_closed".to_owned(),
            })
            .availability_trace(AvailabilityTraceSummary {
                requested_route: RouteRole::Secondary,
                observed_state_label: "unavailable".to_owned(),
                secondary_not_configured: false,
                snapshot_stale: false,
            })
            .final_action(final_action(
                FinalAction::Block,
                None,
                "secondary_unavailable_fail_closed",
            ))
            .add_uncertainty(UncertaintyMarker::StaleCacheUsed)
            .build()
            .unwrap();

        assert_eq!(explain.action(), FinalAction::Block);
        assert!(explain.is_blocked());
        assert!(explain.has_uncertainty());
        assert!(explain.is_complete_for(FinalAction::Block));
    }

    #[test]
    fn builder_builds_app_fallback_explain() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .match_trace(MatchTraceSummary::RuleMatched {
                rule_id: RuleId("r-xyz".to_owned()),
                match_class_label: "Application".to_owned(),
                route_role: RouteRole::Primary,
                conflict_resolved: false,
            })
            .availability_trace(availability_trace(RouteRole::Primary))
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "primary_requested",
            ))
            .add_uncertainty(UncertaintyMarker::HostnameUnavailable)
            .add_signal("app_match")
            .build()
            .unwrap();

        assert_eq!(explain.action(), FinalAction::RoutePrimary);
        assert!(explain.has_uncertainty());
    }

    #[test]
    fn builder_builds_browser_stub_attempt_explain() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(InputSummary {
                destination_hostname: Some("news.example.ru".to_owned()),
                destination_ip_present: true,
                process_name: Some("chrome.exe".to_owned()),
                process_path_extended: Some(
                    r"C:\Program Files\Google\Chrome\chrome.exe".to_owned(),
                ),
                observation_source: ObservationSourceLabel::WfpCallback,
            })
            .match_trace(MatchTraceSummary::RuleMatched {
                rule_id: RuleId("r-001".to_owned()),
                match_class_label: "Zone".to_owned(),
                route_role: RouteRole::Secondary,
                conflict_resolved: false,
            })
            .availability_trace(AvailabilityTraceSummary {
                requested_route: RouteRole::Secondary,
                observed_state_label: "unavailable".to_owned(),
                secondary_not_configured: false,
                snapshot_stale: false,
            })
            .final_action(FinalActionSummary {
                action: FinalAction::BrowserStubAttempt,
                route_role: None,
                reason_label: "browser_stub_enabled".to_owned(),
                stub_considered_but_rejected: false,
            })
            .add_signal("zone_match")
            .add_signal("browser_known")
            .build()
            .unwrap();

        assert_eq!(explain.action(), FinalAction::BrowserStubAttempt);
        assert!(explain.final_action_summary.action.is_fail_closed());
        assert!(explain.is_complete_for(FinalAction::BrowserStubAttempt));
        // Signals sorted alphabetically
        assert_eq!(explain.used_signals, vec!["browser_known", "zone_match"]);
    }

    #[test]
    fn builder_builds_default_route_fail_open_explain() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-002")
            .input_summary(minimal_input())
            .match_trace(MatchTraceSummary::DefaultRoute {
                reason_label: "no_rule_matched".to_owned(),
                behavior_mode_label: "prefer_secondary_when_available".to_owned(),
            })
            .availability_trace(AvailabilityTraceSummary {
                requested_route: RouteRole::Secondary,
                observed_state_label: "degraded".to_owned(),
                secondary_not_configured: false,
                snapshot_stale: false,
            })
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "secondary_unavailable_fail_open",
            ))
            .add_warning(ExplainWarning::PrimaryAdapterDegraded)
            .add_uncertainty(UncertaintyMarker::StaleAvailabilitySnapshot)
            .build()
            .unwrap();

        assert_eq!(explain.action(), FinalAction::RoutePrimary);
        assert!(!explain.is_blocked());
        assert!(explain.has_uncertainty());
    }

    // ── Builder error cases ───────────────────────────────────────────────────

    #[test]
    fn builder_fails_without_input_summary() {
        let result = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .availability_trace(availability_trace(RouteRole::Primary))
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "ok",
            ))
            .build();
        assert_eq!(result, Err(ExplainBuildError::MissingInputSummary));
    }

    #[test]
    fn builder_fails_without_availability_trace() {
        let result = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "ok",
            ))
            .build();
        assert_eq!(result, Err(ExplainBuildError::MissingAvailabilityTrace));
    }

    #[test]
    fn builder_fails_without_final_action() {
        let result = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .availability_trace(availability_trace(RouteRole::Primary))
            .build();
        assert_eq!(result, Err(ExplainBuildError::MissingFinalAction));
    }

    // ── Deterministic ordering ────────────────────────────────────────────────

    #[test]
    fn uncertainty_markers_are_sorted_deterministically() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .availability_trace(availability_trace(RouteRole::Primary))
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "ok",
            ))
            // Added in reverse order
            .add_uncertainty(UncertaintyMarker::StaleAvailabilitySnapshot)
            .add_uncertainty(UncertaintyMarker::HostnameUnavailable)
            .add_uncertainty(UncertaintyMarker::StaleCacheUsed)
            .build()
            .unwrap();

        let expected = {
            let mut v = vec![
                UncertaintyMarker::StaleAvailabilitySnapshot,
                UncertaintyMarker::HostnameUnavailable,
                UncertaintyMarker::StaleCacheUsed,
            ];
            v.sort();
            v
        };
        assert_eq!(explain.uncertainty_markers, expected);
    }

    #[test]
    fn duplicate_markers_are_deduplicated() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .availability_trace(availability_trace(RouteRole::Primary))
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "ok",
            ))
            .add_uncertainty(UncertaintyMarker::StaleCacheUsed)
            .add_uncertainty(UncertaintyMarker::StaleCacheUsed) // duplicate
            .build()
            .unwrap();

        assert_eq!(explain.uncertainty_markers.len(), 1);
    }

    #[test]
    fn used_signals_are_sorted_alphabetically() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .availability_trace(availability_trace(RouteRole::Primary))
            .final_action(final_action(
                FinalAction::RoutePrimary,
                Some(RouteRole::Primary),
                "ok",
            ))
            .add_signal("zone_match")
            .add_signal("app_match")
            .add_signal("hostname_match")
            .build()
            .unwrap();

        assert_eq!(
            explain.used_signals,
            vec!["app_match", "hostname_match", "zone_match"]
        );
    }

    // ── DecisionId ────────────────────────────────────────────────────────────

    #[test]
    fn decision_id_format_starts_with_d_prefix() {
        let id = DecisionId("d-550e8400-e29b-41d4-a716-446655440000".to_owned());
        assert!(id.as_str().starts_with("d-"));
        assert_eq!(id.to_string(), "d-550e8400-e29b-41d4-a716-446655440000");
    }

    // ── compact_summary ───────────────────────────────────────────────────────

    #[test]
    fn compact_summary_includes_action_hostname_and_reason() {
        let explain = DecisionExplainBuilder::new(test_decision_id(), "rev-001")
            .input_summary(minimal_input())
            .availability_trace(availability_trace(RouteRole::Secondary))
            .final_action(final_action(
                FinalAction::RouteSecondary,
                Some(RouteRole::Secondary),
                "secondary_available",
            ))
            .build()
            .unwrap();

        let s = explain.compact_summary();
        assert!(s.contains("route:secondary"));
        assert!(s.contains("example.com"));
        assert!(s.contains("secondary_available"));
    }
}

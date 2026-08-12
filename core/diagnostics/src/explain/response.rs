//! Explain response DTO.
//!
//! [`ExplainResponse`] is the GUI/tray-facing DTO.  All user-visible strings
//! are localization keys (see [`super::keys`]); the GUI resolves them via the
//! locale system.
//!
//! # Section ordering
//!
//! Sections appear in this order (matching the task spec):
//! 1. summary
//! 2. input
//! 3. match (rule matched or default route)
//! 4. lookup / cache
//! 5. availability check
//! 6. final action
//! 7. warnings
//! 8. correlation

use nrr_domain::decision_explain::ExplainDetailLevel;
use serde::{Deserialize, Serialize};

use crate::explain::query::{ExplainDataAvailability, ExplainQueryKind};
use crate::taxonomy::EventCorrelation;

// ── ExplainResponse ───────────────────────────────────────────────────────────

/// Full explain response DTO, ready for GUI/tray consumption.
///
/// Serialises to JSON for IPC.  All user-visible label fields are localization
/// keys; the UI must not display them verbatim.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainResponse {
    /// Whether the result is a historical decision or a diagnostic simulation.
    pub query_kind: String, // "historical" | "synthetic"
    /// Detail level applied to build this response.
    pub detail_level: String, // "compact_ui" | "diagnostics" | "developer_trace"
    /// Availability of explain data (localization key).
    pub availability_key: String,
    /// 1. Summary section — always present.
    pub summary: ExplainSummarySection,
    /// 2. Input section — present when data is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<ExplainInputSection>,
    /// 3. Match section — present when a rule was evaluated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_section: Option<ExplainMatchSection>,
    /// 4. Lookup/cache section — present when lookup data is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lookup_section: Option<ExplainLookupSection>,
    /// 5. Availability check section — always present when data is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_section: Option<ExplainAvailabilitySection>,
    /// 6. Final action section — always present when data is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_action_section: Option<ExplainFinalActionSection>,
    /// 7. Warnings (Diagnostics+ only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ExplainWarningEntry>,
    /// 8. Correlation section.
    pub correlation: ExplainCorrelationSection,
}

impl ExplainResponse {
    /// Returns `true` if this response represents a diagnostic simulation.
    pub fn is_simulation(&self) -> bool {
        self.query_kind == "synthetic"
    }

    /// Returns `true` if explain data is fully available.
    pub fn is_available(&self) -> bool {
        self.availability_key == ExplainDataAvailability::Available.ui_key()
    }

    /// Constructs an unavailable response with the given availability reason.
    pub fn unavailable(
        query_kind: ExplainQueryKind,
        detail_level: ExplainDetailLevel,
        reason: ExplainDataAvailability,
    ) -> Self {
        Self {
            query_kind: query_kind_to_str(query_kind),
            detail_level: detail_level_to_str(detail_level),
            availability_key: reason.ui_key().to_string(),
            summary: ExplainSummarySection {
                summary_key: reason.ui_key().to_string(),
                is_simulation: query_kind.is_simulation(),
            },
            input: None,
            match_section: None,
            lookup_section: None,
            availability_section: None,
            final_action_section: None,
            warnings: Vec::new(),
            correlation: ExplainCorrelationSection::empty(),
        }
    }
}

// ── Section structs ───────────────────────────────────────────────────────────

/// One-line summary of the routing decision outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainSummarySection {
    /// Localization key describing what happened (e.g., `explain.summary.route_primary`).
    pub summary_key: String,
    /// Whether this result is a diagnostic simulation, not an applied decision.
    pub is_simulation: bool,
}

/// Privacy-filtered summary of the input that was evaluated.
///
/// At `CompactUi` level: hostname and process name only.
/// At `Diagnostics`+: adds observed IP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainInputSection {
    /// Destination hostname as observed (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_hostname: Option<String>,
    /// Whether a destination IP was present (CompactUi hides the actual address).
    pub destination_ip_present: bool,
    /// Actual IP address — only populated at Diagnostics+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    /// Process filename only (path stripped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Full process path — Diagnostics+ only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
}

/// Rule match outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainMatchSection {
    /// Localization key: `explain.match.rule_matched` or `explain.match.default_route`.
    pub outcome_key: String,
    /// Rule id if a rule was matched (e.g., `"r-abc123"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    /// Human-readable match class label (e.g., `"ExactFqdn"`, `"Zone"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_class_label: Option<String>,
    /// Route role the rule targets: `"primary"` or `"secondary"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_role: Option<String>,
    /// Whether a same-tier rule conflict was detected and resolved.
    pub conflict_resolved: bool,
    /// Localization key for the default route reason (if no rule matched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_reason_key: Option<String>,
}

/// Cache/lookup metadata section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainLookupSection {
    /// Localization key describing cache state (e.g., `explain.lookup.cache_hit`).
    pub cache_state_key: String,
    /// Whether a usable cache entry was found.
    pub cache_hit: bool,
    /// Whether lookup errors were recorded.
    pub has_errors: bool,
    /// Selected IP address — Diagnostics+ only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_ip: Option<String>,
    /// Whether multiple IPs resolved for the hostname.
    pub is_multi_ip: bool,
    /// TTL of the cache entry in seconds — Diagnostics+.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
}

/// Route availability check outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainAvailabilitySection {
    /// Localization key for secondary availability state.
    pub secondary_state_key: String,
    /// Route that was requested by the match stage.
    pub requested_route: String,
    /// Whether secondary is configured at all.
    pub secondary_configured: bool,
    /// Whether the availability snapshot was stale.
    pub snapshot_stale: bool,
}

/// Final routing action section.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainFinalActionSection {
    /// Localization key for the final action (e.g., `explain.final_action.route_primary`).
    pub action_key: String,
    /// Route role applied (`"primary"`, `"secondary"`, or `None`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_role: Option<String>,
    /// Localization key for the reason (e.g., Fail-Closed reason).
    pub reason_key: String,
}

/// A single warning entry with its localization key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainWarningEntry {
    /// Localization key for this warning.
    pub warning_key: String,
}

/// Correlation identifiers for the explain response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplainCorrelationSection {
    /// Decision ID (`d-{uuid}`) — present for historical decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// Active revision ID at the time of the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<String>,
    /// Operational log correlation identifiers.
    #[serde(skip_serializing_if = "EventCorrelation::is_empty")]
    pub log_correlation: EventCorrelation,
}

impl ExplainCorrelationSection {
    pub fn empty() -> Self {
        Self {
            decision_id: None,
            revision_id: None,
            log_correlation: EventCorrelation::default(),
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────────

pub(crate) fn query_kind_to_str(kind: ExplainQueryKind) -> String {
    match kind {
        ExplainQueryKind::Historical => "historical".into(),
        ExplainQueryKind::Synthetic => "synthetic".into(),
    }
}

pub(crate) fn detail_level_to_str(level: ExplainDetailLevel) -> String {
    match level {
        ExplainDetailLevel::CompactUi => "compact_ui".into(),
        ExplainDetailLevel::Diagnostics => "diagnostics".into(),
        ExplainDetailLevel::DeveloperTrace => "developer_trace".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_response_is_not_available() {
        let r = ExplainResponse::unavailable(
            ExplainQueryKind::Historical,
            ExplainDetailLevel::CompactUi,
            ExplainDataAvailability::DecisionNotFound,
        );
        assert!(!r.is_available());
        assert!(!r.is_simulation());
        assert!(r.input.is_none());
        assert!(r.final_action_section.is_none());
    }

    #[test]
    fn synthetic_response_is_simulation() {
        let r = ExplainResponse::unavailable(
            ExplainQueryKind::Synthetic,
            ExplainDetailLevel::CompactUi,
            ExplainDataAvailability::ServiceUnavailable,
        );
        assert!(r.is_simulation());
    }

    #[test]
    fn response_serializes_to_valid_json() {
        let r = ExplainResponse::unavailable(
            ExplainQueryKind::Historical,
            ExplainDetailLevel::CompactUi,
            ExplainDataAvailability::DecisionNotFound,
        );
        let json = serde_json::to_string(&r).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["query_kind"], "historical");
        assert_eq!(v["detail_level"], "compact_ui");
    }

    #[test]
    fn helper_functions_stable() {
        assert_eq!(
            query_kind_to_str(ExplainQueryKind::Historical),
            "historical"
        );
        assert_eq!(query_kind_to_str(ExplainQueryKind::Synthetic), "synthetic");
        assert_eq!(
            detail_level_to_str(ExplainDetailLevel::CompactUi),
            "compact_ui"
        );
        assert_eq!(
            detail_level_to_str(ExplainDetailLevel::Diagnostics),
            "diagnostics"
        );
        assert_eq!(
            detail_level_to_str(ExplainDetailLevel::DeveloperTrace),
            "developer_trace"
        );
    }
}

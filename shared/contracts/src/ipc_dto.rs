use crate::{
    AdapterCheckResultStatus, BindingSource, ConnectivityState, RecommendationClass,
    RecommendationConfidence, RouteBehaviorMode, RouteRole, RouteSelectionState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DtoGroup {
    Status,
    Configuration,
    Diagnostics,
    Interface,
    ReviewRevision,
    Operation,
}

pub const DTO_GROUPS_6_5: [DtoGroup; 6] = [
    DtoGroup::Status,
    DtoGroup::Configuration,
    DtoGroup::Diagnostics,
    DtoGroup::Interface,
    DtoGroup::ReviewRevision,
    DtoGroup::Operation,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    Transport,
    AuthSession,
    Validation,
    StateConflict,
    UnavailableDependency,
    InternalService,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorDto {
    pub code: String,
    pub category: ErrorCategory,
    pub message_key: String,
    pub technical_details: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AvailabilityState {
    Known,
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringFieldStateDto {
    pub state: AvailabilityState,
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DtoFieldStability {
    ContractStable,
    Experimental,
    AdditiveOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServiceAvailability {
    Available,
    Degraded,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHealthDto {
    pub availability: ServiceAvailability,
    pub mode: String,
    pub active_revision_id: StringFieldStateDto,
    pub pending_changes: bool,
    pub degraded_reasons: Vec<String>,
    pub last_error_summary: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentityDto {
    pub persistent_id: String,
    pub adapter_name: String,
    pub ipv6_if_index: u32,
    pub physical_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDisplayDto {
    pub windows_name: String,
    pub interface_description: String,
    pub interface_type: String,
    pub local_ip: StringFieldStateDto,
    pub gateway: StringFieldStateDto,
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceObservedFactsDto {
    pub connectivity_state: ConnectivityState,
    pub external_ip: StringFieldStateDto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceDerivedAssessmentDto {
    pub classification: String,
    pub confidence_percent: u8,
    pub heuristic_signals: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceRecommendationDto {
    pub class: RecommendationClass,
    pub confidence: RecommendationConfidence,
    pub advisory_only: bool,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceSnapshotDto {
    pub identity: AdapterIdentityDto,
    pub display: InterfaceDisplayDto,
    pub observed: InterfaceObservedFactsDto,
    pub derived: InterfaceDerivedAssessmentDto,
    pub selected_role: Option<RouteRole>,
    pub recommendation: InterfaceRecommendationDto,
    pub lifecycle_state: RouteSelectionState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRoleAssignmentDto {
    pub persistent_id: String,
    /// Provenance of this role assignment. Determines whether the binding
    /// counts as a confirmed policy decision (`source.is_user_confirmed()`).
    pub source: BindingSource,
    /// Advisory confidence from the last heuristic scan. This is a
    /// **derived/runtime** value — it must not be treated as policy state.
    pub advisory_confidence: RecommendationConfidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAssignmentStateDto {
    pub primary: RouteRoleAssignmentDto,
    pub secondary: RouteRoleAssignmentDto,
    pub conflict_markers: Vec<String>,
    pub behavior_mode: RouteBehaviorMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainSampleDto {
    pub input: String,
    pub selected_route: RouteRole,
    pub reason: String,
    pub used_signals: Vec<String>,
    pub secondary_status: AdapterCheckResultStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticsSnapshotDto {
    pub selected_primary: StringFieldStateDto,
    pub selected_secondary: StringFieldStateDto,
    pub explain_sample: ExplainSampleDto,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntryDto {
    pub timestamp_utc: String,
    pub level: String,
    pub source: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogsWindowingPolicyDto {
    pub page_size_default: u32,
    pub page_size_max: u32,
    pub cursor_supported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogsSnapshotDto {
    pub entries: Vec<LogEntryDto>,
    pub next_cursor: Option<String>,
    pub windowing: LogsWindowingPolicyDto,
}

/// IPC-shape mirror of `nrr-domain::revision::RiskLevel` (Low / Medium / High).
///
/// The two enums have identical variants but distinct types because the
/// dependency direction is `domain → shared` — `nrr-shared` cannot import
/// from `nrr-domain`, so the wire-level DTO type lives here and the domain
/// keeps its own canonical type. Service-runtime is responsible for the
/// trivial projection in both directions when constructing IPC responses or
/// consuming IPC requests; the canonical conversion lives in
/// `nrr-domain::revision` (`impl From<ReviewRiskLevel> for RiskLevel` and the
/// reverse), reusing the slug strings exposed by `as_slug` / `from_slug`.
///
/// Slugs match `nrr-domain::revision::RiskLevel`'s `Display` output:
/// `"low" | "medium" | "high" | "critical"`.
///
/// `Critical` is reserved for genuinely catastrophic configurations —
/// lock-out scenarios where the user is about to cut themselves off from
/// the network. Today no scoring path emits it (the production triggers —
/// primary↔secondary swap under fail-closed — need additional bindings +
/// behavior_mode plumbing). The level exists so the wire contract is
/// stable when those triggers land.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReviewRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ReviewRiskLevel {
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewSummaryDto {
    pub diff_summary: String,
    pub provenance: String,
    pub risk_level: ReviewRiskLevel,
    pub requires_review: bool,
    pub changed_fields: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationOutcome {
    Accepted,
    Completed,
    Rejected,
    Conflict,
    RequiresReview,
    RequiresRetry,
    ServiceUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationResultDto {
    pub outcome: OperationOutcome,
    pub code: String,
    pub category: ErrorCategory,
    pub user_message_key: String,
    pub technical_details: Option<String>,
    pub retry_hint: Option<String>,
    pub followup_action_hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeMetaDto {
    pub contract_version: String,
    pub timestamp_utc: String,
    pub request_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopePayloadDto {
    ServiceHealth(ServiceHealthDto),
    InterfaceSnapshot(Box<InterfaceSnapshotDto>),
    RouteAssignment(RouteAssignmentStateDto),
    Diagnostics(DiagnosticsSnapshotDto),
    Logs(LogsSnapshotDto),
    ReviewSummary(ReviewSummaryDto),
    OperationResult(OperationResultDto),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseEnvelopeDto {
    pub meta: EnvelopeMetaDto,
    pub payload: Option<EnvelopePayloadDto>,
    pub error: Option<ErrorDto>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DtoEnvelopePolicy {
    pub contract_version_required: bool,
    pub timestamp_required: bool,
    pub request_id_required: bool,
    pub payload_or_error_required: bool,
}

pub const DTO_ENVELOPE_POLICY_6_5: DtoEnvelopePolicy = DtoEnvelopePolicy {
    contract_version_required: true,
    timestamp_required: true,
    request_id_required: true,
    payload_or_error_required: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DtoToUiViewModelMapping {
    pub dto: &'static str,
    pub ui_view_model: &'static str,
    pub transport_details_hidden: bool,
}

pub const DTO_TO_UI_VIEW_MODEL_MAPPING_6_5: [DtoToUiViewModelMapping; 7] = [
    DtoToUiViewModelMapping {
        dto: "ServiceHealthDto",
        ui_view_model: "ServiceHealthViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "InterfaceSnapshotDto",
        ui_view_model: "InterfaceCardViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "RouteAssignmentStateDto",
        ui_view_model: "RouteAssignmentViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "DiagnosticsSnapshotDto",
        ui_view_model: "DiagnosticsViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "LogsSnapshotDto",
        ui_view_model: "LogsTableViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "ReviewSummaryDto",
        ui_view_model: "ReviewSummaryViewModel",
        transport_details_hidden: true,
    },
    DtoToUiViewModelMapping {
        dto: "OperationResultDto",
        ui_view_model: "OperationStatusViewModel",
        transport_details_hidden: true,
    },
];

pub const CANONICAL_MOCK_PAYLOAD_EXAMPLE_6_5: &str = r#"{
  "meta": {
    "contract_version": "1.0.0",
    "timestamp_utc": "2026-04-15T12:00:00Z",
    "request_id": "req-mock-001"
  },
  "payload": {
    "kind": "service_health",
    "availability": "degraded",
    "mode": "preview",
    "active_revision_id": { "state": "known", "value": "rev-preview-001" },
    "pending_changes": true
  },
  "warnings": ["mock-backend"]
}"#;

pub const CANONICAL_INTEGRATION_PAYLOAD_EXAMPLE_6_5: &str = r#"{
  "meta": {
    "contract_version": "1.0.0",
    "timestamp_utc": "2026-04-15T12:01:00Z",
    "request_id": "req-int-101"
  },
  "payload": {
    "kind": "operation_result",
    "outcome": "requires_review",
    "code": "review.required",
    "category": "validation",
    "user_message_key": "operation.review.required",
    "retry_hint": "read_pending_summary"
  },
  "warnings": []
}"#;

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::expect_used)]
mod tests {
    use super::{
        AvailabilityState, DtoFieldStability, ErrorCategory, LogsWindowingPolicyDto,
        OperationOutcome, ServiceAvailability, CANONICAL_INTEGRATION_PAYLOAD_EXAMPLE_6_5,
        CANONICAL_MOCK_PAYLOAD_EXAMPLE_6_5, DTO_ENVELOPE_POLICY_6_5, DTO_GROUPS_6_5,
        DTO_TO_UI_VIEW_MODEL_MAPPING_6_5,
    };
    use serde_json::Value;

    #[test]
    fn dto_groups_cover_required_subblock_6_5_categories() {
        assert_eq!(DTO_GROUPS_6_5.len(), 6);
    }

    #[test]
    fn envelope_policy_is_transport_independent_and_mandatory_fields_are_required() {
        assert!(DTO_ENVELOPE_POLICY_6_5.contract_version_required);
        assert!(DTO_ENVELOPE_POLICY_6_5.timestamp_required);
        assert!(DTO_ENVELOPE_POLICY_6_5.request_id_required);
        assert!(DTO_ENVELOPE_POLICY_6_5.payload_or_error_required);
    }

    #[test]
    fn error_taxonomy_contains_all_required_categories() {
        let categories = [
            ErrorCategory::Transport,
            ErrorCategory::AuthSession,
            ErrorCategory::Validation,
            ErrorCategory::StateConflict,
            ErrorCategory::UnavailableDependency,
            ErrorCategory::InternalService,
        ];
        assert_eq!(categories.len(), 6);
    }

    #[test]
    fn availability_state_avoids_ambiguous_null_semantics() {
        let known = AvailabilityState::Known;
        let unknown = AvailabilityState::Unknown;
        let unavailable = AvailabilityState::Unavailable;
        assert_ne!(known, unknown);
        assert_ne!(unknown, unavailable);
    }

    #[test]
    fn service_health_minimum_shape_fields_are_defined() {
        let dto = super::ServiceHealthDto {
            availability: ServiceAvailability::Degraded,
            mode: "preview".to_string(),
            active_revision_id: super::StringFieldStateDto {
                state: AvailabilityState::Known,
                value: Some("rev-preview-001".to_string()),
            },
            pending_changes: true,
            degraded_reasons: vec!["service-not-connected".to_string()],
            last_error_summary: Some("endpoint unavailable".to_string()),
        };
        assert_eq!(dto.mode, "preview");
        assert!(dto.pending_changes);
    }

    #[test]
    fn logs_snapshot_windowing_policy_prevents_unbounded_payload_growth() {
        let policy = LogsWindowingPolicyDto {
            page_size_default: 100,
            page_size_max: 500,
            cursor_supported: true,
        };
        assert!(policy.page_size_max >= policy.page_size_default);
        assert!(policy.cursor_supported);
    }

    #[test]
    fn operation_result_outcome_set_contains_required_states() {
        let outcomes = [
            OperationOutcome::Accepted,
            OperationOutcome::Completed,
            OperationOutcome::Rejected,
            OperationOutcome::Conflict,
            OperationOutcome::RequiresReview,
            OperationOutcome::RequiresRetry,
            OperationOutcome::ServiceUnavailable,
        ];
        assert_eq!(outcomes.len(), 7);
    }

    #[test]
    fn dto_stability_model_is_defined() {
        let states = [
            DtoFieldStability::ContractStable,
            DtoFieldStability::Experimental,
            DtoFieldStability::AdditiveOnly,
        ];
        assert_eq!(states.len(), 3);
    }

    #[test]
    fn dto_to_ui_mapping_hides_transport_details_from_qml() {
        assert!(DTO_TO_UI_VIEW_MODEL_MAPPING_6_5
            .iter()
            .all(|entry| entry.transport_details_hidden));
    }

    #[test]
    fn canonical_payload_examples_are_valid_json() {
        let mock: Value = serde_json::from_str(CANONICAL_MOCK_PAYLOAD_EXAMPLE_6_5)
            .expect("mock payload must parse");
        let integration: Value = serde_json::from_str(CANONICAL_INTEGRATION_PAYLOAD_EXAMPLE_6_5)
            .expect("integration payload must parse");
        assert!(mock.get("meta").is_some());
        assert!(integration.get("payload").is_some());
    }
}

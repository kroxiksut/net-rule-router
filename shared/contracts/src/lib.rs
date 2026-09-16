use core::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The line a runtime prints when it comes up, and the one naming what that
/// runtime is responsible for.
///
/// They live here, in the contracts crate every runtime already depends on,
/// because the background service needed exactly these two strings and nothing
/// else from `nrr-application` — and that one unused-in-practice dependency was
/// enough to link 5423 lines of UI and preview code into a service running as
/// LocalSystem. A shared string does not justify a shared dependency edge.
pub fn runtime_boot_banner(component: &str) -> String {
    format!(
        "{} {component} starting",
        crate::product_identity::PRODUCT_NAME
    )
}

/// What this process does — printed under the banner. The service carries the
/// routing engine, enforcement and the kill switch, so the old wording
/// ("starts without routing business logic") was a statement about the code
/// that stopped being true long ago; a boot line that lies is worse than none.
pub fn runtime_boot_role_message(component: &str) -> String {
    match component {
        "service" => "Applies and enforces the routing policy.".to_string(),
        _ => "Presents the routing policy; the background service enforces it.".to_string(),
    }
}

/// A short string identifying the shape of the wire contracts this build
/// speaks: crate version plus the two schema numbers that gate decoding.
///
/// Anything that persists decoded payloads (the GUI's snapshot cache) stores it
/// alongside the data and refuses what does not match. A hand-maintained
/// "cache schema version" was the alternative, and it is the kind of number
/// that is only ever bumped after the bug: nothing forces it to move when a DTO
/// gains a field.
pub fn contract_fingerprint() -> String {
    format!(
        "{}/rules-{}",
        env!("CARGO_PKG_VERSION"),
        rules_json::RULES_JSON_SCHEMA_VERSION
    )
}

pub mod app_identity;
pub mod auto_rule;
pub mod diagnostics_dto;
pub mod eula;
pub mod ipc;
pub mod ipc_dto;
pub mod ipc_flow;
pub mod ipc_payloads;
pub mod ipc_readiness;
pub mod ipc_transport;
pub mod ipc_wire;
pub mod launcher_rpc;
pub mod localization;
pub mod merge_dto;
pub mod pagination;
pub mod platform_profile;
pub mod preset_parser;
pub mod product_identity;
pub mod rules_json;
pub mod rules_overlap;
pub mod settings_export;
pub mod system_info;
// Descriptors + integrity status of the binaries we ship from third parties
// (today: WireGuard LLC's Wintun, Windows only). The GUI renders these, so
// the shapes belong to the wire contract; the port that fills them lives in
// `nrr-platform-api`.
pub mod third_party;
pub use auto_rule::{AutoRuleReason, RuleOrigin};
pub use ipc::{
    ipc_lifecycle_stages, ipc_operation_catalog, CompatibilityClientBehavior, IpcClientProfile,
    IpcContractVersionPolicy, IpcCorrelationModel, IpcCorrelationSource, IpcDataDeliveryKind,
    IpcEnvelopeField, IpcEnvelopePayloadBoundary, IpcExecutionModel, IpcIdempotencyClass,
    IpcInteractionClass, IpcLifecycleStage, IpcOperationName, IpcOperationSpec, IpcRetryPolicy,
    IpcStateUpdateModel, IpcUpdateModel, IpcVersionCompatibilityMatrix,
    IpcVersionCompatibilityRule, VersionCompatibilityCase, IPC_CONTRACT_VERSION_POLICY,
    IPC_CORRELATION_MODEL, IPC_ENVELOPE_PAYLOAD_BOUNDARY, IPC_RETRY_POLICY, IPC_STATE_UPDATE_MODEL,
    IPC_VERSION_COMPATIBILITY_MATRIX,
};
pub use ipc_dto::{
    AdapterIdentityDto, AvailabilityState, DiagnosticsSnapshotDto, DtoEnvelopePolicy,
    DtoFieldStability, DtoGroup, DtoToUiViewModelMapping, EnvelopeMetaDto, EnvelopePayloadDto,
    ErrorCategory, ErrorDto, ExplainSampleDto, InterfaceDerivedAssessmentDto, InterfaceDisplayDto,
    InterfaceObservedFactsDto, InterfaceRecommendationDto, InterfaceSnapshotDto, LogEntryDto,
    LogsSnapshotDto, LogsWindowingPolicyDto, OperationOutcome, OperationResultDto,
    ResponseEnvelopeDto, ReviewRiskLevel, ReviewSummaryDto, RouteAssignmentStateDto,
    RouteRoleAssignmentDto, ServiceAvailability, ServiceHealthDto, StringFieldStateDto,
    CANONICAL_INTEGRATION_PAYLOAD_EXAMPLE_6_5, CANONICAL_MOCK_PAYLOAD_EXAMPLE_6_5,
    DTO_ENVELOPE_POLICY_6_5, DTO_GROUPS_6_5, DTO_TO_UI_VIEW_MODEL_MAPPING_6_5,
};
pub use ipc_flow::{
    mutation_command_contracts, AmbiguousTimeoutHandlingPolicy, CommandSideEffect,
    ConflictDetectionReason, ConsistencyExpectation, MutationCommandContract, MutationCommandId,
    MutationEffectClass, MutationFlowStage, MutationPostcondition, MutationPrecondition,
    MutationResponseMode, OperationFlowClass, OperationResultStatus, ReadQueryId,
    ReadStateReference, RevisionFlowState, RevisionStateTransition,
    AMBIGUOUS_TIMEOUT_HANDLING_POLICY, COMMAND_SIDE_EFFECTS, CONFLICT_REASON_SET,
    MUTATION_COMMAND_SET_BASELINE, OPERATION_RESULT_STATUS_SET, READ_QUERY_SET_BASELINE,
    READ_STATE_REFERENCE_SET, REVISION_MUTATION_STAGES, REVISION_STATE_MACHINE,
};
pub use ipc_readiness::{
    block6_downstream_input_blocks, Block16BoundaryScope, Block6CrossBlockAlignment,
    Block6ReadinessChecklist, BLOCK_6_8_BLOCK16_BOUNDARY, BLOCK_6_8_CROSS_BLOCK_ALIGNMENT,
    BLOCK_6_8_READINESS_CHECKLIST,
};
pub use ipc_transport::{
    ipc_endpoint_security_specs, CallerIdentityCheck, IpcAclPolicy, IpcAclPrincipal,
    IpcCallerIdentityPolicy, IpcDegradationBehavior, IpcEndpointAccessClass, IpcEndpointName,
    IpcEndpointSecuritySpec, IpcFailureAndDegradationPolicy, IpcFailureMode, IpcFailurePolicyRule,
    IpcTransportKind, IPC_ACL_POLICY, IPC_CALLER_IDENTITY_POLICY,
    IPC_FAILURE_AND_DEGRADATION_POLICY, IPC_TRANSPORT_KIND, SERVICE_ENDPOINT_ADDRESS,
};
pub use localization::{
    load_locale_catalog, load_locale_descriptors, load_locale_map, load_locale_reports,
    load_locale_state, resolve_catalog_text, translate_or, LocaleDescriptor, LocaleLoadReport,
    LocaleLoadState, LocaleLoadStatus, LocaleSource, LOCALE_SCHEMA_PATH, LOCALE_SCHEMA_VERSION,
};
pub use settings_export::SettingsExportV1;

mod shell;
pub use shell::*;
mod adapters;
pub use adapters::*;
mod routing;
pub use routing::*;
mod startup;
pub use startup::*;
mod shell_model;
pub use shell_model::*;

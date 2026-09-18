// Envelope, versioning, correlation and retry policy: the rules both ends
// follow around the payload rather than inside it.

use super::{IpcDataDeliveryKind, IpcUpdateModel};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcContractVersionPolicy {
    pub contract_version_in_envelope: bool,
    pub explicit_negotiation_required: bool,
    pub reject_incompatible_versions: bool,
    pub compatibility_matrix_required: bool,
}

/// The wire protocol version both ends speak.
///
/// The one number the dispatcher hard-rejects a request on (`InvalidVersion`)
/// belongs where every peer reads it from. It lived twice — once in the
/// service, once in the client with a "mirrors ..." comment — so a bump on
/// either side compiled green and dropped 100 % of calls, with the client's
/// mismatch branch turning that into an endless reconnect instead of a
/// message. Bump only for an incompatible wire-format change, and record it in
/// [`IPC_VERSION_COMPATIBILITY_MATRIX`].
pub const IPC_PROTOCOL_VERSION: u32 = 1;

pub const IPC_CONTRACT_VERSION_POLICY: IpcContractVersionPolicy = IpcContractVersionPolicy {
    contract_version_in_envelope: true,
    explicit_negotiation_required: true,
    reject_incompatible_versions: true,
    compatibility_matrix_required: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcStateUpdateModel {
    pub default_model: IpcUpdateModel,
    pub status_updates: IpcUpdateModel,
    pub bootstrap_payload: IpcDataDeliveryKind,
    pub followup_updates: IpcDataDeliveryKind,
}

pub const IPC_STATE_UPDATE_MODEL: IpcStateUpdateModel = IpcStateUpdateModel {
    default_model: IpcUpdateModel::Hybrid,
    status_updates: IpcUpdateModel::Hybrid,
    bootstrap_payload: IpcDataDeliveryKind::FullSnapshot,
    followup_updates: IpcDataDeliveryKind::IncrementalUpdate,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcCorrelationSource {
    Gui,
    Tray,
    Service,
}

impl IpcCorrelationSource {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::Tray => "tray",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcCorrelationModel {
    pub request_id_required: bool,
    pub operation_id_required_for_async: bool,
    pub causation_source_required: bool,
    pub contract_version_required: bool,
    pub allowed_sources: &'static [IpcCorrelationSource],
}

const IPC_CORRELATION_SOURCES: [IpcCorrelationSource; 3] = [
    IpcCorrelationSource::Gui,
    IpcCorrelationSource::Tray,
    IpcCorrelationSource::Service,
];

pub const IPC_CORRELATION_MODEL: IpcCorrelationModel = IpcCorrelationModel {
    request_id_required: true,
    operation_id_required_for_async: true,
    causation_source_required: true,
    contract_version_required: true,
    allowed_sources: &IPC_CORRELATION_SOURCES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcIdempotencyClass {
    SafeRead,
    RetryableWithIdempotencyKey,
    NonIdempotentRequiresStateReadback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcRetryPolicy {
    pub require_idempotency_key_for_mutations: bool,
    pub timeout_outcome_is_ambiguous: bool,
    pub require_status_read_after_ambiguous_timeout: bool,
    pub max_safe_retry_attempts: u8,
}

pub const IPC_RETRY_POLICY: IpcRetryPolicy = IpcRetryPolicy {
    require_idempotency_key_for_mutations: true,
    timeout_outcome_is_ambiguous: true,
    require_status_read_after_ambiguous_timeout: true,
    max_safe_retry_attempts: 3,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcEnvelopeField {
    ContractVersion,
    RequestId,
    OperationId,
    TimestampUtc,
    CausationSource,
    Payload,
    Error,
    Warnings,
}

impl IpcEnvelopeField {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ContractVersion => "contract_version",
            Self::RequestId => "request_id",
            Self::OperationId => "operation_id",
            Self::TimestampUtc => "timestamp_utc",
            Self::CausationSource => "causation_source",
            Self::Payload => "payload",
            Self::Error => "error",
            Self::Warnings => "warnings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcEnvelopePayloadBoundary {
    pub envelope_fields: &'static [IpcEnvelopeField],
    pub payload_is_transport_agnostic: bool,
    pub forbid_transport_metadata_inside_payload: bool,
}

const IPC_ENVELOPE_FIELDS: [IpcEnvelopeField; 8] = [
    IpcEnvelopeField::ContractVersion,
    IpcEnvelopeField::RequestId,
    IpcEnvelopeField::OperationId,
    IpcEnvelopeField::TimestampUtc,
    IpcEnvelopeField::CausationSource,
    IpcEnvelopeField::Payload,
    IpcEnvelopeField::Error,
    IpcEnvelopeField::Warnings,
];

pub const IPC_ENVELOPE_PAYLOAD_BOUNDARY: IpcEnvelopePayloadBoundary = IpcEnvelopePayloadBoundary {
    envelope_fields: &IPC_ENVELOPE_FIELDS,
    payload_is_transport_agnostic: true,
    forbid_transport_metadata_inside_payload: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionCompatibilityCase {
    OlderService,
    NewerService,
    IncompatibleContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompatibilityClientBehavior {
    ProceedWithCompatibleSubset,
    RequireCapabilityNegotiation,
    HardFailAndPromptUpgrade,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcVersionCompatibilityRule {
    pub case: VersionCompatibilityCase,
    pub behavior: CompatibilityClientBehavior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcVersionCompatibilityMatrix {
    pub rules: &'static [IpcVersionCompatibilityRule],
}

const IPC_VERSION_COMPATIBILITY_RULES: [IpcVersionCompatibilityRule; 3] = [
    IpcVersionCompatibilityRule {
        case: VersionCompatibilityCase::OlderService,
        behavior: CompatibilityClientBehavior::ProceedWithCompatibleSubset,
    },
    IpcVersionCompatibilityRule {
        case: VersionCompatibilityCase::NewerService,
        behavior: CompatibilityClientBehavior::RequireCapabilityNegotiation,
    },
    IpcVersionCompatibilityRule {
        case: VersionCompatibilityCase::IncompatibleContract,
        behavior: CompatibilityClientBehavior::HardFailAndPromptUpgrade,
    },
];

pub const IPC_VERSION_COMPATIBILITY_MATRIX: IpcVersionCompatibilityMatrix =
    IpcVersionCompatibilityMatrix {
        rules: &IPC_VERSION_COMPATIBILITY_RULES,
    };

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationFlowClass {
    ReadSnapshot,
    ReadStatus,
    DiagnosticProbe,
    AdvisoryRecompute,
    MutationRequest,
    ReviewConfirmation,
    RecoveryAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConsistencyExpectation {
    InstantSnapshot,
    EventualUpdate,
    OperationInProgress,
    RequiresExplicitRefresh,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationFlowStage {
    InputAcceptance,
    Validation,
    Canonicalization,
    CandidateCreation,
    ReviewRequiredDecision,
    ActivationOrRollbackResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationEffectClass {
    AdvisoryUiOnly,
    RequiresRevisionTransition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadQueryId {
    ServiceStatus,
    DiagnosticsSnapshot,
    LogsSnapshot,
    InterfaceSnapshot,
    RouteRoleRecommendations,
    PendingChangesSummary,
}

pub const READ_QUERY_SET_BASELINE: [ReadQueryId; 6] = [
    ReadQueryId::ServiceStatus,
    ReadQueryId::DiagnosticsSnapshot,
    ReadQueryId::LogsSnapshot,
    ReadQueryId::InterfaceSnapshot,
    ReadQueryId::RouteRoleRecommendations,
    ReadQueryId::PendingChangesSummary,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationCommandId {
    RefreshInterfaces,
    SelectPrimarySecondary,
    SaveCandidateChanges,
    ApprovePendingReview,
    RollbackRevision,
    DisableProductImpactTemporary,
}

pub const MUTATION_COMMAND_SET_BASELINE: [MutationCommandId; 6] = [
    MutationCommandId::RefreshInterfaces,
    MutationCommandId::SelectPrimarySecondary,
    MutationCommandId::SaveCandidateChanges,
    MutationCommandId::ApprovePendingReview,
    MutationCommandId::RollbackRevision,
    MutationCommandId::DisableProductImpactTemporary,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationPrecondition {
    ServiceAvailable,
    CallerAuthorized,
    ActiveOrPendingRevisionKnown,
    SelectedInterfacesPresent,
    ReviewTokenValid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationPostcondition {
    CandidateUpdated,
    PendingRevisionCreated,
    ActiveRevisionChanged,
    RollbackApplied,
    SecurityStatusUpdated,
    AuditEventWritten,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MutationResponseMode {
    ReturnImmediateSnapshotSummary,
    ReturnOperationHandleFollowupRead,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MutationCommandContract {
    pub command: MutationCommandId,
    pub effect_class: MutationEffectClass,
    pub preconditions: &'static [MutationPrecondition],
    pub postconditions: &'static [MutationPostcondition],
    pub response_mode: MutationResponseMode,
}

const PRE_REFRESH_INTERFACES: [MutationPrecondition; 2] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
];
const POST_REFRESH_INTERFACES: [MutationPostcondition; 1] =
    [MutationPostcondition::CandidateUpdated];

const PRE_SELECT_PRIMARY_SECONDARY: [MutationPrecondition; 4] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
    MutationPrecondition::ActiveOrPendingRevisionKnown,
    MutationPrecondition::SelectedInterfacesPresent,
];
const POST_SELECT_PRIMARY_SECONDARY: [MutationPostcondition; 2] = [
    MutationPostcondition::CandidateUpdated,
    MutationPostcondition::SecurityStatusUpdated,
];

const PRE_SAVE_CANDIDATE: [MutationPrecondition; 3] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
    MutationPrecondition::ActiveOrPendingRevisionKnown,
];
const POST_SAVE_CANDIDATE: [MutationPostcondition; 2] = [
    MutationPostcondition::PendingRevisionCreated,
    MutationPostcondition::AuditEventWritten,
];

const PRE_APPROVE_PENDING: [MutationPrecondition; 4] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
    MutationPrecondition::ActiveOrPendingRevisionKnown,
    MutationPrecondition::ReviewTokenValid,
];
const POST_APPROVE_PENDING: [MutationPostcondition; 3] = [
    MutationPostcondition::ActiveRevisionChanged,
    MutationPostcondition::SecurityStatusUpdated,
    MutationPostcondition::AuditEventWritten,
];

const PRE_ROLLBACK: [MutationPrecondition; 3] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
    MutationPrecondition::ActiveOrPendingRevisionKnown,
];
const POST_ROLLBACK: [MutationPostcondition; 3] = [
    MutationPostcondition::RollbackApplied,
    MutationPostcondition::SecurityStatusUpdated,
    MutationPostcondition::AuditEventWritten,
];

const PRE_DISABLE_PRODUCT_IMPACT: [MutationPrecondition; 2] = [
    MutationPrecondition::ServiceAvailable,
    MutationPrecondition::CallerAuthorized,
];
const POST_DISABLE_PRODUCT_IMPACT: [MutationPostcondition; 2] = [
    MutationPostcondition::SecurityStatusUpdated,
    MutationPostcondition::AuditEventWritten,
];

const MUTATION_COMMAND_CONTRACTS: [MutationCommandContract; 6] = [
    MutationCommandContract {
        command: MutationCommandId::RefreshInterfaces,
        effect_class: MutationEffectClass::AdvisoryUiOnly,
        preconditions: &PRE_REFRESH_INTERFACES,
        postconditions: &POST_REFRESH_INTERFACES,
        response_mode: MutationResponseMode::ReturnOperationHandleFollowupRead,
    },
    MutationCommandContract {
        command: MutationCommandId::SelectPrimarySecondary,
        effect_class: MutationEffectClass::RequiresRevisionTransition,
        preconditions: &PRE_SELECT_PRIMARY_SECONDARY,
        postconditions: &POST_SELECT_PRIMARY_SECONDARY,
        response_mode: MutationResponseMode::ReturnImmediateSnapshotSummary,
    },
    MutationCommandContract {
        command: MutationCommandId::SaveCandidateChanges,
        effect_class: MutationEffectClass::RequiresRevisionTransition,
        preconditions: &PRE_SAVE_CANDIDATE,
        postconditions: &POST_SAVE_CANDIDATE,
        response_mode: MutationResponseMode::ReturnOperationHandleFollowupRead,
    },
    MutationCommandContract {
        command: MutationCommandId::ApprovePendingReview,
        effect_class: MutationEffectClass::RequiresRevisionTransition,
        preconditions: &PRE_APPROVE_PENDING,
        postconditions: &POST_APPROVE_PENDING,
        response_mode: MutationResponseMode::ReturnOperationHandleFollowupRead,
    },
    MutationCommandContract {
        command: MutationCommandId::RollbackRevision,
        effect_class: MutationEffectClass::RequiresRevisionTransition,
        preconditions: &PRE_ROLLBACK,
        postconditions: &POST_ROLLBACK,
        response_mode: MutationResponseMode::ReturnOperationHandleFollowupRead,
    },
    MutationCommandContract {
        command: MutationCommandId::DisableProductImpactTemporary,
        effect_class: MutationEffectClass::RequiresRevisionTransition,
        preconditions: &PRE_DISABLE_PRODUCT_IMPACT,
        postconditions: &POST_DISABLE_PRODUCT_IMPACT,
        response_mode: MutationResponseMode::ReturnImmediateSnapshotSummary,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationResultStatus {
    Accepted,
    Completed,
    Rejected,
    Conflict,
    RequiresReview,
    RequiresRetry,
    ServiceUnavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConflictDetectionReason {
    StaleRevision,
    MissingInterface,
    IncompatiblePendingChange,
    DeniedMutation,
    StateChangedDuringReview,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadStateReference {
    Latest,
    ByRevision,
    BySnapshotGeneration,
    BestEffortCurrent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandSideEffect {
    RouteRoleBindingChanged,
    PendingRevisionCreated,
    AuditEventWritten,
    SecurityVisibleStatusUpdated,
    UiRefreshTriggered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AmbiguousTimeoutHandlingPolicy {
    pub do_not_assume_success: bool,
    pub do_not_assume_failure: bool,
    pub require_followup_state_read: bool,
}

pub const AMBIGUOUS_TIMEOUT_HANDLING_POLICY: AmbiguousTimeoutHandlingPolicy =
    AmbiguousTimeoutHandlingPolicy {
        do_not_assume_success: true,
        do_not_assume_failure: true,
        require_followup_state_read: true,
    };

pub const REVISION_MUTATION_STAGES: [MutationFlowStage; 6] = [
    MutationFlowStage::InputAcceptance,
    MutationFlowStage::Validation,
    MutationFlowStage::Canonicalization,
    MutationFlowStage::CandidateCreation,
    MutationFlowStage::ReviewRequiredDecision,
    MutationFlowStage::ActivationOrRollbackResult,
];

pub const OPERATION_RESULT_STATUS_SET: [OperationResultStatus; 7] = [
    OperationResultStatus::Accepted,
    OperationResultStatus::Completed,
    OperationResultStatus::Rejected,
    OperationResultStatus::Conflict,
    OperationResultStatus::RequiresReview,
    OperationResultStatus::RequiresRetry,
    OperationResultStatus::ServiceUnavailable,
];

pub const CONFLICT_REASON_SET: [ConflictDetectionReason; 5] = [
    ConflictDetectionReason::StaleRevision,
    ConflictDetectionReason::MissingInterface,
    ConflictDetectionReason::IncompatiblePendingChange,
    ConflictDetectionReason::DeniedMutation,
    ConflictDetectionReason::StateChangedDuringReview,
];

pub const READ_STATE_REFERENCE_SET: [ReadStateReference; 4] = [
    ReadStateReference::Latest,
    ReadStateReference::ByRevision,
    ReadStateReference::BySnapshotGeneration,
    ReadStateReference::BestEffortCurrent,
];

pub const COMMAND_SIDE_EFFECTS: [CommandSideEffect; 5] = [
    CommandSideEffect::RouteRoleBindingChanged,
    CommandSideEffect::PendingRevisionCreated,
    CommandSideEffect::AuditEventWritten,
    CommandSideEffect::SecurityVisibleStatusUpdated,
    CommandSideEffect::UiRefreshTriggered,
];

// `RevisionFlowState` is the IPC/UI flow-state view of revision lifecycle. It
// is intentionally distinct from the domain's persisted statuses
// (`nrr-domain::rules_revision::RevisionStatus` — Candidate, Active,
// Superseded, RolledBack, Rejected — and the older
// `nrr-domain::revision::RevisionState`).
//
// The two abstractions serve different purposes:
//
//   - `RevisionFlowState` represents the user-facing flow during an
//     interactive review/activate sequence (DraftInput → Candidate →
//     PendingReview → Active or Rejected). It drives wizard step transitions
//     and progress indicators.
//
//   - `RevisionStatus` represents the persisted lifecycle row in
//     `revisions.status`. It includes terminal history states (`Superseded`,
//     `RolledBack`) that the flow view does not animate through but that
//     appear in revision-history lists.
//
// Pending-revisions/history DTOs surfaced via `SnapshotInitialResponse`
// transmit `RevisionStatus` slug strings (`"candidate" | "active" |
// "superseded" | "rolled-back" | "rejected"`) — they do not reuse this enum.
// GUI maps slugs to display labels via `tr("revision.status.<slug>", ...)`.
//
// Mapping reference (flow-state ↔ domain status, 1:1 where the flow surfaces
// the status; no entry where the flow does not animate the transition):
//
//   DraftInput      ↔ (transient client-side; no persisted counterpart)
//   Candidate       ↔ RevisionStatus::Candidate
//   PendingReview   ↔ (transient review wizard step; no persisted counterpart)
//   Active          ↔ RevisionStatus::Active
//   RolledBack      ↔ RevisionStatus::RolledBack
//   Rejected        ↔ RevisionStatus::Rejected
//   (no counterpart) ↔ RevisionStatus::Superseded — surfaced via slug only
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RevisionFlowState {
    DraftInput,
    Candidate,
    PendingReview,
    Active,
    RolledBack,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RevisionStateTransition {
    pub from: RevisionFlowState,
    pub to: RevisionFlowState,
    pub trigger: MutationCommandId,
}

pub const REVISION_STATE_MACHINE: [RevisionStateTransition; 6] = [
    RevisionStateTransition {
        from: RevisionFlowState::DraftInput,
        to: RevisionFlowState::Candidate,
        trigger: MutationCommandId::SelectPrimarySecondary,
    },
    RevisionStateTransition {
        from: RevisionFlowState::Candidate,
        to: RevisionFlowState::PendingReview,
        trigger: MutationCommandId::SaveCandidateChanges,
    },
    RevisionStateTransition {
        from: RevisionFlowState::PendingReview,
        to: RevisionFlowState::Active,
        trigger: MutationCommandId::ApprovePendingReview,
    },
    RevisionStateTransition {
        from: RevisionFlowState::Active,
        to: RevisionFlowState::RolledBack,
        trigger: MutationCommandId::RollbackRevision,
    },
    RevisionStateTransition {
        from: RevisionFlowState::PendingReview,
        to: RevisionFlowState::Rejected,
        trigger: MutationCommandId::RollbackRevision,
    },
    RevisionStateTransition {
        from: RevisionFlowState::Candidate,
        to: RevisionFlowState::Rejected,
        trigger: MutationCommandId::DisableProductImpactTemporary,
    },
];

pub fn mutation_command_contracts() -> &'static [MutationCommandContract] {
    &MUTATION_COMMAND_CONTRACTS
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::expect_used)]
mod tests {
    use super::{
        mutation_command_contracts, MutationCommandId, MutationEffectClass, MutationFlowStage,
        MutationResponseMode, OperationFlowClass, RevisionFlowState,
        AMBIGUOUS_TIMEOUT_HANDLING_POLICY, COMMAND_SIDE_EFFECTS, CONFLICT_REASON_SET,
        MUTATION_COMMAND_SET_BASELINE, OPERATION_RESULT_STATUS_SET, READ_QUERY_SET_BASELINE,
        READ_STATE_REFERENCE_SET, REVISION_MUTATION_STAGES, REVISION_STATE_MACHINE,
    };

    #[test]
    fn operation_classes_cover_read_diagnostic_mutation_review_and_recovery() {
        let classes = [
            OperationFlowClass::ReadSnapshot,
            OperationFlowClass::ReadStatus,
            OperationFlowClass::DiagnosticProbe,
            OperationFlowClass::AdvisoryRecompute,
            OperationFlowClass::MutationRequest,
            OperationFlowClass::ReviewConfirmation,
            OperationFlowClass::RecoveryAction,
        ];
        assert_eq!(classes.len(), 7);
    }

    #[test]
    fn baseline_sets_cover_read_queries_and_mutating_commands() {
        assert_eq!(READ_QUERY_SET_BASELINE.len(), 6);
        assert_eq!(MUTATION_COMMAND_SET_BASELINE.len(), 6);
    }

    #[test]
    fn revision_mutation_stages_are_defined_in_order() {
        assert_eq!(REVISION_MUTATION_STAGES.len(), 6);
        assert_eq!(
            REVISION_MUTATION_STAGES[0],
            MutationFlowStage::InputAcceptance
        );
        assert_eq!(
            REVISION_MUTATION_STAGES[5],
            MutationFlowStage::ActivationOrRollbackResult
        );
    }

    #[test]
    fn command_contracts_capture_preconditions_postconditions_and_response_modes() {
        let contracts = mutation_command_contracts();
        let select_roles = contracts
            .iter()
            .find(|item| item.command == MutationCommandId::SelectPrimarySecondary)
            .expect("select primary/secondary command must exist");
        assert_eq!(
            select_roles.effect_class,
            MutationEffectClass::RequiresRevisionTransition
        );
        assert_eq!(
            select_roles.response_mode,
            MutationResponseMode::ReturnImmediateSnapshotSummary
        );

        let refresh = contracts
            .iter()
            .find(|item| item.command == MutationCommandId::RefreshInterfaces)
            .expect("refresh interfaces command must exist");
        assert_eq!(refresh.effect_class, MutationEffectClass::AdvisoryUiOnly);
        assert_eq!(
            refresh.response_mode,
            MutationResponseMode::ReturnOperationHandleFollowupRead
        );
    }

    #[test]
    fn result_conflict_reference_and_side_effect_sets_are_present() {
        assert_eq!(OPERATION_RESULT_STATUS_SET.len(), 7);
        assert_eq!(CONFLICT_REASON_SET.len(), 5);
        assert_eq!(READ_STATE_REFERENCE_SET.len(), 4);
        assert_eq!(COMMAND_SIDE_EFFECTS.len(), 5);
    }

    #[test]
    fn ambiguous_timeout_policy_requires_explicit_state_readback() {
        assert!(AMBIGUOUS_TIMEOUT_HANDLING_POLICY.do_not_assume_success);
        assert!(AMBIGUOUS_TIMEOUT_HANDLING_POLICY.do_not_assume_failure);
        assert!(AMBIGUOUS_TIMEOUT_HANDLING_POLICY.require_followup_state_read);
    }

    #[test]
    fn revision_state_machine_covers_candidate_pending_active_and_rollback_paths() {
        assert!(REVISION_STATE_MACHINE.iter().any(|item| {
            item.from == RevisionFlowState::DraftInput && item.to == RevisionFlowState::Candidate
        }));
        assert!(REVISION_STATE_MACHINE.iter().any(|item| {
            item.from == RevisionFlowState::Candidate && item.to == RevisionFlowState::PendingReview
        }));
        assert!(REVISION_STATE_MACHINE.iter().any(|item| {
            item.from == RevisionFlowState::PendingReview && item.to == RevisionFlowState::Active
        }));
        assert!(REVISION_STATE_MACHINE.iter().any(|item| {
            item.from == RevisionFlowState::Active && item.to == RevisionFlowState::RolledBack
        }));
    }
}

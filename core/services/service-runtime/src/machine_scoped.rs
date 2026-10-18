//! Writing a machine-wide setting from a user-scoped operation.
//!
//! The operations [`MachineScopedSetting::written_by`] names change state that
//! belongs to the MACHINE, not to the caller, yet travel under a class that
//! does not require elevation.
//!
//! Demanding elevation for the whole operation would be wrong: clients
//! read-modify-write the whole row, so refusing every save that merely echoes
//! the current value would turn ordinary settings into a UAC prompt for exactly
//! the users the restriction applies to.
//!
//! So the check is on the VALUE, not on the operation: a non-elevated caller
//! may save anything as long as the machine-wide part comes back unchanged.

use nrr_shared::ipc::IpcOperationName;

use crate::ipc::IpcError;

#[cfg(test)]
mod gate_probes;

/// A machine-wide setting whose write is gated by value inside its handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineScopedSetting {
    DohResolvers,
    LocalDnsSuffixes,
    Retention,
    LogRetention,
    ApplyFailurePolicy,
    ServiceStability,
    TrafficStats,
}

impl MachineScopedSetting {
    /// The setting `op` writes when its handler gates the write by value.
    ///
    /// Exhaustive on purpose: a new operation does not compile until somebody
    /// decides whether it writes machine state this way. The privilege tests
    /// derive the list of value-gated operations from here, and the gate
    /// probes run each one's real handler.
    #[must_use]
    pub const fn written_by(op: IpcOperationName) -> Option<Self> {
        use IpcOperationName as Op;
        match op {
            Op::DohResolversSet => Some(Self::DohResolvers),
            Op::LocalDnsSuffixesSet => Some(Self::LocalDnsSuffixes),
            Op::RetentionSettingsSet => Some(Self::Retention),
            Op::LogRetentionConfigSet => Some(Self::LogRetention),
            Op::ApplyFailurePolicySet => Some(Self::ApplyFailurePolicy),
            Op::ServiceStabilityConfigSet => Some(Self::ServiceStability),
            Op::TrafficStatsSet => Some(Self::TrafficStats),
            Op::ContractNegotiate
            | Op::ServiceHealthGet
            | Op::SnapshotInitialGet
            | Op::SnapshotInterfacesGet
            | Op::SnapshotDiagnosticsGet
            | Op::StatusUpdatesPoll
            | Op::StatusUpdatesSubscribe
            | Op::MutationSubmit
            | Op::OperationStatusGet
            | Op::InterfacesRefreshRequest
            | Op::RollbackRequest
            | Op::ProductImpactDisableTemporary
            | Op::LogsList
            | Op::AuditList
            | Op::SecurityAlertsList
            | Op::RulesList
            | Op::RoutePolicyUpdate
            | Op::RouteLinkProviderSet
            | Op::DohResolversGet
            | Op::LocalDnsSuffixesGet
            | Op::SeedFromBrowserHistory
            | Op::MigrationStatusGet
            | Op::MigrationMarkComplete
            | Op::RetentionSettingsGet
            | Op::ApplyFailurePolicyGet
            | Op::StorageUsageGet
            | Op::RoutingPauseGet
            | Op::RoutingPauseToggle
            | Op::AutostartGet
            | Op::AutostartToggle
            | Op::ExplainGet
            | Op::DiagnosticsExportArchive
            | Op::ServiceStabilityConfigGet
            | Op::LogsClear
            | Op::CacheClear
            | Op::CacheEntriesList
            | Op::PresetExportGet
            | Op::SettingsExportFull
            | Op::RulesMergePreview
            | Op::ConnTraceEntriesList
            | Op::ConnTraceOutageBlocksList
            | Op::LogRetentionConfigGet
            | Op::ThirdPartyComponentsList
            | Op::TrafficStatsGet
            | Op::TrafficHistoryMergeSet
            | Op::TrafficStatsClear
            | Op::AutoRuleCandidatesProbe
            | Op::RefusingAnchorSet
            | Op::LocalNetworksGet
            | Op::LocalNetworksSet
            | Op::AutoRuleCandidatesList
            | Op::AutoRuleCandidatesAccept
            | Op::AutoRuleCandidatesDismiss
            | Op::AutoRuleDismissedList
            | Op::AutoRuleDismissedRestore
            | Op::AutoRuleCandidatesForget
            | Op::BlockNoticeJournalList
            | Op::BlockNoticeJournalAck
            | Op::BlockNoticeMutesList
            | Op::BlockNoticeMutesSet
            | Op::BlockNoticeMutesRemove
            | Op::BlockNoticeMutesClear
            | Op::BlockNoticeRouteToSecondary
            | Op::PrincipalDataPurge
            | Op::PrincipalDataCount
            | Op::VerifyVerdictsList
            | Op::VerifyVerdictsAccept
            | Op::VerifyVerdictsDismiss
            | Op::VpnGatewayCandidatesList
            | Op::RulesRecentChangesList
            | Op::ConnHistoryList
            | Op::ConnHistoryClear
            | Op::ConnHistorySettingsSet => None,
        }
    }

    /// The operation that writes this setting.
    #[must_use]
    pub const fn operation(self) -> IpcOperationName {
        match self {
            Self::DohResolvers => IpcOperationName::DohResolversSet,
            Self::LocalDnsSuffixes => IpcOperationName::LocalDnsSuffixesSet,
            Self::Retention => IpcOperationName::RetentionSettingsSet,
            Self::LogRetention => IpcOperationName::LogRetentionConfigSet,
            Self::ApplyFailurePolicy => IpcOperationName::ApplyFailurePolicySet,
            Self::ServiceStability => IpcOperationName::ServiceStabilityConfigSet,
            Self::TrafficStats => IpcOperationName::TrafficStatsSet,
        }
    }

    /// How the refusal names the setting.
    const fn subject(self) -> &'static str {
        match self {
            Self::DohResolvers => "The DoH/DoT resolver list",
            Self::LocalDnsSuffixes => "The home-network suffix list",
            Self::Retention => "The retention policy",
            Self::LogRetention => "The log and audit retention policy",
            Self::ApplyFailurePolicy => "The apply-failure policy",
            Self::ServiceStability => "This service setting",
            Self::TrafficStats => "Traffic statistics",
        }
    }
}

/// Whether this write may proceed.
///
/// `true` when the caller is elevated, or when the machine-wide value is not
/// actually changing.
#[must_use]
pub fn machine_scoped_write_allowed<T: PartialEq>(
    requested: &T,
    current: &T,
    caller_is_elevated: bool,
) -> bool {
    caller_is_elevated || requested == current
}

/// The refusal, worded so the GUI can explain what to do. Its code is the
/// stable part a client acts on: `Forbidden` means "an administrator could".
#[must_use]
pub fn machine_scoped_refusal(setting: MachineScopedSetting) -> IpcError {
    IpcError::needs_administrator(format_args!(
        "{} is shared by every user of this machine; changing it needs an \
         administrator. Saving it unchanged is always allowed.",
        setting.subject()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcErrorCode;

    #[test]
    fn an_unchanged_value_saves_without_elevation() {
        // The read-modify-write case: the client sends the whole row back,
        // machine-wide fields included, without meaning to change them.
        assert!(machine_scoped_write_allowed(&7, &7, false));
    }

    #[test]
    fn a_changed_value_needs_elevation() {
        assert!(!machine_scoped_write_allowed(&8, &7, false));
        assert!(machine_scoped_write_allowed(&8, &7, true));
    }

    #[test]
    fn the_refusal_names_the_setting_and_the_way_out() {
        let e = machine_scoped_refusal(MachineScopedSetting::DohResolvers);
        assert_eq!(e.code, IpcErrorCode::Forbidden);
        assert!(e.message.contains("DoH/DoT resolver list"));
        assert!(e.message.contains("administrator"));
    }

    /// The router lifts a value-gated refusal only for operations the shared
    /// list names, and clients budget for the password prompt by the same list.
    #[test]
    fn every_value_gated_operation_is_one_the_router_may_lift() {
        for op in IpcOperationName::ALL {
            if MachineScopedSetting::written_by(op).is_some() {
                assert!(
                    nrr_shared::ipc_transport::handler_may_need_administrator(op),
                    "{}",
                    op.slug()
                );
            }
        }
    }

    #[test]
    fn the_refusal_is_typed_as_needing_an_administrator() {
        let e = machine_scoped_refusal(MachineScopedSetting::Retention);
        assert!(nrr_shared::ipc_transport::is_needs_administrator(
            &e.message
        ));
    }

    #[test]
    fn each_setting_maps_back_to_the_operation_that_writes_it() {
        for op in IpcOperationName::ALL {
            if let Some(setting) = MachineScopedSetting::written_by(op) {
                assert_eq!(setting.operation(), op, "{}", op.slug());
            }
        }
    }
}

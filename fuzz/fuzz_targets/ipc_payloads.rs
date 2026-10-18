#![no_main]
//! The payload of a request envelope, handed to every typed request shape a
//! handler deserialises it into. A new `*Request` in `nrr_shared::ipc_payloads`
//! is added to the list below.

use libfuzzer_sys::fuzz_target;
use nrr_shared::ipc_payloads::*;
use nrr_shared::ipc_transport::IPC_MAX_MESSAGE_BYTES;

macro_rules! try_every {
    ($value:expr; $($request:ty),+ $(,)?) => {
        $( let _ = serde_json::from_value::<$request>($value.clone()); )+
    };
}

fuzz_target!(|data: &[u8]| {
    if data.len() > IPC_MAX_MESSAGE_BYTES {
        return;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    try_every!(value;
        ContractNegotiateRequest,
        ServiceHealthRequest,
        SnapshotInterfacesRequest,
        SnapshotDiagnosticsRequest,
        LogsListRequest,
        AuditListRequest,
        SecurityAlertsRequest,
        OperationStatusRequest,
        ProductImpactDisableRequest,
        InterfacesRefreshRequest,
        StatusUpdatesSubscribeRequest,
        StatusUpdatesPollRequest,
        RollbackRequest,
        SnapshotInitialRequest,
        ExplainGetRequest,
        DiagnosticsExportArchiveRequest,
        LogsClearRequest,
        CacheClearRequest,
        CacheEntriesListRequest,
        ConnTraceEntriesListRequest,
        ConnTraceOutageBlocksRequest,
        RouteLinkProviderSetRequest,
        DohResolversSetRequest,
        RoutePolicyUpdateRequest,
        RulesListRequest,
        PresetExportGetRequest,
        SettingsExportFullRequest,
        MergePreviewRequest,
        MutationSubmitRequest,
        VerifyVerdictsListRequest,
        VerifyVerdictsAcceptRequest,
        VerifyVerdictsDismissRequest,
        MigrationStatusGetRequest,
        MigrationMarkCompleteRequest,
        RetentionSettingsGetRequest,
        RetentionSettingsSetRequest,
        LogRetentionConfigGetRequest,
        LogRetentionConfigSetRequest,
        ApplyFailurePolicyGetRequest,
        ApplyFailurePolicySetRequest,
        StorageUsageGetRequest,
        RoutingPauseGetRequest,
        RoutingPauseToggleRequest,
        AutostartGetRequest,
        AutostartToggleRequest,
        LocalDnsSuffixesGetRequest,
        LocalDnsSuffixesSetRequest,
        ServiceStabilityConfigGetRequest,
        ServiceStabilityConfigSetRequest,
        ThirdPartyComponentsListRequest,
        AutoRuleCandidatesProbeRequest,
        RefusingAnchorSetRequest,
        LocalNetworksGetRequest,
        LocalNetworksSetRequest,
        AutoRuleCandidatesListRequest,
        AutoRuleCandidatesActionRequest,
        AutoRuleDismissedListRequest,
        AutoRuleDismissedRestoreRequest,
        BlockNoticeJournalListRequest,
        BlockNoticeJournalAckRequest,
        BlockNoticeMutesListRequest,
        BlockNoticeMutesSetRequest,
        BlockNoticeMutesRemoveRequest,
        BlockNoticeMutesClearRequest,
        BlockNoticeRouteToSecondaryRequest,
        PrincipalDataPurgeRequest,
        PrincipalDataCountRequest,
        TrafficStatsGetRequest,
        TrafficStatsSetRequest,
        TrafficHistoryMergeSetRequest,
        VpnGatewayCandidatesRequest,
        RulesRecentChangesRequest,
        ConnHistoryListRequest,
        ConnHistoryClearRequest,
        ConnHistorySettingsSetRequest,
    );
});

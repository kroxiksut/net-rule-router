// The operation catalogue: what each operation is, who may call it, and
// whether it writes machine-wide state.

use super::{IpcClientProfile, IpcExecutionModel, IpcInteractionClass, IpcOperationName};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcOperationSpec {
    pub name: IpcOperationName,
    pub class: IpcInteractionClass,
    pub execution: IpcExecutionModel,
    /// Which client surfaces may invoke this operation at all. Enforced by the
    /// dispatcher next to the class check — it used to be a note nobody read,
    /// so "GUI only" on two dozen operations meant nothing and the tray could
    /// call every one of them.
    pub allowed_clients: &'static [IpcClientProfile],
    /// Declares that this operation writes state the whole service shares, so
    /// some gate must stand in front of it.
    ///
    /// It is a DECLARATION, not the gate: nothing reads this field at runtime.
    /// Two mechanisms do the actual refusing — the envelope class
    /// (`IpcOperationClass::requires_elevation`), and a by-value check inside the
    /// handler (`machine_scoped_write_allowed`, which lets an unelevated caller
    /// save an unchanged row and demands rights only for a real change).
    /// `acceptance_block16::every_privileged_operation_is_actually_gated` binds
    /// the declaration to one of the two, so a carrier with no gate fails the
    /// build instead of shipping. Do not cite this field as the gate itself.
    pub requires_service_mutation_privilege: bool,
}

const CLIENTS_GUI_ONLY: [IpcClientProfile; 1] = [IpcClientProfile::GuiInteractive];
/// Operations every surface may invoke, the console included. Kept as
/// `IpcClientProfile::ALL` rather than a hand-written list so a new profile is
/// admitted to the handshake by construction — a client that cannot negotiate
/// cannot do anything at all, and finding that out at runtime is the worst
/// place to find it out.
const CLIENTS_ALL: [IpcClientProfile; IpcClientProfile::ALL.len()] = IpcClientProfile::ALL;
const CLIENTS_GUI_AND_TRAY: [IpcClientProfile; 2] = [
    IpcClientProfile::GuiInteractive,
    IpcClientProfile::TrayLightweight,
];

const IPC_OPERATION_CATALOG: [IpcOperationSpec; 70] = [
    IpcOperationSpec {
        name: IpcOperationName::ContractNegotiate,
        class: IpcInteractionClass::HealthCheck,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_ALL,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ServiceHealthGet,
        class: IpcInteractionClass::HealthCheck,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::SnapshotInitialGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::SnapshotInterfacesGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::SnapshotDiagnosticsGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::StatusUpdatesPoll,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    // The tray lives on push events — it is how it shows service state
    // without polling. Marked GUI-only while nothing enforced the field;
    // enforcing it as written would have silenced the tray.
    IpcOperationSpec {
        name: IpcOperationName::StatusUpdatesSubscribe,
        class: IpcInteractionClass::EventUpdate,
        execution: IpcExecutionModel::AsyncAccepted,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::MutationSubmit,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::AsyncWithOperationHandle,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::OperationStatusGet,
        class: IpcInteractionClass::LongRunningOperation,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::InterfacesRefreshRequest,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::AsyncWithOperationHandle,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RollbackRequest,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::AsyncWithOperationHandle,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::ProductImpactDisableTemporary,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::AsyncWithOperationHandle,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::LogsList,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AuditList,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::SecurityAlertsList,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RulesList,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RoutePolicyUpdate,
        // User-scoped write — classed as Command (mutation) but does
        // NOT require service-mutation-privilege because the data is
        // per-SID user configuration, not service-global policy.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RouteLinkProviderSet,
        // User-scoped per-SID write — same pattern as RoutePolicyUpdate.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::DohResolversGet,
        // Read the shared resolver baseline — a plain query.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::DohResolversSet,
        // Machine-wide baseline edit → privileged (elevation), unlike the
        // per-SID route-policy writes.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::SeedFromBrowserHistory,
        // Opt-in per-user maintenance command; reads the caller's own browser
        // history and resolves their rule hosts — no elevation, runs async.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::MigrationStatusGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::MigrationMarkComplete,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    // ── Settings ops ────────────────────────────────────────
    IpcOperationSpec {
        name: IpcOperationName::RetentionSettingsGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RetentionSettingsSet,
        // Service-global policy — admin gate enforced by the
        // identity check on the named-pipe transport.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    // Operational-log + audit NDJSON retention config.
    IpcOperationSpec {
        name: IpcOperationName::LogRetentionConfigGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::LogRetentionConfigSet,
        // Service-global policy; a CHANGE is refused in the handler unless the
        // caller is elevated. Pipe identity decides WHICH process may ask, never
        // whether it may change this.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::ApplyFailurePolicyGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ApplyFailurePolicySet,
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::StorageUsageGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RoutingPauseGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RoutingPauseToggle,
        // User-scoped per-SID write — same pattern as RoutePolicyUpdate.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutostartGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutostartToggle,
        // User-scoped — writes to per-user `HKCU\…\Run` only.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ExplainGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::DiagnosticsExportArchive,
        // No domain mutation — produces a derived artifact on disk.
        // Classed as Query so it does not enter the mutation queue.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        // The console too: asking the service for the archive is the whole
        // reason `nrr-cli` speaks IPC at all — it must not assemble a second one.
        allowed_clients: &CLIENTS_ALL,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ServiceStabilityConfigGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ServiceStabilityConfigSet,
        // Service-global stability policy — admin-gated upstream, same
        // pattern as `ApplyFailurePolicySet`.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::LogsClear,
        // Maintenance command — deletes rotated operational log files.
        // Audit trail is never affected. GUI-only by design (tray has
        // no UX for it).
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::DiagnosticModeSet,
        // Enable/disable extended diagnostics (unredacted detail) for a bounded
        // in-memory session. No elevation, no mutation queue, GUI-only.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::CacheClear,
        // Maintenance command — clears the FQDN/IP resolution cache
        // (rebuildable DB). Audit / service-state DBs are never affected.
        // GUI-only by design.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::CacheEntriesList,
        // Read-only paginated view of the FQDN/IP cache. Pure query — no
        // mutation queue, no elevation. GUI-only (tray has no UX for it).
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::PresetExportGet,
        // Read-only export of the active revision's rules for one route
        // as canonical rules-file txt bytes (base64-wrapped). GUI-only:
        // tray has no file-picker UX. Pure read, no mutation queue.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::SettingsExportFull,
        // Read-only export of adapter bindings + rules paths + behavior
        // mode as YAML (docs/en/rules-file-format.md Settings Export Format). GUI-only, pure read.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RulesMergePreview,
        // Read-only two-way merge preview (file text vs the caller's active
        // revision). Pure query — no mutation queue, no elevation. GUI-only
        // (tray has no merge UX).
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ConnTraceEntriesList,
        // Read-only paginated view of recently-observed outbound connections
        // (in-memory ring). Pure query — no mutation queue, no elevation.
        // GUI-only (tray has no UX for it).
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::ThirdPartyComponentsList,
        // Attribution + live integrity of the shipped third-party binaries.
        // Pure read — hashes a file and checks its signature, changes nothing.
        // GUI-only (the tray has no About surface).
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    // ── Traffic counter ────────────────────────────────────────
    IpcOperationSpec {
        name: IpcOperationName::TrafficStatsGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::TrafficHistoryMergeSet,
        // The ledger it rewrites is machine-wide, exactly like the settings
        // below, so the answer carries the same gate. Joining two connections'
        // history is not a per-user preference.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::TrafficStatsSet,
        // Accounting is machine-wide, so a CHANGE is refused in the handler unless
        // the caller is elevated; saving the row back untouched always passes.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::TrafficStatsClear,
        // Erases what the whole machine did, so the CLASS refuses an unelevated
        // caller outright — there is no unchanged-save case for a wipe.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleCandidatesProbe,
        // The caller's own suggestions, examined on their own machine — no
        // elevation, GUI only (the tray offers no probing surface).
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::RefusingAnchorSet,
        // The caller's own observation about their own site.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    // ── Local networks under the kill-switch ───────────────────
    // Read-only, and the tray offers the local-network question.
    IpcOperationSpec {
        name: IpcOperationName::LocalNetworksGet,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::LocalNetworksSet,
        // The caller's OWN exemptions — per-SID, like every other route policy
        // a non-elevated user may change for themselves.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    // ── Companion-domain suggestions ────────────────────────
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleCandidatesList,
        // Read of an in-memory per-SID registry. GUI + TRAY: the tray is the
        // prompt surface, so tray access is what makes the feature exist.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleCandidatesAccept,
        // Writes the caller's OWN rules — user-scoped, no elevation, exactly
        // like `route.policy.update`. A user accepting a suggestion about
        // their own routing must never meet a UAC prompt.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleCandidatesDismiss,
        // Persists a per-SID refusal — same user-scoped, non-elevated shape.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleDismissedList,
        // Read of the durable per-SID refusal record. GUI + TRAY, same
        // reachability rationale as AutoRuleCandidatesList.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleDismissedRestore,
        // Undoes the caller's OWN refusal — user-scoped, no elevation, same
        // stance as AutoRuleCandidatesDismiss.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::AutoRuleCandidatesForget,
        // Drops the caller's own answer to their own suggestion — nothing
        // outside their SID moves, so no elevation.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    // ── Block-notice mutes + notice-driven routing ──────────────────
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeJournalList,
        // Read of the caller's own undelivered notices. GUI + TRAY: whichever
        // surface comes up first is the one that shows them.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeJournalAck,
        // Drops the caller's own backlog entries once shown — their data,
        // their surface, no elevation.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeMutesList,
        // Read of durable per-SID storage. GUI + TRAY: the tray is the
        // surface the notice (and its mute action) appear on.
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeMutesSet,
        // Writes the caller's OWN mute set — user-scoped, no elevation,
        // exactly like `autorules.candidates.accept`.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeMutesRemove,
        // Undoes one of the caller's own mutes — same user-scoped,
        // non-elevated shape.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeMutesClear,
        // Undoes every one of the caller's own mutes — same shape.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::BlockNoticeRouteToSecondary,
        // Writes the caller's OWN rules through the companion-domain
        // authoring path — user-scoped, no elevation, exactly like
        // `autorules.candidates.accept`.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::PrincipalDataPurge,
        // Caller's own state, no elevation. GUI-only: the tray never
        // triggers full reset.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
    IpcOperationSpec {
        name: IpcOperationName::PrincipalDataCount,
        class: IpcInteractionClass::Query,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: false,
    },
];

pub fn ipc_operation_catalog() -> &'static [IpcOperationSpec] {
    &IPC_OPERATION_CATALOG
}

/// The catalogue entry for one operation, or `None` when the slug is unknown.
pub fn ipc_operation_spec(name: IpcOperationName) -> Option<&'static IpcOperationSpec> {
    IPC_OPERATION_CATALOG.iter().find(|spec| spec.name == name)
}

use core::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcInteractionClass {
    Query,
    Command,
    LongRunningOperation,
    EventUpdate,
    HealthCheck,
}

impl IpcInteractionClass {
    pub const ALL: [Self; 5] = [
        Self::Query,
        Self::Command,
        Self::LongRunningOperation,
        Self::EventUpdate,
        Self::HealthCheck,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Command => "command",
            Self::LongRunningOperation => "long-running-operation",
            Self::EventUpdate => "event-update",
            Self::HealthCheck => "health-check",
        }
    }
}

impl fmt::Display for IpcInteractionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// What kind of client is on the other end, and therefore what it is allowed to
/// ask for.
///
/// A profile can only ever NARROW what an already-authorized caller may do — it
/// is not an authorization mechanism of its own. The real gates are the channel
/// ACL (Windows) or the socket directory's `0700` (Unix), the per-principal
/// partition, and the elevation requirement on privileged classes. What the
/// profile adds is that a client which has no business changing policy cannot do
/// so by accident or by bug.
///
/// How the profile is established differs per OS, and honestly so: Windows
/// PROVES it from the connecting executable, while `SO_PEERCRED` on Unix yields
/// uid/pid/gid but not the executable, so there the caller declares its kind at
/// handshake time and is held to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcClientProfile {
    GuiInteractive,
    TrayLightweight,
    /// The administrative console: reads and diagnoses, never changes policy.
    AdminConsole,
}

impl IpcClientProfile {
    pub const ALL: [Self; 3] = [
        Self::GuiInteractive,
        Self::TrayLightweight,
        Self::AdminConsole,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::GuiInteractive => "gui-interactive",
            Self::TrayLightweight => "tray-lightweight",
            Self::AdminConsole => "admin-console",
        }
    }

    /// Whether a caller with this profile may invoke an operation of `class`.
    ///
    /// Only the console is restricted, and only to the classes that change
    /// nothing: it exists to inspect and to collect diagnostics. Keeping the
    /// rule here — rather than as a discipline inside the console's own code —
    /// is what makes it hold when the console has a bug.
    pub const fn permits(self, class: crate::ipc_transport::IpcOperationClass) -> bool {
        use crate::ipc_transport::IpcOperationClass as C;
        match self {
            Self::GuiInteractive | Self::TrayLightweight => true,
            Self::AdminConsole => matches!(
                class,
                C::ReadSnapshot | C::DiagnosticQuery | C::DiagnosticAction
            ),
        }
    }

    /// The narrower of two profiles: what the OS proved, and what the caller
    /// declared. Declaration never widens.
    pub fn narrowed_by(self, declared: Self) -> Self {
        // Ordering is by capability, and only the console is narrower than the
        // rest — a two-value comparison rather than a general lattice, because
        // inventing an order over "gui vs tray" would be fiction.
        if declared == Self::AdminConsole || self == Self::AdminConsole {
            Self::AdminConsole
        } else {
            self
        }
    }
}

impl fmt::Display for IpcClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for IpcClientProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "gui" | "gui-interactive" => Ok(Self::GuiInteractive),
            "tray" | "tray-lightweight" => Ok(Self::TrayLightweight),
            _ => Err("unknown ipc client profile"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcExecutionModel {
    SyncReply,
    AsyncAccepted,
    AsyncWithOperationHandle,
}

impl IpcExecutionModel {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SyncReply => "sync-reply",
            Self::AsyncAccepted => "async-accepted",
            Self::AsyncWithOperationHandle => "async-with-operation-handle",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcLifecycleStage {
    BootstrapNegotiation,
    InitialSnapshotLoad,
    StatusSubscriptionOrPolling,
    MutationRequest,
    ResultAndStateRefresh,
}

impl IpcLifecycleStage {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::BootstrapNegotiation => "bootstrap-negotiation",
            Self::InitialSnapshotLoad => "initial-snapshot-load",
            Self::StatusSubscriptionOrPolling => "status-subscription-or-polling",
            Self::MutationRequest => "mutation-request",
            Self::ResultAndStateRefresh => "result-and-state-refresh",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcUpdateModel {
    Polling,
    PushEvents,
    Hybrid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcDataDeliveryKind {
    FullSnapshot,
    IncrementalUpdate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcOperationName {
    ContractNegotiate,
    ServiceHealthGet,
    SnapshotInitialGet,
    SnapshotInterfacesGet,
    SnapshotDiagnosticsGet,
    StatusUpdatesPoll,
    StatusUpdatesSubscribe,
    MutationSubmit,
    OperationStatusGet,
    InterfacesRefreshRequest,
    RollbackRequest,
    ProductImpactDisableTemporary,
    /// Paginated operational logs read.
    LogsList,
    /// Paginated audit-trail read.
    AuditList,
    /// Active security alerts read with optional state filter.
    SecurityAlertsList,
    /// Rules of the active revision, optionally filtered by route.
    RulesList,
    /// Atomically write the caller's per-SID route policy
    /// (primary/secondary bindings + behavior mode + secondary-block flag).
    /// User-scoped — does not require an elevated client; the service is
    /// the single writer and serialises updates through the mutation queue.
    RoutePolicyUpdate,
    /// Replace the caller's per-SID **link-provider app** set
    /// for one route binding role — the executables the user confirmed as
    /// establishing/maintaining that link (a VPN client for the secondary role
    /// is the common case). Narrow write on purpose: the VPN onboarding dialog
    /// must not read-modify-write the whole route policy. User-scoped, same
    /// privilege pattern as [`Self::RoutePolicyUpdate`].
    RouteLinkProviderSet,
    /// Read the shared DoH/DoT resolver baseline list (the
    /// machine-wide `doh_resolver_entries`). Query, GUI+tray readable.
    DohResolversGet,
    /// Replace the shared DoH/DoT resolver baseline list. The list
    /// is machine-wide (not per-SID), so this is a privileged write (elevation) —
    /// `requires_service_mutation_privilege`.
    DohResolversSet,
    /// OPT-IN — read the caller's browser history, resolve the
    /// rule-matching hostnames, and cache them (closes the "visited before the
    /// service started" blind spot). Runs asynchronously and returns immediately;
    /// only rule-matching hostnames are ever resolved or cached (privacy).
    SeedFromBrowserHistory,
    /// Read whether a per-SID GUI-driven migration has been
    /// recorded for the caller. Currently the only known migration_id is
    /// `legacy_preferences_v1`.
    MigrationStatusGet,
    /// Record completion of a per-SID GUI-driven migration.
    /// Idempotent: repeated calls with the same `(sid, migration_id)`
    /// preserve the original `completed_at`.
    MigrationMarkComplete,
    /// Read service-wide retention policy (singleton row in
    /// `retention_settings`).
    RetentionSettingsGet,
    /// Write service-wide retention policy. Requires
    /// administrator elevation (MutationStrong); per-statement validation
    /// rejects out-of-range values without entering the storage layer.
    RetentionSettingsSet,
    /// Read the active `ApplyFailurePolicy` (singleton row).
    ApplyFailurePolicyGet,
    /// Write the active `ApplyFailurePolicy`. Admin-only —
    /// the policy governs how the activation coordinator handles partial
    /// failures during multi-step rule application.
    ApplyFailurePolicySet,
    /// On-demand walk of `%ProgramData%\NetRuleRouter` to
    /// report on-disk footprint of the service-state DB, FQDN/IP cache,
    /// operational logs, and audit logs. Read-only and synchronous.
    StorageUsageGet,
    /// Read the caller's per-SID routing-pause record.
    /// Returns `paused = false` for absent rows.
    RoutingPauseGet,
    /// Toggle the caller's per-SID routing-pause state.
    /// User-scoped — does not require service-mutation privilege.
    RoutingPauseToggle,
    /// Read the caller's autostart configuration alongside
    /// the most recent registry observation (`HKCU\…\Run`).
    AutostartGet,
    /// Enable or disable the caller's autostart entry.
    /// User-scoped — writes to the per-user `HKCU\…\Run` hive only.
    AutostartToggle,
    /// Explain query — render the decision-engine outcome
    /// for either a historical `DecisionId` or a synthetic input
    /// sample, with optional redaction level. Read-only, no mutation
    /// queue. Pure function of (rules-snapshot, fqdn cache, input)
    /// plus an audit-log lookup to populate `diagnostic_ids`.
    ExplainGet,
    /// Build a zip archive of operational diagnostics
    /// (manifest, health snapshot, logs window, audit summary, optional
    /// troubleshooting playbooks) and write it to the service-owned
    /// per-user archives directory. Response carries the path; GUI
    /// opens it via Explorer. No mutation, no elevation.
    DiagnosticsExportArchive,
    /// Read the
    /// `ServiceStabilityConfig` from `service_stability_config` (single
    /// row). Read-only.
    ServiceStabilityConfigGet,
    /// Write the
    /// `ServiceStabilityConfig`. Service-global — admin-gated upstream
    /// (same pattern as `ApplyFailurePolicySet`).
    ServiceStabilityConfigSet,
    /// Clear rotated operational log files.
    /// Audit trail is NEVER deleted by this op (design invariant —
    /// `core/diagnostics/src/facade/service.rs:11`). Supports
    /// `dry-run` to report what would be deleted without acting.
    LogsClear,
    /// Clear the FQDN/IP resolution cache
    /// (`nrr_fqdn_ip_cache.db`) on explicit user request. Reuses the
    /// storage-level `CacheRepository::clear_cache`; the audit / service-
    /// state DBs are untouched. Supports `dry-run` to report the row
    /// counts that would be deleted without acting.
    CacheClear,
    /// Read-only, paginated view of the FQDN/IP resolution
    /// cache (`nrr_fqdn_ip_cache.db`) — hostname, resolved IP, freshness
    /// state, source, and timestamps. Query op (no mutation queue, no
    /// elevation). Detail is gated by the active `DiagnosticRedactionLevel`:
    /// in the compact tier hostnames are reduced to their registrable
    /// domain and IPs are masked. Reuses the storage-level
    /// `CacheRepository::list_resolutions`.
    CacheEntriesList,
    /// Read-only export of the active revision's rules
    /// for one route as a canonical rules-file txt blob. Payload schema:
    /// [`crate::ipc_payloads::PresetExportGetRequest`] →
    /// [`crate::ipc_payloads::PresetExportGetResponse`]. Bytes are
    /// base64-encoded so the wire framing stays text-safe. Pure read —
    /// does not touch the mutation queue.
    PresetExportGet,
    /// Read-only export of the full user settings as a
    /// YAML blob (docs/en/rules-file-format.md Settings Export Format). Captures adapter bindings + rules
    /// file paths + behavior mode. Excludes UI preferences (theme,
    /// language, accessibility, route display labels) — those are
    /// device-specific and carried over per device on migration.
    /// Payload schema: [`crate::ipc_payloads::SettingsExportFullRequest`]
    /// → [`crate::ipc_payloads::SettingsExportFullResponse`].
    SettingsExportFull,
    /// Two-way merge preview reconciling the caller's linked
    /// rules-file text with the SERVICE's active revision (per-SID
    /// read-through, like `rules.list`/`preset.export.get`). Pure read — the
    /// merge runs in the service (which owns `nrr-domain`); the request carries
    /// only the file text, the conflict policy, and optional per-conflict
    /// resolutions. Returns three buckets (file-only / service-only /
    /// conflicts) plus the merged book as canonical rules-json for the normal
    /// review + apply flow. Payload schema:
    /// [`crate::ipc_payloads::MergePreviewRequest`] →
    /// [`crate::ipc_payloads::MergePreviewResponse`]. No mutation queue, no
    /// elevation.
    RulesMergePreview,
    /// Read-only, paginated view of the most-recent
    /// observed outbound connections (process, protocol, local/remote address,
    /// egress interface primary|secondary, verdict). Query op (no mutation
    /// queue, no elevation). Detail is gated by the active
    /// `DiagnosticRedactionLevel`: in the compact tier the remote/local IPs are
    /// masked. Reads an in-memory ring the connection-observer feeds — nothing
    /// is persisted. Payload schema:
    /// [`crate::ipc_payloads::ConnTraceEntriesListRequest`] →
    /// [`crate::ipc_payloads::ConnTraceEntriesListResponse`].
    ConnTraceEntriesList,
    /// Enable/disable "extended diagnostics" mode with
    /// an optional TTL (1h/4h) or "until restart". Unredacts hostnames/IPs in
    /// the cache + connection-trace viewers for the session. Command op
    /// (in-memory session write; no elevation, no mutation queue). GUI-only.
    /// Payload: [`crate::ipc_payloads::DiagnosticModeSetRequest`] →
    /// [`crate::diagnostics_dto::DiagnosticModeStateDto`].
    DiagnosticModeSet,
    /// Read the operational-log + audit NDJSON retention
    /// config (singleton row in `log_retention_config`). Query op.
    LogRetentionConfigGet,
    /// Write the operational-log + audit NDJSON
    /// retention config. Admin-gated (MutationStrong); per-field validation
    /// rejects out-of-range values before the storage layer. Command op.
    LogRetentionConfigSet,
    /// Report the third-party binaries this build ships,
    /// with their publisher, licence and a live integrity check (path, SHA-256,
    /// Authenticode signer) of the copy actually on disk. Read-only query — no
    /// mutation queue, no elevation. The service answers because it owns the
    /// platform ports; on Linux/macOS the list is empty (nothing third-party is
    /// shipped) and the GUI hides the surface. Payload schema:
    /// [`crate::ipc_payloads::ThirdPartyComponentsListRequest`] →
    /// [`crate::ipc_payloads::ThirdPartyComponentsListResponse`].
    ThirdPartyComponentsList,
    /// Read per-adapter traffic totals for a day,
    /// session totals, and current settings; optionally a CSV export for a day
    /// range. Read-only query, GUI+tray readable.
    TrafficStatsGet,
    /// Write the service-global traffic-stats
    /// settings (master accounting toggle + loopback/virtual category toggles +
    /// retention days). Service-global — admin-gated (pipe-identity check).
    TrafficStatsSet,
    /// Reset all traffic data (daily ledger + session
    /// totals + cursors); the settings are kept. Service-global command,
    /// admin-gated.
    TrafficStatsClear,
    /// Read the caller's pending companion-domain suggestions —
    /// hosts a routed site turned out to need whose rules do not cover them.
    /// Read-only query over an in-memory per-SID registry. GUI **and tray**:
    /// the tray is the surface that offers the suggestion, so excluding it
    /// would leave the feature with no way to reach the user.
    AutoRuleCandidatesList,
    /// Accept a set of pending companion-domain suggestions,
    /// authoring them into the CALLER'S OWN rules with origin
    /// `auto:user-confirmed`. User-scoped and deliberately NOT elevated — a
    /// user editing their own rules never prompts for administrator rights in
    /// this product (same stance as [`Self::RoutePolicyUpdate`]).
    AutoRuleCandidatesAccept,
    /// Refuse a set of pending companion-domain suggestions. The
    /// refusal is persisted per-SID so the same host is not offered again after
    /// a service restart. User-scoped, non-elevated.
    AutoRuleCandidatesDismiss,
    /// Read the caller's declined companion-domain suggestions —
    /// the durable refusal record `AutoRuleCandidatesDismiss` writes, so the
    /// user can review what they turned down. Read-only, GUI **and tray**,
    /// same reachability rationale as `AutoRuleCandidatesList`.
    AutoRuleDismissedList,
    /// Undo a set of declined companion-domain suggestions,
    /// so the underlying hosts may be offered again. Lifts the suppression
    /// only — it does not resurrect the original offer, which re-earns its
    /// place the next time the observation feed sees it. User-scoped,
    /// deliberately NOT elevated, same stance as `AutoRuleCandidatesDismiss`.
    AutoRuleDismissedRestore,
    /// Erase every trace of a set of companion-domain suggestions — the pending
    /// offer, the durable refusal and the post-authoring quiet period alike.
    /// Distinct from `AutoRuleDismissedRestore`, which lifts a refusal but
    /// leaves the service's memory of the answer: this is the "ask me about it
    /// again from scratch" verb, so the host returns on its own evidence.
    /// User-scoped, non-elevated.
    AutoRuleCandidatesForget,
    /// Read the caller's active block-notice mutes ("do not show this again"
    /// for one host, one app, or block notices as a whole). Read-only query
    /// over durable per-SID storage. GUI **and tray**: the tray is where the
    /// notice — and the mute action on it — appear.
    BlockNoticeMutesList,
    /// Add or refresh one block-notice mute for the caller. An absent expiry
    /// means "until removed". User-scoped and deliberately NOT elevated — a
    /// user silencing their own notices never meets a UAC prompt, same stance
    /// as [`Self::AutoRuleCandidatesAccept`].
    BlockNoticeMutesSet,
    /// Undo one block-notice mute for the caller. Removing a mute that was
    /// never set is a no-op, not an error — the caller only ever asks for
    /// their own mute to go away, not to confirm one existed.
    BlockNoticeMutesRemove,
    /// Undo every block-notice mute for the caller in one call.
    BlockNoticeMutesClear,
    /// Turn one blocked destination into a rule that routes it over the
    /// additional link, authored into the CALLER'S OWN rules through the
    /// SAME path `autorules.candidates.accept` uses — same Free rule cap,
    /// tamper gate and revision audit a hand-typed rule gets. User-scoped,
    /// deliberately NOT elevated.
    BlockNoticeRouteToSecondary,
    /// Full-reset support: erase the CALLER's own auxiliary per-principal
    /// rows — never rules history, the shared cache, or audit. Not elevated.
    PrincipalDataPurge,
}

impl IpcOperationName {
    pub const ALL: [Self; 62] = [
        Self::ContractNegotiate,
        Self::ServiceHealthGet,
        Self::SnapshotInitialGet,
        Self::SnapshotInterfacesGet,
        Self::SnapshotDiagnosticsGet,
        Self::StatusUpdatesPoll,
        Self::StatusUpdatesSubscribe,
        Self::MutationSubmit,
        Self::OperationStatusGet,
        Self::InterfacesRefreshRequest,
        Self::RollbackRequest,
        Self::ProductImpactDisableTemporary,
        Self::LogsList,
        Self::AuditList,
        Self::SecurityAlertsList,
        Self::RulesList,
        Self::RoutePolicyUpdate,
        Self::RouteLinkProviderSet,
        Self::DohResolversGet,
        Self::DohResolversSet,
        Self::SeedFromBrowserHistory,
        Self::MigrationStatusGet,
        Self::MigrationMarkComplete,
        Self::RetentionSettingsGet,
        Self::RetentionSettingsSet,
        Self::ApplyFailurePolicyGet,
        Self::ApplyFailurePolicySet,
        Self::StorageUsageGet,
        Self::RoutingPauseGet,
        Self::RoutingPauseToggle,
        Self::AutostartGet,
        Self::AutostartToggle,
        Self::ExplainGet,
        Self::DiagnosticsExportArchive,
        Self::ServiceStabilityConfigGet,
        Self::ServiceStabilityConfigSet,
        Self::LogsClear,
        Self::CacheClear,
        Self::CacheEntriesList,
        Self::PresetExportGet,
        Self::SettingsExportFull,
        Self::RulesMergePreview,
        Self::ConnTraceEntriesList,
        Self::DiagnosticModeSet,
        Self::LogRetentionConfigGet,
        Self::LogRetentionConfigSet,
        Self::ThirdPartyComponentsList,
        Self::TrafficStatsGet,
        Self::TrafficStatsSet,
        Self::TrafficStatsClear,
        Self::AutoRuleCandidatesList,
        Self::AutoRuleCandidatesAccept,
        Self::AutoRuleCandidatesDismiss,
        Self::AutoRuleDismissedList,
        Self::AutoRuleDismissedRestore,
        Self::AutoRuleCandidatesForget,
        Self::BlockNoticeMutesList,
        Self::BlockNoticeMutesSet,
        Self::BlockNoticeMutesRemove,
        Self::BlockNoticeMutesClear,
        Self::BlockNoticeRouteToSecondary,
        Self::PrincipalDataPurge,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::ContractNegotiate => "contract.negotiate",
            Self::ServiceHealthGet => "service.health.get",
            Self::SnapshotInitialGet => "snapshot.initial.get",
            Self::SnapshotInterfacesGet => "snapshot.interfaces.get",
            Self::SnapshotDiagnosticsGet => "snapshot.diagnostics.get",
            Self::StatusUpdatesPoll => "status.updates.poll",
            Self::StatusUpdatesSubscribe => "status.updates.subscribe",
            Self::MutationSubmit => "mutation.submit",
            Self::OperationStatusGet => "operation.status.get",
            Self::InterfacesRefreshRequest => "interfaces.refresh.request",
            Self::RollbackRequest => "revision.rollback.request",
            Self::ProductImpactDisableTemporary => "product-impact.disable.temporary",
            Self::LogsList => "logs.list",
            Self::AuditList => "audit.list",
            Self::SecurityAlertsList => "security.alerts.list",
            Self::RulesList => "rules.list",
            Self::RoutePolicyUpdate => "route.policy.update",
            Self::RouteLinkProviderSet => "route.link-provider.set",
            Self::DohResolversGet => "doh.resolvers.get",
            Self::DohResolversSet => "doh.resolvers.set",
            Self::SeedFromBrowserHistory => "diagnostics.seed-from-browser-history",
            Self::MigrationStatusGet => "migration.status.get",
            Self::MigrationMarkComplete => "migration.mark.complete",
            Self::RetentionSettingsGet => "settings.retention.get",
            Self::RetentionSettingsSet => "settings.retention.set",
            Self::ApplyFailurePolicyGet => "settings.apply-failure-policy.get",
            Self::ApplyFailurePolicySet => "settings.apply-failure-policy.set",
            Self::StorageUsageGet => "storage.usage.get",
            Self::RoutingPauseGet => "routing.pause.get",
            Self::RoutingPauseToggle => "routing.pause.toggle",
            Self::AutostartGet => "autostart.get",
            Self::AutostartToggle => "autostart.toggle",
            Self::ExplainGet => "diagnostics.explain.get",
            Self::DiagnosticsExportArchive => "diagnostics.export-archive",
            Self::ServiceStabilityConfigGet => "settings.service-stability.get",
            Self::ServiceStabilityConfigSet => "settings.service-stability.set",
            Self::LogsClear => "logs.clear",
            Self::CacheClear => "cache.clear",
            Self::CacheEntriesList => "cache.entries.list",
            Self::PresetExportGet => "preset.export.get",
            Self::SettingsExportFull => "settings.export.full",
            Self::RulesMergePreview => "rules.merge-preview",
            Self::ConnTraceEntriesList => "conn-trace.entries.list",
            Self::DiagnosticModeSet => "diagnostics.mode.set",
            Self::LogRetentionConfigGet => "settings.log-retention.get",
            Self::LogRetentionConfigSet => "settings.log-retention.set",
            Self::ThirdPartyComponentsList => "third-party.components.list",
            Self::TrafficStatsGet => "traffic-stats.get",
            Self::TrafficStatsSet => "traffic-stats.set",
            Self::TrafficStatsClear => "traffic-stats.clear",
            Self::AutoRuleCandidatesList => "autorules.candidates.list",
            Self::AutoRuleCandidatesAccept => "autorules.candidates.accept",
            Self::AutoRuleCandidatesDismiss => "autorules.candidates.dismiss",
            Self::AutoRuleDismissedList => "autorules.dismissed.list",
            Self::AutoRuleDismissedRestore => "autorules.dismissed.restore",
            Self::AutoRuleCandidatesForget => "autorules.candidates.forget",
            Self::BlockNoticeMutesList => "block-notices.mutes.list",
            Self::BlockNoticeMutesSet => "block-notices.mutes.set",
            Self::BlockNoticeMutesRemove => "block-notices.mutes.remove",
            Self::BlockNoticeMutesClear => "block-notices.mutes.clear",
            Self::BlockNoticeRouteToSecondary => "block-notices.route-to-secondary",
            Self::PrincipalDataPurge => "principal-data.purge",
        }
    }

    /// Inverse of [`Self::slug`]. The
    /// launcher RPC dispatcher calls this when parsing the
    /// `operation` field from a `LauncherRpcRequest`. Returns `None`
    /// for unknown slugs; the dispatcher responds with the
    /// `unknown-operation` error code.
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|op| op.slug() == slug)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcOperationSpec {
    pub name: IpcOperationName,
    pub class: IpcInteractionClass,
    pub execution: IpcExecutionModel,
    pub allowed_clients: &'static [IpcClientProfile],
    pub requires_service_mutation_privilege: bool,
}

const CLIENTS_GUI_ONLY: [IpcClientProfile; 1] = [IpcClientProfile::GuiInteractive];
const CLIENTS_GUI_AND_TRAY: [IpcClientProfile; 2] = [
    IpcClientProfile::GuiInteractive,
    IpcClientProfile::TrayLightweight,
];

const IPC_OPERATION_CATALOG: [IpcOperationSpec; 62] = [
    IpcOperationSpec {
        name: IpcOperationName::ContractNegotiate,
        class: IpcInteractionClass::HealthCheck,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
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
    IpcOperationSpec {
        name: IpcOperationName::StatusUpdatesSubscribe,
        class: IpcInteractionClass::EventUpdate,
        execution: IpcExecutionModel::AsyncAccepted,
        allowed_clients: &CLIENTS_GUI_ONLY,
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
        // Service-global policy — admin gate enforced by the pipe identity.
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
        allowed_clients: &CLIENTS_GUI_AND_TRAY,
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
        name: IpcOperationName::TrafficStatsSet,
        // Service-global settings — admin gate enforced by the pipe identity.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
    },
    IpcOperationSpec {
        name: IpcOperationName::TrafficStatsClear,
        // Service-global reset — admin gate enforced by the pipe identity.
        class: IpcInteractionClass::Command,
        execution: IpcExecutionModel::SyncReply,
        allowed_clients: &CLIENTS_GUI_ONLY,
        requires_service_mutation_privilege: true,
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
];

const IPC_LIFECYCLE_STAGES: [IpcLifecycleStage; 5] = [
    IpcLifecycleStage::BootstrapNegotiation,
    IpcLifecycleStage::InitialSnapshotLoad,
    IpcLifecycleStage::StatusSubscriptionOrPolling,
    IpcLifecycleStage::MutationRequest,
    IpcLifecycleStage::ResultAndStateRefresh,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcContractVersionPolicy {
    pub contract_version_in_envelope: bool,
    pub explicit_negotiation_required: bool,
    pub reject_incompatible_versions: bool,
    pub compatibility_matrix_required: bool,
}

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

pub fn ipc_operation_catalog() -> &'static [IpcOperationSpec] {
    &IPC_OPERATION_CATALOG
}

pub fn ipc_lifecycle_stages() -> &'static [IpcLifecycleStage] {
    &IPC_LIFECYCLE_STAGES
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::{
        ipc_lifecycle_stages, ipc_operation_catalog, CompatibilityClientBehavior, IpcClientProfile,
        IpcExecutionModel, IpcInteractionClass, IpcOperationName, VersionCompatibilityCase,
        IPC_CONTRACT_VERSION_POLICY, IPC_CORRELATION_MODEL, IPC_ENVELOPE_PAYLOAD_BOUNDARY,
        IPC_RETRY_POLICY, IPC_STATE_UPDATE_MODEL, IPC_VERSION_COMPATIBILITY_MATRIX,
    };
    use std::collections::HashSet;

    #[test]
    fn taxonomy_contains_required_interaction_classes() {
        let classes = IpcInteractionClass::ALL;
        assert!(classes.contains(&IpcInteractionClass::Query));
        assert!(classes.contains(&IpcInteractionClass::Command));
        assert!(classes.contains(&IpcInteractionClass::LongRunningOperation));
        assert!(classes.contains(&IpcInteractionClass::EventUpdate));
        assert!(classes.contains(&IpcInteractionClass::HealthCheck));
    }

    #[test]
    fn catalog_uses_canonical_operation_names_and_non_empty_client_sets() {
        let catalog = ipc_operation_catalog();
        let mut names = HashSet::new();
        for item in catalog {
            assert!(!item.allowed_clients.is_empty());
            assert!(names.insert(item.name.slug()));
        }
        assert_eq!(catalog.len(), IpcOperationName::ALL.len());
    }

    #[test]
    fn gui_and_tray_profiles_have_different_capabilities() {
        let catalog = ipc_operation_catalog();
        let tray_subscribe = catalog.iter().find(|item| {
            item.name == IpcOperationName::StatusUpdatesSubscribe
                && item
                    .allowed_clients
                    .contains(&IpcClientProfile::TrayLightweight)
        });
        assert!(tray_subscribe.is_none());
    }

    #[test]
    fn interfaces_refresh_request_does_not_require_mutation_privilege() {
        // The external-IP probe / adapter refresh persists nothing and must
        // be callable by a non-elevated GUI or tray session without a UAC
        // prompt. Regression pin for the catalog flag driving the
        // service-side elevation gate.
        let catalog = ipc_operation_catalog();
        let spec = catalog
            .iter()
            .find(|item| item.name == IpcOperationName::InterfacesRefreshRequest)
            .expect("InterfacesRefreshRequest must be in the catalog");
        assert!(!spec.requires_service_mutation_privilege);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn auto_rule_candidate_ops_are_tray_reachable_and_never_elevated() {
        // The tray is the surface that OFFERS a companion-domain suggestion and
        // the surface the user answers it on, so every op — including
        // reviewing and undoing a past refusal — must admit the tray profile.
        // None of them may require elevation: they read and write the
        // caller's own rules, and a UAC prompt in that flow would make the
        // feature unusable for the non-admin session it exists for.
        let catalog = ipc_operation_catalog();
        for name in [
            IpcOperationName::AutoRuleCandidatesList,
            IpcOperationName::AutoRuleCandidatesAccept,
            IpcOperationName::AutoRuleCandidatesDismiss,
            IpcOperationName::AutoRuleDismissedList,
            IpcOperationName::AutoRuleDismissedRestore,
            IpcOperationName::AutoRuleCandidatesForget,
        ] {
            let spec = catalog
                .iter()
                .find(|item| item.name == name)
                .expect("auto-rule op must be in the catalog");
            assert!(
                spec.allowed_clients
                    .contains(&IpcClientProfile::TrayLightweight),
                "{} must be callable from the tray",
                name.slug()
            );
            assert!(
                !spec.requires_service_mutation_privilege,
                "{} must not require elevation",
                name.slug()
            );
            assert_eq!(IpcOperationName::from_slug(name.slug()), Some(name));
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn block_notice_ops_are_tray_reachable_and_never_elevated() {
        // The tray is the surface the block notice — and its mute / "route
        // this" actions — appear on, so every op must admit the tray profile
        // and none may require elevation: they act on the caller's own
        // notices and their own rules.
        let catalog = ipc_operation_catalog();
        for name in [
            IpcOperationName::BlockNoticeMutesList,
            IpcOperationName::BlockNoticeMutesSet,
            IpcOperationName::BlockNoticeMutesRemove,
            IpcOperationName::BlockNoticeMutesClear,
            IpcOperationName::BlockNoticeRouteToSecondary,
        ] {
            let spec = catalog
                .iter()
                .find(|item| item.name == name)
                .expect("block-notice op must be in the catalog");
            assert!(
                spec.allowed_clients
                    .contains(&IpcClientProfile::TrayLightweight),
                "{} must be callable from the tray",
                name.slug()
            );
            assert!(
                !spec.requires_service_mutation_privilege,
                "{} must not require elevation",
                name.slug()
            );
            assert_eq!(IpcOperationName::from_slug(name.slug()), Some(name));
        }
    }

    #[test]
    fn async_operations_return_operation_handle_when_required() {
        let catalog = ipc_operation_catalog();
        assert!(catalog.iter().any(|item| {
            item.name == IpcOperationName::MutationSubmit
                && item.execution == IpcExecutionModel::AsyncWithOperationHandle
        }));
    }

    #[test]
    fn lifecycle_and_version_policy_are_explicit() {
        assert_eq!(ipc_lifecycle_stages().len(), 5);
        assert!(IPC_CONTRACT_VERSION_POLICY.contract_version_in_envelope);
        assert!(IPC_CONTRACT_VERSION_POLICY.explicit_negotiation_required);
        assert!(IPC_CONTRACT_VERSION_POLICY.reject_incompatible_versions);
        assert!(IPC_STATE_UPDATE_MODEL.default_model == super::IpcUpdateModel::Hybrid);
    }

    #[test]
    fn correlation_model_requires_request_operation_source_and_contract_version() {
        assert!(IPC_CORRELATION_MODEL.request_id_required);
        assert!(IPC_CORRELATION_MODEL.operation_id_required_for_async);
        assert!(IPC_CORRELATION_MODEL.causation_source_required);
        assert!(IPC_CORRELATION_MODEL.contract_version_required);
        assert_eq!(IPC_CORRELATION_MODEL.allowed_sources.len(), 3);
    }

    #[test]
    fn idempotency_and_retry_policy_are_explicit_for_ambiguous_timeouts() {
        assert!(IPC_RETRY_POLICY.require_idempotency_key_for_mutations);
        assert!(IPC_RETRY_POLICY.timeout_outcome_is_ambiguous);
        assert!(IPC_RETRY_POLICY.require_status_read_after_ambiguous_timeout);
        assert_eq!(IPC_RETRY_POLICY.max_safe_retry_attempts, 3);
    }

    #[test]
    fn transport_envelope_boundary_is_separate_from_payload() {
        assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.payload_is_transport_agnostic);
        assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.forbid_transport_metadata_inside_payload);
        assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.envelope_fields.len() >= 6);
    }

    #[test]
    fn version_compatibility_matrix_defines_client_behavior_per_case() {
        let rules = IPC_VERSION_COMPATIBILITY_MATRIX.rules;
        assert!(rules.iter().any(|rule| {
            rule.case == VersionCompatibilityCase::OlderService
                && rule.behavior == CompatibilityClientBehavior::ProceedWithCompatibleSubset
        }));
        assert!(rules.iter().any(|rule| {
            rule.case == VersionCompatibilityCase::NewerService
                && rule.behavior == CompatibilityClientBehavior::RequireCapabilityNegotiation
        }));
        assert!(rules.iter().any(|rule| {
            rule.case == VersionCompatibilityCase::IncompatibleContract
                && rule.behavior == CompatibilityClientBehavior::HardFailAndPromptUpgrade
        }));
    }
}

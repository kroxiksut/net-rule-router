// Every IPC operation the service answers, and the slug it travels under.

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
    /// Replace the shared DoH/DoT resolver baseline list. The list is
    /// machine-wide (not per-SID), so a CHANGE needs an administrator — checked
    /// by value in the handler, because a settings page saves the whole list
    /// back whether or not the user touched it.
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
    /// Answer the one-time question "did this connection's history continue as
    /// that one's?". A refusal is an answer and is stored too, so the question
    /// is asked once either way. The question itself rides on
    /// [`Self::TrafficStatsGet`] — it belongs beside the two rows it is about.
    /// Payload schema: [`crate::ipc_payloads::TrafficHistoryMergeSetRequest`] →
    /// [`crate::ipc_payloads::TrafficHistoryMergeSetResponse`].
    TrafficHistoryMergeSet,
    /// Mark (or unmark) a routed site as answering the MAIN link with a
    /// refusal — the one fact about it no measurement here can establish.
    /// Per-SID, no elevation; answers with the full marked list.
    /// [`crate::ipc_payloads::RefusingAnchorSetRequest`] →
    /// [`crate::ipc_payloads::RefusingAnchorSetResponse`].
    RefusingAnchorSet,
    /// Read the local networks the caller may keep reachable while the
    /// kill-switch blocks everything else: what the service discovered (the
    /// main link's own subnets and the host side of hypervisor adapters) plus
    /// the caller's own decisions. Read-only query, per-SID.
    /// [`crate::ipc_payloads::LocalNetworksGetRequest`] →
    /// [`crate::ipc_payloads::LocalNetworksGetResponse`].
    LocalNetworksGet,
    /// Ask the service to check, right now, whether the addresses behind the
    /// caller's pending suggestions answer on the MAIN link. Bounded in count
    /// and time by the caller's probe limits; the verdicts arrive through the
    /// existing `AutoRuleCandidatesChanged` push, so the reply only says the
    /// pass was accepted.
    /// [`crate::ipc_payloads::AutoRuleCandidatesProbeRequest`] →
    /// [`crate::ipc_payloads::AutoRuleCandidatesProbeResponse`].
    AutoRuleCandidatesProbe,
    /// Record the caller's decisions about local networks: refuse a discovered
    /// one, or name one the service cannot discover (a hypervisor in NAT mode
    /// creates no host interface). Per-SID configuration, no elevation.
    /// [`crate::ipc_payloads::LocalNetworksSetRequest`] →
    /// [`crate::ipc_payloads::LocalNetworksSetResponse`].
    LocalNetworksSet,
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
    /// Read the notices raised for the caller while no surface was listening
    /// (no tray, no window). Read-only query over durable per-SID storage;
    /// GUI **and tray**, since either may be the first one up.
    BlockNoticeJournalList,
    /// Drop the backlog entries the caller has now been shown, up to the id
    /// given. Bounded by id rather than "clear it": a notice raised while the
    /// list travelled must survive to be shown next time.
    BlockNoticeJournalAck,
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
    /// How many OTHER OS users this service holds rules for. A count, never an
    /// identity: full reset has to ask "yours or everyone's?", and it cannot
    /// ask that without knowing whether anyone else is there.
    PrincipalDataCount,
}

impl IpcOperationName {
    pub const ALL: [Self; 70] = [
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
        Self::TrafficHistoryMergeSet,
        Self::TrafficStatsClear,
        Self::AutoRuleCandidatesProbe,
        Self::RefusingAnchorSet,
        Self::LocalNetworksGet,
        Self::LocalNetworksSet,
        Self::AutoRuleCandidatesList,
        Self::AutoRuleCandidatesAccept,
        Self::AutoRuleCandidatesDismiss,
        Self::AutoRuleDismissedList,
        Self::AutoRuleDismissedRestore,
        Self::AutoRuleCandidatesForget,
        Self::BlockNoticeJournalList,
        Self::BlockNoticeJournalAck,
        Self::BlockNoticeMutesList,
        Self::BlockNoticeMutesSet,
        Self::BlockNoticeMutesRemove,
        Self::BlockNoticeMutesClear,
        Self::BlockNoticeRouteToSecondary,
        Self::PrincipalDataPurge,
        Self::PrincipalDataCount,
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
            Self::TrafficHistoryMergeSet => "traffic-stats.history-merge.set",
            Self::TrafficStatsClear => "traffic-stats.clear",
            Self::AutoRuleCandidatesProbe => "autorules.candidates.probe",
            Self::RefusingAnchorSet => "autorules.refusing-anchor.set",
            Self::LocalNetworksGet => "settings.local-networks.get",
            Self::LocalNetworksSet => "settings.local-networks.set",
            Self::AutoRuleCandidatesList => "autorules.candidates.list",
            Self::AutoRuleCandidatesAccept => "autorules.candidates.accept",
            Self::AutoRuleCandidatesDismiss => "autorules.candidates.dismiss",
            Self::AutoRuleDismissedList => "autorules.dismissed.list",
            Self::AutoRuleDismissedRestore => "autorules.dismissed.restore",
            Self::AutoRuleCandidatesForget => "autorules.candidates.forget",
            Self::BlockNoticeJournalList => "block-notices.journal.list",
            Self::BlockNoticeJournalAck => "block-notices.journal.ack",
            Self::BlockNoticeMutesList => "block-notices.mutes.list",
            Self::BlockNoticeMutesSet => "block-notices.mutes.set",
            Self::BlockNoticeMutesRemove => "block-notices.mutes.remove",
            Self::BlockNoticeMutesClear => "block-notices.mutes.clear",
            Self::BlockNoticeRouteToSecondary => "block-notices.route-to-secondary",
            Self::PrincipalDataPurge => "principal-data.purge",
            Self::PrincipalDataCount => "principal-data.count",
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

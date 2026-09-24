//! The dependency container every production handler is built from.
//!
//! Split out of `ipc_handlers`; the code is unchanged.

use super::*;

/// Dependency container threaded into [`register_production_handlers`].
/// Adding a new field here is API-stable as long as the call site is
/// updated; the registration entrypoint signature does not change.
pub struct IpcHandlerDeps {
    pub audit_emitter: Arc<dyn IpcAuditEmitter>,
    pub health: Arc<dyn HealthReporter>,
    pub policy: Arc<dyn PolicyManager>,
    pub adapters: Arc<dyn AdaptersSnapshotProvider>,
    pub rules: Arc<dyn RulesSnapshotProvider>,
    pub diagnostics: Arc<dyn DiagnosticsFacade>,
    pub mutation_executor: Arc<dyn MutationExecutor>,
    pub mutation_tokens: Arc<MutationTokenStore>,
    pub operations: Arc<OperationStatusStore>,
    pub event_bus: Arc<EventBus>,
    /// Per-SID route policy reader/writer + GUI-driven
    /// migration ledger. Production wiring uses one impl shared across
    /// the four traits so it can hold a single
    /// `RouteBindingsRepository` connection.
    pub route_policy: Arc<dyn RoutePolicyProvider>,
    pub route_policy_writer: Arc<dyn RoutePolicyWriter>,
    pub migration_status: Arc<dyn MigrationStatusProvider>,
    pub migration_completion: Arc<dyn MigrationCompletionWriter>,
    /// Settings backends. Production wiring assembles these from the
    /// per-SID route-policy repos + RoutingPauseCoordinator +
    /// nrr-platform-windows::autostart.
    pub retention: Arc<dyn RetentionSettingsProvider>,
    pub retention_writer: Arc<dyn RetentionSettingsWriter>,
    /// Operational-log + audit NDJSON retention config.
    pub log_retention: Arc<dyn LogRetentionConfigProvider>,
    pub log_retention_writer: Arc<dyn LogRetentionConfigWriter>,
    pub apply_failure_policy: Arc<dyn ApplyFailurePolicyProvider>,
    pub apply_failure_policy_writer: Arc<dyn ApplyFailurePolicyWriter>,
    pub storage_usage: Arc<dyn StorageUsageProvider>,
    /// Traffic-stats read provider + settings writer, backed by the service
    /// `TrafficSampler`. `None` keeps `traffic-stats.get` /
    /// `traffic-stats.set` registered as `UnimplementedHandler` (degraded boot /
    /// no traffic DB). Wired via `with_traffic_stats(...)`.
    pub traffic_stats: Option<Arc<dyn TrafficStatsProvider>>,
    pub traffic_stats_writer: Option<Arc<dyn TrafficStatsWriter>>,
    /// Companion-domain discovery engine. `None` keeps the three
    /// `autorules.candidates.*` ops registered as `UnimplementedHandler`
    /// (degraded boot / no DNS-observation path). Wired via
    /// `with_auto_rules(...)`.
    pub auto_rules: Option<Arc<crate::auto_rules::AutoRulesEngine>>,
    /// Durable per-SID block-notice mute store. `None` keeps the four
    /// `block-notices.mutes.*` ops registered as `UnimplementedHandler`
    /// (degraded boot / no state DB). Wired via `with_block_notice_mutes(...)`.
    pub block_notice_mutes: Option<Arc<dyn crate::block_notice_mute_store::BlockNoticeMuteStore>>,
    /// The live ledger owner mute writes must reach — without it a mute set
    /// through IPC would only take effect after a service restart. Wired
    /// alongside `block_notice_mutes` via `with_block_notice_mutes(...)`.
    pub block_notice_center: Option<Arc<crate::block_notice_center::BlockNoticeCenter>>,
    /// Durable backlog of notices raised while no surface was subscribed.
    /// `None` keeps the two `block-notices.journal.*` ops unimplemented — a
    /// degraded boot answers "nothing pending" rather than refusing. Wired via
    /// `with_block_notice_journal(...)`.
    pub block_notice_journal:
        Option<Arc<dyn crate::block_notice_journal_store::BlockNoticeJournalStore>>,
    /// Rule author behind `block-notices.route-to-secondary` — the SAME
    /// authoring path companion-domain suggestions use, so a notice-driven
    /// rule passes the same Free rule cap, tamper gate and revision audit a
    /// hand-typed rule does. `None` keeps the op registered as
    /// `UnimplementedHandler`. Wired via `with_block_notice_author(...)`.
    pub block_notice_author: Option<Arc<dyn crate::auto_rules::AutoRuleAuthor>>,
    pub routing_pause: Arc<dyn RoutingPauseProvider>,
    pub routing_pause_writer: Arc<dyn RoutingPauseWriter>,
    pub autostart: Arc<dyn AutostartProvider>,
    pub autostart_writer: Arc<dyn AutostartWriter>,
    /// Security alerts repository. `None` ⇒ the alerts
    /// list handler returns an empty list and ack/resolve mutations
    /// fail with `alerts-store-unavailable`. Wired in `runtime_deps.rs`
    /// once the state DB connection is available.
    pub alerts_repo: Option<Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository>>,
    /// Answers "does anyone but this caller hold revisions?", so clearing a
    /// blocking integrity alert can ask for elevation exactly when it would
    /// adopt somebody else's rows. `None` reads as "nobody else".
    pub other_principals_hold_revisions:
        Option<crate::ipc_handlers::mutation_submit::OtherPrincipalsHoldRevisionsFn>,
    /// Service stability config provider/writer pair.
    /// `None` keeps the register loop registering the fallback stub
    /// for both ops.
    pub service_stability_provider: Option<Arc<dyn ServiceStabilityConfigProvider>>,
    pub service_stability_writer: Option<Arc<dyn ServiceStabilityConfigWriter>>,
    /// Per-user archives directory used by
    /// `DiagnosticsExportArchiveHandler`. `None` falls back to the
    /// fallback stub.
    pub archives_dir: Option<std::path::PathBuf>,
    /// App version baked into archive manifests. `None`
    /// → fallback stub for the export handler.
    pub app_version: Option<String>,
    /// Host system information (OS/CPU/RAM) for the
    /// diagnostic archive's `system_info.json`. Collected by the platform
    /// crate at the composition root (`nrr-service-runtime` is OS-neutral).
    /// `None` writes a minimal system-info section noting it was unavailable.
    pub system_info: Option<nrr_shared::system_info::SystemInfo>,
    /// `nrr_service_state.db` schema version, read once at the composition
    /// root and threaded into `DiagnosticsExportArchiveHandler` for
    /// `health.json`'s `state_schema_version` field. `None` when the state DB
    /// connection was unavailable at startup (degraded boot). Wired via
    /// `with_state_schema_version(...)`.
    pub state_schema_version: Option<u32>,
    /// Grants the requesting principal read on a finished diagnostics archive.
    /// `None` keeps the archive where only the service and administrators can
    /// read it — correct for a build with no OS backend, wrong for a user who
    /// just asked for one. Wired via `with_file_handoff(...)`.
    pub file_handoff: Option<Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>>,
    /// Per-SID Fail-Closed probe. `None` keeps the
    /// snapshot handler without the enforcement banner (banner stays hidden).
    /// Wired through `with_fail_closed_probe(...)`.
    pub fail_closed_probe: Option<Arc<dyn crate::ipc_handlers::providers::FailClosedStateProbe>>,
    /// Preset export source. `None` keeps
    /// `PresetExportGet` registered as `UnimplementedHandler`. Wired
    /// via `with_preset_export_source(...)`.
    pub preset_export_source:
        Option<Arc<dyn crate::production_preset_exporter::PresetExportSource>>,
    /// Settings export source. `None` keeps
    /// `SettingsExportFull` registered as `UnimplementedHandler`.
    /// Wired via `with_settings_export_source(...)`. The clock is
    /// passed alongside so the handler can stamp `exported_at` in ISO
    /// 8601 UTC.
    pub settings_export_source:
        Option<Arc<dyn crate::production_settings_exporter::SettingsExportSource>>,
    pub settings_export_clock: Option<Arc<dyn crate::activation_coordinator::Clock>>,
    /// Post-write recompile hook fired by
    /// `RoutePolicyUpdateHandler` so a routing-active caller's WFP filters
    /// recompile mid-session. `None` ⇒ the update is persist-only (applies
    /// on the next tray reconnect). Wired via `with_route_policy_apply_trigger`.
    pub route_policy_apply_trigger:
        Option<Arc<dyn crate::ipc_handlers::providers::RoutePolicyApplyTrigger>>,
    /// Per-SID link-provider app writer behind
    /// `route.link-provider.set`. `None` keeps the op registered as
    /// `UnimplementedHandler` (degraded boot without a state DB). Wired via
    /// `with_link_provider_writer(...)`.
    pub link_provider_writer: Option<Arc<dyn crate::ipc_handlers::providers::LinkProviderWriter>>,
    /// Full-reset auxiliary-state purge behind `principal-data.purge`.
    /// `None` falls back to `UnimplementedHandler`. Wired via `with_principal_data_purger(...)`.
    pub principal_data_purger: Option<Arc<dyn PrincipalDataPurger>>,
    /// Shared DoH resolver baseline store behind
    /// `doh.resolvers.get` / `doh.resolvers.set`. `None` keeps both ops as
    /// `UnimplementedHandler` (degraded boot without a state DB). Wired via
    /// `with_doh_resolver_store(...)`.
    pub doh_resolver_store:
        Option<Arc<dyn crate::ipc_handlers::doh_resolvers::DohResolverListStore>>,
    /// Opt-in browser-history seeder behind
    /// `diagnostics.seed-from-browser-history`. `None` keeps the op as
    /// `UnimplementedHandler`. Wired via `with_browser_history_seeder(...)`.
    pub browser_history_seeder: Option<Arc<crate::browser_history_seeder::BrowserHistorySeeder>>,
    /// FQDN/IP resolution cache repository. `None` keeps
    /// `CacheClear` registered as `UnimplementedHandler` (cache DB absent
    /// or corrupt). Wired via `with_cache_repository(...)`.
    pub cache_repository:
        Option<Arc<std::sync::Mutex<dyn nrr_storage::repository::CacheRepository + Send>>>,
    /// OS resolver-cache flush port for the `cache.clear` handler's
    /// "clear OS DNS cache" button. `None` keeps that branch reporting
    /// `os_cache_flushed = Some(false)`. Wired via `with_dns_cache_control(...)`.
    pub dns_cache_control: Option<Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>>,
    /// The caller's local-network exemptions (discovered + decided). `None`
    /// keeps both `settings.local-networks.*` operations unimplemented, which
    /// is the degraded-boot behaviour for every other stateful setting here.
    pub local_networks: Option<Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>>,
    /// Runs the "does it answer on the main link?" pass for the caller's
    /// pending suggestions. `None` keeps `autorules.candidates.probe`
    /// unimplemented, exactly like every other unwired capability here.
    pub auto_rule_probe: Option<Arc<dyn crate::ipc_handlers::providers::AutoRuleProbeRunner>>,
    /// Records the sites the caller says refuse main-link addresses. `None`
    /// keeps `autorules.refusing-anchor.set` unimplemented.
    pub refusing_anchors: Option<Arc<dyn crate::ipc_handlers::providers::RefusingAnchorsWriter>>,
    /// Merge-preview source. `None` keeps `RulesMergePreview`
    /// registered as `UnimplementedHandler` (degraded boot / no state DB).
    /// Wired via `with_merge_preview_source(...)`.
    pub merge_preview_source: Option<Arc<dyn crate::production_merge_preview::MergePreviewSource>>,
    /// Connection-trace ring. `None` keeps
    /// `ConnTraceEntriesList` registered as `UnimplementedHandler` (the
    /// connection observer's GUI stream is off). Wired via
    /// `with_conn_trace_ring(...)`.
    pub conn_trace_ring: Option<Arc<crate::conn_observation_consumer::ConnectionTraceRing>>,
    /// Inspector for the shipped third-party binaries.
    /// `None` degrades to the no-op inspector, so `third-party.components.list`
    /// still answers — with the attribution-only assets and no binaries, which
    /// is exactly the correct answer on Linux/macOS. Wired via
    /// `with_third_party_integrity(...)`.
    pub third_party_integrity:
        Option<Arc<dyn nrr_platform_api::third_party::ThirdPartyIntegrityPort>>,
    /// Inputs for the conn-trace `expected_route` stamp (active
    /// user's rules + FQDN cache + routing-active-SID resolver). Optional;
    /// absent (degraded boot / tests) → rows carry an empty `expected_route`.
    /// Wired via `with_conn_trace_expectation(...)`.
    pub conn_trace_expectation: Option<diagnostics_handlers::ConnTraceExpectation>,
    /// Read-only view of the live hostname → fake-address (fake-IP) map
    /// (from the shared `FakeIpAssembly`), so the cache viewer and synthetic
    /// explain probe can surface the virtual address a host resolves to.
    /// `None` (default) leaves the field empty (fake-IP not wired / off).
    /// Wired via `with_fake_ip_bindings(...)`.
    pub fake_ip_bindings: Option<crate::fake_ip::FakeIpBindingView>,
    /// Shared "unenforced application rules" status the
    /// per-SID orchestrator publishes into and `SnapshotInitial` reads for a
    /// GUI banner. Defaults to an empty status (no banner); production wires
    /// the same clone the orchestrator writes via `with_app_enforcement_status`.
    pub app_enforcement: crate::app_enforcement_status::AppEnforcementStatus,
    /// Shared smart-kill-switch shared-IP exclusion
    /// count the orchestrator publishes and `SnapshotInitial` reads for the
    /// GUI warning. Defaults to zero; production wires the orchestrator's
    /// clone via `with_shared_ip_exemption_status`.
    pub shared_ip_exemptions: crate::app_enforcement_status::SharedIpExemptionStatus,
    /// Shared block-all posture flag the orchestrator
    /// publishes and `SnapshotInitial` reads for the "leak protection is
    /// blocking unknown traffic" banner. Defaults to disarmed; production
    /// wires the orchestrator's clone via `with_block_all_posture_status`.
    pub block_all_posture: crate::app_enforcement_status::BlockAllPostureStatus,
    /// Live fake-IP datapath probe over the `FakeIpController`, so
    /// `service.health.get` / `snapshot.initial.get` can surface a
    /// "toggle ON but datapath dead" outage. `None` (default) omits the
    /// wire field. Wired via `with_fake_ip_datapath_probe(...)`.
    pub fake_ip_datapath_probe: Option<FakeIpDatapathProbe>,
}

impl IpcHandlerDeps {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        audit_emitter: Arc<dyn IpcAuditEmitter>,
        health: Arc<dyn HealthReporter>,
        policy: Arc<dyn PolicyManager>,
        adapters: Arc<dyn AdaptersSnapshotProvider>,
        rules: Arc<dyn RulesSnapshotProvider>,
        diagnostics: Arc<dyn DiagnosticsFacade>,
        mutation_executor: Arc<dyn MutationExecutor>,
        mutation_tokens: Arc<MutationTokenStore>,
        operations: Arc<OperationStatusStore>,
        event_bus: Arc<EventBus>,
        route_policy: Arc<dyn RoutePolicyProvider>,
        route_policy_writer: Arc<dyn RoutePolicyWriter>,
        migration_status: Arc<dyn MigrationStatusProvider>,
        migration_completion: Arc<dyn MigrationCompletionWriter>,
        retention: Arc<dyn RetentionSettingsProvider>,
        retention_writer: Arc<dyn RetentionSettingsWriter>,
        log_retention: Arc<dyn LogRetentionConfigProvider>,
        log_retention_writer: Arc<dyn LogRetentionConfigWriter>,
        apply_failure_policy: Arc<dyn ApplyFailurePolicyProvider>,
        apply_failure_policy_writer: Arc<dyn ApplyFailurePolicyWriter>,
        storage_usage: Arc<dyn StorageUsageProvider>,
        routing_pause: Arc<dyn RoutingPauseProvider>,
        routing_pause_writer: Arc<dyn RoutingPauseWriter>,
        autostart: Arc<dyn AutostartProvider>,
        autostart_writer: Arc<dyn AutostartWriter>,
    ) -> Self {
        Self {
            audit_emitter,
            health,
            policy,
            adapters,
            rules,
            diagnostics,
            mutation_executor,
            mutation_tokens,
            operations,
            event_bus,
            route_policy,
            route_policy_writer,
            migration_status,
            migration_completion,
            retention,
            retention_writer,
            log_retention,
            log_retention_writer,
            apply_failure_policy,
            apply_failure_policy_writer,
            storage_usage,
            routing_pause,
            routing_pause_writer,
            autostart,
            autostart_writer,
            alerts_repo: None,
            other_principals_hold_revisions: None,
            service_stability_provider: None,
            service_stability_writer: None,
            archives_dir: None,
            app_version: None,
            system_info: None,
            state_schema_version: None,
            file_handoff: None,
            fail_closed_probe: None,
            preset_export_source: None,
            settings_export_source: None,
            settings_export_clock: None,
            route_policy_apply_trigger: None,
            link_provider_writer: None,
            principal_data_purger: None,
            doh_resolver_store: None,
            browser_history_seeder: None,
            cache_repository: None,
            dns_cache_control: None,
            local_networks: None,
            auto_rule_probe: None,
            refusing_anchors: None,
            merge_preview_source: None,
            traffic_stats: None,
            traffic_stats_writer: None,
            auto_rules: None,
            block_notice_mutes: None,
            block_notice_center: None,
            block_notice_journal: None,
            block_notice_author: None,
            conn_trace_ring: None,
            third_party_integrity: None,
            conn_trace_expectation: None,
            // No fake-IP view by default (field stays empty). Production
            // shares the assembly's view via `with_fake_ip_bindings`.
            fake_ip_bindings: None,
            // Empty status by default (no banner). Production
            // shares the orchestrator's clone via `with_app_enforcement_status`.
            app_enforcement: crate::app_enforcement_status::AppEnforcementStatus::new(),
            // Zero by default (no warning). Production shares the
            // orchestrator's clone via `with_shared_ip_exemption_status`.
            shared_ip_exemptions: crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            // Disarmed by default (no banner). Production shares the
            // orchestrator's clone via `with_block_all_posture_status`.
            block_all_posture: crate::app_enforcement_status::BlockAllPostureStatus::new(),
            // No probe by default (degraded boot / tests) — the health
            // payload omits the field. Production wires the controller's
            // probe via `with_fake_ip_datapath_probe`.
            fake_ip_datapath_probe: None,
        }
    }

    /// Attach the live fake-IP datapath probe (a cheap closure over
    /// `FakeIpController::datapath_status`) so health payloads report
    /// the datapath state alongside the service state.
    pub fn with_fake_ip_datapath_probe(mut self, probe: FakeIpDatapathProbe) -> Self {
        self.fake_ip_datapath_probe = Some(probe);
        self
    }

    /// Attach the reader for [`Self::other_principals_hold_revisions`].
    #[must_use]
    pub fn with_other_principals_reader(
        mut self,
        reads: crate::ipc_handlers::mutation_submit::OtherPrincipalsHoldRevisionsFn,
    ) -> Self {
        self.other_principals_hold_revisions = Some(reads);
        self
    }

    /// Attach the security alerts repository so the list
    /// handler honours `state_filter` and the mutation executor can
    /// route ack/resolve operations through it.
    pub fn with_alerts_repo(
        mut self,
        repo: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository>,
    ) -> Self {
        self.alerts_repo = Some(repo);
        self
    }

    /// Attach the service stability config
    /// provider/writer pair.
    pub fn with_service_stability(
        mut self,
        provider: Arc<dyn ServiceStabilityConfigProvider>,
        writer: Arc<dyn ServiceStabilityConfigWriter>,
    ) -> Self {
        self.service_stability_provider = Some(provider);
        self.service_stability_writer = Some(writer);
        self
    }

    /// Attach the companion-domain discovery engine so the three
    /// `autorules.candidates.*` ops resolve to real handlers. The SAME `Arc` the
    /// DNS-observation consumer feeds and the proposal tick drives.
    #[must_use]
    pub fn with_auto_rules(mut self, engine: Arc<crate::auto_rules::AutoRulesEngine>) -> Self {
        self.auto_rules = Some(engine);
        self
    }

    /// Attach the durable mute store plus the live [`BlockNoticeCenter`]
    /// mute writes must reach, so the four `block-notices.mutes.*` ops
    /// resolve to real handlers and a mute takes hold on the next block
    /// rather than after a restart.
    #[must_use]
    pub fn with_block_notice_mutes(
        mut self,
        store: Arc<dyn crate::block_notice_mute_store::BlockNoticeMuteStore>,
        center: Arc<crate::block_notice_center::BlockNoticeCenter>,
    ) -> Self {
        self.block_notice_mutes = Some(store);
        self.block_notice_center = Some(center);
        self
    }

    /// Attach the backlog the `block-notices.journal.*` ops serve. The same
    /// `Arc` the [`BlockNoticeCenter`] writes to, so what a surface reads is
    /// what the drop path recorded.
    #[must_use]
    pub fn with_block_notice_journal(
        mut self,
        store: Arc<dyn crate::block_notice_journal_store::BlockNoticeJournalStore>,
    ) -> Self {
        self.block_notice_journal = Some(store);
        self
    }

    /// Attach the rule author behind `block-notices.route-to-secondary` —
    /// typically the SAME `Arc` the companion-domain engine's `accept` path
    /// uses, so a notice-driven rule and an accepted suggestion go through
    /// identical policy.
    #[must_use]
    pub fn with_block_notice_author(
        mut self,
        author: Arc<dyn crate::auto_rules::AutoRuleAuthor>,
    ) -> Self {
        self.block_notice_author = Some(author);
        self
    }

    /// Attach the traffic-stats read provider +
    /// settings writer (both backed by the service `TrafficSampler`).
    pub fn with_traffic_stats(
        mut self,
        provider: Arc<dyn TrafficStatsProvider>,
        writer: Arc<dyn TrafficStatsWriter>,
    ) -> Self {
        self.traffic_stats = Some(provider);
        self.traffic_stats_writer = Some(writer);
        self
    }

    /// Attach the per-user archives directory and the
    /// app version string for the diagnostics export handler.
    pub fn with_archives_config(
        mut self,
        archives_dir: std::path::PathBuf,
        app_version: String,
    ) -> Self {
        self.archives_dir = Some(archives_dir);
        self.app_version = Some(app_version);
        self
    }

    /// Attach the host system information for the diagnostic
    /// archive's `system_info.json`. Collected by the platform crate at the
    /// composition root (this crate is OS-neutral).
    #[must_use]
    pub fn with_system_info(mut self, info: nrr_shared::system_info::SystemInfo) -> Self {
        self.system_info = Some(info);
        self
    }

    /// Attach the
    /// `nrr_service_state.db` schema version for the diagnostic archive's
    /// `health.json` (`state_schema_version` field). Read once at the
    /// composition root via `nrr_storage::migration::read_schema_version`.
    /// Takes `Option<u32>` directly (rather than requiring an `if let` at
    /// the call site) since the source read is itself best-effort — `None`
    /// when the state DB connection was unavailable at startup.
    pub fn with_state_schema_version(mut self, version: Option<u32>) -> Self {
        self.state_schema_version = version;
        self
    }

    /// Attach the per-OS file handoff so a finished diagnostics archive
    /// reaches the user who asked for it. Without it the archive stays
    /// readable only by the service and administrators.
    pub fn with_file_handoff(
        mut self,
        handoff: Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
    ) -> Self {
        self.file_handoff = Some(handoff);
        self
    }

    /// Attach the post-write recompile hook
    /// so `route.policy.update` recompiles a routing-active caller's WFP
    /// filters immediately.
    pub fn with_route_policy_apply_trigger(
        mut self,
        trigger: Arc<dyn crate::ipc_handlers::providers::RoutePolicyApplyTrigger>,
    ) -> Self {
        self.route_policy_apply_trigger = Some(trigger);
        self
    }

    /// Attach the per-SID link-provider app writer so
    /// `route.link-provider.set` resolves to the real handler.
    pub fn with_link_provider_writer(
        mut self,
        writer: Arc<dyn crate::ipc_handlers::providers::LinkProviderWriter>,
    ) -> Self {
        self.link_provider_writer = Some(writer);
        self
    }

    /// Attach the full-reset auxiliary-state purger so
    /// `principal-data.purge` resolves to the real handler.
    pub fn with_principal_data_purger(mut self, purger: Arc<dyn PrincipalDataPurger>) -> Self {
        self.principal_data_purger = Some(purger);
        self
    }

    /// Attach the shared DoH resolver baseline store so
    /// `doh.resolvers.get` / `doh.resolvers.set` resolve to real handlers.
    pub fn with_doh_resolver_store(
        mut self,
        store: Arc<dyn crate::ipc_handlers::doh_resolvers::DohResolverListStore>,
    ) -> Self {
        self.doh_resolver_store = Some(store);
        self
    }

    /// Attach the opt-in browser-history seeder so
    /// `diagnostics.seed-from-browser-history` resolves to the real handler.
    pub fn with_browser_history_seeder(
        mut self,
        seeder: Arc<crate::browser_history_seeder::BrowserHistorySeeder>,
    ) -> Self {
        self.browser_history_seeder = Some(seeder);
        self
    }

    /// Attach the per-SID Fail-Closed probe so the
    /// snapshot.interfaces.get handler can populate the
    /// `SecondaryRouteStateDto` for the GUI banner.
    pub fn with_fail_closed_probe(
        mut self,
        probe: Arc<dyn crate::ipc_handlers::providers::FailClosedStateProbe>,
    ) -> Self {
        self.fail_closed_probe = Some(probe);
        self
    }

    /// Attach the preset export source so the
    /// `preset.export.get` handler can read the active revision and
    /// emit canonical rules-file txt bytes.
    pub fn with_preset_export_source(
        mut self,
        source: Arc<dyn crate::production_preset_exporter::PresetExportSource>,
    ) -> Self {
        self.preset_export_source = Some(source);
        self
    }

    /// Attach the settings export source + clock so
    /// the `settings.export.full` handler can emit docs/en/rules-file-format.md Settings Export Format settings-export
    /// YAML stamped with the current UTC moment.
    pub fn with_settings_export_source(
        mut self,
        source: Arc<dyn crate::production_settings_exporter::SettingsExportSource>,
        clock: Arc<dyn crate::activation_coordinator::Clock>,
    ) -> Self {
        self.settings_export_source = Some(source);
        self.settings_export_clock = Some(clock);
        self
    }

    /// Attach the FQDN/IP resolution cache repository so
    /// the `cache.clear` handler can clear it on explicit user request.
    pub fn with_cache_repository(
        mut self,
        cache: Arc<std::sync::Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
    ) -> Self {
        self.cache_repository = Some(cache);
        self
    }

    /// Attach the OS resolver-cache flush port so the `cache.clear`
    /// handler's "clear OS DNS cache" button flushes the real OS cache.
    pub fn with_dns_cache_control(
        mut self,
        port: Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>,
    ) -> Self {
        self.dns_cache_control = Some(port);
        self
    }

    /// Attach the refusing-site writer (see [`Self::refusing_anchors`]).
    pub fn with_refusing_anchors(
        mut self,
        writer: Arc<dyn crate::ipc_handlers::providers::RefusingAnchorsWriter>,
    ) -> Self {
        self.refusing_anchors = Some(writer);
        self
    }

    /// Attach the main-link probe runner (see [`Self::auto_rule_probe`]).
    pub fn with_auto_rule_probe(
        mut self,
        runner: Arc<dyn crate::ipc_handlers::providers::AutoRuleProbeRunner>,
    ) -> Self {
        self.auto_rule_probe = Some(runner);
        self
    }

    /// Attach the caller's local-network exemptions so the settings screen can
    /// list what the service discovered and record what the user decided.
    pub fn with_local_networks(
        mut self,
        provider: Arc<dyn crate::ipc_handlers::providers::LocalNetworksProvider>,
    ) -> Self {
        self.local_networks = Some(provider);
        self
    }

    /// Attach the merge-preview source so the
    /// `rules.merge-preview` handler can reconcile the caller's linked
    /// rules-file text with their active revision.
    pub fn with_merge_preview_source(
        mut self,
        source: Arc<dyn crate::production_merge_preview::MergePreviewSource>,
    ) -> Self {
        self.merge_preview_source = Some(source);
        self
    }

    /// Attach the connection-trace ring so the
    /// `conn-trace.entries.list` handler can serve recent observed connections.
    pub fn with_conn_trace_ring(
        mut self,
        ring: Arc<crate::conn_observation_consumer::ConnectionTraceRing>,
    ) -> Self {
        self.conn_trace_ring = Some(ring);
        self
    }

    /// Attach the third-party binary inspector so
    /// `third-party.components.list` can report the driver's real path, hash
    /// and signature instead of only its licence text.
    pub fn with_third_party_integrity(
        mut self,
        integrity: Arc<dyn nrr_platform_api::third_party::ThirdPartyIntegrityPort>,
    ) -> Self {
        self.third_party_integrity = Some(integrity);
        self
    }

    /// Attach the expected-route inputs so conn-trace rows carry
    /// where routing policy EXPECTS each remote to egress (leak flagging).
    pub fn with_conn_trace_expectation(
        mut self,
        rules: Arc<dyn crate::per_sid_orchestrator::RulesProvider>,
        fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        active_sid: crate::dns_observation_consumer::ActiveSidFn,
    ) -> Self {
        self.conn_trace_expectation = Some((rules, fqdn, active_sid));
        self
    }

    /// Attach the read-only hostname → fake-address (fake-IP) view so
    /// the cache viewer and synthetic explain probe surface the virtual
    /// address a host resolves to.
    pub fn with_fake_ip_bindings(mut self, view: crate::fake_ip::FakeIpBindingView) -> Self {
        self.fake_ip_bindings = Some(view);
        self
    }

    /// Share the `AppEnforcementStatus` the per-SID
    /// orchestrator publishes unresolved app rules into, so the
    /// `SnapshotInitial` handler can surface them to the GUI as a banner.
    pub fn with_app_enforcement_status(
        mut self,
        status: crate::app_enforcement_status::AppEnforcementStatus,
    ) -> Self {
        self.app_enforcement = status;
        self
    }

    /// Share the `SharedIpExemptionStatus` the
    /// per-SID orchestrator publishes its smart-kill-switch exclusion count
    /// into, so `SnapshotInitial` can surface the GUI warning.
    pub fn with_shared_ip_exemption_status(
        mut self,
        status: crate::app_enforcement_status::SharedIpExemptionStatus,
    ) -> Self {
        self.shared_ip_exemptions = status;
        self
    }

    /// Share the `BlockAllPostureStatus` the per-SID
    /// orchestrator publishes its block-all transitions into, so
    /// `SnapshotInitial` can surface the GUI banner.
    pub fn with_block_all_posture_status(
        mut self,
        status: crate::app_enforcement_status::BlockAllPostureStatus,
    ) -> Self {
        self.block_all_posture = status;
        self
    }
}

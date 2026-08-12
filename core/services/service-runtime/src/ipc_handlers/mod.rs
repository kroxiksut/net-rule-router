//! IPC operation handlers for the running service.
//!
//! Every operation in [`IpcOperationName::ALL`] has a registered handler:
//! operations whose real implementation is not yet wired resolve to
//! [`UnimplementedHandler`], which surfaces `RecoveryRequired` to the
//! client. The pseudo "logs.list" / "audit.list" / "security.alerts.list" /
//! "rules.list" operations are not in `IpcOperationName::ALL` — they are
//! exposed as in-process handlers callable directly during composition.
//!
//! ## Module layout
//!
//! | Submodule                  | Responsibility                                   |
//! |----------------------------|--------------------------------------------------|
//! | [`payloads`]               | Wire-format request/response types (serde)       |
//! | [`providers`]              | Trait abstractions for service-internal sources  |
//! | [`stub`]                   | `UnimplementedHandler` placeholder               |
//! | `contract_negotiate`       | `ContractNegotiate` handshake                    |
//! | `service_health`           | `ServiceHealthGet`                               |
//! | `snapshot_interfaces`      | `SnapshotInterfacesGet`                          |
//! | `snapshot_diagnostics`     | `SnapshotDiagnosticsGet`                         |
//! | `snapshot_initial`         | `SnapshotInitialGet` — bundles the above three   |
//! | `logs_list` / `audit_list` | Paginated log/audit reads (used by composer)     |
//! | `security_alerts`          | Active security alerts read (used by composer)   |
//! | `rules_list`               | Rules table read (used by composer)              |

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{IpcAuditEmitter, IpcHandlerRegistry};
use crate::managers::{HealthReporter, PolicyManager};

pub mod payloads;
pub mod providers;
pub mod stub;

pub mod event_bus;
pub mod mutation_token_store;
pub mod operation_status_store;

pub mod audit_list;
pub mod auto_rules_handlers;
pub mod block_notice_handlers;
pub mod contract_negotiate;
pub mod diagnostics_handlers;
pub mod doh_resolvers;
pub mod interfaces_refresh;
pub mod logs_list;
pub mod merge_preview;
pub mod migration_mark_complete;
pub mod migration_status_get;
pub mod mutation_submit;
pub mod operation_status;
pub mod preset_handlers;
pub mod principal_data_handlers;
pub mod product_impact_disable;
pub mod rollback;
pub mod route_link_provider_set;
pub mod route_policy_update;
pub mod rules_list;
pub mod security_alerts;
pub mod seed_browser_history;
pub mod service_health;
pub mod service_stability_handlers;
pub mod settings_handlers;
pub mod snapshot_diagnostics;
pub mod snapshot_initial;
pub mod snapshot_interfaces;
pub mod status_updates_poll;
pub mod status_updates_subscribe;
pub mod third_party_handlers;

#[cfg(test)]
pub(crate) mod test_fakes;

pub use audit_list::AuditListHandler;
pub use auto_rules_handlers::{
    AutoRuleCandidatesAcceptHandler, AutoRuleCandidatesDismissHandler,
    AutoRuleCandidatesForgetHandler, AutoRuleCandidatesListHandler, AutoRuleDismissedListHandler,
    AutoRuleDismissedRestoreHandler,
};
pub use block_notice_handlers::{
    BlockNoticeMutesClearHandler, BlockNoticeMutesListHandler, BlockNoticeMutesRemoveHandler,
    BlockNoticeMutesSetHandler, BlockNoticeRouteToSecondaryHandler,
};
pub use contract_negotiate::{
    service_binary_version, set_service_binary_version, ContractNegotiateHandler,
    MIN_SUPPORTED_CLIENT_VERSION,
};
pub use diagnostics_handlers::{
    CacheClearHandler, CacheEntriesListHandler, DiagnosticsExportArchiveHandler, ExplainGetHandler,
    LogsClearHandler,
};
pub use doh_resolvers::{DohResolverListStore, DohResolversGetHandler, DohResolversSetHandler};
pub use event_bus::{
    EventBus, EventEntry, SubscribeOutcome, SubscriberState, EVENT_BUFFER_CAPACITY,
};
pub use interfaces_refresh::InterfacesRefreshHandler;
pub use logs_list::LogsListHandler;
pub use merge_preview::RulesMergePreviewHandler;
pub use migration_mark_complete::MigrationMarkCompleteHandler;
pub use migration_status_get::MigrationStatusGetHandler;
pub use mutation_submit::MutationSubmitHandler;
pub use mutation_token_store::{
    ConsumeError, MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
pub use operation_status::OperationStatusHandler;
pub use operation_status_store::{
    OperationError, OperationRecord, OperationState, OperationStatusStore,
    DEFAULT_OPERATION_RETENTION,
};
pub use principal_data_handlers::PrincipalDataPurgeHandler;
pub use product_impact_disable::ProductImpactDisableTemporaryHandler;
pub use providers::{
    review_risk_level, AdaptersSnapshotProvider, ApplyFailurePolicyProvider,
    ApplyFailurePolicyWriter, AutostartProvider, AutostartWriter, LogRetentionConfigProvider,
    LogRetentionConfigWriter, MigrationCompletionRecord, MigrationCompletionWriter,
    MigrationStatusProvider, MutationExecutor, MutationOutcome, PrincipalDataPurger,
    RetentionSettingsProvider, RetentionSettingsWriter, RoutePolicyProvider, RoutePolicyWriteError,
    RoutePolicyWriter, RoutingPauseProvider, RoutingPauseWriter, RulesSnapshotProvider,
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter, SettingsWriteError,
    StorageUsageProvider, TrafficStatsProvider, TrafficStatsWriter,
};
pub use rollback::RollbackHandler;
pub use route_link_provider_set::RouteLinkProviderSetHandler;
pub use route_policy_update::RoutePolicyUpdateHandler;
pub use rules_list::RulesListHandler;
pub use security_alerts::SecurityAlertsHandler;
pub use seed_browser_history::SeedFromBrowserHistoryHandler;
pub use service_health::{
    build_service_health_response, service_state_slug, severity_slug, FakeIpDatapathProbe,
    ServiceHealthHandler,
};
pub use service_stability_handlers::{
    ServiceStabilityConfigGetHandler, ServiceStabilityConfigSetHandler,
};
pub use settings_handlers::{
    ApplyFailurePolicyGetHandler, ApplyFailurePolicySetHandler, AutostartGetHandler,
    AutostartToggleHandler, LogRetentionConfigGetHandler, LogRetentionConfigSetHandler,
    RetentionSettingsGetHandler, RetentionSettingsSetHandler, RoutingPauseGetHandler,
    RoutingPauseToggleHandler, StorageUsageGetHandler, TrafficStatsClearHandler,
    TrafficStatsGetHandler, TrafficStatsSetHandler,
};
pub use snapshot_diagnostics::SnapshotDiagnosticsHandler;
pub use snapshot_initial::SnapshotInitialHandler;
pub use snapshot_interfaces::SnapshotInterfacesHandler;
pub use status_updates_poll::{StatusUpdatesPollHandler, STATUS_UPDATES_POLL_DEPRECATION_MESSAGE};
pub use status_updates_subscribe::StatusUpdatesSubscribeHandler;
pub use stub::UnimplementedHandler;

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
            service_stability_provider: None,
            service_stability_writer: None,
            archives_dir: None,
            app_version: None,
            system_info: None,
            state_schema_version: None,
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
            merge_preview_source: None,
            traffic_stats: None,
            traffic_stats_writer: None,
            auto_rules: None,
            block_notice_mutes: None,
            block_notice_center: None,
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

/// Register handlers for every operation in [`IpcOperationName::ALL`].
/// Operations whose real implementation has not yet landed resolve to
/// [`UnimplementedHandler`] (which surfaces `RecoveryRequired` to the
/// client). Individual entries are swapped for real
/// implementations without changing this entrypoint's signature.
pub fn register_production_handlers(registry: &mut IpcHandlerRegistry, deps: Arc<IpcHandlerDeps>) {
    for op in IpcOperationName::ALL {
        match op {
            IpcOperationName::ContractNegotiate => {
                registry.register(op, ContractNegotiateHandler::new());
            }
            IpcOperationName::ServiceHealthGet => {
                let mut handler =
                    ServiceHealthHandler::new(deps.health.clone(), deps.policy.clone());
                if let Some(probe) = deps.fake_ip_datapath_probe.as_ref() {
                    handler = handler.with_fake_ip_datapath_probe(Arc::clone(probe));
                }
                registry.register(op, handler);
            }
            IpcOperationName::SnapshotInterfacesGet => {
                // Chain the Fail-Closed probe when
                // wired so the GUI banner reflects per-SID state.
                // Without a probe (test deps / degraded boot) the
                // handler omits the enforcement banner.
                let mut handler = SnapshotInterfacesHandler::new(deps.adapters.clone());
                if let Some(probe) = deps.fail_closed_probe.clone() {
                    handler = handler.with_fail_closed_probe(probe);
                }
                registry.register(op, handler);
            }
            IpcOperationName::SnapshotDiagnosticsGet => {
                registry.register(
                    op,
                    SnapshotDiagnosticsHandler::new(deps.diagnostics.clone()),
                );
            }
            IpcOperationName::SnapshotInitialGet => {
                let mut handler = SnapshotInitialHandler::new(
                    deps.health.clone(),
                    deps.policy.clone(),
                    deps.adapters.clone(),
                    deps.diagnostics.clone(),
                    deps.route_policy.clone(),
                    deps.apply_failure_policy.clone(),
                    deps.routing_pause.clone(),
                    deps.autostart.clone(),
                    deps.retention.clone(),
                    deps.app_enforcement.clone(),
                    deps.shared_ip_exemptions.clone(),
                    deps.block_all_posture.clone(),
                );
                if let Some(probe) = deps.fake_ip_datapath_probe.as_ref() {
                    handler = handler.with_fake_ip_datapath_probe(Arc::clone(probe));
                }
                registry.register(op, handler);
            }
            IpcOperationName::MutationSubmit => {
                // Wire the tamper gate when the
                // alerts repo is available, so a non-alert mutation is
                // refused while an unacknowledged DB tamper / key-reset
                // alert is active.
                let mut handler = MutationSubmitHandler::new(
                    deps.mutation_executor.clone(),
                    deps.mutation_tokens.clone(),
                    deps.operations.clone(),
                );
                if let Some(repo) = deps.alerts_repo.clone() {
                    handler = handler.with_alerts_repo(repo);
                }
                // Administrative rules lock — refuse a non-elevated caller's
                // rule change with a typed wire code the client renders as a
                // read-only rules section.
                if let Some(stability) = deps.service_stability_provider.clone() {
                    handler = handler.with_stability_provider(stability);
                }
                registry.register(op, handler);
            }
            IpcOperationName::OperationStatusGet => {
                registry.register(op, OperationStatusHandler::new(deps.operations.clone()));
            }
            IpcOperationName::RollbackRequest => {
                let mut handler =
                    RollbackHandler::new(deps.mutation_executor.clone(), deps.operations.clone());
                // Re-activating an older revision is a rule change too.
                if let Some(stability) = deps.service_stability_provider.clone() {
                    handler = handler.with_stability_provider(stability);
                }
                registry.register(op, handler);
            }
            IpcOperationName::InterfacesRefreshRequest => {
                registry.register(op, InterfacesRefreshHandler::new(deps.adapters.clone()));
            }
            IpcOperationName::ProductImpactDisableTemporary => {
                registry.register(
                    op,
                    ProductImpactDisableTemporaryHandler::new(
                        deps.mutation_executor.clone(),
                        deps.mutation_tokens.clone(),
                        deps.operations.clone(),
                    ),
                );
            }
            IpcOperationName::StatusUpdatesPoll => {
                registry.register(op, StatusUpdatesPollHandler::new());
            }
            IpcOperationName::StatusUpdatesSubscribe => {
                registry.register(
                    op,
                    StatusUpdatesSubscribeHandler::new(deps.event_bus.clone()),
                );
            }
            IpcOperationName::LogsList => {
                registry.register(op, LogsListHandler::new(deps.diagnostics.clone()));
            }
            IpcOperationName::AuditList => {
                registry.register(op, AuditListHandler::new(deps.diagnostics.clone()));
            }
            IpcOperationName::SecurityAlertsList => {
                registry.register(op, SecurityAlertsHandler::new(deps.alerts_repo.clone()));
            }
            IpcOperationName::RulesList => {
                registry.register(op, RulesListHandler::new(deps.rules.clone()));
            }
            IpcOperationName::RoutePolicyUpdate => {
                registry.register(
                    op,
                    RoutePolicyUpdateHandler::new(
                        deps.route_policy_writer.clone(),
                        deps.route_policy_apply_trigger.clone(),
                    ),
                );
            }
            IpcOperationName::RouteLinkProviderSet => {
                // Real handler only when the state-DB-backed
                // writer is wired; a degraded boot keeps the stub.
                if let Some(writer) = deps.link_provider_writer.clone() {
                    registry.register(
                        op,
                        RouteLinkProviderSetHandler::new(
                            writer,
                            deps.route_policy_apply_trigger.clone(),
                        ),
                    );
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::DohResolversGet => {
                if let Some(store) = deps.doh_resolver_store.clone() {
                    registry.register(op, DohResolversGetHandler::new(store));
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::DohResolversSet => {
                if let Some(store) = deps.doh_resolver_store.clone() {
                    registry.register(
                        op,
                        DohResolversSetHandler::new(store, deps.route_policy_apply_trigger.clone()),
                    );
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::SeedFromBrowserHistory => {
                if let Some(seeder) = deps.browser_history_seeder.clone() {
                    registry.register(op, SeedFromBrowserHistoryHandler::new(seeder));
                } else {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            }
            IpcOperationName::MigrationStatusGet => {
                registry.register(
                    op,
                    MigrationStatusGetHandler::new(deps.migration_status.clone()),
                );
            }
            IpcOperationName::MigrationMarkComplete => {
                registry.register(
                    op,
                    MigrationMarkCompleteHandler::new(deps.migration_completion.clone()),
                );
            }
            // Settings ops.
            IpcOperationName::RetentionSettingsGet => {
                registry.register(op, RetentionSettingsGetHandler::new(deps.retention.clone()));
            }
            IpcOperationName::RetentionSettingsSet => {
                registry.register(
                    op,
                    RetentionSettingsSetHandler::new(deps.retention_writer.clone()),
                );
            }
            // Log/audit retention config.
            IpcOperationName::LogRetentionConfigGet => {
                registry.register(
                    op,
                    LogRetentionConfigGetHandler::new(deps.log_retention.clone()),
                );
            }
            IpcOperationName::LogRetentionConfigSet => {
                registry.register(
                    op,
                    LogRetentionConfigSetHandler::new(deps.log_retention_writer.clone()),
                );
            }
            IpcOperationName::ApplyFailurePolicyGet => {
                registry.register(
                    op,
                    ApplyFailurePolicyGetHandler::new(deps.apply_failure_policy.clone()),
                );
            }
            IpcOperationName::ApplyFailurePolicySet => {
                registry.register(
                    op,
                    ApplyFailurePolicySetHandler::new(deps.apply_failure_policy_writer.clone()),
                );
            }
            IpcOperationName::StorageUsageGet => {
                registry.register(op, StorageUsageGetHandler::new(deps.storage_usage.clone()));
            }
            IpcOperationName::RoutingPauseGet => {
                registry.register(op, RoutingPauseGetHandler::new(deps.routing_pause.clone()));
            }
            IpcOperationName::RoutingPauseToggle => {
                registry.register(
                    op,
                    RoutingPauseToggleHandler::new(deps.routing_pause_writer.clone()),
                );
            }
            IpcOperationName::AutostartGet => {
                registry.register(op, AutostartGetHandler::new(deps.autostart.clone()));
            }
            IpcOperationName::AutostartToggle => {
                registry.register(
                    op,
                    AutostartToggleHandler::new(deps.autostart_writer.clone()),
                );
            }
            // Each gates on its dep being wired; missing dep falls back to
            // the fallback stub so the catalog-coverage test still sees
            // `RecoveryRequired` when the runtime hasn't fully wired the op
            // (degraded boot path).
            IpcOperationName::ExplainGet => {
                // The kill-switch enforcement verdict reuses
                // the conn-trace expectation deps (fqdn cache + active SID)
                // plus the per-SID policy reader; absent expectation deps →
                // rule verdict only (compact.enforcement stays empty).
                let handler =
                    diagnostics_handlers::ExplainGetHandler::new(deps.diagnostics.clone());
                let handler = match deps.conn_trace_expectation.clone() {
                    Some((_rules, fqdn, active_sid)) => handler.with_enforcement_verdict(
                        deps.route_policy.clone(),
                        fqdn,
                        active_sid,
                    ),
                    None => handler,
                };
                // The synthetic hostname probe carries the virtual
                // address the resolver answers with when fake-IP is wired.
                let handler = match deps.fake_ip_bindings.clone() {
                    Some(view) => handler.with_fake_ip_bindings(view),
                    None => handler,
                };
                registry.register(op, handler);
            }
            IpcOperationName::DiagnosticsExportArchive => {
                match (deps.archives_dir.clone(), deps.app_version.clone()) {
                    (Some(dir), Some(ver)) => {
                        registry.register(
                            op,
                            diagnostics_handlers::DiagnosticsExportArchiveHandler::new(
                                deps.diagnostics.clone(),
                                dir,
                                ver,
                                deps.system_info.clone(),
                                deps.adapters.clone(),
                                deps.route_policy.clone(),
                                deps.state_schema_version,
                            ),
                        );
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::ServiceStabilityConfigGet => {
                match deps.service_stability_provider.clone() {
                    Some(provider) => {
                        registry.register(
                            op,
                            service_stability_handlers::ServiceStabilityConfigGetHandler::new(
                                provider,
                            ),
                        );
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::ServiceStabilityConfigSet => {
                match deps.service_stability_writer.clone() {
                    Some(writer) => {
                        let mut handler =
                            service_stability_handlers::ServiceStabilityConfigSetHandler::new(
                                writer,
                            );
                        // The reader lets the handler tell a real change of the
                        // administrative rules lock from a client echoing the
                        // stored value back on an unrelated save.
                        if let Some(provider) = deps.service_stability_provider.clone() {
                            handler = handler.with_provider(provider);
                        }
                        registry.register(op, handler);
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // Real LogsClear handler. The facade
            // is always present (mock or production); no dep gate.
            IpcOperationName::LogsClear => {
                registry.register(
                    op,
                    diagnostics_handlers::LogsClearHandler::new(deps.diagnostics.clone()),
                );
            }
            // DiagnosticModeSet: the facade is always present, so register
            // the real handler unconditionally (like LogsClear).
            IpcOperationName::DiagnosticModeSet => {
                registry.register(
                    op,
                    diagnostics_handlers::DiagnosticModeSetHandler::new(deps.diagnostics.clone()),
                );
            }
            // CacheClear handler. The FQDN/IP cache DB may
            // be absent or corrupt, so register the real handler only when
            // the repository is wired; otherwise keep the Unimplemented stub
            // so the catalog-coverage invariant still holds.
            IpcOperationName::CacheClear => match deps.cache_repository.clone() {
                Some(cache) => {
                    // Attach the OS-DNS-flush port when wired so the
                    // GUI's "clear OS DNS cache" button works; without it the
                    // handler still clears the app SQLite cache.
                    let mut handler = diagnostics_handlers::CacheClearHandler::new(cache);
                    if let Some(port) = deps.dns_cache_control.clone() {
                        handler = handler.with_dns_cache_control(port);
                    }
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // CacheEntriesList (read-only cache viewer). Gated
            // on the same cache repository as CacheClear; the diagnostics
            // facade (always present) supplies the redaction tier. Falls
            // back to the Unimplemented stub when the cache DB is absent.
            IpcOperationName::CacheEntriesList => match deps.cache_repository.clone() {
                Some(cache) => {
                    // When the expectation inputs are wired (same
                    // tuple the conn-trace handler uses), rows carry
                    // `expected_route` (the cache viewer's "Route" column).
                    let handler = diagnostics_handlers::CacheEntriesListHandler::new(cache);
                    let handler = match deps.conn_trace_expectation.clone() {
                        Some((rules, fqdn, active_sid)) => {
                            handler.with_route_expectation(rules, fqdn, active_sid)
                        }
                        None => handler,
                    };
                    // Each row carries the virtual address next to the
                    // real one when fake-IP is wired.
                    let handler = match deps.fake_ip_bindings.clone() {
                        Some(view) => handler.with_fake_ip_bindings(view),
                        None => handler,
                    };
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // ConnTraceEntriesList (read-only connection-trace viewer).
            // Gated on the connection-trace ring (always wired in production).
            // The local own-machine viewer is never redacted, so it does not
            // need the diagnostics facade. Falls back to the
            // Unimplemented stub when the ring is absent (test fakes).
            IpcOperationName::ConnTraceEntriesList => match deps.conn_trace_ring.clone() {
                Some(ring) => {
                    // When the expectation inputs are wired, rows
                    // carry `expected_route` (leak flagging in the GUI trace).
                    let handler = diagnostics_handlers::ConnTraceEntriesListHandler::new(ring);
                    let handler = match deps.conn_trace_expectation.clone() {
                        Some((rules, fqdn, active_sid)) => {
                            handler.with_route_expectation(rules, fqdn, active_sid)
                        }
                        None => handler,
                    };
                    registry.register(op, handler);
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Attribution + integrity of shipped
            // third-party components. Always a real handler: without an
            // inspector it reports the attribution-only assets and no
            // binaries, which is the correct answer where none are shipped.
            IpcOperationName::ThirdPartyComponentsList => {
                let integrity = deps.third_party_integrity.clone().unwrap_or_else(|| {
                    Arc::new(nrr_platform_api::third_party::NoopThirdPartyIntegrity)
                });
                registry.register(
                    op,
                    third_party_handlers::ThirdPartyComponentsListHandler::new(integrity),
                );
            }
            // PresetExportGet handler. When the
            // `PresetExportSource` is wired, register the real
            // handler; otherwise keep the Unimplemented stub so the
            // catalog-coverage invariant holds in degraded boot paths.
            IpcOperationName::PresetExportGet => match deps.preset_export_source.clone() {
                Some(source) => {
                    registry.register(op, preset_handlers::PresetExportGetHandler::new(source));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // SettingsExportFull handler. Registered
            // only when BOTH the source and the clock are wired (the
            // handler needs `now_secs` for `exported_at`); otherwise
            // falls back to the Unimplemented stub.
            IpcOperationName::SettingsExportFull => {
                match (
                    deps.settings_export_source.clone(),
                    deps.settings_export_clock.clone(),
                ) {
                    (Some(source), Some(clock)) => {
                        registry.register(
                            op,
                            preset_handlers::SettingsExportFullHandler::new(source, clock),
                        );
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // RulesMergePreview handler. Gated on the merge
            // source (needs the state DB); falls back to the Unimplemented
            // stub in degraded boot so the catalog-coverage invariant holds.
            IpcOperationName::RulesMergePreview => match deps.merge_preview_source.clone() {
                Some(source) => {
                    registry.register(op, merge_preview::RulesMergePreviewHandler::new(source));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Gated on the sampler-backed deps.
            IpcOperationName::TrafficStatsGet => match deps.traffic_stats.clone() {
                Some(provider) => {
                    registry.register(op, TrafficStatsGetHandler::new(provider));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::TrafficStatsSet => match deps.traffic_stats_writer.clone() {
                Some(writer) => {
                    registry.register(op, TrafficStatsSetHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::TrafficStatsClear => match deps.traffic_stats_writer.clone() {
                Some(writer) => {
                    registry.register(op, TrafficStatsClearHandler::new(writer));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Companion-domain suggestions — gated on the engine,
            // which is only wired when the DNS-observation path exists.
            IpcOperationName::AutoRuleCandidatesList => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesListHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesAccept => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesAcceptHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesDismiss => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesDismissHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleCandidatesForget => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleCandidatesForgetHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleDismissedList => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleDismissedListHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::AutoRuleDismissedRestore => match deps.auto_rules.clone() {
                Some(engine) => {
                    registry.register(op, AutoRuleDismissedRestoreHandler::new(engine));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            // Block-notice mutes — gated on the durable store; the
            // live-ledger owner is wired alongside it by
            // `with_block_notice_mutes`, never independently.
            IpcOperationName::BlockNoticeMutesList => match deps.block_notice_mutes.clone() {
                Some(store) => {
                    registry.register(op, BlockNoticeMutesListHandler::new(store));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
            IpcOperationName::BlockNoticeMutesSet => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesSetHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::BlockNoticeMutesRemove => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesRemoveHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::BlockNoticeMutesClear => {
                match (
                    deps.block_notice_mutes.clone(),
                    deps.block_notice_center.clone(),
                ) {
                    (Some(store), Some(center)) => {
                        registry.register(op, BlockNoticeMutesClearHandler::new(store, center));
                    }
                    _ => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            // Turns a block notice into a rule through the SAME author the
            // companion-domain `accept` path uses.
            IpcOperationName::BlockNoticeRouteToSecondary => {
                match deps.block_notice_author.clone() {
                    Some(author) => {
                        let mut handler = BlockNoticeRouteToSecondaryHandler::new(author);
                        // Without the centre the rule lands but the notice that
                        // asked for it keeps standing.
                        if let Some(center) = deps.block_notice_center.clone() {
                            handler = handler.with_center(center);
                        }
                        registry.register(op, handler);
                    }
                    None => {
                        registry.register(op, UnimplementedHandler::new(op));
                    }
                }
            }
            IpcOperationName::PrincipalDataPurge => match deps.principal_data_purger.clone() {
                Some(purger) => {
                    registry.register(op, PrincipalDataPurgeHandler::new(purger));
                }
                None => {
                    registry.register(op, UnimplementedHandler::new(op));
                }
            },
        }
    }
}

//! # `nrr-service-runtime` — Windows background service orchestration layer
//!
//! Trust boundary: everything the running service does *except*
//! the SCM/console entrypoint glue lives here, behind narrow trait
//! interfaces that are easy to fake in tests.
//!
//! ## Allowed dependency direction
//!
//! - `nrr-service-runtime` → `nrr-domain`, `nrr-application`,
//!   `nrr-storage`, `nrr-diagnostics`, `nrr-platform-windows`,
//!   `nrr-shared`.
//!
//! ## Forbidden dependency direction
//!
//! - `nrr-service-runtime` MUST NOT depend on, or transitively re-export
//!   from: `nrr-ui-support`, `nrr-mock-backend`, `nrr-desktop-gui`,
//!   `nrr-desktop-tray`, `nrr-launcher`, `nrr-qt-host`, or any QML/C++
//!   bridge artefact.
//! - The reverse direction is also forbidden: GUI/tray crates MUST NOT
//!   depend on `nrr-service-runtime`. They communicate with the running
//!   service exclusively over the IPC contracts in `nrr-shared`.
//!
//! ## Direct-call vs IPC-only surfaces
//!
//! | Domain/application function | Service direct call | GUI/tray access |
//! |---|---|---|
//! | `nrr-domain::decide_route`        | yes (rule engine inside the service loop) | no — GUI receives explain/decision DTOs over IPC |
//! | `nrr-storage::*` open/migrate     | yes (service owns the storage profile) | no — GUI receives `StorageHealth` snapshots only |
//! | `nrr-diagnostics::*` audit/log    | yes (service owns the writers) | no — GUI receives paginated entries / archive handles |
//! | `nrr-platform-windows` apply      | yes (privileged mutation) | no — GUI requests via `ApplyController` IPC |
//! | `nrr-application::ipc_*`          | yes (server side) | yes (DTO/contract layer only) |
//!
//! ## Service-owned state
//!
//! - **Active revision** — `ActiveRevisionState`, written only by the
//!   service through its `PolicyManager`.
//! - **Pending/candidate orchestration** — proposed revisions, review
//!   confirmation tokens, dry-run summaries. GUI initiates, service
//!   validates and audits.
//! - **Applied policy state** — what has actually been pushed to Windows
//!   routing/WFP (the platform layer owns the privileged side; this
//!   crate records that an apply attempt happened).
//! - **Integrity metadata** — content hashes, LKG pointer, recovery
//!   markers; never exposed as raw paths to GUI.
//! - **Audit sinks** — NDJSON audit and operational log writers.
//! - **Privileged mutation boundary** — single-writer queue inside the
//!   service; GUI/tray submit requests, service serialises them.
//!
//! ## Compile-time guardrails
//!
//! `tests/dependency_boundary.rs` reads this crate's `Cargo.toml` at
//! compile time and rejects any dependency line that references a
//! forbidden crate name. CI fails on `cargo test -p nrr-service-runtime`
//! before the regression can land. See that file for the canonical
//! deny-list.

pub mod activation_coordinator;
pub mod active_sid_registry;
pub mod adapters;
pub mod app_destination_memory;
pub mod app_enforcement_status;
pub mod app_observation_lookup;
/// Companion-domain discovery — learns the hosts a routed site
/// needs and, depending on the user's `auto_rules_mode`, offers or applies them.
pub mod auto_rules;
pub mod block_notice_center;
pub mod block_notice_mute_store;
pub mod bootstrap;
pub mod browser_history_seeder;
pub mod confirmed_client_app_resolver;
pub mod conn_observation_consumer;
pub mod crash_recovery;
mod dns_address_sanity;
pub mod dns_egress;
pub mod dns_listener;
pub mod dns_observation_consumer;
pub mod dns_refresh;
pub mod dns_resolver;
pub mod dns_resolver_ports;
pub mod dns_resolver_service;
pub mod dns_upstream;
pub mod dns_wire;
// Neutral enforcement planner (CodegenInput/rules → EnforcementPlan).
// Built incrementally alongside the current `wfp_codegen` path; see the
// module doc.
pub mod doh_seed;
pub mod enforcement_planner;
pub mod explain_snapshot_sink;
// Fake-IP neutral relay: flow parsing, per-flow routing
// decisions and the upstream dialer port. Policy lives here; the TUN adapter
// mechanism stays behind `nrr_platform_api::fake_ip::TunAdapterPort`.
pub mod fake_ip;
pub mod fcrdns_learner;
pub mod fqdn_cache_lookup;
pub mod health;
pub mod integration_ports;
pub mod ipc;
pub mod ipc_handlers;
pub mod isp_block_page_learner;
pub mod killswitch_codegen;
pub mod killswitch_drop_registry;
pub mod known_direct;
pub mod lifecycle;
pub mod managers;
mod net_filter;
pub mod network_rearm;
pub mod per_sid_orchestrator;
pub mod persistent_app_resolver;
pub mod policy_loader;
pub mod power_resume;
pub mod production_coordinator;
pub mod production_diagnostics;
pub mod production_handlers_misc;
pub mod production_merge_preview;
pub mod production_mutation_executor;
pub mod production_per_sid_audit;
pub mod production_policy_manager;
pub mod production_preset_exporter;
pub mod production_rules_provider;
pub mod production_security_alerts;
pub mod production_settings;
pub mod production_settings_exporter;
// Production TrafficStatsProvider/Writer backed by
// the sampler + the service-critical traffic_stats_settings singleton.
pub mod production_traffic;
pub mod recent_rule_addresses;
pub mod recovery_audit;
pub mod route_codegen;
pub mod route_coordinator;
pub mod route_reconciler;
pub mod routed_host_flow_refresh;
pub mod routing_pause;
pub mod rule_hostname_seeder;
pub mod runtime_loop;
pub mod secondary_external_address;
pub mod secondary_ip_policy;
pub mod secondary_liveness;
pub mod service_lifecycle;
pub mod service_stability;
pub mod service_tasks;
pub mod tamper_bootstrap;
// Service-side traffic sampler: reads interface octet
// counters, buckets by role, folds deltas into the daily ledger + session totals.
pub mod traffic_sampler;
pub mod verbosity_control;
pub mod vpn_client_registry;
pub mod vpn_endpoint_learning;
pub mod wfp_codegen;
pub mod wfp_filter_ledger;
pub mod windows_apply_adapter;
// `source_watcher.rs` was removed as part of a backdoor-audit cleanup: the
// file-watcher was a scaffold that never got wired into the production
// runtime and would have constituted a second mutation channel had it
// shipped active. The single sanctioned mutation channel is
// `MutationSubmitHandler` via the named-pipe IPC.
pub mod state;
pub mod supervised_runtime;

pub use runtime_loop::{
    CountingFailureSink, OperationPriority, ServiceSupervisor, ServiceTask, ShutdownReport,
    TaskClass, TaskFailureSink, TaskId, TaskOutcome,
};

pub use service_tasks::{
    build_adapter_monitor_task, build_diagnostics_audit_cleanup_task,
    build_diagnostics_cleanup_task, build_dns_observe_task, build_health_aggregator_task,
    build_ipc_accept_task_bundle, build_operation_results_gc_task, build_revisions_retention_task,
    build_rule_hostname_seed_task, build_traffic_sample_task, IpcAcceptTaskBundle,
    TrafficRoleResolver, TrafficSettingsResolver, TrafficTickDeps, ADAPTER_MONITOR_INTERVAL,
    DIAGNOSTICS_CLEANUP_INTERVAL, HEALTH_AGGREGATOR_INTERVAL, IPC_SHUTDOWN_WATCHER_INTERVAL,
    OPERATION_RESULTS_GC_INTERVAL, RECOVERABLE_DEFAULT_MAX_RESTARTS, TASK_ID_ADAPTER_MONITOR,
    TASK_ID_DIAGNOSTICS_AUDIT_CLEANUP, TASK_ID_DIAGNOSTICS_CLEANUP, TASK_ID_HEALTH_AGGREGATOR,
    TASK_ID_IPC_ACCEPT_LOOP, TASK_ID_IPC_SHUTDOWN_WATCHER, TASK_ID_OPERATION_RESULTS_GC,
    TASK_ID_TRAFFIC_SAMPLE, TRAFFIC_SAMPLE_INTERVAL,
};

pub use supervised_runtime::{run_supervised_runtime, SupervisedRuntimeDeps};

pub use activation_coordinator::{
    ActivationAuditEmitter, ActivationAuditEvent, ActivationCoordinator, ActivationOutcome,
    ApplyFailurePolicy, CandidateSubmission, Clock, ConfirmationToken, DispatchFailure,
    DryRunSummary, IdGenerator, NoopActivationAudit, PolicyError, PreFlightCategory,
    PreFlightWarning, RollbackTarget, RulesApplyDispatcher, SidActionPlanSummary,
};
pub use active_sid_registry::{ActiveSidEntry, ActiveSidRegistry};
pub use per_sid_orchestrator::{
    wire_orchestrator_to_registry, ActiveRulesSnapshot, NoopPerSidApplyAudit, NoopRulesProvider,
    OrchestratorError, OrchestratorRoutePolicyApplyTrigger, PerSidApplyAudit, PerSidApplyAuditKind,
    PerSidApplyAuditRecord, PerSidApplyOrchestrator, PerSidBehaviorMode, PerSidBinding,
    PerSidFilterSet, PerSidPolicySnapshot, RoutePolicySource, RulesProvider,
};
pub use routing_pause::{
    NoopRoutingPauseAudit, PauseDispatcher, PauseError, RoutingPauseAudit, RoutingPauseAuditEvent,
    RoutingPauseCoordinator,
};

pub use health::{HealthAggregator, HealthComponent, HealthComponentSnapshot, ServiceSnapshot};

pub use ipc::{
    HandlerOutcome, IpcAuditEmitter, IpcError, IpcErrorCode, IpcHandler, IpcHandlerRegistry,
    IpcOperationClass, IpcRequestContext, IpcRequestEnvelope, IpcResponseEnvelope, IpcRouter,
    MutationQueue, NoopAuditEmitter as NoopIpcAuditEmitter, IPC_MAX_MESSAGE_BYTES,
    IPC_PROTOCOL_VERSION,
};
pub use ipc_handlers::{
    register_production_handlers, service_binary_version, set_service_binary_version,
    AdaptersSnapshotProvider, ApplyFailurePolicyGetHandler, ApplyFailurePolicyProvider,
    ApplyFailurePolicySetHandler, ApplyFailurePolicyWriter, AuditListHandler, AutostartGetHandler,
    AutostartProvider, AutostartToggleHandler, AutostartWriter, ConsumeError,
    ContractNegotiateHandler, DiagnosticsExportArchiveHandler, EventBus, EventEntry,
    ExplainGetHandler, InterfacesRefreshHandler, IpcHandlerDeps, LogRetentionConfigGetHandler,
    LogRetentionConfigProvider, LogRetentionConfigSetHandler, LogRetentionConfigWriter,
    LogsListHandler, MigrationCompletionRecord, MigrationCompletionWriter,
    MigrationMarkCompleteHandler, MigrationStatusGetHandler, MigrationStatusProvider,
    MutationExecutor, MutationOutcome, MutationSubmitHandler, MutationTokenStore, OperationError,
    OperationRecord, OperationState, OperationStatusHandler, OperationStatusStore,
    ProductImpactDisableTemporaryHandler, RetentionSettingsGetHandler, RetentionSettingsProvider,
    RetentionSettingsSetHandler, RetentionSettingsWriter, RollbackHandler, RoutePolicyProvider,
    RoutePolicyUpdateHandler, RoutePolicyWriteError, RoutePolicyWriter, RoutingPauseGetHandler,
    RoutingPauseProvider, RoutingPauseToggleHandler, RoutingPauseWriter, RulesListHandler,
    RulesSnapshotProvider, SecurityAlertsHandler, ServiceHealthHandler,
    ServiceStabilityConfigGetHandler, ServiceStabilityConfigProvider,
    ServiceStabilityConfigSetHandler, ServiceStabilityConfigWriter, SettingsWriteError,
    SnapshotDiagnosticsHandler, SnapshotInitialHandler, SnapshotInterfacesHandler,
    StatusUpdatesPollHandler, StatusUpdatesSubscribeHandler, StorageUsageGetHandler,
    StorageUsageProvider, StoredMutation, SubscribeOutcome, SubscriberState,
    TrafficStatsGetHandler, TrafficStatsProvider, TrafficStatsSetHandler, TrafficStatsWriter,
    UnimplementedHandler, DEFAULT_MUTATION_TOKEN_TTL, DEFAULT_OPERATION_RETENTION,
    EVENT_BUFFER_CAPACITY, MIN_SUPPORTED_CLIENT_VERSION, STATUS_UPDATES_POLL_DEPRECATION_MESSAGE,
};
// Re-export IPC contract types from nrr-shared that acceptance tests need.
pub use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

pub use policy_loader::{
    NoopAuditEmitter, PolicyLoadResult, PolicyLoader, RecoveryAuditEmitter, RecoveryAuditEvent,
};

pub use bootstrap::{
    bootstrap as run_bootstrap, BootstrapArtifacts, BootstrapConfig, BootstrapStepStatus,
    RetryPolicy,
};

// Re-export the operational tracing-subscriber installer from
// `nrr-diagnostics` so the SCM/console entrypoints in `nrr-windows-service`
// can wire it without taking a direct dependency on the diagnostics crate.
pub use nrr_diagnostics::{
    install_ndjson_tracing, install_ndjson_tracing_with_console,
    install_ndjson_tracing_with_console_and_verbose, install_ndjson_tracing_with_verbose,
    TracingInstallOutcome, TracingVerbosityHandle,
};

// Production settings impls.
pub use production_settings::{
    run_autostart_startup_probe, FakeIpApplyRequest, NoopPauseDispatcher,
    OrchestratorPauseDispatcher, ProductionApplyFailurePolicy, ProductionAutostart,
    ProductionLogRetentionConfig, ProductionRetentionSettings, ProductionRoutingPause,
    ProductionServiceStability, ProductionStorageUsage, SystemClock,
};

// Live tracing-verbosity control seam (policy side).
// `TracingVerbosityHandle` (re-exported above from `nrr-diagnostics`) is the
// mechanism-side impl production wiring passes through this trait.
pub use verbosity_control::VerbosityControl;

// Production ActivationCoordinator stack.
pub use explain_snapshot_sink::{
    ExplainSnapshotSink, NoopExplainSnapshotSink, ProductionExplainSnapshotSink,
};
pub use production_coordinator::{
    probe_lkg_available, run_crash_recovery_on_startup, CrashRecoveryOutcome,
    NoopRulesApplyDispatcher, ProductionActivationAuditEmitter, ProductionApplyMarkerStore,
    ProductionIdGenerator, ProductionRecoveryAuditSink, ProductionRulesApplyDispatcher,
};
pub use production_diagnostics::{DiagnosticSessionHandle, ProductionDiagnosticsFacade};
pub use production_handlers_misc::{
    AdapterAddressRecorder, MonitoredAdaptersSnapshotProvider, NoopAdaptersSnapshotProvider,
    NoopMutationExecutor, ProductionFailClosedProbe, ProductionMigrationCompletionWriter,
    ProductionMigrationStatusProvider, ProductionRoutePolicyProvider, ProductionRoutePolicySource,
    ProductionRoutePolicyWriter, ProductionRulesSnapshotProvider,
};
pub use production_mutation_executor::ProductionMutationExecutor;
pub use production_per_sid_audit::ProductionPerSidApplyAudit;
pub use production_policy_manager::CoordinatorPolicyManager;
pub use production_security_alerts::ProductionSecurityAlertsRepository;

pub use crash_recovery::{
    decide_recovery, execute_safe_disable, ApplyAttemptMarker, ApplyMarkerStore, ApplyPhase,
    CrashCounter, DegradedMode, DegradedModeStatus, NoopRecoveryAuditSink, RecoveryAuditRecord,
    RecoveryAuditSink, RecoveryDecision, RecoveryExecutionResult, SafeDisableOutcome,
    SafeDisableRequest, StartupRecoveryCoordinator, StartupRecoveryState,
};
pub use lifecycle::{
    begin_teardown, clear_teardown, run_runtime, run_runtime_with_artifacts,
    run_runtime_with_bootstrap, teardown_in_progress, LifecycleEvent, ServiceController, StopToken,
    AUTOSTART_POLICY, EVENT_SOURCE_NAME, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME,
    START_TIMEOUT, STOP_TIMEOUT,
};
pub use managers::{
    AcceptError, AcceptErrorCategory, AcceptOutcome, ApplyController, ApplyOutcome,
    BootstrapPhaseStatus, BootstrapReport, DiagnosticsManager, HealthReporter, IpcAcceptor,
    IpcBindError, IpcServer, PolicyManager, ServiceManagers, StorageManager,
};
pub use service_lifecycle::{
    required_service_identity, IdentityRequirement, InstallConfig, InstallOutcome,
    PrivilegeMatrixEntry, RecoveryPolicy, SecurityChecklist, ServiceDirectory,
    ServiceIdentityDecision, ServiceStartMode, UninstallConfig, UninstallOutcome, UpdateConfig,
    UpdateOutcome, NT_LOCAL_SERVICE_ACCOUNT, PRELIMINARY_IDENTITY, PRIVILEGE_MATRIX,
    SERVICE_DIRECTORIES,
};
// Re-export the neutral cross-OS principal type so the transport
// (nrr-windows-service) and integration tests can name the `IpcRequestContext`
// identity without taking a direct `nrr-domain` dependency.
pub use nrr_domain::user_principal::UserPrincipal;
pub use state::{
    ActiveRevisionState, ServiceHealthSeverity, ServicePolicyState, ServiceRuntimeState,
    ServiceShutdownReason,
};
pub use windows_apply_adapter::{
    CollectingAuditSink, InMemoryMarkerStore, InMemorySnapshotStore, NoopCachePort,
    NoopDiagnosticsPort, NoopSnapshotStore, SnapshotStore,
};
// The Windows apply engine (mechanism) is cfg(windows)-only.
#[cfg(windows)]
pub use windows_apply_adapter::{production_apply_layer, ApplyOrchestrator, WindowsApplyAdapter};
// The Linux mechanism is the cfg(not(windows)) skeleton mirror.
#[cfg(not(windows))]
pub use windows_apply_adapter::{production_apply_layer, LinuxApplyLayer};

/// What stage a given runtime dimension is at, as one short slug. Printed by
/// the service binary's `status` verb.
///
/// Slugs: `ready` — the production implementation is what runs; `partial` — it
/// runs, but a named piece of it is still missing. `scaffold` is deliberately
/// absent from the current values: every dimension below has a real
/// implementation, and a banner that says otherwise misreports the service to
/// whoever is diagnosing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceRuntimeOrchestrationSnapshot {
    pub scm_lifecycle: &'static str,
    pub bootstrap: &'static str,
    pub policy_load: &'static str,
    pub ipc_server: &'static str,
    pub health_readiness: &'static str,
    pub recovery: &'static str,
    pub privileged_operations: &'static str,
    pub install_update_hooks: &'static str,
}

/// Maturity of each runtime dimension, as the `status` verb reports it.
///
/// The two `partial` entries name what is missing rather than rounding up:
/// health does not publish per-component statuses or degraded modes yet, and
/// the update hook stops after draining and backing up the state database —
/// replacing the binary is the installer's half.
pub const fn service_runtime_orchestration_snapshot() -> ServiceRuntimeOrchestrationSnapshot {
    ServiceRuntimeOrchestrationSnapshot {
        scm_lifecycle: "ready",
        bootstrap: "ready",
        policy_load: "ready",
        ipc_server: "ready",
        health_readiness: "partial",
        recovery: "ready",
        privileged_operations: "ready",
        install_update_hooks: "partial",
    }
}

#[cfg(test)]
mod tests {
    use super::service_runtime_orchestration_snapshot;

    /// The previous version of this test asserted `"scaffold"` on all eight
    /// dimensions, so it pinned the banner to a claim that stopped being true
    /// subsystem by subsystem. Assert the SHAPE instead: every dimension is one
    /// of the known slugs, and none of them still says `scaffold` — a
    /// dimension that regresses to a stub has to say so deliberately.
    #[test]
    fn every_runtime_dimension_reports_a_known_non_scaffold_stage() {
        let snapshot = service_runtime_orchestration_snapshot();
        let dimensions = [
            ("scm_lifecycle", snapshot.scm_lifecycle),
            ("bootstrap", snapshot.bootstrap),
            ("policy_load", snapshot.policy_load),
            ("ipc_server", snapshot.ipc_server),
            ("health_readiness", snapshot.health_readiness),
            ("recovery", snapshot.recovery),
            ("privileged_operations", snapshot.privileged_operations),
            ("install_update_hooks", snapshot.install_update_hooks),
        ];
        for (name, stage) in dimensions {
            assert!(
                matches!(stage, "ready" | "partial"),
                "{name} reports an unknown stage `{stage}`",
            );
        }
    }
}

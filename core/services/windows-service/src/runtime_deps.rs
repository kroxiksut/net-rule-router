//! Production `SupervisedRuntimeDeps` builder.
//!
//! This file exists in the windows-service binary crate (rather than in
//! `nrr-service-runtime`) for two reasons:
//!
//! 1. Construction of `WindowsNamedPipeServer` is Windows-specific and
//!    lives here.
//! 2. The dep bundle gathers things from across the workspace (storage
//!    topology, platform-windows API, diagnostics retention defaults).
//!    Having one place that wires them keeps both call sites — SCM
//!    `scm_service_main` and console `run_console` — consistent.

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
use nrr_domain::decision_lookup::FreshnessThresholds;
use nrr_platform_windows::dns::WindowsDnsResolver;
use nrr_platform_windows::wfp::{FilterFailureMode, WfpSession};
use nrr_platform_windows::{
    autostart::{AutostartHelper, ProductionAutostartRegistry},
    AdapterMonitor, ProductionWindowsApi, WindowsApiAdapterSource, WindowsApiPort,
};
use nrr_service_runtime::{
    activation_coordinator::{ActivationCoordinator, ApplyFailurePolicy},
    active_sid_registry::ActiveSidRegistry,
    bootstrap::BootstrapArtifacts,
    dns_refresh::DnsRefreshOrchestrator,
    fqdn_cache_lookup::{FqdnCacheLookup, SqliteFqdnCacheLookup},
    health::{HealthAggregator, HealthComponent},
    ipc_handlers::event_bus::EventBus,
    ipc_handlers::mutation_token_store::MutationTokenStore,
    ipc_handlers::operation_status_store::OperationStatusStore,
    managers::{HealthReporter, PolicyManager},
    per_sid_orchestrator::{
        wire_orchestrator_to_registry, NoopPerSidApplyAudit, OrchestratorRoutePolicyApplyTrigger,
        PerSidApplyAudit, PerSidApplyOrchestrator, RoutePolicySource, RulesProvider,
    },
    production_handlers_misc::ProductionRoutePolicySource,
    production_per_sid_audit::ProductionPerSidApplyAudit,
    production_rules_provider::ProductionRulesProvider,
    register_production_handlers,
    routing_pause::{NoopRoutingPauseAudit, PauseDispatcher, RoutingPauseCoordinator},
    service_stability::ServiceStabilityConfig,
    tamper_bootstrap::run_tamper_bootstrap,
    AdaptersSnapshotProvider, ApplyFailurePolicyProvider, ApplyFailurePolicyWriter,
    AutostartProvider, AutostartWriter, CoordinatorPolicyManager, FakeIpApplyRequest,
    IpcAuditEmitter, IpcHandlerDeps, IpcHandlerRegistry, IpcRouter, IpcServer,
    LogRetentionConfigProvider, LogRetentionConfigWriter, MigrationCompletionWriter,
    MigrationStatusProvider, MonitoredAdaptersSnapshotProvider, MutationExecutor,
    NoopIpcAuditEmitter, NoopPauseDispatcher, NoopRulesApplyDispatcher,
    OrchestratorPauseDispatcher, ProductionActivationAuditEmitter, ProductionApplyFailurePolicy,
    ProductionApplyMarkerStore, ProductionAutostart, ProductionDiagnosticsFacade,
    ProductionIdGenerator, ProductionLogRetentionConfig, ProductionMigrationCompletionWriter,
    ProductionMigrationStatusProvider, ProductionMutationExecutor, ProductionRecoveryAuditSink,
    ProductionRetentionSettings, ProductionRoutePolicyProvider, ProductionRoutePolicyWriter,
    ProductionRoutingPause, ProductionRulesApplyDispatcher, ProductionRulesSnapshotProvider,
    ProductionSecurityAlertsRepository, ProductionServiceStability, ProductionStorageUsage,
    RecoveryAuditSink, RetentionSettingsProvider, RetentionSettingsWriter, RoutePolicyProvider,
    RoutePolicyWriter, RoutingPauseProvider, RoutingPauseWriter, RulesSnapshotProvider,
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter, StorageUsageProvider,
    SupervisedRuntimeDeps, SystemClock, TracingVerbosityHandle, VerbosityControl,
};
use rusqlite::Connection;

use crate::named_pipe_server::WindowsNamedPipeServer;

mod apply_trigger;
mod boot_budgets;
mod boot_helpers;
mod build;
mod conn_trace;
mod dns_stack;
mod ipc_surface;
mod offline_reset;
mod per_sid_apply;
mod storage_integrity;
mod storage_reads;
mod types;

use apply_trigger::*;
use boot_budgets::*;
use boot_helpers::*;
pub(crate) use build::*;
use conn_trace::*;
use dns_stack::*;
pub(crate) use offline_reset::*;
use storage_reads::*;
use types::*;

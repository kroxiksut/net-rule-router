#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::default_constructed_unit_structs
)]
//! Integration tests: production handler registration and
//! end-to-end router dispatch coverage. Per-handler behavioural unit
//! tests live next to each handler (`mod tests` blocks); this file
//! exercises the handlers AS A WHOLE through `IpcRouter::dispatch`,
//! which is what the named-pipe transport calls in production.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::error::DiagnosticsResult;
use nrr_diagnostics::explain::{ExplainQuery, ExplainResponse};
use nrr_diagnostics::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, CacheHealthCard, ClearLogsRequest,
    ClearLogsResult, DiagnosticModeStateDto, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    LogHealthCard, SecurityAlertDto, SecurityStatusCard, ServiceHealthCard,
    SetDiagnosticModeRequest,
};
use nrr_diagnostics::facade::pagination::{PageResult, PaginationParams};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_service_runtime::ipc_handlers::payloads::{
    AdapterEntry, ContractNegotiateResponse, InterfacesRefreshResponse, MutationConfirmResponse,
    MutationDryRunResponse, OperationStatusResponse, ProductImpactDisableConfirmResponse,
    ProductImpactDisableDryRunResponse, RollbackResponse, RulesListResponse, RulesRouteFilter,
    ServiceHealthResponse, SnapshotInitialResponse, SnapshotInterfacesResponse, StatusUpdateEvent,
    StatusUpdatesSubscribeResponse,
};
use nrr_service_runtime::{
    register_production_handlers, ActiveRevisionState, AdaptersSnapshotProvider, EventBus,
    HealthReporter, IpcAuditEmitter, IpcClientProfile, IpcErrorCode, IpcHandlerDeps,
    IpcHandlerRegistry, IpcOperationClass, IpcOperationName, IpcRequestContext, IpcRequestEnvelope,
    IpcRouter, MutationExecutor, MutationOutcome, MutationTokenStore, NoopIpcAuditEmitter,
    OperationError, OperationStatusStore, PolicyManager, RulesSnapshotProvider,
    ServiceHealthSeverity, ServicePolicyState, ServiceRuntimeState, StoredMutation,
    IPC_PROTOCOL_VERSION,
};

// ── Test fakes ───────────────────────────────────────────────────────────────

struct FakeHealth {
    state: ServiceRuntimeState,
    severity: ServiceHealthSeverity,
}

impl HealthReporter for FakeHealth {
    fn current_state(&self) -> ServiceRuntimeState {
        self.state
    }
    fn worst_severity(&self) -> ServiceHealthSeverity {
        self.severity
    }
}

struct FakePolicy {
    revision: Option<ActiveRevisionState>,
}

impl PolicyManager for FakePolicy {
    fn load_active(&self) -> ServicePolicyState {
        if self.revision.is_some() {
            ServicePolicyState::ActiveReady
        } else {
            ServicePolicyState::NoState
        }
    }
    fn current_revision(&self) -> Option<ActiveRevisionState> {
        self.revision.clone()
    }
}

struct FakeAdapters {
    response: SnapshotInterfacesResponse,
}

impl AdaptersSnapshotProvider for FakeAdapters {
    fn adapters_snapshot(&self, _force_refresh: bool) -> SnapshotInterfacesResponse {
        self.response.clone()
    }
}

struct FakeRules {
    response: RulesListResponse,
}

impl RulesSnapshotProvider for FakeRules {
    fn rules_snapshot(&self, _route_filter: RulesRouteFilter) -> RulesListResponse {
        self.response.clone()
    }
}

struct FakeExecutor;

impl MutationExecutor for FakeExecutor {
    fn preview(
        &self,
        _kind: nrr_service_runtime::ipc_handlers::payloads::MutationKind,
        _payload: &serde_json::Value,
        _principal: &str,
    ) -> nrr_service_runtime::ipc_handlers::payloads::ReviewSummaryResponse {
        nrr_service_runtime::ipc_handlers::payloads::ReviewSummaryResponse {
            diff_summary: "preview".into(),
            provenance: "test".into(),
            risk_level: nrr_service_runtime::ipc_handlers::payloads::ReviewRiskLevel::Low,
            requires_review: false,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            pro_sections: Vec::new(),
        }
    }
    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({ "applied": true }))
    }
    fn rollback(&self, _principal: &str, target: Option<&str>) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({ "rolled-back-to": target }))
    }
    fn safe_disable(&self, reason: &str) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({
            "safe-disabled": true,
            "reason": reason,
        }))
    }
}

struct FailingExecutor;

impl MutationExecutor for FailingExecutor {
    fn preview(
        &self,
        _kind: nrr_service_runtime::ipc_handlers::payloads::MutationKind,
        _payload: &serde_json::Value,
        _principal: &str,
    ) -> nrr_service_runtime::ipc_handlers::payloads::ReviewSummaryResponse {
        nrr_service_runtime::ipc_handlers::payloads::ReviewSummaryResponse {
            diff_summary: "preview".into(),
            provenance: "test".into(),
            risk_level: nrr_service_runtime::ipc_handlers::payloads::ReviewRiskLevel::High,
            requires_review: true,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            pro_sections: Vec::new(),
        }
    }
    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "mutation.rejected.test".into(),
            message: "test failure".into(),
        })
    }
    fn rollback(&self, _principal: &str, _target: Option<&str>) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "rollback.rejected.test".into(),
            message: "rollback test failure".into(),
        })
    }
    fn safe_disable(&self, _reason: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            code: "safe-disable.rejected.test".into(),
            message: "safe-disable test failure".into(),
        })
    }
}

struct FakeDiagnostics {
    status: Mutex<DiagnosticsStatusDto>,
}

impl FakeDiagnostics {
    fn healthy() -> Self {
        Self {
            status: Mutex::new(DiagnosticsStatusDto {
                overall_healthy: true,
                service_health: ServiceHealthCard {
                    state: "running".into(),
                    active_revision_id: None,
                    pending_changes: 0,
                },
                security_status: SecurityStatusCard {
                    audit_chain_ok: true,
                    active_alert_count: 0,
                    audit_write_healthy: true,
                },
                active_alerts: Vec::new(),
                cache_health: CacheHealthCard {
                    entry_count: 0,
                    healthy: true,
                    rebuilding: false,
                },
                log_health: LogHealthCard {
                    dir_writable: true,
                    total_size_bytes: 0,
                    file_count: 0,
                    dropped_count: 0,
                    last_cleanup_at: None,
                },
                diagnostic_mode: DiagnosticModeStateDto::inactive(),
                stale: false,
            }),
        }
    }
}

impl DiagnosticsFacade for FakeDiagnostics {
    fn get_status(&self) -> DiagnosticsStatusDto {
        self.status.lock().unwrap().clone()
    }
    fn list_log_entries(
        &self,
        _filter: &LogEntryFilter,
        _pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        Ok(PageResult::single_page(Vec::new()))
    }
    fn list_audit_entries(
        &self,
        _filter: &AuditEntryFilter,
        _pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        Ok(PageResult::single_page(Vec::new()))
    }
    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        Ok(Vec::new())
    }
    fn acknowledge_alert(&self, _req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
        Ok(())
    }
    fn set_diagnostic_mode(&self, _req: &SetDiagnosticModeRequest) -> DiagnosticsResult<()> {
        Ok(())
    }
    fn clear_logs(&self, _req: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult> {
        Ok(ClearLogsResult {
            files_deleted: 0,
            bytes_freed: 0,
            dry_run: true,
        })
    }
    fn get_explain(
        &self,
        query: &ExplainQuery,
        level: ExplainDetailLevel,
        _caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        // The catalog-coverage test exercises
        // ExplainGet through this fake. Returning an `Unavailable`
        // response is the documented "facade has no explain data"
        // signal — same as `ProductionDiagnosticsFacade` returns
        // until an explain-snapshot store lands.
        Ok(ExplainResponse::unavailable(
            query.kind(),
            level,
            nrr_diagnostics::explain::ExplainDataAvailability::ServiceUnavailable,
        ))
    }
}

fn deps_with(
    state: ServiceRuntimeState,
    severity: ServiceHealthSeverity,
    revision: Option<ActiveRevisionState>,
) -> Arc<IpcHandlerDeps> {
    deps_full(
        state,
        severity,
        revision,
        Arc::new(FakeExecutor),
        Arc::new(EventBus::new()),
    )
}

fn deps_with_executor(executor: Arc<dyn MutationExecutor>) -> Arc<IpcHandlerDeps> {
    deps_full(
        ServiceRuntimeState::Running,
        ServiceHealthSeverity::Ok,
        None,
        executor,
        Arc::new(EventBus::new()),
    )
}

fn deps_with_event_bus(bus: Arc<EventBus>) -> Arc<IpcHandlerDeps> {
    deps_full(
        ServiceRuntimeState::Running,
        ServiceHealthSeverity::Ok,
        None,
        Arc::new(FakeExecutor),
        bus,
    )
}

fn deps_full(
    state: ServiceRuntimeState,
    severity: ServiceHealthSeverity,
    revision: Option<ActiveRevisionState>,
    executor: Arc<dyn MutationExecutor>,
    event_bus: Arc<EventBus>,
) -> Arc<IpcHandlerDeps> {
    Arc::new(IpcHandlerDeps::new(
        Arc::new(NoopIpcAuditEmitter::default()),
        Arc::new(FakeHealth { state, severity }),
        Arc::new(FakePolicy { revision }),
        Arc::new(FakeAdapters {
            response: SnapshotInterfacesResponse {
                data_source: "windows-live".into(),
                adapters: vec![AdapterEntry {
                    persistent_id: "pid-1".into(),
                    adapter_name: "Wi-Fi".into(),
                    ipv6_if_index: 12,
                    physical_address: None,
                    windows_name: "Wireless LAN".into(),
                    interface_description: "".into(),
                    interface_type: "ieee80211".into(),
                    oper_status: "up".into(),
                }],
                secondary: None,
                rows: Vec::new(),
            },
        }),
        Arc::new(FakeRules {
            response: RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: vec!["zone".into(), "domain".into()],
                active_revision_id: None,
            },
        }),
        Arc::new(FakeDiagnostics::healthy()),
        executor,
        Arc::new(MutationTokenStore::new()),
        Arc::new(OperationStatusStore::new()),
        event_bus,
        // Per-SID providers default to inline empty fakes.
        // Tests that exercise the route-policy handlers swap them
        // in via custom builders.
        Arc::new(EmptyRoutePolicyProvider),
        Arc::new(EmptyRoutePolicyWriter),
        Arc::new(EmptyMigrationStatus),
        Arc::new(EmptyMigrationCompletion),
        // Empty providers for the settings catalog. Real
        // unit tests live in `settings_handlers.rs::tests`; the
        // integration test file asserts the full router wiring composes.
        Arc::new(EmptyRetention),
        Arc::new(EmptyRetentionWriter),
        Arc::new(EmptyLogRetention),
        Arc::new(EmptyLogRetentionWriter),
        Arc::new(EmptyApplyFailurePolicy),
        Arc::new(EmptyApplyFailurePolicyWriter),
        Arc::new(EmptyStorageUsage),
        Arc::new(EmptyRoutingPause),
        Arc::new(EmptyRoutingPauseWriter),
        Arc::new(EmptyAutostart),
        Arc::new(EmptyAutostartWriter),
    ))
}

// Empty provider implementations for integration test
// composition. Settings handlers are unit-tested in
// `src/ipc_handlers/settings_handlers.rs`.
struct EmptyRetention;
impl nrr_service_runtime::RetentionSettingsProvider for EmptyRetention {
    fn get(&self) -> nrr_service_runtime::ipc_handlers::payloads::RetentionSettingsDto {
        nrr_service_runtime::ipc_handlers::payloads::RetentionSettingsDto {
            superseded_days: 30,
            superseded_count_cap: 100,
            rejected_days: 7,
            rolledback_days: 14,
            rolledback_count_cap: 20,
            pin_lkg: true,
            last_cleanup_at: None,
            updated_at: 0,
        }
    }
}

struct EmptyRetentionWriter;
impl nrr_service_runtime::RetentionSettingsWriter for EmptyRetentionWriter {
    fn set(
        &self,
        request: &nrr_service_runtime::ipc_handlers::payloads::RetentionSettingsSetRequest,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::RetentionSettingsDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::RetentionSettingsDto {
                superseded_days: request.superseded_days,
                superseded_count_cap: request.superseded_count_cap,
                rejected_days: request.rejected_days,
                rolledback_days: request.rolledback_days,
                rolledback_count_cap: request.rolledback_count_cap,
                pin_lkg: request.pin_lkg,
                last_cleanup_at: None,
                updated_at: 0,
            },
        )
    }
}

// #20 — empty log/audit retention config provider/writer for router composition.
struct EmptyLogRetention;
impl nrr_service_runtime::LogRetentionConfigProvider for EmptyLogRetention {
    fn get(&self) -> nrr_service_runtime::ipc_handlers::payloads::LogRetentionConfigDto {
        nrr_service_runtime::ipc_handlers::payloads::LogRetentionConfigDto {
            log_max_age_days: 90,
            log_max_size_bytes: 52_428_800,
            audit_max_age_days: 365,
            audit_max_size_bytes: 52_428_800,
            updated_at: 0,
        }
    }
}

struct EmptyLogRetentionWriter;
impl nrr_service_runtime::LogRetentionConfigWriter for EmptyLogRetentionWriter {
    fn set(
        &self,
        request: &nrr_service_runtime::ipc_handlers::payloads::LogRetentionConfigSetRequest,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::LogRetentionConfigDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::LogRetentionConfigDto {
                log_max_age_days: request.log_max_age_days,
                log_max_size_bytes: request.log_max_size_bytes,
                audit_max_age_days: request.audit_max_age_days,
                audit_max_size_bytes: request.audit_max_size_bytes,
                updated_at: 0,
            },
        )
    }
}

struct EmptyApplyFailurePolicy;
impl nrr_service_runtime::ApplyFailurePolicyProvider for EmptyApplyFailurePolicy {
    fn get(&self) -> nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto {
        nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto {
            policy: "all-or-nothing".into(),
            updated_at: 0,
            set_by_sid: None,
        }
    }
}

struct EmptyApplyFailurePolicyWriter;
impl nrr_service_runtime::ApplyFailurePolicyWriter for EmptyApplyFailurePolicyWriter {
    fn set(
        &self,
        slug: &str,
        sid: Option<&str>,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto {
                policy: slug.into(),
                updated_at: 0,
                set_by_sid: sid.map(str::to_string),
            },
        )
    }
}

struct EmptyStorageUsage;
impl nrr_service_runtime::StorageUsageProvider for EmptyStorageUsage {
    fn measure(&self) -> nrr_service_runtime::ipc_handlers::payloads::StorageUsageDto {
        nrr_service_runtime::ipc_handlers::payloads::StorageUsageDto {
            state_db_bytes: None,
            cache_db_bytes: None,
            operational_logs_bytes: 0,
            audit_logs_bytes: 0,
            total_bytes: 0,
            scanned_at: 0,
        }
    }
}

struct EmptyRoutingPause;
impl nrr_service_runtime::RoutingPauseProvider for EmptyRoutingPause {
    fn get(&self, sid: &str) -> nrr_service_runtime::ipc_handlers::payloads::RoutingPauseDto {
        nrr_service_runtime::ipc_handlers::payloads::RoutingPauseDto {
            sid: sid.into(),
            paused: false,
            paused_at: None,
            pause_reason: None,
            updated_at: 0,
        }
    }
}

struct EmptyRoutingPauseWriter;
impl nrr_service_runtime::RoutingPauseWriter for EmptyRoutingPauseWriter {
    fn toggle(
        &self,
        sid: &str,
        paused: bool,
        reason: Option<&str>,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::RoutingPauseDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::RoutingPauseDto {
                sid: sid.into(),
                paused,
                paused_at: if paused { Some(0) } else { None },
                pause_reason: reason.map(str::to_string),
                updated_at: 0,
            },
        )
    }
}

struct EmptyAutostart;
impl nrr_service_runtime::AutostartProvider for EmptyAutostart {
    fn get(&self) -> nrr_service_runtime::ipc_handlers::payloads::AutostartDto {
        nrr_service_runtime::ipc_handlers::payloads::AutostartDto {
            enabled: false,
            last_known_state: "absent".into(),
            overridden_value: None,
            updated_at: 0,
        }
    }
}

struct EmptyAutostartWriter;
impl nrr_service_runtime::AutostartWriter for EmptyAutostartWriter {
    fn toggle(
        &self,
        enabled: bool,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::AutostartDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(nrr_service_runtime::ipc_handlers::payloads::AutostartDto {
            enabled,
            last_known_state: if enabled { "enabled" } else { "disabled" }.into(),
            overridden_value: None,
            updated_at: 0,
        })
    }
}

// Empty provider implementations for the integration
// tests that don't exercise per-SID handlers. The route-policy unit
// tests live in `route_policy_update.rs::tests` (lib-side); this file
// asserts the full router wiring still composes when these slots are
// populated with no-op providers.

struct EmptyRoutePolicyProvider;
impl nrr_service_runtime::RoutePolicyProvider for EmptyRoutePolicyProvider {
    fn get_for_sid(
        &self,
        _sid: &str,
    ) -> Option<nrr_service_runtime::ipc_handlers::payloads::RoutePolicyDto> {
        None
    }
}

struct EmptyRoutePolicyWriter;
impl nrr_service_runtime::RoutePolicyWriter for EmptyRoutePolicyWriter {
    fn update_for_sid(
        &self,
        _sid: &str,
        request: &nrr_service_runtime::ipc_handlers::payloads::RoutePolicyUpdateRequest,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::RoutePolicyDto,
        nrr_service_runtime::RoutePolicyWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::RoutePolicyDto {
                primary: request.primary.clone(),
                secondary: request.secondary.clone(),
                mode: request.mode,
                block_secondary_when_unavailable: request.block_secondary_when_unavailable,
                kill_switch_fail_closed: request.kill_switch_fail_closed,
                kill_switch_protocols: request.kill_switch_protocols,
                kill_switch_block_all: request.kill_switch_block_all,
                kill_switch_enabled: request.kill_switch_enabled,
                allow_dns_over_primary: request.allow_dns_over_primary,
                include_subdomains: request.include_subdomains,
                shared_ip_policy: request.shared_ip_policy.clone(),
                mode_a_coverage_strategy: request.mode_a_coverage_strategy.clone(),
                resolve_hosts_bypass: request.resolve_hosts_bypass,
                secondary_link_provider_apps: Vec::new(),
                doh_lockdown_enabled: request.doh_lockdown_enabled,
                doh_lockdown_scope: request.doh_lockdown_scope.clone(),
                browser_history_auto_seed: request.browser_history_auto_seed,
                kill_switch_strict_shared_ips: request.kill_switch_strict_shared_ips,
                auto_rules_mode: request.auto_rules_mode.clone(),
                auto_rules_eager_delivery_names: request.auto_rules_eager_delivery_names,
                binding_source: request.binding_source,
            },
        )
    }
}

struct EmptyMigrationStatus;
impl nrr_service_runtime::MigrationStatusProvider for EmptyMigrationStatus {
    fn migration_status(
        &self,
        _sid: &str,
        _migration_id: &str,
    ) -> nrr_service_runtime::ipc_handlers::payloads::MigrationStatusGetResponse {
        nrr_service_runtime::ipc_handlers::payloads::MigrationStatusGetResponse {
            completed: false,
            completed_at: None,
            detail_json: None,
        }
    }
}

struct EmptyMigrationCompletion;
impl nrr_service_runtime::MigrationCompletionWriter for EmptyMigrationCompletion {
    fn mark_migration_complete(
        &self,
        _sid: &str,
        _migration_id: &str,
        _detail_json: Option<&str>,
    ) -> Result<
        nrr_service_runtime::MigrationCompletionRecord,
        nrr_service_runtime::RoutePolicyWriteError,
    > {
        Ok(nrr_service_runtime::MigrationCompletionRecord {
            recorded: true,
            completed_at: 0,
        })
    }
}

fn deps_default() -> Arc<IpcHandlerDeps> {
    deps_with(
        ServiceRuntimeState::Running,
        ServiceHealthSeverity::Ok,
        None,
    )
}

fn make_router(deps: Arc<IpcHandlerDeps>) -> IpcRouter {
    let audit: Arc<dyn IpcAuditEmitter> = deps.audit_emitter.clone();
    let mut registry = IpcHandlerRegistry::default();
    register_production_handlers(&mut registry, deps);
    IpcRouter::new(registry, audit, /* mutation_queue_capacity */ 8)
}

fn read_envelope(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: format!("req-{}", op.slug()),
        correlation_id: None,
        operation: op,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload,
    }
}

fn elevated_gui_ctx() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: true,
        // Non-empty SID so per-SID handlers (RoutePolicyUpdate,
        // MigrationMarkComplete) reach the writer rather than reject with
        // "caller SID unavailable".
        caller_principal: nrr_service_runtime::UserPrincipal::from_windows_sid(
            "S-1-5-21-test-elevated-gui",
        )
        .ok(),
    }
}

fn unprivileged_gui_ctx() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: false,
        caller_principal: nrr_service_runtime::UserPrincipal::from_windows_sid(
            "S-1-5-21-test-unprivileged-gui",
        )
        .ok(),
    }
}

// ── Catalog coverage ─────────────────────────────────────────────────────────

#[test]
fn production_handlers_register_every_operation_in_catalog() {
    let router = make_router(deps_default());

    /// `IpcOperationName::ALL` is 35 operations. `REAL` lists the 30 that
    /// return `ok` under the `deps_default()` bundle. The remaining 5 are
    /// dependency-gated handlers that fall back to `UnimplementedHandler`
    /// (RecoveryRequired) when their provider/writer/archive dir is not wired
    /// — `DiagnosticsExportArchive` and `ServiceStabilityConfig` Get/Set among
    /// them; their fully-wired path is exercised by `cross_cutting_4b4.rs`.
    /// `ExplainGet` stays in `REAL` (depends only on `deps.diagnostics`, always
    /// wired). `LogsClear` is real too (DiagnosticsFacade::clear_logs).
    const REAL: [IpcOperationName; 34] = [
        // Always registered: with no inspector wired it reports the
        // attribution-only assets, which is a valid answer, not a degraded one.
        IpcOperationName::ThirdPartyComponentsList,
        IpcOperationName::ContractNegotiate,
        IpcOperationName::ServiceHealthGet,
        IpcOperationName::SnapshotInitialGet,
        IpcOperationName::SnapshotInterfacesGet,
        IpcOperationName::SnapshotDiagnosticsGet,
        IpcOperationName::MutationSubmit,
        IpcOperationName::OperationStatusGet,
        IpcOperationName::RollbackRequest,
        IpcOperationName::InterfacesRefreshRequest,
        IpcOperationName::ProductImpactDisableTemporary,
        IpcOperationName::StatusUpdatesPoll,
        IpcOperationName::StatusUpdatesSubscribe,
        IpcOperationName::LogsList,
        // LogsClear is a real handler wired through
        // DiagnosticsFacade::clear_logs (diagnostics always present in
        // deps_default).
        IpcOperationName::LogsClear,
        IpcOperationName::AuditList,
        IpcOperationName::SecurityAlertsList,
        IpcOperationName::RulesList,
        IpcOperationName::RoutePolicyUpdate,
        IpcOperationName::MigrationStatusGet,
        IpcOperationName::MigrationMarkComplete,
        IpcOperationName::RetentionSettingsGet,
        IpcOperationName::RetentionSettingsSet,
        IpcOperationName::ApplyFailurePolicyGet,
        IpcOperationName::ApplyFailurePolicySet,
        IpcOperationName::StorageUsageGet,
        IpcOperationName::RoutingPauseGet,
        IpcOperationName::RoutingPauseToggle,
        IpcOperationName::AutostartGet,
        IpcOperationName::AutostartToggle,
        IpcOperationName::ExplainGet,
        // #21 — DiagnosticModeSet forwards to DiagnosticsFacade::set_diagnostic_mode
        // (facade always wired in deps_default); a bare `{}` payload is a valid
        // disable request, so it returns ok.
        IpcOperationName::DiagnosticModeSet,
        // #20 — log/audit retention config get/set (FakeLogRetention wired in
        // deps_default). Set gets a valid payload + UserScopedConfiguration
        // envelope below.
        IpcOperationName::LogRetentionConfigGet,
        IpcOperationName::LogRetentionConfigSet,
    ];

    for op in IpcOperationName::ALL {
        let (payload, envelope_overrides) = match op {
            IpcOperationName::ContractNegotiate => (
                serde_json::json!({ "client-version": 1, "client-kind": "gui" }),
                None,
            ),
            IpcOperationName::MutationSubmit => (
                serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
                    "dry-run": true,
                }),
                None,
            ),
            IpcOperationName::OperationStatusGet => {
                (serde_json::json!({ "operation-id": "op-not-found" }), None)
            }
            IpcOperationName::RollbackRequest => (
                serde_json::json!({}),
                Some((IpcOperationClass::RecoveryAction, Some("dummy-token"))),
            ),
            IpcOperationName::InterfacesRefreshRequest => (
                serde_json::json!({}),
                Some((IpcOperationClass::DiagnosticQuery, None)),
            ),
            // ProductImpactDisableTemporary dry-run: ReadSnapshot
            // class, no token, body has dry_run=true.
            IpcOperationName::ProductImpactDisableTemporary => (
                serde_json::json!({ "reason": "test", "dry-run": true }),
                None,
            ),
            IpcOperationName::StatusUpdatesSubscribe => {
                (serde_json::json!({ "client-id": "gui-1" }), None)
            }
            // Per-SID handlers. RoutePolicyUpdate writes
            // (UserScopedConfiguration class, no token), MigrationStatusGet
            // reads (ReadSnapshot class), MigrationMarkComplete writes
            // (UserScopedConfiguration class). The `EmptyRoutePolicyWriter`
            // fake returns `Storage("test fake")` to assert wiring without
            // exercising real DB; that's an Internal error, not phase-A
            // stub, so it's handled below.
            IpcOperationName::RoutePolicyUpdate => (
                serde_json::json!({
                    "primary": null,
                    "secondary": null,
                    "mode": "prefer-primary",
                    "block-secondary-when-unavailable": false,
                    "binding-source": "user-assigned",
                }),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            IpcOperationName::MigrationStatusGet => (
                serde_json::json!({"migration-id": "legacy_preferences_v1"}),
                None,
            ),
            IpcOperationName::MigrationMarkComplete => (
                serde_json::json!({"migration-id": "legacy_preferences_v1"}),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            // Settings ops payloads.
            IpcOperationName::RetentionSettingsSet => (
                serde_json::json!({
                    "superseded-days": 30,
                    "superseded-count-cap": 100,
                    "rejected-days": 7,
                    "rolledback-days": 14,
                    "rolledback-count-cap": 20,
                    "pin-lkg": true,
                }),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            // Log/audit retention config set.
            IpcOperationName::LogRetentionConfigSet => (
                serde_json::json!({
                    "log-max-age-days": 90,
                    "log-max-size-bytes": 52_428_800u64,
                    "audit-max-age-days": 365,
                    "audit-max-size-bytes": 52_428_800u64,
                }),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            IpcOperationName::ApplyFailurePolicySet => (
                serde_json::json!({"policy": "all-or-nothing"}),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            IpcOperationName::RoutingPauseToggle => (
                serde_json::json!({"paused": false}),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            IpcOperationName::AutostartToggle => (
                serde_json::json!({"enabled": false}),
                Some((IpcOperationClass::UserScopedConfiguration, None)),
            ),
            // ExplainGet requires exactly one of
            // decision-id / input-sample. Synthetic with empty fields
            // is a valid request — the facade returns Unavailable.
            IpcOperationName::ExplainGet => (serde_json::json!({"input-sample": {}}), None),
            _ => (serde_json::json!({}), None),
        };
        let mut env = read_envelope(op, payload);
        if let Some((class, token)) = envelope_overrides {
            env.operation_class = class;
            env.confirmation_token = token.map(String::from);
        }
        let resp = router.dispatch(env, elevated_gui_ctx());

        if REAL.contains(&op) {
            // OperationStatusGet returns a domain-level error for an
            // unknown id (PreconditionFailed) — that's expected and
            // still proves the handler is wired.
            if op == IpcOperationName::OperationStatusGet {
                assert_eq!(
                    resp.error.as_ref().unwrap().code,
                    IpcErrorCode::PreconditionFailed
                );
                continue;
            }
            // StatusUpdatesPoll is real-but-deprecated: the handler
            // intentionally returns `RecoveryRequired` with a stable
            // migration message. Distinguishing it from a phase A
            // stub is the message — a phase A stub would say
            // "phase A stub", a deprecated handler says "deprecated".
            if op == IpcOperationName::StatusUpdatesPoll {
                let err = resp.error.as_ref().unwrap();
                assert_eq!(err.code, IpcErrorCode::RecoveryRequired);
                assert!(err.message.contains("deprecated"));
                assert!(!err.message.contains("phase A stub"));
                continue;
            }
            assert!(
                resp.ok,
                "real handler {} should succeed; got error {:?}",
                op.slug(),
                resp.error
            );
        } else {
            // Must surface RecoveryRequired with the documented marker.
            // Catches silent registry drift.
            let err = resp
                .error
                .unwrap_or_else(|| panic!("operation {} returned ok unexpectedly", op.slug()));
            assert_eq!(
                err.code,
                IpcErrorCode::RecoveryRequired,
                "operation {} returned {:?}; expected RecoveryRequired (phase A stub)",
                op.slug(),
                err.code
            );
        }
    }
}

#[test]
fn empty_registry_returns_malformed_request_for_known_operation() {
    let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter::default());
    let registry = IpcHandlerRegistry::default();
    let router = IpcRouter::new(registry, audit, 8);

    let resp = router.dispatch(
        read_envelope(IpcOperationName::ServiceHealthGet, serde_json::json!({})),
        elevated_gui_ctx(),
    );
    let err = resp.error.expect("empty registry errors");
    assert_eq!(err.code, IpcErrorCode::MalformedRequest);
}

#[test]
fn protocol_version_mismatch_short_circuits_before_handler_dispatch() {
    let router = make_router(deps_default());
    let mut req = read_envelope(IpcOperationName::ServiceHealthGet, serde_json::json!({}));
    req.protocol_version = IPC_PROTOCOL_VERSION + 1;
    let resp = router.dispatch(req, elevated_gui_ctx());
    let err = resp.error.expect("version mismatch errors");
    assert_eq!(err.code, IpcErrorCode::InvalidVersion);
}

// ── ContractNegotiate ────────────────────────────────────────────────────────

#[test]
fn contract_negotiate_round_trip() {
    let router = make_router(deps_default());
    let payload = serde_json::json!({
        "client-version": IPC_PROTOCOL_VERSION,
        "client-kind": "gui",
        "supported-features": ["push-events"],
    });
    let resp = router.dispatch(
        read_envelope(IpcOperationName::ContractNegotiate, payload),
        elevated_gui_ctx(),
    );
    assert!(resp.ok);
    let parsed: ContractNegotiateResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.server_version, IPC_PROTOCOL_VERSION);
    assert!(parsed.session_id.starts_with("sess-"));
}

// ── ServiceHealth ────────────────────────────────────────────────────────────

#[test]
fn service_health_round_trip_running() {
    let router = make_router(deps_default());
    let resp = router.dispatch(
        read_envelope(IpcOperationName::ServiceHealthGet, serde_json::json!({})),
        elevated_gui_ctx(),
    );
    let parsed: ServiceHealthResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.service_state, "running");
    assert_eq!(parsed.worst_severity, "ok");
}

#[test]
fn service_health_round_trip_recovery_required() {
    let router = make_router(deps_with(
        ServiceRuntimeState::RecoveryRequired,
        ServiceHealthSeverity::Blocking,
        None,
    ));
    let resp = router.dispatch(
        read_envelope(IpcOperationName::ServiceHealthGet, serde_json::Value::Null),
        elevated_gui_ctx(),
    );
    let parsed: ServiceHealthResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.service_state, "recovery-required");
    assert_eq!(parsed.worst_severity, "blocking");
}

#[test]
fn service_health_includes_active_revision_id_when_loaded() {
    let revision = ActiveRevisionState {
        revision_id: "rev-7c2".into(),
        provenance: "import".into(),
        rule_count: 5,
        behavior_mode: "prefer-primary".into(),
        content_hash_hex: "f".repeat(64),
        activated_at_iso: "2026-05-04T12:00:00Z".into(),
    };
    let router = make_router(deps_with(
        ServiceRuntimeState::Running,
        ServiceHealthSeverity::Ok,
        Some(revision),
    ));
    let resp = router.dispatch(
        read_envelope(IpcOperationName::ServiceHealthGet, serde_json::json!({})),
        elevated_gui_ctx(),
    );
    let parsed: ServiceHealthResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.active_revision_id.as_deref(), Some("rev-7c2"));
}

// ── SnapshotInterfaces ───────────────────────────────────────────────────────

#[test]
fn snapshot_interfaces_round_trip() {
    let router = make_router(deps_default());
    let resp = router.dispatch(
        read_envelope(
            IpcOperationName::SnapshotInterfacesGet,
            serde_json::json!({}),
        ),
        elevated_gui_ctx(),
    );
    let parsed: SnapshotInterfacesResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.data_source, "windows-live");
    assert_eq!(parsed.adapters.len(), 1);
    assert_eq!(parsed.adapters[0].persistent_id, "pid-1");
}

// ── SnapshotDiagnostics ──────────────────────────────────────────────────────

#[test]
fn snapshot_diagnostics_round_trip() {
    let router = make_router(deps_default());
    let resp = router.dispatch(
        read_envelope(
            IpcOperationName::SnapshotDiagnosticsGet,
            serde_json::json!({}),
        ),
        elevated_gui_ctx(),
    );
    assert!(resp.ok);
    let payload = resp.payload.unwrap();
    // `DiagnosticsStatusDto` is serialised with default (snake_case)
    // field naming because it lives in `nrr-diagnostics` and is reused
    // verbatim from the GUI facade contract; only our wire wrapper
    // (`SnapshotDiagnosticsResponse`) uses kebab-case.
    assert_eq!(payload["status"]["overall_healthy"], true);
}

// ── SnapshotInitial composer ─────────────────────────────────────────────────

// ── Mutation flow end-to-end ─────────────────────────────────────────────────

fn mutation_dry_run_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-dry".into(),
        correlation_id: None,
        operation: IpcOperationName::MutationSubmit,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload,
    }
}

fn mutation_confirm_envelope(payload: serde_json::Value, token: &str) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-confirm".into(),
        correlation_id: None,
        operation: IpcOperationName::MutationSubmit,
        operation_class: IpcOperationClass::MutationRequest,
        confirmation_token: Some(token.into()),
        payload,
    }
}

#[test]
fn full_mutation_lifecycle_through_router() {
    // 1. dry-run → token
    // 2. confirm with token → operation_id
    // 3. operation_status_get(operation_id) → completed
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));

    let dry = router.dispatch(
        mutation_dry_run_envelope(serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": { "route": "primary", "rules": [] },
            "dry-run": true,
        })),
        elevated_gui_ctx(),
    );
    assert!(dry.ok, "dry-run should succeed: {:?}", dry.error);
    let dry_payload: MutationDryRunResponse = serde_json::from_value(dry.payload.unwrap()).unwrap();
    assert!(!dry_payload.confirmation_token.is_empty());

    let confirm = router.dispatch(
        mutation_confirm_envelope(
            serde_json::json!({
                "mutation-kind": "rules-update",
                "payload": { "route": "primary", "rules": [] },
                "dry-run": false,
            }),
            &dry_payload.confirmation_token,
        ),
        elevated_gui_ctx(),
    );
    assert!(confirm.ok, "confirm should succeed: {:?}", confirm.error);
    let conf_payload: MutationConfirmResponse =
        serde_json::from_value(confirm.payload.unwrap()).unwrap();

    let status = router.dispatch(
        read_envelope(
            IpcOperationName::OperationStatusGet,
            serde_json::json!({ "operation-id": conf_payload.operation_id }),
        ),
        elevated_gui_ctx(),
    );
    assert!(status.ok);
    let status_payload: OperationStatusResponse =
        serde_json::from_value(status.payload.unwrap()).unwrap();
    assert_eq!(status_payload.state, "completed");
    assert_eq!(status_payload.result.unwrap()["applied"], true);
}

#[test]
fn confirm_without_token_is_rejected_by_router_precondition_gate() {
    // The router's confirmation-token gate fires BEFORE the handler is
    // invoked, so the response is `PreconditionFailed` regardless of
    // anything the handler would have done.
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let mut env = mutation_confirm_envelope(
        serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": {},
            "dry-run": false,
        }),
        "",
    );
    env.confirmation_token = None;
    let resp = router.dispatch(env, elevated_gui_ctx());
    assert_eq!(resp.error.unwrap().code, IpcErrorCode::PreconditionFailed);
}

#[test]
fn mutation_failure_surfaces_on_operation_status() {
    let router = make_router(deps_with_executor(Arc::new(FailingExecutor)));

    let dry: MutationDryRunResponse = serde_json::from_value(
        router
            .dispatch(
                mutation_dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
                    "dry-run": true,
                })),
                elevated_gui_ctx(),
            )
            .payload
            .unwrap(),
    )
    .unwrap();
    let conf: MutationConfirmResponse = serde_json::from_value(
        router
            .dispatch(
                mutation_confirm_envelope(
                    serde_json::json!({
                        "mutation-kind": "rules-update",
                        "payload": {},
                        "dry-run": false,
                    }),
                    &dry.confirmation_token,
                ),
                elevated_gui_ctx(),
            )
            .payload
            .unwrap(),
    )
    .unwrap();
    let status: OperationStatusResponse = serde_json::from_value(
        router
            .dispatch(
                read_envelope(
                    IpcOperationName::OperationStatusGet,
                    serde_json::json!({ "operation-id": conf.operation_id }),
                ),
                elevated_gui_ctx(),
            )
            .payload
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status.state, "failed");
    let err = status.error.unwrap();
    assert_eq!(err.code, "mutation.rejected.test");
}

#[test]
fn rollback_request_requires_recovery_action_class_and_token() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-rb".into(),
        correlation_id: None,
        operation: IpcOperationName::RollbackRequest,
        operation_class: IpcOperationClass::RecoveryAction,
        confirmation_token: Some("any-issued-token".into()),
        payload: serde_json::json!({}),
    };
    let resp = router.dispatch(env, elevated_gui_ctx());
    assert!(resp.ok, "rollback should succeed: {:?}", resp.error);
    let parsed: RollbackResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert!(parsed.operation_id.starts_with("op-"));
}

// ── Interfaces refresh / deprecation / safe-disable end-to-end ──────────────

#[test]
fn interfaces_refresh_returns_fresh_snapshot_via_router() {
    let router = make_router(deps_default());
    let env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-ir".into(),
        correlation_id: None,
        operation: IpcOperationName::InterfacesRefreshRequest,
        operation_class: IpcOperationClass::DiagnosticQuery,
        confirmation_token: None,
        payload: serde_json::json!({}),
    };
    let resp = router.dispatch(env, elevated_gui_ctx());
    assert!(
        resp.ok,
        "interfaces.refresh should succeed: {:?}",
        resp.error
    );
    let parsed: InterfacesRefreshResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    // FakeAdapters returns 1 adapter in deps_default.
    assert_eq!(parsed.adapters.len(), 1);
}

#[test]
fn interfaces_refresh_succeeds_for_non_elevated_client() {
    // Regression pin: the external-IP probe / adapter refresh must be
    // callable from a non-admin GUI session without an elevation prompt,
    // even though the operation is a mutating class.
    let router = make_router(deps_default());
    let env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-ir-non-elevated".into(),
        correlation_id: None,
        operation: IpcOperationName::InterfacesRefreshRequest,
        operation_class: IpcOperationClass::DiagnosticQuery,
        confirmation_token: None,
        payload: serde_json::json!({}),
    };
    let resp = router.dispatch(env, unprivileged_gui_ctx());
    assert!(
        resp.ok,
        "interfaces.refresh must not require elevation: {:?}",
        resp.error
    );
    let parsed: InterfacesRefreshResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.adapters.len(), 1);
}

#[test]
fn status_updates_poll_returns_deprecation_signal_via_router() {
    let router = make_router(deps_default());
    let resp = router.dispatch(
        read_envelope(IpcOperationName::StatusUpdatesPoll, serde_json::json!({})),
        elevated_gui_ctx(),
    );
    let err = resp.error.expect("must error");
    assert_eq!(err.code, IpcErrorCode::RecoveryRequired);
    assert!(
        err.message.contains("deprecated"),
        "deprecation message should contain 'deprecated': {}",
        err.message
    );
    assert!(
        err.message.contains("status.updates.subscribe"),
        "deprecation message should point at the replacement: {}",
        err.message
    );
}

#[test]
fn product_impact_disable_full_two_phase_lifecycle_via_router() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));

    // Dry run.
    let dry_env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-pid-dry".into(),
        correlation_id: None,
        operation: IpcOperationName::ProductImpactDisableTemporary,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({
            "reason": "investigating routing anomaly",
            "dry-run": true,
        }),
    };
    let dry = router.dispatch(dry_env, elevated_gui_ctx());
    assert!(dry.ok, "dry-run should succeed: {:?}", dry.error);
    let dry_payload: ProductImpactDisableDryRunResponse =
        serde_json::from_value(dry.payload.unwrap()).unwrap();
    assert!(!dry_payload.confirmation_token.is_empty());

    // Confirm.
    let confirm_env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-pid-conf".into(),
        correlation_id: None,
        operation: IpcOperationName::ProductImpactDisableTemporary,
        operation_class: IpcOperationClass::SafeDisable,
        confirmation_token: Some(dry_payload.confirmation_token.clone()),
        payload: serde_json::json!({
            "reason": "investigating routing anomaly",
            "dry-run": false,
        }),
    };
    let confirm = router.dispatch(confirm_env, elevated_gui_ctx());
    assert!(confirm.ok, "confirm should succeed: {:?}", confirm.error);
    let conf: ProductImpactDisableConfirmResponse =
        serde_json::from_value(confirm.payload.unwrap()).unwrap();

    // Status poll.
    let status: OperationStatusResponse = serde_json::from_value(
        router
            .dispatch(
                read_envelope(
                    IpcOperationName::OperationStatusGet,
                    serde_json::json!({ "operation-id": conf.operation_id }),
                ),
                elevated_gui_ctx(),
            )
            .payload
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status.state, "completed");
    assert_eq!(status.result.unwrap()["safe-disabled"], true);
}

#[test]
fn product_impact_disable_confirm_without_token_rejected_by_router() {
    let router = make_router(deps_default());
    let env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-pid-no-token".into(),
        correlation_id: None,
        operation: IpcOperationName::ProductImpactDisableTemporary,
        operation_class: IpcOperationClass::SafeDisable,
        confirmation_token: None,
        payload: serde_json::json!({ "reason": "x", "dry-run": false }),
    };
    let resp = router.dispatch(env, elevated_gui_ctx());
    assert_eq!(resp.error.unwrap().code, IpcErrorCode::PreconditionFailed);
}

// ── StatusUpdatesSubscribe end-to-end ────────────────────────────────────────

fn subscribe_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-sub".into(),
        correlation_id: None,
        operation: IpcOperationName::StatusUpdatesSubscribe,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload,
    }
}

#[test]
fn status_updates_subscribe_returns_ack_via_router() {
    let bus = Arc::new(EventBus::new());
    let router = make_router(deps_with_event_bus(bus.clone()));
    bus.publish(StatusUpdateEvent::HealthChanged {
        service_state: "running".into(),
        worst_severity: "ok".into(),
    });

    let resp = router.dispatch(
        subscribe_envelope(serde_json::json!({ "client-id": "gui-1" })),
        elevated_gui_ctx(),
    );
    assert!(resp.ok, "subscribe should succeed: {:?}", resp.error);
    let parsed: StatusUpdatesSubscribeResponse =
        serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert!(parsed.subscription_id.starts_with("sub-"));
    assert_eq!(parsed.current_event_id, 2);
    assert!(!parsed.gap_detected);
    assert_eq!(bus.subscriber_count(), 1);
}

#[test]
fn status_updates_subscribe_with_pre_buffer_cursor_signals_gap() {
    let bus = Arc::new(EventBus::new());
    // Overflow the buffer so the oldest retained event id is well
    // past 1.
    for _ in 0..(nrr_service_runtime::EVENT_BUFFER_CAPACITY + 10) {
        bus.publish(StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: "ok".into(),
        });
    }
    let router = make_router(deps_with_event_bus(bus));

    let resp = router.dispatch(
        subscribe_envelope(serde_json::json!({
            "client-id": "gui-1",
            "last-seen-event-id": 1,
        })),
        elevated_gui_ctx(),
    );
    let parsed: StatusUpdatesSubscribeResponse =
        serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert!(parsed.gap_detected);
}

#[test]
fn status_updates_subscribe_replay_window_within_buffer() {
    // Subscribe, then verify the bus's pending-events query returns
    // exactly the events between last_seen and head. This is the
    // contract the transport pump relies on for replay.
    let bus = Arc::new(EventBus::new());
    bus.publish(StatusUpdateEvent::HealthChanged {
        service_state: "running".into(),
        worst_severity: "ok".into(),
    }); // 1
    bus.publish(StatusUpdateEvent::AdaptersChanged {
        data_source: "windows-live".into(),
    }); // 2
    bus.publish(StatusUpdateEvent::AlertRaised {
        alert_id: "a-1".into(),
        kind: "tamper_alert_raised".into(),
    }); // 3

    let router = make_router(deps_with_event_bus(bus.clone()));
    let resp: StatusUpdatesSubscribeResponse = serde_json::from_value(
        router
            .dispatch(
                subscribe_envelope(serde_json::json!({
                    "client-id": "gui-1",
                    "last-seen-event-id": 1,
                })),
                elevated_gui_ctx(),
            )
            .payload
            .unwrap(),
    )
    .unwrap();

    let pending = bus.peek_pending_for(&resp.subscription_id, 16);
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].event_id, 2);
    assert_eq!(pending[1].event_id, 3);
}

#[test]
fn status_updates_subscribe_rejects_empty_client_id() {
    let bus = Arc::new(EventBus::new());
    let router = make_router(deps_with_event_bus(bus));
    let resp = router.dispatch(
        subscribe_envelope(serde_json::json!({ "client-id": "" })),
        elevated_gui_ctx(),
    );
    assert_eq!(resp.error.unwrap().code, IpcErrorCode::MalformedRequest);
}

#[test]
fn snapshot_initial_bundles_health_adapters_and_diagnostics() {
    let revision = ActiveRevisionState {
        revision_id: "rev-init".into(),
        provenance: "import".into(),
        rule_count: 3,
        behavior_mode: "prefer-primary".into(),
        content_hash_hex: "0".repeat(64),
        activated_at_iso: "2026-05-04T00:00:00Z".into(),
    };
    let router = make_router(deps_with(
        ServiceRuntimeState::Running,
        ServiceHealthSeverity::Ok,
        Some(revision),
    ));
    let resp = router.dispatch(
        read_envelope(IpcOperationName::SnapshotInitialGet, serde_json::json!({})),
        elevated_gui_ctx(),
    );
    let parsed: SnapshotInitialResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert_eq!(parsed.health.service_state, "running");
    assert_eq!(
        parsed.health.active_revision_id.as_deref(),
        Some("rev-init")
    );
    assert_eq!(parsed.adapters.adapters.len(), 1);
    assert!(parsed.diagnostics.overall_healthy);
    assert_eq!(parsed.active_alerts_count, 0);
    assert_eq!(parsed.active_revision_id.as_deref(), Some("rev-init"));
}

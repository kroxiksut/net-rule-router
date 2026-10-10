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
    ClearLogsResult, DiagnosticsDataOrigin, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    LogHealthCard, SecurityAlertDto, SecurityStatusCard, ServiceHealthCard,
};
use nrr_diagnostics::facade::pagination::{PageResult, PaginationParams};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_service_runtime::ipc::canonical_operation_class;
use nrr_service_runtime::ipc_handlers::payloads::{
    AdapterEntry, ContractNegotiateResponse, InterfacesRefreshResponse, MutationConfirmResponse,
    MutationDryRunResponse, OperationStatusResponse, ProductImpactDisableConfirmResponse,
    ProductImpactDisableDryRunResponse, RollbackResponse, RollbackTargetDto, RulesListResponse,
    RulesRouteFilter, ServiceHealthResponse, SnapshotInitialResponse, SnapshotInterfacesResponse,
    StatusUpdateEvent, StatusUpdatesSubscribeResponse,
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
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }
    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({ "applied": true }))
    }
    fn rollback(&self, _principal: &str, target: Option<&str>) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({ "rolled-back-to": target }))
    }
    fn rollback_target(
        &self,
        _principal: &str,
        target: Option<&str>,
    ) -> Result<Option<RollbackTargetDto>, OperationError> {
        Ok(Some(RollbackTargetDto {
            revision_id: target.unwrap_or("rev-lkg").to_string(),
            activated_at: Some(1),
            superseded_at: Some(2),
            rule_count: 1,
        }))
    }
    fn safe_disable(&self, reason: &str) -> MutationOutcome {
        MutationOutcome::Completed(serde_json::json!({
            "safe-disabled": true,
            "reason": reason,
        }))
    }
}

/// `FakeExecutor` that also records whose rules each rollback reached.
#[derive(Default)]
struct RollbackRecorder {
    principals: Mutex<Vec<String>>,
}

impl RollbackRecorder {
    fn principals(&self) -> Vec<String> {
        self.principals.lock().unwrap().clone()
    }
}

impl MutationExecutor for RollbackRecorder {
    fn preview(
        &self,
        kind: nrr_service_runtime::ipc_handlers::payloads::MutationKind,
        payload: &serde_json::Value,
        principal: &str,
    ) -> nrr_service_runtime::ipc_handlers::payloads::ReviewSummaryResponse {
        FakeExecutor.preview(kind, payload, principal)
    }
    fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome {
        FakeExecutor.execute(payload, principal)
    }
    fn rollback(&self, principal: &str, target: Option<&str>) -> MutationOutcome {
        self.principals.lock().unwrap().push(principal.to_string());
        FakeExecutor.rollback(principal, target)
    }
    fn rollback_target(
        &self,
        principal: &str,
        target: Option<&str>,
    ) -> Result<Option<RollbackTargetDto>, OperationError> {
        FakeExecutor.rollback_target(principal, target)
    }
    fn safe_disable(&self, reason: &str) -> MutationOutcome {
        FakeExecutor.safe_disable(reason)
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
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }
    fn execute(&self, _payload: StoredMutation, _principal: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
            code: "mutation.rejected.test".into(),
            message: "test failure".into(),
        })
    }
    fn rollback(&self, _principal: &str, _target: Option<&str>) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
            code: "rollback.rejected.test".into(),
            message: "rollback test failure".into(),
        })
    }
    fn rollback_target(
        &self,
        principal: &str,
        target: Option<&str>,
    ) -> Result<Option<RollbackTargetDto>, OperationError> {
        FakeExecutor.rollback_target(principal, target)
    }
    fn safe_disable(&self, _reason: &str) -> MutationOutcome {
        MutationOutcome::Failed(OperationError {
            args: Default::default(),
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
                    start_relative_to_sign_in: "unknown".to_string(),
                    start_sign_in_gap_ms: None,
                },
                security_status: SecurityStatusCard {
                    audit_chain_ok: true,
                    active_alert_count: 0,
                    audit_write_healthy: true,
                    alerts_readable: true,
                },
                active_alerts: Vec::new(),
                cache_health: CacheHealthCard {
                    entry_count: 0,
                    healthy: true,
                },
                log_health: LogHealthCard {
                    dir_writable: true,
                    total_size_bytes: 0,
                    audit_size_bytes: 0,
                    file_count: 0,
                    dropped_count: 0,
                    last_cleanup_at: None,
                },
                stale: false,
                origin: DiagnosticsDataOrigin::Service,
            }),
        }
    }
}

impl DiagnosticsFacade for FakeDiagnostics {
    fn get_status(
        &self,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsStatusDto {
        self.status.lock().unwrap().clone()
    }
    fn list_log_entries(
        &self,
        _filter: &LogEntryFilter,
        _pagination: &PaginationParams,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        Ok(PageResult::single_page(Vec::new()))
    }
    fn list_audit_entries(
        &self,
        _filter: &AuditEntryFilter,
        _pagination: &PaginationParams,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        Ok(PageResult::single_page(Vec::new()))
    }
    fn list_alerts(
        &self,
        _filter: nrr_diagnostics::facade::service::AlertListFilter,
        _audience: &nrr_shared::diagnostics_dto::DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        Ok(Vec::new())
    }
    fn acknowledge_alert(&self, _req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
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
                    name: "Wireless LAN".into(),
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
                unrecognized: 0,
                main_route_pending: 0,
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

// Empty log/audit retention config provider/writer for router composition.
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
        }
    }
}

struct EmptyApplyFailurePolicyWriter;
impl nrr_service_runtime::ApplyFailurePolicyWriter for EmptyApplyFailurePolicyWriter {
    fn set(
        &self,
        slug: &str,
        _sid: Option<&str>,
    ) -> Result<
        nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto,
        nrr_service_runtime::SettingsWriteError,
    > {
        Ok(
            nrr_service_runtime::ipc_handlers::payloads::ApplyFailurePolicyDto {
                policy: slug.into(),
                updated_at: 0,
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
        _sid: &str,
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
                primary_probe_auto: false,
                primary_probe_timeout_ms: 1500,
                primary_probe_max_targets: 8,
                primary_probe_repeat_secs: 300,
                local_networks_auto_accept: false,
                zone_priority_over_ip: false,
                short_name_completion: false,
                short_name_suffix: String::new(),
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
        operation_class: canonical_operation_class(op, &payload),
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
        caller_pid: None,
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
        caller_pid: None,
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
    const REAL: [IpcOperationName; 33] = [
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
        // Log/audit retention config get/set (FakeLogRetention wired in
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
            // The rollback itself needs a token only its dry-run mints.
            IpcOperationName::RollbackRequest => (serde_json::json!({ "dry-run": true }), None),
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
                    // Required, no wire default: a protection toggle must not
                    // be turnable off by omission.
                    "kill-switch-enabled": false,
                    "kill-switch-block-all": false,
                    "kill-switch-strict-shared-ips": false,
                    "doh-lockdown-enabled": false,
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
            env.confirmation_token = token.map(|t: &str| t.to_string());
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
        operation_class: canonical_operation_class(IpcOperationName::MutationSubmit, &payload),
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
        operation_class: canonical_operation_class(IpcOperationName::MutationSubmit, &payload),
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

/// An envelope the way our client builds it: class derived from the payload.
fn envelope_for(
    op: IpcOperationName,
    payload: serde_json::Value,
    token: Option<&str>,
) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: format!("req-{}", op.slug()),
        correlation_id: None,
        operation: op,
        operation_class: canonical_operation_class(op, &payload),
        confirmation_token: token.map(str::to_string),
        payload,
    }
}

/// An elevated GUI session of the named principal.
fn elevated_ctx_of(sid: &str) -> IpcRequestContext {
    IpcRequestContext {
        caller_principal: nrr_service_runtime::UserPrincipal::from_windows_sid(sid).ok(),
        ..elevated_gui_ctx()
    }
}

/// The confirmation token a dry-run of `op` hands out.
fn dry_run_token(
    router: &IpcRouter,
    op: IpcOperationName,
    payload: serde_json::Value,
    ctx: IpcRequestContext,
) -> String {
    let resp = router.dispatch(envelope_for(op, payload, None), ctx);
    assert!(resp.ok, "{op:?} dry-run: {:?}", resp.error);
    resp.payload.unwrap()["confirmation-token"]
        .as_str()
        .expect("dry-run returns a token")
        .to_string()
}

fn rollback_dry_run(router: &IpcRouter, ctx: IpcRequestContext) -> String {
    dry_run_token(
        router,
        IpcOperationName::RollbackRequest,
        serde_json::json!({ "dry-run": true }),
        ctx,
    )
}

fn rollback_with(
    router: &IpcRouter,
    token: &str,
    ctx: IpcRequestContext,
) -> nrr_service_runtime::IpcResponseEnvelope {
    router.dispatch(
        envelope_for(
            IpcOperationName::RollbackRequest,
            serde_json::json!({}),
            Some(token),
        ),
        ctx,
    )
}

fn error_code(resp: &nrr_service_runtime::IpcResponseEnvelope) -> IpcErrorCode {
    resp.error.as_ref().expect("must be refused").code
}

#[test]
fn rollback_runs_on_the_token_its_own_dry_run_issued() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let token = rollback_dry_run(&router, elevated_gui_ctx());
    let resp = rollback_with(&router, &token, elevated_gui_ctx());
    assert!(resp.ok, "rollback should succeed: {:?}", resp.error);
    let parsed: RollbackResponse = serde_json::from_value(resp.payload.unwrap()).unwrap();
    assert!(parsed.operation_id.starts_with("op-"));
    // One-shot: the same token does not roll back twice.
    let again = rollback_with(&router, &token, elevated_gui_ctx());
    assert_eq!(error_code(&again), IpcErrorCode::ConfirmationUnknown);
}

/// The router only checks that a token is present; the value is what the
/// handler must hold to account.
#[test]
fn rollback_refuses_a_token_nobody_issued() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let resp = rollback_with(&router, "any-issued-token", elevated_gui_ctx());
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationUnknown);
}

#[test]
fn rollback_refuses_a_token_issued_to_another_principal() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let token = rollback_dry_run(&router, elevated_ctx_of("S-1-5-21-test-alice"));
    let resp = rollback_with(&router, &token, elevated_ctx_of("S-1-5-21-test-bob"));
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationUnknown);
}

#[test]
fn rollback_refuses_an_expired_token() {
    let deps = deps_with_executor(Arc::new(FakeExecutor));
    let tokens = Arc::clone(&deps.mutation_tokens);
    let router = make_router(deps);
    let ctx = elevated_gui_ctx();
    let token = tokens.issue(
        IpcOperationName::RollbackRequest,
        StoredMutation::confirmation_of(serde_json::json!({}), ctx.caller_stored(), true),
        std::time::Instant::now() - std::time::Duration::from_secs(1),
    );
    let resp = rollback_with(&router, &token, ctx);
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationExpired);
}

const BASELINE_DRY_RUN: &str = r#"{ "dry-run": true, "admin-baseline": true }"#;
const BASELINE_ROLLBACK: &str = r#"{ "admin-baseline": true }"#;

fn json(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap()
}

fn recording_router() -> (IpcRouter, Arc<RollbackRecorder>) {
    let recorder = Arc::new(RollbackRecorder::default());
    let router = make_router(deps_with_executor(recorder.clone()));
    (router, recorder)
}

/// The user's own rules roll back the way they are edited: no elevation, so
/// the launcher never needs the broker for it.
#[test]
fn an_unelevated_user_rolls_back_their_own_rules() {
    let (router, recorder) = recording_router();
    let token = rollback_dry_run(&router, unprivileged_gui_ctx());
    let resp = rollback_with(&router, &token, unprivileged_gui_ctx());
    assert!(
        resp.ok,
        "own rollback must not need rights: {:?}",
        resp.error
    );
    assert_eq!(recorder.principals(), ["S-1-5-21-test-unprivileged-gui"]);
}

#[test]
fn an_unelevated_user_cannot_roll_back_the_baseline() {
    let (router, recorder) = recording_router();
    let token = dry_run_token(
        &router,
        IpcOperationName::RollbackRequest,
        json(BASELINE_DRY_RUN),
        unprivileged_gui_ctx(),
    );
    let resp = router.dispatch(
        envelope_for(
            IpcOperationName::RollbackRequest,
            json(BASELINE_ROLLBACK),
            Some(&token),
        ),
        unprivileged_gui_ctx(),
    );
    assert_eq!(error_code(&resp), IpcErrorCode::Forbidden);
    assert!(recorder.principals().is_empty());
}

/// The partition follows the derived class: a baseline rollback labelled as
/// the user's own, or the other way round, is refused at the door.
#[test]
fn a_rollback_mislabelling_its_partition_is_refused() {
    let (router, recorder) = recording_router();
    for (payload, label) in [
        (
            json(BASELINE_ROLLBACK),
            IpcOperationClass::UserScopedMutation,
        ),
        (serde_json::json!({}), IpcOperationClass::MutationRequest),
    ] {
        let token = rollback_dry_run(&router, unprivileged_gui_ctx());
        let mut env = envelope_for(IpcOperationName::RollbackRequest, payload, Some(&token));
        env.operation_class = label;
        let resp = router.dispatch(env, unprivileged_gui_ctx());
        assert_eq!(
            error_code(&resp),
            IpcErrorCode::MalformedRequest,
            "{label:?}"
        );
    }
    assert!(recorder.principals().is_empty());
}

/// An administrator rolls back either partition, each on its own token.
#[test]
fn an_elevated_caller_rolls_back_their_own_rules_and_the_baseline() {
    let (router, recorder) = recording_router();
    let own = rollback_dry_run(&router, elevated_gui_ctx());
    assert!(rollback_with(&router, &own, elevated_gui_ctx()).ok);
    let base = dry_run_token(
        &router,
        IpcOperationName::RollbackRequest,
        json(BASELINE_DRY_RUN),
        elevated_gui_ctx(),
    );
    let resp = router.dispatch(
        envelope_for(
            IpcOperationName::RollbackRequest,
            json(BASELINE_ROLLBACK),
            Some(&base),
        ),
        elevated_gui_ctx(),
    );
    assert!(resp.ok, "baseline rollback: {:?}", resp.error);
    assert_eq!(
        recorder.principals(),
        [
            "S-1-5-21-test-elevated-gui".to_string(),
            nrr_storage::BASELINE_PRINCIPAL.to_string()
        ]
    );
}

#[test]
fn an_unelevated_rollback_refuses_another_users_token() {
    let (router, recorder) = recording_router();
    let token = rollback_dry_run(&router, elevated_ctx_of("S-1-5-21-test-alice"));
    let resp = rollback_with(&router, &token, unprivileged_gui_ctx());
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationUnknown);
    assert!(recorder.principals().is_empty());
}

/// Every two-phase operation mints into the same store. A token confirms the
/// operation that issued it and nothing else, in either direction.
#[test]
fn no_operation_accepts_another_operations_token() {
    let router = make_router(deps_with_executor(Arc::new(FakeExecutor)));
    let ctx = elevated_gui_ctx;
    let safe_disable_dry = serde_json::json!({ "reason": "r", "dry-run": true });
    let safe_disable = serde_json::json!({ "reason": "r", "dry-run": false });
    let restart_dry = serde_json::json!({
        "mutation-kind": "audit-chain-restart",
        "payload": { "breaks-digest": "d" },
        "dry-run": true,
    });
    let restart = serde_json::json!({
        "mutation-kind": "audit-chain-restart",
        "payload": { "breaks-digest": "d" },
        "dry-run": false,
    });

    // Safe-disable and audit-chain-restart tokens do not roll back.
    for (op, dry) in [
        (
            IpcOperationName::ProductImpactDisableTemporary,
            &safe_disable_dry,
        ),
        (IpcOperationName::MutationSubmit, &restart_dry),
    ] {
        let token = dry_run_token(&router, op, dry.clone(), ctx());
        let resp = rollback_with(&router, &token, ctx());
        assert_eq!(
            error_code(&resp),
            IpcErrorCode::ConfirmationUnknown,
            "{op:?}"
        );
    }

    // A rollback token neither disables protection nor restarts the chain.
    for (op, confirm) in [
        (
            IpcOperationName::ProductImpactDisableTemporary,
            &safe_disable,
        ),
        (IpcOperationName::MutationSubmit, &restart),
    ] {
        let token = rollback_dry_run(&router, ctx());
        let resp = router.dispatch(envelope_for(op, confirm.clone(), Some(&token)), ctx());
        assert_eq!(
            error_code(&resp),
            IpcErrorCode::ConfirmationUnknown,
            "{op:?}"
        );
    }

    // Nor does a safe-disable token restart the chain, or the other way round.
    let token = dry_run_token(
        &router,
        IpcOperationName::ProductImpactDisableTemporary,
        safe_disable_dry.clone(),
        ctx(),
    );
    let resp = router.dispatch(
        envelope_for(
            IpcOperationName::MutationSubmit,
            restart.clone(),
            Some(&token),
        ),
        ctx(),
    );
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationUnknown);
    let token = dry_run_token(
        &router,
        IpcOperationName::MutationSubmit,
        restart_dry,
        ctx(),
    );
    let resp = router.dispatch(
        envelope_for(
            IpcOperationName::ProductImpactDisableTemporary,
            safe_disable,
            Some(&token),
        ),
        ctx(),
    );
    assert_eq!(error_code(&resp), IpcErrorCode::ConfirmationUnknown);
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
        operation_class: canonical_operation_class(
            IpcOperationName::InterfacesRefreshRequest,
            &serde_json::json!({}),
        ),
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
        operation_class: canonical_operation_class(
            IpcOperationName::InterfacesRefreshRequest,
            &serde_json::json!({}),
        ),
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
    let dry_req_payload = serde_json::json!({
        "reason": "investigating routing anomaly",
        "dry-run": true,
    });
    let dry_env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-pid-dry".into(),
        correlation_id: None,
        operation: IpcOperationName::ProductImpactDisableTemporary,
        operation_class: canonical_operation_class(
            IpcOperationName::ProductImpactDisableTemporary,
            &dry_req_payload,
        ),
        confirmation_token: None,
        payload: dry_req_payload,
    };
    let dry = router.dispatch(dry_env, elevated_gui_ctx());
    assert!(dry.ok, "dry-run should succeed: {:?}", dry.error);
    let dry_payload: ProductImpactDisableDryRunResponse =
        serde_json::from_value(dry.payload.unwrap()).unwrap();
    assert!(!dry_payload.confirmation_token.is_empty());

    // Confirm.
    let confirm_req_payload = serde_json::json!({
        "reason": "investigating routing anomaly",
        "dry-run": false,
    });
    let confirm_env = IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-pid-conf".into(),
        correlation_id: None,
        operation: IpcOperationName::ProductImpactDisableTemporary,
        operation_class: canonical_operation_class(
            IpcOperationName::ProductImpactDisableTemporary,
            &confirm_req_payload,
        ),
        confirmation_token: Some(dry_payload.confirmation_token.clone()),
        payload: confirm_req_payload,
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
        operation_class: canonical_operation_class(
            IpcOperationName::ProductImpactDisableTemporary,
            &serde_json::json!({ "reason": "x", "dry-run": false }),
        ),
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
        operation_class: canonical_operation_class(
            IpcOperationName::StatusUpdatesSubscribe,
            &payload,
        ),
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
    bus.publish(StatusUpdateEvent::SecurityAlertsChanged); // 3

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

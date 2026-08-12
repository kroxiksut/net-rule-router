//! Shared test fakes used by per-handler unit tests in
//! [`super`](crate::ipc_handlers).
//!
//! Compiled both in test and non-test builds (gated only by
//! `#[cfg(test)]` at the module declaration in `mod.rs`) so each
//! handler's `mod tests { … }` block can pull from a single source.

#![cfg(test)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::operation_status_store::OperationError;
use crate::ipc_handlers::payloads::{
    AdapterEntry, MigrationStatusGetResponse, MutationKind, ReviewRiskLevel, ReviewSummaryResponse,
    RoutePolicyDto, RoutePolicyUpdateRequest, RulesListResponse, RulesRouteFilter,
    SnapshotInterfacesResponse,
};
use crate::ipc_handlers::providers::{
    AdaptersSnapshotProvider, MigrationCompletionRecord, MigrationCompletionWriter,
    MigrationStatusProvider, MutationExecutor, MutationOutcome, RoutePolicyProvider,
    RoutePolicyWriteError, RoutePolicyWriter, RulesSnapshotProvider,
    ServiceStabilityConfigProvider,
};
use crate::managers::{HealthReporter, PolicyManager};
use crate::state::{
    ActiveRevisionState, ServiceHealthSeverity, ServicePolicyState, ServiceRuntimeState,
};

// ── Health / Policy ──────────────────────────────────────────────────────────

pub struct FakeHealth {
    pub state: ServiceRuntimeState,
    pub severity: ServiceHealthSeverity,
}

impl HealthReporter for FakeHealth {
    fn current_state(&self) -> ServiceRuntimeState {
        self.state
    }
    fn worst_severity(&self) -> ServiceHealthSeverity {
        self.severity
    }
}

pub struct FakePolicy {
    pub revision: Option<ActiveRevisionState>,
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

// ── Adapters ─────────────────────────────────────────────────────────────────

pub struct FakeAdapters {
    pub adapters: Vec<AdapterEntry>,
    pub data_source: String,
    pub last_force_refresh: AtomicBool,
}

impl FakeAdapters {
    pub fn empty() -> Self {
        Self {
            adapters: Vec::new(),
            data_source: "windows-live".into(),
            last_force_refresh: AtomicBool::new(false),
        }
    }
    pub fn with_one(entry: AdapterEntry) -> Self {
        Self {
            adapters: vec![entry],
            data_source: "windows-live".into(),
            last_force_refresh: AtomicBool::new(false),
        }
    }
}

impl AdaptersSnapshotProvider for FakeAdapters {
    fn adapters_snapshot(&self, force_refresh: bool) -> SnapshotInterfacesResponse {
        self.last_force_refresh
            .store(force_refresh, Ordering::Relaxed);
        SnapshotInterfacesResponse {
            data_source: self.data_source.clone(),
            adapters: self.adapters.clone(),
            // Fake AdaptersSnapshotProvider has no
            // policy-layer visibility; tests that need to exercise
            // the fail-closed banner construct the response directly
            // rather than going through this fake.
            secondary: None,
            // Fake provider carries no enriched rows.
            rows: Vec::new(),
        }
    }
}

// ── Rules ────────────────────────────────────────────────────────────────────

pub struct FakeRules {
    pub response: Mutex<RulesListResponse>,
    pub last_filter: Mutex<Option<RulesRouteFilter>>,
}

impl RulesSnapshotProvider for FakeRules {
    fn rules_snapshot(&self, route_filter: RulesRouteFilter) -> RulesListResponse {
        *self.last_filter.lock().unwrap() = Some(route_filter);
        self.response.lock().unwrap().clone()
    }
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

pub struct FakeDiagnostics {
    pub status: Mutex<DiagnosticsStatusDto>,
    pub logs: Mutex<Vec<LogEntryDto>>,
    pub audit: Mutex<Vec<AuditEntryDto>>,
    pub alerts: Mutex<Vec<SecurityAlertDto>>,
    pub last_log_call: Mutex<Option<(LogEntryFilter, PaginationParams)>>,
    pub last_audit_call: Mutex<Option<(AuditEntryFilter, PaginationParams)>>,
}

impl FakeDiagnostics {
    fn healthy_status() -> DiagnosticsStatusDto {
        DiagnosticsStatusDto {
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
        }
    }

    pub fn healthy() -> Self {
        Self {
            status: Mutex::new(Self::healthy_status()),
            logs: Mutex::new(Vec::new()),
            audit: Mutex::new(Vec::new()),
            alerts: Mutex::new(Vec::new()),
            last_log_call: Mutex::new(None),
            last_audit_call: Mutex::new(None),
        }
    }

    pub fn with_logs(entries: Vec<LogEntryDto>) -> Self {
        let me = Self::healthy();
        *me.logs.lock().unwrap() = entries;
        me
    }

    pub fn with_audit(entries: Vec<AuditEntryDto>) -> Self {
        let me = Self::healthy();
        *me.audit.lock().unwrap() = entries;
        me
    }

    #[allow(dead_code)]
    pub fn with_alerts(entries: Vec<SecurityAlertDto>) -> Self {
        let me = Self::healthy();
        // Mirror into status.active_alerts so SnapshotInitial sees the same list.
        let mut status = Self::healthy_status();
        status.active_alerts = entries.clone();
        status.security_status.active_alert_count = entries.len() as u32;
        *me.status.lock().unwrap() = status;
        *me.alerts.lock().unwrap() = entries;
        me
    }
}

impl DiagnosticsFacade for FakeDiagnostics {
    fn get_status(&self) -> DiagnosticsStatusDto {
        self.status.lock().unwrap().clone()
    }
    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        *self.last_log_call.lock().unwrap() = Some((filter.clone(), pagination.clone()));
        Ok(PageResult::single_page(self.logs.lock().unwrap().clone()))
    }
    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        *self.last_audit_call.lock().unwrap() = Some((filter.clone(), pagination.clone()));
        Ok(PageResult::single_page(self.audit.lock().unwrap().clone()))
    }
    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        Ok(self.alerts.lock().unwrap().clone())
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
    #[allow(clippy::unimplemented)] // test fake: this path isn't exercised
    fn get_explain(
        &self,
        _query: &ExplainQuery,
        _level: ExplainDetailLevel,
        _caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        unimplemented!("FakeDiagnostics::get_explain — not used in phase B tests")
    }
}

// ── MutationExecutor ─────────────────────────────────────────────────────────

/// Records what the mutation submit + rollback handlers asked it to do
/// and either echoes the payload back as a successful result or fails
/// with a configured error.
pub struct FakeMutationExecutor {
    pub executed_count: AtomicUsize,
    pub rollback_count: AtomicUsize,
    pub safe_disable_count: AtomicUsize,
    pub last_rollback_target: Mutex<Option<String>>,
    pub last_safe_disable_reason: Mutex<Option<String>>,
    pub last_executed: Mutex<Option<StoredMutation>>,
    /// Principal threaded into the last `execute` /
    /// `rollback` call, so handler tests can assert the per-principal
    /// SID was derived correctly from the envelope class + `caller_sid`.
    pub last_principal: Mutex<Option<String>>,
    pub fail_with: Option<OperationError>,
}

impl Default for FakeMutationExecutor {
    fn default() -> Self {
        Self {
            executed_count: AtomicUsize::new(0),
            rollback_count: AtomicUsize::new(0),
            safe_disable_count: AtomicUsize::new(0),
            last_rollback_target: Mutex::new(None),
            last_safe_disable_reason: Mutex::new(None),
            last_executed: Mutex::new(None),
            last_principal: Mutex::new(None),
            fail_with: None,
        }
    }
}

impl FakeMutationExecutor {
    pub fn always_fail(code: &str, message: &str) -> Self {
        Self {
            fail_with: Some(OperationError {
                code: code.into(),
                message: message.into(),
            }),
            ..Self::default()
        }
    }

    pub fn executed_count(&self) -> usize {
        self.executed_count.load(Ordering::Relaxed)
    }

    pub fn rollback_count(&self) -> usize {
        self.rollback_count.load(Ordering::Relaxed)
    }

    pub fn safe_disable_count(&self) -> usize {
        self.safe_disable_count.load(Ordering::Relaxed)
    }
}

impl MutationExecutor for FakeMutationExecutor {
    fn preview(
        &self,
        kind: MutationKind,
        _payload: &serde_json::Value,
        _principal: &str,
    ) -> ReviewSummaryResponse {
        ReviewSummaryResponse {
            diff_summary: format!("{kind:?} preview"),
            provenance: "test".into(),
            risk_level: ReviewRiskLevel::Low,
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

    fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome {
        self.executed_count.fetch_add(1, Ordering::Relaxed);
        *self.last_executed.lock().unwrap() = Some(payload.clone());
        *self.last_principal.lock().unwrap() = Some(principal.to_string());
        if let Some(err) = self.fail_with.clone() {
            return MutationOutcome::Failed(err);
        }
        MutationOutcome::Completed(serde_json::json!({
            "kind": format!("{:?}", payload.kind),
        }))
    }

    fn rollback(&self, principal: &str, target_revision_id: Option<&str>) -> MutationOutcome {
        self.rollback_count.fetch_add(1, Ordering::Relaxed);
        *self.last_rollback_target.lock().unwrap() = target_revision_id.map(|s| s.to_string());
        *self.last_principal.lock().unwrap() = Some(principal.to_string());
        if let Some(err) = self.fail_with.clone() {
            return MutationOutcome::Failed(err);
        }
        MutationOutcome::Completed(serde_json::json!({
            "rolled-back-to": target_revision_id,
        }))
    }

    fn safe_disable(&self, reason: &str) -> MutationOutcome {
        self.safe_disable_count.fetch_add(1, Ordering::Relaxed);
        *self.last_safe_disable_reason.lock().unwrap() = Some(reason.to_string());
        if let Some(err) = self.fail_with.clone() {
            return MutationOutcome::Failed(err);
        }
        MutationOutcome::Completed(serde_json::json!({
            "safe-disabled": true,
            "reason": reason,
        }))
    }
}

/// Convenience: build a complete `IpcHandlerDeps` with healthy fakes for
/// integration tests that don't need to vary state.
#[allow(dead_code)]
pub fn healthy_deps() -> Arc<crate::ipc_handlers::IpcHandlerDeps> {
    use crate::ipc::NoopAuditEmitter;
    use crate::ipc_handlers::event_bus::EventBus;
    use crate::ipc_handlers::mutation_token_store::MutationTokenStore;
    use crate::ipc_handlers::operation_status_store::OperationStatusStore;
    Arc::new(crate::ipc_handlers::IpcHandlerDeps {
        auto_rules: None,
        // Block-notice mutes/author absent in test deps; the four
        // `block-notices.mutes.*` ops and `block-notices.route-to-secondary`
        // are registered as the unimplemented-operation stub.
        block_notice_mutes: None,
        block_notice_center: None,
        block_notice_author: None,
        audit_emitter: Arc::new(NoopAuditEmitter),
        health: Arc::new(FakeHealth {
            state: ServiceRuntimeState::Running,
            severity: ServiceHealthSeverity::Ok,
        }),
        policy: Arc::new(FakePolicy { revision: None }),
        adapters: Arc::new(FakeAdapters::empty()),
        rules: Arc::new(FakeRules {
            response: Mutex::new(RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: Vec::new(),
                active_revision_id: None,
            }),
            last_filter: Mutex::new(None),
        }),
        diagnostics: Arc::new(FakeDiagnostics::healthy()),
        mutation_executor: Arc::new(FakeMutationExecutor::default()),
        mutation_tokens: Arc::new(MutationTokenStore::new()),
        operations: Arc::new(OperationStatusStore::new()),
        event_bus: Arc::new(EventBus::new()),
        route_policy: Arc::new(FakeRoutePolicy::default()),
        route_policy_writer: Arc::new(FakeRoutePolicyWriter::default()),
        migration_status: Arc::new(FakeMigrationStatus::default()),
        migration_completion: Arc::new(FakeMigrationCompletion::default()),
        retention: Arc::new(FakeRetention),
        retention_writer: Arc::new(FakeRetentionWriter),
        log_retention: Arc::new(FakeLogRetention),
        log_retention_writer: Arc::new(FakeLogRetentionWriter),
        apply_failure_policy: Arc::new(FakeApplyFailurePolicy),
        apply_failure_policy_writer: Arc::new(FakeApplyFailurePolicyWriter),
        storage_usage: Arc::new(FakeStorageUsage),
        routing_pause: Arc::new(FakeRoutingPause),
        routing_pause_writer: Arc::new(FakeRoutingPauseWriter),
        autostart: Arc::new(FakeAutostart),
        autostart_writer: Arc::new(FakeAutostartWriter),
        // Alerts repo defaults to `None`; tests that
        // exercise the security alerts list/ack/resolve path build their
        // own deps and pass an `InMemorySecurityAlertsRepository`.
        alerts_repo: None,
        // Service stability config defaults to `None`
        // so the catalog-coverage test sees the unimplemented-operation
        // stub for the two ops. Tests that exercise the production path
        // attach a fake provider/writer via `with_service_stability`.
        service_stability_provider: None,
        service_stability_writer: None,
        // Archives config defaults to `None` so the
        // export handler is registered as the unimplemented-operation stub.
        archives_dir: None,
        app_version: None,
        // Host system-info absent in test deps.
        system_info: None,
        // No state DB connection
        // in test deps; `health.json`'s `state_schema_version` reads `None`.
        state_schema_version: None,
        // Fail-Closed probe absent in test deps;
        // SnapshotInterfacesHandler treats `None` as "no banner".
        fail_closed_probe: None,
        // Preset export source absent in test deps;
        // PresetExportGet is registered as the unimplemented-operation stub.
        preset_export_source: None,
        // Settings export source + clock absent in
        // test deps; SettingsExportFull is registered as the stub.
        settings_export_source: None,
        settings_export_clock: None,
        // No recompile hook in test deps;
        // route.policy.update stays persist-only here.
        route_policy_apply_trigger: None,
        // No link-provider writer in test deps;
        // route.link-provider.set resolves to the Unimplemented stub here.
        link_provider_writer: None,
        // No purger in test deps; principal-data.purge resolves to the
        // Unimplemented stub here.
        principal_data_purger: None,
        doh_resolver_store: None,
        browser_history_seeder: None,
        // No cache repo in test deps; CacheClear resolves
        // to the Unimplemented stub here.
        cache_repository: None,
        // No OS-DNS-flush port in test deps.
        dns_cache_control: None,
        // No merge source in test deps; RulesMergePreview
        // resolves to the Unimplemented stub here (catalog-coverage sees it
        // as an unwired op).
        merge_preview_source: None,
        // No traffic sampler in test deps; TrafficStats* resolve to
        // the Unimplemented stub here.
        traffic_stats: None,
        traffic_stats_writer: None,
        // No conn-trace ring in test deps; ConnTraceEntriesList resolves
        // to the Unimplemented stub here.
        conn_trace_ring: None,
        third_party_integrity: None,
        // No expected-route inputs in test deps; trace rows would
        // carry an empty `expected_route`.
        conn_trace_expectation: None,
        // No fake-IP view in test deps; cache/explain rows carry an
        // empty `fake_ip`.
        fake_ip_bindings: None,
        // Empty status in test deps (no unenforced-app
        // banner). The snapshot handler reads it as an empty list.
        app_enforcement: crate::app_enforcement_status::AppEnforcementStatus::new(),
        // Zero exclusions in test deps (no GUI warning).
        shared_ip_exemptions: crate::app_enforcement_status::SharedIpExemptionStatus::new(),
        // Disarmed block-all posture in test deps (no banner).
        block_all_posture: crate::app_enforcement_status::BlockAllPostureStatus::new(),
        // No fake-IP datapath probe in test deps; health payloads omit the
        // `fake-ip-datapath` field.
        fake_ip_datapath_probe: None,
    })
}

// ── Route-policy fakes ───────────────────────────────────────────────────────

#[derive(Default)]
pub struct FakeRoutePolicy {
    pub stored: Mutex<Option<RoutePolicyDto>>,
}

impl RoutePolicyProvider for FakeRoutePolicy {
    fn get_for_sid(&self, _sid: &str) -> Option<RoutePolicyDto> {
        self.stored.lock().unwrap().clone()
    }
}

#[derive(Default)]
pub struct FakeRoutePolicyWriter {
    pub last_sid: Mutex<Option<String>>,
    pub stored: Mutex<Option<RoutePolicyDto>>,
}

impl RoutePolicyWriter for FakeRoutePolicyWriter {
    fn update_for_sid(
        &self,
        sid: &str,
        request: &RoutePolicyUpdateRequest,
    ) -> Result<RoutePolicyDto, RoutePolicyWriteError> {
        *self.last_sid.lock().unwrap() = Some(sid.into());
        let dto = RoutePolicyDto {
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
        };
        *self.stored.lock().unwrap() = Some(dto.clone());
        Ok(dto)
    }
}

#[derive(Default)]
pub struct FakeMigrationStatus {
    pub completed: AtomicBool,
}

impl MigrationStatusProvider for FakeMigrationStatus {
    fn migration_status(&self, _sid: &str, _migration_id: &str) -> MigrationStatusGetResponse {
        let completed = self.completed.load(Ordering::SeqCst);
        MigrationStatusGetResponse {
            completed,
            completed_at: completed.then_some(0),
            detail_json: None,
        }
    }
}

#[derive(Default)]
pub struct FakeMigrationCompletion {
    pub recorded: AtomicBool,
}

impl MigrationCompletionWriter for FakeMigrationCompletion {
    fn mark_migration_complete(
        &self,
        _sid: &str,
        _migration_id: &str,
        _detail_json: Option<&str>,
    ) -> Result<MigrationCompletionRecord, RoutePolicyWriteError> {
        let already = self.recorded.swap(true, Ordering::SeqCst);
        Ok(MigrationCompletionRecord {
            recorded: !already,
            completed_at: 0,
        })
    }
}

// ── Settings fakes ───────────────────────────────────────────────────────────

use crate::ipc_handlers::payloads::{
    ApplyFailurePolicyDto, AutostartDto, LogRetentionConfigDto, LogRetentionConfigSetRequest,
    RetentionSettingsDto, RetentionSettingsSetRequest, RoutingPauseDto, StorageUsageDto,
};
use crate::ipc_handlers::providers::{
    ApplyFailurePolicyProvider, ApplyFailurePolicyWriter, AutostartProvider, AutostartWriter,
    LogRetentionConfigProvider, LogRetentionConfigWriter, RetentionSettingsProvider,
    RetentionSettingsWriter, RoutingPauseProvider, RoutingPauseWriter, SettingsWriteError,
    StorageUsageProvider,
};

pub struct FakeRetention;
impl RetentionSettingsProvider for FakeRetention {
    fn get(&self) -> RetentionSettingsDto {
        RetentionSettingsDto {
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

pub struct FakeRetentionWriter;
impl RetentionSettingsWriter for FakeRetentionWriter {
    fn set(
        &self,
        request: &RetentionSettingsSetRequest,
    ) -> Result<RetentionSettingsDto, SettingsWriteError> {
        Ok(RetentionSettingsDto {
            superseded_days: request.superseded_days,
            superseded_count_cap: request.superseded_count_cap,
            rejected_days: request.rejected_days,
            rolledback_days: request.rolledback_days,
            rolledback_count_cap: request.rolledback_count_cap,
            pin_lkg: request.pin_lkg,
            last_cleanup_at: None,
            updated_at: 0,
        })
    }
}

pub struct FakeLogRetention;
impl LogRetentionConfigProvider for FakeLogRetention {
    fn get(&self) -> LogRetentionConfigDto {
        LogRetentionConfigDto {
            log_max_age_days: 90,
            log_max_size_bytes: 52_428_800,
            audit_max_age_days: 365,
            audit_max_size_bytes: 52_428_800,
            updated_at: 0,
        }
    }
}

pub struct FakeLogRetentionWriter;
impl LogRetentionConfigWriter for FakeLogRetentionWriter {
    fn set(
        &self,
        request: &LogRetentionConfigSetRequest,
    ) -> Result<LogRetentionConfigDto, SettingsWriteError> {
        Ok(LogRetentionConfigDto {
            log_max_age_days: request.log_max_age_days,
            log_max_size_bytes: request.log_max_size_bytes,
            audit_max_age_days: request.audit_max_age_days,
            audit_max_size_bytes: request.audit_max_size_bytes,
            updated_at: 0,
        })
    }
}

pub struct FakeApplyFailurePolicy;
impl ApplyFailurePolicyProvider for FakeApplyFailurePolicy {
    fn get(&self) -> ApplyFailurePolicyDto {
        ApplyFailurePolicyDto {
            policy: "all-or-nothing".into(),
            updated_at: 0,
            set_by_sid: None,
        }
    }
}

pub struct FakeApplyFailurePolicyWriter;
impl ApplyFailurePolicyWriter for FakeApplyFailurePolicyWriter {
    fn set(
        &self,
        slug: &str,
        sid: Option<&str>,
    ) -> Result<ApplyFailurePolicyDto, SettingsWriteError> {
        Ok(ApplyFailurePolicyDto {
            policy: slug.into(),
            updated_at: 0,
            set_by_sid: sid.map(str::to_string),
        })
    }
}

pub struct FakeStorageUsage;
impl StorageUsageProvider for FakeStorageUsage {
    fn measure(&self) -> StorageUsageDto {
        StorageUsageDto {
            state_db_bytes: None,
            cache_db_bytes: None,
            operational_logs_bytes: 0,
            audit_logs_bytes: 0,
            total_bytes: 0,
            scanned_at: 0,
        }
    }
}

pub struct FakeRoutingPause;
impl RoutingPauseProvider for FakeRoutingPause {
    fn get(&self, sid: &str) -> RoutingPauseDto {
        RoutingPauseDto {
            sid: sid.into(),
            paused: false,
            paused_at: None,
            pause_reason: None,
            updated_at: 0,
        }
    }
}

pub struct FakeRoutingPauseWriter;
impl RoutingPauseWriter for FakeRoutingPauseWriter {
    fn toggle(
        &self,
        sid: &str,
        paused: bool,
        reason: Option<&str>,
    ) -> Result<RoutingPauseDto, SettingsWriteError> {
        Ok(RoutingPauseDto {
            sid: sid.into(),
            paused,
            paused_at: if paused { Some(0) } else { None },
            pause_reason: reason.map(str::to_string),
            updated_at: 0,
        })
    }
}

pub struct FakeAutostart;
impl AutostartProvider for FakeAutostart {
    fn get(&self) -> AutostartDto {
        AutostartDto {
            enabled: false,
            last_known_state: "absent".into(),
            overridden_value: None,
            updated_at: 0,
        }
    }
}

pub struct FakeAutostartWriter;
impl AutostartWriter for FakeAutostartWriter {
    fn toggle(&self, enabled: bool) -> Result<AutostartDto, SettingsWriteError> {
        Ok(AutostartDto {
            enabled,
            last_known_state: if enabled { "enabled" } else { "disabled" }.into(),
            overridden_value: None,
            updated_at: 0,
        })
    }
}

/// Machine-wide settings source that answers only the administrative rules
/// lock; every other field stays at its default. Lets the mutation/rollback
/// handler tests state the one thing they are about.
pub struct FakeRulesLock {
    allow: Option<bool>,
}

impl FakeRulesLock {
    /// A machine whose administrator has frozen rule authoring.
    pub fn locked() -> Arc<dyn ServiceStabilityConfigProvider> {
        Arc::new(Self { allow: Some(false) })
    }

    /// A machine that explicitly allows every user to author rules.
    pub fn unlocked() -> Arc<dyn ServiceStabilityConfigProvider> {
        Arc::new(Self { allow: Some(true) })
    }

    /// A row that has never carried an opinion (older service, wiped DB).
    pub fn unset() -> Arc<dyn ServiceStabilityConfigProvider> {
        Arc::new(Self { allow: None })
    }
}

impl ServiceStabilityConfigProvider for FakeRulesLock {
    fn get(&self) -> nrr_shared::ipc_payloads::ServiceStabilityConfigDto {
        nrr_shared::ipc_payloads::ServiceStabilityConfigDto {
            allow_user_rule_edits: self.allow,
            ..Default::default()
        }
    }
}

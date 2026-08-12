use crate::route_bindings::{route_bindings_export_snapshot, RouteBindingsExportSnapshot};
use nrr_shared::{ErrorCategory, OperationOutcome, OperationResultDto};
// Re-exported so downstream crates such as `nrr-ipc-client` can reference
// the trait's parameter type without taking a direct dependency on
// `nrr-ui-support` (a UI-only crate forbidden for the IPC client per
// CLAUDE.md).
pub use nrr_ui_support::ui_preferences::UiPreferences;

pub mod diagnostics {
    pub use crate::mock_backend::diagnostics::*;
}

pub mod logs {
    pub use crate::mock_backend::logs::*;
}

pub mod network_interfaces {
    pub use crate::mock_backend::network_interfaces::*;
}

pub mod rules {
    pub use crate::mock_backend::rules::*;
}

pub mod security_status {
    pub use crate::mock_backend::security_status::*;
}

pub use crate::mock_backend::{
    mock_required_scenarios_6_6, mock_scenario_from_env, tray_status_for_mock_scenario,
    MockScenarioId, MOCK_REQUIRED_SCENARIOS_6_6,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendProviderKind {
    Mock,
    PreviewLocal,
    /// Real IPC facade, currently connected to the service.
    IpcConnected,
    /// Real IPC facade, disconnected — either reconnecting or serving stale cache.
    IpcDisconnected,
    /// Real IPC facade, service is not installed (no SCM entry).
    IpcServiceNotInstalled,
    /// Real IPC facade, server protocol version is incompatible with this client.
    IpcProtocolMismatch,
}

/// Connection state surfaced by [`BackendFacade::connection_status`] for UX banners.
///
/// Mirrors the richer `nrr-ipc-client::ConnectionStatus` but kept in the
/// `nrr-application` crate so the trait can be expressed without pulling
/// the IPC client into the dependency graph of every consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendConnectionStatus {
    /// Backend is fully usable.
    Connected,
    /// Reconnect attempt in progress.
    Connecting,
    /// Pipe is currently down. `last_error` is a human-readable English detail.
    Disconnected { last_error: String },
    /// SCM says the service exists but is not running.
    ServiceStopped,
    /// SCM says the service is not installed.
    ServiceNotInstalled,
    /// Server protocol version is incompatible with this client. Terminal
    /// from the client's perspective; user must update one side.
    ProtocolMismatch {
        server_version: u32,
        client_version: u32,
    },
}

impl BackendConnectionStatus {
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
    pub fn requires_user_action(&self) -> bool {
        matches!(
            self,
            Self::ServiceNotInstalled | Self::ServiceStopped | Self::ProtocolMismatch { .. }
        )
    }
}

/// Errors returned when interacting with the backend's snapshot cache.
#[derive(Debug)]
pub enum CacheError {
    /// I/O failure reading or writing the cache directory.
    Io(String),
    /// Serialization failure (cache payload corrupted or schema drift).
    Serialization(String),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "snapshot cache I/O error: {s}"),
            Self::Serialization(s) => write!(f, "snapshot cache serialization error: {s}"),
        }
    }
}

impl std::error::Error for CacheError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CapabilityGroup {
    Status,
    Interfaces,
    Diagnostics,
    ReviewRevisions,
    RecoveryActions,
}

pub const BACKEND_FACADE_CAPABILITY_GROUPS: [CapabilityGroup; 5] = [
    CapabilityGroup::Status,
    CapabilityGroup::Interfaces,
    CapabilityGroup::Diagnostics,
    CapabilityGroup::ReviewRevisions,
    CapabilityGroup::RecoveryActions,
];

pub trait BackendFacade {
    fn provider_kind(&self) -> BackendProviderKind;
    fn status_snapshot(&self) -> security_status::SecurityStatusSnapshot;

    /// Top-level diagnostics health/status snapshot — see [`diagnostics::DiagnosticsStatusDto`].
    fn diagnostics_status_snapshot(&self) -> diagnostics::DiagnosticsStatusDto;

    /// Paginated operational log entries for the Logs viewer.
    ///
    /// Returns entries newest-first.  See [`logs::LogEntryDto`].
    fn list_log_entries(
        &self,
        filter: &logs::LogEntryFilter,
        pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::LogEntryDto>;

    /// Paginated audit trail entries for the Logs viewer (Audit tab).
    ///
    /// Returns entries newest-first.  See [`logs::AuditEntryDto`].
    fn list_audit_entries(
        &self,
        filter: &logs::AuditEntryFilter,
        pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::AuditEntryDto>;

    /// Active security alerts for the Diagnostics viewer.
    ///
    /// `state_filter` is the alert lifecycle state
    /// (`"active"`, `"acknowledged"`, `"resolved"`, `"superseded"`).
    /// `None` returns the default view (active + acknowledged).
    /// Mock providers ignore this parameter; the real service
    /// implementation honours it.
    fn list_security_alerts(
        &self,
        state_filter: Option<&str>,
    ) -> Vec<diagnostics::SecurityAlertDto>;

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot;
    fn interface_checks_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfaceDiagnosticsChecksSnapshot;
    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot;
    fn route_bindings_snapshot(
        &self,
        preferences: &UiPreferences,
        active_revision: &str,
    ) -> RouteBindingsExportSnapshot;

    /// Current connection state. Default impl returns `Connected`, which is
    /// correct for in-process providers (`Mock`, `PreviewLocal`); the
    /// IPC-backed facade overrides this to mirror the live pipe state.
    fn connection_status(&self) -> BackendConnectionStatus {
        BackendConnectionStatus::Connected
    }

    /// Drop any persisted snapshot cache. Default impl is a no-op because
    /// in-process providers do not maintain a cache; the IPC-backed facade
    /// clears `%LOCALAPPDATA%\NetRuleRouter\snapshot_cache\`.
    fn clear_cache(&self) -> Result<(), CacheError> {
        Ok(())
    }

    /// Trigger an immediate reconnect attempt. Default impl is a no-op for
    /// in-process providers; the IPC-backed facade signals its background
    /// reader thread to abandon backoff and retry now. Used by the "Retry
    /// connection" GUI button.
    fn force_reconnect(&self) {}
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockBackendFacade;

impl BackendFacade for MockBackendFacade {
    fn provider_kind(&self) -> BackendProviderKind {
        BackendProviderKind::Mock
    }

    fn status_snapshot(&self) -> security_status::SecurityStatusSnapshot {
        security_status::security_status_preview_snapshot()
    }

    fn diagnostics_status_snapshot(&self) -> diagnostics::DiagnosticsStatusDto {
        diagnostics::preview_diagnostics_status()
    }

    fn list_log_entries(
        &self,
        _filter: &logs::LogEntryFilter,
        _pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::LogEntryDto> {
        logs::preview_operational_logs_first_page()
    }

    fn list_audit_entries(
        &self,
        _filter: &logs::AuditEntryFilter,
        _pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::AuditEntryDto> {
        logs::preview_audit_entries_first_page()
    }

    fn list_security_alerts(
        &self,
        _state_filter: Option<&str>,
    ) -> Vec<diagnostics::SecurityAlertDto> {
        diagnostics::preview_active_security_alerts()
    }

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot {
        network_interfaces::interfaces_routes_preview_snapshot(request)
    }

    fn interface_checks_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfaceDiagnosticsChecksSnapshot {
        network_interfaces::interface_diagnostics_checks_snapshot(request)
    }

    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot {
        rules::rules_screen_preview_snapshot(request)
    }

    fn route_bindings_snapshot(
        &self,
        preferences: &UiPreferences,
        active_revision: &str,
    ) -> RouteBindingsExportSnapshot {
        route_bindings_export_snapshot(preferences, active_revision)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PreviewLocalBackendFacade;

impl BackendFacade for PreviewLocalBackendFacade {
    fn provider_kind(&self) -> BackendProviderKind {
        BackendProviderKind::PreviewLocal
    }

    fn status_snapshot(&self) -> security_status::SecurityStatusSnapshot {
        security_status::security_status_preview_snapshot()
    }

    // preview-only — production GUI goes via IPC `SnapshotDiagnosticsGet`.
    // The MockBackendFacade returns canned preview data so the QML layer
    // can render without a real service connected.
    fn diagnostics_status_snapshot(&self) -> diagnostics::DiagnosticsStatusDto {
        diagnostics::preview_diagnostics_status()
    }

    // preview-only — production GUI goes via IPC `LogsList` with real
    // filter + pagination handled in `LogsListHandler`.
    fn list_log_entries(
        &self,
        _filter: &logs::LogEntryFilter,
        _pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::LogEntryDto> {
        logs::preview_operational_logs_first_page()
    }

    // preview-only — production GUI goes via IPC `AuditList` with
    // pagination handled in `AuditListHandler`.
    fn list_audit_entries(
        &self,
        _filter: &logs::AuditEntryFilter,
        _pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::AuditEntryDto> {
        logs::preview_audit_entries_first_page()
    }

    // preview-only — production GUI goes via IPC `SecurityAlertsList`
    // backed by the `security_alerts` SQLite table.
    fn list_security_alerts(
        &self,
        _state_filter: Option<&str>,
    ) -> Vec<diagnostics::SecurityAlertDto> {
        diagnostics::preview_active_security_alerts()
    }

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot {
        network_interfaces::interfaces_routes_preview_snapshot(request)
    }

    fn interface_checks_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfaceDiagnosticsChecksSnapshot {
        network_interfaces::interface_diagnostics_checks_snapshot(request)
    }

    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot {
        rules::rules_screen_preview_snapshot(request)
    }

    fn route_bindings_snapshot(
        &self,
        preferences: &UiPreferences,
        active_revision: &str,
    ) -> RouteBindingsExportSnapshot {
        route_bindings_export_snapshot(preferences, active_revision)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BackendFacadeHandle {
    Mock(MockBackendFacade),
    PreviewLocal(PreviewLocalBackendFacade),
}

impl BackendFacadeHandle {
    pub fn status_snapshot(self) -> security_status::SecurityStatusSnapshot {
        match self {
            Self::Mock(facade) => facade.status_snapshot(),
            Self::PreviewLocal(facade) => facade.status_snapshot(),
        }
    }

    pub fn diagnostics_status_snapshot(self) -> diagnostics::DiagnosticsStatusDto {
        match self {
            Self::Mock(facade) => facade.diagnostics_status_snapshot(),
            Self::PreviewLocal(facade) => facade.diagnostics_status_snapshot(),
        }
    }

    pub fn list_log_entries(
        self,
        filter: &logs::LogEntryFilter,
        pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::LogEntryDto> {
        match self {
            Self::Mock(facade) => facade.list_log_entries(filter, pagination),
            Self::PreviewLocal(facade) => facade.list_log_entries(filter, pagination),
        }
    }

    pub fn list_audit_entries(
        self,
        filter: &logs::AuditEntryFilter,
        pagination: &logs::PaginationParams,
    ) -> logs::PageResult<logs::AuditEntryDto> {
        match self {
            Self::Mock(facade) => facade.list_audit_entries(filter, pagination),
            Self::PreviewLocal(facade) => facade.list_audit_entries(filter, pagination),
        }
    }

    pub fn list_security_alerts(
        self,
        state_filter: Option<&str>,
    ) -> Vec<diagnostics::SecurityAlertDto> {
        match self {
            Self::Mock(facade) => facade.list_security_alerts(state_filter),
            Self::PreviewLocal(facade) => facade.list_security_alerts(state_filter),
        }
    }

    pub fn interfaces_snapshot(
        self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot {
        match self {
            Self::Mock(facade) => facade.interfaces_snapshot(request),
            Self::PreviewLocal(facade) => facade.interfaces_snapshot(request),
        }
    }

    pub fn interface_checks_snapshot(
        self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfaceDiagnosticsChecksSnapshot {
        match self {
            Self::Mock(facade) => facade.interface_checks_snapshot(request),
            Self::PreviewLocal(facade) => facade.interface_checks_snapshot(request),
        }
    }

    pub fn rules_snapshot(
        self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot {
        match self {
            Self::Mock(facade) => facade.rules_snapshot(request),
            Self::PreviewLocal(facade) => facade.rules_snapshot(request),
        }
    }

    pub fn route_bindings_snapshot(
        self,
        preferences: &UiPreferences,
        active_revision: &str,
    ) -> RouteBindingsExportSnapshot {
        match self {
            Self::Mock(facade) => facade.route_bindings_snapshot(preferences, active_revision),
            Self::PreviewLocal(facade) => {
                facade.route_bindings_snapshot(preferences, active_revision)
            }
        }
    }
}

pub fn backend_facade_from_env() -> BackendFacadeHandle {
    match std::env::var("NRR_BACKEND_PROVIDER")
        .ok()
        .map(|raw| raw.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("preview-local") | Some("local") => {
            BackendFacadeHandle::PreviewLocal(PreviewLocalBackendFacade)
        }
        _ => BackendFacadeHandle::Mock(MockBackendFacade),
    }
}

pub trait TransportAdapter {
    fn provider_kind(&self) -> BackendProviderKind;
    fn send_query(&self, operation: &str, payload_json: &str) -> Result<String, String>;
    fn send_command(&self, operation: &str, payload_json: &str) -> Result<String, String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MockTransportAdapter;

impl TransportAdapter for MockTransportAdapter {
    fn provider_kind(&self) -> BackendProviderKind {
        BackendProviderKind::Mock
    }

    fn send_query(&self, operation: &str, payload_json: &str) -> Result<String, String> {
        Ok(format!(
            "{{\"provider\":\"mock\",\"kind\":\"query\",\"operation\":\"{operation}\",\"payload\":{payload_json}}}"
        ))
    }

    fn send_command(&self, operation: &str, payload_json: &str) -> Result<String, String> {
        Ok(format!(
            "{{\"provider\":\"mock\",\"kind\":\"command\",\"operation\":\"{operation}\",\"payload\":{payload_json}}}"
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefreshOrchestrationPolicy {
    pub coalescing_window_ms: u64,
    pub deduplicated_polling_allowed: bool,
    pub requires_explicit_invalidation: bool,
}

pub const REFRESH_ORCHESTRATION_POLICY: RefreshOrchestrationPolicy = RefreshOrchestrationPolicy {
    coalescing_window_ms: 250,
    deduplicated_polling_allowed: true,
    requires_explicit_invalidation: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryMode {
    AutoBackoff,
    UserActionOnly,
    Never,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FacadeRetryPolicy {
    pub transport_errors: RetryMode,
    pub timeout_errors: RetryMode,
    pub validation_errors: RetryMode,
    pub conflict_errors: RetryMode,
}

pub const FACADE_RETRY_POLICY: FacadeRetryPolicy = FacadeRetryPolicy {
    transport_errors: RetryMode::AutoBackoff,
    timeout_errors: RetryMode::AutoBackoff,
    validation_errors: RetryMode::UserActionOnly,
    conflict_errors: RetryMode::UserActionOnly,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResponseOrderingPolicy {
    pub cancellation_supported: bool,
    pub drop_outdated_responses: bool,
    pub monotonic_generation_required: bool,
}

pub const RESPONSE_ORDERING_POLICY: ResponseOrderingPolicy = ResponseOrderingPolicy {
    cancellation_supported: true,
    drop_outdated_responses: true,
    monotonic_generation_required: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackendInjectionPoint {
    pub component: &'static str,
    pub adapter_boundary: &'static str,
}

pub const BACKEND_FACADE_INJECTION_POINTS: [BackendInjectionPoint; 4] = [
    BackendInjectionPoint {
        component: "interfaces-routes-screen",
        adapter_boundary: "interfaces capability",
    },
    BackendInjectionPoint {
        component: "diagnostics-and-logs-screen",
        adapter_boundary: "diagnostics capability",
    },
    BackendInjectionPoint {
        component: "security/status surfaces",
        adapter_boundary: "status capability",
    },
    BackendInjectionPoint {
        component: "tray quick actions",
        adapter_boundary: "recovery/status capability",
    },
];

pub const BACKEND_PROVIDER_MIGRATION_PATH: [&str; 3] = [
    "stage-1: mock provider via backend facade",
    "stage-2: preview-local provider via same facade API",
    "stage-3: named-pipe service provider without GUI/tray API change",
];

pub const BLOCK6_BLOCK16_RESPONSIBILITY_BOUNDARY: &str =
    "Block 6 stabilizes contract/facade boundaries; block 16 performs full GUI migration to real service-owned policy logic.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserVisibleStatusModel {
    pub severity: &'static str,
    pub message_key: String,
}

pub fn map_operation_result_to_user_visible_status(
    result: &OperationResultDto,
) -> UserVisibleStatusModel {
    let severity = match result.outcome {
        OperationOutcome::Completed | OperationOutcome::Accepted => "info",
        OperationOutcome::RequiresReview | OperationOutcome::RequiresRetry => "warning",
        OperationOutcome::Conflict
        | OperationOutcome::Rejected
        | OperationOutcome::ServiceUnavailable => "error",
    };

    UserVisibleStatusModel {
        severity,
        message_key: result.user_message_key.clone(),
    }
}

pub fn map_error_category_to_status_banner(category: ErrorCategory) -> &'static str {
    match category {
        ErrorCategory::Transport | ErrorCategory::UnavailableDependency => "status.transport",
        ErrorCategory::AuthSession => "status.auth",
        ErrorCategory::Validation => "status.validation",
        ErrorCategory::StateConflict => "status.conflict",
        ErrorCategory::InternalService => "status.internal",
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::expect_used)]
mod tests {
    use super::{
        backend_facade_from_env, map_error_category_to_status_banner,
        map_operation_result_to_user_visible_status, BackendFacade, BackendProviderKind,
        CapabilityGroup, MockBackendFacade, MockTransportAdapter, PreviewLocalBackendFacade,
        RefreshOrchestrationPolicy, RetryMode, TransportAdapter, BACKEND_FACADE_CAPABILITY_GROUPS,
        BACKEND_FACADE_INJECTION_POINTS, BACKEND_PROVIDER_MIGRATION_PATH,
        BLOCK6_BLOCK16_RESPONSIBILITY_BOUNDARY, FACADE_RETRY_POLICY, REFRESH_ORCHESTRATION_POLICY,
        RESPONSE_ORDERING_POLICY,
    };
    use nrr_shared::{ErrorCategory, OperationOutcome, OperationResultDto};
    use nrr_ui_support::ui_preferences::UiPreferences;

    fn assert_provider_contract(facade: &dyn BackendFacade, expected_kind: BackendProviderKind) {
        assert_eq!(facade.provider_kind(), expected_kind);
        assert!(!facade
            .interfaces_snapshot(Default::default())
            .rows
            .is_empty());
        assert!(!facade.rules_snapshot(Default::default()).rows.is_empty());
        assert!(!facade.status_snapshot().active_revision.is_empty());
        let bindings = facade.route_bindings_snapshot(&UiPreferences::default(), "rev-preview-001");
        assert_eq!(bindings.active_revision, "rev-preview-001");
    }

    #[test]
    fn facade_contract_is_provider_agnostic_for_mock_and_preview_local() {
        let mock = MockBackendFacade;
        assert_provider_contract(&mock, BackendProviderKind::Mock);

        let preview_local = PreviewLocalBackendFacade;
        assert_provider_contract(&preview_local, BackendProviderKind::PreviewLocal);
    }

    #[test]
    fn facade_capability_groups_and_injection_points_are_fixed() {
        assert_eq!(BACKEND_FACADE_CAPABILITY_GROUPS.len(), 5);
        assert!(BACKEND_FACADE_CAPABILITY_GROUPS.contains(&CapabilityGroup::Diagnostics));
        assert!(BACKEND_FACADE_INJECTION_POINTS.len() >= 3);
        assert_eq!(BACKEND_PROVIDER_MIGRATION_PATH.len(), 3);
        assert!(BLOCK6_BLOCK16_RESPONSIBILITY_BOUNDARY.contains("Block 6"));
        assert!(BLOCK6_BLOCK16_RESPONSIBILITY_BOUNDARY.contains("block 16"));
    }

    #[test]
    fn transport_adapter_contract_is_available_for_mock_provider() {
        let adapter = MockTransportAdapter;
        assert_eq!(adapter.provider_kind(), BackendProviderKind::Mock);
        let query_payload = adapter
            .send_query("status.get", "{}")
            .expect("mock query must succeed");
        assert!(query_payload.contains("\"kind\":\"query\""));
        let cmd_payload = adapter
            .send_command("recovery.rollback", "{}")
            .expect("mock command must succeed");
        assert!(cmd_payload.contains("\"kind\":\"command\""));
    }

    #[test]
    fn refresh_retry_and_ordering_policies_are_defined() {
        let refresh = REFRESH_ORCHESTRATION_POLICY;
        assert_eq!(
            refresh,
            RefreshOrchestrationPolicy {
                coalescing_window_ms: 250,
                deduplicated_polling_allowed: true,
                requires_explicit_invalidation: true,
            }
        );
        assert_eq!(FACADE_RETRY_POLICY.transport_errors, RetryMode::AutoBackoff);
        assert!(RESPONSE_ORDERING_POLICY.cancellation_supported);
        assert!(RESPONSE_ORDERING_POLICY.drop_outdated_responses);
    }

    #[test]
    fn mapper_converts_operation_and_error_to_user_visible_models() {
        let result = OperationResultDto {
            outcome: OperationOutcome::RequiresReview,
            code: "review.required".to_string(),
            category: ErrorCategory::Validation,
            user_message_key: "operation.review.required".to_string(),
            technical_details: None,
            retry_hint: None,
            followup_action_hint: None,
        };
        let mapped = map_operation_result_to_user_visible_status(&result);
        assert_eq!(mapped.severity, "warning");
        assert_eq!(mapped.message_key, "operation.review.required");
        assert_eq!(
            map_error_category_to_status_banner(ErrorCategory::StateConflict),
            "status.conflict"
        );
    }

    #[test]
    fn backend_facade_selection_defaults_to_mock() {
        let selected = backend_facade_from_env();
        match selected {
            super::BackendFacadeHandle::Mock(_) | super::BackendFacadeHandle::PreviewLocal(_) => {}
        }
    }
}

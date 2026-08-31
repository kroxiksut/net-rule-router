use crate::route_bindings::{route_bindings_export_snapshot, RouteBindingsExportSnapshot};
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
    /// The service is running and refused this client — wrong account, or no
    /// free connection slot. Needs the user, not a retry.
    Refused { reason: String },
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
    fn list_security_alerts(&self, state_filter: Option<&str>) -> diagnostics::SecurityAlertsView;

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

    fn list_security_alerts(&self, _state_filter: Option<&str>) -> diagnostics::SecurityAlertsView {
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
    fn list_security_alerts(&self, _state_filter: Option<&str>) -> diagnostics::SecurityAlertsView {
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

#[cfg(test)]
#[allow(clippy::assertions_on_constants, clippy::expect_used)]
mod tests {
    use super::{BackendFacade, BackendProviderKind, MockBackendFacade, PreviewLocalBackendFacade};
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
}

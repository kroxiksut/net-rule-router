use nrr_shared::diagnostics_dto::{DiagnosticsStatusDto, SecurityAlertsView};

// One re-export path for these preview modules: `crate::mock_backend`.
// Consumers reach them as `nrr_application::mock_backend::{diagnostics,
// network_interfaces, rules}`, not through this module too.
use crate::mock_backend::{diagnostics, network_interfaces, rules};

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
/// Mirrors `nrr-ipc-client::ConnectionStatus`, kept here so the trait does not
/// pull the IPC client into every consumer. Which states need the user is
/// decided once, by `ConnectionStatus::requires_user_action`.
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
}

pub trait BackendFacade {
    fn provider_kind(&self) -> BackendProviderKind;

    /// Top-level diagnostics health/status snapshot.
    fn diagnostics_status_snapshot(&self) -> DiagnosticsStatusDto;

    /// Security alerts. `state_filter` is the lifecycle state (`"active"`,
    /// `"acknowledged"`, `"resolved"`, `"superseded"`); `None` is the default
    /// view (active + acknowledged). Preview providers ignore it.
    fn list_security_alerts(&self, state_filter: Option<&str>) -> SecurityAlertsView;

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot;
    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot;

    /// Current connection state. `Connected` for in-process providers; the
    /// IPC-backed facade mirrors the live channel.
    fn connection_status(&self) -> BackendConnectionStatus {
        BackendConnectionStatus::Connected
    }

    /// Retry the connection now instead of waiting out the backoff. No-op for
    /// in-process providers.
    fn force_reconnect(&self) {}
}

/// Preview data over an adapter enumeration: this host's by default.
#[derive(Clone, Copy)]
pub struct MockBackendFacade {
    interface_rows: &'static dyn network_interfaces::InterfaceRowsPort,
}

impl MockBackendFacade {
    /// Over another enumeration, so a test does not read this host's adapters.
    #[must_use]
    pub fn over(interface_rows: &'static dyn network_interfaces::InterfaceRowsPort) -> Self {
        Self { interface_rows }
    }
}

impl Default for MockBackendFacade {
    fn default() -> Self {
        Self::over(network_interfaces::local_interface_rows())
    }
}

impl std::fmt::Debug for MockBackendFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockBackendFacade").finish_non_exhaustive()
    }
}

impl BackendFacade for MockBackendFacade {
    fn provider_kind(&self) -> BackendProviderKind {
        BackendProviderKind::Mock
    }

    fn diagnostics_status_snapshot(&self) -> DiagnosticsStatusDto {
        diagnostics::preview_diagnostics_status()
    }

    fn list_security_alerts(&self, _state_filter: Option<&str>) -> SecurityAlertsView {
        diagnostics::preview_active_security_alerts()
    }

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot {
        network_interfaces::interfaces_snapshot_from(self.interface_rows, &request)
    }

    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot {
        rules::rules_screen_preview_snapshot(request)
    }
}

/// Same data as [`MockBackendFacade`], reserved for the future local-only
/// enforcement preview path — distinct [`BackendProviderKind`] so callers can
/// tell the two apart, everything else delegated rather than duplicated.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreviewLocalBackendFacade {
    inner: MockBackendFacade,
}

impl PreviewLocalBackendFacade {
    /// See [`MockBackendFacade::over`].
    #[must_use]
    pub fn over(interface_rows: &'static dyn network_interfaces::InterfaceRowsPort) -> Self {
        Self {
            inner: MockBackendFacade::over(interface_rows),
        }
    }
}

impl BackendFacade for PreviewLocalBackendFacade {
    fn provider_kind(&self) -> BackendProviderKind {
        BackendProviderKind::PreviewLocal
    }

    fn diagnostics_status_snapshot(&self) -> DiagnosticsStatusDto {
        self.inner.diagnostics_status_snapshot()
    }

    fn list_security_alerts(&self, state_filter: Option<&str>) -> SecurityAlertsView {
        self.inner.list_security_alerts(state_filter)
    }

    fn interfaces_snapshot(
        &self,
        request: network_interfaces::RouteSelectionRequest,
    ) -> network_interfaces::InterfacesRoutesPreviewSnapshot {
        self.inner.interfaces_snapshot(request)
    }

    fn rules_snapshot(
        &self,
        request: rules::RulesScreenRequest,
    ) -> rules::RulesScreenPreviewSnapshot {
        self.inner.rules_snapshot(request)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        network_interfaces, BackendFacade, BackendProviderKind, MockBackendFacade,
        PreviewLocalBackendFacade,
    };
    use network_interfaces::{InterfacesDataSource, MockInterfaceRows};

    /// Fixed rows, so the contract is checked the same on every host.
    fn fixed_rows() -> &'static MockInterfaceRows {
        Box::leak(Box::new(MockInterfaceRows::new(
            InterfacesDataSource::FallbackMock,
            network_interfaces::fallback_rows(),
        )))
    }

    fn assert_provider_contract(facade: &dyn BackendFacade, expected_kind: BackendProviderKind) {
        assert_eq!(facade.provider_kind(), expected_kind);
        let interfaces = facade.interfaces_snapshot(Default::default());
        assert_eq!(interfaces.data_source, InterfacesDataSource::FallbackMock);
        assert_eq!(
            interfaces.rows.len(),
            network_interfaces::fallback_rows().len()
        );
        assert!(!facade.rules_snapshot(Default::default()).rows.is_empty());
    }

    #[test]
    fn facade_contract_is_provider_agnostic_for_mock_and_preview_local() {
        let rows = fixed_rows();
        assert_provider_contract(&MockBackendFacade::over(rows), BackendProviderKind::Mock);
        assert_provider_contract(
            &PreviewLocalBackendFacade::over(rows),
            BackendProviderKind::PreviewLocal,
        );
        assert_eq!(rows.probe_requests(), vec![false, false], "never probes");
    }
}

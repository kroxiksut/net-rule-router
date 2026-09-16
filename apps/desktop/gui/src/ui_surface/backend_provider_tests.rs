use super::*;

#[test]
fn mock_and_preview_local_are_not_service_backed() {
    assert!(!backend_provider_is_service_backed(
        BackendProviderKind::Mock
    ));
    assert!(!backend_provider_is_service_backed(
        BackendProviderKind::PreviewLocal
    ));
}

/// Every IPC variant counts as service-backed, including the degraded ones:
/// the transport is real and the reconnect worker keeps trying, so the GUI
/// must fall back to `backendStatus.kind` (which already paints the banner)
/// rather than treating a transient outage as "no service at all".
#[test]
fn every_ipc_variant_is_service_backed() {
    for kind in [
        BackendProviderKind::IpcConnected,
        BackendProviderKind::IpcDisconnected,
        BackendProviderKind::IpcServiceNotInstalled,
        BackendProviderKind::IpcProtocolMismatch,
    ] {
        assert!(backend_provider_is_service_backed(kind), "{kind:?}");
    }
}

/// The launcher hands the GUI a `MockBackendFacade` when the IPC probe
/// fails, so the cold-start snapshot is mock data even on the production
/// path — and the flag must say so.
#[test]
fn ipc_fallback_to_mock_reports_not_service_backed() {
    use nrr_application::backend_facade::MockBackendFacade;
    let facade = MockBackendFacade;
    let backend: &dyn BackendFacade = &facade;
    assert!(!backend_provider_is_service_backed(backend.provider_kind()));
}

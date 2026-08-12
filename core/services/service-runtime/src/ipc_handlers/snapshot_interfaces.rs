//! `SnapshotInterfacesGet` handler — returns the latest adapter
//! snapshot. Backed by [`AdaptersSnapshotProvider`] so tests can stub
//! without spinning up Windows.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::SnapshotInterfacesRequest;
use crate::ipc_handlers::providers::{AdaptersSnapshotProvider, FailClosedStateProbe};

pub struct SnapshotInterfacesHandler {
    adapters: Arc<dyn AdaptersSnapshotProvider>,
    /// Optional Fail-Closed probe. When wired, the
    /// handler composes per-SID `SecondaryRouteStateDto` after the
    /// adapter enumeration and injects it into the response so the
    /// GUI banner gets a fresh value on every snapshot read. `None`
    /// keeps the banner hidden.
    fail_closed_probe: Option<Arc<dyn FailClosedStateProbe>>,
}

impl SnapshotInterfacesHandler {
    pub fn new(adapters: Arc<dyn AdaptersSnapshotProvider>) -> Self {
        Self {
            adapters,
            fail_closed_probe: None,
        }
    }

    /// Chainable wiring for the Fail-Closed probe. Production callers
    /// thread the `ProductionFailClosedProbe` here; test code that
    /// doesn't care about the banner can omit this entirely.
    pub fn with_fail_closed_probe(mut self, probe: Arc<dyn FailClosedStateProbe>) -> Self {
        self.fail_closed_probe = Some(probe);
        self
    }
}

impl IpcHandler for SnapshotInterfacesHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: SnapshotInterfacesRequest = if request.payload.is_null() {
            SnapshotInterfacesRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("snapshot.interfaces.get payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let mut resp = self.adapters.adapters_snapshot(req.force_refresh);
        if let Some(probe) = &self.fail_closed_probe {
            resp.secondary = probe.probe(ctx.caller_stored(), &resp.adapters);
        }
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("snapshot.interfaces.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{AdapterEntry, SnapshotInterfacesResponse};
    use crate::ipc_handlers::test_fakes::FakeAdapters;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::atomic::Ordering;

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-si".into(),
            correlation_id: None,
            operation: IpcOperationName::SnapshotInterfacesGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn returns_adapters_from_provider() {
        let provider = Arc::new(FakeAdapters::with_one(AdapterEntry {
            persistent_id: "pid-1".into(),
            adapter_name: "Wi-Fi".into(),
            ipv6_if_index: 12,
            physical_address: Some("aa:bb:cc:dd:ee:ff".into()),
            windows_name: "Wireless LAN".into(),
            interface_description: "Intel(R) Dual Band".into(),
            interface_type: "ieee80211".into(),
            oper_status: "up".into(),
        }));
        let h = SnapshotInterfacesHandler::new(provider);
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: SnapshotInterfacesResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.data_source, "windows-live");
        assert_eq!(parsed.adapters.len(), 1);
        assert_eq!(parsed.adapters[0].persistent_id, "pid-1");
    }

    #[test]
    fn force_refresh_flag_is_propagated_to_provider() {
        let provider = Arc::new(FakeAdapters::with_one(AdapterEntry {
            persistent_id: "pid-1".into(),
            adapter_name: "Wi-Fi".into(),
            ipv6_if_index: 12,
            physical_address: None,
            windows_name: "Wireless LAN".into(),
            interface_description: "".into(),
            interface_type: "ieee80211".into(),
            oper_status: "up".into(),
        }));
        let h = SnapshotInterfacesHandler::new(provider.clone());
        let _ = h
            .handle(&req(serde_json::json!({ "force-refresh": true })), &ctx())
            .unwrap();
        assert!(provider.last_force_refresh.load(Ordering::Relaxed));

        let _ = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        assert!(!provider.last_force_refresh.load(Ordering::Relaxed));
    }

    #[test]
    fn null_payload_is_treated_as_default_request() {
        let provider = Arc::new(FakeAdapters::empty());
        let h = SnapshotInterfacesHandler::new(provider);
        let resp = h.handle(&req(serde_json::Value::Null), &ctx()).unwrap();
        let _: SnapshotInterfacesResponse = serde_json::from_value(resp).unwrap();
    }

    #[test]
    fn rejects_garbage_payload() {
        let provider = Arc::new(FakeAdapters::empty());
        let h = SnapshotInterfacesHandler::new(provider);
        let err = h
            .handle(&req(serde_json::json!("not an object")), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

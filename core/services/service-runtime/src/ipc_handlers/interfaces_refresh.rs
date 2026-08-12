//! `InterfacesRefreshRequest` handler — synchronously triggers a
//! re-enumeration of network adapters and returns the fresh snapshot
//! to the client.
//!
//! Class is `IpcOperationClass::DiagnosticQuery`: the operation only
//! re-reads adapters and probes an external address, it persists
//! nothing — so it must NOT enter the single-writer mutation queue.
//! When it did (as a `DiagnosticAction`), any heavy policy apply
//! holding the queue pushed the refresh past the caller's deadline and
//! the user saw a timeout instead of addresses. Read-class
//! dispatch also means no elevation and no confirmation token, which
//! is exactly right for a non-admin GUI session pressing "check
//! external address". The probe itself is still user-initiated only —
//! nothing polls this operation.
//!
//! This is the deliberate, user-asked-for refresh — nothing polls it — which
//! makes it the one place allowed to run the per-adapter external-address
//! probe. The read-only `SnapshotInterfacesGet` path deliberately does not:
//! the GUI calls that one on its own initiative (window shown, service
//! reconnected), and a probe firing there would mean the product talking to
//! third-party servers without the user asking. The probe costs a few seconds
//! of wall clock, which is why it lives on the explicit path only.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcOperationClass, IpcRequestContext,
    IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{InterfacesRefreshRequest, InterfacesRefreshResponse};
use crate::ipc_handlers::providers::AdaptersSnapshotProvider;

pub struct InterfacesRefreshHandler {
    adapters: Arc<dyn AdaptersSnapshotProvider>,
}

impl InterfacesRefreshHandler {
    pub fn new(adapters: Arc<dyn AdaptersSnapshotProvider>) -> Self {
        Self { adapters }
    }
}

impl IpcHandler for InterfacesRefreshHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        if request.operation_class != IpcOperationClass::DiagnosticQuery {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "interfaces.refresh.request requires operation_class = diagnostic-query; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        if !request.payload.is_null() {
            let _: InterfacesRefreshRequest = serde_json::from_value(request.payload.clone())
                .map_err(|e| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("interfaces.refresh.request payload invalid: {e}"),
                    diagnostics_id: None,
                })?;
        }

        tracing::info!(
            target: "nrr::interfaces",
            "external-address refresh requested — re-enumerating adapters and probing",
        );
        let started = std::time::Instant::now();
        let resp: InterfacesRefreshResponse = self.adapters.adapters_snapshot_probing_external_ip();
        let (resolved, attempted) =
            resp.rows
                .iter()
                .fold((0usize, 0usize), |(resolved, attempted), row| {
                    let facts = &row.observed_facts;
                    (
                        resolved + usize::from(facts.external_ip.is_some()),
                        attempted + usize::from(facts.external_probe_attempted),
                    )
                });
        tracing::info!(
            target: "nrr::interfaces",
            rows = resp.rows.len(),
            attempted,
            resolved,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "external-address refresh finished",
        );
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("interfaces.refresh.request response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IPC_PROTOCOL_VERSION;
    use crate::ipc_handlers::payloads::AdapterEntry;
    use crate::ipc_handlers::test_fakes::FakeAdapters;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::atomic::Ordering;

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-ir".into(),
            correlation_id: None,
            operation: IpcOperationName::InterfacesRefreshRequest,
            operation_class: IpcOperationClass::DiagnosticQuery,
            confirmation_token: None,
            payload,
        }
    }

    /// The fake does not override the probing entry point, so this also pins
    /// the trait's default: probing delegates to a forced re-enumeration.
    #[test]
    fn refresh_forwards_force_refresh_true_to_provider() {
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
        let h = InterfacesRefreshHandler::new(provider.clone());
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: InterfacesRefreshResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.adapters.len(), 1);
        assert!(provider.last_force_refresh.load(Ordering::Relaxed));
    }

    #[test]
    fn rejects_non_diagnostic_query_class() {
        // Routing the refresh through the mutation queue is exactly the
        // regression this pins against.
        let provider = Arc::new(FakeAdapters::empty());
        let h = InterfacesRefreshHandler::new(provider);
        let mut env = req(serde_json::json!({}));
        env.operation_class = IpcOperationClass::DiagnosticAction;
        let err = h.handle(&env, &ctx()).expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn null_payload_is_default() {
        let provider = Arc::new(FakeAdapters::empty());
        let h = InterfacesRefreshHandler::new(provider);
        let _ = h.handle(&req(serde_json::Value::Null), &ctx()).unwrap();
    }
}

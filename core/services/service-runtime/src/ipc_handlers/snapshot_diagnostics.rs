//! `SnapshotDiagnosticsGet` handler — returns the
//! `DiagnosticsStatusDto` from the diagnostics facade plus an optional
//! synthetic explain sample (not wired yet).

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{SnapshotDiagnosticsRequest, SnapshotDiagnosticsResponse};

pub struct SnapshotDiagnosticsHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl SnapshotDiagnosticsHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for SnapshotDiagnosticsHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let _req: SnapshotDiagnosticsRequest = if request.payload.is_null() {
            SnapshotDiagnosticsRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("snapshot.diagnostics.get payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let status = self.diagnostics.get_status();
        // TODO:: when `_req.include_explain_sample` is true,
        // call `diagnostics.get_explain(ExplainQuery::Synthetic { ... })`
        // and embed the response. Today no synthetic input is available
        // from the runtime, so the field stays `None`.
        let resp = SnapshotDiagnosticsResponse {
            status,
            explain_sample: None,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("snapshot.diagnostics.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::test_fakes::FakeDiagnostics;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

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
            request_id: "r-sd".into(),
            correlation_id: None,
            operation: IpcOperationName::SnapshotDiagnosticsGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn returns_status_from_facade() {
        let h = SnapshotDiagnosticsHandler::new(Arc::new(FakeDiagnostics::healthy()));
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: SnapshotDiagnosticsResponse = serde_json::from_value(resp).unwrap();
        assert!(parsed.status.overall_healthy);
        assert!(parsed.explain_sample.is_none());
    }

    #[test]
    fn null_payload_is_default() {
        let h = SnapshotDiagnosticsHandler::new(Arc::new(FakeDiagnostics::healthy()));
        let _ = h.handle(&req(serde_json::Value::Null), &ctx()).unwrap();
    }

    #[test]
    fn rejects_garbage_payload() {
        let h = SnapshotDiagnosticsHandler::new(Arc::new(FakeDiagnostics::healthy()));
        let err = h
            .handle(&req(serde_json::json!(42)), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

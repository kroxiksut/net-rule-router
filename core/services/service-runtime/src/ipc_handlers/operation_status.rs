//! `OperationStatusGet` handler — synchronous lookup of an operation
//! handle previously returned by `MutationSubmit` (confirm) or
//! `RollbackRequest`.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{
    OperationErrorResponse, OperationStatusRequest, OperationStatusResponse,
};

pub struct OperationStatusHandler {
    store: Arc<OperationStatusStore>,
}

impl OperationStatusHandler {
    pub fn new(store: Arc<OperationStatusStore>) -> Self {
        Self { store }
    }
}

impl IpcHandler for OperationStatusHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: OperationStatusRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("operation.status.get payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        let rec = self.store.get(&body.operation_id).ok_or_else(|| IpcError {
            code: IpcErrorCode::PreconditionFailed,
            message: format!("operation_id `{}` is unknown or expired", body.operation_id),
            diagnostics_id: None,
        })?;

        let resp = OperationStatusResponse {
            state: rec.state.slug().into(),
            progress_hint: rec.progress_hint,
            result: rec.result,
            error: rec.error.map(|e| OperationErrorResponse {
                code: e.code,
                message: e.message,
            }),
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("operation.status.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::operation_status_store::OperationError;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::time::Instant;

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
            request_id: "r-os".into(),
            correlation_id: None,
            operation: IpcOperationName::OperationStatusGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn returns_completed_record() {
        let store = Arc::new(OperationStatusStore::new());
        let id = store.enqueue();
        store.complete(&id, serde_json::json!({ "ok": true }), Instant::now());
        let h = OperationStatusHandler::new(store);
        let resp = h
            .handle(&req(serde_json::json!({ "operation-id": id })), &ctx())
            .unwrap();
        let parsed: OperationStatusResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.state, "completed");
        assert_eq!(parsed.progress_hint, Some(1.0));
        assert_eq!(parsed.result.unwrap()["ok"], true);
        assert!(parsed.error.is_none());
    }

    #[test]
    fn returns_failed_record_with_error() {
        let store = Arc::new(OperationStatusStore::new());
        let id = store.enqueue();
        store.fail(
            &id,
            OperationError {
                code: "mutation.rejected.policy-degraded".into(),
                message: "service is degraded".into(),
            },
            Instant::now(),
        );
        let h = OperationStatusHandler::new(store);
        let resp = h
            .handle(&req(serde_json::json!({ "operation-id": id })), &ctx())
            .unwrap();
        let parsed: OperationStatusResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.state, "failed");
        assert!(parsed.result.is_none());
        let err = parsed.error.unwrap();
        assert_eq!(err.code, "mutation.rejected.policy-degraded");
    }

    #[test]
    fn unknown_operation_id_returns_precondition_failed() {
        let store = Arc::new(OperationStatusStore::new());
        let h = OperationStatusHandler::new(store);
        let err = h
            .handle(
                &req(serde_json::json!({ "operation-id": "op-never-issued" })),
                &ctx(),
            )
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn missing_operation_id_field_is_malformed_request() {
        let store = Arc::new(OperationStatusStore::new());
        let h = OperationStatusHandler::new(store);
        let err = h
            .handle(&req(serde_json::json!({})), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

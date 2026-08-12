//! `LogsList` handler — paginated read of operational log entries via
//! [`DiagnosticsFacade::list_log_entries`].

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{LogsListRequest, LogsListResponse};

pub struct LogsListHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl LogsListHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for LogsListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: LogsListRequest = if request.payload.is_null() {
            LogsListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("logs.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let page: LogsListResponse = self
            .diagnostics
            .list_log_entries(&req.filter, &req.pagination)
            .map_err(|e| IpcError {
                code: IpcErrorCode::Internal,
                message: format!("logs.list facade error: {e}"),
                diagnostics_id: None,
            })?;

        serde_json::to_value(page).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("logs.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::test_fakes::FakeDiagnostics;
    use nrr_diagnostics::facade::dto::LogEntryDto;
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
            request_id: "r-ll".into(),
            correlation_id: None,
            operation: IpcOperationName::SnapshotDiagnosticsGet, // op id is irrelevant to handler
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn entry(id: &str) -> LogEntryDto {
        LogEntryDto {
            event_id: id.into(),
            created_at: 0,
            level: "info".into(),
            category: "service".into(),
            kind: "service.started".into(),
            message_key: "diag.service.started.summary".into(),
            has_payload: false,
            correlation_summary: Vec::new(),
        }
    }

    #[test]
    fn returns_log_page_from_facade() {
        let diag = Arc::new(FakeDiagnostics::with_logs(vec![entry("e-1"), entry("e-2")]));
        let h = LogsListHandler::new(diag);
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: LogsListResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.items.len(), 2);
    }

    #[test]
    fn passes_filter_and_pagination_through_to_facade() {
        let diag = Arc::new(FakeDiagnostics::with_logs(vec![entry("e-1")]));
        let h = LogsListHandler::new(diag.clone());
        let payload = serde_json::json!({
            "filter": { "level_min": "warn" },
            "pagination": { "cursor": null, "page_size": 25 },
        });
        let _ = h.handle(&req(payload), &ctx()).unwrap();
        let last = diag.last_log_call.lock().unwrap().clone().unwrap();
        assert_eq!(last.0.level_min.as_deref(), Some("warn"));
        assert_eq!(last.1.page_size, 25);
    }

    #[test]
    fn rejects_garbage_payload() {
        let h = LogsListHandler::new(Arc::new(FakeDiagnostics::healthy()));
        let err = h
            .handle(&req(serde_json::json!("nope")), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

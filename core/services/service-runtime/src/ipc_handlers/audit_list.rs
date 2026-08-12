//! `AuditList` handler — paginated read of audit trail entries via
//! [`DiagnosticsFacade::list_audit_entries`].

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{AuditListRequest, AuditListResponse};

pub struct AuditListHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl AuditListHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for AuditListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: AuditListRequest = if request.payload.is_null() {
            AuditListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("audit.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let page: AuditListResponse = self
            .diagnostics
            .list_audit_entries(&req.filter, &req.pagination)
            .map_err(|e| IpcError {
                code: IpcErrorCode::Internal,
                message: format!("audit.list facade error: {e}"),
                diagnostics_id: None,
            })?;

        serde_json::to_value(page).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("audit.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::test_fakes::FakeDiagnostics;
    use nrr_diagnostics::facade::dto::AuditEntryDto;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn entry(seq: u64) -> AuditEntryDto {
        AuditEntryDto {
            event_id: format!("adt-{seq}"),
            seq,
            kind: "revision_activated".into(),
            created_at: 0,
            result: "success".into(),
            reason_code: "review.approved".into(),
            revision_id: Some("rev-1".into()),
            has_payload_summary: false,
        }
    }

    #[test]
    fn returns_audit_page_from_facade() {
        let diag = Arc::new(FakeDiagnostics::with_audit(vec![
            entry(1),
            entry(2),
            entry(3),
        ]));
        let h = AuditListHandler::new(diag);
        let resp = h
            .handle(
                &IpcRequestEnvelope {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    request_id: "r-al".into(),
                    correlation_id: None,
                    operation: IpcOperationName::SnapshotDiagnosticsGet,
                    operation_class: IpcOperationClass::ReadSnapshot,
                    confirmation_token: None,
                    payload: serde_json::json!({}),
                },
                &IpcRequestContext {
                    client_profile: IpcClientProfile::GuiInteractive,
                    caller_is_elevated: false,
                    caller_principal: None,
                },
            )
            .unwrap();
        let parsed: AuditListResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.items[0].seq, 1);
    }
}

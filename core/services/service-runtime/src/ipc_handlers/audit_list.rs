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
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
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
            .list_audit_entries(&req.filter, &req.pagination, &ctx.diagnostics_audience())
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
                    caller_pid: None,
                },
            )
            .unwrap();
        let parsed: AuditListResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.items.len(), 3);
        assert_eq!(parsed.items[0].seq, 1);
    }

    /// The facade takes an audience, so the compiler forces one to be passed —
    /// but passing the machine-wide one from the handler that serves ordinary
    /// users would hand every account the whole trail, and compile fine. This
    /// pins WHICH audience the handler asks for.
    #[test]
    fn an_unelevated_caller_is_scoped_to_itself_and_an_elevated_one_is_not() {
        use nrr_domain::user_principal::UserPrincipal;
        use nrr_shared::diagnostics_dto::DiagnosticsAudience;

        let ask = |elevated: bool| {
            let diag = Arc::new(FakeDiagnostics::with_audit(vec![entry(1)]));
            let facade: Arc<dyn DiagnosticsFacade> =
                Arc::clone(&diag) as Arc<dyn DiagnosticsFacade>;
            let h = AuditListHandler::new(facade);
            h.handle(
                &IpcRequestEnvelope {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    request_id: "r-al".into(),
                    correlation_id: None,
                    operation: IpcOperationName::AuditList,
                    operation_class: IpcOperationClass::DiagnosticQuery,
                    confirmation_token: None,
                    payload: serde_json::json!({}),
                },
                &IpcRequestContext {
                    client_profile: IpcClientProfile::GuiInteractive,
                    caller_is_elevated: elevated,
                    caller_principal: UserPrincipal::from_windows_sid("S-1-5-21-9").ok(),
                    caller_pid: None,
                },
            )
            .expect("handled");
            let seen = diag.last_audience.lock().unwrap().clone();
            seen.expect("the handler must name an audience")
        };

        assert_eq!(
            ask(false),
            DiagnosticsAudience::Principal("S-1-5-21-9".to_string()),
            "an ordinary caller reads its own trail, not the machine's"
        );
        assert_eq!(ask(true), DiagnosticsAudience::Machine);
    }
}

//! `MigrationMarkComplete` handler.
//!
//! Records GUI-driven migration completion for `(caller_sid, migration_id)`.
//! Idempotent: repeated calls preserve the original `completed_at`. The
//! response carries `recorded: bool` so the GUI can distinguish first-run
//! from idempotent re-runs in audit/logging.
//!
//! User-scoped class — flows through the mutation queue (single-writer
//! invariant) but does not require an elevated client.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{MigrationMarkCompleteRequest, MigrationMarkCompleteResponse};
use crate::ipc_handlers::providers::{MigrationCompletionWriter, RoutePolicyWriteError};

pub struct MigrationMarkCompleteHandler {
    writer: Arc<dyn MigrationCompletionWriter>,
}

impl MigrationMarkCompleteHandler {
    pub fn new(writer: Arc<dyn MigrationCompletionWriter>) -> Self {
        Self { writer }
    }
}

impl IpcHandler for MigrationMarkCompleteHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message:
                    "caller SID unavailable; transport must populate IpcRequestContext.caller_stored()"
                        .into(),
                diagnostics_id: None,
            });
        }

        let req: MigrationMarkCompleteRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("migration.mark.complete payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        match self.writer.mark_migration_complete(
            ctx.caller_stored(),
            &req.migration_id,
            req.detail_json.as_deref(),
        ) {
            Ok(record) => {
                let resp = MigrationMarkCompleteResponse {
                    recorded: record.recorded,
                    completed_at: record.completed_at,
                };
                serde_json::to_value(resp).map_err(|e| IpcError {
                    code: IpcErrorCode::Internal,
                    message: format!("migration.mark.complete response serialisation failed: {e}"),
                    diagnostics_id: None,
                })
            }
            Err(RoutePolicyWriteError::EmptySid) => Err(IpcError {
                code: IpcErrorCode::Internal,
                message: "caller SID is empty (writer-side validation)".into(),
                diagnostics_id: None,
            }),
            Err(e) => Err(IpcError {
                code: IpcErrorCode::Internal,
                message: e.to_string(),
                diagnostics_id: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::MIGRATION_ID_LEGACY_PREFERENCES_V1;
    use crate::ipc_handlers::providers::MigrationCompletionRecord;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    struct FakeCompletion {
        recorded: bool,
        completed_at: u64,
    }
    impl MigrationCompletionWriter for FakeCompletion {
        fn mark_migration_complete(
            &self,
            _sid: &str,
            _migration_id: &str,
            _detail_json: Option<&str>,
        ) -> Result<MigrationCompletionRecord, RoutePolicyWriteError> {
            Ok(MigrationCompletionRecord {
                recorded: self.recorded,
                completed_at: self.completed_at,
            })
        }
    }

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-3".into(),
            correlation_id: None,
            operation: IpcOperationName::MigrationMarkComplete,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    fn payload() -> serde_json::Value {
        serde_json::json!({
            "migration-id": MIGRATION_ID_LEGACY_PREFERENCES_V1,
            "detail-json": "{\"n\":3}",
        })
    }

    #[test]
    fn empty_sid_is_internal_error() {
        let h = MigrationMarkCompleteHandler::new(Arc::new(FakeCompletion {
            recorded: true,
            completed_at: 0,
        }) as Arc<dyn MigrationCompletionWriter>);
        let err = h.handle(&req(payload()), &ctx("")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
    }

    #[test]
    fn first_record_returns_recorded_true() {
        let h = MigrationMarkCompleteHandler::new(Arc::new(FakeCompletion {
            recorded: true,
            completed_at: 99,
        }) as Arc<dyn MigrationCompletionWriter>);
        let value = h.handle(&req(payload()), &ctx("S")).unwrap();
        let parsed: MigrationMarkCompleteResponse = serde_json::from_value(value).unwrap();
        assert!(parsed.recorded);
        assert_eq!(parsed.completed_at, 99);
    }

    #[test]
    fn idempotent_record_returns_recorded_false() {
        let h = MigrationMarkCompleteHandler::new(Arc::new(FakeCompletion {
            recorded: false,
            completed_at: 50,
        }) as Arc<dyn MigrationCompletionWriter>);
        let value = h.handle(&req(payload()), &ctx("S")).unwrap();
        let parsed: MigrationMarkCompleteResponse = serde_json::from_value(value).unwrap();
        assert!(!parsed.recorded);
        assert_eq!(parsed.completed_at, 50);
    }

    #[test]
    fn malformed_payload_is_malformed_request() {
        let h = MigrationMarkCompleteHandler::new(Arc::new(FakeCompletion {
            recorded: true,
            completed_at: 0,
        }) as Arc<dyn MigrationCompletionWriter>);
        let err = h
            .handle(&req(serde_json::json!({"x": 1})), &ctx("S"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

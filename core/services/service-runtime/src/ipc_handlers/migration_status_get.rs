//! `MigrationStatusGet` handler.
//!
//! Reads `migration_state` row for `(caller_sid, migration_id)`. The
//! GUI uses this on cold start to decide whether to drive the legacy
//! preferences migration (`MIGRATION_ID_LEGACY_PREFERENCES_V1`).
//!
//! `caller_sid.is_empty()` is treated as "not yet completed" (returns
//! `completed = false`) rather than an error, so cross-platform tests
//! and non-Windows transports do not see spurious `Internal` errors
//! from this read-only handler.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{MigrationStatusGetRequest, MigrationStatusGetResponse};
use crate::ipc_handlers::providers::MigrationStatusProvider;

pub struct MigrationStatusGetHandler {
    status: Arc<dyn MigrationStatusProvider>,
}

impl MigrationStatusGetHandler {
    pub fn new(status: Arc<dyn MigrationStatusProvider>) -> Self {
        Self { status }
    }
}

impl IpcHandler for MigrationStatusGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: MigrationStatusGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("migration.status.get payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        let resp = if ctx.caller_stored().is_empty() {
            MigrationStatusGetResponse {
                completed: false,
                completed_at: None,
                detail_json: None,
            }
        } else {
            self.status
                .migration_status(ctx.caller_stored(), &req.migration_id)
        };

        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("migration.status.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::MIGRATION_ID_LEGACY_PREFERENCES_V1;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    struct FakeStatus {
        completed: bool,
    }
    impl MigrationStatusProvider for FakeStatus {
        fn migration_status(&self, _sid: &str, _migration_id: &str) -> MigrationStatusGetResponse {
            MigrationStatusGetResponse {
                completed: self.completed,
                completed_at: if self.completed { Some(99) } else { None },
                detail_json: if self.completed {
                    Some("{}".into())
                } else {
                    None
                },
            }
        }
    }

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
        }
    }

    fn req() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-2".into(),
            correlation_id: None,
            operation: IpcOperationName::MigrationStatusGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({
                "migration-id": MIGRATION_ID_LEGACY_PREFERENCES_V1,
            }),
        }
    }

    #[test]
    fn empty_sid_returns_not_completed_without_calling_provider() {
        let h = MigrationStatusGetHandler::new(
            Arc::new(FakeStatus { completed: true }) as Arc<dyn MigrationStatusProvider>
        );
        let value = h.handle(&req(), &ctx("")).unwrap();
        let parsed: MigrationStatusGetResponse = serde_json::from_value(value).unwrap();
        assert!(!parsed.completed);
        assert!(parsed.completed_at.is_none());
    }

    #[test]
    fn populated_sid_delegates_to_provider() {
        let h = MigrationStatusGetHandler::new(
            Arc::new(FakeStatus { completed: true }) as Arc<dyn MigrationStatusProvider>
        );
        let value = h.handle(&req(), &ctx("S-1-5-21-A")).unwrap();
        let parsed: MigrationStatusGetResponse = serde_json::from_value(value).unwrap();
        assert!(parsed.completed);
        assert_eq!(parsed.completed_at, Some(99));
    }

    #[test]
    fn malformed_payload_returns_malformed_request() {
        let h = MigrationStatusGetHandler::new(
            Arc::new(FakeStatus { completed: false }) as Arc<dyn MigrationStatusProvider>
        );
        let mut bad = req();
        bad.payload = serde_json::json!({"wrong": "field"});
        let err = h.handle(&bad, &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

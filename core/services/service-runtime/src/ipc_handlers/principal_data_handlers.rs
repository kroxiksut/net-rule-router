//! `principal-data.purge` handler — full reset's auxiliary-state cleanup.
//! Caller-scoped, never elevated; see `nrr_storage::principal_purge` for scope.

use nrr_shared::ipc_payloads::PrincipalDataPurgeRequest;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::providers::{PrincipalDataPurger, RoutePolicyWriteError};

fn principal(ctx: &IpcRequestContext) -> Result<&str, IpcError> {
    let sid = ctx.caller_stored();
    if sid.is_empty() {
        return Err(IpcError {
            code: IpcErrorCode::Unauthorized,
            message: "this request carries no user identity, so it cannot be scoped to a user"
                .to_string(),
            diagnostics_id: None,
        });
    }
    Ok(sid)
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    match err {
        RoutePolicyWriteError::EmptySid => IpcError {
            code: IpcErrorCode::Unauthorized,
            message: "this request carries no user identity, so it cannot be scoped to a user"
                .to_string(),
            diagnostics_id: None,
        },
        other => IpcError {
            code: IpcErrorCode::Internal,
            message: format!("principal-data.purge: {other:?}"),
            diagnostics_id: None,
        },
    }
}

pub struct PrincipalDataPurgeHandler {
    purger: std::sync::Arc<dyn PrincipalDataPurger>,
}

impl PrincipalDataPurgeHandler {
    pub fn new(purger: std::sync::Arc<dyn PrincipalDataPurger>) -> Self {
        Self { purger }
    }
}

impl IpcHandler for PrincipalDataPurgeHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let _: PrincipalDataPurgeRequest =
            serde_json::from_value(request.payload.clone()).unwrap_or_default();
        let response = self.purger.purge_for_sid(sid).map_err(map_write_error)?;
        serde_json::to_value(response).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("principal-data.purge serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_shared::ipc_payloads::PrincipalDataPurgeResponse;
    use std::sync::{Arc, Mutex};

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
        }
    }

    fn req() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-purge".into(),
            correlation_id: None,
            operation: IpcOperationName::PrincipalDataPurge,
            operation_class: IpcOperationClass::UserScopedMutation,
            confirmation_token: None,
            payload: serde_json::Value::Null,
        }
    }

    struct RecordingPurger {
        calls: Mutex<Vec<String>>,
        result: Result<PrincipalDataPurgeResponse, RoutePolicyWriteError>,
    }

    impl PrincipalDataPurger for RecordingPurger {
        fn purge_for_sid(
            &self,
            sid: &str,
        ) -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError> {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(sid.to_string());
            self.result.clone()
        }
    }

    #[test]
    fn purges_the_callers_own_sid_and_returns_the_summary() {
        let purger = Arc::new(RecordingPurger {
            calls: Mutex::new(Vec::new()),
            result: Ok(PrincipalDataPurgeResponse {
                rows_deleted: 9,
                tables_touched: 9,
            }),
        });
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let value = handler.handle(&req(), &ctx(Some("S-A"))).expect("purge");
        let parsed: PrincipalDataPurgeResponse = serde_json::from_value(value).expect("decode");
        assert_eq!(parsed.rows_deleted, 9);
        assert_eq!(parsed.tables_touched, 9);
        assert_eq!(
            purger
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_slice(),
            &["S-A".to_string()]
        );
    }

    #[test]
    fn an_unattributed_caller_is_refused_before_reaching_the_purger() {
        let purger = Arc::new(RecordingPurger {
            calls: Mutex::new(Vec::new()),
            result: Ok(PrincipalDataPurgeResponse::default()),
        });
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let err = handler.handle(&req(), &ctx(None)).expect_err("no identity");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
        assert!(purger
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }

    #[test]
    fn a_storage_failure_maps_to_internal() {
        let purger = Arc::new(RecordingPurger {
            calls: Mutex::new(Vec::new()),
            result: Err(RoutePolicyWriteError::Storage("disk full".into())),
        });
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let err = handler
            .handle(&req(), &ctx(Some("S-A")))
            .expect_err("storage failure");
        assert_eq!(err.code, IpcErrorCode::Internal);
    }
}

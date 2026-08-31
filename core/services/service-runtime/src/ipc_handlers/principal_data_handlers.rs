//! `principal-data.purge` / `principal-data.count` handlers — full reset's
//! auxiliary-state cleanup and the question it has to ask first.
//! Caller-scoped unless the request asks for every principal, which needs
//! elevation; see `nrr_storage::principal_purge` for scope.

use nrr_shared::ipc_payloads::{PrincipalDataCountResponse, PrincipalDataPurgeRequest};

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
        // An absent payload is the plain "reset my own data" call and keeps the
        // defaults. A payload that is PRESENT but unreadable is not: silently
        // defaulting it turned "erase my rules history too" into a purge that
        // kept the history and still answered success.
        let req: PrincipalDataPurgeRequest = if request.payload.is_null() {
            PrincipalDataPurgeRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("principal-data.purge payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };
        let response = if req.all_principals {
            // Erasing other users' routing is an administrative act. The
            // elevation check is here rather than in the catalog because the
            // SAME operation is the ordinary, non-elevated self-reset.
            if !ctx.caller_is_elevated {
                return Err(IpcError {
                    code: IpcErrorCode::Forbidden,
                    message: "clearing every user's data needs administrator approval".to_string(),
                    diagnostics_id: None,
                });
            }
            self.purger
                .purge_all_principals(req.include_rules_history)
                .map_err(map_write_error)?
        } else {
            let mut response = self
                .purger
                .purge_for_sid(sid, req.include_rules_history)
                .map_err(map_write_error)?;
            response.principals_purged = 1;
            response
        };
        serde_json::to_value(response).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("principal-data.purge serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

/// "Is anyone else's routing stored here?" — the question full reset has to
/// answer before it can offer a choice of scope.
pub struct PrincipalDataCountHandler {
    purger: std::sync::Arc<dyn PrincipalDataPurger>,
}

impl PrincipalDataCountHandler {
    pub fn new(purger: std::sync::Arc<dyn PrincipalDataPurger>) -> Self {
        Self { purger }
    }
}

impl IpcHandler for PrincipalDataCountHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let other_principals = self
            .purger
            .other_principal_count(sid)
            .map_err(map_write_error)?;
        serde_json::to_value(PrincipalDataCountResponse { other_principals }).map_err(|e| {
            IpcError {
                code: IpcErrorCode::Internal,
                message: format!("principal-data.count serialisation failed: {e}"),
                diagnostics_id: None,
            }
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
            caller_pid: None,
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
        rules_asked: Mutex<Vec<bool>>,
        result: Result<PrincipalDataPurgeResponse, RoutePolicyWriteError>,
    }

    impl RecordingPurger {
        fn new(result: Result<PrincipalDataPurgeResponse, RoutePolicyWriteError>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                rules_asked: Mutex::new(Vec::new()),
                result,
            }
        }
    }

    impl PrincipalDataPurger for RecordingPurger {
        fn purge_all_principals(
            &self,
            include_rules_history: bool,
        ) -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError> {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push("*".to_string());
            self.rules_asked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(include_rules_history);
            self.result.clone()
        }

        fn other_principal_count(&self, _sid: &str) -> Result<u32, RoutePolicyWriteError> {
            Ok(0)
        }

        fn purge_for_sid(
            &self,
            sid: &str,
            include_rules_history: bool,
        ) -> Result<PrincipalDataPurgeResponse, RoutePolicyWriteError> {
            self.calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(sid.to_string());
            self.rules_asked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(include_rules_history);
            self.result.clone()
        }
    }

    #[test]
    fn purges_the_callers_own_sid_and_returns_the_summary() {
        let purger = Arc::new(RecordingPurger::new(Ok(PrincipalDataPurgeResponse {
            rows_deleted: 9,
            tables_touched: 9,
            rules_rows_deleted: 0,
            principals_purged: 0,
        })));
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

    /// The flag is what separates routine cleanup from a full reset, so it has
    /// to survive the wire rather than default quietly to "delete the rules".
    #[test]
    fn the_rules_history_flag_reaches_the_purger_only_when_asked_for() {
        for asked in [false, true] {
            let purger = Arc::new(RecordingPurger::new(Ok(
                PrincipalDataPurgeResponse::default(),
            )));
            let handler =
                PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
            let mut envelope = req();
            envelope.payload = serde_json::json!({ "include-rules-history": asked });
            handler.handle(&envelope, &ctx(Some("S-A"))).expect("purge");
            assert_eq!(
                purger
                    .rules_asked
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_slice(),
                &[asked]
            );
        }
    }

    #[test]
    fn an_unreadable_payload_is_refused_instead_of_silently_defaulted() {
        // `include-rules-history` misspelled (or of the wrong type) used to fall
        // back to the defaults: the history stayed, and the caller was told the
        // purge succeeded.
        let purger = Arc::new(RecordingPurger::new(Ok(PrincipalDataPurgeResponse {
            rows_deleted: 0,
            tables_touched: 0,
            rules_rows_deleted: 0,
            principals_purged: 0,
        })));
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let mut request = req();
        request.payload = serde_json::json!({ "include-rules-history": "yes please" });
        let err = handler
            .handle(&request, &ctx(Some("S-A")))
            .expect_err("a payload we cannot read is not a purge request");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        assert!(
            purger
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "nothing may be purged on a request we did not understand"
        );
    }

    #[test]
    fn an_unattributed_caller_is_refused_before_reaching_the_purger() {
        let purger = Arc::new(RecordingPurger::new(Ok(
            PrincipalDataPurgeResponse::default(),
        )));
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
        let purger = Arc::new(RecordingPurger::new(Err(RoutePolicyWriteError::Storage(
            "disk full".into(),
        ))));
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let err = handler
            .handle(&req(), &ctx(Some("S-A")))
            .expect_err("storage failure");
        assert_eq!(err.code, IpcErrorCode::Internal);
    }
}

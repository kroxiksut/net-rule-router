//! `rules.verify.verdicts.{list,accept,dismiss}` — the user's answer to a `?`
//! rule that does not open where it is written. Scoped to the caller's own
//! principal, never elevated: the window, the tray and the terminal all show
//! the notice.

use std::sync::Arc;
use std::time::SystemTime;

use nrr_shared::ipc_payloads::{
    VerifyVerdictsAcceptRequest, VerifyVerdictsAcceptResponse, VerifyVerdictsDismissRequest,
    VerifyVerdictsDismissResponse, VerifyVerdictsListResponse,
};

use crate::auto_rules::AutoRulesEngine;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::tamper_bootstrap::SECURITY_ALERT_GATE_CODE;

/// An unattributed caller cannot be served: verdicts are per principal.
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

fn parse<T: serde::de::DeserializeOwned + Default>(
    request: &IpcRequestEnvelope,
    op: &str,
) -> Result<T, IpcError> {
    if request.payload.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    })
}

fn reply<T: serde::Serialize>(value: T, op: &str) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op} serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

pub struct VerifyVerdictsListHandler {
    engine: Arc<AutoRulesEngine>,
}

impl VerifyVerdictsListHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for VerifyVerdictsListHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        reply(
            VerifyVerdictsListResponse {
                verdicts: self.engine.verify_verdicts(sid),
            },
            "rules.verify.verdicts.list",
        )
    }
}

pub struct VerifyVerdictsAcceptHandler {
    engine: Arc<AutoRulesEngine>,
}

impl VerifyVerdictsAcceptHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for VerifyVerdictsAcceptHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let req: VerifyVerdictsAcceptRequest = parse(request, "rules.verify.verdicts.accept")?;
        match self
            .engine
            .accept_verify_verdicts(sid, &req.rule_ids, SystemTime::now())
        {
            Ok(moved) => reply(
                VerifyVerdictsAcceptResponse { moved },
                "rules.verify.verdicts.accept",
            ),
            // Refused by the executor (rules lock, security alert, rule cap):
            // its own code travels on, and every verdict stays as it was.
            Err(e) => Err(IpcError {
                code: if e.code == SECURITY_ALERT_GATE_CODE {
                    IpcErrorCode::SecurityAlertUnacknowledged
                } else {
                    IpcErrorCode::PreconditionFailed
                },
                message: format!("{}: {}", e.code, e.message),
                diagnostics_id: None,
            }),
        }
    }
}

pub struct VerifyVerdictsDismissHandler {
    engine: Arc<AutoRulesEngine>,
}

impl VerifyVerdictsDismissHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for VerifyVerdictsDismissHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let req: VerifyVerdictsDismissRequest = parse(request, "rules.verify.verdicts.dismiss")?;
        reply(
            VerifyVerdictsDismissResponse {
                dismissed: self.engine.dismiss_verify_verdicts(sid, &req.rule_ids),
            },
            "rules.verify.verdicts.dismiss",
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auto_rules::{
        AutoRulesModeFn, DismissalStore, InMemoryDismissalStore, InMemoryPendingStore,
    };
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::per_sid_orchestrator::{NoopRulesProvider, RulesProvider};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_storage::auto_rules::AutoRulesMode;

    fn engine() -> Arc<AutoRulesEngine> {
        let mode: AutoRulesModeFn = Arc::new(|_| AutoRulesMode::Off);
        Arc::new(AutoRulesEngine::new(
            Arc::new(NoopRulesProvider) as Arc<dyn RulesProvider>,
            mode,
            Arc::new(InMemoryDismissalStore::new()) as Arc<dyn DismissalStore>,
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::UNIX_EPOCH,
        ))
    }

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::Tui,
            caller_is_elevated: false,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
            caller_pid: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-vv".into(),
            correlation_id: None,
            operation: IpcOperationName::VerifyVerdictsList,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn a_caller_with_no_verdicts_gets_an_empty_list_and_answers_change_nothing() {
        let engine = engine();
        let list = VerifyVerdictsListHandler::new(Arc::clone(&engine))
            .handle(&req(serde_json::Value::Null), &ctx(Some("S-1-5-21-1")))
            .expect("list");
        let list: VerifyVerdictsListResponse = serde_json::from_value(list).expect("decode");
        assert!(list.verdicts.is_empty());

        let ids = serde_json::json!({ "rule-ids": ["r-nope"] });
        let accept = VerifyVerdictsAcceptHandler::new(Arc::clone(&engine))
            .handle(&req(ids.clone()), &ctx(Some("S-1-5-21-1")))
            .expect("accept");
        assert_eq!(accept["moved"], 0);
        let dismiss = VerifyVerdictsDismissHandler::new(engine)
            .handle(&req(ids), &ctx(Some("S-1-5-21-1")))
            .expect("dismiss");
        assert_eq!(dismiss["dismissed"], 0);
    }

    #[test]
    fn an_unattributed_caller_is_refused() {
        let err = VerifyVerdictsListHandler::new(engine())
            .handle(&req(serde_json::Value::Null), &ctx(None))
            .expect_err("no identity");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }
}

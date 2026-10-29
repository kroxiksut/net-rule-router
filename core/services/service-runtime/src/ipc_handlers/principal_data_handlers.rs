//! `principal-data.purge` / `principal-data.count` handlers — full reset's
//! auxiliary-state cleanup and the question it has to ask first.
//! Caller-scoped unless the request asks for every principal, which needs
//! elevation; see `nrr_storage::principal_purge` for scope.

use nrr_shared::ipc_payloads::{PrincipalDataCountResponse, PrincipalDataPurgeRequest};

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::operation_status_store::OperationError;
use crate::ipc_handlers::providers::{
    MutationExecutor, MutationOutcome, PrincipalDataPurger, RoutePolicyWriteError,
    RULES_LOCKED_ERROR_CODE,
};
use nrr_shared::ipc_payloads::MutationKind;

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
    /// Runs the caller's rules erasure as a reset to the baseline.
    rules_reset: Option<std::sync::Arc<dyn MutationExecutor>>,
}

impl PrincipalDataPurgeHandler {
    pub fn new(purger: std::sync::Arc<dyn PrincipalDataPurger>) -> Self {
        Self {
            purger,
            rules_reset: None,
        }
    }

    /// Erasing one's own rules history goes through the reset to the baseline:
    /// its gates, the activation in flight, its audit and its event.
    #[must_use]
    pub fn with_rules_reset(mut self, executor: std::sync::Arc<dyn MutationExecutor>) -> Self {
        self.rules_reset = Some(executor);
        self
    }
}

/// The wire code of a gate the reset to the baseline would refuse at.
fn gate_error(refusal: OperationError) -> IpcError {
    let code = if refusal.code == RULES_LOCKED_ERROR_CODE {
        IpcErrorCode::RulesLocked
    } else if refusal.code == crate::tamper_bootstrap::SECURITY_ALERT_GATE_CODE {
        IpcErrorCode::SecurityAlertUnacknowledged
    } else if refusal.code == IpcErrorCode::BusyConflict.client_slug() {
        IpcErrorCode::BusyConflict
    } else {
        IpcErrorCode::Forbidden
    };
    IpcError {
        code,
        message: refusal.message,
        diagnostics_id: None,
    }
}

impl CheckedIpcHandler for PrincipalDataPurgeHandler {
    type Checked = PrincipalDataPurgeRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        principal(ctx)?;
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
        // Erasing other users' routing is an administrative act. The elevation
        // check is here rather than in the catalog because the SAME operation
        // is the ordinary, non-elevated self-reset.
        if req.all_principals && !ctx.caller_is_elevated {
            return Err(IpcError::needs_administrator(
                "clearing every user's data needs administrator approval",
            ));
        }
        if req.include_rules_history {
            if let Some(refusal) = self.rules_reset.as_ref().and_then(|executor| {
                executor.closed_gate(MutationKind::RulesResetToBaseline, ctx.caller_is_elevated)
            }) {
                return Err(gate_error(refusal));
            }
        }
        Ok(req)
    }

    fn execute(
        &self,
        req: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let response = if req.all_principals {
            match self.rules_reset.as_ref() {
                Some(executor) if req.include_rules_history => {
                    let mut purged = None;
                    executor
                        .erase_every_users_rules(&mut || {
                            purged = Some(self.purger.purge_all_principals(true));
                        })
                        .map_err(gate_error)?;
                    purged
                        .unwrap_or(Err(RoutePolicyWriteError::Storage(
                            "the erase did not run".into(),
                        )))
                        .map_err(map_write_error)?
                }
                _ => self
                    .purger
                    .purge_all_principals(req.include_rules_history)
                    .map_err(map_write_error)?,
            }
        } else {
            if req.include_rules_history {
                if let Some(executor) = self.rules_reset.as_ref() {
                    let reset = StoredMutation {
                        kind: MutationKind::RulesResetToBaseline,
                        payload: serde_json::json!({}),
                        correlation_id: Some("full-reset".into()),
                        issuer_sid: sid.to_owned(),
                        caller_is_elevated: ctx.caller_is_elevated,
                    };
                    if let MutationOutcome::Failed(refusal) = executor.execute(reset, sid) {
                        return Err(gate_error(refusal));
                    }
                }
            }
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
        // A misspelled (or wrongly typed) `include-rules-history` must be
        // refused, not silently defaulted — defaulting would leave the
        // history in place while telling the caller the purge succeeded.
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

    /// Erasing every user's data is machine-wide; erasing one's own is not.
    /// The same operation carries both, so the handler is the only gate.
    #[test]
    fn purging_every_principal_needs_elevation_and_purging_ones_own_does_not() {
        let everyone = || {
            let mut envelope = req();
            envelope.payload = serde_json::json!({ "all-principals": true });
            envelope
        };
        let calls = |purger: &RecordingPurger| {
            purger
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        };

        let purger = Arc::new(RecordingPurger::new(Ok(
            PrincipalDataPurgeResponse::default(),
        )));
        let handler =
            PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>);
        let err = handler
            .handle(&everyone(), &ctx(Some("S-A")))
            .expect_err("an unelevated caller must not erase other users' data");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(calls(&purger).is_empty(), "nothing may be purged");

        handler
            .handle(&req(), &ctx(Some("S-A")))
            .expect("resetting one's own data needs no rights");
        assert_eq!(calls(&purger), vec!["S-A".to_string()]);

        let admin = IpcRequestContext {
            caller_is_elevated: true,
            ..ctx(Some("S-A"))
        };
        handler
            .handle(&everyone(), &admin)
            .expect("an administrator may clear every user");
        assert_eq!(calls(&purger), vec!["S-A".to_string(), "*".to_string()]);
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

    /// The fake executor behind a gate that is open or closed.
    struct Gated {
        inner: crate::ipc_handlers::test_fakes::FakeMutationExecutor,
        closed: bool,
    }

    impl MutationExecutor for Gated {
        fn preview(
            &self,
            kind: MutationKind,
            payload: &serde_json::Value,
            principal: &str,
        ) -> crate::ipc_handlers::payloads::ReviewSummaryResponse {
            self.inner.preview(kind, payload, principal)
        }
        fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome {
            self.inner.execute(payload, principal)
        }
        fn closed_gate(
            &self,
            _kind: MutationKind,
            _caller_is_elevated: bool,
        ) -> Option<crate::ipc_handlers::operation_status_store::OperationError> {
            self.closed.then(
                || crate::ipc_handlers::operation_status_store::OperationError {
                    args: Default::default(),
                    code: crate::ipc_handlers::providers::RULES_LOCKED_ERROR_CODE.into(),
                    message: "locked".into(),
                },
            )
        }
        fn rollback(&self, principal: &str, target: Option<&str>) -> MutationOutcome {
            self.inner.rollback(principal, target)
        }
        fn rollback_target(
            &self,
            principal: &str,
            target: Option<&str>,
        ) -> Result<
            Option<nrr_shared::ipc_payloads::RollbackTargetDto>,
            crate::ipc_handlers::operation_status_store::OperationError,
        > {
            self.inner.rollback_target(principal, target)
        }
        fn safe_disable(
            &self,
            principal: &str,
            reason: &str,
            term: nrr_shared::ipc_payloads::SafeDisableTerm,
        ) -> MutationOutcome {
            self.inner.safe_disable(principal, reason, term)
        }
    }

    /// Erasing one's rules history is a reset to the baseline like the menu's:
    /// refused under the administrator's rules lock or a tamper alert, and
    /// otherwise run as that reset, so an apply in flight, the audit and the
    /// user's clients all hear of it.
    #[test]
    fn erasing_the_rules_history_is_a_reset_to_the_baseline() {
        for closed in [true, false] {
            let purger = Arc::new(RecordingPurger::new(Ok(
                PrincipalDataPurgeResponse::default(),
            )));
            let reset = Arc::new(Gated {
                inner: crate::ipc_handlers::test_fakes::FakeMutationExecutor::default(),
                closed,
            });
            let handler =
                PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>)
                    .with_rules_reset(Arc::clone(&reset) as Arc<dyn MutationExecutor>);
            let mut envelope = req();
            envelope.payload = serde_json::json!({ "include-rules-history": true });
            let result = handler.handle(&envelope, &ctx(Some("S-A")));
            let calls = purger
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if closed {
                let err = result.expect_err("locked");
                assert_eq!(err.code, IpcErrorCode::RulesLocked);
                assert!(calls.is_empty(), "nothing erased under the lock");
                assert_eq!(reset.inner.executed_count(), 0);
            } else {
                result.expect("purged");
                assert_eq!(calls, ["S-A".to_string()]);
                let ran = reset
                    .inner
                    .last_executed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .expect("the reset ran");
                assert_eq!(ran.kind, MutationKind::RulesResetToBaseline);
                assert_eq!(
                    reset
                        .inner
                        .last_principal
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .as_deref(),
                    Some("S-A")
                );
            }
        }
    }

    /// The rules storage with an activation in flight, or idle: the erase runs
    /// only inside it.
    struct Erasing {
        inner: Gated,
        busy: bool,
        erased_inside: Mutex<bool>,
    }

    impl MutationExecutor for Erasing {
        fn preview(
            &self,
            kind: MutationKind,
            payload: &serde_json::Value,
            principal: &str,
        ) -> crate::ipc_handlers::payloads::ReviewSummaryResponse {
            self.inner.preview(kind, payload, principal)
        }
        fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome {
            self.inner.execute(payload, principal)
        }
        fn erase_every_users_rules(
            &self,
            erase: &mut dyn FnMut(),
        ) -> Result<(), crate::ipc_handlers::operation_status_store::OperationError> {
            if self.busy {
                return Err(
                    crate::ipc_handlers::operation_status_store::OperationError {
                        args: Default::default(),
                        code: IpcErrorCode::BusyConflict.client_slug().into(),
                        message: "another rules change is still being applied".into(),
                    },
                );
            }
            erase();
            *self.erased_inside.lock().unwrap_or_else(|p| p.into_inner()) = true;
            Ok(())
        }
        fn rollback(&self, principal: &str, target: Option<&str>) -> MutationOutcome {
            self.inner.rollback(principal, target)
        }
        fn rollback_target(
            &self,
            principal: &str,
            target: Option<&str>,
        ) -> Result<
            Option<nrr_shared::ipc_payloads::RollbackTargetDto>,
            crate::ipc_handlers::operation_status_store::OperationError,
        > {
            self.inner.rollback_target(principal, target)
        }
        fn safe_disable(
            &self,
            principal: &str,
            reason: &str,
            term: nrr_shared::ipc_payloads::SafeDisableTerm,
        ) -> MutationOutcome {
            self.inner.safe_disable(principal, reason, term)
        }
    }

    /// An administrator's erase of every user's rules is every user's reset
    /// to the baseline: it waits out an apply in flight instead of deleting
    /// under it, and runs where each user's clients are told.
    #[test]
    fn erasing_every_users_rules_goes_through_the_rules_storage() {
        for busy in [true, false] {
            let purger = Arc::new(RecordingPurger::new(Ok(
                PrincipalDataPurgeResponse::default(),
            )));
            let storage = Arc::new(Erasing {
                inner: Gated {
                    inner: crate::ipc_handlers::test_fakes::FakeMutationExecutor::default(),
                    closed: false,
                },
                busy,
                erased_inside: Mutex::new(false),
            });
            let handler =
                PrincipalDataPurgeHandler::new(Arc::clone(&purger) as Arc<dyn PrincipalDataPurger>)
                    .with_rules_reset(Arc::clone(&storage) as Arc<dyn MutationExecutor>);
            let mut envelope = req();
            envelope.payload = serde_json::json!({
                "all-principals": true,
                "include-rules-history": true,
            });
            let mut admin = ctx(Some("S-A"));
            admin.caller_is_elevated = true;
            let result = handler.handle(&envelope, &admin);
            let calls = purger
                .calls
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if busy {
                assert_eq!(result.expect_err("busy").code, IpcErrorCode::BusyConflict);
                assert!(calls.is_empty(), "nothing erased under an apply: {calls:?}");
            } else {
                result.expect("erased");
                assert_eq!(calls, ["*".to_string()]);
                assert!(
                    *storage
                        .erased_inside
                        .lock()
                        .unwrap_or_else(|p| p.into_inner()),
                    "the erase ran inside the rules storage"
                );
            }
        }
    }
}

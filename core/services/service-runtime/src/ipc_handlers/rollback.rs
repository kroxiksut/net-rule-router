//! `RollbackRequest` handler — restore a previous policy revision (or
//! the LKG when no target is specified).
//!
//! Like [`MutationSubmit`](super::mutation_submit::MutationSubmitHandler)
//! confirm, the operation runs through [`MutationExecutor::rollback`]
//! synchronously and is tracked through the
//! [`OperationStatusStore`]. The router gates this handler on
//! `IpcOperationClass::RecoveryAction` (token + audit + elevation), so
//! by the time we are dispatched the envelope already carries a
//! confirmation token and the audit event has been written.

use std::sync::Arc;
use std::time::Instant;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcOperationClass, IpcRequestContext,
    IpcRequestEnvelope,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{RollbackRequest, RollbackResponse};
use crate::ipc_handlers::providers::{
    rule_edits_allowed_for, MutationExecutor, MutationOutcome, ServiceStabilityConfigProvider,
    RULES_LOCKED_MESSAGE,
};

pub struct RollbackHandler {
    executor: Arc<dyn MutationExecutor>,
    operation_store: Arc<OperationStatusStore>,
    /// Reader for the machine-wide administrative rules lock. `None` leaves
    /// the gate open (degraded boot / tests).
    stability: Option<Arc<dyn ServiceStabilityConfigProvider>>,
}

impl RollbackHandler {
    pub fn new(
        executor: Arc<dyn MutationExecutor>,
        operation_store: Arc<OperationStatusStore>,
    ) -> Self {
        Self {
            executor,
            operation_store,
            stability: None,
        }
    }

    /// Attach the reader for the machine-wide administrative rules lock.
    /// Rolling back re-activates a different rule set, so it is a rule change
    /// like any other and must not become the way around the lock.
    #[must_use]
    pub fn with_stability_provider(
        mut self,
        provider: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.stability = Some(provider);
        self
    }
}

impl IpcHandler for RollbackHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        if request.operation_class != IpcOperationClass::RecoveryAction {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "rollback.request requires operation_class = recovery-action; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        if !rule_edits_allowed_for(self.stability.as_ref(), ctx.caller_is_elevated) {
            return Err(IpcError {
                code: IpcErrorCode::RulesLocked,
                message: RULES_LOCKED_MESSAGE.into(),
                diagnostics_id: None,
            });
        }

        let body: RollbackRequest = if request.payload.is_null() {
            RollbackRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("rollback.request payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        // Rollback is scoped to the caller's own principal (own SID when
        // authenticated, else baseline for the elevated / harness path).
        // `RecoveryAction` is elevation-gated by the router, but the
        // *target* partition is still the caller's rules.
        let principal = if ctx.caller_stored().is_empty() {
            nrr_storage::BASELINE_PRINCIPAL.to_string()
        } else {
            ctx.caller_stored().to_string()
        };
        let op_id = self.operation_store.enqueue();
        let outcome = self
            .executor
            .rollback(&principal, body.target_revision_id.as_deref());
        match outcome {
            MutationOutcome::Completed(result) => {
                self.operation_store
                    .complete(&op_id, result, Instant::now());
            }
            MutationOutcome::Failed(error) => {
                self.operation_store.fail(&op_id, error, Instant::now());
            }
        }

        let resp = RollbackResponse {
            operation_id: op_id,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("rollback.request response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IPC_PROTOCOL_VERSION;
    use crate::ipc_handlers::operation_status_store::OperationState;
    use crate::ipc_handlers::test_fakes::{FakeMutationExecutor, FakeRulesLock};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-rb".into(),
            correlation_id: None,
            operation: IpcOperationName::RollbackRequest,
            operation_class: IpcOperationClass::RecoveryAction,
            confirmation_token: Some("issued-token".into()),
            payload,
        }
    }

    #[test]
    fn rollback_to_lkg_completes_synchronously() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), ops.clone());
        let resp_v = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let resp: RollbackResponse = serde_json::from_value(resp_v).unwrap();
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Completed);
        assert_eq!(exec.rollback_count(), 1);
        assert_eq!(*exec.last_rollback_target.lock().unwrap(), None);
    }

    #[test]
    fn rollback_to_target_revision_propagates_id_to_executor() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), ops);
        let _ = h
            .handle(
                &req(serde_json::json!({ "target-revision-id": "rev-42" })),
                &ctx(),
            )
            .unwrap();
        assert_eq!(
            *exec.last_rollback_target.lock().unwrap(),
            Some("rev-42".to_string())
        );
    }

    #[test]
    fn rejects_non_recovery_action_class() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec, ops);
        let mut env = req(serde_json::json!({}));
        env.operation_class = IpcOperationClass::ReadSnapshot;
        let err = h.handle(&env, &ctx()).expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn null_payload_is_rollback_to_lkg() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), ops);
        let _ = h.handle(&req(serde_json::Value::Null), &ctx()).unwrap();
        assert_eq!(*exec.last_rollback_target.lock().unwrap(), None);
    }

    /// A non-elevated caller who cannot author a rule must not be able to
    /// reach an older rule set through the recovery door either.
    #[test]
    fn locked_machine_refuses_a_non_elevated_rollback() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), ops)
            .with_stability_provider(FakeRulesLock::locked());
        let non_elevated = IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-KID").ok(),
        };
        let err = h
            .handle(&req(serde_json::json!({})), &non_elevated)
            .expect_err("locked machine must refuse the rollback");
        assert_eq!(err.code, IpcErrorCode::RulesLocked);
        assert_eq!(exec.rollback_count(), 0);
    }

    /// The administrator still recovers a previous revision on a locked box.
    #[test]
    fn locked_machine_still_allows_an_elevated_rollback() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), ops)
            .with_stability_provider(FakeRulesLock::locked());
        h.handle(&req(serde_json::json!({})), &ctx())
            .expect("elevated rollback must pass the lock");
        assert_eq!(exec.rollback_count(), 1);
    }
}

//! `ProductImpactDisableTemporary` handler — the temporary safe-disable
//! gate. Removes all routes/filters owned by the service and parks the
//! runtime in `ApplyLayerDisabled` mode until the user re-enables.
//!
//! Two-phase protocol mirrored on
//! [`MutationSubmit`](super::mutation_submit::MutationSubmitHandler) so
//! the GUI can show a review surface ("you are about to disable
//! enforcement") before the user confirms.
//!
//! - **Dry run:** envelope class = `ReadSnapshot`. Mints a
//!   confirmation token, returns review summary.
//! - **Confirm:** envelope class = `SafeDisable`. Token mandatory;
//!   router enforces it before dispatch and audit fires. The token must
//!   have been issued by this operation's dry-run to the same principal.
//!
//! The reason string is captured both in the stored mutation (used at
//! confirm) and in the executor invocation, so the audit trail carries
//! the operator-visible justification verbatim.

use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcOperationClass, IpcRequestContext,
    IpcRequestEnvelope,
};
use crate::ipc_handlers::mutation_token_store::{
    MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{
    ProductImpactDisableConfirmResponse, ProductImpactDisableDryRunResponse,
    ProductImpactDisableRequest, ReviewRiskLevel, ReviewSummaryResponse,
};
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};

/// Where the reviewed `reason` waits for the confirm, which refuses a
/// different one.
const SAFE_DISABLE_REASON_KEY: &str = "_nrr_safe_disable_reason";

pub struct ProductImpactDisableTemporaryHandler {
    executor: Arc<dyn MutationExecutor>,
    token_store: Arc<MutationTokenStore>,
    operation_store: Arc<OperationStatusStore>,
    token_ttl: Duration,
}

impl ProductImpactDisableTemporaryHandler {
    pub fn new(
        executor: Arc<dyn MutationExecutor>,
        token_store: Arc<MutationTokenStore>,
        operation_store: Arc<OperationStatusStore>,
    ) -> Self {
        Self {
            executor,
            token_store,
            operation_store,
            token_ttl: DEFAULT_MUTATION_TOKEN_TTL,
        }
    }
}

impl IpcHandler for ProductImpactDisableTemporaryHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: ProductImpactDisableRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("product-impact.disable.temporary payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        if body.dry_run {
            self.handle_dry_run(request, body, ctx)
        } else {
            self.handle_confirm(request, body, ctx)
        }
    }
}

impl ProductImpactDisableTemporaryHandler {
    fn handle_dry_run(
        &self,
        request: &IpcRequestEnvelope,
        body: ProductImpactDisableRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        if request.operation_class != IpcOperationClass::ReadSnapshot {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "product-impact.disable.temporary dry-run requires operation_class = read-snapshot; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        // Safe-disable is intentionally classified `High` — the GUI's
        // review surface should treat it as a destructive change.
        let summary = ReviewSummaryResponse {
            diff_summary: format!("safe-disable: {}", body.reason),
            provenance: "ipc.product-impact.disable.temporary".into(),
            risk_level: ReviewRiskLevel::High,
            requires_review: true,
            changed_fields: vec!["apply-layer".into()],
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        };

        let stored = StoredMutation::confirmation_of(
            serde_json::json!({ SAFE_DISABLE_REASON_KEY: body.reason }),
            ctx.caller_stored(),
            ctx.caller_is_elevated,
        );
        let now = Instant::now();
        let token = self.token_store.issue(
            IpcOperationName::ProductImpactDisableTemporary,
            stored,
            now + self.token_ttl,
        );

        let resp = ProductImpactDisableDryRunResponse {
            review_risk_level: summary.risk_level,
            review_summary: summary,
            confirmation_token: token,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!(
                "product-impact.disable.temporary dry-run response serialisation failed: {e}"
            ),
            diagnostics_id: None,
        })
    }

    fn handle_confirm(
        &self,
        request: &IpcRequestEnvelope,
        body: ProductImpactDisableRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        if request.operation_class != IpcOperationClass::SafeDisable {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "product-impact.disable.temporary confirm requires operation_class = safe-disable; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        let token = request
            .confirmation_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "product-impact.disable.temporary confirm requires a non-empty confirmation token".into(),
                diagnostics_id: None,
            })?;

        let now = Instant::now();
        let stored = self
            .token_store
            .consume_for(
                token,
                IpcOperationName::ProductImpactDisableTemporary,
                ctx.caller_stored(),
                now,
            )
            .map_err(IpcError::from)?;

        let stored_reason = stored
            .payload
            .get(SAFE_DISABLE_REASON_KEY)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Sanity: the confirm body's reason must match what was
        // reviewed during dry-run. A divergence is a client bug; we
        // refuse to disable enforcement on a different rationale than
        // the one the operator just OK'd.
        if body.reason != stored_reason {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "confirm reason does not match dry-run reason".into(),
                diagnostics_id: None,
            });
        }

        let op_id = self
            .operation_store
            .enqueue_for(crate::ipc_handlers::operation_status_store::owner_of(ctx));
        let outcome = self.executor.safe_disable(&stored_reason);
        match outcome {
            MutationOutcome::Completed(result) => {
                self.operation_store
                    .complete(&op_id, result, Instant::now());
            }
            MutationOutcome::Failed(error) => {
                self.operation_store.fail(&op_id, error, Instant::now());
            }
        }

        let resp = ProductImpactDisableConfirmResponse {
            operation_id: op_id,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!(
                "product-impact.disable.temporary confirm response serialisation failed: {e}"
            ),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IPC_PROTOCOL_VERSION;
    use crate::ipc_handlers::operation_status_store::OperationState;
    use crate::ipc_handlers::test_fakes::FakeMutationExecutor;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
            caller_pid: None,
        }
    }

    fn dry_run_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-pid-dry".into(),
            correlation_id: None,
            operation: IpcOperationName::ProductImpactDisableTemporary,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn confirm_envelope(payload: serde_json::Value, token: &str) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-pid-conf".into(),
            correlation_id: None,
            operation: IpcOperationName::ProductImpactDisableTemporary,
            operation_class: IpcOperationClass::SafeDisable,
            confirmation_token: Some(token.into()),
            payload,
        }
    }

    fn make_handler() -> (
        ProductImpactDisableTemporaryHandler,
        Arc<MutationTokenStore>,
        Arc<OperationStatusStore>,
        Arc<FakeMutationExecutor>,
    ) {
        let executor = Arc::new(FakeMutationExecutor::default());
        let tokens = Arc::new(MutationTokenStore::new());
        let ops = Arc::new(OperationStatusStore::new());
        let h = ProductImpactDisableTemporaryHandler::new(
            executor.clone(),
            tokens.clone(),
            ops.clone(),
        );
        (h, tokens, ops, executor)
    }

    #[test]
    fn dry_run_returns_high_risk_summary_and_token() {
        let (h, tokens, _ops, _exec) = make_handler();
        let resp = h
            .handle(
                &dry_run_envelope(serde_json::json!({
                    "reason": "investigating routing anomaly",
                    "dry-run": true,
                })),
                &ctx(),
            )
            .expect("happy dry-run");
        let parsed: ProductImpactDisableDryRunResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.review_risk_level, ReviewRiskLevel::High);
        assert!(parsed.review_summary.requires_review);
        assert!(!parsed.confirmation_token.is_empty());
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn confirm_executes_safe_disable_and_returns_operation_id() {
        let (h, _tokens, ops, exec) = make_handler();
        let dry: ProductImpactDisableDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "reason": "investigating routing anomaly",
                    "dry-run": true,
                })),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();

        let resp: ProductImpactDisableConfirmResponse = serde_json::from_value(
            h.handle(
                &confirm_envelope(
                    serde_json::json!({
                        "reason": "investigating routing anomaly",
                        "dry-run": false,
                    }),
                    &dry.confirmation_token,
                ),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();

        assert!(resp.operation_id.starts_with("op-"));
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Completed);
        assert_eq!(exec.safe_disable_count(), 1);
        assert_eq!(
            *exec.last_safe_disable_reason.lock().unwrap(),
            Some("investigating routing anomaly".to_string())
        );
    }

    #[test]
    fn confirm_rejects_reason_mismatch() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let dry: ProductImpactDisableDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "reason": "reason-A",
                    "dry-run": true,
                })),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({ "reason": "reason-B", "dry-run": false }),
                    &dry.confirmation_token,
                ),
                &ctx(),
            )
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("reason"));
    }

    #[test]
    fn confirm_rejects_non_safe_disable_class() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let mut env = confirm_envelope(
            serde_json::json!({ "reason": "x", "dry-run": false }),
            "any-token",
        );
        env.operation_class = IpcOperationClass::MutationRequest;
        let err = h.handle(&env, &ctx()).expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    fn ctx_sid(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
            ..ctx()
        }
    }

    /// The token is the reviewing principal's; another one cannot spend it.
    #[test]
    fn confirm_refuses_a_token_issued_to_another_principal() {
        let (h, _tokens, _ops, exec) = make_handler();
        let body = serde_json::json!({ "reason": "r", "dry-run": true });
        let dry: ProductImpactDisableDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(body), &ctx_sid("S-1-5-21-A"))
                .unwrap(),
        )
        .unwrap();
        let confirm = serde_json::json!({ "reason": "r", "dry-run": false });
        let err = h
            .handle(
                &confirm_envelope(confirm.clone(), &dry.confirmation_token),
                &ctx_sid("S-1-5-21-B"),
            )
            .expect_err("a foreign principal must be refused");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
        assert_eq!(exec.safe_disable_count(), 0);
    }

    /// A token another operation minted in the shared store is not one.
    #[test]
    fn confirm_refuses_a_token_of_another_operation() {
        let (h, tokens, _ops, exec) = make_handler();
        let foreign = tokens.issue(
            IpcOperationName::RollbackRequest,
            StoredMutation::confirmation_of(
                serde_json::json!({ SAFE_DISABLE_REASON_KEY: "r" }),
                "",
                true,
            ),
            Instant::now() + DEFAULT_MUTATION_TOKEN_TTL,
        );
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({ "reason": "r", "dry-run": false }),
                    &foreign,
                ),
                &ctx(),
            )
            .expect_err("a rollback token must not disable protection");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
        assert_eq!(exec.safe_disable_count(), 0);
    }

    #[test]
    fn confirm_unknown_token_returns_confirmation_unknown() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({ "reason": "x", "dry-run": false }),
                    "no-such-token",
                ),
                &ctx(),
            )
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
    }
}

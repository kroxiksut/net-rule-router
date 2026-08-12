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
//!   router enforces it before dispatch and audit fires.
//!
//! The reason string is captured both in the stored mutation (used at
//! confirm) and in the executor invocation, so the audit trail carries
//! the operator-visible justification verbatim.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcOperationClass, IpcRequestContext,
    IpcRequestEnvelope,
};
use crate::ipc_handlers::mutation_token_store::{
    ConsumeError, MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{
    MutationKind, ProductImpactDisableConfirmResponse, ProductImpactDisableDryRunResponse,
    ProductImpactDisableRequest, ReviewRiskLevel, ReviewSummaryResponse,
};
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};

/// Marker we stash in the token store so the confirm path can recover
/// the original `reason` after consume. We reuse `MutationKind` /
/// `StoredMutation` rather than introducing a parallel type — the
/// payload is JSON-shaped and `kind` is the enum tag distinguishing
/// safe-disable from a normal rules/preset mutation.
///
/// Wire-level `MutationKind` does not currently carry a `SafeDisable`
/// variant — adding one to a serde-derived enum that is in the public
/// wire schema is a contract change. We sidestep this by
/// stashing the `reason` directly in the JSON payload under a private
/// key; the confirm path reads it back to invoke
/// [`MutationExecutor::safe_disable`].
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
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: ProductImpactDisableRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("product-impact.disable.temporary payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        if body.dry_run {
            self.handle_dry_run(request, body)
        } else {
            self.handle_confirm(request, body)
        }
    }
}

impl ProductImpactDisableTemporaryHandler {
    fn handle_dry_run(
        &self,
        request: &IpcRequestEnvelope,
        body: ProductImpactDisableRequest,
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
            pro_sections: Vec::new(),
        };

        let stored_payload = serde_json::json!({
            SAFE_DISABLE_REASON_KEY: body.reason,
        });
        let stored = StoredMutation {
            // Reuse `RulesUpdate` as a placeholder kind — the confirm
            // path keys off `_nrr_safe_disable_reason` to recognise
            // safe-disable, not off `kind`. This keeps the wire-level
            // `MutationKind` enum stable.
            kind: MutationKind::RulesUpdate,
            payload: stored_payload,
            correlation_id: None,
            // Safe-disable is its own elevated `SafeDisable`-class flow;
            // it does not key off the per-principal issuer binding.
            issuer_sid: String::new(),
            // The `SafeDisable` class is elevation-gated by the router, and
            // the confirm path calls `safe_disable`, never `execute` — the
            // flag is carried for completeness, not consulted here.
            caller_is_elevated: true,
        };
        let now = Instant::now();
        let token = self.token_store.issue(stored, now + self.token_ttl);

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
        let stored = self.token_store.consume(token, now).map_err(|e| match e {
            ConsumeError::NotFound => IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "confirmation token unknown — re-run dry-run".into(),
                diagnostics_id: None,
            },
            ConsumeError::Expired => IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "confirmation token expired — re-run dry-run".into(),
                diagnostics_id: None,
            },
        })?;

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

        let op_id = self.operation_store.enqueue();
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

    #[test]
    fn confirm_unknown_token_returns_precondition_failed() {
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
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }
}

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

use crate::boot_clock::BootInstant;
use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcOperationClass,
    IpcRequestContext, IpcRequestEnvelope, Prechecked,
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
/// The reviewed term, kept beside the reason for the same check.
const SAFE_DISABLE_TERM_KEY: &str = "_nrr_safe_disable_term";

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

/// A safe-disable request its precheck accepted.
pub enum CheckedSafeDisable {
    DryRun(ProductImpactDisableRequest),
    /// The token is spent; the reason is the one that was reviewed, and the
    /// routing paused is that of whoever ran the dry-run.
    Confirm {
        reason: String,
        principal: String,
        term: nrr_shared::ipc_payloads::SafeDisableTerm,
    },
}

impl CheckedIpcHandler for ProductImpactDisableTemporaryHandler {
    type Checked = CheckedSafeDisable;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        let body: ProductImpactDisableRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("product-impact.disable.temporary payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        if body.dry_run {
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
            Ok(CheckedSafeDisable::DryRun(body))
        } else {
            self.precheck_confirm(request, body, ctx)
        }
    }

    fn execute(
        &self,
        checked: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        match checked.into_inner() {
            CheckedSafeDisable::DryRun(body) => self.handle_dry_run(body, ctx),
            CheckedSafeDisable::Confirm {
                reason,
                principal,
                term,
            } => self.handle_confirm(&reason, &principal, term, ctx),
        }
    }
}

impl ProductImpactDisableTemporaryHandler {
    fn handle_dry_run(
        &self,
        body: ProductImpactDisableRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
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
            cross_set_duplicates: Vec::new(),
        };

        let stored = StoredMutation::confirmation_of(
            serde_json::json!({
                SAFE_DISABLE_REASON_KEY: body.reason,
                SAFE_DISABLE_TERM_KEY: body.term.slug(),
            }),
            ctx.caller_stored(),
            ctx.caller_is_elevated,
        );
        let token = self.token_store.issue(
            IpcOperationName::ProductImpactDisableTemporary,
            stored,
            BootInstant::now() + self.token_ttl,
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

    /// Spends the token, refused or not, and checks it against the request.
    fn precheck_confirm(
        &self,
        request: &IpcRequestEnvelope,
        body: ProductImpactDisableRequest,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedSafeDisable, IpcError> {
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

        // It pauses the caller's own routing; with no caller there is nobody
        // to pause, and nobody else's routing is the caller's to lift.
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Unauthorized,
                message: "product-impact.disable.temporary needs the caller's identity".into(),
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

        let now = BootInstant::now();
        // An elevated confirm may be an administrator answering a standard
        // account's prompt: it is that account's dry-run, and its routing.
        let stored = self
            .token_store
            .consume_for_confirmer(
                token,
                IpcOperationName::ProductImpactDisableTemporary,
                ctx.caller_stored(),
                ctx.caller_is_elevated,
                now,
            )
            .map_err(IpcError::from)?;
        let principal = if stored.issuer_sid.is_empty() {
            ctx.caller_stored().to_owned()
        } else {
            stored.issuer_sid.clone()
        };

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
        // The same for the term: a pause longer than the one reviewed is never
        // taken on the confirm's word.
        let stored_term = stored
            .payload
            .get(SAFE_DISABLE_TERM_KEY)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if body.term.slug() != stored_term {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "confirm term does not match dry-run term".into(),
                diagnostics_id: None,
            });
        }
        Ok(CheckedSafeDisable::Confirm {
            reason: stored_reason,
            principal,
            term: body.term,
        })
    }

    fn handle_confirm(
        &self,
        stored_reason: &str,
        principal: &str,
        term: nrr_shared::ipc_payloads::SafeDisableTerm,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let op_id = self
            .operation_store
            .enqueue_for(crate::ipc_handlers::operation_status_store::owner_of(ctx));
        let outcome = self.executor.safe_disable(principal, stored_reason, term);
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
    use crate::ipc::{IpcHandler, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::operation_status_store::OperationState;
    use crate::ipc_handlers::test_fakes::FakeMutationExecutor;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: Some(nrr_domain::user_principal::UserPrincipal::from_linux_uid(
                1000,
            )),
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
        // The caller's own routing, not the machine's.
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(ctx().caller_stored())
        );
    }

    fn dry_run_token(h: &ProductImpactDisableTemporaryHandler, term: &str) -> String {
        let dry: ProductImpactDisableDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "reason": "r", "dry-run": true, "term": term,
                })),
                &ctx(),
            )
            .expect("dry-run"),
        )
        .expect("parse");
        dry.confirmation_token
    }

    #[test]
    fn the_reviewed_term_reaches_the_executor() {
        let (h, _tokens, _ops, exec) = make_handler();
        let token = dry_run_token(&h, "one-hour");
        h.handle(
            &confirm_envelope(
                serde_json::json!({ "reason": "r", "dry-run": false, "term": "one-hour" }),
                &token,
            ),
            &ctx(),
        )
        .expect("confirm");
        assert_eq!(
            *exec.last_safe_disable_term.lock().unwrap(),
            Some(nrr_shared::ipc_payloads::SafeDisableTerm::OneHour)
        );
    }

    #[test]
    fn a_confirm_naming_another_term_than_the_reviewed_one_is_refused() {
        let (h, _tokens, _ops, exec) = make_handler();
        let token = dry_run_token(&h, "fifteen-minutes");
        let refused = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({ "reason": "r", "dry-run": false, "term": "until-restart" }),
                    &token,
                ),
                &ctx(),
            )
            .expect_err("a longer pause than reviewed");
        assert_eq!(refused.code, IpcErrorCode::PreconditionFailed);
        assert_eq!(exec.safe_disable_count(), 0);
    }

    #[test]
    fn an_unknown_term_mints_no_token() {
        let (h, tokens, _ops, _exec) = make_handler();
        let refused = h
            .handle(
                &dry_run_envelope(serde_json::json!({
                    "reason": "r", "dry-run": true, "term": "forever",
                })),
                &ctx(),
            )
            .expect_err("no such term");
        assert_eq!(refused.code, IpcErrorCode::MalformedRequest);
        assert_eq!(tokens.len(), 0);
    }

    /// A standard account runs the dry-run; the confirm arrives elevated under
    /// the administrator who answered the prompt. It pauses the account's own
    /// routing. An unelevated stranger with the token is still refused.
    #[test]
    fn an_elevated_confirm_by_another_principal_pauses_the_dry_runs_owner() {
        let user = IpcRequestContext {
            caller_is_elevated: false,
            ..ctx()
        };
        let as_principal = |uid: u32, elevated: bool| IpcRequestContext {
            caller_is_elevated: elevated,
            caller_principal: Some(nrr_domain::user_principal::UserPrincipal::from_linux_uid(
                uid,
            )),
            ..ctx()
        };
        let dry_run = |h: &ProductImpactDisableTemporaryHandler| -> String {
            let dry: ProductImpactDisableDryRunResponse = serde_json::from_value(
                h.handle(
                    &dry_run_envelope(serde_json::json!({ "reason": "r", "dry-run": true })),
                    &user,
                )
                .expect("dry-run"),
            )
            .expect("parse");
            dry.confirmation_token
        };
        let confirm = serde_json::json!({ "reason": "r", "dry-run": false });

        let (h, _tokens, _ops, exec) = make_handler();
        let token = dry_run(&h);
        h.handle(
            &confirm_envelope(confirm.clone(), &token),
            &as_principal(0, true),
        )
        .expect("an administrator confirms the account's dry-run");
        assert_eq!(exec.safe_disable_count(), 1);
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(user.caller_stored())
        );

        let token = dry_run(&h);
        let err = h
            .handle(
                &confirm_envelope(confirm, &token),
                &as_principal(1001, false),
            )
            .expect_err("a stranger's confirm");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
        assert_eq!(exec.safe_disable_count(), 1);
    }

    #[test]
    fn confirm_without_a_caller_pauses_nobody() {
        let (h, _tokens, _ops, exec) = make_handler();
        let anonymous = IpcRequestContext {
            caller_principal: None,
            ..ctx()
        };
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({ "reason": "x", "dry-run": false }),
                    "any-token",
                ),
                &anonymous,
            )
            .expect_err("no caller, no pause");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
        assert_eq!(exec.safe_disable_count(), 0);
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

    /// An unelevated caller: an elevated one may confirm another account's
    /// dry-run, see the test above.
    fn ctx_sid(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
            ..ctx()
        }
    }

    /// The token is the reviewing principal's; another unelevated one cannot
    /// spend it.
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
            BootInstant::now() + DEFAULT_MUTATION_TOKEN_TTL,
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

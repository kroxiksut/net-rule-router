//! `RollbackRequest` handler — restore a previous policy revision (or
//! the LKG when no target is specified).
//!
//! Two-phase like [`ProductImpactDisableTemporary`](super::product_impact_disable):
//!
//! - **Dry run:** envelope class = `ReadSnapshot`. Names the revision the
//!   rollback restores and mints a confirmation token bound to this
//!   operation, the caller's principal and that revision; with nothing to
//!   roll back to it answers so, with no token.
//! - **Rollback:** the caller's own chain is `UserScopedMutation` (token +
//!   audit, no elevation); the shared baseline is `MutationRequest`, the
//!   class of any edit of it, which the router holds to elevation. Spends
//!   that token, then runs [`MutationExecutor::rollback`] synchronously,
//!   tracked through the [`OperationStatusStore`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{
    canonical_operation_class, HandlerOutcome, IpcError, IpcErrorCode, IpcHandler,
    IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::mutation_submit::resolve_confirm_principal;
use crate::ipc_handlers::mutation_token_store::{
    MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{
    OperationErrorResponse, RollbackDryRunResponse, RollbackRequest, RollbackResponse,
};
use crate::ipc_handlers::providers::{
    rule_edits_allowed_for, MutationExecutor, MutationOutcome, ServiceStabilityConfigProvider,
    RULES_LOCKED_MESSAGE,
};

/// Where the dry-run's target and partition wait for the rollback, which
/// refuses any other.
const ROLLBACK_TARGET_KEY: &str = "_nrr_rollback_target";
const ROLLBACK_BASELINE_KEY: &str = "_nrr_rollback_admin_baseline";
/// The revision the dry-run showed: the rollback restores it even if the
/// last-known-good moved on in between.
const ROLLBACK_RESOLVED_KEY: &str = "_nrr_rollback_resolved";

pub struct RollbackHandler {
    executor: Arc<dyn MutationExecutor>,
    token_store: Arc<MutationTokenStore>,
    operation_store: Arc<OperationStatusStore>,
    token_ttl: Duration,
    /// Reader for the machine-wide administrative rules lock. `None` leaves
    /// the gate open (degraded boot / tests).
    stability: Option<Arc<dyn ServiceStabilityConfigProvider>>,
}

impl RollbackHandler {
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

    #[cfg(test)]
    fn with_token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = ttl;
        self
    }
}

impl IpcHandler for RollbackHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: RollbackRequest = if request.payload.is_null() {
            RollbackRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("rollback.request payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let expected_class =
            canonical_operation_class(IpcOperationName::RollbackRequest, &request.payload);
        if request.operation_class != expected_class {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "rollback.request requires operation_class = {}; got {:?}",
                    expected_class.slug(),
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        // Refused on the dry-run too, so a locked user hears it before the
        // real request rather than after.
        if !rule_edits_allowed_for(self.stability.as_ref(), ctx.caller_is_elevated) {
            return Err(IpcError {
                code: IpcErrorCode::RulesLocked,
                message: RULES_LOCKED_MESSAGE.into(),
                diagnostics_id: None,
            });
        }

        if body.dry_run {
            self.handle_dry_run(body, ctx)
        } else {
            self.handle_rollback(request, body, ctx)
        }
    }
}

impl RollbackHandler {
    fn handle_dry_run(&self, body: RollbackRequest, ctx: &IpcRequestContext) -> HandlerOutcome {
        let principal =
            resolve_confirm_principal(rollback_class(body.admin_baseline), ctx.caller_stored())?;
        let response = match self
            .executor
            .rollback_target(&principal, body.target_revision_id.as_deref())
        {
            Err(error) => RollbackDryRunResponse {
                error: Some(OperationErrorResponse {
                    code: error.code,
                    message: error.message,
                    args: error.args,
                }),
                ..RollbackDryRunResponse::default()
            },
            Ok(None) => RollbackDryRunResponse::default(),
            Ok(Some(target)) => {
                let stored = StoredMutation::confirmation_of(
                    serde_json::json!({
                        ROLLBACK_TARGET_KEY: body.target_revision_id,
                        ROLLBACK_BASELINE_KEY: body.admin_baseline,
                        ROLLBACK_RESOLVED_KEY: target.revision_id,
                    }),
                    ctx.caller_stored(),
                    ctx.caller_is_elevated,
                );
                let token = self.token_store.issue(
                    IpcOperationName::RollbackRequest,
                    stored,
                    Instant::now() + self.token_ttl,
                );
                RollbackDryRunResponse {
                    confirmation_token: Some(token),
                    target: Some(target),
                    error: None,
                }
            }
        };
        serde_json::to_value(response).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("rollback.request dry-run response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }

    fn handle_rollback(
        &self,
        request: &IpcRequestEnvelope,
        body: RollbackRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        // Before the token is spent, so an unauthenticated caller keeps it.
        let principal = resolve_confirm_principal(request.operation_class, ctx.caller_stored())?;
        let token = request
            .confirmation_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "rollback.request requires a confirmation token from its dry-run".into(),
                diagnostics_id: None,
            })?;
        let stored = self
            .token_store
            .consume_for(
                token,
                IpcOperationName::RollbackRequest,
                ctx.caller_stored(),
                Instant::now(),
            )
            .map_err(IpcError::from)?;
        let reviewed_target = stored
            .payload
            .get(ROLLBACK_TARGET_KEY)
            .and_then(serde_json::Value::as_str);
        let reviewed_baseline = stored
            .payload
            .get(ROLLBACK_BASELINE_KEY)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let Some(resolved) = stored
            .payload
            .get(ROLLBACK_RESOLVED_KEY)
            .and_then(serde_json::Value::as_str)
        else {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "the dry-run found nothing to roll back to".into(),
                diagnostics_id: None,
            });
        };
        if reviewed_target != body.target_revision_id.as_deref()
            || reviewed_baseline != body.admin_baseline
        {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "rollback target does not match the dry-run's".into(),
                diagnostics_id: None,
            });
        }
        let op_id = self
            .operation_store
            .enqueue_for(crate::ipc_handlers::operation_status_store::owner_of(ctx));
        let outcome = self.executor.rollback(&principal, Some(resolved));
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

/// The class the rollback itself carries, so the dry-run reads the partition
/// the rollback will write.
fn rollback_class(admin_baseline: bool) -> crate::ipc::IpcOperationClass {
    canonical_operation_class(
        IpcOperationName::RollbackRequest,
        &serde_json::json!({ "admin-baseline": admin_baseline }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::operation_status_store::{OperationError, OperationState};
    use crate::ipc_handlers::test_fakes::{FakeMutationExecutor, FakeRulesLock, FAKE_LKG_REVISION};
    use nrr_shared::ipc::IpcClientProfile;

    const SID: &str = "S-1-5-21-ROLLER";

    fn ctx_as(elevated: bool, sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: elevated,
            caller_principal: sid.and_then(|s| crate::UserPrincipal::from_windows_sid(s).ok()),
            caller_pid: None,
        }
    }

    fn ctx() -> IpcRequestContext {
        ctx_as(true, Some(SID))
    }

    /// The envelope the way our client builds it: class derived from the payload.
    fn envelope(token: Option<&str>, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-rb".into(),
            correlation_id: None,
            operation: IpcOperationName::RollbackRequest,
            operation_class: canonical_operation_class(IpcOperationName::RollbackRequest, &payload),
            confirmation_token: token.map(str::to_string),
            payload,
        }
    }

    fn handler(exec: &Arc<FakeMutationExecutor>) -> (RollbackHandler, Arc<OperationStatusStore>) {
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(
            exec.clone(),
            Arc::new(MutationTokenStore::new()),
            ops.clone(),
        );
        (h, ops)
    }

    fn dry_run_answer(
        h: &RollbackHandler,
        payload: serde_json::Value,
        ctx: &IpcRequestContext,
    ) -> RollbackDryRunResponse {
        serde_json::from_value(h.handle(&envelope(None, payload), ctx).expect("dry-run")).unwrap()
    }

    fn dry_run_with(
        h: &RollbackHandler,
        payload: serde_json::Value,
        ctx: &IpcRequestContext,
    ) -> String {
        dry_run_answer(h, payload, ctx)
            .confirmation_token
            .expect("a target, so a token")
    }

    fn dry_run(h: &RollbackHandler, target: Option<&str>, ctx: &IpcRequestContext) -> String {
        let mut payload = serde_json::json!({ "dry-run": true });
        if let Some(t) = target {
            payload["target-revision-id"] = t.into();
        }
        dry_run_with(h, payload, ctx)
    }

    fn rollback(
        h: &RollbackHandler,
        token: &str,
        payload: serde_json::Value,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        h.handle(&envelope(Some(token), payload), ctx)
    }

    #[test]
    fn rollback_to_lkg_completes_synchronously() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, ops) = handler(&exec);
        let token = dry_run(&h, None, &ctx());
        let resp_v = rollback(&h, &token, serde_json::json!({}), &ctx()).unwrap();
        let resp: RollbackResponse = serde_json::from_value(resp_v).unwrap();
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Completed);
        assert_eq!(exec.rollback_count(), 1);
        assert_eq!(
            exec.last_rollback_target.lock().unwrap().as_deref(),
            Some(FAKE_LKG_REVISION),
            "the revision the dry-run showed, not whatever the LKG is by now"
        );
    }

    /// The dry-run names what will be restored, so the dialog can show it.
    #[test]
    fn the_dry_run_names_the_revision_it_restores() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let answer = dry_run_answer(&h, serde_json::json!({ "dry-run": true }), &ctx());
        let target = answer.target.expect("a target");
        assert_eq!(target.revision_id, FAKE_LKG_REVISION);
        assert_eq!(target.rule_count, 3);
        assert!(answer.error.is_none());
    }

    /// Nothing to roll back to is an answer, not a token for a rollback that
    /// would fail after the user confirmed it.
    #[test]
    fn with_no_earlier_revision_the_dry_run_says_so_and_mints_nothing() {
        let exec = Arc::new(FakeMutationExecutor {
            rollback_target: Ok(None),
            ..FakeMutationExecutor::default()
        });
        let (h, _ops) = handler(&exec);
        let answer = dry_run_answer(&h, serde_json::json!({ "dry-run": true }), &ctx());
        assert!(answer.confirmation_token.is_none());
        assert!(answer.target.is_none());
        assert!(answer.error.is_none());
    }

    #[test]
    fn a_target_that_cannot_be_read_is_reported_by_its_code() {
        let exec = Arc::new(FakeMutationExecutor {
            rollback_target: Err(OperationError {
                args: Default::default(),
                code: "revision-integrity-rejected".into(),
                message: "x".into(),
            }),
            ..FakeMutationExecutor::default()
        });
        let (h, _ops) = handler(&exec);
        let answer = dry_run_answer(&h, serde_json::json!({ "dry-run": true }), &ctx());
        assert!(answer.confirmation_token.is_none());
        assert_eq!(
            answer.error.map(|e| e.code).as_deref(),
            Some("revision-integrity-rejected")
        );
    }

    /// A failed rollback is answered as accepted with its operation id; the
    /// verdict is on the operation record the GUI reads next.
    #[test]
    fn a_failed_rollback_is_recorded_as_failed() {
        let exec = Arc::new(FakeMutationExecutor::always_fail(
            "activation-not-recorded",
            "x",
        ));
        let (h, ops) = handler(&exec);
        let token = dry_run(&h, None, &ctx());
        let resp: RollbackResponse =
            serde_json::from_value(rollback(&h, &token, serde_json::json!({}), &ctx()).unwrap())
                .unwrap();
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Failed);
    }

    #[test]
    fn rollback_to_target_revision_propagates_id_to_executor() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let token = dry_run(&h, Some("rev-42"), &ctx());
        rollback(
            &h,
            &token,
            serde_json::json!({ "target-revision-id": "rev-42" }),
            &ctx(),
        )
        .unwrap();
        assert_eq!(
            *exec.last_rollback_target.lock().unwrap(),
            Some("rev-42".to_string())
        );
    }

    /// The token authorises the target that was reviewed, not another one.
    #[test]
    fn a_token_for_one_target_does_not_roll_back_to_another() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let token = dry_run(&h, Some("rev-42"), &ctx());
        let err = rollback(
            &h,
            &token,
            serde_json::json!({ "target-revision-id": "rev-7" }),
            &ctx(),
        )
        .expect_err("a different target must be refused");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert_eq!(exec.rollback_count(), 0);
    }

    #[test]
    fn a_token_the_service_never_issued_is_refused() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let err = rollback(&h, "x", serde_json::json!({}), &ctx()).expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
        assert_eq!(exec.rollback_count(), 0);
    }

    #[test]
    fn an_expired_token_is_refused() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let ops = Arc::new(OperationStatusStore::new());
        let h = RollbackHandler::new(exec.clone(), Arc::new(MutationTokenStore::new()), ops)
            .with_token_ttl(Duration::ZERO);
        let token = dry_run(&h, None, &ctx());
        let err = rollback(&h, &token, serde_json::json!({}), &ctx()).expect_err("expired");
        assert_eq!(err.code, IpcErrorCode::ConfirmationExpired);
        assert_eq!(exec.rollback_count(), 0);
    }

    #[test]
    fn rejects_a_class_that_does_not_match_the_request() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        for (payload, wrong) in [
            (serde_json::json!({}), IpcOperationClass::ReadSnapshot),
            (serde_json::json!({}), IpcOperationClass::MutationRequest),
            (
                serde_json::json!({ "admin-baseline": true }),
                IpcOperationClass::UserScopedMutation,
            ),
            (
                serde_json::json!({ "dry-run": true }),
                IpcOperationClass::UserScopedMutation,
            ),
        ] {
            let mut env = envelope(Some("t"), payload.clone());
            env.operation_class = wrong;
            let err = h.handle(&env, &ctx()).expect_err("mislabelled");
            assert_eq!(
                err.code,
                IpcErrorCode::MalformedRequest,
                "{payload} as {wrong:?}"
            );
        }
        assert_eq!(exec.rollback_count(), 0);
    }

    #[test]
    fn null_payload_is_rollback_to_lkg() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let token = dry_run(&h, None, &ctx());
        rollback(&h, &token, serde_json::Value::Null, &ctx()).unwrap();
        assert_eq!(
            exec.last_rollback_target.lock().unwrap().as_deref(),
            Some(FAKE_LKG_REVISION)
        );
    }

    /// The caller's own chain needs no rights, and it is the caller's own.
    #[test]
    fn an_unelevated_caller_rolls_back_its_own_rules() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let user = ctx_as(false, Some(SID));
        let token = dry_run(&h, None, &user);
        rollback(&h, &token, serde_json::json!({}), &user).expect("own rollback");
        assert_eq!(exec.last_principal.lock().unwrap().as_deref(), Some(SID));
    }

    /// The same partition rule as an edit: the elevated form is the baseline,
    /// and an administrator's plain rollback is still their own chain.
    #[test]
    fn the_baseline_form_rolls_back_the_shared_baseline() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let token = dry_run_with(
            &h,
            serde_json::json!({ "dry-run": true, "admin-baseline": true }),
            &ctx(),
        );
        rollback(
            &h,
            &token,
            serde_json::json!({ "admin-baseline": true }),
            &ctx(),
        )
        .expect("baseline rollback");
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(nrr_storage::BASELINE_PRINCIPAL)
        );
        let token = dry_run(&h, None, &ctx());
        rollback(&h, &token, serde_json::json!({}), &ctx()).expect("own rollback");
        assert_eq!(exec.last_principal.lock().unwrap().as_deref(), Some(SID));
    }

    /// A token reviewed for one partition does not roll back the other.
    #[test]
    fn a_token_for_the_own_chain_does_not_roll_back_the_baseline() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let token = dry_run(&h, None, &ctx());
        let err = rollback(
            &h,
            &token,
            serde_json::json!({ "admin-baseline": true }),
            &ctx(),
        )
        .expect_err("partition differs from the dry-run's");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert_eq!(exec.rollback_count(), 0);
    }

    /// Nobody to attribute an own chain to: refused, never read as baseline.
    #[test]
    fn an_anonymous_own_rollback_is_refused() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let anonymous = ctx_as(true, None);
        let err = h
            .handle(
                &envelope(None, serde_json::json!({ "dry-run": true })),
                &anonymous,
            )
            .expect_err("no principal to read a chain of");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        let err = rollback(&h, "x", serde_json::json!({}), &anonymous).expect_err("no principal");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert_eq!(exec.rollback_count(), 0);
    }

    /// A non-elevated caller who cannot author a rule must not be able to
    /// reach an older rule set through the rollback door either.
    #[test]
    fn locked_machine_refuses_a_non_elevated_rollback() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let h = h.with_stability_provider(FakeRulesLock::locked());
        let non_elevated = ctx_as(false, Some("S-1-5-21-KID"));
        let err = h
            .handle(
                &envelope(None, serde_json::json!({ "dry-run": true })),
                &non_elevated,
            )
            .expect_err("locked machine must refuse the dry-run already");
        assert_eq!(err.code, IpcErrorCode::RulesLocked);
        let err = rollback(&h, "x", serde_json::json!({}), &non_elevated)
            .expect_err("locked machine must refuse the rollback");
        assert_eq!(err.code, IpcErrorCode::RulesLocked);
        assert_eq!(exec.rollback_count(), 0);
    }

    /// The administrator still recovers a previous revision on a locked box.
    #[test]
    fn locked_machine_still_allows_an_elevated_rollback() {
        let exec = Arc::new(FakeMutationExecutor::default());
        let (h, _ops) = handler(&exec);
        let h = h.with_stability_provider(FakeRulesLock::locked());
        let token = dry_run(&h, None, &ctx());
        rollback(&h, &token, serde_json::json!({}), &ctx())
            .expect("elevated rollback must pass the lock");
        assert_eq!(exec.rollback_count(), 1);
    }
}

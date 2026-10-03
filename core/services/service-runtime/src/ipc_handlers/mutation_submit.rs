//! `MutationSubmit` handler — the only entrypoint for changing service
//! state from the GUI.
//!
//! ## Two-step protocol
//!
//! 1. **Dry run.** Client sends `dry_run = true` with
//!    `operation_class = ReadSnapshot` (router does not require a token
//!    for this class, by design — there isn't one yet). The handler
//!    computes a `ReviewSummary`, mints a confirmation token, stashes
//!    the mutation payload under it, and returns
//!    `{ review_summary, confirmation_token, review_risk_level }`.
//!
//! 2. **Confirm.** Client sends `dry_run = false` with the token in
//!    the envelope's `confirmation_token` field and
//!    `operation_class = MutationRequest`. The router enforces token
//!    presence and audit emission *before* dispatch reaches us. We
//!    consume the token (one-shot), execute the mutation through
//!    [`MutationExecutor`], and return `{ operation_id }`.
//!
//! ## Class-based dry-run gate
//!
//! This reuses the router's existing `requires_confirmation_token`
//! check rather than introducing a new gate. Clients pick the class
//! per request:
//! - dry-run ⇒ `ReadSnapshot` (no token)
//! - confirm ⇒ `MutationRequest` (token mandatory)
//!
//! The handler enforces consistency between `dry_run` and class so a
//! confused client gets `MalformedRequest`, not silent success.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcOperationClass, IpcRequestContext,
    IpcRequestEnvelope,
};
use crate::ipc_handlers::mutation_token_store::{
    MutationTokenStore, StoredMutation, DEFAULT_MUTATION_TOKEN_TTL,
};
use crate::ipc_handlers::operation_status_store::OperationStatusStore;
use crate::ipc_handlers::payloads::{
    MutationConfirmResponse, MutationDryRunResponse, MutationKind, MutationSubmitRequest,
};
use crate::ipc_handlers::providers::{
    review_risk_level, rule_edits_allowed_for, MutationExecutor, MutationOutcome,
    ServiceStabilityConfigProvider, RULES_LOCKED_MESSAGE,
};
use crate::tamper_bootstrap::{
    is_blocking_alert_kind, mutation_refused_by_alert, mutations_blocked_by_alert,
    SECURITY_ALERT_GATE_MESSAGE,
};
use nrr_diagnostics::audit::alert::SecurityAlertsRepository;
use nrr_shared::ipc::IpcOperationName;

/// Answers whether any principal OTHER than the caller (and the shared
/// baseline) holds revisions.
///
/// A closure over the state DB at the composition root, so this module never
/// learns what a revision table looks like. `None` (tests, degraded boot) reads
/// as "nobody else", which keeps the pre-existing behaviour.
pub type OtherPrincipalsHoldRevisionsFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub struct MutationSubmitHandler {
    executor: Arc<dyn MutationExecutor>,
    token_store: Arc<MutationTokenStore>,
    operation_store: Arc<OperationStatusStore>,
    token_ttl: Duration,
    /// When wired, the handler refuses any
    /// non-alert mutation while an unacknowledged DB tamper / key-reset
    /// alert is active. `None` in early bring-up / tests leaves the
    /// gate open.
    alerts_repo: Option<Arc<dyn SecurityAlertsRepository>>,
    /// Reader for the machine-wide administrative rules lock. `None` leaves
    /// the gate open (degraded boot / tests) — see `rule_edits_allowed_for`.
    stability: Option<Arc<dyn ServiceStabilityConfigProvider>>,
    /// Reader for "would clearing this alert speak for somebody else?" — see
    /// [`OtherPrincipalsHoldRevisionsFn`].
    other_principals_hold_revisions: Option<OtherPrincipalsHoldRevisionsFn>,
}

impl MutationSubmitHandler {
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
            alerts_repo: None,
            stability: None,
            other_principals_hold_revisions: None,
        }
    }

    /// Attach the security-alerts repository so
    /// the handler can enforce the tamper gate. Without it, the gate is
    /// inert (no blocking).
    #[must_use]
    pub fn with_alerts_repo(mut self, repo: Arc<dyn SecurityAlertsRepository>) -> Self {
        self.alerts_repo = Some(repo);
        self
    }

    /// Attach the reader for [`Self::other_principals_hold_revisions`].
    #[must_use]
    pub fn with_other_principals_reader(mut self, reads: OtherPrincipalsHoldRevisionsFn) -> Self {
        self.other_principals_hold_revisions = Some(reads);
        self
    }

    /// Attach the reader for the machine-wide administrative rules lock, so a
    /// non-elevated caller is refused at the wire with a code the client can
    /// render as a durable read-only state. Without it the gate is inert.
    #[must_use]
    pub fn with_stability_provider(
        mut self,
        provider: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.stability = Some(provider);
        self
    }

    /// Override the default 5-minute TTL. Used by tests; production
    /// path always uses [`DEFAULT_MUTATION_TOKEN_TTL`].
    #[cfg(test)]
    pub fn with_token_ttl(mut self, ttl: Duration) -> Self {
        self.token_ttl = ttl;
        self
    }
}

impl IpcHandler for MutationSubmitHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: MutationSubmitRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("mutation.submit payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        let is_alert_mutation = matches!(
            body.mutation_kind,
            MutationKind::SecurityAlertAck | MutationKind::SecurityAlertResolve
        );
        // The stand-in for other users' alerts is never stored: what it stands
        // for only an administrator can clear, and they see the alerts proper.
        if is_alert_mutation
            && body
                .payload
                .get("alert-id")
                .and_then(serde_json::Value::as_str)
                == Some(crate::alert_audience::OTHER_PRINCIPAL_ALERT_ID)
        {
            return Err(IpcError {
                code: IpcErrorCode::Forbidden,
                message: "This alert concerns another user's rules — administrator rights required"
                    .into(),
                diagnostics_id: None,
            });
        }

        // Tamper gate, answered here on both phases so the dry-run is refused
        // too; the executor enforces the same predicate for every other writer.
        if let Some(repo) = self.alerts_repo.as_ref() {
            if mutation_refused_by_alert(body.mutation_kind, repo.as_ref()) {
                return Err(IpcError {
                    code: IpcErrorCode::SecurityAlertUnacknowledged,
                    message: SECURITY_ALERT_GATE_MESSAGE.into(),
                    diagnostics_id: None,
                });
            }
            // Clearing a blocking alert adopts the rows it lists as legitimate —
            // after a key reset, every row the lost key signed. Where the caller
            // is the only user with revisions — the ordinary single-user machine —
            // that statement is about their own data and needs no ceremony.
            // Where somebody else's rows would be adopted too, it is a decision
            // taken on another person's behalf, and that is what elevation is
            // for in this product (the same line the shared baseline sits
            // behind). Note the write path is already administrator-only, so
            // this is not what stops tampering; it is what stops one user
            // silently blessing another's rows.
            // Resolving an already acknowledged tamper / key-reset alert adopts
            // rows just the same, with no active alert left to trip the check.
            let targets_blocking_alert = || {
                body.payload
                    .get("alert-id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|id| repo.find_by_id(id).ok().flatten())
                    .is_some_and(|a| is_blocking_alert_kind(&a.kind))
            };
            if is_alert_mutation
                && !ctx.caller_is_elevated
                && (mutations_blocked_by_alert(repo.as_ref()) || targets_blocking_alert())
                && self
                    .other_principals_hold_revisions
                    .as_ref()
                    .is_some_and(|reads| reads(ctx.caller_stored()))
            {
                return Err(IpcError {
                    code: IpcErrorCode::Forbidden,
                    message: "Clearing this alert also adopts other users' rules — \
                              administrator rights required"
                        .into(),
                    diagnostics_id: None,
                });
            }
        }

        // Administrative rules lock. Refused on BOTH phases: the dry-run
        // already persists a candidate revision, and a client that learns the
        // answer only at confirm would show the user a diff it can never
        // apply. Elevation, not the target partition, is the discriminator —
        // an administrator keeps editing both the baseline and their own
        // rules. Kinds that do not change routing (alert acknowledgement)
        // stay open by `MutationKind::changes_rules`.
        if body.mutation_kind.changes_rules()
            && !rule_edits_allowed_for(self.stability.as_ref(), ctx.caller_is_elevated)
        {
            return Err(IpcError {
                code: IpcErrorCode::RulesLocked,
                message: RULES_LOCKED_MESSAGE.into(),
                diagnostics_id: None,
            });
        }

        if body.dry_run {
            self.handle_dry_run(request, body, ctx)
        } else {
            self.handle_confirm(request, body, ctx)
        }
    }
}

/// The rules partition a confirmed rule-book write (an edit or a rollback)
/// lands in, from its derived class and the authenticated caller.
///
/// - [`IpcOperationClass::UserScopedMutation`] → the caller's own SID. A
///   transport or harness that omits the SID has nobody to attribute the
///   write to, so it is refused as unauthenticated.
/// - an elevation-gated class → the shared admin baseline; the router has
///   already demanded the rights before the handler runs.
pub(crate) fn resolve_confirm_principal(
    class: IpcOperationClass,
    caller_sid: &str,
) -> Result<String, IpcError> {
    match class {
        IpcOperationClass::UserScopedMutation => {
            if caller_sid.is_empty() {
                return Err(IpcError {
                    code: IpcErrorCode::Forbidden,
                    message: "user-scoped mutation requires an authenticated caller SID".into(),
                    diagnostics_id: None,
                });
            }
            Ok(caller_sid.to_string())
        }
        class if class.requires_elevation() => Ok(nrr_storage::BASELINE_PRINCIPAL.to_string()),
        class => Err(IpcError {
            code: IpcErrorCode::MalformedRequest,
            message: format!("{} does not write a rules partition", class.slug()),
            diagnostics_id: None,
        }),
    }
}

/// Principal the **dry-run** preview is diffed against. A preview is a
/// read against the caller's effective active rules (read-through to
/// baseline for an un-diverged user), so it keys off the caller's own
/// SID when authenticated, falling back to baseline otherwise.
fn preview_principal(caller_sid: &str) -> String {
    if caller_sid.is_empty() {
        nrr_storage::BASELINE_PRINCIPAL.to_string()
    } else {
        caller_sid.to_string()
    }
}

impl MutationSubmitHandler {
    fn handle_dry_run(
        &self,
        request: &IpcRequestEnvelope,
        body: MutationSubmitRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        // Class consistency: dry-run intentionally bypasses the
        // router-level token gate by declaring `ReadSnapshot`. A
        // mismatched envelope is almost certainly a client bug.
        if request.operation_class != IpcOperationClass::ReadSnapshot {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "mutation.submit dry-run requires operation_class = read-snapshot; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        // Preview the caller's effective rules and bind
        // the minted token to the caller's SID so it cannot be replayed
        // by a different principal on confirm.
        //
        // An admin "set baseline" dry-run (payload flag
        // `admin-baseline: true`) previews against the BASELINE partition
        // so the diff matches what the elevated confirm will commit, even
        // if the admin has its own diverged per-SID rules. The dry-run
        // itself is read-only (no elevation needed to preview baseline);
        // the commit is gated by the `mutation-request` class on confirm.
        let admin_baseline = body
            .payload
            .get("admin-baseline")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let principal = if admin_baseline {
            nrr_storage::BASELINE_PRINCIPAL.to_string()
        } else {
            preview_principal(ctx.caller_stored())
        };
        let summary = self
            .executor
            .preview(body.mutation_kind, &body.payload, &principal);
        let unverified_rows = match body.mutation_kind {
            MutationKind::SecurityAlertAck | MutationKind::SecurityAlertResolve => self
                .executor
                .unverified_rows(body.mutation_kind, &body.payload),
            _ => Vec::new(),
        };
        let now = Instant::now();
        let token = self.token_store.issue(
            IpcOperationName::MutationSubmit,
            StoredMutation::from_request(&body, ctx.caller_stored(), ctx.caller_is_elevated),
            now + self.token_ttl,
        );

        let resp = MutationDryRunResponse {
            review_risk_level: review_risk_level(&summary),
            review_summary: summary,
            confirmation_token: token,
            unverified_rows,
            audit_chain: self.executor.audit_chain_preview(body.mutation_kind),
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("mutation.submit dry-run response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }

    fn handle_confirm(
        &self,
        request: &IpcRequestEnvelope,
        body: MutationSubmitRequest,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        // Confirm accepts either the elevated baseline
        // class (`MutationRequest`) or the non-elevated per-principal
        // class (`UserScopedMutation`). The router has already enforced
        // the token gate (both classes require one) and, for
        // `MutationRequest`, elevation.
        if !matches!(
            request.operation_class,
            IpcOperationClass::MutationRequest | IpcOperationClass::UserScopedMutation
        ) {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!(
                    "mutation.submit confirm requires operation_class = mutation-request \
                     or user-scoped-mutation; got {:?}",
                    request.operation_class
                ),
                diagnostics_id: None,
            });
        }

        // Derive the target principal from the class + authenticated
        // caller SID BEFORE consuming the token, so an unauthenticated
        // user-scoped confirm is refused without spending the token.
        let principal = if body.mutation_kind == MutationKind::AuditChainRestart {
            // No partition to act on: the restart records the administrator
            // who confirmed it, whoever ran the dry-run.
            ctx.caller_stored().to_string()
        } else {
            resolve_confirm_principal(request.operation_class, ctx.caller_stored())?
        };

        // Router has already verified the token is present and
        // non-empty (PreconditionFailed). Defensive check below
        // surfaces a well-formed error if the router contract drifts.
        let token = request
            .confirmation_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "mutation.submit confirm requires a non-empty confirmation token".into(),
                diagnostics_id: None,
            })?;

        let now = Instant::now();
        let stored = self
            .token_store
            .consume(token, IpcOperationName::MutationSubmit, now)
            .map_err(IpcError::from)?;

        // Cross-principal token isolation, scoped to
        // `UserScopedMutation` only. The token was minted during a dry-run
        // by `stored.issuer_sid`; a different authenticated principal must
        // not replay it to commit content under ITS OWN per-SID scope.
        //
        // Deliberately NOT applied to `MutationRequest`
        // (admin baseline edit): the target is the shared baseline (not
        // the caller's partition), authorization is the router-enforced
        // elevation, and the elevated confirm legitimately arrives under a
        // different SID than the dry-run when a cross-account UAC (or the
        // elevation broker) relays it. Binding the baseline token to the
        // dry-run SID would wrongly reject that flow.
        //
        // Skipped when the issuer SID is empty (non-Windows / harness).
        if request.operation_class == IpcOperationClass::UserScopedMutation
            && !stored.issuer_sid.is_empty()
            && stored.issuer_sid != ctx.caller_stored()
        {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "confirmation token was issued for a different principal".into(),
                diagnostics_id: None,
            });
        }

        // Cross-check: the stored payload must agree with the body the
        // client just sent. The body's `mutation_kind` and `payload`
        // are advisory on confirm, but a divergence is a clear sign
        // of a client/middleware bug — fail loudly rather than execute
        // something the user didn't review.
        if stored.kind != body.mutation_kind {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: format!(
                    "confirm body mutation_kind ({:?}) does not match stored kind ({:?})",
                    body.mutation_kind, stored.kind
                ),
                diagnostics_id: None,
            });
        }

        let op_id = self
            .operation_store
            .enqueue_for(crate::ipc_handlers::operation_status_store::owner_of(ctx));
        let outcome = self.executor.execute(stored, &principal);
        match outcome {
            MutationOutcome::Completed(result) => {
                self.operation_store
                    .complete(&op_id, result, Instant::now());
            }
            MutationOutcome::Failed(error) => {
                self.operation_store.fail(&op_id, error, Instant::now());
            }
        }

        let resp = MutationConfirmResponse {
            operation_id: op_id,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("mutation.submit confirm response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IPC_PROTOCOL_VERSION;
    use crate::ipc_handlers::operation_status_store::OperationState;
    use crate::ipc_handlers::payloads::MutationKind;
    use crate::ipc_handlers::test_fakes::{FakeMutationExecutor, FakeRulesLock};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
            caller_pid: None,
        }
    }

    /// A non-elevated GUI session authenticated as `sid`.
    fn ctx_sid(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
            caller_pid: None,
        }
    }

    /// A confirm envelope declaring the per-principal
    /// `user-scoped-mutation` class.
    fn user_scoped_confirm_envelope(payload: serde_json::Value, token: &str) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-usm".into(),
            correlation_id: None,
            operation: IpcOperationName::MutationSubmit,
            operation_class: IpcOperationClass::UserScopedMutation,
            confirmation_token: Some(token.into()),
            payload,
        }
    }

    fn rules_dry_run_body() -> serde_json::Value {
        serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": { "route": "primary", "rules": [] },
            "dry-run": true,
        })
    }

    fn rules_confirm_body() -> serde_json::Value {
        serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": { "route": "primary", "rules": [] },
            "dry-run": false,
        })
    }

    /// Run a dry-run as `sid` and return the minted confirmation token.
    fn issue_token_as(h: &MutationSubmitHandler, sid: &str) -> String {
        let resp: MutationDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(rules_dry_run_body()), &ctx_sid(sid))
                .expect("dry-run"),
        )
        .unwrap();
        resp.confirmation_token
    }

    fn dry_run_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-dry".into(),
            correlation_id: None,
            operation: IpcOperationName::MutationSubmit,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn confirm_envelope(payload: serde_json::Value, token: &str) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-conf".into(),
            correlation_id: None,
            operation: IpcOperationName::MutationSubmit,
            operation_class: IpcOperationClass::MutationRequest,
            confirmation_token: Some(token.into()),
            payload,
        }
    }

    fn make_handler() -> (
        MutationSubmitHandler,
        Arc<MutationTokenStore>,
        Arc<OperationStatusStore>,
        Arc<FakeMutationExecutor>,
    ) {
        let executor = Arc::new(FakeMutationExecutor::default());
        let tokens = Arc::new(MutationTokenStore::new());
        let ops = Arc::new(OperationStatusStore::new());
        let h = MutationSubmitHandler::new(executor.clone(), tokens.clone(), ops.clone());
        (h, tokens, ops, executor)
    }

    #[test]
    fn dry_run_returns_review_summary_and_token() {
        let (h, tokens, _ops, _exec) = make_handler();
        let resp = h
            .handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": { "route": "primary", "rules": [] },
                    "dry-run": true,
                })),
                &ctx(),
            )
            .expect("happy dry-run");
        let parsed: MutationDryRunResponse = serde_json::from_value(resp).unwrap();
        assert!(!parsed.confirmation_token.is_empty());
        assert_eq!(tokens.len(), 1);
    }

    #[test]
    fn dry_run_rejects_mutation_request_class() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let mut env = dry_run_envelope(serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": {},
            "dry-run": true,
        }));
        env.operation_class = IpcOperationClass::MutationRequest;
        let err = h.handle(&env, &ctx()).expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn confirm_executes_mutation_and_returns_operation_id() {
        let (h, tokens, ops, exec) = make_handler();
        // Issue a token via dry-run.
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": { "route": "primary", "rules": [] },
                    "dry-run": true,
                })),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();

        // Confirm with the issued token.
        let resp: MutationConfirmResponse = serde_json::from_value(
            h.handle(
                &confirm_envelope(
                    serde_json::json!({
                        "mutation-kind": "rules-update",
                        "payload": { "route": "primary", "rules": [] },
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
        assert_eq!(tokens.len(), 0, "token must be consumed");
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Completed);
        assert_eq!(exec.executed_count(), 1);
    }

    #[test]
    fn confirm_rejects_unknown_token() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({
                        "mutation-kind": "rules-update",
                        "payload": {},
                        "dry-run": false,
                    }),
                    "no-such-token",
                ),
                &ctx(),
            )
            .expect_err("unknown token");
        assert_eq!(err.code, IpcErrorCode::ConfirmationUnknown);
    }

    #[test]
    fn confirm_rejects_expired_token() {
        let (executor, tokens, ops) = (
            Arc::new(FakeMutationExecutor::default()),
            Arc::new(MutationTokenStore::new()),
            Arc::new(OperationStatusStore::new()),
        );
        let h = MutationSubmitHandler::new(executor, tokens.clone(), ops)
            .with_token_ttl(Duration::from_nanos(1));
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
                    "dry-run": true,
                })),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();
        // Sleep just long enough that the 1-nanosecond token is past
        // its expiry on the next monotonic clock read.
        std::thread::sleep(Duration::from_millis(2));
        let err = h
            .handle(
                &confirm_envelope(
                    serde_json::json!({
                        "mutation-kind": "rules-update",
                        "payload": {},
                        "dry-run": false,
                    }),
                    &dry.confirmation_token,
                ),
                &ctx(),
            )
            .expect_err("expired");
        assert_eq!(err.code, IpcErrorCode::ConfirmationExpired);
        assert_eq!(tokens.len(), 0, "expired token must still be removed");
    }

    #[test]
    fn confirm_rejects_kind_mismatch_between_body_and_stored() {
        let (h, _tokens, _ops, _exec) = make_handler();
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
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
                    serde_json::json!({
                        "mutation-kind": "preset-import",
                        "payload": {},
                        "dry-run": false,
                    }),
                    &dry.confirmation_token,
                ),
                &ctx(),
            )
            .expect_err("kind mismatch");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn confirm_records_failure_when_executor_fails() {
        let executor = Arc::new(FakeMutationExecutor::always_fail(
            "mutation.rejected.policy-degraded",
            "service is degraded",
        ));
        let tokens = Arc::new(MutationTokenStore::new());
        let ops = Arc::new(OperationStatusStore::new());
        let h = MutationSubmitHandler::new(executor, tokens, ops.clone());
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
                    "dry-run": true,
                })),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();
        let resp: MutationConfirmResponse = serde_json::from_value(
            h.handle(
                &confirm_envelope(
                    serde_json::json!({
                        "mutation-kind": "rules-update",
                        "payload": {},
                        "dry-run": false,
                    }),
                    &dry.confirmation_token,
                ),
                &ctx(),
            )
            .unwrap(),
        )
        .unwrap();
        let rec = ops.get(&resp.operation_id).unwrap();
        assert_eq!(rec.state, OperationState::Failed);
        assert_eq!(rec.error.unwrap().code, "mutation.rejected.policy-degraded");
    }

    fn alerts_with_active_tamper(
    ) -> Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> {
        use nrr_diagnostics::audit::alert::{
            InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState,
        };
        let repo = InMemorySecurityAlertsRepository::new();
        repo.insert(&SecurityAlert {
            alert_id: "alt-dbtamper-rev-1".into(),
            kind: "db_tamper_detected".into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: "scan".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1,
            updated_at: 1,
            reason_code: "integrity.db_row_hmac_mismatch".into(),
        })
        .expect("seed alert");
        Arc::new(repo)
    }

    #[test]
    fn tamper_gate_blocks_rules_update_dry_run() {
        let (h, _t, _o, _e) = make_handler();
        let h = h.with_alerts_repo(alerts_with_active_tamper());
        let err = h
            .handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "rules-update",
                    "payload": {},
                    "dry-run": true,
                })),
                &ctx(),
            )
            .expect_err("must be blocked");
        assert_eq!(err.code, IpcErrorCode::SecurityAlertUnacknowledged);
        assert!(err.message.contains("acknowledge"));
    }

    /// Clearing a key-reset alert adopts every row the lost key signed, so on a
    /// machine where someone else holds revisions it adopts their rules too. That is a
    /// statement made on another person's behalf, and it costs elevation — the
    /// same line the shared baseline sits behind.
    ///
    /// It is NOT what stops tampering: the state DB is administrator-writable
    /// only. It stops one user silently blessing another's rows.
    #[test]
    fn clearing_the_alert_for_other_users_rows_needs_elevation() {
        let (h, _t, _o, _e) = make_handler();
        let h = h
            .with_alerts_repo(alerts_with_active_tamper())
            .with_other_principals_reader(Arc::new(|_caller: &str| true));
        let err = h
            .handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "security-alert-ack",
                    "payload": { "alert-id": "alt-dbtamper-rev-1" },
                    "dry-run": true,
                })),
                &ctx_sid("S-1-5-21-1-2-3-1001"),
            )
            .expect_err("an unelevated caller must not adopt another user's rows");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(err.message.contains("other users"), "{}", err.message);
    }

    /// Resolving an alert already acknowledged still adopts rows, so the same
    /// line holds with no active alert left; a non-blocking kind stays open.
    #[test]
    fn resolving_an_acknowledged_blocking_alert_for_other_users_rows_needs_elevation() {
        use nrr_diagnostics::audit::alert::{
            InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState,
        };
        let repo = InMemorySecurityAlertsRepository::new();
        for (id, kind) in [
            ("alt-keyreset-1", "key_reset_with_existing_data"),
            ("alt-audit-1", "tamper_alert_raised"),
        ] {
            repo.insert(&SecurityAlert {
                alert_id: id.into(),
                kind: kind.into(),
                state: SecurityAlertState::Acknowledged,
                raised_event_seq: 0,
                raised_file: "scan".into(),
                ack_event_seq: None,
                ack_file: None,
                resolved_event_seq: None,
                resolved_file: None,
                created_at: 1,
                updated_at: 1,
                reason_code: "r".into(),
            })
            .expect("seed alert");
        }
        let (h, _t, _o, _e) = make_handler();
        let h = h
            .with_alerts_repo(Arc::new(repo))
            .with_other_principals_reader(Arc::new(|_caller: &str| true));
        let resolve = |id: &str| {
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "security-alert-resolve",
                    "payload": { "alert-id": id },
                    "dry-run": true,
                })),
                &ctx_sid("S-1-5-21-1-2-3-1001"),
            )
        };
        let err = resolve("alt-keyreset-1").expect_err("adopts other users' rows");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(
            resolve("alt-audit-1").is_ok(),
            "a kind that adopts nothing needs no elevation"
        );
    }

    /// The entry standing in for another user's alerts names no stored alert;
    /// acknowledging it says who can, rather than "not found".
    #[test]
    fn the_stand_in_for_other_users_alerts_cannot_be_acknowledged() {
        let (h, _t, _o, _e) = make_handler();
        let h = h
            .with_alerts_repo(alerts_with_active_tamper())
            .with_other_principals_reader(Arc::new(|_caller: &str| false));
        for kind in ["security-alert-ack", "security-alert-resolve"] {
            let err = h
                .handle(
                    &dry_run_envelope(serde_json::json!({
                        "mutation-kind": kind,
                        "payload": { "alert-id": crate::alert_audience::OTHER_PRINCIPAL_ALERT_ID },
                        "dry-run": true,
                    })),
                    &ctx_sid("S-1-5-21-1-2-3-1001"),
                )
                .expect_err("nothing stored to acknowledge");
            assert_eq!(err.code, IpcErrorCode::Forbidden, "{kind}");
            assert!(err.message.contains("another user"), "{}", err.message);
        }
    }

    /// The ordinary machine: one user, their own rules, no ceremony. Without
    /// this half the gate would be indistinguishable from "always ask an
    /// administrator", which would leave a single non-admin user unable to
    /// clear an alert raised by nothing worse than a key reset — with every
    /// mutation blocked until somebody with rights showed up.
    #[test]
    fn the_only_user_on_the_machine_clears_their_own_alert_unaided() {
        let (h, _t, _o, _e) = make_handler();
        let h = h
            .with_alerts_repo(alerts_with_active_tamper())
            .with_other_principals_reader(Arc::new(|_caller: &str| false));
        let resp = h.handle(
            &dry_run_envelope(serde_json::json!({
                "mutation-kind": "security-alert-ack",
                "payload": { "alert-id": "alt-dbtamper-rev-1" },
                "dry-run": true,
            })),
            &ctx_sid("S-1-5-21-1-2-3-1001"),
        );
        assert!(
            resp.is_ok(),
            "nobody else's rows are adopted, so nothing to ask for: {resp:?}"
        );
    }

    #[test]
    fn tamper_gate_exempts_security_alert_ack() {
        let (h, _t, _o, _e) = make_handler();
        let h = h.with_alerts_repo(alerts_with_active_tamper());
        // A SecurityAlertAck dry-run must pass the gate (it's how the
        // user clears it). FakeMutationExecutor::preview returns a
        // summary for any kind, so this resolves to a token, not Forbidden.
        let resp = h.handle(
            &dry_run_envelope(serde_json::json!({
                "mutation-kind": "security-alert-ack",
                "payload": { "alert-id": "alt-dbtamper-rev-1" },
                "dry-run": true,
            })),
            &ctx(),
        );
        assert!(
            resp.is_ok(),
            "alert-ack must be exempt from the tamper gate"
        );
    }

    /// Answers every kind with one row, so the test shows the handler asks
    /// only for alert kinds.
    struct RowsExecutor(FakeMutationExecutor);

    impl MutationExecutor for RowsExecutor {
        fn preview(
            &self,
            kind: MutationKind,
            payload: &serde_json::Value,
            principal: &str,
        ) -> crate::ipc_handlers::payloads::ReviewSummaryResponse {
            self.0.preview(kind, payload, principal)
        }
        fn unverified_rows(
            &self,
            _kind: MutationKind,
            _payload: &serde_json::Value,
        ) -> Vec<nrr_shared::ipc_payloads::UnverifiedRowDto> {
            vec![nrr_shared::ipc_payloads::UnverifiedRowDto {
                row: nrr_shared::ipc_payloads::IntegrityRowRef {
                    row_kind: nrr_shared::ipc_payloads::IntegrityRowKind::Revision,
                    principal: nrr_storage::BASELINE_PRINCIPAL.into(),
                    revision_id: "rev-1".into(),
                    content_hash: "ab".into(),
                },
                baseline: true,
                created_at: 1,
                source: None,
                status: None,
                rule_count: None,
            }]
        }
        fn execute(&self, payload: StoredMutation, principal: &str) -> MutationOutcome {
            self.0.execute(payload, principal)
        }
        fn rollback(&self, principal: &str, target: Option<&str>) -> MutationOutcome {
            self.0.rollback(principal, target)
        }
        fn rollback_target(
            &self,
            principal: &str,
            target: Option<&str>,
        ) -> Result<
            Option<nrr_shared::ipc_payloads::RollbackTargetDto>,
            crate::ipc_handlers::operation_status_store::OperationError,
        > {
            self.0.rollback_target(principal, target)
        }
        fn safe_disable(&self, reason: &str) -> MutationOutcome {
            self.0.safe_disable(reason)
        }
    }

    #[test]
    fn an_alert_dry_run_lists_the_rows_acknowledging_would_adopt() {
        let h = MutationSubmitHandler::new(
            Arc::new(RowsExecutor(FakeMutationExecutor::default())),
            Arc::new(MutationTokenStore::new()),
            Arc::new(OperationStatusStore::new()),
        );
        let ack: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(serde_json::json!({
                    "mutation-kind": "security-alert-ack",
                    "payload": { "alert-id": "alt-1" },
                    "dry-run": true,
                })),
                &ctx(),
            )
            .expect("alert dry-run"),
        )
        .unwrap();
        assert_eq!(ack.unverified_rows.len(), 1);

        let rules: MutationDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(rules_dry_run_body()), &ctx())
                .expect("rules dry-run"),
        )
        .unwrap();
        assert!(
            rules.unverified_rows.is_empty(),
            "a rules preview is not an integrity review"
        );
    }

    #[test]
    fn tamper_gate_open_when_no_active_alert() {
        use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
        let (h, _t, _o, _e) = make_handler();
        let h = h.with_alerts_repo(Arc::new(InMemorySecurityAlertsRepository::new()));
        let resp = h.handle(
            &dry_run_envelope(serde_json::json!({
                "mutation-kind": "rules-update",
                "payload": {},
                "dry-run": true,
            })),
            &ctx(),
        );
        assert!(resp.is_ok(), "no active alert → gate open");
    }

    // ── Per-principal user-scoped mutations ──────────────

    #[test]
    fn user_scoped_confirm_commits_under_callers_own_sid() {
        let (h, _tokens, _ops, exec) = make_handler();
        const SID_A: &str = "S-1-5-21-1111-2222-3333-1001";
        let token = issue_token_as(&h, SID_A);
        let resp: MutationConfirmResponse = serde_json::from_value(
            h.handle(
                &user_scoped_confirm_envelope(rules_confirm_body(), &token),
                &ctx_sid(SID_A),
            )
            .expect("user-scoped confirm"),
        )
        .unwrap();
        assert!(resp.operation_id.starts_with("op-"));
        assert_eq!(exec.executed_count(), 1);
        // The principal threaded to the executor is the caller's own SID,
        // NOT the admin baseline — a non-elevated user edits its own rules.
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(SID_A),
            "user-scoped mutation must commit under the caller's SID"
        );
    }

    #[test]
    fn elevated_mutation_request_confirm_targets_baseline() {
        // The legacy / admin path: a `mutation-request` confirm lands on
        // the global baseline principal (elevation enforced by the router,
        // not exercised here — the handler trusts the class).
        let (h, _tokens, _ops, exec) = make_handler();
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(rules_dry_run_body()), &ctx())
                .unwrap(),
        )
        .unwrap();
        h.handle(
            &confirm_envelope(rules_confirm_body(), &dry.confirmation_token),
            &ctx(),
        )
        .expect("baseline confirm");
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(nrr_storage::BASELINE_PRINCIPAL),
            "mutation-request confirm must target the baseline principal"
        );
    }

    #[test]
    fn user_scoped_confirm_without_caller_sid_is_rejected_unauthenticated() {
        let (h, _tokens, _ops, exec) = make_handler();
        // Dry-run with no SID still mints a token (back-compat); the
        // user-scoped CONFIRM is what requires an authenticated caller.
        let token = issue_token_as(&h, "");
        let err = h
            .handle(
                &user_scoped_confirm_envelope(rules_confirm_body(), &token),
                &ctx_sid(""),
            )
            .expect_err("must reject unauthenticated user-scoped confirm");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(err.message.contains("authenticated"));
        assert_eq!(exec.executed_count(), 0, "must not execute");
    }

    #[test]
    fn token_issued_for_principal_a_is_rejected_for_principal_b() {
        let (h, tokens, _ops, exec) = make_handler();
        const SID_A: &str = "S-1-5-21-1111-2222-3333-1001";
        const SID_B: &str = "S-1-5-21-1111-2222-3333-1002";
        // A runs the dry-run; B tries to confirm with A's token.
        let token = issue_token_as(&h, SID_A);
        let err = h
            .handle(
                &user_scoped_confirm_envelope(rules_confirm_body(), &token),
                &ctx_sid(SID_B),
            )
            .expect_err("cross-principal token replay must be refused");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("different principal"));
        assert_eq!(exec.executed_count(), 0, "must not execute B's replay");
        assert_eq!(tokens.len(), 0, "the replayed token is still consumed");
    }

    #[test]
    fn baseline_mutation_request_confirm_ignores_issuer_sid_mismatch() {
        // An admin "set baseline" edit (mutation-request)
        // may be confirmed under a DIFFERENT SID than the dry-run issuer
        // (the elevation broker / a cross-account UAC relays it). The
        // per-principal issuer check must NOT fire for the baseline class,
        // and the target is the baseline partition.
        let (h, _tokens, _ops, exec) = make_handler();
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(
                &dry_run_envelope(rules_dry_run_body()),
                &ctx_sid("S-1-5-21-USER"),
            )
            .unwrap(),
        )
        .unwrap();
        h.handle(
            &confirm_envelope(rules_confirm_body(), &dry.confirmation_token),
            &ctx_sid("S-1-5-21-ADMIN"),
        )
        .expect("baseline confirm across SIDs must succeed");
        assert_eq!(
            exec.last_principal.lock().unwrap().as_deref(),
            Some(nrr_storage::BASELINE_PRINCIPAL),
            "mutation-request confirm targets baseline regardless of caller SID"
        );
    }

    #[test]
    fn own_token_round_trips_for_same_principal() {
        // Control for the cross-principal test: A's token confirmed by A
        // succeeds.
        let (h, _tokens, _ops, exec) = make_handler();
        const SID_A: &str = "S-1-5-21-1111-2222-3333-1001";
        let token = issue_token_as(&h, SID_A);
        h.handle(
            &user_scoped_confirm_envelope(rules_confirm_body(), &token),
            &ctx_sid(SID_A),
        )
        .expect("same-principal confirm");
        assert_eq!(exec.executed_count(), 1);
    }

    /// A chain restart names the administrator who confirmed it, not the
    /// baseline partition and not whoever ran the dry-run.
    #[test]
    fn a_chain_restart_acts_as_the_confirming_administrator() {
        const USER: &str = "S-1-5-21-10-20-30-1001";
        const ADMIN: &str = "S-1-5-21-10-20-30-500";
        let (h, _tokens, _ops, exec) = make_handler();
        let body = |dry_run: bool| {
            serde_json::json!({
                "mutation-kind": "audit-chain-restart",
                "payload": { "breaks-digest": "d1" },
                "dry-run": dry_run,
            })
        };
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(body(true)), &ctx_sid(USER))
                .expect("dry-run"),
        )
        .unwrap();
        let admin = IpcRequestContext {
            caller_is_elevated: true,
            ..ctx_sid(ADMIN)
        };
        h.handle(
            &confirm_envelope(body(false), &dry.confirmation_token),
            &admin,
        )
        .expect("confirm");
        assert_eq!(exec.last_principal.lock().unwrap().as_deref(), Some(ADMIN));
    }

    /// Use this to keep MutationKind exhaustive when new variants land.
    #[test]
    fn mutation_kind_serde_roundtrip_for_all_variants() {
        #[allow(deprecated)]
        let all = [
            MutationKind::RulesUpdate,
            MutationKind::RouteBindingsUpdate,
            MutationKind::PresetImport,
            MutationKind::PresetExport,
            MutationKind::SettingsExport,
            MutationKind::RulesResetToBaseline,
            MutationKind::AuditChainRestart,
        ];
        for k in all {
            let s = serde_json::to_string(&k).unwrap();
            let back: MutationKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
        }
    }

    // ── Administrative rules lock ────────────────────────────────────────

    /// A restricted account is the whole point of the feature: its edits must
    /// die at the service with a code the GUI can turn into a read-only
    /// rules section, not with a generic failure it would show as a toast.
    #[test]
    fn locked_machine_refuses_a_non_elevated_rules_dry_run() {
        let (h, tokens, _ops, exec) = make_handler();
        let h = h.with_stability_provider(FakeRulesLock::locked());
        let err = h
            .handle(
                &dry_run_envelope(rules_dry_run_body()),
                &ctx_sid("S-1-5-21-KID"),
            )
            .expect_err("locked machine must refuse the preview");
        assert_eq!(err.code, IpcErrorCode::RulesLocked);
        assert_eq!(exec.executed_count(), 0);
        assert_eq!(
            tokens.len(),
            0,
            "no confirmation token may be minted for a change that can never be applied"
        );
    }

    /// The confirm phase is gated independently — a token minted before the
    /// administrator turned the lock on must not still be spendable.
    #[test]
    fn locked_machine_refuses_a_non_elevated_confirm_even_with_a_valid_token() {
        let (unlocked, _t, _o, _e) = make_handler();
        const SID: &str = "S-1-5-21-KID";
        let token = issue_token_as(&unlocked, SID);

        let (h, _tokens, _ops, exec) = make_handler();
        let h = h.with_stability_provider(FakeRulesLock::locked());
        let err = h
            .handle(
                &user_scoped_confirm_envelope(rules_confirm_body(), &token),
                &ctx_sid(SID),
            )
            .expect_err("locked machine must refuse the confirm");
        assert_eq!(err.code, IpcErrorCode::RulesLocked);
        assert_eq!(exec.executed_count(), 0, "nothing may be applied");
    }

    /// The administrator who set the lock still edits rules — both the shared
    /// baseline and their own. Elevation, not the target partition, decides.
    #[test]
    fn locked_machine_still_lets_an_elevated_caller_edit() {
        let (h, _tokens, _ops, exec) = make_handler();
        let h = h.with_stability_provider(FakeRulesLock::locked());
        let dry: MutationDryRunResponse = serde_json::from_value(
            h.handle(&dry_run_envelope(rules_dry_run_body()), &ctx())
                .expect("elevated preview must pass the lock"),
        )
        .unwrap();
        h.handle(
            &confirm_envelope(rules_confirm_body(), &dry.confirmation_token),
            &ctx(),
        )
        .expect("elevated confirm must pass the lock");
        assert_eq!(exec.executed_count(), 1);
    }

    /// The default posture: nobody has locked anything, so a restricted user
    /// keeps editing their own rules exactly as before.
    #[test]
    fn unlocked_machine_leaves_a_non_elevated_caller_alone() {
        for provider in [FakeRulesLock::unlocked(), FakeRulesLock::unset()] {
            let (h, _tokens, _ops, exec) = make_handler();
            let h = h.with_stability_provider(provider);
            const SID: &str = "S-1-5-21-KID";
            let token = issue_token_as(&h, SID);
            h.handle(
                &user_scoped_confirm_envelope(rules_confirm_body(), &token),
                &ctx_sid(SID),
            )
            .expect("an unlocked machine must not gate anyone");
            assert_eq!(exec.executed_count(), 1);
        }
    }

    /// Locking rules must not silence the security banner: acknowledging an
    /// alert changes no routing, and a refusal there would only train the
    /// user to ignore it.
    #[test]
    fn locked_machine_still_allows_security_alert_acknowledgement() {
        let (h, _t, _o, _e) = make_handler();
        let h = h.with_stability_provider(FakeRulesLock::locked());
        h.handle(
            &dry_run_envelope(serde_json::json!({
                "mutation-kind": "security-alert-ack",
                "payload": { "alert-id": "alt-1" },
                "dry-run": true,
            })),
            &ctx_sid("S-1-5-21-KID"),
        )
        .expect("alert acknowledgement is not a rule change");
    }
}

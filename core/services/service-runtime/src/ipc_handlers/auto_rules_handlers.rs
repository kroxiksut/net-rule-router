//! `autorules.candidates.{list,accept,dismiss}` and
//! `autorules.dismissed.{list,restore}` handlers.
//!
//! The ops the tray drives when the service has found hosts a routed site
//! needs, plus reviewing and undoing past refusals. All are scoped to the
//! CALLER's own principal and none requires elevation — a user answering a
//! question about their own routing must never meet a UAC prompt, which is
//! also why the tray is an allowed client.

use std::sync::Arc;
use std::time::SystemTime;

use nrr_shared::ipc_payloads::{
    AutoRuleCandidatesActionRequest, AutoRuleCandidatesActionResponse,
    AutoRuleCandidatesListResponse, AutoRuleDismissedListResponse, AutoRuleDismissedRestoreRequest,
    AutoRuleDismissedRestoreResponse,
};

use crate::auto_rules::{ActionSummary, AutoRulesEngine};
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

/// Resolves the principal a request acts for.
///
/// An unattributed caller (a transport that could not capture an identity)
/// cannot be served: suggestions, refusals and rules are all per-principal, so
/// guessing here would show one user another user's findings.
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

fn parse_ids(request: &IpcRequestEnvelope) -> Result<Vec<String>, IpcError> {
    if request.payload.is_null() {
        return Ok(Vec::new());
    }
    let parsed: AutoRuleCandidatesActionRequest = serde_json::from_value(request.payload.clone())
        .map_err(|e| IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("autorules payload invalid: {e}"),
        diagnostics_id: None,
    })?;
    Ok(parsed.ids)
}

fn parse_dismissed_restore_ids(request: &IpcRequestEnvelope) -> Result<Vec<String>, IpcError> {
    if request.payload.is_null() {
        return Ok(Vec::new());
    }
    let parsed: AutoRuleDismissedRestoreRequest = serde_json::from_value(request.payload.clone())
        .map_err(|e| IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("autorules dismissed-restore payload invalid: {e}"),
        diagnostics_id: None,
    })?;
    Ok(parsed.ids)
}

fn action_response(summary: ActionSummary) -> HandlerOutcome {
    serde_json::to_value(AutoRuleCandidatesActionResponse {
        applied: summary.applied,
        unknown: summary.unknown,
        pending: summary.pending as u64,
    })
    .map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("autorules response serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

// ── list ─────────────────────────────────────────────────────────────────────

pub struct AutoRuleCandidatesListHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleCandidatesListHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleCandidatesListHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        serde_json::to_value(AutoRuleCandidatesListResponse {
            candidates: self.engine.candidates(sid),
        })
        .map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("autorules.candidates.list serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

// ── accept ───────────────────────────────────────────────────────────────────

pub struct AutoRuleCandidatesAcceptHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleCandidatesAcceptHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleCandidatesAcceptHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let ids = parse_ids(request)?;
        match self.engine.accept(sid, &ids, SystemTime::now()) {
            Ok(summary) => action_response(summary),
            // The rule write was refused — the Free rule cap, an unacknowledged
            // security alert holding the tamper gate shut, a policy error. Pass
            // the executor's own code through so the caller can tell the user
            // what to do about it rather than seeing a generic failure.
            Err(e) => Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: format!("{}: {}", e.code, e.message),
                diagnostics_id: None,
            }),
        }
    }
}

// ── dismiss ──────────────────────────────────────────────────────────────────

pub struct AutoRuleCandidatesDismissHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleCandidatesDismissHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleCandidatesDismissHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let ids = parse_ids(request)?;
        action_response(self.engine.dismiss(sid, &ids, SystemTime::now()))
    }
}

// ── forget ───────────────────────────────────────────────────────────────────

pub struct AutoRuleCandidatesForgetHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleCandidatesForgetHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleCandidatesForgetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let ids = parse_ids(request)?;
        action_response(self.engine.forget_candidates(sid, &ids, SystemTime::now()))
    }
}

// ── dismissed.list ───────────────────────────────────────────────────────────

pub struct AutoRuleDismissedListHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleDismissedListHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleDismissedListHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        serde_json::to_value(AutoRuleDismissedListResponse {
            dismissed: self.engine.list_dismissed(sid),
        })
        .map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("autorules.dismissed.list serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

// ── dismissed.restore ────────────────────────────────────────────────────────

pub struct AutoRuleDismissedRestoreHandler {
    engine: Arc<AutoRulesEngine>,
}

impl AutoRuleDismissedRestoreHandler {
    pub fn new(engine: Arc<AutoRulesEngine>) -> Self {
        Self { engine }
    }
}

impl IpcHandler for AutoRuleDismissedRestoreHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let ids = parse_dismissed_restore_ids(request)?;
        let summary = self.engine.restore_dismissed(sid, &ids, SystemTime::now());
        serde_json::to_value(AutoRuleDismissedRestoreResponse {
            restored: summary.applied,
            unknown: summary.unknown,
        })
        .map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("autorules.dismissed.restore serialisation failed: {e}"),
            diagnostics_id: None,
        })
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
    use crate::per_sid_orchestrator::{ActiveRulesSnapshot, NoopRulesProvider, RulesProvider};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_storage::auto_rule_dismissals::AutoRuleDismissal;
    use nrr_storage::auto_rules::AutoRulesMode;

    fn engine() -> Arc<AutoRulesEngine> {
        engine_with_store().0
    }

    /// Also hands back the durable store, so a test can seed a refusal
    /// directly — `dismiss` only records ids that are in the live pending set,
    /// which the review/restore surface must not depend on: a refusal can
    /// outlive the service restart that forgot the original candidate.
    fn engine_with_store() -> (Arc<AutoRulesEngine>, Arc<InMemoryDismissalStore>) {
        let mode: AutoRulesModeFn = Arc::new(|_| AutoRulesMode::Suggest);
        let store = Arc::new(InMemoryDismissalStore::new());
        let engine = Arc::new(AutoRulesEngine::new(
            Arc::new(NoopRulesProvider) as Arc<dyn RulesProvider>,
            mode,
            Arc::clone(&store) as Arc<dyn DismissalStore>,
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::UNIX_EPOCH,
        ));
        (engine, store)
    }

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::TrayLightweight,
            caller_is_elevated: false,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-ar".into(),
            correlation_id: None,
            operation: IpcOperationName::AutoRuleCandidatesList,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn listing_for_a_caller_with_nothing_pending_returns_an_empty_set() {
        let h = AutoRuleCandidatesListHandler::new(engine());
        let value = h
            .handle(&req(serde_json::Value::Null), &ctx(Some("S-A")))
            .expect("list");
        let parsed: AutoRuleCandidatesListResponse = serde_json::from_value(value).expect("decode");
        assert!(parsed.candidates.is_empty());
    }

    #[test]
    fn an_unattributed_caller_is_refused_rather_than_served_someone_elses_set() {
        let h = AutoRuleCandidatesListHandler::new(engine());
        let err = h
            .handle(&req(serde_json::Value::Null), &ctx(None))
            .expect_err("no identity");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }

    #[test]
    fn dismissing_unknown_ids_succeeds_and_reports_them_as_unknown() {
        let h = AutoRuleCandidatesDismissHandler::new(engine());
        let value = h
            .handle(
                &req(serde_json::json!({ "ids": ["arc-nope"] })),
                &ctx(Some("S-A")),
            )
            .expect("dismiss");
        let parsed: AutoRuleCandidatesActionResponse =
            serde_json::from_value(value).expect("decode");
        assert_eq!(parsed.applied, 0);
        assert_eq!(parsed.unknown, 1);
    }

    #[test]
    fn a_malformed_payload_is_rejected_before_it_reaches_the_engine() {
        let h = AutoRuleCandidatesAcceptHandler::new(engine());
        let err = h
            .handle(&req(serde_json::json!({ "ids": 7 })), &ctx(Some("S-A")))
            .expect_err("malformed");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn accepting_nothing_is_a_clean_no_op() {
        let h = AutoRuleCandidatesAcceptHandler::new(engine());
        let value = h
            .handle(&req(serde_json::json!({ "ids": [] })), &ctx(Some("S-A")))
            .expect("accept");
        let parsed: AutoRuleCandidatesActionResponse =
            serde_json::from_value(value).expect("decode");
        assert_eq!(parsed.applied, 0);
        assert_eq!(parsed.unknown, 0);
        assert_eq!(parsed.pending, 0);
    }

    #[test]
    fn dismissed_list_for_a_caller_with_nothing_declined_returns_an_empty_set() {
        let h = AutoRuleDismissedListHandler::new(engine());
        let value = h
            .handle(&req(serde_json::Value::Null), &ctx(Some("S-A")))
            .expect("dismissed list");
        let parsed: AutoRuleDismissedListResponse = serde_json::from_value(value).expect("decode");
        assert!(parsed.dismissed.is_empty());
    }

    #[test]
    fn dismissed_list_is_refused_for_an_unattributed_caller() {
        let h = AutoRuleDismissedListHandler::new(engine());
        let err = h
            .handle(&req(serde_json::Value::Null), &ctx(None))
            .expect_err("no identity");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }

    #[test]
    fn a_dismissed_candidate_appears_in_the_review_list_and_can_be_restored() {
        let (e, store) = engine_with_store();
        store.record(
            "S-A",
            &[AutoRuleDismissal {
                candidate_id: "arc-1".to_string(),
                anchor: "site.example".to_string(),
                proposed_match: "cdn.example".to_string(),
                dto_json: String::new(),
            }],
            0,
        );

        let listed = AutoRuleDismissedListHandler::new(Arc::clone(&e))
            .handle(&req(serde_json::Value::Null), &ctx(Some("S-A")))
            .expect("dismissed list");
        let parsed: AutoRuleDismissedListResponse = serde_json::from_value(listed).expect("decode");
        assert_eq!(parsed.dismissed.len(), 1);
        assert_eq!(parsed.dismissed[0].candidate_id, "arc-1");

        let restored = AutoRuleDismissedRestoreHandler::new(Arc::clone(&e))
            .handle(
                &req(serde_json::json!({ "ids": ["arc-1"] })),
                &ctx(Some("S-A")),
            )
            .expect("restore");
        let parsed: AutoRuleDismissedRestoreResponse =
            serde_json::from_value(restored).expect("decode");
        assert_eq!(parsed.restored, 1);
        assert_eq!(parsed.unknown, 0);

        let listed = AutoRuleDismissedListHandler::new(e)
            .handle(&req(serde_json::Value::Null), &ctx(Some("S-A")))
            .expect("dismissed list after restore");
        let parsed: AutoRuleDismissedListResponse = serde_json::from_value(listed).expect("decode");
        assert!(parsed.dismissed.is_empty());
    }

    #[test]
    fn restoring_unknown_ids_succeeds_and_reports_them_as_unknown() {
        let h = AutoRuleDismissedRestoreHandler::new(engine());
        let value = h
            .handle(
                &req(serde_json::json!({ "ids": ["arc-nope"] })),
                &ctx(Some("S-A")),
            )
            .expect("restore");
        let parsed: AutoRuleDismissedRestoreResponse =
            serde_json::from_value(value).expect("decode");
        assert_eq!(parsed.restored, 0);
        assert_eq!(parsed.unknown, 1);
    }

    #[test]
    fn restore_rejects_a_malformed_payload_before_it_reaches_the_engine() {
        let h = AutoRuleDismissedRestoreHandler::new(engine());
        let err = h
            .handle(&req(serde_json::json!({ "ids": 7 })), &ctx(Some("S-A")))
            .expect_err("malformed");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    /// `ActiveRulesSnapshot` is referenced so the test module keeps compiling
    /// against the provider contract the engine depends on.
    #[allow(dead_code)]
    fn _snapshot_type_is_in_scope(s: ActiveRulesSnapshot) -> ActiveRulesSnapshot {
        s
    }
}

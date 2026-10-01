//! `SecurityAlertsList` handler.
//!
//! | `state_filter`      | Returned set                               |
//! |---------------------|--------------------------------------------|
//! | `None` / `"open"`   | Active + Acknowledged, newest first        |
//! | `"active"`          | Active only, oldest first                  |
//! | `"acknowledged"`    | Acknowledged only, oldest first            |
//! | `"resolved"`        | Resolved only, oldest first                |
//! | `"superseded"`      | Superseded only, oldest first              |
//! | `"all"`             | All states, oldest first across categories |
//!
//! Read through the diagnostics facade, scoped to the audience the service
//! derives from the connection: an alert about another user's rules reaches a
//! non-elevated caller only as one entry that names nobody.

use std::sync::Arc;

use nrr_diagnostics::audit::alert::SecurityAlertState;
use nrr_diagnostics::facade::service::{AlertListFilter, DiagnosticsFacade};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{SecurityAlertsRequest, SecurityAlertsResponse};

pub struct SecurityAlertsHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
}

impl SecurityAlertsHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self { diagnostics }
    }
}

impl IpcHandler for SecurityAlertsHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: SecurityAlertsRequest = if request.payload.is_null() {
            SecurityAlertsRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("security.alerts.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let filter = match req.state_filter.as_deref() {
            None | Some("") | Some("open") => AlertListFilter::Open,
            Some("active") => AlertListFilter::In(SecurityAlertState::Active),
            Some("acknowledged") => AlertListFilter::In(SecurityAlertState::Acknowledged),
            Some("resolved") => AlertListFilter::In(SecurityAlertState::Resolved),
            Some("superseded") => AlertListFilter::In(SecurityAlertState::Superseded),
            Some("all") => AlertListFilter::All,
            Some(other) => {
                return Err(IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("unknown state_filter '{other}'"),
                    diagnostics_id: None,
                });
            }
        };
        let alerts = self
            .diagnostics
            .list_alerts(filter, &ctx.diagnostics_audience())
            .map_err(|e| IpcError {
                code: IpcErrorCode::Internal,
                message: format!("alerts repo query failed: {e}"),
                diagnostics_id: None,
            })?;

        serde_json::to_value(SecurityAlertsResponse { alerts }).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("security.alerts.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::production_diagnostics::ProductionDiagnosticsFacade;
    use nrr_diagnostics::audit::alert::{
        InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertsRepository,
    };
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
    const BOB: &str = "S-1-5-21-1000-1000-1000-1002";

    fn sample(id: &str, state: SecurityAlertState) -> SecurityAlert {
        SecurityAlert {
            alert_id: id.into(),
            kind: "tamper_alert_raised".into(),
            state,
            raised_event_seq: 1,
            raised_file: "nrr_audit_20260509-1.ndjson".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 100,
            updated_at: 100,
            reason_code: "integrity.audit_chain_mismatch".into(),
        }
    }

    fn pointer_alert(principal: &str) -> SecurityAlert {
        SecurityAlert {
            kind: "db_tamper_detected".into(),
            reason_code: "integrity.db_row_hmac_mismatch".into(),
            ..sample(
                &format!("alt-dbtamper-pointer:{principal}@abc"),
                SecurityAlertState::Active,
            )
        }
    }

    fn handler(alerts: &[SecurityAlert]) -> SecurityAlertsHandler {
        let repo = Arc::new(InMemorySecurityAlertsRepository::new());
        for alert in alerts {
            repo.insert(alert).unwrap();
        }
        let dir = std::env::temp_dir();
        SecurityAlertsHandler::new(Arc::new(ProductionDiagnosticsFacade::new(
            &dir,
            &dir,
            None,
            repo as Arc<dyn SecurityAlertsRepository>,
            None,
        )))
    }

    fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-sa".into(),
            correlation_id: None,
            operation: IpcOperationName::SecurityAlertsList,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn caller(principal: Option<&str>, elevated: bool) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: elevated,
            caller_principal: principal
                .and_then(|sid| crate::UserPrincipal::from_windows_sid(sid).ok()),
            caller_pid: None,
        }
    }

    fn dispatch_as(
        handler: &SecurityAlertsHandler,
        payload: serde_json::Value,
        ctx: &IpcRequestContext,
    ) -> SecurityAlertsResponse {
        let resp = handler.handle(&envelope(payload), ctx).expect("handler ok");
        serde_json::from_value(resp).expect("parse response")
    }

    fn dispatch(
        handler: &SecurityAlertsHandler,
        payload: serde_json::Value,
    ) -> SecurityAlertsResponse {
        dispatch_as(handler, payload, &caller(None, false))
    }

    #[test]
    fn an_empty_store_lists_nothing() {
        let resp = dispatch(&handler(&[]), serde_json::json!({}));
        assert!(resp.alerts.is_empty());
    }

    #[test]
    fn open_filter_returns_active_and_acknowledged() {
        let h = handler(&[
            sample("a-active", SecurityAlertState::Active),
            sample("a-ack", SecurityAlertState::Acknowledged),
            sample("a-resolved", SecurityAlertState::Resolved),
        ]);
        let resp = dispatch(&h, serde_json::json!({}));
        assert_eq!(resp.alerts.len(), 2);
        assert!(resp
            .alerts
            .iter()
            .all(|a| a.state == "active" || a.state == "acknowledged"));
    }

    #[test]
    fn state_filter_active_returns_only_active() {
        let h = handler(&[
            sample("a-1", SecurityAlertState::Active),
            sample("a-2", SecurityAlertState::Acknowledged),
        ]);
        let resp = dispatch(&h, serde_json::json!({"state-filter": "active"}));
        assert_eq!(resp.alerts.len(), 1);
        assert_eq!(resp.alerts[0].alert_id, "a-1");
    }

    #[test]
    fn state_filter_all_returns_every_state() {
        let h = handler(&[
            sample("a-1", SecurityAlertState::Active),
            sample("a-2", SecurityAlertState::Acknowledged),
            sample("a-3", SecurityAlertState::Resolved),
            sample("a-4", SecurityAlertState::Superseded),
        ]);
        let resp = dispatch(&h, serde_json::json!({"state-filter": "all"}));
        assert_eq!(resp.alerts.len(), 4);
    }

    #[test]
    fn unknown_state_filter_returns_malformed_request() {
        let err = handler(&[])
            .handle(
                &envelope(serde_json::json!({"state-filter": "bogus"})),
                &caller(None, false),
            )
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    /// The audience comes from the connection: an ordinary user sees their own
    /// row's alert and the machine's, and another user's only as an entry that
    /// names nobody; an administrator sees every alert as stored.
    #[test]
    fn another_users_alert_reaches_a_user_without_their_sid() {
        let h = handler(&[
            sample("alt-audit-1", SecurityAlertState::Active),
            pointer_alert(ALICE),
            pointer_alert(BOB),
        ]);
        for state_filter in ["open", "active", "all"] {
            let payload = serde_json::json!({ "state-filter": state_filter });
            let alice = dispatch_as(&h, payload.clone(), &caller(Some(ALICE), false));
            let mut ids: Vec<&str> = alice.alerts.iter().map(|a| a.alert_id.as_str()).collect();
            ids.sort_unstable();
            let own = format!("alt-dbtamper-pointer:{ALICE}@abc");
            assert_eq!(
                ids,
                [
                    "alt-audit-1",
                    own.as_str(),
                    crate::alert_audience::OTHER_PRINCIPAL_ALERT_ID,
                ],
                "{state_filter}"
            );
            let wire = serde_json::to_string(&alice).unwrap();
            assert!(!wire.contains(BOB), "{state_filter}: {wire}");

            let admin = dispatch_as(&h, payload, &caller(Some(ALICE), true));
            assert_eq!(admin.alerts.len(), 3, "{state_filter}");
            assert!(
                admin.alerts.iter().any(|a| a.alert_id.contains(BOB)),
                "{state_filter}"
            );
        }
    }
}

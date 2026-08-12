//! `SecurityAlertsList` handler.
//!
//! Reads alerts directly from `Arc<dyn SecurityAlertsRepository>`
//! (the SQLite-backed `security_alerts` table) and honours
//! `state_filter`:
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
//! When `IpcHandlerDeps::alerts_repo` is `None` (early bring-up), the
//! handler returns an empty list rather than `Internal` — alerts are a
//! soft surface and the rest of the GUI keeps painting.

use std::sync::Arc;

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::facade::dto::SecurityAlertDto;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{SecurityAlertsRequest, SecurityAlertsResponse};

pub struct SecurityAlertsHandler {
    /// `None` ⇒ handler returns an empty list (early bring-up / no
    /// state DB available). All four `IpcHandlerDeps` constructions
    /// must wire this in production.
    repo: Option<Arc<dyn SecurityAlertsRepository>>,
}

impl SecurityAlertsHandler {
    pub fn new(repo: Option<Arc<dyn SecurityAlertsRepository>>) -> Self {
        Self { repo }
    }
}

impl IpcHandler for SecurityAlertsHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: SecurityAlertsRequest = if request.payload.is_null() {
            SecurityAlertsRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("security.alerts.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        let Some(repo) = self.repo.as_ref() else {
            return serde_json::to_value(SecurityAlertsResponse { alerts: Vec::new() }).map_err(
                |e| IpcError {
                    code: IpcErrorCode::Internal,
                    message: format!("security.alerts.list serialise failed: {e}"),
                    diagnostics_id: None,
                },
            );
        };

        let alerts = match req.state_filter.as_deref() {
            None | Some("") | Some("open") => repo.list_open(),
            Some("active") => repo.list_by_state(SecurityAlertState::Active),
            Some("acknowledged") => repo.list_by_state(SecurityAlertState::Acknowledged),
            Some("resolved") => repo.list_by_state(SecurityAlertState::Resolved),
            Some("superseded") => repo.list_by_state(SecurityAlertState::Superseded),
            Some("all") => list_all(repo.as_ref()),
            Some(other) => {
                return Err(IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("unknown state_filter '{other}'"),
                    diagnostics_id: None,
                });
            }
        }
        .map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("alerts repo query failed: {e}"),
            diagnostics_id: None,
        })?;

        let dto: Vec<SecurityAlertDto> = alerts.into_iter().map(alert_to_dto).collect();
        serde_json::to_value(SecurityAlertsResponse { alerts: dto }).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("security.alerts.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

fn list_all(
    repo: &dyn SecurityAlertsRepository,
) -> nrr_diagnostics::error::DiagnosticsResult<Vec<SecurityAlert>> {
    let mut out = Vec::new();
    for state in [
        SecurityAlertState::Active,
        SecurityAlertState::Acknowledged,
        SecurityAlertState::Resolved,
        SecurityAlertState::Superseded,
    ] {
        out.extend(repo.list_by_state(state)?);
    }
    Ok(out)
}

fn alert_to_dto(a: SecurityAlert) -> SecurityAlertDto {
    let requires_action = a.requires_action();
    SecurityAlertDto {
        alert_id: a.alert_id,
        kind: a.kind,
        state: a.state.as_str().to_string(),
        created_at: a.created_at,
        updated_at: a.updated_at,
        reason_code: a.reason_code,
        raised_file: a.raised_file,
        requires_action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

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

    fn dispatch(
        handler: &SecurityAlertsHandler,
        payload: serde_json::Value,
    ) -> SecurityAlertsResponse {
        let resp = handler
            .handle(
                &IpcRequestEnvelope {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    request_id: "r-sa".into(),
                    correlation_id: None,
                    operation: IpcOperationName::SecurityAlertsList,
                    operation_class: IpcOperationClass::ReadSnapshot,
                    confirmation_token: None,
                    payload,
                },
                &IpcRequestContext {
                    client_profile: IpcClientProfile::GuiInteractive,
                    caller_is_elevated: false,
                    caller_principal: None,
                },
            )
            .expect("handler ok");
        serde_json::from_value(resp).expect("parse response")
    }

    #[test]
    fn no_repo_wired_returns_empty_list() {
        let h = SecurityAlertsHandler::new(None);
        let resp = dispatch(&h, serde_json::json!({}));
        assert!(resp.alerts.is_empty());
    }

    #[test]
    fn open_filter_returns_active_and_acknowledged() {
        let repo = Arc::new(InMemorySecurityAlertsRepository::new());
        repo.insert(&sample("a-active", SecurityAlertState::Active))
            .unwrap();
        repo.insert(&sample("a-ack", SecurityAlertState::Acknowledged))
            .unwrap();
        repo.insert(&sample("a-resolved", SecurityAlertState::Resolved))
            .unwrap();
        let h = SecurityAlertsHandler::new(Some(repo as Arc<dyn SecurityAlertsRepository>));
        let resp = dispatch(&h, serde_json::json!({}));
        assert_eq!(resp.alerts.len(), 2);
        assert!(resp
            .alerts
            .iter()
            .all(|a| a.state == "active" || a.state == "acknowledged"));
    }

    #[test]
    fn state_filter_active_returns_only_active() {
        let repo = Arc::new(InMemorySecurityAlertsRepository::new());
        repo.insert(&sample("a-1", SecurityAlertState::Active))
            .unwrap();
        repo.insert(&sample("a-2", SecurityAlertState::Acknowledged))
            .unwrap();
        let h = SecurityAlertsHandler::new(Some(repo as Arc<dyn SecurityAlertsRepository>));
        let resp = dispatch(&h, serde_json::json!({"state-filter": "active"}));
        assert_eq!(resp.alerts.len(), 1);
        assert_eq!(resp.alerts[0].alert_id, "a-1");
    }

    #[test]
    fn state_filter_all_returns_every_state() {
        let repo = Arc::new(InMemorySecurityAlertsRepository::new());
        repo.insert(&sample("a-1", SecurityAlertState::Active))
            .unwrap();
        repo.insert(&sample("a-2", SecurityAlertState::Acknowledged))
            .unwrap();
        repo.insert(&sample("a-3", SecurityAlertState::Resolved))
            .unwrap();
        repo.insert(&sample("a-4", SecurityAlertState::Superseded))
            .unwrap();
        let h = SecurityAlertsHandler::new(Some(repo as Arc<dyn SecurityAlertsRepository>));
        let resp = dispatch(&h, serde_json::json!({"state-filter": "all"}));
        assert_eq!(resp.alerts.len(), 4);
    }

    #[test]
    fn unknown_state_filter_returns_malformed_request() {
        let repo = Arc::new(InMemorySecurityAlertsRepository::new());
        let h = SecurityAlertsHandler::new(Some(repo as Arc<dyn SecurityAlertsRepository>));
        let err = h
            .handle(
                &IpcRequestEnvelope {
                    protocol_version: IPC_PROTOCOL_VERSION,
                    request_id: "r-sa".into(),
                    correlation_id: None,
                    operation: IpcOperationName::SecurityAlertsList,
                    operation_class: IpcOperationClass::ReadSnapshot,
                    confirmation_token: None,
                    payload: serde_json::json!({"state-filter": "bogus"}),
                },
                &IpcRequestContext {
                    client_profile: IpcClientProfile::GuiInteractive,
                    caller_is_elevated: false,
                    caller_principal: None,
                },
            )
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

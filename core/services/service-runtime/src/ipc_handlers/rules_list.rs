//! `RulesList` handler — returns the current revision's rules table
//! filtered by route. Backed by [`RulesSnapshotProvider`]; production
//! impl reads from `nrr-storage` + active revision.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{RulesListRequest, RulesListResponse};
use crate::ipc_handlers::providers::RulesSnapshotProvider;

pub struct RulesListHandler {
    rules: Arc<dyn RulesSnapshotProvider>,
}

impl RulesListHandler {
    pub fn new(rules: Arc<dyn RulesSnapshotProvider>) -> Self {
        Self { rules }
    }
}

impl IpcHandler for RulesListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RulesListRequest = if request.payload.is_null() {
            RulesListRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("rules.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };

        // Scope the listing to the caller's per-SID active
        // revision (read-through to baseline when un-diverged). An empty
        // caller SID maps to the baseline partition. Without this, a user
        // who applied rules under their own SID saw an empty table because
        // the listing read the baseline partition.
        let principal = if ctx.caller_stored().is_empty() {
            nrr_storage::BASELINE_PRINCIPAL.to_string()
        } else {
            ctx.caller_stored().to_string()
        };
        let resp: RulesListResponse = self.rules.rules_snapshot_for(req.route, &principal);
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("rules.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{RuleRowEntry, RulesRouteFilter};
    use crate::ipc_handlers::test_fakes::FakeRules;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-rl".into(),
            correlation_id: None,
            operation: IpcOperationName::SnapshotDiagnosticsGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn row(id: &str, route: &str) -> RuleRowEntry {
        RuleRowEntry {
            id: id.into(),
            rule_type: "domain".into(),
            match_value: "example.com".into(),
            target_route: route.into(),
            comment: None,
            enabled: true,
            validation_status: "ok".into(),
            validation_message_key: None,
            hosts_override: None,
            origin: None,
        }
    }

    #[test]
    fn returns_rule_rows_from_provider() {
        let provider = Arc::new(FakeRules {
            response: Mutex::new(RulesListResponse {
                rows: vec![row("R-1", "primary"), row("R-2", "secondary")],
                supported_rule_types: vec!["zone".into(), "domain".into()],
                active_revision_id: Some("rev-1".into()),
            }),
            last_filter: Mutex::new(None),
        });
        let h = RulesListHandler::new(provider);
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: RulesListResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.rows.len(), 2);
        assert_eq!(parsed.active_revision_id.as_deref(), Some("rev-1"));
    }

    #[test]
    fn route_filter_is_propagated_to_provider() {
        let provider = Arc::new(FakeRules {
            response: Mutex::new(RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: Vec::new(),
                active_revision_id: None,
            }),
            last_filter: Mutex::new(None),
        });
        let h = RulesListHandler::new(provider.clone());
        let _ = h
            .handle(&req(serde_json::json!({ "route": "primary" })), &ctx())
            .unwrap();
        assert_eq!(
            *provider.last_filter.lock().unwrap(),
            Some(RulesRouteFilter::Primary)
        );
    }

    #[test]
    fn defaults_to_all_routes_when_field_missing() {
        let provider = Arc::new(FakeRules {
            response: Mutex::new(RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: Vec::new(),
                active_revision_id: None,
            }),
            last_filter: Mutex::new(None),
        });
        let h = RulesListHandler::new(provider.clone());
        let _ = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        assert_eq!(
            *provider.last_filter.lock().unwrap(),
            Some(RulesRouteFilter::All)
        );
    }
}

//! `RulesRecentChangesList` — what the caller changed in their own rules
//! lately. Whose rules is taken from the connection, never from the request.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{
    RulesRecentChangesRequest, RulesRecentChangesResponse, RECENT_RULE_CHANGES_MAX_LOOKBACK_SECS,
};
use crate::ipc_handlers::providers::RulesSnapshotProvider;

pub struct RulesRecentChangesHandler {
    rules: Arc<dyn RulesSnapshotProvider>,
    now: fn() -> i64,
}

impl RulesRecentChangesHandler {
    pub fn new(rules: Arc<dyn RulesSnapshotProvider>) -> Self {
        Self {
            rules,
            now: unix_now,
        }
    }

    #[cfg(test)]
    fn with_clock(mut self, now: fn() -> i64) -> Self {
        self.now = now;
        self
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl IpcHandler for RulesRecentChangesHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RulesRecentChangesRequest = if request.payload.is_null() {
            RulesRecentChangesRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("rules.recent-changes.list payload invalid: {e}"),
                diagnostics_id: None,
            })?
        };
        // Nobody to attribute the request to, or the administrator's baseline:
        // no own revisions to tell.
        let principal = ctx.caller_stored();
        let resp = if principal.is_empty() || principal == nrr_storage::BASELINE_PRINCIPAL {
            RulesRecentChangesResponse::default()
        } else {
            let now = (self.now)();
            let since = req.since.clamp(
                now.saturating_sub(RECENT_RULE_CHANGES_MAX_LOOKBACK_SECS),
                now,
            );
            self.rules
                .recent_changes_for(principal, since, now)
                .map_err(|e| IpcError {
                    code: IpcErrorCode::Internal,
                    message: format!("rules.recent-changes.list: {e}"),
                    diagnostics_id: None,
                })?
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("rules.recent-changes.list response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{RulesListResponse, RulesRouteFilter};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        asked: Mutex<Vec<(String, i64, i64)>>,
    }

    impl RulesSnapshotProvider for Recorder {
        fn rules_snapshot(&self, _route_filter: RulesRouteFilter) -> RulesListResponse {
            RulesListResponse {
                rows: Vec::new(),
                supported_rule_types: Vec::new(),
                active_revision_id: None,
                unrecognized: 0,
                main_route_pending: 0,
                base_revision: None,
            }
        }

        fn recent_changes_for(
            &self,
            principal: &str,
            since: i64,
            now: i64,
        ) -> Result<RulesRecentChangesResponse, String> {
            self.asked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((principal.to_owned(), since, now));
            Ok(RulesRecentChangesResponse {
                history_starts_at: Some(since),
                ..RulesRecentChangesResponse::default()
            })
        }
    }

    const NOW: i64 = 1_800_000_000;

    fn fixed_now() -> i64 {
        NOW
    }

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: sid.and_then(|s| crate::UserPrincipal::from_windows_sid(s).ok()),
            caller_pid: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-recent".into(),
            correlation_id: None,
            operation: IpcOperationName::RulesRecentChangesList,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn handler(provider: Arc<Recorder>) -> RulesRecentChangesHandler {
        RulesRecentChangesHandler::new(provider).with_clock(fixed_now)
    }

    #[test]
    fn the_caller_is_whoever_holds_the_connection() {
        let provider = Arc::new(Recorder::default());
        let h = handler(Arc::clone(&provider));
        h.handle(
            &req(serde_json::json!({ "since": NOW - 60, "principal": "S-1-5-21-9-9-9-9" })),
            &ctx(Some("S-1-5-21-1-2-3-1001")),
        )
        .unwrap_or_else(|e| panic!("{e:?}"));
        let asked = provider
            .asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            asked,
            vec![("S-1-5-21-1-2-3-1001".to_owned(), NOW - 60, NOW)]
        );
    }

    #[test]
    fn the_period_is_held_to_the_last_seven_days() {
        let provider = Arc::new(Recorder::default());
        let h = handler(Arc::clone(&provider));
        let sid = Some("S-1-5-21-1-2-3-1001");
        for since in [0, NOW + 3600] {
            h.handle(&req(serde_json::json!({ "since": since })), &ctx(sid))
                .unwrap_or_else(|e| panic!("{e:?}"));
        }
        let asked = provider
            .asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let sinces: Vec<i64> = asked.iter().map(|(_, since, _)| *since).collect();
        assert_eq!(
            sinces,
            vec![NOW - RECENT_RULE_CHANGES_MAX_LOOKBACK_SECS, NOW]
        );
    }

    #[test]
    fn an_unattributed_request_has_nothing_to_tell() {
        let provider = Arc::new(Recorder::default());
        let h = handler(Arc::clone(&provider));
        let resp = h
            .handle(&req(serde_json::Value::Null), &ctx(None))
            .unwrap_or_else(|e| panic!("{e:?}"));
        let parsed: RulesRecentChangesResponse =
            serde_json::from_value(resp).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(parsed, RulesRecentChangesResponse::default());
        assert!(provider
            .asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty());
    }

    #[test]
    fn a_malformed_payload_is_refused() {
        let h = handler(Arc::new(Recorder::default()));
        let err = h
            .handle(
                &req(serde_json::json!({ "since": "yesterday" })),
                &ctx(Some("S-1-5-21-1-2-3-1001")),
            )
            .err()
            .unwrap_or_else(|| panic!("must refuse"));
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}

//! `StatusUpdatesSubscribe` handler — registers a push-event
//! subscription with the [`EventBus`] and returns the initial ack.
//!
//! Push delivery itself happens outside this handler: the named-pipe
//! transport in `nrr-windows-service` drains
//! [`EventBus::peek_pending_for`] on the subscriber's pipe and writes
//! [`StatusUpdatePushFrame`](super::payloads::StatusUpdatePushFrame)
//! envelopes (with `request_id = ""` and
//! `correlation_id = subscription_id`).
//!
//! This handler's contract:
//! 1. Validate the request body.
//! 2. Resolve the resume cursor against the bus's ring buffer:
//!    - `last_seen_event_id = None` ⇒ start at current head.
//!    - `last_seen_event_id` within buffer ⇒ replay missed events.
//!    - `last_seen_event_id` pre-dates buffer ⇒ `gap_detected = true`,
//!      cursor clamped to head, client should resync via
//!      `SnapshotInitialGet`.
//! 3. Return ack `{ subscription_id, current_event_id, gap_detected }`.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::event_bus::EventBus;
use crate::ipc_handlers::payloads::{
    StatusUpdatesSubscribeRequest, StatusUpdatesSubscribeResponse,
};

pub struct StatusUpdatesSubscribeHandler {
    bus: Arc<EventBus>,
}

impl StatusUpdatesSubscribeHandler {
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self { bus }
    }
}

impl IpcHandler for StatusUpdatesSubscribeHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let body: StatusUpdatesSubscribeRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
            code: IpcErrorCode::MalformedRequest,
            message: format!("status.updates.subscribe payload invalid: {e}"),
            diagnostics_id: None,
        })?;

        if body.client_id.trim().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: "status.updates.subscribe requires a non-empty client_id".into(),
                diagnostics_id: None,
            });
        }

        let outcome = self.bus.subscribe(body.client_id, body.last_seen_event_id);
        let resp = StatusUpdatesSubscribeResponse {
            subscription_id: outcome.subscription_id,
            current_event_id: outcome.current_event_id,
            gap_detected: outcome.gap_detected,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("status.updates.subscribe response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::event_bus::EVENT_BUFFER_CAPACITY;
    use crate::ipc_handlers::payloads::StatusUpdateEvent;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

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
            request_id: "r-sub".into(),
            correlation_id: None,
            operation: IpcOperationName::StatusUpdatesSubscribe,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn health() -> StatusUpdateEvent {
        StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: "ok".into(),
        }
    }

    #[test]
    fn first_time_subscribe_returns_current_head_no_gap() {
        let bus = Arc::new(EventBus::new());
        bus.publish(health());
        let h = StatusUpdatesSubscribeHandler::new(bus.clone());
        let resp = h
            .handle(&req(serde_json::json!({ "client-id": "gui-1" })), &ctx())
            .unwrap();
        let parsed: StatusUpdatesSubscribeResponse = serde_json::from_value(resp).unwrap();
        assert!(parsed.subscription_id.starts_with("sub-"));
        assert_eq!(parsed.current_event_id, 2);
        assert!(!parsed.gap_detected);
    }

    #[test]
    fn resubscribe_with_recent_cursor_does_not_signal_gap() {
        let bus = Arc::new(EventBus::new());
        bus.publish(health()); // id=1
        bus.publish(health()); // id=2
        let h = StatusUpdatesSubscribeHandler::new(bus);
        let resp = h
            .handle(
                &req(serde_json::json!({
                    "client-id": "gui-1",
                    "last-seen-event-id": 1,
                })),
                &ctx(),
            )
            .unwrap();
        let parsed: StatusUpdatesSubscribeResponse = serde_json::from_value(resp).unwrap();
        assert!(!parsed.gap_detected);
    }

    #[test]
    fn resubscribe_with_pre_buffer_cursor_signals_gap() {
        let bus = Arc::new(EventBus::new());
        for _ in 0..(EVENT_BUFFER_CAPACITY + 10) {
            bus.publish(health());
        }
        let h = StatusUpdatesSubscribeHandler::new(bus);
        let resp = h
            .handle(
                &req(serde_json::json!({
                    "client-id": "gui-1",
                    "last-seen-event-id": 1,
                })),
                &ctx(),
            )
            .unwrap();
        let parsed: StatusUpdatesSubscribeResponse = serde_json::from_value(resp).unwrap();
        assert!(parsed.gap_detected);
    }

    #[test]
    fn rejects_empty_client_id() {
        let bus = Arc::new(EventBus::new());
        let h = StatusUpdatesSubscribeHandler::new(bus);
        let err = h
            .handle(&req(serde_json::json!({ "client-id": "" })), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn rejects_missing_client_id_field() {
        let bus = Arc::new(EventBus::new());
        let h = StatusUpdatesSubscribeHandler::new(bus);
        let err = h
            .handle(&req(serde_json::json!({})), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn subscribing_increments_subscriber_count() {
        let bus = Arc::new(EventBus::new());
        let h = StatusUpdatesSubscribeHandler::new(bus.clone());
        let _ = h
            .handle(&req(serde_json::json!({ "client-id": "gui-1" })), &ctx())
            .unwrap();
        let _ = h
            .handle(&req(serde_json::json!({ "client-id": "tray-1" })), &ctx())
            .unwrap();
        assert_eq!(bus.subscriber_count(), 2);
    }
}

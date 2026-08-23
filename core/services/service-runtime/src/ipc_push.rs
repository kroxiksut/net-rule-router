//! Push-event delivery, minus the transport.
//!
//! Both IPC servers owe a subscribed client the same thing: after a
//! `StatusUpdatesSubscribe`, drain that subscription's pending events onto the
//! connection in order, advance its cursor past what was delivered, and count a
//! drop when a write fails. Only the framing differs — a Win32 named pipe on one
//! side, an `AF_UNIX` stream on the other — so the decision logic lives here and
//! each server passes in its own writer.

use std::time::Duration;

use nrr_shared::ipc_payloads::StatusUpdatePushFrame;

use crate::IpcResponseEnvelope;

use crate::ipc_handlers::EventBus;

/// How long a connection waits for a request before checking the bus. Short
/// enough that a push feels immediate, long enough that an idle connection is
/// not a spin loop.
pub const PUSH_POLL_INTERVAL: Duration = Duration::from_millis(150);

/// Events written per tick. A backlog drains over several ticks rather than
/// blocking the connection on one enormous burst.
pub const PUSH_BATCH_SIZE: usize = 32;

/// Parses `StatusUpdatesSubscribeResponse.subscription_id` out of a router
/// response. `None` for non-subscribe ops or shape mismatches (the dispatcher
/// already validated the wire shape, so this is defence in depth).
pub fn extract_subscription_id(env: &IpcResponseEnvelope) -> Option<String> {
    let payload = env.payload.as_ref()?;
    payload
        .get("subscription-id")
        .or_else(|| payload.get("subscription_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// One push pump tick. Returns `true` when a write failed, which the caller
/// must treat as "close this connection".
///
/// `write` sends one envelope over the connection; its error text is only
/// logged. The cursor advances to the last envelope written, so a failed frame
/// stays pending and can still be replayed within the buffer window.
pub fn flush_push_frames<W>(
    event_bus: &EventBus,
    subscription_id: &str,
    batch_size: usize,
    mut write: W,
) -> bool
where
    W: FnMut(&IpcResponseEnvelope) -> Result<(), String>,
{
    let pending = event_bus.peek_pending_for(subscription_id, batch_size);
    let mut last_id: Option<u64> = None;
    for entry in pending {
        let push_payload = StatusUpdatePushFrame {
            event_id: entry.event_id,
            event: entry.event.clone(),
        };
        let json_payload = match serde_json::to_value(&push_payload) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::ipc-push",
                    subscription_id,
                    event_id = entry.event_id,
                    error = %e,
                    "push event could not be encoded, skipped"
                );
                continue;
            }
        };
        // The wire tag is the only stable name for the variant here; reading it
        // back beats duplicating a slug table.
        let event_type = json_payload
            .get("event")
            .and_then(|e| e.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let env = IpcResponseEnvelope {
            request_id: String::new(),
            correlation_id: subscription_id.to_string(),
            operation_id: None,
            ok: true,
            stale: false,
            diagnostics_id: None,
            user_action_required: false,
            payload: Some(json_payload),
            error: None,
        };
        if let Err(e) = write(&env) {
            event_bus.record_drop(subscription_id, 1);
            tracing::warn!(
                target: "nrr::ipc-push",
                subscription_id,
                event_id = entry.event_id,
                event_type,
                error = %e,
                "push frame write failed, subscriber dropped it"
            );
            return true;
        }
        tracing::debug!(
            target: "nrr::ipc-push",
            subscription_id,
            event_id = entry.event_id,
            event_type,
            "push frame written"
        );
        last_id = Some(entry.event_id);
    }
    if let Some(id) = last_id {
        event_bus.advance_cursor(subscription_id, id);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;

    fn adapters_event() -> StatusUpdateEvent {
        StatusUpdateEvent::AdaptersChanged {
            data_source: "wmi".into(),
        }
    }

    /// Collects the envelopes a tick produces, in order.
    fn collector(
        sink: &mut Vec<IpcResponseEnvelope>,
    ) -> impl FnMut(&IpcResponseEnvelope) -> Result<(), String> + '_ {
        move |env: &IpcResponseEnvelope| {
            sink.push(env.clone());
            Ok(())
        }
    }

    #[test]
    fn writes_pending_events_in_order_and_advances_the_cursor() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let id1 = bus.publish(StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: "ok".into(),
        });
        let id2 = bus.publish(adapters_event());

        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut sent)
        ));

        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].request_id, "");
        assert_eq!(sent[0].correlation_id, s.subscription_id);
        assert!(sent[0].ok && sent[0].error.is_none());
        let first: StatusUpdatePushFrame =
            serde_json::from_value(sent[0].payload.clone().expect("payload")).expect("decode");
        let second: StatusUpdatePushFrame =
            serde_json::from_value(sent[1].payload.clone().expect("payload")).expect("decode");
        assert_eq!((first.event_id, second.event_id), (id1, id2));
        assert!(
            bus.peek_pending_for(&s.subscription_id, 32).is_empty(),
            "cursor should have advanced past the last delivered id"
        );
    }

    #[test]
    fn nothing_pending_writes_nothing() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut sent)
        ));
        assert!(sent.is_empty());
    }

    #[test]
    fn batch_caps_at_size_and_leaves_the_remainder_pending() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let ids: Vec<u64> = (0..5).map(|_| bus.publish(adapters_event())).collect();

        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            2,
            collector(&mut sent)
        ));
        assert_eq!(sent.len(), 2);

        let pending = bus.peek_pending_for(&s.subscription_id, 32);
        assert_eq!(pending.len(), 3, "remainder should still be pending");
        assert_eq!(pending[0].event_id, ids[2]);
    }

    /// A failed write must not consume the event: the cursor stays put so a
    /// re-subscribe can replay it, one drop is recorded, and the caller is told
    /// to close the connection.
    #[test]
    fn a_failed_write_records_a_drop_and_asks_for_a_close() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let id1 = bus.publish(adapters_event());
        let id2 = bus.publish(adapters_event());

        assert!(flush_push_frames(&bus, &s.subscription_id, 32, |_| Err(
            "transport broken".to_string()
        )));

        let pending = bus.peek_pending_for(&s.subscription_id, 32);
        assert_eq!(pending.len(), 2, "no events delivered yet");
        assert_eq!((pending[0].event_id, pending[1].event_id), (id1, id2));
        assert_eq!(
            bus.take_dropped_count(&s.subscription_id),
            1,
            "exactly one drop recorded for the failed frame"
        );
    }

    #[test]
    fn an_unknown_subscription_is_a_no_op() {
        let bus = EventBus::new();
        let _ = bus.publish(adapters_event());
        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            "no-such-sub",
            32,
            collector(&mut sent)
        ));
        assert!(sent.is_empty());
    }

    /// Cursor advancement is sticky across ticks: a later tick picks up only
    /// what arrived since the previous one.
    #[test]
    fn successive_ticks_pick_up_only_new_events() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);

        let _ = bus.publish(adapters_event());
        let mut first = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut first)
        ));
        assert_eq!(first.len(), 1);

        let mut second = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut second)
        ));
        assert!(second.is_empty(), "no new events, no writes");

        let id2 = bus.publish(adapters_event());
        let mut third = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut third)
        ));
        let frame: StatusUpdatePushFrame =
            serde_json::from_value(third[0].payload.clone().expect("payload")).expect("decode");
        assert_eq!(frame.event_id, id2);
    }

    #[test]
    fn subscription_id_is_read_from_either_spelling() {
        let mut env = IpcResponseEnvelope {
            request_id: "r".into(),
            correlation_id: String::new(),
            operation_id: None,
            ok: true,
            stale: false,
            diagnostics_id: None,
            user_action_required: false,
            payload: Some(serde_json::json!({ "subscription-id": "sub-1" })),
            error: None,
        };
        assert_eq!(extract_subscription_id(&env).as_deref(), Some("sub-1"));
        env.payload = Some(serde_json::json!({ "subscription_id": "sub-2" }));
        assert_eq!(extract_subscription_id(&env).as_deref(), Some("sub-2"));
        env.payload = Some(serde_json::json!({ "other": 1 }));
        assert_eq!(extract_subscription_id(&env), None);
        env.payload = None;
        assert_eq!(extract_subscription_id(&env), None);
    }
}

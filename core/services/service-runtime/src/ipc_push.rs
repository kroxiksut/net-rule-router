//! Push-event delivery, minus the transport.
//!
//! Both IPC servers owe a subscribed client the same thing: after a
//! `StatusUpdatesSubscribe`, drain that subscription's pending events onto the
//! connection in order, advance its cursor past what was delivered, and give the
//! connection up when a write fails. Only the framing differs — a Win32 named pipe on one
//! side, an `AF_UNIX` stream on the other — so the decision logic lives here and
//! each server passes in its own writer.

use std::time::Duration;

use nrr_shared::ipc_payloads::{StatusUpdatePushFrame, PUSH_GAP_EVENT_TYPE};

use crate::IpcResponseEnvelope;

use crate::ipc_handlers::EventBus;

/// How long an idle connection waits before checking the bus anyway. A publish
/// wakes the connection at once (`EventBus::set_waker`); this is only the net
/// under a wake that was missed, and the bound on noticing a service stop.
pub const PUSH_SAFETY_INTERVAL: Duration = Duration::from_secs(1);

/// Events written per batch; a flush keeps taking batches until nothing is
/// pending, so one burst cannot be left waiting for the next wake.
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

/// What one response did to a connection's push subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionChange {
    Unchanged,
    Opened(String),
    Replaced { previous: String, current: String },
}

/// Serve a connection its NEWEST subscription.
///
/// A client that subscribes again on the same connection puts the new channel
/// in force. Keeping the first id left every later subscription on the bus with
/// nobody reading it, and a bus that replaces a client's earlier subscription
/// would have left the connection reading an id that no longer exists.
pub fn adopt_subscription(
    current: &mut Option<String>,
    response: &IpcResponseEnvelope,
    event_bus: Option<&EventBus>,
) -> SubscriptionChange {
    if !response.ok {
        return SubscriptionChange::Unchanged;
    }
    let Some(new_id) = extract_subscription_id(response) else {
        return SubscriptionChange::Unchanged;
    };
    match current.replace(new_id.clone()) {
        None => SubscriptionChange::Opened(new_id),
        Some(previous) if previous == new_id => SubscriptionChange::Unchanged,
        Some(previous) => {
            if let Some(bus) = event_bus {
                bus.unsubscribe(&previous);
            }
            SubscriptionChange::Replaced {
                previous,
                current: new_id,
            }
        }
    }
}

/// The frame that says "events were dropped, re-read the state". It carries the
/// last id the subscriber can no longer get, so the ids stay monotonic.
fn resync_marker(subscription_id: &str, event_id: u64) -> IpcResponseEnvelope {
    IpcResponseEnvelope {
        request_id: String::new(),
        correlation_id: subscription_id.to_string(),
        operation_id: None,
        ok: true,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: Some(serde_json::json!({
            "event-id": event_id,
            "event": { "type": PUSH_GAP_EVENT_TYPE },
        })),
        error: None,
    }
}

/// One push pump tick. Returns `true` when a write failed, which the caller
/// must treat as "close this connection": the client then reconnects, replays
/// its subscription and tells its surface about the gap.
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
    // A subscriber that fell behind the ring is told before anything else, so
    // it re-reads the state instead of rendering from a stream with a hole.
    if let Some(resume_at) = event_bus.lost_events_resume_at(subscription_id) {
        let marker = resync_marker(subscription_id, resume_at - 1);
        if let Err(e) = write(&marker) {
            tracing::warn!(
                target: "nrr::ipc-push",
                subscription_id,
                error = %e,
                "resync marker write failed, connection given up"
            );
            return true;
        }
        tracing::warn!(
            target: "nrr::ipc-push",
            subscription_id,
            resume_at,
            "subscriber fell behind the event ring, resync marker sent"
        );
        event_bus.advance_cursor(subscription_id, resume_at - 1);
    }
    loop {
        let pending = event_bus.peek_pending_for(subscription_id, batch_size);
        let full = pending.len() >= batch_size;
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
                        msg_key = "ipcpush-encode-failed",
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
                tracing::warn!(
                    target: "nrr::ipc-push",
                    msg_key = "ipcpush-write-failed",
                    subscription_id,
                    event_id = entry.event_id,
                    event_type,
                    error = %e,
                    "push frame write failed, connection given up"
                );
                // What did go out is not sent twice to a resumed subscription.
                if let Some(id) = last_id {
                    event_bus.advance_cursor(subscription_id, id);
                }
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
        // Another batch only when this one was full and moved the cursor.
        if !full || last_id.is_none() {
            return false;
        }
    }
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
        let id1 = bus.publish(StatusUpdateEvent::AdaptersChanged {
            data_source: "test".into(),
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

    /// A burst past one batch is not left waiting for a wake that no further
    /// publish will send.
    #[test]
    fn a_backlog_larger_than_a_batch_drains_in_one_flush() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        for _ in 0..(PUSH_BATCH_SIZE * 2 + 5) {
            bus.publish(adapters_event());
        }
        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            PUSH_BATCH_SIZE,
            collector(&mut sent)
        ));
        assert_eq!(sent.len(), PUSH_BATCH_SIZE * 2 + 5);
        assert!(bus.peek_pending_for(&s.subscription_id, 1).is_empty());
    }

    fn subscribe_response(subscription_id: &str) -> IpcResponseEnvelope {
        IpcResponseEnvelope {
            request_id: "r".into(),
            correlation_id: "c".into(),
            operation_id: None,
            ok: true,
            stale: false,
            diagnostics_id: None,
            user_action_required: false,
            payload: Some(serde_json::json!({ "subscription-id": subscription_id })),
            error: None,
        }
    }

    /// A tray that re-subscribed every ten seconds on one connection left a
    /// subscription behind each time; the bus filled to its cap with them.
    #[test]
    fn a_second_subscribe_on_a_connection_replaces_the_first_on_the_bus() {
        let bus = EventBus::new();
        let first = bus.subscribe("tray-1".into(), None).subscription_id;
        let mut current = None;
        assert_eq!(
            adopt_subscription(&mut current, &subscribe_response(&first), Some(&bus)),
            SubscriptionChange::Opened(first.clone())
        );

        let second = bus.subscribe("tray-2".into(), None).subscription_id;
        assert_eq!(
            adopt_subscription(&mut current, &subscribe_response(&second), Some(&bus)),
            SubscriptionChange::Replaced {
                previous: first,
                current: second.clone()
            }
        );
        assert_eq!(current.as_deref(), Some(second.as_str()));
        assert_eq!(bus.subscriber_count(), 1);

        // The connection now reads the subscription that is still there.
        let id = bus.publish(adapters_event());
        let mut sent = Vec::new();
        assert!(!flush_push_frames(&bus, &second, 32, collector(&mut sent)));
        assert_eq!(sent.len(), 1);
        let frame: StatusUpdatePushFrame =
            serde_json::from_value(sent[0].payload.clone().expect("payload")).expect("decode");
        assert_eq!(frame.event_id, id);
    }

    #[test]
    fn responses_that_are_not_a_subscription_leave_it_alone() {
        let bus = EventBus::new();
        let mut current = Some("sub-a".to_string());
        let mut failed = subscribe_response("sub-b");
        failed.ok = false;
        assert_eq!(
            adopt_subscription(&mut current, &failed, Some(&bus)),
            SubscriptionChange::Unchanged
        );
        let mut other = subscribe_response("x");
        other.payload = Some(serde_json::json!({ "rules": [] }));
        assert_eq!(
            adopt_subscription(&mut current, &other, Some(&bus)),
            SubscriptionChange::Unchanged
        );
        assert_eq!(current.as_deref(), Some("sub-a"));
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
    fn a_burst_larger_than_one_batch_is_drained_in_one_flush() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        for _ in 0..5 {
            bus.publish(adapters_event());
        }

        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            2,
            collector(&mut sent)
        ));
        assert_eq!(sent.len(), 5);
        assert!(bus.peek_pending_for(&s.subscription_id, 32).is_empty());
    }

    #[test]
    fn a_write_failing_mid_burst_leaves_the_remainder_pending() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let ids: Vec<u64> = (0..5).map(|_| bus.publish(adapters_event())).collect();

        let mut written = 0;
        assert!(flush_push_frames(&bus, &s.subscription_id, 2, |_| {
            written += 1;
            if written > 3 {
                Err("transport broken".to_string())
            } else {
                Ok(())
            }
        }));

        let pending = bus.peek_pending_for(&s.subscription_id, 32);
        assert_eq!(pending.len(), 2, "unwritten events stay pending");
        assert_eq!(pending[0].event_id, ids[3]);
    }

    /// A failed write must not consume the event: the cursor stays put so a
    /// re-subscribe can replay it, and the caller is told to close the
    /// connection.
    #[test]
    fn a_failed_write_leaves_the_event_pending_and_asks_for_a_close() {
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
    }

    /// A subscriber that falls behind the ring hears about the hole first, then
    /// gets what the ring still holds; a failed marker write keeps the debt.
    #[test]
    fn a_subscriber_behind_the_ring_gets_a_resync_marker_before_the_rest() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        let over = crate::ipc_handlers::EVENT_BUFFER_CAPACITY + 5;
        let ids: Vec<u64> = (0..over).map(|_| bus.publish(adapters_event())).collect();

        assert!(flush_push_frames(&bus, &s.subscription_id, 32, |_| Err(
            "transport broken".to_string()
        )));
        assert!(
            bus.lost_events_resume_at(&s.subscription_id).is_some(),
            "a failed marker write must not consume the debt"
        );

        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            32,
            collector(&mut sent)
        ));
        let marker = sent[0].payload.clone().expect("payload");
        assert_eq!(marker["event"]["type"], PUSH_GAP_EVENT_TYPE);
        assert_eq!(sent[0].correlation_id, s.subscription_id);
        let first_kept = ids[5];
        assert_eq!(marker["event-id"], first_kept - 1);
        let next: StatusUpdatePushFrame =
            serde_json::from_value(sent[1].payload.clone().expect("payload")).expect("decode");
        assert_eq!(next.event_id, first_kept);

        let mut again = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &s.subscription_id,
            1000,
            collector(&mut again)
        ));
        assert!(
            again.iter().all(|e| e
                .payload
                .as_ref()
                .is_some_and(|p| p["event"]["type"] != PUSH_GAP_EVENT_TYPE)),
            "one hole is announced once"
        );
    }

    /// Another user's flood leaving the ring sends this subscriber nothing: no
    /// re-read for a hole it does not have, and no hint that the other user
    /// was busy. Its own events still arrive.
    #[test]
    fn another_users_flood_sends_no_resync_marker() {
        let bus = EventBus::new();
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), None);
        for _ in 0..(crate::ipc_handlers::EVENT_BUFFER_CAPACITY * 2) {
            bus.publish_for("S-1-A", adapters_event());
        }
        let his = bus.publish_for("S-1-B", adapters_event());

        let mut sent = Vec::new();
        assert!(!flush_push_frames(
            &bus,
            &bob.subscription_id,
            32,
            collector(&mut sent)
        ));
        assert_eq!(sent.len(), 1, "{sent:?}");
        let frame: StatusUpdatePushFrame =
            serde_json::from_value(sent[0].payload.clone().expect("payload")).expect("decode");
        assert_eq!(frame.event_id, his);
    }

    /// The marker is machine-neutral: it names no event and no principal, so
    /// it can be sent to whoever fell behind without leaking another user's news.
    #[test]
    fn the_resync_marker_carries_no_event_content() {
        let marker = resync_marker("sub-1", 7);
        let payload = marker.payload.expect("payload");
        assert_eq!(payload["event"], serde_json::json!({ "type": "push-gap" }));
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

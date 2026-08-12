//! Service-side event bus that backs `StatusUpdatesSubscribe`.
//!
//! ## Responsibilities
//!
//! - Assign a monotonic `event_id` to every published event.
//! - Buffer the last [`EVENT_BUFFER_CAPACITY`] events in a ring so a
//!   client that briefly disconnects can resume without losing
//!   anything within that window.
//! - Track per-subscription cursors so the transport layer (the
//!   named-pipe server) knows which events still need to be pushed
//!   to which subscriber.
//! - Detect *gap* situations on resubscribe — when the client's
//!   `last_seen_event_id` is older than the oldest buffered event —
//!   and signal the client to do a fresh `SnapshotInitialGet`.
//! - Track per-subscriber `dropped_count` for slow consumers (the
//!   transport bumps this when a pipe write fails); the next
//!   successful push ahead of fresh events is an
//!   [`StatusUpdateEvent::Overflow`] frame so the GUI can resync.
//!
//! ## What this module *does not* own
//!
//! The actual pipe-side push pump lives in `nrr-windows-service`.
//! This module exposes the data structures and lookup methods the
//! pump needs; threading and I/O happen outside.
//!
//! ## Threading model
//!
//! All state is behind a single `Mutex` for simplicity. Throughput is
//! not a concern — events are sparse (state changes, not log lines)
//! and the critical section is microseconds.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::ipc_handlers::payloads::StatusUpdateEvent;

/// Maximum events held in the ring buffer. The spec target is 100 —
/// large enough that brief disconnects (service restart, GUI relaunch)
/// don't lose anything, small enough that memory stays trivial.
pub const EVENT_BUFFER_CAPACITY: usize = 100;

/// Buffered event with its assigned monotonic id.
#[derive(Clone, Debug)]
pub struct EventEntry {
    pub event_id: u64,
    pub event: StatusUpdateEvent,
}

/// Per-subscriber state tracked by the bus.
#[derive(Clone, Debug)]
pub struct SubscriberState {
    pub client_id: String,
    /// Lowest `event_id` we still owe this subscriber. Each successful
    /// transport push advances this past the pushed event.
    pub cursor_event_id: u64,
    /// Bumped by the transport when a pipe write fails. The subscriber
    /// receives an `Overflow { dropped_count }` frame on its next
    /// successful push (and the counter resets to zero).
    pub dropped_count: u64,
}

/// Outcome of a `subscribe` call. The handler echoes
/// `subscription_id` and `current_event_id` to the client; `gap_detected`
/// flags that the client's resume cursor was older than the bus's
/// oldest retained event, so the client should resync via
/// `SnapshotInitialGet`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubscribeOutcome {
    pub subscription_id: String,
    pub current_event_id: u64,
    pub gap_detected: bool,
}

#[derive(Default)]
pub struct EventBus {
    next_event_id: AtomicU64,
    /// Ring buffer of the most recent events. Front = oldest, back =
    /// newest. We trim the front when length exceeds
    /// [`EVENT_BUFFER_CAPACITY`].
    buffer: Mutex<VecDeque<EventEntry>>,
    subscribers: Mutex<HashMap<String, SubscriberState>>,
    sub_id_counter: AtomicU64,
}

// The bus guards subscribers/buffer behind locks; `lock().expect(...)`
// propagates poisoning (a prior panic) as a panic — deliberate, not an error.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl EventBus {
    pub fn new() -> Self {
        Self {
            next_event_id: AtomicU64::new(1),
            buffer: Mutex::new(VecDeque::with_capacity(EVENT_BUFFER_CAPACITY)),
            subscribers: Mutex::new(HashMap::new()),
            sub_id_counter: AtomicU64::new(1),
        }
    }

    /// Assign the next `event_id` and append to the buffer. Returns
    /// the newly-issued id. The transport pump observes this through
    /// [`peek_pending_for`] and pushes it to subscribers.
    pub fn publish(&self, event: StatusUpdateEvent) -> u64 {
        let id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        let mut buf = self.buffer.lock().expect("event bus buffer poisoned");
        buf.push_back(EventEntry {
            event_id: id,
            event,
        });
        while buf.len() > EVENT_BUFFER_CAPACITY {
            buf.pop_front();
        }
        id
    }

    /// Snapshot of the next id that *will* be assigned. A client that
    /// just subscribed records this in
    /// [`StatusUpdatesSubscribeResponse::current_event_id`] so it knows
    /// the resume point if its connection drops.
    pub fn current_event_id(&self) -> u64 {
        self.next_event_id.load(Ordering::SeqCst)
    }

    /// `event_id` of the oldest event still in the buffer, or `None`
    /// if the buffer is empty.
    pub fn oldest_event_id(&self) -> Option<u64> {
        self.buffer
            .lock()
            .expect("event bus buffer poisoned")
            .front()
            .map(|e| e.event_id)
    }

    /// Register a new subscription. `last_seen_event_id` is the
    /// client's resume cursor; `None` means "start from current head".
    ///
    /// Returns the subscription id, the current head, and whether a
    /// gap was detected (the client's cursor pre-dates the buffer).
    pub fn subscribe(
        &self,
        client_id: String,
        last_seen_event_id: Option<u64>,
    ) -> SubscribeOutcome {
        let n = self.sub_id_counter.fetch_add(1, Ordering::Relaxed);
        let sub_id = format!("sub-{n:016x}");
        let head = self.current_event_id();
        let oldest = self.oldest_event_id();

        let (cursor, gap_detected) = match last_seen_event_id {
            None => (head, false),
            Some(seen) => {
                // Client wants events strictly after `seen`.
                let resume_at = seen.saturating_add(1);
                match oldest {
                    Some(oldest_id) if resume_at < oldest_id => {
                        // Cursor pre-dates the buffer. Clamp to head;
                        // missed events are not replayed.
                        (head, true)
                    }
                    _ => (resume_at, false),
                }
            }
        };

        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        subs.insert(
            sub_id.clone(),
            SubscriberState {
                client_id,
                cursor_event_id: cursor,
                dropped_count: 0,
            },
        );

        SubscribeOutcome {
            subscription_id: sub_id,
            current_event_id: head,
            gap_detected,
        }
    }

    /// Drop a subscription. Called when the underlying pipe closes or
    /// the client explicitly cancels.
    pub fn unsubscribe(&self, subscription_id: &str) {
        self.subscribers
            .lock()
            .expect("subscribers poisoned")
            .remove(subscription_id);
    }

    /// Read pending events for `subscription_id` without advancing
    /// the cursor. The transport pump uses this to know what to push
    /// next; on successful push it calls [`advance_cursor`] to
    /// acknowledge delivery.
    ///
    /// `max_count = 0` returns nothing (the transport batches in
    /// chunks).
    pub fn peek_pending_for(&self, subscription_id: &str, max_count: usize) -> Vec<EventEntry> {
        if max_count == 0 {
            return Vec::new();
        }
        let subs = self.subscribers.lock().expect("subscribers poisoned");
        let Some(sub) = subs.get(subscription_id) else {
            return Vec::new();
        };
        let cursor = sub.cursor_event_id;
        drop(subs);

        let buf = self.buffer.lock().expect("event bus buffer poisoned");
        buf.iter()
            .filter(|e| e.event_id >= cursor)
            .take(max_count)
            .cloned()
            .collect()
    }

    /// Acknowledge delivery up to and including `event_id` for
    /// `subscription_id`. Called by the transport pump after a
    /// successful pipe write.
    pub fn advance_cursor(&self, subscription_id: &str, event_id: u64) {
        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        if let Some(sub) = subs.get_mut(subscription_id) {
            sub.cursor_event_id = sub.cursor_event_id.max(event_id + 1);
        }
    }

    /// Increment the per-subscriber dropped counter (called by the
    /// transport when a pipe write fails). The next successful push
    /// will be preceded by an `Overflow { dropped_count }` frame.
    pub fn record_drop(&self, subscription_id: &str, count: u64) {
        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        if let Some(sub) = subs.get_mut(subscription_id) {
            sub.dropped_count = sub.dropped_count.saturating_add(count);
        }
    }

    /// Take and reset the dropped counter for `subscription_id`. The
    /// transport calls this right before a successful flush so it
    /// knows to emit an `Overflow` frame first.
    pub fn take_dropped_count(&self, subscription_id: &str) -> u64 {
        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        if let Some(sub) = subs.get_mut(subscription_id) {
            let dropped = sub.dropped_count;
            sub.dropped_count = 0;
            dropped
        } else {
            0
        }
    }

    /// Snapshot the subscriber table for diagnostics / tests.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().expect("subscribers poisoned").len()
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer.lock().expect("event bus buffer poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(severity: &str) -> StatusUpdateEvent {
        StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: severity.into(),
        }
    }

    #[test]
    fn publish_assigns_monotonic_event_ids_starting_at_one() {
        let bus = EventBus::new();
        let id1 = bus.publish(health("ok"));
        let id2 = bus.publish(health("warning"));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(bus.current_event_id(), 3);
    }

    #[test]
    fn buffer_caps_at_capacity_and_drops_oldest() {
        let bus = EventBus::new();
        for _ in 0..(EVENT_BUFFER_CAPACITY + 50) {
            bus.publish(health("ok"));
        }
        assert_eq!(bus.buffer_len(), EVENT_BUFFER_CAPACITY);
        assert_eq!(
            bus.oldest_event_id(),
            Some((EVENT_BUFFER_CAPACITY as u64 + 50 - EVENT_BUFFER_CAPACITY as u64) + 1)
        );
    }

    #[test]
    fn subscribe_with_no_cursor_starts_at_head_no_gap() {
        let bus = EventBus::new();
        bus.publish(health("ok"));
        let s = bus.subscribe("client-1".into(), None);
        assert_eq!(s.current_event_id, 2);
        assert!(!s.gap_detected);
        // Cursor at head ⇒ no pending.
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn subscribe_within_buffer_replays_missed_events() {
        let bus = EventBus::new();
        bus.publish(health("ok")); // id=1
        bus.publish(health("warning")); // id=2
        bus.publish(health("degraded")); // id=3
        let s = bus.subscribe("client-1".into(), Some(1));
        assert!(!s.gap_detected);
        let pending = bus.peek_pending_for(&s.subscription_id, 16);
        // Should replay 2 and 3 (events strictly after 1).
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].event_id, 2);
        assert_eq!(pending[1].event_id, 3);
    }

    #[test]
    fn subscribe_with_pre_buffer_cursor_signals_gap() {
        let bus = EventBus::new();
        for _ in 0..(EVENT_BUFFER_CAPACITY + 5) {
            bus.publish(health("ok"));
        }
        // Oldest in buffer is 6; client claims it last saw id 1.
        let s = bus.subscribe("client-1".into(), Some(1));
        assert!(s.gap_detected);
        // No replay: cursor jumped to head, peek is empty.
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn advance_cursor_consumes_pending_events() {
        let bus = EventBus::new();
        bus.publish(health("ok")); // 1
        bus.publish(health("ok")); // 2
        let s = bus.subscribe("client-1".into(), Some(0));
        let pending = bus.peek_pending_for(&s.subscription_id, 16);
        assert_eq!(pending.len(), 2);
        bus.advance_cursor(&s.subscription_id, 2);
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn dropped_counter_round_trips_through_record_and_take() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        bus.record_drop(&s.subscription_id, 3);
        bus.record_drop(&s.subscription_id, 2);
        assert_eq!(bus.take_dropped_count(&s.subscription_id), 5);
        assert_eq!(bus.take_dropped_count(&s.subscription_id), 0);
    }

    #[test]
    fn unsubscribe_removes_state() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        assert_eq!(bus.subscriber_count(), 1);
        bus.unsubscribe(&s.subscription_id);
        assert_eq!(bus.subscriber_count(), 0);
        // peek on unknown subscription is empty, not panic.
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn subscribe_ids_are_unique_per_call() {
        let bus = EventBus::new();
        let s1 = bus.subscribe("client-1".into(), None);
        let s2 = bus.subscribe("client-1".into(), None);
        assert_ne!(s1.subscription_id, s2.subscription_id);
    }

    #[test]
    fn peek_with_zero_max_count_returns_nothing() {
        let bus = EventBus::new();
        bus.publish(health("ok"));
        let s = bus.subscribe("client-1".into(), Some(0));
        assert!(bus.peek_pending_for(&s.subscription_id, 0).is_empty());
    }

    #[test]
    fn empty_bus_subscribe_with_seen_id_clamps_to_head_no_gap() {
        // No events buffered; client says it has seen id 5. Bus is
        // empty, so "oldest" is None — `gap_detected` is false (no
        // gap to detect). The cursor parks at head waiting for new
        // events.
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), Some(5));
        assert!(!s.gap_detected);
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }
}

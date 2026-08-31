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
use std::time::{Duration, Instant};

use crate::ipc_handlers::payloads::StatusUpdateEvent;

/// Maximum events held in the ring buffer. The spec target is 100 —
/// large enough that brief disconnects (service restart, GUI relaunch)
/// don't lose anything, small enough that memory stays trivial.
pub const EVENT_BUFFER_CAPACITY: usize = 100;

/// Most subscriptions the bus keeps at once. One per live GUI/tray connection
/// is the normal shape, so this is generous — it exists because a pipe that
/// dies without its `unsubscribe` leaves its entry behind, and nothing else
/// ever removed one.
pub const MAX_SUBSCRIPTIONS: usize = 64;

/// How long a subscription may go untouched before a later `subscribe` sweeps
/// it. A live client polls far more often than this; anything quieter is a
/// connection nobody is on the other end of.
pub const SUBSCRIPTION_IDLE_TTL: Duration = Duration::from_secs(30 * 60);

/// Buffered event with its assigned monotonic id.
#[derive(Clone, Debug)]
pub struct EventEntry {
    pub event_id: u64,
    pub event: StatusUpdateEvent,
    /// Whose event this is. `None` means it concerns the machine and every
    /// subscriber may see it; `Some(principal)` means only that principal's
    /// clients may. Without this a block notice, an auto-rule candidate or the
    /// additional link's external ADDRESS - all of them facts about one user's
    /// session - were pushed to every logged-in user's GUI.
    pub audience: Option<String>,
}

/// Per-subscriber state tracked by the bus.
#[derive(Clone, Debug)]
pub struct SubscriberState {
    pub client_id: String,
    /// The principal this subscription belongs to, from the connection's peer
    /// credentials. `None` only where the transport cannot name one, and such a
    /// subscriber sees machine-wide events only.
    pub principal: Option<String>,
    /// Lowest `event_id` we still owe this subscriber. Each successful
    /// transport push advances this past the pushed event.
    pub cursor_event_id: u64,
    /// Bumped by the transport when a pipe write fails. The subscriber
    /// receives an `Overflow { dropped_count }` frame on its next
    /// successful push (and the counter resets to zero).
    pub dropped_count: u64,
    /// Last time the transport read or acknowledged anything for this
    /// subscription. What separates a quiet client from a dead one.
    pub last_activity: Instant,
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
    /// Publish an event. An event that names a principal in its own payload is
    /// routed TO that principal even when published through this machine-wide
    /// entry point: the payload has already said whose news it is, and letting
    /// the call site disagree with it is how a user's pause, coverage or tunnel
    /// ends up on every other session's screen. [`StatusUpdateEvent::addressee`]
    /// is the single answer both paths read.
    pub fn publish(&self, event: StatusUpdateEvent) -> u64 {
        let audience = event.addressee().map(str::to_string);
        self.publish_to(audience, event)
    }

    /// Publish an event that concerns ONE principal. Only that principal's
    /// subscribers receive it.
    pub fn publish_for(&self, principal: impl Into<String>, event: StatusUpdateEvent) -> u64 {
        self.publish_to(Some(principal.into()), event)
    }

    fn publish_to(&self, audience: Option<String>, event: StatusUpdateEvent) -> u64 {
        let id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        let mut buf = self.buffer.lock().expect("event bus buffer poisoned");
        buf.push_back(EventEntry {
            event_id: id,
            event,
            audience,
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
        self.subscribe_as(client_id, None, last_seen_event_id)
    }

    /// As [`Self::subscribe`], naming the principal behind the connection so
    /// per-principal events reach only their own client.
    pub fn subscribe_as(
        &self,
        client_id: String,
        principal: Option<String>,
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
        let now = Instant::now();
        // One client, one subscription: a GUI that reconnects (or retries the
        // subscribe) used to leave its previous entry behind forever.
        subs.retain(|_, sub| sub.client_id != client_id);
        subs.retain(|_, sub| now.duration_since(sub.last_activity) < SUBSCRIPTION_IDLE_TTL);
        // Still full: drop the one nobody has touched in the longest time. It is
        // the likeliest corpse, and refusing the new subscriber instead would
        // lock a live GUI out because of dead ones.
        while subs.len() >= MAX_SUBSCRIPTIONS {
            let Some(stalest) = subs
                .iter()
                .min_by_key(|(_, sub)| sub.last_activity)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            subs.remove(&stalest);
        }
        subs.insert(
            sub_id.clone(),
            SubscriberState {
                client_id,
                principal,
                cursor_event_id: cursor,
                dropped_count: 0,
                last_activity: now,
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
        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        let Some(sub) = subs.get_mut(subscription_id) else {
            return Vec::new();
        };
        sub.last_activity = Instant::now();
        let cursor = sub.cursor_event_id;
        let principal = sub.principal.clone();
        drop(subs);

        let buf = self.buffer.lock().expect("event bus buffer poisoned");
        buf.iter()
            .filter(|e| e.event_id >= cursor)
            .filter(|e| match (&e.audience, &principal) {
                // Machine-wide: everybody sees it.
                (None, _) => true,
                // Somebody's own event reaches only them; a subscriber whose
                // principal the transport could not name sees none of these.
                (Some(audience), Some(mine)) => audience == mine,
                (Some(_), None) => false,
            })
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
            sub.last_activity = Instant::now();
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

    /// A block notice, an auto-rule offer and the additional link's external
    /// ADDRESS are facts about ONE user's session. Published on an unscoped bus
    /// they reached every logged-in user's GUI.
    #[test]
    fn a_users_own_event_reaches_only_their_own_subscriber() {
        let bus = EventBus::new();
        let alice = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), Some(0));
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), Some(0));

        bus.publish_for("S-1-A", health("ok"));
        bus.publish(health("ok"));

        assert_eq!(
            bus.peek_pending_for(&alice.subscription_id, 16).len(),
            2,
            "her own event plus the machine-wide one",
        );
        assert_eq!(
            bus.peek_pending_for(&bob.subscription_id, 16).len(),
            1,
            "only the machine-wide one",
        );
    }

    /// A transport that cannot name the principal behind a connection gets the
    /// machine-wide events and nothing else - the safe end of the ambiguity.
    #[test]
    fn an_unnamed_subscriber_sees_only_machine_wide_events() {
        let bus = EventBus::new();
        let anon = bus.subscribe("gui".into(), Some(0));
        bus.publish_for("S-1-A", health("ok"));
        assert!(bus.peek_pending_for(&anon.subscription_id, 16).is_empty());
        bus.publish(health("ok"));
        assert_eq!(bus.peek_pending_for(&anon.subscription_id, 16).len(), 1);
    }
    use super::*;

    fn health(severity: &str) -> StatusUpdateEvent {
        StatusUpdateEvent::HealthChanged {
            service_state: "running".into(),
            worst_severity: severity.into(),
        }
    }

    /// An event that names a principal must reach only that principal, even when
    /// it goes through the machine-wide entry point. Six of the seventeen event
    /// kinds carry a SID, and three of them WERE broadcast: a user's pause, their
    /// enforcement status with its candidate list, and the tunnel they had not
    /// assigned all went to every session on the machine.
    #[test]
    fn an_event_that_names_a_principal_is_routed_to_them_even_via_plain_publish() {
        let bus = EventBus::new();
        let mine = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), Some(0));
        let theirs = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), Some(0));

        bus.publish(StatusUpdateEvent::RoutingPauseStateChanged {
            sid: "S-1-A".to_string(),
            paused: true,
        });

        assert_eq!(
            bus.peek_pending_for(&mine.subscription_id, 16).len(),
            1,
            "the user whose pause it is must hear about it"
        );
        assert!(
            bus.peek_pending_for(&theirs.subscription_id, 16).is_empty(),
            "another session must not learn that this user paused routing"
        );
    }

    /// The machine-wide half must keep working — most events genuinely concern
    /// the whole machine, and routing them per-principal would silence them.
    #[test]
    fn an_event_that_names_nobody_still_reaches_everyone() {
        let bus = EventBus::new();
        let mine = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), Some(0));
        let theirs = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), Some(0));
        bus.publish(StatusUpdateEvent::AdaptersChanged {
            data_source: "test".to_string(),
        });
        assert_eq!(bus.peek_pending_for(&mine.subscription_id, 16).len(), 1);
        assert_eq!(bus.peek_pending_for(&theirs.subscription_id, 16).len(), 1);
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

    #[test]
    fn one_client_keeps_one_subscription() {
        // A GUI that reconnects (or retries the subscribe) used to leave its
        // previous entry behind, and nothing ever removed it.
        let bus = EventBus::new();
        let first = bus.subscribe("gui-a".into(), None);
        let second = bus.subscribe("gui-a".into(), None);
        assert_ne!(first.subscription_id, second.subscription_id);
        assert_eq!(bus.subscriber_count(), 1);
        bus.publish(health("ok"));
        assert!(
            bus.peek_pending_for(&first.subscription_id, 8).is_empty(),
            "the superseded subscription is gone, not merely quiet"
        );
        assert_eq!(bus.peek_pending_for(&second.subscription_id, 8).len(), 1);
    }

    #[test]
    fn the_subscription_table_is_bounded() {
        // Each entry is small, but nothing removed them: a client that dies
        // without unsubscribing left one behind for the life of the service.
        let bus = EventBus::new();
        for n in 0..(MAX_SUBSCRIPTIONS + 10) {
            bus.subscribe(format!("gui-{n}"), None);
        }
        assert!(
            bus.subscriber_count() <= MAX_SUBSCRIPTIONS,
            "count = {}",
            bus.subscriber_count()
        );
    }

    #[test]
    fn a_live_subscriber_survives_the_sweep_a_stale_one_does_not() {
        let bus = EventBus::new();
        let live = bus.subscribe("gui-live".into(), None);
        let stale = bus.subscribe("gui-stale".into(), None);
        // Age the stale one past the TTL without sleeping. `Instant` cannot
        // predate the monotonic epoch (boot), so on a machine up for less than
        // the TTL the aged instant is unrepresentable — skip instead of
        // failing on host uptime.
        {
            let mut subs = bus.subscribers.lock().unwrap_or_else(|p| p.into_inner());
            let entry = subs.get_mut(&stale.subscription_id).expect("stale entry");
            let Some(aged) =
                Instant::now().checked_sub(SUBSCRIPTION_IDLE_TTL + Duration::from_secs(1))
            else {
                return;
            };
            entry.last_activity = aged;
        }
        bus.subscribe("gui-new".into(), None);
        assert!(
            bus.peek_pending_for(&stale.subscription_id, 1).is_empty(),
            "an untouched subscription is swept"
        );
        bus.publish(health("ok"));
        assert_eq!(
            bus.peek_pending_for(&live.subscription_id, 8).len(),
            1,
            "a live one keeps its place"
        );
    }
}

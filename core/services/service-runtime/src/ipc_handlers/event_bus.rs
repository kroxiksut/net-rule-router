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
//! - Detect *gap* situations on resubscribe — when the ring has dropped an
//!   event the client was owed — and signal the client to do a fresh
//!   `SnapshotInitialGet`.
//!
//! A subscriber whose connection cannot take a frame is not signalled here:
//! the transport closes that connection, and the client's own reconnect and
//! `push-gap` are the recovery path. A subscriber that merely lags past the
//! ring is told by [`EventBus::lost_events_resume_at`] and the transport.
//!
//! A loss is judged per audience: another user's events leaving the ring are
//! no hole in this subscriber's stream, so they neither cost it a re-read nor
//! tell it that the other user was busy.
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
use std::sync::{Arc, Mutex};
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

/// Most principals whose eviction mark is kept apart. Past it the oldest mark
/// joins the machine-wide one: everyone may then re-read once for nothing, but
/// nobody misses a hole.
pub const MAX_EVICTION_AUDIENCES: usize = 256;

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

/// Called by a publish that concerns the subscriber, so its connection thread
/// wakes at once instead of polling. Must not block: it runs on the publisher.
#[derive(Clone)]
pub struct PushWaker(Arc<dyn Fn() + Send + Sync>);

impl PushWaker {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(wake))
    }
}

impl std::fmt::Debug for PushWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PushWaker")
    }
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
    /// Last time the transport read or acknowledged anything for this
    /// subscription. What separates a quiet client from a dead one.
    pub last_activity: Instant,
    /// Set once the transport has a connection to wake.
    pub waker: Option<PushWaker>,
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

/// The most recent events, front = oldest, and what fell off the front.
#[derive(Default)]
struct Ring {
    events: VecDeque<EventEntry>,
    /// Per audience, the newest event id the ring has dropped; the `None` key
    /// holds the machine-wide events every subscriber is owed.
    evicted_through: HashMap<Option<String>, u64>,
}

impl Ring {
    fn push(&mut self, entry: EventEntry) {
        self.events.push_back(entry);
        while self.events.len() > EVENT_BUFFER_CAPACITY {
            if let Some(dropped) = self.events.pop_front() {
                self.mark_evicted(dropped.audience, dropped.event_id);
            }
        }
    }

    fn mark_evicted(&mut self, audience: Option<String>, event_id: u64) {
        let mark = self.evicted_through.entry(audience).or_insert(0);
        *mark = (*mark).max(event_id);
        let principals =
            self.evicted_through.len() - usize::from(self.evicted_through.contains_key(&None));
        if principals > MAX_EVICTION_AUDIENCES {
            let oldest = self
                .evicted_through
                .iter()
                .filter(|(audience, _)| audience.is_some())
                .min_by_key(|(_, id)| **id)
                .map(|(audience, id)| (audience.clone(), *id));
            if let Some((audience, id)) = oldest {
                self.evicted_through.remove(&audience);
                let machine = self.evicted_through.entry(None).or_insert(0);
                *machine = (*machine).max(id);
            }
        }
    }

    /// Newest dropped id a subscriber of `principal` would have been shown;
    /// `0` when the ring has dropped none of them.
    fn lost_through(&self, principal: Option<&str>) -> u64 {
        let machine = self.evicted_through.get(&None).copied().unwrap_or(0);
        let own = principal
            .and_then(|p| self.evicted_through.get(&Some(p.to_string())))
            .copied()
            .unwrap_or(0);
        machine.max(own)
    }
}

#[derive(Default)]
pub struct EventBus {
    next_event_id: AtomicU64,
    /// Trimmed to [`EVENT_BUFFER_CAPACITY`] on every publish.
    buffer: Mutex<Ring>,
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
            buffer: Mutex::new(Ring {
                events: VecDeque::with_capacity(EVENT_BUFFER_CAPACITY + 1),
                evicted_through: HashMap::new(),
            }),
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
        // Numbered under the buffer's lock: numbered outside it, a smaller id
        // could land behind a larger one and a reader that saw the larger would
        // never be pushed the smaller.
        let mut buf = self.buffer.lock().expect("event bus buffer poisoned");
        let id = self.next_event_id.fetch_add(1, Ordering::SeqCst);
        buf.push(EventEntry {
            event_id: id,
            event,
            audience: audience.clone(),
        });
        drop(buf);
        self.wake_subscribers(audience.as_deref());
        id
    }

    /// Wake the connections an event for `audience` concerns. Run outside both
    /// locks: a waker is foreign code.
    fn wake_subscribers(&self, audience: Option<&str>) {
        let wakers: Vec<PushWaker> = self
            .subscribers
            .lock()
            .expect("subscribers poisoned")
            .values()
            .filter(|s| audience.is_none() || s.principal.as_deref() == audience)
            .filter_map(|s| s.waker.clone())
            .collect();
        for waker in wakers {
            (waker.0)();
        }
    }

    /// Attach the wake-up of the connection serving `subscription_id`, and fire
    /// it once: events published before the connection could be woken (a
    /// resumed cursor) are already owed.
    pub fn set_waker(&self, subscription_id: &str, waker: PushWaker) {
        let attached = {
            let mut subs = self.subscribers.lock().expect("subscribers poisoned");
            subs.get_mut(subscription_id)
                .map(|sub| sub.waker = Some(waker.clone()))
                .is_some()
        };
        if attached {
            (waker.0)();
        }
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
            .events
            .front()
            .map(|e| e.event_id)
    }

    /// Register a new subscription. `last_seen_event_id` is the
    /// client's resume cursor; `None` means "start from current head".
    ///
    /// Returns the subscription id, the current head, and whether a
    /// gap was detected (the ring dropped an event this client was owed).
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
        let lost_through = self
            .buffer
            .lock()
            .expect("event bus buffer poisoned")
            .lost_through(principal.as_deref());

        let (cursor, gap_detected) = match last_seen_event_id {
            None => (head, false),
            // Client wants events strictly after `seen`. A hole is not replayed
            // around: the client re-reads the state and follows from the head.
            Some(seen) => {
                let resume_at = seen.saturating_add(1);
                if lost_through >= resume_at {
                    (head, true)
                } else {
                    (resume_at, false)
                }
            }
        };

        let mut subs = self.subscribers.lock().expect("subscribers poisoned");
        let now = Instant::now();
        // One client, one subscription — but only the SAME principal's client
        // replaces it. `client_id` is chosen by the client (the GUI mints
        // `gui-<ms>`), so matching on it alone let another user guess the id and
        // silently cut a victim's push channel.
        subs.retain(|_, sub| sub.client_id != client_id || sub.principal != principal);
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
                last_activity: now,
                waker: None,
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
        buf.events
            .iter()
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

    /// When the ring has already dropped an event this subscriber was still
    /// owed, the id to resume at past the hole. The cursor is left alone: the
    /// transport tells the client first and then advances past the hole.
    pub fn lost_events_resume_at(&self, subscription_id: &str) -> Option<u64> {
        let (cursor, principal) = {
            let subs = self.subscribers.lock().expect("subscribers poisoned");
            let sub = subs.get(subscription_id)?;
            (sub.cursor_event_id, sub.principal.clone())
        };
        let lost_through = self
            .buffer
            .lock()
            .expect("event bus buffer poisoned")
            .lost_through(principal.as_deref());
        (lost_through > 0 && lost_through >= cursor).then_some(lost_through + 1)
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

    /// Snapshot the subscriber table for diagnostics / tests.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().expect("subscribers poisoned").len()
    }

    /// Is anyone able to receive `principal`'s own events right now?
    ///
    /// A subscription starts at the CURRENT head, so an event published
    /// before the client connected is never delivered to it. A caller that
    /// remembers what it has already announced therefore has to know
    /// whether the announcement had an audience — otherwise "announced"
    /// records a push into an empty room and the news is never repeated.
    pub fn has_subscriber_for(&self, principal: &str) -> bool {
        self.subscribers
            .lock()
            .expect("subscribers poisoned")
            .values()
            .any(|s| s.principal.as_deref() == Some(principal))
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer
            .lock()
            .expect("event bus buffer poisoned")
            .events
            .len()
    }
}

#[cfg(test)]
mod tests {

    /// A block notice, an auto-rule offer and the additional link's external
    /// ADDRESS are facts about ONE user's session. Published on an unscoped bus
    /// they reached every logged-in user's GUI.
    #[test]
    fn another_user_cannot_evict_a_subscription_by_reusing_its_client_id() {
        let bus = EventBus::new();
        let victim = bus.subscribe_as("gui-1".into(), Some("S-1-A".into()), None);
        bus.subscribe_as("gui-1".into(), Some("S-1-B".into()), None);
        bus.publish_for("S-1-A", adapters("ok"));
        assert_eq!(
            bus.peek_pending_for(&victim.subscription_id, 8).len(),
            1,
            "the victim's subscription must survive"
        );

        let reopened = bus.subscribe_as("gui-1".into(), Some("S-1-A".into()), None);
        assert!(
            bus.peek_pending_for(&victim.subscription_id, 8).is_empty(),
            "the same user re-subscribing still replaces its own entry"
        );
        assert_ne!(reopened.subscription_id, victim.subscription_id);
    }

    #[test]
    fn a_users_own_event_reaches_only_their_own_subscriber() {
        let bus = EventBus::new();
        let alice = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), Some(0));
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), Some(0));

        bus.publish_for("S-1-A", adapters("ok"));
        bus.publish(adapters("ok"));

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
        bus.publish_for("S-1-A", adapters("ok"));
        assert!(bus.peek_pending_for(&anon.subscription_id, 16).is_empty());
        bus.publish(adapters("ok"));
        assert_eq!(bus.peek_pending_for(&anon.subscription_id, 16).len(), 1);
    }
    use super::*;

    fn adapters(source: &str) -> StatusUpdateEvent {
        StatusUpdateEvent::AdaptersChanged {
            data_source: source.into(),
        }
    }

    fn counting_waker() -> (PushWaker, Arc<std::sync::atomic::AtomicUsize>) {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let waker = PushWaker::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        (waker, count)
    }

    /// The connection thread sleeps until the bus wakes it; a publish that
    /// concerns another user's session must not.
    #[test]
    fn a_publish_wakes_only_the_subscribers_it_concerns() {
        let bus = EventBus::new();
        let alice = bus.subscribe_as("gui-a".into(), Some("S-1-A".into()), None);
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), None);
        let (alice_waker, alice_wakes) = counting_waker();
        let (bob_waker, bob_wakes) = counting_waker();
        bus.set_waker(&alice.subscription_id, alice_waker);
        bus.set_waker(&bob.subscription_id, bob_waker);
        // Attaching fires once: events owed since a resumed cursor.
        assert_eq!(alice_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(bob_wakes.load(Ordering::SeqCst), 1);

        bus.publish_for("S-1-A", adapters("ok"));
        assert_eq!(alice_wakes.load(Ordering::SeqCst), 2);
        assert_eq!(bob_wakes.load(Ordering::SeqCst), 1, "not Bob's news");

        bus.publish(adapters("ok"));
        assert_eq!(alice_wakes.load(Ordering::SeqCst), 3);
        assert_eq!(
            bob_wakes.load(Ordering::SeqCst),
            2,
            "machine-wide reaches all"
        );
    }

    #[test]
    fn an_unsubscribed_connection_is_never_woken() {
        let bus = EventBus::new();
        let sub = bus.subscribe("gui".into(), None);
        let (waker, wakes) = counting_waker();
        bus.set_waker(&sub.subscription_id, waker);
        bus.unsubscribe(&sub.subscription_id);
        bus.publish(adapters("ok"));
        assert_eq!(wakes.load(Ordering::SeqCst), 1, "only the attach-time wake");
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
            paused_at: None,
            resumes_at_ms: None,
            until_restart: false,
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
        let id1 = bus.publish(adapters("ok"));
        let id2 = bus.publish(adapters("warning"));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(bus.current_event_id(), 3);
    }

    #[test]
    fn buffer_caps_at_capacity_and_drops_oldest() {
        let bus = EventBus::new();
        for _ in 0..(EVENT_BUFFER_CAPACITY + 50) {
            bus.publish(adapters("ok"));
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
        bus.publish(adapters("ok"));
        let s = bus.subscribe("client-1".into(), None);
        assert_eq!(s.current_event_id, 2);
        assert!(!s.gap_detected);
        // Cursor at head ⇒ no pending.
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn subscribe_within_buffer_replays_missed_events() {
        let bus = EventBus::new();
        bus.publish(adapters("ok")); // id=1
        bus.publish(adapters("warning")); // id=2
        bus.publish(adapters("degraded")); // id=3
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
            bus.publish(adapters("ok"));
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
        bus.publish(adapters("ok")); // 1
        bus.publish(adapters("ok")); // 2
        let s = bus.subscribe("client-1".into(), Some(0));
        let pending = bus.peek_pending_for(&s.subscription_id, 16);
        assert_eq!(pending.len(), 2);
        bus.advance_cursor(&s.subscription_id, 2);
        assert!(bus.peek_pending_for(&s.subscription_id, 16).is_empty());
    }

    #[test]
    fn a_subscriber_that_lags_past_the_ring_is_owed_a_resync() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        assert_eq!(bus.lost_events_resume_at(&s.subscription_id), None);
        for _ in 0..(EVENT_BUFFER_CAPACITY + 5) {
            bus.publish(adapters("ok"));
        }
        // Ids 1..=105 published, the ring holds 6..=105.
        assert_eq!(bus.lost_events_resume_at(&s.subscription_id), Some(6));
        bus.advance_cursor(&s.subscription_id, 5);
        assert_eq!(bus.lost_events_resume_at(&s.subscription_id), None);
        assert_eq!(
            bus.peek_pending_for(&s.subscription_id, 1)[0].event_id,
            6,
            "the events still held are delivered after the marker"
        );
    }

    #[test]
    fn a_subscriber_within_the_ring_or_unknown_is_owed_nothing() {
        let bus = EventBus::new();
        let s = bus.subscribe("client-1".into(), None);
        for _ in 0..EVENT_BUFFER_CAPACITY {
            bus.publish(adapters("ok"));
        }
        assert_eq!(bus.lost_events_resume_at(&s.subscription_id), None);
        assert_eq!(bus.lost_events_resume_at("no-such-sub"), None);
    }

    /// Bob is never woken for Alice's events, so his cursor stays where it was
    /// while her flood runs through the ring. That is no hole in his stream:
    /// told otherwise he would re-read everything every hundred of her events,
    /// and learn from it how busy she is.
    #[test]
    fn another_users_flood_is_no_loss_for_a_subscriber() {
        let bus = EventBus::new();
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), None);
        for _ in 0..(EVENT_BUFFER_CAPACITY * 3) {
            bus.publish_for("S-1-A", adapters("ok"));
        }
        assert_eq!(bus.lost_events_resume_at(&bob.subscription_id), None);

        let resumed = bus.subscribe_as("gui-b2".into(), Some("S-1-B".into()), Some(0));
        assert!(!resumed.gap_detected, "a resume over her events only");
        assert!(bus
            .peek_pending_for(&resumed.subscription_id, 16)
            .is_empty());
    }

    /// The other way round: Alice's flood pushing out Bob's OWN event, or a
    /// machine-wide one, is a hole Bob is told about.
    #[test]
    fn a_flood_that_pushes_out_a_subscribers_own_event_is_a_loss() {
        let bus = EventBus::new();
        let bob = bus.subscribe_as("gui-b".into(), Some("S-1-B".into()), None);
        let his = bus.publish_for("S-1-B", adapters("ok"));
        for _ in 0..EVENT_BUFFER_CAPACITY {
            bus.publish_for("S-1-A", adapters("ok"));
        }
        assert_eq!(
            bus.lost_events_resume_at(&bob.subscription_id),
            Some(his + 1)
        );
        let resumed = bus.subscribe_as("gui-b2".into(), Some("S-1-B".into()), Some(0));
        assert!(resumed.gap_detected);

        let carol = bus.subscribe_as("gui-c".into(), Some("S-1-C".into()), None);
        let machine = bus.publish(adapters("ok"));
        for _ in 0..EVENT_BUFFER_CAPACITY {
            bus.publish_for("S-1-A", adapters("ok"));
        }
        assert_eq!(
            bus.lost_events_resume_at(&carol.subscription_id),
            Some(machine + 1)
        );
    }

    /// Past the cap of principals tracked apart, a dropped mark is folded into
    /// the machine-wide one: a needless re-read, never a silent hole.
    #[test]
    fn the_eviction_marks_are_bounded_without_losing_a_hole() {
        let bus = EventBus::new();
        let first = bus.subscribe_as("gui-0".into(), Some("S-0".into()), Some(0));
        let own = bus.publish_for("S-0", adapters("ok"));
        for n in 1..=(MAX_EVICTION_AUDIENCES + EVENT_BUFFER_CAPACITY) {
            bus.publish_for(format!("S-{n}"), adapters("ok"));
        }
        let marks = bus
            .buffer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .evicted_through
            .len();
        assert!(marks <= MAX_EVICTION_AUDIENCES + 1, "marks = {marks}");
        assert!(
            bus.lost_events_resume_at(&first.subscription_id)
                .is_some_and(|resume| resume > own),
            "the first user's dropped event is still a hole"
        );
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
        bus.publish(adapters("ok"));
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
        // A GUI that reconnects (or retries the subscribe) must not accumulate
        // a stale entry alongside the new one.
        let bus = EventBus::new();
        let first = bus.subscribe("gui-a".into(), None);
        let second = bus.subscribe("gui-a".into(), None);
        assert_ne!(first.subscription_id, second.subscription_id);
        assert_eq!(bus.subscriber_count(), 1);
        bus.publish(adapters("ok"));
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
        bus.publish(adapters("ok"));
        assert_eq!(
            bus.peek_pending_for(&live.subscription_id, 8).len(),
            1,
            "a live one keeps its place"
        );
    }
}

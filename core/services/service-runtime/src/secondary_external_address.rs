//! "Your additional route's external address is …" — the service side.
//!
//! # The problem this solves
//!
//! When the additional link comes up, the only question the user actually has
//! is *which address the outside world now sees*. Many link clients cannot
//! answer it themselves, so the user goes looking for a third-party "what is my
//! IP" page. The product already knows how to ask — one source-bound STUN
//! binding request per adapter — so it can simply say so, once, right after the
//! link connects.
//!
//! # Shape
//!
//! - **Detecting the connection** is not this module's job: it consumes a
//!   snapshot of the user's currently usable additional link (interface index,
//!   the adapter's own IPv4 and its description) produced by the route
//!   coordinator, which is the single place that decides what "usable" means.
//!   A change of identity — or an appearance after an absence — is a new
//!   incarnation of the link, i.e. a connection.
//! - **Deciding whether to speak** is pure and lives in [`ExternalAddressAnnouncer::observe`]
//!   and [`ExternalAddressAnnouncer::on_probe_result`], both of which take
//!   `now: Instant` so the whole anti-spam policy is testable without sleeping.
//! - **Asking the network** happens on a detached thread, never on the caller's.
//!
//! # Cost, and why the probe is detached
//!
//! The probe is a UDP round-trip with a hard budget of a few seconds. Running it
//! on the tick thread would park a supervised task for that long; joining it
//! anywhere on a pool thread is the mistake that once produced a wedged
//! datapath. So the tick spawns, forgets, and the worker reports back by calling
//! into the announcer itself. Steady state — a link that stays connected — costs
//! one map lookup per tick and nothing else: the probe runs once per
//! incarnation, not once per tick.
//!
//! # Anti-spam
//!
//! Every (re)connection is announced, including one that lands on the exit
//! address the user was told about last time: "the tunnel is up and this is
//! still what the world sees" is the confirmation the notice exists to give,
//! and withholding it read as the notice being broken. What is left is a floor
//! against flapping — at most one notice per [`ANNOUNCE_MIN_INTERVAL`] — plus
//! the settle requirement below.
//!
//! A link must have held one identity for [`LINK_SETTLE`] before it is probed,
//! so flaps shorter than that never cost a probe. The delay is short: a tunnel
//! client usually raises the adapter a beat before it installs the routes the
//! probe needs, and the answer to "not ready yet" is to ask again
//! ([`MAX_PROBE_ATTEMPTS`]), not to wait longer up front for everyone.
//!
//! A probe that comes back empty publishes nothing. "We could not tell you your
//! address" is a diagnostic (it is in the operational log), not a notification:
//! it asks the user to act on something they cannot act on.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nrr_shared::ipc_payloads::StatusUpdateEvent;

use crate::ipc_handlers::event_bus::EventBus;

// ── Tunables ─────────────────────────────────────────────────────────────────

/// How long a link must hold one identity before it is probed, and how long
/// after an unanswered probe before the next attempt.
///
/// One tick's worth at the task's cadence. The user watches the tunnel come up
/// and expects the address with it, so this is deliberately near the floor; a
/// client that has not installed its routes yet is covered by the retry, not by
/// making everyone wait.
pub const LINK_SETTLE: Duration = Duration::from_secs(2);

/// Attempts per incarnation before the link is left alone. A path that cannot
/// answer after this many tries will not answer at all, and the notice is a
/// courtesy — it must not turn into a permanent poll.
pub const MAX_PROBE_ATTEMPTS: u8 = 6;

/// Floor between two notices for one user. Only guards against a flapping
/// tunnel: a reconnect is announced whether or not the address changed.
pub const ANNOUNCE_MIN_INTERVAL: Duration = Duration::from_secs(20);

/// Maximum principals tracked concurrently. Free is single-active-user, so in
/// practice this is one; the cap only stops fast-user-switching from growing the
/// map without bound. On overflow the least recently seen principal is dropped —
/// it is the one whose remembered address is most likely stale anyway.
const MAX_TRACKED_PRINCIPALS: usize = 8;

// ── Ports ────────────────────────────────────────────────────────────────────

/// Asks the network what address is seen behind `source`. `None` means the
/// question could not be answered — no route, a filtered path, a dead endpoint.
///
/// A closure over the platform probe rather than a direct call, so this module
/// stays free of transport concerns and the anti-spam policy is testable with a
/// probe that answers instantly.
pub type ExternalAddressProbeFn = Arc<dyn Fn(Ipv4Addr) -> Option<Ipv4Addr> + Send + Sync>;

/// Produces the currently usable additional link of every routing-active user.
/// Empty while nobody has a usable one.
pub type SecondaryLinkSourceFn = Arc<dyn Fn() -> Vec<SecondaryLink> + Send + Sync>;

// ── Values ───────────────────────────────────────────────────────────────────

/// One user's usable additional link, as the announcer needs to see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecondaryLink {
    pub sid: String,
    pub interface_index: u32,
    /// The adapter's own IPv4 — what a probe socket binds to so the answer
    /// describes THIS link.
    pub source_ipv4: Ipv4Addr,
    /// Human-readable adapter description, carried into the notice.
    pub adapter_name: String,
}

impl SecondaryLink {
    /// What makes this the *same* link as before. The description deliberately
    /// plays no part: a driver renaming its adapter is not a reconnection.
    fn identity(&self) -> (u32, Ipv4Addr) {
        (self.interface_index, self.source_ipv4)
    }
}

/// Everything the periodic tick needs, assembled at the composition root.
///
/// One field instead of two on the runtime deps: the announcer and the snapshot
/// source are useless apart, and pairing them here means a profile that cannot
/// build one cannot accidentally spawn the tick with the other.
#[derive(Clone)]
pub struct ExternalAddressWiring {
    pub announcer: Arc<ExternalAddressAnnouncer>,
    pub links: SecondaryLinkSourceFn,
}

/// What [`ExternalAddressAnnouncer::on_probe_result`] did, for logging and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnnounceOutcome {
    /// The event was published.
    Announced,
    /// The probe came back without an address — nothing is shown.
    NoAddress,
    /// The previous notice is still too recent — a flapping link.
    SuppressedTooSoon,
    /// The user has no tracked link any more (unbound mid-probe).
    Stale,
}

// ── Announcer ────────────────────────────────────────────────────────────────

/// Per-principal bookkeeping. The announcement timestamp outlives the link on
/// purpose — it is the floor a flapping tunnel is measured against.
#[derive(Clone, Debug)]
struct LinkState {
    /// Identity of the link as of the last tick; `None` while it is absent.
    identity: Option<(u32, Ipv4Addr)>,
    /// When `identity` was first seen with its current value, or when the last
    /// unanswered probe came back — both gate the next attempt.
    since: Instant,
    /// A probe has already been started for this attempt.
    probed: bool,
    /// A probe worker is running right now.
    in_flight: bool,
    /// Probes started for this incarnation, answered or not.
    attempts: u8,
    announced_at: Option<Instant>,
    /// Last tick that mentioned this principal — the eviction key.
    touched: Instant,
}

impl LinkState {
    fn new(now: Instant) -> Self {
        Self {
            identity: None,
            since: now,
            probed: false,
            in_flight: false,
            attempts: 0,
            announced_at: None,
            touched: now,
        }
    }
}

/// Turns "the additional link connected" into at most one tray notice carrying
/// the address the outside world sees behind it.
pub struct ExternalAddressAnnouncer {
    events: Option<Arc<EventBus>>,
    probe: ExternalAddressProbeFn,
    state: Mutex<HashMap<String, LinkState>>,
}

impl ExternalAddressAnnouncer {
    pub fn new(events: Arc<EventBus>, probe: ExternalAddressProbeFn) -> Self {
        Self {
            events: Some(events),
            probe,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Announcer without a push channel: it still runs the whole decision path
    /// (and logs it) but nothing is delivered. Used by tests and by profiles
    /// where no event bus is wired.
    #[must_use]
    pub fn without_events(probe: ExternalAddressProbeFn) -> Self {
        Self {
            events: None,
            probe,
            state: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, LinkState>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One tick: fold the current snapshot into the per-principal state and
    /// start a probe for every link that has just settled.
    ///
    /// Returns the links a probe was started for, so callers that want to drive
    /// the flow synchronously (tests) can. Production ignores it — the workers
    /// report back on their own.
    pub fn tick(self: &Arc<Self>, links: &[SecondaryLink]) -> Vec<SecondaryLink> {
        let due = self.observe(links, Instant::now());
        for link in &due {
            self.spawn_probe(link.clone());
        }
        due
    }

    /// The pure half of the tick: update the state machine and report which
    /// links are due a probe. No network, no threads, injected clock.
    pub fn observe(&self, links: &[SecondaryLink], now: Instant) -> Vec<SecondaryLink> {
        let mut state = self.lock();
        let mut due = Vec::new();

        for link in links {
            let entry = state
                .entry(link.sid.clone())
                .or_insert_with(|| LinkState::new(now));
            entry.touched = now;
            let identity = link.identity();
            if entry.identity != Some(identity) {
                // A new incarnation: a fresh connection, a re-IP, or a move to
                // a different adapter. The announced-address memory survives —
                // it is what suppresses "you reconnected to the same exit".
                entry.identity = Some(identity);
                entry.since = now;
                entry.probed = false;
                entry.attempts = 0;
                continue;
            }
            if entry.probed || entry.in_flight || entry.attempts >= MAX_PROBE_ATTEMPTS {
                continue;
            }
            if now.saturating_duration_since(entry.since) < LINK_SETTLE {
                continue;
            }
            entry.probed = true;
            entry.in_flight = true;
            entry.attempts = entry.attempts.saturating_add(1);
            due.push(link.clone());
        }

        // Principals whose link is gone: forget the identity so its return
        // counts as a connection, and keep everything else.
        for (sid, entry) in state.iter_mut() {
            if links.iter().any(|link| &link.sid == sid) {
                continue;
            }
            entry.identity = None;
            entry.probed = false;
            entry.attempts = 0;
        }
        evict_overflow(&mut state);
        due
    }

    /// Fold one probe answer into the state and publish if the anti-spam rules
    /// allow it.
    pub fn on_probe_result(
        &self,
        link: &SecondaryLink,
        observed: Option<Ipv4Addr>,
        now: Instant,
    ) -> AnnounceOutcome {
        let mut state = self.lock();
        let Some(entry) = state.get_mut(&link.sid) else {
            return AnnounceOutcome::Stale;
        };
        entry.in_flight = false;

        let Some(address) = observed else {
            // Usually "the client raised the adapter but has not installed its
            // routes yet", which the next attempt resolves. Re-arm rather than
            // give up: the settle gate doubles as the retry delay.
            let retry = entry.attempts < MAX_PROBE_ATTEMPTS;
            if retry {
                entry.probed = false;
                entry.since = now;
            }
            tracing::info!(
                target: "nrr::interfaces",
                sid = %link.sid,
                adapter = %link.adapter_name,
                attempt = entry.attempts,
                retry,
                "additional route connected but its external address could not be observed — nothing shown to the user",
            );
            return AnnounceOutcome::NoAddress;
        };

        let too_soon = entry
            .announced_at
            .is_some_and(|at| now.saturating_duration_since(at) < ANNOUNCE_MIN_INTERVAL);
        if too_soon {
            tracing::debug!(
                target: "nrr::interfaces",
                sid = %link.sid,
                "additional route changed its external address again within the quiet period — notice suppressed",
            );
            return AnnounceOutcome::SuppressedTooSoon;
        }

        entry.announced_at = Some(now);
        drop(state);

        tracing::info!(
            target: "nrr::interfaces",
            sid = %link.sid,
            adapter = %link.adapter_name,
            "external address of the additional route observed after it connected — telling the user",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish(StatusUpdateEvent::SecondaryExternalAddressObserved {
                sid: link.sid.clone(),
                adapter_name: link.adapter_name.clone(),
                external_address: address.to_string(),
            });
        }
        AnnounceOutcome::Announced
    }

    /// Run one probe off the caller's thread and report back.
    ///
    /// Detached on purpose: the worker can sit in the OS resolver or a socket
    /// call for longer than any timeout set on the socket, and a supervised tick
    /// thread must never be the one waiting. Nothing joins it; if the service is
    /// stopping when it finishes, it simply takes a mutex and finds no state
    /// worth changing.
    fn spawn_probe(self: &Arc<Self>, link: SecondaryLink) {
        let announcer = Arc::clone(self);
        let probed = link.clone();
        let spawned = thread::Builder::new()
            .name("nrr-secondary-extip".to_string())
            .spawn(move || {
                let observed = (announcer.probe)(probed.source_ipv4);
                announcer.on_probe_result(&probed, observed, Instant::now());
            });
        if let Err(error) = spawned {
            // Could not start the worker: release the in-flight latch so the
            // next tick can retry rather than leaving the link silent forever.
            if let Some(entry) = self.lock().get_mut(&link.sid) {
                entry.in_flight = false;
                entry.probed = false;
            }
            tracing::debug!(
                target: "nrr::interfaces",
                error = %error,
                "external-address probe worker for the additional route not started",
            );
        }
    }
}

/// Drop the least recently seen principals once the map is over the cap.
fn evict_overflow(state: &mut HashMap<String, LinkState>) {
    while state.len() > MAX_TRACKED_PRINCIPALS {
        let victim = state
            .iter()
            .min_by_key(|(_, entry)| entry.touched)
            .map(|(sid, _)| sid.clone());
        match victim {
            Some(sid) => {
                state.remove(&sid);
            }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-test";

    fn link(index: u32, source: [u8; 4]) -> SecondaryLink {
        SecondaryLink {
            sid: SID.to_string(),
            interface_index: index,
            source_ipv4: Ipv4Addr::from(source),
            adapter_name: "Test VPN Adapter".to_string(),
        }
    }

    fn announcer() -> ExternalAddressAnnouncer {
        ExternalAddressAnnouncer::without_events(Arc::new(|_| None))
    }

    fn addr(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    #[test]
    fn a_link_is_probed_only_after_it_settles() {
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        assert!(
            a.observe(std::slice::from_ref(&l), t0).is_empty(),
            "the tick that first sees the link must not probe it"
        );
        assert!(
            a.observe(
                std::slice::from_ref(&l),
                t0 + LINK_SETTLE - Duration::from_secs(1)
            )
            .is_empty(),
            "still inside the settle window"
        );
        assert_eq!(
            a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE),
            vec![l.clone()]
        );
        assert!(
            a.observe(&[l], t0 + LINK_SETTLE * 4).is_empty(),
            "one probe per incarnation, not one per tick"
        );
    }

    #[test]
    fn a_flap_shorter_than_the_settle_window_never_reaches_the_probe() {
        // The acceptance run saw the adapter drop and return twice within six
        // minutes. A cycle that completes inside the settle window must cost
        // nothing at all.
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        assert!(a.observe(std::slice::from_ref(&l), t0).is_empty());
        assert!(a.observe(&[], t0 + Duration::from_secs(5)).is_empty());
        assert!(a
            .observe(std::slice::from_ref(&l), t0 + Duration::from_secs(10))
            .is_empty());
        // The clock restarted with the reconnection, so the original settle
        // deadline proves nothing.
        assert!(a
            .observe(std::slice::from_ref(&l), t0 + LINK_SETTLE)
            .is_empty());
        assert_eq!(
            a.observe(
                std::slice::from_ref(&l),
                t0 + Duration::from_secs(10) + LINK_SETTLE
            ),
            vec![l]
        );
    }

    #[test]
    fn a_reconnect_on_the_same_address_is_announced_again() {
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        assert_eq!(
            a.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE),
            AnnounceOutcome::Announced
        );

        // …the tunnel drops and comes back past the quiet period, on the same
        // exit node. The user reconnected and is owed the confirmation: an
        // unchanged address is still the answer to "did it come up, and as
        // whom?".
        let later = t0 + ANNOUNCE_MIN_INTERVAL * 2;
        a.observe(&[], later);
        a.observe(std::slice::from_ref(&l), later);
        assert_eq!(
            a.observe(std::slice::from_ref(&l), later + LINK_SETTLE),
            vec![l.clone()]
        );
        assert_eq!(
            a.on_probe_result(&l, Some(addr(10)), later + LINK_SETTLE),
            AnnounceOutcome::Announced,
        );
    }

    #[test]
    fn an_unanswered_probe_is_retried_and_then_left_alone() {
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        let mut at = t0;
        for attempt in 1..=u32::from(MAX_PROBE_ATTEMPTS) {
            at += LINK_SETTLE;
            assert_eq!(
                a.observe(std::slice::from_ref(&l), at),
                vec![l.clone()],
                "attempt {attempt} should have been started",
            );
            assert_eq!(a.on_probe_result(&l, None, at), AnnounceOutcome::NoAddress);
        }
        // Spent: a path that never answered is not polled for the rest of this
        // incarnation.
        assert!(a
            .observe(std::slice::from_ref(&l), at + LINK_SETTLE * 4)
            .is_empty());
        // A reconnect is a new incarnation and starts the attempts over.
        let renewed = link(7, [10, 88, 1, 77]);
        a.observe(std::slice::from_ref(&renewed), at + LINK_SETTLE * 4);
        assert_eq!(
            a.observe(std::slice::from_ref(&renewed), at + LINK_SETTLE * 6),
            vec![renewed]
        );
    }

    #[test]
    fn a_new_address_inside_the_quiet_period_waits() {
        // A load-balanced pool hands out a different exit address on every
        // reconnect; without the floor, every flap would pop a window.
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        assert_eq!(
            a.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE),
            AnnounceOutcome::Announced
        );

        let soon = t0 + ANNOUNCE_MIN_INTERVAL / 2;
        assert_eq!(
            a.on_probe_result(&l, Some(addr(11)), soon),
            AnnounceOutcome::SuppressedTooSoon,
        );
        // Suppression does not rewrite the remembered address, so once the
        // floor has passed the next observation is still judged against what
        // the user was actually told.
        let after = t0 + LINK_SETTLE + ANNOUNCE_MIN_INTERVAL + Duration::from_secs(1);
        assert_eq!(
            a.on_probe_result(&l, Some(addr(11)), after),
            AnnounceOutcome::Announced,
        );
    }

    #[test]
    fn a_probe_without_an_answer_shows_nothing_and_remembers_nothing() {
        let a = announcer();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        assert_eq!(
            a.on_probe_result(&l, None, t0 + LINK_SETTLE),
            AnnounceOutcome::NoAddress
        );
        // Nothing was announced, so the very next answer — whatever it is — is
        // still news and is not held back by a floor that never started.
        assert_eq!(
            a.on_probe_result(
                &l,
                Some(addr(10)),
                t0 + LINK_SETTLE + Duration::from_secs(1)
            ),
            AnnounceOutcome::Announced,
        );
    }

    #[test]
    fn a_re_ip_without_a_disconnect_counts_as_a_new_connection() {
        // The adapter never left, but the tunnel renewed its inner address:
        // the exit address may well have changed with it.
        let a = announcer();
        let t0 = Instant::now();
        let first = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&first), t0);
        assert_eq!(
            a.observe(std::slice::from_ref(&first), t0 + LINK_SETTLE),
            vec![first.clone()]
        );
        a.on_probe_result(&first, Some(addr(10)), t0 + LINK_SETTLE);

        let renewed = link(7, [10, 88, 2, 9]);
        let t1 = t0 + LINK_SETTLE + Duration::from_secs(1);
        assert!(a.observe(std::slice::from_ref(&renewed), t1).is_empty());
        assert_eq!(
            a.observe(std::slice::from_ref(&renewed), t1 + LINK_SETTLE),
            vec![renewed]
        );
    }

    #[test]
    fn a_re_ip_while_a_probe_is_out_does_not_double_probe() {
        // The worker is detached, so the state machine — not a join — is what
        // keeps one probe per principal in the air.
        let a = announcer();
        let t0 = Instant::now();
        let first = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&first), t0);
        assert_eq!(
            a.observe(std::slice::from_ref(&first), t0 + LINK_SETTLE),
            vec![first.clone()]
        );

        let renewed = link(7, [10, 88, 2, 9]);
        let t1 = t0 + LINK_SETTLE + Duration::from_secs(1);
        a.observe(std::slice::from_ref(&renewed), t1);
        assert!(
            a.observe(std::slice::from_ref(&renewed), t1 + LINK_SETTLE)
                .is_empty(),
            "the earlier probe has not reported yet"
        );
        a.on_probe_result(&first, Some(addr(10)), t1 + LINK_SETTLE);
        assert_eq!(
            a.observe(std::slice::from_ref(&renewed), t1 + LINK_SETTLE * 2),
            vec![renewed]
        );
    }

    #[test]
    fn a_probe_answer_for_an_unknown_principal_is_dropped() {
        let a = announcer();
        let stranger = SecondaryLink {
            sid: "S-1-5-21-someone-else".to_string(),
            ..link(7, [10, 88, 1, 41])
        };
        assert_eq!(
            a.on_probe_result(&stranger, Some(addr(10)), Instant::now()),
            AnnounceOutcome::Stale
        );
    }

    #[test]
    fn tracked_principals_are_capped() {
        let a = announcer();
        let t0 = Instant::now();
        for n in 0..(MAX_TRACKED_PRINCIPALS as u32 + 4) {
            let l = SecondaryLink {
                sid: format!("S-1-5-21-{n}"),
                ..link(n + 1, [10, 88, 1, 41])
            };
            a.observe(&[l], t0 + Duration::from_secs(u64::from(n)));
        }
        assert_eq!(a.lock().len(), MAX_TRACKED_PRINCIPALS);
    }

    /// Announcer wired to a real bus, so what reaches the tray can be asserted
    /// rather than inferred from a return value.
    fn announcer_on_bus() -> (ExternalAddressAnnouncer, Arc<EventBus>) {
        let bus = Arc::new(EventBus::new());
        (
            ExternalAddressAnnouncer::new(Arc::clone(&bus), Arc::new(|_| None)),
            bus,
        )
    }

    fn published(bus: &EventBus) -> Vec<StatusUpdateEvent> {
        let outcome = bus.subscribe("test".to_string(), Some(0));
        bus.peek_pending_for(&outcome.subscription_id, 64)
            .into_iter()
            .map(|entry| entry.event)
            .collect()
    }

    #[test]
    fn a_probe_that_found_nothing_pushes_nothing() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        assert_eq!(
            a.on_probe_result(&l, None, t0 + LINK_SETTLE),
            AnnounceOutcome::NoAddress
        );
        assert_eq!(
            bus.buffer_len(),
            0,
            "an unknown address is not a notification"
        );
    }

    #[test]
    fn only_the_first_of_a_flap_run_reaches_the_tray() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        a.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE);
        // Same exit node on the next cycle, then a different one while the
        // quiet period still holds — the shape of a tunnel flapping through a
        // load-balanced pool.
        a.on_probe_result(&l, Some(addr(10)), t0 + ANNOUNCE_MIN_INTERVAL / 4);
        a.on_probe_result(&l, Some(addr(11)), t0 + ANNOUNCE_MIN_INTERVAL / 2);

        let events = published(&bus);
        assert_eq!(
            events.len(),
            1,
            "one notice per quiet period, whatever the flapping"
        );
        match &events[0] {
            StatusUpdateEvent::SecondaryExternalAddressObserved {
                sid,
                adapter_name,
                external_address,
            } => {
                assert_eq!(sid, SID);
                assert_eq!(adapter_name, "Test VPN Adapter");
                assert_eq!(external_address, "203.0.113.10");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn the_settle_window_fits_inside_the_quiet_period() {
        assert!(
            LINK_SETTLE < ANNOUNCE_MIN_INTERVAL,
            "a link must be able to settle and speak inside one quiet period"
        );
    }
}

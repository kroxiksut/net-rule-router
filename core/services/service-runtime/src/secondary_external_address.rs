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
//!   coordinator, which is the single place that decides what "usable" means,
//!   or where there is none by [`bound_secondary_link`].
//!   A change of identity — or an appearance after an absence — is a new
//!   incarnation of the link, i.e. a connection.
//! - **Deciding whether to speak** is pure and lives in [`ExternalAddressAnnouncer::observe`]
//!   and [`ExternalAddressAnnouncer::on_probe_result`], both of which take
//!   `now: Instant` so the whole anti-spam policy is testable without sleeping.
//! - **Asking the network** happens on a detached thread, never on the caller's.
//! - **Whether to ask at all** is the user's: the check is opt-in per user
//!   (`external_address_auto_check`), off by default, because it sends a
//!   request through the tunnel. A user who has not opted in is never even
//!   resolved, so the steady state costs them nothing.
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
//!
//! # Withdrawal
//!
//! An address describes one incarnation of the link. When that incarnation
//! ends — the link goes down, or comes back under another identity — the users
//! told about it hear that it no longer holds, so no client keeps showing the
//! exit of a tunnel that is gone. A reconnect inside the quiet period refills
//! the value without announcing it.
//!
//! A wake, or another network behind the same link, asks again without
//! withdrawing; only an exit that changed is announced.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nrr_shared::ipc_payloads::StatusUpdateEvent;

use crate::ipc_handlers::event_bus::EventBus;
use crate::power_resume::{process_sleeps, SleepLedger};

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

/// The users the service is routing for right now.
pub type ServedSidsFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Did this user ask for the automatic check? Read on every tick, so switching
/// it takes effect without a restart.
pub type AutoCheckOptInFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// One user's currently usable additional link, `None` while there is none.
pub type SecondaryLinkOfFn = Arc<dyn Fn(&str) -> Option<SecondaryLink> + Send + Sync>;

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
    /// The link's own next hops: a different set under the same identity is
    /// a move to another network, whose exit may differ.
    pub gateways: Vec<Ipv4Addr>,
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
/// One field on the runtime deps: the parts are useless apart, and pairing them
/// here means a profile that cannot build one cannot spawn the tick without it.
#[derive(Clone)]
pub struct ExternalAddressWiring {
    pub announcer: Arc<ExternalAddressAnnouncer>,
    pub served: ServedSidsFn,
    pub opted_in: AutoCheckOptInFn,
    pub link_of: SecondaryLinkOfFn,
}

impl ExternalAddressWiring {
    /// The links of the served users who asked for the check.
    pub fn watched_links(&self) -> Vec<SecondaryLink> {
        let mut links = Vec::new();
        for sid in (self.served)() {
            if !(self.opted_in)(&sid) {
                // Dropping out of the snapshot would read as the link going
                // down and withdraw an address that is still true.
                self.announcer.forget(&sid);
                continue;
            }
            links.extend((self.link_of)(&sid));
        }
        links
    }

    /// One tick of the task. A user who switched the check off drops out of
    /// the snapshot, so switching it back on while connected counts as a
    /// connection and is answered once.
    pub fn tick(&self) -> Vec<SecondaryLink> {
        self.tick_at(Instant::now())
    }

    fn tick_at(&self, now: Instant) -> Vec<SecondaryLink> {
        self.announcer.tick_at(&self.watched_links(), now)
    }
}

/// The opt-in as stored in the user's route policy. A row that cannot be read
/// reads as off: the check is never sent on a guess.
pub fn stored_opt_in(state_conn: Arc<Mutex<rusqlite::Connection>>) -> AutoCheckOptInFn {
    Arc::new(move |sid: &str| {
        let guard = state_conn.lock().unwrap_or_else(|p| p.into_inner());
        nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
            .load_for_sid(sid)
            .is_ok_and(|record| record.external_address_auto_check)
    })
}

/// `sid`'s additional link as `adapters` show it: the adapter its binding
/// names, up and holding an IPv4. For a platform without a route coordinator to
/// resolve it.
pub fn bound_secondary_link(
    sid: &str,
    adapters: &[nrr_platform_api::adapters::AdapterInfo],
    bound_name: &str,
) -> Option<SecondaryLink> {
    let adapter = crate::catch_all_exemptions::bound_adapter(adapters, Some(bound_name))?;
    if !adapter.oper_status.is_up() {
        return None;
    }
    let name = if adapter.friendly_name.is_empty() {
        &adapter.description
    } else {
        &adapter.friendly_name
    };
    Some(SecondaryLink {
        sid: sid.to_string(),
        interface_index: adapter.index,
        source_ipv4: adapter.ipv4_addresses.first().copied()?,
        adapter_name: name.clone(),
        gateways: adapter.gateways.clone(),
    })
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
    /// A check after a wake or a move found the exit the user already holds.
    Unchanged,
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
    /// The user holds an address for the current incarnation.
    told: bool,
    /// The address they hold.
    told_address: Option<Ipv4Addr>,
    /// The link's next hops, sorted, as last seen.
    path: Vec<Ipv4Addr>,
    /// The probe due confirms the held address rather than announcing one.
    recheck: bool,
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
            told: false,
            told_address: None,
            path: Vec::new(),
            recheck: false,
        }
    }

    /// The incarnation the user was told about has ended. `true` when they
    /// hold an address that must now be withdrawn.
    fn end_incarnation(&mut self) -> bool {
        self.told_address = None;
        self.recheck = false;
        std::mem::take(&mut self.told)
    }

    /// Probe again after the settle window, attempts counted afresh.
    fn rearm(&mut self, now: Instant) {
        self.since = now;
        self.probed = false;
        self.attempts = 0;
    }
}

fn path_of(link: &SecondaryLink) -> Vec<Ipv4Addr> {
    let mut path = link.gateways.clone();
    path.sort_unstable();
    path.dedup();
    path
}

/// Turns "the additional link connected" into at most one tray notice carrying
/// the address the outside world sees behind it.
pub struct ExternalAddressAnnouncer {
    events: Option<Arc<EventBus>>,
    probe: ExternalAddressProbeFn,
    state: Mutex<HashMap<String, LinkState>>,
    /// Where wakes are counted: an exit learned before a sleep is checked
    /// again after it.
    sleeps: Arc<SleepLedger>,
    wakes_seen: AtomicU64,
}

impl ExternalAddressAnnouncer {
    pub fn new(events: Arc<EventBus>, probe: ExternalAddressProbeFn) -> Self {
        Self::with_events(Some(events), probe)
    }

    /// Announcer without a push channel: it still runs the whole decision path
    /// (and logs it) but nothing is delivered. Used by tests and by profiles
    /// where no event bus is wired.
    #[must_use]
    pub fn without_events(probe: ExternalAddressProbeFn) -> Self {
        Self::with_events(None, probe)
    }

    fn with_events(events: Option<Arc<EventBus>>, probe: ExternalAddressProbeFn) -> Self {
        let sleeps = process_sleeps();
        Self {
            events,
            probe,
            state: Mutex::new(HashMap::new()),
            wakes_seen: AtomicU64::new(sleeps.wakes()),
            sleeps,
        }
    }

    /// Count wakes in `sleeps` instead of the process's own ledger.
    #[must_use]
    pub fn with_sleeps(mut self, sleeps: Arc<SleepLedger>) -> Self {
        self.wakes_seen = AtomicU64::new(sleeps.wakes());
        self.sleeps = sleeps;
        self
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
        self.tick_at(links, Instant::now())
    }

    fn tick_at(self: &Arc<Self>, links: &[SecondaryLink], now: Instant) -> Vec<SecondaryLink> {
        let due = self.observe(links, now);
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
        let mut withdrawn = Vec::new();
        let wakes = self.sleeps.wakes();
        let woke = self.wakes_seen.swap(wakes, Ordering::AcqRel) != wakes;

        for link in links {
            let entry = state
                .entry(link.sid.clone())
                .or_insert_with(|| LinkState::new(now));
            entry.touched = now;
            let identity = link.identity();
            let path = path_of(link);
            if entry.identity != Some(identity) {
                // A new incarnation: a fresh connection, a re-IP, or a move to
                // a different adapter. The announcement time survives — it is
                // the floor a flapping tunnel is measured against.
                if entry.end_incarnation() {
                    withdrawn.push(link.sid.clone());
                }
                entry.identity = Some(identity);
                entry.path = path;
                entry.rearm(now);
                // Whatever probe is still in the air belongs to the previous
                // incarnation and will be discarded on arrival; leaving the
                // flag set would keep this one from ever being probed.
                entry.in_flight = false;
                continue;
            }
            // Same link, but a sleep or another network behind it: the exit
            // the user holds may no longer be theirs. Not a reconnection, so
            // nothing is withdrawn while it is asked again.
            if woke || entry.path != path {
                entry.path = path;
                entry.recheck = entry.told;
                entry.rearm(now);
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
            if entry.end_incarnation() {
                withdrawn.push(sid.clone());
            }
            entry.identity = None;
            entry.probed = false;
            entry.attempts = 0;
        }
        evict_overflow(&mut state);
        drop(state);
        for sid in withdrawn {
            self.withdraw(sid);
        }
        due
    }

    /// Stop tracking `sid` without telling them anything: they switched the
    /// check off, which ends nothing about the link itself.
    pub fn forget(&self, sid: &str) {
        self.lock().remove(sid);
    }

    fn withdraw(&self, sid: String) {
        tracing::info!(
            target: "nrr::interfaces",
            msg_key = "secext-withdrawn",
            sid = %sid,
            "additional route went down or changed — its external address is no longer shown",
        );
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid.clone(),
                StatusUpdateEvent::SecondaryExternalAddressCleared { sid },
            );
        }
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
        // The answer must belong to the incarnation that asked. A link that
        // re-connected while its probe was in the air has a different identity
        // now, and publishing the old exit as the current one is worse than
        // publishing nothing — the flag is left alone because it belongs to the
        // probe of the new incarnation, not to this one.
        if entry.identity != Some(link.identity()) {
            return AnnounceOutcome::Stale;
        }
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
                msg_key = "secext-probe-no-address",
                sid = %link.sid,
                adapter = %link.adapter_name,
                attempt = entry.attempts,
                retry,
                "additional route connected but its external address could not be observed — nothing shown to the user",
            );
            return AnnounceOutcome::NoAddress;
        };
        if std::mem::take(&mut entry.recheck) && entry.told_address == Some(address) {
            return AnnounceOutcome::Unchanged;
        }

        let too_soon = entry
            .announced_at
            .is_some_and(|at| now.saturating_duration_since(at) < ANNOUNCE_MIN_INTERVAL);
        entry.told = true;
        entry.told_address = Some(address);
        if too_soon {
            drop(state);
            tracing::debug!(
                target: "nrr::interfaces",
                sid = %link.sid,
                "additional route changed its external address again within the quiet period — notice suppressed",
            );
            // The previous address was withdrawn when the link went down, so
            // the value is still owed; only the announcement is held back.
            self.publish_observed(link, address, true);
            return AnnounceOutcome::SuppressedTooSoon;
        }

        entry.announced_at = Some(now);
        drop(state);

        tracing::info!(
            target: "nrr::interfaces",
            msg_key = "secext-observed",
            sid = %link.sid,
            adapter = %link.adapter_name,
            "external address of the additional route observed after it connected — telling the user",
        );
        self.publish_observed(link, address, false);
        AnnounceOutcome::Announced
    }

    fn publish_observed(&self, link: &SecondaryLink, address: Ipv4Addr, quiet: bool) {
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                link.sid.clone(),
                StatusUpdateEvent::SecondaryExternalAddressObserved {
                    sid: link.sid.clone(),
                    adapter_name: link.adapter_name.clone(),
                    external_address: address.to_string(),
                    quiet,
                },
            );
        }
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
            gateways: Vec::new(),
        }
    }

    /// Wakes other tests record into the process's ledger stay out of these.
    fn announcer() -> ExternalAddressAnnouncer {
        ExternalAddressAnnouncer::without_events(Arc::new(|_| None)).with_sleeps(Arc::default())
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
    fn one_probe_per_incarnation_stays_in_the_air() {
        // The worker is detached, so the state machine — not a join — is what
        // keeps a settled link from being probed twice over.
        let a = announcer();
        let t0 = Instant::now();
        let only = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&only), t0);
        assert_eq!(
            a.observe(std::slice::from_ref(&only), t0 + LINK_SETTLE),
            vec![only.clone()]
        );
        assert!(
            a.observe(std::slice::from_ref(&only), t0 + LINK_SETTLE * 2)
                .is_empty(),
            "the probe of this incarnation has not reported yet"
        );
    }

    #[test]
    fn a_re_ip_while_a_probe_is_out_probes_anew_and_discards_the_old_answer() {
        // The old probe measured the exit of a connection that no longer
        // exists. Waiting for it left the live one unprobed, and folding its
        // answer in published the previous exit as the current one.
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
        assert_eq!(
            a.observe(std::slice::from_ref(&renewed), t1 + LINK_SETTLE),
            vec![renewed.clone()],
            "the new incarnation must not wait on the old probe"
        );
        assert_eq!(
            a.on_probe_result(&first, Some(addr(10)), t1 + LINK_SETTLE),
            AnnounceOutcome::Stale,
            "an answer about the previous connection is not the current address"
        );
        // And the live probe still owns its slot: its own answer lands.
        assert_eq!(
            a.on_probe_result(&renewed, Some(addr(11)), t1 + LINK_SETTLE * 2),
            AnnounceOutcome::Announced
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
            ExternalAddressAnnouncer::new(Arc::clone(&bus), Arc::new(|_| None))
                .with_sleeps(Arc::default()),
            bus,
        )
    }

    fn published(bus: &EventBus) -> Vec<StatusUpdateEvent> {
        let outcome = bus.subscribe_as("test".to_string(), Some(SID.to_string()), Some(0));
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

        let observed: Vec<(String, bool)> = published(&bus)
            .into_iter()
            .map(|event| match event {
                StatusUpdateEvent::SecondaryExternalAddressObserved {
                    sid,
                    adapter_name,
                    external_address,
                    quiet,
                } => {
                    assert_eq!(sid, SID);
                    assert_eq!(adapter_name, "Test VPN Adapter");
                    (external_address, quiet)
                }
                other => panic!("unexpected event: {other:?}"),
            })
            .collect();
        assert_eq!(
            observed.iter().filter(|(_, quiet)| !quiet).count(),
            1,
            "one notice per quiet period, whatever the flapping"
        );
        assert_eq!(observed[0], ("203.0.113.10".to_string(), false));
        assert_eq!(
            observed.last(),
            Some(&("203.0.113.11".to_string(), true)),
            "the value the clients hold is still the current one"
        );
    }

    /// Every event `bus` holds for the test user that withdraws an address.
    fn withdrawals(bus: &EventBus) -> usize {
        published(bus)
            .iter()
            .filter(|event| {
                matches!(
                    event,
                    StatusUpdateEvent::SecondaryExternalAddressCleared { sid } if sid == SID
                )
            })
            .count()
    }

    #[test]
    fn a_link_that_goes_down_withdraws_the_address_it_was_told() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        a.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE * 2);
        assert_eq!(withdrawals(&bus), 0, "the link is still up");

        a.observe(&[], t0 + LINK_SETTLE * 3);
        assert_eq!(withdrawals(&bus), 1, "the tunnel is gone, so is its exit");
        a.observe(&[], t0 + LINK_SETTLE * 4);
        assert_eq!(withdrawals(&bus), 1, "said once, not once per tick");
    }

    #[test]
    fn a_link_that_never_got_an_address_goes_down_silently() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        a.on_probe_result(&l, None, t0 + LINK_SETTLE);
        a.observe(&[], t0 + LINK_SETTLE * 2);
        assert_eq!(
            bus.buffer_len(),
            0,
            "nothing was shown, nothing to take back"
        );
    }

    #[test]
    fn a_re_ip_withdraws_the_old_exit_until_the_new_one_is_known() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let first = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&first), t0);
        a.observe(std::slice::from_ref(&first), t0 + LINK_SETTLE);
        a.on_probe_result(&first, Some(addr(10)), t0 + LINK_SETTLE);

        let renewed = link(7, [10, 88, 2, 9]);
        a.observe(std::slice::from_ref(&renewed), t0 + LINK_SETTLE * 2);
        assert_eq!(withdrawals(&bus), 1);
    }

    #[test]
    fn a_quick_reconnect_refills_the_address_without_a_notice() {
        let (a, bus) = announcer_on_bus();
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        a.observe(std::slice::from_ref(&l), t0);
        a.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        a.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE);
        let down = t0 + LINK_SETTLE * 2;
        a.observe(&[], down);
        a.observe(std::slice::from_ref(&l), down);
        assert_eq!(
            a.observe(std::slice::from_ref(&l), down + LINK_SETTLE),
            vec![l.clone()]
        );
        assert_eq!(
            a.on_probe_result(&l, Some(addr(10)), down + LINK_SETTLE),
            AnnounceOutcome::SuppressedTooSoon
        );
        match published(&bus).last() {
            Some(StatusUpdateEvent::SecondaryExternalAddressObserved {
                external_address,
                quiet,
                ..
            }) => {
                assert_eq!(external_address, "203.0.113.10");
                assert!(quiet, "inside the quiet period nothing is announced");
            }
            other => panic!("the address was not refilled: {other:?}"),
        }
        // The refilled value is withdrawn like any other.
        a.observe(&[], down + LINK_SETTLE * 2);
        assert_eq!(withdrawals(&bus), 2);
    }

    /// `l` settles and its exit `address` is announced at `t0 + LINK_SETTLE`.
    fn told(a: &ExternalAddressAnnouncer, l: &SecondaryLink, t0: Instant, address: Ipv4Addr) {
        a.observe(std::slice::from_ref(l), t0);
        a.observe(std::slice::from_ref(l), t0 + LINK_SETTLE);
        assert_eq!(
            a.on_probe_result(l, Some(address), t0 + LINK_SETTLE),
            AnnounceOutcome::Announced
        );
    }

    /// The lid was closed overnight and the tunnel came back with the same
    /// adapter and inner address, possibly through another exit: the exit is
    /// asked again, and the user hears only of a change.
    #[test]
    fn a_wake_checks_the_exit_again_and_tells_only_a_change() {
        let sleeps = Arc::new(SleepLedger::default());
        let bus = Arc::new(EventBus::new());
        let a = ExternalAddressAnnouncer::new(Arc::clone(&bus), Arc::new(|_| None))
            .with_sleeps(Arc::clone(&sleeps));
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        told(&a, &l, t0, addr(10));

        let woke = t0 + ANNOUNCE_MIN_INTERVAL * 2;
        let wall = std::time::SystemTime::now();
        sleeps.record(wall, Duration::from_secs(8 * 3600));
        assert!(a.observe(std::slice::from_ref(&l), woke).is_empty());
        assert_eq!(
            a.observe(std::slice::from_ref(&l), woke + LINK_SETTLE),
            vec![l.clone()],
            "the exit learned before the sleep is not checked again"
        );
        assert_eq!(
            a.on_probe_result(&l, Some(addr(10)), woke + LINK_SETTLE),
            AnnounceOutcome::Unchanged
        );
        assert!(
            a.observe(std::slice::from_ref(&l), woke + LINK_SETTLE * 3)
                .is_empty(),
            "one check per wake"
        );
        assert_eq!(withdrawals(&bus), 0, "the address held through the sleep");

        let next = woke + ANNOUNCE_MIN_INTERVAL * 2;
        sleeps.record(
            wall + Duration::from_secs(24 * 3600),
            Duration::from_secs(3600),
        );
        a.observe(std::slice::from_ref(&l), next);
        assert_eq!(
            a.observe(std::slice::from_ref(&l), next + LINK_SETTLE),
            vec![l.clone()]
        );
        assert_eq!(
            a.on_probe_result(&l, Some(addr(11)), next + LINK_SETTLE),
            AnnounceOutcome::Announced
        );
        let notices: Vec<String> = published(&bus)
            .into_iter()
            .filter_map(|event| match event {
                StatusUpdateEvent::SecondaryExternalAddressObserved {
                    external_address, ..
                } => Some(external_address),
                _ => None,
            })
            .collect();
        assert_eq!(notices, ["203.0.113.10", "203.0.113.11"]);
    }

    /// The additional link moved to another network and kept its adapter and
    /// address, as a Wi-Fi link handed the same lease often does: its exit is
    /// asked again.
    #[test]
    fn a_move_to_another_network_under_the_same_link_checks_the_exit_again() {
        let a = announcer();
        let t0 = Instant::now();
        let home = SecondaryLink {
            gateways: vec![Ipv4Addr::new(192, 168, 1, 1)],
            ..link(7, [192, 168, 1, 20])
        };
        told(&a, &home, t0, addr(10));
        assert!(
            a.observe(std::slice::from_ref(&home), t0 + LINK_SETTLE * 3)
                .is_empty(),
            "a link that stays put is not probed again"
        );

        let office = SecondaryLink {
            gateways: vec![Ipv4Addr::new(192, 168, 1, 254)],
            ..home.clone()
        };
        let moved = t0 + ANNOUNCE_MIN_INTERVAL * 2;
        assert!(a.observe(std::slice::from_ref(&office), moved).is_empty());
        assert_eq!(
            a.observe(std::slice::from_ref(&office), moved + LINK_SETTLE),
            vec![office.clone()],
            "the exit of the previous network is still shown as this one's"
        );
        assert_eq!(
            a.on_probe_result(&office, Some(addr(12)), moved + LINK_SETTLE),
            AnnounceOutcome::Announced
        );
    }

    #[test]
    fn switching_the_check_off_withdraws_nothing() {
        use std::sync::atomic::Ordering;
        let rig = opt_in_rig(true);
        let bus = Arc::new(EventBus::new());
        let announcer = Arc::new(
            ExternalAddressAnnouncer::new(Arc::clone(&bus), Arc::new(|_| Some(addr(10))))
                .with_sleeps(Arc::default()),
        );
        let opted_in = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let wiring = ExternalAddressWiring {
            announcer: Arc::clone(&announcer),
            served: rig.wiring.served.clone(),
            opted_in: {
                let opted_in = Arc::clone(&opted_in);
                Arc::new(move |_sid: &str| opted_in.load(Ordering::SeqCst))
            },
            link_of: rig.wiring.link_of.clone(),
        };
        let t0 = Instant::now();
        let l = link(7, [10, 88, 1, 41]);
        announcer.observe(std::slice::from_ref(&l), t0);
        announcer.observe(std::slice::from_ref(&l), t0 + LINK_SETTLE);
        announcer.on_probe_result(&l, Some(addr(10)), t0 + LINK_SETTLE);

        opted_in.store(false, Ordering::SeqCst);
        wiring.tick_at(t0 + LINK_SETTLE * 2);
        wiring.tick_at(t0 + LINK_SETTLE * 3);
        assert_eq!(
            withdrawals(&bus),
            0,
            "the link is still up, its address still true"
        );
    }

    /// A wiring over one user whose link is up while `connected` holds, with a
    /// probe that answers at once and counts its calls.
    struct OptInRig {
        wiring: ExternalAddressWiring,
        probes: Arc<std::sync::atomic::AtomicUsize>,
        resolved: Arc<std::sync::atomic::AtomicUsize>,
        connected: Arc<std::sync::atomic::AtomicBool>,
    }

    fn opt_in_rig(opted_in: bool) -> OptInRig {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let probes = Arc::new(AtomicUsize::new(0));
        let resolved = Arc::new(AtomicUsize::new(0));
        let connected = Arc::new(AtomicBool::new(true));
        let counter = Arc::clone(&probes);
        let announcer = Arc::new(
            ExternalAddressAnnouncer::without_events(Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                Some(addr(10))
            }))
            .with_sleeps(Arc::default()),
        );
        let link_of: SecondaryLinkOfFn = {
            let resolved = Arc::clone(&resolved);
            let connected = Arc::clone(&connected);
            Arc::new(move |_sid: &str| {
                resolved.fetch_add(1, Ordering::SeqCst);
                connected
                    .load(Ordering::SeqCst)
                    .then(|| link(7, [10, 88, 1, 41]))
            })
        };
        OptInRig {
            wiring: ExternalAddressWiring {
                announcer,
                served: Arc::new(|| vec![SID.to_string()]),
                opted_in: Arc::new(move |_sid: &str| opted_in),
                link_of,
            },
            probes,
            resolved,
            connected,
        }
    }

    /// The probe runs on its own thread; give it a moment to report.
    fn wait_for_probes(rig: &OptInRig, want: usize) -> usize {
        use std::sync::atomic::Ordering;
        let deadline = Instant::now() + Duration::from_secs(5);
        while rig.probes.load(Ordering::SeqCst) < want && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(20));
        rig.probes.load(Ordering::SeqCst)
    }

    #[test]
    fn without_the_opt_in_a_connect_sends_nothing() {
        use std::sync::atomic::Ordering;
        let rig = opt_in_rig(false);
        let t0 = Instant::now();
        for step in 0..6 {
            assert!(rig.wiring.tick_at(t0 + LINK_SETTLE * step).is_empty());
        }
        rig.connected.store(false, Ordering::SeqCst);
        rig.wiring.tick_at(t0 + LINK_SETTLE * 7);
        rig.connected.store(true, Ordering::SeqCst);
        rig.wiring.tick_at(t0 + LINK_SETTLE * 8);
        rig.wiring.tick_at(t0 + LINK_SETTLE * 10);
        // Nothing was due, so no worker was ever started to count.
        assert_eq!(
            rig.probes.load(Ordering::SeqCst),
            0,
            "no request leaves unasked"
        );
        assert_eq!(
            rig.resolved.load(Ordering::SeqCst),
            0,
            "a user who did not opt in is never even resolved"
        );
    }

    #[test]
    fn with_the_opt_in_each_connect_is_probed_once() {
        use std::sync::atomic::Ordering;
        let rig = opt_in_rig(true);
        let t0 = Instant::now();
        assert!(rig.wiring.tick_at(t0).is_empty(), "not settled yet");
        assert_eq!(rig.wiring.tick_at(t0 + LINK_SETTLE).len(), 1);
        assert_eq!(wait_for_probes(&rig, 1), 1);
        for step in 2..6 {
            assert!(rig.wiring.tick_at(t0 + LINK_SETTLE * step).is_empty());
        }
        assert_eq!(
            rig.probes.load(Ordering::SeqCst),
            1,
            "a link that stays up costs nothing"
        );

        rig.connected.store(false, Ordering::SeqCst);
        rig.wiring.tick_at(t0 + LINK_SETTLE * 6);
        rig.connected.store(true, Ordering::SeqCst);
        rig.wiring.tick_at(t0 + LINK_SETTLE * 7);
        assert_eq!(rig.wiring.tick_at(t0 + LINK_SETTLE * 8).len(), 1);
        assert_eq!(
            wait_for_probes(&rig, 2),
            2,
            "a reconnect is a new connection"
        );
    }

    #[test]
    fn the_stored_opt_in_is_off_until_the_user_turns_it_on() {
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::route_bindings::{
            BindingSource, RouteBindingsRepository, RoutePolicyRecord,
        };
        let runner = nrr_storage::SqliteMigrationRunner::for_state_db(
            rusqlite::Connection::open_in_memory().expect("in-memory state DB"),
        );
        runner.run_pending_migrations().expect("state migrations");
        let conn = Arc::new(Mutex::new(runner.into_connection()));
        let opted_in = stored_opt_in(Arc::clone(&conn));
        assert!(!opted_in(SID), "a user with no policy row has not opted in");

        let mut record = RoutePolicyRecord::empty(BindingSource::UserAssigned);
        {
            let guard = conn.lock().expect("lock");
            RouteBindingsRepository::new(&guard)
                .update_for_sid(SID, &record, 1)
                .expect("write");
        }
        assert!(!opted_in(SID), "the default policy leaves it off");

        record.external_address_auto_check = true;
        {
            let guard = conn.lock().expect("lock");
            RouteBindingsRepository::new(&guard)
                .update_for_sid(SID, &record, 2)
                .expect("write");
        }
        assert!(opted_in(SID));
        assert!(!opted_in("S-1-5-21-someone-else"), "the choice is per user");
    }

    #[test]
    fn a_bound_link_counts_only_while_it_is_up_with_an_address() {
        use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
        let tunnel = AdapterInfo {
            index: 9,
            adapter_name: "wg0".into(),
            description: String::new(),
            friendly_name: "wg0".into(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(10, 88, 1, 41)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        };
        let link = bound_secondary_link(SID, std::slice::from_ref(&tunnel), "wg0")
            .expect("an up tunnel with an address");
        assert_eq!(link.interface_index, 9);
        assert_eq!(link.source_ipv4, Ipv4Addr::new(10, 88, 1, 41));
        assert_eq!(link.adapter_name, "wg0");

        assert!(bound_secondary_link(SID, std::slice::from_ref(&tunnel), "tun1").is_none());
        let down = AdapterInfo {
            oper_status: IfOperStatus::Down,
            ..tunnel.clone()
        };
        assert!(bound_secondary_link(SID, &[down], "wg0").is_none());
        let bare = AdapterInfo {
            ipv4_addresses: Vec::new(),
            ..tunnel
        };
        assert!(bound_secondary_link(SID, &[bare], "wg0").is_none());
    }

    #[test]
    fn the_settle_window_fits_inside_the_quiet_period() {
        assert!(
            LINK_SETTLE < ANNOUNCE_MIN_INTERVAL,
            "a link must be able to settle and speak inside one quiet period"
        );
    }
}

//! Main-link resends and closes, folded to one outcome per connection.
//!
//! The stack reports every resent segment, and one loss burst on a busy
//! download resends several in the same millisecond. Counted per segment, that
//! made a working image host "not answer" before its first transfer finished.
//! A connection counts as stalled once, and only when the stack is still
//! resending a retransmission timeout after it started.

use std::collections::HashMap;
use std::net::SocketAddr;

use nrr_platform_api::conn_observe::ConnectionProgress;

/// Fast retransmits of one loss burst land within a round trip; a resend this
/// long after the first comes from a timeout. No working path has a one-second
/// round trip.
const TIMEOUT_RESEND_GAP_MS: u64 = 1_000;

/// Longer than the stack keeps resending before it abandons a connection, so an
/// entry idle this long is dead and a reused port starts clean.
const IDLE_TTL_MS: u64 = 120_000;

const MAX_CONNECTIONS: usize = 4096;

type ConnectionKey = (SocketAddr, SocketAddr);

#[derive(Debug, Clone, Copy)]
struct Resends {
    first_ms: u64,
    last_ms: u64,
    stalled: bool,
    /// Our own filter dropped it; its resends go into that filter.
    ours: bool,
    /// The stack reported this connection as established. Only then does its
    /// close say anything about the peer.
    established: bool,
}

impl Resends {
    fn started(at_ms: u64) -> Self {
        Self {
            first_ms: at_ms,
            last_ms: at_ms,
            stalled: false,
            ours: false,
            established: false,
        }
    }
}

#[derive(Debug)]
pub(super) struct ConnectionStallTracker {
    connections: HashMap<ConnectionKey, Resends>,
    cap: usize,
}

impl Default for ConnectionStallTracker {
    fn default() -> Self {
        Self {
            connections: HashMap::new(),
            cap: MAX_CONNECTIONS,
        }
    }
}

impl ConnectionStallTracker {
    /// `Some(true)` once per connection, when it is confirmed stalled;
    /// `Some(false)` for the close of a connection that was ESTABLISHED;
    /// `None` while a resend is not yet evidence, for an attempt, and for the
    /// close of a connection that never came up.
    ///
    /// That last case is why the attempt is recorded at all. A client that
    /// gives up on a destination which never answered closes its socket, and
    /// the stack reports that close like any other — read as an orderly close,
    /// it said "this host answers on the main link" about a host that had not
    /// answered at all, and silenced the offer to route it. Measured on the
    /// stand: `curl` exit 28 against a dead address produced one "completion".
    pub(super) fn note(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        progress: ConnectionProgress,
        at_ms: u64,
    ) -> Option<bool> {
        let key = (local, remote);
        match progress {
            ConnectionProgress::Attempt => {
                if !self.connections.contains_key(&key) {
                    self.make_room(at_ms);
                }
                let entry = self
                    .connections
                    .entry(key)
                    .or_insert_with(|| Resends::started(at_ms));
                if at_ms.saturating_sub(entry.last_ms) >= IDLE_TTL_MS {
                    *entry = Resends::started(at_ms);
                }
                entry.established = true;
                entry.last_ms = entry.last_ms.max(at_ms);
                None
            }
            ConnectionProgress::ClosedInOrder => {
                let entry = self.connections.remove(&key);
                let ours = entry.is_some_and(|r| r.ours);
                let established = entry.is_some_and(|r| r.established);
                (!ours && established).then_some(false)
            }
            ConnectionProgress::Retransmit => {
                if !self.connections.contains_key(&key) {
                    self.make_room(at_ms);
                }
                let entry = self
                    .connections
                    .entry(key)
                    .or_insert_with(|| Resends::started(at_ms));
                if at_ms.saturating_sub(entry.last_ms) >= IDLE_TTL_MS {
                    *entry = Resends::started(at_ms);
                }
                entry.last_ms = entry.last_ms.max(at_ms);
                if entry.ours
                    || entry.stalled
                    || at_ms.saturating_sub(entry.first_ms) < TIMEOUT_RESEND_GAP_MS
                {
                    return None;
                }
                entry.stalled = true;
                Some(true)
            }
        }
    }

    /// Marks a connection our own filter dropped: the stack resends into the
    /// filter, and those resends say nothing about the peer.
    pub(super) fn exclude(&mut self, local: SocketAddr, remote: SocketAddr, at_ms: u64) {
        let key = (local, remote);
        if !self.connections.contains_key(&key) {
            self.make_room(at_ms);
        }
        let entry = self
            .connections
            .entry(key)
            .or_insert_with(|| Resends::started(at_ms));
        entry.ours = true;
        entry.last_ms = entry.last_ms.max(at_ms);
    }

    /// Dead entries go first. Past that a suspect gives way before a confirmed
    /// stall or one of our own drops: forgetting a suspect only delays its
    /// verdict, forgetting the others would count a connection twice or blame
    /// the peer for our filter.
    fn make_room(&mut self, now_ms: u64) {
        if self.connections.len() < self.cap {
            return;
        }
        self.connections
            .retain(|_, r| now_ms.saturating_sub(r.last_ms) < IDLE_TTL_MS);
        while self.connections.len() >= self.cap {
            let Some(victim) = self
                .connections
                .iter()
                .min_by_key(|(_, r)| (r.stalled || r.ours, r.last_ms))
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.connections.remove(&victim);
        }
    }

    #[cfg(test)]
    fn with_cap(cap: usize) -> Self {
        Self {
            connections: HashMap::new(),
            cap: cap.max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn conn(local_port: u16) -> ConnectionKey {
        (
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), local_port)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 443)),
        )
    }

    fn resend(t: &mut ConnectionStallTracker, port: u16, at_ms: u64) -> Option<bool> {
        let (local, remote) = conn(port);
        t.note(local, remote, ConnectionProgress::Retransmit, at_ms)
    }

    fn attempt(t: &mut ConnectionStallTracker, port: u16, at_ms: u64) -> Option<bool> {
        let (local, remote) = conn(port);
        t.note(local, remote, ConnectionProgress::Attempt, at_ms)
    }

    fn close(t: &mut ConnectionStallTracker, port: u16, at_ms: u64) -> Option<bool> {
        let (local, remote) = conn(port);
        t.note(local, remote, ConnectionProgress::ClosedInOrder, at_ms)
    }

    #[test]
    fn resends_into_our_own_filter_are_never_a_stall() {
        let mut t = ConnectionStallTracker::default();
        let (local, remote) = conn(50000);
        t.exclude(local, remote, 0);
        assert_eq!(resend(&mut t, 50000, 0), None);
        assert_eq!(resend(&mut t, 50000, 3_000), None);
        assert_eq!(close(&mut t, 50000, 3_100), None);
        // Another connection to the same peer is judged on its own.
        assert_eq!(resend(&mut t, 50001, 0), None);
        assert_eq!(resend(&mut t, 50001, 3_000), Some(true));
    }

    #[test]
    fn a_loss_burst_on_a_working_connection_is_not_a_stall() {
        // The field shape: the connection comes up, three resends land in one
        // millisecond, then the transfer finishes.
        let mut t = ConnectionStallTracker::default();
        assert_eq!(attempt(&mut t, 50000, 999), None);
        for _ in 0..3 {
            assert_eq!(resend(&mut t, 50000, 1_000), None);
        }
        assert_eq!(resend(&mut t, 50000, 1_001), None);
        assert_eq!(close(&mut t, 50000, 1_021), Some(false));
    }

    #[test]
    fn one_burst_across_parallel_connections_is_not_a_stall() {
        let mut t = ConnectionStallTracker::default();
        for port in 50000..50006 {
            assert_eq!(resend(&mut t, port, 5_000), None);
            assert_eq!(resend(&mut t, port, 5_040), None);
        }
    }

    #[test]
    fn a_connection_still_resending_after_a_timeout_stalls_exactly_once() {
        // Backoff of a segment nobody acknowledges.
        let mut t = ConnectionStallTracker::default();
        assert_eq!(resend(&mut t, 50000, 0), None);
        assert_eq!(resend(&mut t, 50000, 300), None);
        assert_eq!(resend(&mut t, 50000, 900), None);
        assert_eq!(resend(&mut t, 50000, 2_100), Some(true));
        assert_eq!(resend(&mut t, 50000, 4_500), None);
        assert_eq!(resend(&mut t, 50000, 9_300), None);
    }

    #[test]
    fn an_orderly_close_is_a_completion_and_frees_the_tuple() {
        let mut t = ConnectionStallTracker::default();
        assert_eq!(attempt(&mut t, 50000, 0), None);
        assert_eq!(resend(&mut t, 50000, 0), None);
        assert_eq!(close(&mut t, 50000, 500), Some(false));
        // A new connection on the same tuple: its clock starts over.
        assert_eq!(resend(&mut t, 50000, 1_500), None);
        assert_eq!(resend(&mut t, 50000, 1_600), None);
    }

    #[test]
    fn a_close_without_resends_is_still_a_completion() {
        let mut t = ConnectionStallTracker::default();
        assert_eq!(attempt(&mut t, 50000, 0), None);
        assert_eq!(close(&mut t, 50000, 0), Some(false));
    }

    /// The case that made the establishment matter: a client gives up on a
    /// destination that never answered and closes its socket. Counted as a
    /// completion, that close said "this host answers on the main link" about a
    /// host that had answered nothing, and silenced the offer to route it.
    #[test]
    fn closing_a_connection_that_never_came_up_says_nothing() {
        let mut t = ConnectionStallTracker::default();
        assert_eq!(close(&mut t, 50000, 5_000), None);
        // Nor does one that only ever resent its handshake.
        assert_eq!(resend(&mut t, 50001, 0), None);
        assert_eq!(close(&mut t, 50001, 400), None);
    }

    #[test]
    fn a_tuple_reused_after_the_idle_window_starts_clean() {
        let mut t = ConnectionStallTracker::default();
        assert_eq!(resend(&mut t, 50000, 0), None);
        assert_eq!(resend(&mut t, 50000, IDLE_TTL_MS + 10), None);
        assert_eq!(resend(&mut t, 50000, IDLE_TTL_MS + 20), None);
    }

    #[test]
    fn a_clock_running_backwards_never_confirms() {
        let mut t = ConnectionStallTracker::default();
        assert_eq!(resend(&mut t, 50000, 5_000), None);
        assert_eq!(resend(&mut t, 50000, 1_000), None);
    }

    /// An attempt is not a verdict — but it IS remembered, because the close
    /// that follows means opposite things depending on whether it happened.
    #[test]
    fn attempts_are_not_evidence_but_are_remembered() {
        let mut t = ConnectionStallTracker::default();
        let (local, remote) = conn(50000);
        assert_eq!(t.note(local, remote, ConnectionProgress::Attempt, 0), None);
        assert_eq!(t.connections.len(), 1);
    }

    #[test]
    fn a_full_tracker_forgets_a_suspect_before_a_stall() {
        let mut t = ConnectionStallTracker::with_cap(2);
        assert_eq!(resend(&mut t, 1, 0), None);
        assert_eq!(resend(&mut t, 1, 1_000), Some(true));
        assert_eq!(resend(&mut t, 2, 1_100), None);
        // A third connection evicts the suspect, never the stall.
        assert_eq!(resend(&mut t, 3, 1_200), None);
        assert_eq!(t.connections.len(), 2);
        assert_eq!(resend(&mut t, 1, 3_000), None, "a stall is counted once");
        // The suspect's clock restarted, so this resend proves nothing yet;
        // remembered, it would have confirmed (1_100 -> 2_200).
        assert_eq!(resend(&mut t, 2, 2_200), None);
    }
}

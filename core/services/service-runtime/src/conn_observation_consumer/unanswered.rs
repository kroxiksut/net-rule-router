//! Connections the far side stopped answering, on any link.
//!
//! The stack backs off a retransmission timeout by doubling it, so a
//! connection nobody answers resends at growing intervals until the stack
//! gives up. A loss the peer recovers from looks different: one burst of fast
//! resends, or resends at a steady pace. Only the doubling counts here, which
//! keeps a lossy but working link out of the log.
//!
//! The verdict answers "did the network drop it, or did we": a connection our
//! own filter dropped is excluded, and every report names the program and the
//! link, so a user whose corporate tunnel dies can see it was not the router.

use std::collections::HashMap;
use std::net::SocketAddr;

use nrr_platform_api::conn_observe::egress::EgressRole;
use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionProgress, ConnectionVerdict, TransportProtocol,
};

/// Resends closer than this are one burst (fast retransmit, SACK recovery).
const BURST_MS: u64 = 200;
/// The first timeout resend follows the first resend within the initial RTO.
const FIRST_TIMEOUT_GAP_MAX_MS: u64 = 3_000;
/// A backed-off gap at least this many tenths of the one before. The stack
/// doubles; timestamps jitter.
const BACKOFF_MIN_TENTHS: u64 = 15;
const BACKOFF_MAX_TENTHS: u64 = 30;
/// Backed-off resends and silence before a connection counts as unanswered.
const MIN_TIMEOUT_RESENDS: u32 = 4;
const UNANSWERED_AFTER_MS: u64 = 8_000;
/// Longer than the stack keeps resending, so an entry idle this long is dead.
const IDLE_TTL_MS: u64 = 180_000;
const MAX_CONNECTIONS: usize = 4096;

/// Lines per window; a link going down takes every connection with it.
const MAX_LINES_PER_WINDOW: u32 = 20;
const LINE_WINDOW_MS: u64 = 60_000;

type ConnectionKey = (SocketAddr, SocketAddr);

/// One connection the far side stopped answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Silence {
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
    pub(super) program: Option<String>,
    pub(super) pid: u32,
    pub(super) role: EgressRole,
    pub(super) ifindex: u32,
    /// First resend of the episode, Unix ms.
    pub(super) since_ms: u64,
    pub(super) resends: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Still resending into silence.
    Unanswered(Silence),
    /// The stack closed a connection that was unanswered; `at_ms` is the close.
    Closed { silence: Silence, at_ms: u64 },
}

#[derive(Debug, Clone, Copy)]
struct Episode {
    first_ms: u64,
    last_ms: u64,
    last_gap_ms: u64,
    timeouts: u32,
    resends: u32,
}

impl Episode {
    fn started(at_ms: u64) -> Self {
        Self {
            first_ms: at_ms,
            last_ms: at_ms,
            last_gap_ms: 0,
            timeouts: 0,
            resends: 1,
        }
    }

    fn backs_off(&self, gap_ms: u64) -> bool {
        if self.last_gap_ms == 0 {
            gap_ms <= FIRST_TIMEOUT_GAP_MAX_MS
        } else {
            let gap = gap_ms.saturating_mul(10);
            gap >= self.last_gap_ms.saturating_mul(BACKOFF_MIN_TENTHS)
                && gap <= self.last_gap_ms.saturating_mul(BACKOFF_MAX_TENTHS)
        }
    }
}

#[derive(Debug)]
struct Entry {
    program: Option<String>,
    pid: u32,
    role: EgressRole,
    ifindex: u32,
    last_ms: u64,
    ours: bool,
    episode: Option<Episode>,
    reported: bool,
}

impl Entry {
    fn new(role: EgressRole, ifindex: u32, pid: u32, at_ms: u64) -> Self {
        Self {
            program: None,
            pid,
            role,
            ifindex,
            last_ms: at_ms,
            ours: false,
            episode: None,
            reported: false,
        }
    }

    fn silence(&self, key: ConnectionKey, episode: &Episode) -> Silence {
        Silence {
            local: key.0,
            remote: key.1,
            program: self.program.clone(),
            pid: self.pid,
            role: self.role,
            ifindex: self.ifindex,
            since_ms: episode.first_ms,
            resends: episode.resends,
        }
    }
}

/// What the caller knows about one observation of a connection.
#[derive(Debug, Clone, Copy)]
pub(super) struct Seen<'a> {
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
    pub(super) progress: ConnectionProgress,
    pub(super) role: EgressRole,
    pub(super) ifindex: u32,
    pub(super) pid: u32,
    /// Set on the establishment only; resends carry a pid alone.
    pub(super) program: Option<&'a str>,
    pub(super) at_ms: u64,
}

#[derive(Debug)]
pub(super) struct UnansweredTracker {
    connections: HashMap<ConnectionKey, Entry>,
    cap: usize,
    window_start_ms: u64,
    lines_in_window: u32,
    omitted_in_window: u32,
}

impl Default for UnansweredTracker {
    fn default() -> Self {
        Self::with_cap(MAX_CONNECTIONS)
    }
}

impl UnansweredTracker {
    fn with_cap(cap: usize) -> Self {
        Self {
            connections: HashMap::new(),
            cap: cap.max(1),
            window_start_ms: 0,
            lines_in_window: 0,
            omitted_in_window: 0,
        }
    }

    /// An established connection, a resend or a close. Returns at most one
    /// outcome per connection and state: unanswered once, closed once.
    pub(super) fn note(&mut self, seen: Seen<'_>) -> Option<Outcome> {
        let key = (seen.local, seen.remote);
        let at_ms = seen.at_ms;
        match seen.progress {
            ConnectionProgress::Attempt => {
                let entry = self.entry(key, seen);
                entry.program = seen.program.map(str::to_owned);
                entry.pid = seen.pid;
                None
            }
            ConnectionProgress::ClosedInOrder => {
                let entry = self.connections.remove(&key)?;
                let episode = entry.episode.filter(|_| entry.reported && !entry.ours)?;
                Some(Outcome::Closed {
                    silence: entry.silence(key, &episode),
                    at_ms,
                })
            }
            ConnectionProgress::Retransmit => {
                let entry = self.entry(key, seen);
                if entry.pid == 0 {
                    entry.pid = seen.pid;
                }
                if entry.ours {
                    return None;
                }
                let Some(episode) = entry.episode.as_mut() else {
                    entry.episode = Some(Episode::started(at_ms));
                    return None;
                };
                let gap_ms = at_ms.saturating_sub(episode.last_ms);
                if gap_ms < BURST_MS {
                    episode.last_ms = episode.last_ms.max(at_ms);
                    episode.resends += 1;
                    return None;
                }
                if !episode.backs_off(gap_ms) {
                    // Answered in between: a new loss, not the same silence.
                    *episode = Episode::started(at_ms);
                    entry.reported = false;
                    return None;
                }
                episode.timeouts += 1;
                episode.resends += 1;
                episode.last_gap_ms = gap_ms;
                episode.last_ms = at_ms;
                let unanswered = episode.timeouts >= MIN_TIMEOUT_RESENDS
                    && at_ms.saturating_sub(episode.first_ms) >= UNANSWERED_AFTER_MS;
                if !unanswered || entry.reported {
                    return None;
                }
                entry.reported = true;
                let episode = *episode;
                Some(Outcome::Unanswered(entry.silence(key, &episode)))
            }
        }
    }

    /// Our own filter dropped this connection: its resends go into that filter.
    pub(super) fn exclude(&mut self, local: SocketAddr, remote: SocketAddr, at_ms: u64) {
        let key = (local, remote);
        if !self.connections.contains_key(&key) {
            self.make_room(at_ms);
        }
        self.connections
            .entry(key)
            .or_insert_with(|| Entry::new(EgressRole::Unknown, 0, 0, at_ms))
            .ours = true;
    }

    /// Whether a line may be written now. On the first line of a new window,
    /// returns how many the previous window held back.
    pub(super) fn admit_line(&mut self, now_ms: u64) -> (bool, u32) {
        let mut omitted = 0;
        if now_ms.saturating_sub(self.window_start_ms) >= LINE_WINDOW_MS
            || now_ms < self.window_start_ms
        {
            omitted = std::mem::take(&mut self.omitted_in_window);
            self.window_start_ms = now_ms;
            self.lines_in_window = 0;
        }
        if self.lines_in_window >= MAX_LINES_PER_WINDOW {
            self.omitted_in_window += 1;
            return (false, omitted);
        }
        self.lines_in_window += 1;
        (true, omitted)
    }

    fn entry(&mut self, key: ConnectionKey, seen: Seen<'_>) -> &mut Entry {
        if !self.connections.contains_key(&key) {
            self.make_room(seen.at_ms);
        }
        let entry = self
            .connections
            .entry(key)
            .or_insert_with(|| Entry::new(seen.role, seen.ifindex, seen.pid, seen.at_ms));
        if seen.at_ms.saturating_sub(entry.last_ms) >= IDLE_TTL_MS && entry.episode.is_some() {
            entry.episode = None;
            entry.reported = false;
        }
        if seen.role != EgressRole::Unknown {
            entry.role = seen.role;
            entry.ifindex = seen.ifindex;
        }
        entry.last_ms = entry.last_ms.max(seen.at_ms);
        entry
    }

    /// Dead entries go first, then the quietest; a reported silence and our own
    /// drops outlive the rest so a close is still matched and never blamed on
    /// the peer.
    fn make_room(&mut self, now_ms: u64) {
        if self.connections.len() < self.cap {
            return;
        }
        self.connections
            .retain(|_, e| now_ms.saturating_sub(e.last_ms) < IDLE_TTL_MS);
        while self.connections.len() >= self.cap {
            let Some(victim) = self
                .connections
                .iter()
                .min_by_key(|(_, e)| (e.reported || e.ours, e.last_ms))
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.connections.remove(&victim);
        }
    }
}

impl super::ConnectionObservationConsumer {
    /// Feeds one observation to the unanswered-connection tracker and writes
    /// its verdict. Every link counts: the question is about the far side.
    // `pub(super)`: the impl is split across files.
    pub(super) fn note_unanswered(
        &self,
        obs: &ConnectionObservation,
        rec: &super::ConnectionTraceRecord,
        now_ms: u64,
    ) {
        if obs.protocol != TransportProtocol::Tcp
            || matches!(rec.egress.role, EgressRole::Loopback | EgressRole::Unknown)
        {
            return;
        }
        // A filter classify fires before the handshake and says nothing yet.
        if obs.progress == ConnectionProgress::Attempt && obs.verdict != ConnectionVerdict::Unknown
        {
            return;
        }
        let program = rec
            .process_path
            .as_deref()
            .map(nrr_domain::app_offer::program_name);
        let at_ms = obs.observed_unix_ms.unwrap_or(now_ms);
        let (outcome, admitted, omitted) = {
            let mut tracker = self.unanswered.lock().unwrap_or_else(|p| p.into_inner());
            let Some(outcome) = tracker.note(Seen {
                local: obs.local,
                remote: obs.remote,
                progress: obs.progress,
                role: rec.egress.role,
                ifindex: rec.egress.ifindex,
                pid: obs.pid,
                program: program.as_deref(),
                at_ms,
            }) else {
                return;
            };
            let (admitted, omitted) = tracker.admit_line(now_ms);
            (outcome, admitted, omitted)
        };
        if omitted > 0 {
            tracing::info!(
                target: "nrr::conn-trace",
                msg_key = "conn-unanswered-omitted",
                omitted,
                "more unanswered connections were seen in the last minute than are listed",
            );
        }
        if admitted {
            self.log_unanswered(&outcome, at_ms);
        }
    }

    fn log_unanswered(&self, outcome: &Outcome, at_ms: u64) {
        let silence = match outcome {
            Outcome::Unanswered(silence) | Outcome::Closed { silence, .. } => silence,
        };
        // Read only when a line is written, which the window caps.
        let adapter = self
            .api
            .get_adapter_infos()
            .ok()
            .and_then(|all| all.into_iter().find(|a| a.index == silence.ifindex))
            .map(|a| a.friendly_name)
            .unwrap_or_default();
        let program = silence.program.as_deref().unwrap_or("?");
        let link = super::role_str(silence.role);
        let silent_s = at_ms.saturating_sub(silence.since_ms) / 1_000;
        match outcome {
            Outcome::Unanswered(_) => tracing::info!(
                target: "nrr::conn-trace",
                msg_key = "conn-unanswered",
                program,
                pid = silence.pid,
                link,
                ifindex = silence.ifindex,
                adapter = adapter.as_str(),
                remote = %silence.remote,
                local_port = silence.local.port(),
                silent_s,
                resends = silence.resends,
                "the far side stopped answering a connection; NetRuleRouter did not block it",
            ),
            Outcome::Closed { .. } => tracing::info!(
                target: "nrr::conn-trace",
                msg_key = "conn-unanswered-closed",
                program,
                pid = silence.pid,
                link,
                ifindex = silence.ifindex,
                adapter = adapter.as_str(),
                remote = %silence.remote,
                local_port = silence.local.port(),
                silent_s,
                "the stack closed a connection the far side had stopped answering",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const IFINDEX: u32 = 19;

    fn key(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 25)), 443),
        )
    }

    fn seen(port: u16, progress: ConnectionProgress, at_ms: u64) -> Seen<'static> {
        let (local, remote) = key(port);
        Seen {
            local,
            remote,
            progress,
            role: EgressRole::Other,
            ifindex: IFINDEX,
            pid: 4242,
            program: (progress == ConnectionProgress::Attempt).then_some("client.exe"),
            at_ms,
        }
    }

    fn established(t: &mut UnansweredTracker, port: u16, at_ms: u64) {
        assert_eq!(t.note(seen(port, ConnectionProgress::Attempt, at_ms)), None);
    }

    fn resends(t: &mut UnansweredTracker, port: u16, times: &[u64]) -> Vec<Outcome> {
        times
            .iter()
            .filter_map(|&at| t.note(seen(port, ConnectionProgress::Retransmit, at)))
            .collect()
    }

    /// Resend times of a stack doubling a 300 ms timeout from `start`.
    fn backoff_from(start: u64, count: usize) -> Vec<u64> {
        let mut at = start;
        let mut gap = 300;
        let mut out = vec![at];
        for _ in 1..count {
            at += gap;
            gap *= 2;
            out.push(at);
        }
        out
    }

    #[test]
    fn a_connection_resending_into_silence_is_reported_once_with_its_program() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        let out = resends(&mut t, 50_000, &backoff_from(1_000, 8));
        assert_eq!(out.len(), 1, "{out:?}");
        let Outcome::Unanswered(silence) = &out[0] else {
            panic!("expected unanswered, got {out:?}");
        };
        assert_eq!(silence.program.as_deref(), Some("client.exe"));
        assert_eq!(silence.role, EgressRole::Other);
        assert_eq!(silence.ifindex, IFINDEX);
        assert_eq!(silence.since_ms, 1_000);
    }

    #[test]
    fn the_close_of_an_unanswered_connection_is_reported_and_frees_it() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        resends(&mut t, 50_000, &backoff_from(1_000, 8));
        let closed = t.note(seen(50_000, ConnectionProgress::ClosedInOrder, 60_000));
        assert!(
            matches!(&closed, Some(Outcome::Closed { at_ms: 60_000, silence }) if silence.since_ms == 1_000),
            "{closed:?}"
        );
        assert!(t.connections.is_empty());
    }

    #[test]
    fn a_loss_the_peer_recovers_from_is_never_reported() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        // Two timeouts, then answered; the next loss starts afresh.
        assert!(resends(&mut t, 50_000, &[1_000, 1_300, 1_900]).is_empty());
        assert!(resends(&mut t, 50_000, &[30_000, 30_300, 30_900]).is_empty());
        assert_eq!(
            t.note(seen(50_000, ConnectionProgress::ClosedInOrder, 40_000)),
            None
        );
    }

    #[test]
    fn steady_resends_on_a_lossy_working_link_are_never_reported() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        let steady: Vec<u64> = (0..60).map(|i| 1_000 + i * 400).collect();
        assert!(resends(&mut t, 50_000, &steady).is_empty());
    }

    #[test]
    fn a_fast_retransmit_burst_is_one_resend() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        let burst: Vec<u64> = (0..50).map(|i| 1_000 + i * 2).collect();
        assert!(resends(&mut t, 50_000, &burst).is_empty());
    }

    #[test]
    fn a_short_silence_is_not_yet_unanswered() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 0);
        assert!(resends(&mut t, 50_000, &backoff_from(1_000, 4)).is_empty());
    }

    #[test]
    fn resends_into_our_own_filter_are_never_reported() {
        let mut t = UnansweredTracker::default();
        let (local, remote) = key(50_000);
        established(&mut t, 50_000, 0);
        t.exclude(local, remote, 500);
        assert!(resends(&mut t, 50_000, &backoff_from(1_000, 10)).is_empty());
        assert_eq!(
            t.note(seen(50_000, ConnectionProgress::ClosedInOrder, 90_000)),
            None
        );
    }

    #[test]
    fn a_connection_seen_only_by_its_resends_is_reported_without_a_program() {
        let mut t = UnansweredTracker::default();
        let out = resends(&mut t, 50_000, &backoff_from(1_000, 8));
        assert!(
            matches!(&out[..], [Outcome::Unanswered(s)] if s.program.is_none() && s.pid == 4242),
            "{out:?}"
        );
    }

    #[test]
    fn a_full_tracker_keeps_a_reported_silence_over_a_quiet_connection() {
        let mut t = UnansweredTracker::with_cap(2);
        established(&mut t, 50_000, 0);
        resends(&mut t, 50_000, &backoff_from(1_000, 8));
        established(&mut t, 50_001, 100_000);
        established(&mut t, 50_002, 100_001);
        assert!(t.connections.contains_key(&key(50_000)));
        assert!(!t.connections.contains_key(&key(50_001)));
    }

    #[test]
    fn lines_past_the_window_cap_are_held_back_and_counted_once() {
        let mut t = UnansweredTracker::default();
        for _ in 0..MAX_LINES_PER_WINDOW {
            assert_eq!(t.admit_line(1_000), (true, 0));
        }
        assert_eq!(t.admit_line(2_000), (false, 0));
        assert_eq!(t.admit_line(3_000), (false, 0));
        assert_eq!(t.admit_line(1_000 + LINE_WINDOW_MS), (true, 2));
        assert_eq!(t.admit_line(1_001 + LINE_WINDOW_MS), (true, 0));
    }

    #[test]
    fn a_clock_running_backwards_never_reports() {
        let mut t = UnansweredTracker::default();
        established(&mut t, 50_000, 100_000);
        assert!(resends(&mut t, 50_000, &[100_000, 90_000, 80_000, 70_000, 60_000]).is_empty());
    }
}

//! Which upstream DNS server the loopback resolver forwards to.
//!
//! Mode B puts our listener in front of every name query on the machine, so the
//! upstream it forwards to is a single point of failure: pick a server that does
//! not answer and name resolution stops working machine-wide, with nothing in
//! the UI to explain it. Enumeration is per-OS ([`SystemDnsServersPort`]);
//! choosing among the candidates is policy and lives here — probe before
//! committing, rotate when the active one stops answering, re-enumerate when the
//! network changes.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};

/// Standard DNS port; the OS never reports a port with its server list.
const DNS_PORT: u16 = 53;

/// Consecutive forward failures that retire the active server. One lost
/// datagram is ordinary UDP; three in a row on a link that is otherwise up is
/// the server, not the network.
const FAILURES_BEFORE_ROTATE: u32 = 3;

/// Floor between re-enumerations. Enumerating shells out to the OS, and a burst
/// of failures (or a flapping link) would otherwise hammer it.
const MIN_REFRESH_GAP: Duration = Duration::from_secs(10);

/// Name used to probe a candidate. Reserved by RFC 2606, answered by every
/// recursive resolver, owned by nobody — and the probe accepts ANY well-formed
/// reply (NXDOMAIN and REFUSED included), so what is being tested is reachability
/// of the server, never the health of the wider internet.
const PROBE_NAME: &str = "example.com";

/// Probe budget. Short: this runs while the resolver is arming, and a candidate
/// that needs longer than this is not the one to put in front of every query.
const PROBE_TIMEOUT: Duration = Duration::from_millis(700);

/// Answers "does this server reply at all". Behind a trait so the pool's
/// rotation logic is unit-tested without sockets.
pub trait UpstreamProbe: Send + Sync {
    fn responds(&self, server: SocketAddr) -> bool;
}

/// Production probe: one `A` query, any well-formed reply counts.
pub struct UdpUpstreamProbe {
    timeout: Duration,
}

impl Default for UdpUpstreamProbe {
    fn default() -> Self {
        Self {
            timeout: PROBE_TIMEOUT,
        }
    }
}

impl UpstreamProbe for UdpUpstreamProbe {
    fn responds(&self, server: SocketAddr) -> bool {
        static PROBE_ID: AtomicU32 = AtomicU32::new(0x5100);
        let id = PROBE_ID.fetch_add(1, Ordering::Relaxed) as u16;
        let Some(query) = crate::dns_wire::build_a_query(id, PROBE_NAME) else {
            return false;
        };
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            return false;
        };
        if sock.set_read_timeout(Some(self.timeout)).is_err()
            || sock.send_to(&query, server).is_err()
        {
            return false;
        }
        let mut buf = [0u8; 512];
        let Ok(n) = sock.recv(&mut buf) else {
            return false;
        };
        // Only the id has to match: an NXDOMAIN or REFUSED proves the server is
        // there, which is the whole question.
        n >= crate::dns_wire::DNS_HEADER_LEN && u16::from_be_bytes([buf[0], buf[1]]) == id
    }
}

/// Accepts every candidate. For tests and for callers that deliberately skip
/// probing.
pub struct AcceptingProbe;

impl UpstreamProbe for AcceptingProbe {
    fn responds(&self, _server: SocketAddr) -> bool {
        true
    }
}

/// Names the interface whose resolver should be preferred — the link the
/// routing policy actually sends traffic over. `None` while nothing is bound or
/// resolvable, which simply leaves the OS enumeration order in charge.
pub type PreferredInterfaceFn = Arc<dyn Fn() -> Option<u32> + Send + Sync>;

struct PoolState {
    /// Candidates in preference order, as last enumerated.
    candidates: Vec<UpstreamDnsCandidate>,
    /// The server currently being forwarded to.
    active: Option<Ipv4Addr>,
    /// Consecutive failures reported against `active`.
    failures: u32,
    last_refresh: Option<Instant>,
}

/// The live choice of upstream DNS server.
///
/// Cloneable handle semantics: wrap in `Arc` and share — every consumer sees the
/// same active server, and a rotation triggered by one is immediately visible to
/// the others.
pub struct UpstreamDnsPool {
    servers: Arc<dyn SystemDnsServersPort>,
    probe: Arc<dyn UpstreamProbe>,
    preferred_interface: OnceLock<PreferredInterfaceFn>,
    state: Mutex<PoolState>,
}

impl UpstreamDnsPool {
    pub fn new(servers: Arc<dyn SystemDnsServersPort>, probe: Arc<dyn UpstreamProbe>) -> Self {
        Self {
            servers,
            probe,
            preferred_interface: OnceLock::new(),
            state: Mutex::new(PoolState {
                candidates: Vec::new(),
                active: None,
                failures: 0,
                last_refresh: None,
            }),
        }
    }

    /// Prefer the resolver of the interface this returns.
    ///
    /// Reachability alone picks the wrong server when the machine's default
    /// route belongs to a link the policy does not use: that link's resolver
    /// answers for the internet but knows nothing of the bound link's internal
    /// names, and the traffic itself still leaves over the bound link. The
    /// preference only reorders — an unreachable preferred server is still
    /// passed over.
    pub fn with_preferred_interface(self, preferred: PreferredInterfaceFn) -> Self {
        self.set_preferred_interface(preferred);
        self
    }

    /// Same, for the shared pool: it is built before the routing coordinator
    /// that answers the question exists. First writer wins.
    pub fn set_preferred_interface(&self, preferred: PreferredInterfaceFn) {
        let _ = self.preferred_interface.set(preferred);
    }

    /// A pool pinned to one server, with no enumeration and no probing. The
    /// shape callers use when the upstream is dictated rather than discovered
    /// (tests, and any caller handed an explicit address).
    pub fn fixed(server: SocketAddr) -> Self {
        let ip = match server {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };
        Self {
            servers: Arc::new(nrr_platform_api::dns::StaticDnsServers::new(vec![ip])),
            probe: Arc::new(AcceptingProbe),
            preferred_interface: OnceLock::new(),
            state: Mutex::new(PoolState {
                candidates: vec![UpstreamDnsCandidate::new(None, ip)],
                active: Some(ip),
                failures: 0,
                last_refresh: Some(Instant::now()),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The server to forward to right now, or `None` while no candidate has been
    /// found to answer. `None` means "do not redirect": leaving the OS resolver
    /// alone beats pointing it at a black hole.
    pub fn current(&self) -> Option<SocketAddr> {
        self.lock()
            .active
            .map(|ip| SocketAddr::from((ip, DNS_PORT)))
    }

    /// A forward succeeded — the active server is good.
    pub fn note_success(&self) {
        self.lock().failures = 0;
    }

    /// A forward failed. Returns the replacement once the failure streak retires
    /// the active server, so the caller can retry the same query immediately
    /// instead of making the client wait for its own timeout.
    pub fn note_failure(&self) -> Option<SocketAddr> {
        {
            let mut state = self.lock();
            state.failures = state.failures.saturating_add(1);
            if state.failures < FAILURES_BEFORE_ROTATE {
                return None;
            }
        }
        let retired = self.lock().active;
        let replacement = self.reselect(retired);
        if replacement != retired {
            tracing::warn!(
                target: "nrr::dns-resolver",
                retired = ?retired,
                active = ?replacement,
                "upstream DNS stopped answering — switched to another server",
            );
        }
        replacement
            .filter(|ip| Some(*ip) != retired)
            .map(|ip| SocketAddr::from((ip, DNS_PORT)))
    }

    /// Re-enumerate and re-probe now, regardless of the failure streak. Called
    /// when arming and whenever the OS reports a network change — a new link
    /// usually means a new resolver, and the old one may still answer while
    /// pointing at the wrong network.
    pub fn refresh(&self) -> Option<SocketAddr> {
        let previous = self.lock().active;
        {
            let mut state = self.lock();
            state.last_refresh = None; // an explicit refresh ignores the floor
        }
        let selected = self.reselect(None);
        if selected != previous {
            tracing::info!(
                target: "nrr::dns-resolver",
                previous = ?previous,
                active = ?selected,
                "upstream DNS re-selected after a network change",
            );
        }
        selected.map(|ip| SocketAddr::from((ip, DNS_PORT)))
    }

    /// The OS reported a network change. Re-selects at most once per
    /// [`MIN_REFRESH_GAP`] — this is called from the adapter hook, which fires
    /// on every interface flap, and re-selection shells out to the OS.
    pub fn note_network_change(&self) -> Option<SocketAddr> {
        let due = {
            let state = self.lock();
            state
                .last_refresh
                .is_none_or(|at| at.elapsed() >= MIN_REFRESH_GAP)
        };
        if !due {
            return self.current();
        }
        self.refresh()
    }

    /// Pick the first candidate that answers, preferring anything over `avoid`.
    /// Re-enumerates from the OS when the candidate list is stale.
    fn reselect(&self, avoid: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let stale = {
            let state = self.lock();
            state
                .last_refresh
                .is_none_or(|at| at.elapsed() >= MIN_REFRESH_GAP)
        };
        if stale {
            let fresh = self.servers.upstream_candidates_v4();
            let mut state = self.lock();
            state.last_refresh = Some(Instant::now());
            if !fresh.is_empty() {
                state.candidates = fresh;
            }
        }
        let candidates = self.lock().candidates.clone();
        // Preferred interface first, then everything else, and the server we are
        // trying to move off of last.
        let preferred = self.preferred_interface.get().and_then(|resolve| resolve());
        let on_preferred =
            |c: &UpstreamDnsCandidate| preferred.is_some() && c.interface_index == preferred;
        let mut ordered: Vec<&UpstreamDnsCandidate> = Vec::with_capacity(candidates.len());
        ordered.extend(
            candidates
                .iter()
                .filter(|c| Some(c.server) != avoid && on_preferred(c)),
        );
        ordered.extend(
            candidates
                .iter()
                .filter(|c| Some(c.server) != avoid && !on_preferred(c)),
        );
        ordered.extend(candidates.iter().filter(|c| Some(c.server) == avoid));
        for ip in ordered.into_iter().map(|c| c.server) {
            if self.probe.responds(SocketAddr::from((ip, DNS_PORT))) {
                let mut state = self.lock();
                state.active = Some(ip);
                state.failures = 0;
                return Some(ip);
            }
        }
        // Nothing answered. Keep the previous choice rather than blanking it:
        // a machine that is briefly offline has no better server to offer, and
        // dropping the redirect mid-session would be the louder failure.
        self.lock().active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::dns::{StaticDnsServers, UpstreamDnsCandidate};
    use std::sync::atomic::AtomicUsize;

    /// Probe answering only for an allow-list, counting calls.
    struct ScriptedProbe {
        alive: Mutex<Vec<Ipv4Addr>>,
        calls: AtomicUsize,
    }

    impl ScriptedProbe {
        fn new(alive: Vec<Ipv4Addr>) -> Arc<Self> {
            Arc::new(Self {
                alive: Mutex::new(alive),
                calls: AtomicUsize::new(0),
            })
        }

        fn set_alive(&self, alive: Vec<Ipv4Addr>) {
            *self.alive.lock().unwrap_or_else(|p| p.into_inner()) = alive;
        }
    }

    impl UpstreamProbe for ScriptedProbe {
        fn responds(&self, server: SocketAddr) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let SocketAddr::V4(v4) = server else {
                return false;
            };
            self.alive
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(v4.ip())
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, last, 1)
    }

    fn pool(candidates: Vec<Ipv4Addr>, probe: Arc<ScriptedProbe>) -> UpstreamDnsPool {
        UpstreamDnsPool::new(Arc::new(StaticDnsServers::new(candidates)), probe)
    }

    #[test]
    fn a_dead_preferred_server_is_skipped_for_one_that_answers() {
        // The boot bug: the disconnected adapter's DNS is enumerated first.
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(1), ip(0)], Arc::clone(&probe));
        assert_eq!(
            pool.refresh(),
            Some(SocketAddr::from((ip(0), 53))),
            "the server that answers must win over the one merely listed first"
        );
    }

    #[test]
    fn the_bound_links_resolver_wins_over_the_one_that_merely_owns_the_default_route() {
        // Both answer, and the default-route link is enumerated first — but the
        // policy sends traffic over the bound link, and only its resolver knows
        // that network's internal names.
        let probe = ScriptedProbe::new(vec![ip(0), ip(1)]);
        let servers = StaticDnsServers::with_interfaces(vec![
            UpstreamDnsCandidate::new(Some(11), ip(1)),
            UpstreamDnsCandidate::new(Some(17), ip(0)),
        ]);
        let pool = UpstreamDnsPool::new(Arc::new(servers), probe)
            .with_preferred_interface(Arc::new(|| Some(17)));
        assert_eq!(pool.refresh(), Some(SocketAddr::from((ip(0), 53))));
    }

    #[test]
    fn a_preferred_interface_that_does_not_answer_is_still_passed_over() {
        let probe = ScriptedProbe::new(vec![ip(1)]);
        let servers = StaticDnsServers::with_interfaces(vec![
            UpstreamDnsCandidate::new(Some(11), ip(1)),
            UpstreamDnsCandidate::new(Some(17), ip(0)),
        ]);
        let pool = UpstreamDnsPool::new(Arc::new(servers), probe)
            .with_preferred_interface(Arc::new(|| Some(17)));
        assert_eq!(
            pool.refresh(),
            Some(SocketAddr::from((ip(1), 53))),
            "preference reorders, it never overrides reachability"
        );
    }

    #[test]
    fn no_candidate_answering_yields_no_upstream() {
        let probe = ScriptedProbe::new(vec![]);
        let pool = pool(vec![ip(1)], Arc::clone(&probe));
        assert_eq!(pool.refresh(), None);
        assert_eq!(pool.current(), None, "never commit to an unprobed server");
    }

    #[test]
    fn rotation_needs_a_streak_and_then_moves_off_the_dead_server() {
        let probe = ScriptedProbe::new(vec![ip(0), ip(2)]);
        let pool = pool(vec![ip(0), ip(2)], Arc::clone(&probe));
        assert_eq!(pool.refresh(), Some(SocketAddr::from((ip(0), 53))));

        probe.set_alive(vec![ip(2)]); // the active server goes away
        for _ in 1..FAILURES_BEFORE_ROTATE {
            assert_eq!(pool.note_failure(), None, "a short streak must not rotate");
        }
        assert_eq!(
            pool.note_failure(),
            Some(SocketAddr::from((ip(2), 53))),
            "the streak retires the active server and hands back the replacement"
        );
        assert_eq!(pool.current(), Some(SocketAddr::from((ip(2), 53))));
    }

    #[test]
    fn a_success_clears_the_streak() {
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        pool.refresh();
        pool.note_failure();
        pool.note_failure();
        pool.note_success();
        assert_eq!(
            pool.note_failure(),
            None,
            "failures must be consecutive to count"
        );
    }

    #[test]
    fn the_last_good_server_is_kept_when_everything_stops_answering() {
        let probe = ScriptedProbe::new(vec![ip(0)]);
        let pool = pool(vec![ip(0)], Arc::clone(&probe));
        pool.refresh();
        probe.set_alive(vec![]);
        pool.refresh();
        assert_eq!(
            pool.current(),
            Some(SocketAddr::from((ip(0), 53))),
            "a brief outage must not blank the upstream mid-session"
        );
    }
}

//! "Does this address answer over THIS link?" — asked directly.
//!
//! The passive verdict ([`nrr_domain::companion_affinity::PrimaryBehavior`]) is
//! built from traffic that happened to occur. With the additional route down
//! there is no such traffic to learn from, so every suggestion stays
//! unexamined — and the user is asked to decide with no evidence at all. This
//! module answers the question on demand instead.
//!
//! Which link is asked about is the caller's choice: the probe binds the
//! source address it is given, so the same mechanism answers "does the main
//! link reach it" and "would the tunnel reach it". The names here stay neutral
//! for that reason — an offer to move a host into the tunnel is worth nothing
//! until somebody has checked that the tunnel can carry it.
//!
//! Two things it deliberately is NOT:
//!
//! - **not a judgement about the site.** A connection that completes proves the
//!   packet arrives, nothing more: a service can answer a main-link address with
//!   a refusal (an assistant service does exactly that). The verdict feeds the same
//!   `PrimaryHealthEvent` channel the observed traffic feeds, and the wording in
//!   the GUI stays a statement of connectivity.
//! - **not on the data path.** It runs when the user asks (or on their opt-in),
//!   from its own thread, bounded in count and time.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What one probe established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathVerdict {
    /// The address accepted a connection over the link that was asked about.
    Answered,
    /// It definitely did not: refused, or silent past the timeout.
    Silent,
    /// The probe could not be carried out (no source address, socket refused to
    /// open). Reported as its own outcome — guessing either way would put a
    /// verdict on the screen that nothing measured.
    Indeterminate,
}

/// The mechanism: one bounded TCP connect attempt, optionally from a chosen
/// source address, which is what decides the link the packet leaves by.
pub trait PathProbe: Send + Sync {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict;

    /// A connection to `target:443`, then a ClientHello naming `server_name`.
    /// `Answered` only when a TLS record comes back: a path that lets TCP
    /// through and silences or resets the hello by name is `Silent` — exactly
    /// what [`Self::probe`] reports as reachable. A mechanism without it cannot
    /// tell.
    fn probe_tls(
        &self,
        _target: Ipv4Addr,
        _server_name: &str,
        _source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PathVerdict {
        PathVerdict::Indeterminate
    }
}

/// The ClientHello exchange over an already connected `stream`, each read and
/// write bounded by `timeout`.
pub fn tls_exchange(
    stream: &mut std::net::TcpStream,
    server_name: &str,
    timeout: Duration,
) -> PathVerdict {
    use std::io::{Read, Write};

    let mut fresh = [[0u8; 32]; 3];
    if fresh.iter_mut().any(|b| getrandom::fill(b).is_err()) {
        return PathVerdict::Indeterminate;
    }
    let Some(hello) = crate::tls_hello::client_hello(server_name, &fresh[0], &fresh[1], &fresh[2])
    else {
        return PathVerdict::Indeterminate;
    };
    if timeout.is_zero()
        || stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return PathVerdict::Indeterminate;
    }
    if let Err(e) = stream.write_all(&hello) {
        return verdict_of_io_error(e.kind());
    }
    let mut header = [0u8; 5];
    let mut got = 0;
    loop {
        match stream.read(&mut header[got..]) {
            // Closed after the hello: the reset-by-name case, seen as EOF.
            Ok(0) => return PathVerdict::Silent,
            Ok(n) => {
                got += n;
                if let Some(answer) = crate::tls_hello::classify_first_record(&header[..got]) {
                    return match answer {
                        crate::tls_hello::TlsAnswer::Handshake
                        | crate::tls_hello::TlsAnswer::Alert => PathVerdict::Answered,
                        // Something on the path answered in the server's place.
                        crate::tls_hello::TlsAnswer::NotTls => PathVerdict::Silent,
                    };
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return verdict_of_io_error(e.kind()),
        }
    }
}

/// Only a refusal, a reset or a timeout is evidence the host did not answer;
/// anything else means nothing was measured.
fn verdict_of_io_error(kind: std::io::ErrorKind) -> PathVerdict {
    match kind {
        std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::WouldBlock
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::BrokenPipe
        | std::io::ErrorKind::UnexpectedEof => PathVerdict::Silent,
        _ => PathVerdict::Indeterminate,
    }
}

/// Production probe. A refused connection counts as `Silent`: for this question
/// "the main link cannot get me there" and "there is nothing listening" are the
/// same answer, and both mean the user's site will not load that way.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPathProbe;

impl SystemPathProbe {
    /// A connected socket from `source` (when given), or the verdict that ends
    /// the probe here.
    fn connect(
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> Result<socket2::Socket, PathVerdict> {
        let address = std::net::SocketAddr::from((target, port));
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .map_err(|_| PathVerdict::Indeterminate)?;
        nrr_platform_api::own_traffic::mark_own_socket(&socket);
        if let Some(source) = source {
            // Binding is what decides the link. Without it the OS would pick by
            // route — and the pinned destination's route points at the tunnel,
            // which is the opposite of the question being asked.
            socket
                .bind(&std::net::SocketAddr::from((source, 0)).into())
                .map_err(|_| PathVerdict::Indeterminate)?;
        }
        // A zero budget cannot measure anything, and the platform reports the
        // attempt as a timeout — indistinguishable from a host that stayed
        // silent, which is evidence the block-detector acts on.
        if timeout.is_zero() {
            return Err(PathVerdict::Indeterminate);
        }
        socket
            .connect_timeout(&address.into(), timeout)
            .map_err(|e| verdict_of_io_error(e.kind()))?;
        Ok(socket)
    }
}

impl PathProbe for SystemPathProbe {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict {
        match Self::connect(target, port, source, timeout) {
            Ok(_) => PathVerdict::Answered,
            Err(verdict) => verdict,
        }
    }

    fn probe_tls(
        &self,
        target: Ipv4Addr,
        server_name: &str,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict {
        match Self::connect(target, 443, source, timeout) {
            Ok(socket) => tls_exchange(&mut socket.into(), server_name, timeout),
            Err(verdict) => verdict,
        }
    }
}

/// Test double returning a scripted verdict and counting attempts.
#[derive(Debug)]
pub struct MockPathProbe {
    verdict: PathVerdict,
    attempts: Mutex<Vec<(Ipv4Addr, u16, Option<Ipv4Addr>)>>,
}

impl MockPathProbe {
    pub fn new(verdict: PathVerdict) -> Self {
        Self {
            verdict,
            attempts: Mutex::new(Vec::new()),
        }
    }

    pub fn attempts(&self) -> Vec<(Ipv4Addr, u16, Option<Ipv4Addr>)> {
        self.attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl PathProbe for MockPathProbe {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PathVerdict {
        self.attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((target, port, source));
        self.verdict
    }

    fn probe_tls(
        &self,
        target: Ipv4Addr,
        _server_name: &str,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PathVerdict {
        self.probe(target, 443, source, timeout)
    }
}

// ── Limits ───────────────────────────────────────────────────────────────────

/// What bounds one probing pass. Every value is clamped on the way in, so a
/// stored row from another build — or a hand-edited one — cannot ask the service
/// for an unbounded sweep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeLimits {
    pub timeout: Duration,
    pub max_targets: usize,
    /// How long a verdict for one host is trusted before probing it again.
    pub repeat_after: Duration,
}

impl ProbeLimits {
    pub const TIMEOUT_RANGE: (Duration, Duration) =
        (Duration::from_millis(300), Duration::from_secs(5));
    pub const MAX_TARGETS_RANGE: (usize, usize) = (1, 32);
    pub const REPEAT_AFTER_RANGE: (Duration, Duration) =
        (Duration::from_secs(30), Duration::from_secs(24 * 3600));

    /// Clamped construction — the only way to build one.
    pub fn new(timeout: Duration, max_targets: usize, repeat_after: Duration) -> Self {
        Self {
            timeout: timeout.clamp(Self::TIMEOUT_RANGE.0, Self::TIMEOUT_RANGE.1),
            max_targets: max_targets.clamp(Self::MAX_TARGETS_RANGE.0, Self::MAX_TARGETS_RANGE.1),
            repeat_after: repeat_after
                .clamp(Self::REPEAT_AFTER_RANGE.0, Self::REPEAT_AFTER_RANGE.1),
        }
    }
}

impl Default for ProbeLimits {
    /// A pass a person waits through: eight addresses at 1.5 s worst case, and
    /// one answer per host per five minutes.
    fn default() -> Self {
        Self::new(Duration::from_millis(1500), 8, Duration::from_secs(300))
    }
}

// ── The pass ─────────────────────────────────────────────────────────────────

/// One host to examine and the addresses it is known by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeTarget {
    pub hostname: String,
    pub addresses: Vec<Ipv4Addr>,
}

/// Result of one pass, for the log and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbePassSummary {
    pub answered: u32,
    pub silent: u32,
    pub indeterminate: u32,
    /// Hosts skipped because a recent verdict already covers them.
    pub skipped_recent: u32,
    /// Hosts skipped because the pass hit [`ProbeLimits::max_targets`].
    pub skipped_over_limit: u32,
}

/// Runs bounded probing passes and remembers when each host was last examined.
///
/// The verdict is reported through a caller-supplied sink — in production the
/// auto-rules engine's `note_primary_health`, which is the same channel the
/// observed traffic uses. One channel means the GUI has one story to tell,
/// whether the evidence arrived by itself or was asked for.
pub struct PathProber {
    probe: Arc<dyn PathProbe>,
    last_probed: Mutex<std::collections::HashMap<String, Instant>>,
}

/// `(hostname, answered)` — `answered == false` means definitely silent.
/// Indeterminate outcomes are never reported: they are not evidence.
pub type ProbeVerdictSink = dyn Fn(&str, bool) + Send + Sync;

impl PathProber {
    pub fn new(probe: Arc<dyn PathProbe>) -> Self {
        Self {
            probe,
            last_probed: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// A prober over the same mechanism with a repeat memory of its own.
    #[must_use]
    pub fn sibling(&self) -> Self {
        Self::new(Arc::clone(&self.probe))
    }

    /// Probe `targets` on port `port` from `source`, respecting `limits`.
    ///
    /// One address per host is enough to answer "does the main link get there":
    /// a host whose first address answers is reachable, and walking the rest
    /// would multiply the wait for no extra information. A host is retried on
    /// its NEXT address only while the outcome is indeterminate.
    pub fn run_pass(
        &self,
        targets: &[ProbeTarget],
        port: u16,
        source: Option<Ipv4Addr>,
        limits: ProbeLimits,
        now: Instant,
        report: &ProbeVerdictSink,
    ) -> ProbePassSummary {
        let mut summary = ProbePassSummary::default();
        let mut examined = 0usize;
        for target in targets {
            if target.hostname.is_empty() || target.addresses.is_empty() {
                continue;
            }
            if self.recently_probed(&target.hostname, limits.repeat_after, now) {
                summary.skipped_recent += 1;
                continue;
            }
            if examined >= limits.max_targets {
                summary.skipped_over_limit += 1;
                continue;
            }
            examined += 1;
            let mut verdict = PathVerdict::Indeterminate;
            for address in &target.addresses {
                verdict = self.probe.probe(*address, port, source, limits.timeout);
                if verdict != PathVerdict::Indeterminate {
                    break;
                }
            }
            match verdict {
                PathVerdict::Answered => {
                    summary.answered += 1;
                    self.mark_probed(&target.hostname, now);
                    report(&target.hostname, true);
                }
                PathVerdict::Silent => {
                    summary.silent += 1;
                    self.mark_probed(&target.hostname, now);
                    report(&target.hostname, false);
                }
                // Not remembered: an attempt that established nothing must not
                // block the next one behind the repeat window.
                PathVerdict::Indeterminate => summary.indeterminate += 1,
            }
        }
        summary
    }

    fn recently_probed(&self, hostname: &str, repeat_after: Duration, now: Instant) -> bool {
        self.last_probed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(hostname)
            .is_some_and(|at| now.saturating_duration_since(*at) < repeat_after)
    }

    fn mark_probed(&self, hostname: &str, now: Instant) {
        let mut seen = self.last_probed.lock().unwrap_or_else(|p| p.into_inner());
        // Bounded: a browsing session's worth of hosts, then start over.
        if seen.len() >= 4096 {
            seen.clear();
        }
        seen.insert(hostname.to_string(), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A local server that reads the hello and then does `respond`.
    fn exchange_with(respond: fn(&mut std::net::TcpStream)) -> PathVerdict {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut peer, _) = listener.accept().expect("accept");
            let mut header = [0u8; 5];
            peer.read_exact(&mut header).expect("hello header");
            assert_eq!(header[0], 0x16, "a TLS handshake record arrives");
            // The whole hello, as a real server reads it: closing with unread
            // bytes makes the OS reset the connection, which can overtake the
            // answer and turn this test into a race.
            let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            peer.read_exact(&mut body).expect("hello body");
            respond(&mut peer);
            // Hold the connection until the client has read and closed it.
            let _ = peer.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = peer.read(&mut [0u8; 1]);
        });
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let verdict = tls_exchange(&mut stream, "site.example", Duration::from_millis(400));
        drop(stream);
        server.join().expect("server");
        verdict
    }

    /// Real servers take the hand-built hello. Needs the internet:
    /// `cargo test -p nrr-service-runtime -- --ignored live_tls`.
    #[test]
    #[ignore = "needs the internet"]
    fn live_tls_probe_gets_a_server_hello_from_real_fronts() {
        use std::net::ToSocketAddrs;
        for name in ["www.wikipedia.org", "www.cloudflare.com", "www.google.com"] {
            let target = (name, 443)
                .to_socket_addrs()
                .expect("resolve")
                .find_map(|a| match a {
                    std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                    std::net::SocketAddr::V6(_) => None,
                })
                .expect("an IPv4 address");
            assert_eq!(
                SystemPathProbe.probe_tls(target, name, None, Duration::from_secs(5)),
                PathVerdict::Answered,
                "{name}"
            );
        }
    }

    /// TCP gets through in every case below; only a TLS answer counts.
    #[test]
    fn only_a_tls_record_back_means_the_name_gets_through() {
        use std::io::Write;
        assert_eq!(
            exchange_with(|p| p.write_all(&[0x16, 0x03, 0x03, 0x00, 0x5a]).expect("write")),
            PathVerdict::Answered
        );
        assert_eq!(
            exchange_with(|p| p.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02]).expect("write")),
            PathVerdict::Answered,
            "an alert is still a TLS peer answering"
        );
        assert_eq!(
            exchange_with(|p| {
                let _ = p.shutdown(std::net::Shutdown::Both);
            }),
            PathVerdict::Silent,
            "closed after the hello"
        );
        assert_eq!(
            exchange_with(|p| p.write_all(b"HTTP/1.1 403 Forbidden\r\n").expect("write")),
            PathVerdict::Silent,
            "something else answered in the server's place"
        );
        assert_eq!(
            exchange_with(|_| std::thread::sleep(Duration::from_millis(700))),
            PathVerdict::Silent,
            "the hello went unanswered"
        );
    }

    /// A probe that could not run is not a host that stayed silent: the
    /// block-detector treats silence as evidence, and a zero timeout measured
    /// nothing at all.
    #[test]
    fn a_probe_that_cannot_run_is_indeterminate_not_silent() {
        let probe = SystemPathProbe;
        let verdict = probe.probe(
            Ipv4Addr::new(203, 0, 113, 1),
            443,
            None,
            std::time::Duration::ZERO,
        );
        assert_eq!(verdict, PathVerdict::Indeterminate);
    }

    fn target(host: &str, last_octet: u8) -> ProbeTarget {
        ProbeTarget {
            hostname: host.to_string(),
            addresses: vec![Ipv4Addr::new(203, 0, 113, last_octet)],
        }
    }

    /// Verdicts a test collected, and the sink that fills it.
    type CollectedVerdicts = Arc<Mutex<Vec<(String, bool)>>>;

    fn collect() -> (CollectedVerdicts, Box<ProbeVerdictSink>) {
        let seen: Arc<Mutex<Vec<(String, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let seen = Arc::clone(&seen);
            Box::new(move |host: &str, answered: bool| {
                seen.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((host.to_string(), answered));
            }) as Box<ProbeVerdictSink>
        };
        (seen, sink)
    }

    #[test]
    fn limits_are_clamped_not_trusted() {
        let wild = ProbeLimits::new(Duration::from_secs(600), 10_000, Duration::from_millis(1));
        assert_eq!(wild.timeout, ProbeLimits::TIMEOUT_RANGE.1);
        assert_eq!(wild.max_targets, ProbeLimits::MAX_TARGETS_RANGE.1);
        assert_eq!(wild.repeat_after, ProbeLimits::REPEAT_AFTER_RANGE.0);
    }

    #[test]
    fn a_pass_stops_at_the_target_limit_and_says_what_it_skipped() {
        let prober = PathProber::new(Arc::new(MockPathProbe::new(PathVerdict::Answered)));
        let targets: Vec<ProbeTarget> = (1..=5)
            .map(|i| target(&format!("h{i}.example"), i))
            .collect();
        let (seen, sink) = collect();
        let limits = ProbeLimits::new(Duration::from_millis(500), 2, Duration::from_secs(300));

        let summary = prober.run_pass(&targets, 443, None, limits, Instant::now(), &*sink);

        assert_eq!(summary.answered, 2);
        assert_eq!(
            summary.skipped_over_limit, 3,
            "the rest are reported, not dropped silently"
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_recent_verdict_is_not_asked_for_again() {
        let prober = PathProber::new(Arc::new(MockPathProbe::new(PathVerdict::Silent)));
        let targets = vec![target("one.example", 1)];
        let (_seen, sink) = collect();
        let limits = ProbeLimits::default();
        let start = Instant::now();

        let first = prober.run_pass(&targets, 443, None, limits, start, &*sink);
        assert_eq!(first.silent, 1);

        let again = prober.run_pass(&targets, 443, None, limits, start, &*sink);
        assert_eq!(again.skipped_recent, 1);
        assert_eq!(again.silent, 0);

        // Past the repeat window it is asked again.
        let later = prober.run_pass(
            &targets,
            443,
            None,
            limits,
            start + limits.repeat_after + Duration::from_secs(1),
            &*sink,
        );
        assert_eq!(later.silent, 1);
    }

    #[test]
    fn an_indeterminate_outcome_is_not_reported_as_evidence() {
        let prober = PathProber::new(Arc::new(MockPathProbe::new(PathVerdict::Indeterminate)));
        let targets = vec![target("one.example", 1)];
        let (seen, sink) = collect();

        let summary = prober.run_pass(
            &targets,
            443,
            None,
            ProbeLimits::default(),
            Instant::now(),
            &*sink,
        );

        assert_eq!(summary.indeterminate, 1);
        assert!(
            seen.lock().unwrap().is_empty(),
            "nothing was established, so nothing is claimed"
        );
        // And it did not consume the repeat window.
        let retry = prober.run_pass(
            &targets,
            443,
            None,
            ProbeLimits::default(),
            Instant::now(),
            &*sink,
        );
        assert_eq!(retry.skipped_recent, 0);
    }

    #[test]
    fn the_source_address_is_passed_through_so_the_packet_leaves_by_the_main_link() {
        let probe = Arc::new(MockPathProbe::new(PathVerdict::Answered));
        let prober = PathProber::new(Arc::clone(&probe) as Arc<dyn PathProbe>);
        let (_seen, sink) = collect();
        let source = Ipv4Addr::new(192, 168, 0, 105);

        prober.run_pass(
            &[target("one.example", 1)],
            443,
            Some(source),
            ProbeLimits::default(),
            Instant::now(),
            &*sink,
        );

        assert_eq!(
            probe.attempts(),
            vec![(Ipv4Addr::new(203, 0, 113, 1), 443, Some(source))]
        );
    }
}

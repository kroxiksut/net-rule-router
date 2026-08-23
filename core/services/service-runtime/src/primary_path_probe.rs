//! "Does this address answer on the main link?" — asked directly.
//!
//! The passive verdict ([`nrr_domain::companion_affinity::PrimaryBehavior`]) is
//! built from traffic that happened to occur. With the additional route down
//! there is no such traffic to learn from, so every suggestion stays
//! unexamined — and the user is asked to decide with no evidence at all. This
//! module answers the question on demand instead.
//!
//! Two things it deliberately is NOT:
//!
//! - **not a judgement about the site.** A connection that completes proves the
//!   packet arrives, nothing more: a service can answer a main-link address with
//!   a refusal (ChatGPT does exactly that). The verdict feeds the same
//!   `PrimaryHealthEvent` channel the observed traffic feeds, and the wording in
//!   the GUI stays a statement of connectivity.
//! - **not on the data path.** It runs when the user asks (or on their opt-in),
//!   from its own thread, bounded in count and time.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What one probe established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryPathVerdict {
    /// The address accepted a connection over the main link.
    Answered,
    /// It definitely did not: refused, or silent past the timeout.
    Silent,
    /// The probe could not be carried out (no source address, socket refused to
    /// open). Reported as its own outcome — guessing either way would put a
    /// verdict on the screen that nothing measured.
    Indeterminate,
}

/// The mechanism: one bounded TCP connect attempt, optionally from a chosen
/// source address so the packet leaves by the main link.
pub trait PrimaryPathProbe: Send + Sync {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PrimaryPathVerdict;
}

/// Production probe. A refused connection counts as `Silent`: for this question
/// "the main link cannot get me there" and "there is nothing listening" are the
/// same answer, and both mean the user's site will not load that way.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemPrimaryPathProbe;

impl PrimaryPathProbe for SystemPrimaryPathProbe {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> PrimaryPathVerdict {
        let address = std::net::SocketAddr::from((target, port));
        let Ok(socket) = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        ) else {
            return PrimaryPathVerdict::Indeterminate;
        };
        if let Some(source) = source {
            // Binding is what decides the link. Without it the OS would pick by
            // route — and the pinned destination's route points at the tunnel,
            // which is the opposite of the question being asked.
            if socket
                .bind(&std::net::SocketAddr::from((source, 0)).into())
                .is_err()
            {
                return PrimaryPathVerdict::Indeterminate;
            }
        }
        match socket.connect_timeout(&address.into(), timeout) {
            Ok(()) => PrimaryPathVerdict::Answered,
            Err(_) => PrimaryPathVerdict::Silent,
        }
    }
}

/// Test double returning a scripted verdict and counting attempts.
#[derive(Debug)]
pub struct MockPrimaryPathProbe {
    verdict: PrimaryPathVerdict,
    attempts: Mutex<Vec<(Ipv4Addr, u16, Option<Ipv4Addr>)>>,
}

impl MockPrimaryPathProbe {
    pub fn new(verdict: PrimaryPathVerdict) -> Self {
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

impl PrimaryPathProbe for MockPrimaryPathProbe {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PrimaryPathVerdict {
        self.attempts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((target, port, source));
        self.verdict
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
pub struct PrimaryPathProber {
    probe: Arc<dyn PrimaryPathProbe>,
    last_probed: Mutex<std::collections::HashMap<String, Instant>>,
}

/// `(hostname, answered)` — `answered == false` means definitely silent.
/// Indeterminate outcomes are never reported: they are not evidence.
pub type ProbeVerdictSink = dyn Fn(&str, bool) + Send + Sync;

impl PrimaryPathProber {
    pub fn new(probe: Arc<dyn PrimaryPathProbe>) -> Self {
        Self {
            probe,
            last_probed: Mutex::new(std::collections::HashMap::new()),
        }
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
            let mut verdict = PrimaryPathVerdict::Indeterminate;
            for address in &target.addresses {
                verdict = self.probe.probe(*address, port, source, limits.timeout);
                if verdict != PrimaryPathVerdict::Indeterminate {
                    break;
                }
            }
            match verdict {
                PrimaryPathVerdict::Answered => {
                    summary.answered += 1;
                    self.mark_probed(&target.hostname, now);
                    report(&target.hostname, true);
                }
                PrimaryPathVerdict::Silent => {
                    summary.silent += 1;
                    self.mark_probed(&target.hostname, now);
                    report(&target.hostname, false);
                }
                // Not remembered: an attempt that established nothing must not
                // block the next one behind the repeat window.
                PrimaryPathVerdict::Indeterminate => summary.indeterminate += 1,
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
        let prober = PrimaryPathProber::new(Arc::new(MockPrimaryPathProbe::new(
            PrimaryPathVerdict::Answered,
        )));
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
        let prober = PrimaryPathProber::new(Arc::new(MockPrimaryPathProbe::new(
            PrimaryPathVerdict::Silent,
        )));
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
        let prober = PrimaryPathProber::new(Arc::new(MockPrimaryPathProbe::new(
            PrimaryPathVerdict::Indeterminate,
        )));
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
        let probe = Arc::new(MockPrimaryPathProbe::new(PrimaryPathVerdict::Answered));
        let prober = PrimaryPathProber::new(Arc::clone(&probe) as Arc<dyn PrimaryPathProbe>);
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

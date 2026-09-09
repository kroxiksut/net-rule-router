//! Did the user go to this host, or did a page take them there?
//!
//! ## The gap this closes
//!
//! Every self-signed offer ([`crate::auto_rules::AutoRulesEngine::note_main_link_blocked_host`])
//! says the same thing: connections to this host start on the main link and
//! nothing comes back. Measured on the field, that is true of an ad exchange
//! the provider cuts just as much as of a site the user tried to open — and
//! the model had no way to tell the two apart, so it offered to route hosts
//! nobody had ever visited.
//!
//! The missing fact is not about the host. It is about how the connection came
//! to exist: a person opening a page starts a BURST, while a name pulled in by
//! somebody else's page arrives inside a burst that was already running.
//!
//! ## What is measured
//!
//! For each process, the gap since its previous connection and what followed
//! this one. Three outcomes per named destination:
//!
//! - **navigation** — quiet before it, a burst after it. The page a person opened.
//! - **companion** — it arrived inside a burst somebody else started.
//! - **solo** — quiet before AND after: nothing followed it. A banner refreshing
//!   on a timer in an open tab looks exactly like this, which is why "quiet
//!   before" alone cannot mean navigation: on a machine averaging one
//!   connection per second almost every timer tick would qualify.
//!
//! ## What this deliberately does NOT do
//!
//! It changes nothing. No offer is withheld, no verdict is altered, no counter
//! the user sees moves. It counts and it says what it counted, so the
//! thresholds below can be chosen from a distribution instead of from
//! intuition. Acting on the measurement is a separate decision.
//!
//! ## Bounds
//!
//! Memory is capped and ages out, like [`crate::primary_stall_registry`]:
//! nothing is persisted, and a restart re-learns from the next connection.

use std::collections::HashMap;
use std::sync::Mutex;

/// Quiet needed BEFORE a connection for it to be a candidate navigation.
///
/// A page load is preceded by a person reading the previous one; a resource
/// pulled by that page follows within milliseconds.
const QUIET_BEFORE_MS: u64 = 2_000;

/// How long after a candidate its burst is still counted as its own.
const BURST_WINDOW_MS: u64 = 3_000;

/// Connections that must follow within the window to call it a burst. Below
/// this the candidate stands alone — which is what a timer-driven refresh
/// looks like, and what a page load never does.
const BURST_MIN_FOLLOWERS: u32 = 3;

/// How long a host's or a process's counts stay meaningful. Matches
/// [`crate::primary_stall_registry::ENTRY_TTL`] — the verdict these numbers
/// travel beside ages out on the same clock.
const ENTRY_TTL_MS: u64 = 6 * 60 * 60 * 1_000;

/// Most hosts counted at once, and most processes tracked at once.
const MAX_HOSTS: usize = 4096;
const MAX_PROCESSES: usize = 256;

/// How often the accumulated distribution is worth saying out loud.
const REPORT_EVERY_MS: u64 = 10 * 60 * 1_000;

/// Upper edges of the gap buckets, in milliseconds. The last bucket catches
/// everything above the final edge.
const GAP_BUCKET_EDGES_MS: [u64; 6] = [250, 500, 1_000, 2_000, 5_000, 15_000];

/// Upper edges of the burst-size buckets (connections following a candidate).
const BURST_BUCKET_EDGES: [u32; 4] = [0, 2, 4, 9];

/// How a named destination was reached, totalled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostCounts {
    /// Quiet before, burst after — a page the user opened.
    pub navigations: u32,
    /// Arrived inside a burst somebody else started.
    pub companions: u32,
    /// Quiet before and after: nothing followed it.
    pub solo: u32,
}

impl HostCounts {
    #[must_use]
    pub fn total(&self) -> u32 {
        self.navigations
            .saturating_add(self.companions)
            .saturating_add(self.solo)
    }
}

/// What the registry has seen overall — the shape the thresholds are chosen
/// from. Bucket counts, never individual timings: the question is where the
/// mass sits, and a raw log of every gap would be both huge and personal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Distribution {
    /// Gaps between consecutive connections of one process, bucketed by
    /// [`GAP_BUCKET_EDGES_MS`] plus an overflow bucket.
    pub gap_buckets: [u32; GAP_BUCKET_EDGES_MS.len() + 1],
    /// Followers seen after a candidate, bucketed by [`BURST_BUCKET_EDGES`]
    /// plus an overflow bucket.
    pub burst_buckets: [u32; BURST_BUCKET_EDGES.len() + 1],
    /// Named destinations counted so far.
    pub hosts: usize,
    /// Processes with at least one connection in the window.
    pub processes: usize,
}

/// A connection that could still turn out to be a navigation, waiting to see
/// whether anything follows it.
#[derive(Debug, Clone)]
struct Candidate {
    /// `None` when the destination could not be named — it still holds the
    /// slot (so the next connection is not mistaken for a second candidate)
    /// but no host is credited when it settles.
    hostname: Option<String>,
    at_ms: u64,
    followers: u32,
}

#[derive(Debug)]
struct ProcState {
    last_at_ms: u64,
    /// Whether a gap has actually been observed for this process yet. The
    /// first sighting has nothing before it: the process was very likely busy
    /// before the service started watching, and treating that as quiet made
    /// the first connection after every start a navigation.
    primed: bool,
    candidate: Option<Candidate>,
    /// Navigations this process has ever produced. A process that has produced
    /// none has never been observed going quiet, so its hosts' zeroes say
    /// nothing about them — see [`NavigationRegistry::process_ever_navigated`].
    navigations: u32,
}

/// Per-host "went there" versus "was taken there".
pub struct NavigationRegistry {
    procs: Mutex<HashMap<String, ProcState>>,
    hosts: Mutex<HashMap<String, (HostCounts, u64)>>,
    dist: Mutex<(Distribution, u64)>,
    /// When candidates were last settled without a new connection to settle
    /// them — see the lazy sweep in [`NavigationRegistry::note_attempt`].
    last_sweep_ms: Mutex<u64>,
    quiet_before_ms: u64,
    burst_window_ms: u64,
    burst_min_followers: u32,
    ttl_ms: u64,
    host_cap: usize,
    proc_cap: usize,
    report_every_ms: u64,
}

impl Default for NavigationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NavigationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            procs: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
            dist: Mutex::new((Distribution::default(), 0)),
            last_sweep_ms: Mutex::new(0),
            quiet_before_ms: QUIET_BEFORE_MS,
            burst_window_ms: BURST_WINDOW_MS,
            burst_min_followers: BURST_MIN_FOLLOWERS,
            ttl_ms: ENTRY_TTL_MS,
            host_cap: MAX_HOSTS,
            proc_cap: MAX_PROCESSES,
            report_every_ms: REPORT_EVERY_MS,
        }
    }

    /// Override the timings and bounds. Builder-style; production keeps the
    /// defaults and only tests narrow them.
    #[must_use]
    pub fn with_timings(
        mut self,
        quiet_before_ms: u64,
        burst_window_ms: u64,
        burst_min_followers: u32,
    ) -> Self {
        self.quiet_before_ms = quiet_before_ms;
        self.burst_window_ms = burst_window_ms;
        self.burst_min_followers = burst_min_followers;
        self
    }

    #[must_use]
    pub fn with_bounds(mut self, ttl_ms: u64, host_cap: usize, proc_cap: usize) -> Self {
        self.ttl_ms = ttl_ms;
        self.host_cap = host_cap.max(1);
        self.proc_cap = proc_cap.max(1);
        self
    }

    #[must_use]
    pub fn with_report_interval(mut self, report_every_ms: u64) -> Self {
        self.report_every_ms = report_every_ms;
        self
    }

    /// One outbound connection attempt.
    ///
    /// `process` is the initiating image path — the only identity both
    /// observers supply (the WFP net-event source reports `pid: 0` by design).
    /// An unattributed connection is ignored: without knowing whose burst it
    /// belongs to there is nothing to measure.
    ///
    /// `hostname` is `None` when the destination could not be named; such a
    /// connection still shapes its process's bursts, it just credits no host.
    ///
    /// Returns the accumulated distribution when enough time has passed to be
    /// worth logging — the same "speak only when there is something to say"
    /// shape [`crate::primary_stall_registry::PrimaryStallRegistry::note`] has.
    pub fn note_attempt(
        &self,
        process: Option<&str>,
        hostname: Option<&str>,
        at_ms: u64,
    ) -> Option<Distribution> {
        let process = process.filter(|p| !p.is_empty())?;
        // A candidate nothing followed is settled by the next connection of
        // ITS process — which for a background process can be a long wait. One
        // pass per burst window catches those without a second sink to wire or
        // a timer to own.
        self.sweep_if_due(at_ms);
        let settled = {
            let mut procs = self.procs.lock().unwrap_or_else(|p| p.into_inner());
            Self::expire_procs(&mut procs, at_ms, self.ttl_ms);
            let entry = procs.entry(process.to_string()).or_insert(ProcState {
                last_at_ms: at_ms,
                primed: false,
                candidate: None,
                navigations: 0,
            });
            if !entry.primed {
                entry.primed = true;
                entry.last_at_ms = at_ms;
                Self::evict_procs_to_cap(&mut procs, self.proc_cap);
                return self.due_report(at_ms);
            }
            let gap = at_ms.saturating_sub(entry.last_at_ms);
            entry.last_at_ms = entry.last_at_ms.max(at_ms);
            self.record_gap(gap);

            let mut settled = None;
            match entry.candidate.take() {
                Some(mut candidate)
                    if at_ms.saturating_sub(candidate.at_ms) <= self.burst_window_ms =>
                {
                    // Inside the candidate's window: this connection is part of
                    // its burst, and is itself a companion.
                    candidate.followers = candidate.followers.saturating_add(1);
                    entry.candidate = Some(candidate);
                    if let Some(host) = hostname {
                        settled = Some((host.to_string(), Outcome::Companion));
                    }
                }
                Some(candidate) => {
                    // The window closed. Settle it, then judge this connection
                    // on its own gap.
                    let outcome = self.settle(&candidate, &mut entry.navigations);
                    if let Some(host) = candidate.hostname.as_deref() {
                        self.credit(host, outcome, at_ms);
                    }
                    settled = self.begin_or_credit(entry, hostname, gap, at_ms);
                }
                None => {
                    settled = self.begin_or_credit(entry, hostname, gap, at_ms);
                }
            }
            Self::evict_procs_to_cap(&mut procs, self.proc_cap);
            settled
        };
        if let Some((host, outcome)) = settled {
            self.credit(&host, outcome, at_ms);
        }
        self.due_report(at_ms)
    }

    /// [`Self::sweep`], but at most once per burst window.
    fn sweep_if_due(&self, now_ms: u64) {
        {
            let mut last = self.last_sweep_ms.lock().unwrap_or_else(|p| p.into_inner());
            if now_ms.saturating_sub(*last) < self.burst_window_ms {
                return;
            }
            *last = now_ms;
        }
        self.sweep(now_ms);
    }

    /// Settle candidates whose window has closed without another connection
    /// arriving to close them. Without this a burstless candidate would sit
    /// uncounted until its process spoke again — which for a background
    /// process can be never.
    pub fn sweep(&self, now_ms: u64) {
        self.hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, (_, last)| now_ms.saturating_sub(*last) < self.ttl_ms);
        let ripe: Vec<(Candidate, Outcome)> = {
            let mut procs = self.procs.lock().unwrap_or_else(|p| p.into_inner());
            Self::expire_procs(&mut procs, now_ms, self.ttl_ms);
            let mut ripe = Vec::new();
            for state in procs.values_mut() {
                let Some(candidate) = state.candidate.as_ref() else {
                    continue;
                };
                if now_ms.saturating_sub(candidate.at_ms) <= self.burst_window_ms {
                    continue;
                }
                let Some(candidate) = state.candidate.take() else {
                    continue;
                };
                let outcome = self.settle(&candidate, &mut state.navigations);
                ripe.push((candidate, outcome));
            }
            ripe
        };
        for (candidate, outcome) in ripe {
            if let Some(host) = candidate.hostname.as_deref() {
                self.credit(host, outcome, now_ms);
            }
        }
    }

    /// What was counted for `hostname`. All zeroes for a host never seen.
    #[must_use]
    pub fn counts_of(&self, hostname: &str) -> HostCounts {
        self.hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(hostname)
            .map(|(counts, _)| *counts)
            .unwrap_or_default()
    }

    /// Has this process ever been seen starting a burst?
    ///
    /// The guard against a measurement that quietly means nothing: a process
    /// that never goes quiet produces no navigations at all, and every host it
    /// touches would read as "the user never went there". A consumer that
    /// suppresses on zero navigations must ask this first.
    #[must_use]
    pub fn process_ever_navigated(&self, process: &str) -> bool {
        self.procs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(process)
            .is_some_and(|state| state.navigations > 0)
    }

    /// The accumulated shape, for a caller that wants to ask rather than be told.
    #[must_use]
    pub fn distribution(&self) -> Distribution {
        let mut dist = self
            .dist
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .0
            .clone();
        dist.hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner()).len();
        dist.processes = self.procs.lock().unwrap_or_else(|p| p.into_inner()).len();
        dist
    }

    /// Start a candidate when the gap says so, otherwise credit a companion.
    fn begin_or_credit(
        &self,
        entry: &mut ProcState,
        hostname: Option<&str>,
        gap: u64,
        at_ms: u64,
    ) -> Option<(String, Outcome)> {
        if gap >= self.quiet_before_ms {
            entry.candidate = Some(Candidate {
                hostname: hostname.map(str::to_string),
                at_ms,
                followers: 0,
            });
            return None;
        }
        hostname.map(|host| (host.to_string(), Outcome::Companion))
    }

    fn settle(&self, candidate: &Candidate, navigations: &mut u32) -> Outcome {
        self.record_burst(candidate.followers);
        if candidate.followers >= self.burst_min_followers {
            *navigations = navigations.saturating_add(1);
            Outcome::Navigation
        } else {
            Outcome::Solo
        }
    }

    fn credit(&self, hostname: &str, outcome: Outcome, at_ms: u64) {
        let mut hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        hosts.retain(|_, (_, last)| at_ms.saturating_sub(*last) < self.ttl_ms);
        let (counts, last) = hosts
            .entry(hostname.to_string())
            .or_insert((HostCounts::default(), at_ms));
        *last = (*last).max(at_ms);
        match outcome {
            Outcome::Navigation => counts.navigations = counts.navigations.saturating_add(1),
            Outcome::Companion => counts.companions = counts.companions.saturating_add(1),
            Outcome::Solo => counts.solo = counts.solo.saturating_add(1),
        }
        while hosts.len() > self.host_cap {
            let Some(oldest) = hosts
                .iter()
                .min_by_key(|(_, (_, last))| *last)
                .map(|(h, _)| h.clone())
            else {
                break;
            };
            hosts.remove(&oldest);
        }
    }

    fn record_gap(&self, gap_ms: u64) {
        let idx = GAP_BUCKET_EDGES_MS
            .iter()
            .position(|edge| gap_ms < *edge)
            .unwrap_or(GAP_BUCKET_EDGES_MS.len());
        let mut dist = self.dist.lock().unwrap_or_else(|p| p.into_inner());
        dist.0.gap_buckets[idx] = dist.0.gap_buckets[idx].saturating_add(1);
    }

    fn record_burst(&self, followers: u32) {
        let idx = BURST_BUCKET_EDGES
            .iter()
            .position(|edge| followers <= *edge)
            .unwrap_or(BURST_BUCKET_EDGES.len());
        let mut dist = self.dist.lock().unwrap_or_else(|p| p.into_inner());
        dist.0.burst_buckets[idx] = dist.0.burst_buckets[idx].saturating_add(1);
    }

    /// The distribution, but only once per reporting interval.
    fn due_report(&self, at_ms: u64) -> Option<Distribution> {
        {
            let mut dist = self.dist.lock().unwrap_or_else(|p| p.into_inner());
            if dist.1 == 0 {
                dist.1 = at_ms;
                return None;
            }
            if at_ms.saturating_sub(dist.1) < self.report_every_ms {
                return None;
            }
            dist.1 = at_ms;
        }
        Some(self.distribution())
    }

    fn expire_procs(procs: &mut HashMap<String, ProcState>, now_ms: u64, ttl_ms: u64) {
        procs.retain(|_, state| now_ms.saturating_sub(state.last_at_ms) < ttl_ms);
    }

    fn evict_procs_to_cap(procs: &mut HashMap<String, ProcState>, cap: usize) {
        while procs.len() > cap {
            let Some(oldest) = procs
                .iter()
                .min_by_key(|(_, state)| state.last_at_ms)
                .map(|(p, _)| p.clone())
            else {
                return;
            };
            procs.remove(&oldest);
        }
    }
}

/// How one connection turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Navigation,
    Companion,
    Solo,
}

/// Say how a host was reached, beside the verdict that it does not open.
///
/// `debug`, not `info`: this is evidence for choosing a threshold, not a fact
/// about the user's network. It is emitted once per verdict change, which the
/// stall registry already rate-limits.
pub fn log_counts(hostname: &str, counts: &HostCounts) {
    tracing::debug!(
        target: "nrr::navigation",
        hostname = %hostname,
        navigations = counts.navigations,
        companions = counts.companions,
        solo = counts.solo,
        "how this destination was reached before it stopped answering",
    );
}

/// Say what the timings look like overall, so the thresholds can be chosen
/// from the shape rather than guessed.
pub fn log_distribution(dist: &Distribution) {
    tracing::debug!(
        target: "nrr::navigation",
        gap_buckets = ?dist.gap_buckets,
        gap_edges_ms = ?GAP_BUCKET_EDGES_MS,
        burst_buckets = ?dist.burst_buckets,
        burst_edges = ?BURST_BUCKET_EDGES,
        hosts = dist.hosts,
        processes = dist.processes,
        "connection timing distribution",
    );
}

/// Process-wide registry, wired the way
/// [`crate::primary_stall_registry::global_primary_stalls`] is: the observer
/// writes it and the auto-rule path reads it, from different build functions
/// in one process. Tests construct [`NavigationRegistry`] directly.
pub fn global_navigation() -> std::sync::Arc<NavigationRegistry> {
    static GLOBAL: std::sync::OnceLock<std::sync::Arc<NavigationRegistry>> =
        std::sync::OnceLock::new();
    GLOBAL
        .get_or_init(|| std::sync::Arc::new(NavigationRegistry::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Short timings so a test reads as a sequence of events, not of clocks.
    fn registry() -> NavigationRegistry {
        NavigationRegistry::new().with_timings(1_000, 500, 3)
    }

    const PROC: &str = "C:/apps/browser.exe";

    /// One connection long before the interesting one. A process's FIRST
    /// sighting has no observed gap in front of it, so every test that means
    /// "quiet, then something" has to establish the process first — exactly as
    /// a running browser establishes itself before the user opens a page.
    fn warm(reg: &NavigationRegistry, at_ms: u64) {
        reg.note_attempt(Some(PROC), None, at_ms);
    }

    /// A page load: quiet, then the page, then everything the page pulls in.
    fn page_load(reg: &NavigationRegistry, at_ms: u64, page: &str, pulled: &[&str]) {
        warm(reg, at_ms.saturating_sub(10_000));
        reg.note_attempt(Some(PROC), Some(page), at_ms);
        for (i, host) in pulled.iter().enumerate() {
            reg.note_attempt(Some(PROC), Some(host), at_ms + 50 + i as u64 * 10);
        }
        reg.sweep(at_ms + 5_000);
    }

    #[test]
    fn the_page_a_person_opened_is_a_navigation_and_what_it_pulled_is_not() {
        let reg = registry();
        page_load(
            &reg,
            10_000,
            "site.example",
            &["ads.tracker.example", "cdn.example", "beacon.example"],
        );

        assert_eq!(
            reg.counts_of("site.example"),
            HostCounts {
                navigations: 1,
                companions: 0,
                solo: 0
            },
            "quiet before it and a burst after it is what opening a page looks like"
        );
        // The positive control that makes the assertion above mean something:
        // the same measurement must NOT call the ad host a navigation.
        assert_eq!(
            reg.counts_of("ads.tracker.example"),
            HostCounts {
                navigations: 0,
                companions: 1,
                solo: 0
            },
            "a name the page pulled in arrived inside somebody else's burst"
        );
    }

    /// The case that made "quiet before" insufficient: on a sparse machine a
    /// banner refreshing on a timer has quiet on both sides of it.
    #[test]
    fn a_lone_connection_in_the_quiet_is_not_a_navigation() {
        let reg = registry();
        warm(&reg, 1_000);
        reg.note_attempt(Some(PROC), Some("ads.tracker.example"), 10_000);
        reg.sweep(20_000);

        assert_eq!(
            reg.counts_of("ads.tracker.example"),
            HostCounts {
                navigations: 0,
                companions: 0,
                solo: 1
            },
            "nothing followed it, so nobody opened anything"
        );
    }

    #[test]
    fn a_burst_too_small_to_be_a_page_settles_as_solo() {
        let reg = registry();
        warm(&reg, 1_000);
        reg.note_attempt(Some(PROC), Some("api.example"), 10_000);
        reg.note_attempt(Some(PROC), Some("api.example"), 10_100);
        reg.sweep(20_000);

        let counts = reg.counts_of("api.example");
        assert_eq!(counts.navigations, 0, "two connections are not a page load");
        assert_eq!(counts.total(), 2, "both connections were still counted");
    }

    /// The guard the consumer must consult: a process that never goes quiet
    /// produces no navigations, and its hosts' zeroes describe the process, not
    /// the hosts.
    #[test]
    fn a_process_that_never_goes_quiet_reports_that_it_has_never_navigated() {
        let reg = registry();
        // Continuous chatter: every gap is below the quiet threshold.
        for i in 0..30_u64 {
            reg.note_attempt(Some(PROC), Some("noisy.example"), 10_000 + i * 100);
        }
        assert!(
            !reg.process_ever_navigated(PROC),
            "no quiet was ever observed, so no navigation could be"
        );
        // And the positive control: once it does go quiet and open a page, it says so.
        page_load(
            &reg,
            30_000,
            "site.example",
            &["a.example", "b.example", "c.example"],
        );
        assert!(
            reg.process_ever_navigated(PROC),
            "a real page load is what makes the answer true"
        );
    }

    #[test]
    fn an_unnamed_destination_shapes_the_burst_but_credits_no_host() {
        let reg = registry();
        warm(&reg, 1_000);
        reg.note_attempt(Some(PROC), Some("site.example"), 10_000);
        for i in 0..3_u64 {
            reg.note_attempt(Some(PROC), None, 10_050 + i * 10);
        }
        reg.sweep(20_000);

        assert_eq!(
            reg.counts_of("site.example").navigations,
            1,
            "connections nobody could name still prove a burst happened"
        );
        assert_eq!(
            reg.distribution().hosts,
            1,
            "but they add no host of their own"
        );
    }

    #[test]
    fn an_unattributed_connection_is_ignored() {
        let reg = registry();
        assert!(reg
            .note_attempt(None, Some("site.example"), 10_000)
            .is_none());
        assert!(reg
            .note_attempt(Some(""), Some("site.example"), 10_000)
            .is_none());
        assert_eq!(reg.counts_of("site.example"), HostCounts::default());
    }

    #[test]
    fn two_processes_do_not_share_a_burst() {
        let reg = registry();
        const OTHER: &str = "C:/apps/updater.exe";
        warm(&reg, 1_000);
        reg.note_attempt(Some(PROC), Some("site.example"), 10_000);
        // The other process is busy at the same moment; its traffic must not
        // become the burst that confirms this page.
        for i in 0..5_u64 {
            reg.note_attempt(Some(OTHER), Some("update.example"), 10_050 + i * 10);
        }
        reg.sweep(20_000);

        assert_eq!(
            reg.counts_of("site.example").navigations,
            0,
            "somebody else's traffic is not this page's burst"
        );
    }

    #[test]
    fn the_distribution_is_reported_once_per_interval() {
        let reg = registry().with_report_interval(1_000);
        assert!(
            reg.note_attempt(Some(PROC), Some("a.example"), 10_000)
                .is_none(),
            "the first observation starts the interval rather than reporting one"
        );
        assert!(reg
            .note_attempt(Some(PROC), Some("b.example"), 10_500)
            .is_none());
        let reported = reg.note_attempt(Some(PROC), Some("c.example"), 11_200);
        assert!(reported.is_some(), "the interval elapsed");
        assert!(
            reg.note_attempt(Some(PROC), Some("d.example"), 11_300)
                .is_none(),
            "and it does not repeat until the next one"
        );
    }

    #[test]
    fn hosts_and_processes_stay_within_their_caps() {
        let reg = registry().with_bounds(60_000, 2, 2);
        for i in 0..6_u64 {
            let host = format!("host{i}.example");
            let proc = format!("C:/apps/p{i}.exe");
            reg.note_attempt(Some(&proc), Some(&host), 10_000 + i * 100);
            reg.sweep(10_000 + i * 100 + 5_000);
        }
        let dist = reg.distribution();
        assert!(dist.hosts <= 2, "host map stayed capped: {}", dist.hosts);
        assert!(
            dist.processes <= 2,
            "process map stayed capped: {}",
            dist.processes
        );
    }

    #[test]
    fn entries_age_out_after_the_ttl() {
        // Longer than the warm-up the page-load helper puts in front of the
        // page: a TTL shorter than that would evict the process itself and
        // the test would be measuring the wrong eviction.
        let reg = registry().with_bounds(20_000, 64, 64);
        page_load(
            &reg,
            10_000,
            "site.example",
            &["a.example", "b.example", "c.example"],
        );
        assert_eq!(reg.counts_of("site.example").navigations, 1);
        // Far beyond the TTL: the next observation sweeps the old entries out.
        reg.note_attempt(Some(PROC), Some("later.example"), 100_000);
        reg.sweep(100_000);
        assert_eq!(
            reg.counts_of("site.example"),
            HostCounts::default(),
            "a verdict built from last week's browsing describes nothing"
        );
    }
}

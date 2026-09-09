//! Which named destinations stall on the MAIN link — for every host, not only
//! for companion candidates.
//!
//! ## The gap this closes
//!
//! The connection observer already reports how each named destination fares on
//! the primary route: a resent segment is a stall, an orderly close is a
//! completion ([`nrr_domain::companion_affinity::PrimaryHealthEvent`]). Until
//! now the only consumer was the companion-affinity ledger, and it keeps that
//! evidence solely for hosts it already tracks as CANDIDATES — a companion of a
//! routed site. `note_primary_health` drops the event on the floor for anything
//! else.
//!
//! So the product could watch a plain rule host fail to open, over and over,
//! and remember nothing about it. That is the whole evidence base for answering
//! "why does this site not load", and it was being discarded for exactly the
//! hosts nobody had a theory about yet.
//!
//! ## What this does, and what it deliberately does not
//!
//! It records the outcomes per hostname and says so once, when a host's verdict
//! changes. That is all. It installs nothing, answers no query differently and
//! proposes no rule: a diagnostic that changes behaviour is not a diagnostic.
//! Acting on the finding — asking a second resolver, or offering to route the
//! host the other way — is a separate decision that belongs to the caller.
//!
//! The verdict itself is NOT restated here: it comes from
//! [`nrr_domain::companion_affinity::primary_behavior_from`], the same rule the
//! companion ledger applies, so the two cannot come to disagree about what
//! "stalling" means.
//!
//! ## Bounds
//!
//! Everything learned from traffic is capped and ages out. A host nobody has
//! touched within [`ENTRY_TTL`] is forgotten, and the map never exceeds
//! [`MAX_HOSTS`] — the least recently seen entry gives way. Nothing is
//! persisted: a restart re-learns from the next connection.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nrr_domain::companion_affinity::{primary_behavior_from, PrimaryBehavior, PrimaryHealthEvent};

/// How long a host's outcomes stay meaningful. A front-end pool rotates within
/// hours, and a verdict built from yesterday's addresses describes a path that
/// no longer exists.
pub const ENTRY_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// Most hosts remembered at once. Far above the number a person browses in a
/// TTL window, and the point is only that the map cannot grow with traffic.
pub const MAX_HOSTS: usize = 4096;

/// Whether early teardowns count towards the verdict here.
///
/// They do not, matching the companion ledger's default: a connection killed
/// right after the handshake has causes of its own (a server closing an idle
/// keep-alive), and this registry exists to find the silent-drop case, where
/// nothing answers at all.
const COUNT_CUTS: bool = false;

/// What was seen for one hostname on the main link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tally {
    stalls: u32,
    cuts: u32,
    completions: u32,
    last_seen: Instant,
    /// The verdict already reported, so a steady state is not re-logged on
    /// every packet. `None` until the first report.
    reported: Option<PrimaryBehavior>,
}

impl Tally {
    fn new(now: Instant) -> Self {
        Self {
            stalls: 0,
            cuts: 0,
            completions: 0,
            last_seen: now,
            reported: None,
        }
    }

    fn behavior(&self) -> PrimaryBehavior {
        primary_behavior_from(
            self.completions,
            self.stalls,
            if COUNT_CUTS { self.cuts } else { 0 },
        )
    }
}

/// What one observation changed, so the caller decides whether to say anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StallReport {
    pub hostname: String,
    pub behavior: PrimaryBehavior,
    pub stalls: u32,
    pub completions: u32,
}

/// Per-host outcomes on the main link.
pub struct PrimaryStallRegistry {
    hosts: Mutex<HashMap<String, Tally>>,
    ttl: Duration,
    cap: usize,
}

impl Default for PrimaryStallRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PrimaryStallRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hosts: Mutex::new(HashMap::new()),
            ttl: ENTRY_TTL,
            cap: MAX_HOSTS,
        }
    }

    /// Override the bounds. Builder-style; production keeps the defaults and
    /// only tests narrow them.
    #[must_use]
    pub fn with_bounds(mut self, ttl: Duration, cap: usize) -> Self {
        self.ttl = ttl;
        self.cap = cap.max(1);
        self
    }

    /// Record one outcome. Returns a report ONLY when the host's verdict just
    /// changed — steady state is silent by construction, so a caller that logs
    /// every report cannot flood.
    pub fn note(&self, hostname: &str, event: PrimaryHealthEvent) -> Option<StallReport> {
        self.note_at(hostname, event, Instant::now())
    }

    /// [`Self::note`] with the clock supplied, so ageing is testable without
    /// sleeping.
    pub fn note_at(
        &self,
        hostname: &str,
        event: PrimaryHealthEvent,
        now: Instant,
    ) -> Option<StallReport> {
        if hostname.is_empty() {
            return None;
        }
        let mut hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        Self::expire(&mut hosts, now, self.ttl);

        let entry = hosts
            .entry(hostname.to_string())
            .or_insert_with(|| Tally::new(now));
        // An entry that sat out the window starts over: its counts describe a
        // path the provider has since re-pointed.
        if now.saturating_duration_since(entry.last_seen) >= self.ttl {
            *entry = Tally::new(now);
        }
        entry.last_seen = now;
        match event {
            PrimaryHealthEvent::Stalled => entry.stalls = entry.stalls.saturating_add(1),
            PrimaryHealthEvent::Cut => entry.cuts = entry.cuts.saturating_add(1),
            PrimaryHealthEvent::Completed => {
                entry.completions = entry.completions.saturating_add(1)
            }
        }

        let behavior = entry.behavior();
        let changed = entry.reported != Some(behavior);
        entry.reported = Some(behavior);
        let report = changed.then(|| StallReport {
            hostname: hostname.to_string(),
            behavior,
            stalls: entry.stalls,
            completions: entry.completions,
        });

        // Evict AFTER the entry is updated, so a full map still admits what is
        // new — refusing the newcomer would freeze the set on whatever was seen
        // first.
        Self::evict_to_cap(&mut hosts, self.cap);
        report
    }

    /// Current verdict for a host, for a caller that wants to ask rather than
    /// be told. `Unknown` for anything not remembered.
    #[must_use]
    pub fn behavior_of(&self, hostname: &str) -> PrimaryBehavior {
        self.hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(hostname)
            .map_or(PrimaryBehavior::Unknown, Tally::behavior)
    }

    /// Verdict for `hostname` AND everything under it, merged.
    ///
    /// A rule is written as a suffix, so it carries the whole subtree — and
    /// asking only about the bare name answers a narrower question than the
    /// rule poses. A domain whose apex answers while two of its names are cut
    /// is not a domain the main link carries.
    ///
    /// Merging follows [`PrimaryBehavior::merge`]'s rule, which the companion
    /// ledger already applies to a suffix proposal: one failing member makes
    /// the whole offer failing, and only unanimity the other way makes it work.
    #[must_use]
    pub fn behavior_of_subtree(&self, hostname: &str) -> PrimaryBehavior {
        let suffix = format!(".{hostname}");
        self.hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(host, _)| *host == hostname || host.ends_with(&suffix))
            .map(|(_, tally)| tally.behavior())
            .fold(PrimaryBehavior::Unknown, PrimaryBehavior::merge)
    }

    /// Hosts currently judged to stall, newest sighting first. The diagnostic
    /// answer to "what is not opening right now".
    #[must_use]
    pub fn stalling(&self) -> Vec<String> {
        let hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        let mut rows: Vec<(&String, &Tally)> = hosts
            .iter()
            .filter(|(_, t)| t.behavior() == PrimaryBehavior::Stalls)
            .collect();
        rows.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen));
        rows.into_iter().map(|(h, _)| h.clone()).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn expire(hosts: &mut HashMap<String, Tally>, now: Instant, ttl: Duration) {
        hosts.retain(|_, t| now.saturating_duration_since(t.last_seen) < ttl);
    }

    fn evict_to_cap(hosts: &mut HashMap<String, Tally>, cap: usize) {
        while hosts.len() > cap {
            let Some(oldest) = hosts
                .iter()
                .min_by_key(|(_, t)| t.last_seen)
                .map(|(h, _)| h.clone())
            else {
                return;
            };
            hosts.remove(&oldest);
        }
    }
}

/// Say what changed, once per transition.
///
/// `info`, not `warn`: a host that does not open is a fact about the network,
/// not a fault of ours, and a warning the user cannot act on is noise. The
/// registry only hands out a report when the verdict actually moved, so this
/// cannot repeat while the state holds.
pub fn log_report(report: &StallReport) {
    match report.behavior {
        PrimaryBehavior::Stalls => tracing::info!(
            target: "nrr::primary-stall",
            hostname = %report.hostname,
            stalls = report.stalls,
            "destination does not answer on the main link — connections start and nothing comes back",
        ),
        PrimaryBehavior::Cut => tracing::info!(
            target: "nrr::primary-stall",
            hostname = %report.hostname,
            "destination is answered and then cut on the main link",
        ),
        PrimaryBehavior::Responds => tracing::debug!(
            target: "nrr::primary-stall",
            hostname = %report.hostname,
            completions = report.completions,
            "destination answers on the main link",
        ),
        PrimaryBehavior::Unknown => tracing::debug!(
            target: "nrr::primary-stall",
            hostname = %report.hostname,
            stalls = report.stalls,
            completions = report.completions,
            "destination's outcomes on the main link now point both ways",
        ),
    }
}

/// Process-wide registry.
///
/// The observer consumer and any future reader live in different runtime build
/// functions; the service is one process and this is process-global evidence,
/// so a `OnceLock` singleton is the wiring, exactly as
/// [`crate::recent_rule_addresses`] does it. Tests construct
/// [`PrimaryStallRegistry`] directly and never touch this.
pub fn global_primary_stalls() -> std::sync::Arc<PrimaryStallRegistry> {
    static GLOBAL: std::sync::OnceLock<std::sync::Arc<PrimaryStallRegistry>> =
        std::sync::OnceLock::new();
    GLOBAL
        .get_or_init(|| std::sync::Arc::new(PrimaryStallRegistry::new()))
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stall(reg: &PrimaryStallRegistry, host: &str, times: u32) -> Option<StallReport> {
        let mut last = None;
        for _ in 0..times {
            last = reg.note(host, PrimaryHealthEvent::Stalled);
        }
        last
    }

    #[test]
    fn a_host_that_only_stalls_is_reported_once_the_evidence_is_in() {
        // The case this exists for: connections start and nothing comes back,
        // repeatedly, and nothing else ever completes.
        let reg = PrimaryStallRegistry::new();
        assert!(
            stall(&reg, "translate.example.ru", 2).is_none(),
            "one or two is not evidence"
        );
        let report = stall(&reg, "translate.example.ru", 1).expect("the third confirms it");
        assert_eq!(report.behavior, PrimaryBehavior::Stalls);
        assert_eq!(report.stalls, 3);
        assert_eq!(reg.stalling(), vec!["translate.example.ru".to_string()]);
    }

    #[test]
    fn a_steady_verdict_is_reported_once_not_on_every_packet() {
        // A report per observation would bury the log the moment a site is
        // genuinely down — which is exactly when the log has to stay readable.
        let reg = PrimaryStallRegistry::new();
        stall(&reg, "host.example", 3).expect("first verdict");
        for _ in 0..50 {
            assert!(
                reg.note("host.example", PrimaryHealthEvent::Stalled)
                    .is_none(),
                "the same verdict must not be re-reported"
            );
        }
    }

    #[test]
    fn a_host_that_recovers_is_reported_again() {
        // The transition back matters as much: it is what tells the reader the
        // path healed rather than the evidence ageing out.
        let reg = PrimaryStallRegistry::new();
        stall(&reg, "host.example", 3).expect("stalls");
        // A completion alone leaves the evidence pointing both ways.
        let mixed = reg
            .note("host.example", PrimaryHealthEvent::Completed)
            .expect("verdict changed");
        assert_eq!(mixed.behavior, PrimaryBehavior::Unknown);
    }

    /// A rule is written as a suffix, so the question it poses is about the
    /// whole subtree. The field case: the apex and `www` answered while two
    /// other names under the domain were cut, and asking only about the apex
    /// would have called that domain healthy.
    #[test]
    fn a_domain_is_judged_by_everything_under_it() {
        let reg = PrimaryStallRegistry::new();
        reg.note("talk.example", PrimaryHealthEvent::Completed);
        reg.note("www.talk.example", PrimaryHealthEvent::Completed);
        assert_eq!(
            reg.behavior_of_subtree("talk.example"),
            PrimaryBehavior::Responds,
        );

        stall(&reg, "forum.talk.example", 3).expect("stalls");
        assert_eq!(
            reg.behavior_of_subtree("talk.example"),
            PrimaryBehavior::Stalls,
            "one cut name settles the domain",
        );
        // The bare name is unchanged — the two questions are different.
        assert_eq!(reg.behavior_of("talk.example"), PrimaryBehavior::Responds,);
        // And a neighbour that merely ENDS with the same letters is not under
        // it: only a dot-separated label boundary counts.
        stall(&reg, "nottalk.example", 3).expect("stalls");
        assert_eq!(
            reg.behavior_of_subtree("anything.example"),
            PrimaryBehavior::Unknown
        );
    }

    #[test]
    fn a_host_that_completes_is_never_called_stalling() {
        let reg = PrimaryStallRegistry::new();
        let report = reg
            .note("good.example", PrimaryHealthEvent::Completed)
            .expect("first verdict");
        assert_eq!(report.behavior, PrimaryBehavior::Responds);
        assert!(reg.stalling().is_empty());
    }

    #[test]
    fn evidence_ages_out_so_a_rotated_pool_is_judged_afresh() {
        // A verdict built from addresses the provider has since re-pointed
        // describes a path that no longer exists.
        let reg = PrimaryStallRegistry::new().with_bounds(Duration::from_secs(60), 64);
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.note_at("host.example", PrimaryHealthEvent::Stalled, t0);
        }
        assert_eq!(reg.behavior_of("host.example"), PrimaryBehavior::Stalls);

        let later = t0 + Duration::from_secs(61);
        reg.note_at("host.example", PrimaryHealthEvent::Stalled, later);
        assert_eq!(
            reg.behavior_of("host.example"),
            PrimaryBehavior::Unknown,
            "the stale counts must not carry the verdict forward"
        );
    }

    #[test]
    fn the_map_is_bounded_and_the_oldest_gives_way() {
        let reg = PrimaryStallRegistry::new().with_bounds(Duration::from_secs(3600), 2);
        let t0 = Instant::now();
        reg.note_at("a.example", PrimaryHealthEvent::Stalled, t0);
        reg.note_at(
            "b.example",
            PrimaryHealthEvent::Stalled,
            t0 + Duration::from_secs(1),
        );
        reg.note_at(
            "c.example",
            PrimaryHealthEvent::Stalled,
            t0 + Duration::from_secs(2),
        );

        assert_eq!(reg.len(), 2);
        assert_eq!(
            reg.behavior_of("a.example"),
            PrimaryBehavior::Unknown,
            "the least recently seen host gave way"
        );
    }

    #[test]
    fn an_unnamed_destination_is_not_recorded() {
        let reg = PrimaryStallRegistry::new();
        assert!(reg.note("", PrimaryHealthEvent::Stalled).is_none());
        assert!(reg.is_empty());
    }
}

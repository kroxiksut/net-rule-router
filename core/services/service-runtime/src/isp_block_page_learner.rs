//! Learning an operator's notice page from what the resolver already sees.
//!
//! The shipped table ([`nrr_domain::isp_block_pages`]) is a seed: an operator
//! renames its page whenever it likes, and a release per rename is not a plan.
//! What gives a notice page away is its company — it is resolved right after
//! MANY DIFFERENT hosts that no rule covers, because it is where each of them
//! ends up. An ordinary neighbour on a page follows one site, not fifty.
//!
//! Counting DISTINCT predecessors is the whole point: a hundred visits to one
//! broken site must never promote whatever it loads next.
//!
//! Nothing here decides routing. It answers "is this host a notice page", and
//! the suggestion layer decides what that is worth.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many distinct rule-less hosts must precede a candidate before it counts
/// as a notice page.
pub const DEFAULT_MIN_DISTINCT_PREDECESSORS: usize = 4;

/// How long after a rule-less host a resolution still counts as "right after"
/// it. A redirect to a notice page arrives within a page load.
pub const DEFAULT_PAIRING_WINDOW: Duration = Duration::from_secs(10);

/// How long a candidate keeps the evidence gathered for it. Evidence that
/// stopped accumulating describes an operator setup that no longer exists.
pub const DEFAULT_EVIDENCE_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// Cap on tracked candidates. Reaching it stops new candidates, never evicts a
/// learned page — the failure mode is "learns nothing new", not "forgets".
pub const DEFAULT_CANDIDATE_CAP: usize = 256;

/// Tunables, so a test can reach a verdict without waiting hours.
#[derive(Clone, Copy, Debug)]
pub struct BlockPageLearnerConfig {
    pub min_distinct_predecessors: usize,
    pub pairing_window: Duration,
    pub evidence_ttl: Duration,
    pub candidate_cap: usize,
}

impl Default for BlockPageLearnerConfig {
    fn default() -> Self {
        Self {
            min_distinct_predecessors: DEFAULT_MIN_DISTINCT_PREDECESSORS,
            pairing_window: DEFAULT_PAIRING_WINDOW,
            evidence_ttl: DEFAULT_EVIDENCE_TTL,
            candidate_cap: DEFAULT_CANDIDATE_CAP,
        }
    }
}

/// One name lookup, as the learner needs to see it.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedHost<'a> {
    pub hostname: &'a str,
    /// A rule of the user's covers this host. Such a host is never a notice
    /// page — otherwise the product would eventually accuse its own routing.
    pub rule_covered: bool,
}

/// A host the learner accepted as a notice page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearnedBlockPage {
    pub host: String,
    /// Distinct rule-less hosts seen immediately before it.
    pub distinct_predecessors: usize,
}

/// What one resolution produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockPageObservation {
    /// Set when THIS observation crossed the threshold, so the caller logs a
    /// newly learned page once rather than on every later sighting.
    pub learned: Option<LearnedBlockPage>,
    /// The host the operator answered for: a notice page was resolved right
    /// after it. This is the site worth offering to route.
    pub blocked_host: Option<String>,
    /// The notice page that named it — diagnostics only.
    pub notice_page: Option<String>,
}

impl BlockPageObservation {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.learned.is_none() && self.blocked_host.is_none()
    }
}

struct Candidate {
    predecessors: HashSet<String>,
    last_seen: Instant,
    learned: bool,
    /// Seen resolved on its own, with no rule-less host in front of it. An
    /// operator's notice page is only ever reached BY being redirected to;
    /// something that also comes up by itself is ordinary background traffic
    /// that merely happens to follow a lot of other names.
    seen_alone: bool,
}

struct State {
    /// Most recent rule-less host and when it was resolved.
    last_rule_less: Option<(String, Instant)>,
    candidates: HashMap<String, Candidate>,
}

/// Session-scoped learner. Cheap to query: a hit on the seed table or one map
/// lookup, no allocation on the hot path.
pub struct IspBlockPageLearner {
    config: BlockPageLearnerConfig,
    state: Mutex<State>,
}

impl Default for IspBlockPageLearner {
    fn default() -> Self {
        Self::new(BlockPageLearnerConfig::default())
    }
}

impl IspBlockPageLearner {
    #[must_use]
    pub fn new(config: BlockPageLearnerConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                last_rule_less: None,
                candidates: HashMap::new(),
            }),
        }
    }

    /// Feed one resolution.
    pub fn observe(&self, host: ResolvedHost<'_>, now: Instant) -> BlockPageObservation {
        let mut out = BlockPageObservation::default();
        let hostname = normalize(host.hostname);
        if hostname.is_empty() {
            return out;
        }
        let seeded = nrr_domain::isp_block_pages::is_block_page_hostname(&hostname);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());

        // A rule-covered host is only ever a predecessor candidate's context;
        // it can never become a notice page itself.
        if host.rule_covered {
            state.last_rule_less = None;
            return out;
        }

        let predecessor = state.last_rule_less.take().and_then(|(prev, at)| {
            let fresh = now.saturating_duration_since(at) <= self.config.pairing_window;
            // Same site on both sides is a page loading its own subdomain, not
            // a redirect to an operator.
            (fresh && !same_site(&prev, &hostname)).then_some(prev)
        });
        state.last_rule_less = Some((hostname.clone(), now));

        let Some(predecessor) = predecessor else {
            // Resolved with nothing in front of it. Whatever this host is, it
            // is not only reachable by redirect — so it is not a notice page,
            // and any evidence collected for it was coincidence. This is what
            // told `beacons.gcp.gvt2.com` apart from an operator's page: both
            // follow many different names, only one of them also stands alone.
            if let Some(entry) = state.candidates.get_mut(&hostname) {
                entry.seen_alone = true;
                entry.learned = false;
            }
            return out;
        };
        let threshold = self.config.min_distinct_predecessors;
        let cap = self.config.candidate_cap;
        let ttl = self.config.evidence_ttl;
        Self::expire(&mut state, now, ttl);

        let known = state.candidates.contains_key(&hostname);
        if known || state.candidates.len() < cap {
            let entry = state
                .candidates
                .entry(hostname.clone())
                .or_insert(Candidate {
                    predecessors: HashSet::new(),
                    last_seen: now,
                    learned: false,
                    seen_alone: false,
                });
            entry.last_seen = now;
            entry.predecessors.insert(predecessor.clone());
            // Platform telemetry follows everything the machine does, so the
            // distinct-predecessor count says nothing about it. No operator
            // serves its notice page from one of these zones.
            let disqualified = entry.seen_alone
                || crate::fake_ip::self_heal::is_platform_infrastructure(&hostname);
            if disqualified {
                entry.learned = false;
            } else if !entry.learned && entry.predecessors.len() >= threshold {
                entry.learned = true;
                out.learned = Some(LearnedBlockPage {
                    host: hostname.clone(),
                    distinct_predecessors: entry.predecessors.len(),
                });
            }
        }

        // A page we already recognise names its predecessor as blocked right
        // away — the seed exists exactly so the first victim is not wasted.
        let recognised = seeded || state.candidates.get(&hostname).is_some_and(|c| c.learned);
        if recognised {
            out.blocked_host = Some(predecessor);
            out.notice_page = Some(hostname);
        }
        out
    }

    /// Is `hostname` a notice page — shipped seed or learned here?
    #[must_use]
    pub fn is_block_page(&self, hostname: &str) -> bool {
        if nrr_domain::isp_block_pages::is_block_page_hostname(hostname) {
            return true;
        }
        let host = normalize(hostname);
        if host.is_empty() {
            return false;
        }
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .candidates
            .get(&host)
            .is_some_and(|c| c.learned)
    }

    /// Everything learned this session, for diagnostics.
    #[must_use]
    pub fn learned(&self) -> Vec<LearnedBlockPage> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<LearnedBlockPage> = state
            .candidates
            .iter()
            .filter(|(_, c)| c.learned)
            .map(|(host, c)| LearnedBlockPage {
                host: host.clone(),
                distinct_predecessors: c.predecessors.len(),
            })
            .collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }

    /// Drop candidates whose evidence went stale. A learned page is kept: it
    /// earned its place, and re-learning it costs another threshold of drops.
    fn expire(state: &mut State, now: Instant, ttl: Duration) {
        state
            .candidates
            .retain(|_, c| c.learned || now.saturating_duration_since(c.last_seen) <= ttl);
    }
}

/// Process-wide learner, so the resolver's observer and any reader of the
/// learned set look at one instance. Same singleton rationale as
/// `global_recent_rule_addresses`.
pub fn global_isp_block_page_learner() -> std::sync::Arc<IspBlockPageLearner> {
    static LEARNER: std::sync::OnceLock<std::sync::Arc<IspBlockPageLearner>> =
        std::sync::OnceLock::new();
    std::sync::Arc::clone(
        LEARNER.get_or_init(|| std::sync::Arc::new(IspBlockPageLearner::default())),
    )
}

/// Sink for a host an operator answered for. Production hands it to the
/// suggestion journal; `None` keeps the detector diagnostic-only.
pub type BlockedHostSinkFn = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

/// [`crate::dns_listener::ResolutionObserver`] that feeds the learner and
/// reports what an operator page named.
pub struct LearningResolutionObserver {
    learner: std::sync::Arc<IspBlockPageLearner>,
    blocked_host_sink: Option<BlockedHostSinkFn>,
}

impl LearningResolutionObserver {
    #[must_use]
    pub fn new(learner: std::sync::Arc<IspBlockPageLearner>) -> Self {
        Self {
            learner,
            blocked_host_sink: None,
        }
    }

    /// Report hosts an operator page named: `(blocked host, notice page)`.
    #[must_use]
    pub fn with_blocked_host_sink(mut self, sink: BlockedHostSinkFn) -> Self {
        self.blocked_host_sink = Some(sink);
        self
    }
}

impl crate::dns_listener::ResolutionObserver for LearningResolutionObserver {
    fn note_resolution(&self, hostname: &str, rule_covered: bool) {
        let seen = self.learner.observe(
            ResolvedHost {
                hostname,
                rule_covered,
            },
            Instant::now(),
        );
        if let Some(learned) = seen.learned.as_ref() {
            tracing::info!(
                target: "nrr::dns-resolver",
                page = %learned.host,
                distinct_predecessors = learned.distinct_predecessors,
                "learned an operator notice page — it kept answering for different sites no rule covers",
            );
        }
        let (Some(blocked), Some(page)) = (seen.blocked_host.as_ref(), seen.notice_page.as_ref())
        else {
            return;
        };
        tracing::info!(
            target: "nrr::dns-resolver",
            host = %blocked,
            page = %page,
            "the operator answered for this host with its notice page — the site is blocked upstream, not broken",
        );
        if let Some(sink) = self.blocked_host_sink.as_ref() {
            sink(blocked, page);
        }
    }
}

fn normalize(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Do both names belong to one site? Compared on the last two labels, which is
/// enough to tell `cdn.example.com` from `warning.rt.ru` without a public-suffix
/// list — the cost of being wrong is one missed candidate, not a wrong route.
fn same_site(left: &str, right: &str) -> bool {
    registrable_tail(left) == registrable_tail(right)
}

fn registrable_tail(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let take = labels.len().min(2);
    labels[labels.len() - take..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(threshold: usize) -> BlockPageLearnerConfig {
        BlockPageLearnerConfig {
            min_distinct_predecessors: threshold,
            ..BlockPageLearnerConfig::default()
        }
    }

    fn rule_less(hostname: &str) -> ResolvedHost<'_> {
        ResolvedHost {
            hostname,
            rule_covered: false,
        }
    }

    fn covered(hostname: &str) -> ResolvedHost<'_> {
        ResolvedHost {
            hostname,
            rule_covered: true,
        }
    }

    /// One blocked site followed by the operator's page.
    fn visit(
        learner: &IspBlockPageLearner,
        site: &str,
        page: &str,
        at: Instant,
    ) -> BlockPageObservation {
        learner.observe(rule_less(site), at);
        learner.observe(rule_less(page), at + Duration::from_secs(1))
    }

    #[test]
    fn a_host_that_also_resolves_on_its_own_is_never_a_notice_page() {
        // The 0811 false match: `beacons.gcp.gvt2.com` follows many different
        // names, exactly like an operator's page — but it also comes up by
        // itself, and a notice page is only ever arrived at.
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        visit(&learner, "one.example", "beacon.telemetry.test", t0);
        // A resolution with nothing fresh in front of it (the pairing window
        // has long passed).
        learner.observe(
            rule_less("beacon.telemetry.test"),
            t0 + Duration::from_secs(600),
        );
        let after = visit(
            &learner,
            "two.example",
            "beacon.telemetry.test",
            t0 + Duration::from_secs(700),
        );
        assert!(after.learned.is_none(), "must not be promoted");
        assert!(after.blocked_host.is_none(), "must accuse nobody");
        assert!(!learner.is_block_page("beacon.telemetry.test"));
    }

    #[test]
    fn platform_telemetry_is_never_a_notice_page() {
        // A named platform zone is refused outright, without waiting for the
        // stands-alone evidence above to arrive.
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        visit(&learner, "one.example", "collect.app-measurement.com", t0);
        let after = visit(
            &learner,
            "two.example",
            "collect.app-measurement.com",
            t0 + Duration::from_secs(60),
        );
        assert!(after.learned.is_none());
        assert!(!learner.is_block_page("collect.app-measurement.com"));
    }

    #[test]
    fn a_page_that_follows_enough_different_sites_is_learned() {
        let learner = IspBlockPageLearner::new(cfg(3));
        let t0 = Instant::now();
        assert!(visit(&learner, "one.example", "notice.isp.test", t0)
            .learned
            .is_none());
        assert!(visit(
            &learner,
            "two.example",
            "notice.isp.test",
            t0 + Duration::from_secs(60)
        )
        .learned
        .is_none());
        let learned = visit(
            &learner,
            "three.example",
            "notice.isp.test",
            t0 + Duration::from_secs(120),
        )
        .learned
        .expect("third distinct predecessor crosses the threshold");

        assert_eq!(learned.host, "notice.isp.test");
        assert_eq!(learned.distinct_predecessors, 3);
        assert!(learner.is_block_page("notice.isp.test"));
        // Reported once, not on every later sighting.
        assert!(visit(
            &learner,
            "four.example",
            "notice.isp.test",
            t0 + Duration::from_secs(180)
        )
        .learned
        .is_none());
    }

    #[test]
    fn one_site_visited_many_times_never_promotes_its_neighbour() {
        // The whole reason the threshold counts DISTINCT predecessors.
        let learner = IspBlockPageLearner::new(cfg(3));
        let t0 = Instant::now();
        for i in 0..25 {
            let at = t0 + Duration::from_secs(i * 30);
            assert!(visit(&learner, "broken.example", "tracker.other.test", at).is_empty());
        }
        assert!(!learner.is_block_page("tracker.other.test"));
        assert!(learner.learned().is_empty());
    }

    #[test]
    fn a_host_the_user_routes_is_never_learned() {
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        learner.observe(rule_less("one.example"), t0);
        learner.observe(covered("my.routed.site"), t0 + Duration::from_secs(1));
        learner.observe(rule_less("two.example"), t0 + Duration::from_secs(2));
        learner.observe(covered("my.routed.site"), t0 + Duration::from_secs(3));

        assert!(!learner.is_block_page("my.routed.site"));
    }

    #[test]
    fn a_subdomain_of_the_same_site_is_not_evidence() {
        // A page loading its own CDN host is ordinary company, not a redirect.
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        learner.observe(rule_less("shop.example.com"), t0);
        learner.observe(rule_less("cdn.example.com"), t0 + Duration::from_secs(1));
        learner.observe(rule_less("www.example.com"), t0 + Duration::from_secs(2));
        learner.observe(rule_less("cdn.example.com"), t0 + Duration::from_secs(3));

        assert!(!learner.is_block_page("cdn.example.com"));
    }

    #[test]
    fn a_resolution_outside_the_pairing_window_is_not_evidence() {
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        learner.observe(rule_less("one.example"), t0);
        learner.observe(rule_less("notice.isp.test"), t0 + Duration::from_secs(300));
        learner.observe(rule_less("two.example"), t0 + Duration::from_secs(600));
        learner.observe(rule_less("notice.isp.test"), t0 + Duration::from_secs(900));

        assert!(!learner.is_block_page("notice.isp.test"));
    }

    #[test]
    fn a_seeded_page_names_its_predecessor_on_the_very_first_sighting() {
        // The field case: youporn.com, then the operator's page. No learning
        // needed — the seed is there so the first victim is not wasted.
        let learner = IspBlockPageLearner::default();
        let t0 = Instant::now();
        learner.observe(rule_less("youporn.com"), t0);
        let seen = learner.observe(rule_less("fz139.ttk.ru"), t0 + Duration::from_secs(1));

        assert_eq!(seen.blocked_host.as_deref(), Some("youporn.com"));
        assert_eq!(seen.notice_page.as_deref(), Some("fz139.ttk.ru"));
        assert!(seen.learned.is_none(), "a seeded page is not 'learned'");
    }

    #[test]
    fn a_learned_page_names_predecessors_from_then_on() {
        let learner = IspBlockPageLearner::new(cfg(2));
        let t0 = Instant::now();
        visit(&learner, "one.example", "notice.isp.test", t0);
        let crossing = visit(
            &learner,
            "two.example",
            "notice.isp.test",
            t0 + Duration::from_secs(60),
        );
        assert!(crossing.learned.is_some());
        assert_eq!(crossing.blocked_host.as_deref(), Some("two.example"));

        let later = visit(
            &learner,
            "three.example",
            "notice.isp.test",
            t0 + Duration::from_secs(120),
        );
        assert!(later.learned.is_none(), "learned is reported once");
        assert_eq!(later.blocked_host.as_deref(), Some("three.example"));
    }

    #[test]
    fn an_unrecognised_host_names_nobody() {
        let learner = IspBlockPageLearner::new(cfg(5));
        let t0 = Instant::now();
        let seen = visit(&learner, "one.example", "ordinary.test", t0);
        assert!(seen.blocked_host.is_none());
        assert!(seen.is_empty());
    }

    #[test]
    fn the_shipped_seed_answers_without_any_observation() {
        let learner = IspBlockPageLearner::default();
        assert!(learner.is_block_page("fz139.ttk.ru"));
        assert!(learner.is_block_page("FZ139.TTK.RU."));
        assert!(!learner.is_block_page("example.com"));
    }

    #[test]
    fn stale_evidence_expires_but_a_learned_page_stays() {
        let mut config = cfg(2);
        config.evidence_ttl = Duration::from_secs(60);
        let learner = IspBlockPageLearner::new(config);
        let t0 = Instant::now();

        // One predecessor, then a long silence — the evidence is dropped.
        visit(&learner, "one.example", "candidate.test", t0);
        visit(
            &learner,
            "two.example",
            "candidate.test",
            t0 + Duration::from_secs(3600),
        );
        assert!(
            !learner.is_block_page("candidate.test"),
            "evidence did not carry over the gap"
        );

        // Two predecessors inside the window do learn it, and it survives.
        let t1 = t0 + Duration::from_secs(7200);
        visit(&learner, "three.example", "learned.test", t1);
        visit(
            &learner,
            "four.example",
            "learned.test",
            t1 + Duration::from_secs(10),
        );
        assert!(learner.is_block_page("learned.test"));
        visit(
            &learner,
            "five.example",
            "other.test",
            t1 + Duration::from_secs(99999),
        );
        assert!(
            learner.is_block_page("learned.test"),
            "a learned page is never expired"
        );
    }

    #[test]
    fn the_candidate_cap_stops_growth_without_losing_what_was_learned() {
        let mut config = cfg(2);
        config.candidate_cap = 2;
        let learner = IspBlockPageLearner::new(config);
        let t0 = Instant::now();

        visit(&learner, "a.example", "first.test", t0);
        visit(
            &learner,
            "b.example",
            "first.test",
            t0 + Duration::from_secs(1),
        );
        assert!(learner.is_block_page("first.test"));

        visit(
            &learner,
            "c.example",
            "second.test",
            t0 + Duration::from_secs(2),
        );
        // Cap reached: a third candidate is refused outright.
        visit(
            &learner,
            "d.example",
            "third.test",
            t0 + Duration::from_secs(3),
        );
        visit(
            &learner,
            "e.example",
            "third.test",
            t0 + Duration::from_secs(4),
        );
        assert!(!learner.is_block_page("third.test"));
        assert!(learner.is_block_page("first.test"));
    }
}

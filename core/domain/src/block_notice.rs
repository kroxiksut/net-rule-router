//! Block notices — turning a stream of blocked packets into something a person
//! can read.
//!
//! Enforcement blocks per connection attempt, and a blocked application retries
//! hard: one acceptance run showed 211 drops from a single messenger in fifteen
//! seconds. Notifying per drop would be unusable, so this module folds attempts
//! into **episodes**: one (destination, application, reason) triple is one
//! notice, however many times it is retried, and the retry count rides along as
//! evidence rather than as more notices.
//!
//! A notice fires on the FIRST attempt of an episode, not once the episode
//! settles: the user is staring at a page that will not load, and a notice that
//! waits for quiet arrives after they have given up. Later attempts of the same
//! episode only update its counters.
//!
//! Muting lives here too, because "should this be shown" is policy, not
//! mechanism: the same answer must hold for the tray, the notification centre
//! and any future surface. Four scopes, deliberately no more — one host, one
//! application, one reason, or block notices as a class — each either for a
//! while or for good.
//!
//! Pure and I/O-free by construction: the caller supplies the clock, the caller
//! persists the mutes. That keeps the storm-control rules testable without a
//! network stack, which is the whole reason they are worth having.

use std::collections::HashMap;

/// How long a quiet destination keeps its episode open. A retry after this
/// gap is a new episode and earns a fresh notice — the user has had time to
/// move on and the block is news again.
pub const DEFAULT_EPISODE_GAP_MS: u64 = 60_000;

/// Cap on tracked episodes. Bounded memory beats completeness: on overflow the
/// coldest episode is dropped, costing at most one repeated notice.
pub const DEFAULT_MAX_EPISODES: usize = 256;

/// Why a connection was blocked. Drives the wording, and the wording is the
/// difference between "we protected you" and "something is broken".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BlockReason {
    /// The route this host is pinned to is down, so letting it out would leak.
    RouteUnavailable,
    /// The application is confined to a route and no rule covers this host.
    NotCoveredByRules,
    /// A rule says block outright.
    BlockedByRule,
    /// Ours, but the filter behind it could not be identified. Naming a cause
    /// here would send the user editing rules that may have nothing to do with
    /// it — say only what is known.
    Unattributed,
}

impl BlockReason {
    /// Stable slug for the wire and for locale keys.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::RouteUnavailable => "route-unavailable",
            Self::NotCoveredByRules => "not-covered-by-rules",
            Self::BlockedByRule => "blocked-by-rule",
            Self::Unattributed => "unattributed",
        }
    }

    /// Inverse of [`Self::slug`]; `None` for anything else.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "route-unavailable" => Some(Self::RouteUnavailable),
            "not-covered-by-rules" => Some(Self::NotCoveredByRules),
            "blocked-by-rule" => Some(Self::BlockedByRule),
            "unattributed" => Some(Self::Unattributed),
            _ => None,
        }
    }
}

/// What a mute applies to.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MuteScope {
    /// One destination, by the name shown to the user.
    Host(String),
    /// Every block from one application, by image name.
    App(String),
    /// Every block that happened for one reason. "Tell me when a rule blocks
    /// something, but not every time the tunnel drops" is a distinct wish from
    /// silencing a host or an application, and neither of those can express it.
    Reason(BlockReason),
    /// Block notices as a whole.
    All,
}

/// One mute: a scope plus how long it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mute {
    pub scope: MuteScope,
    /// Wall-clock ms after which the mute lapses; `None` means indefinitely.
    pub until_ms: Option<u64>,
}

impl Mute {
    /// Mute that never lapses on its own.
    #[must_use]
    pub fn forever(scope: MuteScope) -> Self {
        Self {
            scope,
            until_ms: None,
        }
    }

    /// Mute that lapses at `until_ms`.
    #[must_use]
    pub fn until(scope: MuteScope, until_ms: u64) -> Self {
        Self {
            scope,
            until_ms: Some(until_ms),
        }
    }

    /// Is this mute still in force at `now_ms`?
    #[must_use]
    pub fn holds_at(&self, now_ms: u64) -> bool {
        self.until_ms.is_none_or(|until| now_ms < until)
    }
}

/// One blocked connection attempt, as enforcement saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockAttempt {
    /// Destination name when known; the address is the fallback identity.
    pub host: Option<String>,
    /// Destination address, always known.
    pub dest: String,
    /// Image name of the process that tried, when known.
    pub app: Option<String>,
    pub reason: BlockReason,
}

impl BlockAttempt {
    /// What the user is told the destination is.
    #[must_use]
    pub fn destination_label(&self) -> &str {
        self.host.as_deref().unwrap_or(&self.dest)
    }

    fn key(&self) -> EpisodeKey {
        // A route that is down is ONE fact, not one per address: everything
        // bound to it fails at once, and the user has a single thing to do
        // about it. Keying that reason by host would turn one outage into a
        // stream of popups saying the same sentence.
        if self.reason == BlockReason::RouteUnavailable {
            return EpisodeKey {
                destination: String::new(),
                app: String::new(),
                reason: self.reason,
            };
        }
        EpisodeKey {
            destination: self.destination_label().to_owned(),
            app: self.app.clone().unwrap_or_default(),
            reason: self.reason,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct EpisodeKey {
    destination: String,
    app: String,
    reason: BlockReason,
}

/// An episode ready to be shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockNotice {
    pub destination: String,
    /// Empty when the owning process could not be determined.
    pub app: String,
    pub reason: BlockReason,
    pub first_attempt_ms: u64,
    pub attempts: u32,
}

#[derive(Clone, Debug)]
struct EpisodeState {
    last_attempt_ms: u64,
    attempts: u32,
}

/// Folds attempts into episodes and answers "show this?".
#[derive(Debug)]
pub struct BlockNoticeLedger {
    episodes: HashMap<EpisodeKey, EpisodeState>,
    mutes: Vec<Mute>,
    episode_gap_ms: u64,
    max_episodes: usize,
}

impl Default for BlockNoticeLedger {
    fn default() -> Self {
        Self::new(DEFAULT_EPISODE_GAP_MS, DEFAULT_MAX_EPISODES)
    }
}

impl BlockNoticeLedger {
    #[must_use]
    pub fn new(episode_gap_ms: u64, max_episodes: usize) -> Self {
        Self {
            episodes: HashMap::new(),
            mutes: Vec::new(),
            episode_gap_ms,
            max_episodes: max_episodes.max(1),
        }
    }

    /// Replace the mute set — the caller owns persistence and reloads it here.
    pub fn set_mutes(&mut self, mutes: Vec<Mute>) {
        self.mutes = mutes;
    }

    /// Mutes still in force at `now_ms`, for showing the user what they silenced.
    #[must_use]
    pub fn active_mutes(&self, now_ms: u64) -> Vec<&Mute> {
        self.mutes.iter().filter(|m| m.holds_at(now_ms)).collect()
    }

    /// Record one blocked attempt. Returns a notice only when this attempt opens
    /// a NEW episode and nothing mutes it; a retry of a live episode returns
    /// `None` after counting.
    pub fn record(&mut self, now_ms: u64, attempt: &BlockAttempt) -> Option<BlockNotice> {
        let key = attempt.key();
        let opens_episode = match self.episodes.get(&key) {
            Some(state) => now_ms.saturating_sub(state.last_attempt_ms) > self.episode_gap_ms,
            None => true,
        };

        if opens_episode {
            self.evict_if_full(&key);
            self.episodes.insert(
                key.clone(),
                EpisodeState {
                    last_attempt_ms: now_ms,
                    attempts: 1,
                },
            );
        } else if let Some(state) = self.episodes.get_mut(&key) {
            state.last_attempt_ms = now_ms;
            state.attempts = state.attempts.saturating_add(1);
        }

        // Muted attempts are still counted — the history stays honest, only the
        // popup is withheld. Checked after counting for exactly that reason.
        if !opens_episode || self.is_muted(now_ms, attempt) {
            return None;
        }
        // Built from the attempt, not the key: a collapsed episode carries no
        // host in its key, but the notice still names the address that opened
        // it as the concrete example.
        Some(BlockNotice {
            destination: attempt.destination_label().to_owned(),
            app: attempt.app.clone().unwrap_or_default(),
            reason: attempt.reason,
            first_attempt_ms: now_ms,
            attempts: 1,
        })
    }

    /// Forget every episode about `destination`, whichever app or reason it was
    /// filed under. Returns how many were dropped.
    ///
    /// The user acted on the notice — routed the host, say — so the question it
    /// asked is answered. Keeping the episode would leave the notice standing
    /// after its own resolution, and let a drop that arrives before the new
    /// policy lands look like the same unanswered problem.
    pub fn resolve_destination(&mut self, destination: &str) -> usize {
        let wanted = destination
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if wanted.is_empty() {
            return 0;
        }
        let before = self.episodes.len();
        self.episodes
            .retain(|key, _| key.destination.trim_end_matches('.').to_ascii_lowercase() != wanted);
        before - self.episodes.len()
    }

    /// Attempts counted for a live episode, for enriching a notice already shown.
    #[must_use]
    pub fn attempts_so_far(&self, attempt: &BlockAttempt) -> u32 {
        self.episodes
            .get(&attempt.key())
            .map_or(0, |state| state.attempts)
    }

    fn is_muted(&self, now_ms: u64, attempt: &BlockAttempt) -> bool {
        self.mutes.iter().filter(|m| m.holds_at(now_ms)).any(|m| {
            match &m.scope {
                MuteScope::All => true,
                MuteScope::Host(h) => h == attempt.destination_label(),
                // An unknown app matches no app-scoped mute: silencing "the
                // process we could not name" would silence unrelated blocks.
                MuteScope::App(a) => attempt.app.as_deref() == Some(a.as_str()),
                MuteScope::Reason(r) => *r == attempt.reason,
            }
        })
    }

    fn evict_if_full(&mut self, incoming: &EpisodeKey) {
        if self.episodes.len() < self.max_episodes || self.episodes.contains_key(incoming) {
            return;
        }
        let coldest = self
            .episodes
            .iter()
            .min_by_key(|(_, state)| state.last_attempt_ms)
            .map(|(key, _)| key.clone());
        if let Some(key) = coldest {
            self.episodes.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(host: &str, app: &str) -> BlockAttempt {
        BlockAttempt {
            host: Some(host.to_owned()),
            dest: "203.0.113.7".to_owned(),
            app: Some(app.to_owned()),
            reason: BlockReason::NotCoveredByRules,
        }
    }

    #[test]
    fn a_retrying_application_is_one_notice_not_a_storm() {
        let mut ledger = BlockNoticeLedger::default();
        let a = attempt("cdn.example", "telegram.exe");

        assert!(ledger.record(0, &a).is_some());
        for tick in 1..211 {
            assert!(
                ledger.record(tick * 70, &a).is_none(),
                "retry {tick} must not raise a second notice"
            );
        }
        assert_eq!(ledger.attempts_so_far(&a), 211);
    }

    #[test]
    fn resolving_a_destination_clears_every_episode_it_owns() {
        // The user routed the host from the notice: the question is answered
        // for every app that hit it, not just the one that happened to ask.
        let mut ledger = BlockNoticeLedger::default();
        let chrome = attempt("cdn.example", "chrome.exe");
        let telegram = attempt("cdn.example", "telegram.exe");
        let other = attempt("other.example", "chrome.exe");
        assert!(ledger.record(0, &chrome).is_some());
        assert!(ledger.record(0, &telegram).is_some());
        assert!(ledger.record(0, &other).is_some());

        assert_eq!(
            ledger.resolve_destination("CDN.Example."),
            2,
            "case and trailing dot are noise"
        );
        assert_eq!(ledger.attempts_so_far(&chrome), 0);
        assert_eq!(ledger.attempts_so_far(&telegram), 0);
        assert_eq!(
            ledger.attempts_so_far(&other),
            1,
            "an unrelated host is untouched"
        );
    }

    #[test]
    fn resolving_an_unknown_or_blank_destination_changes_nothing() {
        let mut ledger = BlockNoticeLedger::default();
        let a = attempt("cdn.example", "chrome.exe");
        assert!(ledger.record(0, &a).is_some());

        assert_eq!(ledger.resolve_destination("nothing.here"), 0);
        assert_eq!(ledger.resolve_destination("   "), 0);
        assert_eq!(ledger.attempts_so_far(&a), 1);
    }

    #[test]
    fn a_resolved_destination_can_raise_a_fresh_notice_later() {
        // Resolution is not a mute: if the host is blocked again after the fix,
        // that is news and must be shown.
        let mut ledger = BlockNoticeLedger::default();
        let a = attempt("cdn.example", "chrome.exe");
        assert!(ledger.record(0, &a).is_some());
        ledger.resolve_destination("cdn.example");

        assert!(
            ledger.record(1, &a).is_some(),
            "the next block is a new episode"
        );
    }

    #[test]
    fn the_same_destination_after_a_quiet_gap_is_news_again() {
        let mut ledger = BlockNoticeLedger::default();
        let a = attempt("cdn.example", "chrome.exe");

        assert!(ledger.record(0, &a).is_some());
        assert!(ledger.record(DEFAULT_EPISODE_GAP_MS, &a).is_none());
        let later = DEFAULT_EPISODE_GAP_MS * 2 + 1;
        let notice = ledger.record(later, &a).expect("a new episode");
        assert_eq!(notice.first_attempt_ms, later);
        assert_eq!(notice.attempts, 1);
    }

    #[test]
    fn each_mute_scope_silences_exactly_what_it_names() {
        let noisy = attempt("cdn.example", "telegram.exe");
        let other_host = attempt("other.example", "telegram.exe");
        let other_app = attempt("cdn.example", "chrome.exe");

        let mut by_host = BlockNoticeLedger::default();
        by_host.set_mutes(vec![Mute::forever(MuteScope::Host("cdn.example".into()))]);
        assert!(by_host.record(0, &noisy).is_none());
        assert!(by_host.record(0, &other_host).is_some());

        let mut by_app = BlockNoticeLedger::default();
        by_app.set_mutes(vec![Mute::forever(MuteScope::App("telegram.exe".into()))]);
        assert!(by_app.record(0, &noisy).is_none());
        assert!(by_app.record(0, &other_app).is_some());

        let mut all = BlockNoticeLedger::default();
        all.set_mutes(vec![Mute::forever(MuteScope::All)]);
        assert!(all.record(0, &noisy).is_none());
        assert!(all.record(0, &other_host).is_none());
    }

    #[test]
    fn a_lapsed_mute_stops_silencing_and_counting_never_stopped() {
        let mut ledger = BlockNoticeLedger::default();
        let a = attempt("cdn.example", "chrome.exe");
        ledger.set_mutes(vec![Mute::until(
            MuteScope::Host("cdn.example".into()),
            5_000,
        )]);

        assert!(ledger.record(0, &a).is_none());
        assert_eq!(ledger.attempts_so_far(&a), 1, "muted attempts still count");
        // Past the mute AND past the episode gap, so this opens a new episode.
        assert!(ledger.record(DEFAULT_EPISODE_GAP_MS + 5_001, &a).is_some());
    }

    #[test]
    fn an_app_scoped_mute_never_matches_an_unnamed_process() {
        let mut ledger = BlockNoticeLedger::default();
        ledger.set_mutes(vec![Mute::forever(MuteScope::App(String::new()))]);
        let unnamed = BlockAttempt {
            host: Some("cdn.example".into()),
            dest: "203.0.113.7".into(),
            app: None,
            reason: BlockReason::RouteUnavailable,
        };
        assert!(ledger.record(0, &unnamed).is_some());
    }

    #[test]
    fn the_coldest_episode_is_dropped_at_the_cap() {
        let mut ledger = BlockNoticeLedger::new(DEFAULT_EPISODE_GAP_MS, 2);
        let first = attempt("a.example", "chrome.exe");
        let second = attempt("b.example", "chrome.exe");
        let third = attempt("c.example", "chrome.exe");

        ledger.record(0, &first);
        ledger.record(10, &second);
        ledger.record(20, &third);

        // The coldest key went; the two most recent kept their counts.
        assert_eq!(ledger.attempts_so_far(&first), 0);
        assert_eq!(ledger.attempts_so_far(&second), 1);
        assert_eq!(ledger.attempts_so_far(&third), 1);
    }

    /// Turning the secondary adapter off makes every address bound to it
    /// fail within seconds. One outage must read as one notice, whichever
    /// address happened to be first, and the count must cover them all.
    #[test]
    fn a_dead_route_speaks_once_no_matter_how_many_addresses_hit_it() {
        let mut ledger = BlockNoticeLedger::default();
        let down = |host: &str, app: &str| BlockAttempt {
            host: Some(host.into()),
            dest: "203.0.113.7".into(),
            app: Some(app.into()),
            reason: BlockReason::RouteUnavailable,
        };
        let first = down("chatgpt.com", "chrome.exe");

        let notice = ledger.record(0, &first).expect("the outage is news once");
        assert_eq!(notice.destination, "chatgpt.com", "names a real example");

        assert!(ledger
            .record(10, &down("www.youtube.com", "chrome.exe"))
            .is_none());
        assert!(ledger
            .record(20, &down("web.whatsapp.com", "telegram.exe"))
            .is_none());
        assert!(ledger
            .record(30, &down("chatgpt.com", "chrome.exe"))
            .is_none());
        assert_eq!(ledger.attempts_so_far(&first), 4, "all of them counted");
    }

    /// The collapse is scoped to that one reason: a rule that blocks an
    /// address is a fact about the address, and two addresses are two facts.
    #[test]
    fn other_reasons_still_speak_per_address() {
        let mut ledger = BlockNoticeLedger::default();
        assert!(ledger
            .record(0, &attempt("a.example", "chrome.exe"))
            .is_some());
        assert!(ledger
            .record(10, &attempt("b.example", "chrome.exe"))
            .is_some());
    }

    #[test]
    fn the_address_stands_in_when_the_name_is_unknown() {
        let nameless = BlockAttempt {
            host: None,
            dest: "203.0.113.7".into(),
            app: None,
            reason: BlockReason::BlockedByRule,
        };
        assert_eq!(nameless.destination_label(), "203.0.113.7");
    }
}

//! What the last main-link check found for a rule's address.
//!
//! The suggestions inbox already answers "does the main link reach this?" for
//! addresses it is offering. A user looking at rules they already have wants
//! the same fact for those: a rule whose address the main link reaches may be
//! one they no longer need — or one the site refuses to serve there, which is
//! exactly why they added it. The verdict is reported as a fact and worded that
//! way in the GUI; nothing in enforcement reads it.
//!
//! Kept in memory on purpose. A verdict is a statement about the network as it
//! was minutes ago; persisting it across restarts would show the user an answer
//! from a different link on a different day. Nothing prunes the map either —
//! [`VERDICT_TTL`] retires an answer, and a verdict for a rule that no longer
//! exists is never read because the row it would annotate is gone.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a verdict is worth showing. Past this the row reads as unchecked
/// again rather than quoting an answer from another session of the network.
pub const VERDICT_TTL: Duration = Duration::from_secs(30 * 60);

/// Outcome of one probe against a rule's address over the main link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainRouteVerdict {
    /// Something answered on the main link. NOT "the rule is unnecessary": a
    /// site can answer there and still refuse to serve this user.
    Answered,
    /// Nothing answered within the probe budget.
    Silent,
}

impl MainRouteVerdict {
    /// Wire slug carried in `RuleRowEntry::main_route`.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Silent => "silent",
        }
    }
}

/// One principal's answers, keyed by the hostname that was probed.
type HostVerdicts = HashMap<String, (MainRouteVerdict, Instant)>;

/// Per-principal verdicts.
#[derive(Debug, Default)]
pub struct MainRouteVerdicts {
    inner: Mutex<HashMap<String, HostVerdicts>>,
}

impl MainRouteVerdicts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HostVerdicts>> {
        // Poison recovery: the map is plain data, and the workspace lint denies
        // `unwrap_used`.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Record what the probe found for `hostname`.
    pub fn record(&self, sid: &str, hostname: &str, verdict: MainRouteVerdict, now: Instant) {
        let key = normalize(hostname);
        if key.is_empty() {
            return;
        }
        self.lock()
            .entry(sid.to_string())
            .or_default()
            .insert(key, (verdict, now));
    }

    /// The verdict for `hostname`, or `None` when it was never checked or the
    /// answer has aged out.
    #[must_use]
    pub fn get(&self, sid: &str, hostname: &str, now: Instant) -> Option<MainRouteVerdict> {
        let key = normalize(hostname);
        let guard = self.lock();
        let (verdict, at) = guard.get(sid)?.get(&key).copied()?;
        (now.duration_since(at) < VERDICT_TTL).then_some(verdict)
    }
}

/// Rule values carry the shapes a rule file allows; the probe and the lookup
/// must agree on one spelling.
fn normalize(hostname: &str) -> String {
    hostname
        .trim()
        .trim_start_matches("*.")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_verdict_reads_back_for_every_spelling_of_the_host() {
        let v = MainRouteVerdicts::new();
        let now = Instant::now();
        v.record("S-1", "Example.COM.", MainRouteVerdict::Answered, now);
        assert_eq!(
            v.get("S-1", "*.example.com", now),
            Some(MainRouteVerdict::Answered),
            "a suffix rule and its apex are the same host to the probe"
        );
    }

    #[test]
    fn an_unchecked_host_has_no_verdict() {
        let v = MainRouteVerdicts::new();
        assert_eq!(v.get("S-1", "example.com", Instant::now()), None);
    }

    #[test]
    fn a_verdict_ages_out() {
        let v = MainRouteVerdicts::new();
        let now = Instant::now();
        v.record("S-1", "example.com", MainRouteVerdict::Silent, now);
        assert_eq!(
            v.get("S-1", "example.com", now + VERDICT_TTL),
            None,
            "an answer this old describes a different network"
        );
    }

    #[test]
    fn verdicts_are_per_principal() {
        let v = MainRouteVerdicts::new();
        let now = Instant::now();
        v.record("S-1", "example.com", MainRouteVerdict::Answered, now);
        assert_eq!(v.get("S-2", "example.com", now), None);
    }
}

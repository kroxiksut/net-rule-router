//! At boot the service usually starts before the VPN does, so "the additional
//! route is down" is the expected state, not news. Until a principal's
//! additional route has been up once, its down status is published quietly
//! for a while and its blocks are not announced as an outage; one notice
//! follows only if the route never comes up. A block is judged by when it
//! happened, not when it is read: the observer reports drops in batches, and
//! one from before the first rise must not turn into news after it.
//!
//! Installed once by the production service. Without it nothing is quiet,
//! which is what tests and tools get.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// How long a never-up additional route stays quiet after the service starts:
/// long enough for a VPN client that connects at sign-in.
pub const STARTUP_QUIET: Duration = Duration::from_secs(180);

/// Statuses of the additional route that mean "not up yet" rather than a fault
/// the user must fix.
const QUIET_STATUSES: [&str; 2] = ["secondary-down", "adapter-gone"];

struct StartupQuiet {
    quiet_until_ms: i64,
    /// When each principal's additional route was first usable since the start.
    first_up_ms: Mutex<HashMap<String, i64>>,
}

impl StartupQuiet {
    fn new(now_ms: i64) -> Self {
        let window = i64::try_from(STARTUP_QUIET.as_millis()).unwrap_or(i64::MAX);
        Self {
            quiet_until_ms: now_ms.saturating_add(window),
            first_up_ms: Mutex::new(HashMap::new()),
        }
    }

    fn note_up(&self, principal: &str, now_ms: i64) {
        let mut first = self.first_up_ms.lock().unwrap_or_else(|p| p.into_inner());
        if !first.contains_key(principal) {
            first.insert(principal.to_owned(), now_ms);
        }
    }

    fn never_up(&self, principal: &str) -> bool {
        self.down_at(principal, i64::MAX)
    }

    /// Whether `principal`'s route had not come up yet at `at_ms`.
    fn down_at(&self, principal: &str, at_ms: i64) -> bool {
        let first = self.first_up_ms.lock().unwrap_or_else(|p| p.into_inner());
        if principal.is_empty() {
            first.values().all(|&up| up > at_ms)
        } else {
            first.get(principal).is_none_or(|&up| up > at_ms)
        }
    }

    fn quiet(&self, principal: &str, role: &str, status: &str, now_ms: i64) -> bool {
        role == "secondary"
            && QUIET_STATUSES.contains(&status)
            && now_ms < self.quiet_until_ms
            && self.never_up(principal)
    }
}

static INSTALLED: OnceLock<StartupQuiet> = OnceLock::new();

/// Start the quiet window at `now_ms`. The first call wins.
pub fn install(now_ms: i64) -> bool {
    INSTALLED.set(StartupQuiet::new(now_ms)).is_ok()
}

/// `principal`'s additional route is usable at `now_ms`.
pub fn note_up(principal: &str, now_ms: i64) {
    if let Some(state) = INSTALLED.get() {
        state.note_up(principal, now_ms);
    }
}

/// Whether `principal`'s additional route had not come up since the start by
/// `at_ms`, when a drop happened; `None` (time unknown) asks about now. An
/// empty principal (a drop no user owns) asks about anyone.
pub fn down_at(principal: &str, at_ms: Option<u64>) -> bool {
    let at_ms = at_ms.map_or(i64::MAX, |at| i64::try_from(at).unwrap_or(i64::MAX));
    INSTALLED
        .get()
        .is_some_and(|state| state.down_at(principal, at_ms))
}

/// Whether a `status` report for `principal`'s `role` is published quietly.
pub fn quiet(principal: &str, role: &str, status: &str, now_ms: i64) -> bool {
    INSTALLED
        .get()
        .is_some_and(|state| state.quiet(principal, role, status, now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: i64 = 1_000_000;
    const LATER: i64 = START + 181_000;

    #[test]
    fn a_route_that_never_came_up_is_quiet_only_during_the_wait() {
        let q = StartupQuiet::new(START);
        assert!(q.quiet("u", "secondary", "secondary-down", START + 1));
        assert!(q.quiet("u", "secondary", "adapter-gone", START + 1));
        assert!(!q.quiet("u", "secondary", "secondary-down", LATER));
        assert!(q.never_up("u"), "still never up after the wait");
    }

    #[test]
    fn once_up_a_drop_is_news_again() {
        let q = StartupQuiet::new(START);
        q.note_up("u", START + 1);
        assert!(!q.quiet("u", "secondary", "secondary-down", START + 1));
        assert!(!q.never_up("u"));
        assert!(q.never_up("other"), "each user has their own route");
    }

    #[test]
    fn faults_and_the_main_route_are_never_quiet() {
        let q = StartupQuiet::new(START);
        assert!(!q.quiet("u", "primary", "secondary-down", START + 1));
        assert!(!q.quiet("u", "secondary", "adapter-choice-needed", START + 1));
        assert!(!q.quiet("u", "secondary", "adapter-failed", START + 1));
    }

    #[test]
    fn a_drop_nobody_owns_asks_about_anyone() {
        let q = StartupQuiet::new(START);
        assert!(q.never_up(""));
        q.note_up("u", START + 1);
        assert!(!q.never_up(""));
    }

    #[test]
    fn a_drop_is_judged_by_when_it_happened_not_when_it_is_read() {
        let q = StartupQuiet::new(START);
        let up = START + 120_000;
        q.note_up("u", up);
        assert!(
            q.down_at("u", up - 2_000),
            "dropped before the rise, read after it"
        );
        assert!(!q.down_at("u", up), "the rise itself counts as up");
        assert!(!q.down_at("u", up + 2_000));
        assert!(q.down_at("", up - 1));
        assert!(!q.down_at("", up + 1));
    }

    #[test]
    fn the_first_rise_stays_the_reference() {
        let q = StartupQuiet::new(START);
        q.note_up("u", START + 10);
        q.note_up("u", START + 50_000);
        assert!(!q.down_at("u", START + 20));
    }

    #[test]
    fn nothing_is_quiet_until_installed() {
        // The global is never installed in unit tests.
        assert!(!quiet("u", "secondary", "secondary-down", START));
        assert!(!down_at("u", None));
        assert!(!down_at("u", Some(0)));
    }
}

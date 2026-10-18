//! At boot the service usually starts before the VPN does, so "the additional
//! route is down" is the expected state, not news. Until a principal's
//! additional route has been up once, its down status is published quietly
//! for a while and its blocks are not announced as an outage; one notice
//! follows only if the route never comes up.
//!
//! Installed once by the production service. Without it nothing is quiet,
//! which is what tests and tools get.

use std::collections::HashSet;
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
    /// Principals whose additional route has been usable since the start.
    seen_up: Mutex<HashSet<String>>,
}

impl StartupQuiet {
    fn new(now_ms: i64) -> Self {
        let window = i64::try_from(STARTUP_QUIET.as_millis()).unwrap_or(i64::MAX);
        Self {
            quiet_until_ms: now_ms.saturating_add(window),
            seen_up: Mutex::new(HashSet::new()),
        }
    }

    fn note_up(&self, principal: &str) {
        let mut seen = self.seen_up.lock().unwrap_or_else(|p| p.into_inner());
        if !seen.contains(principal) {
            seen.insert(principal.to_owned());
        }
    }

    fn never_up(&self, principal: &str) -> bool {
        let seen = self.seen_up.lock().unwrap_or_else(|p| p.into_inner());
        if principal.is_empty() {
            seen.is_empty()
        } else {
            !seen.contains(principal)
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

/// `principal`'s additional route is usable.
pub fn note_up(principal: &str) {
    if let Some(state) = INSTALLED.get() {
        state.note_up(principal);
    }
}

/// Whether `principal`'s additional route has never been up since the start.
/// An empty principal (a drop no user owns) asks about anyone.
pub fn never_up(principal: &str) -> bool {
    INSTALLED
        .get()
        .is_some_and(|state| state.never_up(principal))
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
        q.note_up("u");
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
        q.note_up("u");
        assert!(!q.never_up(""));
    }

    #[test]
    fn nothing_is_quiet_until_installed() {
        // The global is never installed in unit tests.
        assert!(!quiet("u", "secondary", "secondary-down", START));
        assert!(!never_up("u"));
    }
}

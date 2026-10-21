//! A monotonic clock that keeps counting while the machine sleeps, for
//! deadlines that must expire across a suspend. `Instant` on Linux is
//! `CLOCK_MONOTONIC`, which stops during sleep, so a 30-minute memory would
//! outlive a night in suspend and pin an address the pool has since given away.
//!
//! The mechanism is the platform's: the service installs its own source once at
//! start-up, before anything reads the clock. Without one, the clock falls back
//! to `Instant` — correct on platforms whose monotonic clock already counts sleep.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

static SOURCE: OnceLock<fn() -> Duration> = OnceLock::new();
static FALLBACK_START: OnceLock<Instant> = OnceLock::new();

/// Where the fallback clock starts counting: far enough from zero that a
/// reading minus a window is still a reading, as it is with a real boot clock.
const FALLBACK_EPOCH: Duration = Duration::from_secs(24 * 60 * 60);

#[cfg(test)]
thread_local! {
    /// Sleep a test simulates on its own thread: this clock counts it, `Instant`
    /// does not.
    static SLEPT: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
}

/// Move this thread's readings forward as a suspend of `by` would.
#[cfg(test)]
pub(crate) fn simulate_sleep(by: Duration) {
    SLEPT.with(|slept| slept.set(slept.get().saturating_add(by)));
}

/// Install the platform's suspend-aware clock (time since boot). Only the first
/// call counts.
pub fn install_source(source: fn() -> Duration) {
    let _ = SOURCE.set(source);
}

/// A point on the suspend-aware clock. Comparable only with another reading of
/// the same clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BootInstant(Duration);

impl BootInstant {
    #[must_use]
    pub fn now() -> Self {
        let reading = match SOURCE.get() {
            Some(source) => source(),
            None => {
                FALLBACK_EPOCH.saturating_add(FALLBACK_START.get_or_init(Instant::now).elapsed())
            }
        };
        #[cfg(test)]
        let reading = reading.saturating_add(SLEPT.with(std::cell::Cell::get));
        Self(reading)
    }

    /// The reading `by` before this one; `None` before the clock's start.
    #[must_use]
    pub fn checked_sub(self, by: Duration) -> Option<Self> {
        self.0.checked_sub(by).map(Self)
    }

    /// Time from `earlier` to this reading; zero if `earlier` is later.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Time since this reading, counting sleep; zero if the clock reads earlier.
    #[must_use]
    pub fn elapsed(self) -> Duration {
        Self::now().0.saturating_sub(self.0)
    }
}

impl std::ops::Add<Duration> for BootInstant {
    type Output = Self;

    fn add(self, by: Duration) -> Self {
        Self(self.0.saturating_add(by))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_never_goes_backwards() {
        let at = BootInstant::now();
        assert!(at.elapsed() >= Duration::ZERO);
        let future = BootInstant(at.0 + Duration::from_secs(3600));
        assert_eq!(future.elapsed(), Duration::ZERO);
    }

    #[test]
    fn a_window_back_from_now_is_still_a_reading() {
        let now = BootInstant::now();
        let earlier = now
            .checked_sub(Duration::from_secs(60))
            .expect("the clock reads past its start");
        assert_eq!(
            now.saturating_duration_since(earlier),
            Duration::from_secs(60)
        );
        assert_eq!(
            BootInstant(Duration::ZERO).checked_sub(Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn a_simulated_sleep_moves_this_clock_and_not_instant() {
        let (at, mono) = (BootInstant::now(), Instant::now());
        simulate_sleep(Duration::from_secs(3600));
        assert!(at.elapsed() >= Duration::from_secs(3600));
        assert!(mono.elapsed() < Duration::from_secs(3600));
    }

    #[test]
    fn readings_are_ordered() {
        let first = BootInstant::now();
        let second = BootInstant::now();
        assert!(second >= first);
    }
}

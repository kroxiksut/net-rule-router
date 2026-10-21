//! `CLOCK_BOOTTIME`: monotonic like `Instant`, but it keeps counting while the
//! machine is suspended, which `CLOCK_MONOTONIC` does not.

#![allow(unsafe_code)]

use std::time::Duration;

/// Time since boot, sleep included. A kernel that refuses the clock (it has
/// existed since 2.6.39) falls back to the monotonic one.
#[must_use]
pub fn since_boot() -> Duration {
    #[cfg(target_os = "linux")]
    {
        read(libc::CLOCK_BOOTTIME)
            .or_else(|| read(libc::CLOCK_MONOTONIC))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Duration::ZERO
    }
}

#[cfg(target_os = "linux")]
fn read(clock: libc::clockid_t) -> Option<Duration> {
    let mut at = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `at` is live and writable for the call, which fills it and
    // keeps no pointer.
    let rc = unsafe { libc::clock_gettime(clock, &mut at) };
    if rc != 0 {
        return None;
    }
    Some(Duration::new(
        u64::try_from(at.tv_sec).ok()?,
        u32::try_from(at.tv_nsec).ok()?,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn the_boot_clock_runs_forward_and_is_at_least_the_monotonic_one() {
        let first = since_boot();
        let second = since_boot();
        assert!(second >= first);
        // BOOTTIME = MONOTONIC + time spent suspended.
        assert!(
            first + Duration::from_millis(50) >= read(libc::CLOCK_MONOTONIC).unwrap_or_default()
        );
    }
}

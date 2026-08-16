//! Linux mechanism behind
//! [`nrr_platform_api::local_time::LocalTimeZonePort`].
//!
//! `localtime_r` resolves the instant against the machine's tz database, so the
//! answer is daylight-aware and follows a `/etc/localtime` change without a
//! service restart. The offset is taken at the instant the caller asks about,
//! not at "now": a ledger row from before a DST switch keys to the day it
//! actually fell on.

#![allow(unsafe_code)]

use nrr_platform_api::local_time::LocalTimeZonePort;

/// Production implementation over the C library's time-zone resolution.
#[derive(Debug, Default)]
pub struct LinuxTimeZone;

impl LocalTimeZonePort for LinuxTimeZone {
    #[cfg(target_os = "linux")]
    fn utc_offset_seconds(&self, now_ms: i64) -> i32 {
        // UTC is the honest answer when the tz database cannot be read: it is
        // what the neutral fallback already means, and inventing an offset
        // would silently misfile every ledger row keyed with it.
        offset_at(now_ms).unwrap_or(0)
    }

    #[cfg(not(target_os = "linux"))]
    fn utc_offset_seconds(&self, _now_ms: i64) -> i32 {
        0
    }
}

#[cfg(target_os = "linux")]
fn offset_at(now_ms: i64) -> Option<i32> {
    // No-op on 64-bit, where `time_t` is `i64`; load-bearing on a 32-bit target,
    // where it is `i32` and an out-of-range instant must fail rather than wrap.
    #[allow(clippy::useless_conversion)]
    let instant: libc::time_t = now_ms.div_euclid(1000).try_into().ok()?;
    // SAFETY: `libc::tm` is a plain-data struct; an all-zero value is a valid
    // one to hand `localtime_r` as its output buffer.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `instant` and `tm` are live for the call; `localtime_r` writes
    // only into `tm` and keeps no reference to either (that is what makes it
    // the reentrant variant).
    let resolved = unsafe { libc::localtime_r(&instant, &mut tm) };
    if resolved.is_null() {
        return None;
    }
    // `tm_gmtoff` is seconds EAST of UTC — already the port's sign convention,
    // unlike the Win32 bias, which is the negation. Note it is not always a
    // whole number of minutes: for instants before standard time existed the
    // tz database answers with the zone's Local Mean Time.
    tm.tm_gmtoff.try_into().ok()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn offset_is_a_sane_civil_offset() {
        // Real time zones span UTC-12..UTC+14. Whatever the build host is set
        // to, the answer has to land inside that.
        let secs = LinuxTimeZone.utc_offset_seconds(1_700_000_000_000);
        assert!((-12 * 3600..=14 * 3600).contains(&secs), "offset {secs}");
    }

    #[test]
    fn the_offset_lands_on_a_whole_minute() {
        // Every civil zone in the tz database is a whole number of minutes;
        // a stray second means the value was not read as seconds-east.
        let secs = LinuxTimeZone.utc_offset_seconds(1_700_000_000_000);
        assert_eq!(secs % 60, 0, "offset {secs} is not a whole minute");
    }

    #[test]
    fn the_same_instant_answers_the_same_twice() {
        let first = LinuxTimeZone.utc_offset_seconds(1_700_000_000_000);
        let second = LinuxTimeZone.utc_offset_seconds(1_700_000_000_000);
        assert_eq!(first, second);
    }

    #[test]
    fn an_absurd_instant_still_answers_in_the_civil_range() {
        // The ledger can hand over a clock that jumped. glibc does NOT refuse
        // such an instant: it answers from the tz database, which for
        // pre-standard-time dates is the zone's Local Mean Time — a real
        // offset, just not a whole number of minutes. What must hold is that
        // the port never panics and never leaves the civil range.
        let secs = LinuxTimeZone.utc_offset_seconds(i64::MIN);
        assert!((-12 * 3600..=14 * 3600).contains(&secs), "offset {secs}");
    }
}

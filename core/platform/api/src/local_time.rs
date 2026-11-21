//! Local-time port — the OS knows the machine's civil time zone; neutral code
//! does not.
//!
//! The traffic ledger keys its rows by the user's LOCAL day: a day boundary at
//! midnight UTC would flip "today" mid-morning for anyone east of Greenwich.
//! The port returns offsets and resolved midnight instants. Callers keep their
//! own presentation and day arithmetic.

use jiff::{
    civil::Date,
    tz::{AmbiguousOffset, TimeZone},
    Timestamp,
};

/// Supplies the machine's civil-time offset from UTC. One implementation per
/// OS; [`UtcTimeZone`] is the neutral fallback (offset 0).
pub trait LocalTimeZonePort: Send + Sync {
    /// Offset of local civil time from UTC in seconds at `now_ms`
    /// (milliseconds since the Unix epoch). Positive east of Greenwich.
    fn utc_offset_seconds(&self, now_ms: i64) -> i32;

    /// First occurrence of local midnight on the date containing `at_ms`.
    /// Returns `None` when midnight was skipped during a clock change.
    fn local_midnight_ms(&self, at_ms: i64) -> Option<i64>;
}

/// Neutral fallback: treats local time as UTC.
#[derive(Debug, Default)]
pub struct UtcTimeZone;

impl LocalTimeZonePort for UtcTimeZone {
    fn utc_offset_seconds(&self, _now_ms: i64) -> i32 {
        0
    }

    fn local_midnight_ms(&self, at_ms: i64) -> Option<i64> {
        FixedTimeZone(0).local_midnight_ms(at_ms)
    }
}

/// Fixed-offset implementation for tests and for platforms where the offset is
/// resolved once at composition time.
#[derive(Debug)]
pub struct FixedTimeZone(pub i32);

impl LocalTimeZonePort for FixedTimeZone {
    fn utc_offset_seconds(&self, _now_ms: i64) -> i32 {
        self.0
    }

    fn local_midnight_ms(&self, at_ms: i64) -> Option<i64> {
        local_epoch_day(at_ms, self.0)
            .checked_mul(86_400_000)?
            .checked_sub(i64::from(self.0) * 1000)
    }
}

/// Resolves the configured system zone with the platform's time-zone database.
/// Windows binaries select their native Windows port to use the actual
/// Windows rules, including local DST configuration.
#[derive(Debug, Default)]
pub struct DatabaseTimeZone;

impl LocalTimeZonePort for DatabaseTimeZone {
    fn utc_offset_seconds(&self, at_ms: i64) -> i32 {
        Timestamp::from_millisecond(at_ms).map_or(0, |at| system_zone().to_offset(at).seconds())
    }

    fn local_midnight_ms(&self, at_ms: i64) -> Option<i64> {
        let at = Timestamp::from_millisecond(at_ms).ok()?;
        let tz = system_zone();
        midnight_in(&tz, tz.to_datetime(at).date())
    }
}

#[cfg(unix)]
fn system_zone() -> TimeZone {
    use std::{
        sync::{Mutex, PoisonError},
        time::{Duration, Instant},
    };

    static CACHE: Mutex<Option<(Instant, TimeZone)>> = Mutex::new(None);
    let mut cached = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, zone)) = cached
        .as_ref()
        .filter(|(read_at, _)| read_at.elapsed() < Duration::from_secs(1))
    {
        return zone.clone();
    }

    // Recheck once a second so a local time-zone change takes effect during
    // the running session. Jiff would otherwise keep this result for 5 min.
    jiff::tz::reset_system_time_zone_cache();
    let zone = TimeZone::system();
    *cached = Some((Instant::now(), zone.clone()));
    zone
}

#[cfg(not(unix))]
fn system_zone() -> TimeZone {
    TimeZone::system()
}

fn midnight_in(tz: &TimeZone, day: Date) -> Option<i64> {
    let midnight = tz.to_ambiguous_timestamp(day.at(0, 0, 0, 0));
    if matches!(midnight.offset(), AmbiguousOffset::Gap { .. }) {
        return None;
    }
    Some(midnight.earlier().ok()?.as_millisecond())
}

/// The epoch-day of the LOCAL calendar date at `now_ms`, given the offset
/// supplied by the port. Shared helper so every consumer (sampler tick, GUI
/// parity notes, tests) keys days identically.
#[must_use]
pub fn local_epoch_day(now_ms: i64, utc_offset_seconds: i32) -> i64 {
    let shifted = now_ms.saturating_add(i64::from(utc_offset_seconds).saturating_mul(1000));
    shifted.div_euclid(86_400_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_fallback_matches_plain_epoch_day() {
        assert_eq!(
            local_epoch_day(1_700_000_000_000, 0),
            1_700_000_000 / 86_400
        );
    }

    #[test]
    fn eastern_offset_rolls_the_day_earlier() {
        // 2023-11-14T22:13:20Z; UTC+8 makes it already the 15th locally.
        let now_ms = 1_700_000_000_000;
        let utc_day = local_epoch_day(now_ms, 0);
        assert_eq!(local_epoch_day(now_ms, 8 * 3600), utc_day + 1);
    }

    #[test]
    fn western_offset_can_roll_the_day_back() {
        // 2023-11-14T01:00:00Z is still the 13th at UTC-5.
        let now_ms = (1_699_923_600 + 3_600) * 1_000;
        let utc_day = local_epoch_day(now_ms, 0);
        assert_eq!(local_epoch_day(now_ms, -5 * 3600), utc_day - 1);
    }

    #[test]
    fn negative_timestamps_floor_correctly() {
        assert_eq!(local_epoch_day(-1, 0), -1);
        assert_eq!(local_epoch_day(-86_400_000, 0), -1);
    }

    #[test]
    fn missing_midnight_does_not_set_a_cutoff_and_a_repeated_midnight_uses_the_first() {
        let gap = jiff::tz::TimeZone::get("America/Sao_Paulo").expect("Sao Paulo time zone");
        let gap_day = jiff::civil::date(2018, 11, 4);
        assert_eq!(midnight_in(&gap, gap_day), None);

        let fold = jiff::tz::TimeZone::get("America/Havana").expect("Havana time zone");
        let fold_day = jiff::civil::date(2024, 11, 3);
        let expected: jiff::Timestamp = "2024-11-03T04:00:00Z".parse().expect("first midnight");
        assert_eq!(
            midnight_in(&fold, fold_day),
            Some(expected.as_millisecond())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_running_process_picks_up_a_new_configured_zone_within_a_second() {
        use std::{env, fs, process::Command, thread, time::Duration};

        const ZONE_FILE_ENV: &str = "NRR_TEST_LOCAL_TIME_ZONE_FILE";
        const WEST: &str = "/usr/share/zoneinfo/Etc/GMT+2";
        const EAST: &str = "/usr/share/zoneinfo/Etc/GMT-3";
        if let Some(path) = env::var_os(ZONE_FILE_ENV) {
            let at: Timestamp = "2025-01-01T00:30:00Z".parse().expect("test instant");
            let zone = DatabaseTimeZone;
            assert_eq!(zone.utc_offset_seconds(at.as_millisecond()), -2 * 3600);
            fs::copy(EAST, path).expect("replace the private TZ fixture");
            thread::sleep(Duration::from_millis(1100));

            assert_eq!(zone.utc_offset_seconds(at.as_millisecond()), 3 * 3600);
            assert_eq!(
                zone.local_midnight_ms(at.as_millisecond()),
                Some(at.as_millisecond() - 3 * 3_600_000 - 30 * 60_000)
            );
            return;
        }

        // Only the child uses this private TZ file. The host zone and other
        // tests' environment stay untouched.
        let dir = tempfile::tempdir().expect("private zone directory");
        let path = dir.path().join("test-tz");
        fs::copy(WEST, &path).expect("prepare the private TZ fixture");
        let output = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "local_time::tests::a_running_process_picks_up_a_new_configured_zone_within_a_second",
            ])
            .env(ZONE_FILE_ENV, &path)
            .env("TZ", &path)
            .output()
            .expect("run the child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

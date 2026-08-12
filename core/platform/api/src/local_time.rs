//! Local-time port — the OS knows the machine's civil time zone; neutral code
//! does not.
//!
//! The traffic ledger keys its rows by the user's LOCAL day: a day boundary at
//! midnight UTC would flip "today" mid-morning for anyone east of Greenwich.
//! Only the offset crosses this port — all arithmetic on it stays neutral.

/// Supplies the machine's civil-time offset from UTC. One implementation per
/// OS; [`UtcTimeZone`] is the neutral fallback (offset 0).
pub trait LocalTimeZonePort: Send + Sync {
    /// Offset of local civil time from UTC in seconds at `now_ms`
    /// (milliseconds since the Unix epoch). Positive east of Greenwich.
    fn utc_offset_seconds(&self, now_ms: i64) -> i32;
}

/// Neutral fallback: treats local time as UTC.
#[derive(Debug, Default)]
pub struct UtcTimeZone;

impl LocalTimeZonePort for UtcTimeZone {
    fn utc_offset_seconds(&self, _now_ms: i64) -> i32 {
        0
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
}

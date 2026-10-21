//! The machine's UTC offset, for timestamps a person reads.
//!
//! Every stored timestamp stays UTC Unix milliseconds; only the human-readable
//! rendering (`created_at_iso`, log/audit file names) is local, because a log
//! read at 10:33 must not say 02:33.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use chrono::{Local, Offset};

/// How long a read offset is reused. Short enough that a DST switch shows up
/// within the minute, long enough that a busy log never queries the OS twice.
const REFRESH_MILLIS: i64 = 60_000;

/// Packed cache: the offset in the low 20 bits, the read's monotonic timestamp
/// in the high bits. One atomic keeps the pair consistent.
static CACHE: AtomicI64 = AtomicI64::new(i64::MIN);

/// Seconds to add to UTC to get local wall-clock time.
#[must_use]
pub fn seconds() -> i32 {
    // The cache ages on the monotonic clock: aged on the wall clock, a clock
    // set back would hold the old offset until it passed the read's mark.
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let now_ms =
        i64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(i64::MAX);
    cached_or_read(&CACHE, now_ms, || {
        Local::now().offset().fix().local_minus_utc()
    })
}

fn cached_or_read(cache: &AtomicI64, now_ms: i64, read: impl FnOnce() -> i32) -> i32 {
    let cached = cache.load(Ordering::Relaxed);
    if cached != i64::MIN {
        let (at_ms, offset) = unpack(cached);
        if (0..REFRESH_MILLIS).contains(&now_ms.saturating_sub(at_ms)) {
            return offset;
        }
    }
    let offset = read();
    cache.store(pack(now_ms, offset), Ordering::Relaxed);
    offset
}

/// `+HH:MM` / `-HH:MM`, or `Z` at UTC — the RFC-3339 tail for [`seconds`].
#[must_use]
pub fn rfc3339_suffix(offset_seconds: i32) -> String {
    if offset_seconds == 0 {
        return "Z".to_string();
    }
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let abs = offset_seconds.unsigned_abs();
    let hours = abs / 3600;
    let minutes = (abs % 3600) / 60;
    format!("{sign}{hours:02}:{minutes:02}")
}

fn pack(at_ms: i64, offset: i32) -> i64 {
    // Milliseconds truncated to seconds so the pair fits one i64 with room to
    // spare; the refresh window is a minute, so the lost precision is free.
    ((at_ms / 1000) << 20) | i64::from(offset & 0x000F_FFFF)
}

fn unpack(packed: i64) -> (i64, i32) {
    let at_ms = (packed >> 20) * 1000;
    // Sign-extend the 20-bit offset field (±14 h fits in 17 bits).
    let raw = (packed & 0x000F_FFFF) as i32;
    let offset = if raw & 0x0008_0000 != 0 {
        raw | !0x000F_FFFF
    } else {
        raw
    };
    (at_ms, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_round_trips_positive_and_negative_offsets() {
        for offset in [0, 3600, 8 * 3600, -5 * 3600 - 1800, 14 * 3600, -12 * 3600] {
            let (at, got) = unpack(pack(1_786_415_263_829, offset));
            assert_eq!(got, offset);
            assert_eq!(at, 1_786_415_263_000);
        }
    }

    #[test]
    fn suffix_renders_sign_hours_and_half_hour_zones() {
        assert_eq!(rfc3339_suffix(0), "Z");
        assert_eq!(rfc3339_suffix(8 * 3600), "+08:00");
        assert_eq!(rfc3339_suffix(-(5 * 3600 + 1800)), "-05:30");
        assert_eq!(rfc3339_suffix(5 * 3600 + 2700), "+05:45");
    }

    #[test]
    fn a_read_offset_is_reused_for_a_minute_then_read_again() {
        let cache = AtomicI64::new(i64::MIN);
        assert_eq!(cached_or_read(&cache, 5_000, || 3 * 3600), 3 * 3600);
        assert_eq!(
            cached_or_read(&cache, 64_000, || panic!("read within the minute")),
            3 * 3600
        );
        // The zone changed meanwhile: the next read past the minute sees it.
        assert_eq!(cached_or_read(&cache, 66_000, || 4 * 3600), 4 * 3600);
    }

    /// A mark ahead of the clock is never "fresh": the cached pair is read
    /// again instead of being held until the clock catches up with it.
    #[test]
    fn a_mark_ahead_of_the_clock_is_read_again() {
        let cache = AtomicI64::new(pack(3_600_000, 3 * 3600));
        assert_eq!(cached_or_read(&cache, 1_000, || -5 * 3600), -5 * 3600);
    }

    #[test]
    fn seconds_is_stable_within_the_refresh_window() {
        let first = seconds();
        assert_eq!(seconds(), first);
    }
}

//! The wall clock and the local time zone, behind function pointers so the
//! screen's tests run on a fixed instant.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug)]
pub struct Clock {
    /// Milliseconds since the Unix epoch.
    pub now_ms: fn() -> i64,
    /// Offset of local civil time from UTC at an instant, in seconds.
    pub utc_offset: fn(i64) -> i32,
}

impl Default for Clock {
    fn default() -> Self {
        Self {
            now_ms: system_now_ms,
            utc_offset: system_utc_offset,
        }
    }
}

fn system_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn system_utc_offset(ms: i64) -> i32 {
    use chrono::TimeZone;
    chrono::DateTime::from_timestamp_millis(ms).map_or(0, |utc| {
        chrono::Local
            .offset_from_utc_datetime(&utc.naive_utc())
            .local_minus_utc()
    })
}

impl Clock {
    pub fn now(&self) -> i64 {
        (self.now_ms)()
    }

    /// The local calendar day the traffic ledger keys "today" by.
    pub fn local_day(&self) -> i64 {
        let now = self.now();
        nrr_platform_api::local_time::local_epoch_day(now, (self.utc_offset)(now))
    }

    /// `YYYY-MM-DD HH:MM` in local time, as the GUI's tables print it.
    pub fn format(&self, ms: i64) -> String {
        let local = ms.saturating_add(i64::from((self.utc_offset)(ms)).saturating_mul(1000));
        let minutes = local.div_euclid(60_000);
        let (days, minute_of_day) = (minutes.div_euclid(1440), minutes.rem_euclid(1440));
        let (year, month, day) = civil_from_days(days);
        format!(
            "{year:04}-{month:02}-{day:02} {:02}:{:02}",
            minute_of_day / 60,
            minute_of_day % 60
        )
    }
}

/// Proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's
/// algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed() -> i64 {
        1_700_000_000_000
    }

    fn utc_plus_three(_: i64) -> i32 {
        3 * 3600
    }

    #[test]
    fn a_local_stamp_reads_like_the_gui_tables() {
        let clock = Clock {
            now_ms: fixed,
            utc_offset: utc_plus_three,
        };
        // 2023-11-14T22:13:20Z is already the 15th at UTC+3.
        assert_eq!(clock.format(fixed()), "2023-11-15 01:13");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}

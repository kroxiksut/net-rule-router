//! The rules list's «Recent» filter: where each period starts, and when a
//! change happened, said the way the list shows it (`recentPeriodSince`,
//! `recentChangeTime` and `recentChangeStamp` in `pure.js`).
//!
//! No clock and no time zone are read here: the caller passes the moment and
//! the reader's offset from UTC at that moment, in minutes east.

const DAY: i64 = 86_400;

/// The periods the filter offers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RecentPeriod {
    /// The last hour.
    Hour,
    /// Since the reader's local midnight.
    #[default]
    Today,
    /// The last seven days.
    Week,
}

impl RecentPeriod {
    /// All periods, shortest first, as the filter lists them.
    pub const ALL: [Self; 3] = [Self::Hour, Self::Today, Self::Week];

    /// `"hour"`, `"today"` or `"week"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Today => "today",
            Self::Week => "week",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == slug)
    }
}

/// Unix seconds `period` starts at, for a reader `offset_minutes` east of UTC
/// at `now`.
pub fn recent_period_since(period: RecentPeriod, now: i64, offset_minutes: i64) -> i64 {
    match period {
        RecentPeriod::Hour => now - 3_600,
        RecentPeriod::Today => {
            let local = now + offset_minutes * 60;
            local - local.rem_euclid(DAY) - offset_minutes * 60
        }
        RecentPeriod::Week => now - 7 * DAY,
    }
}

/// The local day number and the minute of that day.
fn local_day(at: i64, offset_minutes: i64) -> (i64, i64) {
    let local = at + offset_minutes * 60;
    (local.div_euclid(DAY), local.rem_euclid(DAY) / 60)
}

/// Day and month of a day number (days since 1970-01-01).
fn day_month(days: i64) -> (i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (day, month)
}

fn clock(minute_of_day: i64) -> String {
    format!("{:02}:{:02}", minute_of_day / 60, minute_of_day % 60)
}

/// `14.10 14:32`: the date always shown.
pub fn recent_change_stamp(at: i64, offset_minutes: i64) -> String {
    let (day_number, minute) = local_day(at, offset_minutes);
    let (day, month) = day_month(day_number);
    format!("{day:02}.{month:02} {}", clock(minute))
}

/// `14:32` today, `yesterday` with `{time}` filled the day before, and
/// [`recent_change_stamp`] otherwise. Each moment takes its own offset, so a
/// change on the other side of a clock shift reads as it did then.
pub fn recent_change_time(
    at: i64,
    at_offset_minutes: i64,
    now: i64,
    now_offset_minutes: i64,
    yesterday: &str,
) -> String {
    let (day, minute) = local_day(at, at_offset_minutes);
    let (today, _) = local_day(now, now_offset_minutes);
    if day == today {
        clock(minute)
    } else if day + 1 == today {
        yesterday.replace("{time}", &clock(minute))
    } else {
        recent_change_stamp(at, at_offset_minutes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_and_month_follow_the_calendar() {
        assert_eq!(day_month(0), (1, 1));
        assert_eq!(day_month(59), (1, 3));
        // 2024 is a leap year: 29 February exists.
        assert_eq!(day_month(19_782), (29, 2));
    }
}

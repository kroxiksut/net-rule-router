//! UTC instants and the TUI's civil-time presentation.

use jiff::{tz::Offset, Timestamp, ZonedDateTime};

pub fn now_ms() -> i64 {
    Timestamp::now().as_millisecond()
}

pub fn now_seconds() -> i64 {
    now_ms().div_euclid(1000)
}

pub fn export_stamp() -> String {
    format_export_stamp(Timestamp::now())
}

fn format_export_stamp(at: Timestamp) -> String {
    format!("{at:.3}")
}

pub fn utc_offset_seconds(ms: i64) -> i32 {
    crate::platform::local_time_zone().utc_offset_seconds(ms)
}

pub fn local_time(ms: i64) -> Option<ZonedDateTime> {
    let at = Timestamp::from_millisecond(ms).ok()?;
    let offset = Offset::from_seconds(utc_offset_seconds(ms)).ok()?;
    Some(at.to_zoned_datetime(offset.to_time_zone()))
}

pub fn display_local_time(ms: i64) -> Option<ZonedDateTime> {
    if ms <= 0 {
        return None;
    }
    // Snapshots are independent of the machine time zone.
    #[cfg(test)]
    let at = Timestamp::from_millisecond(ms)
        .ok()
        .map(|at| at.to_zoned_datetime(Offset::UTC.to_time_zone()));
    #[cfg(not(test))]
    let at = local_time(ms);
    at
}

pub fn display_offset(offset: Offset) -> String {
    let seconds = offset.seconds();
    let sign = if seconds < 0 { '-' } else { '+' };
    let minutes = (seconds.unsigned_abs() + 30) / 60;
    format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_offsets_keep_the_minute_precision_of_log_stamps() {
        assert_eq!(
            display_offset(Offset::from_seconds(-43).expect("offset")),
            "-00:01"
        );
        assert_eq!(
            display_offset(Offset::from_seconds(19_800).expect("offset")),
            "+05:30"
        );
        assert_eq!(display_offset(Offset::UTC), "+00:00");
    }

    #[test]
    fn exported_timestamps_keep_three_utc_fraction_digits() {
        assert_eq!(
            format_export_stamp(Timestamp::UNIX_EPOCH),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            format_export_stamp(Timestamp::new(0, 123_999_999).expect("timestamp")),
            "1970-01-01T00:00:00.123Z"
        );
    }
}

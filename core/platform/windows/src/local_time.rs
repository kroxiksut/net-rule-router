//! Windows implementation of the neutral local-time port: the machine's civil
//! offset from UTC, daylight-aware, straight from the OS time-zone settings.

#![cfg(target_os = "windows")]

use jiff::{
    civil::{Date, DateTime, Time, Weekday},
    tz::Offset,
    Timestamp,
};
use nrr_platform_api::local_time::LocalTimeZonePort;
use windows::Win32::{
    Foundation::SYSTEMTIME,
    System::Time::{
        GetDynamicTimeZoneInformation, GetTimeZoneInformationForYear,
        DYNAMIC_TIME_ZONE_INFORMATION, TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION,
    },
};

/// Resolves each instant using the rules Windows reports for that year.
#[derive(Debug, Default)]
pub struct WindowsTimeZone;

impl LocalTimeZonePort for WindowsTimeZone {
    fn utc_offset_seconds(&self, at_ms: i64) -> i32 {
        let offset = || {
            let at = Timestamp::from_millisecond(at_ms).ok()?;
            let zone = read_zone()?;
            offset_in_local_year(at, |year| YearRules::read(year, &zone))
        };
        offset().map_or(0, Offset::seconds)
    }

    fn local_midnight_ms(&self, at_ms: i64) -> Option<i64> {
        let at = Timestamp::from_millisecond(at_ms).ok()?;
        let zone = read_zone()?;
        midnight_in_local_year(at, |year| YearRules::read(year, &zone))
    }
}

#[allow(unsafe_code)]
fn read_zone() -> Option<DYNAMIC_TIME_ZONE_INFORMATION> {
    let mut info = DYNAMIC_TIME_ZONE_INFORMATION::default();
    // SAFETY: Windows only writes to this live output struct.
    let result = unsafe { GetDynamicTimeZoneInformation(&mut info) };
    (result != TIME_ZONE_ID_INVALID).then_some(info)
}

fn offset_in_local_year(at: Timestamp, read: impl Fn(i16) -> Option<YearRules>) -> Option<Offset> {
    let utc_year = Offset::UTC.to_datetime(at).year();
    let offset = read(utc_year)?.offset_at(at);
    // Windows stores rules by local year. Use the first offset to find the
    // adjacent year when the UTC and civil calendars straddle New Year's Day.
    let local_year = offset.to_datetime(at).year();
    if local_year == utc_year {
        return Some(offset);
    }
    let adjacent = read(local_year)?.offset_at(at);
    // A backward bias change at New Year can make both projections land
    // outside their rule's year. Keep the original offset in that interval.
    Some(if adjacent.to_datetime(at).year() == local_year {
        adjacent
    } else {
        offset
    })
}

fn midnight_in_local_year(at: Timestamp, read: impl Fn(i16) -> Option<YearRules>) -> Option<i64> {
    let day = offset_in_local_year(at, &read)?.to_datetime(at).date();
    let rules = read(day.year())?;
    let local = day.at(0, 0, 0, 0);
    [rules.standard, rules.daylight]
        .into_iter()
        .filter_map(|offset| {
            let at = offset.to_timestamp(local).ok()?;
            (offset_in_local_year(at, &read)? == offset).then_some(at.as_millisecond())
        })
        .min()
}

struct YearRules {
    standard: Offset,
    daylight: Offset,
    standard_starts: Option<Timestamp>,
    daylight_starts: Option<Timestamp>,
}

impl YearRules {
    #[allow(unsafe_code)]
    fn read(year: i16, zone: &DYNAMIC_TIME_ZONE_INFORMATION) -> Option<Self> {
        let info = if zone.DynamicDaylightTimeDisabled.0 != 0 {
            // Windows uses the fixed system rules in this mode. If the user
            // turned off DST, the system supplies zero transition months.
            TIME_ZONE_INFORMATION {
                Bias: zone.Bias,
                StandardBias: zone.StandardBias,
                DaylightBias: zone.DaylightBias,
                StandardDate: zone.StandardDate,
                DaylightDate: zone.DaylightDate,
                ..Default::default()
            }
        } else {
            let mut yearly = TIME_ZONE_INFORMATION::default();
            let lookup_year = year.max(1601) as u16;
            // SAFETY: both pointers refer to live structs of the specified
            // types. Windows reads the zone and writes the yearly rules.
            unsafe { GetTimeZoneInformationForYear(lookup_year, Some(zone), &mut yearly) }.ok()?;
            yearly
        };
        Self::from_information(&info, year)
    }

    fn from_information(info: &TIME_ZONE_INFORMATION, year: i16) -> Option<Self> {
        let offset = |extra| {
            let seconds = info.Bias.checked_add(extra)?.checked_mul(-60)?;
            Offset::from_seconds(seconds).ok()
        };
        let standard = offset(if info.StandardDate.wMonth == 0 {
            0
        } else {
            info.StandardBias
        })?;
        let daylight = offset(if info.DaylightDate.wMonth == 0 {
            0
        } else {
            info.DaylightBias
        })?;
        Some(Self {
            standard,
            daylight,
            standard_starts: transition(&info.StandardDate, year, daylight)?,
            daylight_starts: transition(&info.DaylightDate, year, standard)?,
        })
    }

    fn offset_at(&self, at: Timestamp) -> Offset {
        let in_daylight = match (self.daylight_starts, self.standard_starts) {
            (Some(start), Some(end)) if start < end => at >= start && at < end,
            (Some(start), Some(end)) if start > end => at >= start || at < end,
            (Some(start), None) => at >= start,
            (None, Some(end)) => at < end,
            _ => false,
        };
        if in_daylight {
            self.daylight
        } else {
            self.standard
        }
    }
}

fn transition(rule: &SYSTEMTIME, year: i16, offset_before: Offset) -> Option<Option<Timestamp>> {
    if rule.wMonth == 0 {
        return Some(None);
    }
    let month = i8::try_from(rule.wMonth).ok()?;
    let date = if rule.wYear == 0 {
        // Relative Windows rules count weekdays from Sunday. Week five
        // means the last occurrence, including months with four.
        let weekday = [
            Weekday::Sunday,
            Weekday::Monday,
            Weekday::Tuesday,
            Weekday::Wednesday,
            Weekday::Thursday,
            Weekday::Friday,
            Weekday::Saturday,
        ]
        .get(usize::from(rule.wDayOfWeek))
        .copied()?;
        let nth = match rule.wDay {
            1..=4 => i8::try_from(rule.wDay).ok()?,
            5 => -1,
            _ => return None,
        };
        Date::new(year, month, 1)
            .ok()?
            .nth_weekday_of_month(nth, weekday)
            .ok()?
    } else {
        Date::new(
            i16::try_from(rule.wYear).ok()?,
            month,
            i8::try_from(rule.wDay).ok()?,
        )
        .ok()?
    };
    let clock = Time::new(
        i8::try_from(rule.wHour).ok()?,
        i8::try_from(rule.wMinute).ok()?,
        i8::try_from(rule.wSecond).ok()?,
        i32::from(rule.wMilliseconds) * 1_000_000,
    )
    .ok()?;
    let at = offset_before
        .to_timestamp(DateTime::from_parts(date, clock))
        .ok()?;
    Some(Some(at))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_is_a_sane_civil_offset() {
        // Real time zones span UTC-12..UTC+14.
        let secs = WindowsTimeZone.utc_offset_seconds(0);
        assert!((-12 * 3600..=14 * 3600).contains(&secs), "offset {secs}");
    }

    #[test]
    fn historical_bias_uses_the_requested_years_rule() {
        let earlier = rules_with_dst(4);
        let later = rules_with_dst(3);
        let instant = utc("2024-03-20T12:00:00Z");
        assert_eq!(earlier.offset_at(instant).seconds(), -5 * 3600);
        assert_eq!(later.offset_at(instant).seconds(), -4 * 3600);
    }

    #[test]
    fn new_year_uses_the_civil_year_on_both_sides_of_utc() {
        let eastern = yearly_bias(-120, -180);
        let western = yearly_bias(180, 240);
        assert_eq!(
            offset_in_local_year(utc("2024-12-31T23:30:00Z"), eastern).map(Offset::seconds),
            Some(3 * 3600),
            "it is already 2025 east of UTC"
        );
        assert_eq!(
            offset_in_local_year(utc("2025-01-01T01:30:00Z"), western).map(Offset::seconds),
            Some(-3 * 3600),
            "it is still 2024 west of UTC"
        );
    }

    fn yearly_bias(earlier: i32, later: i32) -> impl Fn(i16) -> Option<YearRules> {
        move |year| {
            YearRules::from_information(
                &TIME_ZONE_INFORMATION {
                    Bias: if year == 2024 { earlier } else { later },
                    ..Default::default()
                },
                year,
            )
        }
    }

    #[test]
    fn a_windows_fold_uses_its_first_midnight_and_a_gap_has_no_midnight() {
        let read = |_| Some(rules_with_dst(3));
        assert_eq!(
            midnight_in_local_year(utc("2024-03-10T12:00:00Z"), read),
            None
        );
        assert_eq!(
            midnight_in_local_year(utc("2024-11-03T12:00:00Z"), read),
            Some(utc("2024-11-03T04:00:00Z").as_millisecond())
        );
    }

    #[test]
    fn new_year_bias_change_can_skip_midnight() {
        assert_eq!(
            midnight_in_local_year(utc("2025-01-01T12:00:00Z"), yearly_bias(-120, -180)),
            None
        );
    }

    #[test]
    fn no_dst_uses_the_fixed_base_bias_even_with_extra_bias_fields() {
        let zone = DYNAMIC_TIME_ZONE_INFORMATION {
            Bias: 300,
            StandardBias: 15,
            DaylightBias: -60,
            DynamicDaylightTimeDisabled: windows::Win32::Foundation::BOOLEAN(1),
            ..Default::default()
        };
        let read = |year| YearRules::read(year, &zone);
        assert_eq!(
            offset_in_local_year(utc("2024-07-01T12:00:00Z"), read).map(Offset::seconds),
            Some(-5 * 3600)
        );
        assert_eq!(
            midnight_in_local_year(utc("2024-07-01T12:00:00Z"), read),
            Some(utc("2024-07-01T05:00:00Z").as_millisecond())
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn current_offset_matches_the_active_windows_bias() {
        use windows::Win32::System::Time::GetTimeZoneInformation;

        let before = Timestamp::now();
        let mut info = TIME_ZONE_INFORMATION::default();
        // SAFETY: Windows only writes this live output struct.
        let kind = unsafe { GetTimeZoneInformation(&mut info) };
        let after = Timestamp::now();
        let extra = match kind {
            0 => 0,
            1 => info.StandardBias,
            2 => info.DaylightBias,
            _ => panic!("can read the current Windows time-zone information"),
        };
        let expected = -(info.Bias + extra) * 60;
        // A clock change may occur while the API runs. Either surrounding
        // instant can have the offset in force when it read the zone.
        assert!([before, after].into_iter().any(|instant| {
            WindowsTimeZone.utc_offset_seconds(instant.as_millisecond()) == expected
        }));
    }

    fn rules_with_dst(spring_month: u16) -> YearRules {
        let standard = SYSTEMTIME {
            wMonth: 11,
            wDay: 1,
            wHour: 1,
            ..Default::default()
        };
        let daylight = SYSTEMTIME {
            wMonth: spring_month,
            wDay: 2,
            ..Default::default()
        };
        YearRules::from_information(
            &TIME_ZONE_INFORMATION {
                Bias: 300,
                DaylightBias: -60,
                StandardDate: standard,
                DaylightDate: daylight,
                ..Default::default()
            },
            2024,
        )
        .expect("valid Windows rule")
    }

    fn utc(value: &str) -> Timestamp {
        value.parse().expect("UTC instant")
    }
}

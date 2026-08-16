//! Windows implementation of the neutral local-time port: the machine's civil
//! offset from UTC, daylight-aware, straight from the OS time-zone settings.

#![cfg(target_os = "windows")]

use nrr_platform_api::local_time::LocalTimeZonePort;

/// Reads the current offset via `GetTimeZoneInformation` on every call, so a
/// time-zone change (travel, DST switch) is picked up on the next tick without
/// a service restart.
#[derive(Debug, Default)]
pub struct WindowsTimeZone;

impl LocalTimeZonePort for WindowsTimeZone {
    fn utc_offset_seconds(&self, _now_ms: i64) -> i32 {
        current_offset_minutes().saturating_mul(60)
    }
}

#[allow(unsafe_code)]
fn current_offset_minutes() -> i32 {
    use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // `GetTimeZoneInformation` return values (no named constants in the
    // binding): 1 = standard time in effect, 2 = daylight time in effect.
    const STANDARD: u32 = 1;
    const DAYLIGHT: u32 = 2;
    let mut tzi = TIME_ZONE_INFORMATION::default();
    // SAFETY: `tzi` is a valid, writable struct for the duration of the call;
    // the API only fills it in.
    let id = unsafe { GetTimeZoneInformation(&mut tzi) };
    // Win32 bias is minutes to ADD to local time to reach UTC, so the civil
    // offset is its negation. The active variant's extra bias applies on top.
    let variant_bias = match id {
        DAYLIGHT => tzi.DaylightBias,
        STANDARD => tzi.StandardBias,
        _ => 0,
    };
    -(tzi.Bias.saturating_add(variant_bias))
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
}

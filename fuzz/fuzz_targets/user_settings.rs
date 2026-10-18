#![no_main]
//! `user-settings.json`, which any process of the same user can rewrite: the
//! parse and the format round trip.

use libfuzzer_sys::fuzz_target;
use nrr_shared::user_settings::{format_user_settings, parse_user_settings, UserSettings};

/// The store refuses a file above this size before parsing it.
const MAX_FILE_BYTES: usize = 256 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FILE_BYTES {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let Ok(settings) = parse_user_settings(&text) else {
        return;
    };
    let _ = settings.is_newer_format();
    let mut recorded = settings.clone();
    recorded.record_rules_file_written("/fuzz/rules_primary.txt", "00");
    let _ = recorded.rules_file_hand_edited("/fuzz/rules_primary.txt", Some("11"));
    if let Ok(formatted) = format_user_settings(&settings) {
        let _ = parse_user_settings(&formatted);
    }
    let mut merged = UserSettings::default();
    let _ = merged.adopt_changes(&UserSettings::default(), &settings);
});

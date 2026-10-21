#![no_main]
//! A foreign name on its way to a screen: whatever the bytes, the shown text
//! carries no character that executes, reorders or hides text, and stays
//! within the display cap.

use libfuzzer_sys::fuzz_target;
use nrr_shared::display_text::{
    display_text, needs_substitute, without_unsafe, DISPLAY_MAX_CHARS,
};

/// A registry `DisplayName` or a long exe path; well above the cap, so the cut
/// is exercised on every long input.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let shown = display_text(&text);
    assert!(!shown.chars().any(needs_substitute), "{shown:?}");
    assert!(shown.chars().count() <= DISPLAY_MAX_CHARS);
    if text.chars().count() <= DISPLAY_MAX_CHARS {
        assert_eq!(shown.chars().count(), text.chars().count());
    }
    assert_eq!(display_text(&shown), shown, "showing twice changes nothing");
    let kept = without_unsafe(&text);
    assert!(!kept.chars().any(needs_substitute), "{kept:?}");
    assert_eq!(kept.chars().count(), text.chars().count());
});

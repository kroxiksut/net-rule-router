#![no_main]
//! Free text from a stored log line on its way to a reader who is not an
//! administrator: whatever the bytes, masking never panics, stays within its
//! bound, leaves a second pass nothing to do, and a hostile line is either
//! shipped as valid JSON or not at all.

use libfuzzer_sys::fuzz_target;
use nrr_diagnostics::logs::privacy::{mask_paths_in_free_text, mask_paths_in_stored_line};
use nrr_diagnostics::privacy::path_scrub::MAX_SCRUB_INPUT_BYTES;

/// Past the scan bound, so the cut is exercised too.
const MAX_INPUT: usize = MAX_SCRUB_INPUT_BYTES + 4096;

/// The marker is 13 bytes and the shortest path it replaces is 3.
const GROWTH: usize = 5;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data).into_owned();

    let mut payload = serde_json::json!({ "error": text, "errors": [text], "count": 1 });
    mask_paths_in_free_text(&mut payload);
    let once = payload["error"].as_str().map(str::to_owned).unwrap_or_default();
    assert!(once.len() <= text.len() * GROWTH + 16, "{} -> {}", text.len(), once.len());
    assert_eq!(payload["errors"][0].as_str(), Some(once.as_str()));
    assert_eq!(payload["count"], 1);
    if once.len() <= MAX_SCRUB_INPUT_BYTES {
        let mut again = payload.clone();
        assert!(!mask_paths_in_free_text(&mut again), "{once:?}");
    }

    // The same bytes as a line from a log file.
    if let Some(line) = mask_paths_in_stored_line(&text) {
        if line.as_ref() != text {
            assert!(serde_json::from_str::<serde_json::Value>(&line).is_ok());
        }
    }
});

#![no_main]
//! One read from an inotify descriptor watching a rule folder: the event
//! walk, the names any user writing there chose, and the verdict on whether
//! the folder's programs may have changed.

use libfuzzer_sys::fuzz_target;

/// The watches read into a 16 KiB buffer.
const READ_BUFFER_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > READ_BUFFER_BYTES {
        return;
    }
    let (events, _relevant) = nrr_platform_linux::inotify_events::fuzz_events(data);
    assert!(events <= data.len() / 16 + 1);
});

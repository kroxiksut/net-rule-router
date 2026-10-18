#![no_main]
//! One buffer `ReadDirectoryChangesW` filled for a watched rule folder: the
//! record chain, the UTF-16 names any user writing there chose, and the
//! verdict on whether the folder's programs may have changed.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::app_folders::{notify_buffer_is_relevant, notify_records, MAX_NOTIFY_RECORDS};

/// The watch hands the OS a 64 KiB buffer.
const NOTIFY_BUFFER_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > NOTIFY_BUFFER_BYTES {
        return;
    }
    let records = notify_records(data);
    assert!(records.len() <= MAX_NOTIFY_RECORDS);
    let _ = notify_buffer_is_relevant(data);
});

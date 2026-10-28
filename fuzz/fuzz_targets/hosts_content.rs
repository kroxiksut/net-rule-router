#![no_main]
//! The OS hosts file, which another local program can rewrite: the clients'
//! "any real mapping?" classifier never panics on any bytes, and it agrees
//! with the service's parser whenever that parser finds a mapping.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::hosts_file::fuzzing::{HAS_ENTRIES_READ_LIMIT, SERVICE_READ_LIMIT};
use nrr_platform_api::hosts_file::parse_hosts_map;
use nrr_shared::platform_profile::hosts_content_has_entries;

fuzz_target!(|data: &[u8]| {
    // Neither reader parses a file above its bound.
    if data.len() as u64 > SERVICE_READ_LIMIT {
        return;
    }
    // Both read only valid UTF-8.
    let Ok(content) = std::str::from_utf8(data) else {
        return;
    };
    let map = parse_hosts_map(content);
    if data.len() as u64 > HAS_ENTRIES_READ_LIMIT {
        return;
    }
    if !map.is_empty() {
        assert!(hosts_content_has_entries(content), "{content:?}");
    }
});

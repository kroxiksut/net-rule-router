#![no_main]
//! `resolvectl monitor --json=short` output: systemd-resolved's account of
//! answers whose names and records a remote server chose, split into lines by
//! the bounded reader and then parsed one line at a time.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::dns_observe::MAX_ADDRESSES_PER_FAMILY;
use nrr_platform_linux::dns_observe::{
    fuzz_monitor_stream, parse_monitor_line, MAX_MONITOR_LINE_BYTES,
};

fuzz_target!(|data: &[u8]| {
    // Every line yields at most two observations.
    assert!(fuzz_monitor_stream(data) <= 2 * (data.iter().filter(|b| **b == b'\n').count() + 1));
    if data.len() > MAX_MONITOR_LINE_BYTES {
        return;
    }
    let Ok(line) = std::str::from_utf8(data) else {
        return;
    };
    let observations: Vec<_> = parse_monitor_line(line).collect();
    assert!(observations.len() <= 2);
    for observation in observations {
        assert!(observation.ipv4s.len() <= MAX_ADDRESSES_PER_FAMILY);
        assert!(observation.ipv6s.len() <= MAX_ADDRESSES_PER_FAMILY);
    }
});

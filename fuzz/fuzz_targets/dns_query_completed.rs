#![no_main]
//! One `Microsoft-Windows-DNS-Client` event 3008 payload: the UTF-16 strings
//! the DNS client wrote, and inside them the answers a remote server or an
//! on-path spoofer chose.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::dns_observe::{parse_query_completed, MAX_ADDRESSES_PER_FAMILY};

/// An ETW event, header included, is at most 64 KiB.
const ETW_EVENT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > ETW_EVENT_BYTES {
        return;
    }
    if let Some(observation) = parse_query_completed(data) {
        assert!(!(observation.ipv4s.is_empty() && observation.ipv6s.is_empty()));
        assert!(observation.ipv4s.len() <= MAX_ADDRESSES_PER_FAMILY);
        assert!(observation.ipv6s.len() <= MAX_ADDRESSES_PER_FAMILY);
        assert!(observation.ipv6s.iter().all(|ip| ip.to_ipv4_mapped().is_none()));
    }
});

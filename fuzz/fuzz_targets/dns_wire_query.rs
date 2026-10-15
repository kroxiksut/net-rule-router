#![no_main]
//! A DNS query as it reaches the local resolver: the question parse and every
//! response the listener builds back from the query bytes.

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::dns_wire;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The resolver reads one UDP datagram into a buffer of this size.
const MAX_UDP_QUERY: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_UDP_QUERY {
        return;
    }
    let _ = dns_wire::parse_question(data);
    let _ = dns_wire::question_key(data);
    let _ = dns_wire::is_truncated(data);
    let v4 = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
    let v6 = [Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
    let _ = dns_wire::build_a_response(data, &v4, 60);
    let _ = dns_wire::build_aaaa_response(data, &v6, 60);
    let _ = dns_wire::build_error_response(data, dns_wire::RCODE_SERVFAIL);
    let _ = dns_wire::build_negative_response(
        data,
        dns_wire::RCODE_NXDOMAIN,
        dns_wire::NEGATIVE_TTL_SECS,
    );
});

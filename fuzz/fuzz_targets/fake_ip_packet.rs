#![no_main]
//! One raw IP packet read off the fake-IP adapter: flow keying and the echo
//! request parse, before any state is touched.

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::fake_ip::flow;

/// The adapter's MTU bounds a packet.
const MAX_PACKET: usize = 65_535;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PACKET {
        return;
    }
    let _ = flow::parse_packet(data);
    let _ = flow::parse_echo_request(data);
});

#![no_main]
//! Client OPT/count/compression bytes and upstream response bytes meet at the
//! actual UDP send boundary. Neither may bypass its size limit or panic.
use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::dns_wire;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_535 {
        return;
    }
    let query =
        dns_wire::build_address_query(7, "large.example", dns_wire::QTYPE_A).expect("query");
    let ips: Vec<_> = (1..=32).map(|n| Ipv4Addr::new(192, 0, 2, n)).collect();
    let reply = dns_wire::build_a_response(&query, &ips, 60).expect("reply");
    if let Some(output) = dns_wire::fuzz_udp_reply(data, reply) {
        assert!(output.len() <= 65_507);
    }
    if let Some(output) = dns_wire::fuzz_udp_reply(&query, data.to_vec()) {
        assert!(output.len() <= 512);
    }
    // The same hostile query also reaches synthetic response construction.
    let _ = dns_wire::build_a_response(data, &ips, 60);
});

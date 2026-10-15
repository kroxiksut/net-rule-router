#![no_main]
//! An upstream reply: the A/AAAA and PTR answer walks, and the TCP length
//! framing a DNS-over-TCP peer shapes.

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::dns_wire;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    if data.len() > dns_wire::DNS_TCP_MAX_MESSAGE + 2 {
        return;
    }
    // The id the packet carries, so the "matching reply" path is reached as
    // often as the mismatch path.
    let id = match data {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    };
    for qtype in [dns_wire::QTYPE_A, dns_wire::QTYPE_AAAA, dns_wire::QTYPE_CNAME] {
        let _ = dns_wire::parse_address_response(id, "host.example", qtype, data);
        let _ = dns_wire::parse_address_response(id ^ 1, "host.example", qtype, data);
    }
    let _ = dns_wire::parse_ptr_response(id, Ipv4Addr::new(192, 0, 2, 7), data);

    let mut cursor = std::io::Cursor::new(data);
    while let Ok(Some(message)) =
        dns_wire::read_tcp_message(&mut cursor, dns_wire::DNS_TCP_MAX_MESSAGE)
    {
        let _ = dns_wire::parse_question(&message);
        let _ = dns_wire::is_truncated(&message);
        let mut out = Vec::new();
        let _ = dns_wire::write_tcp_message(&mut out, &message);
    }
});

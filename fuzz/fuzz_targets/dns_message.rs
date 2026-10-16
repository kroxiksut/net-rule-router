#![no_main]
//! An upstream reply to the Linux resolver: header, question echo, answer walk and name compression.

use libfuzzer_sys::fuzz_target;
use nrr_platform_linux::dns_message::{decode_response, AddressFamily};

/// The TCP length prefix caps a reply at 65535 bytes.
const MAX_REPLY_BYTES: usize = 65_535;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_REPLY_BYTES {
        return;
    }
    // The id the packet carries, so the matching-reply path is reached as
    // often as the mismatch path.
    let id = match data {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    };
    for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
        let _ = decode_response(data, id, "host.example", family);
        let _ = decode_response(data, id ^ 1, "host.example", family);
    }
});

#![no_main]
//! One netlink datagram from the NFLOG socket: the message walk, the packet
//! attributes and the IP header inside the copied payload.

use libfuzzer_sys::fuzz_target;

/// The observer reads into a 64 KiB buffer.
const READ_BUFFER_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > READ_BUFFER_BYTES {
        return;
    }
    nrr_platform_linux::nflog::fuzz_datagram(data);
    let _ = nrr_platform_linux::nflog::parse_packet(data);
    let _ = nrr_platform_linux::nflog::parse_ip_payload(data);
});

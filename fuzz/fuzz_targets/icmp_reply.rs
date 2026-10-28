#![no_main]
//! One datagram off the Linux ICMP sockets, which see every ICMP message any
//! host sends the machine: the hop-limited probe's classifier (echo reply,
//! time exceeded and unreachable with the quoted request) and the liveness
//! probe's reply match.

use libfuzzer_sys::fuzz_target;

/// Both probes read into a 1500-byte buffer.
const READ_BUFFER_BYTES: usize = 1500;

fuzz_target!(|data: &[u8]| {
    if data.len() > READ_BUFFER_BYTES {
        return;
    }
    let _ = nrr_platform_linux::icmp_echo::fuzz_datagram(data);
    let _ = nrr_platform_linux::reachability::fuzz_datagram(data);
});

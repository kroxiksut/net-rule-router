//! Linux mechanism behind
//! [`nrr_platform_api::reachability::ReachabilityProbe`].
//!
//! ICMP echo over a datagram ICMP socket where the host allows one, over a raw
//! ICMP socket otherwise.
//!
//! The datagram flavour is tried first because it needs no capability — but it
//! is gated on `net.ipv4.ping_group_range`, and being root is NOT a bypass: a
//! host whose range is empty (`1 0`, which is what WSL2 ships) refuses it with
//! `EACCES` for uid 0 as well. Relying on it alone would leave the probe
//! permanently indeterminate there, and an always-reachable liveness check
//! never notices a dead tunnel. The raw socket needs `CAP_NET_RAW`, which the
//! service has as root.
//!
//! ## Fail-SAFE direction
//!
//! Anything that stops the probe from running — socket, send, or a malformed
//! reply — answers `true`. Only a definite no-reply-within-timeout answers
//! `false`, because the caller turns a `false` into fail-closed traffic and an
//! indeterminate probe must never be what blocks a working adapter.
//!
//! ## Why the identifier is not matched
//!
//! On a datagram ICMP socket the kernel OVERWRITES the echo identifier with the
//! socket's own port and rewrites it back on the reply, so the value we put
//! there is not the value that comes back. A raw socket, in turn, receives
//! every process's ICMP, so a sequence number alone can collide with someone
//! else's ping. Replies are therefore matched on the sequence number plus the
//! echoed payload — the one field no kernel rewrites and no other pinger
//! spells the same way.

#![allow(unsafe_code)]
// The socket half has no caller off Linux; the packet codec below still
// compiles and is still tested there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::Ipv4Addr;
use std::time::Duration;

pub use nrr_platform_api::reachability::{
    AlwaysReachableProbe, MockReachabilityProbe, ReachabilityProbe,
};

/// Production ICMP-echo probe over a datagram ICMP socket.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxIcmpProbe;

impl ReachabilityProbe for LinuxIcmpProbe {
    #[cfg(target_os = "linux")]
    fn is_reachable(&self, target: Ipv4Addr, timeout: Duration) -> bool {
        // `Err` means the probe never ran; only `Ok(false)` is a real silence.
        echo_once(target, timeout).unwrap_or(true)
    }

    #[cfg(not(target_os = "linux"))]
    fn is_reachable(&self, _target: Ipv4Addr, _timeout: Duration) -> bool {
        true
    }
}

// ── Packet codec (pure; tested on every host) ────────────────────────────────

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
/// Type, code, checksum, identifier, sequence.
const ICMP_HEADER_LEN: usize = 8;
/// Enough payload to look like a normal ping to anything counting bytes.
const ECHO_PAYLOAD: &[u8] = b"nrr-reachability";

/// RFC 1071 one's-complement sum. Returns the value to store in the checksum
/// field, which is the complement of the sum — so running this over a complete
/// packet, checksum field included, yields zero.
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    // A trailing odd byte is padded on the right, per the RFC.
    if let Some(&last) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an echo request. `identifier` is written for well-formedness only —
/// a datagram ICMP socket replaces it (see the module note).
fn build_echo_request(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ICMP_HEADER_LEN + payload.len());
    packet.push(ICMP_ECHO_REQUEST);
    packet.push(0); // code
    packet.extend_from_slice(&[0, 0]); // checksum, filled in below
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(payload);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Sequence number and echoed payload of `datagram`, when it is a well-formed
/// ICMP echo reply.
///
/// A datagram ICMP socket delivers the ICMP header onward; a raw socket
/// prepends the IPv4 header. Both shapes are accepted — an echo reply's first
/// byte is `0`, so it can never be mistaken for an IPv4 header, whose version
/// nibble is `4`.
fn echo_reply_parts(datagram: &[u8]) -> Option<(u16, &[u8])> {
    let icmp = match datagram.first() {
        Some(first) if first >> 4 == 4 => {
            let header_len = usize::from(first & 0x0f) * 4;
            datagram.get(header_len..)?
        }
        _ => datagram,
    };
    if icmp.len() < ICMP_HEADER_LEN || icmp[0] != ICMP_ECHO_REPLY || icmp[1] != 0 {
        return None;
    }
    Some((
        u16::from_be_bytes([icmp[6], icmp[7]]),
        &icmp[ICMP_HEADER_LEN..],
    ))
}

/// Is this reply the answer to the request we just sent?
///
/// Sequence alone is not enough on a raw socket, which sees every process's
/// ICMP; the echoed payload is what makes the match ours.
fn is_our_reply(datagram: &[u8], sequence: u16, payload: &[u8]) -> bool {
    echo_reply_parts(datagram) == Some((sequence, payload))
}

// ── Socket mechanism (Linux only) ────────────────────────────────────────────

/// Send one echo request and wait for its reply.
///
/// `Ok(true)` — the target answered. `Ok(false)` — the timeout expired in
/// silence, the only answer that may fail-close. `Err` — the probe could not be
/// run, which the caller turns into "reachable".
#[cfg(target_os = "linux")]
fn echo_once(target: Ipv4Addr, timeout: Duration) -> std::io::Result<bool> {
    use std::time::Instant;

    let socket = IcmpSocket::open()?;
    socket.set_receive_timeout(timeout)?;

    // A fresh sequence per probe: a reply to the PREVIOUS probe, arriving late,
    // must not be read as an answer to this one.
    let sequence = next_sequence();
    let request = build_echo_request(sequence, sequence, ECHO_PAYLOAD);
    socket.send_to(&request, target)?;

    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 1500];
    loop {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        match socket.receive(&mut buffer) {
            // The socket carries whatever ICMP the kernel routes to it; another
            // process's ping is not ours to count.
            Ok(len) if is_our_reply(&buffer[..len], sequence, ECHO_PAYLOAD) => return Ok(true),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Monotonic per-process sequence source.
#[cfg(target_os = "linux")]
fn next_sequence() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Owning wrapper over the ICMP socket descriptor, so every early return closes
/// it exactly once.
#[cfg(target_os = "linux")]
struct IcmpSocket(libc::c_int);

#[cfg(target_os = "linux")]
impl IcmpSocket {
    /// Datagram first (no capability needed), raw as the fallback (needs
    /// `CAP_NET_RAW`). The datagram flavour is refused outright — for root too —
    /// on a host with an empty `net.ipv4.ping_group_range`, so without the
    /// fallback the probe would be permanently indeterminate there.
    fn open() -> std::io::Result<Self> {
        Self::open_kind(libc::SOCK_DGRAM).or_else(|_| Self::open_kind(libc::SOCK_RAW))
    }

    fn open_kind(kind: libc::c_int) -> std::io::Result<Self> {
        // SAFETY: `socket` takes three integers and returns a descriptor.
        let fd = unsafe { libc::socket(libc::AF_INET, kind, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    fn set_receive_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        // A zero timeval means "block forever" — never that. Anything under a
        // microsecond rounds up so a tiny timeout cannot become an eternal one.
        let micros = timeout.as_micros().max(1);
        let tv = libc::timeval {
            tv_sec: (micros / 1_000_000) as libc::time_t,
            tv_usec: (micros % 1_000_000) as libc::suseconds_t,
        };
        // SAFETY: `tv` is live for the call and its length is the size the
        // option expects; the kernel only reads it.
        let rc = unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn send_to(&self, packet: &[u8], target: Ipv4Addr) -> std::io::Result<()> {
        // SAFETY: `sockaddr_in` is plain data; an all-zero value is valid to
        // fill in field by field.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from(target).to_be(),
        };
        // SAFETY: the buffer and the address are live for the call; the length
        // passed is the size of the address actually written.
        let sent = unsafe {
            libc::sendto(
                self.0,
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
                0,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn receive(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: `buffer` is live and writable for its own length.
        let read = unsafe {
            libc::recv(
                self.0,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(read as usize)
    }
}

#[cfg(target_os = "linux")]
impl Drop for IcmpSocket {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by this value and closed once.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_request_checksums_to_zero() {
        // The defining property of the internet checksum: summing a complete
        // packet, its own checksum field included, cancels out.
        let packet = build_echo_request(0x1234, 7, ECHO_PAYLOAD);
        assert_eq!(internet_checksum(&packet), 0);
    }

    #[test]
    fn a_built_request_is_an_echo_request_carrying_its_sequence() {
        let packet = build_echo_request(0xabcd, 0x0102, b"x");
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(packet[1], 0);
        assert_eq!(&packet[4..6], &[0xab, 0xcd]);
        assert_eq!(&packet[6..8], &[0x01, 0x02]);
        assert_eq!(&packet[8..], b"x");
    }

    #[test]
    fn the_checksum_covers_an_odd_length_payload() {
        // The trailing byte is padded, not dropped — otherwise two packets
        // differing only in their last byte would checksum the same.
        let odd = build_echo_request(1, 1, b"abc");
        assert_eq!(internet_checksum(&odd), 0);
        let other = build_echo_request(1, 1, b"abd");
        assert_ne!(odd[2..4], other[2..4]);
    }

    /// The shape a datagram ICMP socket delivers: ICMP header onward.
    fn echo_reply(sequence: u16) -> Vec<u8> {
        let mut packet = build_echo_request(0x1111, sequence, ECHO_PAYLOAD);
        packet[0] = ICMP_ECHO_REPLY;
        packet
    }

    #[test]
    fn a_reply_yields_its_sequence_and_payload() {
        assert_eq!(
            echo_reply_parts(&echo_reply(0x2a2b)),
            Some((0x2a2b, ECHO_PAYLOAD))
        );
        assert!(is_our_reply(&echo_reply(0x2a2b), 0x2a2b, ECHO_PAYLOAD));
    }

    #[test]
    fn another_pingers_reply_with_the_same_sequence_is_not_ours() {
        // A raw socket sees every process's ICMP. Matching on the sequence
        // alone would let someone else's ping answer for our target.
        let mut foreign = build_echo_request(0x1111, 5, b"not-ours");
        foreign[0] = ICMP_ECHO_REPLY;
        assert!(!is_our_reply(&foreign, 5, ECHO_PAYLOAD));
        assert!(is_our_reply(&echo_reply(5), 5, ECHO_PAYLOAD));
    }

    #[test]
    fn a_reply_to_the_previous_probe_is_not_an_answer_to_this_one() {
        assert!(!is_our_reply(&echo_reply(41), 42, ECHO_PAYLOAD));
    }

    #[test]
    fn a_reply_behind_an_ipv4_header_is_still_read() {
        // A raw socket would prepend the IP header. An echo reply starts with
        // 0x00, so the version nibble tells the two shapes apart with no
        // ambiguity.
        let mut datagram = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        datagram.extend_from_slice(&echo_reply(9));
        assert_eq!(echo_reply_parts(&datagram).map(|(seq, _)| seq), Some(9));
    }

    #[test]
    fn an_echo_request_is_not_mistaken_for_a_reply() {
        // Our own outgoing packet can come back on a shared socket; counting it
        // would report every dead target as alive.
        let request = build_echo_request(1, 5, ECHO_PAYLOAD);
        assert!(echo_reply_parts(&request).is_none());
    }

    #[test]
    fn truncated_and_empty_datagrams_are_rejected() {
        assert!(echo_reply_parts(&[]).is_none());
        assert!(echo_reply_parts(&[0, 0, 0, 0]).is_none());
        // An IPv4 header claiming more length than the datagram has.
        assert!(echo_reply_parts(&[0x4f, 0, 0, 0]).is_none());
    }

    #[test]
    fn a_destination_unreachable_message_is_not_an_answer() {
        // Type 3 arrives on the same socket and means the opposite of alive.
        let mut packet = echo_reply(4);
        packet[0] = 3;
        assert!(echo_reply_parts(&packet).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_answers_its_own_ping() {
        // Needs an openable ICMP socket (root, or a gid inside
        // `net.ipv4.ping_group_range`). Where that is not granted the probe
        // cannot run, and the fail-safe direction returns `true` anyway — so
        // this assertion holds either way, and passes for the right reason on
        // a host that can actually send.
        let probe = LinuxIcmpProbe;
        assert!(probe.is_reachable(Ipv4Addr::LOCALHOST, Duration::from_secs(1)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_address_that_cannot_answer_reports_silence_when_the_probe_can_run() {
        // 192.0.2.0/24 is TEST-NET-1: reserved for documentation, routed
        // nowhere. If the socket opens, the only honest outcome is silence.
        let target = Ipv4Addr::new(192, 0, 2, 1);
        if IcmpSocket::open().is_err() {
            return; // No permission to send: nothing to assert.
        }
        assert!(!LinuxIcmpProbe.is_reachable(target, Duration::from_millis(300)));
    }
}

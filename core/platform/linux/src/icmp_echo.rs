//! Linux mechanism behind [`nrr_platform_api::icmp_echo::IcmpEchoPort`].
//!
//! A raw ICMP socket, not the datagram flavour the liveness probe prefers: only
//! a raw socket sees the "time exceeded" and "unreachable" messages routers
//! send back, and those are the whole point of a hop-limited probe. The service
//! has `CAP_NET_RAW` as root.
//!
//! A raw socket receives every process's ICMP, so an answer is ours only when it
//! names our identifier and sequence: an echo reply carries them directly, an
//! ICMP error quotes the first bytes of the request it is about.

#![allow(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::Ipv4Addr;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::icmp_echo::{EchoOutcome, EchoProbe, IcmpEchoPort};

use crate::reachability::ICMP_HEADER_LEN;

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_DEST_UNREACHABLE: u8 = 3;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const IPPROTO_ICMP: u8 = 1;

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxIcmpEcho;

/// IPv4 header length and the bytes after it, when `packet` holds a whole header.
fn split_ipv4(packet: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    Some(packet.split_at(header_len))
}

fn source_of(header: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(header[12], header[13], header[14], header[15])
}

fn destination_of(header: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(header[16], header[17], header[18], header[19])
}

fn names_request(icmp: &[u8], identifier: u16, sequence: u16) -> bool {
    icmp.len() >= ICMP_HEADER_LEN
        && u16::from_be_bytes([icmp[4], icmp[5]]) == identifier
        && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
}

/// What one datagram off the raw socket says about our probe, or `None` when it
/// is about something else.
fn classify(
    datagram: &[u8],
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Option<EchoOutcome> {
    let (outer, icmp) = split_ipv4(datagram)?;
    if icmp.len() < ICMP_HEADER_LEN {
        return None;
    }
    let from = source_of(outer);
    match icmp[0] {
        ICMP_ECHO_REPLY => (from == destination
            && names_request(icmp, identifier, sequence)
            && &icmp[ICMP_HEADER_LEN..] == payload)
            .then_some(EchoOutcome::Reply),
        kind @ (ICMP_TIME_EXCEEDED | ICMP_DEST_UNREACHABLE) => {
            let (inner, quoted) = split_ipv4(&icmp[ICMP_HEADER_LEN..])?;
            let ours = inner[9] == IPPROTO_ICMP
                && destination_of(inner) == destination
                && quoted.first() == Some(&ICMP_ECHO_REQUEST)
                && names_request(quoted, identifier, sequence);
            if !ours {
                return None;
            }
            Some(if kind == ICMP_TIME_EXCEEDED {
                EchoOutcome::TtlExpired { router: from }
            } else {
                EchoOutcome::Unreachable {
                    from,
                    code: icmp[1],
                }
            })
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl IcmpEchoPort for LinuxIcmpEcho {
    fn echo(&self, probe: &EchoProbe) -> Result<EchoOutcome, PlatformError> {
        use crate::reachability::{build_echo_request, next_sequence, IcmpSocket};
        use std::time::Instant;

        let errno = |operation: &'static str| {
            move |e: std::io::Error| PlatformError::Errno {
                operation,
                code: e.raw_os_error().unwrap_or(0),
                message: e.to_string(),
            }
        };
        let socket = IcmpSocket::open_kind(libc::SOCK_RAW).map_err(errno("socket(SOCK_RAW)"))?;
        socket
            .set_ttl(probe.ttl)
            .map_err(errno("setsockopt(IP_TTL)"))?;
        if let Some(source) = probe.source {
            socket.bind_source(source).map_err(errno("bind"))?;
        }
        let identifier = std::process::id() as u16;
        let sequence = next_sequence();
        let request = build_echo_request(identifier, sequence, &probe.payload);
        socket
            .send_to(&request, probe.destination)
            .map_err(errno("sendto"))?;

        let deadline = Instant::now() + probe.timeout;
        let mut buffer = [0u8; 1500];
        loop {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(EchoOutcome::TimedOut);
            };
            socket
                .set_receive_timeout(left)
                .map_err(errno("setsockopt(SO_RCVTIMEO)"))?;
            match socket.receive(&mut buffer) {
                Ok(len) => {
                    if let Some(outcome) = classify(
                        &buffer[..len],
                        probe.destination,
                        identifier,
                        sequence,
                        &probe.payload,
                    ) {
                        return Ok(outcome);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(EchoOutcome::TimedOut)
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(errno("recv")(e)),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl IcmpEchoPort for LinuxIcmpEcho {
    fn echo(&self, _probe: &EchoProbe) -> Result<EchoOutcome, PlatformError> {
        Err(PlatformError::NotSupported {
            reason: "the Linux ICMP mechanism runs only on Linux",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reachability::build_echo_request;

    const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
    const CLIENT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);
    const PAYLOAD: &[u8] = b"probe";

    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, IPPROTO_ICMP, 0, 0];
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(body);
        packet
    }

    fn reply(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut icmp = build_echo_request(identifier, sequence, payload);
        icmp[0] = ICMP_ECHO_REPLY;
        ipv4(TARGET, CLIENT, &icmp)
    }

    fn error(kind: u8, code: u8, identifier: u16, sequence: u16) -> Vec<u8> {
        let request = build_echo_request(identifier, sequence, PAYLOAD);
        let quoted = ipv4(CLIENT, TARGET, &request[..ICMP_HEADER_LEN]);
        let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted);
        ipv4(ROUTER, CLIENT, &icmp)
    }

    #[test]
    fn our_echo_reply_is_the_answer() {
        assert_eq!(
            classify(&reply(7, 9, PAYLOAD), TARGET, 7, 9, PAYLOAD),
            Some(EchoOutcome::Reply)
        );
    }

    #[test]
    fn a_router_quoting_our_request_ran_out_the_hop_limit() {
        assert_eq!(
            classify(&error(ICMP_TIME_EXCEEDED, 0, 7, 9), TARGET, 7, 9, PAYLOAD),
            Some(EchoOutcome::TtlExpired { router: ROUTER })
        );
    }

    #[test]
    fn unreachable_keeps_the_sender_and_code() {
        assert_eq!(
            classify(
                &error(ICMP_DEST_UNREACHABLE, 1, 7, 9),
                TARGET,
                7,
                9,
                PAYLOAD
            ),
            Some(EchoOutcome::Unreachable {
                from: ROUTER,
                code: 1
            })
        );
    }

    #[test]
    fn another_processes_traffic_is_not_ours() {
        assert_eq!(classify(&reply(8, 9, PAYLOAD), TARGET, 7, 9, PAYLOAD), None);
        assert_eq!(
            classify(&reply(7, 9, b"other"), TARGET, 7, 9, PAYLOAD),
            None
        );
        assert_eq!(
            classify(&error(ICMP_TIME_EXCEEDED, 0, 7, 10), TARGET, 7, 9, PAYLOAD),
            None
        );
        assert_eq!(
            classify(&error(ICMP_TIME_EXCEEDED, 0, 7, 9), ROUTER, 7, 9, PAYLOAD),
            None
        );
    }

    #[test]
    fn our_own_outgoing_request_is_not_an_answer() {
        let request = ipv4(CLIENT, TARGET, &build_echo_request(7, 9, PAYLOAD));
        assert_eq!(classify(&request, TARGET, 7, 9, PAYLOAD), None);
    }

    #[test]
    fn truncated_datagrams_are_ignored() {
        assert_eq!(classify(&[], TARGET, 7, 9, PAYLOAD), None);
        assert_eq!(classify(&[0x45, 0, 0], TARGET, 7, 9, PAYLOAD), None);
        let mut short_quote = error(ICMP_TIME_EXCEEDED, 0, 7, 9);
        short_quote.truncate(20 + 8 + 20 + 4);
        assert_eq!(classify(&short_quote, TARGET, 7, 9, PAYLOAD), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_answers_when_a_raw_socket_is_allowed() {
        if crate::reachability::IcmpSocket::open_kind(libc::SOCK_RAW).is_err() {
            return; // No CAP_NET_RAW: nothing to assert.
        }
        let outcome = LinuxIcmpEcho.echo(&EchoProbe {
            destination: Ipv4Addr::LOCALHOST,
            source: None,
            ttl: 64,
            payload: PAYLOAD.to_vec(),
            timeout: std::time::Duration::from_secs(1),
        });
        assert!(matches!(outcome, Ok(EchoOutcome::Reply)), "{outcome:?}");
    }
}

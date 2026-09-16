//! ICMP echo to a virtual address, carried to the real host and answered back.
//!
//! `ping` and `traceroute` aimed at a name land on a virtual address nobody
//! lives at. The probe goes out to the real address over the route the rules
//! give that name, with the hop limit the tool set, and what comes back — the
//! reply, a router's "time exceeded", an "unreachable" — is rebuilt toward the
//! client, so the tool reads the real path without knowing the real address.
//!
//! Same inherent impl, split across files.

use std::sync::atomic::AtomicUsize;

use nrr_platform_api::icmp_echo::EchoOutcome;
use smoltcp::wire::Icmpv4TimeExceeded;

use super::*;
use crate::fake_ip::flow::EchoCall;

/// Relayed echoes in flight at once. `traceroute` sends three per hop and
/// waits for them; past this a probe is dropped — the tool prints `*` — rather
/// than another thread started.
const MAX_ECHOES_IN_FLIGHT: usize = 32;

/// Hop limit of the answers we build; they cross only the adapter.
const ECHO_ANSWER_HOP_LIMIT: u8 = 64;

/// Answers built off the poll loop, waiting for it to write them.
#[derive(Default)]
pub(super) struct EchoAnswers {
    ready: Mutex<Vec<Vec<u8>>>,
    in_flight: AtomicUsize,
}

impl FakeIpStack {
    /// Carry `call` when the relay would carry a connection to its destination.
    /// `false` leaves the packet to the stack exactly as before.
    pub(super) fn relay_echo(&mut self, call: EchoCall) -> bool {
        let decision = self.relay.decide_endpoints(
            SocketAddr::new(call.source.into(), 0),
            SocketAddr::new(call.destination.into(), 0),
        );
        let RelayDecision::Relay { target, .. } = decision else {
            return false;
        };
        let answers = Arc::clone(&self.echo_answers);
        if answers.in_flight.fetch_add(1, Ordering::SeqCst) >= MAX_ECHOES_IN_FLIGHT {
            answers.in_flight.fetch_sub(1, Ordering::SeqCst);
            return true;
        }
        let dialer = Arc::clone(&self.dialer);
        let waker = Arc::clone(&self.waker);
        let log_gate = Arc::clone(&self.log_gate);
        let worker_answers = Arc::clone(&answers);
        let spawned = std::thread::Builder::new()
            .name("nrr-fake-ip-echo".into())
            .spawn(move || {
                match dialer.echo(&target, call.ttl, &call.payload) {
                    Ok(outcome) => {
                        if let Some(packet) = build_echo_answer(&call, outcome) {
                            guard(&worker_answers.ready).push(packet);
                            waker.wake();
                        }
                    }
                    Err(error) => {
                        if log_gate.first(format!("echo:{}", target.hostname)) {
                            tracing::debug!(
                                target: "nrr::fake-ip",
                                hostname = %target.hostname,
                                route = ?target.route,
                                %error,
                                "relayed echo could not be sent (first per host this session) — the tool sees no answer",
                            );
                        }
                    }
                }
                worker_answers.in_flight.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            answers.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        true
    }

    /// Write every echo answer that arrived since the last step.
    pub(super) fn flush_echo_answers(&mut self) {
        let ready = std::mem::take(&mut *guard(&self.echo_answers.ready));
        for packet in ready {
            self.device.write_client_packet(&packet);
        }
    }
}

/// The packet the client should receive for `outcome`, or `None` when nothing
/// came back and silence is the honest answer.
fn build_echo_answer(call: &EchoCall, outcome: EchoOutcome) -> Option<Vec<u8>> {
    let quoted = Ipv4Repr {
        src_addr: call.source,
        dst_addr: call.destination,
        next_header: IpProtocol::Icmp,
        payload_len: call.quoted_icmp.len() + call.payload.len(),
        hop_limit: call.ttl,
    };
    let (from, icmp) = match outcome {
        // Answered from the virtual address: that is the host the tool asked for.
        EchoOutcome::Reply => (
            call.destination,
            Icmpv4Repr::EchoReply {
                ident: call.ident,
                seq_no: call.seq_no,
                data: &call.payload,
            },
        ),
        EchoOutcome::TtlExpired { router } => (
            router,
            Icmpv4Repr::TimeExceeded {
                reason: Icmpv4TimeExceeded::TtlExpired,
                header: quoted,
                data: &call.quoted_icmp,
            },
        ),
        EchoOutcome::Unreachable { from, code } => (
            from,
            Icmpv4Repr::DstUnreachable {
                reason: Icmpv4DstUnreachable::from(code),
                header: quoted,
                data: &call.quoted_icmp,
            },
        ),
        EchoOutcome::TimedOut => return None,
    };
    let outer = Ipv4Repr {
        src_addr: from,
        dst_addr: call.source,
        next_header: IpProtocol::Icmp,
        payload_len: icmp.buffer_len(),
        hop_limit: ECHO_ANSWER_HOP_LIMIT,
    };
    let checksums = ChecksumCapabilities::default();
    let mut packet = vec![0u8; outer.buffer_len() + icmp.buffer_len()];
    let (header, body) = packet.split_at_mut(outer.buffer_len());
    icmp.emit(&mut Icmpv4Packet::new_unchecked(body), &checksums);
    outer.emit(&mut Ipv4Packet::new_unchecked(header), &checksums);
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
    const FAKE: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 9);
    const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    fn call() -> EchoCall {
        EchoCall {
            source: CLIENT,
            destination: FAKE,
            ttl: 2,
            ident: 0x0102,
            seq_no: 7,
            payload: b"abcd".to_vec(),
            quoted_icmp: [8, 0, 0x12, 0x34, 0x01, 0x02, 0, 7],
        }
    }

    fn parse(packet: &[u8]) -> (Ipv4Repr, Vec<u8>) {
        let checksums = ChecksumCapabilities::default();
        let ip = Ipv4Packet::new_checked(packet).expect("an IPv4 packet");
        assert!(ip.verify_checksum());
        let repr = Ipv4Repr::parse(&ip, &checksums).expect("a valid header");
        let icmp = Icmpv4Packet::new_checked(ip.payload()).expect("an ICMP message");
        assert!(icmp.verify_checksum());
        (repr, ip.payload().to_vec())
    }

    #[test]
    fn a_reply_comes_from_the_virtual_address_with_the_request_echoed() {
        let packet = build_echo_answer(&call(), EchoOutcome::Reply).expect("an answer");
        let (ip, icmp) = parse(&packet);
        assert_eq!((ip.src_addr, ip.dst_addr), (FAKE, CLIENT));
        let message = Icmpv4Packet::new_checked(&icmp[..]).expect("icmp");
        assert_eq!(message.msg_type(), smoltcp::wire::Icmpv4Message::EchoReply);
        assert_eq!((message.echo_ident(), message.echo_seq_no()), (0x0102, 7));
        assert_eq!(message.data(), b"abcd");
    }

    /// `tracert` pairs a "time exceeded" with its probe by the quote, and names
    /// the hop by the sender — so both must be the real router and our request.
    #[test]
    fn time_exceeded_comes_from_the_router_quoting_the_original_request() {
        let packet = build_echo_answer(&call(), EchoOutcome::TtlExpired { router: ROUTER })
            .expect("an answer");
        let (ip, icmp) = parse(&packet);
        assert_eq!((ip.src_addr, ip.dst_addr), (ROUTER, CLIENT));
        assert_eq!(icmp[0], 11);
        assert_eq!(icmp[1], 0);
        // Only the header and eight bytes are quoted, so the quoted length
        // claims more than is there — as it does from any real router.
        let inner = Ipv4Packet::new_unchecked(&icmp[8..]);
        assert_eq!((inner.src_addr(), inner.dst_addr()), (CLIENT, FAKE));
        assert_eq!(inner.next_header(), IpProtocol::Icmp);
        assert_eq!(&icmp[8 + 20..], &call().quoted_icmp);
    }

    #[test]
    fn unreachable_keeps_the_code_the_network_gave() {
        let packet = build_echo_answer(
            &call(),
            EchoOutcome::Unreachable {
                from: ROUTER,
                code: 1,
            },
        )
        .expect("an answer");
        let (ip, icmp) = parse(&packet);
        assert_eq!(ip.src_addr, ROUTER);
        assert_eq!((icmp[0], icmp[1]), (3, 1));
    }

    #[test]
    fn silence_is_passed_on_as_silence() {
        assert!(build_echo_answer(&call(), EchoOutcome::TimedOut).is_none());
    }
}

//! The drops our own rules made, read back from their NFLOG reports.
//!
//! The procfs observer sees sockets, never verdicts: a connection we dropped
//! looks exactly like one never made. Every drop the lowering emits jumps to a
//! chain that logs the packet to [`NRR_NFLOG_GROUP`] under a rate limit before
//! dropping it ([`crate::drop_tag`]), so the packet arrives here with the role of
//! the rule that dropped it, its owner's uid and its addresses.
//!
//! ## Cost
//!
//! Nothing on a packet that is not dropped: the accept path is the rule it
//! always was. A dropped packet pays a jump, a token-bucket check and, within
//! the limit, an 80-byte copy into a netlink message. Here, parsing is a few
//! bounds-checked reads on a reader thread; naming the program is deferred to
//! the drain, bounded per drain, and only for drops that have a socket.
//!
//! The codec below is pure and tested on every host; the socket and the
//! observer ([`observer`]) are Linux-only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nrr_platform_api::conn_observe::TransportProtocol;

use crate::drop_tag::{DropKind, DropTag};

#[cfg(target_os = "linux")]
pub mod observer;

#[cfg(target_os = "linux")]
pub use observer::{NflogDropObserver, NflogStats};

// ── Wire constants (uapi: linux/netlink.h, linux/netfilter/nfnetlink_log.h) ──

const NLMSG_HEADER_LEN: usize = 16;
/// `struct nfgenmsg`: family, version, resource id (the group, big-endian).
const NFGENMSG_LEN: usize = 4;
const NLA_HEADER_LEN: usize = 4;
/// Strips `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` from an attribute type.
const NLA_TYPE_MASK: u16 = 0x3fff;
const NLMSG_ALIGNMENT: usize = 4;

pub(crate) const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

const NFNL_SUBSYS_ULOG: u16 = 4;
/// `NFULNL_MSG_PACKET` in the ULOG subsystem.
pub(crate) const NFULNL_PACKET: u16 = NFNL_SUBSYS_ULOG << 8;
/// `NFULNL_MSG_CONFIG` in the ULOG subsystem.
const NFULNL_CONFIG: u16 = (NFNL_SUBSYS_ULOG << 8) | 1;

const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;

const NFULA_TIMESTAMP: u16 = 3;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_UID: u16 = 11;

const AF_UNSPEC: u8 = 0;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;
/// More chained extension headers than this inside an 80-byte copy is not a
/// packet worth reading further.
const MAX_IPV6_EXTENSIONS: usize = 4;

const fn align(value: usize) -> usize {
    value.div_ceil(NLMSG_ALIGNMENT) * NLMSG_ALIGNMENT
}

// ── Configuration (pure) ─────────────────────────────────────────────────────

/// One `NFULNL_MSG_CONFIG` request with a single attribute, acknowledged.
fn encode_config(sequence: u32, group: u16, attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let attr_len = NLA_HEADER_LEN + payload.len();
    let total = NLMSG_HEADER_LEN + NFGENMSG_LEN + align(attr_len);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u32).to_ne_bytes());
    out.extend_from_slice(&NFULNL_CONFIG.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    // The group binding is family-independent; `AF_UNSPEC` says so.
    out.push(AF_UNSPEC);
    out.push(0);
    out.extend_from_slice(&group.to_be_bytes());
    out.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0);
    out
}

/// Become the listener of `group`. The kernel allows one per group and
/// answers `EBUSY` while another program holds it.
pub(crate) fn encode_bind(sequence: u32, group: u16) -> Vec<u8> {
    encode_config(sequence, group, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND])
}

/// Copy the first `copy_range` bytes of each packet.
pub(crate) fn encode_copy_mode(sequence: u32, group: u16, copy_range: u32) -> Vec<u8> {
    // `struct nfulnl_msg_config_mode`: be32 range, u8 mode, u8 pad.
    let mut mode = [0u8; 6];
    mode[..4].copy_from_slice(&copy_range.to_be_bytes());
    mode[4] = NFULNL_COPY_PACKET;
    encode_config(sequence, group, NFULA_CFG_MODE, &mode)
}

// ── Parsing (pure) ───────────────────────────────────────────────────────────

/// The netlink messages of one datagram as `(type, body)`. A truncated or
/// malformed length ends the walk: a bad frame costs the rest of the datagram.
pub(crate) fn messages(datagram: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut offset = 0usize;
    std::iter::from_fn(move || {
        let header = datagram.get(offset..offset + NLMSG_HEADER_LEN)?;
        let length = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if length < NLMSG_HEADER_LEN {
            return None;
        }
        let body = datagram.get(offset + NLMSG_HEADER_LEN..offset + length)?;
        let message_type = u16::from_ne_bytes([header[4], header[5]]);
        offset += align(length);
        Some((message_type, body))
    })
}

/// The errno of an `NLMSG_ERROR` body, negative, or `0` for an acknowledgement.
pub(crate) fn error_code(body: &[u8]) -> Option<i32> {
    let raw = body.get(..4)?;
    Some(i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// One packet our rules dropped, as the kernel reported it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DroppedPacket {
    pub tag: DropTag,
    /// The sending socket's owner; `None` for a packet with no socket behind it
    /// (the kernel's own resets and ICMP).
    pub uid: Option<u32>,
    pub protocol: TransportProtocol,
    /// Source address and port; port `0` when the transport has none.
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// When the kernel stamped it, if it did; the output path usually does not.
    pub at_unix_ms: Option<u64>,
}

/// Why a packet message was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketRejection {
    /// Another program's rule logging to our group.
    Foreign,
    /// Truncated, or not an IP packet.
    Unreadable,
}

/// Parse the body of one `NFULNL_MSG_PACKET`.
pub fn parse_packet(body: &[u8]) -> Result<DroppedPacket, PacketRejection> {
    let mut prefix = None;
    let mut uid = None;
    let mut payload = None;
    let mut at_unix_ms = None;
    for (attr_type, value) in attributes(body.get(NFGENMSG_LEN..).unwrap_or_default()) {
        match attr_type {
            NFULA_PREFIX => prefix = Some(value),
            NFULA_UID => uid = be_u32(value),
            NFULA_PAYLOAD => payload = Some(value),
            NFULA_TIMESTAMP => at_unix_ms = timestamp_ms(value),
            _ => {}
        }
    }
    let prefix = prefix.ok_or(PacketRejection::Foreign)?;
    let text = prefix.split(|b| *b == 0).next().unwrap_or_default();
    let tag = std::str::from_utf8(text)
        .ok()
        .and_then(DropTag::parse_prefix)
        .ok_or(PacketRejection::Foreign)?;
    let (protocol, local, remote) = payload
        .and_then(parse_ip_payload)
        .ok_or(PacketRejection::Unreadable)?;
    Ok(DroppedPacket {
        tag,
        uid,
        protocol,
        local,
        remote,
        at_unix_ms,
    })
}

/// The tag a consumer should read. On Windows IPv6 is closed by its own
/// filter; here the block-all is family-less and drops IPv6 first, so an IPv6
/// packet it dropped is the same news as the Windows IPv6 cut.
#[must_use]
pub fn reported_tag(tag: DropTag, remote: &SocketAddr) -> DropTag {
    if tag.kind == DropKind::BlockAll && remote.is_ipv6() {
        DropTag {
            kind: DropKind::Ipv6Cut,
            ..tag
        }
    } else {
        tag
    }
}

fn attributes(mut data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let header = data.get(..NLA_HEADER_LEN)?;
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        if length < NLA_HEADER_LEN {
            return None;
        }
        let value = data.get(NLA_HEADER_LEN..length)?;
        let attr_type = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        data = data.get(align(length)..).unwrap_or_default();
        Some((attr_type, value))
    })
}

fn be_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?))
}

/// `struct nfulnl_msg_packet_timestamp`: be64 seconds, be64 microseconds.
fn timestamp_ms(value: &[u8]) -> Option<u64> {
    let secs = u64::from_be_bytes(value.get(..8)?.try_into().ok()?);
    let micros = u64::from_be_bytes(value.get(8..16)?.try_into().ok()?);
    secs.checked_mul(1000)?.checked_add(micros / 1000)
}

/// Protocol and both endpoints of an IPv4 or IPv6 packet. Ports are `0` when
/// the transport has none, the packet is a later fragment, or the copy ended
/// before them — the addresses are still worth reporting.
pub fn parse_ip_payload(packet: &[u8]) -> Option<(TransportProtocol, SocketAddr, SocketAddr)> {
    match packet.first()? >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<(TransportProtocol, SocketAddr, SocketAddr)> {
    let header = packet.get(..20)?;
    let header_len = usize::from(header[0] & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let proto = header[9];
    let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
    let later_fragment = u16::from_be_bytes([header[6], header[7]]) & 0x1fff != 0;
    let (sport, dport) = if later_fragment {
        (0, 0)
    } else {
        ports(proto, packet.get(header_len..))
    };
    Some((
        transport(proto),
        SocketAddr::new(IpAddr::V4(src), sport),
        SocketAddr::new(IpAddr::V4(dst), dport),
    ))
}

fn parse_ipv6(packet: &[u8]) -> Option<(TransportProtocol, SocketAddr, SocketAddr)> {
    let header = packet.get(..40)?;
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).ok()?);
    let (proto, transport_at) = skip_ipv6_extensions(packet, header[6]);
    let (sport, dport) = match transport_at {
        Some(at) => ports(proto, packet.get(at..)),
        None => (0, 0),
    };
    Some((
        transport(proto),
        SocketAddr::new(IpAddr::V6(src), sport),
        SocketAddr::new(IpAddr::V6(dst), dport),
    ))
}

/// The transport protocol and where its header starts; `None` for the start
/// when it lies beyond the copy or behind a later fragment.
fn skip_ipv6_extensions(packet: &[u8], first: u8) -> (u8, Option<usize>) {
    let mut next = first;
    let mut at = 40usize;
    for _ in 0..MAX_IPV6_EXTENSIONS {
        let extension = matches!(
            next,
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_FRAGMENT
        );
        if !extension {
            return (next, Some(at));
        }
        let Some(ext) = packet.get(at..at + 4) else {
            return (next, None);
        };
        if next == IPPROTO_FRAGMENT {
            if u16::from_be_bytes([ext[2], ext[3]]) & 0xfff8 != 0 {
                return (ext[0], None);
            }
            at += 8;
        } else {
            at += (usize::from(ext[1]) + 1) * 8;
        }
        next = ext[0];
    }
    (next, None)
}

fn ports(proto: u8, transport_header: Option<&[u8]>) -> (u16, u16) {
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return (0, 0);
    }
    match transport_header.and_then(|t| t.get(..4)) {
        Some(p) => (
            u16::from_be_bytes([p[0], p[1]]),
            u16::from_be_bytes([p[2], p[3]]),
        ),
        None => (0, 0),
    }
}

const fn transport(proto: u8) -> TransportProtocol {
    match proto {
        IPPROTO_TCP => TransportProtocol::Tcp,
        IPPROTO_UDP => TransportProtocol::Udp,
        other => TransportProtocol::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 TCP SYN from 192.0.2.10:51634 to 198.51.100.7:443.
    fn ipv4_syn() -> Vec<u8> {
        let mut p = vec![
            0x45,
            0,
            0,
            60,
            0x12,
            0x34,
            0x40,
            0,
            64,
            IPPROTO_TCP,
            0,
            0,
            192,
            0,
            2,
            10,
            198,
            51,
            100,
            7,
        ];
        p.extend_from_slice(&51634u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    /// An IPv6 UDP datagram from 2001:db8::10:40000 to 2001:db8::53:53 behind a
    /// hop-by-hop header.
    fn ipv6_udp_behind_hop_by_hop() -> Vec<u8> {
        let src: Ipv6Addr = "2001:db8::10".parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
        let dst: Ipv6Addr = "2001:db8::53".parse().unwrap_or(Ipv6Addr::UNSPECIFIED);
        let mut p = vec![0x60, 0, 0, 0, 0, 16, IPPROTO_HOPOPTS, 64];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&[IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&[0, 8, 0, 0]);
        p
    }

    fn attr(out: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        out.extend_from_slice(&((NLA_HEADER_LEN + value.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&attr_type.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(align(out.len()), 0);
    }

    /// A packet message the way the kernel builds one: nfgenmsg, the hardware
    /// header attribute, then prefix, uid and payload.
    fn packet_body(prefix: &str, uid: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![2, 0];
        body.extend_from_slice(&crate::drop_tag::NRR_NFLOG_GROUP.to_be_bytes());
        // NFULA_PACKET_HDR: be16 hw_protocol, hook, pad.
        attr(&mut body, 1, &[0x08, 0x00, 3, 0]);
        let mut prefix = prefix.as_bytes().to_vec();
        prefix.push(0);
        attr(&mut body, NFULA_PREFIX, &prefix);
        if let Some(uid) = uid {
            attr(&mut body, NFULA_UID, &uid.to_be_bytes());
        }
        attr(&mut body, NFULA_PAYLOAD, payload);
        body
    }

    fn framed(message_type: u16, body: &[u8]) -> Vec<u8> {
        let total = NLMSG_HEADER_LEN + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(total as u32).to_ne_bytes());
        out.extend_from_slice(&message_type.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(body);
        out.resize(align(out.len()), 0);
        out
    }

    fn addr(text: &str) -> SocketAddr {
        text.parse()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    #[test]
    fn the_bind_request_names_the_group_big_endian_and_asks_for_an_ack() {
        let message = encode_bind(7, 0x4E52);
        assert_eq!(message.len(), 28);
        assert_eq!(&message[..4], &28u32.to_ne_bytes());
        assert_eq!(&message[4..6], &0x0401u16.to_ne_bytes());
        assert_eq!(&message[6..8], &5u16.to_ne_bytes());
        assert_eq!(&message[8..12], &7u32.to_ne_bytes());
        // nfgenmsg: AF_UNSPEC, version 0, group 0x4E52 big-endian.
        assert_eq!(&message[16..20], &[0, 0, 0x4E, 0x52]);
        // NFULA_CFG_CMD = BIND, padded.
        assert_eq!(&message[20..22], &5u16.to_ne_bytes());
        assert_eq!(&message[22..24], &NFULA_CFG_CMD.to_ne_bytes());
        assert_eq!(&message[24..28], &[NFULNL_CFG_CMD_BIND, 0, 0, 0]);
    }

    #[test]
    fn the_copy_mode_asks_for_the_packet_up_to_the_snaplen() {
        let message = encode_copy_mode(8, 0x4E52, 80);
        assert_eq!(message.len(), 32);
        assert_eq!(&message[..4], &32u32.to_ne_bytes());
        assert_eq!(&message[20..22], &10u16.to_ne_bytes());
        assert_eq!(&message[22..24], &NFULA_CFG_MODE.to_ne_bytes());
        assert_eq!(&message[24..30], &[0, 0, 0, 80, NFULNL_COPY_PACKET, 0]);
    }

    #[test]
    fn a_v4_packet_message_parses_into_tag_uid_and_endpoints() {
        let datagram = framed(
            NFULNL_PACKET,
            &packet_body("nrr:pin", Some(1000), &ipv4_syn()),
        );
        let parsed: Vec<_> = messages(&datagram)
            .filter(|(t, _)| *t == NFULNL_PACKET)
            .map(|(_, body)| parse_packet(body))
            .collect();
        assert_eq!(
            parsed,
            vec![Ok(DroppedPacket {
                tag: DropTag::user(DropKind::Pin),
                uid: Some(1000),
                protocol: TransportProtocol::Tcp,
                local: addr("192.0.2.10:51634"),
                remote: addr("198.51.100.7:443"),
                at_unix_ms: None,
            })]
        );
    }

    #[test]
    fn a_v6_payload_is_read_past_its_extension_header() {
        let parsed = parse_ip_payload(&ipv6_udp_behind_hop_by_hop());
        assert_eq!(
            parsed,
            Some((
                TransportProtocol::Udp,
                addr("[2001:db8::10]:40000"),
                addr("[2001:db8::53]:53"),
            ))
        );
    }

    #[test]
    fn a_packet_without_a_socket_carries_no_uid_and_a_service_drop_keeps_its_scope() {
        let body = packet_body("nrr:all:sys", None, &ipv4_syn());
        let packet = parse_packet(&body).expect("ours");
        assert_eq!(packet.uid, None);
        assert_eq!(
            packet.tag,
            DropTag {
                kind: DropKind::BlockAll,
                system: true,
            }
        );
    }

    #[test]
    fn another_programs_prefix_is_not_taken_for_ours() {
        let body = packet_body("ufw-block", Some(1000), &ipv4_syn());
        assert_eq!(parse_packet(&body), Err(PacketRejection::Foreign));
    }

    #[test]
    fn a_truncated_payload_is_unreadable_and_a_short_one_keeps_its_addresses() {
        let body = packet_body("nrr:rule", Some(1000), &ipv4_syn()[..12]);
        assert_eq!(parse_packet(&body), Err(PacketRejection::Unreadable));
        let parsed = parse_ip_payload(&ipv4_syn()[..22]);
        assert_eq!(
            parsed,
            Some((
                TransportProtocol::Tcp,
                addr("192.0.2.10:0"),
                addr("198.51.100.7:0"),
            ))
        );
    }

    #[test]
    fn a_later_fragment_names_no_ports() {
        let mut packet = ipv4_syn();
        packet[6] = 0x00;
        packet[7] = 0x10;
        let (_, local, remote) = parse_ip_payload(&packet).expect("addresses");
        assert_eq!((local.port(), remote.port()), (0, 0));
    }

    #[test]
    fn an_icmp_drop_reports_its_protocol_number() {
        let mut packet = ipv4_syn();
        packet[9] = 1;
        let (protocol, _, remote) = parse_ip_payload(&packet).expect("addresses");
        assert_eq!(protocol, TransportProtocol::Other(1));
        assert_eq!(remote.port(), 0);
    }

    #[test]
    fn the_kernel_timestamp_is_read_in_milliseconds() {
        let mut body = packet_body("nrr:pin", Some(1000), &ipv4_syn());
        let mut stamp = 1_782_445_490u64.to_be_bytes().to_vec();
        stamp.extend_from_slice(&400_123u64.to_be_bytes());
        attr(&mut body, NFULA_TIMESTAMP, &stamp);
        let packet = parse_packet(&body).expect("ours");
        assert_eq!(packet.at_unix_ms, Some(1_782_445_490_400));
    }

    #[test]
    fn several_messages_in_one_datagram_are_all_read_and_an_ack_is_seen() {
        let mut datagram = framed(NFULNL_PACKET, &packet_body("nrr:pin", Some(1), &ipv4_syn()));
        datagram.extend(framed(NLMSG_ERROR, &0i32.to_ne_bytes()));
        datagram.extend(framed(
            NFULNL_PACKET,
            &packet_body("nrr:v6", Some(2), &ipv6_udp_behind_hop_by_hop()),
        ));
        let seen: Vec<u16> = messages(&datagram).map(|(t, _)| t).collect();
        assert_eq!(seen, vec![NFULNL_PACKET, NLMSG_ERROR, NFULNL_PACKET]);
        let ack = messages(&datagram)
            .find(|(t, _)| *t == NLMSG_ERROR)
            .and_then(|(_, body)| error_code(body));
        assert_eq!(ack, Some(0));
    }

    #[test]
    fn a_bad_length_ends_the_walk_instead_of_looping() {
        let mut datagram = framed(NFULNL_PACKET, &packet_body("nrr:pin", Some(1), &ipv4_syn()));
        datagram.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(messages(&datagram).count(), 1);
    }

    #[test]
    fn an_ipv6_drop_by_the_block_all_reads_as_the_ipv6_cut() {
        let all = DropTag::user(DropKind::BlockAll);
        assert_eq!(
            reported_tag(all, &addr("[2001:db8::53]:443")).kind,
            DropKind::Ipv6Cut
        );
        assert_eq!(reported_tag(all, &addr("198.51.100.7:443")), all);
        let pin = DropTag::user(DropKind::Pin);
        assert_eq!(reported_tag(pin, &addr("[2001:db8::53]:443")), pin);
    }
}

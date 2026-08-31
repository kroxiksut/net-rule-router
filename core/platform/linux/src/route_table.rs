//! Linux mechanism for the IPv4 route table: rtnetlink.
//!
//! The kernel's own interface for reading and changing routes — the same one
//! `ip route` drives. We already speak it in [`crate::network_change`] (an
//! `AF_NETLINK`/`NETLINK_ROUTE` socket subscribed to the change feed), so this
//! adds the request/response half rather than a new dependency: no async
//! runtime, no `iproute2` on the host, and errors arrive as kernel error codes
//! instead of text to parse.
//!
//! ## Shape of the module
//!
//! Message ENCODING and DUMP PARSING are pure functions over byte slices, so
//! they compile and are tested on every host, Windows included. Only the socket
//! round-trip is `cfg(target_os = "linux")`. That split is what let this land
//! with real tests rather than "it compiles".
//!
//! ## `is_ours`
//!
//! Always reported as `false`, exactly as the Windows FFI does: the marker is
//! storage-anchored — the caller cross-references persisted
//! `(destination, prefix, ifindex)` tuples. A route protocol number would be a
//! tempting shortcut and a wrong one, since nothing stops another program from
//! using the same value.

#![allow(unsafe_code)]
// The socket half has no caller off Linux; the encoder/parser below still
// compiles and is still tested there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::Ipv4Addr;

use nrr_platform_api::enforcement::RouteTableRef;
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::types::RouteEntry;

// ── Wire constants (uapi: linux/netlink.h, linux/rtnetlink.h) ────────────────

/// `struct nlmsghdr`: length, type, flags, sequence, port id.
const NLMSG_HEADER_LEN: usize = 16;
/// `struct rtmsg`, which follows the header on every route message.
const RTMSG_LEN: usize = 12;
/// `struct rtattr` header: length + type.
const RTATTR_HEADER_LEN: usize = 4;
/// Netlink pads every message and attribute to a 4-byte boundary.
const NLMSG_ALIGNMENT: usize = 4;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
/// `NLM_F_ROOT | NLM_F_MATCH` — "dump everything matching".
const NLM_F_DUMP: u16 = 0x0100 | 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;

const AF_INET_U8: u8 = 2;

/// `RT_TABLE_MAIN`. The table every ordinary route lives in.
const RT_TABLE_MAIN: u8 = 254;
/// `RTPROT_STATIC` — "an administrator added this". The same intent as the
/// Windows side's `MIB_IPPROTO_NETMGMT`, and just as much a hint rather than an
/// identity.
const RTPROT_STATIC: u8 = 4;
/// `RT_SCOPE_UNIVERSE` — the destination is somewhere beyond this box.
const RT_SCOPE_UNIVERSE: u8 = 0;
/// `RTN_UNICAST`.
const RTN_UNICAST: u8 = 1;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;

/// Round `value` up to the netlink alignment.
const fn align(value: usize) -> usize {
    value.div_ceil(NLMSG_ALIGNMENT) * NLMSG_ALIGNMENT
}

// ── Encoding (pure) ──────────────────────────────────────────────────────────

/// Which table number a neutral [`RouteTableRef`] names.
///
/// `Principal` has no number until per-user routing assigns one, and inventing
/// `main` for it would silently write a user's route into everybody's table —
/// so it refuses instead.
fn table_number(table: &RouteTableRef) -> Result<u32, PlatformError> {
    match table {
        RouteTableRef::Main => Ok(u32::from(RT_TABLE_MAIN)),
        RouteTableRef::Tagged(n) => Ok(*n),
        RouteTableRef::Principal(_) => Err(PlatformError::NotSupported {
            reason: "per-principal routing tables are not assigned yet; \
                     writing this route into the main table would apply it to every user",
        }),
    }
}

/// Append one `struct rtattr` with a payload, padded to the alignment.
fn push_attr(buffer: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let len = RTATTR_HEADER_LEN + payload.len();
    buffer.extend_from_slice(&(len as u16).to_ne_bytes());
    buffer.extend_from_slice(&attr_type.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align(buffer.len()), 0);
}

/// Encode `RTM_NEWROUTE` / `RTM_DELROUTE` for one entry.
///
/// `sequence` is echoed by the kernel in its `NLMSG_ERROR` reply, which is how
/// the round-trip below knows the acknowledgement belongs to this request.
fn encode_route_mutation(
    message_type: u16,
    entry: &RouteEntry,
    sequence: u32,
) -> Result<Vec<u8>, PlatformError> {
    let table = table_number(&entry.table)?;
    if entry.prefix_length > 32 {
        return Err(PlatformError::StateCorrupted {
            detail: format!(
                "route carries prefix length {}, which is not a v4 prefix",
                entry.prefix_length
            ),
        });
    }

    let mut body = Vec::with_capacity(64);
    // struct rtmsg
    body.push(AF_INET_U8); // rtm_family
    body.push(entry.prefix_length); // rtm_dst_len
    body.push(0); // rtm_src_len
    body.push(0); // rtm_tos
                  // A table number above 255 does not fit the byte; the kernel then reads
                  // RTA_TABLE and expects RT_TABLE_UNSPEC here.
    body.push(if table <= u32::from(u8::MAX) {
        table as u8
    } else {
        0
    });
    body.push(RTPROT_STATIC); // rtm_protocol
    body.push(RT_SCOPE_UNIVERSE); // rtm_scope
    body.push(RTN_UNICAST); // rtm_type
    body.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
    debug_assert_eq!(body.len(), RTMSG_LEN);

    push_attr(&mut body, RTA_DST, &entry.destination.octets());
    // An unspecified next hop is an on-link route: the attribute must be absent
    // rather than zero, or the kernel routes to 0.0.0.0.
    if !entry.next_hop.is_unspecified() {
        push_attr(&mut body, RTA_GATEWAY, &entry.next_hop.octets());
    }
    push_attr(&mut body, RTA_OIF, &entry.interface_index.to_ne_bytes());
    push_attr(&mut body, RTA_PRIORITY, &entry.metric.to_ne_bytes());
    if table > u32::from(u8::MAX) {
        push_attr(&mut body, RTA_TABLE, &table.to_ne_bytes());
    }

    let flags = match message_type {
        RTM_NEWROUTE => NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        _ => NLM_F_REQUEST | NLM_F_ACK,
    };
    Ok(frame(message_type, flags, sequence, &body))
}

/// Encode the `RTM_GETROUTE` dump request.
fn encode_route_dump(sequence: u32) -> Vec<u8> {
    let mut body = vec![0u8; RTMSG_LEN];
    body[0] = AF_INET_U8; // rtm_family — v4 routes only
    frame(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, &body)
}

/// Prepend the netlink header to a message body.
fn frame(message_type: u16, flags: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let total = NLMSG_HEADER_LEN + body.len();
    let mut out = Vec::with_capacity(align(total));
    out.extend_from_slice(&(total as u32).to_ne_bytes());
    out.extend_from_slice(&message_type.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    // Port id 0 — the kernel fills in ours.
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(align(out.len()), 0);
    out
}

// ── Dump parsing (pure) ──────────────────────────────────────────────────────

/// What one parsed datagram carried.
#[derive(Debug, Default, PartialEq, Eq)]
struct DumpChunk {
    routes: Vec<RouteEntry>,
    /// The kernel signalled `NLMSG_DONE` — the dump is complete.
    done: bool,
    /// `NLMSG_ERROR` with a non-zero code, as a negative errno.
    error: Option<i32>,
}

/// Walk one received datagram, collecting IPv4 routes.
///
/// One `recv` can hold several messages back to back, each padded to a 4-byte
/// boundary. A malformed or truncated length ends the walk rather than looping:
/// a bad frame costs the rest of that datagram, not the thread.
fn parse_dump_chunk(datagram: &[u8]) -> DumpChunk {
    let mut chunk = DumpChunk::default();
    let mut offset = 0usize;
    while offset + NLMSG_HEADER_LEN <= datagram.len() {
        let length = u32::from_ne_bytes([
            datagram[offset],
            datagram[offset + 1],
            datagram[offset + 2],
            datagram[offset + 3],
        ]) as usize;
        if length < NLMSG_HEADER_LEN || offset + length > datagram.len() {
            return chunk;
        }
        let message_type = u16::from_ne_bytes([datagram[offset + 4], datagram[offset + 5]]);
        let body = &datagram[offset + NLMSG_HEADER_LEN..offset + length];
        match message_type {
            NLMSG_DONE => {
                chunk.done = true;
                return chunk;
            }
            NLMSG_ERROR => {
                // `struct nlmsgerr` opens with the negative errno.
                if body.len() >= 4 {
                    let code = i32::from_ne_bytes([body[0], body[1], body[2], body[3]]);
                    if code != 0 {
                        chunk.error = Some(code);
                        return chunk;
                    }
                }
            }
            RTM_NEWROUTE => {
                if let Some(route) = parse_route_message(body) {
                    chunk.routes.push(route);
                }
            }
            _ => {}
        }
        offset += align(length);
    }
    chunk
}

/// Parse one `RTM_NEWROUTE` body into a neutral [`RouteEntry`].
///
/// `None` for anything that is not an ordinary IPv4 unicast route we could act
/// on — a v6 row, a truncated body, or a route with no output interface.
fn parse_route_message(body: &[u8]) -> Option<RouteEntry> {
    if body.len() < RTMSG_LEN || body[0] != AF_INET_U8 {
        return None;
    }
    let prefix_length = body[1];
    let table_byte = body[4];
    let route_type = body[7];
    if route_type != RTN_UNICAST {
        return None;
    }

    let mut destination = Ipv4Addr::UNSPECIFIED;
    let mut next_hop = Ipv4Addr::UNSPECIFIED;
    let mut interface_index: Option<u32> = None;
    let mut metric = 0u32;
    let mut table = u32::from(table_byte);

    let mut offset = RTMSG_LEN;
    while offset + RTATTR_HEADER_LEN <= body.len() {
        let len = u16::from_ne_bytes([body[offset], body[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
        if len < RTATTR_HEADER_LEN || offset + len > body.len() {
            break;
        }
        let payload = &body[offset + RTATTR_HEADER_LEN..offset + len];
        match attr_type {
            RTA_DST if payload.len() == 4 => {
                destination = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            }
            RTA_GATEWAY if payload.len() == 4 => {
                next_hop = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            }
            RTA_OIF if payload.len() == 4 => {
                interface_index = Some(u32::from_ne_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]));
            }
            RTA_PRIORITY if payload.len() == 4 => {
                metric = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            RTA_TABLE if payload.len() == 4 => {
                table = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            _ => {}
        }
        offset += align(len);
    }

    Some(RouteEntry {
        destination,
        prefix_length,
        next_hop,
        interface_index: interface_index?,
        metric,
        // Storage-anchored, exactly as on Windows — see the module doc.
        is_ours: false,
        table: if table == u32::from(RT_TABLE_MAIN) {
            RouteTableRef::Main
        } else {
            RouteTableRef::Tagged(table)
        },
    })
}

// ── Socket round-trip (Linux only) ───────────────────────────────────────────

/// Read the IPv4 route table.
#[cfg(target_os = "linux")]
pub fn get_ipv4_routes() -> Result<Vec<RouteEntry>, PlatformError> {
    let socket = NetlinkRequestSocket::open()?;
    socket.send(&encode_route_dump(socket.sequence))?;
    let mut routes = Vec::new();
    loop {
        let datagram = socket.receive()?;
        let chunk = parse_dump_chunk(&datagram);
        if let Some(code) = chunk.error {
            return Err(errno_error("dump the IPv4 route table", code));
        }
        routes.extend(chunk.routes);
        if chunk.done {
            return Ok(routes);
        }
    }
}

/// Add one IPv4 route. An entry that already exists comes back as `EEXIST`,
/// which classifies as [`nrr_platform_api::error::ErrorClass::Conflict`] —
/// the same signal the Windows backend raises for a duplicate.
#[cfg(target_os = "linux")]
pub fn add_ipv4_route(entry: &RouteEntry) -> Result<(), PlatformError> {
    let socket = NetlinkRequestSocket::open()?;
    socket.send(&encode_route_mutation(
        RTM_NEWROUTE,
        entry,
        socket.sequence,
    )?)?;
    socket.expect_ack("add an IPv4 route")
}

/// Delete one IPv4 route. A route that is already gone comes back as `ENOENT`,
/// which classifies as [`nrr_platform_api::error::ErrorClass::Idempotent`] —
/// deleting what is not there is success for a reconcile.
#[cfg(target_os = "linux")]
pub fn delete_ipv4_route(entry: &RouteEntry) -> Result<(), PlatformError> {
    let socket = NetlinkRequestSocket::open()?;
    socket.send(&encode_route_mutation(
        RTM_DELROUTE,
        entry,
        socket.sequence,
    )?)?;
    socket.expect_ack("delete an IPv4 route")
}

/// Wrap a kernel errno in the neutral error the port declares.
///
/// The kernel reports it negated; `PlatformError::Errno` carries the positive
/// value, and `classify` turns `EEXIST` into `Conflict` and `ENOENT` into
/// `Idempotent` — the same distinctions the Windows side gets from its Win32
/// codes, which is what keeps an idempotent reconcile idempotent on both.
#[cfg(target_os = "linux")]
fn errno_error(operation: &'static str, negative_errno: i32) -> PlatformError {
    let code = -negative_errno;
    PlatformError::Errno {
        operation,
        code,
        message: std::io::Error::from_raw_os_error(code).to_string(),
    }
}

/// A short-lived `NETLINK_ROUTE` socket for one request/response exchange.
///
/// Deliberately not shared or pooled: a route change happens at human speed,
/// and a per-call socket cannot leak a half-read dump into the next caller.
#[cfg(target_os = "linux")]
struct NetlinkRequestSocket {
    fd: libc::c_int,
    sequence: u32,
}

/// Wraps the current `errno` with the operation that produced it.
///
/// NOT `Transient`: the contract doc on `PlatformError::Errno` says exactly why
/// — collapsing these turns "this route already exists" into an endless retry,
/// and `EPERM` in a container into an endless retry of something that can never
/// succeed. `classify_errno` already knows idempotent from conflict from
/// privilege; it just needs to be given the number.
#[cfg(target_os = "linux")]
fn last_errno(operation: &'static str) -> PlatformError {
    let error = std::io::Error::last_os_error();
    PlatformError::Errno {
        operation,
        code: error.raw_os_error().unwrap_or(0),
        message: error.to_string(),
    }
}

#[cfg(target_os = "linux")]
impl NetlinkRequestSocket {
    fn open() -> Result<Self, PlatformError> {
        // SAFETY: three integers in, a descriptor out.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(last_errno("open rtnetlink socket"));
        }
        // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid starting value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // No multicast groups: this socket asks and listens for its own answer.
        // SAFETY: the address is live for the call and its declared length
        // matches the struct actually passed.
        let rc = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let error = last_errno("bind rtnetlink socket");
            // SAFETY: `fd` is the descriptor just opened and not yet shared.
            unsafe { libc::close(fd) };
            return Err(error);
        }
        Ok(Self {
            fd,
            // Any non-zero value distinguishes our reply from unsolicited
            // traffic; the exchange is one request long, so a constant is
            // enough and keeps the socket reproducible in logs.
            sequence: 1,
        })
    }

    fn send(&self, message: &[u8]) -> Result<(), PlatformError> {
        // SAFETY: `message` is live for the call and its length is its own.
        let sent = unsafe {
            libc::send(
                self.fd,
                message.as_ptr().cast::<libc::c_void>(),
                message.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(last_errno("send rtnetlink request"));
        }
        Ok(())
    }

    /// One datagram. The buffer is generous because a dump packs many routes
    /// per message and a short buffer would truncate rather than split.
    fn receive(&self) -> Result<Vec<u8>, PlatformError> {
        let mut buffer = vec![0u8; 32 * 1024];
        // SAFETY: the buffer is live and its capacity is what we pass.
        let read = unsafe {
            libc::recv(
                self.fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        if read < 0 {
            return Err(last_errno("read rtnetlink reply"));
        }
        buffer.truncate(read as usize);
        Ok(buffer)
    }

    /// Read the acknowledgement the kernel owes a mutation request.
    fn expect_ack(&self, operation: &'static str) -> Result<(), PlatformError> {
        let datagram = self.receive()?;
        let chunk = parse_dump_chunk(&datagram);
        match chunk.error {
            Some(code) => Err(errno_error(operation, code)),
            // A zero-code `NLMSG_ERROR` IS the acknowledgement.
            None => Ok(()),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetlinkRequestSocket {
    fn drop(&mut self) {
        // SAFETY: the descriptor is ours and closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::new(10, 20, 30, 0),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(10, 20, 0, 1),
            interface_index: 7,
            metric: 42,
            is_ours: true,
            table: RouteTableRef::Main,
        }
    }

    /// The header the kernel reads first must describe the whole message, or it
    /// silently ignores the request.
    #[test]
    fn an_encoded_mutation_declares_its_own_length() {
        let msg = encode_route_mutation(RTM_NEWROUTE, &entry(), 1).expect("encode");
        let declared = u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(
            declared,
            msg.len(),
            "declared length must cover the message"
        );
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), RTM_NEWROUTE);
        let flags = u16::from_ne_bytes([msg[6], msg[7]]);
        assert!(flags & NLM_F_CREATE != 0, "an add must ask to create");
        assert!(flags & NLM_F_ACK != 0, "we must be told whether it worked");
    }

    /// Round-trip through our own parser: what we encode is what a kernel
    /// message of that shape means.
    #[test]
    fn an_encoded_route_parses_back_to_the_same_entry() {
        let original = entry();
        let msg = encode_route_mutation(RTM_NEWROUTE, &original, 1).expect("encode");
        let parsed = parse_route_message(&msg[NLMSG_HEADER_LEN..]).expect("parse");
        assert_eq!(parsed.destination, original.destination);
        assert_eq!(parsed.prefix_length, original.prefix_length);
        assert_eq!(parsed.next_hop, original.next_hop);
        assert_eq!(parsed.interface_index, original.interface_index);
        assert_eq!(parsed.metric, original.metric);
        assert_eq!(parsed.table, RouteTableRef::Main);
        assert!(
            !parsed.is_ours,
            "ownership is storage-anchored, never on the wire"
        );
    }

    /// An on-link route has no gateway, and the attribute must be ABSENT — a
    /// zero gateway would tell the kernel to route to 0.0.0.0.
    #[test]
    fn an_on_link_route_carries_no_gateway_attribute() {
        let mut e = entry();
        e.next_hop = Ipv4Addr::UNSPECIFIED;
        let msg = encode_route_mutation(RTM_NEWROUTE, &e, 1).expect("encode");
        let body = &msg[NLMSG_HEADER_LEN..];
        let mut offset = RTMSG_LEN;
        let mut saw_gateway = false;
        while offset + RTATTR_HEADER_LEN <= body.len() {
            let len = u16::from_ne_bytes([body[offset], body[offset + 1]]) as usize;
            let attr = u16::from_ne_bytes([body[offset + 2], body[offset + 3]]);
            if len < RTATTR_HEADER_LEN {
                break;
            }
            saw_gateway |= attr == RTA_GATEWAY;
            offset += align(len);
        }
        assert!(!saw_gateway);
        let parsed = parse_route_message(body).expect("parse");
        assert!(parsed.next_hop.is_unspecified());
    }

    /// A table beyond a byte moves into `RTA_TABLE`, and `rtm_table` must then
    /// read as unspecified — otherwise the kernel uses the truncated byte.
    #[test]
    fn a_large_table_number_moves_into_its_own_attribute() {
        let mut e = entry();
        e.table = RouteTableRef::Tagged(1000);
        let msg = encode_route_mutation(RTM_NEWROUTE, &e, 1).expect("encode");
        let body = &msg[NLMSG_HEADER_LEN..];
        assert_eq!(body[4], 0, "rtm_table must be unspecified for a wide table");
        let parsed = parse_route_message(body).expect("parse");
        assert_eq!(parsed.table, RouteTableRef::Tagged(1000));
    }

    /// A per-principal table has no number yet. Falling back to `main` would
    /// apply one user's route to everyone, so encoding refuses.
    #[test]
    fn a_principal_table_refuses_rather_than_defaulting_to_main() {
        let mut e = entry();
        e.table = RouteTableRef::Principal(
            nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(1000),
        );
        assert!(matches!(
            encode_route_mutation(RTM_NEWROUTE, &e, 1),
            Err(PlatformError::NotSupported { .. })
        ));
    }

    /// The dump walker must reach the second message in a datagram: the kernel
    /// packs several per `recv`.
    #[test]
    fn a_dump_chunk_walks_every_message_it_carries() {
        let mut datagram = encode_route_mutation(RTM_NEWROUTE, &entry(), 1).expect("encode");
        let mut second = entry();
        second.destination = Ipv4Addr::new(192, 168, 5, 0);
        second.interface_index = 9;
        datagram.extend(encode_route_mutation(RTM_NEWROUTE, &second, 1).expect("encode"));
        let chunk = parse_dump_chunk(&datagram);
        assert_eq!(chunk.routes.len(), 2);
        assert_eq!(chunk.routes[1].destination, Ipv4Addr::new(192, 168, 5, 0));
        assert_eq!(chunk.routes[1].interface_index, 9);
    }

    /// `NLMSG_DONE` ends the dump; anything after it in the same datagram is
    /// not ours to read.
    #[test]
    fn done_ends_the_walk() {
        let mut datagram = frame(NLMSG_DONE, 0, 1, &[]);
        datagram.extend(encode_route_mutation(RTM_NEWROUTE, &entry(), 1).expect("encode"));
        let chunk = parse_dump_chunk(&datagram);
        assert!(chunk.done);
        assert!(chunk.routes.is_empty());
    }

    /// A truncated length must end the walk instead of looping forever.
    #[test]
    fn a_truncated_message_ends_the_walk_without_hanging() {
        let mut datagram = encode_route_mutation(RTM_NEWROUTE, &entry(), 1).expect("encode");
        let real_len = datagram.len();
        // Claim far more than the datagram holds.
        datagram[0..4].copy_from_slice(&((real_len + 4096) as u32).to_ne_bytes());
        let chunk = parse_dump_chunk(&datagram);
        assert!(chunk.routes.is_empty());
        assert!(!chunk.done);
    }

    /// A non-zero `NLMSG_ERROR` is the kernel refusing, and must not read as an
    /// empty-but-successful dump.
    #[test]
    fn an_error_frame_is_reported_not_swallowed() {
        let mut body = (-17i32).to_ne_bytes().to_vec(); // -EEXIST
        body.extend_from_slice(&[0u8; 16]); // the echoed request header
        let datagram = frame(NLMSG_ERROR, 0, 1, &body);
        let chunk = parse_dump_chunk(&datagram);
        assert_eq!(chunk.error, Some(-17));
    }

    /// A zero-code `NLMSG_ERROR` is the acknowledgement of a successful
    /// mutation — the one case where "error" means "fine".
    #[test]
    fn a_zero_code_error_frame_is_an_acknowledgement() {
        let mut body = 0i32.to_ne_bytes().to_vec();
        body.extend_from_slice(&[0u8; 16]);
        let chunk = parse_dump_chunk(&frame(NLMSG_ERROR, 0, 1, &body));
        assert_eq!(chunk.error, None);
    }

    /// v6 rows share the dump when the kernel is asked broadly; they are not
    /// ours to return through a v4 port.
    #[test]
    fn a_non_v4_route_is_skipped() {
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = 10; // AF_INET6
        body[7] = RTN_UNICAST;
        assert!(parse_route_message(&body).is_none());
    }

    /// A route with no output interface cannot be acted on.
    #[test]
    fn a_route_without_an_interface_is_skipped() {
        let mut body = vec![0u8; RTMSG_LEN];
        body[0] = AF_INET_U8;
        body[7] = RTN_UNICAST;
        push_attr(&mut body, RTA_DST, &[10, 0, 0, 0]);
        assert!(parse_route_message(&body).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_socket_failure_carries_its_errno_instead_of_reading_as_retryable() {
        use nrr_platform_api::error::ErrorClass;

        // Any failing syscall sets errno; the point is what we WRAP it as.
        let _ = std::fs::File::open("/nrr-does-not-exist");
        let error = super::last_errno("open rtnetlink socket");

        match &error {
            nrr_platform_api::error::PlatformError::Errno { code, .. } => {
                assert_ne!(*code, 0, "the errno must survive the wrapping");
            }
            other => panic!("a netlink failure must not collapse into {other:?}"),
        }
        assert_ne!(
            error.classify(),
            ErrorClass::Retryable,
            "ENOENT is not something to retry forever"
        );
    }
}

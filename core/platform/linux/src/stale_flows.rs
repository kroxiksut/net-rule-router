//! Linux mechanism behind [`StaleFlowReset`]: the kernel's own socket table,
//! read over `NETLINK_SOCK_DIAG`, and `SOCK_DESTROY` to close a listed socket.
//!
//! One dump per family lists every established TCP socket with its endpoints,
//! owning uid and inode. Both families, because a dual-stack socket reaches an
//! IPv4 peer through a v4-mapped address and is invisible to an `AF_INET` dump.
//! The inode names the process only through a `/proc/<pid>/fd` walk, which is
//! limited to the uids that own a match.
//!
//! Closing needs `CAP_NET_ADMIN` and a kernel built with
//! `CONFIG_INET_DIAG_DESTROY`. A refusal for either reason is counted as not
//! torn down and logged — the caller must never read it as success.
//!
//! The message codec is pure and tested on every host; only the socket half is
//! Linux-only.

#![allow(unsafe_code)]
// The socket half has no caller off Linux; the codec below still compiles and
// is still tested there.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use std::sync::Mutex;

use nrr_platform_api::enforcement::UserPrincipal;
use nrr_platform_api::fake_ip::stale_flows::{EstablishedFlow, StaleFlowReset, StaleFlowSweep};

/// Production [`StaleFlowReset`] over `sock_diag`.
#[derive(Debug, Default)]
pub struct LinuxStaleFlowReset {
    /// The kernel's id of each connection the last listing returned, so a reset
    /// names exactly that socket — bound interface and cookie included — rather
    /// than whatever holds the same four-tuple by then.
    listed: Mutex<HashMap<(SocketAddrV4, SocketAddrV4), SockId>>,
}

impl LinuxStaleFlowReset {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn established(&self) -> Option<Vec<DiagSocket>> {
        match dump_established() {
            Ok(sockets) => Some(sockets),
            Err(error) => {
                tracing::warn!(
                    target: "nrr::flow-reset",
                    msg_key = "linux-flow-reset-dump-failed",
                    error = %error,
                    "could not read the kernel's connection table; no connection was reset",
                );
                None
            }
        }
    }
}

impl StaleFlowReset for LinuxStaleFlowReset {
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep {
        let Some(sockets) = self.established() else {
            return StaleFlowSweep::default();
        };
        let ids: Vec<SockId> = sockets
            .iter()
            .filter(|s| {
                s.v4_endpoints()
                    .is_some_and(|(_, remote)| addr_in_range(*remote.ip(), base, prefix_len))
            })
            .map(|s| s.id)
            .collect();
        if ids.is_empty() {
            return StaleFlowSweep::default();
        }
        let tally = destroy_all(&ids);
        tally.report();
        StaleFlowSweep {
            found: ids.len(),
            torn_down: tally.destroyed,
        }
    }

    fn established_flows_to(&self, targets: &[Ipv4Addr]) -> Vec<EstablishedFlow> {
        if targets.is_empty() {
            return Vec::new();
        }
        let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
        let Some(sockets) = self.established() else {
            return Vec::new();
        };
        let matched: Vec<(SocketAddrV4, SocketAddrV4, &DiagSocket)> = sockets
            .iter()
            .filter_map(|s| {
                let (local, remote) = s.v4_endpoints()?;
                wanted.contains(remote.ip()).then_some((local, remote, s))
            })
            .collect();
        {
            let mut listed = self.listed.lock().unwrap_or_else(|p| p.into_inner());
            listed.clear();
            listed.extend(matched.iter().map(|(l, r, s)| ((*l, *r), s.id)));
        }
        if matched.is_empty() {
            return Vec::new();
        }
        let owners = processes_holding(matched.iter().map(|(_, _, s)| *s));
        matched
            .into_iter()
            .map(|(local, remote, socket)| {
                let process = owners.get(&u64::from(socket.inode));
                EstablishedFlow {
                    local,
                    remote,
                    // The kernel always knows the creating uid, even for a
                    // socket whose process is gone.
                    owner: Some(
                        UserPrincipal::from_linux_uid(socket.uid)
                            .as_stored()
                            .to_owned(),
                    ),
                    pid: process.map(|p| p.0),
                    image: process.and_then(|p| p.1.clone()),
                }
            })
            .collect()
    }

    fn reset_established(&self, flows: &[EstablishedFlow]) -> usize {
        if flows.is_empty() {
            return 0;
        }
        let ids = {
            let listed = self.listed.lock().unwrap_or_else(|p| p.into_inner());
            ids_for(flows, &listed)
        };
        let tally = destroy_all(&ids);
        tally.report();
        tally.destroyed
    }
}

/// The kernel id to destroy for each flow: the one its listing returned, or —
/// for a flow this instance never listed — one built from the endpoints, which
/// finds an unbound socket.
fn ids_for(
    flows: &[EstablishedFlow],
    listed: &HashMap<(SocketAddrV4, SocketAddrV4), SockId>,
) -> Vec<SockId> {
    flows
        .iter()
        .map(|f| {
            listed
                .get(&(f.local, f.remote))
                .copied()
                .unwrap_or_else(|| SockId::for_v4(f.local, f.remote))
        })
        .collect()
}

/// CIDR containment; a prefix above 32 matches nothing.
fn addr_in_range(addr: Ipv4Addr, base: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    (u32::from(addr) & mask) == (u32::from(base) & mask)
}

// ── Message codec (pure; tested on every host) ───────────────────────────────

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ALIGNMENT: usize = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;

/// Linux's values, spelled out so the codec is the same on every build host.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const TCP_ESTABLISHED: u8 = 1;
const ENOENT: i32 = 2;
const EPERM: i32 = 1;
const EOPNOTSUPP: i32 = 95;

/// `struct inet_diag_sockid`: ports, two 16-byte addresses, interface, cookie.
const SOCKID_LEN: usize = 48;
/// `struct inet_diag_req_v2`: family, protocol, ext, pad, states, sockid.
const REQUEST_LEN: usize = 8 + SOCKID_LEN;
/// `struct inet_diag_msg`: family, state, timer, retrans, sockid, then
/// expires, rqueue, wqueue, uid, inode.
const DIAG_MSG_LEN: usize = 4 + SOCKID_LEN + 20;
const UID_OFFSET: usize = 4 + SOCKID_LEN + 12;
const INODE_OFFSET: usize = UID_OFFSET + 4;
/// "Do not check the cookie" — for an id built rather than listed.
const NO_COOKIE: u32 = u32::MAX;

/// The kernel's identity of one socket, kept byte for byte as the dump gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SockId {
    family: u8,
    raw: [u8; SOCKID_LEN],
}

impl SockId {
    /// An `AF_INET` id from endpoints alone: no bound interface, no cookie.
    fn for_v4(local: SocketAddrV4, remote: SocketAddrV4) -> Self {
        let mut raw = [0u8; SOCKID_LEN];
        raw[0..2].copy_from_slice(&local.port().to_be_bytes());
        raw[2..4].copy_from_slice(&remote.port().to_be_bytes());
        raw[4..8].copy_from_slice(&local.ip().octets());
        raw[20..24].copy_from_slice(&remote.ip().octets());
        // Interface 0 (36..40) stays zero; both cookie words say "unchecked".
        raw[40..44].copy_from_slice(&NO_COOKIE.to_ne_bytes());
        raw[44..48].copy_from_slice(&NO_COOKIE.to_ne_bytes());
        Self {
            family: AF_INET,
            raw,
        }
    }

    fn sport(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]])
    }

    fn dport(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    fn address(&self, offset: usize) -> Option<Ipv4Addr> {
        let bytes = &self.raw[offset..offset + 16];
        match self.family {
            AF_INET => Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            AF_INET6 => {
                let mut v6 = [0u8; 16];
                v6.copy_from_slice(bytes);
                Ipv6Addr::from(v6).to_ipv4_mapped()
            }
            _ => None,
        }
    }
}

/// One established socket as the dump reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagSocket {
    id: SockId,
    state: u8,
    uid: u32,
    inode: u32,
}

impl DiagSocket {
    /// Local and remote endpoints as IPv4 — a dual-stack socket's v4-mapped
    /// pair unmapped. `None` for a real IPv6 connection, which the port does
    /// not cover.
    fn v4_endpoints(&self) -> Option<(SocketAddrV4, SocketAddrV4)> {
        let local = self.id.address(4)?;
        let remote = self.id.address(20)?;
        Some((
            SocketAddrV4::new(local, self.id.sport()),
            SocketAddrV4::new(remote, self.id.dport()),
        ))
    }
}

fn header(buf: &mut Vec<u8>, length: usize, message_type: u16, flags: u16, seq: u32) {
    buf.extend_from_slice(&(length as u32).to_ne_bytes());
    buf.extend_from_slice(&message_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
}

fn request(
    family: u8,
    sockid: &[u8; SOCKID_LEN],
    message_type: u16,
    flags: u16,
    seq: u32,
) -> Vec<u8> {
    let length = NLMSG_HEADER_LEN + REQUEST_LEN;
    let mut buf = Vec::with_capacity(length);
    header(&mut buf, length, message_type, flags, seq);
    buf.extend_from_slice(&[family, IPPROTO_TCP, 0, 0]);
    buf.extend_from_slice(&(1u32 << TCP_ESTABLISHED).to_ne_bytes());
    buf.extend_from_slice(sockid);
    buf
}

/// Ask for every established TCP socket of `family`.
fn encode_dump_request(family: u8, seq: u32) -> Vec<u8> {
    request(
        family,
        &[0u8; SOCKID_LEN],
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
    )
}

/// Ask the kernel to close exactly `id`, and to say whether it did.
fn encode_destroy_request(id: &SockId, seq: u32) -> Vec<u8> {
    request(
        id.family,
        &id.raw,
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
    )
}

/// Where one received datagram leaves a dump.
#[derive(Debug, PartialEq, Eq)]
enum DumpProgress {
    More,
    Done,
    /// The kernel refused the dump; the errno.
    Failed(i32),
    /// A frame whose length does not fit; the rest of the dump is unreadable.
    Malformed,
}

/// Walk one datagram's messages, appending each established socket to `out`.
fn parse_dump_datagram(datagram: &[u8], out: &mut Vec<DiagSocket>) -> DumpProgress {
    let mut offset = 0usize;
    while offset + NLMSG_HEADER_LEN <= datagram.len() {
        let length = read_u32(datagram, offset) as usize;
        if length < NLMSG_HEADER_LEN || offset + length > datagram.len() {
            return DumpProgress::Malformed;
        }
        let message_type = u16::from_ne_bytes([datagram[offset + 4], datagram[offset + 5]]);
        let payload = &datagram[offset + NLMSG_HEADER_LEN..offset + length];
        match message_type {
            NLMSG_DONE => return DumpProgress::Done,
            NLMSG_ERROR => match error_code(payload) {
                Some(0) => {}
                Some(errno) => return DumpProgress::Failed(errno),
                None => return DumpProgress::Malformed,
            },
            SOCK_DIAG_BY_FAMILY => {
                if let Some(socket) = parse_diag_msg(payload) {
                    if socket.state == TCP_ESTABLISHED {
                        out.push(socket);
                    }
                }
            }
            _ => {}
        }
        offset += length.div_ceil(NLMSG_ALIGNMENT) * NLMSG_ALIGNMENT;
    }
    DumpProgress::More
}

fn parse_diag_msg(payload: &[u8]) -> Option<DiagSocket> {
    if payload.len() < DIAG_MSG_LEN {
        return None;
    }
    let mut raw = [0u8; SOCKID_LEN];
    raw.copy_from_slice(&payload[4..4 + SOCKID_LEN]);
    Some(DiagSocket {
        id: SockId {
            family: payload[0],
            raw,
        },
        state: payload[1],
        uid: read_u32(payload, UID_OFFSET),
        inode: read_u32(payload, INODE_OFFSET),
    })
}

/// `struct nlmsgerr`'s error as a positive errno; `0` is an acknowledgement.
fn error_code(payload: &[u8]) -> Option<i32> {
    let bytes: [u8; 4] = payload.get(0..4)?.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes).saturating_neg())
}

/// The acknowledgement for request `seq` in one datagram: `Some(0)` closed,
/// `Some(errno)` refused, `None` when the datagram carries no answer to it.
fn parse_ack(datagram: &[u8], seq: u32) -> Option<i32> {
    let mut offset = 0usize;
    while offset + NLMSG_HEADER_LEN <= datagram.len() {
        let length = read_u32(datagram, offset) as usize;
        if length < NLMSG_HEADER_LEN || offset + length > datagram.len() {
            return None;
        }
        let message_type = u16::from_ne_bytes([datagram[offset + 4], datagram[offset + 5]]);
        if message_type == NLMSG_ERROR && read_u32(datagram, offset + 8) == seq {
            return error_code(&datagram[offset + NLMSG_HEADER_LEN..offset + length]);
        }
        offset += length.div_ceil(NLMSG_ALIGNMENT) * NLMSG_ALIGNMENT;
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// What the kernel did with one destroy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestroyOutcome {
    Destroyed,
    /// Closed on its own since the listing — nothing left to do.
    Gone,
    /// The kernel was built without `CONFIG_INET_DIAG_DESTROY`.
    Unsupported,
    /// Missing privilege, or any other refusal; the errno.
    Refused(i32),
}

fn classify_destroy(errno: i32) -> DestroyOutcome {
    match errno {
        0 => DestroyOutcome::Destroyed,
        ENOENT => DestroyOutcome::Gone,
        EOPNOTSUPP => DestroyOutcome::Unsupported,
        other => DestroyOutcome::Refused(other),
    }
}

/// One batch of destroy requests, counted by outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct DestroyTally {
    destroyed: usize,
    gone: usize,
    unsupported: usize,
    refused: usize,
    last_refusal: Option<i32>,
}

impl DestroyTally {
    fn record(&mut self, outcome: DestroyOutcome) {
        match outcome {
            DestroyOutcome::Destroyed => self.destroyed += 1,
            DestroyOutcome::Gone => self.gone += 1,
            DestroyOutcome::Unsupported => self.unsupported += 1,
            DestroyOutcome::Refused(errno) => {
                self.refused += 1;
                self.last_refusal = Some(errno);
            }
        }
    }

    /// Log what was NOT closed and why; the caller logs what was.
    fn report(&self) {
        if self.unsupported > 0 {
            tracing::warn!(
                target: "nrr::flow-reset",
                msg_key = "linux-flow-reset-unsupported",
                refused = self.unsupported,
                "the kernel cannot close connections on request (built without CONFIG_INET_DIAG_DESTROY); they stay on their previous route until they close",
            );
        }
        if self.refused > 0 {
            let error = self.last_refusal.map_or_else(String::new, |errno| {
                if errno == EPERM {
                    "CAP_NET_ADMIN is missing".to_owned()
                } else {
                    std::io::Error::from_raw_os_error(errno).to_string()
                }
            });
            tracing::warn!(
                target: "nrr::flow-reset",
                msg_key = "linux-flow-reset-refused",
                refused = self.refused,
                error = %error,
                "the kernel refused to close connections; they stay on their previous route until they close",
            );
        }
    }
}

// ── Socket mechanism ─────────────────────────────────────────────────────────

/// Sockets one family's dump may hold before the rest is ignored: a machine
/// past this is a server, and a partial pass beats an unbounded one.
const MAX_DUMP_SOCKETS: usize = 65_536;
/// Long enough for a busy table, short enough that a wedged kernel answer
/// cannot hold the enforcement pass that called us.
#[cfg(target_os = "linux")]
const RECEIVE_TIMEOUT_SECS: libc::time_t = 2;

#[cfg(not(target_os = "linux"))]
fn dump_established() -> Result<Vec<DiagSocket>, String> {
    Err("sock_diag needs a Linux kernel".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn destroy_all(ids: &[SockId]) -> DestroyTally {
    DestroyTally {
        unsupported: ids.len(),
        ..DestroyTally::default()
    }
}

#[cfg(not(target_os = "linux"))]
fn processes_holding<'a>(
    _sockets: impl Iterator<Item = &'a DiagSocket>,
) -> HashMap<u64, (u32, Option<String>)> {
    HashMap::new()
}

/// Inode to `(pid, image file name)` for the given sockets, walking only the
/// processes of the uids that own them.
#[cfg(target_os = "linux")]
fn processes_holding<'a>(
    sockets: impl Iterator<Item = &'a DiagSocket>,
) -> HashMap<u64, (u32, Option<String>)> {
    let wanted: HashMap<u64, u32> = sockets
        .filter(|s| s.inode != 0)
        .map(|s| (u64::from(s.inode), s.uid))
        .collect();
    if wanted.is_empty() {
        return HashMap::new();
    }
    crate::conn_observe::socket_owners(&wanted)
        .into_iter()
        .map(|(inode, owner)| {
            let image = owner.exe.as_deref().and_then(|exe| {
                std::path::Path::new(exe)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            });
            (inode, (owner.pid, image))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn dump_established() -> Result<Vec<DiagSocket>, String> {
    let socket = DiagNetlink::open().map_err(|e| e.to_string())?;
    let mut sockets = socket
        .dump(AF_INET, 1)
        .map_err(|e| format!("IPv4 dump: {e}"))?;
    // A kernel without IPv6 refuses this family; its v4 answer still stands.
    if let Ok(v6) = socket.dump(AF_INET6, 2) {
        sockets.extend(v6);
    }
    Ok(sockets)
}

#[cfg(target_os = "linux")]
fn destroy_all(ids: &[SockId]) -> DestroyTally {
    let mut tally = DestroyTally::default();
    if ids.is_empty() {
        return tally;
    }
    let socket = match DiagNetlink::open() {
        Ok(socket) => socket,
        Err(e) => {
            for _ in ids {
                tally.record(DestroyOutcome::Refused(e.raw_os_error().unwrap_or(0)));
            }
            return tally;
        }
    };
    for (seq, id) in (1u32..).zip(ids) {
        let errno = socket
            .destroy(id, seq)
            .unwrap_or_else(|e| e.raw_os_error().unwrap_or(0));
        tally.record(classify_destroy(errno));
    }
    tally
}

/// An `AF_NETLINK`/`NETLINK_SOCK_DIAG` socket, closed on drop.
#[cfg(target_os = "linux")]
struct DiagNetlink(libc::c_int);

#[cfg(target_os = "linux")]
impl Drop for DiagNetlink {
    fn drop(&mut self) {
        // SAFETY: the descriptor is owned by this value and closed only here.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
impl DiagNetlink {
    fn open() -> std::io::Result<Self> {
        // SAFETY: three integers in, a descriptor out.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let socket = Self(fd);
        let timeout = libc::timeval {
            tv_sec: RECEIVE_TIMEOUT_SECS,
            tv_usec: 0,
        };
        // SAFETY: the option takes a `timeval` by pointer with its own size;
        // the value is live for the call.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(timeout).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(socket)
    }

    fn send(&self, message: &[u8]) -> std::io::Result<()> {
        // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid value, and
        // port id 0 addresses the kernel.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the message and address are live for the call and their
        // declared lengths match what is passed.
        let sent = unsafe {
            libc::sendto(
                self.0,
                message.as_ptr().cast::<libc::c_void>(),
                message.len(),
                0,
                std::ptr::addr_of!(kernel).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: `buffer` is live and writable for its own length.
            let read = unsafe {
                libc::recv(
                    self.0,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                    0,
                )
            };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn dump(&self, family: u8, seq: u32) -> std::io::Result<Vec<DiagSocket>> {
        self.send(&encode_dump_request(family, seq))?;
        // A dump datagram never exceeds this; a shorter buffer would truncate
        // a message rather than split it.
        let mut buffer = vec![0u8; 64 * 1024];
        let mut sockets = Vec::new();
        loop {
            let read = self.recv(&mut buffer)?;
            if read == 0 {
                return Ok(sockets);
            }
            match parse_dump_datagram(&buffer[..read], &mut sockets) {
                DumpProgress::More if sockets.len() < MAX_DUMP_SOCKETS => {}
                DumpProgress::More | DumpProgress::Done => return Ok(sockets),
                DumpProgress::Failed(errno) => {
                    return Err(std::io::Error::from_raw_os_error(errno))
                }
                DumpProgress::Malformed => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed sock_diag frame",
                    ))
                }
            }
        }
    }

    /// The errno the kernel answered `SOCK_DESTROY` with; `0` = closed.
    fn destroy(&self, id: &SockId, seq: u32) -> std::io::Result<i32> {
        self.send(&encode_destroy_request(id, seq))?;
        let mut buffer = [0u8; 1024];
        // The answer is the next frame; a few reads tolerate a stray one.
        for _ in 0..4 {
            let read = self.recv(&mut buffer)?;
            if let Some(errno) = parse_ack(&buffer[..read], seq) {
                return Ok(errno);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no acknowledgement for SOCK_DESTROY",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// One `inet_diag_msg` frame as the kernel sends it.
    fn diag_frame(
        family: u8,
        state: u8,
        sockid: &[u8; SOCKID_LEN],
        uid: u32,
        inode: u32,
    ) -> Vec<u8> {
        let mut payload = vec![family, state, 0, 0];
        payload.extend_from_slice(sockid);
        payload.extend_from_slice(&[0u8; 12]); // expires, rqueue, wqueue
        payload.extend_from_slice(&uid.to_ne_bytes());
        payload.extend_from_slice(&inode.to_ne_bytes());
        // Attributes the kernel appends; the walk must step over them.
        payload.extend_from_slice(&[5, 0, 8, 0, 0]);
        frame(SOCK_DIAG_BY_FAMILY, 7, &payload)
    }

    fn frame(message_type: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        header(
            &mut bytes,
            NLMSG_HEADER_LEN + payload.len(),
            message_type,
            0,
            seq,
        );
        bytes.extend_from_slice(payload);
        while bytes.len() % NLMSG_ALIGNMENT != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn error_frame(seq: u32, errno: i32) -> Vec<u8> {
        let mut payload = (-errno).to_ne_bytes().to_vec();
        payload.extend_from_slice(&[0u8; NLMSG_HEADER_LEN]);
        frame(NLMSG_ERROR, seq, &payload)
    }

    fn mapped(ip: Ipv4Addr) -> [u8; 16] {
        ip.to_ipv6_mapped().octets()
    }

    fn v6_sockid(local: [u8; 16], lport: u16, remote: [u8; 16], rport: u16) -> [u8; SOCKID_LEN] {
        let mut raw = [0u8; SOCKID_LEN];
        raw[0..2].copy_from_slice(&lport.to_be_bytes());
        raw[2..4].copy_from_slice(&rport.to_be_bytes());
        raw[4..20].copy_from_slice(&local);
        raw[20..36].copy_from_slice(&remote);
        raw[36..40].copy_from_slice(&3u32.to_ne_bytes()); // bound to ifindex 3
        raw[40..44].copy_from_slice(&0x1234u32.to_ne_bytes());
        raw
    }

    #[test]
    fn a_dump_request_asks_for_established_tcp_of_one_family() {
        let bytes = encode_dump_request(AF_INET6, 9);
        assert_eq!(bytes.len(), NLMSG_HEADER_LEN + REQUEST_LEN);
        assert_eq!(read_u32(&bytes, 0) as usize, bytes.len());
        assert_eq!(
            u16::from_ne_bytes([bytes[4], bytes[5]]),
            SOCK_DIAG_BY_FAMILY
        );
        assert_eq!(
            u16::from_ne_bytes([bytes[6], bytes[7]]),
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(read_u32(&bytes, 8), 9);
        assert_eq!(&bytes[16..20], &[AF_INET6, IPPROTO_TCP, 0, 0]);
        assert_eq!(read_u32(&bytes, 20), 1 << TCP_ESTABLISHED);
        assert!(
            bytes[24..].iter().all(|b| *b == 0),
            "a dump names no socket"
        );
    }

    /// The destroy request must name the listed socket byte for byte — its
    /// bound interface and cookie included — or the kernel closes nothing, or
    /// a different socket.
    #[test]
    fn a_destroy_request_carries_the_listed_id_verbatim() {
        let raw = v6_sockid(
            mapped(v4(192, 0, 2, 7)),
            50_000,
            mapped(v4(203, 0, 113, 9)),
            443,
        );
        let id = SockId {
            family: AF_INET6,
            raw,
        };
        let bytes = encode_destroy_request(&id, 42);
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), SOCK_DESTROY);
        assert_eq!(
            u16::from_ne_bytes([bytes[6], bytes[7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(read_u32(&bytes, 8), 42);
        assert_eq!(bytes[16], AF_INET6);
        assert_eq!(bytes[17], IPPROTO_TCP);
        assert_eq!(&bytes[24..], &raw[..]);
    }

    #[test]
    fn a_dump_yields_v4_and_dual_stack_sockets_with_their_owner() {
        let plain = SockId::for_v4(
            SocketAddrV4::new(v4(192, 0, 2, 7), 50_000),
            SocketAddrV4::new(v4(203, 0, 113, 9), 443),
        );
        let mut datagram = diag_frame(AF_INET, TCP_ESTABLISHED, &plain.raw, 1000, 4242);
        datagram.extend(diag_frame(
            AF_INET6,
            TCP_ESTABLISHED,
            &v6_sockid(
                mapped(v4(192, 0, 2, 7)),
                50_001,
                mapped(v4(203, 0, 113, 10)),
                443,
            ),
            1001,
            4343,
        ));
        let mut out = Vec::new();
        assert_eq!(parse_dump_datagram(&datagram, &mut out), DumpProgress::More);
        assert_eq!(out.len(), 2);

        assert_eq!(
            out[0].v4_endpoints(),
            Some((
                SocketAddrV4::new(v4(192, 0, 2, 7), 50_000),
                SocketAddrV4::new(v4(203, 0, 113, 9), 443)
            ))
        );
        assert_eq!((out[0].uid, out[0].inode), (1000, 4242));
        assert_eq!(
            out[1].v4_endpoints(),
            Some((
                SocketAddrV4::new(v4(192, 0, 2, 7), 50_001),
                SocketAddrV4::new(v4(203, 0, 113, 10), 443)
            ))
        );
        assert_eq!((out[1].uid, out[1].inode), (1001, 4343));
    }

    #[test]
    fn a_real_ipv6_connection_is_not_reported_as_ipv4() {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let datagram = diag_frame(AF_INET6, TCP_ESTABLISHED, &v6_sockid(v6, 1, v6, 2), 0, 1);
        let mut out = Vec::new();
        parse_dump_datagram(&datagram, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].v4_endpoints(), None);
    }

    #[test]
    fn only_established_sockets_are_kept() {
        let id = SockId::for_v4(
            SocketAddrV4::new(v4(192, 0, 2, 7), 1),
            SocketAddrV4::new(v4(203, 0, 113, 9), 2),
        );
        let fin_wait = 4u8;
        let mut out = Vec::new();
        parse_dump_datagram(&diag_frame(AF_INET, fin_wait, &id.raw, 0, 1), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn done_ends_the_dump_and_an_error_frame_fails_it() {
        let mut out = Vec::new();
        assert_eq!(
            parse_dump_datagram(&frame(NLMSG_DONE, 1, &[0, 0, 0, 0]), &mut out),
            DumpProgress::Done
        );
        assert_eq!(
            parse_dump_datagram(&error_frame(1, EPERM), &mut out),
            DumpProgress::Failed(EPERM)
        );
    }

    #[test]
    fn a_lying_frame_ends_the_walk_instead_of_looping() {
        let mut out = Vec::new();
        let mut liar = frame(SOCK_DIAG_BY_FAMILY, 1, &[0u8; 8]);
        liar[0..4].copy_from_slice(&4u32.to_ne_bytes());
        assert_eq!(
            parse_dump_datagram(&liar, &mut out),
            DumpProgress::Malformed
        );
        let mut overrun = frame(SOCK_DIAG_BY_FAMILY, 1, &[0u8; 8]);
        overrun[0..4].copy_from_slice(&9999u32.to_ne_bytes());
        assert_eq!(
            parse_dump_datagram(&overrun, &mut out),
            DumpProgress::Malformed
        );
        // Too short to be a socket: skipped, not misread.
        assert_eq!(
            parse_dump_datagram(&frame(SOCK_DIAG_BY_FAMILY, 1, &[0u8; 8]), &mut out),
            DumpProgress::More
        );
        assert!(out.is_empty());
    }

    /// An unsupported kernel and a missing privilege are refusals, never a
    /// success: the port's count is what the caller reports to the user.
    #[test]
    fn the_acknowledgement_is_classified_honestly() {
        assert_eq!(parse_ack(&error_frame(5, 0), 5), Some(0));
        assert_eq!(
            parse_ack(&error_frame(4, 0), 5),
            None,
            "another request's answer"
        );
        assert_eq!(classify_destroy(0), DestroyOutcome::Destroyed);
        assert_eq!(
            classify_destroy(parse_ack(&error_frame(5, EOPNOTSUPP), 5).unwrap_or(0)),
            DestroyOutcome::Unsupported
        );
        assert_eq!(classify_destroy(EPERM), DestroyOutcome::Refused(EPERM));
        assert_eq!(classify_destroy(ENOENT), DestroyOutcome::Gone);

        let mut tally = DestroyTally::default();
        for errno in [0, EOPNOTSUPP, EPERM, ENOENT] {
            tally.record(classify_destroy(errno));
        }
        assert_eq!(tally.destroyed, 1);
        assert_eq!((tally.unsupported, tally.refused, tally.gone), (1, 1, 1));
    }

    /// A flow built from endpoints alone must find the same socket the kernel
    /// would list for an unbound `AF_INET` connection.
    #[test]
    fn an_id_built_from_endpoints_round_trips() {
        let local = SocketAddrV4::new(v4(192, 0, 2, 7), 50_000);
        let remote = SocketAddrV4::new(v4(203, 0, 113, 9), 443);
        let id = SockId::for_v4(local, remote);
        let socket = DiagSocket {
            id,
            state: TCP_ESTABLISHED,
            uid: 0,
            inode: 0,
        };
        assert_eq!(socket.v4_endpoints(), Some((local, remote)));
        assert_eq!(read_u32(&id.raw, 36), 0, "no bound interface");
        assert_eq!(read_u32(&id.raw, 40), NO_COOKIE);
        assert_eq!(read_u32(&id.raw, 44), NO_COOKIE);
        assert_eq!(&id.raw[4..8], &[192, 0, 2, 7]);
        assert_eq!(&id.raw[0..2], &50_000u16.to_be_bytes());
    }

    #[test]
    fn a_listed_flow_is_reset_by_its_listed_id() {
        let local = SocketAddrV4::new(v4(192, 0, 2, 7), 50_001);
        let remote = SocketAddrV4::new(v4(203, 0, 113, 10), 443);
        let listed_id = SockId {
            family: AF_INET6,
            raw: v6_sockid(
                mapped(*local.ip()),
                local.port(),
                mapped(*remote.ip()),
                remote.port(),
            ),
        };
        let listed = HashMap::from([((local, remote), listed_id)]);
        let flow = |local, remote| EstablishedFlow {
            local,
            remote,
            owner: None,
            pid: None,
            image: None,
        };
        let other_local = SocketAddrV4::new(v4(192, 0, 2, 7), 50_002);
        let ids = ids_for(&[flow(local, remote), flow(other_local, remote)], &listed);
        assert_eq!(ids[0], listed_id);
        assert_eq!(ids[1], SockId::for_v4(other_local, remote));
    }

    #[test]
    fn addr_in_range_is_cidr_containment() {
        let pool = v4(198, 18, 0, 0);
        assert!(addr_in_range(v4(198, 19, 255, 255), pool, 15));
        assert!(!addr_in_range(v4(198, 20, 0, 0), pool, 15));
        assert!(addr_in_range(v4(203, 0, 113, 1), pool, 0));
        assert!(!addr_in_range(pool, pool, 33));
    }

    /// Listing needs no privilege, so this reads the live table as any user:
    /// our own loopback connection must come back with our uid and process.
    #[cfg(target_os = "linux")]
    #[test]
    fn our_own_connection_is_listed_with_its_owner_and_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = listener.local_addr().expect("addr");
        let client = std::net::TcpStream::connect(server).expect("connect");
        let (_accepted, _) = listener.accept().expect("accept");
        let local = match client.local_addr().expect("local") {
            std::net::SocketAddr::V4(v4) => v4,
            std::net::SocketAddr::V6(_) => unreachable!("bound to IPv4"),
        };

        let reset = LinuxStaleFlowReset::new();
        let flows = reset.established_flows_to(&[Ipv4Addr::LOCALHOST]);
        let ours = flows
            .iter()
            .find(|f| f.local == local)
            .expect("our connection is in the kernel's table");
        // SAFETY: `geteuid` reads process state and takes no pointer.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            ours.owner.as_deref(),
            Some(UserPrincipal::from_linux_uid(uid).as_stored())
        );
        assert_eq!(ours.pid, Some(std::process::id()));
        assert!(ours.image.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn listing_an_address_nothing_talks_to_finds_nothing() {
        let reset = LinuxStaleFlowReset::new();
        assert!(reset.established_flows_to(&[v4(192, 0, 2, 254)]).is_empty());
        assert!(reset.established_flows_to(&[]).is_empty());
    }

    /// The assertion the port exists for: a listed connection is closed and
    /// its application sees the abort. Needs `CAP_NET_ADMIN`; run as root with
    /// `--ignored`. A kernel without `CONFIG_INET_DIAG_DESTROY` (the WSL2 one)
    /// must report the refusal, not a success.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root (CAP_NET_ADMIN)"]
    fn a_listed_connection_is_destroyed_and_its_reader_sees_the_abort() {
        use std::io::Read;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut client =
            std::net::TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let (_accepted, _) = listener.accept().expect("accept");
        let local = client.local_addr().expect("local");

        let reset = LinuxStaleFlowReset::new();
        let ours: Vec<EstablishedFlow> = reset
            .established_flows_to(&[Ipv4Addr::LOCALHOST])
            .into_iter()
            .filter(|f| std::net::SocketAddr::V4(f.local) == local)
            .collect();
        assert_eq!(ours.len(), 1);
        let ids = ids_for(
            &ours,
            &reset.listed.lock().unwrap_or_else(|p| p.into_inner()),
        );
        let tally = destroy_all(&ids);
        if tally.unsupported == 1 {
            assert_eq!(tally.destroyed, 0);
            assert_eq!(
                reset.reset_established(&ours),
                0,
                "a refusal counted as closed"
            );
            return;
        }
        assert_eq!(tally.destroyed, 1, "{tally:?}");

        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let mut byte = [0u8; 1];
        let read = client.read(&mut byte);
        assert!(
            matches!(&read, Err(e) if e.raw_os_error() == Some(libc::ECONNABORTED)),
            "the reader must see the abort, got {read:?}"
        );
    }
}

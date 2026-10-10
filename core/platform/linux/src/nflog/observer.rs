//! The NFLOG socket, its reader thread, and the drain that names the program
//! behind each drop.
//!
//! The reader only parses and queues, into a bounded channel; a full channel
//! costs the newest report, counted, never the reader's pace. Naming the
//! program is the drain's job: a TCP connection whose SYN we dropped is still
//! in `SYN_SENT` while it retries, and a UDP socket outlives its refused send,
//! so the socket table finds its inode and the procfs walk the conn observer
//! already does finds the process. At most one walk per drain and per second,
//! over at most [`MAX_ATTRIBUTED_PER_DRAIN`] sockets; a miss is reported with
//! the uid alone.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};
use nrr_platform_api::enforcement::UserPrincipal;
use nrr_platform_api::error::PlatformError;

use super::{
    encode_bind, encode_copy_mode, error_code, messages, parse_packet, reported_tag, DroppedPacket,
    PacketRejection, NFULNL_PACKET, NLMSG_ERROR,
};
use crate::conn_observe::{parse_socket_table, socket_owners, unmapped, ProcSocket};
use crate::drop_tag::{DropTag, NFLOG_SNAPLEN, NRR_NFLOG_GROUP};

/// Reports held between drains: above what the rate limits let through in one
/// two-second drain interval.
const CHANNEL_CAPACITY: usize = 1024;
const MAX_PER_DRAIN: usize = 512;
const RECEIVE_BUFFER_BYTES: libc::c_int = 256 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
/// How long a read blocks before the reader looks at its stop flag.
const READ_TIMEOUT_SECS: libc::time_t = 1;
/// How long the bind and copy-mode handshake waits for the kernel's answer.
const CONFIGURE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
/// A connection's retries inside this window are one attempt: TCP resends a
/// dropped SYN for about two minutes, and Windows reports the connect once.
const REPEAT_WINDOW_MS: u64 = 120_000;
const MAX_TRACKED_FLOWS: usize = 4096;
/// Sockets named per drain; the rest go out with their uid only.
const MAX_ATTRIBUTED_PER_DRAIN: usize = 64;
/// The process walk runs at most this often, whatever the drain cadence.
const MIN_WALK_INTERVAL_MS: u64 = 1_000;
const OWNER_TTL_MS: u64 = 60_000;
const MAX_CACHED_OWNERS: usize = 1024;

/// What the reader saw, for a status line or a test. Monotonic counters.
#[derive(Debug, Default)]
pub struct NflogStats {
    /// Packet reports read from the socket.
    pub received: AtomicU64,
    /// Reports discarded because the drain fell behind.
    pub overflowed: AtomicU64,
    /// Times the kernel could not deliver because our buffer was full; how
    /// many reports each one cost is not known.
    pub kernel_overruns: AtomicU64,
    /// Reports another program's rule sent to our group.
    pub foreign: AtomicU64,
    /// Datagrams a local process, not the kernel, sent to our socket.
    pub forged: AtomicU64,
    pub unreadable: AtomicU64,
    /// Retries of a connection already reported.
    pub repeats: AtomicU64,
}

/// [`ConnectionObservationSource`] of the drops our rules made: every
/// observation is a [`ConnectionVerdict::Block`] attributed to us, its
/// `nrr_drop_spec_id` the [`DropTag::spec_id`] of the rule's role.
pub struct NflogDropObserver {
    packets: Mutex<Receiver<DroppedPacket>>,
    stats: Arc<NflogStats>,
    stop: Arc<AtomicBool>,
    state: Mutex<DrainState>,
}

impl NflogDropObserver {
    /// Listen on [`NRR_NFLOG_GROUP`]. `EPERM` means no `CAP_NET_ADMIN`, or
    /// another program already listens on the group; either way drops are
    /// still enforced, only no longer reported.
    pub fn start() -> Result<Self, PlatformError> {
        let socket = NflogSocket::open(NRR_NFLOG_GROUP)?;
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let stats = Arc::new(NflogStats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stats = Arc::clone(&stats);
        let reader_stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("nrr-nflog".to_owned())
            .spawn(move || read_loop(&socket, &sender, &reader_stats, &reader_stop))
            .map_err(|e| PlatformError::Transient {
                operation: "start the drop-report reader",
                detail: e.to_string(),
            })?;
        Ok(Self {
            packets: Mutex::new(receiver),
            stats,
            stop,
            state: Mutex::new(DrainState::default()),
        })
    }

    #[must_use]
    pub fn stats(&self) -> Arc<NflogStats> {
        Arc::clone(&self.stats)
    }
}

impl Drop for NflogDropObserver {
    fn drop(&mut self) {
        // The reader notices within one read timeout and closes the socket.
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ConnectionObservationSource for NflogDropObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        let packets: Vec<DroppedPacket> = {
            let receiver = self.packets.lock().unwrap_or_else(|p| p.into_inner());
            receiver.try_iter().take(MAX_PER_DRAIN).collect()
        };
        if packets.is_empty() {
            return Vec::new();
        }
        let now_ms = now_unix_ms();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let read = packets.len();
        let fresh: Vec<DroppedPacket> = packets
            .into_iter()
            .filter(|packet| state.first_sighting(packet, now_ms))
            .collect();
        self.stats
            .repeats
            .fetch_add((read - fresh.len()) as u64, Ordering::Relaxed);
        let owners = state.attribute(&fresh, now_ms);
        drop(state);
        fresh
            .into_iter()
            .zip(owners)
            .map(|(packet, owner)| observation(packet, owner))
            .collect()
    }
}

fn observation(packet: DroppedPacket, owner: Option<Owner>) -> ConnectionObservation {
    let tag = reported_tag(packet.tag, &packet.remote);
    ConnectionObservation {
        pid: owner.as_ref().map_or(0, |o| o.pid),
        process_path: owner.and_then(|o| o.exe),
        user_sid: packet
            .uid
            .map(|uid| UserPrincipal::from_linux_uid(uid).as_stored().to_owned()),
        protocol: packet.protocol,
        local: packet.local,
        remote: packet.remote,
        verdict: ConnectionVerdict::Block,
        drop_filter_id: None,
        // Only a report with our own prefix gets this far.
        blocked_by_nrr: Some(true),
        nrr_drop_spec_id: Some(tag.spec_id()),
        observed_unix_ms: packet.at_unix_ms,
        progress: ConnectionProgress::Attempt,
    }
}

fn read_loop(
    socket: &NflogSocket,
    sender: &SyncSender<DroppedPacket>,
    stats: &NflogStats,
    stop: &AtomicBool,
) {
    let mut buffer = vec![0u8; READ_BUFFER_BYTES];
    while !stop.load(Ordering::Relaxed) {
        let read = match socket.receive(&mut buffer) {
            Ok(Received::Kernel(read)) => read,
            Ok(Received::Forged) => {
                stats.forged.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(libc::EAGAIN | libc::EINTR) => continue,
            Err(libc::ENOBUFS) => {
                stats.kernel_overruns.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(errno) => {
                tracing::warn!(
                    target: "nrr::nflog",
                    error = %std::io::Error::from_raw_os_error(errno),
                    "the drop-report reader stopped; drops are still enforced but no longer reported",
                );
                return;
            }
        };
        let received_ms = now_unix_ms();
        for (message_type, body) in messages(&buffer[..read]) {
            if message_type != NFULNL_PACKET {
                continue;
            }
            stats.received.fetch_add(1, Ordering::Relaxed);
            match parse_packet(body) {
                Ok(mut packet) => {
                    packet.at_unix_ms.get_or_insert(received_ms);
                    match sender.try_send(packet) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            stats.overflowed.fetch_add(1, Ordering::Relaxed);
                        }
                        // The observer is gone.
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                Err(PacketRejection::Foreign) => {
                    stats.foreign.fetch_add(1, Ordering::Relaxed);
                }
                Err(PacketRejection::Unreadable) => {
                    stats.unreadable.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ── Drain-side state ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct Owner {
    pid: u32,
    exe: Option<String>,
}

struct CachedOwner {
    owner: Option<Owner>,
    at_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    tag: DropTag,
    protocol: TransportProtocol,
    local: SocketAddr,
    remote: SocketAddr,
}

#[derive(Default)]
struct DrainState {
    first_seen: HashMap<FlowKey, u64>,
    owners: HashMap<u64, CachedOwner>,
    last_walk_ms: Option<u64>,
}

impl DrainState {
    /// Whether this is the first report of its connection inside the window.
    fn first_sighting(&mut self, packet: &DroppedPacket, now_ms: u64) -> bool {
        let key = FlowKey {
            tag: packet.tag,
            protocol: packet.protocol,
            local: packet.local,
            remote: packet.remote,
        };
        let fresh = |seen: u64| now_ms.saturating_sub(seen) < REPEAT_WINDOW_MS;
        if self.first_seen.get(&key).is_some_and(|&seen| fresh(seen)) {
            return false;
        }
        if self.first_seen.len() >= MAX_TRACKED_FLOWS {
            self.first_seen.retain(|_, seen| fresh(*seen));
            // A flood of distinct flows: forgetting costs a repeated report,
            // never memory.
            if self.first_seen.len() >= MAX_TRACKED_FLOWS {
                self.first_seen.clear();
            }
        }
        self.first_seen.insert(key, now_ms);
        true
    }

    /// The program behind each packet, where it can be named this drain.
    fn attribute(&mut self, packets: &[DroppedPacket], now_ms: u64) -> Vec<Option<Owner>> {
        if !packets.iter().any(wants_owner) {
            return vec![None; packets.len()];
        }
        let tables = SocketTables::read(packets);
        let sockets: Vec<Option<u64>> = packets
            .iter()
            .map(|packet| {
                wants_owner(packet)
                    .then(|| sending_socket(tables.rows(packet.protocol), packet))
                    .flatten()
                    .map(|row| row.inode)
            })
            .collect();

        self.owners
            .retain(|_, cached| now_ms.saturating_sub(cached.at_ms) < OWNER_TTL_MS);
        let mut wanted: HashMap<u64, u32> = HashMap::new();
        for (packet, inode) in packets.iter().zip(&sockets) {
            if wanted.len() >= MAX_ATTRIBUTED_PER_DRAIN {
                break;
            }
            if let (Some(inode), Some(uid)) = (inode, packet.uid) {
                if !self.owners.contains_key(inode) {
                    wanted.insert(*inode, uid);
                }
            }
        }
        let walk_due = self
            .last_walk_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= MIN_WALK_INTERVAL_MS);
        if !wanted.is_empty() && walk_due {
            self.last_walk_ms = Some(now_ms);
            let found = socket_owners(&wanted);
            if self.owners.len() + wanted.len() > MAX_CACHED_OWNERS {
                self.owners.clear();
            }
            for inode in wanted.keys() {
                let owner = found.get(inode).map(|o| Owner {
                    pid: o.pid,
                    exe: o.exe.clone(),
                });
                self.owners.insert(
                    *inode,
                    CachedOwner {
                        owner,
                        at_ms: now_ms,
                    },
                );
            }
        }
        sockets
            .iter()
            .map(|inode| self.owners.get(inode.as_ref()?)?.owner.clone())
            .collect()
    }
}

/// Only a packet with a socket behind it and ports to look it up by.
fn wants_owner(packet: &DroppedPacket) -> bool {
    packet.uid.is_some()
        && packet.local.port() != 0
        && matches!(
            packet.protocol,
            TransportProtocol::Tcp | TransportProtocol::Udp
        )
}

/// The rows of the socket tables a drain's packets need, endpoints unmapped
/// so a dual-stack socket compares with the IPv4 packet it sent.
#[derive(Default)]
struct SocketTables {
    tcp: Vec<ProcSocket>,
    udp: Vec<ProcSocket>,
}

impl SocketTables {
    fn read(packets: &[DroppedPacket]) -> Self {
        let needs = |protocol| {
            packets
                .iter()
                .any(|p| wants_owner(p) && p.protocol == protocol)
        };
        let mut tables = Self::default();
        if needs(TransportProtocol::Tcp) {
            read_table("/proc/net/tcp", false, &mut tables.tcp);
            read_table("/proc/net/tcp6", true, &mut tables.tcp);
        }
        if needs(TransportProtocol::Udp) {
            read_table("/proc/net/udp", false, &mut tables.udp);
            read_table("/proc/net/udp6", true, &mut tables.udp);
        }
        tables
    }

    fn rows(&self, protocol: TransportProtocol) -> &[ProcSocket] {
        match protocol {
            TransportProtocol::Tcp => &self.tcp,
            TransportProtocol::Udp => &self.udp,
            TransportProtocol::Other(_) => &[],
        }
    }
}

fn read_table(path: &str, v6: bool, out: &mut Vec<ProcSocket>) {
    // A kernel without IPv6 has no `tcp6`: nothing to find there.
    if let Ok(text) = std::fs::read_to_string(path) {
        out.extend(unmapped_rows(&text, v6));
    }
}

fn unmapped_rows(text: &str, v6: bool) -> impl Iterator<Item = ProcSocket> + '_ {
    parse_socket_table(text, v6).into_iter().map(|mut row| {
        row.local = unmapped(row.local);
        row.remote = unmapped(row.remote);
        row
    })
}

/// The socket that sent `packet`: same owner, same source port, bound to its
/// source address or the wildcard, and connected to its destination — or, for
/// UDP, not connected at all. An exact match wins over a wildcard one.
fn sending_socket<'r>(rows: &'r [ProcSocket], packet: &DroppedPacket) -> Option<&'r ProcSocket> {
    rows.iter()
        .filter(|row| Some(row.uid) == packet.uid)
        .filter(|row| row.local.port() == packet.local.port())
        .filter(|row| bound_to(row.local.ip(), packet.local.ip()))
        .filter(|row| {
            row.remote == packet.remote
                || (packet.protocol == TransportProtocol::Udp && row.remote.port() == 0)
        })
        .max_by_key(|row| {
            (
                row.remote == packet.remote,
                row.local.ip() == packet.local.ip(),
            )
        })
}

/// A v4 wildcard cannot have sent an IPv6 packet; a v6 wildcard can send
/// either family.
fn bound_to(bound: IpAddr, sent_from: IpAddr) -> bool {
    bound == sent_from
        || match bound {
            IpAddr::V4(v4) => v4.is_unspecified() && sent_from.is_ipv4(),
            IpAddr::V6(v6) => v6.is_unspecified(),
        }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

// ── The socket ───────────────────────────────────────────────────────────────

struct NflogSocket {
    fd: libc::c_int,
}

fn errno_error(operation: &'static str, code: i32) -> PlatformError {
    PlatformError::Errno {
        operation,
        code,
        message: std::io::Error::from_raw_os_error(code).to_string(),
    }
}

fn last_errno(operation: &'static str) -> PlatformError {
    let error = std::io::Error::last_os_error();
    errno_error(operation, error.raw_os_error().unwrap_or(0))
}

impl NflogSocket {
    fn open(group: u16) -> Result<Self, PlatformError> {
        // SAFETY: three integers in, a descriptor out.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if fd < 0 {
            return Err(last_errno("open the netfilter netlink socket"));
        }
        // Owned from here, so every early return below closes it.
        let socket = Self { fd };
        // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid starting value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: the address is live for the call and its declared length
        // matches the struct passed.
        let rc = unsafe {
            libc::bind(
                socket.fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(last_errno("bind the netfilter netlink socket"));
        }
        // A larger buffer only absorbs bursts; the default still works.
        let _ = socket.set_option(libc::SO_RCVBUF, &RECEIVE_BUFFER_BYTES);
        let timeout = libc::timeval {
            tv_sec: READ_TIMEOUT_SECS,
            tv_usec: 0,
        };
        socket.set_option(libc::SO_RCVTIMEO, &timeout)?;
        socket.configure(&encode_bind(1, group), "listen on the drop-report group")?;
        socket.configure(
            &encode_copy_mode(2, group, NFLOG_SNAPLEN),
            "set the drop-report copy range",
        )?;
        Ok(socket)
    }

    fn set_option<T>(&self, name: libc::c_int, value: &T) -> Result<(), PlatformError> {
        // SAFETY: `value` is live for the call and its size is what we declare.
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                name,
                std::ptr::from_ref(value).cast::<libc::c_void>(),
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(last_errno("configure the netfilter netlink socket"));
        }
        Ok(())
    }

    fn send(&self, message: &[u8], operation: &'static str) -> Result<(), PlatformError> {
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
            return Err(last_errno(operation));
        }
        Ok(())
    }

    /// One datagram into `buffer`; the positive errno on failure.
    fn receive(&self, buffer: &mut [u8]) -> Result<Received, i32> {
        // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid starting value.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut source_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: the buffer and the address are live for the call, and the
        // lengths passed are their own.
        let read = unsafe {
            libc::recvfrom(
                self.fd,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
                std::ptr::addr_of_mut!(source).cast::<libc::sockaddr>(),
                &mut source_len,
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0));
        }
        if !from_kernel(&source) {
            return Ok(Received::Forged);
        }
        Ok(Received::Kernel(read as usize))
    }

    /// Send a configuration request and read its acknowledgement. Reports may
    /// already be queued ahead of it and are skipped, as is anything a local
    /// process sent us: only the kernel's answer completes the handshake.
    fn configure(&self, request: &[u8], operation: &'static str) -> Result<(), PlatformError> {
        self.send(request, operation)?;
        let deadline = std::time::Instant::now() + CONFIGURE_DEADLINE;
        let mut buffer = vec![0u8; 16 * 1024];
        while std::time::Instant::now() < deadline {
            let read = match self.receive(&mut buffer) {
                Ok(Received::Kernel(read)) => read,
                Ok(Received::Forged) | Err(libc::EINTR) => continue,
                Err(errno) => return Err(errno_error(operation, errno)),
            };
            let answer = messages(&buffer[..read])
                .find(|(message_type, _)| *message_type == NLMSG_ERROR)
                .and_then(|(_, body)| error_code(body));
            match answer {
                Some(0) => return Ok(()),
                Some(negative) => return Err(errno_error(operation, -negative)),
                None => {}
            }
        }
        Err(PlatformError::Transient {
            operation,
            detail: "the kernel did not acknowledge the request".to_owned(),
        })
    }
}

/// What one read returned.
enum Received {
    /// A datagram from the kernel, this many bytes long.
    Kernel(usize),
    /// A datagram another process sent to our port; its content is ignored.
    Forged,
}

/// Netlink stamps the sender's port on every datagram, and the kernel's is 0.
/// Any local process may unicast to our port, so a report or an acknowledgement
/// counts only from the kernel.
fn from_kernel(source: &libc::sockaddr_nl) -> bool {
    i32::from(source.nl_family) == libc::AF_NETLINK && source.nl_pid == 0
}

impl Drop for NflogSocket {
    fn drop(&mut self) {
        // SAFETY: the descriptor is ours and closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drop_tag::DropKind;

    fn addr(text: &str) -> SocketAddr {
        text.parse()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
    }

    fn dropped(protocol: TransportProtocol, local: &str, remote: &str) -> DroppedPacket {
        DroppedPacket {
            tag: DropTag::user(DropKind::Pin),
            uid: Some(1000),
            protocol,
            local: addr(local),
            remote: addr(remote),
            at_unix_ms: Some(1_782_445_490_400),
        }
    }

    /// Rows as the kernel prints them: a listener on the same port, the SYN_SENT
    /// connect we dropped, another user's socket, and a wildcard-bound UDP
    /// socket plus a connected one on another port.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:C9B2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 5
   1: 0A0200C0:C9B2 076433C6:01BB 02 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 20 4 30 10 -1
   2: 0A0200C0:C9B3 076433C6:01BB 02 00000000:00000000 00:00000000 00000000  1001        0 33333 1 0000000000000000 20 4 30 10 -1
";
    const UDP: &str = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:9C40 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 44444 2 0000000000000000 0
   1: 0A0200C0:9C41 357100CB:0035 01 00000000:00000000 00:00000000 00000000  1000        0 55555 2 0000000000000000 0
";

    #[test]
    fn a_dropped_syn_finds_its_connecting_socket_not_the_listener() {
        let rows: Vec<ProcSocket> = unmapped_rows(TCP, false).collect();
        let packet = dropped(
            TransportProtocol::Tcp,
            "192.0.2.10:51634",
            "198.51.100.7:443",
        );
        assert_eq!(sending_socket(&rows, &packet).map(|r| r.inode), Some(22222));
    }

    #[test]
    fn another_users_socket_is_never_the_sender() {
        let rows: Vec<ProcSocket> = unmapped_rows(TCP, false).collect();
        let mut packet = dropped(
            TransportProtocol::Tcp,
            "192.0.2.10:51635",
            "198.51.100.7:443",
        );
        assert_eq!(sending_socket(&rows, &packet), None);
        packet.uid = Some(1001);
        assert_eq!(sending_socket(&rows, &packet).map(|r| r.inode), Some(33333));
    }

    #[test]
    fn an_unconnected_udp_socket_on_the_wildcard_is_the_sender() {
        let rows: Vec<ProcSocket> = unmapped_rows(UDP, false).collect();
        let wildcard = dropped(
            TransportProtocol::Udp,
            "192.0.2.10:40000",
            "203.0.113.9:443",
        );
        assert_eq!(
            sending_socket(&rows, &wildcard).map(|r| r.inode),
            Some(44444)
        );
        let connected = dropped(
            TransportProtocol::Udp,
            "192.0.2.10:40001",
            "203.0.113.53:53",
        );
        assert_eq!(
            sending_socket(&rows, &connected).map(|r| r.inode),
            Some(55555)
        );
        let elsewhere = dropped(TransportProtocol::Udp, "192.0.2.10:40001", "203.0.113.9:53");
        assert_eq!(sending_socket(&rows, &elsewhere), None);
    }

    #[test]
    fn only_a_datagram_from_port_zero_is_the_kernels() {
        // SAFETY: `sockaddr_nl` is plain data; zeroed is a valid value.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        source.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        assert!(from_kernel(&source));
        source.nl_pid = 4242;
        assert!(!from_kernel(&source), "a local process's port");
        source.nl_pid = 0;
        source.nl_family = 0;
        assert!(!from_kernel(&source), "an address recvfrom never filled");
    }

    #[test]
    fn a_v4_wildcard_never_sent_an_ipv6_packet() {
        let any_v4 = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        let any_v6 = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        let v6 = addr("[2001:db8::10]:1").ip();
        let v4 = addr("192.0.2.10:1").ip();
        assert!(!bound_to(any_v4, v6));
        assert!(bound_to(any_v4, v4));
        assert!(bound_to(any_v6, v4));
        assert!(bound_to(any_v6, v6));
    }

    #[test]
    fn retries_of_one_connection_are_reported_once_per_window() {
        let mut state = DrainState::default();
        let syn = dropped(
            TransportProtocol::Tcp,
            "192.0.2.10:51634",
            "198.51.100.7:443",
        );
        assert!(state.first_sighting(&syn, 1_000));
        assert!(!state.first_sighting(&syn, 4_000));
        let mut next_connect = syn.clone();
        next_connect.local = addr("192.0.2.10:51636");
        assert!(state.first_sighting(&next_connect, 4_000));
        assert!(state.first_sighting(&syn, 1_000 + REPEAT_WINDOW_MS));
    }

    #[test]
    fn packets_without_a_socket_are_not_looked_up() {
        let mut state = DrainState::default();
        let mut kernel_reset = dropped(
            TransportProtocol::Tcp,
            "192.0.2.10:443",
            "198.51.100.7:51634",
        );
        kernel_reset.uid = None;
        let icmp = dropped(
            TransportProtocol::Other(1),
            "192.0.2.10:0",
            "198.51.100.7:0",
        );
        assert_eq!(
            state.attribute(&[kernel_reset, icmp], 5_000),
            vec![None, None]
        );
        assert_eq!(state.last_walk_ms, None, "no walk for packets nobody owns");
    }

    #[test]
    fn an_observation_is_our_block_with_the_roles_spec_id_and_the_users_principal() {
        let packet = dropped(
            TransportProtocol::Tcp,
            "192.0.2.10:51634",
            "198.51.100.7:443",
        );
        let owner = Owner {
            pid: 4242,
            exe: Some("/usr/bin/example-browser".to_owned()),
        };
        let obs = observation(packet, Some(owner));
        assert_eq!(obs.verdict, ConnectionVerdict::Block);
        assert_eq!(obs.blocked_by_nrr, Some(true));
        assert_eq!(
            obs.nrr_drop_spec_id,
            Some(DropTag::user(DropKind::Pin).spec_id())
        );
        assert_eq!(obs.user_sid.as_deref(), Some("unix:uid:1000"));
        assert_eq!(obs.pid, 4242);
        assert_eq!(
            obs.process_path.as_deref(),
            Some("/usr/bin/example-browser")
        );
        assert_eq!(obs.progress, ConnectionProgress::Attempt);
        assert_eq!(obs.observed_unix_ms, Some(1_782_445_490_400));
    }

    #[test]
    fn an_ipv6_block_all_drop_carries_the_ipv6_cut_id() {
        let mut packet = dropped(
            TransportProtocol::Tcp,
            "[2001:db8::10]:51634",
            "[2001:db8::53]:443",
        );
        packet.tag = DropTag::user(DropKind::BlockAll);
        let obs = observation(packet, None);
        assert_eq!(
            obs.nrr_drop_spec_id,
            Some(DropTag::user(DropKind::Ipv6Cut).spec_id())
        );
        assert_eq!(obs.pid, 0);
        assert_eq!(obs.process_path, None);
    }
}

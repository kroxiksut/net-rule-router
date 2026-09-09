//! Passive observation of this machine's outbound connections, from procfs.
//!
//! The Linux counterpart of the Windows WFP-net-event / ETW sources. It answers
//! the question the app-routing path asks — WHICH addresses does this program
//! talk to — without a driver, without eBPF and without privileges beyond what
//! the daemon already has.
//!
//! ## What it sees, and what it cannot
//!
//! The kernel publishes every socket in `/proc/net/{tcp,tcp6,udp,udp6}` with its
//! endpoints, owning uid and socket inode. Walking `/proc/<pid>/fd` maps that
//! inode to the process holding it, and `/proc/<pid>/exe` names its binary. That
//! is a full picture of connections that EXIST when the poll runs.
//!
//! It is not a picture of connections that HAPPENED. A socket opened and closed
//! between two polls is never seen, and no verdict is available at all — a
//! blocked connection looks exactly like one that was never made. Both limits
//! are stated in what it produces ([`ConnectionVerdict::Unknown`]): a consumer
//! that read "not seen" as "not attempted" would draw the wrong conclusion about
//! a rule that is quietly failing.
//!
//! ## Why the cost is bounded
//!
//! Reading the four tables is a handful of file reads whose size follows the
//! socket count, not the traffic. The expensive half — walking every process's
//! file descriptors — runs ONLY when a socket appears that was not there before,
//! which on an idle machine is never. Nothing here sits on the data path.

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};

/// TCP states worth reporting: an established connection, and one still being
/// set up. Listening and teardown states describe no outbound destination.
const TCP_ESTABLISHED: u8 = 0x01;
const TCP_SYN_SENT: u8 = 0x02;

/// One row of a `/proc/net/*` socket table, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSocket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub uid: u32,
    pub inode: u64,
    /// Raw TCP state byte; datagram tables carry `0x07` and no handshake.
    pub state: u8,
}

/// Observes outbound connections by polling procfs.
pub struct ProcfsConnectionObserver {
    /// Socket inodes already reported. A socket is an event ONCE: what matters
    /// is the connection, not its continued existence.
    seen: Mutex<HashSet<u64>>,
}

impl Default for ProcfsConnectionObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcfsConnectionObserver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl ConnectionObservationSource for ProcfsConnectionObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        let tables = [
            ("/proc/net/tcp", TransportProtocol::Tcp, false),
            ("/proc/net/tcp6", TransportProtocol::Tcp, true),
            ("/proc/net/udp", TransportProtocol::Udp, false),
            ("/proc/net/udp6", TransportProtocol::Udp, true),
        ];

        let mut current: HashSet<u64> = HashSet::new();
        let mut fresh: Vec<(ProcSocket, TransportProtocol)> = Vec::new();
        {
            let seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            for (path, protocol, v6) in tables {
                // A kernel built without IPv6 has no `tcp6`. Missing and
                // unreadable are the same answer here — nothing to report.
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                for socket in parse_socket_table(&text, v6) {
                    if !is_outbound(&socket, protocol) {
                        continue;
                    }
                    current.insert(socket.inode);
                    if !seen.contains(&socket.inode) {
                        fresh.push((socket, protocol));
                    }
                }
            }
        }

        {
            // Forget inodes whose sockets are gone, so the set tracks the
            // machine rather than growing for the life of the process.
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            seen.retain(|inode| current.contains(inode));
            seen.extend(current.iter().copied());
        }

        if fresh.is_empty() {
            return Vec::new();
        }
        // The expensive walk: once per drain, and only when something is new.
        let wanted: HashMap<u64, u32> = fresh.iter().map(|(s, _)| (s.inode, s.uid)).collect();
        let owners = socket_owners(&wanted);

        fresh
            .into_iter()
            .map(|(socket, protocol)| {
                let owner = owners.get(&socket.inode);
                let principal =
                    nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(socket.uid);
                ConnectionObservation {
                    pid: owner.map_or(0, |o| o.pid),
                    process_path: owner.and_then(|o| o.exe.clone()),
                    user_sid: Some(principal.as_stored().to_owned()),
                    protocol,
                    local: socket.local,
                    remote: socket.remote,
                    // procfs reports sockets, never decisions: a connection the
                    // policy dropped leaves no row to read.
                    verdict: ConnectionVerdict::Unknown,
                    drop_filter_id: None,
                    blocked_by_nrr: None,
                    nrr_drop_spec_id: None,
                    observed_unix_ms: None,
                    progress: ConnectionProgress::Attempt,
                }
            })
            .collect()
    }
}

/// The process holding a socket.
struct SocketOwner {
    pid: u32,
    exe: Option<String>,
}

/// Map socket inodes to the processes holding them, by walking `/proc/<pid>/fd`.
///
/// `wanted` carries each socket's owning uid, and only processes of those uids
/// are opened: a socket belongs to the user who created it, so every other
/// process on the machine is a directory listing with no possible answer in it.
/// On a desktop that is most of them.
///
/// Best-effort by nature: a process can exit mid-walk, another user's
/// descriptors are unreadable to a non-root caller, and a daemon that dropped
/// privileges after opening its socket no longer matches its own uid. An
/// unattributed connection is still worth reporting — it carries the
/// destination, which is what the routing path needs — so a miss yields
/// `pid = 0` rather than a dropped event.
fn socket_owners(wanted: &HashMap<u64, u32>) -> HashMap<u64, SocketOwner> {
    use std::os::unix::fs::MetadataExt;

    let mut owners: HashMap<u64, SocketOwner> = HashMap::new();
    let uids: HashSet<u32> = wanted.values().copied().collect();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        // One `stat` decides whether the descriptor walk is worth doing.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !uids.contains(&meta.uid()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        // Resolved at most once per process, and only for a process that turns
        // out to own one of the sockets in question.
        let mut exe: Option<Option<String>> = None;
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = socket_inode(&target.to_string_lossy()) else {
                continue;
            };
            if !wanted.contains_key(&inode) || owners.contains_key(&inode) {
                continue;
            }
            let path = exe.get_or_insert_with(|| {
                std::fs::read_link(entry.path().join("exe"))
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned())
            });
            owners.insert(
                inode,
                SocketOwner {
                    pid,
                    exe: path.clone(),
                },
            );
        }
        if owners.len() == wanted.len() {
            break;
        }
    }
    owners
}

/// `socket:[12345]` to `12345`. Any other descriptor target is not a socket.
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|digits| digits.parse().ok())
}

/// Whether this row describes traffic leaving for somewhere.
fn is_outbound(socket: &ProcSocket, protocol: TransportProtocol) -> bool {
    if socket.remote.port() == 0 || socket.remote.ip().is_unspecified() {
        return false;
    }
    match protocol {
        // A datagram socket has no handshake to be in the middle of: `connect()`
        // only fixes the peer, and the row lives as long as the socket.
        TransportProtocol::Udp => true,
        _ => socket.state == TCP_ESTABLISHED || socket.state == TCP_SYN_SENT,
    }
}

/// Parse a `/proc/net/{tcp,udp}[6]` table. Pure over the text, so its tests run
/// on every host.
#[must_use]
pub fn parse_socket_table(text: &str, v6: bool) -> Vec<ProcSocket> {
    text.lines()
        .skip(1)
        .filter_map(|line| parse_row(line, v6))
        .collect()
}

fn parse_row(line: &str, v6: bool) -> Option<ProcSocket> {
    let mut fields = line.split_whitespace();
    let _slot = fields.next()?;
    let local = parse_endpoint(fields.next()?, v6)?;
    let remote = parse_endpoint(fields.next()?, v6)?;
    let state = u8::from_str_radix(fields.next()?, 16).ok()?;
    // Skips tx_queue:rx_queue, tr:tm->when and retrnsmt.
    let uid = fields.nth(3)?.parse().ok()?;
    let _timeout = fields.next()?;
    let inode = fields.next()?.parse().ok()?;
    Some(ProcSocket {
        local,
        remote,
        uid,
        inode,
        state,
    })
}

/// `0100007F:1F90` to `127.0.0.1:8080`.
///
/// The kernel prints each 32-bit word in HOST byte order, so on a little-endian
/// machine the octets arrive reversed — and an IPv6 address is four such words,
/// each reversed on its own rather than the address as a whole.
fn parse_endpoint(field: &str, v6: bool) -> Option<SocketAddr> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = if v6 {
        if addr.len() != 32 {
            return None;
        }
        let mut octets = [0u8; 16];
        for word in 0..4 {
            let raw = u32::from_str_radix(&addr[word * 8..word * 8 + 8], 16).ok()?;
            octets[word * 4..word * 4 + 4].copy_from_slice(&raw.to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        if addr.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(addr, 16).ok()?;
        IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 28942 1 0000000000000000 100 0 0 10 5
   1: 0F02000A:C9B2 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 44551 1 0000000000000000 20 4 30 10 -1
";

    fn addr(text: &str) -> SocketAddr {
        text.parse()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    #[test]
    fn a_row_parses_into_the_endpoints_the_kernel_meant() {
        let sockets = parse_socket_table(TCP_TABLE, false);

        assert_eq!(sockets.len(), 2);
        let established = &sockets[1];
        assert_eq!(established.local, addr("10.0.2.15:51634"));
        assert_eq!(established.remote, addr("23.10.20.131:443"));
        assert_eq!(established.uid, 1000);
        assert_eq!(established.inode, 44551);
        assert_eq!(established.state, TCP_ESTABLISHED);
    }

    /// A listener names no destination, so it is not an outbound connection —
    /// reporting it would put the machine's own services in a routing trace.
    #[test]
    fn a_listening_socket_is_not_an_outbound_connection() {
        let sockets = parse_socket_table(TCP_TABLE, false);

        assert!(!is_outbound(&sockets[0], TransportProtocol::Tcp));
        assert!(is_outbound(&sockets[1], TransportProtocol::Tcp));
    }

    /// Each 32-bit word is byte-swapped on its own. Treating the address as one
    /// long number would reverse the words too and name a different host.
    #[test]
    fn a_v6_address_is_four_independently_swapped_words() {
        let table = "  sl  local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 000080FE00000000FF67B4FE7B8B3902:C9B2 0D0C0B0A0908070605040302010000FF:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 51222 1 0000000000000000
";
        let sockets = parse_socket_table(table, true);

        assert_eq!(sockets.len(), 1);
        let expected: Ipv6Addr = "a0b:c0d:607:809:203:405:ff00:1"
            .parse()
            .unwrap_or(Ipv6Addr::UNSPECIFIED);
        assert_eq!(sockets[0].remote.ip(), IpAddr::V6(expected));
        assert_eq!(sockets[0].remote.port(), 443);
    }

    #[test]
    fn a_socket_descriptor_yields_its_inode() {
        assert_eq!(socket_inode("socket:[44551]"), Some(44551));
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("anon_inode:[eventpoll]"), None);
    }

    /// A datagram socket has no handshake to be in the middle of: the row lives
    /// while the socket does, and its peer IS the destination.
    #[test]
    fn a_connected_udp_socket_counts_even_though_it_has_no_state() {
        let table = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0F02000A:E5B4 08080808:0035 07 00000000:00000000 00:00000000 00000000  1000        0 51000 2 0000000000000000 0
";
        let sockets = parse_socket_table(table, false);

        assert!(is_outbound(&sockets[0], TransportProtocol::Udp));
        assert_eq!(sockets[0].remote, addr("8.8.8.8:53"));
    }

    /// A truncated or unexpected row is skipped, never guessed at: procfs
    /// formats differ between kernels, and inventing a destination from a
    /// half-read line would put a wrong address in a routing decision.
    #[test]
    fn a_malformed_row_is_skipped_rather_than_guessed() {
        let table = "  sl  local_address rem_address   st
   0: 0F02000A:C9B2 5DB8D822
   1: nonsense
";
        assert!(parse_socket_table(table, false).is_empty());
    }
}

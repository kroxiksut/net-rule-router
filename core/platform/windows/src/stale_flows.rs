//! Windows mechanism for [`StaleFlowReset`] — tear down TCP connections a
//! service restart left pointing at now-dead fake addresses (see the port's
//! module doc in `nrr_platform_api::fake_ip::stale_flows` for why).
//!
//! Reads the IPv4 TCP connection table the same way `flow_owner` does
//! (`GetExtendedTcpTable` / `TCP_TABLE_OWNER_PID_ALL`), then asks the OS to
//! delete the control block of every row whose remote address falls in the
//! given range via `SetTcpEntry` + `MIB_TCP_STATE_DELETE_TCB`. Only
//! `ESTABLISHED` rows are attempted: `SetTcpEntry` rejects any other state,
//! and a row that was never established was never a candidate, so that
//! rejection would not be a real failure — filtering up front keeps `found`
//! meaningful and avoids counting expected refusals as lost teardowns.
//! Deleting a control block needs administrator rights; without them every
//! row is simply skipped, which is why teardown is best-effort by contract.
//!
//! The owner of a listed connection is the user of its owning process
//! (`dwOwningPid` -> process token -> SID string), resolved once per process.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};

use windows::Win32::NetworkManagement::IpHelper::{
    SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
};

use nrr_platform_api::fake_ip::stale_flows::{EstablishedFlow, StaleFlowReset, StaleFlowSweep};

use crate::flow_owner::{read_tcp_owner_pid_table, row_endpoint};
use crate::win32_ffi::console_session::process_user_sid;

/// Production [`StaleFlowReset`] over the Windows TCP connection table.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsStaleFlowReset;

impl WindowsStaleFlowReset {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

/// Which processes hold ESTABLISHED outbound TCP connections right now,
/// busiest first.
///
/// A diagnostic, and only that: it installs nothing and decides nothing.
/// It exists for one question the logs could not answer — when the service
/// stops it removes its routes and filters, every live connection that was
/// travelling by them changes path, and a TCP session does not survive that.
/// The user sees an application lose its connection at the moment the
/// service stopped and cannot tell whether we caused it. Naming who was
/// connected turns that into evidence instead of a guess.
///
/// Reads the same table as the flow reset above, so there is one notion of
/// "an established connection", not two.
#[must_use]
pub fn established_connections_by_process(cap: usize) -> Vec<(String, usize)> {
    let Some(buffer) = read_tcp_owner_pid_table() else {
        return Vec::new();
    };
    let mut by_pid: HashMap<u32, usize> = HashMap::new();
    // SAFETY: `read_tcp_owner_pid_table` fills the buffer with a valid
    // `MIB_TCPTABLE_OWNER_PID`; its `dwNumEntries` header is followed by that
    // many contiguous rows, and only those rows are read.
    unsafe {
        let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        let rows = std::ptr::addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>();
        for i in 0..count {
            let row = &*rows.add(i);
            if row.dwState != MIB_TCP_STATE_ESTAB.0 as u32 {
                continue;
            }
            *by_pid.entry(row.dwOwningPid).or_insert(0) += 1;
        }
    }
    let mut out: Vec<(String, usize)> = by_pid
        .into_iter()
        .map(|(pid, n)| {
            let name = crate::app_path_resolver::image_name_for_pid(pid)
                .unwrap_or_else(|| format!("pid {pid}"));
            (name, n)
        })
        .collect();
    // Busiest first, then by name so the same machine logs the same order.
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.truncate(cap);
    out
}

impl StaleFlowReset for WindowsStaleFlowReset {
    fn reset_flows_to(&self, base: Ipv4Addr, prefix_len: u8) -> StaleFlowSweep {
        let Some(buffer) = read_tcp_owner_pid_table() else {
            return StaleFlowSweep::default();
        };
        let mut sweep = StaleFlowSweep::default();
        // SAFETY: `read_tcp_owner_pid_table` fills the buffer with a valid
        // `MIB_TCPTABLE_OWNER_PID`; its `dwNumEntries` header is followed by
        // that many contiguous `MIB_TCPROW_OWNER_PID` rows. We only read
        // within those rows.
        unsafe {
            let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            let count = (*table).dwNumEntries as usize;
            let rows = std::ptr::addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>();
            for i in 0..count {
                let row = &*rows.add(i);
                if !row_is_established_in_range(row, base, prefix_len) {
                    continue;
                }
                sweep.found += 1;
                if delete_tcb(&delete_tcb_entry(row)) {
                    sweep.torn_down += 1;
                }
            }
        }
        sweep
    }

    fn established_flows_to(&self, targets: &[Ipv4Addr]) -> Vec<EstablishedFlow> {
        if targets.is_empty() {
            return Vec::new();
        }
        let wanted: HashSet<u32> = targets.iter().copied().map(u32::from).collect();
        let Some(buffer) = read_tcp_owner_pid_table() else {
            return Vec::new();
        };
        let mut matched: Vec<(SocketAddrV4, SocketAddrV4, u32)> = Vec::new();
        // SAFETY: same invariant as `reset_flows_to` above — the buffer holds a
        // valid `MIB_TCPTABLE_OWNER_PID` and we read only its declared rows.
        unsafe {
            let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            let count = (*table).dwNumEntries as usize;
            let rows = std::ptr::addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>();
            for i in 0..count {
                let row = &*rows.add(i);
                if row.dwState == MIB_TCP_STATE_ESTAB.0 as u32
                    && wanted.contains(&u32::from_be(row.dwRemoteAddr))
                {
                    let (local, remote) = row_endpoints(row);
                    matched.push((local, remote, row.dwOwningPid));
                }
            }
        }
        // A browser holds many connections to one front; ask for its token and image
        // name once; the image is read now, the process may be gone after the reset.
        let mut owners: HashMap<u32, (Option<String>, Option<String>)> = HashMap::new();
        matched
            .into_iter()
            .map(|(local, remote, pid)| {
                let (owner, image) = owners
                    .entry(pid)
                    .or_insert_with(|| {
                        (
                            process_user_sid(pid),
                            crate::app_path_resolver::image_name_for_pid(pid),
                        )
                    })
                    .clone();
                EstablishedFlow {
                    local,
                    remote,
                    owner,
                    pid: Some(pid),
                    image,
                }
            })
            .collect()
    }

    fn reset_established(&self, flows: &[EstablishedFlow]) -> usize {
        flows
            .iter()
            .filter(|flow| delete_tcb(&delete_tcb_entry_for(flow)))
            .count()
    }
}

/// A table row's local and remote endpoints, host order.
fn row_endpoints(row: &MIB_TCPROW_OWNER_PID) -> (SocketAddrV4, SocketAddrV4) {
    let (local_ip, local_port) = row_endpoint(row.dwLocalAddr, row.dwLocalPort);
    let (remote_ip, remote_port) = row_endpoint(row.dwRemoteAddr, row.dwRemotePort);
    (
        SocketAddrV4::new(local_ip, local_port),
        SocketAddrV4::new(remote_ip, remote_port),
    )
}

/// `ESTABLISHED` and its remote address inside `base`/`prefix_len` — the only
/// rows worth attempting a teardown on.
fn row_is_established_in_range(row: &MIB_TCPROW_OWNER_PID, base: Ipv4Addr, prefix_len: u8) -> bool {
    row.dwState == MIB_TCP_STATE_ESTAB.0 as u32
        && addr_in_range(
            Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
            base,
            prefix_len,
        )
}

/// CIDR containment: is `addr` inside `base`/`prefix_len`? A `prefix_len`
/// above 32 matches nothing — there is no such network.
fn addr_in_range(addr: Ipv4Addr, base: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(addr) & mask) == (u32::from(base) & mask)
}

/// Build the row `SetTcpEntry` needs to delete `row`'s control block.
/// Addresses and ports are copied verbatim from the table row: both are
/// already network byte order, the layout `SetTcpEntry` expects, so nothing
/// here reorders them.
fn delete_tcb_entry(row: &MIB_TCPROW_OWNER_PID) -> MIB_TCPROW_LH {
    let mut entry = MIB_TCPROW_LH {
        dwLocalAddr: row.dwLocalAddr,
        dwLocalPort: row.dwLocalPort,
        dwRemoteAddr: row.dwRemoteAddr,
        dwRemotePort: row.dwRemotePort,
        ..Default::default()
    };
    entry.Anonymous.State = MIB_TCP_STATE_DELETE_TCB;
    entry
}

/// The same delete request for a listed connection: the inverse of
/// [`row_endpoints`], back to network byte order.
fn delete_tcb_entry_for(flow: &EstablishedFlow) -> MIB_TCPROW_LH {
    let mut entry = MIB_TCPROW_LH {
        dwLocalAddr: u32::from(*flow.local.ip()).to_be(),
        dwLocalPort: u32::from(flow.local.port().to_be()),
        dwRemoteAddr: u32::from(*flow.remote.ip()).to_be(),
        dwRemotePort: u32::from(flow.remote.port().to_be()),
        ..Default::default()
    };
    entry.Anonymous.State = MIB_TCP_STATE_DELETE_TCB;
    entry
}

/// Ask the OS to tear down one `ESTABLISHED` connection. Best-effort: a
/// refusal (typically missing administrator rights, or the connection already
/// gone) just leaves it standing.
fn delete_tcb(entry: &MIB_TCPROW_LH) -> bool {
    // SAFETY: `entry` is a fully initialized, stack-local `MIB_TCPROW_LH`;
    // `SetTcpEntry` reads it and does not retain the pointer past the call.
    unsafe { SetTcpEntry(entry) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POOL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);

    #[test]
    fn addr_in_range_accepts_both_ends_of_a_slash_15() {
        assert!(addr_in_range(Ipv4Addr::new(198, 18, 0, 0), POOL, 15));
        assert!(addr_in_range(Ipv4Addr::new(198, 19, 255, 255), POOL, 15));
    }

    #[test]
    fn addr_in_range_rejects_the_address_just_outside_a_slash_15() {
        assert!(!addr_in_range(Ipv4Addr::new(198, 20, 0, 0), POOL, 15));
        assert!(!addr_in_range(Ipv4Addr::new(198, 17, 255, 255), POOL, 15));
    }

    #[test]
    fn addr_in_range_slash_32_matches_only_the_exact_address() {
        let host = Ipv4Addr::new(198, 18, 0, 42);
        assert!(addr_in_range(host, host, 32));
        assert!(!addr_in_range(Ipv4Addr::new(198, 18, 0, 43), host, 32));
    }

    #[test]
    fn addr_in_range_rejects_an_impossible_prefix() {
        assert!(!addr_in_range(POOL, POOL, 33));
    }

    #[test]
    fn row_is_established_in_range_requires_both_state_and_address() {
        let mut row = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_ESTAB.0 as u32,
            dwLocalAddr: 0x0100_000A,
            dwLocalPort: 0x0000_BB01,
            dwRemoteAddr: u32::from_le_bytes(POOL.octets()),
            dwRemotePort: 0x0000_5000,
            dwOwningPid: 4242,
        };
        assert!(row_is_established_in_range(&row, POOL, 15));

        // Same address, but not ESTABLISHED (LISTEN) — must not match.
        row.dwState = windows::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_LISTEN.0 as u32;
        assert!(!row_is_established_in_range(&row, POOL, 15));
    }

    #[test]
    fn delete_tcb_entry_copies_addresses_and_ports_verbatim_and_sets_delete_state() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_ESTAB.0 as u32,
            dwLocalAddr: 0x0200_000A,
            dwLocalPort: 0x0000_BB01,
            dwRemoteAddr: u32::from_le_bytes(POOL.octets()),
            dwRemotePort: 0x0000_5000,
            dwOwningPid: 4242,
        };

        let entry = delete_tcb_entry(&row);

        assert_eq!(entry.dwLocalAddr, row.dwLocalAddr);
        assert_eq!(entry.dwLocalPort, row.dwLocalPort);
        assert_eq!(entry.dwRemoteAddr, row.dwRemoteAddr);
        assert_eq!(entry.dwRemotePort, row.dwRemotePort);
        // SAFETY: reading back the union field this same function just wrote.
        let state = unsafe { entry.Anonymous.State };
        assert_eq!(state, MIB_TCP_STATE_DELETE_TCB);
    }

    /// A listed connection must reset the very row it was listed from: the
    /// decision runs on host-order endpoints, `SetTcpEntry` on the raw row.
    #[test]
    fn a_listed_connection_deletes_exactly_the_row_it_came_from() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: MIB_TCP_STATE_ESTAB.0 as u32,
            dwLocalAddr: u32::from_le_bytes([192, 0, 2, 7]),
            dwLocalPort: 0x0000_50C3, // 50000, network order in the low word
            dwRemoteAddr: u32::from_le_bytes([203, 0, 113, 9]),
            dwRemotePort: 0x0000_BB01, // 443
            dwOwningPid: 4242,
        };
        let (local, remote) = row_endpoints(&row);
        assert_eq!(
            local,
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), 50_000)
        );
        assert_eq!(
            remote,
            SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443)
        );

        let flow = EstablishedFlow {
            local,
            remote,
            owner: None,
            pid: None,
            image: None,
        };
        let from_flow = delete_tcb_entry_for(&flow);
        let from_row = delete_tcb_entry(&row);
        assert_eq!(from_flow.dwLocalAddr, from_row.dwLocalAddr);
        assert_eq!(from_flow.dwLocalPort, from_row.dwLocalPort);
        assert_eq!(from_flow.dwRemoteAddr, from_row.dwRemoteAddr);
        assert_eq!(from_flow.dwRemotePort, from_row.dwRemotePort);
        // SAFETY: reading back the union field this same function just wrote.
        let state = unsafe { from_flow.Anonymous.State };
        assert_eq!(state, MIB_TCP_STATE_DELETE_TCB);
    }

    /// Listing only reads the table, so it is safe against the live machine.
    #[test]
    fn listing_an_address_nothing_talks_to_finds_nothing() {
        let nobody = Ipv4Addr::new(192, 0, 2, 254);
        assert!(WindowsStaleFlowReset
            .established_flows_to(&[nobody])
            .is_empty());
        assert!(WindowsStaleFlowReset.established_flows_to(&[]).is_empty());
    }

    #[test]
    fn the_owner_of_our_own_process_resolves_to_a_sid() {
        let sid = process_user_sid(std::process::id()).expect("own token is readable");
        assert!(sid.starts_with("S-1-"), "{sid}");
    }
}

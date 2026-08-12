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

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB,
};

use nrr_platform_api::fake_ip::stale_flows::{StaleFlowReset, StaleFlowSweep};

use crate::flow_owner::read_tcp_owner_pid_table;

/// Production [`StaleFlowReset`] over the Windows TCP connection table.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsStaleFlowReset;

impl WindowsStaleFlowReset {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
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
                if delete_established_row(row) {
                    sweep.torn_down += 1;
                }
            }
        }
        sweep
    }
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

/// Ask the OS to tear down one `ESTABLISHED` row. Best-effort: a refusal
/// (typically missing administrator rights) just leaves this row standing.
fn delete_established_row(row: &MIB_TCPROW_OWNER_PID) -> bool {
    let entry = delete_tcb_entry(row);
    // SAFETY: `entry` is a fully initialized, stack-local `MIB_TCPROW_LH`;
    // `SetTcpEntry` reads it and does not retain the pointer past the call.
    unsafe { SetTcpEntry(&entry) == 0 }
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
}

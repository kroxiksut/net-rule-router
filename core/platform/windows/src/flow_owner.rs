//! Windows mechanism for [`FlowOwnerLookup`] — name the process that owns a
//! relayed TCP flow, so the VPN self-heal can tell a VPN client's control
//! connection apart from ordinary traffic.
//!
//! The lookup reads the IPv4 TCP connection table (`GetExtendedTcpTable` with
//! `TCP_TABLE_OWNER_PID_ALL`), finds the row whose local and remote endpoints
//! match the relayed flow, and resolves its owning PID to an image basename via
//! `QueryFullProcessImageNameW`. Every step is best-effort: a missing row, a
//! process that already exited, or insufficient rights all return `None`, and
//! the relay simply keeps serving the flow.
//!
//! IPv6 flows return `None` for now — the fake pool the relay hands out is
//! IPv4, so the client's connection to a fake address is IPv4; a v6 client
//! endpoint would need the `AF_INET6` table and is not worth the extra FFI until
//! a v6 relay path exists.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::{Ipv4Addr, SocketAddr};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use nrr_platform_api::FlowOwnerLookup;

/// Production [`FlowOwnerLookup`] over the Windows TCP connection table.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFlowOwnerLookup;

impl WindowsFlowOwnerLookup {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl FlowOwnerLookup for WindowsFlowOwnerLookup {
    fn owner_image_name(&self, local: SocketAddr, remote: SocketAddr) -> Option<String> {
        let (SocketAddr::V4(local_v4), SocketAddr::V4(remote_v4)) = (local, remote) else {
            return None; // IPv4 relay only (see module doc)
        };
        let pid = owning_pid_v4(
            (*local_v4.ip(), local_v4.port()),
            (*remote_v4.ip(), remote_v4.port()),
        )?;
        process_image_basename(pid)
    }
}

/// One (local, remote) IPv4 endpoint pair, network-independent.
type Endpoint = (Ipv4Addr, u16);

/// Scan the IPv4 TCP table for the row matching `local`/`remote` and return its
/// owning PID. `None` when the table cannot be read or holds no such row.
fn owning_pid_v4(local: Endpoint, remote: Endpoint) -> Option<u32> {
    let buffer = read_tcp_owner_pid_table()?;
    // SAFETY: `read_tcp_owner_pid_table` returns a buffer the API filled with a
    // valid `MIB_TCPTABLE_OWNER_PID`; its `dwNumEntries` header is followed by
    // that many contiguous `MIB_TCPROW_OWNER_PID` rows. We only read within
    // those rows.
    unsafe {
        let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        let count = (*table).dwNumEntries as usize;
        let rows = std::ptr::addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>();
        for i in 0..count {
            let row = &*rows.add(i);
            if row_endpoint(row.dwLocalAddr, row.dwLocalPort) == local
                && row_endpoint(row.dwRemoteAddr, row.dwRemotePort) == remote
            {
                return Some(row.dwOwningPid);
            }
        }
    }
    None
}

/// Decode a table row's address+port pair into a host-order [`Endpoint`].
/// `MIB_TCPROW_OWNER_PID` stores the address as a network-order `u32` and the
/// port in the low two bytes in network byte order.
fn row_endpoint(addr: u32, port: u32) -> Endpoint {
    let ip = Ipv4Addr::from(u32::from_be(addr));
    let port = (((port & 0xff) << 8) | ((port >> 8) & 0xff)) as u16;
    (ip, port)
}

/// Two-call `GetExtendedTcpTable`: size probe, then a right-sized read. Returns
/// the raw table buffer, or `None` on any error.
///
/// `pub(crate)`: `stale_flows` reuses this to walk the same table for a
/// different purpose (range membership, not endpoint matching).
pub(crate) fn read_tcp_owner_pid_table() -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    // SAFETY: the size probe passes a null table pointer, which the API accepts,
    // writing the required byte count into `size`. It returns
    // ERROR_INSUFFICIENT_BUFFER when the table is non-empty.
    let probe = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if probe != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size as usize];
    // SAFETY: `buffer` is `size` bytes, exactly what the probe requested; the
    // API fills it with a `MIB_TCPTABLE_OWNER_PID`. `size` is updated in place.
    let code = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if code != 0 {
        return None;
    }
    Some(buffer)
}

/// The lower-cased image basename (e.g. `"wireguard.exe"`) of process `pid`, or
/// `None` when the process cannot be opened or queried (already exited, or the
/// service lacks rights — either way self-heal simply skips this flow).
fn process_image_basename(pid: u32) -> Option<String> {
    // SAFETY: `OpenProcess` returns a handle we close below on every path.
    let handle: HANDLE =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = [0u16; 260]; // MAX_PATH
    let mut len = buf.len() as u32;
    // SAFETY: `handle` is a live process handle; `buf`/`len` describe a valid
    // wide-string output buffer. On success `len` is updated to the char count.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    };
    // SAFETY: `handle` was opened above and is not used after this call.
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.ok()?;
    let full = String::from_utf16_lossy(&buf[..len as usize]);
    let base = full
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&full)
        .trim()
        .to_ascii_lowercase();
    if base.is_empty() {
        None
    } else {
        Some(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_endpoint_decodes_network_order_address_and_port() {
        // The table stores the network-order address bytes [10,0,0,2] in a DWORD
        // read back as a native (little-endian) u32 — exactly `from_le_bytes` of
        // those bytes. The port is 443 in the low word in network order.
        let addr = u32::from_le_bytes([10, 0, 0, 2]);
        let port_raw: u32 = 0x0000_BB01; // network-order 443 in the low word
        assert_eq!(
            row_endpoint(addr, port_raw),
            (Ipv4Addr::new(10, 0, 0, 2), 443)
        );
    }

    #[test]
    fn looking_up_our_own_process_or_a_missing_flow_never_panics() {
        // No matching connection exists for this synthetic pair; the table read
        // (or the absence of a row) must degrade to None rather than panic.
        let lookup = WindowsFlowOwnerLookup::new();
        let out = lookup.owner_image_name(
            "10.255.255.254:1".parse().expect("addr"),
            "198.18.0.7:443".parse().expect("addr"),
        );
        assert!(out.is_none());
    }

    #[test]
    fn ipv6_endpoints_are_declined() {
        let lookup = WindowsFlowOwnerLookup::new();
        let out = lookup.owner_image_name(
            "[::1]:51000".parse().expect("addr"),
            "[fc00::1]:443".parse().expect("addr"),
        );
        assert!(out.is_none());
    }
}

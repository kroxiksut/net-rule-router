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

use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;

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
pub(crate) fn row_endpoint(addr: u32, port: u32) -> Endpoint {
    let ip = Ipv4Addr::from(u32::from_be(addr));
    let port = (((port & 0xff) << 8) | ((port >> 8) & 0xff)) as u16;
    (ip, port)
}

/// Reads of the table before giving up on one that keeps outgrowing the buffer.
const TABLE_READ_ATTEMPTS: usize = 4;

/// Rows of slack over the size the API asked for: connections open between
/// that answer and the next read.
const TABLE_HEADROOM_ROWS: usize = 64;

/// `GetExtendedTcpTable` into a buffer grown until the table fits. Returns the
/// raw table buffer, or `None` on a real error, which is logged.
///
/// `pub(crate)`: `stale_flows` reuses this to walk the same table for a
/// different purpose (range membership, not endpoint matching).
pub(crate) fn read_tcp_owner_pid_table() -> Option<Vec<u8>> {
    let read = read_growing(
        std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>(),
        TABLE_HEADROOM_ROWS * std::mem::size_of::<MIB_TCPROW_OWNER_PID>(),
        |buffer, size| {
            // SAFETY: `buffer` is writable for `*size` bytes, which is its full
            // length; the API writes at most that much, or only updates `size`.
            unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr().cast::<c_void>()),
                    size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            }
        },
    );
    match read {
        Ok(buffer) => Some(buffer),
        Err(TableReadError::Failed(code)) => {
            tracing::warn!(
                target: "nrr::conn-observe",
                code,
                "reading the TCP connection table failed",
            );
            None
        }
        Err(TableReadError::KeptGrowing { last_size }) => {
            tracing::warn!(
                target: "nrr::conn-observe",
                last_size,
                attempts = TABLE_READ_ATTEMPTS,
                "the TCP connection table kept outgrowing the read buffer",
            );
            None
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TableReadError {
    /// The API's error code.
    Failed(u32),
    /// Every attempt came back too small; the size it last asked for.
    KeptGrowing { last_size: u32 },
}

/// Call `fetch(buffer, size)` — a Win32 "fill this, or tell me the size" API —
/// until it succeeds, growing the buffer to the size it asks for plus
/// `headroom`, for at most [`TABLE_READ_ATTEMPTS`] calls.
fn read_growing(
    initial: usize,
    headroom: usize,
    mut fetch: impl FnMut(&mut [u8], &mut u32) -> u32,
) -> Result<Vec<u8>, TableReadError> {
    let mut buffer = vec![0u8; initial];
    let mut last_size = 0u32;
    for _ in 0..TABLE_READ_ATTEMPTS {
        let mut size =
            u32::try_from(buffer.len()).map_err(|_| TableReadError::KeptGrowing { last_size })?;
        match fetch(&mut buffer, &mut size) {
            0 => return Ok(buffer),
            code if code == ERROR_INSUFFICIENT_BUFFER.0 => {
                last_size = size;
                // Grow even on an answer no larger than the buffer, or the next
                // attempt would fail the same way.
                let next = (size as usize)
                    .max(buffer.len())
                    .saturating_add(headroom.max(1));
                buffer.clear();
                buffer.resize(next, 0);
            }
            code => return Err(TableReadError::Failed(code)),
        }
    }
    Err(TableReadError::KeptGrowing { last_size })
}

/// The lower-cased image basename (e.g. `"wireguard.exe"`) of process `pid`, or
/// `None` when the process cannot be opened or queried (already exited, or the
/// service lacks rights — either way self-heal simply skips this flow).
fn process_image_basename(pid: u32) -> Option<String> {
    let full = crate::win32_ffi::process::process_image_path(pid)?;
    let full = full.to_string_lossy();
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

    /// A fake "fill or report the size" API over a table that is `sizes[n]`
    /// bytes on the n-th call.
    fn table_growing_by_call(sizes: Vec<u32>) -> impl FnMut(&mut [u8], &mut u32) -> u32 {
        let mut call = 0usize;
        move |buffer, size| {
            let needed = sizes[call.min(sizes.len() - 1)];
            call += 1;
            assert_eq!(*size as usize, buffer.len());
            if *size < needed {
                *size = needed;
                return ERROR_INSUFFICIENT_BUFFER.0;
            }
            buffer[0] = 0xAB;
            0
        }
    }

    #[test]
    fn a_table_that_grows_between_calls_is_still_read() {
        // Asked for 100 bytes, then the table grew past 100 + headroom.
        let got = read_growing(8, 16, table_growing_by_call(vec![100, 200, 200]));
        let buffer = got.expect("read on the third call");
        assert!(buffer.len() >= 200);
        assert_eq!(buffer[0], 0xAB);
    }

    #[test]
    fn a_table_that_fits_is_read_in_one_call() {
        let mut calls = 0;
        let mut inner = table_growing_by_call(vec![4]);
        let got = read_growing(8, 16, |b, s| {
            calls += 1;
            inner(b, s)
        });
        assert_eq!(got.map(|b| b.len()), Ok(8));
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_table_outgrowing_every_attempt_is_reported_not_emptied() {
        let sizes = (1..=TABLE_READ_ATTEMPTS as u32 + 1)
            .map(|n| n * 10_000)
            .collect();
        let got = read_growing(8, 16, table_growing_by_call(sizes));
        assert_eq!(
            got,
            Err(TableReadError::KeptGrowing {
                last_size: TABLE_READ_ATTEMPTS as u32 * 10_000
            })
        );
    }

    #[test]
    fn a_size_answer_no_larger_than_the_buffer_still_grows_it() {
        let mut seen = Vec::new();
        let got = read_growing(8, 16, |buffer, size| {
            seen.push(buffer.len());
            if seen.len() < 3 {
                return ERROR_INSUFFICIENT_BUFFER.0; // `size` left as offered
            }
            *size = 0;
            0
        });
        assert!(got.is_ok());
        assert_eq!(seen, vec![8, 24, 40]);
    }

    #[test]
    fn a_real_error_is_returned_as_is() {
        let got = read_growing(8, 16, |_, _| 87); // ERROR_INVALID_PARAMETER
        assert_eq!(got, Err(TableReadError::Failed(87)));
    }

    #[test]
    fn the_live_table_reads() {
        let buffer = read_tcp_owner_pid_table().expect("the TCP table is readable");
        assert!(buffer.len() >= std::mem::size_of::<MIB_TCPTABLE_OWNER_PID>());
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

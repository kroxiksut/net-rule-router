//! `GetAdaptersAddresses` FFI binding.
//!
//! Backs `WindowsApiPort::get_adapter_infos` with a real Win32 call.
//!
//! ## Buffer growth strategy
//!
//! `GetAdaptersAddresses` is a classic Win32 "two-pass or grow-and-retry"
//! API: the caller hands in a buffer plus its size; the API either
//! succeeds or returns `ERROR_BUFFER_OVERFLOW` along with the required
//! size in the same `*mut u32`. We start at 16 KiB (covers most home
//! machines in one pass), retry up to 4 times doubling/clamping to a
//! 16 MiB ceiling, and fail with `Transient` if growth still doesn't
//! suffice — that scenario indicates an adversarial environment, not a
//! genuine adapter count.
//!
//! ## Encoding contract
//!
//! - `AdapterName` is the **ASCII GUID string** (`{12AB...}`) — read via
//!   [`super::wide::pcstr_lossy`].
//! - `Description` and `FriendlyName` are wide (UTF-16) — read via
//!   [`super::wide::pwstr_lossy`].
//!
//! ## IPv6 policy
//!
//! Only `AF_INET` (IPv4) is requested. Any IPv6 unicast or gateway
//! addresses present on the adapter are silently filtered out at the
//! `sin_family` check — `AdapterInfo` carries IPv4 only by design (see
//! `core/platform/windows/src/types.rs` module doc).

#![allow(unsafe_code)]

use std::net::Ipv4Addr;

use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
    GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_UNICAST_ADDRESS_LH,
};
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR, SOCKADDR_IN};

use crate::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use crate::error::PlatformError;

use super::wide::{pcstr_lossy, pwstr_lossy};

/// Initial buffer size for the first `GetAdaptersAddresses` call.
/// 16 KiB covers a typical home machine (5–10 adapters) without retry.
const INITIAL_BUFFER_BYTES: u32 = 16 * 1024;

/// Hard ceiling on the buffer size — defends against pathological
/// retries if Windows keeps returning `ERROR_BUFFER_OVERFLOW`.
const MAX_BUFFER_BYTES: u32 = 16 * 1024 * 1024;

/// Maximum number of grow-and-retry passes before giving up.
const MAX_RETRIES: u8 = 4;

const OPERATION: &str = "GetAdaptersAddresses";

/// Enumerate all IPv4 adapters via `GetAdaptersAddresses`.
///
/// Returns adapters as observed by the Win32 API at call time. The
/// caller is responsible for filtering virtual / loopback adapters
/// (see `crate::adapters::is_virtual_adapter`).
pub fn enumerate_adapters() -> Result<Vec<AdapterInfo>, PlatformError> {
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    let mut size = INITIAL_BUFFER_BYTES;
    for _ in 0..MAX_RETRIES {
        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let mut out_size = size;

        // SAFETY: `buf` is freshly allocated to `size` bytes. `head` is
        // a valid, properly aligned pointer (Vec<u8>::as_mut_ptr is at
        // least 1-byte aligned; the IP_ADAPTER_ADDRESSES_LH header is
        // packed and Win32 fills it via byte-wise writes). `out_size` is
        // initialised to `size`. Win32 contract: it writes within
        // `out_size` bytes, and on overflow updates `out_size` with the
        // required length. Lifetime of `buf` covers the call.
        let code = unsafe {
            GetAdaptersAddresses(u32::from(AF_INET.0), flags, None, Some(head), &mut out_size)
        };

        if code == NO_ERROR.0 {
            // SAFETY: Win32 produced a valid linked-list-of-`IP_ADAPTER_
            // ADDRESSES_LH` that lives inside `buf`. `walk_chain` only
            // reads through `Next`/inner pointers and dereferences while
            // they remain non-null and within the buffer Win32 wrote.
            let result = unsafe { walk_chain(head) };
            return Ok(result);
        }
        if code == ERROR_NO_DATA.0 {
            return Ok(Vec::new());
        }
        if code == ERROR_BUFFER_OVERFLOW.0 {
            // Grow to whatever Win32 asked for, doubling the previous
            // size as a floor (avoids ping-pong if Win32 reports the
            // exact required size and another adapter shows up between
            // calls), and clamp to the safety ceiling.
            let next = out_size.max(size.saturating_mul(2)).min(MAX_BUFFER_BYTES);
            if next <= size {
                return Err(PlatformError::Transient {
                    operation: OPERATION,
                    detail: format!(
                        "buffer growth stuck: required {out_size} ≤ current {size}, ceiling {MAX_BUFFER_BYTES}"
                    ),
                });
            }
            size = next;
            continue;
        }
        return Err(PlatformError::Win32 {
            operation: OPERATION,
            code,
            message: format!("Win32 error {code}"),
        });
    }
    Err(PlatformError::Transient {
        operation: OPERATION,
        detail: format!("buffer growth exceeded {MAX_RETRIES} retries"),
    })
}

/// Walk the linked list returned by `GetAdaptersAddresses`.
///
/// # Safety
///
/// `head` must be either null or a pointer to a valid
/// `IP_ADAPTER_ADDRESSES_LH` linked list as produced by
/// `GetAdaptersAddresses` into a buffer that remains live for the
/// duration of the call.
unsafe fn walk_chain(head: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<AdapterInfo> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0u32;
    while !cur.is_null() && guard < MAX_ADAPTERS_GUARD {
        // SAFETY: `cur` is non-null and points to a Win32-produced
        // `IP_ADAPTER_ADDRESSES_LH` inside our buffer.
        let entry = unsafe { &*cur };
        if let Some(info) = unsafe { read_entry(entry) } {
            out.push(info);
        }
        cur = entry.Next;
        guard += 1;
    }
    out
}

/// Defensive cap on linked-list traversal — Windows never returns
/// anywhere near this many adapters in practice (typical: 5–20). A
/// circular list would otherwise loop forever.
const MAX_ADAPTERS_GUARD: u32 = 4096;

/// Read one `IP_ADAPTER_ADDRESSES_LH` entry into our `AdapterInfo`.
///
/// # Safety
///
/// `entry` must be a valid reference (already dereffed safely via the
/// chain walker). Inner pointers (`AdapterName`, `Description`,
/// `FirstUnicastAddress`, `FirstGatewayAddress`) must be either null or
/// valid as filled by `GetAdaptersAddresses`.
unsafe fn read_entry(entry: &IP_ADAPTER_ADDRESSES_LH) -> Option<AdapterInfo> {
    // SAFETY: union access — the `Anonymous` arm carries `IfIndex` per
    // the IP Helper API contract. The other arm is `Alignment: u64`,
    // which is also a valid `repr(C)` union view.
    let if_index = unsafe { entry.Anonymous1.Anonymous.IfIndex };

    // SAFETY: `AdapterName` is a Win32-owned, null-terminated PCSTR
    // valid for the lifetime of the buffer.
    let adapter_name = unsafe { pcstr_lossy(entry.AdapterName.0 as *const u8) };

    // SAFETY: same for `Description` (PWSTR / UTF-16).
    let description = unsafe { pwstr_lossy(entry.Description.0 as *const u16) };

    // SAFETY: same for `FriendlyName` — the renameable connection name.
    let friendly_name = unsafe { pwstr_lossy(entry.FriendlyName.0 as *const u16) };

    let mac = read_mac(entry);
    let interface_type = InterfaceType::from_raw(entry.IfType);
    let oper_status = decode_oper_status(entry.OperStatus.0);

    // SAFETY: linked-list head pointers remain valid for buffer lifetime.
    let ipv4_addresses = unsafe { walk_unicast(entry.FirstUnicastAddress) };
    let gateways = unsafe { walk_gateways(entry.FirstGatewayAddress) };

    Some(AdapterInfo {
        index: if_index,
        adapter_name,
        description,
        friendly_name,
        mac,
        interface_type,
        oper_status,
        ipv4_addresses,
        gateways,
    })
}

fn read_mac(entry: &IP_ADAPTER_ADDRESSES_LH) -> Option<[u8; 6]> {
    if entry.PhysicalAddressLength == 6 {
        let pa = entry.PhysicalAddress;
        Some([pa[0], pa[1], pa[2], pa[3], pa[4], pa[5]])
    } else {
        None
    }
}

/// Map `IF_OPER_STATUS` raw value to our domain `IfOperStatus`.
///
/// Win32 values per `IfMib.h`:
/// `1=Up, 2=Down, 3=Testing, 4=Unknown, 5=Dormant, 6=NotPresent, 7=LowerLayerDown`.
fn decode_oper_status(raw: i32) -> IfOperStatus {
    match raw {
        1 => IfOperStatus::Up,
        2 => IfOperStatus::Down,
        3 => IfOperStatus::Testing,
        5 => IfOperStatus::Dormant,
        6 => IfOperStatus::NotPresent,
        7 => IfOperStatus::LowerLayerDown,
        _ => IfOperStatus::Unknown,
    }
}

/// Walk the unicast address linked list, collecting IPv4 only.
///
/// # Safety
///
/// `head` must be either null or a valid pointer to an
/// `IP_ADAPTER_UNICAST_ADDRESS_LH` list as filled by Win32.
unsafe fn walk_unicast(head: *const IP_ADAPTER_UNICAST_ADDRESS_LH) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0u32;
    while !cur.is_null() && guard < MAX_ADDRS_GUARD {
        // SAFETY: Win32-produced linked-list node, alive for buffer lifetime.
        let node = unsafe { &*cur };
        if let Some(addr) = unsafe { sockaddr_to_ipv4(node.Address.lpSockaddr) } {
            out.push(addr);
        }
        cur = node.Next;
        guard += 1;
    }
    out
}

/// Walk the gateway address linked list, collecting IPv4 only.
///
/// # Safety
///
/// Same contract as [`walk_unicast`] but for the gateway list.
unsafe fn walk_gateways(head: *const IP_ADAPTER_GATEWAY_ADDRESS_LH) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut cur = head;
    let mut guard = 0u32;
    while !cur.is_null() && guard < MAX_ADDRS_GUARD {
        // SAFETY: Win32-produced linked-list node.
        let node = unsafe { &*cur };
        if let Some(addr) = unsafe { sockaddr_to_ipv4(node.Address.lpSockaddr) } {
            out.push(addr);
        }
        cur = node.Next;
        guard += 1;
    }
    out
}

const MAX_ADDRS_GUARD: u32 = 1024;

/// Decode a `SOCKADDR*` into an `Ipv4Addr` if (and only if) it is
/// `AF_INET`. IPv6 addresses are silently dropped — adapter info
/// carries IPv4 only.
///
/// # Safety
///
/// `ptr` must be either null or point at a valid `SOCKADDR` whose
/// memory is owned by the surrounding Win32 buffer.
unsafe fn sockaddr_to_ipv4(ptr: *const SOCKADDR) -> Option<Ipv4Addr> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: `ptr` is non-null and points at a valid SOCKADDR header.
    let family = unsafe { (*ptr).sa_family };
    if family != AF_INET {
        return None;
    }
    // SAFETY: when `sa_family == AF_INET`, the layout is `SOCKADDR_IN`.
    let sa_in = unsafe { &*(ptr as *const SOCKADDR_IN) };
    // SAFETY: `S_addr` is a valid arm of the IN_ADDR union; bytes are
    // network-order (big-endian) per the Win32 contract.
    let net_order = unsafe { sa_in.sin_addr.S_un.S_addr };
    let host_order = u32::from_be(net_order);
    Some(Ipv4Addr::from(host_order))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_oper_status_known_values() {
        assert_eq!(decode_oper_status(1), IfOperStatus::Up);
        assert_eq!(decode_oper_status(2), IfOperStatus::Down);
        assert_eq!(decode_oper_status(3), IfOperStatus::Testing);
        assert_eq!(decode_oper_status(5), IfOperStatus::Dormant);
        assert_eq!(decode_oper_status(6), IfOperStatus::NotPresent);
        assert_eq!(decode_oper_status(7), IfOperStatus::LowerLayerDown);
    }

    #[test]
    fn decode_oper_status_unknown_falls_back() {
        assert_eq!(decode_oper_status(0), IfOperStatus::Unknown);
        assert_eq!(decode_oper_status(99), IfOperStatus::Unknown);
        assert_eq!(decode_oper_status(-1), IfOperStatus::Unknown);
    }

    /// Smoke test that the `enumerate_adapters` call compiles and
    /// returns *some* `Result` on Windows. We don't assert the contents
    /// because they depend on the test machine's adapter inventory.
    /// On CI without admin rights `Ok(Vec)` is the expected outcome
    /// (`GetAdaptersAddresses` is a non-privileged call).
    ///
    /// This test runs only on Windows (the module is `cfg`-gated).
    #[test]
    fn enumerate_adapters_returns_ok_on_windows() {
        let result = enumerate_adapters();
        // The most common outcomes on a healthy host: `Ok(non-empty)`.
        // CI VMs may legitimately return empty (no IPv4 adapters); we
        // accept both. Errors point at a real Win32 problem.
        match result {
            Ok(_) => {}
            Err(e) => panic!("enumerate_adapters failed unexpectedly: {e}"),
        }
    }
}

//! IPv4 forwarding-table FFI (`GetIpForwardTable2`,
//! `CreateIpForwardEntry2`, `DeleteIpForwardEntry2`).
//!
//! Backs three `WindowsApiPort` methods:
//! - `get_ip_forward_table` — enumerate all IPv4 routes
//! - `create_ip_forward_entry` — add one route
//! - `delete_ip_forward_entry` — remove one route
//!
//! ## Memory ownership
//!
//! `GetIpForwardTable2` allocates a `MIB_IPFORWARD_TABLE2*` and the
//! caller must release it via `FreeMibTable`. We free it in the same
//! function before returning the owned `Vec<RouteEntry>` — callers
//! never see the raw pointer.
//!
//! ## `is_ours` flag
//!
//! `RouteEntry::is_ours` is a domain-level marker the storage layer
//! cross-references against persisted `(destination, prefix, ifIndex)`
//! tuples to determine which routes the apply layer added. This FFI
//! always reports `is_ours = false` — the caller stamps the field
//! after consulting `nrr-storage`.
//!
//! ## Route protocol
//!
//! Routes added via [`create_ip_forward_entry`] are marked with
//! `MIB_IPPROTO_NETMGMT` (numeric value `3`, also known as
//! `RouteProtocolNetMgmt`). This is the standard Windows convention
//! for routes added by user-mode network management code. It is
//! **not** a reliable cross-process identifier — multiple apps may
//! use the same protocol value — which is why `is_ours` is
//! storage-anchored, not protocol-anchored.

#![allow(unsafe_code)]

use std::mem::MaybeUninit;
use std::net::Ipv4Addr;

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET,
};

use crate::error::PlatformError;
use crate::types::RouteEntry;

const GET_OP: &str = "GetIpForwardTable2";
const CREATE_OP: &str = "CreateIpForwardEntry2";
const DELETE_OP: &str = "DeleteIpForwardEntry2";
const LUID_OP: &str = "ConvertInterfaceIndexToLuid";

/// Resolve a Windows `IfIndex` to its interface LUID (`NET_LUID.Value`).
///
/// The kill-switch pins a `FWPM_CONDITION_IP_LOCAL_INTERFACE` egress
/// condition, whose value is the 64-bit interface LUID — not the
/// `IfIndex`. `ConvertInterfaceIndexToLuid` is the documented mapping.
/// Returns `Err` on any non-`NO_ERROR` status (e.g. the index no longer
/// names a live interface); callers treat a failed resolution as
/// "no usable secondary LUID" and skip the kill-switch (fail-open).
pub fn interface_luid_for_index(ifindex: u32) -> Result<u64, PlatformError> {
    // Zero-initialised union; `ConvertInterfaceIndexToLuid` overwrites it.
    let mut luid = NET_LUID_LH { Value: 0 };
    // SAFETY: `ifindex` is a plain in-value; `&mut luid` is a valid
    // out-pointer living on this stack frame for the synchronous call.
    let status = unsafe { ConvertInterfaceIndexToLuid(ifindex, &mut luid) };
    if status != NO_ERROR {
        return Err(PlatformError::Win32 {
            operation: LUID_OP,
            code: status.0,
            message: format!(
                "ConvertInterfaceIndexToLuid({ifindex}) → 0x{:08X}",
                status.0
            ),
        });
    }
    // SAFETY: `NET_LUID_LH` is a union of a `u64 Value` and a bitfield
    // view of the same 64 bits; `Value` is always a valid read.
    Ok(unsafe { luid.Value })
}

/// `MIB_IPPROTO_NETMGMT` — standard "added by network management code"
/// protocol value. Defined in `iprtrmib.h` as `3`. The `windows-rs`
/// crate exposes it via [`windows::Win32::NetworkManagement::Ndis::
/// MIB_IPPROTO_NETMGMT`] but that constant uses a newtype wrapper; we
/// store the raw `i32` value used by `MIB_IPFORWARD_ROW2.Protocol`.
const PROTO_NET_MGMT_RAW: i32 = 3;

/// Enumerate all IPv4 forwarding-table entries.
///
/// Returns each route with `is_ours = false`. The caller is expected
/// to consult `nrr-storage` to mark its own routes.
pub fn enumerate_routes() -> Result<Vec<RouteEntry>, PlatformError> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

    // SAFETY: `GetIpForwardTable2` writes a freshly-allocated
    // `MIB_IPFORWARD_TABLE2*` into `table_ptr`. `AF_INET` (u16) is a
    // valid `ADDRESS_FAMILY` value. On error the pointer remains null
    // and we don't free it.
    let code = unsafe { GetIpForwardTable2(AF_INET, &mut table_ptr).0 };
    if code != NO_ERROR.0 {
        return Err(PlatformError::Win32 {
            operation: GET_OP,
            code,
            message: format!("Win32 error {code}"),
        });
    }
    if table_ptr.is_null() {
        // Defensive: success path with null table is undocumented but
        // produces no entries.
        return Ok(Vec::new());
    }

    // SAFETY: `table_ptr` was filled by Win32 and is non-null. We read
    // through it to walk the entries, then hand the pointer to
    // `FreeMibTable` (also Win32-owned) to release the allocation.
    let result = unsafe { read_table(table_ptr) };

    // SAFETY: `table_ptr` was allocated by Win32 via the matching
    // `GetIpForwardTable2`; this is the only correct way to release it.
    unsafe { FreeMibTable(table_ptr.cast()) };

    Ok(result)
}

/// Read every `MIB_IPFORWARD_ROW2` from a Win32-allocated table.
///
/// # Safety
///
/// `table` must be a valid, non-null pointer returned by
/// `GetIpForwardTable2` and not yet freed.
unsafe fn read_table(table: *const MIB_IPFORWARD_TABLE2) -> Vec<RouteEntry> {
    // SAFETY: `table` is a valid Win32 allocation per caller invariant.
    let header = unsafe { &*table };
    let count = header.NumEntries as usize;
    if count == 0 {
        return Vec::new();
    }
    // The `Table` field is declared as `[MIB_IPFORWARD_ROW2; 1]` (a
    // C VLA stand-in). The real allocation has `NumEntries` rows in
    // contiguous memory starting at `&header.Table[0]`.
    let first = header.Table.as_ptr();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: Win32 guarantees `count` consecutive valid rows after
        // `first`. Index arithmetic stays within the Win32 allocation.
        let row_ptr = unsafe { first.add(i) };
        // SAFETY: same — each row is a valid `MIB_IPFORWARD_ROW2`.
        let row = unsafe { &*row_ptr };
        if let Some(entry) = decode_row(row) {
            out.push(entry);
        }
    }
    out
}

/// Decode one `MIB_IPFORWARD_ROW2`. Returns `None` for IPv6 entries
/// (we only carry IPv4 in `RouteEntry`).
fn decode_row(row: &MIB_IPFORWARD_ROW2) -> Option<RouteEntry> {
    let dest = read_ipv4_from_inet(&row.DestinationPrefix.Prefix)?;
    let next_hop = read_ipv4_from_inet(&row.NextHop)?;
    Some(RouteEntry {
        destination: dest,
        prefix_length: row.DestinationPrefix.PrefixLength,
        next_hop,
        interface_index: row.InterfaceIndex,
        metric: row.Metric,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    })
}

/// Read the IPv4 address out of a `SOCKADDR_INET` union, returning
/// `None` if the entry is not IPv4 (IPv6 routes are out of scope —
/// see `core/platform/windows/src/types.rs` module doc).
fn read_ipv4_from_inet(addr: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: `si_family` is the discriminator arm of the union and
    // can always be read regardless of the variant currently set —
    // both `SOCKADDR_IN` and `SOCKADDR_IN6` start with the
    // `sin_family` / `sin6_family` field at the same offset.
    let family = unsafe { addr.si_family };
    if family != AF_INET {
        return None;
    }
    // SAFETY: `family == AF_INET` selects the `Ipv4: SOCKADDR_IN`
    // arm; reading `Ipv4` is sound when the family matches.
    let sa_in: SOCKADDR_IN = unsafe { addr.Ipv4 };
    // SAFETY: `S_addr` is a valid arm of the IN_ADDR union; bytes are
    // network-order per the Win32 contract.
    let net_order = unsafe { sa_in.sin_addr.S_un.S_addr };
    Some(Ipv4Addr::from(u32::from_be(net_order)))
}

/// Add a route. The new entry is tagged with `MIB_IPPROTO_NETMGMT`
/// (see module doc) and `Origin = NlroManual` (numeric 0) — typical
/// for routes installed by user-mode management code.
pub fn add_route(entry: &RouteEntry) -> Result<(), PlatformError> {
    let row = build_row(entry, /* with_protocol */ true);
    // SAFETY: `row` is a `repr(C)` `MIB_IPFORWARD_ROW2` populated with
    // valid IPv4 SOCKADDR_INET fields and a non-zero `InterfaceIndex`.
    // Win32 reads it but never retains the pointer past the call.
    let code = unsafe { CreateIpForwardEntry2(&row).0 };
    if code == NO_ERROR.0 {
        return Ok(());
    }
    Err(PlatformError::Win32 {
        operation: CREATE_OP,
        code,
        message: format!("Win32 error {code}"),
    })
}

/// Delete a route. Win32 matches the row by destination prefix and
/// interface — `Metric` and `NextHop` are also keyed in
/// `DeleteIpForwardEntry2`, so we fill them too.
pub fn delete_route(entry: &RouteEntry) -> Result<(), PlatformError> {
    let row = build_row(entry, /* with_protocol */ false);
    // SAFETY: same as [`add_route`].
    let code = unsafe { DeleteIpForwardEntry2(&row).0 };
    if code == NO_ERROR.0 {
        return Ok(());
    }
    Err(PlatformError::Win32 {
        operation: DELETE_OP,
        code,
        message: format!("Win32 error {code}"),
    })
}

/// Build a zeroed `MIB_IPFORWARD_ROW2` with the relevant fields set
/// from a `RouteEntry`. `with_protocol = true` stamps the row with
/// `MIB_IPPROTO_NETMGMT` for [`add_route`]; delete leaves
/// `Protocol = 0` because Win32 keys the lookup on
/// `(DestinationPrefix, InterfaceIndex, NextHop)` only.
fn build_row(entry: &RouteEntry, with_protocol: bool) -> MIB_IPFORWARD_ROW2 {
    // SAFETY: `MIB_IPFORWARD_ROW2` is `repr(C)`; the all-zero pattern is a
    // valid bit pattern to construct the struct before we initialise it.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { MaybeUninit::zeroed().assume_init() };

    // On the ADD path, stamp the documented default field values BEFORE
    // overriding the ones we care about. This is MANDATORY, not cosmetic: a
    // zeroed row leaves `ValidLifetime` and `PreferredLifetime` at 0, which
    // Windows treats as a zero-lifetime (deprecated) route. Such a route shows
    // as `Alive` in `Get-NetRoute` but is DEPRIORITISED in route selection — it
    // loses even to a SHORTER-prefix route on another interface. That was the
    // root cause of the mode-A `/2` counter-overlay losing to a VPN's
    // `0.0.0.0/1` + `128.0.0.0/1` redirect (so all non-rule traffic stayed on
    // the tunnel). `InitializeIpForwardEntry` sets infinite lifetimes and the
    // other defaults `route.exe` relies on — a manual `route add` of the same
    // `/2` wins, ours did not, purely because we skipped this call. The delete
    // path keys only on (DestinationPrefix, InterfaceIndex, NextHop), so it
    // needs no defaults and stays zeroed (preserving its no-protocol-stamp
    // contract).
    if with_protocol {
        // SAFETY: `row` is a valid, owned `MIB_IPFORWARD_ROW2`; the call only
        // writes default values into it.
        unsafe { InitializeIpForwardEntry(&mut row) };
    }

    // Destination prefix — wrap an `Ipv4Addr` into a SOCKADDR_INET / V4 arm.
    row.DestinationPrefix.Prefix = inet_from_ipv4(entry.destination);
    row.DestinationPrefix.PrefixLength = entry.prefix_length;

    row.NextHop = inet_from_ipv4(entry.next_hop);

    // Anonymous1 union has `InterfaceLuid: NET_LUID_LH | InterfaceIndex: u32`.
    // We fill `InterfaceIndex` only — Win32 looks up the LUID by index.
    // Setting LUID to zero is the documented "not specified" sentinel.
    // SAFETY: `NET_LUID_LH` is a union of `Value: u64` and a bitfield
    // struct; the all-zero pattern is the documented "not specified"
    // sentinel that defers to `InterfaceIndex` for lookup.
    row.InterfaceLuid = NET_LUID_LH { Value: 0 };
    row.InterfaceIndex = entry.interface_index;

    row.Metric = entry.metric;

    if with_protocol {
        // `Protocol` is `NL_ROUTE_PROTOCOL` newtype (i32). NetMgmt = 3.
        row.Protocol.0 = PROTO_NET_MGMT_RAW;
    }

    row
}

/// Build a `SOCKADDR_INET` whose IPv4 arm carries the given address.
fn inet_from_ipv4(addr: Ipv4Addr) -> SOCKADDR_INET {
    let mut inet: SOCKADDR_INET =
        // SAFETY: zeroed SOCKADDR_INET is a documented "no-address"
        // sentinel; we immediately overwrite the V4 arm.
        unsafe { MaybeUninit::zeroed().assume_init() };
    inet.Ipv4 = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from(addr).to_be(),
            },
        },
        sin_zero: [0; 8],
    };
    inet
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: enumerate works on a real Windows host. The kernel
    /// always has at least one IPv4 route (loopback), so we expect
    /// non-empty output. Read-only — no admin rights required.
    #[test]
    fn enumerate_routes_returns_non_empty_on_windows() {
        let routes = enumerate_routes().expect("GetIpForwardTable2 must succeed");
        assert!(
            !routes.is_empty(),
            "kernel always carries at least one IPv4 route"
        );
        for r in &routes {
            assert!(!r.is_ours, "FFI never marks routes as ours");
        }
    }

    /// Round-trip: build a row, decode it back, expect the same fields.
    /// Catches mistakes in `inet_from_ipv4` ↔ `read_ipv4_from_inet`.
    #[test]
    fn build_row_roundtrip_matches_decode() {
        let entry = RouteEntry {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 5,
            metric: 100,
            is_ours: true, // ignored by build_row
            table: nrr_platform_api::RouteTableRef::Main,
        };
        let row = build_row(&entry, true);
        let decoded = decode_row(&row).expect("IPv4 row must decode");
        assert_eq!(decoded.destination, entry.destination);
        assert_eq!(decoded.prefix_length, entry.prefix_length);
        assert_eq!(decoded.next_hop, entry.next_hop);
        assert_eq!(decoded.interface_index, entry.interface_index);
        assert_eq!(decoded.metric, entry.metric);
        // FFI always reports is_ours = false — caller stamps via storage.
        assert!(!decoded.is_ours);
        // Protocol stamped for add path.
        assert_eq!(row.Protocol.0, PROTO_NET_MGMT_RAW);
    }

    #[test]
    fn build_row_for_delete_omits_protocol_stamp() {
        let entry = RouteEntry {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 5,
            metric: 100,
            is_ours: true,
            table: nrr_platform_api::RouteTableRef::Main,
        };
        let row = build_row(&entry, false);
        assert_eq!(
            row.Protocol.0, 0,
            "delete path leaves Protocol unstamped — Win32 keys on prefix+ifindex"
        );
    }
}

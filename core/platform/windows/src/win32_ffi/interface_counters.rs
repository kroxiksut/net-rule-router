//! Block T (traffic counter) — per-interface octet counters via `GetIfTable2`.
//!
//! Backs `WindowsInterfaceCounterSource` (`crate::interface_traffic`). Unlike
//! `GetAdaptersAddresses` (which carries no byte counters), `MIB_IF_ROW2`
//! includes the cumulative `InOctets` / `OutOctets` the kernel already tracks,
//! plus the stable `Alias` (friendly name) we key the ledger on.
//!
//! ## Memory ownership
//!
//! `GetIfTable2` allocates a `MIB_IF_TABLE2*`; the caller must release it via
//! `FreeMibTable`. We free it in the same function before returning the owned
//! `Vec<InterfaceCounters>` — callers never see the raw pointer (mirrors
//! [`super::route_table::enumerate_routes`]).
//!
//! ## Identity anchor
//!
//! `stable_name` is `MIB_IF_ROW2.Alias` — the friendly interface name, which is
//! stable across a VPN reconnect (unlike the GUID/LUID/ifindex). It falls back
//! to `Description` only if the alias is empty.

#![allow(unsafe_code)]

use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

use nrr_platform_api::adapters::{
    description_matches_virtual_software, text_indicates_vpn_tunnel, InterfaceType,
};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::interface_traffic::InterfaceCounters;

use super::wide::pwstr_lossy;

const GET_OP: &str = "GetIfTable2";

/// `IF_OPER_STATUS` value for an operationally-up interface (`IfOperStatusUp`).
const IF_OPER_STATUS_UP: i32 = 1;

/// Enumerate every interface's cumulative octet counters.
pub fn read_interface_counters() -> Result<Vec<InterfaceCounters>, PlatformError> {
    let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

    // SAFETY: `GetIfTable2` writes a freshly-allocated `MIB_IF_TABLE2*` into
    // `table_ptr`. On error the pointer remains null and we don't free it.
    let code = unsafe { GetIfTable2(&mut table_ptr).0 };
    if code != NO_ERROR.0 {
        return Err(PlatformError::Win32 {
            operation: GET_OP,
            code,
            message: format!("Win32 error {code}"),
        });
    }
    if table_ptr.is_null() {
        return Ok(Vec::new());
    }

    // SAFETY: `table_ptr` was filled by Win32 and is non-null; `read_table`
    // only reads within the `NumEntries` rows Win32 allocated.
    let result = unsafe { read_table(table_ptr) };

    // SAFETY: `table_ptr` was allocated by the matching `GetIfTable2`; this is
    // the only correct way to release it.
    unsafe { FreeMibTable(table_ptr.cast()) };

    Ok(result)
}

/// Read every `MIB_IF_ROW2` from a Win32-allocated table.
///
/// # Safety
///
/// `table` must be a valid, non-null pointer returned by `GetIfTable2` and not
/// yet freed.
unsafe fn read_table(table: *const MIB_IF_TABLE2) -> Vec<InterfaceCounters> {
    // SAFETY: `table` is a valid Win32 allocation per caller invariant.
    let header = unsafe { &*table };
    let count = header.NumEntries as usize;
    if count == 0 {
        return Vec::new();
    }
    // `Table` is declared `[MIB_IF_ROW2; 1]` (a C VLA stand-in); the real
    // allocation has `NumEntries` contiguous rows starting at `&Table[0]`.
    let first = header.Table.as_ptr();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: Win32 guarantees `count` consecutive valid rows after `first`.
        let row = unsafe { &*first.add(i) };
        out.push(decode_row(row));
    }
    out
}

/// Decode one `MIB_IF_ROW2` into a neutral [`InterfaceCounters`].
fn decode_row(row: &MIB_IF_ROW2) -> InterfaceCounters {
    // SAFETY: `Alias` / `Description` are fixed `[u16; 257]` arrays that Win32
    // null-terminates; `pwstr_lossy` scans to the terminator (bounded).
    let alias = unsafe { pwstr_lossy(row.Alias.as_ptr()) };
    let description = unsafe { pwstr_lossy(row.Description.as_ptr()) };

    let stable_name = if alias.is_empty() {
        description.clone()
    } else {
        alias
    };
    let interface_type = InterfaceType::from_raw(row.Type);
    // Block T Feature 1 — the raw MIB type alone under-detects a real VPN
    // adapter (see `text_indicates_vpn_tunnel`'s doc comment), so OR it with
    // the same name/description keyword heuristic the "Interfaces & routes"
    // VPN-likelihood assessment uses.
    let is_tunnel = matches!(interface_type, InterfaceType::Tunnel)
        || text_indicates_vpn_tunnel(&format!("{stable_name} {description}"));

    InterfaceCounters {
        display_name: stable_name.clone(),
        stable_name,
        interface_type,
        is_virtual: description_matches_virtual_software(&description),
        is_tunnel,
        is_up: row.OperStatus.0 == IF_OPER_STATUS_UP,
        in_octets: row.InOctets,
        out_octets: row.OutOctets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: enumerate works on a real Windows host. The kernel always
    /// has at least the loopback interface, so we expect non-empty output.
    /// Read-only — no admin rights required.
    #[test]
    fn read_interface_counters_returns_non_empty_on_windows() {
        let counters = read_interface_counters().expect("GetIfTable2 must succeed");
        assert!(
            !counters.is_empty(),
            "kernel always carries at least the loopback interface"
        );
        // Every row must carry a non-empty identity anchor.
        for c in &counters {
            assert!(
                !c.stable_name.is_empty(),
                "each interface must have an alias or description"
            );
        }
    }
}

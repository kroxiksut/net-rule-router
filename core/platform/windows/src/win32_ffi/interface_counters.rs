//! Traffic-counter core — per-interface octet counters via `GetIfTable2` —
//! and the adapter-kind facts read from the same rows.
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
use nrr_platform_api::interface_rows::AdapterKindFacts;
use nrr_platform_api::interface_traffic::InterfaceCounters;

use crate::adapter_kind::{kind_facts, WindowsIfFacts};

use super::wide::pwstr_lossy;

const GET_OP: &str = "GetIfTable2";

/// `IF_OPER_STATUS` value for an operationally-up interface (`IfOperStatusUp`).
const IF_OPER_STATUS_UP: i32 = 1;

/// Enumerate every interface's cumulative octet counters.
pub fn read_interface_counters() -> Result<Vec<InterfaceCounters>, PlatformError> {
    walk_if_table(decode_row)
}

/// What the OS says each interface is, keyed by lowercase `{GUID}` — the
/// spelling `GetAdaptersAddresses` reports as `AdapterName`.
pub fn read_interface_kind_facts(
) -> Result<std::collections::HashMap<String, AdapterKindFacts>, PlatformError> {
    walk_if_table(|row| {
        // SAFETY: `Description` is a fixed `[u16; 257]` Win32 null-terminates.
        let description = unsafe { pwstr_lossy(row.Description.as_ptr()) };
        let facts = kind_facts(&WindowsIfFacts {
            if_type: row.Type,
            physical_medium: row.PhysicalMediumType.0,
            hardware_interface: row.InterfaceAndOperStatusFlags._bitfield & HARDWARE_INTERFACE != 0,
            description: &description,
        });
        (guid_key(&row.InterfaceGuid), facts)
    })
    .map(|rows| rows.into_iter().collect())
}

/// `HardwareInterface`, bit 0 of `InterfaceAndOperStatusFlags`.
const HARDWARE_INTERFACE: u8 = 0x1;

fn guid_key(guid: &windows::core::GUID) -> String {
    let d = guid.data4;
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid.data1, guid.data2, guid.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Decode every row of `GetIfTable2`, freeing the table before returning.
fn walk_if_table<T>(decode: impl Fn(&MIB_IF_ROW2) -> T) -> Result<Vec<T>, PlatformError> {
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
    let result = unsafe { read_table(table_ptr, decode) };

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
unsafe fn read_table<T>(table: *const MIB_IF_TABLE2, decode: impl Fn(&MIB_IF_ROW2) -> T) -> Vec<T> {
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
        out.push(decode(row));
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
    // The raw MIB type alone under-detects a real VPN adapter (see
    // `text_indicates_vpn_tunnel`'s doc comment), so OR it with the same
    // name/description keyword heuristic the "Interfaces & routes"
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

    #[test]
    fn guid_key_matches_the_adapter_name_spelling() {
        let guid = windows::core::GUID::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef);
        assert_eq!(guid_key(&guid), "{01234567-89ab-cdef-0123-456789abcdef}");
    }

    #[test]
    fn kind_facts_cover_the_loopback_interface() {
        let facts = read_interface_kind_facts().expect("GetIfTable2 must succeed");
        assert!(
            facts
                .values()
                .any(|f| f.medium == nrr_platform_api::interface_rows::LinkMedium::Loopback),
            "the kernel always carries a loopback interface"
        );
    }

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

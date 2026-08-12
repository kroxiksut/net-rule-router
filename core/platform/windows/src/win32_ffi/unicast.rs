//! `GetUnicastIpAddressTable` — local unicast address → interface index, for
//! BOTH address families.
//!
//! The connection-egress trace maps a connection's local (source) address to
//! the interface it left through. Adapter enumeration (`adapters.rs`) is
//! IPv4-only, so this dedicated table is what lets the trace label IPv6
//! egress too (provider vs secondary adapter) instead of reporting it as unknown.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

use crate::error::PlatformError;

/// Query all local unicast addresses (IPv4 + IPv6) paired with the interface
/// index that owns each, via `GetUnicastIpAddressTable(AF_UNSPEC)`.
pub fn query_unicast_ip_addresses() -> Result<Vec<(IpAddr, u32)>, PlatformError> {
    let mut table_ptr: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: the API allocates `*table_ptr` on success; we free it with
    // `FreeMibTable` below. `&mut table_ptr` is a valid out-pointer.
    let err = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table_ptr) };
    if err != WIN32_ERROR(0) {
        return Err(PlatformError::Win32 {
            operation: "GetUnicastIpAddressTable",
            code: err.0,
            message: format!("Win32 error 0x{:08X}", err.0),
        });
    }
    if table_ptr.is_null() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    // SAFETY: on success `table_ptr` is a valid API-allocated table; its
    // `NumEntries` rows follow the header contiguously in `Table`. Each row's
    // `Address` union arm is selected by `si_family` (the documented contract).
    // The table is freed before returning.
    unsafe {
        let table = &*table_ptr;
        let count = table.NumEntries as usize;
        let rows = std::slice::from_raw_parts(table.Table.as_ptr(), count);
        for row in rows {
            let family = row.Address.si_family;
            if family == AF_INET {
                // `S_addr` is the IN_ADDR union arm; bytes are network-order
                // (big-endian), matching the adapter-enumeration decode.
                let net_order = row.Address.Ipv4.sin_addr.S_un.S_addr;
                out.push((
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(net_order))),
                    row.InterfaceIndex,
                ));
            } else if family == AF_INET6 {
                // `Byte` is the 16-byte address in order; `Ipv6Addr::from`
                // takes the octets as-is.
                let bytes = row.Address.Ipv6.sin6_addr.u.Byte;
                out.push((IpAddr::V6(Ipv6Addr::from(bytes)), row.InterfaceIndex));
            }
        }
        FreeMibTable(table_ptr as *const c_void);
    }
    Ok(out)
}

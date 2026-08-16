//! IPv4 addresses per interface, via `getifaddrs(3)`.
//!
//! Split from [`crate::adapters`] because it is the one part of adapter
//! enumeration that cannot be read as text: sysfs exposes what a device IS but
//! not the addresses assigned to it, and `/proc/net/fib_trie` is a routing
//! structure, not an address list. `getifaddrs` is the portable answer the
//! kernel intends for this question.
//!
//! Same discipline as [`crate::peer_cred`]: the FFI call is the only `unsafe`
//! here, it is confined to one function, and everything above it is ordinary
//! safe Rust.

#![cfg(target_os = "linux")]
// Localized: `getifaddrs`/`freeifaddrs` and the walk over the returned linked
// list are the only `unsafe` in this module. `std` exposes no interface-address
// enumeration.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::Ipv4Addr;

/// Every interface's IPv4 unicast addresses, keyed by link name.
///
/// An empty map on failure rather than an error: an adapter with no addresses
/// is an ordinary state the routing layer already handles, and failing the
/// whole enumeration because one syscall did not answer would hide every other
/// interface too.
pub(crate) fn ipv4_addresses_by_interface() -> HashMap<String, Vec<Ipv4Addr>> {
    let mut out: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` writes an owned linked list into `head` and returns
    // 0 on success. On failure it leaves nothing to free, so we return early.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: the cursor is non-null and points into the list `getifaddrs`
        // just built; it stays valid until `freeifaddrs` below.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: non-null per the check above, and NUL-terminated by contract.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: non-null per the check above. Reading `sa_family` is valid
        // for any address family; only after it matches AF_INET do we treat the
        // pointer as the larger `sockaddr_in`.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }
        // SAFETY: the family says this is a `sockaddr_in`, which is what the
        // kernel allocated for it.
        let addr = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
        let raw = u32::from_be(addr.sin_addr.s_addr);
        out.entry(name).or_default().push(Ipv4Addr::from(raw));
    }
    // SAFETY: `head` came from a successful `getifaddrs` and is freed exactly
    // once; the cursor above never freed anything.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live host: the loopback interface exists and carries 127.0.0.1. This is
    /// the one claim about the syscall that holds on every Linux machine,
    /// including a container with no real NIC.
    #[test]
    fn the_loopback_interface_reports_its_address() {
        let map = ipv4_addresses_by_interface();
        let loopback = map
            .get("lo")
            .expect("every Linux host has a loopback interface");
        assert!(
            loopback.contains(&Ipv4Addr::LOCALHOST),
            "expected 127.0.0.1 among {loopback:?}"
        );
    }
}

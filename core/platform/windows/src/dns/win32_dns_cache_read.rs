//! Windows OS resolver-cache **read** (`DnsGetCacheDataTable` +
//! cache-only `DnsQuery_W`).
//!
//! ## Why
//!
//! The complement to the flush port (`win32_dns_cache`). Suffix/zone
//! enforcement learns hostnames only from live DNS traffic (ETW event 3008). A
//! name resolved before the service started — or served straight from the OS
//! resolver cache so no wire query fires — is invisible to the observer, so its
//! zone permit is never emitted (a name cached before the service started).
//! Flushing forces a re-query; reading is the passive alternative — snapshot
//! what the OS already resolved and seed the FQDN cache with the rule-matching
//! entries, no flush and no wire round-trip.
//!
//! ## FFI — two calls
//!
//! 1. [`DnsGetCacheDataTable`] (`dnsapi.dll`, undocumented, long-stable, used by
//!    `Get-DnsClientCache`) writes the head of a singly-linked list of
//!    [`DnsCacheEntry`] — each node carries the wide hostname and the record
//!    `wType`. It does NOT carry the record data, so we read only names+types
//!    here and skip types other than `A` and `AAAA`.
//! 2. For every such name we issue a **cache-only** [`DnsQuery_W`] per type
//!    with `DNS_QUERY_NO_WIRE_QUERY` (`0x10`): it returns the cached records
//!    without touching the network, so this whole port never blocks on DNS.
//!
//! ## Memory ownership
//!
//! `DnsGetCacheDataTable` allocates each node and its `pszName` on the DNS API
//! heap; we free every node's name and the node itself with `DnsFree(_,
//! DnsFreeFlat)` (the convention the Wine/ReactOS `dnsapi` implementations and
//! the community C# wrappers use for this table). The per-name `DnsQuery_W`
//! chain is freed with `DnsFree(_, DnsFreeRecordList)`, exactly as the proven
//! resolver does. The walk is length-bounded so a corrupted `pNext` cannot spin
//! forever. NOTE: the node free-contract is the one piece to confirm on the
//! next HW run — a mismatched free here would be a heap fault, so the enclosing
//! wiring must keep this port opt-in until that pass is green.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_platform_api::dns::{
    canonicalize_hostname, DnsCacheReadError, DnsCacheReadPort, OsCachedResolution,
};
use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_OPTIONS, DNS_RECORDA, DNS_TYPE,
    DNS_TYPE_A, DNS_TYPE_AAAA,
};

/// `DNS_QUERY_NO_WIRE_QUERY` — answer only from the local resolver cache; never
/// emit a network query. Not surfaced as a named constant by windows-rs 0.58,
/// so we spell the documented bit directly.
const DNS_QUERY_NO_WIRE_QUERY: u32 = 0x0000_0010;

/// `A` and `AAAA` record types as they appear in a [`DnsCacheEntry::w_type`]
/// field.
const DNS_TYPE_A_U16: u16 = 1;
const DNS_TYPE_AAAA_U16: u16 = 28;

/// Defensive bound on the cache-list walk. The Windows resolver cache holds at
/// most a few thousand entries in practice; this is far above that and only
/// guards against a corrupted `pNext`.
const MAX_CACHE_ENTRIES: usize = 8192;

/// The free walk must release what the OS allocated whatever the read cap is;
/// this bound only stops a cyclic list.
const FREE_WALK_SAFETY_BOUND: usize = 1 << 24;

/// Undocumented `dnsapi.dll` cache-entry node. Layout is stable across
/// Windows versions (matched by `Get-DnsClientCache`, Wine, ReactOS): a forward
/// link, the wide hostname, the record type, its data length, and flags.
#[repr(C)]
struct DnsCacheEntry {
    /// Next node, or null at the tail.
    p_next: *mut DnsCacheEntry,
    /// NUL-terminated wide hostname owned by the DNS API heap.
    psz_name: *const u16,
    /// DNS record type (`1` = `A`).
    w_type: u16,
    /// Record data length (unused here — we re-query for the data).
    w_data_length: u16,
    /// Entry flags (unused here).
    dw_flags: u32,
}

#[link(name = "dnsapi")]
extern "system" {
    /// Undocumented `dnsapi.dll` export used by `Get-DnsClientCache`. Writes the
    /// head of the cache linked list into `*table` and returns non-zero on
    /// success. Stable since Windows 2000.
    fn DnsGetCacheDataTable(table: *mut *mut DnsCacheEntry) -> i32;
}

/// Production [`DnsCacheReadPort`] backed by `dnsapi.dll`.
///
/// Stateless; safe to share via `Arc<dyn DnsCacheReadPort>`.
#[derive(Debug, Default)]
pub struct WindowsDnsCacheRead;

impl WindowsDnsCacheRead {
    pub const fn new() -> Self {
        Self
    }
}

impl DnsCacheReadPort for WindowsDnsCacheRead {
    fn read_resolver_cache(&self) -> Result<Vec<OsCachedResolution>, DnsCacheReadError> {
        self.read_resolver_cache_matching(&|_| true)
    }

    fn read_resolver_cache_matching(
        &self,
        keep: &dyn Fn(&str) -> bool,
    ) -> Result<Vec<OsCachedResolution>, DnsCacheReadError> {
        let mut head: *mut DnsCacheEntry = std::ptr::null_mut();
        // SAFETY: `head` is a valid out-slot; the export writes a freshly
        // allocated list head (or leaves it null) and returns non-zero on
        // success. No caller-owned memory is passed in.
        let ok = unsafe { DnsGetCacheDataTable(&mut head) };
        if ok == 0 {
            return Err(DnsCacheReadError::Failed { code: 0 });
        }
        if head.is_null() {
            // Success with an empty cache.
            return Ok(Vec::new());
        }

        // First pass: collect the canonical names and which of the two
        // address types each has cached. We read every node before freeing
        // anything so the free pass is a simple walk.
        let mut names: BTreeMap<String, CachedTypes> = BTreeMap::new();
        let mut current = head;
        let mut visited = 0usize;
        while !current.is_null() && visited < MAX_CACHE_ENTRIES {
            // SAFETY: `current` is a valid node from the DNS API; we read
            // POD fields only and never dereference `psz_name` past its
            // NUL terminator (see `wide_to_string`).
            let node = unsafe { &*current };
            let is_a = node.w_type == DNS_TYPE_A_U16;
            if (is_a || node.w_type == DNS_TYPE_AAAA_U16) && !node.psz_name.is_null() {
                // SAFETY: `psz_name` is a NUL-terminated wide string owned by
                // the DNS API heap, valid until we free the list below.
                if let Some(name) = unsafe { wide_to_string(node.psz_name) } {
                    let canonical = canonicalize_hostname(&name);
                    if !canonical.is_empty() && keep(&canonical) {
                        let types = names.entry(canonical).or_default();
                        if is_a {
                            types.a = true;
                        } else {
                            types.aaaa = true;
                        }
                    }
                }
            }
            current = node.p_next;
            visited += 1;
        }

        // Free the cache table (names + nodes). See the module "Memory
        // ownership" note: DnsFreeFlat per name and per node.
        // SAFETY: every node came from `DnsGetCacheDataTable`; we free each
        // exactly once, tail-to-forward via the saved `p_next`, and never
        // touch a node after freeing it.
        unsafe { free_cache_table(head) };

        // Second pass: cache-only lookups. No network I/O.
        let mut out = Vec::with_capacity(names.len());
        for (name, types) in names {
            let mut addresses: Vec<IpAddr> = Vec::new();
            if types.a {
                addresses.extend(cache_only_lookup(&name, DNS_TYPE_A));
            }
            if types.aaaa {
                addresses.extend(cache_only_lookup(&name, DNS_TYPE_AAAA));
            }
            if !addresses.is_empty() {
                out.push(OsCachedResolution {
                    canonical_hostname: name,
                    addresses,
                });
            }
        }
        Ok(out)
    }
}

/// Which address types the OS cache lists for one name.
#[derive(Default)]
struct CachedTypes {
    a: bool,
    aaaa: bool,
}

/// Cache-only `want` (`A` or `AAAA`) lookup for `canonical` (already
/// lower-cased, no trailing dot). Returns the cached addresses, or empty on
/// any error / cache miss.
fn cache_only_lookup(canonical: &str, want: DNS_TYPE) -> Vec<IpAddr> {
    if canonical.is_empty() || canonical.contains('\0') {
        return Vec::new();
    }
    let wide: Vec<u16> = canonical.encode_utf16().chain([0]).collect();
    let mut records: *mut DNS_RECORDA = std::ptr::null_mut();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string borrowed for the
    // call; `records` is the output chain slot. `DNS_QUERY_NO_WIRE_QUERY`
    // restricts the query to the local cache, so no network round-trip occurs.
    let win_err = unsafe {
        DnsQuery_W(
            PCWSTR(wide.as_ptr()),
            want,
            DNS_QUERY_OPTIONS(DNS_QUERY_NO_WIRE_QUERY),
            None,
            &mut records,
            None,
        )
    };
    let mut addresses = Vec::new();
    if win_err.0 == 0 && !records.is_null() {
        // SAFETY: non-null Win32-allocated `DNS_RECORDA` chain; each union
        // arm is read only after its `wType` check.
        addresses = unsafe { collect_addresses(records, want) };
    }
    // SAFETY: release any allocated chain (no-op on null), matching the proven
    // resolver's ownership handling.
    if !records.is_null() {
        let opaque = records as *const c_void;
        unsafe { DnsFree(Some(opaque), DnsFreeRecordList) };
    }
    addresses
}

/// Walk a `DNS_RECORDA` chain and collect every address of type `want`; an
/// IPv4-mapped `AAAA` is its IPv4 address.
///
/// # Safety
///
/// `head` must be a non-null Win32-allocated DNS record list, not yet freed.
unsafe fn collect_addresses(head: *mut DNS_RECORDA, want: DNS_TYPE) -> Vec<IpAddr> {
    let mut addresses = Vec::new();
    let mut current = head;
    // A cached answer is tiny; bound the walk against a corrupt chain.
    const MAX_CHAIN_LEN: usize = 256;
    let mut visited = 0usize;
    while !current.is_null() && visited < MAX_CHAIN_LEN {
        // SAFETY: `current` is a valid `DNS_RECORDA`; POD field reads.
        let record = unsafe { &*current };
        let wtype = DNS_TYPE(record.wType);
        if wtype == want && wtype == DNS_TYPE_A {
            // SAFETY: the `A: DNS_A_DATA` union arm is selected by the type
            // check; `IpAddress` is a network-order u32 per the Win32 contract.
            let net_order = unsafe { record.Data.A.IpAddress };
            addresses.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(net_order))));
        } else if wtype == want && wtype == DNS_TYPE_AAAA {
            // SAFETY: the `AAAA: DNS_AAAA_DATA` union arm is selected by the
            // type check; `IP6Byte` is the address in network order.
            let octets = unsafe { record.Data.AAAA.Ip6Address.IP6Byte };
            addresses.push(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical());
        }
        current = record.pNext;
        visited += 1;
    }
    addresses
}

/// Read a NUL-terminated wide string into an owned `String`.
///
/// # Safety
///
/// `ptr` must be non-null and point at a NUL-terminated UTF-16 buffer that
/// stays valid for the duration of the read.
unsafe fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    // Bound the scan; hostnames are ≤ 255 chars but allow generous slack.
    const MAX_NAME_LEN: usize = 1024;
    // SAFETY: caller guarantees a NUL-terminated buffer; we stop at the first
    // NUL or the defensive bound, never reading past the terminator.
    while len < MAX_NAME_LEN && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr..ptr+len` is within the validated NUL-terminated buffer.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf16_lossy(slice))
}

/// Free the `DnsGetCacheDataTable` linked list: each node's name and the node
/// itself, via `DnsFree(_, DnsFreeFlat)`.
///
/// # Safety
///
/// `head` must be the non-null list returned by `DnsGetCacheDataTable`, not yet
/// freed.
unsafe fn free_cache_table(head: *mut DnsCacheEntry) {
    // SAFETY: forwarded contract; `DnsFreeFlat` is the release for both the
    // node and its name allocation.
    unsafe {
        free_list(head, FREE_WALK_SAFETY_BOUND, &mut |p| {
            DnsFree(Some(p), DnsFreeFlat)
        })
    };
}

/// Walk the whole list and hand every name and node allocation to `free`, once
/// each. `p_next` is captured before the node is released.
///
/// # Safety
///
/// `head` must be null or a valid list whose nodes and names `free` may release.
unsafe fn free_list(head: *mut DnsCacheEntry, bound: usize, free: &mut dyn FnMut(*const c_void)) {
    let mut current = head;
    let mut visited = 0usize;
    while !current.is_null() && visited < bound {
        // SAFETY: `current` is a live node; read its fields before releasing.
        let node = unsafe { &*current };
        let next = node.p_next;
        let name = node.psz_name;
        if !name.is_null() {
            free(name as *const c_void);
        }
        free(current as *const c_void);
        current = next;
        visited += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The port must never panic or block; on any box it returns a snapshot
    /// (possibly empty) or a `Failed`/`Unsupported` error. This also exercises
    /// the real `DnsGetCacheDataTable` + free path on Windows CI.
    #[test]
    fn read_resolver_cache_does_not_panic_on_windows() {
        let port = WindowsDnsCacheRead::new();
        match port.read_resolver_cache() {
            Ok(entries) => {
                // Every returned entry must be canonical and carry ≥1 address.
                for e in entries {
                    assert_eq!(
                        e.canonical_hostname,
                        canonicalize_hostname(&e.canonical_hostname)
                    );
                    assert!(!e.addresses.is_empty());
                }
            }
            Err(DnsCacheReadError::Failed { .. }) | Err(DnsCacheReadError::Unsupported { .. }) => {}
        }
    }

    #[test]
    fn free_walk_releases_every_node_past_the_read_cap() {
        static NAME: [u16; 2] = [b'a' as u16, 0];
        let total = MAX_CACHE_ENTRIES + 500;
        let mut nodes: Vec<DnsCacheEntry> = (0..total)
            .map(|_| DnsCacheEntry {
                p_next: std::ptr::null_mut(),
                psz_name: NAME.as_ptr(),
                w_type: DNS_TYPE_A_U16,
                w_data_length: 0,
                dw_flags: 0,
            })
            .collect();
        let base = nodes.as_mut_ptr();
        for i in 0..total - 1 {
            // SAFETY: both indexes are within `nodes`.
            unsafe { (*base.add(i)).p_next = base.add(i + 1) };
        }
        let mut freed = 0usize;
        // SAFETY: the callback only counts; nothing is released.
        unsafe { free_list(base, FREE_WALK_SAFETY_BOUND, &mut |_| freed += 1) };
        assert_eq!(freed, total * 2, "every node and its name must be freed");
    }

    #[test]
    fn cache_only_lookup_rejects_empty_and_nul() {
        for want in [DNS_TYPE_A, DNS_TYPE_AAAA] {
            assert!(cache_only_lookup("", want).is_empty());
            assert!(cache_only_lookup("bad\0name", want).is_empty());
        }
    }
}

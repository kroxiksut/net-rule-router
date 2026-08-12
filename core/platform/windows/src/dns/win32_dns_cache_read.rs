//! Windows OS resolver-cache **read** (`DnsGetCacheDataTable` +
//! cache-only `DnsQuery_W`).
//!
//! ## Why
//!
//! The complement to the flush port (`win32_dns_cache`). Suffix/zone
//! enforcement learns hostnames only from live DNS traffic (ETW event 3008). A
//! name resolved before the service started — or served straight from the OS
//! resolver cache so no wire query fires — is invisible to the observer, so its
//! zone permit is never emitted (e.g. `avito.ru`/`ya.ru` cached before start).
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
//!    here and skip non-`A` types.
//! 2. For every `A`-type name we issue a **cache-only** [`DnsQuery_W`] with
//!    `DNS_QUERY_NO_WIRE_QUERY` (`0x10`): it returns the cached `A` records
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

use std::ffi::c_void;
use std::net::Ipv4Addr;

use nrr_platform_api::dns::{
    canonicalize_hostname, DnsCacheReadError, DnsCacheReadPort, OsCachedResolution,
};
use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_OPTIONS, DNS_RECORDA, DNS_TYPE,
    DNS_TYPE_A,
};

/// `DNS_QUERY_NO_WIRE_QUERY` — answer only from the local resolver cache; never
/// emit a network query. Not surfaced as a named constant by windows-rs 0.58,
/// so we spell the documented bit directly.
const DNS_QUERY_NO_WIRE_QUERY: u32 = 0x0000_0010;

/// `A` record type as it appears in a [`DnsCacheEntry::w_type`] field.
const DNS_TYPE_A_U16: u16 = 1;

/// Defensive bound on the cache-list walk. The Windows resolver cache holds at
/// most a few thousand entries in practice; this is far above that and only
/// guards against a corrupted `pNext`.
const MAX_CACHE_ENTRIES: usize = 8192;

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

        // First pass: collect the canonical `A`-record names. We read every
        // node before freeing anything so the free pass is a simple walk.
        let mut names: Vec<String> = Vec::new();
        let mut current = head;
        let mut visited = 0usize;
        while !current.is_null() && visited < MAX_CACHE_ENTRIES {
            // SAFETY: `current` is a valid node from the DNS API; we read
            // POD fields only and never dereference `psz_name` past its
            // NUL terminator (see `wide_to_string`).
            let node = unsafe { &*current };
            if node.w_type == DNS_TYPE_A_U16 && !node.psz_name.is_null() {
                // SAFETY: `psz_name` is a NUL-terminated wide string owned by
                // the DNS API heap, valid until we free the list below.
                if let Some(name) = unsafe { wide_to_string(node.psz_name) } {
                    let canonical = canonicalize_hostname(&name);
                    if !canonical.is_empty() {
                        names.push(canonical);
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

        // Second pass: cache-only A-record lookups. No network I/O.
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let addresses = cache_only_a_lookup(&name);
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

/// Cache-only `A` lookup for `canonical` (already lower-cased, no trailing dot).
/// Returns the cached IPv4 addresses, or empty on any error / cache miss.
fn cache_only_a_lookup(canonical: &str) -> Vec<Ipv4Addr> {
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
            DNS_TYPE_A,
            DNS_QUERY_OPTIONS(DNS_QUERY_NO_WIRE_QUERY),
            None,
            &mut records,
            None,
        )
    };
    let mut addresses = Vec::new();
    if win_err.0 == 0 && !records.is_null() {
        // SAFETY: non-null Win32-allocated `DNS_RECORDA` chain; we read the
        // union `A` arm only after checking `wType == DNS_TYPE_A`.
        addresses = unsafe { collect_a_addresses(records) };
    }
    // SAFETY: release any allocated chain (no-op on null), matching the proven
    // resolver's ownership handling.
    if !records.is_null() {
        let opaque = records as *const c_void;
        unsafe { DnsFree(Some(opaque), DnsFreeRecordList) };
    }
    addresses
}

/// Walk a `DNS_RECORDA` chain and collect every IPv4 (`A`) address.
///
/// # Safety
///
/// `head` must be a non-null Win32-allocated DNS record list, not yet freed.
unsafe fn collect_a_addresses(head: *mut DNS_RECORDA) -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    let mut current = head;
    // A cached A answer is tiny; bound the walk against a corrupt chain.
    const MAX_CHAIN_LEN: usize = 256;
    let mut visited = 0usize;
    while !current.is_null() && visited < MAX_CHAIN_LEN {
        // SAFETY: `current` is a valid `DNS_RECORDA`; POD field reads.
        let record = unsafe { &*current };
        if DNS_TYPE(record.wType) == DNS_TYPE_A {
            // SAFETY: the `A: DNS_A_DATA` union arm is selected by the type
            // check; `IpAddress` is a network-order u32 per the Win32 contract.
            let net_order = unsafe { record.Data.A.IpAddress };
            addresses.push(Ipv4Addr::from(u32::from_be(net_order)));
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
/// freed. Each node is freed exactly once; `p_next` is captured before the node
/// is released so the walk never touches freed memory.
unsafe fn free_cache_table(head: *mut DnsCacheEntry) {
    let mut current = head;
    let mut visited = 0usize;
    while !current.is_null() && visited < MAX_CACHE_ENTRIES {
        // SAFETY: `current` is a live node; capture `p_next` and `psz_name`
        // before freeing so nothing is read after release.
        let node = unsafe { &*current };
        let next = node.p_next;
        let name = node.psz_name;
        if !name.is_null() {
            // SAFETY: `name` was allocated by the DNS API for this node.
            unsafe { DnsFree(Some(name as *const c_void), DnsFreeFlat) };
        }
        // SAFETY: free the node allocation itself; not dereferenced afterward.
        unsafe { DnsFree(Some(current as *const c_void), DnsFreeFlat) };
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
    fn cache_only_lookup_rejects_empty_and_nul() {
        assert!(cache_only_a_lookup("").is_empty());
        assert!(cache_only_a_lookup("bad\0name").is_empty());
    }
}

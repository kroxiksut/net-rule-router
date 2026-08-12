//! Windows production DNS resolver
//! (`DnsQuery_W` + `DNS_RECORDW` walk + `DnsFree`).
//!
//! The W-form takes a wide UTF-16 hostname and writes a Win32-allocated
//! linked list of `DNS_RECORDW` records (typed as `DNS_RECORDA` in
//! windows-rs 0.58 — the binding doesn't currently model the W/A
//! distinction for the linked-list type; the body layout is identical
//! and we cast at use site to read the wide `pName` and the
//! `Data.A.IpAddress` union arm).
//!
//! ## Memory ownership
//!
//! Win32 owns the `DNS_RECORDA*` chain; we walk it without taking
//! ownership and call [`DnsFree`] with `DnsFreeRecordList` before
//! returning. The owned [`ResolvedRecord`] is fully populated from the
//! chain before the free call.
//!
//! ## Error mapping
//!
//! `DnsQuery_W` returns a `WIN32_ERROR` code; we project it onto
//! [`DnsResolverError`] via [`map_dns_error`]:
//!
//! | Win32 code | Variant | Notes |
//! |-----------|---------|-------|
//! | `DNS_ERROR_RCODE_NAME_ERROR` (`9003`) | [`NxDomain`] | NXDOMAIN |
//! | `DNS_ERROR_RCODE_REFUSED` (`9005`)    | [`Refused`]  | REFUSED  |
//! | `DNS_INFO_NO_RECORDS` (`9501`)        | [`NxDomain`] | Empty answer (no A records) |
//! | `DNS_REQUEST_PENDING` (`9506`)        | [`Timeout`]  | async resolution did not complete (sync mode shouldn't see this) |
//! | `ERROR_TIMEOUT` (`1460`)              | [`Timeout`]  | Server unreachable |
//! | `ERROR_INVALID_NAME` (`123`)          | [`InvalidName`] | Win32 rejected the name |
//! | other                                  | [`Network`]  | Generic resolver / transport failure |
//!
//! [`NxDomain`]: super::DnsResolverError::NxDomain
//! [`Refused`]: super::DnsResolverError::Refused
//! [`Timeout`]: super::DnsResolverError::Timeout
//! [`InvalidName`]: super::DnsResolverError::InvalidName
//! [`Network`]: super::DnsResolverError::Network
//! [`DnsFree`]: windows::Win32::NetworkManagement::Dns::DnsFree

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::Ipv4Addr;

use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::Dns::{
    DnsFree, DnsFreeRecordList, DnsQuery_W, DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE, DNS_TYPE_A,
};

use super::{canonicalize_hostname, DnsResolverError, DnsResolverPort, ResolvedRecord};

#[allow(dead_code)] // referenced by structured-logging hooks in the supervisor task and by a sanity test
const OPERATION: &str = "DnsQuery_W";

/// `DNS_ERROR_RCODE_NAME_ERROR` — authoritative NXDOMAIN.
const DNS_ERROR_RCODE_NAME_ERROR: u32 = 9003;
/// `DNS_ERROR_RCODE_REFUSED` — server refused the query.
const DNS_ERROR_RCODE_REFUSED: u32 = 9005;
/// `DNS_INFO_NO_RECORDS` — query succeeded but no records were
/// returned for the requested type. Treated as NXDOMAIN for our
/// negative-cache purposes (no A record == cannot reach).
const DNS_INFO_NO_RECORDS: u32 = 9501;
/// `DNS_REQUEST_PENDING` — should not appear in synchronous mode but
/// surface defensively as a timeout if it does.
const DNS_REQUEST_PENDING: u32 = 9506;
/// `ERROR_TIMEOUT` — server unreachable within the system timeout.
const ERROR_TIMEOUT: u32 = 1460;
/// `ERROR_INVALID_NAME` — Win32 rejected the hostname format before
/// issuing the query.
const ERROR_INVALID_NAME: u32 = 123;

/// Production resolver backed by the Win32 DNS API.
///
/// Stateless: every call opens a fresh `DnsQuery_W` and releases the
/// returned record chain before returning. Safe to share via
/// `Arc<dyn DnsResolverPort>` — no internal state, no locks.
#[derive(Debug, Default)]
pub struct WindowsDnsResolver;

impl WindowsDnsResolver {
    pub const fn new() -> Self {
        Self
    }
}

impl DnsResolverPort for WindowsDnsResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
        let canonical = canonicalize_hostname(hostname);
        if canonical.is_empty() || canonical.contains('\0') {
            return Err(DnsResolverError::InvalidName { name: canonical });
        }

        // UTF-16 NUL-terminated for PCWSTR.
        let wide: Vec<u16> = canonical.encode_utf16().chain([0]).collect();

        let mut records: *mut DNS_RECORDA = std::ptr::null_mut();

        // SAFETY: `wide` is a valid null-terminated UTF-16 string;
        // `PCWSTR` borrows the pointer for the call. `records` is the
        // output slot Win32 writes a freshly-allocated chain pointer
        // into on success. `None` for `pextra`/`preserved` selects
        // default DNS server list / no reserved field.
        let win_err = unsafe {
            DnsQuery_W(
                PCWSTR(wide.as_ptr()),
                DNS_TYPE_A,
                DNS_QUERY_STANDARD,
                None,
                &mut records,
                None,
            )
        };
        let code = win_err.0;

        let result = if code != 0 {
            Err(map_dns_error(code, &canonical))
        } else if records.is_null() {
            // Defensive: success path with null chain — treat as
            // empty answer.
            Err(DnsResolverError::NxDomain {
                hostname: canonical.clone(),
            })
        } else {
            // SAFETY: chain pointer is non-null and points at a
            // Win32-allocated `DNS_RECORDA`-typed linked list. We
            // cast to the wide-form `DNS_RECORDW` reading the
            // identical underlying layout; only `pName` differs in
            // typed form (PSTR vs PWSTR) and we don't dereference it.
            let collected = unsafe { collect_a_records(records, &canonical) };
            if collected.addresses.is_empty() {
                Err(DnsResolverError::NxDomain {
                    hostname: canonical,
                })
            } else {
                Ok(collected)
            }
        };

        // SAFETY: even on the error path we must release any
        // Win32-allocated chain. `DnsFree` is a no-op when `pdata` is
        // null, which matches our defensive branch above.
        if !records.is_null() {
            let opaque = records as *const c_void;
            unsafe { DnsFree(Some(opaque), DnsFreeRecordList) };
        }

        result
    }
}

/// Walk the `DNS_RECORDA`-typed chain and collect every IPv4 (`A`)
/// record into a [`ResolvedRecord`].
///
/// # Safety
///
/// `head` must be a non-null pointer to a Win32-allocated DNS record
/// linked list, not yet freed. The chain is walked via the in-struct
/// `pNext` pointer; we never advance past a NULL terminator.
unsafe fn collect_a_records(head: *mut DNS_RECORDA, canonical: &str) -> ResolvedRecord {
    let mut addresses: Vec<Ipv4Addr> = Vec::new();
    let mut min_ttl: Option<u32> = None;
    let mut current = head;
    // Bound the walk defensively — a corrupted chain should not put
    // us in an infinite loop. `MAX_CHAIN_LEN` is well above any
    // realistic answer (typical A response has ≤ 16 records).
    const MAX_CHAIN_LEN: usize = 256;
    let mut visited = 0usize;

    while !current.is_null() && visited < MAX_CHAIN_LEN {
        // SAFETY: `current` is a valid `DNS_RECORDA`. Reading the
        // `wType`, `dwTtl`, and union `Data.A.IpAddress` arm is sound
        // when the record actually carries an A answer; we check
        // `wType == DNS_TYPE_A` before reading the union.
        let record = unsafe { &*current };
        let wtype = DNS_TYPE(record.wType);
        if wtype == DNS_TYPE_A {
            // SAFETY: `wtype == DNS_TYPE_A` selects the `A: DNS_A_DATA`
            // arm of the `Data` union. `IpAddress` is a u32 in
            // network byte order per the Win32 contract.
            let net_order = unsafe { record.Data.A.IpAddress };
            addresses.push(Ipv4Addr::from(u32::from_be(net_order)));
            let ttl = record.dwTtl;
            min_ttl = Some(match min_ttl {
                Some(prev) => prev.min(ttl),
                None => ttl,
            });
        }
        current = record.pNext;
        visited += 1;
    }

    ResolvedRecord {
        canonical_hostname: canonical.to_string(),
        addresses,
        ttl_seconds: min_ttl,
    }
}

/// Map a Win32 DNS error code into our domain error type.
pub(super) fn map_dns_error(code: u32, hostname: &str) -> DnsResolverError {
    match code {
        DNS_ERROR_RCODE_NAME_ERROR | DNS_INFO_NO_RECORDS => DnsResolverError::NxDomain {
            hostname: hostname.to_string(),
        },
        DNS_ERROR_RCODE_REFUSED => DnsResolverError::Refused {
            hostname: hostname.to_string(),
            code,
        },
        DNS_REQUEST_PENDING | ERROR_TIMEOUT => DnsResolverError::Timeout {
            hostname: hostname.to_string(),
        },
        ERROR_INVALID_NAME => DnsResolverError::InvalidName {
            name: hostname.to_string(),
        },
        _ => DnsResolverError::Network {
            hostname: hostname.to_string(),
            code,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_dns_error_recognises_nxdomain_aliases() {
        for code in [DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS] {
            assert!(matches!(
                map_dns_error(code, "x.test"),
                DnsResolverError::NxDomain { .. }
            ));
        }
    }

    #[test]
    fn map_dns_error_refused_carries_code() {
        match map_dns_error(DNS_ERROR_RCODE_REFUSED, "x.test") {
            DnsResolverError::Refused { code, .. } => {
                assert_eq!(code, DNS_ERROR_RCODE_REFUSED);
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn map_dns_error_timeout_for_pending_and_win32_timeout() {
        assert!(matches!(
            map_dns_error(DNS_REQUEST_PENDING, "x"),
            DnsResolverError::Timeout { .. }
        ));
        assert!(matches!(
            map_dns_error(ERROR_TIMEOUT, "x"),
            DnsResolverError::Timeout { .. }
        ));
    }

    #[test]
    fn map_dns_error_invalid_name_for_win32_123() {
        assert!(matches!(
            map_dns_error(ERROR_INVALID_NAME, "x"),
            DnsResolverError::InvalidName { .. }
        ));
    }

    #[test]
    fn map_dns_error_unknown_falls_through_to_network() {
        match map_dns_error(0xDEAD, "x.test") {
            DnsResolverError::Network { code, .. } => assert_eq!(code, 0xDEAD),
            other => panic!("expected Network, got {other:?}"),
        }
    }

    #[test]
    fn resolve_a_rejects_empty_hostname() {
        let r = WindowsDnsResolver::new();
        let err = r.resolve_a("").expect_err("empty hostname must error");
        assert!(matches!(err, DnsResolverError::InvalidName { .. }));
    }

    #[test]
    fn resolve_a_rejects_hostname_with_embedded_nul() {
        let r = WindowsDnsResolver::new();
        let err = r
            .resolve_a("bad\0name.test")
            .expect_err("embedded NUL must error");
        assert!(matches!(err, DnsResolverError::InvalidName { .. }));
    }

    /// Real DNS smoke test. Resolves `cloudflare.com` against the
    /// system resolver. Marked `#[ignore]` because it requires
    /// outbound network (CI may not have it) and the answer changes
    /// over time.
    ///
    /// Run on demand: `cargo test -p nrr-platform-windows --
    /// resolve_a_resolves_known_host_on_windows --ignored`.
    #[test]
    #[ignore = "requires outbound DNS resolution; flaky on offline build hosts"]
    fn resolve_a_resolves_known_host_on_windows() {
        let r = WindowsDnsResolver::new();
        let record = r
            .resolve_a("cloudflare.com")
            .expect("cloudflare.com must resolve via system resolver");
        assert!(
            !record.addresses.is_empty(),
            "answer must contain ≥1 A record"
        );
        assert_eq!(record.canonical_hostname, "cloudflare.com");
        // Cloudflare TTL is typically a few minutes; sanity check it
        // is finite and positive.
        assert!(record.ttl_seconds.map(|t| t > 0).unwrap_or(false));
    }

    /// Real DNS smoke test for the NXDOMAIN path. Uses a deliberately
    /// invalid TLD that the IANA reserves for examples.
    #[test]
    #[ignore = "requires outbound DNS resolution; flaky on offline build hosts"]
    fn resolve_a_returns_nxdomain_for_invalid_test_name_on_windows() {
        let r = WindowsDnsResolver::new();
        let err = r
            .resolve_a("never-resolves.invalid")
            .expect_err("invalid TLD must NXDOMAIN");
        assert!(
            matches!(
                err,
                DnsResolverError::NxDomain { .. } | DnsResolverError::Network { .. }
            ),
            "expected NxDomain (or Network if offline), got {err:?}"
        );
    }

    /// Silences a `dead_code` warning for [`OPERATION`] until the
    /// supervisor task references it for structured logging.
    #[test]
    fn operation_label_is_referenced() {
        assert_eq!(OPERATION, "DnsQuery_W");
    }
}

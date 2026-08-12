//! DNS resolver subsystem.
//!
//! Defines the platform-agnostic [`DnsResolverPort`] trait, the data
//! types that flow across it ([`ResolvedRecord`], [`DnsResolverError`]),
//! and a [`MockDnsResolver`] for unit tests. The real Windows
//! implementation backed by `DnsQuery_W` lives in `win32_dns`
//! (`nrr_platform_windows::dns::win32_dns`).
//!
//! ## Architectural seam
//!
//! `DnsResolverPort` is the single boundary between the service layer
//! and the OS resolver. Callers (the DNS refresh task, manual cache
//! refresh handlers) only ever see this trait — they never reach
//! Win32 directly. This keeps:
//!
//! - `nrr-service-runtime` testable without admin rights or live DNS,
//! - `cargo check --workspace` working on Linux/macOS CI,
//! - alternative resolver backends (DoH, system stub) plug-compatible
//!   for any future Pro-tier extension.
//!
//! ## Scope
//!
//! - IPv4 (`DNS_TYPE_A`) only. IPv6 (`AAAA`) is intentionally out of
//!   scope for the Free edition — see `crate::types` module docs.
//! - Synchronous, blocking calls. Callers wrap in their own threading
//!   model (the refresh task uses `build_dns_refresh_task` which
//!   runs on the supervisor tick thread).
//! - No DoH/DoT — uses the system resolver, honours `%SystemRoot%\\
//!   System32\\drivers\\etc\\hosts`, follows the configured DNS
//!   servers.

use std::net::Ipv4Addr;
use std::sync::Mutex;

// ── DTOs ─────────────────────────────────────────────────────────────────────

/// Result of a successful `A`-record query.
///
/// All addresses share the queried hostname; `ttl_seconds` is the
/// **minimum** TTL across the returned record set so callers can use a
/// single expiry timestamp without surprising the OS resolver cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRecord {
    /// Canonical hostname queried. Normalised by the resolver: lower-
    /// cased, no trailing dot.
    pub canonical_hostname: String,
    /// IPv4 addresses returned by DNS. Always non-empty in `Ok`
    /// results — empty answers are reported as
    /// [`DnsResolverError::NxDomain`] instead.
    pub addresses: Vec<Ipv4Addr>,
    /// Minimum TTL (seconds) across returned records. `None` when the
    /// resolver could not surface a TTL (rare — system stub usually
    /// caps very small TTLs at a few seconds).
    pub ttl_seconds: Option<u32>,
}

/// Reasons a DNS resolution can fail.
///
/// The variants intentionally mirror the categories the storage
/// negative-cache schema understands (`nxdomain`, `resolve_failed`,
/// `unsupported_addr_family`) plus the engine-level errors that need
/// to be surfaced separately (timeout, refused) so callers can decide
/// on retry strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResolverError {
    /// Hostname is syntactically invalid (empty, contains NUL, …).
    InvalidName { name: String },
    /// DNS returned NXDOMAIN — authoritative "this name does not
    /// exist". Cache as negative for the documented negative TTL.
    NxDomain { hostname: String },
    /// DNS query timed out. Transient — caller may retry.
    Timeout { hostname: String },
    /// DNS server refused the query (`REFUSED` rcode or transport
    /// error). Soft-failure — schedule retry.
    Refused { hostname: String, code: u32 },
    /// Network failure reaching the DNS server (cable unplugged,
    /// adapter down). Caller treats as transient.
    Network { hostname: String, code: u32 },
    /// The platform does not support DNS at all (non-Windows build
    /// returns this from the production resolver helpers).
    UnsupportedPlatform { reason: &'static str },
}

impl DnsResolverError {
    /// Returns the hostname the error applies to, when one was
    /// supplied. Useful for logging / negative-cache key derivation.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            Self::InvalidName { name } => Some(name),
            Self::NxDomain { hostname }
            | Self::Timeout { hostname }
            | Self::Refused { hostname, .. }
            | Self::Network { hostname, .. } => Some(hostname),
            Self::UnsupportedPlatform { .. } => None,
        }
    }

    /// Returns `true` when the error is *authoritative* — the resolver
    /// is confident the name will not produce different results on
    /// immediate retry. Currently only `NxDomain` and `InvalidName`.
    pub fn is_authoritative(&self) -> bool {
        matches!(self, Self::NxDomain { .. } | Self::InvalidName { .. })
    }
}

// ── OS resolver-cache control ───────────────────────────────────────────────

/// Reasons an OS resolver-cache flush can fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsCacheFlushError {
    /// The OS API reported failure. `code` is the raw OS status when one
    /// is available, `0` when the API only reports a boolean failure.
    Failed { code: u32 },
    /// The platform has no flushable system resolver cache (or the
    /// mechanism is not implemented for this OS yet).
    Unsupported { reason: &'static str },
}

/// Control surface over the **OS-level** DNS resolver cache.
///
/// Why this port exists: suffix/zone rule
/// enforcement learns hostnames ONLY by observing live DNS queries
/// (ETW `Microsoft-Windows-DNS-Client` event 3008 on Windows). A host
/// resolved *before* the service started — or before a fail-closed
/// block-all armed — sits in the OS resolver cache, so subsequent
/// lookups never hit the wire, the observer never sees the name, the
/// FQDN cache never learns it, and the codegen never emits its permit.
/// Flushing the OS cache at those boundaries forces every next lookup
/// back onto the wire where the observer can see it.
///
/// Policy (when to flush) stays in `nrr-service-runtime`; this trait is
/// the per-OS mechanism only (policy/mechanism seam).
pub trait DnsCacheControlPort: Send + Sync {
    /// Flush the OS resolver cache. Idempotent; safe to call repeatedly.
    fn flush_resolver_cache(&self) -> Result<(), DnsCacheFlushError>;
}

/// Default no-op implementation: reports success without touching any
/// OS state. Used by tests and as the unwired default so the
/// orchestration layer never needs an `Option` dance.
#[derive(Debug, Default)]
pub struct NoopDnsCacheControl;

impl DnsCacheControlPort for NoopDnsCacheControl {
    fn flush_resolver_cache(&self) -> Result<(), DnsCacheFlushError> {
        Ok(())
    }
}

/// Test mock counting flush invocations. Always compiled (not
/// `#[cfg(test)]`) so dependent crates can use it in their tests, same
/// convention as [`MockDnsResolver`].
#[derive(Debug, Default)]
pub struct MockDnsCacheControl {
    flushes: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

impl MockDnsCacheControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `flush_resolver_cache` calls since construction.
    pub fn flush_count(&self) -> usize {
        self.flushes.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Make subsequent flush calls fail (still counted).
    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

impl DnsCacheControlPort for MockDnsCacheControl {
    fn flush_resolver_cache(&self) -> Result<(), DnsCacheFlushError> {
        self.flushes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            Err(DnsCacheFlushError::Failed { code: 0 })
        } else {
            Ok(())
        }
    }
}

// ── OS resolver-cache read ──────────────────────────────────────────────────

/// One A-record entry read from the OS resolver cache: a hostname and the
/// IPv4 addresses currently cached for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsCachedResolution {
    /// Canonical hostname (lower-cased, no trailing dot) as it appears in the
    /// OS cache.
    pub canonical_hostname: String,
    /// IPv4 addresses the OS currently has cached for the hostname. May be
    /// empty when the cached entry is a negative/CNAME-only record; callers
    /// skip empties.
    pub addresses: Vec<Ipv4Addr>,
}

/// Reasons an OS resolver-cache read can fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsCacheReadError {
    /// The OS API reported failure. `code` is the raw OS status when one is
    /// available, `0` when the API only reports a boolean/null failure.
    Failed { code: u32 },
    /// The platform has no readable system resolver cache (or the mechanism is
    /// not implemented for this OS yet).
    Unsupported { reason: &'static str },
}

/// Read surface over the **OS-level** DNS resolver cache.
///
/// The complement to [`DnsCacheControlPort`]. Suffix/zone enforcement
/// learns hostnames only by observing live DNS queries (ETW event 3008 on
/// Windows). A host resolved *before* the service started — or served straight
/// from the OS resolver cache so no wire query ever fires — is invisible to the
/// observer, so its zone permit is never emitted and the catch-all blocks it.
/// Flushing (the control port) forces a re-query; reading (this port) is the
/// passive alternative — snapshot what the OS already resolved and seed the
/// FQDN cache with the rule-matching entries directly, no flush and no wire
/// round-trip.
///
/// Policy (which entries to keep, when to snapshot) stays in
/// `nrr-service-runtime`; this trait is the per-OS mechanism only
/// (policy/mechanism seam). Implementations MUST return hostnames in canonical
/// form (lower-case, no trailing dot) and MUST NOT block on the network.
pub trait DnsCacheReadPort: Send + Sync {
    /// Enumerate the A-records currently in the OS resolver cache. The result
    /// is a point-in-time snapshot; entries with no IPv4 addresses may be
    /// omitted or returned with an empty `addresses` vec.
    fn read_resolver_cache(&self) -> Result<Vec<OsCachedResolution>, DnsCacheReadError>;
}

/// Default no-op implementation: reports an empty cache. Used by tests and as
/// the unwired default so the orchestration layer never needs an `Option`
/// dance. (An empty snapshot is indistinguishable from "nothing cached", which
/// is the safe interpretation — the observer path still learns hosts.)
#[derive(Debug, Default)]
pub struct NoopDnsCacheRead;

impl DnsCacheReadPort for NoopDnsCacheRead {
    fn read_resolver_cache(&self) -> Result<Vec<OsCachedResolution>, DnsCacheReadError> {
        Ok(Vec::new())
    }
}

/// Test mock returning a preconfigured snapshot and counting reads. Always
/// compiled (not `#[cfg(test)]`) so dependent crates can use it in their tests,
/// same convention as [`MockDnsResolver`]/[`MockDnsCacheControl`].
#[derive(Debug, Default)]
pub struct MockDnsCacheRead {
    entries: Mutex<Vec<OsCachedResolution>>,
    reads: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}

// Test-only mock: `Mutex::lock().unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockDnsCacheRead {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the snapshot the next `read_resolver_cache` returns.
    pub fn set_entries(&self, entries: Vec<OsCachedResolution>) {
        *self.entries.lock().unwrap() = entries;
    }

    /// Number of `read_resolver_cache` calls since construction.
    pub fn read_count(&self) -> usize {
        self.reads.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Make subsequent reads fail (still counted).
    pub fn set_fail(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }
}

// Test-only mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl DnsCacheReadPort for MockDnsCacheRead {
    fn read_resolver_cache(&self) -> Result<Vec<OsCachedResolution>, DnsCacheReadError> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(DnsCacheReadError::Failed { code: 0 });
        }
        Ok(self.entries.lock().unwrap().clone())
    }
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Abstraction over a synchronous IPv4 DNS resolver.
///
/// One implementation per platform; mocks for tests. Methods take
/// `&self` so the trait is `Sync` and can be shared via `Arc<dyn …>`
/// across the supervisor tick thread and ad-hoc IPC handler calls.
pub trait DnsResolverPort: Send + Sync {
    /// Resolve `hostname` to a set of IPv4 addresses (`A` records).
    ///
    /// Implementations MUST normalise `hostname` to lower-case, no
    /// trailing dot before issuing the query and before populating
    /// [`ResolvedRecord::canonical_hostname`]. Empty hostnames or
    /// hostnames containing NUL bytes / characters that Win32 rejects
    /// MUST surface as [`DnsResolverError::InvalidName`].
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError>;
}

// ── Mock implementation ─────────────────────────────────────────────────────

/// Test-only mock. Pre-configures per-hostname success / failure
/// results; any hostname not pre-configured returns
/// [`DnsResolverError::NxDomain`].
///
/// Always compiled (not `#[cfg(test)]`) so the service-runtime crate
/// can construct it in integration tests without re-implementing the
/// trait.
pub struct MockDnsResolver {
    inner: Mutex<MockState>,
}

#[derive(Default)]
struct MockState {
    responses: Vec<(String, Result<ResolvedRecord, DnsResolverError>)>,
    queries: Vec<String>,
}

// Test-only mock: `Mutex::lock().unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockState::default()),
        }
    }

    /// Configure a successful response for `hostname`. Last write
    /// wins. `hostname` is lower-cased before lookup so callers may
    /// pass it in any case.
    pub fn set_response(&self, hostname: &str, record: ResolvedRecord) {
        let mut s = self.inner.lock().unwrap();
        let canonical = canonicalize_hostname(hostname);
        s.responses.retain(|(h, _)| h != &canonical);
        s.responses.push((canonical, Ok(record)));
    }

    /// Configure an error response for `hostname`.
    pub fn set_error(&self, hostname: &str, error: DnsResolverError) {
        let mut s = self.inner.lock().unwrap();
        let canonical = canonicalize_hostname(hostname);
        s.responses.retain(|(h, _)| h != &canonical);
        s.responses.push((canonical, Err(error)));
    }

    /// Returns a snapshot of the hostnames passed to
    /// [`resolve_a`](DnsResolverPort::resolve_a) since construction.
    pub fn observed_queries(&self) -> Vec<String> {
        self.inner.lock().unwrap().queries.clone()
    }
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

// Test-only mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl DnsResolverPort for MockDnsResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
        let canonical = canonicalize_hostname(hostname);
        let mut s = self.inner.lock().unwrap();
        s.queries.push(canonical.clone());
        for (host, result) in s.responses.iter() {
            if host == &canonical {
                return result.clone();
            }
        }
        Err(DnsResolverError::NxDomain {
            hostname: canonical,
        })
    }
}

/// Lower-case + strip trailing dot. Used by both [`MockDnsResolver`]
/// and the production Windows resolver (`WindowsDnsResolver`) to keep
/// the canonical hostname form consistent across implementations.
///
/// `pub` (rather than `pub(crate)`) so the `nrr-platform-windows`
/// re-export makes it visible to `win32_dns.rs`.
pub fn canonicalize_hostname(input: &str) -> String {
    let trimmed = input.trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_lowercases_and_strips_trailing_dot() {
        assert_eq!(canonicalize_hostname("Example.COM."), "example.com");
        assert_eq!(canonicalize_hostname("example.com"), "example.com");
        assert_eq!(canonicalize_hostname(""), "");
    }

    #[test]
    fn mock_default_response_is_nxdomain() {
        let r = MockDnsResolver::new();
        let err = r
            .resolve_a("nope.example")
            .expect_err("unconfigured hostname must error");
        match err {
            DnsResolverError::NxDomain { hostname } => assert_eq!(hostname, "nope.example"),
            other => panic!("expected NxDomain, got {other:?}"),
        }
    }

    #[test]
    fn mock_records_observed_queries() {
        let r = MockDnsResolver::new();
        let _ = r.resolve_a("a.test");
        let _ = r.resolve_a("B.test");
        assert_eq!(
            r.observed_queries(),
            vec!["a.test".to_string(), "b.test".to_string()]
        );
    }

    #[test]
    fn mock_set_response_overwrites_previous() {
        let r = MockDnsResolver::new();
        let first = ResolvedRecord {
            canonical_hostname: "x.test".into(),
            addresses: vec![Ipv4Addr::new(1, 1, 1, 1)],
            ttl_seconds: Some(60),
        };
        let second = ResolvedRecord {
            canonical_hostname: "x.test".into(),
            addresses: vec![Ipv4Addr::new(2, 2, 2, 2)],
            ttl_seconds: Some(120),
        };
        r.set_response("x.test", first);
        r.set_response("x.test", second.clone());
        assert_eq!(r.resolve_a("x.test").unwrap(), second);
    }

    #[test]
    fn mock_set_error_returns_configured_variant() {
        let r = MockDnsResolver::new();
        r.set_error(
            "down.test",
            DnsResolverError::Timeout {
                hostname: "down.test".into(),
            },
        );
        assert!(matches!(
            r.resolve_a("down.test"),
            Err(DnsResolverError::Timeout { .. })
        ));
    }

    #[test]
    fn mock_cache_control_counts_flushes_and_can_fail() {
        let c = MockDnsCacheControl::new();
        assert_eq!(c.flush_count(), 0);
        assert!(c.flush_resolver_cache().is_ok());
        c.set_fail(true);
        assert_eq!(
            c.flush_resolver_cache(),
            Err(DnsCacheFlushError::Failed { code: 0 })
        );
        assert_eq!(c.flush_count(), 2);
    }

    #[test]
    fn noop_cache_control_always_succeeds() {
        assert!(NoopDnsCacheControl.flush_resolver_cache().is_ok());
    }

    #[test]
    fn noop_cache_read_returns_empty() {
        assert_eq!(NoopDnsCacheRead.read_resolver_cache(), Ok(Vec::new()));
    }

    #[test]
    fn mock_cache_read_returns_configured_and_counts_and_can_fail() {
        let r = MockDnsCacheRead::new();
        assert_eq!(r.read_count(), 0);
        assert_eq!(r.read_resolver_cache(), Ok(Vec::new()));
        let entries = vec![OsCachedResolution {
            canonical_hostname: "avito.ru".into(),
            addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
        }];
        r.set_entries(entries.clone());
        assert_eq!(r.read_resolver_cache(), Ok(entries));
        r.set_fail(true);
        assert_eq!(
            r.read_resolver_cache(),
            Err(DnsCacheReadError::Failed { code: 0 })
        );
        assert_eq!(r.read_count(), 3);
    }

    #[test]
    fn error_is_authoritative_only_for_nxdomain_and_invalid() {
        assert!(DnsResolverError::NxDomain {
            hostname: "x".into()
        }
        .is_authoritative());
        assert!(DnsResolverError::InvalidName { name: "x".into() }.is_authoritative());
        assert!(!DnsResolverError::Timeout {
            hostname: "x".into()
        }
        .is_authoritative());
        assert!(!DnsResolverError::Network {
            hostname: "x".into(),
            code: 0
        }
        .is_authoritative());
    }
}

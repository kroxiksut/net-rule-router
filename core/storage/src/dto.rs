use std::net::IpAddr;
use std::time::SystemTime;

use nrr_domain::decision_lookup::{CacheEntryState, LookupDirection, LookupError};

use crate::resolution_source::StorageResolutionSource;

// ── Lookup input / output ─────────────────────────────────────────────────────

/// Input to a cache lookup operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLookupRequest {
    /// Normalized hostname (lowercase, no trailing dot, IDNA-encoded).
    pub hostname: Option<String>,
    /// Lookup direction(s) to attempt.
    pub direction: LookupDirection,
    /// Active revision id at the time of this lookup — stored in the lookup
    /// event for correlation with explain output.
    pub active_revision_id: Option<String>,
    /// Wall-clock time when the lookup was initiated (UTC).
    pub requested_at: SystemTime,
}

/// A single IPv4 address entry retrieved from the cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedIpEntry {
    pub addr: IpAddr,
    pub cache_state: CacheEntryState,
    pub source: StorageResolutionSource,
    /// When this mapping was resolved.  `None` for entries without recorded
    /// timestamp (e.g. early cache seeds before tracking was added).
    pub resolved_at: Option<SystemTime>,
    /// TTL from the DNS response.  `None` when the entry has no DNS TTL
    /// (manually seeded, observed from traffic, etc.).
    pub ttl_seconds: Option<u32>,
    /// Absolute expiry time for this entry (`resolved_at + TTL`).
    /// Used by the service loop to schedule background refreshes.
    pub expires_at: Option<SystemTime>,
    /// Revision that was active when this entry was written.
    pub active_revision_id: Option<String>,
}

/// Result of a cache lookup — storage side, before conversion to
/// [`LookupResult`][nrr_domain::decision_lookup::LookupResult].
///
/// `build_lookup_envelope` on [`CacheRepository`][crate::repository::CacheRepository]
/// converts this into the domain-level type expected by the rule engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLookupResult {
    /// All IPv4 addresses cached for the requested hostname (forward lookup).
    pub resolved_ips: Vec<CachedIpEntry>,
    /// Freshness of the best entry across `resolved_ips`.  `None` if no entry
    /// exists at all (`Missing` state).
    pub overall_freshness: Option<CacheEntryState>,
    /// Source of the best entry.  `None` when `resolved_ips` is empty.
    pub best_source: Option<StorageResolutionSource>,
    /// True when multiple IPs exist for the hostname (multi-IP result).
    pub is_multi_ip: bool,
    /// Lookup errors encountered (timeout, cache unavailable, etc.).
    pub errors: Vec<LookupError>,
    /// When the negative cache entry expires (`retry_after` column).
    /// `Some` only when `overall_freshness == NegativeCached`.
    /// Used by the service loop to schedule the next retry.
    pub negative_cache_expires_at: Option<SystemTime>,
}

// ── Write input types ─────────────────────────────────────────────────────────

/// Successful DNS/lookup resolution to be written into the cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolutionEntry {
    /// Normalized canonical hostname (lowercase, no trailing dot).
    pub canonical_hostname: String,
    /// Raw hostname as observed (may differ from canonical in mixed-case traffic).
    pub raw_hostname_sample: Option<String>,
    /// Resolved usable addresses, either family.
    pub resolved_ips: Vec<IpAddr>,
    /// TTL from the DNS response.  `None` when unavailable — fallback TTL is
    /// applied by the repository.
    pub ttl_seconds: Option<u32>,
    pub source: StorageResolutionSource,
    pub resolved_at: SystemTime,
    pub active_revision_id: Option<String>,
}

/// One hostname whose freshest DNS-sourced resolution has expired.
///
/// Returned by
/// [`CacheRepository::list_expired_resolutions`][crate::repository::CacheRepository::list_expired_resolutions]
/// and consumed by the DNS refresh task in `nrr-service-runtime`. The
/// task picks up the rows in `last_seen_at`-descending order (hot
/// first) and re-resolves each via the platform's DNS resolver, then
/// writes the result back via
/// [`CacheRepository::upsert_resolution`][crate::repository::CacheRepository::upsert_resolution]
/// (success) or
/// [`record_failed_resolution`][crate::repository::CacheRepository::record_failed_resolution]
/// (failure).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredHostname {
    /// Canonical hostname (lowercase, no trailing dot).
    pub canonical_hostname: String,
    /// When the hostname was most recently observed. `None` for rows
    /// whose `last_seen_at` was never written (pre-12.3 schema seeds).
    pub last_seen_at: Option<SystemTime>,
}

/// A failed or NXDOMAIN lookup to be written into the negative cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegativeCacheEntry {
    /// Input that was looked up (hostname or IP string).
    pub input: String,
    /// Why the lookup produced no usable result.
    pub reason: NegativeCacheReason,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub source: StorageResolutionSource,
}

/// Reason for a negative cache entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegativeCacheReason {
    /// DNS returned NXDOMAIN or an empty answer.
    NxDomain,
    /// DNS query timed out or failed with a network error.
    ResolveFailed,
    /// The input is native IPv6 — not usable in Free edition matching.
    UnsupportedAddressFamily,
}

impl NegativeCacheReason {
    /// TEXT value stored in the `negative_cache.reason` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NxDomain => "nxdomain",
            Self::ResolveFailed => "resolve_failed",
            Self::UnsupportedAddressFamily => "unsupported_addr_family",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "nxdomain" => Some(Self::NxDomain),
            "resolve_failed" => Some(Self::ResolveFailed),
            "unsupported_addr_family" => Some(Self::UnsupportedAddressFamily),
            _ => None,
        }
    }
}

// ── Cleanup / reset ───────────────────────────────────────────────────────────

/// How long a direct tenant stays in the shared-IP census without being seen
/// again. Aging one out narrows the kill-switch exemption, so this errs long.
pub const SHARED_IP_DIRECT_HOST_MAX_AGE_SECS: u64 = 30 * 86_400;

/// Parameters that govern the cleanup pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupPolicy {
    /// Remove expired negative cache entries older than this (seconds).
    pub max_negative_cache_age_secs: u64,
    /// Maximum number of lookup event rows to keep.
    pub max_lookup_events: usize,
    /// Remove lookup events older than this (seconds).
    pub max_lookup_event_age_secs: u64,
    /// Drop a shared-IP direct tenant not re-observed for this long (seconds).
    pub max_shared_ip_direct_host_age_secs: u64,
    /// Maximum rows removed per single SQL statement (prevents lock starvation).
    pub batch_size: usize,
    /// Whether to run `VACUUM` / WAL checkpoint after this cleanup pass.
    pub run_vacuum: bool,
}

impl Default for CleanupPolicy {
    fn default() -> Self {
        Self {
            max_negative_cache_age_secs: 3_600,
            max_lookup_events: 500,
            max_lookup_event_age_secs: 86_400,
            max_shared_ip_direct_host_age_secs: SHARED_IP_DIRECT_HOST_MAX_AGE_SECS,
            batch_size: 200,
            run_vacuum: false,
        }
    }
}

/// Summary of what was removed during a cleanup pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupSummary {
    pub expired_resolutions_removed: u64,
    pub negative_cache_entries_removed: u64,
    pub lookup_events_removed: u64,
    pub shared_ip_direct_hosts_removed: u64,
    pub vacuumed: bool,
}

/// Why the FQDN/IP cache was cleared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheResetReason {
    ManualUserReset,
    CorruptionDetected,
    RevisionChanged { new_revision_id: String },
    RulesFileChanged,
    SchemaUpgrade,
}

/// Summary returned after clearing the cache.
#[derive(Clone, Debug)]
pub struct CacheResetSummary {
    pub reason: CacheResetReason,
    pub resolutions_removed: u64,
    pub negative_cache_removed: u64,
    pub lookup_events_removed: u64,
    pub shared_ip_direct_hosts_removed: u64,
    pub completed_at: SystemTime,
}

// ── Integrity / recovery ──────────────────────────────────────────────────────

/// Result of a startup integrity check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityCheckResult {
    Ok,
    /// `nrr_fqdn_ip_cache.db` is corrupt — can be rebuilt without user action.
    CacheCorruptRebuildable,
    /// `nrr_service_state.db` integrity failed.
    PolicyIntegrityFailed {
        details: String,
    },
    /// Database schema is from a newer binary — cannot downgrade.
    UnsupportedSchemaVersion {
        found: u32,
        max_supported: u32,
    },
    /// Database file is not reachable.
    StorageUnavailable(String),
}

/// Action the service/recovery flow should take in response to
/// an [`IntegrityCheckResult`].  The storage layer produces this; it does not
/// execute the action itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    None,
    RebuildCache,
    RestoreFromBackup,
    /// Recoverable from the principal's own trusted history (the keyed sweep
    /// in the service does it).
    FallbackToLastKnownGood,
    /// Problem cannot be resolved automatically — show user dialog.
    RequireUserAction(String),
}

// ── Migration ─────────────────────────────────────────────────────────────────

/// Summary returned after running pending migrations.
#[derive(Clone, Debug)]
pub struct MigrationSummary {
    pub from_version: u32,
    pub to_version: u32,
    /// Human-readable names of the migrations that were applied.
    pub migrations_applied: Vec<String>,
    pub completed_at: SystemTime,
}

/// Result of schema verification after migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaVerification {
    pub version: u32,
    pub required_tables_present: bool,
    pub foreign_keys_ok: bool,
    pub indexes_ok: bool,
}

impl SchemaVerification {
    pub fn is_ok(&self) -> bool {
        self.required_tables_present && self.foreign_keys_ok && self.indexes_ok
    }
}

// ── Live aggregate counts ─────────────────────────────────────────────────────

/// Live aggregate row counts from the FQDN/IP cache data tables.
///
/// Produced by [`CacheRepository::get_cache_stats`][crate::repository::CacheRepository::get_cache_stats]
/// for the GUI health surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheStats {
    pub hostname_count: u64,
    pub ip_count: u64,
    /// Total rows in `hostname_ip_resolutions`.
    pub resolution_count: u64,
    /// Rows in `hostname_ip_resolutions` with `freshness_state = 'stale_usable'`.
    pub stale_resolution_count: u64,
    pub negative_cache_count: u64,
    pub lookup_events_count: u64,
    /// Current value of `cache_metadata.cache_generation` (incremented on clear).
    pub cache_generation: u64,
}

/// Names seen at one address, as [`CacheRepository::names_for_address`]
/// returns them.
///
/// [`CacheRepository::names_for_address`]: crate::repository::CacheRepository::names_for_address
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddressNames {
    /// Most recently seen first, capped by the caller's limit.
    pub names: Vec<String>,
    /// Distinct names in all, including the ones the limit left out.
    pub total: u32,
}

// ── Cache entries viewer ──────────────────────────────────────────────────────

/// One flat `(hostname, ip)` resolution row for the read-only cache-entries
/// viewer (Diagnostics → Cache → "Show cache entries").
///
/// Produced by
/// [`CacheRepository::list_resolutions`][crate::repository::CacheRepository::list_resolutions].
/// One row per `hostname_ip_resolutions` entry (multi-IP hostnames yield
/// multiple rows). Purely diagnostic — never consumed by the rule engine.
///
/// `freshness_state` and `source` are the raw TEXT column values (e.g.
/// `"fresh"`, `"stale_usable"`, `"dns"`, `"observed_from_traffic"`); the
/// service layer maps them to localised labels and applies redaction before
/// they reach the GUI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheEntryRow {
    /// Canonical (lowercase, no trailing dot) hostname.
    pub canonical_hostname: String,
    /// Canonical dotted-decimal IPv4 / bracketless IPv6 string.
    pub canonical_ip: String,
    /// Raw `freshness_state` column value.
    pub freshness_state: String,
    /// Raw `source` column value.
    pub source: String,
    /// When the mapping was resolved.
    pub resolved_at: SystemTime,
    /// Absolute expiry time for the mapping.
    pub expires_at: SystemTime,
}

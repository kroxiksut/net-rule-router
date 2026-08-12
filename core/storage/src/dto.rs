use std::net::Ipv4Addr;
use std::time::SystemTime;

use nrr_domain::decision_lookup::{CacheEntryState, LookupDirection, LookupError};

use crate::resolution_source::StorageResolutionSource;

// ── Lookup input / output ─────────────────────────────────────────────────────

/// Input to a cache lookup operation.
///
/// At least one of `hostname` or `observed_ip` must be `Some`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLookupRequest {
    /// Normalized hostname (lowercase, no trailing dot, IDNA-encoded).
    pub hostname: Option<String>,
    /// Observed IPv4 address from WFP (already normalized; native IPv6 excluded
    /// in Free edition).
    pub observed_ip: Option<Ipv4Addr>,
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
    pub addr: Ipv4Addr,
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

/// A single hostname entry from a reverse lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedHostnameEntry {
    pub hostname: String,
    pub cache_state: CacheEntryState,
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
    /// Hostnames associated with the observed IP (reverse lookup, diagnostic only).
    pub reverse_hostnames: Vec<CachedHostnameEntry>,
    /// Freshness of the best entry across `resolved_ips`.  `None` if no entry
    /// exists at all (`Missing` state).
    pub overall_freshness: Option<CacheEntryState>,
    /// Source of the best entry.  `None` when `resolved_ips` is empty.
    pub best_source: Option<StorageResolutionSource>,
    /// True when multiple IPs exist for the hostname (multi-IP result).
    pub is_multi_ip: bool,
    /// True when the observed IP is not present in the cached hostname IP set
    /// (observed vs cached mismatch).
    pub has_conflict: bool,
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
    /// Resolved usable IPv4 addresses.
    pub resolved_ips: Vec<Ipv4Addr>,
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

/// Minimal event record written to the `lookup_events` table for explain
/// correlation.  No raw hostname or IP is stored — only a direction + state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupEventEntry {
    pub direction: LookupDirection,
    pub result_state: LookupResultState,
    pub error_code: Option<String>,
    pub duration_ms: u32,
    pub created_at: SystemTime,
    /// Short TTL expiry — row is removed during the next cleanup pass.
    pub expires_at: SystemTime,
}

/// Outcome state of a single lookup event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupResultState {
    Hit,
    Miss,
    StaleUsed,
    NegativeCached,
    Conflicting,
    Error,
}

impl LookupResultState {
    /// TEXT value stored in the `lookup_events.result_state` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::StaleUsed => "stale_used",
            Self::NegativeCached => "negative_cached",
            Self::Conflicting => "conflicting",
            Self::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "hit" => Some(Self::Hit),
            "miss" => Some(Self::Miss),
            "stale_used" => Some(Self::StaleUsed),
            "negative_cached" => Some(Self::NegativeCached),
            "conflicting" => Some(Self::Conflicting),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

// ── Cleanup / reset ───────────────────────────────────────────────────────────

/// Parameters that govern the cleanup pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupPolicy {
    /// Remove expired negative cache entries older than this (seconds).
    pub max_negative_cache_age_secs: u64,
    /// Maximum number of lookup event rows to keep.
    pub max_lookup_events: usize,
    /// Remove lookup events older than this (seconds).
    pub max_lookup_event_age_secs: u64,
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
    pub completed_at: SystemTime,
}

// ── Integrity / recovery ──────────────────────────────────────────────────────

/// Result of a startup integrity check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityCheckResult {
    Ok,
    /// `nrr_fqdn_ip_cache.db` is corrupt — can be rebuilt without user action.
    CacheCorruptRebuildable,
    /// `nrr_service_state.db` integrity failed — must fall back to LKG.
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
    /// Fall back to the last-known-good revision pointer.
    FallbackToLastKnownGood,
    /// Problem cannot be resolved automatically — show user dialog.
    RequireUserAction(String),
}

/// Per-database integrity state as seen by the health checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbIntegrityState {
    Ok,
    CacheCorruptRebuildable,
    PolicyIntegrityFailed,
    UnsupportedSchema,
    Unavailable,
}

/// Aggregated integrity status for both databases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityStatus {
    pub cache_db: DbIntegrityState,
    pub state_db: DbIntegrityState,
    pub last_verified_at: Option<SystemTime>,
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
/// and consumed by [`build_cache_diagnostic_summary`][crate::explain::build_cache_diagnostic_summary]
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

// ── Health ────────────────────────────────────────────────────────────────────

/// User-visible health state of a single database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverallHealthState {
    Healthy,
    Rebuilding,
    Stale,
    Corrupted,
    ResetRequired,
    Unavailable,
}

/// Health snapshot for a single database file.
#[derive(Clone, Debug)]
pub struct DbHealthStatus {
    pub path_exists: bool,
    pub schema_version: Option<u32>,
    pub last_migration_at: Option<SystemTime>,
    pub last_integrity_check_at: Option<SystemTime>,
    pub last_cleanup_at: Option<SystemTime>,
    /// For the FQDN cache DB, the most recent time the
    /// cache was rebuilt or refreshed (read from
    /// `cache_metadata.last_rebuild_at`). `None` for the state DB and
    /// for a never-rebuilt cache. Surfaced via `StorageHealthStatus`
    /// into the GUI's diagnostics section so operators can tell
    /// whether the cache view is fresh.
    pub last_rebuild_at: Option<SystemTime>,
    pub overall: OverallHealthState,
}

/// Aggregated health status for both storage databases.
#[derive(Clone, Debug)]
pub struct StorageHealthStatus {
    pub cache_db: DbHealthStatus,
    pub state_db: DbHealthStatus,
    pub checked_at: SystemTime,
}

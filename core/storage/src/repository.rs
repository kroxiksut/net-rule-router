//! Storage layer trait interfaces.
//!
//! These four traits define the complete public boundary between the service
//! layer and the SQLite backend.
//!
//! No SQL leaks past this boundary.  The service layer depends on these traits;
//! the SQLite implementation struct lives in a private submodule.
//!
//! # Ownership model
//!
//! - **`CacheRepository`** — owns the FQDN/IP cache (`nrr_fqdn_ip_cache.db`).
//!   Rebuildable on corruption without user interaction.
//! - **`RevisionMetadataRepository`** — owns service-critical state
//!   (`nrr_service_state.db`): active revision pointer, LKG pointer, integrity
//!   metadata.  Corruption here triggers a LKG fallback, not a simple rebuild.
//! - **`MigrationRunner`** — schema evolution for both databases.
//! - **`StorageHealthChecker`** — read-only health snapshot for diagnostics and
//!   the GUI status surface (via the service facade).
//!
//! # Startup sequence
//!
//! ```text
//! MigrationRunner::run_pending_migrations()      // upgrade schema if needed
//!   → MigrationRunner::verify_schema()           // assert tables / indexes OK
//!   → RevisionMetadataRepository::check_integrity() // validate pointers + hash
//!   → (if cache corrupt) CacheRepository::clear_cache(CorruptionDetected)
//!   → service snapshot exposed
//! ```

use std::net::Ipv4Addr;
use std::time::SystemTime;

use nrr_domain::decision_lookup::{FreshnessThresholds, LookupResult};
use nrr_domain::revision::RevisionId;

use crate::dto::{
    CacheEntryRow, CacheLookupRequest, CacheLookupResult, CacheResetReason, CacheResetSummary,
    CacheStats, CleanupPolicy, CleanupSummary, ExpiredHostname, IntegrityCheckResult,
    IntegrityStatus, LookupEventEntry, MigrationSummary, NegativeCacheEntry, NegativeCacheReason,
    RecoveryAction, ResolutionEntry, SchemaVerification, StorageHealthStatus,
};
use crate::error::StorageResult;
use crate::resolution_source::StorageResolutionSource;

// ── CacheRepository ───────────────────────────────────────────────────────────

/// Read/write interface for the FQDN/IP cache database.
///
/// All methods operate synchronously on a single connection (WAL mode).
/// Callers in async context must wrap calls in `tokio::task::spawn_blocking`.
pub trait CacheRepository {
    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up all cached IPv4 entries for a hostname.
    ///
    /// Returns `Ok` with an empty/`Missing` result when the hostname is not in
    /// the cache — `Err` only on storage failures.
    fn get_by_hostname(
        &self,
        hostname: &str,
        thresholds: &FreshnessThresholds,
        strategy: crate::resolution_source::CachePriorityStrategy,
    ) -> StorageResult<CacheLookupResult>;

    /// Look up all cached hostnames associated with an IP (reverse lookup).
    ///
    /// Results are diagnostic context only — never the sole basis for a match.
    fn get_by_ip(
        &self,
        ip: Ipv4Addr,
        thresholds: &FreshnessThresholds,
    ) -> StorageResult<CacheLookupResult>;

    /// Combined forward + optional reverse lookup, converted into the
    /// [`LookupResult`] type expected by the rule engine.
    ///
    /// This is the single call the service layer makes on the critical path.
    /// Internally it calls `get_by_hostname` / `get_by_ip`, selects the best
    /// IP (Fresh > StaleUsable > ObservedFromTraffic), and maps storage types
    /// to domain types without leaking SQL or storage details to the engine.
    ///
    /// `strategy` is the caller's (active user's) cache-source priority; it
    /// only reorders which source wins a tie — `CachePriorityStrategy::default()`
    /// is [`FreshestFirst`](crate::resolution_source::CachePriorityStrategy::FreshestFirst).
    fn build_lookup_envelope(
        &self,
        request: &CacheLookupRequest,
        thresholds: &FreshnessThresholds,
        strategy: crate::resolution_source::CachePriorityStrategy,
    ) -> StorageResult<LookupResult>;

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Upsert a successful resolution result.
    ///
    /// Updates `last_seen_at` and extends `expires_at` for existing entries.
    /// Preserves history when the IP set changes for the same hostname.
    fn upsert_resolution(&self, entry: ResolutionEntry) -> StorageResult<()>;

    /// Write a negative cache entry (NXDOMAIN, timeout, or unsupported AF).
    fn upsert_negative_cache(&self, entry: NegativeCacheEntry) -> StorageResult<()>;

    /// Convenience method: record a failed DNS lookup directly into the negative
    /// cache.  `retry_after` is when the caller should attempt resolution again
    /// (typically `now + FreshnessThresholds::negative_ttl_secs`).
    fn record_failed_resolution(
        &self,
        input: &str,
        reason: NegativeCacheReason,
        retry_after: SystemTime,
        source: StorageResolutionSource,
    ) -> StorageResult<()>;

    /// Record a minimal lookup event for explain correlation.
    ///
    /// No raw hostname or IP is stored — only direction, state, and timestamps.
    fn record_lookup_event(&self, event: LookupEventEntry) -> StorageResult<()>;

    // ── DNS refresh ──────────────────────────────────────────────────────────

    /// List hostnames whose freshest DNS-sourced resolution has
    /// expired by `now` and should be re-resolved.
    ///
    /// Sort priority is hot-first — most recently observed hostnames
    /// (`hostnames.last_seen_at`) come back first so that with a
    /// limited per-tick batch the task spends its budget on names
    /// users are actually hitting. The DNS refresh task in
    /// `nrr-service-runtime` is the single intended caller; manual
    /// cache-refresh IPC handlers may also consume it.
    ///
    /// Returns at most `limit` rows. Rows sourced from
    /// [`StorageResolutionSource::ObservedFromTraffic`][crate::resolution_source::StorageResolutionSource::ObservedFromTraffic]
    /// are intentionally excluded — those are network observations,
    /// not DNS lookups; re-querying them via DNS would be a category
    /// error.
    fn list_expired_resolutions(
        &self,
        now: SystemTime,
        limit: usize,
    ) -> StorageResult<Vec<ExpiredHostname>>;

    /// List cached canonical hostnames whose name ends with
    /// `.{suffix}`. Used by the WFP filter codegen to fan-out
    /// `SuffixDomain` and `Zone` rules across the live
    /// FQDN/IP cache.
    ///
    /// Match semantics mirror the domain `CanonicalAddressMatch`
    /// rules:
    /// - `SuffixDomain("example.com")` matches `www.example.com`,
    ///   `api.example.com`, but NOT `example.com` itself (the apex
    ///   is intentionally excluded).
    /// - `Zone("ru")` matches `any.thing.ru` but NOT the bare `ru`
    ///   label (zones never apply to a single-label hostname).
    ///
    /// Implementations MUST be case-insensitive on the suffix input
    /// — the storage layer normalises hostnames to lowercase on
    /// write, so callers may pass either form.
    ///
    /// Returns at most `limit` rows. Order is implementation-defined
    /// (callers don't depend on it); the `SqliteCacheStore` returns
    /// rows in `canonical_host ASC` for deterministic test snapshots.
    fn list_hostnames_under_suffix(&self, suffix: &str, limit: usize)
        -> StorageResult<Vec<String>>;

    /// List cached `(hostname, ip)` resolution rows for the read-only
    /// cache-entries viewer (Diagnostics → Cache).
    ///
    /// Rows are ordered `canonical_host ASC, canonical_ip ASC` for a
    /// deterministic, stable page window. The method fetches up to
    /// `limit + 1` rows starting at `offset` so the caller can detect
    /// whether another page exists (the extra row is the "has more"
    /// probe; callers typically keep only the first `limit`). A `limit`
    /// of `0` short-circuits to an empty vector.
    ///
    /// Purely diagnostic — this never feeds the rule engine and applies
    /// no freshness recomputation; the raw stored column values are
    /// returned verbatim in [`CacheEntryRow`][crate::dto::CacheEntryRow].
    ///
    /// `query`: when non-empty, filter to rows whose canonical
    /// host OR canonical IP matches it, case-insensitive; empty = no filter.
    /// A query containing `*` uses it
    /// as a wildcard; a query containing a dot (full hostname / IP) matches
    /// exactly; a bare token is an implicit substring. Keeps the GUI cache
    /// search server-side (WHERE LIKE) instead of draining the whole cache
    /// into the client.
    fn list_resolutions(
        &self,
        offset: u32,
        limit: u32,
        query: &str,
    ) -> StorageResult<Vec<CacheEntryRow>>;

    // ── Shared-IP census ───────────────────────────────────────────────────────

    /// Record that a **direct** (non-secondary) hostname was observed sharing
    /// `ip` with a secondary rule. Idempotent per `(ip, hostname)` — repeats
    /// refresh `last_seen` and `primary_ruled`, so a rule edit corrects the
    /// flag on the next observation. Feeds `direct_on_ip` for the shared-IP
    /// policy. `primary_ruled` = a rule of the user's own sends this host out
    /// the main route.
    fn record_shared_ip_direct_host(
        &self,
        ip: std::net::Ipv4Addr,
        hostname: &str,
        now_ms: i64,
        primary_ruled: bool,
    ) -> StorageResult<()>;

    /// Drop every census row for `hostname`. Called when a host stops counting
    /// as direct — it became a rule, or it was parked as a suggestion for the
    /// additional route. Leaving the rows in place would keep its addresses
    /// marked "shared with a direct host" and keep the smart kill-switch
    /// exempting them, which is the opposite of what routing that host means.
    /// Returns the number of rows removed.
    fn forget_shared_ip_direct_host(&self, hostname: &str) -> StorageResult<u32>;

    /// Count distinct **direct** (non-secondary) hostnames observed on `ip`
    /// (`direct_on_ip`). `0` ⇒ the IP is not (observably) shared.
    fn direct_host_count_for_ip(&self, ip: std::net::Ipv4Addr) -> StorageResult<u32>;

    /// Every IP the shared-IP census has seen on at
    /// least one direct (non-rule) hostname, in one query. The "smart"
    /// kill-switch consults this set per apply/reconcile pass; a per-IP
    /// [`Self::direct_host_count_for_ip`] loop would issue thousands of point
    /// queries a second on large pin sets.
    fn shared_ip_census_ips(&self) -> StorageResult<Vec<std::net::Ipv4Addr>>;

    /// The subset of [`Self::shared_ip_census_ips`] carrying at least one
    /// tenant a main-route rule claims. Blocking one of these does not push
    /// the tenant into the tunnel — it kills a host the user's own rule sent
    /// the other way — so the fail-closed exemption subtraction spares them.
    fn shared_ip_census_primary_ruled_ips(&self) -> StorageResult<Vec<std::net::Ipv4Addr>>;

    // ── Fake-IP bindings (persistent hostname -> pool index) ─────────────────

    /// Load every persisted fake-IP binding, oldest-touched first, after
    /// validating `pool_stamp` against the stored one. A missing or different
    /// stamp means the pool geometry changed: the table is wiped, the new
    /// stamp stored, and an empty list returned — stored indexes from another
    /// pool would map hostnames onto the wrong addresses.
    fn load_fake_ip_bindings(&self, pool_stamp: &str) -> StorageResult<Vec<(String, u32)>>;

    /// Persist (or re-deal) one `domain -> pool_index` binding. Replaces any
    /// row holding either side of the pair (a recycled index retires its old
    /// domain in the same write).
    fn record_fake_ip_binding(
        &self,
        domain: &str,
        pool_index: u32,
        now_ms: i64,
    ) -> StorageResult<()>;

    /// Remove the binding at `pool_index`, if any.
    fn remove_fake_ip_binding(&self, pool_index: u32) -> StorageResult<()>;

    // ── Revision lifecycle ────────────────────────────────────────────────────

    /// Mark cache entries from previous revisions as `stale_usable`.
    ///
    /// Entries are kept as reusable network observations; they are not deleted.
    /// Returns the number of rows updated.
    fn mark_revision_stale(&self, new_active_revision_id: &str) -> StorageResult<u64>;

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Remove expired resolutions, negative cache entries, and old lookup
    /// events according to `policy`.  Runs `periodic_vacuum` when
    /// `policy.run_vacuum` is `true`.
    fn cleanup_expired(
        &self,
        now: SystemTime,
        policy: &CleanupPolicy,
    ) -> StorageResult<CleanupSummary>;

    /// Delete all FQDN/IP cache rows.  Does not touch `nrr_service_state.db`,
    /// audit events, or user rules files.
    fn clear_cache(&self, reason: CacheResetReason) -> StorageResult<CacheResetSummary>;

    /// Delete every cached IPv4 in `[start, end]` (inclusive) together with its
    /// hostname resolutions, shared-IP census rows, and any hostnames left with
    /// no resolutions. Returns the number of resolution mappings removed.
    ///
    /// Targeted sweep for address ranges that must never be modelled as real
    /// endpoints (e.g. a virtual address pool that leaked into the cache);
    /// unlike [`Self::clear_cache`] the rest of the cache survives.
    fn purge_ip_range_v4(
        &self,
        start: std::net::Ipv4Addr,
        end: std::net::Ipv4Addr,
    ) -> StorageResult<u64>;

    /// Run `VACUUM INTO` (or an incremental WAL checkpoint) to reclaim space
    /// after a large cleanup.  Should not be called on the decision-critical path.
    fn periodic_vacuum(&self) -> StorageResult<()>;

    /// Returns live aggregate row counts from the FQDN/IP cache data tables.
    ///
    /// Used by the service facade to populate
    /// [`CacheDiagnosticSummary`][crate::explain::CacheDiagnosticSummary] for the
    /// GUI health surface.  The query is a single-pass SELECT — inexpensive on
    /// a warm WAL database.
    fn get_cache_stats(&self) -> StorageResult<CacheStats>;

    /// Stamp the `cache_metadata.last_rebuild_at` field
    /// with `now_ms`. Called by the DNS refresh orchestrator after a
    /// successful resolver batch so the diagnostics surface can show
    /// "cache last refreshed at HH:MM".
    ///
    /// `clear_cache` also writes this column (full rebuild). This
    /// method is for incremental warm-up writes where the cache is
    /// not cleared — just refreshed for one or more hostnames.
    ///
    /// UPSERT semantics: creates the singleton row if absent
    /// (matches `clear_cache`'s write — same `id=1` CHECK).
    fn touch_last_rebuild_at(&self, now_ms: i64) -> StorageResult<()>;

    /// Read the most recent rebuild/refresh timestamp.
    /// Returns `Ok(None)` when the singleton row has not been written
    /// (fresh install, no warm-up writes, no clear yet). The IPC
    /// status handler exposes this via `StorageHealthStatus`.
    fn get_last_rebuild_at_ms(&self) -> StorageResult<Option<i64>>;

    /// Run `PRAGMA integrity_check(1)` on the cache database.
    ///
    /// Called during the startup integrity sequence before loading
    /// active policy.  A non-ok result means the cache is corrupt and should be
    /// rebuilt; it never blocks service start — the service can operate without
    /// the cache (entries are `Missing` until rebuilt).
    ///
    /// Returns `RecoveryAction::RebuildCache` when the check fails so the service
    /// layer can schedule a rebuild without executing it inside this call.
    fn check_cache_integrity(&self) -> StorageResult<(IntegrityCheckResult, RecoveryAction)>;
}

// ── RevisionMetadataRepository ────────────────────────────────────────────────

/// Read/write interface for service-critical state in `nrr_service_state.db`.
///
/// Corruption here is NOT recoverable by a simple rebuild — it triggers a
/// fallback to the last-known-good revision.
pub trait RevisionMetadataRepository {
    // ── Revision pointers ─────────────────────────────────────────────────────

    /// Returns the currently active policy revision id, or `None` if no
    /// revision has been activated yet (fresh install).
    fn get_active_revision(&self) -> StorageResult<Option<RevisionId>>;

    /// Sets the active revision pointer.  Called by the service after a policy
    /// revision is validated and applied.
    fn set_active_revision(&self, revision_id: &RevisionId) -> StorageResult<()>;

    /// Returns the last-known-good revision id, or `None` if not yet set.
    fn get_last_known_good(&self) -> StorageResult<Option<RevisionId>>;

    /// Promotes a revision to last-known-good.  Called after a revision has
    /// been running without incident for the configured grace period.
    fn set_last_known_good(&self, revision_id: &RevisionId) -> StorageResult<()>;

    // ── Integrity ─────────────────────────────────────────────────────────────

    /// Runs a full integrity check and returns the result.
    ///
    /// The storage layer checks SQLite `PRAGMA integrity_check`, validates the
    /// active revision pointer format, and verifies any stored content hash.
    /// It returns a [`RecoveryAction`] alongside the result so the service
    /// layer can decide what to do — the storage layer never applies the action.
    fn check_integrity(&self) -> StorageResult<(IntegrityCheckResult, RecoveryAction)>;

    /// Persists the outcome of the latest integrity check (timestamp + result)
    /// for health reporting.
    fn record_integrity_check(
        &self,
        result: &IntegrityCheckResult,
        checked_at: SystemTime,
    ) -> StorageResult<()>;

    /// Returns the latest stored integrity status for health reporting without
    /// re-running the check.
    fn get_integrity_status(&self) -> StorageResult<IntegrityStatus>;
}

// ── MigrationRunner ───────────────────────────────────────────────────────────

/// Schema migration interface for both SQLite databases.
///
/// Migrations are idempotent SQL scripts embedded in the crate.  Each migration
/// runs in its own transaction.  A pre-migration backup of `nrr_service_state.db`
/// is made before any structural change.
pub trait MigrationRunner {
    /// Returns the schema version currently present in the database.
    fn current_schema_version(&self) -> StorageResult<u32>;

    /// Applies all pending migrations in version order.
    ///
    /// Returns a [`MigrationSummary`] describing what was applied.  Returns `Ok`
    /// with `from_version == to_version` when no migrations were pending.
    fn run_pending_migrations(&self) -> StorageResult<MigrationSummary>;

    /// Verifies that the schema is internally consistent after migration
    /// (tables, indexes, foreign keys).
    fn verify_schema(&self) -> StorageResult<SchemaVerification>;
}

// ── StorageHealthChecker ──────────────────────────────────────────────────────

/// Read-only health snapshot for the GUI diagnostics surface.
///
/// The snapshot is delivered to the GUI through the service facade
/// over IPC — the GUI never reads SQLite directly.
pub trait StorageHealthChecker {
    /// Returns a point-in-time health snapshot for both databases.
    fn check_health(&self) -> StorageResult<StorageHealthStatus>;
}

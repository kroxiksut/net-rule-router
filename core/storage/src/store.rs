//! Concrete SQLite repository implementations.
//!
//! [`SqliteCacheStore`] implements [`CacheRepository`] against `nrr_fqdn_ip_cache.db`.
//! [`SqliteStateStore`] implements [`RevisionMetadataRepository`] against
//! `nrr_service_state.db`.
//!
//! Both structs take ownership of a migrated [`Connection`] (obtained from
//! [`SqliteMigrationRunner::into_connection`][crate::migration::SqliteMigrationRunner]).
//! Trait methods are `&self`; [`RefCell`] provides interior mutability for the
//! methods that need `&mut Connection` to create transactions.

use std::cell::RefCell;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use rusqlite::{params, Connection, OptionalExtension};

use nrr_domain::decision_lookup::{
    CacheEntryState, FreshnessThresholds, LookupExplainData, LookupExtendedMetadata, LookupResult,
    LookupSource, LookupStandardSignals, ResolvedAddressEntry, ResolvedHostnameEntry,
};
use nrr_domain::revision::RevisionId;

use crate::dto::{
    CacheEntryRow, CacheLookupRequest, CacheLookupResult, CacheResetReason, CacheResetSummary,
    CacheStats, CachedHostnameEntry, CachedIpEntry, CleanupPolicy, CleanupSummary, DbHealthStatus,
    DbIntegrityState, ExpiredHostname, IntegrityCheckResult, IntegrityStatus, LookupEventEntry,
    NegativeCacheEntry, NegativeCacheReason, OverallHealthState, RecoveryAction, ResolutionEntry,
    StorageHealthStatus,
};
use crate::error::{StorageError, StorageResult};
use crate::integrity;
use crate::repository::{CacheRepository, RevisionMetadataRepository, StorageHealthChecker};
use crate::resolution_source::{CachePriorityStrategy, StorageResolutionSource};
use crate::schema::{lookup_direction_as_str, FreshnessStateDb};

// ── SqliteCacheStore ──────────────────────────────────────────────────────────

/// SQLite-backed implementation of [`CacheRepository`].
///
/// Owns one connection to `nrr_fqdn_ip_cache.db`.  The connection was opened
/// and migrated by [`SqliteMigrationRunner`][crate::migration::SqliteMigrationRunner]
/// before this struct was constructed.
/// Backstop age (seconds) after which even a held DNS-sourced last-known-good
/// resolution is dropped by cleanup. A rule host that could not be
/// re-resolved for this long is treated as dead so the cache cannot grow
/// unbounded; anything refreshed within the window is retained.
const HELD_RESOLUTION_BACKSTOP_SECS: i64 = 30 * 86_400;

pub struct SqliteCacheStore {
    conn: RefCell<Connection>,
    thresholds: FreshnessThresholds,
}

impl SqliteCacheStore {
    /// Creates a new store from an already-migrated connection.
    ///
    /// `thresholds` is needed to compute `expires_at` when writing resolutions
    /// (for entries whose DNS response carries no explicit TTL).
    pub fn new(conn: Connection, thresholds: FreshnessThresholds) -> Self {
        Self {
            conn: RefCell::new(conn),
            thresholds,
        }
    }

    /// Consumes the store and returns the underlying connection.
    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }
}

impl CacheRepository for SqliteCacheStore {
    // ── Lookup ────────────────────────────────────────────────────────────────

    fn get_by_hostname(
        &self,
        hostname: &str,
        thresholds: &FreshnessThresholds,
        strategy: CachePriorityStrategy,
    ) -> StorageResult<CacheLookupResult> {
        let conn = self.conn.borrow();
        let now_ms = system_time_to_ms(SystemTime::now());

        // Last-known-good wins over a transient negative. The
        // negative cache is only honoured when we have NO positive resolution
        // for the host: a domain rule's IPs rarely change, so a transient
        // NXDOMAIN / timeout during a re-resolution must NOT purge the cached
        // address the leak-guard and routing depend on. We therefore defer the
        // negative-cache check until after the forward lookup and only apply it
        // when the positive set is empty (genuine never-resolved host).

        // Forward lookup: hostname → resolved IPv4 entries.
        let mut stmt = conn
            .prepare(
                "SELECT a.canonical_ip, r.freshness_state, r.source,
                        r.resolved_at, r.ttl_seconds, r.expires_at, r.active_revision_id
                 FROM hostname_ip_resolutions r
                 JOIN ip_addresses a ON a.id = r.ip_id
                 JOIN hostnames    h ON h.id = r.hostname_id
                 WHERE h.canonical_host = ?1
                   AND a.address_family = 'ipv4'
                 ORDER BY r.resolved_at DESC",
            )
            .map_err(db_err)?;

        struct RawRow {
            canonical_ip: String,
            freshness_str: String,
            source_str: String,
            resolved_at_ms: i64,
            ttl_seconds: Option<i64>,
            expires_at_ms: i64,
            active_revision_id: Option<String>,
        }

        let raw: Vec<RawRow> = stmt
            .query_map(params![hostname], |r| {
                Ok(RawRow {
                    canonical_ip: r.get(0)?,
                    freshness_str: r.get(1)?,
                    source_str: r.get(2)?,
                    resolved_at_ms: r.get(3)?,
                    ttl_seconds: r.get(4)?,
                    expires_at_ms: r.get(5)?,
                    active_revision_id: r.get(6)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        let mut resolved_ips: Vec<CachedIpEntry> = Vec::with_capacity(raw.len());
        for row in raw {
            let addr: Ipv4Addr = row.canonical_ip.parse().map_err(|e| {
                StorageError::Internal(format!("parse IP {:?}: {e}", row.canonical_ip))
            })?;
            let stored = FreshnessStateDb::from_str(&row.freshness_str)
                .unwrap_or(FreshnessStateDb::StaleNotUsable);
            let source = StorageResolutionSource::from_str(&row.source_str)
                .unwrap_or(StorageResolutionSource::CacheRebuild);

            resolved_ips.push(CachedIpEntry {
                addr,
                cache_state: effective_freshness(stored, row.expires_at_ms, now_ms, thresholds),
                source,
                resolved_at: Some(ms_to_system_time(row.resolved_at_ms)),
                ttl_seconds: row.ttl_seconds.map(|t| t as u32),
                expires_at: Some(ms_to_system_time(row.expires_at_ms)),
                active_revision_id: row.active_revision_id,
            });
        }

        // Only when there is NO last-known-good resolution do we honour a live
        // negative-cache entry (genuine never-resolved / NXDOMAIN host).
        if resolved_ips.is_empty() {
            let neg_hash = input_hash(hostname);
            let neg_hit: Option<(String, i64)> = conn
                .query_row(
                    "SELECT reason, expires_at FROM negative_cache
                     WHERE input_hash = ?1 AND expires_at > ?2",
                    params![neg_hash, now_ms],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db_err)?;
            if let Some((_reason, neg_expires_ms)) = neg_hit {
                return Ok(CacheLookupResult {
                    resolved_ips: Vec::new(),
                    reverse_hostnames: Vec::new(),
                    overall_freshness: Some(CacheEntryState::NegativeCached),
                    best_source: None,
                    is_multi_ip: false,
                    has_conflict: false,
                    errors: Vec::new(),
                    negative_cache_expires_at: Some(ms_to_system_time(neg_expires_ms)),
                });
            }
        }

        let overall_freshness = best_freshness(&resolved_ips);
        let best_source = best_source_of(&resolved_ips, strategy);
        let is_multi_ip = resolved_ips.len() > 1;

        Ok(CacheLookupResult {
            resolved_ips,
            reverse_hostnames: Vec::new(),
            overall_freshness,
            best_source,
            is_multi_ip,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        })
    }

    fn get_by_ip(
        &self,
        ip: Ipv4Addr,
        _thresholds: &FreshnessThresholds,
    ) -> StorageResult<CacheLookupResult> {
        let conn = self.conn.borrow();
        let canonical_ip = ip.to_string();

        let mut stmt = conn
            .prepare(
                "SELECT h.canonical_host, r.freshness_state, r.diagnostic_flags
                 FROM hostname_ip_resolutions r
                 JOIN hostnames    h ON h.id = r.hostname_id
                 JOIN ip_addresses a ON a.id = r.ip_id
                 WHERE a.address_family = 'ipv4' AND a.canonical_ip = ?1
                 ORDER BY r.resolved_at DESC",
            )
            .map_err(db_err)?;

        let hostnames: Vec<CachedHostnameEntry> = stmt
            .query_map(params![canonical_ip], |r| {
                let hostname: String = r.get(0)?;
                let freshness_str: String = r.get(1)?;
                Ok((hostname, freshness_str))
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?
            .into_iter()
            .map(|(hostname, freshness_str)| CachedHostnameEntry {
                hostname,
                cache_state: FreshnessStateDb::from_str(&freshness_str)
                    .map(|s| s.to_domain())
                    .unwrap_or(CacheEntryState::StaleNotUsable),
            })
            .collect();

        Ok(CacheLookupResult {
            resolved_ips: Vec::new(),
            reverse_hostnames: hostnames,
            overall_freshness: None,
            best_source: None,
            is_multi_ip: false,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        })
    }

    fn build_lookup_envelope(
        &self,
        request: &CacheLookupRequest,
        thresholds: &FreshnessThresholds,
        strategy: CachePriorityStrategy,
    ) -> StorageResult<LookupResult> {
        use nrr_domain::decision_lookup::LookupDirection;

        let empty = || CacheLookupResult {
            resolved_ips: Vec::new(),
            reverse_hostnames: Vec::new(),
            overall_freshness: None,
            best_source: None,
            is_multi_ip: false,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        };

        let forward = match (&request.hostname, request.direction.clone()) {
            (Some(h), LookupDirection::HostnameToIp | LookupDirection::Both) => {
                self.get_by_hostname(h, thresholds, strategy)?
            }
            _ => empty(),
        };

        let reverse = match (request.observed_ip, request.direction.clone()) {
            (Some(ip), LookupDirection::IpToHostname | LookupDirection::Both) => {
                self.get_by_ip(ip, thresholds)?
            }
            _ => empty(),
        };

        // Conflict: observed IP not found in the cached IP set for this hostname.
        let has_conflict = request.observed_ip.is_some_and(|obs| {
            !forward.resolved_ips.is_empty() && !forward.resolved_ips.iter().any(|e| e.addr == obs)
        });

        // Select the best IP for ExactIp matching.
        let selected_ip = select_best_ip(&forward.resolved_ips, request.observed_ip, strategy);

        let cache_hit = !forward.resolved_ips.is_empty();
        let all_resolved: Vec<ResolvedAddressEntry> = forward
            .resolved_ips
            .iter()
            .map(|e| ResolvedAddressEntry {
                addr: e.addr,
                cache_state: e.cache_state.clone(),
                source: e.source.to_lookup_source(),
                resolved_at: e.resolved_at,
                ttl_seconds: e.ttl_seconds,
            })
            .collect();

        let reverse_hostnames: Vec<ResolvedHostnameEntry> = reverse
            .reverse_hostnames
            .into_iter()
            .map(|h| ResolvedHostnameEntry {
                hostname: h.hostname,
                cache_state: h.cache_state,
            })
            .collect();

        Ok(LookupResult {
            selected_ip: selected_ip.clone(),
            is_multi_ip: forward.is_multi_ip,
            has_conflict,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit,
                    freshness: forward.overall_freshness,
                    source: forward.best_source.map(|s| s.to_lookup_source()),
                    errors: forward.errors,
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: all_resolved,
                    reverse_hostnames,
                    selected_entry_ttl_secs: selected_ip.as_ref().and_then(|e| e.ttl_seconds),
                    selected_entry_resolved_at: selected_ip.as_ref().and_then(|e| e.resolved_at),
                },
            },
        })
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    fn upsert_resolution(&self, entry: ResolutionEntry) -> StorageResult<()> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;

        let resolved_at_ms = system_time_to_ms(entry.resolved_at);
        // `fallback_ttl_secs` is both the no-TTL fallback AND a lower FLOOR on
        // the refresh cadence: a CDN that reports a 60 s TTL is floored
        // so we re-resolve at most every ~5 min (not every minute), while a
        // longer advertised TTL is honoured. `expires_at` only drives WHEN the
        // DNS-refresh task re-resolves — it does NOT purge the row: a failed
        // refresh keeps the last-known-good entry (see `cleanup_expired`), so the
        // rule's /32 stays available to the leak-guard.
        let ttl = entry
            .ttl_seconds
            .unwrap_or(self.thresholds.fallback_ttl_secs)
            .max(self.thresholds.fallback_ttl_secs);
        let expires_at_ms = resolved_at_ms + ttl as i64 * 1_000;
        let source_str = entry.source.as_str();
        let rev_id = entry.active_revision_id.as_deref();

        // 1. Upsert hostname row.
        tx.execute(
            "INSERT INTO hostnames (canonical_host, raw_sample, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(canonical_host) DO UPDATE SET
                 last_seen_at = excluded.last_seen_at,
                 raw_sample   = COALESCE(excluded.raw_sample, raw_sample)",
            params![
                entry.canonical_hostname,
                entry.raw_hostname_sample,
                resolved_at_ms
            ],
        )
        .map_err(db_err)?;

        let hostname_id: i64 = tx
            .query_row(
                "SELECT id FROM hostnames WHERE canonical_host = ?1",
                params![entry.canonical_hostname],
                |r| r.get(0),
            )
            .map_err(db_err)?;

        // 2. Upsert each resolved IPv4 address.
        for ip in &entry.resolved_ips {
            let canonical_ip = ip.to_string();
            let packed = ipv4_packed(*ip);

            tx.execute(
                "INSERT INTO ip_addresses
                 (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at)
                 VALUES ('ipv4', ?1, ?2, ?3, ?3)
                 ON CONFLICT(address_family, canonical_ip) DO UPDATE SET
                     last_seen_at = excluded.last_seen_at,
                     ipv4_packed  = excluded.ipv4_packed",
                params![canonical_ip, packed, resolved_at_ms],
            )
            .map_err(db_err)?;

            let ip_id: i64 = tx
                .query_row(
                    "SELECT id FROM ip_addresses
                     WHERE address_family = 'ipv4' AND canonical_ip = ?1",
                    params![canonical_ip],
                    |r| r.get(0),
                )
                .map_err(db_err)?;

            // 3. Upsert resolution row (one per hostname/ip/source triple).
            tx.execute(
                "INSERT INTO hostname_ip_resolutions
                 (hostname_id, ip_id, source, ttl_seconds, resolved_at,
                  expires_at, freshness_state, active_revision_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'fresh', ?7)
                 ON CONFLICT(hostname_id, ip_id, source) DO UPDATE SET
                     ttl_seconds        = excluded.ttl_seconds,
                     resolved_at        = excluded.resolved_at,
                     expires_at         = excluded.expires_at,
                     freshness_state    = 'fresh',
                     active_revision_id = excluded.active_revision_id",
                params![
                    hostname_id,
                    ip_id,
                    source_str,
                    entry.ttl_seconds.map(|t| t as i64),
                    resolved_at_ms,
                    expires_at_ms,
                    rev_id,
                ],
            )
            .map_err(db_err)?;
        }

        tx.commit().map_err(db_err)
    }

    fn record_shared_ip_direct_host(
        &self,
        ip: Ipv4Addr,
        hostname: &str,
        now_ms: i64,
        primary_ruled: bool,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let packed = ipv4_packed(ip);
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        conn.execute(
            "INSERT INTO shared_ip_direct_hosts (ipv4_packed, hostname, last_seen, primary_ruled)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ipv4_packed, hostname) DO UPDATE SET
                 last_seen     = excluded.last_seen,
                 primary_ruled = excluded.primary_ruled",
            params![packed, host, now_ms, i64::from(primary_ruled)],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn forget_shared_ip_direct_host(&self, hostname: &str) -> StorageResult<u32> {
        let conn = self.conn.borrow();
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return Ok(0);
        }
        let removed = conn
            .execute(
                "DELETE FROM shared_ip_direct_hosts WHERE hostname = ?1",
                params![host],
            )
            .map_err(db_err)?;
        Ok(removed as u32)
    }

    fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> StorageResult<u32> {
        let conn = self.conn.borrow();
        let packed = ipv4_packed(ip);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT hostname) FROM shared_ip_direct_hosts \
                 WHERE ipv4_packed = ?1",
                params![packed],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        Ok(n.max(0) as u32)
    }

    fn shared_ip_census_ips(&self) -> StorageResult<Vec<Ipv4Addr>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare("SELECT DISTINCT ipv4_packed FROM shared_ip_direct_hosts")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .map_err(db_err)?
            .filter_map(|r| r.ok())
            .map(|packed| Ipv4Addr::from(packed as u32))
            .collect();
        Ok(rows)
    }

    fn shared_ip_census_primary_ruled_ips(&self) -> StorageResult<Vec<Ipv4Addr>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT ipv4_packed FROM shared_ip_direct_hosts \
                 WHERE primary_ruled = 1",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, i64>(0))
            .map_err(db_err)?
            .filter_map(|r| r.ok())
            .map(|packed| Ipv4Addr::from(packed as u32))
            .collect();
        Ok(rows)
    }

    fn upsert_negative_cache(&self, entry: NegativeCacheEntry) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let hash = input_hash(&entry.input);
        let created_at_ms = system_time_to_ms(entry.created_at);
        let expires_at_ms = system_time_to_ms(entry.expires_at);

        conn.execute(
            "INSERT INTO negative_cache
             (input_hash, reason, created_at, expires_at, retry_after, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(input_hash) DO UPDATE SET
                 reason      = excluded.reason,
                 created_at  = excluded.created_at,
                 expires_at  = excluded.expires_at,
                 retry_after = excluded.retry_after,
                 source      = excluded.source",
            params![
                hash,
                entry.reason.as_str(),
                created_at_ms,
                expires_at_ms,
                expires_at_ms, // retry_after = expires_at
                entry.source.as_str(),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn record_failed_resolution(
        &self,
        input: &str,
        reason: NegativeCacheReason,
        retry_after: SystemTime,
        source: StorageResolutionSource,
    ) -> StorageResult<()> {
        let now = SystemTime::now();
        self.upsert_negative_cache(NegativeCacheEntry {
            input: input.to_string(),
            reason,
            created_at: now,
            expires_at: retry_after,
            source,
        })
    }

    fn record_lookup_event(&self, event: LookupEventEntry) -> StorageResult<()> {
        let conn = self.conn.borrow();
        conn.execute(
            "INSERT INTO lookup_events
             (direction, result_state, error_code, duration_ms, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                lookup_direction_as_str(&event.direction),
                event.result_state.as_str(),
                event.error_code,
                event.duration_ms as i64,
                system_time_to_ms(event.created_at),
                system_time_to_ms(event.expires_at),
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // ── DNS refresh ──────────────────────────────────────────────────────────

    fn list_expired_resolutions(
        &self,
        now: SystemTime,
        limit: usize,
    ) -> StorageResult<Vec<ExpiredHostname>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.conn.borrow();
        let now_ms = system_time_to_ms(now);
        // Hot-first ordering: a hostname's "hotness" is `last_seen_at`,
        // i.e. the most recent successful lookup. We GROUP BY the
        // hostname to collapse multi-IP rows, then sort the bucket
        // by the hostname's own freshness rather than the per-row
        // resolution age. `source IN ('dns', 'manual_refresh')`
        // excludes `observed_from_traffic` rows — those are passive
        // observations, not DNS lookups.
        let mut stmt = conn
            .prepare(
                "SELECT h.canonical_host, MAX(h.last_seen_at)
                 FROM hostname_ip_resolutions r
                 JOIN hostnames h ON h.id = r.hostname_id
                 WHERE r.expires_at <= ?1
                   AND r.source IN ('dns', 'manual_refresh')
                 GROUP BY h.canonical_host
                 ORDER BY MAX(h.last_seen_at) DESC, h.canonical_host ASC
                 LIMIT ?2",
            )
            .map_err(db_err)?;

        let rows = stmt
            .query_map(params![now_ms, limit as i64], |r| {
                let hostname: String = r.get(0)?;
                let last_seen_ms: Option<i64> = r.get(1)?;
                Ok(ExpiredHostname {
                    canonical_hostname: hostname,
                    last_seen_at: last_seen_ms.map(ms_to_system_time),
                })
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    fn list_hostnames_under_suffix(
        &self,
        suffix: &str,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        if limit == 0 || suffix.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.conn.borrow();
        let normalised = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        // The LIKE pattern is `%.{suffix}` — `%` is "any prefix
        // including empty", but the literal `.` before the suffix
        // makes the apex (`{suffix}` itself) not match. SQLite escape
        // characters in suffix would only matter if the canonical
        // hostnames contained `%` / `_`, which they don't (lowercase
        // ASCII / punycode IDN).
        let pattern = format!("%.{normalised}");
        // Order by RECENCY, not alphabetically. The result feeds the
        // per-rule zone/suffix fan-out, which is bounded (SUFFIX_FANOUT_BACKSTOP). With
        // the old `canonical_host ASC` a busy zone (e.g. `.ru`) that exceeded the
        // cap only ever permitted the alphabetically-first N hosts, so an actively
        // visited late-alphabet host (`yandex.ru`) never earned an ALE permit and
        // was blocked by the catch-all. `last_seen_at DESC` keeps the hosts the
        // user is actually using inside the window; `canonical_host ASC` breaks
        // ties deterministically so identical-timestamp rows stay stable.
        let mut stmt = conn
            .prepare(
                "SELECT canonical_host FROM hostnames
                 WHERE canonical_host LIKE ?1
                 ORDER BY last_seen_at DESC, canonical_host ASC
                 LIMIT ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![pattern, limit as i64], |r| r.get::<_, String>(0))
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    fn list_resolutions(
        &self,
        offset: u32,
        limit: u32,
        query: &str,
    ) -> StorageResult<Vec<CacheEntryRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.conn.borrow();
        // Fetch `limit + 1` so the caller can detect a further page. The
        // deterministic `canonical_host, canonical_ip` ordering gives a
        // stable window across successive offset-based reads.
        let fetch = i64::from(limit) + 1;
        // Optional server-side filter on host/IP so a large
        // cache is searched in SQLite (WHERE LIKE) instead of drained into the
        // GUI. Always bind `?3`: an empty query becomes the wildcard `%`
        // (matches every row), so there is one SQL and one param set.
        //
        // EXACT-match by default for full hostnames/IPs: searching
        // `google.com` shows exactly that host (and only it), not every
        // `*google*` hit drowning it out. A `*` in the query is the
        // user-facing wildcard (translated to LIKE `%` AFTER escaping the
        // real metacharacters), so `*.google.com` lists the subdomains and
        // `*google*` gives substring behaviour.
        //
        // A BARE token (no `.`, no `*`) is an implicit
        // substring: nobody has a cache row whose whole hostname is `2gis`,
        // so the exact interpretation made single-word searches always come
        // back empty. Full-hostname/IP queries (they contain a dot) keep the
        // exact semantics above. Matching stays case-insensitive.
        let trimmed = query.trim();
        let like_pattern = if trimmed.is_empty() {
            "%".to_string()
        } else {
            let escaped = trimmed
                .to_lowercase()
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            if trimmed.contains('*') {
                escaped.replace('*', "%")
            } else if trimmed.contains('.') {
                escaped
            } else {
                format!("%{escaped}%")
            }
        };
        // The viewer must show EFFECTIVE freshness, not the frozen
        // stored slug. A row written `fresh` whose `expires_at` has elapsed is really
        // stale; the lookup path already recomputes this via `effective_freshness`,
        // but the viewer returned the raw column, so expired entries kept showing
        // "fresh". Recompute here against `expires_at`/now so the cache view is honest.
        let now_ms = system_time_to_ms(SystemTime::now());
        let thresholds = &self.thresholds;
        let mut stmt = conn
            .prepare(
                "SELECT h.canonical_host, i.canonical_ip, r.freshness_state, r.source,
                        r.resolved_at, r.expires_at
                 FROM hostname_ip_resolutions r
                 JOIN hostnames h ON h.id = r.hostname_id
                 JOIN ip_addresses i ON i.id = r.ip_id
                 WHERE (LOWER(h.canonical_host) LIKE ?3 ESCAPE '\\'
                        OR LOWER(i.canonical_ip) LIKE ?3 ESCAPE '\\')
                 ORDER BY h.canonical_host ASC, i.canonical_ip ASC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![fetch, i64::from(offset), like_pattern], |r| {
                let canonical_hostname: String = r.get(0)?;
                let canonical_ip: String = r.get(1)?;
                let freshness_state: String = r.get(2)?;
                let source: String = r.get(3)?;
                let resolved_at_ms: i64 = r.get(4)?;
                let expires_at_ms: i64 = r.get(5)?;
                // Recompute the display freshness (explicitly-marked stale/conflict/
                // negative states are trusted as-is by `effective_freshness`; only a
                // `fresh` row past its expiry is downgraded to stale-usable/-not-usable).
                let effective_freshness_state = FreshnessStateDb::from_str(&freshness_state)
                    .map(|stored| effective_freshness(stored, expires_at_ms, now_ms, thresholds))
                    .and_then(|st| FreshnessStateDb::from_domain(&st))
                    .map(|f| f.as_str().to_string())
                    .unwrap_or(freshness_state);
                Ok(CacheEntryRow {
                    canonical_hostname,
                    canonical_ip,
                    freshness_state: effective_freshness_state,
                    source,
                    resolved_at: ms_to_system_time(resolved_at_ms),
                    expires_at: ms_to_system_time(expires_at_ms),
                })
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    // ── Revision lifecycle ────────────────────────────────────────────────────

    fn mark_revision_stale(&self, new_active_revision_id: &str) -> StorageResult<u64> {
        let conn = self.conn.borrow();
        let rows = conn
            .execute(
                "UPDATE hostname_ip_resolutions
                 SET freshness_state = 'stale_usable'
                 WHERE freshness_state = 'fresh'
                   AND (active_revision_id IS NULL OR active_revision_id != ?1)",
                params![new_active_revision_id],
            )
            .map_err(db_err)?;
        Ok(rows as u64)
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    fn cleanup_expired(
        &self,
        now: SystemTime,
        policy: &CleanupPolicy,
    ) -> StorageResult<CleanupSummary> {
        let now_ms = system_time_to_ms(now);
        let batch = policy.batch_size as i64;
        let neg_cutoff_ms = now_ms - policy.max_negative_cache_age_secs as i64 * 1_000;
        let evt_cutoff_ms = now_ms - policy.max_lookup_event_age_secs as i64 * 1_000;

        let (expired_resolutions_removed, negative_cache_entries_removed, lookup_events_removed) = {
            let mut conn = self.conn.borrow_mut();
            let tx = conn.transaction().map_err(db_err)?;

            // Expired resolutions (in batches to avoid long locks).
            //
            // HOLD last-known-good: a DNS-sourced (rule) resolution is
            // NOT purged just because its refresh window elapsed. It is kept so
            // the leak-guard's /32 block set survives a failed re-resolution /
            // an unavailable secondary adapter, and is only dropped by a
            // 30-day backstop (a host that could not be refreshed for a month).
            // Observed-from-traffic rows remain ephemeral — they expire normally
            // so the cache does not grow with every site the user browses.
            // (A successful refresh replaces a held row in place via
            // `upsert_resolution`'s ON CONFLICT, keeping it current.)
            let held_backstop_ms = now_ms - HELD_RESOLUTION_BACKSTOP_SECS * 1_000;
            let expired_resolutions_removed: u64 = tx
                .execute(
                    "DELETE FROM hostname_ip_resolutions WHERE id IN (
                         SELECT id FROM hostname_ip_resolutions
                         WHERE expires_at < ?1
                           AND (source = 'observed_from_traffic' OR resolved_at < ?2)
                         ORDER BY id LIMIT ?3)",
                    params![now_ms, held_backstop_ms, batch],
                )
                .map_err(db_err)? as u64;

            // Orphaned parent rows (left after resolution deletion).
            tx.execute(
                "DELETE FROM hostnames
                 WHERE id NOT IN (SELECT DISTINCT hostname_id FROM hostname_ip_resolutions)",
                [],
            )
            .map_err(db_err)?;
            tx.execute(
                "DELETE FROM ip_addresses
                 WHERE id NOT IN (SELECT DISTINCT ip_id FROM hostname_ip_resolutions)",
                [],
            )
            .map_err(db_err)?;

            // Expired negative cache entries.
            let negative_cache_entries_removed: u64 = tx
                .execute(
                    "DELETE FROM negative_cache WHERE id IN (
                         SELECT id FROM negative_cache
                         WHERE expires_at < ?1 OR created_at < ?2
                         ORDER BY id LIMIT ?3)",
                    params![now_ms, neg_cutoff_ms, batch],
                )
                .map_err(db_err)? as u64;

            // Lookup events: expired first, then overflow trim.
            let lookup_events_removed: u64 = tx
                .execute(
                    "DELETE FROM lookup_events WHERE id IN (
                         SELECT id FROM lookup_events
                         WHERE expires_at < ?1 OR created_at < ?2
                         ORDER BY id LIMIT ?3)",
                    params![now_ms, evt_cutoff_ms, batch],
                )
                .map_err(db_err)? as u64;

            // Overflow trim: keep only the most recent max_lookup_events rows.
            tx.execute(
                "DELETE FROM lookup_events
                 WHERE id NOT IN (
                     SELECT id FROM lookup_events
                     ORDER BY created_at DESC
                     LIMIT ?1)",
                params![policy.max_lookup_events as i64],
            )
            .map_err(db_err)?;

            tx.commit().map_err(db_err)?;

            (
                expired_resolutions_removed,
                negative_cache_entries_removed,
                lookup_events_removed,
            )
            // `conn` (borrow_mut) is dropped here, before periodic_vacuum borrows immutably.
        };

        let vacuumed = if policy.run_vacuum {
            self.periodic_vacuum().is_ok()
        } else {
            false
        };

        Ok(CleanupSummary {
            expired_resolutions_removed,
            negative_cache_entries_removed,
            lookup_events_removed,
            vacuumed,
        })
    }

    fn clear_cache(&self, reason: CacheResetReason) -> StorageResult<CacheResetSummary> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        let now_ms = system_time_to_ms(SystemTime::now());

        // Delete child rows first, then parents.
        let resolutions_removed: u64 = tx
            .execute("DELETE FROM hostname_ip_resolutions", [])
            .map_err(db_err)? as u64;
        tx.execute("DELETE FROM hostnames", []).map_err(db_err)?;
        tx.execute("DELETE FROM ip_addresses", []).map_err(db_err)?;

        let negative_cache_removed: u64 = tx
            .execute("DELETE FROM negative_cache", [])
            .map_err(db_err)? as u64;
        let lookup_events_removed: u64 = tx
            .execute("DELETE FROM lookup_events", [])
            .map_err(db_err)? as u64;

        // Update metadata singleton (may not yet exist on very first clear).
        tx.execute(
            "INSERT INTO cache_metadata (id, schema_version, created_at, last_rebuild_at, cache_generation)
             VALUES (1, 1, ?1, ?1, 1)
             ON CONFLICT(id) DO UPDATE SET
                 last_rebuild_at   = excluded.last_rebuild_at,
                 cache_generation  = cache_generation + 1",
            params![now_ms],
        )
        .map_err(db_err)?;

        tx.commit().map_err(db_err)?;

        Ok(CacheResetSummary {
            reason,
            resolutions_removed,
            negative_cache_removed,
            lookup_events_removed,
            completed_at: SystemTime::now(),
        })
    }

    fn load_fake_ip_bindings(&self, pool_stamp: &str) -> StorageResult<Vec<(String, u32)>> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        let stored: Option<String> = tx
            .query_row(
                "SELECT stamp FROM fake_ip_pool_meta WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if stored.as_deref() != Some(pool_stamp) {
            tx.execute("DELETE FROM fake_ip_bindings", [])
                .map_err(db_err)?;
            tx.execute(
                "INSERT INTO fake_ip_pool_meta (id, stamp) VALUES (1, ?1)
                 ON CONFLICT(id) DO UPDATE SET stamp = excluded.stamp",
                params![pool_stamp],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            return Ok(Vec::new());
        }
        let bindings = {
            let mut stmt = tx
                .prepare("SELECT domain, pool_index FROM fake_ip_bindings ORDER BY touched_at ASC, pool_index ASC")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32))
                })
                .map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)?
        };
        tx.commit().map_err(db_err)?;
        Ok(bindings)
    }

    fn record_fake_ip_binding(
        &self,
        domain: &str,
        pool_index: u32,
        now_ms: i64,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        // OR REPLACE on purpose: it retires the row holding this index AND any
        // row holding this domain in one statement (both are unique).
        conn.execute(
            "INSERT OR REPLACE INTO fake_ip_bindings (pool_index, domain, touched_at)
             VALUES (?1, ?2, ?3)",
            params![i64::from(pool_index), domain, now_ms],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn remove_fake_ip_binding(&self, pool_index: u32) -> StorageResult<()> {
        let conn = self.conn.borrow();
        conn.execute(
            "DELETE FROM fake_ip_bindings WHERE pool_index = ?1",
            params![i64::from(pool_index)],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn purge_ip_range_v4(&self, start: Ipv4Addr, end: Ipv4Addr) -> StorageResult<u64> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(db_err)?;
        let (lo, hi) = (ipv4_packed(start), ipv4_packed(end));

        // Children first — the connection does not rely on FK cascades.
        let resolutions_removed: u64 = tx
            .execute(
                "DELETE FROM hostname_ip_resolutions
                 WHERE ip_id IN (
                     SELECT id FROM ip_addresses
                     WHERE ipv4_packed IS NOT NULL AND ipv4_packed BETWEEN ?1 AND ?2
                 )",
                params![lo, hi],
            )
            .map_err(db_err)? as u64;
        tx.execute(
            "DELETE FROM ip_addresses
             WHERE ipv4_packed IS NOT NULL AND ipv4_packed BETWEEN ?1 AND ?2",
            params![lo, hi],
        )
        .map_err(db_err)?;
        tx.execute(
            "DELETE FROM shared_ip_direct_hosts WHERE ipv4_packed BETWEEN ?1 AND ?2",
            params![lo, hi],
        )
        .map_err(db_err)?;
        // A hostname whose only mappings were purged carries no information —
        // drop it so lookups see a clean miss instead of an empty entry.
        tx.execute(
            "DELETE FROM hostnames
             WHERE id NOT IN (SELECT DISTINCT hostname_id FROM hostname_ip_resolutions)",
            [],
        )
        .map_err(db_err)?;

        tx.commit().map_err(db_err)?;
        Ok(resolutions_removed)
    }

    fn periodic_vacuum(&self) -> StorageResult<()> {
        let conn = self.conn.borrow();
        // WAL checkpoint with TRUNCATE mode reclaims WAL file space without a
        // full VACUUM rebuild.  Errors are non-fatal — log in production.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(db_err)
    }

    fn touch_last_rebuild_at(&self, now_ms: i64) -> StorageResult<()> {
        let conn = self.conn.borrow();
        // UPSERT: create the singleton row when it doesn't exist
        // (fresh DB, no `clear_cache` has run yet) or update the
        // existing one. `schema_version`/`created_at`/`cache_generation`
        // get sensible defaults on first insert; subsequent updates
        // touch only `last_rebuild_at`.
        conn.execute(
            "INSERT INTO cache_metadata
                 (id, schema_version, created_at, last_rebuild_at, cache_generation)
             VALUES (1, 1, ?1, ?1, 0)
             ON CONFLICT(id) DO UPDATE SET
                 last_rebuild_at = excluded.last_rebuild_at",
            params![now_ms],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn get_last_rebuild_at_ms(&self) -> StorageResult<Option<i64>> {
        let conn = self.conn.borrow();
        let v: Option<Option<i64>> = conn
            .query_row(
                "SELECT last_rebuild_at FROM cache_metadata WHERE id = 1",
                [],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(db_err)?;
        Ok(v.flatten())
    }

    fn get_cache_stats(&self) -> StorageResult<CacheStats> {
        let conn = self.conn.borrow();

        let count_one = |sql: &str| -> StorageResult<u64> {
            conn.query_row(sql, [], |r| r.get::<_, i64>(0))
                .map(|n| n.max(0) as u64)
                .map_err(db_err)
        };

        let hostname_count = count_one("SELECT COUNT(*) FROM hostnames")?;
        let ip_count = count_one("SELECT COUNT(*) FROM ip_addresses")?;
        let resolution_count = count_one("SELECT COUNT(*) FROM hostname_ip_resolutions")?;
        let stale_resolution_count = count_one(
            "SELECT COUNT(*) FROM hostname_ip_resolutions WHERE freshness_state = 'stale_usable'",
        )?;
        let negative_cache_count = count_one("SELECT COUNT(*) FROM negative_cache")?;
        let lookup_events_count = count_one("SELECT COUNT(*) FROM lookup_events")?;

        let cache_generation: u64 = conn
            .query_row(
                "SELECT cache_generation FROM cache_metadata WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(db_err)?
            .map(|n| n.max(0) as u64)
            .unwrap_or(0);

        Ok(CacheStats {
            hostname_count,
            ip_count,
            resolution_count,
            stale_resolution_count,
            negative_cache_count,
            lookup_events_count,
            cache_generation,
        })
    }

    fn check_cache_integrity(&self) -> StorageResult<(IntegrityCheckResult, RecoveryAction)> {
        let conn = self.conn.borrow();
        let check: String = conn
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(db_err)?;
        if check == "ok" {
            Ok((IntegrityCheckResult::Ok, RecoveryAction::None))
        } else {
            Ok((
                IntegrityCheckResult::CacheCorruptRebuildable,
                RecoveryAction::RebuildCache,
            ))
        }
    }
}

// ── SqliteStateStore ──────────────────────────────────────────────────────────

/// SQLite-backed implementation of [`RevisionMetadataRepository`].
///
/// Owns one connection to `nrr_service_state.db`.
pub struct SqliteStateStore {
    conn: RefCell<Connection>,
}

impl SqliteStateStore {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
        }
    }

    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }
}

impl RevisionMetadataRepository for SqliteStateStore {
    fn get_active_revision(&self) -> StorageResult<Option<RevisionId>> {
        let conn = self.conn.borrow();
        let raw: Option<String> = conn
            .query_row(
                "SELECT revision_id FROM active_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        raw.map(RevisionId::from_prefixed_string)
            .transpose()
            .map_err(|e| StorageError::Internal(format!("parse active revision: {e}")))
    }

    fn set_active_revision(&self, revision_id: &RevisionId) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let hash = integrity::compute_revision_hash(revision_id.as_str());
        conn.execute(
            "INSERT INTO active_revision (id, revision_id, activated_at, integrity_hash)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                 revision_id      = excluded.revision_id,
                 activated_at     = excluded.activated_at,
                 integrity_hash   = excluded.integrity_hash,
                 last_verified_at = NULL",
            params![
                revision_id.as_str(),
                system_time_to_ms(SystemTime::now()),
                hash
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn get_last_known_good(&self) -> StorageResult<Option<RevisionId>> {
        let conn = self.conn.borrow();
        let raw: Option<String> = conn
            .query_row(
                "SELECT revision_id FROM last_known_good WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        raw.map(RevisionId::from_prefixed_string)
            .transpose()
            .map_err(|e| StorageError::Internal(format!("parse LKG revision: {e}")))
    }

    fn set_last_known_good(&self, revision_id: &RevisionId) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let hash = integrity::compute_revision_hash(revision_id.as_str());
        conn.execute(
            "INSERT INTO last_known_good (id, revision_id, promoted_at, integrity_hash)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                 revision_id    = excluded.revision_id,
                 promoted_at    = excluded.promoted_at,
                 integrity_hash = excluded.integrity_hash",
            params![
                revision_id.as_str(),
                system_time_to_ms(SystemTime::now()),
                hash
            ],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn check_integrity(&self) -> StorageResult<(IntegrityCheckResult, RecoveryAction)> {
        let conn = self.conn.borrow();

        // 1. SQLite structural integrity.
        let check: String = conn
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(db_err)?;
        if check != "ok" {
            return Ok((
                IntegrityCheckResult::PolicyIntegrityFailed { details: check },
                RecoveryAction::FallbackToLastKnownGood,
            ));
        }

        // 2. Validate active revision format and hash (if present).
        let active_row: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT revision_id, integrity_hash FROM active_revision WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        let active_id = if let Some((raw, stored_hash)) = &active_row {
            // 2a. Format check.
            if RevisionId::from_prefixed_string(raw.clone()).is_err() {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("active revision has invalid format: {raw:?}"),
                    },
                    RecoveryAction::FallbackToLastKnownGood,
                ));
            }
            // 2b. Hash verification (only when hash was written by v2+ schema).
            if let Some(h) = stored_hash {
                if !integrity::verify_revision_hash(raw, h) {
                    return Ok((
                        IntegrityCheckResult::PolicyIntegrityFailed {
                            details: format!("active revision integrity_hash mismatch for {raw:?}"),
                        },
                        RecoveryAction::FallbackToLastKnownGood,
                    ));
                }
            }
            Some(raw.clone())
        } else {
            None
        };

        // 3. Check LKG presence and hash when an active revision is set.
        let lkg_row: Option<(String, Option<String>)> = conn
            .query_row(
                "SELECT revision_id, integrity_hash FROM last_known_good WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        if active_id.is_some() && lkg_row.is_none() {
            // LKG missing — not a hard failure on first start, but service cannot
            // fall back safely. The service layer should record
            // IntegrityFailureKind::MissingLastKnownGood in its health state and
            // escalate if a rollback is actually needed.
            return Ok((IntegrityCheckResult::Ok, RecoveryAction::None));
        }

        // 4. Verify LKG hash (if present).
        if let Some((lkg_id, Some(h))) = &lkg_row {
            if !integrity::verify_revision_hash(lkg_id, h) {
                return Ok((
                    IntegrityCheckResult::PolicyIntegrityFailed {
                        details: format!("last_known_good integrity_hash mismatch for {lkg_id:?}"),
                    },
                    RecoveryAction::RequireUserAction(
                        "LKG revision hash mismatch — fallback target may be corrupt".to_string(),
                    ),
                ));
            }
        }

        Ok((IntegrityCheckResult::Ok, RecoveryAction::None))
    }

    fn record_integrity_check(
        &self,
        result: &IntegrityCheckResult,
        checked_at: SystemTime,
    ) -> StorageResult<()> {
        let conn = self.conn.borrow();
        let (result_str, detail) = integrity_result_text(result);
        conn.execute(
            "INSERT INTO integrity_log (result, detail, checked_at) VALUES (?1, ?2, ?3)",
            params![result_str, detail, system_time_to_ms(checked_at)],
        )
        .map_err(db_err)?;
        Ok(())
    }

    fn get_integrity_status(&self) -> StorageResult<IntegrityStatus> {
        let conn = self.conn.borrow();
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT result, checked_at FROM integrity_log ORDER BY checked_at DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        let (state_db, last_verified_at) = match row {
            Some((result_str, checked_at_ms)) => {
                let state = match result_str.as_str() {
                    "ok" => DbIntegrityState::Ok,
                    "cache_corrupt" => DbIntegrityState::CacheCorruptRebuildable,
                    "policy_failed" => DbIntegrityState::PolicyIntegrityFailed,
                    "unsupported" => DbIntegrityState::UnsupportedSchema,
                    _ => DbIntegrityState::Unavailable,
                };
                (state, Some(ms_to_system_time(checked_at_ms)))
            }
            None => (DbIntegrityState::Ok, None),
        };

        Ok(IntegrityStatus {
            cache_db: DbIntegrityState::Ok, // filled by CacheRepository side
            state_db,
            last_verified_at,
        })
    }
}

impl StorageHealthChecker for SqliteCacheStore {
    fn check_health(&self) -> StorageResult<StorageHealthStatus> {
        let conn = self.conn.borrow();
        let now = SystemTime::now();

        // Schema version — always present after migration.
        let schema_version: Option<i64> = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;

        let last_migration_ms: Option<i64> = conn
            .query_row("SELECT MAX(applied_at) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        // cache_metadata singleton — may not exist on a fresh DB before the first
        // clear/rebuild, so fall back to NULL for all optional columns.
        let meta: Option<(Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT last_cleanup_at, last_rebuild_at FROM cache_metadata WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        let (last_cleanup_ms, last_rebuild_ms) = meta.unwrap_or((None, None));

        let cache_db = DbHealthStatus {
            path_exists: true,
            schema_version: schema_version.map(|v| v as u32),
            last_migration_at: last_migration_ms.map(ms_to_system_time),
            last_integrity_check_at: None, // populated by the integrity flow
            last_cleanup_at: last_cleanup_ms.map(ms_to_system_time),
            // Propagate cache rebuild timestamp from the singleton row.
            // `None` means the cache has not been explicitly rebuilt or
            // DNS-refreshed yet (fresh install or no warm-up writes).
            last_rebuild_at: last_rebuild_ms.map(ms_to_system_time),
            overall: OverallHealthState::Healthy,
        };

        Ok(StorageHealthStatus {
            cache_db,
            state_db: DbHealthStatus {
                path_exists: true,
                schema_version: None,
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            checked_at: now,
        })
    }
}

impl StorageHealthChecker for SqliteStateStore {
    fn check_health(&self) -> StorageResult<StorageHealthStatus> {
        let conn = self.conn.borrow();
        let now = SystemTime::now();

        let schema_version: Option<i64> = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;

        let last_migration_ms: Option<i64> = conn
            .query_row("SELECT MAX(applied_at) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        let last_check_ms: Option<i64> = conn
            .query_row("SELECT MAX(checked_at) FROM integrity_log", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        let state_db = DbHealthStatus {
            path_exists: true,
            schema_version: schema_version.map(|v| v as u32),
            last_migration_at: last_migration_ms.map(ms_to_system_time),
            last_integrity_check_at: last_check_ms.map(ms_to_system_time),
            last_cleanup_at: None,
            last_rebuild_at: None,
            overall: OverallHealthState::Healthy,
        };

        Ok(StorageHealthStatus {
            cache_db: DbHealthStatus {
                path_exists: true,
                schema_version: None,
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            state_db,
            checked_at: now,
        })
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn db_err(e: rusqlite::Error) -> StorageError {
    StorageError::Internal(e.to_string())
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn ms_to_system_time(ms: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms.max(0) as u64)
}

fn ipv4_packed(ip: Ipv4Addr) -> i64 {
    u32::from(ip) as i64
}

/// FNV-1a 64-bit hash of an input string — used to store hostname/IP lookup
/// keys without persisting raw values.
fn input_hash(input: &str) -> String {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h = OFFSET;
    for b in input.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("{h:016x}")
}

/// Recomputes the effective freshness of a cache entry at query time.
///
/// The stored `freshness_state` may have been set to `stale_usable` by a
/// revision change.  For entries still recorded as `fresh`, we re-evaluate
/// against `expires_at` and the current clock.
fn effective_freshness(
    stored: FreshnessStateDb,
    expires_at_ms: i64,
    now_ms: i64,
    thresholds: &FreshnessThresholds,
) -> CacheEntryState {
    match stored {
        FreshnessStateDb::Fresh => {
            if expires_at_ms > now_ms {
                CacheEntryState::Fresh
            } else {
                let beyond_secs = (now_ms - expires_at_ms) / 1_000;
                if beyond_secs <= thresholds.stale_usable_max_age_secs as i64 {
                    CacheEntryState::StaleUsable
                } else {
                    CacheEntryState::StaleNotUsable
                }
            }
        }
        // Explicitly marked states (revision change, conflict, etc.) are trusted.
        FreshnessStateDb::StaleUsable => CacheEntryState::StaleUsable,
        FreshnessStateDb::StaleNotUsable => CacheEntryState::StaleNotUsable,
        FreshnessStateDb::Conflicting => CacheEntryState::Conflicting,
        FreshnessStateDb::NegativeCached => CacheEntryState::NegativeCached,
    }
}

/// Selects the best IP from resolved cache entries for ExactIp matching.
///
/// Preference order: Fresh > StaleUsable; Dns/ManualRefresh > ObservedFromTraffic.
/// Falls back to `observed_ip` (from WFP traffic) if no usable cache entry exists.
fn select_best_ip(
    entries: &[CachedIpEntry],
    observed_ip: Option<Ipv4Addr>,
    strategy: CachePriorityStrategy,
) -> Option<ResolvedAddressEntry> {
    let best = entries
        .iter()
        .filter(|e| e.cache_state.is_usable_for_matching())
        .max_by_key(|e| {
            let f = match &e.cache_state {
                CacheEntryState::Fresh => 2u8,
                CacheEntryState::StaleUsable => 1,
                _ => 0,
            };
            // Freshness dominates; the user's cache-priority strategy decides
            // the source tie-break. `FreshestFirst` (default) reproduces the
            // pre-0719 ordering.
            let s = strategy.selection_rank(&e.source);
            (f, s)
        });

    if let Some(e) = best {
        return Some(ResolvedAddressEntry {
            addr: e.addr,
            cache_state: e.cache_state.clone(),
            source: e.source.to_lookup_source(),
            resolved_at: e.resolved_at,
            ttl_seconds: e.ttl_seconds,
        });
    }

    // No usable cache entry — use the IP observed directly from WFP traffic.
    observed_ip.map(|ip| ResolvedAddressEntry {
        addr: ip,
        cache_state: CacheEntryState::Missing,
        source: LookupSource::ObservedFromTraffic,
        resolved_at: None,
        ttl_seconds: None,
    })
}

/// Returns the most-fresh state across all resolved IP entries.
fn best_freshness(entries: &[CachedIpEntry]) -> Option<CacheEntryState> {
    entries
        .iter()
        .max_by_key(|e| match &e.cache_state {
            CacheEntryState::Fresh => 4u8,
            CacheEntryState::StaleUsable => 3,
            CacheEntryState::Conflicting => 2,
            CacheEntryState::NegativeCached => 1,
            CacheEntryState::StaleNotUsable => 0,
            CacheEntryState::Missing => 0,
        })
        .map(|e| e.cache_state.clone())
}

/// Returns the highest-priority source across all resolved IP entries, ranked
/// by the user's cache-priority `strategy` (`FreshestFirst` reproduces the
/// pre-0719 `Dns > ManualRefresh > ObservedFromTraffic > OsCacheSeed >
/// ImportedSeed > CacheRebuild` order).
fn best_source_of(
    entries: &[CachedIpEntry],
    strategy: CachePriorityStrategy,
) -> Option<StorageResolutionSource> {
    entries
        .iter()
        .max_by_key(|e| strategy.report_rank(&e.source))
        .map(|e| e.source.clone())
}

/// Converts an `IntegrityCheckResult` to a `(result_text, detail)` pair for
/// storage in `integrity_log`.
fn integrity_result_text(result: &IntegrityCheckResult) -> (&'static str, Option<String>) {
    match result {
        IntegrityCheckResult::Ok => ("ok", None),
        IntegrityCheckResult::CacheCorruptRebuildable => ("cache_corrupt", None),
        IntegrityCheckResult::PolicyIntegrityFailed { details } => {
            ("policy_failed", Some(details.clone()))
        }
        IntegrityCheckResult::UnsupportedSchemaVersion {
            found,
            max_supported,
        } => (
            "unsupported",
            Some(format!("found={found} max={max_supported}")),
        ),
        IntegrityCheckResult::StorageUnavailable(msg) => ("unavailable", Some(msg.clone())),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn migrated_cache_store(dir: &tempfile::TempDir) -> SqliteCacheStore {
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        )
    }

    /// Short-TTL thresholds for exercising the expiry MECHANISM. Production
    /// defaults hold entries for a week (leak-guard stickiness), so
    /// mechanism tests that assert "expired after an hour" build the store with
    /// a small `fallback_ttl_secs` floor instead.
    fn short_ttl_thresholds() -> FreshnessThresholds {
        FreshnessThresholds {
            fresh_max_age_secs: 300,
            stale_usable_max_age_secs: 3_600,
            fallback_ttl_secs: 10,
            negative_ttl_secs: 30,
        }
    }

    fn migrated_cache_store_short_ttl(dir: &tempfile::TempDir) -> SqliteCacheStore {
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        SqliteCacheStore::new(runner.into_connection(), short_ttl_thresholds())
    }

    fn migrated_state_store(dir: &tempfile::TempDir) -> SqliteStateStore {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        SqliteStateStore::new(runner.into_connection())
    }

    fn sample_resolution(hostname: &str, ip: Ipv4Addr) -> ResolutionEntry {
        ResolutionEntry {
            canonical_hostname: hostname.to_string(),
            raw_hostname_sample: None,
            resolved_ips: vec![ip],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: SystemTime::now(),
            active_revision_id: Some("rev-test-001".to_string()),
        }
    }

    // ── upsert + get_by_hostname ──────────────────────────────────────────────

    #[test]
    fn upsert_and_get_by_hostname() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        store
            .upsert_resolution(sample_resolution("example.com", ip))
            .expect("upsert");

        let result = store
            .get_by_hostname(
                "example.com",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert_eq!(result.resolved_ips.len(), 1);
        assert_eq!(result.resolved_ips[0].addr, ip);
        assert_eq!(result.resolved_ips[0].cache_state, CacheEntryState::Fresh);
        assert_eq!(result.resolved_ips[0].source, StorageResolutionSource::Dns);
        assert!(!result.is_multi_ip);
        assert!(!result.has_conflict);
    }

    #[test]
    fn get_by_hostname_missing_returns_empty() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        let result = store
            .get_by_hostname(
                "nxdomain.example",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert!(result.resolved_ips.is_empty());
        assert!(result.overall_freshness.is_none());
    }

    #[test]
    fn upsert_multi_ip_hostname() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip1 = Ipv4Addr::new(1, 1, 1, 1);
        let ip2 = Ipv4Addr::new(1, 0, 0, 1);

        let entry = ResolutionEntry {
            canonical_hostname: "cloudflare.com".to_string(),
            raw_hostname_sample: None,
            resolved_ips: vec![ip1, ip2],
            ttl_seconds: Some(60),
            source: StorageResolutionSource::Dns,
            resolved_at: SystemTime::now(),
            active_revision_id: None,
        };
        store.upsert_resolution(entry).expect("upsert");

        let result = store
            .get_by_hostname(
                "cloudflare.com",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert_eq!(result.resolved_ips.len(), 2);
        assert!(result.is_multi_ip);
    }

    #[test]
    fn upsert_updates_existing_entry() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        store
            .upsert_resolution(sample_resolution("host.local", ip))
            .expect("first");
        // Second upsert with a different TTL — should update, not duplicate.
        let entry2 = ResolutionEntry {
            ttl_seconds: Some(600),
            ..sample_resolution("host.local", ip)
        };
        store.upsert_resolution(entry2).expect("second");

        let result = store
            .get_by_hostname(
                "host.local",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        // Still one entry (same hostname/ip/source triple).
        assert_eq!(result.resolved_ips.len(), 1);
        assert_eq!(result.resolved_ips[0].ttl_seconds, Some(600));
    }

    // ── get_by_ip ─────────────────────────────────────────────────────────────

    #[test]
    fn get_by_ip_finds_hostname() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip = Ipv4Addr::new(8, 8, 8, 8);

        store
            .upsert_resolution(sample_resolution("dns.google", ip))
            .expect("upsert");

        let result = store
            .get_by_ip(ip, &FreshnessThresholds::default_production())
            .expect("get_by_ip");
        assert_eq!(result.reverse_hostnames.len(), 1);
        assert_eq!(result.reverse_hostnames[0].hostname, "dns.google");
    }

    // ── mark_revision_stale ───────────────────────────────────────────────────

    #[test]
    fn mark_revision_stale_transitions_fresh_entries() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // Write with rev-001.
        store
            .upsert_resolution(sample_resolution("host.example", Ipv4Addr::new(1, 2, 3, 4)))
            .expect("upsert");

        // Activate rev-002 — entries from rev-001 should become stale_usable.
        let updated = store.mark_revision_stale("rev-002").expect("mark");
        assert_eq!(updated, 1);

        let result = store
            .get_by_hostname(
                "host.example",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert_eq!(
            result.resolved_ips[0].cache_state,
            CacheEntryState::StaleUsable
        );
    }

    #[test]
    fn mark_revision_stale_skips_same_revision() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store
            .upsert_resolution(sample_resolution("h.example", Ipv4Addr::new(5, 6, 7, 8)))
            .expect("upsert");

        // "New" revision is the same as the one used for writing — no rows updated.
        let updated = store.mark_revision_stale("rev-test-001").expect("mark");
        assert_eq!(updated, 0);
    }

    // ── negative cache ────────────────────────────────────────────────────────

    #[test]
    fn negative_cache_blocks_hostname_lookup() {
        use crate::dto::NegativeCacheReason;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        let now = SystemTime::now();
        store
            .upsert_negative_cache(NegativeCacheEntry {
                input: "nxdomain.test".to_string(),
                reason: NegativeCacheReason::NxDomain,
                created_at: now,
                expires_at: now + std::time::Duration::from_secs(30),
                source: StorageResolutionSource::Dns,
            })
            .expect("neg upsert");

        let result = store
            .get_by_hostname(
                "nxdomain.test",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert!(result.resolved_ips.is_empty());
        assert_eq!(
            result.overall_freshness,
            Some(CacheEntryState::NegativeCached)
        );
    }

    // ── record_lookup_event ───────────────────────────────────────────────────

    #[test]
    fn record_lookup_event_inserts_row() {
        use crate::dto::LookupResultState;
        use nrr_domain::decision_lookup::LookupDirection;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        store
            .record_lookup_event(LookupEventEntry {
                direction: LookupDirection::HostnameToIp,
                result_state: LookupResultState::Hit,
                error_code: None,
                duration_ms: 5,
                created_at: now,
                expires_at: now + std::time::Duration::from_secs(3600),
            })
            .expect("record");

        let conn = store.into_connection();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM lookup_events", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 1);
    }

    // ── clear_cache ───────────────────────────────────────────────────────────

    #[test]
    fn clear_cache_removes_all_data() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store
            .upsert_resolution(sample_resolution("h1.example", Ipv4Addr::new(1, 1, 1, 1)))
            .expect("upsert");
        store
            .upsert_resolution(sample_resolution("h2.example", Ipv4Addr::new(2, 2, 2, 2)))
            .expect("upsert");

        let summary = store
            .clear_cache(CacheResetReason::ManualUserReset)
            .expect("clear");
        assert!(summary.resolutions_removed >= 2);

        let result = store
            .get_by_hostname(
                "h1.example",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert!(result.resolved_ips.is_empty());
    }

    #[test]
    fn fake_ip_bindings_roundtrip_and_stamp_wipe() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // First load stores the stamp and returns nothing.
        assert!(store
            .load_fake_ip_bindings("v4=198.18.0.0/15")
            .expect("load")
            .is_empty());
        store
            .record_fake_ip_binding("old.example", 2, 100)
            .expect("record");
        store
            .record_fake_ip_binding("new.example", 3, 200)
            .expect("record");
        assert_eq!(
            store
                .load_fake_ip_bindings("v4=198.18.0.0/15")
                .expect("load"),
            vec![
                ("old.example".to_string(), 2),
                ("new.example".to_string(), 3)
            ]
        );

        // Re-dealing the index replaces the old domain; re-dealing the domain
        // replaces the old index.
        store
            .record_fake_ip_binding("taken.example", 2, 300)
            .expect("record");
        store
            .record_fake_ip_binding("new.example", 7, 400)
            .expect("record");
        assert_eq!(
            store
                .load_fake_ip_bindings("v4=198.18.0.0/15")
                .expect("load"),
            vec![
                ("taken.example".to_string(), 2),
                ("new.example".to_string(), 7)
            ]
        );

        store.remove_fake_ip_binding(2).expect("remove");
        assert_eq!(
            store
                .load_fake_ip_bindings("v4=198.18.0.0/15")
                .expect("load"),
            vec![("new.example".to_string(), 7)]
        );

        // A different pool stamp wipes the table.
        assert!(store
            .load_fake_ip_bindings("v4=10.0.0.0/8")
            .expect("load")
            .is_empty());
        assert!(store
            .load_fake_ip_bindings("v4=10.0.0.0/8")
            .expect("load")
            .is_empty());
    }

    #[test]
    fn forgetting_a_census_host_stops_its_ips_counting_as_shared() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip = Ipv4Addr::new(157, 240, 0, 63);
        store
            .record_shared_ip_direct_host(ip, "static.cdninstagram.com", 1, false)
            .expect("census");
        store
            .record_shared_ip_direct_host(ip, "unrelated.example", 1, false)
            .expect("census");
        assert_eq!(store.direct_host_count_for_ip(ip).expect("count"), 2);

        // The trailing dot and the case are what a resolver hands us.
        let removed = store
            .forget_shared_ip_direct_host("Static.CDNInstagram.com.")
            .expect("forget");
        assert_eq!(removed, 1);
        assert_eq!(
            store.direct_host_count_for_ip(ip).expect("count"),
            1,
            "the other tenant still keeps the IP shared"
        );
        // Idempotent: a host that left the census is not an error.
        assert_eq!(
            store
                .forget_shared_ip_direct_host("static.cdninstagram.com")
                .expect("forget"),
            0
        );
    }

    #[test]
    fn purge_ip_range_v4_removes_only_the_range() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store
            .upsert_resolution(sample_resolution(
                "fake.example",
                Ipv4Addr::new(198, 18, 0, 35),
            ))
            .expect("upsert");
        store
            .upsert_resolution(sample_resolution(
                "real.example",
                Ipv4Addr::new(93, 184, 216, 34),
            ))
            .expect("upsert");
        store
            .record_shared_ip_direct_host(Ipv4Addr::new(198, 19, 1, 2), "victim.example", 1, false)
            .expect("census");
        store
            .record_shared_ip_direct_host(Ipv4Addr::new(8, 8, 8, 8), "kept.example", 1, false)
            .expect("census");

        let removed = store
            .purge_ip_range_v4(
                Ipv4Addr::new(198, 18, 0, 0),
                Ipv4Addr::new(198, 19, 255, 255),
            )
            .expect("purge");
        assert_eq!(removed, 1);

        let purged = store
            .get_by_hostname(
                "fake.example",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert!(purged.resolved_ips.is_empty());
        let kept = store
            .get_by_hostname(
                "real.example",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("get");
        assert_eq!(kept.resolved_ips.len(), 1);
        assert_eq!(
            store
                .direct_host_count_for_ip(Ipv4Addr::new(198, 19, 1, 2))
                .expect("count"),
            0
        );
        assert_eq!(
            store
                .direct_host_count_for_ip(Ipv4Addr::new(8, 8, 8, 8))
                .expect("count"),
            1
        );
    }

    // ── build_lookup_envelope ─────────────────────────────────────────────────

    #[test]
    fn build_lookup_envelope_returns_lookup_result() {
        use nrr_domain::decision_lookup::LookupDirection;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let ip = Ipv4Addr::new(93, 184, 216, 34);

        store
            .upsert_resolution(sample_resolution("example.com", ip))
            .expect("upsert");

        let request = CacheLookupRequest {
            hostname: Some("example.com".to_string()),
            observed_ip: Some(ip),
            direction: LookupDirection::Both,
            active_revision_id: None,
            requested_at: SystemTime::now(),
        };
        let result = store
            .build_lookup_envelope(
                &request,
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("envelope");

        assert!(result.selected_ip.is_some());
        assert_eq!(result.selected_ip.unwrap().addr, ip);
        assert!(result.explain_data.standard.cache_hit);
        assert!(!result.has_conflict);
    }

    #[test]
    fn build_lookup_envelope_conflict_detected() {
        use nrr_domain::decision_lookup::LookupDirection;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let cached_ip = Ipv4Addr::new(1, 2, 3, 4);
        let observed_ip = Ipv4Addr::new(5, 6, 7, 8); // different from cached

        store
            .upsert_resolution(sample_resolution("conflict.example", cached_ip))
            .expect("upsert");

        let request = CacheLookupRequest {
            hostname: Some("conflict.example".to_string()),
            observed_ip: Some(observed_ip),
            direction: LookupDirection::Both,
            active_revision_id: None,
            requested_at: SystemTime::now(),
        };
        let result = store
            .build_lookup_envelope(
                &request,
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("envelope");

        assert!(
            result.has_conflict,
            "observed IP not in cached set should be a conflict"
        );
    }

    // ── SqliteStateStore ──────────────────────────────────────────────────────

    #[test]
    fn state_store_set_and_get_active_revision() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-abc-001".to_string()).expect("rev");

        store.set_active_revision(&rev).expect("set");
        let got = store.get_active_revision().expect("get");
        assert_eq!(got.unwrap().as_str(), "rev-abc-001");
    }

    #[test]
    fn state_store_get_active_revision_none_on_fresh_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let got = store.get_active_revision().expect("get");
        assert!(got.is_none());
    }

    #[test]
    fn state_store_set_and_get_lkg() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-lkg-001".to_string()).expect("rev");

        store.set_last_known_good(&rev).expect("set");
        let got = store.get_last_known_good().expect("get");
        assert_eq!(got.unwrap().as_str(), "rev-lkg-001");
    }

    #[test]
    fn state_store_check_integrity_ok_on_fresh_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let (result, action) = store.check_integrity().expect("check");
        assert_eq!(result, IntegrityCheckResult::Ok);
        assert_eq!(action, RecoveryAction::None);
    }

    #[test]
    fn state_store_record_and_get_integrity_status() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let now = SystemTime::now();

        store
            .record_integrity_check(&IntegrityCheckResult::Ok, now)
            .expect("record");

        let status = store.get_integrity_status().expect("status");
        assert_eq!(status.state_db, DbIntegrityState::Ok);
        assert!(status.last_verified_at.is_some());
    }

    #[test]
    fn state_store_set_active_overrides_previous() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);

        let r1 = RevisionId::from_prefixed_string("rev-v1".to_string()).expect("r1");
        let r2 = RevisionId::from_prefixed_string("rev-v2".to_string()).expect("r2");

        store.set_active_revision(&r1).expect("set r1");
        store.set_active_revision(&r2).expect("set r2");

        let got = store.get_active_revision().expect("get");
        assert_eq!(got.unwrap().as_str(), "rev-v2");
    }

    // ── cleanup, vacuum, cache_generation ───────────────────────────────────

    #[test]
    fn cleanup_expired_removes_expired_resolutions() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // Insert a resolution that is already expired (expires_at in the past).
        let far_past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        {
            let conn = store.conn.borrow();
            // Seed hostname + ip rows.
            conn.execute(
                "INSERT INTO hostnames (canonical_host, first_seen_at, last_seen_at) VALUES ('old.example', 0, 0)",
                [],
            ).expect("hostname");
            conn.execute(
                "INSERT INTO ip_addresses (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at) VALUES ('ipv4', '9.9.9.9', 151587081, 0, 0)",
                [],
            ).expect("ip");
            conn.execute(
                "INSERT INTO hostname_ip_resolutions
                 (hostname_id, ip_id, source, ttl_seconds, resolved_at, expires_at, freshness_state)
                 VALUES (1, 1, 'dns', 60, 0, ?1, 'fresh')",
                rusqlite::params![system_time_to_ms(far_past)],
            )
            .expect("resolution");
        }

        let policy = crate::dto::CleanupPolicy {
            run_vacuum: false,
            ..Default::default()
        };
        let summary = store
            .cleanup_expired(SystemTime::now(), &policy)
            .expect("cleanup");
        assert_eq!(summary.expired_resolutions_removed, 1);

        // Hostname and IP rows should also be gone (orphan cleanup).
        let conn = store.into_connection();
        let h_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
            .expect("h");
        let ip_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ip_addresses", [], |r| r.get(0))
            .expect("ip");
        assert_eq!(h_count, 0);
        assert_eq!(ip_count, 0);
    }

    #[test]
    fn cleanup_expired_removes_stale_negative_cache() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // Insert expired negative cache entry.
        let far_past = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO negative_cache (input_hash, reason, created_at, expires_at, retry_after, source)
                 VALUES ('deadbeef00000001', 'nxdomain', ?1, ?1, ?1, 'dns')",
                rusqlite::params![system_time_to_ms(far_past)],
            ).expect("neg insert");
        }

        let policy = crate::dto::CleanupPolicy {
            max_negative_cache_age_secs: 10, // 10 s — far_past is >> 10 s old
            run_vacuum: false,
            ..Default::default()
        };
        let summary = store
            .cleanup_expired(SystemTime::now(), &policy)
            .expect("cleanup");
        assert_eq!(summary.negative_cache_entries_removed, 1);
    }

    #[test]
    fn cleanup_expired_with_vacuum_does_not_error() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let policy = crate::dto::CleanupPolicy {
            run_vacuum: true,
            ..Default::default()
        };
        let summary = store
            .cleanup_expired(SystemTime::now(), &policy)
            .expect("cleanup");
        assert!(
            summary.vacuumed,
            "vacuumed should be true when run_vacuum = true"
        );
    }

    #[test]
    fn clear_cache_increments_cache_generation() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store
            .upsert_resolution(sample_resolution("h.example", Ipv4Addr::new(1, 2, 3, 4)))
            .expect("upsert");
        store
            .clear_cache(CacheResetReason::ManualUserReset)
            .expect("clear1");
        store
            .upsert_resolution(sample_resolution("h2.example", Ipv4Addr::new(5, 6, 7, 8)))
            .expect("upsert2");
        store
            .clear_cache(CacheResetReason::ManualUserReset)
            .expect("clear2");

        let gen: i64 = {
            let conn = store.conn.borrow();
            conn.query_row(
                "SELECT cache_generation FROM cache_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("gen")
        };
        assert_eq!(gen, 2, "two clears should yield cache_generation = 2");
    }

    #[test]
    fn cleanup_lookup_events_removes_overflow() {
        use crate::dto::{LookupEventEntry, LookupResultState};
        use nrr_domain::decision_lookup::LookupDirection;
        use std::time::Duration;

        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();
        let far_future = now + Duration::from_secs(86_400);

        // Insert 5 lookup events with a far-future expires_at.
        for _ in 0..5 {
            store
                .record_lookup_event(LookupEventEntry {
                    direction: LookupDirection::HostnameToIp,
                    result_state: LookupResultState::Hit,
                    error_code: None,
                    duration_ms: 1,
                    created_at: now,
                    expires_at: far_future,
                })
                .expect("record");
        }

        // Cleanup with max_lookup_events = 3 — overflow trim should remove 2.
        let policy = crate::dto::CleanupPolicy {
            max_lookup_events: 3,
            run_vacuum: false,
            ..Default::default()
        };
        store.cleanup_expired(now, &policy).expect("cleanup");

        let conn = store.into_connection();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM lookup_events", [], |r| r.get(0))
            .expect("count");
        assert!(
            count <= 3,
            "overflow trim must leave at most max_lookup_events rows, got {count}"
        );
    }

    #[test]
    fn cache_store_check_health_returns_schema_version() {
        use crate::repository::StorageHealthChecker;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let health = store.check_health().expect("health");
        assert_eq!(health.cache_db.schema_version, Some(4));
        assert!(health.cache_db.path_exists);
        assert!(health.cache_db.last_migration_at.is_some());
    }

    #[test]
    fn cache_store_check_health_records_last_cleanup_after_clear() {
        use crate::repository::StorageHealthChecker;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // Before clear, no metadata row → last_cleanup_at is None.
        let health_before = store.check_health().expect("health before");
        assert!(health_before.cache_db.last_cleanup_at.is_none());

        // clear_cache sets last_rebuild_at and cache_generation in cache_metadata.
        store
            .clear_cache(CacheResetReason::ManualUserReset)
            .expect("clear");

        // After clear, cache_metadata row exists; cleanup path still None (only
        // cleanup_expired sets last_cleanup_at — that's a future migration step).
        // Verify schema_version is still reported correctly.
        let health_after = store.check_health().expect("health after");
        assert_eq!(health_after.cache_db.schema_version, Some(4));
    }

    #[test]
    fn cache_store_touch_last_rebuild_at_creates_singleton_on_fresh_db() {
        use crate::repository::CacheRepository;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        // No singleton row on a fresh DB.
        assert_eq!(
            store.get_last_rebuild_at_ms().expect("get"),
            None,
            "fresh DB must have no last_rebuild_at"
        );

        store
            .touch_last_rebuild_at(1_700_000_000_000)
            .expect("touch");

        assert_eq!(
            store.get_last_rebuild_at_ms().expect("get"),
            Some(1_700_000_000_000)
        );
    }

    #[test]
    fn cache_store_touch_last_rebuild_at_updates_existing_singleton() {
        use crate::repository::CacheRepository;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store.touch_last_rebuild_at(1_000).expect("touch 1");
        store.touch_last_rebuild_at(2_000).expect("touch 2");
        assert_eq!(store.get_last_rebuild_at_ms().expect("get"), Some(2_000));
    }

    #[test]
    fn cache_store_touch_last_rebuild_at_surfaces_in_health_status() {
        use crate::repository::{CacheRepository, StorageHealthChecker};
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);

        store
            .touch_last_rebuild_at(1_700_000_000_000)
            .expect("touch");
        let health = store.check_health().expect("health");
        assert!(
            health.cache_db.last_rebuild_at.is_some(),
            "last_rebuild_at must be propagated to StorageHealthStatus"
        );
    }

    // ── integrity checks ─────────────────────────────────────────────────────

    #[test]
    fn state_store_integrity_hash_stored_on_set_active_revision() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-hash-001".to_string()).expect("rev");

        store.set_active_revision(&rev).expect("set");

        let stored_hash: Option<String> = {
            let conn = store.conn.borrow();
            conn.query_row(
                "SELECT integrity_hash FROM active_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("query")
        };
        assert!(stored_hash.is_some(), "integrity_hash must be written");
        let h = stored_hash.unwrap();
        assert_eq!(h.len(), 64, "SHA-256 hex must be 64 chars");
        assert!(
            crate::integrity::verify_revision_hash("rev-hash-001", &h),
            "stored hash must verify against the revision id"
        );
    }

    #[test]
    fn state_store_integrity_hash_stored_on_set_lkg() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-lkg-hash".to_string()).expect("rev");

        store.set_last_known_good(&rev).expect("set");

        let stored_hash: Option<String> = {
            let conn = store.conn.borrow();
            conn.query_row(
                "SELECT integrity_hash FROM last_known_good WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .expect("query")
        };
        assert!(stored_hash.is_some());
        let h = stored_hash.unwrap();
        assert!(crate::integrity::verify_revision_hash("rev-lkg-hash", &h));
    }

    #[test]
    fn state_store_check_integrity_ok_with_valid_hashes() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-valid-001".to_string()).expect("rev");

        store.set_active_revision(&rev).expect("set active");
        store.set_last_known_good(&rev).expect("set lkg");

        let (result, action) = store.check_integrity().expect("check");
        assert_eq!(result, IntegrityCheckResult::Ok);
        assert_eq!(action, RecoveryAction::None);
    }

    #[test]
    fn state_store_check_integrity_detects_active_hash_mismatch() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-tamper-001".to_string()).expect("rev");

        store.set_active_revision(&rev).expect("set");

        // Tamper with the stored hash directly.
        {
            let conn = store.conn.borrow();
            conn.execute(
                "UPDATE active_revision SET integrity_hash = 'deadbeef' WHERE id = 1",
                [],
            )
            .expect("tamper");
        }

        let (result, action) = store.check_integrity().expect("check");
        assert!(
            matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
            "hash mismatch must yield PolicyIntegrityFailed, got {result:?}"
        );
        assert_eq!(action, RecoveryAction::FallbackToLastKnownGood);
    }

    #[test]
    fn state_store_check_integrity_detects_lkg_hash_mismatch() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-lkg-tamper".to_string()).expect("rev");

        store.set_active_revision(&rev).expect("set active");
        store.set_last_known_good(&rev).expect("set lkg");

        // Tamper with the LKG hash.
        {
            let conn = store.conn.borrow();
            conn.execute(
                "UPDATE last_known_good SET integrity_hash = 'deadbeef' WHERE id = 1",
                [],
            )
            .expect("tamper lkg");
        }

        let (result, action) = store.check_integrity().expect("check");
        assert!(
            matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
            "lkg hash mismatch must yield PolicyIntegrityFailed, got {result:?}"
        );
        // LKG itself is suspect — cannot safely fall back to it.
        assert!(
            matches!(action, RecoveryAction::RequireUserAction(_)),
            "corrupt LKG must require user action, got {action:?}"
        );
    }

    #[test]
    fn state_store_check_integrity_missing_lkg_returns_ok_on_first_start() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);
        let rev = RevisionId::from_prefixed_string("rev-no-lkg".to_string()).expect("rev");

        // Set active revision but never promote LKG (first-start scenario).
        store.set_active_revision(&rev).expect("set active");

        let (result, action) = store.check_integrity().expect("check");
        // Not a failure — just means rollback is unsafe until LKG is promoted.
        assert_eq!(result, IntegrityCheckResult::Ok);
        assert_eq!(action, RecoveryAction::None);
    }

    #[test]
    fn state_store_check_integrity_detects_bad_revision_format() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_state_store(&dir);

        // Inject a row with an invalid revision_id format directly (bypasses
        // RevisionId validation in set_active_revision).
        {
            let conn = store.conn.borrow();
            conn.execute(
                "INSERT INTO active_revision (id, revision_id, activated_at)
                 VALUES (1, 'NOT_A_VALID_REVISION', 0)",
                [],
            )
            .expect("inject bad row");
        }

        let (result, action) = store.check_integrity().expect("check");
        assert!(matches!(
            result,
            IntegrityCheckResult::PolicyIntegrityFailed { .. }
        ));
        assert_eq!(action, RecoveryAction::FallbackToLastKnownGood);
    }

    #[test]
    fn cache_store_check_cache_integrity_ok_on_fresh_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let (result, action) = store.check_cache_integrity().expect("check");
        assert_eq!(result, IntegrityCheckResult::Ok);
        assert_eq!(action, RecoveryAction::None);
    }

    // ── get_cache_stats ───────────────────────────────────────────────────────

    #[test]
    fn get_cache_stats_zero_on_fresh_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let stats = store.get_cache_stats().expect("stats");

        assert_eq!(stats.hostname_count, 0);
        assert_eq!(stats.ip_count, 0);
        assert_eq!(stats.resolution_count, 0);
        assert_eq!(stats.stale_resolution_count, 0);
        assert_eq!(stats.negative_cache_count, 0);
        assert_eq!(stats.lookup_events_count, 0);
        assert_eq!(stats.cache_generation, 0);
    }

    #[test]
    fn get_cache_stats_counts_all_entities() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "alpha.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert alpha");

        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "beta.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(2, 2, 2, 2)],
                ttl_seconds: Some(60),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert beta");

        let stats = store.get_cache_stats().expect("stats");
        assert_eq!(stats.hostname_count, 2, "two distinct hostnames");
        assert_eq!(
            stats.ip_count, 3,
            "three distinct IPs across both hostnames"
        );
        assert_eq!(
            stats.resolution_count, 3,
            "three hostname→IP resolution rows"
        );
        assert_eq!(stats.stale_resolution_count, 0, "none stale yet");
        assert_eq!(stats.cache_generation, 0, "no clear yet");
    }

    #[test]
    fn get_cache_stats_stale_count_after_revision_change() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "example.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(5, 5, 5, 5)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert");

        let staled = store.mark_revision_stale("rev-002").expect("mark stale");
        assert_eq!(staled, 1);

        let stats = store.get_cache_stats().expect("stats");
        assert_eq!(stats.resolution_count, 1, "entry still exists");
        assert_eq!(stats.stale_resolution_count, 1, "entry is stale");
    }

    // ── list_resolutions ──────────────────────────────────────────────────────

    #[test]
    fn list_resolutions_orders_and_respects_offset_limit_and_has_more() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "alpha.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert alpha");
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "beta.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(2, 2, 2, 2)],
                ttl_seconds: Some(60),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert beta");

        // Full window: fetches limit+1 but only 3 rows exist. Ordered by
        // (canonical_host, canonical_ip): 1.0.0.1 sorts before 1.1.1.1.
        let all = store.list_resolutions(0, 10, "").expect("list all");
        assert_eq!(all.len(), 3, "three resolution rows exist");
        assert_eq!(all[0].canonical_hostname, "alpha.test");
        assert_eq!(all[0].canonical_ip, "1.0.0.1");
        assert_eq!(all[0].freshness_state, "fresh");
        assert_eq!(all[0].source, "dns");
        assert_eq!(all[1].canonical_hostname, "alpha.test");
        assert_eq!(all[1].canonical_ip, "1.1.1.1");
        assert_eq!(all[2].canonical_hostname, "beta.test");
        assert_eq!(all[2].canonical_ip, "2.2.2.2");

        // First page of size 2: fetches 3 (limit+1) so the caller sees a
        // "has more" probe row beyond the requested two.
        let page1 = store.list_resolutions(0, 2, "").expect("page 1");
        assert_eq!(page1.len(), 3, "limit+1 fetched → caller detects more");
        assert!(page1.len() as u32 > 2, "more pages available");
        assert_eq!(page1[0].canonical_ip, "1.0.0.1");
        assert_eq!(page1[1].canonical_ip, "1.1.1.1");

        // Second page (offset 2): only the last row remains, no probe row.
        let page2 = store.list_resolutions(2, 2, "").expect("page 2");
        assert_eq!(page2.len(), 1, "last row only, no further pages");
        assert_eq!(page2[0].canonical_hostname, "beta.test");

        // Zero limit short-circuits.
        assert!(store
            .list_resolutions(0, 0, "")
            .expect("zero limit")
            .is_empty());
    }

    // Server-side query filters on host OR IP, case-insensitive,
    // with LIKE metacharacters escaped so a literal search stays literal.
    #[test]
    fn list_resolutions_filters_by_query_on_host_or_ip() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "alpha.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert alpha");
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "beta.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(20, 0, 0, 2)],
                ttl_seconds: Some(60),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-001".into()),
            })
            .expect("upsert beta");

        // EXACT host match by default (query contains a
        // dot), case-insensitive.
        let by_host = store
            .list_resolutions(0, 10, "ALPHA.test")
            .expect("by host");
        assert_eq!(by_host.len(), 1);
        assert_eq!(by_host[0].canonical_hostname, "alpha.test");
        // A bare token (no dot, no `*`) is an implicit
        // substring so single-word searches find their hosts.
        let bare = store
            .list_resolutions(0, 10, "ALPHA")
            .expect("bare fragment");
        assert_eq!(bare.len(), 1, "bare token substring-matches its host");
        assert_eq!(bare[0].canonical_hostname, "alpha.test");

        // `*` is the user-facing wildcard: `*alpha*` restores substring; a
        // suffix pattern lists everything under the zone.
        let by_wild = store.list_resolutions(0, 10, "*ALPHA*").expect("wild");
        assert_eq!(by_wild.len(), 1);
        assert_eq!(by_wild[0].canonical_hostname, "alpha.test");
        let by_suffix = store.list_resolutions(0, 10, "*.test").expect("suffix");
        assert_eq!(by_suffix.len(), 2, "alpha.test + beta.test");

        // Exact IP match; a bare IP fragment does not match.
        let by_ip = store.list_resolutions(0, 10, "20.0.0.2").expect("by ip");
        assert_eq!(by_ip.len(), 1);
        assert_eq!(by_ip[0].canonical_hostname, "beta.test");
        assert!(store
            .list_resolutions(0, 10, "20.0.0")
            .expect("ip fragment")
            .is_empty());

        // No match.
        assert!(store
            .list_resolutions(0, 10, "nonexistent")
            .expect("no match")
            .is_empty());

        // LIKE metacharacters are escaped → treated literally (no row contains '%').
        assert!(store
            .list_resolutions(0, 10, "%")
            .expect("literal percent")
            .is_empty());
    }

    // ── periodic_vacuum ───────────────────────────────────────────────────────

    #[test]
    fn periodic_vacuum_preserves_data_and_schema() {
        use crate::repository::MigrationRunner;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");

        // Upsert some entries, then vacuum.
        {
            let store = migrated_cache_store(&dir);
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: "vacuum.test".into(),
                    raw_hostname_sample: None,
                    resolved_ips: vec![Ipv4Addr::new(3, 3, 3, 3)],
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: SystemTime::now(),
                    active_revision_id: None,
                })
                .expect("upsert");

            store.periodic_vacuum().expect("vacuum must not error");
        }

        // Re-open — schema must still pass verify_schema.
        let conn = open_connection(&path).expect("reopen");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        let v = runner.verify_schema().expect("verify");
        assert!(v.is_ok(), "schema must be intact after vacuum: {v:?}");

        // Data inserted before vacuum must still be readable.
        let conn = runner.into_connection();
        let store = SqliteCacheStore::new(conn, FreshnessThresholds::default_production());
        let result = store
            .get_by_hostname(
                "vacuum.test",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("lookup");
        assert!(!result.resolved_ips.is_empty(), "data must survive vacuum");
    }

    // ── WAL concurrent access ─────────────────────────────────────────────────

    #[test]
    fn wal_multiple_connections_open_to_same_file() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");

        // Create and migrate once.
        {
            let conn = open_connection(&path).expect("open");
            let runner = SqliteMigrationRunner::for_cache_db(conn);
            runner.run_pending_migrations().expect("migrate");
        }

        // Open two independent connections simultaneously — WAL allows this.
        let conn1 = open_connection(&path).expect("conn1");
        let conn2 = open_connection(&path).expect("conn2");

        let c1: i64 = conn1
            .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
            .expect("c1");
        let c2: i64 = conn2
            .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
            .expect("c2");
        assert_eq!(c1, c2, "both readers must see the same data");

        let m1: String = conn1
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("mode1");
        let m2: String = conn2
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("mode2");
        assert_eq!(m1, "wal");
        assert_eq!(m2, "wal");
    }

    #[test]
    fn wal_reader_observes_committed_write() {
        // Verifies that a second connection opened after a write sees the
        // committed data — the basic WAL durability guarantee.
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");

        {
            let conn = open_connection(&path).expect("open writer");
            let runner = SqliteMigrationRunner::for_cache_db(conn);
            runner.run_pending_migrations().expect("migrate");
            let store = SqliteCacheStore::new(
                runner.into_connection(),
                FreshnessThresholds::default_production(),
            );
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: "durable.test".into(),
                    raw_hostname_sample: None,
                    resolved_ips: vec![Ipv4Addr::new(7, 7, 7, 7)],
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: SystemTime::now(),
                    active_revision_id: None,
                })
                .expect("write");
        } // writer connection closed here; WAL checkpointed on close

        let reader = open_connection(&path).expect("reader");
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 1, "reader must observe committed write");
    }

    // ── invalidation cause integration ────────────────────────────────────────

    #[test]
    fn invalidation_cause_file_modified_marks_stale_not_full_clear() {
        use crate::rebuild::InvalidationCause;

        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "rules.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![Ipv4Addr::new(9, 9, 9, 9)],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: now,
                active_revision_id: Some("rev-a".into()),
            })
            .expect("upsert");

        // ExternalFileModified → mark-stale, not full clear.
        let cause = InvalidationCause::ExternalFileModified;
        assert!(
            !cause.requires_full_clear(),
            "file change is a mark-stale invalidation"
        );

        let staled = store.mark_revision_stale("rev-b").expect("mark stale");
        assert_eq!(staled, 1);

        // Entry must still be in the cache (just marked stale).
        let result = store
            .get_by_hostname(
                "rules.test",
                &FreshnessThresholds::default_production(),
                CachePriorityStrategy::default(),
            )
            .expect("lookup");
        assert!(
            !result.resolved_ips.is_empty(),
            "entry must survive mark-stale"
        );
        assert!(
            result
                .resolved_ips
                .iter()
                .any(|e| e.cache_state == CacheEntryState::StaleUsable),
            "entry must be stale after mark_revision_stale",
        );

        // CacheStats must reflect the stale count without inflating resolution_count.
        let stats = store.get_cache_stats().expect("stats");
        assert_eq!(stats.resolution_count, 1);
        assert_eq!(stats.stale_resolution_count, 1);
    }

    // ── list_expired_resolutions ────────────────────────────────────────────

    fn seed_resolution(
        store: &SqliteCacheStore,
        hostname: &str,
        ip: Ipv4Addr,
        source: StorageResolutionSource,
        resolved_at: SystemTime,
        ttl_secs: u32,
    ) {
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: hostname.to_string(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(ttl_secs),
                source,
                resolved_at,
                active_revision_id: None,
            })
            .expect("upsert");
    }

    /// Touches `hostnames.last_seen_at` to mark the hostname as hot.
    /// Mirrors what `get_by_hostname` would do via its lookup pass.
    fn touch_last_seen(store: &SqliteCacheStore, hostname: &str, at: SystemTime) {
        let conn = store.conn.borrow();
        conn.execute(
            "UPDATE hostnames SET last_seen_at = ?1 WHERE canonical_host = ?2",
            rusqlite::params![system_time_to_ms(at), hostname],
        )
        .expect("touch");
    }

    #[test]
    fn list_expired_resolutions_returns_only_expired_dns_rows() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store_short_ttl(&dir);

        let now = SystemTime::now();
        let past_resolved = now - Duration::from_secs(3_600); // 1h ago, ttl 60s → expired
        let recent_resolved = now - Duration::from_secs(10); // 10s ago, ttl 3600s → fresh

        seed_resolution(
            &store,
            "expired.test",
            Ipv4Addr::new(1, 1, 1, 1),
            StorageResolutionSource::Dns,
            past_resolved,
            60,
        );
        seed_resolution(
            &store,
            "fresh.test",
            Ipv4Addr::new(2, 2, 2, 2),
            StorageResolutionSource::Dns,
            recent_resolved,
            3_600,
        );

        let listed = store
            .list_expired_resolutions(now, 16)
            .expect("list_expired_resolutions");
        assert_eq!(listed.len(), 1, "only the expired row should be listed");
        assert_eq!(listed[0].canonical_hostname, "expired.test");
    }

    #[test]
    fn list_expired_resolutions_excludes_observed_from_traffic() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store_short_ttl(&dir);

        let now = SystemTime::now();
        let past = now - Duration::from_secs(3_600);

        // Two expired rows — one DNS-sourced, one observed-from-traffic.
        seed_resolution(
            &store,
            "dns.test",
            Ipv4Addr::new(1, 1, 1, 1),
            StorageResolutionSource::Dns,
            past,
            60,
        );
        seed_resolution(
            &store,
            "observed.test",
            Ipv4Addr::new(2, 2, 2, 2),
            StorageResolutionSource::ObservedFromTraffic,
            past,
            60,
        );

        let listed = store
            .list_expired_resolutions(now, 16)
            .expect("list_expired_resolutions");
        assert_eq!(listed.len(), 1, "observed-from-traffic must be skipped");
        assert_eq!(listed[0].canonical_hostname, "dns.test");
    }

    #[test]
    fn list_expired_resolutions_orders_hot_first() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store_short_ttl(&dir);

        let now = SystemTime::now();
        let past = now - Duration::from_secs(3_600);

        for name in ["cold.test", "warm.test", "hot.test"] {
            seed_resolution(
                &store,
                name,
                Ipv4Addr::new(1, 1, 1, 1),
                StorageResolutionSource::Dns,
                past,
                60,
            );
        }
        // Stagger `last_seen_at` so `hot.test` is hottest.
        touch_last_seen(&store, "cold.test", now - Duration::from_secs(86_400));
        touch_last_seen(&store, "warm.test", now - Duration::from_secs(3_600));
        touch_last_seen(&store, "hot.test", now - Duration::from_secs(10));

        let listed = store
            .list_expired_resolutions(now, 16)
            .expect("list_expired_resolutions");
        assert_eq!(
            listed
                .iter()
                .map(|e| e.canonical_hostname.as_str())
                .collect::<Vec<_>>(),
            vec!["hot.test", "warm.test", "cold.test"]
        );
    }

    #[test]
    fn list_expired_resolutions_respects_limit() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store_short_ttl(&dir);

        let now = SystemTime::now();
        let past = now - Duration::from_secs(3_600);
        for i in 0..5 {
            seed_resolution(
                &store,
                &format!("h{i}.test"),
                Ipv4Addr::new(10, 0, 0, i as u8),
                StorageResolutionSource::Dns,
                past,
                60,
            );
        }

        let listed = store
            .list_expired_resolutions(now, 2)
            .expect("list_expired_resolutions");
        assert_eq!(listed.len(), 2);

        let none = store.list_expired_resolutions(now, 0).expect("limit=0");
        assert!(none.is_empty(), "limit=0 must short-circuit");
    }

    #[test]
    fn list_expired_resolutions_returns_empty_for_fresh_db() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let listed = store
            .list_expired_resolutions(SystemTime::now(), 16)
            .expect("list");
        assert!(listed.is_empty());
    }

    // ── list_hostnames_under_suffix ─────────────────────────────────────────

    #[test]
    fn list_hostnames_under_suffix_returns_only_subdomains_not_apex() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        seed_resolution(
            &store,
            "example.com",
            Ipv4Addr::new(1, 1, 1, 1),
            StorageResolutionSource::Dns,
            now,
            300,
        );
        seed_resolution(
            &store,
            "www.example.com",
            Ipv4Addr::new(2, 2, 2, 2),
            StorageResolutionSource::Dns,
            now,
            300,
        );
        seed_resolution(
            &store,
            "api.example.com",
            Ipv4Addr::new(3, 3, 3, 3),
            StorageResolutionSource::Dns,
            now,
            300,
        );

        let listed = store
            .list_hostnames_under_suffix("example.com", 16)
            .expect("list");
        assert_eq!(
            listed,
            vec!["api.example.com".to_string(), "www.example.com".to_string()],
            "apex hostname must be excluded, subdomains returned in ASC order"
        );
    }

    #[test]
    fn list_hostnames_under_suffix_respects_limit_and_zero_short_circuits() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();

        for sub in ["a.test", "b.test", "c.test", "d.test"] {
            seed_resolution(
                &store,
                sub,
                Ipv4Addr::new(10, 0, 0, 0),
                StorageResolutionSource::Dns,
                now,
                300,
            );
        }

        let two = store
            .list_hostnames_under_suffix("test", 2)
            .expect("list 2");
        assert_eq!(two.len(), 2);

        let zero = store
            .list_hostnames_under_suffix("test", 0)
            .expect("list 0");
        assert!(zero.is_empty(), "limit=0 must short-circuit");
    }

    #[test]
    fn list_hostnames_under_suffix_is_case_insensitive_and_strips_trailing_dot() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let now = SystemTime::now();
        seed_resolution(
            &store,
            "api.example.com",
            Ipv4Addr::new(1, 1, 1, 1),
            StorageResolutionSource::Dns,
            now,
            300,
        );

        let upper = store
            .list_hostnames_under_suffix("EXAMPLE.COM", 16)
            .expect("upper");
        assert_eq!(upper, vec!["api.example.com".to_string()]);

        let with_dot = store
            .list_hostnames_under_suffix("example.com.", 16)
            .expect("trailing dot");
        assert_eq!(with_dot, vec!["api.example.com".to_string()]);
    }

    #[test]
    fn list_hostnames_under_suffix_empty_suffix_returns_empty() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store(&dir);
        let listed = store.list_hostnames_under_suffix("", 16).expect("list");
        assert!(listed.is_empty());
    }
}

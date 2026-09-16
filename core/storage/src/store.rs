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

use crate::schema::AddressFamily;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::time::SystemTime;

use rusqlite::{params, Connection, OptionalExtension};

use nrr_domain::decision_lookup::{
    CacheEntryState, FreshnessThresholds, LookupExplainData, LookupExtendedMetadata, LookupResult,
    LookupStandardSignals, ResolvedAddressEntry,
};
use nrr_domain::revision::RevisionId;

use crate::dto::{
    CacheEntryRow, CacheLookupRequest, CacheLookupResult, CacheResetReason, CacheResetSummary,
    CacheStats, CachedIpEntry, CleanupPolicy, CleanupSummary, DbHealthStatus, DbIntegrityState,
    ExpiredHostname, IntegrityCheckResult, IntegrityStatus, LookupEventEntry, NegativeCacheEntry,
    NegativeCacheReason, OverallHealthState, RecoveryAction, ResolutionEntry, StorageHealthStatus,
};
use crate::error::{StorageError, StorageResult};
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

        // Forward lookup: hostname → resolved entries, either family. The
        // family is NOT filtered here: a reader that acts on one family says so
        // itself, and hiding rows at the query would make «not cached» and
        // «cached in the other family» indistinguishable upstream.
        let mut stmt = conn
            .prepare(
                "SELECT a.canonical_ip, r.freshness_state, r.source,
                        r.resolved_at, r.ttl_seconds, r.expires_at, r.active_revision_id
                 FROM hostname_ip_resolutions r
                 JOIN ip_addresses a ON a.id = r.ip_id
                 JOIN hostnames    h ON h.id = r.hostname_id
                 WHERE h.canonical_host = ?1
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
            let addr: IpAddr = row.canonical_ip.parse().map_err(|e| {
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
                    overall_freshness: Some(CacheEntryState::NegativeCached),
                    best_source: None,
                    is_multi_ip: false,
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
            overall_freshness,
            best_source,
            is_multi_ip,
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
            overall_freshness: None,
            best_source: None,
            is_multi_ip: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        };

        let forward = match (&request.hostname, request.direction.clone()) {
            (Some(h), LookupDirection::HostnameToIp | LookupDirection::Both) => {
                self.get_by_hostname(h, thresholds, strategy)?
            }
            _ => empty(),
        };

        // Select the best IP for ExactIp matching.
        let selected_ip = select_best_ip(&forward.resolved_ips, strategy);

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

        Ok(LookupResult {
            selected_ip: selected_ip.clone(),
            is_multi_ip: forward.is_multi_ip,
            explain_data: LookupExplainData {
                standard: LookupStandardSignals {
                    cache_hit,
                    freshness: forward.overall_freshness,
                    source: forward.best_source.map(|s| s.to_lookup_source()),
                    errors: forward.errors,
                },
                extended: LookupExtendedMetadata {
                    all_resolved_ips: all_resolved,
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

        // 2. Upsert each resolved address. The family comes from the address,
        // never from the call site: one address must not be filed twice.
        for ip in &entry.resolved_ips {
            let family = AddressFamily::of(*ip).as_str();
            // `Display` for both families is the canonical text form (RFC 5952
            // compresses and lower-cases v6), which is what the UNIQUE key
            // relies on.
            let canonical_ip = ip.to_string();
            // The packed column is a v4-only index; a v6 row leaves it NULL.
            let packed = match ip {
                IpAddr::V4(v4) => Some(ipv4_packed(*v4)),
                IpAddr::V6(_) => None,
            };

            tx.execute(
                "INSERT INTO ip_addresses
                 (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(address_family, canonical_ip) DO UPDATE SET
                     last_seen_at = excluded.last_seen_at,
                     ipv4_packed  = excluded.ipv4_packed",
                params![family, canonical_ip, packed, resolved_at_ms],
            )
            .map_err(db_err)?;

            let ip_id: i64 = tx
                .query_row(
                    "SELECT id FROM ip_addresses
                     WHERE address_family = ?1 AND canonical_ip = ?2",
                    params![family, canonical_ip],
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

    fn snapshot_resolutions(&self) -> StorageResult<Vec<(String, IpAddr, SystemTime)>> {
        let conn = self.conn.borrow();
        // Same join, same per-hostname ordering as `get_by_hostname`; only the
        // hostname predicate is gone. Freshness is deliberately NOT filtered
        // here either — that path returns every cached row and lets the caller
        // apply its own confirmation window.
        let mut stmt = conn
            .prepare(
                "SELECT h.canonical_host, a.canonical_ip, r.resolved_at
                 FROM hostname_ip_resolutions r
                 JOIN ip_addresses a ON a.id = r.ip_id
                 JOIN hostnames    h ON h.id = r.hostname_id
                 ORDER BY h.canonical_host ASC, r.resolved_at DESC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (host, ip, resolved_at_ms) = row.map_err(db_err)?;
            // A row whose address does not parse is a corrupt cell, not a
            // reason to fail the whole snapshot: skipping it degrades exactly
            // one address, the way the per-hostname path degrades a whole
            // lookup on a read error.
            let Ok(addr) = ip.parse::<IpAddr>() else {
                continue;
            };
            out.push((host, addr, ms_to_system_time(resolved_at_ms)));
        }
        Ok(out)
    }

    fn snapshot_hostnames(&self) -> StorageResult<Vec<(String, i64)>> {
        let conn = self.conn.borrow();
        // Same ORDER BY as `list_hostnames_under_suffix`, minus its LIKE and
        // LIMIT: the snapshot applies those in memory.
        let mut stmt = conn
            .prepare(
                "SELECT canonical_host, last_seen_at FROM hostnames
                 ORDER BY last_seen_at DESC, canonical_host ASC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(db_err)?);
        }
        Ok(out)
    }

    fn shared_ip_direct_host_counts(&self) -> StorageResult<Vec<(Ipv4Addr, u32)>> {
        let conn = self.conn.borrow();
        let mut stmt = conn
            .prepare(
                "SELECT ipv4_packed, COUNT(DISTINCT hostname) \
                 FROM shared_ip_direct_hosts GROUP BY ipv4_packed",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (packed, count) = row.map_err(db_err)?;
            out.push((Ipv4Addr::from(packed as u32), count.max(0) as u32));
        }
        Ok(out)
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
        // A failed row is an error, not a shorter census. This list is
        // SUBTRACTED from the kill-switch's pin/block set, so dropping entries
        // silently blocks an address shared with a direct host — the exact
        // collateral the census exists to spare. The caller degrades an Err to
        // an empty census and logs it, which is the strict direction and a
        // visible one; `.ok()` per row was neither.
        let mut out = Vec::new();
        for row in stmt.query_map([], |r| r.get::<_, i64>(0)).map_err(db_err)? {
            out.push(Ipv4Addr::from(row.map_err(db_err)? as u32));
        }
        Ok(out)
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
        // The LIKE pattern is `%.{suffix}` — `%` is "any prefix including
        // empty", but the literal `.` before the suffix makes the apex
        // (`{suffix}` itself) not match.
        //
        // The suffix comes from a USER'S rule, so it is the side that has to be
        // escaped: an unescaped zone `_u` matched `.ru`, `.eu` and `.nu` alike,
        // and `%` matched every hostname containing a dot. This result feeds the
        // zone fan-out, i.e. which hosts earn permits and routes — a wildcard
        // slipping in here silently widens the rule. (The old comment argued the
        // other side of the join: metacharacters in the stored hostnames.)
        let pattern = format!("%.{}", escape_like_literal(&normalised));
        // Order by RECENCY, not alphabetically. The result feeds the
        // per-rule zone/suffix fan-out, which is bounded (SUFFIX_FANOUT_BACKSTOP). With
        // the old `canonical_host ASC` a busy zone (e.g. `.ru`) that exceeded the
        // cap only ever permitted the alphabetically-first N hosts, so an actively
        // visited late-alphabet host (`zulu.example`) never earned an ALE permit and
        // was blocked by the catch-all. `last_seen_at DESC` keeps the hosts the
        // user is actually using inside the window; `canonical_host ASC` breaks
        // ties deterministically so identical-timestamp rows stay stable.
        let mut stmt = conn
            .prepare(
                "SELECT canonical_host FROM hostnames
                 WHERE canonical_host LIKE ?1 ESCAPE '\\'
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
        // `search.example` shows exactly that host (and only it), not every
        // `*google*` hit drowning it out. A `*` in the query is the
        // user-facing wildcard (translated to LIKE `%` AFTER escaping the
        // real metacharacters), so `*.search.example` lists the subdomains and
        // `*google*` gives substring behaviour.
        //
        // A BARE token (no `.`, no `*`) is an implicit
        // substring: nobody has a cache row whose whole hostname is `citymap`,
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
        // TRUNCATE reclaims the journal without a full VACUUM rebuild. Errors
        // are non-fatal — log in production.
        crate::migration::checkpoint_wal_truncate(&conn)
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
    /// Row-signing key, when the caller has one. Without it the integrity check
    /// can still verify structure and format, but a row's `row_hmac` cannot be
    /// recomputed — an unsigned answer, never a failed one.
    signing_key: Option<Vec<u8>>,
}

mod health;
mod state_store;
// ── Private helpers ───────────────────────────────────────────────────────────

fn db_err(e: rusqlite::Error) -> StorageError {
    StorageError::Internal(e.to_string())
}

/// Escape a value that is spliced into a `LIKE` pattern, for use with
/// `ESCAPE '\'`. Anything derived from a user's rule (a zone, a suffix, a
/// search term) goes through this: `_` and `%` are wildcards, so a zone named
/// `_u` would otherwise match `.ru` and `.eu` as readily as itself.
fn escape_like_literal(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
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
fn select_best_ip(
    entries: &[CachedIpEntry],
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

    best.map(|e| ResolvedAddressEntry {
        addr: e.addr,
        cache_state: e.cache_state.clone(),
        source: e.source.to_lookup_source(),
        resolved_at: e.resolved_at,
        ttl_seconds: e.ttl_seconds,
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
        IntegrityCheckResult::OkNoRollbackTarget => ("ok", Some("no rollback target".to_string())),
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
mod tests;

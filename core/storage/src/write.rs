//! Write/refresh policy and TTL helpers.
//!
//! This module is pure logic — no SQLite, no I/O, no state.  It provides the
//! types and functions the service layer uses to:
//!
//! - Apply TTL clamping before writing a resolution result
//! - Decide how (and when) the DNS resolver should be invoked next
//! - Build a negative cache entry from a failed resolution
//!
//! # Resolver boundary
//!
//! The storage layer (`nrr-storage`) **never** performs DNS lookups.  It stores
//! results supplied by the service resolver and returns [`RefreshSchedule`]s
//! that tell the service loop *when* to resolve next.  The service decides
//! *whether* to honour those hints based on its own state (fail-closed mode,
//! resolver availability, etc.).

use std::time::{Duration, SystemTime};

use nrr_domain::decision_lookup::CacheEntryState;

use crate::dto::{CacheLookupResult, NegativeCacheEntry, NegativeCacheReason};
use crate::resolution_source::StorageResolutionSource;

// ── TtlPolicy ─────────────────────────────────────────────────────────────────

/// Constraints applied to TTL values before they are written into the cache.
///
/// DNS responses may carry unreasonably short or long TTLs.  `TtlPolicy`
/// clamps them to a safe range and provides a fallback for responses that carry
/// no TTL at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TtlPolicy {
    /// Minimum TTL applied regardless of the DNS response (seconds).
    /// Prevents excessively aggressive re-resolution.
    pub min_ttl_secs: u32,
    /// Maximum TTL cap (seconds).  Entries are never kept fresh beyond this.
    pub max_ttl_secs: u32,
    /// Fallback TTL when the DNS response carries no explicit TTL (seconds).
    pub fallback_ttl_secs: u32,
}

impl TtlPolicy {
    /// Production-safe defaults: 10 s floor, 24 h ceiling, 60 s fallback.
    pub fn default_production() -> Self {
        Self {
            min_ttl_secs: 10,
            max_ttl_secs: 86_400, // 24 h
            fallback_ttl_secs: 60,
        }
    }
}

/// Applies `policy` to a raw DNS TTL value.
///
/// - `None` → use `policy.fallback_ttl_secs`
/// - Value below minimum → clamp to `policy.min_ttl_secs`
/// - Value above maximum → clamp to `policy.max_ttl_secs`
pub fn apply_ttl_policy(dns_ttl: Option<u32>, policy: &TtlPolicy) -> u32 {
    let raw = dns_ttl.unwrap_or(policy.fallback_ttl_secs);
    raw.clamp(policy.min_ttl_secs, policy.max_ttl_secs)
}

// ── RefreshPolicy ─────────────────────────────────────────────────────────────

/// Why the service is operating in cache-only mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheOnlyReason {
    /// Cache has a fresh authoritative entry — DNS resolution is unnecessary.
    EntryFresh,
    /// Fail-closed grace period is active — avoid external DNS traffic.
    FailClosedGracePeriod,
    /// DNS resolver is currently unavailable.
    ResolverUnavailable,
}

/// Decision for the DNS resolver produced by [`compute_refresh_policy`].
///
/// The service layer maps this to its own resolver invocation logic.  It may
/// override [`AllowSynchronous`][RefreshPolicy::AllowSynchronous] to
/// [`CacheOnly`][RefreshPolicy::CacheOnly] when it is in fail-closed mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshPolicy {
    /// Cache is missing or too stale — resolve synchronously before routing
    /// if the latency budget allows.
    AllowSynchronous,
    /// Cache is stale but usable — route with the cached result and schedule a
    /// background refresh.
    BackgroundRefreshEligible,
    /// Negative cache is in effect — skip DNS until `retry_after`.
    SkipNegativeCached { retry_after: SystemTime },
    /// Do not invoke the DNS resolver — cache is authoritative or the service
    /// is in a mode that prohibits external resolution.
    CacheOnly { reason: CacheOnlyReason },
}

/// Derives the [`RefreshPolicy`] from a completed cache lookup.
///
/// This function only uses data available in [`CacheLookupResult`] — it does
/// not know about the service's fail-closed state.  Callers that are in
/// fail-closed or resolver-unavailable mode should override
/// [`AllowSynchronous`][RefreshPolicy::AllowSynchronous] to
/// [`CacheOnly`][RefreshPolicy::CacheOnly] after calling this function.
pub fn compute_refresh_policy(result: &CacheLookupResult) -> RefreshPolicy {
    match &result.overall_freshness {
        None | Some(CacheEntryState::Missing) | Some(CacheEntryState::StaleNotUsable) => {
            RefreshPolicy::AllowSynchronous
        }

        Some(CacheEntryState::Fresh) => RefreshPolicy::CacheOnly {
            reason: CacheOnlyReason::EntryFresh,
        },

        Some(CacheEntryState::StaleUsable) | Some(CacheEntryState::Conflicting) => {
            RefreshPolicy::BackgroundRefreshEligible
        }

        Some(CacheEntryState::NegativeCached) => {
            let retry_after = result
                .negative_cache_expires_at
                .unwrap_or_else(|| SystemTime::now() + Duration::from_secs(30));
            RefreshPolicy::SkipNegativeCached { retry_after }
        }
    }
}

// ── RefreshSchedule ───────────────────────────────────────────────────────────

/// Scheduling data for the service loop's refresh task queue.
///
/// Computed by [`compute_refresh_schedule`] from a [`CacheLookupResult`].
/// The service loop uses this to decide *when* to enqueue a background
/// refresh, and to avoid re-querying an IP that hit the negative cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshSchedule {
    /// What the DNS resolver should do for this lookup.
    pub policy: RefreshPolicy,
    /// When the freshest cached entry expires.  The background refresh should
    /// fire before this time so routing stays uninterrupted.
    /// `None` when no cached entry exists.
    pub entry_expires_at: Option<SystemTime>,
    /// When the negative cache entry expires (`retry_after` column).
    /// `None` when there was no negative cache hit.
    pub negative_cache_until: Option<SystemTime>,
}

/// Computes the refresh schedule from a cache lookup result.
pub fn compute_refresh_schedule(result: &CacheLookupResult) -> RefreshSchedule {
    let policy = compute_refresh_policy(result);

    // Use the latest expiry across all resolved IP entries as the background
    // refresh deadline — background task fires before the freshest entry expires.
    let entry_expires_at = result
        .resolved_ips
        .iter()
        .filter_map(|e| e.expires_at)
        .max();

    RefreshSchedule {
        policy,
        entry_expires_at,
        negative_cache_until: result.negative_cache_expires_at,
    }
}

// ── build_negative_entry ──────────────────────────────────────────────────────

/// Builds a [`NegativeCacheEntry`] from a failed DNS resolution.
///
/// `negative_ttl_secs` is taken directly from
/// [`FreshnessThresholds::negative_ttl_secs`][nrr_domain::decision_lookup::FreshnessThresholds::negative_ttl_secs]
/// to keep this function free of a dependency on `FreshnessThresholds` for
/// callers that already extracted the value.
///
/// The resulting entry should be written via
/// [`CacheRepository::upsert_negative_cache`][crate::repository::CacheRepository::upsert_negative_cache]
/// or
/// [`CacheRepository::record_failed_resolution`][crate::repository::CacheRepository::record_failed_resolution].
pub fn build_negative_entry(
    input: &str,
    reason: NegativeCacheReason,
    source: StorageResolutionSource,
    now: SystemTime,
    negative_ttl_secs: u32,
) -> NegativeCacheEntry {
    let expires_at = now + Duration::from_secs(negative_ttl_secs as u64);
    NegativeCacheEntry {
        input: input.to_string(),
        reason,
        created_at: now,
        expires_at,
        source,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use nrr_domain::decision_lookup::CacheEntryState;

    use crate::dto::{CacheLookupResult, CachedIpEntry};
    use crate::resolution_source::StorageResolutionSource;

    // ── apply_ttl_policy ─────────────────────────────────────────────────────

    fn default_policy() -> TtlPolicy {
        TtlPolicy {
            min_ttl_secs: 10,
            max_ttl_secs: 3_600,
            fallback_ttl_secs: 60,
        }
    }

    #[test]
    fn ttl_policy_uses_dns_value_in_range() {
        assert_eq!(apply_ttl_policy(Some(300), &default_policy()), 300);
    }

    #[test]
    fn ttl_policy_uses_fallback_when_none() {
        assert_eq!(apply_ttl_policy(None, &default_policy()), 60);
    }

    #[test]
    fn ttl_policy_clamps_to_min() {
        assert_eq!(apply_ttl_policy(Some(1), &default_policy()), 10);
    }

    #[test]
    fn ttl_policy_clamps_to_max() {
        assert_eq!(apply_ttl_policy(Some(999_999), &default_policy()), 3_600);
    }

    #[test]
    fn ttl_policy_accepts_exact_min() {
        assert_eq!(apply_ttl_policy(Some(10), &default_policy()), 10);
    }

    #[test]
    fn ttl_policy_accepts_exact_max() {
        assert_eq!(apply_ttl_policy(Some(3_600), &default_policy()), 3_600);
    }

    #[test]
    fn ttl_policy_default_production_is_sane() {
        let p = TtlPolicy::default_production();
        assert!(p.min_ttl_secs < p.max_ttl_secs);
        assert!(p.fallback_ttl_secs >= p.min_ttl_secs);
        assert!(p.fallback_ttl_secs <= p.max_ttl_secs);
    }

    // ── compute_refresh_policy ───────────────────────────────────────────────

    fn result_with_freshness(freshness: Option<CacheEntryState>) -> CacheLookupResult {
        CacheLookupResult {
            resolved_ips: Vec::new(),
            reverse_hostnames: Vec::new(),
            overall_freshness: freshness,
            best_source: None,
            is_multi_ip: false,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        }
    }

    #[test]
    fn refresh_policy_allow_sync_for_missing() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(None)),
            RefreshPolicy::AllowSynchronous
        );
    }

    #[test]
    fn refresh_policy_allow_sync_for_explicit_missing() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(Some(CacheEntryState::Missing))),
            RefreshPolicy::AllowSynchronous
        );
    }

    #[test]
    fn refresh_policy_allow_sync_for_stale_not_usable() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(Some(
                CacheEntryState::StaleNotUsable
            ))),
            RefreshPolicy::AllowSynchronous
        );
    }

    #[test]
    fn refresh_policy_cache_only_for_fresh() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(Some(CacheEntryState::Fresh))),
            RefreshPolicy::CacheOnly {
                reason: CacheOnlyReason::EntryFresh
            }
        );
    }

    #[test]
    fn refresh_policy_background_for_stale_usable() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(Some(CacheEntryState::StaleUsable))),
            RefreshPolicy::BackgroundRefreshEligible
        );
    }

    #[test]
    fn refresh_policy_background_for_conflicting() {
        assert_eq!(
            compute_refresh_policy(&result_with_freshness(Some(CacheEntryState::Conflicting))),
            RefreshPolicy::BackgroundRefreshEligible
        );
    }

    #[test]
    fn refresh_policy_skip_for_negative_cached_with_retry_after() {
        let retry_after = SystemTime::now() + Duration::from_secs(30);
        let result = CacheLookupResult {
            overall_freshness: Some(CacheEntryState::NegativeCached),
            negative_cache_expires_at: Some(retry_after),
            ..result_with_freshness(None)
        };
        match compute_refresh_policy(&result) {
            RefreshPolicy::SkipNegativeCached { retry_after: ra } => {
                assert_eq!(ra, retry_after);
            }
            other => panic!("expected SkipNegativeCached, got {other:?}"),
        }
    }

    #[test]
    fn refresh_policy_skip_negative_uses_default_when_no_retry_after() {
        let result = CacheLookupResult {
            overall_freshness: Some(CacheEntryState::NegativeCached),
            negative_cache_expires_at: None,
            ..result_with_freshness(None)
        };
        assert!(matches!(
            compute_refresh_policy(&result),
            RefreshPolicy::SkipNegativeCached { .. }
        ));
    }

    // ── compute_refresh_schedule ─────────────────────────────────────────────

    fn make_ip_entry(freshness: CacheEntryState, expires_at: Option<SystemTime>) -> CachedIpEntry {
        CachedIpEntry {
            addr: Ipv4Addr::new(1, 2, 3, 4),
            cache_state: freshness,
            source: StorageResolutionSource::Dns,
            resolved_at: None,
            ttl_seconds: None,
            expires_at,
            active_revision_id: None,
        }
    }

    #[test]
    fn schedule_has_entry_expires_at_from_best_entry() {
        let t = SystemTime::now() + Duration::from_secs(300);
        let result = CacheLookupResult {
            resolved_ips: vec![make_ip_entry(CacheEntryState::Fresh, Some(t))],
            overall_freshness: Some(CacheEntryState::Fresh),
            negative_cache_expires_at: None,
            ..result_with_freshness(None)
        };
        let sched = compute_refresh_schedule(&result);
        assert_eq!(sched.entry_expires_at, Some(t));
    }

    #[test]
    fn schedule_picks_latest_expiry_from_multiple_entries() {
        let t1 = SystemTime::now() + Duration::from_secs(100);
        let t2 = SystemTime::now() + Duration::from_secs(500);
        let result = CacheLookupResult {
            resolved_ips: vec![
                make_ip_entry(CacheEntryState::Fresh, Some(t1)),
                make_ip_entry(CacheEntryState::Fresh, Some(t2)),
            ],
            overall_freshness: Some(CacheEntryState::Fresh),
            negative_cache_expires_at: None,
            ..result_with_freshness(None)
        };
        let sched = compute_refresh_schedule(&result);
        // Background refresh should fire before the *latest* expiry.
        assert_eq!(sched.entry_expires_at, Some(t2));
    }

    #[test]
    fn schedule_negative_cache_until_propagated() {
        let retry = SystemTime::now() + Duration::from_secs(60);
        let result = CacheLookupResult {
            overall_freshness: Some(CacheEntryState::NegativeCached),
            negative_cache_expires_at: Some(retry),
            ..result_with_freshness(None)
        };
        let sched = compute_refresh_schedule(&result);
        assert_eq!(sched.negative_cache_until, Some(retry));
    }

    #[test]
    fn schedule_entry_expires_at_none_when_no_entries() {
        let sched = compute_refresh_schedule(&result_with_freshness(None));
        assert!(sched.entry_expires_at.is_none());
    }

    // ── build_negative_entry ─────────────────────────────────────────────────

    #[test]
    fn build_negative_entry_uses_ttl_for_expiry() {
        let now = SystemTime::now();
        let entry = build_negative_entry(
            "nxdomain.example",
            NegativeCacheReason::NxDomain,
            StorageResolutionSource::Dns,
            now,
            30,
        );
        assert_eq!(entry.input, "nxdomain.example");
        assert_eq!(entry.expires_at, now + Duration::from_secs(30));
        assert_eq!(entry.created_at, now);
    }

    #[test]
    fn build_negative_entry_resolve_failed() {
        let now = SystemTime::now();
        let entry = build_negative_entry(
            "timeout.example",
            NegativeCacheReason::ResolveFailed,
            StorageResolutionSource::Dns,
            now,
            60,
        );
        assert_eq!(entry.reason, NegativeCacheReason::ResolveFailed);
        assert_eq!(entry.source, StorageResolutionSource::Dns);
    }

    #[test]
    fn build_negative_entry_ipv6_unsupported() {
        let now = SystemTime::now();
        let entry = build_negative_entry(
            "2001:db8::1",
            NegativeCacheReason::UnsupportedAddressFamily,
            StorageResolutionSource::ObservedFromTraffic,
            now,
            300,
        );
        assert_eq!(entry.reason, NegativeCacheReason::UnsupportedAddressFamily);
        assert_eq!(entry.source, StorageResolutionSource::ObservedFromTraffic);
        assert_eq!(entry.expires_at, now + Duration::from_secs(300));
    }

    // ── integration: SqliteCacheStore::record_failed_resolution ─────────────

    #[test]
    fn record_failed_resolution_writes_negative_cache() {
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::{CacheRepository, MigrationRunner};
        use crate::store::SqliteCacheStore;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );

        let retry_after = SystemTime::now() + Duration::from_secs(30);
        store
            .record_failed_resolution(
                "nxdomain.test",
                NegativeCacheReason::NxDomain,
                retry_after,
                StorageResolutionSource::Dns,
            )
            .expect("record");

        let result = store
            .get_by_hostname(
                "nxdomain.test",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(
            result.overall_freshness,
            Some(CacheEntryState::NegativeCached)
        );
        assert!(result.resolved_ips.is_empty());
        assert!(result.negative_cache_expires_at.is_some());
    }

    #[test]
    fn record_failed_resolution_timeout_creates_negative_entry() {
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::{CacheRepository, MigrationRunner};
        use crate::store::SqliteCacheStore;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );

        let retry_after = SystemTime::now() + Duration::from_secs(10);
        store
            .record_failed_resolution(
                "timeout.test",
                NegativeCacheReason::ResolveFailed,
                retry_after,
                StorageResolutionSource::Dns,
            )
            .expect("record");

        let result = store
            .get_by_hostname(
                "timeout.test",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(
            result.overall_freshness,
            Some(CacheEntryState::NegativeCached)
        );
        // retry_after should be surfaced as negative_cache_expires_at.
        assert!(result.negative_cache_expires_at.is_some());
    }

    #[test]
    fn upsert_ip_set_change_adds_new_ip() {
        use crate::dto::ResolutionEntry;
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::{CacheRepository, MigrationRunner};
        use crate::store::SqliteCacheStore;
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use std::net::Ipv4Addr;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );

        let ip1 = Ipv4Addr::new(1, 2, 3, 4);
        let ip2 = Ipv4Addr::new(5, 6, 7, 8);

        // First write: hostname → [ip1]
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "multi.example".to_string(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip1],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert1");

        // Second write: hostname → [ip1, ip2] (IP set grows)
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "multi.example".to_string(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip1, ip2],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert2");

        let result = store
            .get_by_hostname(
                "multi.example",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(
            result.resolved_ips.len(),
            2,
            "both IPs should be present after set expansion"
        );
        assert!(result.is_multi_ip);
    }

    #[test]
    fn manual_refresh_source_stored_and_returned() {
        use crate::dto::ResolutionEntry;
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::{CacheRepository, MigrationRunner};
        use crate::store::SqliteCacheStore;
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use std::net::Ipv4Addr;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );

        let ip = Ipv4Addr::new(10, 0, 0, 1);
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "manual.example".to_string(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::ManualRefresh,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert");

        let result = store
            .get_by_hostname(
                "manual.example",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(
            result.resolved_ips[0].source,
            StorageResolutionSource::ManualRefresh
        );
        assert_eq!(result.overall_freshness, Some(CacheEntryState::Fresh));
    }

    #[test]
    fn fresh_entry_has_expires_at_populated() {
        use crate::dto::ResolutionEntry;
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::{CacheRepository, MigrationRunner};
        use crate::store::SqliteCacheStore;
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use std::net::Ipv4Addr;

        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        // Small `fallback_ttl_secs` floor so the 300 s DNS TTL is honoured as-is
        // (production floors to a week for leak-guard stickiness).
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds {
                fallback_ttl_secs: 10,
                ..FreshnessThresholds::default_production()
            },
        );

        let ip = Ipv4Addr::new(1, 1, 1, 1);
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "expire.example".to_string(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert");

        let result = store
            .get_by_hostname(
                "expire.example",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        let entry = &result.resolved_ips[0];
        assert!(
            entry.expires_at.is_some(),
            "expires_at must be set for fresh entries"
        );
        // Expiry should be roughly now + 300s.
        let expires = entry.expires_at.unwrap();
        let delta = expires
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_secs();
        assert!(
            delta > 280 && delta <= 300,
            "expiry should be ~300s from now, got {delta}s"
        );

        // compute_refresh_schedule should surface entry_expires_at.
        let schedule = compute_refresh_schedule(&result);
        assert!(schedule.entry_expires_at.is_some());
    }
}

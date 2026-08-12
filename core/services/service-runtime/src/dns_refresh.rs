//! DNS refresh orchestrator.
//!
//! Drives the [`DnsResolverPort`] against the FQDN/IP cache: pulls
//! expired hostnames (hot-first) via
//! [`CacheRepository::list_expired_resolutions`], re-resolves each one,
//! and writes the outcome back into the cache. The supervisor task
//! builder [`build_dns_refresh_task`][crate::service_tasks::build_dns_refresh_task]
//! wraps this orchestrator into a periodic [`ServiceTask`][crate::runtime_loop::ServiceTask].
//!
//! ## Failure handling
//!
//! - **Authoritative failures** ([`DnsResolverError::NxDomain`] /
//!   [`DnsResolverError::InvalidName`]) write a negative-cache entry
//!   with [`NegativeCacheReason::NxDomain`] so subsequent lookups
//!   skip the resolver for the configured negative TTL.
//! - **Transient failures** (timeout, refused, network) write a
//!   negative-cache entry with
//!   [`NegativeCacheReason::ResolveFailed`] and a short retry window
//!   ([`DnsRefreshOrchestrator::negative_ttl_secs`] / 4). The next
//!   tick will pick the entry up again once it's past `retry_after`.
//! - **Unsupported platform** is logged once per tick and the task
//!   exits with [`RefreshSummary::skipped`] incremented; nothing is
//!   written to the cache.
//!
//! ## Concurrency
//!
//! The orchestrator holds the cache through an
//! `Arc<Mutex<dyn CacheRepository + Send>>` — `SqliteCacheStore` uses
//! interior `RefCell` and is therefore `Send` but not `Sync`. Per-
//! tick the mutex is locked twice: once to read the expired list,
//! once per write. We deliberately do NOT hold the lock across the
//! DNS round-trip — those can take hundreds of milliseconds and
//! would block any other consumer of the cache (lookup port, manual
//! refresh handler).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort, ResolvedRecord};
use nrr_storage::dto::{ExpiredHostname, NegativeCacheReason, ResolutionEntry};
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::net_filter::{contains_fake_pool_addr, is_non_routable_v4};

/// Outcome of one [`DnsRefreshOrchestrator::run_once`] invocation.
///
/// `attempted` is always the number of rows
/// [`list_expired_resolutions`](CacheRepository::list_expired_resolutions)
/// returned; the other counters sum to `attempted` (or
/// `attempted - cache_errors` when the cache itself failed mid-batch).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefreshSummary {
    pub attempted: u32,
    pub succeeded: u32,
    pub failed_authoritative: u32,
    pub failed_transient: u32,
    pub cache_errors: u32,
    /// Number of expired hostnames the task chose not to query or not to
    /// write — backoff suppression, an unsupported-platform abort, or an
    /// answer with nothing usable in it. Every attempted row lands in
    /// exactly one counter; a bucketless row is an accounting bug (the
    /// archive had 44% of attempts vanish, which made the tick
    /// log useless for regression triage).
    pub skipped: u32,
    /// Subset of `skipped`: the OS resolver handed back our own fake-IP
    /// pool (Mode B self-interception) — no signal about the host.
    pub fake_intercepted: u32,
    /// Subset of `skipped`: the answer contained only loopback /
    /// unspecified addresses (hosts-file pin) — nothing cacheable.
    pub loopback_pinned: u32,
}

impl RefreshSummary {
    /// `true` when at least one expired hostname was processed (or
    /// attempted). Callers may use this to decide whether to log at
    /// `info!` or `debug!` level — empty ticks don't deserve `info!`.
    pub fn made_progress(&self) -> bool {
        self.attempted > 0
    }
}

/// Default negative TTL applied to refresh failures.
///
/// Picked to match the documented `FreshnessThresholds::default_production`
/// negative TTL: 5 minutes for `NxDomain`, 1 minute for transient
/// errors (resolved as `negative_ttl_secs / 4`).
pub const DEFAULT_NEGATIVE_TTL_SECS: u64 = 300;

/// DNS refresh orchestrator.
///
/// Constructed once per service runtime, shared via `Arc` between the
/// supervisor task closure and any IPC handler that wants to trigger
/// a manual refresh. All methods are `&self`; internal state is held
/// behind the shared cache mutex.
pub struct DnsRefreshOrchestrator {
    resolver: Arc<dyn DnsResolverPort>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    negative_ttl_secs: u64,
    /// hostnames already logged this orchestrator's
    /// lifetime for a refresh resolving only to loopback/unspecified
    /// (hosts-file pin). Same class of spam as
    /// [`crate::rule_hostname_seeder::RuleHostnameSeeder`]'s equivalent gate:
    /// a stale hosts-file pin keeps expiring and re-refreshing every tick, so
    /// without this the line would repeat indefinitely. Cleared per hostname
    /// the moment it refreshes to a routable address again, so a later
    /// re-pin logs again.
    loopback_logged: Mutex<HashSet<String>>,
    /// Per-hostname retry gate for loopback-pinned rows. Their expired cache
    /// row deliberately stays in place (recovery path) and gets no negative
    /// TTL, so `list_expired_resolutions` re-offers them on EVERY tick — a
    /// provider-poisoned preset re-queried each host every few seconds and the
    /// resulting chatter rotated real history out of the operational log. The
    /// gate doubles from [`REFRESH_LOOPBACK_BACKOFF_MIN`] to
    /// [`REFRESH_LOOPBACK_BACKOFF_MAX`]; cleared the moment the host refreshes
    /// to a routable address.
    loopback_retry_after: Mutex<HashMap<String, (Instant, Duration)>>,
}

/// First wait before a loopback-pinned hostname is re-queried by the refresh.
const REFRESH_LOOPBACK_BACKOFF_MIN: Duration = Duration::from_secs(60);

/// Ceiling for the loopback-pin retry wait: the pin usually outlives the
/// session (hosts file / provider DNS poisoning), so re-checking it rarely is
/// enough — parity with the seeder's ceiling.
const REFRESH_LOOPBACK_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

impl DnsRefreshOrchestrator {
    pub fn new(
        resolver: Arc<dyn DnsResolverPort>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
    ) -> Self {
        Self {
            resolver,
            cache,
            negative_ttl_secs: DEFAULT_NEGATIVE_TTL_SECS,
            loopback_logged: Mutex::new(HashSet::new()),
            loopback_retry_after: Mutex::new(HashMap::new()),
        }
    }

    /// `true` while `hostname` is inside its post-loopback-pin wait.
    fn loopback_retry_suppressed(&self, hostname: &str) -> bool {
        let guard = self
            .loopback_retry_after
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard
            .get(hostname)
            .is_some_and(|(due, _)| Instant::now() < *due)
    }

    /// Record a loopback-pinned refresh and schedule the next attempt,
    /// doubling the wait up to [`REFRESH_LOOPBACK_BACKOFF_MAX`].
    fn note_loopback_pinned(&self, hostname: &str) -> Duration {
        let mut guard = self
            .loopback_retry_after
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let next_wait = guard
            .get(hostname)
            .map(|(_, wait)| (*wait * 2).min(REFRESH_LOOPBACK_BACKOFF_MAX))
            .unwrap_or(REFRESH_LOOPBACK_BACKOFF_MIN);
        guard.insert(
            hostname.to_string(),
            (Instant::now() + next_wait, next_wait),
        );
        next_wait
    }

    /// Record a Mode-B self-intercepted refresh (the answer was our own
    /// fake-pool address) and schedule a FLAT re-check at the minimum wait.
    /// Never doubles: interception is a property of the resolver path, not of
    /// the host, so escalating would ban a perfectly healthy hostname. Also
    /// resets any escalated wait a real failure had accumulated — the host
    /// answered, just through the intercepted path.
    fn note_fake_intercepted(&self, hostname: &str) -> Duration {
        let mut guard = self
            .loopback_retry_after
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(
            hostname.to_string(),
            (
                Instant::now() + REFRESH_LOOPBACK_BACKOFF_MIN,
                REFRESH_LOOPBACK_BACKOFF_MIN,
            ),
        );
        REFRESH_LOOPBACK_BACKOFF_MIN
    }

    /// Drop `hostname`'s loopback retry gate — it refreshed to a routable
    /// address, so a later re-pin starts the backoff from the minimum again.
    fn clear_loopback_pinned(&self, hostname: &str) {
        let mut guard = self
            .loopback_retry_after
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(hostname);
    }

    /// Override the default negative TTL (seconds).
    pub fn with_negative_ttl_secs(mut self, secs: u64) -> Self {
        self.negative_ttl_secs = secs;
        self
    }

    /// Returns `true` the first time `hostname` is seen refreshing only to
    /// loopback/unspecified addresses; `false` while it repeats. Paired with
    /// [`Self::clear_loopback_log`], which re-arms the gate once `hostname`
    /// refreshes to a routable address again.
    fn note_loopback_log_once(&self, hostname: &str) -> bool {
        let mut guard = self
            .loopback_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(hostname.to_string())
    }

    /// Re-arm the loopback-log gate for `hostname` (see
    /// [`Self::note_loopback_log_once`]).
    fn clear_loopback_log(&self, hostname: &str) {
        let mut guard = self
            .loopback_logged
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(hostname);
    }

    /// Process up to `batch_limit` expired hostnames.
    ///
    /// `now` is injected to keep the orchestrator deterministic in
    /// tests. Production callers pass `SystemTime::now()`.
    pub fn run_once(&self, now: SystemTime, batch_limit: usize) -> RefreshSummary {
        let mut summary = RefreshSummary::default();

        let expired = match self.list_expired(now, batch_limit) {
            Ok(rows) => rows,
            Err(()) => {
                summary.cache_errors = summary.cache_errors.saturating_add(1);
                return summary;
            }
        };

        summary.attempted = expired.len() as u32;

        for row in expired {
            // Loopback-pinned rows keep re-expiring by design; honor their
            // in-memory backoff instead of re-querying every tick.
            if self.loopback_retry_suppressed(&row.canonical_hostname) {
                summary.skipped = summary.skipped.saturating_add(1);
                continue;
            }
            self.refresh_one(&row, now, &mut summary);
        }

        // when at least one resolution succeeded
        // (cache mutation observed), bump `cache_metadata.last_rebuild_at`
        // so explain output + diagnostics health surface a fresh
        // timestamp. Silent skip on lock failure: cache may still be
        // serving reads via another guard; the timestamp is best-
        // effort, not load-bearing for correctness.
        if summary.succeeded > 0 {
            self.touch_last_rebuild_at(now);
        }

        summary
    }

    fn touch_last_rebuild_at(&self, now: SystemTime) {
        let now_ms = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::dns",
                    "cache mutex poisoned; skipping touch_last_rebuild_at"
                );
                return;
            }
        };
        if let Err(e) = guard.touch_last_rebuild_at(now_ms) {
            tracing::warn!(
                target: "nrr::dns",
                error = %e,
                "touch_last_rebuild_at failed after successful DNS refresh batch"
            );
        }
    }

    fn list_expired(&self, now: SystemTime, limit: usize) -> Result<Vec<ExpiredHostname>, ()> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::dns",
                    "cache mutex poisoned; skipping refresh tick"
                );
                return Err(());
            }
        };
        match guard.list_expired_resolutions(now, limit) {
            Ok(v) => Ok(v),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::dns",
                    error = %e,
                    "list_expired_resolutions failed; skipping tick"
                );
                Err(())
            }
        }
    }

    fn refresh_one(&self, row: &ExpiredHostname, now: SystemTime, summary: &mut RefreshSummary) {
        match self.resolver.resolve_a(&row.canonical_hostname) {
            Ok(mut record) => {
                // Mode B self-interception: the OS resolver path is redirected
                // to our own resolver, so a system-level re-resolution hands
                // our fake-pool address back. That answer carries no signal
                // about the host — skip it on a FLAT short retry instead of
                // walking the hosts-file backoff ladder (observed :
                // youtube/ytimg banned for minutes by their own fake answers).
                let fake_intercepted = contains_fake_pool_addr(&record.addresses);
                // Drop non-routable IPs (loopback/unspecified) before writing
                // back. A hostname can flip to a hosts-file loopback pin
                // between refreshes; such a mapping must never re-enter the
                // cache (it would build a bogus /32 route out the secondary).
                record.addresses.retain(|ip| !is_non_routable_v4(ip));
                if record.addresses.is_empty() && fake_intercepted {
                    summary.skipped = summary.skipped.saturating_add(1);
                    summary.fake_intercepted = summary.fake_intercepted.saturating_add(1);
                    let wait = self.note_fake_intercepted(&row.canonical_hostname);
                    tracing::debug!(
                        target: "nrr::dns",
                        hostname = %row.canonical_hostname,
                        retry_in_secs = wait.as_secs(),
                        "refresh answered from our own fake-IP pool (Mode B interception) — skipped without backoff escalation",
                    );
                } else if record.addresses.is_empty() {
                    summary.skipped = summary.skipped.saturating_add(1);
                    summary.loopback_pinned = summary.loopback_pinned.saturating_add(1);
                    let wait = self.note_loopback_pinned(&row.canonical_hostname);
                    if self.note_loopback_log_once(&row.canonical_hostname) {
                        tracing::info!(
                            target: "nrr::dns",
                            hostname = %row.canonical_hostname,
                            retry_in_secs = wait.as_secs(),
                            "refresh resolved only to loopback/unspecified (hosts file?) — not cached",
                        );
                    } else {
                        tracing::debug!(
                            target: "nrr::dns",
                            hostname = %row.canonical_hostname,
                            retry_in_secs = wait.as_secs(),
                            "refresh still resolving only to loopback/unspecified (deduped; already logged this session)",
                        );
                    }
                    // Benign skip: nothing usable to write. Leaving the stale
                    // row in place lets a later refresh recover if the pin
                    // disappears. `succeeded` stays untouched, so this does not
                    // bump `last_rebuild_at`.
                } else {
                    self.clear_loopback_log(&row.canonical_hostname);
                    self.clear_loopback_pinned(&row.canonical_hostname);
                    if self.write_success(record, now) {
                        summary.succeeded = summary.succeeded.saturating_add(1);
                    } else {
                        summary.cache_errors = summary.cache_errors.saturating_add(1);
                    }
                }
            }
            Err(DnsResolverError::UnsupportedPlatform { reason }) => {
                tracing::info!(
                    target: "nrr::dns",
                    reason = %reason,
                    "DNS resolver unsupported on this platform; aborting refresh tick"
                );
                summary.skipped = summary.attempted.saturating_sub(
                    summary.succeeded + summary.failed_authoritative + summary.failed_transient,
                );
            }
            Err(err) => {
                let authoritative = err.is_authoritative();
                if self.write_failure(&row.canonical_hostname, &err, now) {
                    if authoritative {
                        summary.failed_authoritative =
                            summary.failed_authoritative.saturating_add(1);
                    } else {
                        summary.failed_transient = summary.failed_transient.saturating_add(1);
                    }
                } else {
                    summary.cache_errors = summary.cache_errors.saturating_add(1);
                }
            }
        }
    }

    fn write_success(&self, record: ResolvedRecord, now: SystemTime) -> bool {
        let entry = ResolutionEntry {
            canonical_hostname: record.canonical_hostname,
            raw_hostname_sample: None,
            resolved_ips: record.addresses,
            ttl_seconds: record.ttl_seconds,
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: None,
        };
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Err(e) = guard.upsert_resolution(entry) {
            tracing::warn!(
                target: "nrr::dns",
                error = %e,
                "upsert_resolution failed during refresh"
            );
            return false;
        }
        true
    }

    fn write_failure(&self, hostname: &str, err: &DnsResolverError, now: SystemTime) -> bool {
        // Authoritative errors get the full negative TTL; transient
        // errors get a shorter retry window so the refresh task picks
        // them up sooner.
        let (reason, retry_after_secs) = if err.is_authoritative() {
            (NegativeCacheReason::NxDomain, self.negative_ttl_secs)
        } else {
            (
                NegativeCacheReason::ResolveFailed,
                (self.negative_ttl_secs / 4).max(15),
            )
        };
        let retry_after = now + Duration::from_secs(retry_after_secs);
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Err(e) = guard.record_failed_resolution(
            hostname,
            reason,
            retry_after,
            StorageResolutionSource::Dns,
        ) {
            tracing::warn!(
                target: "nrr::dns",
                error = %e,
                hostname = %hostname,
                "record_failed_resolution failed during refresh"
            );
            return false;
        }
        true
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_platform_api::dns::{MockDnsResolver, ResolvedRecord};
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::store::SqliteCacheStore;
    use rusqlite::Connection;

    /// Build an in-memory `SqliteCacheStore` for unit tests. WAL is
    /// fine on file-backed DBs but for in-memory DBs SQLite uses
    /// rollback journals automatically — the migration runner accepts
    /// both.
    fn make_cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
        let conn = Connection::open_in_memory().expect("in-memory");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        // Small `fallback_ttl_secs` floor so these expiry-mechanism tests can
        // seed short-TTL rows that actually expire. Production floors to a week
        // for leak-guard stickiness (HW-0705), which would keep every seeded
        // row unexpired and defeat the refresh tests.
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds {
                fallback_ttl_secs: 10,
                ..FreshnessThresholds::default_production()
            },
        );
        Arc::new(Mutex::new(store))
    }

    fn seed_expired(
        cache: &Arc<Mutex<dyn CacheRepository + Send>>,
        hostname: &str,
        ip: Ipv4Addr,
        resolved_at: SystemTime,
        ttl: u32,
    ) {
        let guard = cache.lock().unwrap();
        guard
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: hostname.into(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(ttl),
                source: StorageResolutionSource::Dns,
                resolved_at,
                active_revision_id: None,
            })
            .expect("seed upsert");
    }

    #[test]
    fn note_loopback_log_once_dedups_until_cleared() {
        let resolver: Arc<dyn DnsResolverPort> = Arc::new(MockDnsResolver::new());
        let orchestrator = DnsRefreshOrchestrator::new(resolver, make_cache());
        assert!(
            orchestrator.note_loopback_log_once("ad.test"),
            "first sighting logs"
        );
        assert!(
            !orchestrator.note_loopback_log_once("ad.test"),
            "repeat sighting is deduped"
        );
        orchestrator.clear_loopback_log("ad.test");
        assert!(
            orchestrator.note_loopback_log_once("ad.test"),
            "cleared state re-arms the gate"
        );
    }

    #[test]
    fn loopback_pinned_hostname_is_not_requeried_every_tick() {
        // A loopback-pinned row is deliberately left in the cache (so it can
        // recover if the pin disappears), which means `list_expired_resolutions`
        // keeps offering it on every tick. Without a backoff each tick re-queries
        // it, and on a preset full of provider-stubbed names that chatter rotated
        // real history out of the operational log.
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_response(
            "ad.test",
            ResolvedRecord {
                canonical_hostname: "ad.test".into(),
                addresses: vec![Ipv4Addr::new(127, 0, 0, 1)],
                ttl_seconds: Some(120),
            },
        );
        let cache = make_cache();
        seed_expired(
            &cache,
            "ad.test",
            Ipv4Addr::new(198, 51, 100, 9),
            now - Duration::from_secs(3_600),
            60,
        );
        let orchestrator = DnsRefreshOrchestrator::new(
            Arc::clone(&resolver_mock) as Arc<dyn DnsResolverPort>,
            cache,
        );

        let first = orchestrator.run_once(now, 16);
        assert_eq!(first.attempted, 1);
        assert_eq!(resolver_mock.observed_queries().len(), 1);

        let second = orchestrator.run_once(now, 16);
        assert_eq!(
            resolver_mock.observed_queries().len(),
            1,
            "the pinned host must stay inside its backoff instead of being re-queried"
        );
        assert_eq!(second.skipped, 1, "the skip is reported, not silent");
    }

    #[test]
    fn a_routable_refresh_clears_the_loopback_backoff() {
        let orchestrator = DnsRefreshOrchestrator::new(
            Arc::new(MockDnsResolver::new()) as Arc<dyn DnsResolverPort>,
            make_cache(),
        );
        orchestrator.note_loopback_pinned("ad.test");
        assert!(orchestrator.loopback_retry_suppressed("ad.test"));
        orchestrator.clear_loopback_pinned("ad.test");
        assert!(
            !orchestrator.loopback_retry_suppressed("ad.test"),
            "a host that resolves again must be retried at once"
        );
    }

    #[test]
    fn run_once_returns_empty_summary_when_cache_has_no_expired() {
        let resolver: Arc<dyn DnsResolverPort> = Arc::new(MockDnsResolver::new());
        let cache = make_cache();
        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache);
        let summary = orchestrator.run_once(SystemTime::now(), 16);
        assert_eq!(summary, RefreshSummary::default());
        assert!(!summary.made_progress());
    }

    #[test]
    fn run_once_resolves_expired_hostname_and_writes_back() {
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_response(
            "expired.test",
            ResolvedRecord {
                canonical_hostname: "expired.test".into(),
                addresses: vec![Ipv4Addr::new(203, 0, 113, 5)],
                ttl_seconds: Some(120),
            },
        );
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock.clone();
        let cache = make_cache();
        seed_expired(
            &cache,
            "expired.test",
            Ipv4Addr::new(198, 51, 100, 1),
            now - Duration::from_secs(3_600),
            60,
        );

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache.clone());
        let summary = orchestrator.run_once(now, 16);
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed_authoritative, 0);
        assert_eq!(summary.failed_transient, 0);
        assert_eq!(summary.cache_errors, 0);

        // Resolver was asked exactly once for the hostname during the
        // refresh pass.
        assert_eq!(
            resolver_mock.observed_queries(),
            vec!["expired.test".to_string()]
        );

        // The newly-resolved IP must be present in the cache and
        // freshness-classified as Fresh. The previously-seeded
        // expired row stays in the table until `cleanup_expired`
        // prunes it — that is the production contract: the refresh
        // task adds, the cleanup task prunes.
        let guard = cache.lock().unwrap();
        let lookup = guard
            .get_by_hostname(
                "expired.test",
                &FreshnessThresholds::default_production(),
                nrr_storage::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("lookup after refresh");
        assert!(lookup
            .resolved_ips
            .iter()
            .any(|e| e.addr == Ipv4Addr::new(203, 0, 113, 5)
                && e.cache_state == nrr_domain::decision_lookup::CacheEntryState::Fresh));

        // successful refresh batch must bump
        // `cache_metadata.last_rebuild_at` so explain output reflects
        // the cache's last-good-update timestamp.
        let last_rebuild = guard
            .get_last_rebuild_at_ms()
            .expect("get_last_rebuild_at_ms");
        assert!(
            last_rebuild.is_some(),
            "last_rebuild_at must be populated after successful refresh"
        );
    }

    #[test]
    fn run_once_does_not_touch_last_rebuild_at_when_no_progress() {
        // empty refresh tick (no expired rows) must
        // NOT bump last_rebuild_at: the column reflects "cache content
        // changed", not "task ticked".
        let resolver: Arc<dyn DnsResolverPort> = Arc::new(MockDnsResolver::new());
        let cache = make_cache();
        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache.clone());
        let summary = orchestrator.run_once(SystemTime::now(), 16);
        assert_eq!(summary.succeeded, 0);

        let guard = cache.lock().unwrap();
        let last_rebuild = guard
            .get_last_rebuild_at_ms()
            .expect("get_last_rebuild_at_ms");
        assert!(
            last_rebuild.is_none(),
            "last_rebuild_at must stay None when no progress made"
        );
    }

    #[test]
    fn run_once_skips_writing_loopback_only_resolution() {
        // A previously-cached hostname now resolves only to loopback (e.g. it
        // got pinned in an ad-blocking hosts file). The refresh must not write
        // the loopback IP back into the cache.
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_response(
            "ad.test",
            ResolvedRecord {
                canonical_hostname: "ad.test".into(),
                addresses: vec![Ipv4Addr::new(127, 0, 0, 1)],
                ttl_seconds: Some(120),
            },
        );
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock;
        let cache = make_cache();
        seed_expired(
            &cache,
            "ad.test",
            Ipv4Addr::new(198, 51, 100, 9),
            now - Duration::from_secs(3_600),
            60,
        );

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache.clone());
        let summary = orchestrator.run_once(now, 16);
        assert_eq!(summary.attempted, 1);
        assert_eq!(
            summary.succeeded, 0,
            "a loopback-only resolution is not written back"
        );
        assert_eq!(summary.cache_errors, 0);
        // the row must land in a counter — a bucketless attempt
        // makes the tick log unable to account for its own batch.
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.loopback_pinned, 1);
        assert_eq!(summary.fake_intercepted, 0);

        // No successful cache mutation → last_rebuild_at must stay None.
        let guard = cache.lock().unwrap();
        assert!(guard
            .get_last_rebuild_at_ms()
            .expect("get_last_rebuild_at_ms")
            .is_none());
    }

    #[test]
    fn run_once_skips_fake_pool_answer_without_backoff_escalation() {
        // Mode B self-interception: the system resolver hands back OUR OWN
        // fake-pool address. It must not be cached, and — unlike a hosts-file
        // loopback pin — it must never walk the doubling backoff ladder
        // : youtube/ytimg spent minutes banned by their own
        // virtual answers during a fake-IP datapath outage).
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_response(
            "tube.test",
            ResolvedRecord {
                canonical_hostname: "tube.test".into(),
                addresses: vec![Ipv4Addr::new(198, 18, 0, 60)],
                ttl_seconds: Some(120),
            },
        );
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock;
        let cache = make_cache();
        seed_expired(
            &cache,
            "tube.test",
            Ipv4Addr::new(198, 51, 100, 9),
            now - Duration::from_secs(3_600),
            60,
        );

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache.clone());
        let summary = orchestrator.run_once(now, 16);
        assert_eq!(summary.attempted, 1);
        assert_eq!(
            summary.succeeded, 0,
            "a fake-pool answer is not written back"
        );
        // the interception must be visible in the tick counters
        // (44% of a phase's attempts once vanished into this branch).
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.fake_intercepted, 1);
        assert_eq!(summary.loopback_pinned, 0);
        {
            let guard = cache.lock().unwrap();
            assert!(guard
                .get_last_rebuild_at_ms()
                .expect("get_last_rebuild_at_ms")
                .is_none());
        }

        // The retry gate is armed (no immediate re-query hammering)…
        assert!(orchestrator.loopback_retry_suppressed("tube.test"));
        // …but the wait NEVER escalates on repeats, unlike a loopback pin.
        assert_eq!(
            orchestrator.note_fake_intercepted("tube.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN
        );
        assert_eq!(
            orchestrator.note_fake_intercepted("tube.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN,
            "flat wait: interception is a resolver-path property, not a host property"
        );
        // Contrast: the loopback ladder doubles from wherever the gate stands.
        assert_eq!(
            orchestrator.note_loopback_pinned("pin.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN
        );
        assert_eq!(
            orchestrator.note_loopback_pinned("pin.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN * 2
        );
        // A fake-intercepted verdict RESETS an escalated ladder: the host is
        // alive, only the path is intercepted.
        assert_eq!(
            orchestrator.note_fake_intercepted("pin.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN
        );
        assert_eq!(
            orchestrator.note_loopback_pinned("pin.test"),
            REFRESH_LOOPBACK_BACKOFF_MIN * 2,
            "ladder resumes doubling from the reset minimum"
        );
    }

    #[test]
    fn run_once_records_negative_but_keeps_last_known_good_on_nxdomain() {
        // leak-guard stickiness: an NXDOMAIN on re-resolution records
        // a negative cache entry, but the previously-resolved (last-known-good)
        // address is RETAINED and still served, so the /32 the leak-guard and
        // routing depend on does not vanish on a transient/failed re-resolution.
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_error(
            "gone.test",
            DnsResolverError::NxDomain {
                hostname: "gone.test".into(),
            },
        );
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock;
        let cache = make_cache();
        seed_expired(
            &cache,
            "gone.test",
            Ipv4Addr::new(198, 51, 100, 2),
            now - Duration::from_secs(3_600),
            60,
        );

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache.clone());
        let summary = orchestrator.run_once(now, 16);
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.failed_authoritative, 1);
        assert_eq!(summary.succeeded, 0);

        let guard = cache.lock().unwrap();
        // The negative cache WAS recorded (the orchestrator did its job)...
        assert_eq!(
            guard.get_cache_stats().expect("stats").negative_cache_count,
            1,
            "NXDOMAIN must record a negative cache entry"
        );
        // ...but the last-known-good positive still wins the lookup — it is not
        // purged, and the negative does not shadow it.
        let lookup = guard
            .get_by_hostname(
                "gone.test",
                &FreshnessThresholds::default_production(),
                nrr_storage::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("lookup");
        assert_ne!(
            lookup.overall_freshness,
            Some(nrr_domain::decision_lookup::CacheEntryState::NegativeCached),
            "last-known-good must survive a transient NXDOMAIN"
        );
        assert_eq!(
            lookup.resolved_ips.first().map(|e| e.addr),
            Some(Ipv4Addr::new(198, 51, 100, 2)),
            "the previously-resolved address is retained"
        );
    }

    #[test]
    fn run_once_writes_short_negative_cache_on_timeout() {
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        resolver_mock.set_error(
            "slow.test",
            DnsResolverError::Timeout {
                hostname: "slow.test".into(),
            },
        );
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock;
        let cache = make_cache();
        seed_expired(
            &cache,
            "slow.test",
            Ipv4Addr::new(198, 51, 100, 3),
            now - Duration::from_secs(3_600),
            60,
        );

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache).with_negative_ttl_secs(300);
        let summary = orchestrator.run_once(now, 16);
        assert_eq!(summary.failed_transient, 1);
        assert_eq!(summary.failed_authoritative, 0);
    }

    #[test]
    fn run_once_respects_batch_limit() {
        let now = SystemTime::now();
        let resolver_mock = Arc::new(MockDnsResolver::new());
        for i in 0..5 {
            let host = format!("h{i}.test");
            resolver_mock.set_response(
                &host,
                ResolvedRecord {
                    canonical_hostname: host.clone(),
                    addresses: vec![Ipv4Addr::new(10, 0, 0, i)],
                    ttl_seconds: Some(60),
                },
            );
        }
        let resolver: Arc<dyn DnsResolverPort> = resolver_mock.clone();
        let cache = make_cache();
        for i in 0..5 {
            seed_expired(
                &cache,
                &format!("h{i}.test"),
                Ipv4Addr::new(192, 0, 2, i),
                now - Duration::from_secs(3_600),
                60,
            );
        }

        let orchestrator = DnsRefreshOrchestrator::new(resolver, cache);
        let summary = orchestrator.run_once(now, 2);
        assert_eq!(summary.attempted, 2);
        assert_eq!(summary.succeeded, 2);
        // The remaining 3 hostnames stay expired until the next tick.
    }
}

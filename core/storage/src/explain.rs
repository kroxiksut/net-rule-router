//! Privacy-tiered explain metadata, retention policy, and cache diagnostic
//! summary.
//!
//! # Privacy model
//!
//! Three redaction levels control what explain detail is surfaced to callers:
//!
//! | Level        | What is revealed                                                 |
//! |--------------|------------------------------------------------------------------|
//! | `Compact`    | Cache hit/miss, freshness label, source label, error presence    |
//! | `Standard`   | + selected IP, ambiguity/conflict flags, TTL                     |
//! | `Diagnostics`| + all resolved IPs, reverse hostnames, resolution timestamps     |
//!
//! `Compact` is safe for the normal explain panel shown to all users.
//! `Standard` is the default for the diagnostics drawer / explain detail view.
//! `Diagnostics` requires explicit developer/diagnostics mode opt-in.
//!
//! # Boundary
//!
//! - `LookupExplainSummary` is a storage-layer view built from `CacheLookupResult`.
//! - `CacheDiagnosticSummary` is a GUI-facing DTO for the health / diagnostics
//!   surface exposed by the service facade.
//! - `diagnostic_flags` bitfield (`DiagnosticFlags`) must never appear in
//!   `Compact` output — only aggregated boolean signals are safe.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use nrr_domain::decision_lookup::CacheEntryState;

use crate::dto::OverallHealthState;
use crate::dto::{CacheLookupResult, CacheStats, StorageHealthStatus};
use crate::resolution_source::StorageResolutionSource;

// ── DiagnosticRedactionLevel ──────────────────────────────────────────────────

/// How much explain detail is revealed in a given display context.
///
/// The levels are ordered from least to most revealing; `>=` comparisons
/// can be used to check whether a level includes a feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum DiagnosticRedactionLevel {
    /// Safe for the normal explain panel: only categorical labels, no addresses.
    Compact,
    /// Extended explain / diagnostics drawer: adds selected IP, ambiguity flags.
    #[default]
    Standard,
    /// Developer / full diagnostics mode: reveals all IPs, hostnames, timestamps.
    Diagnostics,
}

// ── LookupExplainSummary ──────────────────────────────────────────────────────

/// Storage-side privacy-filtered explain snapshot, ready for the service facade.
///
/// Fields in each tier are populated only when the chosen redaction level
/// permits them.  Callers must not assume that any `Option` field is present
/// at a lower redaction level than documented.
///
/// # Field tiers
///
/// **Compact** (always present):
/// - `cache_hit`, `freshness_label`, `source_label`, `has_errors`
///
/// **Standard** (present when `level >= Standard`):
/// - `selected_ip`, `is_multi_ip`, `has_conflict`, `ttl_seconds`
///
/// **Diagnostics** (present when `level >= Diagnostics`):
/// - `all_resolved_ips`, `reverse_hostnames`, `resolved_at`, `expires_at`
#[derive(Clone, Debug)]
pub struct LookupExplainSummary {
    // ── Compact tier (always populated) ──────────────────────────────────────
    /// Whether any usable cache entry was found for this lookup.
    pub cache_hit: bool,
    /// Human-readable freshness label of the best cache entry.
    /// `None` when no entry exists (`Missing` state).
    pub freshness_label: Option<&'static str>,
    /// Human-readable source label of the best cache entry.
    /// `None` when no entry exists.
    pub source_label: Option<&'static str>,
    /// `true` when any lookup errors were recorded.
    pub has_errors: bool,

    // ── Standard tier (populated when level >= Standard) ──────────────────
    /// The IPv4 address that was selected for `ExactIp` matching.
    pub selected_ip: Option<Ipv4Addr>,
    /// Whether multiple IPs map to the same hostname (ambiguity marker).
    pub is_multi_ip: bool,
    /// Whether the observed IP was not found in the cached hostname IP set.
    pub has_conflict: bool,
    /// TTL of the selected cache entry (seconds).
    pub ttl_seconds: Option<u32>,

    // ── Diagnostics tier (populated when level >= Diagnostics) ────────────
    /// All resolved IPv4 addresses for the hostname.
    pub all_resolved_ips: Option<Vec<Ipv4Addr>>,
    /// Reverse-resolved hostnames for the observed IP.
    pub reverse_hostnames: Option<Vec<String>>,
    /// When the selected entry was resolved.
    pub resolved_at: Option<SystemTime>,
    /// When the selected entry expires (absolute time).
    pub expires_at: Option<SystemTime>,
}

// ── build_explain_summary ─────────────────────────────────────────────────────

/// Builds a privacy-filtered explain summary from a raw cache lookup result.
///
/// The returned `LookupExplainSummary` only populates fields permitted by
/// `level`.  Higher tiers include all lower-tier fields.
pub fn build_explain_summary(
    result: &CacheLookupResult,
    level: DiagnosticRedactionLevel,
) -> LookupExplainSummary {
    let best = best_ip_entry(result);

    // ── Compact ───────────────────────────────────────────────────────────────
    let cache_hit = !result.resolved_ips.is_empty()
        && result
            .overall_freshness
            .as_ref()
            .map(|f| f.is_usable_for_matching())
            .unwrap_or(false);

    let freshness_label = result.overall_freshness.as_ref().map(freshness_label_of);
    let source_label = result.best_source.as_ref().map(source_label_of);
    let has_errors = !result.errors.is_empty();

    if level == DiagnosticRedactionLevel::Compact {
        return LookupExplainSummary {
            cache_hit,
            freshness_label,
            source_label,
            has_errors,
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            ttl_seconds: None,
            all_resolved_ips: None,
            reverse_hostnames: None,
            resolved_at: None,
            expires_at: None,
        };
    }

    // ── Standard ─────────────────────────────────────────────────────────────
    let selected_ip = best.map(|e| e.addr);
    let is_multi_ip = result.is_multi_ip;
    let has_conflict = result.has_conflict;
    let ttl_seconds = best.and_then(|e| e.ttl_seconds);

    if level == DiagnosticRedactionLevel::Standard {
        return LookupExplainSummary {
            cache_hit,
            freshness_label,
            source_label,
            has_errors,
            selected_ip,
            is_multi_ip,
            has_conflict,
            ttl_seconds,
            all_resolved_ips: None,
            reverse_hostnames: None,
            resolved_at: None,
            expires_at: None,
        };
    }

    // ── Diagnostics ──────────────────────────────────────────────────────────
    LookupExplainSummary {
        cache_hit,
        freshness_label,
        source_label,
        has_errors,
        selected_ip,
        is_multi_ip,
        has_conflict,
        ttl_seconds,
        all_resolved_ips: Some(result.resolved_ips.iter().map(|e| e.addr).collect()),
        reverse_hostnames: Some(
            result
                .reverse_hostnames
                .iter()
                .map(|h| h.hostname.clone())
                .collect(),
        ),
        resolved_at: best.and_then(|e| e.resolved_at),
        expires_at: best.and_then(|e| e.expires_at),
    }
}

// ── RetentionKnobs ────────────────────────────────────────────────────────────

/// Retention policy knobs for the lookup events cleanup pass.
///
/// These values are consumed by `CleanupPolicy` (via the service loop)
/// to decide when to expire lookup history rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionKnobs {
    /// Maximum number of lookup event rows to keep (overflow trimmed oldest-first).
    pub max_lookup_events: usize,
    /// Maximum age for full lookup events (seconds).  Rows older than this are
    /// removed regardless of `max_lookup_events`.
    pub max_event_age_secs: u64,
    /// Maximum rows removed per single SQL DELETE (prevents lock starvation).
    pub cleanup_batch_size: usize,
    /// Redaction level to apply when exporting diagnostic snapshots.
    pub diagnostic_export_level: DiagnosticRedactionLevel,
}

impl Default for RetentionKnobs {
    fn default() -> Self {
        Self {
            max_lookup_events: 500,
            max_event_age_secs: 86_400, // 24 h
            cleanup_batch_size: 200,
            diagnostic_export_level: DiagnosticRedactionLevel::Standard,
        }
    }
}

impl RetentionKnobs {
    /// Converts these knobs into the `CleanupPolicy` used by `cleanup_expired`.
    pub fn to_cleanup_policy(&self) -> crate::dto::CleanupPolicy {
        crate::dto::CleanupPolicy {
            max_negative_cache_age_secs: 3_600,
            max_lookup_events: self.max_lookup_events,
            max_lookup_event_age_secs: self.max_event_age_secs,
            batch_size: self.cleanup_batch_size,
            run_vacuum: false,
        }
    }
}

// ── CacheDiagnosticSummary ────────────────────────────────────────────────────

/// Aggregated cache health and lookup statistics for the GUI diagnostics surface.
///
/// Produced by the service layer from `StorageHealthStatus` and
/// `CacheStats`.  No raw hostnames, IPs, or SQL internals are exposed.
///
/// The GUI receives this through the service facade over IPC —
/// it never reads SQLite directly.
#[derive(Clone, Debug)]
pub struct CacheDiagnosticSummary {
    // ── Metadata (from schema_migrations + cache_metadata) ────────────────────
    pub schema_version: Option<u32>,
    pub cache_generation: u64,
    pub last_cleanup_at: Option<SystemTime>,
    pub last_rebuild_at: Option<SystemTime>,
    pub last_integrity_check_at: Option<SystemTime>,

    // ── Live counts (from data tables) ───────────────────────────────────────
    pub hostname_count: u64,
    pub ip_count: u64,
    pub resolution_count: u64,
    pub stale_resolution_count: u64,
    pub negative_cache_count: u64,
    pub lookup_events_count: u64,

    // ── Aggregate health ─────────────────────────────────────────────────────
    pub overall_health: OverallHealthState,
    pub diagnostic_level: DiagnosticRedactionLevel,
}

/// Builds a `CacheDiagnosticSummary` from a health snapshot and live stats.
///
/// `level` must match the diagnostic_export_level in `RetentionKnobs` (or be
/// at most `Standard` when exposing over IPC to untrusted callers).
pub fn build_cache_diagnostic_summary(
    health: &StorageHealthStatus,
    stats: &CacheStats,
    level: DiagnosticRedactionLevel,
) -> CacheDiagnosticSummary {
    CacheDiagnosticSummary {
        schema_version: health.cache_db.schema_version,
        cache_generation: stats.cache_generation,
        last_cleanup_at: health.cache_db.last_cleanup_at,
        // `DbHealthStatus.last_rebuild_at` is populated by
        // `SqliteCacheStore::check_health`. `DnsRefreshOrchestrator` bumps
        // the underlying `cache_metadata.last_rebuild_at` after each
        // successful batch, so this surface reflects the cache's
        // last-known good update timestamp.
        last_rebuild_at: health.cache_db.last_rebuild_at,
        last_integrity_check_at: health.cache_db.last_integrity_check_at,
        hostname_count: stats.hostname_count,
        ip_count: stats.ip_count,
        resolution_count: stats.resolution_count,
        stale_resolution_count: stats.stale_resolution_count,
        negative_cache_count: stats.negative_cache_count,
        lookup_events_count: stats.lookup_events_count,
        overall_health: health.cache_db.overall.clone(),
        diagnostic_level: level,
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns the best usable IP entry from the lookup result (Fresh > StaleUsable;
/// Dns/ManualRefresh > ObservedFromTraffic).
fn best_ip_entry(result: &CacheLookupResult) -> Option<&crate::dto::CachedIpEntry> {
    result
        .resolved_ips
        .iter()
        .filter(|e| e.cache_state.is_usable_for_matching())
        .max_by_key(|e| {
            let f = match &e.cache_state {
                CacheEntryState::Fresh => 2u8,
                CacheEntryState::StaleUsable => 1,
                _ => 0,
            };
            let s = match &e.source {
                StorageResolutionSource::Dns | StorageResolutionSource::ManualRefresh => 2u8,
                StorageResolutionSource::ObservedFromTraffic => 1,
                _ => 0,
            };
            (f, s)
        })
}

fn freshness_label_of(state: &CacheEntryState) -> &'static str {
    match state {
        CacheEntryState::Fresh => "fresh",
        CacheEntryState::StaleUsable => "stale_usable",
        CacheEntryState::StaleNotUsable => "stale_not_usable",
        CacheEntryState::Conflicting => "conflicting",
        CacheEntryState::NegativeCached => "negative_cached",
        CacheEntryState::Missing => "missing",
    }
}

fn source_label_of(source: &StorageResolutionSource) -> &'static str {
    match source {
        StorageResolutionSource::Dns => "dns",
        StorageResolutionSource::ObservedFromTraffic => "observed",
        StorageResolutionSource::ManualRefresh => "manual",
        StorageResolutionSource::ImportedSeed => "imported",
        StorageResolutionSource::CacheRebuild => "rebuild",
        StorageResolutionSource::OsCacheSeed => "os_cache",
        StorageResolutionSource::ReverseConfirmed => "reverse_confirmed",
        StorageResolutionSource::BrowserHistorySeed => "browser_history",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use nrr_domain::decision_lookup::{CacheEntryState, LookupError};

    use crate::dto::{CacheLookupResult, CachedHostnameEntry, CachedIpEntry};
    use crate::resolution_source::StorageResolutionSource;

    fn fresh_result(ip: Ipv4Addr) -> CacheLookupResult {
        let now = SystemTime::now();
        let expires = now + Duration::from_secs(300);
        CacheLookupResult {
            resolved_ips: vec![CachedIpEntry {
                addr: ip,
                cache_state: CacheEntryState::Fresh,
                source: StorageResolutionSource::Dns,
                resolved_at: Some(now),
                ttl_seconds: Some(300),
                expires_at: Some(expires),
                active_revision_id: None,
            }],
            reverse_hostnames: Vec::new(),
            overall_freshness: Some(CacheEntryState::Fresh),
            best_source: Some(StorageResolutionSource::Dns),
            is_multi_ip: false,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        }
    }

    fn missing_result() -> CacheLookupResult {
        CacheLookupResult {
            resolved_ips: Vec::new(),
            reverse_hostnames: Vec::new(),
            overall_freshness: None,
            best_source: None,
            is_multi_ip: false,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        }
    }

    fn conflict_result(cached_ip: Ipv4Addr) -> CacheLookupResult {
        let mut r = fresh_result(cached_ip);
        r.has_conflict = true;
        r
    }

    fn multi_ip_result() -> CacheLookupResult {
        let now = SystemTime::now();
        CacheLookupResult {
            resolved_ips: vec![
                CachedIpEntry {
                    addr: Ipv4Addr::new(1, 1, 1, 1),
                    cache_state: CacheEntryState::Fresh,
                    source: StorageResolutionSource::Dns,
                    resolved_at: Some(now),
                    ttl_seconds: Some(60),
                    expires_at: Some(now + Duration::from_secs(60)),
                    active_revision_id: None,
                },
                CachedIpEntry {
                    addr: Ipv4Addr::new(1, 0, 0, 1),
                    cache_state: CacheEntryState::Fresh,
                    source: StorageResolutionSource::Dns,
                    resolved_at: Some(now),
                    ttl_seconds: Some(60),
                    expires_at: Some(now + Duration::from_secs(60)),
                    active_revision_id: None,
                },
            ],
            reverse_hostnames: Vec::new(),
            overall_freshness: Some(CacheEntryState::Fresh),
            best_source: Some(StorageResolutionSource::Dns),
            is_multi_ip: true,
            has_conflict: false,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        }
    }

    fn error_result() -> CacheLookupResult {
        let mut r = missing_result();
        r.errors = vec![LookupError::DnsResolveFailed];
        r
    }

    // ── DiagnosticRedactionLevel ordering ────────────────────────────────────

    #[test]
    fn redaction_levels_are_ordered_compact_lt_standard_lt_diagnostics() {
        assert!(DiagnosticRedactionLevel::Compact < DiagnosticRedactionLevel::Standard);
        assert!(DiagnosticRedactionLevel::Standard < DiagnosticRedactionLevel::Diagnostics);
    }

    // ── build_explain_summary — Compact ──────────────────────────────────────

    #[test]
    fn compact_fresh_hit_sets_cache_hit_and_labels() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let result = fresh_result(ip);
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Compact);

        assert!(summary.cache_hit);
        assert_eq!(summary.freshness_label, Some("fresh"));
        assert_eq!(summary.source_label, Some("dns"));
        assert!(!summary.has_errors);
    }

    #[test]
    fn compact_hides_ip_and_timestamps() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let result = fresh_result(ip);
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Compact);

        assert!(
            summary.selected_ip.is_none(),
            "IP must be hidden in Compact mode"
        );
        assert!(summary.all_resolved_ips.is_none());
        assert!(summary.reverse_hostnames.is_none());
        assert!(summary.resolved_at.is_none());
        assert!(summary.expires_at.is_none());
        assert!(!summary.is_multi_ip, "multi_ip flag hidden in Compact mode");
        assert!(!summary.has_conflict);
    }

    #[test]
    fn compact_missing_has_no_freshness_label() {
        let result = missing_result();
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Compact);

        assert!(!summary.cache_hit);
        assert!(summary.freshness_label.is_none());
        assert!(summary.source_label.is_none());
    }

    #[test]
    fn compact_error_sets_has_errors() {
        let result = error_result();
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Compact);
        assert!(summary.has_errors);
    }

    // ── build_explain_summary — Standard ─────────────────────────────────────

    #[test]
    fn standard_reveals_selected_ip() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let result = fresh_result(ip);
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Standard);

        assert_eq!(summary.selected_ip, Some(ip));
    }

    #[test]
    fn standard_reveals_conflict_and_multi_ip_flags() {
        let result = conflict_result(Ipv4Addr::new(5, 6, 7, 8));
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Standard);
        assert!(summary.has_conflict);

        let multi = multi_ip_result();
        let ms = build_explain_summary(&multi, DiagnosticRedactionLevel::Standard);
        assert!(ms.is_multi_ip);
    }

    #[test]
    fn standard_reveals_ttl() {
        let ip = Ipv4Addr::new(1, 1, 1, 1);
        let result = fresh_result(ip);
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Standard);
        assert_eq!(summary.ttl_seconds, Some(300));
    }

    #[test]
    fn standard_still_hides_all_ips_and_timestamps() {
        let result = multi_ip_result();
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Standard);
        assert!(
            summary.all_resolved_ips.is_none(),
            "all IPs hidden at Standard level"
        );
        assert!(summary.resolved_at.is_none());
        assert!(summary.expires_at.is_none());
    }

    // ── build_explain_summary — Diagnostics ──────────────────────────────────

    #[test]
    fn diagnostics_reveals_all_resolved_ips() {
        let result = multi_ip_result();
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Diagnostics);

        let ips = summary
            .all_resolved_ips
            .expect("all_resolved_ips must be Some at Diagnostics");
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(ips.contains(&Ipv4Addr::new(1, 0, 0, 1)));
    }

    #[test]
    fn diagnostics_reveals_timestamps() {
        let ip = Ipv4Addr::new(8, 8, 8, 8);
        let result = fresh_result(ip);
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Diagnostics);

        assert!(summary.resolved_at.is_some());
        assert!(summary.expires_at.is_some());
    }

    #[test]
    fn diagnostics_reveals_reverse_hostnames() {
        let ip = Ipv4Addr::new(9, 9, 9, 9);
        let mut result = fresh_result(ip);
        result.reverse_hostnames = vec![CachedHostnameEntry {
            hostname: "dns.quad9.net".to_string(),
            cache_state: CacheEntryState::Fresh,
        }];
        let summary = build_explain_summary(&result, DiagnosticRedactionLevel::Diagnostics);

        let hosts = summary
            .reverse_hostnames
            .expect("reverse hostnames at Diagnostics");
        assert_eq!(hosts, ["dns.quad9.net"]);
    }

    // ── RetentionKnobs ───────────────────────────────────────────────────────

    #[test]
    fn retention_knobs_default_is_sane() {
        let k = RetentionKnobs::default();
        assert_eq!(k.max_lookup_events, 500);
        assert_eq!(k.max_event_age_secs, 86_400);
        assert_eq!(k.cleanup_batch_size, 200);
        assert_eq!(
            k.diagnostic_export_level,
            DiagnosticRedactionLevel::Standard
        );
    }

    #[test]
    fn retention_knobs_to_cleanup_policy_maps_fields() {
        let k = RetentionKnobs {
            max_lookup_events: 100,
            max_event_age_secs: 3_600,
            cleanup_batch_size: 50,
            diagnostic_export_level: DiagnosticRedactionLevel::Compact,
        };
        let policy = k.to_cleanup_policy();
        assert_eq!(policy.max_lookup_events, 100);
        assert_eq!(policy.max_lookup_event_age_secs, 3_600);
        assert_eq!(policy.batch_size, 50);
        assert!(!policy.run_vacuum);
    }

    // ── freshness / source labels ────────────────────────────────────────────

    #[test]
    fn freshness_labels_cover_all_variants() {
        let variants = [
            (CacheEntryState::Fresh, "fresh"),
            (CacheEntryState::StaleUsable, "stale_usable"),
            (CacheEntryState::StaleNotUsable, "stale_not_usable"),
            (CacheEntryState::Conflicting, "conflicting"),
            (CacheEntryState::NegativeCached, "negative_cached"),
            (CacheEntryState::Missing, "missing"),
        ];
        for (variant, expected) in &variants {
            assert_eq!(freshness_label_of(variant), *expected);
        }
    }

    #[test]
    fn source_labels_cover_all_variants() {
        let variants = [
            (StorageResolutionSource::Dns, "dns"),
            (StorageResolutionSource::ObservedFromTraffic, "observed"),
            (StorageResolutionSource::ManualRefresh, "manual"),
            (StorageResolutionSource::ImportedSeed, "imported"),
            (StorageResolutionSource::CacheRebuild, "rebuild"),
        ];
        for (variant, expected) in &variants {
            assert_eq!(source_label_of(variant), *expected);
        }
    }

    // ── build_cache_diagnostic_summary ───────────────────────────────────────

    #[test]
    fn cache_diagnostic_summary_fields_from_health_and_stats() {
        use crate::dto::{DbHealthStatus, StorageHealthStatus};

        let health = StorageHealthStatus {
            cache_db: DbHealthStatus {
                path_exists: true,
                schema_version: Some(1),
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            state_db: DbHealthStatus {
                path_exists: true,
                schema_version: Some(2),
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            checked_at: SystemTime::now(),
        };
        let stats = CacheStats {
            hostname_count: 10,
            ip_count: 15,
            resolution_count: 12,
            stale_resolution_count: 2,
            negative_cache_count: 3,
            lookup_events_count: 50,
            cache_generation: 1,
        };

        let summary =
            build_cache_diagnostic_summary(&health, &stats, DiagnosticRedactionLevel::Standard);

        assert_eq!(summary.schema_version, Some(1));
        assert_eq!(summary.cache_generation, 1);
        assert_eq!(summary.hostname_count, 10);
        assert_eq!(summary.ip_count, 15);
        assert_eq!(summary.resolution_count, 12);
        assert_eq!(summary.stale_resolution_count, 2);
        assert_eq!(summary.negative_cache_count, 3);
        assert_eq!(summary.lookup_events_count, 50);
        assert!(matches!(
            summary.overall_health,
            OverallHealthState::Healthy
        ));
        assert_eq!(summary.diagnostic_level, DiagnosticRedactionLevel::Standard);
    }
}

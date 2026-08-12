//! FQDN/IP lookup contracts for the routing decision pipeline.
//!
//! This module formalises the **lookup stage**: the second step of the routing
//! decision pipeline that enriches a [`NormalizedDecisionInput`] with resolved
//! address mappings before rule matching begins.
//!
//! # What the lookup stage does
//!
//! Given a normalized hostname and/or observed IP, the stage attempts to:
//! 1. Resolve hostname → IP(s) using the local FQDN/IP cache.
//! 2. Optionally reverse-resolve IP → hostname(s) for diagnostic context.
//! 3. Select the "best" IP for `ExactIp` rule matching.
//! 4. Emit cache hit/miss signals and freshness metadata for explain output.
//!
//! The stage produces a [`LookupResult`] that is passed directly to the rule
//! matching stage.
//!
//! # Do-resolve policy — critical-path constraint
//!
//! Routing decisions run on the WFP callout critical path, so live DNS queries
//! during a decision must be tightly bounded.  The [`DoResolvePolicy`] type
//! captures the three modes:
//!
//! | Mode                    | When used                                           |
//! |-------------------------|-----------------------------------------------------|
//! | `CacheOnly`             | Default; no live DNS during decision                |
//! | `AllowWithTimeout`      | Explicit opt-in with a short budget (≤ 50 ms)       |
//! | `CacheWithBackgroundRefresh` | Use stale data; schedule async refresh         |
//!
//! **Default policy**: `CacheOnly` + `CacheWithBackgroundRefresh` for stale
//! entries.  The cache is populated/refreshed out-of-band by the lookup
//! service.
//!
//! # Multi-IP policy
//!
//! A single hostname may resolve to multiple IP addresses.  For `ExactIp` rule
//! matching, the rule is considered a match if **any** current IP for the
//! hostname matches.  [`LookupResult::selected_ip`] records which IP was
//! chosen and its source so the explain output can attribute the match.
//!
//! # Multi-hostname reverse lookup policy
//!
//! Reverse DNS may return multiple hostnames for one IP.  These are treated as
//! **diagnostic/context signals only** — they are never the sole basis for a
//! rule match.  They appear only in `extended_metadata`, not the standard
//! explain UI, because they can reveal internal network topology.
//!
//! # Freshness thresholds
//!
//! [`FreshnessThresholds`] is a named contract type: the lookup stage uses it
//! to classify entries; the cache implementation must honour it.
//!
//! # Privacy tiers in explain output
//!
//! | Metadata                            | Tier               |
//! |-------------------------------------|--------------------|
//! | Cache hit / miss indicator          | `StandardUi`       |
//! | Freshness label (fresh / stale)     | `StandardUi`       |
//! | Source label (dns / cache / manual) | `StandardUi`       |
//! | Lookup success / error              | `StandardUi`       |
//! | Full resolved IP list               | `ExtendedDiagnostics` |
//! | DNS server used                     | `ExtendedDiagnostics` |
//! | Raw TTL values                      | `ExtendedDiagnostics` |
//! | Reverse DNS hostnames               | `ExtendedDiagnostics` |
//! | Exact resolution timestamps         | `ExtendedDiagnostics` |
//!
//! The split exists because full IP lists and internal hostnames can reveal
//! network topology and should not be surfaced in a default user-facing panel.

use std::net::Ipv4Addr;
use std::time::SystemTime;

use crate::revision::RevisionId;

// ── LookupDirection ───────────────────────────────────────────────────────────

/// Direction of the lookup request.
///
/// `HostnameToIp` is the primary path (most connections go through DNS).
/// `IpToHostname` is used for reverse-lookup context in explain output.
/// `Both` is used when a hostname and an observed IP are both available and
/// the pipeline wants to cross-validate them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupDirection {
    /// Forward: hostname → IP address(es).
    HostnameToIp,
    /// Reverse: IP → hostname(s).  Results are diagnostic only.
    IpToHostname,
    /// Both directions.  Used when hostname and observed IP are both available.
    Both,
}

// ── LookupRequest ─────────────────────────────────────────────────────────────

/// Input to the lookup stage.
///
/// Constructed from [`NormalizedDecisionInput`] by the pipeline orchestrator.
/// Both fields are optional because a connection may have only a hostname (DNS
/// layer available) or only an IP (direct connection, DNS bypassed).
///
/// At least one of `hostname` or `observed_ip` must be `Some` — the pipeline
/// must not call the lookup stage with both absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupRequest {
    /// Normalized hostname (lowercase, no trailing dot, IDNA-encoded).
    /// `None` for direct-IP connections.
    pub hostname: Option<String>,
    /// Observed IPv4 address from the WFP callback (already normalized).
    /// `None` when the IP was absent or was a non-mappable native IPv6.
    pub observed_ip: Option<Ipv4Addr>,
    /// Which lookup directions to attempt.
    pub direction: LookupDirection,
    /// Active policy revision this lookup is evaluated against.
    pub active_revision_id: RevisionId,
    /// Wall-clock time when the lookup was initiated.
    pub requested_at: SystemTime,
}

// ── CacheEntryState ───────────────────────────────────────────────────────────

/// Freshness state of a single cache entry.
///
/// The transition model is:
/// ```text
/// Missing → (resolve) → Fresh → (TTL expires) → StaleUsable → (threshold) → StaleNotUsable
///                                                    ↓
///                                             (background refresh) → Fresh
/// NegativeCached  — DNS NXDOMAIN or empty answer, cached for negative_ttl
/// Conflicting     — multiple contradictory mappings for the same key
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheEntryState {
    /// Within TTL; authoritative for matching.
    Fresh,
    /// TTL expired but within the stale-usable window; used for matching while
    /// a background refresh is scheduled.
    StaleUsable,
    /// Too stale to trust for matching; pipeline falls back to observed IP only.
    StaleNotUsable,
    /// No entry exists in the cache for this key.
    Missing,
    /// Multiple contradictory mappings exist (e.g. hostname maps to two
    /// different canonical IPs with conflicting rule implications).
    /// The pipeline uses `observed_ip` if available and emits a conflict signal.
    Conflicting,
    /// A negative DNS result (NXDOMAIN or no-answer) is cached.
    /// The hostname is known not to resolve; `ExactIp` matching via lookup
    /// is skipped for this request.
    NegativeCached,
}

impl CacheEntryState {
    /// Returns `true` if this state is usable for `ExactIp` matching.
    pub fn is_usable_for_matching(&self) -> bool {
        matches!(self, Self::Fresh | Self::StaleUsable)
    }
}

// ── LookupSource ─────────────────────────────────────────────────────────────

/// Where a resolved address entry came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupSource {
    /// Live DNS query performed during this decision (only when `DoResolvePolicy::AllowWithTimeout`).
    DnsResolution,
    /// Entry retrieved from the local FQDN/IP cache.
    CacheHit,
    /// Entry was populated via a manual user-initiated refresh.
    ManualRefresh,
    /// IP was observed directly from WFP traffic, not from DNS.
    ObservedFromTraffic,
}

// ── ResolvedAddressEntry ──────────────────────────────────────────────────────

/// A single resolved IPv4 address with its cache metadata.
///
/// Extended metadata fields (`resolved_at`, `ttl_seconds`) are populated only
/// when available and are surfaced in explain only at `ExtendedDiagnostics`
/// tier to avoid exposing resolution timestamps in the standard UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAddressEntry {
    /// The resolved IPv4 address.
    pub addr: Ipv4Addr,
    /// Freshness state of this entry in the cache.
    pub cache_state: CacheEntryState,
    /// Source of this entry.
    pub source: LookupSource,
    /// When this entry was resolved.  `ExtendedDiagnostics` tier only.
    pub resolved_at: Option<SystemTime>,
    /// TTL from the DNS response (seconds).  `ExtendedDiagnostics` tier only.
    pub ttl_seconds: Option<u32>,
}

// ── ResolvedHostnameEntry ─────────────────────────────────────────────────────

/// A single reverse-resolved hostname with its cache metadata.
///
/// Used only for diagnostic context — never for rule matching.
/// Always surfaced at `ExtendedDiagnostics` tier only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedHostnameEntry {
    /// The reverse-resolved hostname (normalized: lowercase, no trailing dot).
    pub hostname: String,
    /// Freshness state of this reverse entry.
    pub cache_state: CacheEntryState,
}

// ── LookupError ───────────────────────────────────────────────────────────────

/// Error that occurred during a lookup attempt.
///
/// Lookup errors are non-fatal: the pipeline continues with whatever data is
/// available.  Errors are recorded in [`LookupResult::errors`] and surfaced
/// in explain at `StandardUi` tier (label only, no internal details).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupError {
    /// The lookup did not complete within the allowed time budget.
    LookupTimeout {
        /// How many milliseconds elapsed before the timeout.
        elapsed_ms: u32,
    },
    /// A live DNS resolve attempt failed (network error, SERVFAIL, etc.).
    DnsResolveFailed,
    /// The local cache was unavailable (I/O error, corruption, not yet ready).
    CacheUnavailable,
}

// ── DoResolvePolicy ───────────────────────────────────────────────────────────

/// Policy that governs whether and how live DNS resolution is allowed during a
/// routing decision.
///
/// Routing decisions run on the WFP callout critical path.  Live DNS adds
/// latency and can cause cascading delays.  The default policy is
/// `CacheWithBackgroundRefresh`: use cached data (even if stale), and schedule
/// a background refresh when the entry is stale.
///
/// The cache implementation must respect the `budget_ms` constraint in
/// `AllowWithTimeout` and must implement the background refresh mechanism
/// required by `CacheWithBackgroundRefresh`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoResolvePolicy {
    /// Use only the local cache.  No live DNS during this decision.
    /// If the cache is missing, the pipeline uses `observed_ip` only.
    CacheOnly,
    /// Allow a live DNS query with a strict time budget.
    /// Should only be used in non-latency-critical contexts (e.g. test harness).
    AllowWithTimeout {
        /// Maximum milliseconds to wait for a DNS response.  Must be ≤ 50 ms
        /// on the WFP callout path.
        budget_ms: u32,
    },
    /// Use cache data (even if stale), and schedule an async background refresh
    /// when the entry is `StaleUsable` or `Missing`.  **Default policy.**
    CacheWithBackgroundRefresh,
}

// ── FreshnessThresholds ───────────────────────────────────────────────────────

/// TTL thresholds that classify cache entry freshness.
///
/// This type is a **named contract**: the lookup stage uses these thresholds
/// to classify entries; the cache implementation must expose and honour them.
///
/// # Default values
///
/// | Threshold                   | Default      |
/// |-----------------------------|--------------|
/// | `fresh_max_age_secs`        | 300 s        |
/// | `stale_usable_max_age_secs` | 2 592 000 s  |
/// | `fallback_ttl_secs`         | 300 s        |
/// | `negative_ttl_secs`         | 30 s         |
/// Bounds for the user-configurable FQDN cache refresh interval.
/// This is the SSOT referenced by BOTH the GUI SpinBox limits and the Rust
/// clamp — the interval flows into `FreshnessThresholds::fallback_ttl_secs`
/// (the refresh floor) at cache-store construction.
pub const CACHE_REFRESH_MIN_SECS: u32 = 60; // 1 minute
/// Upper bound: 24 hours.
pub const CACHE_REFRESH_MAX_SECS: u32 = 86_400;
/// Recommended default: 5 minutes.
pub const CACHE_REFRESH_DEFAULT_SECS: u32 = 300;

/// Clamps a refresh interval to `[CACHE_REFRESH_MIN_SECS, CACHE_REFRESH_MAX_SECS]`.
///
/// Defense-in-depth: the GUI limits the SpinBox, but the value can still reach
/// the backend out of range (a direct IPC call, an imported settings file, or a
/// row written by an older build). Every code path that consumes the interval
/// clamps through this function so a bad value can never drive the cache into
/// hammering the network (too small) or freezing enforcement updates (too big).
pub fn clamp_cache_refresh_secs(v: u32) -> u32 {
    v.clamp(CACHE_REFRESH_MIN_SECS, CACHE_REFRESH_MAX_SECS)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshnessThresholds {
    /// Maximum age (seconds) for an entry to be classified as `Fresh`.
    pub fresh_max_age_secs: u32,
    /// Maximum age (seconds) for an expired entry to be classified as
    /// `StaleUsable` (background refresh eligible).  Entries older than this
    /// are classified as `StaleNotUsable`.
    pub stale_usable_max_age_secs: u32,
    /// TTL (seconds) to apply when a DNS response carries no explicit TTL.
    pub fallback_ttl_secs: u32,
    /// TTL (seconds) for a cached negative DNS result (NXDOMAIN / no-answer).
    pub negative_ttl_secs: u32,
}

impl FreshnessThresholds {
    /// Returns the default production thresholds.
    ///
    /// Two independent timers, do not conflate them:
    /// - **Refresh cadence** — `fallback_ttl_secs` (5 min) is BOTH the no-TTL
    ///   fallback AND a lower FLOOR in `upsert_resolution`: a CDN's 60 s TTL is
    ///   floored to 5 min (so we re-resolve at most every 5 min, not every
    ///   minute), while a site advertising a LONGER TTL is honoured as-is. This
    ///   keeps a routed site's IPs current without hammering the network.
    /// - **Retention / hold** — separate from expiry: `cleanup_expired` does NOT
    ///   purge a DNS-sourced (rule) last-known-good entry when a refresh fails;
    ///   it is held until a successful re-resolution replaces it (a 30-day
    ///   backstop drops truly-dead hosts). This is what keeps the fail-closed
    ///   `/32` block set populated for emergency blocking while the secondary
    ///   adapter / DNS is unavailable. `stale_usable_max_age_secs` is large so a
    ///   held entry classifies as usable, not `StaleNotUsable`. Positives also
    ///   win over a transient negative cache in `get_by_hostname`.
    pub fn default_production() -> Self {
        Self {
            fresh_max_age_secs: 300,
            stale_usable_max_age_secs: 2_592_000,
            fallback_ttl_secs: 300,
            negative_ttl_secs: 30,
        }
    }
}

// ── LookupExplainData ─────────────────────────────────────────────────────────

/// Privacy-tiered explain metadata produced by the lookup stage.
///
/// `standard` fields are shown in the normal explain panel.
/// `extended` fields are shown only in the extended/developer diagnostics view,
/// because they can reveal network topology, internal host names, or precise
/// resolution timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupExplainData {
    /// Fields safe for the standard explain UI.
    pub standard: LookupStandardSignals,
    /// Fields restricted to extended diagnostics.
    pub extended: LookupExtendedMetadata,
}

/// Standard-tier explain signals — safe for the default explain panel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupStandardSignals {
    /// Whether the lookup found any usable data in the cache.
    pub cache_hit: bool,
    /// Freshness of the best entry used for matching.
    /// `None` when no cache data was available at all.
    pub freshness: Option<CacheEntryState>,
    /// Source of the data used for matching.
    /// `None` when only the observed IP was used (no cache/DNS involved).
    pub source: Option<LookupSource>,
    /// Lookup errors encountered, if any.
    pub errors: Vec<LookupError>,
}

/// Extended-diagnostics–tier lookup metadata.
/// Revealed only in developer/diagnostic mode due to privacy considerations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupExtendedMetadata {
    /// Full list of resolved IPv4 addresses for the hostname (all entries, not
    /// just the selected one).  Reveals network topology.
    pub all_resolved_ips: Vec<ResolvedAddressEntry>,
    /// Reverse-resolved hostnames for the observed IP.  May reveal internal
    /// naming conventions.
    pub reverse_hostnames: Vec<ResolvedHostnameEntry>,
    /// Raw TTL of the selected cache entry, if known.
    pub selected_entry_ttl_secs: Option<u32>,
    /// When the selected entry was resolved, if known.
    pub selected_entry_resolved_at: Option<SystemTime>,
}

// ── LookupResult ─────────────────────────────────────────────────────────────

/// Output of the lookup stage — enriched address data ready for rule matching.
///
/// This is the boundary object between stage 2 (lookup) and stage 3 (rule
/// matching).
///
/// # Selected IP for ExactIp matching
///
/// When multiple IPs are available for a hostname, the lookup stage selects
/// one for `ExactIp` matching and records it in `selected_ip`.  The selection
/// prefers `Fresh` entries over `StaleUsable` ones, and cache entries over
/// observed-traffic IPs.  If both are present and consistent, the cache entry
/// is preferred and `observed_ip` is noted in `extended_metadata`.
///
/// Rule matching must use `selected_ip` as the authoritative IP for `ExactIp`
/// matching — it must not re-derive it from `explain_data`.
///
/// # Partial results are valid
///
/// A `LookupResult` with an empty `all_resolved_ips` but a populated
/// `selected_ip` (from `ObservedFromTraffic`) is valid — this covers direct-IP
/// connections where DNS lookup was not possible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupResult {
    /// IPv4 address selected for `ExactIp` rule matching.
    ///
    /// `None` means no usable IP could be determined (all lookups failed or
    /// returned non-IPv4 results).  `ExactIp` matching is skipped.
    pub selected_ip: Option<ResolvedAddressEntry>,
    /// Whether there were multiple IPs for the hostname (ambiguity marker).
    ///
    /// When `true`, the explain output must note the selected IP and its
    /// source so the user can understand which address triggered the match.
    pub is_multi_ip: bool,
    /// Whether conflicting hostname-to-IP mappings were detected in the cache.
    pub has_conflict: bool,
    /// Privacy-tiered explain metadata for this lookup.
    pub explain_data: LookupExplainData,
}

impl LookupResult {
    /// Returns `true` if the lookup produced a usable IP for `ExactIp` matching.
    pub fn has_usable_ip(&self) -> bool {
        self.selected_ip
            .as_ref()
            .map(|e| e.cache_state.is_usable_for_matching())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── CacheEntryState ───────────────────────────────────────────────────────

    #[test]
    fn fresh_entry_is_usable_for_matching() {
        assert!(CacheEntryState::Fresh.is_usable_for_matching());
    }

    #[test]
    fn stale_usable_entry_is_usable_for_matching() {
        assert!(CacheEntryState::StaleUsable.is_usable_for_matching());
    }

    #[test]
    fn stale_not_usable_entry_is_not_usable_for_matching() {
        assert!(!CacheEntryState::StaleNotUsable.is_usable_for_matching());
    }

    #[test]
    fn missing_entry_is_not_usable_for_matching() {
        assert!(!CacheEntryState::Missing.is_usable_for_matching());
    }

    #[test]
    fn conflicting_entry_is_not_usable_for_matching() {
        assert!(!CacheEntryState::Conflicting.is_usable_for_matching());
    }

    #[test]
    fn negative_cached_entry_is_not_usable_for_matching() {
        assert!(!CacheEntryState::NegativeCached.is_usable_for_matching());
    }

    // ── FreshnessThresholds ───────────────────────────────────────────────────

    #[test]
    fn default_production_thresholds_are_sane() {
        let t = FreshnessThresholds::default_production();
        assert!(
            t.fresh_max_age_secs < t.stale_usable_max_age_secs,
            "fresh window must be smaller than stale-usable window"
        );
        assert!(t.fallback_ttl_secs > 0);
        assert!(t.negative_ttl_secs > 0);
        assert!(
            t.negative_ttl_secs < t.fresh_max_age_secs,
            "negative cache TTL should be shorter than positive fresh window"
        );
    }

    #[test]
    fn cache_refresh_clamp_bounds() {
        assert_eq!(clamp_cache_refresh_secs(0), CACHE_REFRESH_MIN_SECS);
        assert_eq!(clamp_cache_refresh_secs(30), CACHE_REFRESH_MIN_SECS);
        assert_eq!(
            clamp_cache_refresh_secs(CACHE_REFRESH_MIN_SECS),
            CACHE_REFRESH_MIN_SECS
        );
        assert_eq!(clamp_cache_refresh_secs(300), 300);
        assert_eq!(
            clamp_cache_refresh_secs(CACHE_REFRESH_MAX_SECS),
            CACHE_REFRESH_MAX_SECS
        );
        assert_eq!(clamp_cache_refresh_secs(u32::MAX), CACHE_REFRESH_MAX_SECS);
        // Default must itself be in range (clamping the default is a no-op).
        assert_eq!(
            clamp_cache_refresh_secs(CACHE_REFRESH_DEFAULT_SECS),
            CACHE_REFRESH_DEFAULT_SECS
        );
    }

    // ── LookupResult ─────────────────────────────────────────────────────────

    fn make_entry(addr: Ipv4Addr, state: CacheEntryState) -> ResolvedAddressEntry {
        ResolvedAddressEntry {
            addr,
            cache_state: state,
            source: LookupSource::CacheHit,
            resolved_at: None,
            ttl_seconds: None,
        }
    }

    fn empty_explain() -> LookupExplainData {
        LookupExplainData {
            standard: LookupStandardSignals {
                cache_hit: false,
                freshness: None,
                source: None,
                errors: vec![],
            },
            extended: LookupExtendedMetadata {
                all_resolved_ips: vec![],
                reverse_hostnames: vec![],
                selected_entry_ttl_secs: None,
                selected_entry_resolved_at: None,
            },
        }
    }

    #[test]
    fn lookup_result_has_usable_ip_when_fresh_entry_selected() {
        let result = LookupResult {
            selected_ip: Some(make_entry(
                Ipv4Addr::new(93, 184, 216, 34),
                CacheEntryState::Fresh,
            )),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: empty_explain(),
        };
        assert!(result.has_usable_ip());
    }

    #[test]
    fn lookup_result_has_usable_ip_when_stale_usable_selected() {
        let result = LookupResult {
            selected_ip: Some(make_entry(
                Ipv4Addr::new(1, 1, 1, 1),
                CacheEntryState::StaleUsable,
            )),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: empty_explain(),
        };
        assert!(result.has_usable_ip());
    }

    #[test]
    fn lookup_result_no_usable_ip_when_selected_is_none() {
        let result = LookupResult {
            selected_ip: None,
            is_multi_ip: false,
            has_conflict: false,
            explain_data: empty_explain(),
        };
        assert!(!result.has_usable_ip());
    }

    #[test]
    fn lookup_result_no_usable_ip_when_selected_is_stale_not_usable() {
        let result = LookupResult {
            selected_ip: Some(make_entry(
                Ipv4Addr::new(10, 0, 0, 1),
                CacheEntryState::StaleNotUsable,
            )),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: empty_explain(),
        };
        assert!(!result.has_usable_ip());
    }

    #[test]
    fn lookup_result_no_usable_ip_when_selected_is_missing() {
        let result = LookupResult {
            selected_ip: Some(make_entry(
                Ipv4Addr::new(10, 0, 0, 1),
                CacheEntryState::Missing,
            )),
            is_multi_ip: false,
            has_conflict: false,
            explain_data: empty_explain(),
        };
        assert!(!result.has_usable_ip());
    }

    // ── Privacy tiers — explain data structure ────────────────────────────────

    #[test]
    fn standard_signals_cache_hit_structure() {
        let signals = LookupStandardSignals {
            cache_hit: true,
            freshness: Some(CacheEntryState::Fresh),
            source: Some(LookupSource::CacheHit),
            errors: vec![],
        };
        assert!(signals.cache_hit);
        assert_eq!(signals.freshness, Some(CacheEntryState::Fresh));
        assert!(signals.errors.is_empty());
    }

    #[test]
    fn standard_signals_lookup_timeout_error_structure() {
        let signals = LookupStandardSignals {
            cache_hit: false,
            freshness: None,
            source: None,
            errors: vec![LookupError::LookupTimeout { elapsed_ms: 52 }],
        };
        assert!(!signals.cache_hit);
        assert_eq!(signals.errors.len(), 1);
        assert!(matches!(
            signals.errors[0],
            LookupError::LookupTimeout { elapsed_ms: 52 }
        ));
    }

    #[test]
    fn extended_metadata_reverse_hostnames_are_diagnostic_only() {
        // Reverse hostname entries are in extended, never in standard signals
        let extended = LookupExtendedMetadata {
            all_resolved_ips: vec![],
            reverse_hostnames: vec![ResolvedHostnameEntry {
                hostname: "internal.corp".to_owned(),
                cache_state: CacheEntryState::Fresh,
            }],
            selected_entry_ttl_secs: Some(300),
            selected_entry_resolved_at: None,
        };
        assert_eq!(extended.reverse_hostnames.len(), 1);
        assert_eq!(extended.reverse_hostnames[0].hostname, "internal.corp");
    }

    // ── DoResolvePolicy ───────────────────────────────────────────────────────

    #[test]
    fn do_resolve_policy_allow_with_timeout_carries_budget() {
        let policy = DoResolvePolicy::AllowWithTimeout { budget_ms: 30 };
        assert!(matches!(
            policy,
            DoResolvePolicy::AllowWithTimeout { budget_ms: 30 }
        ));
    }

    // ── LookupDirection ───────────────────────────────────────────────────────

    #[test]
    fn lookup_direction_variants_are_distinct() {
        assert_ne!(LookupDirection::HostnameToIp, LookupDirection::IpToHostname);
        assert_ne!(LookupDirection::Both, LookupDirection::HostnameToIp);
    }
}

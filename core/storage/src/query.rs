//! Lookup query semantics — pure classification logic over cache results.
//!
//! This module contains no SQLite, no I/O, and no state.  It is used by the
//! service layer to:
//!
//! - Classify raw IP strings from WFP traffic before building a lookup request
//! - Derive the [`LookupResultState`] for `lookup_events` from a result
//! - Classify the ambiguity kind (multi-IP, mismatch, reverse ambiguity)
//! - Compute a refresh hint for the service loop scheduler
//!
//! All functions are deterministic and side-effect-free.

use std::net::{Ipv4Addr, Ipv6Addr};

use nrr_domain::decision_lookup::CacheEntryState;

use crate::dto::{CacheLookupResult, LookupResultState};

// ── ObservedIpClassification ──────────────────────────────────────────────────

/// Classification of a raw IP string as received from WFP traffic capture.
///
/// Call [`classify_observed_ip`] on every IP string before building a
/// [`CacheLookupRequest`][crate::dto::CacheLookupRequest].  Only
/// [`IPv4`][ObservedIpClassification::IPv4] values should be forwarded to the
/// cache lookup path; the other variants require special handling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedIpClassification {
    /// Valid IPv4 address — usable for routing in the Free edition.
    IPv4(Ipv4Addr),
    /// Valid IPv6 address — present in traffic but not routable in the Free
    /// edition.  The caller should write a negative cache entry with
    /// [`NegativeCacheReason::UnsupportedAddressFamily`][crate::dto::NegativeCacheReason::UnsupportedAddressFamily]
    /// so subsequent lookups for this address short-circuit immediately.
    IPv6Unsupported(Ipv6Addr),
    /// The string does not parse as any recognised IP address format.
    ParseError,
}

/// Classifies a raw IP string from WFP traffic.
///
/// The function is strict: no port stripping, no bracket removal.  The WFP
/// layer is expected to supply a bare, normalised address string.
pub fn classify_observed_ip(raw: &str) -> ObservedIpClassification {
    if let Ok(addr) = raw.parse::<Ipv4Addr>() {
        return ObservedIpClassification::IPv4(addr);
    }
    if let Ok(addr) = raw.parse::<Ipv6Addr>() {
        return ObservedIpClassification::IPv6Unsupported(addr);
    }
    ObservedIpClassification::ParseError
}

// ── AmbiguityKind ─────────────────────────────────────────────────────────────

/// Ambiguity classification of a completed cache lookup.
///
/// Computed by [`classify_ambiguity`] from the boolean fields in
/// [`CacheLookupResult`].  Lets callers avoid interpreting `is_multi_ip` and
/// `has_conflict` independently.
///
/// ## Decision model
///
/// The rule engine never relies on reverse lookup as the *sole* routing basis.
/// [`MultipleReverseHostnames`][AmbiguityKind::MultipleReverseHostnames] is a
/// diagnostic signal — it does not block routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmbiguityKind {
    /// No ambiguity: at most one IP, consistent with the observed IP (if any).
    None,
    /// The hostname resolves to two or more IPs (`is_multi_ip = true`).
    MultipleIps,
    /// The observed IP is absent from the cached hostname IP set
    /// (`has_conflict = true`, `is_multi_ip = false`).
    IpMismatch,
    /// Both `is_multi_ip` and `has_conflict` hold simultaneously.
    MultipleIpsAndMismatch,
    /// The observed IP maps to more than one hostname in the reverse cache
    /// (diagnostic only; single IP, no forward mismatch).
    MultipleReverseHostnames,
}

/// Classifies the ambiguity kind from a cache lookup result.
pub fn classify_ambiguity(result: &CacheLookupResult) -> AmbiguityKind {
    match (
        result.is_multi_ip,
        result.has_conflict,
        result.reverse_hostnames.len() > 1,
    ) {
        (true, true, _) => AmbiguityKind::MultipleIpsAndMismatch,
        (true, false, _) => AmbiguityKind::MultipleIps,
        (false, true, _) => AmbiguityKind::IpMismatch,
        (false, false, true) => AmbiguityKind::MultipleReverseHostnames,
        (false, false, false) => AmbiguityKind::None,
    }
}

// ── RefreshHint ───────────────────────────────────────────────────────────────

/// Hint to the service loop about whether a DNS refresh is warranted.
///
/// Computed by [`compute_refresh_hint`].  The service loop decides *when* and
/// *how* to act on these hints — the storage layer never schedules or performs
/// DNS queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshHint {
    /// Entry is fresh — no action needed until next TTL expiry.
    NotNeeded,
    /// Entry is stale but still usable — schedule a background refresh.
    /// Routing proceeds with the stale entry while the refresh is in flight.
    BackgroundRefreshEligible,
    /// Entry is absent or beyond the stale-usable window — resolve before the
    /// next routing decision if the latency budget allows.
    ImmediateRequired,
}

/// Computes the refresh hint from a cache lookup result.
pub fn compute_refresh_hint(result: &CacheLookupResult) -> RefreshHint {
    match &result.overall_freshness {
        // No entry or too stale — service should resolve now if possible.
        None | Some(CacheEntryState::Missing) | Some(CacheEntryState::StaleNotUsable) => {
            RefreshHint::ImmediateRequired
        }

        Some(CacheEntryState::Fresh) => RefreshHint::NotNeeded,

        // Respect the negative TTL — re-querying before it expires is wasteful.
        Some(CacheEntryState::NegativeCached) => RefreshHint::NotNeeded,

        // Stale usable: keep routing while a background refresh runs.
        Some(CacheEntryState::StaleUsable) => RefreshHint::BackgroundRefreshEligible,

        // Conflicting: a refresh might resolve the contradiction.
        Some(CacheEntryState::Conflicting) => RefreshHint::BackgroundRefreshEligible,
    }
}

// ── derive_event_state ────────────────────────────────────────────────────────

/// Derives the [`LookupResultState`] to record in `lookup_events`.
///
/// The mapping is priority-ordered:
/// 1. Any error → `Error`
/// 2. Conflict detected → `Conflicting`
/// 3. `overall_freshness` maps to a result state
///
/// This function should be called immediately after [`CacheRepository::build_lookup_envelope`]
/// or [`CacheRepository::get_by_hostname`] to produce the event record.
///
/// [`CacheRepository::build_lookup_envelope`]: crate::repository::CacheRepository::build_lookup_envelope
/// [`CacheRepository::get_by_hostname`]: crate::repository::CacheRepository::get_by_hostname
pub fn derive_event_state(result: &CacheLookupResult) -> LookupResultState {
    if !result.errors.is_empty() {
        return LookupResultState::Error;
    }
    if result.has_conflict {
        return LookupResultState::Conflicting;
    }
    match &result.overall_freshness {
        None | Some(CacheEntryState::Missing) | Some(CacheEntryState::StaleNotUsable) => {
            LookupResultState::Miss
        }

        Some(CacheEntryState::NegativeCached) => LookupResultState::NegativeCached,
        Some(CacheEntryState::Fresh) => LookupResultState::Hit,
        Some(CacheEntryState::StaleUsable) => LookupResultState::StaleUsed,
        Some(CacheEntryState::Conflicting) => LookupResultState::Conflicting,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    use nrr_domain::decision_lookup::{CacheEntryState, LookupError};

    use crate::dto::CachedHostnameEntry;

    // ── classify_observed_ip ─────────────────────────────────────────────────

    #[test]
    fn classify_valid_ipv4() {
        let c = classify_observed_ip("93.184.216.34");
        assert_eq!(
            c,
            ObservedIpClassification::IPv4("93.184.216.34".parse().unwrap())
        );
    }

    #[test]
    fn classify_loopback_ipv4() {
        let c = classify_observed_ip("127.0.0.1");
        assert_eq!(c, ObservedIpClassification::IPv4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn classify_ipv6_full() {
        let c = classify_observed_ip("2001:db8::1");
        assert!(matches!(c, ObservedIpClassification::IPv6Unsupported(_)));
    }

    #[test]
    fn classify_ipv6_loopback() {
        let c = classify_observed_ip("::1");
        assert!(matches!(c, ObservedIpClassification::IPv6Unsupported(_)));
    }

    #[test]
    fn classify_ipv6_mapped_ipv4() {
        // ::ffff:1.2.3.4 is an IPv6 address — not routable in Free edition.
        let c = classify_observed_ip("::ffff:1.2.3.4");
        assert!(matches!(c, ObservedIpClassification::IPv6Unsupported(_)));
    }

    #[test]
    fn classify_garbage_is_parse_error() {
        assert_eq!(
            classify_observed_ip("not-an-ip"),
            ObservedIpClassification::ParseError
        );
    }

    #[test]
    fn classify_empty_string_is_parse_error() {
        assert_eq!(
            classify_observed_ip(""),
            ObservedIpClassification::ParseError
        );
    }

    #[test]
    fn classify_ip_with_port_is_parse_error() {
        // WFP layer must strip port before calling us.
        assert_eq!(
            classify_observed_ip("1.2.3.4:80"),
            ObservedIpClassification::ParseError
        );
    }

    // ── classify_ambiguity ───────────────────────────────────────────────────

    fn minimal_result(
        is_multi_ip: bool,
        has_conflict: bool,
        reverse_count: usize,
    ) -> CacheLookupResult {
        CacheLookupResult {
            resolved_ips: Vec::new(),
            reverse_hostnames: (0..reverse_count)
                .map(|i| CachedHostnameEntry {
                    hostname: format!("host{i}.example"),
                    cache_state: CacheEntryState::Fresh,
                })
                .collect(),
            overall_freshness: None,
            best_source: None,
            is_multi_ip,
            has_conflict,
            errors: Vec::new(),
            negative_cache_expires_at: None,
        }
    }

    #[test]
    fn ambiguity_none_when_single_ip_no_conflict() {
        assert_eq!(
            classify_ambiguity(&minimal_result(false, false, 0)),
            AmbiguityKind::None
        );
    }

    #[test]
    fn ambiguity_multiple_ips() {
        assert_eq!(
            classify_ambiguity(&minimal_result(true, false, 0)),
            AmbiguityKind::MultipleIps
        );
    }

    #[test]
    fn ambiguity_ip_mismatch() {
        assert_eq!(
            classify_ambiguity(&minimal_result(false, true, 0)),
            AmbiguityKind::IpMismatch
        );
    }

    #[test]
    fn ambiguity_multiple_ips_and_mismatch() {
        assert_eq!(
            classify_ambiguity(&minimal_result(true, true, 0)),
            AmbiguityKind::MultipleIpsAndMismatch
        );
    }

    #[test]
    fn ambiguity_multiple_reverse_hostnames() {
        assert_eq!(
            classify_ambiguity(&minimal_result(false, false, 2)),
            AmbiguityKind::MultipleReverseHostnames
        );
    }

    #[test]
    fn ambiguity_multiple_ips_dominates_multiple_reverse() {
        // MultipleIps takes priority over MultipleReverseHostnames.
        assert_eq!(
            classify_ambiguity(&minimal_result(true, false, 3)),
            AmbiguityKind::MultipleIps
        );
    }

    #[test]
    fn ambiguity_none_with_single_reverse() {
        assert_eq!(
            classify_ambiguity(&minimal_result(false, false, 1)),
            AmbiguityKind::None
        );
    }

    // ── compute_refresh_hint ─────────────────────────────────────────────────

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
    fn refresh_hint_not_needed_for_fresh() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(CacheEntryState::Fresh))),
            RefreshHint::NotNeeded
        );
    }

    #[test]
    fn refresh_hint_not_needed_for_negative_cached() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(
                CacheEntryState::NegativeCached
            ))),
            RefreshHint::NotNeeded
        );
    }

    #[test]
    fn refresh_hint_background_for_stale_usable() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(CacheEntryState::StaleUsable))),
            RefreshHint::BackgroundRefreshEligible
        );
    }

    #[test]
    fn refresh_hint_background_for_conflicting() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(CacheEntryState::Conflicting))),
            RefreshHint::BackgroundRefreshEligible
        );
    }

    #[test]
    fn refresh_hint_immediate_for_missing() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(None)),
            RefreshHint::ImmediateRequired
        );
    }

    #[test]
    fn refresh_hint_immediate_for_stale_not_usable() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(
                CacheEntryState::StaleNotUsable
            ))),
            RefreshHint::ImmediateRequired
        );
    }

    #[test]
    fn refresh_hint_immediate_for_explicit_missing() {
        assert_eq!(
            compute_refresh_hint(&result_with_freshness(Some(CacheEntryState::Missing))),
            RefreshHint::ImmediateRequired
        );
    }

    // ── derive_event_state ───────────────────────────────────────────────────

    #[test]
    fn event_state_hit_for_fresh() {
        assert_eq!(
            derive_event_state(&result_with_freshness(Some(CacheEntryState::Fresh))),
            LookupResultState::Hit
        );
    }

    #[test]
    fn event_state_stale_used_for_stale_usable() {
        assert_eq!(
            derive_event_state(&result_with_freshness(Some(CacheEntryState::StaleUsable))),
            LookupResultState::StaleUsed
        );
    }

    #[test]
    fn event_state_miss_for_none() {
        assert_eq!(
            derive_event_state(&result_with_freshness(None)),
            LookupResultState::Miss
        );
    }

    #[test]
    fn event_state_miss_for_stale_not_usable() {
        assert_eq!(
            derive_event_state(&result_with_freshness(Some(
                CacheEntryState::StaleNotUsable
            ))),
            LookupResultState::Miss
        );
    }

    #[test]
    fn event_state_negative_cached() {
        assert_eq!(
            derive_event_state(&result_with_freshness(Some(
                CacheEntryState::NegativeCached
            ))),
            LookupResultState::NegativeCached
        );
    }

    #[test]
    fn event_state_conflicting_from_has_conflict_flag() {
        let mut r = result_with_freshness(Some(CacheEntryState::Fresh));
        r.has_conflict = true;
        assert_eq!(derive_event_state(&r), LookupResultState::Conflicting);
    }

    #[test]
    fn event_state_conflicting_from_freshness_state() {
        assert_eq!(
            derive_event_state(&result_with_freshness(Some(CacheEntryState::Conflicting))),
            LookupResultState::Conflicting
        );
    }

    #[test]
    fn event_state_error_takes_priority_over_everything() {
        let mut r = result_with_freshness(Some(CacheEntryState::Fresh));
        r.has_conflict = true;
        r.errors.push(LookupError::CacheUnavailable);
        assert_eq!(derive_event_state(&r), LookupResultState::Error);
    }

    #[test]
    fn event_state_conflict_takes_priority_over_freshness() {
        let mut r = result_with_freshness(Some(CacheEntryState::StaleNotUsable));
        r.has_conflict = true;
        assert_eq!(derive_event_state(&r), LookupResultState::Conflicting);
    }

    // ── IPv6 negative cache pathway ──────────────────────────────────────────

    #[test]
    fn ipv6_unsupported_addr_is_accessible() {
        let c = classify_observed_ip("2001:db8::1");
        if let ObservedIpClassification::IPv6Unsupported(addr) = c {
            // Caller can format addr for the negative cache input field.
            assert!(!addr.to_string().is_empty());
        } else {
            panic!("expected IPv6Unsupported");
        }
    }

    // ── ipv4 classification coverage ─────────────────────────────────────────

    #[test]
    fn classify_all_zeros_is_ipv4() {
        let c = classify_observed_ip("0.0.0.0");
        assert!(matches!(c, ObservedIpClassification::IPv4(_)));
    }

    #[test]
    fn classify_broadcast_is_ipv4() {
        let c = classify_observed_ip("255.255.255.255");
        assert!(matches!(c, ObservedIpClassification::IPv4(_)));
    }

    // ── stale and missing states (integration — uses real SQLite) ────────────

    fn migrated_cache_store_with_raw<F>(
        dir: &tempfile::TempDir,
        setup: F,
    ) -> crate::store::SqliteCacheStore
    where
        F: FnOnce(&rusqlite::Connection),
    {
        use crate::migration::{open_connection, SqliteMigrationRunner};
        use crate::repository::MigrationRunner;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let path = dir.path().join("cache.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        setup(&conn);
        crate::store::SqliteCacheStore::new(conn, FreshnessThresholds::default_production())
    }

    fn insert_resolution_raw(
        conn: &rusqlite::Connection,
        hostname: &str,
        ip: Ipv4Addr,
        resolved_at_ms: i64,
        expires_at_ms: i64,
        freshness_state: &str,
    ) {
        let ip_str = ip.to_string();
        let packed = u32::from(ip) as i64;
        conn.execute(
            "INSERT OR IGNORE INTO hostnames \
             (canonical_host, first_seen_at, last_seen_at) VALUES (?1, ?2, ?2)",
            rusqlite::params![hostname, resolved_at_ms],
        )
        .expect("hostname");
        let hostname_id: i64 = conn
            .query_row(
                "SELECT id FROM hostnames WHERE canonical_host = ?1",
                rusqlite::params![hostname],
                |r| r.get(0),
            )
            .expect("hostname_id");
        conn.execute(
            "INSERT OR IGNORE INTO ip_addresses \
             (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at) \
             VALUES ('ipv4', ?1, ?2, ?3, ?3)",
            rusqlite::params![ip_str, packed, resolved_at_ms],
        )
        .expect("ip");
        let ip_id: i64 = conn
            .query_row(
                "SELECT id FROM ip_addresses \
                 WHERE address_family = 'ipv4' AND canonical_ip = ?1",
                rusqlite::params![ip_str],
                |r| r.get(0),
            )
            .expect("ip_id");
        conn.execute(
            "INSERT INTO hostname_ip_resolutions \
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state) \
             VALUES (?1, ?2, 'dns', ?3, ?4, ?5)",
            rusqlite::params![
                hostname_id,
                ip_id,
                resolved_at_ms,
                expires_at_ms,
                freshness_state
            ],
        )
        .expect("resolution");
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    #[test]
    fn stale_usable_state_returned_when_within_window() {
        use crate::repository::CacheRepository;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let now = now_ms();
        // expires_at 30 seconds ago — within the 3 600-second stale-usable window.
        let past = now - 30_000;
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let store = migrated_cache_store_with_raw(&dir, |conn| {
            insert_resolution_raw(conn, "stale.example", ip, past - 300_000, past, "fresh");
        });

        let result = store
            .get_by_hostname(
                "stale.example",
                &FreshnessThresholds::default_production(),
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(result.resolved_ips.len(), 1);
        assert_eq!(
            result.resolved_ips[0].cache_state,
            CacheEntryState::StaleUsable,
            "entry expired 30 s ago should be StaleUsable"
        );
        assert_eq!(result.overall_freshness, Some(CacheEntryState::StaleUsable));
        assert_eq!(
            compute_refresh_hint(&result),
            RefreshHint::BackgroundRefreshEligible
        );
        assert_eq!(derive_event_state(&result), LookupResultState::StaleUsed);
    }

    #[test]
    fn stale_not_usable_state_returned_when_beyond_window() {
        use crate::repository::CacheRepository;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let now = now_ms();
        // expires_at 2 hours ago — beyond the 3 600-second stale-usable window.
        let past = now - 7_200_000;
        let ip = Ipv4Addr::new(10, 0, 0, 2);

        let store = migrated_cache_store_with_raw(&dir, |conn| {
            insert_resolution_raw(conn, "old.example", ip, past - 300_000, past, "fresh");
        });

        // Short stale-usable window for this mechanism test: production defaults
        // hold entries usable for a week (leak-guard stickiness), so a
        // 2-h-old entry would still be StaleUsable under the real thresholds.
        let result = store
            .get_by_hostname(
                "old.example",
                &FreshnessThresholds {
                    stale_usable_max_age_secs: 3_600,
                    ..FreshnessThresholds::default_production()
                },
                crate::resolution_source::CachePriorityStrategy::default(),
            )
            .expect("get");

        assert_eq!(
            result.resolved_ips[0].cache_state,
            CacheEntryState::StaleNotUsable,
            "entry expired 2 h ago should be StaleNotUsable"
        );
        assert_eq!(
            compute_refresh_hint(&result),
            RefreshHint::ImmediateRequired
        );
        assert_eq!(derive_event_state(&result), LookupResultState::Miss);
    }

    #[test]
    fn reverse_lookup_absent_returns_empty() {
        use crate::repository::CacheRepository;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let store = migrated_cache_store_with_raw(&dir, |_conn| {});

        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let result = store
            .get_by_ip(ip, &FreshnessThresholds::default_production())
            .expect("get_by_ip");

        assert!(
            result.reverse_hostnames.is_empty(),
            "IP not in cache → reverse lookup must return empty"
        );
        assert!(result.overall_freshness.is_none());
        assert_eq!(
            compute_refresh_hint(&result),
            RefreshHint::ImmediateRequired
        );
        assert_eq!(derive_event_state(&result), LookupResultState::Miss);
    }

    #[test]
    fn reverse_lookup_with_multiple_hostnames_classified_as_ambiguous() {
        use crate::repository::CacheRepository;
        use nrr_domain::decision_lookup::FreshnessThresholds;

        let dir = tempfile::tempdir().expect("tmp");
        let ip = Ipv4Addr::new(8, 8, 8, 8);

        // Two different hostnames map to the same IP.
        let store = migrated_cache_store_with_raw(&dir, |conn| {
            let now = now_ms();
            insert_resolution_raw(conn, "dns1.google", ip, now, now + 300_000, "fresh");
            insert_resolution_raw(conn, "dns.google", ip, now, now + 300_000, "fresh");
        });

        let result = store
            .get_by_ip(ip, &FreshnessThresholds::default_production())
            .expect("get_by_ip");

        assert_eq!(result.reverse_hostnames.len(), 2);
        assert_eq!(
            classify_ambiguity(&result),
            AmbiguityKind::MultipleReverseHostnames
        );
    }
}

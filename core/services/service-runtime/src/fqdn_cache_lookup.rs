//! FQDN cache lookup port for the WFP filter
//! codegen.
//!
//! The codegen needs two narrow queries against the FQDN/IP cache:
//!
//! - `ips_for_hostname` — for [`ExactFqdn`] rule fan-out across the
//!   cached resolution set of a single hostname.
//! - `hostnames_under_suffix` — for [`Zone`] rule fan-out across every
//!   subdomain the cache currently knows about under the given suffix.
//! - `hostnames_for_suffix_domain` — the same, plus the apex, for
//!   [`SuffixDomain`] rule fan-out.
//!
//! [`ExactFqdn`]: nrr_domain::canonical::CanonicalAddressMatch::ExactFqdn
//! [`SuffixDomain`]: nrr_domain::canonical::CanonicalAddressMatch::SuffixDomain
//! [`Zone`]: nrr_domain::canonical::CanonicalAddressMatch::Zone
//!
//! ## Why a separate trait
//!
//! `CacheRepository` (in `nrr-storage`) is the full SQLite surface —
//! 17 methods covering writes, retention, integrity, statistics. The
//! codegen only needs two read-only projections, and exposing the
//! full repository to it would make the unit test surface huge
//! (every test would need a fully-migrated SQLite store).
//!
//! [`FqdnCacheLookup`] is the narrow port. Tests use
//! [`MockFqdnCacheLookup`] which carries a pre-canned hashmap;
//! production uses [`SqliteFqdnCacheLookup`] which delegates to an
//! `Arc<Mutex<dyn CacheRepository + Send>>`.
//!
//! Cold-cache reads return empty results. The codegen then emits
//! diagnostics ([`crate::wfp_codegen::CodegenDiagnostic`]) so the
//! GUI can surface "no filter generated — DNS warm-up pending"
//! messages.
//!
//! ## Retention is not enforceability
//!
//! The store keeps last-known-good rows for weeks; this port hands enforcement
//! only what a live resolution confirmed inside
//! [`ENFORCEMENT_CONFIRMATION_WINDOW`]. Every enforcement view — WFP permits,
//! the kill-switch pin set, the fail-closed block set, `/32` routes, the
//! shared-IP census and the direct-answer steering set — reads through this one
//! method, so they all narrow together and cannot drift into an incoherent
//! partial commit (a route with no matching filter, or a block with no rule
//! behind it).

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use nrr_domain::decision_lookup::FreshnessThresholds;
use nrr_storage::dto::CacheLookupRequest;
use nrr_storage::repository::CacheRepository;

/// How recently a cached address must have been CONFIRMED by a live resolution
/// before enforcement is allowed to act on it.
///
/// The FQDN cache is deliberately a long-lived, last-known-good store: a row is
/// held for up to 30 days (`stale_usable_max_age_secs`) and a failed refresh
/// never purges it, so a rule's `/32` survives an outage. That is the right
/// retention policy for *remembering* an address — it is the wrong policy for
/// *enforcing* one. `upsert_resolution` unions addresses per
/// `(hostname, ip, source)`, so an address that has rotated out of a hostname's
/// answer keeps its old `resolved_at` forever while the hostname accumulates
/// new ones. Without this window a cold start could turn into 1050 fail-closed
/// filters built almost entirely from the previous day's cache — and because
/// large CDNs recycle front-end addresses between names, yesterday's rule-host
/// addresses were serving unrelated direct hosts today, which were then dropped.
///
/// The window is per-ADDRESS (each row carries its own `resolved_at`), so a
/// hostname keeps enforcing the addresses it still answers with and silently
/// sheds the ones it no longer does — no extra query, no extra state.
///
/// **6 hours**, chosen against three independent bounds:
/// - **Re-confirmation cadence.** Cached rows expire on `max(ttl, 300 s)` and
///   the refresh task re-resolves 50 of them every 60 s, so a live, resolvable
///   address is re-confirmed roughly every 5 minutes. Falling out of a 6 h
///   window means ~70 consecutive missed confirmations — a genuinely rotated or
///   dead address, never a transient DNS hiccup.
/// - **Operator reality.** It spans a full working session plus a sleep/travel
///   gap, so a resumed machine still boots with a populated block set instead of
///   an empty one.
/// - **Address rotation.** Front-end pools rotate over hours-to-days, not
///   minutes; 6 h is comfortably inside one pool generation and far below the
///   day-scale drift that caused the incident.
///
/// It is the durable counterpart of
/// [`crate::recent_rule_addresses::ENTRY_TTL`], which applies the same rule
/// ("a pool the provider has rotated away from stops being enforceable") to the
/// in-memory index; that one can be short because it is rebuilt from the first
/// resolution after a restart, this one must survive restarts and outages.
///
/// Blast radius is bounded in the safe direction: an address that falls out of
/// the window loses only its own `/32` — the mode-B catch-all block-all still
/// covers everything, and the very next resolution of that hostname (the
/// seeder now re-seeds it, since it reads through this same window) puts the
/// address back with a current timestamp.
pub const ENFORCEMENT_CONFIRMATION_WINDOW: Duration = Duration::from_secs(6 * 60 * 60);

/// Narrow read-only port the codegen consumes.
///
/// All methods are `&self` so the port can be shared via `Arc`
/// across threads. Implementations MUST be cheap to call repeatedly
/// — the codegen issues one query per rule.
pub trait FqdnCacheLookup: Send + Sync {
    /// Return every cached IPv4 address mapped to `hostname` that enforcement
    /// may act on.
    ///
    /// The production adapter answers only with addresses a live resolution
    /// confirmed within [`ENFORCEMENT_CONFIRMATION_WINDOW`]: the cache retains
    /// last-known-good rows for weeks so a rule survives an outage, but an
    /// address nobody has re-observed in hours has very likely been recycled to
    /// another tenant, and pinning or blocking it hits that tenant instead.
    /// Returns an empty list when the hostname is not cached, every cached
    /// address is beyond the window, or the cache reports a negative entry.
    fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr>;

    /// List every cached canonical hostname that ends with
    /// `.{suffix}` (with leading dot — apex of the suffix itself is
    /// excluded). Used for `SuffixDomain` and `Zone` rule fan-out.
    ///
    /// `limit` caps the result set — the codegen passes a sane
    /// default (e.g. 1024) to keep an oversize suffix from emitting
    /// a runaway filter set.
    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String>;

    /// Every cached hostname a `SuffixDomain(label)` rule covers: the
    /// subdomains, **plus the apex `label` itself** when the cache knows an
    /// address for it (`*.x` covers `x`; see
    /// [`nrr_domain::decision_matching::match_suffix_domain`]).
    ///
    /// This is the single expansion helper for suffix-rule fan-out — every
    /// enforcement path (WFP filters, routes, the shared-IP census, fake-IP
    /// scope, expected-route attribution) calls it so the enforced set cannot
    /// drift from what the decision engine says it matched. `Zone` rules keep
    /// calling [`Self::hostnames_under_suffix`] directly: the bare zone label is
    /// not a member of its own zone.
    ///
    /// The apex is gated on having cached addresses so a cold cache still
    /// yields an empty list, and callers keep emitting their "DNS warm-up
    /// pending" diagnostic instead of silently producing zero filters. The
    /// result stays within `limit` and sorted, so filter-id derivation and
    /// fan-out ordinals stay deterministic — and a saturated suffix still
    /// returns exactly `limit` entries, which is how callers detect truncation.
    fn hostnames_for_suffix_domain(&self, label: &str, limit: usize) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let mut hosts = self.hostnames_under_suffix(label, limit);
        let apex = label.trim().trim_end_matches('.').to_ascii_lowercase();
        if apex.is_empty() || hosts.contains(&apex) || self.ips_for_hostname(&apex).is_empty() {
            return hosts;
        }
        // At the cap, the apex displaces one subdomain rather than being
        // dropped: it is the host this rule most obviously names, and losing it
        // would re-open the very leak apex coverage closes.
        if hosts.len() >= limit {
            hosts.pop();
        }
        hosts.push(apex);
        hosts.sort();
        hosts
    }

    /// Number of distinct **direct** (non-secondary)
    /// hostnames observed sharing `ip` (`direct_on_ip` for the shared-IP
    /// policy). `0` ⇒ not observably shared. Defaults to `0` so test mocks and
    /// cold caches behave as "no sharing seen" (→ every IP committed), i.e. the
    /// shared-IP policy is a no-op until real collateral has been recorded.
    fn direct_host_count_for_ip(&self, _ip: Ipv4Addr) -> u32 {
        0
    }

    /// The full shared-IP census in one call:
    /// every IP observed on at least one direct (non-rule) hostname. The
    /// "smart" kill-switch subtracts this set from its per-IP pin/block set on
    /// every apply/reconcile pass, so it must be one bulk query, not a per-IP
    /// loop. Defaults to empty ("no sharing seen") so mocks and cold caches
    /// keep the historic pin-everything behaviour.
    fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        std::collections::HashSet::new()
    }

    /// The subset of [`Self::shared_direct_ips`] whose direct tenant a MAIN-route
    /// rule claims. Blocking such an address does not divert the tenant into the
    /// tunnel — it kills a host the user's own rule sent the other way — so the
    /// fail-closed exemption subtraction spares these even when hostname-level
    /// enforcement is off. Defaults to empty: mocks and cold caches keep the
    /// stricter behaviour.
    fn shared_direct_ips_primary_ruled(&self) -> std::collections::HashSet<Ipv4Addr> {
        std::collections::HashSet::new()
    }
}

// ── Mock implementation ─────────────────────────────────────────────────────

/// Test-only [`FqdnCacheLookup`] backed by an in-memory map.
///
/// Always compiled (not `#[cfg(test)]`) so integration tests in
/// other crates and `nrr-service-runtime`'s own unit tests share one
/// fixture shape. The mock owns its state behind a [`Mutex`] so test
/// callers can mutate it through `&MockFqdnCacheLookup`.
#[derive(Default)]
pub struct MockFqdnCacheLookup {
    inner: Mutex<MockState>,
}

#[derive(Default)]
struct MockState {
    /// `canonical_hostname → cached IPv4 set`.
    entries: Vec<(String, Vec<Ipv4Addr>)>,
}

// Test-support mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockFqdnCacheLookup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `ips` as the cached resolution set for `hostname`.
    /// Last write wins.
    pub fn set_ips(&self, hostname: &str, ips: Vec<Ipv4Addr>) {
        let canonical = canonicalize_hostname(hostname);
        let mut g = self.inner.lock().unwrap();
        g.entries.retain(|(h, _)| h != &canonical);
        g.entries.push((canonical, ips));
    }

    /// Drop every cached entry. Useful for resetting the mock
    /// between phases of a single test.
    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }
}

// Test-support mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl FqdnCacheLookup for MockFqdnCacheLookup {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
        let canonical = canonicalize_hostname(hostname);
        let g = self.inner.lock().unwrap();
        for (h, ips) in g.entries.iter() {
            if h == &canonical {
                return ips.clone();
            }
        }
        Vec::new()
    }

    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let trimmed = canonicalize_hostname(suffix);
        if trimmed.is_empty() {
            return Vec::new();
        }
        let needle = format!(".{trimmed}");
        let mut matched: Vec<String> = {
            let g = self.inner.lock().unwrap();
            g.entries
                .iter()
                .filter(|(h, _)| h.ends_with(&needle))
                .map(|(h, _)| h.clone())
                .collect()
        };
        matched.sort();
        matched.truncate(limit);
        matched
    }
}

fn canonicalize_hostname(input: &str) -> String {
    input.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ── Production SQLite adapter ───────────────────────────────────────────────

/// Production [`FqdnCacheLookup`] backed by `nrr_fqdn_ip_cache.db`.
///
/// Wraps an `Arc<Mutex<dyn CacheRepository + Send>>` so the same
/// underlying store can be shared with the existing
/// [`SqliteCachePort`][crate::adapters::sqlite_cache::SqliteCachePort]
/// (engine lookup path) and with the DNS refresh task.
///
/// On storage failures (poisoned mutex, SQL error) the methods
/// degrade to empty results and log at `warn!` — the codegen will
/// emit `CodegenDiagnostic::HostnameUnresolved` / `SuffixEmpty` for
/// the affected rules, matching the contract for cold-cache reads.
pub struct SqliteFqdnCacheLookup {
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    thresholds: FreshnessThresholds,
    /// See [`ENFORCEMENT_CONFIRMATION_WINDOW`] — how recently an address must
    /// have been confirmed by a live resolution to reach enforcement.
    confirmation_window: Duration,
}

impl SqliteFqdnCacheLookup {
    pub fn new(
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        thresholds: FreshnessThresholds,
    ) -> Self {
        Self {
            cache,
            thresholds,
            confirmation_window: ENFORCEMENT_CONFIRMATION_WINDOW,
        }
    }

    /// Override the confirmation window. Builder-style; every production call
    /// site keeps the [`ENFORCEMENT_CONFIRMATION_WINDOW`] default.
    pub fn with_confirmation_window(mut self, window: Duration) -> Self {
        self.confirmation_window = window;
        self
    }

    /// [`FqdnCacheLookup::ips_for_hostname`] with an injected `now`, so the
    /// window is exercised deterministically instead of by sleeping.
    fn ips_confirmed_at(&self, hostname: &str, now: SystemTime) -> Vec<Ipv4Addr> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    "fqdn cache mutex poisoned; treating as cold for ips_for_hostname"
                );
                return Vec::new();
            }
        };
        let request = CacheLookupRequest {
            hostname: Some(hostname.to_string()),
            observed_ip: None,
            direction: nrr_domain::decision_lookup::LookupDirection::HostnameToIp,
            active_revision_id: None,
            requested_at: now,
        };
        // Codegen/seeder path uses `all_resolved_ips` (every cached IP → its
        // own /32 permit), never `selected_ip`/`best_source`, so the
        // cache-priority strategy is irrelevant here — pass the default.
        match guard.build_lookup_envelope(
            &request,
            &self.thresholds,
            nrr_storage::resolution_source::CachePriorityStrategy::default(),
        ) {
            Ok(env) => {
                // One subtraction, then one comparison per row — the entries
                // and the vector are already being built, so the window costs
                // no extra allocation and no extra query.
                let cutoff = now.checked_sub(self.confirmation_window);
                env.explain_data
                    .extended
                    .all_resolved_ips
                    .iter()
                    .filter(|e| confirmed_since(e.resolved_at, cutoff))
                    .map(|e| e.addr)
                    .collect()
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    error = %e,
                    hostname = %hostname,
                    "fqdn cache lookup failed; treating as cold"
                );
                Vec::new()
            }
        }
    }
}

/// Is a cached address still inside the confirmation window?
///
/// A row with no recorded `resolved_at` — and the degenerate case of a clock so
/// close to the epoch that the cutoff underflows — counts as confirmed: the age
/// is unknown, and silently dropping a possibly-live address would thin the
/// block set. Unknown age fails toward protection, never toward a leak.
#[inline]
fn confirmed_since(resolved_at: Option<SystemTime>, cutoff: Option<SystemTime>) -> bool {
    match (cutoff, resolved_at) {
        (Some(cutoff), Some(at)) => at >= cutoff,
        _ => true,
    }
}

impl FqdnCacheLookup for SqliteFqdnCacheLookup {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<Ipv4Addr> {
        self.ips_confirmed_at(hostname, SystemTime::now())
    }

    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    "fqdn cache mutex poisoned; treating suffix lookup as cold"
                );
                return Vec::new();
            }
        };
        match guard.list_hostnames_under_suffix(suffix, limit) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    error = %e,
                    suffix = %suffix,
                    "list_hostnames_under_suffix failed; treating as cold"
                );
                Vec::new()
            }
        }
    }

    fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return 0,
        };
        // A read error degrades to "not shared" → the IP is committed, never
        // silently dropped from routing on a census hiccup.
        guard.direct_host_count_for_ip(ip).unwrap_or(0)
    }

    fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return std::collections::HashSet::new(),
        };
        // A read error degrades to "no sharing seen" → the smart kill-switch
        // pins everything that pass (fail toward protection, never toward a
        // silent un-pin of the whole set).
        guard
            .shared_ip_census_ips()
            .map(|v| v.into_iter().collect())
            .unwrap_or_default()
    }

    fn shared_direct_ips_primary_ruled(&self) -> std::collections::HashSet<Ipv4Addr> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return std::collections::HashSet::new(),
        };
        // Same degradation direction as above: on a read error nothing is
        // spared, so the failure mode is "too strict", never "silently leaky".
        guard
            .shared_ip_census_primary_ruled_ips()
            .map(|v| v.into_iter().collect())
            .unwrap_or_default()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_empty_for_unknown_hostname() {
        let cache = MockFqdnCacheLookup::new();
        assert!(cache.ips_for_hostname("unknown.test").is_empty());
    }

    #[test]
    fn mock_set_ips_round_trips() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "Api.Example.COM",
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)],
        );
        // Canonicalised lookup (any casing).
        assert_eq!(
            cache.ips_for_hostname("api.example.com"),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)]
        );
        assert_eq!(
            cache.ips_for_hostname("API.EXAMPLE.COM"),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)]
        );
    }

    #[test]
    fn mock_set_ips_last_write_wins() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("x.test", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        cache.set_ips("x.test", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        assert_eq!(
            cache.ips_for_hostname("x.test"),
            vec![Ipv4Addr::new(2, 2, 2, 2)]
        );
    }

    #[test]
    fn mock_hostnames_under_suffix_excludes_apex() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(3, 3, 3, 3)]);
        let listed = cache.hostnames_under_suffix("example.com", 16);
        assert_eq!(
            listed,
            vec!["api.example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn suffix_domain_expansion_includes_the_cached_apex() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        assert_eq!(
            cache.hostnames_for_suffix_domain("example.com", 16),
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        // Zone fan-out is unchanged — the apex stays out.
        assert_eq!(
            cache.hostnames_under_suffix("example.com", 16),
            vec!["www.example.com".to_string()]
        );
    }

    #[test]
    fn suffix_domain_expansion_skips_an_uncached_apex() {
        // Cold apex → the list stays empty so the caller still emits its
        // "DNS warm-up pending" diagnostic instead of a phantom target.
        let cache = MockFqdnCacheLookup::new();
        assert!(cache
            .hostnames_for_suffix_domain("example.com", 16)
            .is_empty());
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        assert_eq!(
            cache.hostnames_for_suffix_domain("example.com", 16),
            vec!["www.example.com".to_string()]
        );
    }

    #[test]
    fn suffix_domain_expansion_keeps_the_apex_at_the_fan_out_cap() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        for sub in ["a", "b", "c", "d"] {
            cache.set_ips(
                &format!("{sub}.example.com"),
                vec![Ipv4Addr::new(2, 2, 2, 2)],
            );
        }
        let hosts = cache.hostnames_for_suffix_domain("example.com", 3);
        // Exactly `limit` entries — callers read a saturated list as "truncated"
        // and emit their cap diagnostic; the apex is kept, a subdomain gives way.
        assert_eq!(hosts.len(), 3);
        assert!(hosts.contains(&"example.com".to_string()));
    }

    #[test]
    fn suffix_domain_expansion_zero_limit_short_circuits() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(cache
            .hostnames_for_suffix_domain("example.com", 0)
            .is_empty());
    }

    #[test]
    fn mock_hostnames_under_suffix_respects_limit() {
        let cache = MockFqdnCacheLookup::new();
        for sub in ["a", "b", "c", "d"] {
            cache.set_ips(&format!("{sub}.test"), vec![Ipv4Addr::new(1, 1, 1, 1)]);
        }
        let listed = cache.hostnames_under_suffix("test", 2);
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn mock_hostnames_under_suffix_case_insensitive() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        let listed = cache.hostnames_under_suffix("EXAMPLE.COM", 16);
        assert_eq!(listed, vec!["api.example.com".to_string()]);
    }

    #[test]
    fn mock_hostnames_under_suffix_zero_limit_short_circuits() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(cache.hostnames_under_suffix("example.com", 0).is_empty());
    }

    #[test]
    fn mock_clear_drops_all_entries() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("x.test", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        cache.clear();
        assert!(cache.ips_for_hostname("x.test").is_empty());
    }

    /// SqliteFqdnCacheLookup round-trip — uses a real in-memory
    /// SQLite store to exercise the production path. The
    /// `list_hostnames_under_suffix` SQL is the
    /// underlying contract for this port (apex exclusion +
    /// case-insensitive).
    #[test]
    fn sqlite_adapter_returns_cached_ips_and_subdomains() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::resolution_source::StorageResolutionSource;
        use nrr_storage::store::SqliteCacheStore;
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let thresholds = FreshnessThresholds::default_production();
        let store = SqliteCacheStore::new(runner.into_connection(), thresholds.clone());
        // Seed two subdomains under example.com.
        let now = std::time::SystemTime::now();
        for (h, ip) in [
            ("api.example.com", Ipv4Addr::new(203, 0, 113, 1)),
            ("www.example.com", Ipv4Addr::new(203, 0, 113, 2)),
        ] {
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: h.into(),
                    raw_hostname_sample: None,
                    resolved_ips: vec![ip],
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: now,
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, thresholds);

        // Forward lookup returns the cached IP set.
        let ips = adapter.ips_for_hostname("api.example.com");
        assert_eq!(ips, vec![Ipv4Addr::new(203, 0, 113, 1)]);

        // Suffix fan-out returns both subdomains, in ASC order.
        let subs = adapter.hostnames_under_suffix("example.com", 16);
        assert_eq!(
            subs,
            vec!["api.example.com".to_string(), "www.example.com".to_string()]
        );
    }

    // ── Confirmation window ──────────────────────────────────────────────────

    /// A migrated in-memory cache store, ready to seed.
    fn confirmation_store() -> nrr_storage::store::SqliteCacheStore {
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::store::SqliteCacheStore;
        use rusqlite::Connection;

        let conn = Connection::open_in_memory().expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        )
    }

    fn seed(
        store: &nrr_storage::store::SqliteCacheStore,
        host: &str,
        ip: Ipv4Addr,
        at: SystemTime,
    ) {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::resolution_source::StorageResolutionSource;
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: host.into(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: at,
                active_revision_id: None,
            })
            .expect("upsert");
    }

    /// The  incident in miniature: a rule host whose cache still holds
    /// yesterday's front-end address alongside today's. Only today's may reach
    /// enforcement — yesterday's now serves an unrelated tenant, and a `/32`
    /// pin/block over it hits that tenant, not the rule host.
    #[test]
    fn a_rotated_out_address_is_withheld_while_the_confirmed_one_is_kept() {
        let store = confirmation_store();
        let now = SystemTime::now();
        let rotated = Ipv4Addr::new(209, 85, 233, 188);
        let current = Ipv4Addr::new(142, 250, 1, 1);
        let yesterday = now
            .checked_sub(Duration::from_secs(26 * 60 * 60))
            .expect("clock past the epoch");
        seed(&store, "aistudio.google.com", rotated, yesterday);
        seed(&store, "aistudio.google.com", current, now);

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());
        assert_eq!(
            adapter.ips_for_hostname("aistudio.google.com"),
            vec![current],
            "the address confirmed today enforces; yesterday's does not"
        );
    }

    /// The window boundary, both sides, on one fixture — and the all-stale case,
    /// which must read as a cold cache so callers keep emitting their
    /// "DNS warm-up pending" diagnostic instead of enforcing phantom targets.
    #[test]
    fn confirmation_window_boundary_and_fully_stale_host() {
        let store = confirmation_store();
        let now = SystemTime::now();
        let inside = Ipv4Addr::new(203, 0, 113, 10);
        let outside = Ipv4Addr::new(203, 0, 113, 11);
        // A second either side of the window — `resolved_at` round-trips through
        // millisecond storage, so an exactly-on-the-edge timestamp would be a
        // sub-millisecond coin flip, not a behaviour assertion.
        seed(
            &store,
            "edge.example.com",
            inside,
            now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW - Duration::from_secs(1))
                .expect("clock past the epoch"),
        );
        seed(
            &store,
            "edge.example.com",
            outside,
            now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(1))
                .expect("clock past the epoch"),
        );
        seed(
            &store,
            "abandoned.example.com",
            Ipv4Addr::new(203, 0, 113, 12),
            now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
                .expect("clock past the epoch"),
        );

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());
        // A second inside the window is still confirmed; a second past it is not.
        assert_eq!(
            adapter.ips_confirmed_at("edge.example.com", now),
            vec![inside]
        );
        assert!(
            adapter
                .ips_confirmed_at("abandoned.example.com", now)
                .is_empty(),
            "a host with nothing confirmed reads as cold, not as enforceable"
        );
        // Widening the window brings the held last-known-good rows back — the
        // retention policy is untouched, only what enforcement acts on changed.
        let cache2 = Arc::clone(&adapter.cache);
        let wide = SqliteFqdnCacheLookup::new(cache2, FreshnessThresholds::default_production())
            .with_confirmation_window(Duration::from_secs(30 * 24 * 60 * 60));
        assert_eq!(wide.ips_confirmed_at("abandoned.example.com", now).len(), 1);
    }

    #[test]
    fn an_entry_without_a_timestamp_stays_enforceable() {
        // Unknown age must fail toward protection: keeping the address costs a
        // /32 that may be obsolete, dropping it silently thins the block set.
        let now = SystemTime::now();
        let cutoff = now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW);
        assert!(confirmed_since(None, cutoff));
        assert!(confirmed_since(Some(now), None));
        assert!(!confirmed_since(
            now.checked_sub(Duration::from_secs(7 * 60 * 60)),
            cutoff
        ));
    }
}

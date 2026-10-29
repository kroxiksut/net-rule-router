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

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, OnceLock};
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
/// - **Operator reality.** It spans a full working session, and it counts only
///   waking time ([`crate::power_resume::SleepLedger`]), so a machine resumed
///   after a night keeps its block set instead of an empty one.
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
    /// Return every cached address mapped to `hostname` that enforcement may
    /// act on, EITHER FAMILY.
    ///
    /// A caller that can only act on one family narrows for itself and says so
    /// at the call site. Filtering here would make «not cached» and «cached in
    /// the other family» indistinguishable, which is the difference between
    /// «warm up DNS» and «this rule cannot be enforced».
    ///
    /// The production adapter answers only with addresses a live resolution
    /// confirmed within [`ENFORCEMENT_CONFIRMATION_WINDOW`]: the cache retains
    /// last-known-good rows for weeks so a rule survives an outage, but an
    /// address nobody has re-observed in hours has very likely been recycled to
    /// another tenant, and pinning or blocking it hits that tenant instead.
    /// Returns an empty list when the hostname is not cached, every cached
    /// address is beyond the window, or the cache reports a negative entry.
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr>;

    /// List every cached canonical hostname that ends with
    /// `.{suffix}` (with leading dot — apex of the suffix itself is
    /// excluded). Used for `SuffixDomain` and `Zone` rule fan-out.
    ///
    /// `limit` caps the result set — the codegen passes a sane
    /// default (e.g. 1024) to keep an oversize suffix from emitting
    /// a runaway filter set.
    ///
    /// The cap keeps the most recently seen hosts; the result is in NAME order,
    /// because a host's position is its fan-out ordinal and recency order would
    /// renumber the plan on every observation.
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

    /// Every cached hostname a `base.*` rule covers, most recently seen first
    /// and at most `limit`
    /// ([`nrr_domain::decision_matching::match_any_zone_domain`]). Defaults to
    /// none, so mocks and cold caches give the rule no `*.base.<zone>` twins.
    fn hostnames_for_any_zone(&self, _base: &str, _limit: usize) -> Vec<String> {
        Vec::new()
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

    /// A point-in-time copy of everything this lookup can answer, when the
    /// implementation can produce one cheaply.
    ///
    /// One filter compute asks the cache tens of thousands of times; against
    /// SQLite that is tens of thousands of locks and prepared statements on the
    /// connection the live observation path is writing to. An implementation
    /// that can hand over the whole table at once says so here, and the compute
    /// runs against memory. `None` (the default, and what every mock keeps)
    /// means "keep asking me directly".
    fn snapshot_for_compute(&self) -> Option<Arc<FqdnCacheSnapshot>> {
        None
    }

    /// [`Self::snapshot_for_compute`] cut down to `addresses`, as
    /// [`FqdnCacheSnapshot::scoped_to`] cuts it. An implementation that can
    /// read only those rows does: this is asked on the DNS path.
    fn snapshot_for_addresses(&self, addresses: &[IpAddr]) -> Option<FqdnCacheSnapshot> {
        self.snapshot_for_compute()
            .map(|full| full.scoped_to(addresses))
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
    entries: Vec<(String, Vec<IpAddr>)>,
}

// Test-support mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockFqdnCacheLookup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `ips` as the cached resolution set for `hostname`.
    /// Last write wins.
    /// Takes  because almost every fixture is v4; a v6 fixture uses
    /// [`Self::set_addresses`].
    pub fn set_ips(&self, hostname: &str, ips: Vec<Ipv4Addr>) {
        self.set_addresses(hostname, ips.into_iter().map(IpAddr::V4).collect());
    }

    /// Register `addrs` (either family) as the cached set for `hostname`.
    pub fn set_addresses(&self, hostname: &str, ips: Vec<IpAddr>) {
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
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
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

    fn hostnames_for_any_zone(&self, base: &str, limit: usize) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        covered_by_any_zone(g.entries.iter().map(|(h, _)| h.as_str()), base, limit)
    }
}

/// The hosts among `hosts` a `base.*` rule covers, lowercased, in the order
/// given: not every stored name is lowercase, and the rule's base is.
fn covered_by_any_zone<'a>(
    hosts: impl Iterator<Item = &'a str>,
    base: &str,
    limit: usize,
) -> Vec<String> {
    hosts
        .map(str::to_ascii_lowercase)
        .filter(|h| nrr_domain::decision_matching::match_any_zone_domain(h, base).is_some())
        .take(limit)
        .collect()
}

fn canonicalize_hostname(input: &str) -> String {
    input.trim().trim_end_matches('.').to_ascii_lowercase()
}

// ── Production SQLite adapter ───────────────────────────────────────────────

/// Production [`FqdnCacheLookup`] backed by `nrr_fqdn_ip_cache.db`.
///
/// Wraps an `Arc<Mutex<dyn CacheRepository + Send>>` so the same store is
/// shared with the DNS refresh task.
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
    /// The window counts waking time: nothing re-confirms an address during a
    /// sleep, and a night's sleep would otherwise empty every rule's set at
    /// once while the tunnel is still reconnecting.
    sleeps: Arc<crate::power_resume::SleepLedger>,
    /// The last whole-cache snapshot, handed out again while no news reached
    /// the cache: a pass over N users asked for 1 + 2N of them, each five
    /// table reads under the lock the DNS answer path also needs.
    last_snapshot: Mutex<Option<KeptSnapshot>>,
}

/// A snapshot and the cache state it was read at.
struct KeptSnapshot {
    generation: u64,
    taken: std::time::Instant,
    snapshot: Arc<FqdnCacheSnapshot>,
}

/// How long a snapshot is handed out again: the confirmation cutoff it was
/// read with must not drift.
const SNAPSHOT_REUSE: Duration = Duration::from_secs(1);

impl SqliteFqdnCacheLookup {
    pub fn new(
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        thresholds: FreshnessThresholds,
    ) -> Self {
        Self {
            cache,
            thresholds,
            confirmation_window: ENFORCEMENT_CONFIRMATION_WINDOW,
            sleeps: crate::power_resume::process_sleeps(),
            last_snapshot: Mutex::new(None),
        }
    }

    /// Read sleeps from `sleeps` instead of the process ledger.
    pub fn with_sleep_ledger(mut self, sleeps: Arc<crate::power_resume::SleepLedger>) -> Self {
        self.sleeps = sleeps;
        self
    }

    fn cutoff(&self, now: SystemTime) -> Option<SystemTime> {
        self.sleeps.awake_cutoff(now, self.confirmation_window)
    }

    /// Override the confirmation window. Builder-style; every production call
    /// site keeps the [`ENFORCEMENT_CONFIRMATION_WINDOW`] default.
    pub fn with_confirmation_window(mut self, window: Duration) -> Self {
        self.confirmation_window = window;
        self
    }

    /// [`FqdnCacheLookup::ips_for_hostname`] with an injected `now`, so the
    /// window is exercised deterministically instead of by sleeping.
    fn ips_confirmed_at(&self, hostname: &str, now: SystemTime) -> Vec<IpAddr> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-mutex-poisoned-ips",
                    "fqdn cache mutex poisoned; treating as cold for ips_for_hostname"
                );
                return Vec::new();
            }
        };
        let request = CacheLookupRequest {
            hostname: Some(hostname.to_string()),
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
                let cutoff = self.cutoff(now);
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
                    msg_key = "fqdncache-lookup-failed",
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
    fn snapshot_for_compute(&self) -> Option<Arc<FqdnCacheSnapshot>> {
        // Read before the snapshot: a write in between leaves the kept one
        // fresher than its generation, never staler.
        let generation = self
            .cache
            .lock()
            .ok()
            .and_then(|guard| guard.change_generation());
        let mut kept = self.last_snapshot.lock().unwrap_or_else(|p| p.into_inner());
        if let (Some(generation), Some(last)) = (generation, kept.as_ref()) {
            if last.generation == generation && last.taken.elapsed() < SNAPSHOT_REUSE {
                return Some(Arc::clone(&last.snapshot));
            }
        }
        let snapshot = Arc::new(FqdnCacheSnapshot::take(
            self.cache.as_ref(),
            self.cutoff(SystemTime::now()),
        ));
        *kept = generation.map(|generation| KeptSnapshot {
            generation,
            taken: std::time::Instant::now(),
            snapshot: Arc::clone(&snapshot),
        });
        Some(snapshot)
    }

    fn snapshot_for_addresses(&self, addresses: &[IpAddr]) -> Option<FqdnCacheSnapshot> {
        Some(FqdnCacheSnapshot::take_for_addresses(
            self.cache.as_ref(),
            self.cutoff(SystemTime::now()),
            addresses,
        ))
    }

    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
        self.ips_confirmed_at(hostname, SystemTime::now())
    }

    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-mutex-poisoned-suffix",
                    "fqdn cache mutex poisoned; treating suffix lookup as cold"
                );
                return Vec::new();
            }
        };
        match guard.list_hostnames_under_suffix(suffix, limit) {
            Ok(mut v) => {
                v.sort_unstable();
                v
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-suffix-lookup-failed",
                    error = %e,
                    suffix = %suffix,
                    "list_hostnames_under_suffix failed; treating as cold"
                );
                Vec::new()
            }
        }
    }

    fn hostnames_for_any_zone(&self, base: &str, limit: usize) -> Vec<String> {
        let Ok(guard) = self.cache.lock() else {
            return Vec::new();
        };
        // The query over-reads (`base` anywhere as whole labels); a few times
        // the limit leaves room for the names the zone test drops.
        match guard.list_hostnames_with_site(base, limit.saturating_mul(4)) {
            Ok(hosts) => covered_by_any_zone(hosts.iter().map(String::as_str), base, limit),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-site-lookup-failed",
                    error = %e,
                    "list_hostnames_with_site failed; treating as cold"
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
        census_or_empty(guard.shared_ip_census_ips())
    }

    fn shared_direct_ips_primary_ruled(&self) -> std::collections::HashSet<Ipv4Addr> {
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return std::collections::HashSet::new(),
        };
        // Same degradation direction as above: on a read error nothing is
        // spared, so the failure mode is "too strict", never "silently leaky".
        census_or_empty(guard.shared_ip_census_primary_ruled_ips())
    }
}

/// An unreadable census is an empty one — nothing spared — and says so.
fn census_or_empty(
    read: nrr_storage::StorageResult<Vec<Ipv4Addr>>,
) -> std::collections::HashSet<Ipv4Addr> {
    match read {
        Ok(ips) => ips.into_iter().collect(),
        Err(e) => {
            tracing::warn!(
                target: "nrr::wfp-codegen",
                msg_key = "fqdncache-shared-hosts-read-failed",
                error = %e,
                "shared-IP census read failed; sparing nothing this pass"
            );
            std::collections::HashSet::new()
        }
    }
}

// ── Snapshot ────────────────────────────────────────────────────────────────

/// A [`FqdnCacheLookup`] answering entirely from memory, taken in a handful of
/// queries.
///
/// The codegen asks the cache for the addresses of every rule host, every
/// hostname under every suffix, and the census for every candidate address. Via
/// [`SqliteFqdnCacheLookup`] each of those is a lock, a prepared statement and a
/// query against the SAME connection the live DNS observation path is writing
/// to, so one pass over a 229-rule book cost tens of thousands of round trips —
/// 18.9 s on the owner's machine, against a table that reads whole in
/// milliseconds.
///
/// The snapshot is also more correct than what it replaces: a compute now sees
/// ONE state of the cache instead of a slightly different one per lookup.
pub struct FqdnCacheSnapshot {
    /// `canonical hostname → addresses`, filtered by the confirmation window
    /// and kept in the `resolved_at DESC` order the per-hostname query returns,
    /// so filter ids derive identically. Keyed by the string as STORED and
    /// matched exactly, because the query it stands in for is
    /// `WHERE canonical_host = ?1`.
    by_hostname: HashMap<String, Vec<IpAddr>>,
    /// Every cached hostname in `last_seen_at DESC, canonical_host ASC` order —
    /// what suffix fan-out walks, and the order that decides which hosts of a
    /// capped zone earn a permit.
    hostnames_by_recency: Vec<String>,
    /// Built on the first suffix question.
    suffix_index: OnceLock<SuffixIndex>,
    direct_host_counts: HashMap<Ipv4Addr, u32>,
    shared_direct: std::collections::HashSet<Ipv4Addr>,
    shared_direct_primary_ruled: std::collections::HashSet<Ipv4Addr>,
}

/// Cached hostnames keyed by their labels reversed, lowered once.
///
/// The hosts under a suffix are then one range of the map. A pass asked every
/// suffix and zone rule for its hosts by lowering and testing every cached
/// name, several times per pass and per user: with hundreds of such rules and
/// tens of thousands of names, the seconds a pass took.
#[derive(Default)]
struct SuffixIndex {
    /// `com.example.www` → positions in `hostnames_by_recency`.
    by_reversed: BTreeMap<String, Vec<usize>>,
}

impl SuffixIndex {
    fn build(hosts: &[String]) -> Self {
        let mut by_reversed: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (at, host) in hosts.iter().enumerate() {
            by_reversed
                .entry(reversed_labels(&host.to_ascii_lowercase()))
                .or_default()
                .push(at);
        }
        Self { by_reversed }
    }

    /// Positions of the hosts strictly under `suffix` (lowercase, no trailing
    /// dot), in recency order: what `LIKE '%.suffix'` matches, the apex out.
    fn under(&self, suffix: &str) -> Vec<usize> {
        let prefix = format!("{}.", reversed_labels(suffix));
        let mut at: Vec<usize> = self
            .by_reversed
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .flat_map(|(_, positions)| positions.iter().copied())
            .collect();
        at.sort_unstable();
        at
    }
}

/// `www.example.com` → `com.example.www`.
fn reversed_labels(host: &str) -> String {
    host.rsplit('.').collect::<Vec<_>>().join(".")
}

impl FqdnCacheSnapshot {
    /// Takes the snapshot. A failed read yields an EMPTY snapshot for that
    /// part, which is the same degradation the per-call adapter applies: a cold
    /// cache, never a wrong one.
    /// Keeps the addresses confirmed at or after `cutoff`, all of them when
    /// `None`.
    pub fn take(cache: &Mutex<dyn CacheRepository + Send>, cutoff: Option<SystemTime>) -> Self {
        let guard = match cache.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-mutex-poisoned-snapshot",
                    "fqdn cache mutex poisoned; taking an empty snapshot"
                );
                return Self::empty();
            }
        };
        let mut by_hostname: HashMap<String, Vec<IpAddr>> = HashMap::new();
        match guard.snapshot_resolutions() {
            Ok(rows) => {
                for (host, addr, resolved_at) in rows {
                    if !confirmed_since(Some(resolved_at), cutoff) {
                        continue;
                    }
                    by_hostname.entry(host).or_default().push(addr);
                }
            }
            Err(e) => tracing::warn!(
                target: "nrr::wfp-codegen",
                msg_key = "fqdncache-snapshot-failed",
                error = %e,
                "fqdn cache snapshot failed; treating as cold"
            ),
        }
        let hostnames_by_recency: Vec<String> = guard
            .snapshot_hostnames()
            .map(|rows| rows.into_iter().map(|(host, _)| host).collect())
            .unwrap_or_default();
        let direct_host_counts = guard
            .shared_ip_direct_host_counts()
            .map(|rows| rows.into_iter().collect())
            .unwrap_or_default();
        let shared_direct = census_or_empty(guard.shared_ip_census_ips());
        let shared_direct_primary_ruled =
            census_or_empty(guard.shared_ip_census_primary_ruled_ips());
        drop(guard);

        Self {
            by_hostname,
            hostnames_by_recency,
            suffix_index: OnceLock::new(),
            direct_host_counts,
            shared_direct,
            shared_direct_primary_ruled,
        }
    }

    /// What [`Self::take`] followed by [`Self::scoped_to`] gives, read by
    /// index lookups on `wanted` instead of whole tables.
    pub fn take_for_addresses(
        cache: &Mutex<dyn CacheRepository + Send>,
        cutoff: Option<SystemTime>,
        wanted: &[IpAddr],
    ) -> Self {
        let read = match cache.lock() {
            Ok(guard) => guard.snapshot_for_addresses(wanted),
            Err(_) => return Self::empty(),
        };
        let rows = match read {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::wfp-codegen",
                    msg_key = "fqdncache-snapshot-failed",
                    error = %e,
                    "fqdn cache snapshot failed; treating as cold"
                );
                return Self::empty();
            }
        };
        let mut by_hostname: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for (host, addr, resolved_at) in rows.resolutions {
            if confirmed_since(Some(resolved_at), cutoff) {
                by_hostname.entry(host).or_default().push(addr);
            }
        }
        let hostnames_by_recency = rows
            .hostnames
            .into_iter()
            .map(|(host, _)| host)
            .filter(|host| by_hostname.contains_key(host))
            .collect();
        Self {
            by_hostname,
            hostnames_by_recency,
            suffix_index: OnceLock::new(),
            shared_direct: rows.direct_host_counts.iter().map(|(ip, _)| *ip).collect(),
            direct_host_counts: rows.direct_host_counts.into_iter().collect(),
            shared_direct_primary_ruled: rows.primary_ruled.into_iter().collect(),
        }
    }

    fn empty() -> Self {
        Self {
            by_hostname: HashMap::new(),
            hostnames_by_recency: Vec::new(),
            suffix_index: OnceLock::new(),
            direct_host_counts: HashMap::new(),
            shared_direct: std::collections::HashSet::new(),
            shared_direct_primary_ruled: std::collections::HashSet::new(),
        }
    }

    /// Hostnames the snapshot knows an enforceable address for.
    pub fn hostname_count(&self) -> usize {
        self.by_hostname.len()
    }

    /// The snapshot as a plan about `wanted` alone needs it: each host keeps
    /// only those of its addresses, a host with none drops out, the census
    /// keeps only them. What a plan decides about an address rests on the
    /// facts naming it, so it routes `wanted` as a plan over the whole cache
    /// would — bar a host past a per-host or per-rule cap, which the next full
    /// pass settles.
    #[must_use]
    pub fn scoped_to(&self, wanted: &[IpAddr]) -> Self {
        let wanted: std::collections::HashSet<IpAddr> = wanted.iter().copied().collect();
        let by_hostname: HashMap<String, Vec<IpAddr>> = self
            .by_hostname
            .iter()
            .filter_map(|(host, ips)| {
                let kept: Vec<IpAddr> = ips
                    .iter()
                    .copied()
                    .filter(|ip| wanted.contains(ip))
                    .collect();
                (!kept.is_empty()).then(|| (host.clone(), kept))
            })
            .collect();
        let hostnames_by_recency = self
            .hostnames_by_recency
            .iter()
            .filter(|host| by_hostname.contains_key(host.as_str()))
            .cloned()
            .collect();
        let kept = |ip: &Ipv4Addr| wanted.contains(&IpAddr::V4(*ip));
        Self {
            by_hostname,
            hostnames_by_recency,
            suffix_index: OnceLock::new(),
            direct_host_counts: self
                .direct_host_counts
                .iter()
                .filter(|(ip, _)| kept(ip))
                .map(|(ip, count)| (*ip, *count))
                .collect(),
            shared_direct: self.shared_direct.iter().copied().filter(kept).collect(),
            shared_direct_primary_ruled: self
                .shared_direct_primary_ruled
                .iter()
                .copied()
                .filter(kept)
                .collect(),
        }
    }
}

/// The pass's snapshot when the live lookup could take one, the live lookup
/// otherwise (mocks).
pub fn snapshot_or_live<'a>(
    snapshot: Option<&'a FqdnCacheSnapshot>,
    live: &'a dyn FqdnCacheLookup,
) -> &'a dyn FqdnCacheLookup {
    match snapshot {
        Some(snapshot) => snapshot,
        None => live,
    }
}

impl FqdnCacheLookup for FqdnCacheSnapshot {
    fn ips_for_hostname(&self, hostname: &str) -> Vec<IpAddr> {
        // Exact match, like the `WHERE canonical_host = ?1` it replaces.
        self.by_hostname.get(hostname).cloned().unwrap_or_default()
    }

    fn hostnames_under_suffix(&self, suffix: &str, limit: usize) -> Vec<String> {
        if limit == 0 || suffix.is_empty() {
            return Vec::new();
        }
        let normalised = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        if normalised.is_empty() {
            return Vec::new();
        }
        // `LIKE '%.{suffix}'` in SQLite is ASCII-case-INSENSITIVE and the
        // stored names are not all lowercase; the index lowers them once.
        let positions = self
            .suffix_index
            .get_or_init(|| SuffixIndex::build(&self.hostnames_by_recency))
            .under(&normalised);
        let mut hosts = nrr_storage::suffix_window::fair_suffix_window(
            positions
                .into_iter()
                .filter_map(|at| self.hostnames_by_recency.get(at).cloned()),
            &normalised,
            limit,
        );
        hosts.sort_unstable();
        hosts
    }

    fn hostnames_for_any_zone(&self, base: &str, limit: usize) -> Vec<String> {
        covered_by_any_zone(
            self.hostnames_by_recency.iter().map(String::as_str),
            base,
            limit,
        )
    }

    fn direct_host_count_for_ip(&self, ip: Ipv4Addr) -> u32 {
        self.direct_host_counts.get(&ip).copied().unwrap_or(0)
    }

    fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.shared_direct.clone()
    }

    fn shared_direct_ips_primary_ruled(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.shared_direct_primary_ruled.clone()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod suffix_index_tests {
    use super::SuffixIndex;

    /// The index answers what the scan it replaces answered: case folded, the
    /// apex out, a label boundary, recency order kept.
    #[test]
    fn the_index_finds_what_a_scan_of_every_name_finds() {
        let hosts: Vec<String> = [
            "www.Example.com",
            "example.com",
            "xexample.com",
            "a.b.example.com",
            "example.com.evil.test",
            "cdn.example.co.uk",
            "co.uk",
            "x..example.com",
            "API.EXAMPLE.COM",
            "trailing.example.com.",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let index = SuffixIndex::build(&hosts);
        for suffix in [
            "example.com",
            "com",
            "co.uk",
            "uk",
            "b.example.com",
            "nothing.test",
        ] {
            let needle = format!(".{suffix}");
            let scanned: Vec<usize> = hosts
                .iter()
                .enumerate()
                .filter(|(_, h)| h.to_ascii_lowercase().ends_with(&needle))
                .map(|(at, _)| at)
                .collect();
            assert_eq!(index.under(suffix), scanned, "{suffix}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

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
            vec![Ipv4Addr::new(100, 64, 1, 1), Ipv4Addr::new(100, 64, 2, 2)],
        );
        // Canonicalised lookup (any casing).
        assert_eq!(
            cache.ips_for_hostname("api.example.com"),
            vec![Ipv4Addr::new(100, 64, 1, 1), Ipv4Addr::new(100, 64, 2, 2)]
        );
        assert_eq!(
            cache.ips_for_hostname("API.EXAMPLE.COM"),
            vec![Ipv4Addr::new(100, 64, 1, 1), Ipv4Addr::new(100, 64, 2, 2)]
        );
    }

    #[test]
    fn mock_set_ips_last_write_wins() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("x.test", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        cache.set_ips("x.test", vec![Ipv4Addr::new(100, 64, 2, 2)]);
        assert_eq!(
            cache.ips_for_hostname("x.test"),
            vec![Ipv4Addr::new(100, 64, 2, 2)]
        );
    }

    #[test]
    fn mock_hostnames_under_suffix_excludes_apex() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(100, 64, 2, 2)]);
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(100, 64, 3, 3)]);
        let listed = cache.hostnames_under_suffix("example.com", 16);
        assert_eq!(
            listed,
            vec!["api.example.com".to_string(), "www.example.com".to_string()]
        );
    }

    #[test]
    fn suffix_domain_expansion_includes_the_cached_apex() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(100, 64, 2, 2)]);
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
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(100, 64, 2, 2)]);
        assert_eq!(
            cache.hostnames_for_suffix_domain("example.com", 16),
            vec!["www.example.com".to_string()]
        );
    }

    #[test]
    fn suffix_domain_expansion_keeps_the_apex_at_the_fan_out_cap() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        for sub in ["a", "b", "c", "d"] {
            cache.set_ips(
                &format!("{sub}.example.com"),
                vec![Ipv4Addr::new(100, 64, 2, 2)],
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
        cache.set_ips("example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        assert!(cache
            .hostnames_for_suffix_domain("example.com", 0)
            .is_empty());
    }

    #[test]
    fn mock_hostnames_under_suffix_respects_limit() {
        let cache = MockFqdnCacheLookup::new();
        for sub in ["a", "b", "c", "d"] {
            cache.set_ips(&format!("{sub}.test"), vec![Ipv4Addr::new(100, 64, 1, 1)]);
        }
        let listed = cache.hostnames_under_suffix("test", 2);
        assert_eq!(listed.len(), 2);
    }

    #[test]
    fn mock_hostnames_under_suffix_case_insensitive() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        let listed = cache.hostnames_under_suffix("EXAMPLE.COM", 16);
        assert_eq!(listed, vec!["api.example.com".to_string()]);
    }

    #[test]
    fn mock_hostnames_under_suffix_zero_limit_short_circuits() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(100, 64, 1, 1)]);
        assert!(cache.hostnames_under_suffix("example.com", 0).is_empty());
    }

    #[test]
    fn mock_clear_drops_all_entries() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("x.test", vec![Ipv4Addr::new(100, 64, 1, 1)]);
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
                    resolved_ips: vec![IpAddr::V4(ip)],
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

    /// Recency picks WHICH hosts a capped suffix keeps; the order they come
    /// back in is their names'. A host seen again must not renumber the plan.
    #[test]
    fn suffix_hosts_are_chosen_by_recency_and_listed_by_name() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::resolution_source::StorageResolutionSource;
        use nrr_storage::store::SqliteCacheStore;

        let runner = SqliteMigrationRunner::for_cache_db(
            rusqlite::Connection::open_in_memory().expect("open"),
        );
        runner.run_pending_migrations().expect("migrate");
        let thresholds = FreshnessThresholds::default_production();
        let store = SqliteCacheStore::new(runner.into_connection(), thresholds.clone());
        let now = std::time::SystemTime::now();
        // `www` is the most recently seen of the two, by more than the hour
        // recency is compared to.
        for (h, ip, ago) in [
            ("www.example.com", Ipv4Addr::new(203, 0, 113, 2), 10),
            ("api.example.com", Ipv4Addr::new(203, 0, 113, 1), 7200),
        ] {
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: h.into(),
                    raw_hostname_sample: None,
                    resolved_ips: vec![IpAddr::V4(ip)],
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: now - Duration::from_secs(ago),
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let live = SqliteFqdnCacheLookup::new(cache, thresholds);
        let snapshot = live.snapshot_for_compute().expect("snapshot");

        for view in [&live as &dyn FqdnCacheLookup, &*snapshot] {
            assert_eq!(
                view.hostnames_under_suffix("example.com", 16),
                vec!["api.example.com".to_string(), "www.example.com".to_string()]
            );
            assert_eq!(
                view.hostnames_under_suffix("example.com", 1),
                vec!["www.example.com".to_string()],
                "the cap keeps the host in use"
            );
        }
    }

    // ── Snapshot parity ──────────────────────────────────────────────────────

    /// The snapshot replaces the per-hostname path on the ENFORCEMENT path, so
    /// "faster" is worth nothing unless the answers are identical. This is the
    /// fixture that says so: several hosts under a shared suffix, a host with
    /// two addresses, one address outside the confirmation window, an apex, a
    /// host with mixed casing, and a name no rule mentions.
    #[test]
    fn the_snapshot_answers_exactly_what_the_per_hostname_path_answers() {
        let store = confirmation_store();
        let now = SystemTime::now();
        let fresh = |secs: u64| {
            now.checked_sub(Duration::from_secs(secs))
                .expect("clock past the epoch")
        };
        seed(
            &store,
            "example.com",
            Ipv4Addr::new(203, 0, 113, 1),
            fresh(10),
        );
        seed(
            &store,
            "www.example.com",
            Ipv4Addr::new(203, 0, 113, 2),
            fresh(20),
        );
        seed(
            &store,
            "www.example.com",
            Ipv4Addr::new(203, 0, 113, 3),
            fresh(5),
        );
        seed(
            &store,
            "api.example.com",
            Ipv4Addr::new(203, 0, 113, 4),
            fresh(30),
        );
        // Beyond the window: neither path may enforce it.
        seed(
            &store,
            "stale.example.com",
            Ipv4Addr::new(203, 0, 113, 5),
            now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
                .expect("clock past the epoch"),
        );
        seed(
            &store,
            "Deep.Sub.Example.Com",
            Ipv4Addr::new(203, 0, 113, 6),
            fresh(40),
        );
        seed(
            &store,
            "other.test",
            Ipv4Addr::new(198, 51, 100, 9),
            fresh(50),
        );

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let live = SqliteFqdnCacheLookup::new(
            Arc::clone(&cache),
            FreshnessThresholds::default_production(),
        );
        let snapshot = live
            .snapshot_for_compute()
            .expect("sqlite adapter snapshots");

        for host in [
            "example.com",
            "www.example.com",
            "api.example.com",
            "stale.example.com",
            "deep.sub.example.com",
            "DEEP.SUB.EXAMPLE.COM",
            "other.test",
            "never.heard.of.it",
        ] {
            assert_eq!(
                snapshot.ips_for_hostname(host),
                live.ips_for_hostname(host),
                "addresses differ for {host}"
            );
        }

        for (suffix, limit) in [
            ("example.com", 16),
            ("sub.example.com", 16),
            ("example.com", 1),
            ("example.com", 0),
            ("test", 16),
            ("nothing.here", 16),
            ("", 16),
        ] {
            assert_eq!(
                snapshot.hostnames_under_suffix(suffix, limit),
                live.hostnames_under_suffix(suffix, limit),
                "suffix fan-out differs for {suffix} (limit {limit})"
            );
            // The suffix-domain helper is a default method over the two above,
            // so it must agree as well — that is what the codegen actually calls.
            assert_eq!(
                snapshot.hostnames_for_suffix_domain(suffix, limit),
                live.hostnames_for_suffix_domain(suffix, limit),
                "suffix-domain expansion differs for {suffix} (limit {limit})"
            );
        }
    }

    /// The snapshot is the only way cached addresses reach the Windows
    /// codegens, so a family it drops is a family nothing enforces, whatever the
    /// planner decides. It carries both; which one is named is the planner's call.
    #[test]
    fn the_snapshot_carries_both_families() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::resolution_source::StorageResolutionSource;
        let store = confirmation_store();
        let v6: IpAddr = "fd00::1".parse().expect("v6");
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "dual.example.com".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), v6],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert");
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let live = SqliteFqdnCacheLookup::new(
            Arc::clone(&cache),
            FreshnessThresholds::default_production(),
        );
        let snapshot = live
            .snapshot_for_compute()
            .expect("sqlite adapter snapshots");

        let mut got = snapshot.ips_for_hostname("dual.example.com");
        got.sort();
        let mut want = live.ips_for_hostname("dual.example.com");
        want.sort();
        assert_eq!(
            got, want,
            "the snapshot answers what the per-hostname path answers"
        );
        assert!(got.contains(&v6), "{got:?}");
    }

    /// A host whose every address aged out must read as COLD through the
    /// snapshot too — positive control for the filter above, because a snapshot
    /// that forgot the window would look identical on every fresh host.
    #[test]
    fn the_snapshot_applies_the_confirmation_window() {
        let store = confirmation_store();
        let now = SystemTime::now();
        seed(
            &store,
            "aged.example.com",
            Ipv4Addr::new(203, 0, 113, 77),
            now.checked_sub(ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60))
                .expect("clock past the epoch"),
        );
        seed(
            &store,
            "current.example.com",
            Ipv4Addr::new(203, 0, 113, 78),
            now,
        );

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let live = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());
        let snapshot = live.snapshot_for_compute().expect("snapshot");

        assert!(snapshot.ips_for_hostname("aged.example.com").is_empty());
        assert_eq!(
            snapshot.ips_for_hostname("current.example.com"),
            vec![Ipv4Addr::new(203, 0, 113, 78)]
        );
        assert_eq!(
            snapshot.hostname_count(),
            1,
            "only the confirmed host is in"
        );
    }

    // ── Confirmation window ──────────────────────────────────────────────────

    /// A migrated in-memory cache store, ready to seed.
    /// A pass over N users asks for the whole cache 1 + 2N times, each ask
    /// five table reads under the lock the DNS answer path needs too: while no
    /// new address arrived they share one reading, and news is read at once.
    #[test]
    fn a_pass_reads_the_cache_once_until_news_arrives() {
        let now = SystemTime::now();
        let concrete = Arc::new(Mutex::new(confirmation_store()));
        seed(
            &concrete.lock().expect("store"),
            "mail.example",
            Ipv4Addr::new(203, 0, 113, 21),
            now,
        );
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = concrete.clone();
        let lookup = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());

        let first = lookup.snapshot_for_compute().expect("snapshot");
        let again = lookup.snapshot_for_compute().expect("snapshot");
        assert!(
            Arc::ptr_eq(&first, &again),
            "the second ask read the cache again"
        );

        seed(
            &concrete.lock().expect("store"),
            "mail.example",
            Ipv4Addr::new(203, 0, 113, 22),
            now,
        );
        let after_news = lookup.snapshot_for_compute().expect("snapshot");
        assert!(
            !Arc::ptr_eq(&first, &after_news),
            "a new address waited for a later ask"
        );
        assert_eq!(after_news.ips_for_hostname("mail.example").len(), 2);
    }

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
                resolved_ips: vec![IpAddr::V4(ip)],
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
        let rotated = Ipv4Addr::new(203, 0, 113, 165);
        let current = Ipv4Addr::new(203, 0, 113, 147);
        let yesterday = now
            .checked_sub(Duration::from_secs(26 * 60 * 60))
            .expect("clock past the epoch");
        seed(&store, "aistudio.search.example", rotated, yesterday);
        seed(&store, "aistudio.search.example", current, now);

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());
        assert_eq!(
            adapter.ips_for_hostname("aistudio.search.example"),
            vec![current],
            "the address confirmed today enforces; yesterday's does not"
        );
    }

    /// A laptop closed for ten hours: nothing could re-confirm a rule host's
    /// address while it slept, so the morning's first pass must still pin and
    /// block it while the tunnel reconnects, not drop every rule's set at once.
    /// An address already stale when the lid closed stays out.
    #[test]
    fn a_night_asleep_does_not_age_the_rule_addresses_out() {
        let store = confirmation_store();
        let now = SystemTime::now();
        let hour = Duration::from_secs(60 * 60);
        let confirmed = Ipv4Addr::new(203, 0, 113, 21);
        let stale = Ipv4Addr::new(203, 0, 113, 22);
        // Confirmed shortly before the lid closed; the other one was already
        // nearly seven hours old by then.
        seed(&store, "mail.example", confirmed, now - 11 * hour);
        seed(&store, "mail.example", stale, now - 17 * hour);
        let sleeps = Arc::new(crate::power_resume::SleepLedger::default());
        // Woke ten minutes ago after ten hours asleep.
        sleeps.record(now - Duration::from_secs(600), 10 * hour);

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production())
            .with_sleep_ledger(sleeps);
        assert_eq!(
            adapter.ips_confirmed_at("mail.example", now),
            vec![confirmed]
        );
        let snapshot = adapter.snapshot_for_compute().expect("snapshot");
        assert_eq!(snapshot.ips_for_hostname("mail.example"), vec![confirmed]);
    }

    /// After the clock steps back, a row stamped in the future must age out of
    /// the window like any other, not stay confirmed for the length of the step.
    #[test]
    fn a_future_stamp_ages_out_of_the_window_from_now() {
        let store = confirmation_store();
        let now = SystemTime::now();
        let stamped_ahead = now + Duration::from_secs(5 * 60 * 60);
        seed(
            &store,
            "ahead.example",
            Ipv4Addr::new(203, 0, 113, 77),
            stamped_ahead,
        );

        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let adapter = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production());
        let after_window = now + ENFORCEMENT_CONFIRMATION_WINDOW + Duration::from_secs(60);
        assert!(
            adapter
                .ips_confirmed_at("ahead.example", after_window)
                .is_empty(),
            "the stamp was trusted past the confirmation window"
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

    /// A first contact plans over this view, so it must answer about the
    /// wanted addresses exactly as the whole snapshot does, and know nothing
    /// else.
    #[test]
    fn a_scoped_snapshot_keeps_only_the_wanted_addresses() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::resolution_source::StorageResolutionSource;
        let store = confirmation_store();
        let wanted = Ipv4Addr::new(203, 0, 113, 1);
        let other = Ipv4Addr::new(203, 0, 113, 2);
        let elsewhere = Ipv4Addr::new(198, 51, 100, 3);
        let now = SystemTime::now();
        for (host, ips) in [
            ("a.cdn.example", vec![wanted, other]),
            ("b.cdn.example", vec![elsewhere]),
            ("direct.example", vec![wanted]),
        ] {
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: host.into(),
                    raw_hostname_sample: None,
                    resolved_ips: ips.into_iter().map(IpAddr::V4).collect(),
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: now,
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        store
            .record_shared_ip_direct_host(wanted, "direct.example", 1, true)
            .expect("census");
        store
            .record_shared_ip_direct_host(elsewhere, "direct.example", 1, false)
            .expect("census");
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let full = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production())
            .snapshot_for_compute()
            .expect("sqlite adapter snapshots");

        let scoped = full.scoped_to(&[IpAddr::V4(wanted)]);

        assert_eq!(
            scoped.ips_for_hostname("a.cdn.example"),
            vec![IpAddr::V4(wanted)]
        );
        assert!(scoped.ips_for_hostname("b.cdn.example").is_empty());
        assert_eq!(
            scoped.hostnames_under_suffix("cdn.example", SUFFIX_LIMIT_FOR_TESTS),
            vec!["a.cdn.example".to_string()]
        );
        assert_eq!(
            scoped.direct_host_count_for_ip(wanted),
            full.direct_host_count_for_ip(wanted)
        );
        assert_eq!(scoped.shared_direct_ips(), [wanted].into_iter().collect());
        assert_eq!(
            scoped.shared_direct_ips_primary_ruled(),
            full.shared_direct_ips_primary_ruled()
                .into_iter()
                .filter(|ip| *ip == wanted)
                .collect()
        );
    }

    /// The first contact reads only the rows on its addresses; what it plans
    /// from must still be the whole snapshot cut down, or it routes an
    /// address the next pass takes back (or misses one it keeps).
    #[test]
    fn reading_only_the_wanted_addresses_gives_the_whole_snapshot_cut_down() {
        use nrr_storage::dto::ResolutionEntry;
        use nrr_storage::resolution_source::StorageResolutionSource;
        let store = confirmation_store();
        let wanted = Ipv4Addr::new(203, 0, 113, 1);
        let other = Ipv4Addr::new(203, 0, 113, 2);
        let stale = Ipv4Addr::new(203, 0, 113, 9);
        let v6: IpAddr = "2001:db8::7".parse().expect("v6");
        let now = SystemTime::now();
        let long_ago = now - Duration::from_secs(3_600);
        for (host, ips, at) in [
            ("z.cdn.example", vec![IpAddr::V4(wanted), v6], now),
            (
                "a.cdn.example",
                vec![IpAddr::V4(wanted), IpAddr::V4(other)],
                now,
            ),
            ("old.cdn.example", vec![IpAddr::V4(stale)], long_ago),
            ("m.cdn.example", vec![IpAddr::V4(other)], now),
        ] {
            store
                .upsert_resolution(ResolutionEntry {
                    canonical_hostname: host.into(),
                    raw_hostname_sample: None,
                    resolved_ips: ips,
                    ttl_seconds: Some(300),
                    source: StorageResolutionSource::Dns,
                    resolved_at: at,
                    active_revision_id: None,
                })
                .expect("upsert");
        }
        store
            .record_shared_ip_direct_host(wanted, "direct.example", 1, true)
            .expect("census");
        store
            .record_shared_ip_direct_host(wanted, "www.direct.example", 1, false)
            .expect("census");
        store
            .record_shared_ip_direct_host(other, "other.example", 1, false)
            .expect("census");
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let lookup = SqliteFqdnCacheLookup::new(cache, FreshnessThresholds::default_production())
            .with_confirmation_window(Duration::from_secs(600));
        let addresses = [
            IpAddr::V4(wanted),
            v6,
            IpAddr::V4(stale),
            IpAddr::V4(wanted),
        ];

        let expected = lookup
            .snapshot_for_compute()
            .expect("whole snapshot")
            .scoped_to(&addresses);
        let read = lookup
            .snapshot_for_addresses(&addresses)
            .expect("scoped read");

        assert_eq!(read.by_hostname, expected.by_hostname);
        assert_eq!(read.hostnames_by_recency, expected.hostnames_by_recency);
        assert_eq!(read.direct_host_counts, expected.direct_host_counts);
        assert_eq!(read.shared_direct, expected.shared_direct);
        assert_eq!(
            read.shared_direct_primary_ruled,
            expected.shared_direct_primary_ruled
        );
        assert!(
            read.ips_for_hostname("old.cdn.example").is_empty(),
            "an address past the confirmation window is not planned"
        );
    }

    const SUFFIX_LIMIT_FOR_TESTS: usize = 64;
}

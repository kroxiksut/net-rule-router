//! rule-hostname FQDN cache seeder.
//!
//! Both the route codegen and the WFP codegen fan a domain rule out to
//! IPs by reading the FQDN cache (`FqdnCacheLookup`). But nothing in the
//! live service ever *populates* that cache from the rules themselves —
//! the DNS refresh task only re-resolves rows that already exist, so a
//! brand-new domain rule's hostname would never enter the cache and would
//! produce zero routes/filters.
//!
//! This seeder closes that gap for every rule that names a **concrete**
//! hostname: it reads the active rule book, collects those hostnames,
//! resolves the ones not already cached via the DNS resolver, and upserts
//! the results so the next route/WFP recompute can fan them out.
//!
//! ## Scope and honest limits
//!
//! - **`ExactFqdn`** (`api.example.com`) — seeded here; works end-to-end.
//! - **`SuffixDomain`** (`*.example.com`) — only its **apex** (`example.com`)
//!   is seeded. Since  a suffix rule covers its apex, and the apex
//!   is the one host under the suffix that is known by name rather than by
//!   observation — without seeding it, `*.example.com` would produce no route
//!   for `example.com` on a cold cache, which is exactly the leak apex
//!   coverage exists to close. The open-ended set of *subdomains* still
//!   cannot be enumerated (there is no API that lists "every host under
//!   example.com"); those enter the cache via DNS observation or a matching
//!   `ExactFqdn` rule. A documented Free-tier limitation, not a bug.
//!   Plenty of such apexes (`ytimg.com`, `cdninstagram.com`, `musical.ly`) are
//!   zones that publish no address at all, so once the resolver has said so
//!   authoritatively often enough, the apex is parked for this rule book — the
//!   `*.x` rule's real job, the subdomains, is unaffected.
//! - **`Zone`** (`ru`, `intra`) — **NOT** seeded at all: a zone rule does not
//!   cover its bare label, so there is no concrete hostname to resolve.
//! - **`ExactIp`** needs no DNS and is unaffected.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort};
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::net_filter::{contains_fake_pool_addr, is_non_routable_v4};
use crate::per_sid_orchestrator::RulesProvider;

/// Outcome of one seed pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SeedSummary {
    /// Hostnames freshly resolved + upserted this pass.
    pub resolved: u32,
    /// Hostnames skipped because the cache already has IPs for them.
    pub already_cached: u32,
    /// Hostnames the resolver failed to resolve — a DNS *problem* (timeout,
    /// SERVFAIL, refused, unreachable upstream). Excludes the names confirmed
    /// to publish no address record at all; those are counted in
    /// [`Self::apex_absent`] instead.
    pub failed: u32,
    /// Suffix-rule apexes confirmed to have **no address record** and parked
    /// for the lifetime of this rule book (see [`RuleHostnameSeeder::apex_absent`]).
    ///
    /// A distinct, NON-error outcome: `ytimg.com` / `cdninstagram.com` and the
    /// rest of the CDN apex family exist as zones but were never meant to be
    /// addressable, so "no A record" is the correct, final answer rather than a
    /// resolver failure. Counting them as failures made them 2/3 of the DNS
    /// failure statistic and buried the real resolution problems.
    pub apex_absent: u32,
}

impl SeedSummary {
    pub fn made_progress(&self) -> bool {
        self.resolved > 0
    }
}

/// how many times a cold rule hostname is resolved per seed
/// pass, unioning all returned A-records. `3` captures a useful slice of a
/// rotating CDN's pool without hammering the resolver; later rotation is picked
/// up incrementally by the DNS refresh task.
const SEED_RESOLVE_ATTEMPTS: usize = 3;

/// First wait after a hostname fails to resolve, before it is tried again.
const SEED_RETRY_BACKOFF_MIN: Duration = Duration::from_secs(60);

/// Ceiling for the retry wait. A rule may legitimately name a host that has no
/// address at all (a bare apex used only as a suffix, a service that is gone);
/// re-checking such a name every few minutes costs a query and a log line for
/// nothing, and at a seed pass every couple of seconds it dominated both the
/// query load and the operational log. It still gets re-checked, just rarely.
const SEED_RETRY_BACKOFF_MAX: Duration = Duration::from_secs(30 * 60);

/// How many consecutive seed passes must come back *authoritatively* negative
/// before a suffix apex is parked as "has no address record".
///
/// The resolver port already tells us NXDOMAIN / NODATA apart from a transient
/// failure ([`DnsResolverError::is_authoritative`]), and that is the signal we
/// key on — but a single authoritative negative is not proof about the *name*:
/// a captive portal, a hijacking upstream, or our own kill-switch mid-transition
/// can all answer "no such name" for a name that exists. Requiring the same
/// verdict on `3` separate passes — each of which is itself
/// [`SEED_RESOLVE_ATTEMPTS`] queries, and which the retry backoff spaces
/// 60 s / 120 s / 240 s apart — costs at most ~3 minutes and 9 queries of
/// evidence before parking, while making a transient impostor answer
/// essentially unable to park a live name. Lower (`1`) trusts one bad moment;
/// higher buys nothing once the backoff has spread the samples across minutes.
const SEED_APEX_ABSENT_CONFIRMATIONS: u32 = 3;

/// Resolves the active rule book's `ExactFqdn` hostnames into the FQDN
/// cache so domain-rule fan-out has IPs to work with.
pub struct RuleHostnameSeeder {
    resolver: Arc<dyn DnsResolverPort>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    fqdn_lookup: Arc<dyn FqdnCacheLookup>,
    rules_provider: Arc<dyn RulesProvider>,
    /// hostnames already logged this seeder's lifetime for
    /// resolving only to loopback/unspecified (hosts-file pin). The seeder is
    /// constructed once and re-runs `seed_for_principal` on every hook tick,
    /// re-deriving the SAME cold hostname set each pass — without this the
    /// INFO line repeated every tick for as long as the pin held (HW: 704
    /// repeats for `musical.ly`). Cleared per hostname the moment it resolves
    /// to a routable address again, so a later re-pin logs again.
    loopback_warned: Mutex<HashSet<String>>,
    /// Per-hostname retry gate for names that failed to resolve: when the next
    /// attempt is due, and how long the wait after it will be. Without it every
    /// pass re-queried every unresolvable name, which on a real rule set meant
    /// thousands of pointless queries and log lines per hour. Cleared as soon
    /// as a name resolves.
    retry_after: Mutex<HashMap<String, (Instant, Duration)>>,
    ///  — consecutive authoritative negatives per suffix apex, and
    /// with them the set of apexes parked off the rotation entirely (count
    /// at or above [`SEED_APEX_ABSENT_CONFIRMATIONS`]).
    ///
    /// `ytimg.com`, `cdninstagram.com`, `twimg.com`, `musical.ly` and the rest
    /// of the CDN family are zones, not hosts: the apex publishes no A record
    /// and never will, so the 30-minute retry ceiling still meant a permanent
    /// trickle of queries and log lines, and made these names the bulk of the
    /// DNS failure statistic. Parking one is safe ONLY because a `*.x` rule is
    /// what put it here — subdomain coverage is untouched, and an apex with no
    /// address has nothing to enforce anyway.
    ///
    /// Process memory only, and deliberately so: this is an observation about
    /// the current rule book, not policy. Cleared when the derived hostname set
    /// changes in a way that concerns it (see `retire_stale_apex_parking`) and
    /// gone on service restart.
    apex_negatives: Mutex<HashMap<String, u32>>,
    /// Fingerprint of the derived `(hostname, covered-by-suffix)` set, per
    /// principal. A change means the rule book was reloaded and every parked
    /// apex must be re-verified; keyed per principal so alternating principals
    /// with different books do not reset each other every pass.
    previous_hostnames: Mutex<HashMap<String, BTreeMap<String, bool>>>,
    /// Serializes seed passes: `seed_for_principal` can be triggered from
    /// several places at once (periodic tick, rules-changed hooks), and
    /// overlapping passes resolved the same cold hostnames concurrently —
    /// multiplying upstream query load and racing the retry backoff. A pass
    /// that finds another one in flight returns immediately (the running pass
    /// covers the same derived hostname set; the next tick retries anyway).
    pass_gate: Mutex<()>,
}

impl RuleHostnameSeeder {
    pub fn new(
        resolver: Arc<dyn DnsResolverPort>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn_lookup: Arc<dyn FqdnCacheLookup>,
        rules_provider: Arc<dyn RulesProvider>,
    ) -> Self {
        Self {
            resolver,
            cache,
            fqdn_lookup,
            rules_provider,
            loopback_warned: Mutex::new(HashSet::new()),
            retry_after: Mutex::new(HashMap::new()),
            apex_negatives: Mutex::new(HashMap::new()),
            previous_hostnames: Mutex::new(HashMap::new()),
            pass_gate: Mutex::new(()),
        }
    }

    /// `true` while `host` is inside its post-failure wait.
    fn retry_suppressed(&self, host: &str) -> bool {
        let guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .get(host)
            .is_some_and(|(due, _)| Instant::now() < *due)
    }

    /// Record a failed resolution and schedule the next attempt, doubling the
    /// wait up to [`SEED_RETRY_BACKOFF_MAX`].
    ///
    /// A failure reported while the previous wait is STILL RUNNING does not
    /// escalate (and does not push the due time out): it comes from an attempt
    /// that started before the schedule existed — overlapping passes racing
    /// the same host — and carries no new information about the host. Without
    /// this, one burst of concurrent passes walked a host 60→1800 s in
    /// milliseconds (observed : ytimg.com banned for 30 minutes off
    /// six simultaneous boot-time failures, which YouTube then wore).
    fn note_resolve_failed(&self, host: &str) -> Duration {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let next_wait = match guard.get(host) {
            Some((due, wait)) if now < *due => return *wait,
            Some((_, wait)) => (*wait * 2).min(SEED_RETRY_BACKOFF_MAX),
            None => SEED_RETRY_BACKOFF_MIN,
        };
        guard.insert(host.to_string(), (now + next_wait, next_wait));
        next_wait
    }

    /// Record a Mode-B self-intercepted seed answer and schedule a FLAT
    /// re-check at the minimum wait. Never doubles (interception is a property
    /// of the resolver path, not of the host) and resets any escalated wait a
    /// real failure had accumulated.
    fn note_fake_intercepted(&self, host: &str) -> Duration {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(
            host.to_string(),
            (
                Instant::now() + SEED_RETRY_BACKOFF_MIN,
                SEED_RETRY_BACKOFF_MIN,
            ),
        );
        SEED_RETRY_BACKOFF_MIN
    }

    /// Drop `host`'s retry gate — it resolved, so the next failure starts the
    /// backoff from the minimum again.
    fn clear_resolve_failed(&self, host: &str) {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        guard.remove(host);
    }

    /// `true` once `host` has been confirmed to publish no address record and is
    /// parked off the rotation (see `apex_negatives`).
    fn apex_absent(&self, host: &str) -> bool {
        let guard = self
            .apex_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard
            .get(host)
            .is_some_and(|seen| *seen >= SEED_APEX_ABSENT_CONFIRMATIONS)
    }

    /// Record one authoritative negative for a suffix apex. Returns `true` when
    /// this observation reaches [`SEED_APEX_ABSENT_CONFIRMATIONS`] — i.e. the
    /// caller should park `host` and stop querying it.
    fn note_apex_negative(&self, host: &str) -> bool {
        let mut guard = self
            .apex_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let seen = guard.entry(host.to_string()).or_insert(0);
        *seen = seen.saturating_add(1);
        *seen >= SEED_APEX_ABSENT_CONFIRMATIONS
    }

    /// Forget `host`'s accumulated negatives — it answered with an address, so
    /// the evidence that it has none is void.
    fn clear_apex_negative(&self, host: &str) {
        let mut guard = self
            .apex_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(host);
    }

    /// Un-park the apexes this rule-book edit actually says something about.
    ///
    /// Parking is only safe because a `*.x` rule put the apex here, so it has to
    /// be reconsidered when the apex leaves the derived set or stops being
    /// suffix-covered. It says nothing about the OTHER parked apexes: the rule
    /// book changes constantly while auto-rules accept suggestions, and wiping
    /// the lot sent every parked CDN apex back through three confirmation passes
    /// — nine queries each — for an edit that never mentioned them.
    ///
    /// Diffing against the previous set (rather than a hash of it) is also what
    /// keeps this correct across principals: the parked map is keyed by host
    /// alone, and a host another SID parked is simply absent from this diff.
    fn retire_stale_apex_parking(&self, principal: &str, hostnames: &BTreeMap<String, bool>) {
        let mut guard = self
            .previous_hostnames
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let previous = guard.insert(principal.to_string(), hostnames.clone());
        let Some(previous) = previous else {
            return;
        };
        if previous == *hostnames {
            return;
        }
        drop(guard);
        let mut parked = self
            .apex_negatives
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        parked.retain(|host, _| {
            // Absent from `previous` means it is not this principal's to judge.
            !previous.contains_key(host) || hostnames.get(host) == Some(&true)
        });
    }

    /// Returns `true` the first time `host` is seen resolving only to
    /// loopback/unspecified addresses; `false` while it repeats. Paired with
    /// [`Self::clear_loopback_warn`], which re-arms the gate once `host`
    /// resolves to a routable address again.
    fn note_loopback_warn_once(&self, host: &str) -> bool {
        let mut guard = self
            .loopback_warned
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.insert(host.to_string())
    }

    /// Re-arm the loopback-warn gate for `host` (see
    /// [`Self::note_loopback_warn_once`]).
    fn clear_loopback_warn(&self, host: &str) {
        let mut guard = self
            .loopback_warned
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        guard.remove(host);
    }

    /// Resolve + upsert every not-yet-cached `ExactFqdn` hostname in
    /// `principal`'s effective rule book. Hostnames that already have
    /// cached IPs are skipped (the DNS refresh task keeps those warm).
    pub fn seed_for_principal(&self, principal: &str, now: SystemTime) -> SeedSummary {
        let mut summary = SeedSummary::default();
        // Another pass is already resolving this rule book — let it finish.
        // See `pass_gate`: overlapping passes multiplied query load and raced
        // the per-host retry backoff.
        let Ok(_pass) = self.pass_gate.try_lock() else {
            return summary;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(principal) else {
            return summary;
        };
        let mut hostnames: BTreeMap<String, bool> = BTreeMap::new();
        collect_rule_hostnames(&snapshot.rule_book.primary, &mut hostnames);
        collect_rule_hostnames(&snapshot.rule_book.secondary, &mut hostnames);
        // A reloaded rule book invalidates every "this apex has no address"
        // observation — the rules that made parking safe may have changed.
        self.retire_stale_apex_parking(principal, &hostnames);

        for (host, covered_by_suffix) in hostnames {
            // Already cached (any IPs present) → leave it to the DNS
            // refresh task to keep warm; don't re-resolve on every pass.
            if !self.fqdn_lookup.ips_for_hostname(&host).is_empty() {
                summary.already_cached = summary.already_cached.saturating_add(1);
                continue;
            }
            // Confirmed to publish no address record — off the rotation until
            // the rule book changes. Reported as its own outcome so it never
            // shows up as a DNS failure.
            if self.apex_absent(&host) {
                summary.apex_absent = summary.apex_absent.saturating_add(1);
                continue;
            }
            // Still inside the wait after a failed attempt — skip silently.
            if self.retry_suppressed(&host) {
                continue;
            }
            match self.resolve_union(&host) {
                Ok(SeedResolve {
                    record: Some(mut record),
                    ..
                }) => {
                    // Mode B self-interception: the OS resolver path is
                    // redirected to our own resolver, so this seed query got
                    // OUR fake-pool address back. No signal about the host —
                    // re-check on a FLAT minimum wait, never escalating (a
                    // healthy hostname must not walk the poisoned-host ladder
                    // because of its own virtual answer).
                    let fake_intercepted = contains_fake_pool_addr(&record.addresses);
                    // Drop non-routable IPs (loopback/unspecified). An
                    // ad-blocking hosts file may pin a rule's domain to
                    // 127.0.0.1 / 0.0.0.0; caching that would build a
                    // nonsensical /32 route out the secondary (VPN) link.
                    record.addresses.retain(|ip| !is_non_routable_v4(ip));
                    if record.addresses.is_empty() && fake_intercepted {
                        let wait = self.note_fake_intercepted(&host);
                        tracing::debug!(
                            target: "nrr::rule-seed",
                            hostname = %host,
                            retry_in_secs = wait.as_secs(),
                            "rule hostname answered from our own fake-IP pool (Mode B interception) — skipped without backoff escalation",
                        );
                        continue;
                    }
                    if record.addresses.is_empty() {
                        // A poisoned/pinned answer is as unusable as no answer,
                        // and it repeats on every pass until the hosts file or
                        // the upstream changes — so it rides the SAME per-host
                        // backoff as a failed resolve. Without this, a preset
                        // full of provider-poisoned hosts re-queried every pass
                        // and the retry chatter drowned the operational log
                        // (one 44-minute session kept only its last 9 minutes).
                        let wait = self.note_resolve_failed(&host);
                        if self.note_loopback_warn_once(&host) {
                            tracing::info!(
                                target: "nrr::rule-seed",
                                hostname = %host,
                                retry_in_secs = wait.as_secs(),
                                "rule hostname resolved only to loopback/unspecified (hosts file?) — not cached or routed",
                            );
                        } else {
                            tracing::debug!(
                                target: "nrr::rule-seed",
                                hostname = %host,
                                retry_in_secs = wait.as_secs(),
                                "rule hostname still resolving only to loopback/unspecified (deduped; already logged this session)",
                            );
                        }
                        continue;
                    }
                    self.clear_loopback_warn(&host);
                    self.clear_resolve_failed(&host);
                    self.clear_apex_negative(&host);
                    if self.upsert(record, now) {
                        summary.resolved = summary.resolved.saturating_add(1);
                    } else {
                        summary.failed = summary.failed.saturating_add(1);
                    }
                }
                Ok(SeedResolve {
                    record: None,
                    authoritative_negative,
                }) => {
                    // "This name has no address" — but only park it when a
                    // `*.x` rule is what named the apex, so the subdomains the
                    // rule really exists for stay covered. A bare `ExactFqdn`
                    // rule IS its hostname: parking that would silently kill
                    // the rule, so it keeps riding the (rare) retry ceiling.
                    if authoritative_negative && covered_by_suffix && self.note_apex_negative(&host)
                    {
                        summary.apex_absent = summary.apex_absent.saturating_add(1);
                        tracing::info!(
                            target: "nrr::rule-seed",
                            hostname = %host,
                            confirmations = SEED_APEX_ABSENT_CONFIRMATIONS,
                            "suffix-rule apex publishes no address record — parked until the rule book changes; subdomain coverage is unaffected",
                        );
                        continue;
                    }
                    let wait = self.note_resolve_failed(&host);
                    tracing::debug!(
                        target: "nrr::rule-seed",
                        hostname = %host,
                        retry_in_secs = wait.as_secs(),
                        "rule hostname did not resolve — backing off before the next attempt",
                    );
                    summary.failed = summary.failed.saturating_add(1);
                }
                Err(reason) => {
                    tracing::info!(
                        target: "nrr::rule-seed",
                        reason = %reason,
                        "DNS resolver unsupported; aborting rule-hostname seed pass",
                    );
                    break;
                }
            }
        }
        summary
    }

    /// resolve `host` up to [`SEED_RESOLVE_ATTEMPTS`] times
    /// and UNION every A-record returned, so a rotating / multi-A CDN (Facebook
    /// edge out of `157.240.0.0/16`, Cloudflare) seeds more of its address pool
    /// on the first (cold) pass instead of a single snapshot — the miss that let
    /// a `ping` to a not-yet-seeded edge IP leak past the kill-switch. Later
    /// rotation is still absorbed incrementally by the DNS refresh task (which
    /// unions through `upsert_resolution`). Returns:
    /// - `Ok(SeedResolve { record: Some(..), .. })` — at least one attempt
    ///   resolved; addresses unioned, TTL/hostname taken from the first success.
    /// - `Ok(SeedResolve { record: None, .. })` — no attempt yielded an address;
    ///   `authoritative_negative` says whether that was the name's own verdict.
    /// - `Err(reason)` — the resolver is unsupported on this platform; the caller
    ///   aborts the whole pass.
    fn resolve_union(&self, host: &str) -> Result<SeedResolve, String> {
        let mut merged: Option<nrr_platform_api::dns::ResolvedRecord> = None;
        let mut seen: BTreeSet<std::net::Ipv4Addr> = BTreeSet::new();
        // Downgraded by the first attempt that either answered or failed for a
        // reason other than the name itself — one timeout in the batch is
        // enough to make the batch inconclusive.
        let mut authoritative_negative = true;
        for _ in 0..SEED_RESOLVE_ATTEMPTS {
            match self.resolver.resolve_a(host) {
                Ok(record) => {
                    authoritative_negative = false;
                    match merged.as_mut() {
                        None => {
                            seen.extend(record.addresses.iter().copied());
                            merged = Some(record);
                        }
                        Some(m) => {
                            for ip in record.addresses {
                                if seen.insert(ip) {
                                    m.addresses.push(ip);
                                }
                            }
                        }
                    }
                }
                Err(DnsResolverError::UnsupportedPlatform { reason }) => {
                    return Err(reason.to_string())
                }
                // Transient failure on one attempt — keep whatever the other
                // attempts yielded (a rotating resolver often succeeds on a
                // retry). An NXDOMAIN / NODATA answer is not a failure of the
                // query but the answer to it, and is what lets the caller tell
                // "no such address record" from "could not ask right now".
                Err(e) => authoritative_negative &= e.is_authoritative(),
            }
        }
        Ok(SeedResolve {
            record: merged,
            authoritative_negative,
        })
    }

    fn upsert(&self, record: nrr_platform_api::dns::ResolvedRecord, now: SystemTime) -> bool {
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
                target: "nrr::rule-seed",
                error = %e,
                "upsert_resolution failed during rule-hostname seed",
            );
            return false;
        }
        true
    }
}

/// Outcome of one multi-attempt seed resolve (see
/// [`RuleHostnameSeeder::resolve_union`]).
struct SeedResolve {
    /// The unioned answer, when any attempt produced one.
    record: Option<nrr_platform_api::dns::ResolvedRecord>,
    /// Every attempt came back as an *authoritative* negative — NXDOMAIN or an
    /// empty answer, i.e. the name's own verdict rather than a transient
    /// failure. Meaningless when `record` is `Some`.
    authoritative_negative: bool,
}

/// The concrete hostnames the enabled rules of `set` name, accumulated into
/// `out` with a flag saying whether a **suffix** rule (`*.x`) covers each:
/// every `ExactFqdn` value, plus the apex of every `SuffixDomain` (a `*.x` rule
/// covers `x` itself). `Zone` values are excluded — the bare zone label is not
/// a host the rule covers.
///
/// The flag is what makes parking an address-less apex safe: it says the
/// subdomains under the name are still enforced without it.
fn collect_rule_hostnames(set: &CanonicalRuleSet, out: &mut BTreeMap<String, bool>) {
    for rule in set.rules().iter().filter(|r| r.enabled) {
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                out.entry(host.clone()).or_insert(false);
            }
            Some(CanonicalAddressMatch::SuffixDomain(host)) => {
                let covered = out.entry(host.clone()).or_insert(true);
                *covered = true;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleBook};
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use nrr_platform_api::dns::{MockDnsResolver, ResolvedRecord};
    use std::net::Ipv4Addr;

    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_storage::store::SqliteCacheStore;

    /// Build an in-memory cache store shared between the seeder's upsert
    /// path and the `SqliteFqdnCacheLookup` used for the "already cached?"
    /// check + test verification — exercises the real storage contract.
    #[allow(clippy::expect_used)]
    fn in_memory_cache() -> (
        Arc<Mutex<dyn CacheRepository + Send>>,
        Arc<crate::fqdn_cache_lookup::SqliteFqdnCacheLookup>,
    ) {
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use rusqlite::Connection;
        let conn = Connection::open_in_memory().expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let thresholds = FreshnessThresholds::default_production();
        let store = SqliteCacheStore::new(runner.into_connection(), thresholds.clone());
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let lookup = Arc::new(crate::fqdn_cache_lookup::SqliteFqdnCacheLookup::new(
            Arc::clone(&cache),
            thresholds,
        ));
        (cache, lookup)
    }

    struct FakeRules {
        secondary: Mutex<CanonicalRuleSet>,
        primary: Mutex<CanonicalRuleSet>,
    }
    impl FakeRules {
        fn new(primary: CanonicalRuleSet, secondary: CanonicalRuleSet) -> Self {
            Self {
                secondary: Mutex::new(secondary),
                primary: Mutex::new(primary),
            }
        }
        /// Swap the secondary set — stands in for a rule-book reload.
        #[allow(clippy::unwrap_used)]
        fn set_secondary(&self, set: CanonicalRuleSet) {
            *self.secondary.lock().unwrap() = set;
        }
    }
    impl RulesProvider for FakeRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            self.active_rules_for("__baseline__")
        }
        fn active_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: self.primary.lock().unwrap().clone(),
                    secondary: self.secondary.lock().unwrap().clone(),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn suffix_rule(id: &str, host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(host.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn fqdn_rule(id: &str, host: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn record(host: &str, ips: &[Ipv4Addr]) -> ResolvedRecord {
        ResolvedRecord {
            canonical_hostname: host.into(),
            addresses: ips.to_vec(),
            ttl_seconds: Some(300),
        }
    }

    fn empty() -> CanonicalRuleSet {
        CanonicalRuleSet::from_rules(vec![])
    }

    fn seeder(
        resolver: Arc<MockDnsResolver>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        lookup: Arc<crate::fqdn_cache_lookup::SqliteFqdnCacheLookup>,
        rules: Arc<FakeRules>,
    ) -> RuleHostnameSeeder {
        RuleHostnameSeeder::new(
            resolver as Arc<dyn DnsResolverPort>,
            cache,
            lookup as Arc<dyn FqdnCacheLookup>,
            rules as Arc<dyn RulesProvider>,
        )
    }

    fn pre_seed(cache: &Arc<Mutex<dyn CacheRepository + Send>>, host: &str, ip: Ipv4Addr) {
        cache
            .lock()
            .unwrap()
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: host.into(),
                raw_hostname_sample: None,
                resolved_ips: vec![ip],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("pre-seed");
    }

    #[test]
    fn seeds_uncached_exact_fqdn_hostnames() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "api.example.com",
            record("api.example.com", &[Ipv4Addr::new(1, 2, 3, 4)]),
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "api.example.com")]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 1);
        assert!(sum.made_progress());
        // The IP is now resolvable through the real cache.
        assert_eq!(
            lookup.ips_for_hostname("api.example.com"),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[test]
    fn skips_already_cached_hostnames_without_resolving() {
        let resolver = Arc::new(MockDnsResolver::new());
        let (cache, lookup) = in_memory_cache();
        pre_seed(&cache, "api.example.com", Ipv4Addr::new(9, 9, 9, 9));
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "api.example.com")]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.already_cached, 1);
        assert_eq!(sum.resolved, 0);
        assert!(
            resolver.observed_queries().is_empty(),
            "must not hit DNS for an already-cached host"
        );
    }

    #[test]
    fn seeds_the_suffix_apex_but_ignores_zone_and_ip_rules() {
        let resolver = Arc::new(MockDnsResolver::new());
        let (cache, lookup) = in_memory_cache();
        let zone = CanonicalRule {
            id: RuleId("r-zone".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone("ru".into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        let ip = CanonicalRule {
            id: RuleId("r-ip".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(8, 8, 8, 8))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![zone, ip]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(
            sum,
            SeedSummary::default(),
            "a zone label is not a host and an IP needs no DNS → nothing seeded"
        );
        assert!(resolver.observed_queries().is_empty());
    }

    #[test]
    fn suffix_rule_apex_is_seeded() {
        //  — `*.example.com` covers "example.com", and the apex is
        // the one host under the suffix that is known by name. Without seeding
        // it, a cold cache would produce no route for the apex.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "example.com",
            record("example.com", &[Ipv4Addr::new(203, 0, 113, 5)]),
        );
        let (cache, lookup) = in_memory_cache();
        let suffix = CanonicalRule {
            id: RuleId("r-suf".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain("example.com".into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        };
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![suffix]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 1);
        assert_eq!(
            lookup.ips_for_hostname("example.com"),
            vec![Ipv4Addr::new(203, 0, 113, 5)]
        );
    }

    #[test]
    fn loopback_only_resolution_is_not_seeded() {
        // An ad-blocking hosts file pins the rule's domain to 127.0.0.1.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "ad.example.com",
            record("ad.example.com", &[Ipv4Addr::new(127, 0, 0, 1)]),
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "ad.example.com")]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 0);
        assert_eq!(
            sum.failed, 0,
            "loopback-only is a benign skip, not a resolver failure"
        );
        assert!(lookup.ips_for_hostname("ad.example.com").is_empty());
    }

    #[test]
    fn fake_pool_answer_is_skipped_without_backoff_escalation() {
        // Mode B self-interception: the seed query got OUR OWN fake-pool
        // address back. Not cached, and — unlike a hosts-file pin or a real
        // resolve failure — the retry wait stays FLAT at the minimum
        // : rule hosts walked the 60→240 s ladder off their own
        // virtual answers while the fake-IP datapath was down).
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "tube.example.com",
            record("tube.example.com", &[Ipv4Addr::new(198, 18, 0, 60)]),
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "tube.example.com")]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 0);
        assert_eq!(
            sum.failed, 0,
            "a self-intercepted answer is a benign skip, not a failure"
        );
        assert!(lookup.ips_for_hostname("tube.example.com").is_empty());
        // The gate is armed (no immediate re-query)…
        assert!(s.retry_suppressed("tube.example.com"));
        // …and repeats never escalate; a real-failure ladder resets to the
        // minimum on interception (the host is alive, the path is not).
        assert_eq!(
            s.note_fake_intercepted("tube.example.com"),
            SEED_RETRY_BACKOFF_MIN
        );
        assert_eq!(
            s.note_fake_intercepted("tube.example.com"),
            SEED_RETRY_BACKOFF_MIN
        );
        assert_eq!(
            s.note_resolve_failed("dead.example.com"),
            SEED_RETRY_BACKOFF_MIN
        );
        assert_eq!(
            s.note_fake_intercepted("dead.example.com"),
            SEED_RETRY_BACKOFF_MIN,
            "interception resets an escalated wait back to the flat minimum"
        );
    }

    #[test]
    fn mixed_resolution_seeds_only_routable_ips() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "mix.example.com",
            record(
                "mix.example.com",
                &[Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(1, 2, 3, 4)],
            ),
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "mix.example.com")]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 1);
        // The unspecified address is dropped; only the public IP is cached.
        assert_eq!(
            lookup.ips_for_hostname("mix.example.com"),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[test]
    fn counts_resolver_failures() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "down.example.com",
            DnsResolverError::NxDomain {
                hostname: "down.example.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "down.example.com")]),
            empty(),
        ));
        let s = seeder(Arc::clone(&resolver), cache, Arc::clone(&lookup), rules);
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.failed, 1);
        assert_eq!(sum.resolved, 0);
        assert!(lookup.ips_for_hostname("down.example.com").is_empty());
    }

    #[test]
    fn a_failed_hostname_is_not_re_queried_on_the_next_pass() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "down.example.com",
            DnsResolverError::NxDomain {
                hostname: "down.example.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "down.example.com")]),
            empty(),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);

        let first = s.seed_for_principal("S-A", SystemTime::now());
        let queries_after_first = resolver.observed_queries().len();
        let second = s.seed_for_principal("S-A", SystemTime::now());

        assert_eq!(first.failed, 1);
        assert_eq!(
            second.failed, 0,
            "the second pass must skip the name instead of re-querying it"
        );
        assert_eq!(
            resolver.observed_queries().len(),
            queries_after_first,
            "no query may leave the seeder while the backoff holds"
        );

        // Clearing the gate (what a successful resolve does) re-arms querying.
        s.clear_resolve_failed("down.example.com");
        let third = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(third.failed, 1);
        assert!(resolver.observed_queries().len() > queries_after_first);
    }

    #[test]
    fn concurrent_failures_do_not_escalate_the_backoff() {
        let resolver = Arc::new(MockDnsResolver::new());
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(empty(), empty()));
        let s = seeder(resolver, cache, lookup, rules);

        // First failure starts the schedule at the minimum.
        let first = s.note_resolve_failed("racy.example.com");
        assert_eq!(first, SEED_RETRY_BACKOFF_MIN);
        // Failures reported while that wait is still running come from
        // attempts that started before the schedule existed (overlapping
        // passes racing one host); they must NOT double the wait.
        for _ in 0..5 {
            let repeat = s.note_resolve_failed("racy.example.com");
            assert_eq!(
                repeat, SEED_RETRY_BACKOFF_MIN,
                "a failure inside the running wait must not escalate"
            );
        }
    }

    #[test]
    fn note_loopback_warn_once_dedups_until_cleared() {
        let resolver = Arc::new(MockDnsResolver::new());
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(empty(), empty()));
        let s = seeder(resolver, cache, lookup, rules);
        assert!(
            s.note_loopback_warn_once("ad.example.com"),
            "first sighting logs"
        );
        assert!(
            !s.note_loopback_warn_once("ad.example.com"),
            "repeat sighting is deduped"
        );
        s.clear_loopback_warn("ad.example.com");
        assert!(
            s.note_loopback_warn_once("ad.example.com"),
            "cleared state re-arms the gate"
        );
    }

    /// Run `passes` seed passes back to back, clearing the per-host retry gate
    /// between them so the test does not have to wait out the real backoff.
    fn run_passes(s: &RuleHostnameSeeder, hosts: &[&str], passes: usize) -> SeedSummary {
        let mut last = SeedSummary::default();
        for _ in 0..passes {
            last = s.seed_for_principal("S-A", SystemTime::now());
            for host in hosts {
                s.clear_resolve_failed(host);
            }
        }
        last
    }

    #[test]
    fn an_address_less_suffix_apex_is_parked_and_not_counted_as_a_dns_failure() {
        // `*.ytimg.com` names an apex that is a zone, not a host: the resolver
        // answers authoritatively "no address record" forever. After
        // `SEED_APEX_ABSENT_CONFIRMATIONS` such passes the apex leaves the
        // rotation — no more queries, and no more DNS-failure counts.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "ytimg.com",
            DnsResolverError::NxDomain {
                hostname: "ytimg.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "ytimg.com")]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);

        let confirming = run_passes(
            &s,
            &["ytimg.com"],
            SEED_APEX_ABSENT_CONFIRMATIONS as usize - 1,
        );
        assert_eq!(confirming.failed, 1, "still inconclusive → a plain failure");
        assert_eq!(confirming.apex_absent, 0);
        assert!(!s.apex_absent("ytimg.com"));

        let parking = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(parking.apex_absent, 1);
        assert_eq!(
            parking.failed, 0,
            "a name with no address record is not a DNS failure"
        );
        assert!(s.apex_absent("ytimg.com"));

        // Parked: subsequent passes report the outcome without querying.
        let queries_at_parking = resolver.observed_queries().len();
        let after = run_passes(&s, &["ytimg.com"], 3);
        assert_eq!(after.apex_absent, 1);
        assert_eq!(after.failed, 0);
        assert_eq!(
            resolver.observed_queries().len(),
            queries_at_parking,
            "a parked apex must never be queried again"
        );
    }

    #[test]
    fn a_resolvable_apex_is_never_parked() {
        // The apex-is-addressable shape: the suffix apex resolves fine, so the
        // authoritative-negative evidence never accumulates and the apex keeps
        // being seeded exactly as before.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "live.example.com",
            record("live.example.com", &[Ipv4Addr::new(203, 0, 113, 7)]),
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![
                suffix_rule("r1", "live.example.com"),
                suffix_rule("r2", "dead.example.com"),
            ]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );

        let last = run_passes(
            &s,
            &["live.example.com", "dead.example.com"],
            SEED_APEX_ABSENT_CONFIRMATIONS as usize + 2,
        );
        assert!(
            !s.apex_absent("live.example.com"),
            "an apex that answers with an address must stay on the rotation"
        );
        assert!(s.apex_absent("dead.example.com"));
        assert_eq!(
            lookup.ips_for_hostname("live.example.com"),
            vec![Ipv4Addr::new(203, 0, 113, 7)]
        );
        assert_eq!(last.already_cached, 1, "the live apex stays warm in cache");
        assert_eq!(last.apex_absent, 1);
        assert_eq!(last.failed, 0);
    }

    #[test]
    fn an_apex_that_starts_answering_forgets_its_negatives() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "waking.example.com",
            DnsResolverError::NxDomain {
                hostname: "waking.example.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "waking.example.com")]),
        ));
        let s = seeder(
            Arc::clone(&resolver),
            Arc::clone(&cache),
            Arc::clone(&lookup),
            rules,
        );

        run_passes(
            &s,
            &["waking.example.com"],
            SEED_APEX_ABSENT_CONFIRMATIONS as usize - 1,
        );
        // The zone starts publishing an address before the threshold is met.
        resolver.set_response(
            "waking.example.com",
            record("waking.example.com", &[Ipv4Addr::new(198, 51, 100, 9)]),
        );
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 1);
        assert!(!s.apex_absent("waking.example.com"));
        assert_eq!(
            lookup.ips_for_hostname("waking.example.com"),
            vec![Ipv4Addr::new(198, 51, 100, 9)]
        );
    }

    #[test]
    fn transient_failures_never_park_an_apex() {
        // Timeout / SERVFAIL say nothing about the name — only the resolver's
        // authoritative verdict may take an apex off the rotation.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "slow.example.com",
            DnsResolverError::Timeout {
                hostname: "slow.example.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "slow.example.com")]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);

        let last = run_passes(
            &s,
            &["slow.example.com"],
            SEED_APEX_ABSENT_CONFIRMATIONS as usize + 2,
        );
        assert!(!s.apex_absent("slow.example.com"));
        assert_eq!(last.failed, 1, "still a real DNS failure");
        assert_eq!(last.apex_absent, 0);
    }

    #[test]
    fn an_exact_fqdn_rule_apex_is_never_parked() {
        // A bare `ExactFqdn` rule IS its hostname — parking it would silently
        // retire the rule, so it keeps riding the (30-minute) retry ceiling.
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "gone.example.com",
            DnsResolverError::NxDomain {
                hostname: "gone.example.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "gone.example.com")]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);

        let last = run_passes(
            &s,
            &["gone.example.com"],
            SEED_APEX_ABSENT_CONFIRMATIONS as usize + 2,
        );
        assert!(!s.apex_absent("gone.example.com"));
        assert_eq!(last.failed, 1);
        assert_eq!(last.apex_absent, 0);
    }

    /// Parks `ytimg.com` behind a `*.ytimg.com` rule and hands back the pieces.
    fn parked_apex_fixture() -> (Arc<MockDnsResolver>, Arc<FakeRules>, RuleHostnameSeeder) {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_error(
            "ytimg.com",
            DnsResolverError::NxDomain {
                hostname: "ytimg.com".into(),
            },
        );
        let (cache, lookup) = in_memory_cache();
        let rules = Arc::new(FakeRules::new(
            empty(),
            CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "ytimg.com")]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, Arc::clone(&rules));
        run_passes(&s, &["ytimg.com"], SEED_APEX_ABSENT_CONFIRMATIONS as usize);
        assert!(s.apex_absent("ytimg.com"));
        (resolver, rules, s)
    }

    /// Auto-rules rewrite the rule book every time the user accepts a
    /// suggestion. An edit that never mentions a parked apex must not send it
    /// back through three confirmation passes.
    #[test]
    fn an_unrelated_rule_edit_leaves_a_parked_apex_parked() {
        let (resolver, rules, s) = parked_apex_fixture();
        let asked_for = |host: &str| {
            resolver
                .observed_queries()
                .iter()
                .filter(|q| q.as_str() == host)
                .count()
        };
        let before = asked_for("ytimg.com");

        rules.set_secondary(CanonicalRuleSet::from_rules(vec![
            suffix_rule("r1", "ytimg.com"),
            fqdn_rule("r2", "api.example.com"),
        ]));
        let sum = s.seed_for_principal("S-A", SystemTime::now());

        assert!(s.apex_absent("ytimg.com"));
        assert_eq!(sum.apex_absent, 1);
        assert_eq!(
            asked_for("ytimg.com"),
            before,
            "an edit that never mentioned the apex must not re-query it"
        );
    }

    /// The reason parking is safe at all is the `*.x` rule. Take it away and the
    /// apex has to be re-verified, whatever else the edit did.
    #[test]
    fn losing_suffix_coverage_re_verifies_the_apex() {
        let (resolver, rules, s) = parked_apex_fixture();
        let queries_while_parked = resolver.observed_queries().len();

        // Same hostname, now named exactly rather than as a suffix.
        rules.set_secondary(CanonicalRuleSet::from_rules(vec![fqdn_rule(
            "r1",
            "ytimg.com",
        )]));
        let sum = s.seed_for_principal("S-A", SystemTime::now());

        assert!(!s.apex_absent("ytimg.com"));
        assert_eq!(sum.apex_absent, 0);
        assert!(
            resolver.observed_queries().len() > queries_while_parked,
            "an apex that lost its suffix rule must go back on the rotation"
        );
    }

    #[test]
    fn the_derived_hostname_set_tracks_suffix_coverage() {
        // `x` and `*.x` derive the same hostname, but only the second makes
        // parking safe — the derived set must tell them apart.
        let mut exact = BTreeMap::new();
        collect_rule_hostnames(
            &CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "example.com")]),
            &mut exact,
        );
        let mut suffix = BTreeMap::new();
        collect_rule_hostnames(
            &CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "example.com")]),
            &mut suffix,
        );
        assert_eq!(exact.get("example.com"), Some(&false));
        assert_eq!(suffix.get("example.com"), Some(&true));
        assert_ne!(exact, suffix, "the derived set must tell the two apart");
        // A suffix rule alongside an exact one still marks the host covered,
        // whichever order the sets are collected in.
        let mut both = BTreeMap::new();
        collect_rule_hostnames(
            &CanonicalRuleSet::from_rules(vec![
                fqdn_rule("r1", "example.com"),
                suffix_rule("r2", "example.com"),
            ]),
            &mut both,
        );
        assert_eq!(both.get("example.com"), Some(&true));
    }

    #[test]
    fn collects_from_both_routes_deduped() {
        let resolver = Arc::new(MockDnsResolver::new());
        resolver.set_response(
            "a.example.com",
            record("a.example.com", &[Ipv4Addr::new(1, 1, 1, 1)]),
        );
        resolver.set_response(
            "b.example.com",
            record("b.example.com", &[Ipv4Addr::new(2, 2, 2, 2)]),
        );
        let (cache, lookup) = in_memory_cache();
        // Same host in both routes → resolved once (deduped by BTreeSet).
        let rules = Arc::new(FakeRules::new(
            CanonicalRuleSet::from_rules(vec![fqdn_rule("p1", "a.example.com")]),
            CanonicalRuleSet::from_rules(vec![
                fqdn_rule("s1", "a.example.com"),
                fqdn_rule("s2", "b.example.com"),
            ]),
        ));
        let s = seeder(Arc::clone(&resolver), cache, lookup, rules);
        let sum = s.seed_for_principal("S-A", SystemTime::now());
        assert_eq!(sum.resolved, 2);
        let queries = resolver.observed_queries();
        // Deduped ACROSS routes: `a.example.com` is in both the primary and the
        // secondary set but is seeded once — so it is queried
        // `SEED_RESOLVE_ATTEMPTS` times (the HW-0707 union multi-resolve), NOT
        // `2 * SEED_RESOLVE_ATTEMPTS` (which is what a per-route double-seed
        // would produce).
        assert_eq!(
            queries
                .iter()
                .filter(|q| q.as_str() == "a.example.com")
                .count(),
            SEED_RESOLVE_ATTEMPTS
        );
    }
}

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
//!   Plenty of such apexes (`cdn.example`, `cdninsta.test`, `app.example`) are
//!   zones that publish no address at all, so once the resolver has said so
//!   authoritatively often enough, the apex is parked for this rule book — the
//!   `*.x` rule's real job, the subdomains, is unaffected.
//! - **`Zone`** (`ru`, `intra`) — **NOT** seeded at all: a zone rule does not
//!   cover its bare label, so there is no concrete hostname to resolve.
//! - **`ExactIp`** needs no DNS and is unaffected.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort};
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::net_filter::{contains_fake_pool_addr, is_non_routable};
use crate::per_sid_orchestrator::RulesProvider;
use nrr_platform_api::dns::AddressFamily;

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
    /// A distinct, NON-error outcome: `cdn.example` / `cdninsta.test` and the
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

/// Retry pacing while the leak guard is BLOCKING with the additional link
/// unresolved. A rule host with no known address has no protection at all in
/// that state — the guard can only block addresses it knows, so every second of
/// backoff is a second the rule is unenforced and the host reachable over the
/// main link. The pacing above is tuned for the calm case, where a name that
/// will not resolve costs a query for nothing; here the same patience is what
/// leaves the hole open, so the wait drops to seconds and stops escalating
/// early. Both revert the moment the link resolves.
const SEED_RETRY_BACKOFF_MIN_UNPROTECTED: Duration = Duration::from_secs(5);
const SEED_RETRY_BACKOFF_MAX_UNPROTECTED: Duration = Duration::from_secs(60);

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
    /// repeats for `app.example`). Cleared per hostname the moment it resolves
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
    /// `cdn.example`, `cdninsta.test`, `app.example` and the rest
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
    /// Whether the leak guard is blocking with the additional link unresolved.
    /// Drives the retry pacing (see [`SEED_RETRY_BACKOFF_MIN_UNPROTECTED`]).
    /// `None` (default) reports "not blocking" and keeps the calm pacing.
    leak_guard: Option<Arc<dyn crate::dns_resolver::LeakGuardPosture>>,
    /// Serializes seed passes. Overlapping passes resolved the same cold names
    /// concurrently, multiplying query load and racing the retry backoff; a
    /// pass that finds another in flight returns at once.
    pass_gate: Mutex<()>,
}

/// How long a recompute waits for the rule-host seed before going ahead with
/// what the cache already holds. Through a tunnel that times out every query
/// the wait was minutes, and every route change waited with it.
pub const SEED_WAIT_BUDGET: Duration = Duration::from_secs(2);

/// Whether [`RuleHostnameSeeder::seed_within`] finished before its caller moved on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedWait {
    Finished,
    /// Still resolving (or another pass was); a late success recomputes itself.
    Detached,
}

enum Handoff {
    Waiting,
    Abandoned,
    Done,
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
            leak_guard: None,
            retry_after: Mutex::new(HashMap::new()),
            apex_negatives: Mutex::new(HashMap::new()),
            previous_hostnames: Mutex::new(HashMap::new()),
            pass_gate: Mutex::new(()),
        }
    }

    /// Read the live leak-guard posture, so retry pacing tightens exactly while
    /// an unresolved rule host is also an unprotected one.
    #[must_use]
    pub fn with_leak_guard_posture(
        mut self,
        posture: Arc<dyn crate::dns_resolver::LeakGuardPosture>,
    ) -> Self {
        self.leak_guard = Some(posture);
        self
    }

    /// Is the guard blocking right now? A latch read; `false` when unwired.
    fn unprotected(&self) -> bool {
        self.leak_guard.as_ref().is_some_and(|g| g.blocking())
    }

    /// `true` while `host` is inside its post-failure wait.
    fn retry_suppressed(&self, host: &str) -> bool {
        let guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        let Some((due, wait)) = guard.get(host) else {
            return false;
        };
        // A wait scheduled while everything was calm can be minutes long, and
        // the guard usually arms in the middle of one (the tunnel drops, or the
        // link is not up yet at logon). Honouring it as scheduled would leave
        // the host unprotected for the rest of that wait, so an escalated wait
        // is re-read against the shorter ceiling rather than re-scheduled —
        // the entry keeps its own pacing for when the guard disarms.
        let capped = if self.unprotected() {
            (*wait).min(SEED_RETRY_BACKOFF_MAX_UNPROTECTED)
        } else {
            *wait
        };
        let effective_due = due.checked_sub(*wait - capped).unwrap_or(*due);
        Instant::now() < effective_due
    }

    /// Record a failed resolution and schedule the next attempt, doubling the
    /// wait up to [`SEED_RETRY_BACKOFF_MAX`].
    ///
    /// A failure reported while the previous wait is STILL RUNNING does not
    /// escalate (and does not push the due time out): it comes from an attempt
    /// that started before the schedule existed — overlapping passes racing
    /// the same host — and carries no new information about the host. Without
    /// this, one burst of concurrent passes walked a host 60→1800 s in
    /// milliseconds (observed : a delivery apex banned for 30 minutes off
    /// six simultaneous boot-time failures, which YouTube then wore).
    fn note_resolve_failed(&self, host: &str) -> Duration {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let (min_wait, max_wait) = if self.unprotected() {
            (
                SEED_RETRY_BACKOFF_MIN_UNPROTECTED,
                SEED_RETRY_BACKOFF_MAX_UNPROTECTED,
            )
        } else {
            (SEED_RETRY_BACKOFF_MIN, SEED_RETRY_BACKOFF_MAX)
        };
        let next_wait = match guard.get(host) {
            Some((due, wait)) if now < *due => return *wait,
            Some((_, wait)) => (*wait * 2).min(max_wait),
            None => min_wait,
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

    /// Schedule `host`'s retry gate as if the wait had started `elapsed` ago,
    /// so a test can observe a long wait mid-flight without sleeping.
    #[cfg(test)]
    fn schedule_retry_for_test(&self, host: &str, wait: Duration, elapsed: Duration) {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        let due = Instant::now() + (wait - elapsed);
        guard.insert(host.to_string(), (due, wait));
    }

    /// Let `host`'s current wait fall due without changing what it escalated
    /// to, so a test can walk the backoff without sleeping through it.
    #[cfg(test)]
    fn expire_retry_gate_for_test(&self, host: &str) {
        let mut guard = self.retry_after.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((due, _)) = guard.get_mut(host) {
            *due = Instant::now();
        }
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

    /// Seed `principals` on a worker thread, waiting at most `budget`.
    ///
    /// A pass that outlives the wait keeps going and calls `on_late_progress`
    /// when it resolved anything, so what it lands still reaches the routes.
    pub fn seed_within(
        self: &Arc<Self>,
        principals: Vec<String>,
        budget: Duration,
        on_late_progress: Arc<dyn Fn() + Send + Sync>,
    ) -> SeedWait {
        if principals.is_empty() {
            return SeedWait::Finished;
        }
        // Whoever holds the gate recomputes on its own progress; a second
        // worker would only return empty.
        if self.pass_gate.try_lock().is_err() {
            return SeedWait::Detached;
        }
        let handoff = Arc::new((Mutex::new(Handoff::Waiting), Condvar::new()));
        let worker = {
            let seeder = Arc::clone(self);
            let handoff = Arc::clone(&handoff);
            move || {
                let mut progressed = false;
                for sid in &principals {
                    let summary = seeder.seed_for_principal(sid, SystemTime::now());
                    if summary.made_progress() {
                        progressed = true;
                        tracing::info!(
                            target: "nrr::rule-seed",
                            sid = %sid,
                            resolved = summary.resolved,
                            "proactively seeded rule hostnames before recompute (leak-guard coverage)",
                        );
                    }
                }
                let (state, ready) = &*handoff;
                let mut guard = state.lock().unwrap_or_else(|p| p.into_inner());
                let abandoned = matches!(*guard, Handoff::Abandoned);
                *guard = Handoff::Done;
                drop(guard);
                ready.notify_one();
                if abandoned && progressed {
                    on_late_progress();
                }
            }
        };
        if let Err(e) = std::thread::Builder::new()
            .name("nrr-rule-seed".into())
            .spawn(worker)
        {
            tracing::warn!(
                target: "nrr::rule-seed",
                "could not start the rule-host seed worker — recomputing from the cache as it is: {e}",
            );
            return SeedWait::Detached;
        }
        let (state, ready) = &*handoff;
        let guard = state.lock().unwrap_or_else(|p| p.into_inner());
        let (mut guard, _) = ready
            .wait_timeout_while(guard, budget, |s| matches!(s, Handoff::Waiting))
            .unwrap_or_else(|p| p.into_inner());
        if matches!(*guard, Handoff::Done) {
            return SeedWait::Finished;
        }
        *guard = Handoff::Abandoned;
        tracing::info!(
            target: "nrr::rule-seed",
            budget_ms = budget.as_millis(),
            "rule-host seed is still resolving — routes recompute from the cache now, and again if the seed lands anything",
        );
        SeedWait::Detached
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
                    let fake_intercepted =
                        contains_fake_pool_addr(record.addresses.iter().copied());
                    // Drop non-routable IPs (loopback/unspecified). An
                    // ad-blocking hosts file may pin a rule's domain to
                    // 127.0.0.1 / 0.0.0.0; caching that would build a
                    // nonsensical /32 route out the secondary (VPN) link.
                    record.addresses.retain(|ip| !is_non_routable(ip));
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
        let mut seen: BTreeSet<std::net::IpAddr> = BTreeSet::new();
        // Downgraded by the first attempt that either answered or failed for a
        // reason other than the name itself — one timeout in the batch is
        // enough to make the batch inconclusive.
        let mut authoritative_negative = true;
        for _ in 0..SEED_RESOLVE_ATTEMPTS {
            match self.resolver.resolve(host, AddressFamily::Ipv4) {
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
mod tests;

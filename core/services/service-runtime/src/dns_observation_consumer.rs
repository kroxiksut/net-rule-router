//! DNS-observation consumer.
//!
//! Closes the suffix/zone gap. `ExactFqdn` rules are pre-seeded by
//! [`crate::rule_hostname_seeder`], but suffix/zone rules
//! (`*.example.com`, `.ru`) match an open-ended set of sub-hostnames that
//! cannot be enumerated. The only way to learn their IPs is to **observe**
//! the resolutions the machine makes.
//!
//! This consumer takes passively-observed resolutions (from the platform's
//! [`DnsObservationSource`](nrr_platform_api::dns_observe::DnsObservationSource)),
//! keeps the ones whose hostname matches an **active rule** (suffix, zone,
//! or exact) for the routing-active user, and writes them to the FQDN
//! cache. The existing route/WFP codegen then fans those cached hosts out
//! into routes/filters. Observations that match no rule are discarded — the
//! cache only grows for hostnames a rule actually cares about (bounded;
//! avoids caching every site the user visits).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
use nrr_domain::decision_matching::{match_suffix_domain, match_zone};
use nrr_domain::rule_specificity::match_specificity;
use nrr_platform_api::dns::{DnsCacheReadPort, NoopDnsCacheRead};
use nrr_platform_api::dns_observe::DnsObservation;
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::repository::CacheRepository;
use nrr_storage::resolution_source::StorageResolutionSource;

use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::net_filter::{contains_fake_pool_addr, is_non_routable_v4};
use crate::per_sid_orchestrator::RulesProvider;

/// Returns the routing-active SID (Free single-active-user), or `None`.
pub type ActiveSidFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Outcome of consuming a batch of observations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeSummary {
    /// Observations whose hostname matched an active rule and were cached.
    pub matched: u32,
    /// Observations discarded (no matching rule).
    pub ignored: u32,
    /// newly-detected collateral cases this
    /// batch: a direct (non-secondary) host resolving to an IP already routed
    /// to the secondary/VPN link by a secondary rule. Counts post-dedup, so a
    /// re-observed pair does not re-increment.
    pub collateral: u32,
}

impl ConsumeSummary {
    pub fn made_progress(&self) -> bool {
        self.matched > 0
    }
}

/// Matches observed resolutions against the active user's rules and caches
/// the ones that match.
pub struct DnsObservationConsumer {
    rules_provider: Arc<dyn RulesProvider>,
    cache: Arc<Mutex<dyn CacheRepository + Send>>,
    /// Read-only reverse port used by the collateral detector to learn which
    /// IPs the secondary rules currently resolve to. Shares the same FQDN
    /// cache the codegen reads, so it sees exactly the IPs that become `/32`
    /// routes out the secondary link.
    fqdn_lookup: Arc<dyn FqdnCacheLookup>,
    active_sid: ActiveSidFn,
    /// Dedup keys (`"{direct_host}|{ip}"`) for collateral warnings already
    /// emitted this process lifetime, so the periodic observe tick does not
    /// re-warn the same victim/IP pair every few seconds.
    collateral_warned: Mutex<HashSet<String>>,
    /// OS resolver-cache reader used by [`seed_from_os_cache`]. Reads
    /// what the OS already resolved (hosts served from its cache never hit the
    /// wire, so the ETW observer misses them) and seeds the rule-matching ones.
    /// Defaults to [`NoopDnsCacheRead`] (returns empty) so the seed is inert
    /// until a backend is wired in via [`with_dns_cache_read`].
    ///
    /// [`seed_from_os_cache`]: DnsObservationConsumer::seed_from_os_cache
    /// [`with_dns_cache_read`]: DnsObservationConsumer::with_dns_cache_read
    dns_cache_read: Arc<dyn DnsCacheReadPort>,
    /// known-direct registry
    /// [`learn_reverse_confirmed_direct`] feeds. `None` (default) disables
    /// direct-learning (the strict block-all posture).
    ///
    /// [`learn_reverse_confirmed_direct`]: DnsObservationConsumer::learn_reverse_confirmed_direct
    known_direct: Option<Arc<crate::known_direct::KnownDirectRegistry>>,
    /// True while the fake-IP relay stack is live. When it is, a collateral
    /// direct host is actively steered/rescued onto the primary by name, so the
    /// "shares its IP with a secondary rule" WARN is no longer describing a
    /// real problem — it is downgraded to a debug line to stop the log churn.
    /// The census tenant recording still runs (it feeds the shared-IP heuristic
    /// that also protects the non-fake path). Default: always false — warn as
    /// before until a gate is wired in.
    fake_ip_running: Arc<dyn Fn() -> bool + Send + Sync>,
    ///  — "is the secondary currently able to carry traffic?" The
    /// production wiring reads the SAME usability source of truth the
    /// conn-observe live-secondary drop counter uses: the route coordinator's
    /// gated resolve must yield a secondary interface AND no fail-closed
    /// block-all may be armed. While the secondary is UNUSABLE a shared-IP
    /// collateral must not be described as "egresses the secondary link" —
    /// nothing is pinned to a link that cannot carry traffic; the direct host
    /// stays on the primary and the event is logged as "pin skipped" instead.
    /// Default: always `true` — historic behaviour until a gate is wired in.
    secondary_usable: Arc<dyn Fn() -> bool + Send + Sync>,
    /// `(hostname, ip)` pairs already reverse-confirmed recently. A CDN host
    /// under a blocked burst re-confirms the same (or rotating) addresses many
    /// times a minute; each acceptance re-writes the same cache row, re-emits
    /// the info line, and re-arms a reconcile for facts the table already
    /// holds (0725 run 9: one host re-confirmed 120 times in 11 minutes, the
    /// dominant source of the ~1 Hz recompute churn). Entries expire after
    /// [`REVERSE_CONFIRM_MEMO_TTL`], so a still-active address refreshes its
    /// `last_seen` at a bounded cadence instead of per drop.
    reverse_confirm_memo: Mutex<HashMap<(String, Ipv4Addr), SystemTime>>,
    ///  — companion-domain learner. The observations this consumer
    /// DISCARDS are precisely the interesting ones: a hostname matching no rule,
    /// seen while a routed site is active, is a candidate to be that site's
    /// missing CDN. Feeding the learner here costs one hash insert per
    /// observation on a drain that already runs, so no new provider, no new
    /// tick, and nothing on the connection path. `None` (default) disables the
    /// feature entirely.
    auto_rules: Option<Arc<crate::auto_rules::AutoRulesEngine>>,
    /// Hosts already dropped from the shared-IP census this process lifetime,
    /// so the purge runs once per host rather than on every observe tick.
    census_purged: Mutex<HashSet<String>>,
}

/// How long a reverse-confirmed `(hostname, ip)` pair suppresses identical
/// re-confirmations. Long enough to collapse a blocked burst into one cache
/// write, short enough that `last_seen` ordering stays honest.
const REVERSE_CONFIRM_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Hard bound on the memo map. On overflow the whole memo is dropped (the
/// cost is one redundant cache write per pair, not correctness).
const REVERSE_CONFIRM_MEMO_MAX: usize = 8192;

impl DnsObservationConsumer {
    pub fn new(
        rules_provider: Arc<dyn RulesProvider>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn_lookup: Arc<dyn FqdnCacheLookup>,
        active_sid: ActiveSidFn,
    ) -> Self {
        Self {
            rules_provider,
            cache,
            fqdn_lookup,
            active_sid,
            collateral_warned: Mutex::new(HashSet::new()),
            dns_cache_read: Arc::new(NoopDnsCacheRead),
            known_direct: None,
            fake_ip_running: Arc::new(|| false),
            secondary_usable: Arc::new(|| true),
            reverse_confirm_memo: Mutex::new(HashMap::new()),
            auto_rules: None,
            census_purged: Mutex::new(HashSet::new()),
        }
    }

    ///  — inject the companion-domain learner so this consumer's
    /// observations also feed companion discovery. Builder-style; without it the
    /// feature is inert and `consume` behaves exactly as before.
    #[must_use]
    pub fn with_auto_rules(mut self, engine: Arc<crate::auto_rules::AutoRulesEngine>) -> Self {
        self.auto_rules = Some(engine);
        self
    }

    ///  — inject the "secondary is usable" gate (see the field doc).
    /// While it reports `false`, a newly-detected collateral pair is logged as
    /// "pin skipped — secondary unusable" (info) instead of the WARN that
    /// claims the direct host egresses the secondary link. Detection, the
    /// summary count, and the shared-IP census recording are unaffected.
    /// Builder-style; existing call sites and tests keep the always-usable
    /// default.
    pub fn with_secondary_usable_gate(mut self, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.secondary_usable = gate;
        self
    }

    /// Block D (fake-IP) — inject the "relay stack is live" gate so the
    /// collateral WARN is silenced (downgraded to debug) while fake-IP is
    /// actively steering those hosts onto the primary. Builder-style; existing
    /// call sites and tests keep the warn-always default.
    pub fn with_fake_ip_gate(mut self, gate: Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        self.fake_ip_running = gate;
        self
    }

    /// inject the known-direct registry so
    /// [`learn_reverse_confirmed_direct`] can register positively-direct
    /// destinations for block-all exemptions. Builder-style.
    ///
    /// [`learn_reverse_confirmed_direct`]: DnsObservationConsumer::learn_reverse_confirmed_direct
    pub fn with_known_direct_registry(
        mut self,
        registry: Arc<crate::known_direct::KnownDirectRegistry>,
    ) -> Self {
        self.known_direct = Some(registry);
        self
    }

    /// inject the OS resolver-cache reader that [`seed_from_os_cache`]
    /// uses (Windows `WindowsDnsCacheRead`, Linux `LinuxDnsCacheRead`, or the
    /// `NoopDnsCacheRead` default). Builder-style so existing call sites and
    /// tests are unaffected.
    ///
    /// [`seed_from_os_cache`]: DnsObservationConsumer::seed_from_os_cache
    pub fn with_dns_cache_read(mut self, reader: Arc<dyn DnsCacheReadPort>) -> Self {
        self.dns_cache_read = reader;
        self
    }

    /// Consume a batch of observations: cache the ones matching an active
    /// rule, discard the rest. No active user / no rules → nothing matches.
    pub fn consume(&self, observations: &[DnsObservation], now: SystemTime) -> ConsumeSummary {
        let mut summary = ConsumeSummary::default();
        if observations.is_empty() {
            return summary;
        }
        let Some(sid) = (self.active_sid)() else {
            // No routing-active user → nothing to enforce.
            summary.ignored = observations.len() as u32;
            return summary;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            summary.ignored = observations.len() as u32;
            return summary;
        };

        // Built lazily (only when a non-secondary host appears) and once per
        // batch — maps every IPv4 a secondary rule currently routes out the
        // secondary link → the rule host that owns it.
        let mut secondary_owners: Option<HashMap<Ipv4Addr, String>> = None;
        //  — secondary usability, read lazily (the gated resolve
        // enumerates adapters) and at most once per batch, mirroring how the
        // conn-observe consumer reads its egress context once per batch.
        let mut secondary_usable_memo: Option<bool> = None;
        //  — open the companion-learning batch ONCE for the whole
        // drain. The engine's mutex is taken here rather than per observation,
        // and a principal whose `auto_rules_mode` is `off` yields `None` so the
        // loop below does no learning work at all.
        let mut learning = self
            .auto_rules
            .as_ref()
            .and_then(|engine| engine.begin_batch(&sid));
        let batch_ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        for obs in observations {
            if obs.ipv4s.is_empty() {
                continue;
            }
            // Drop non-routable IPs (loopback/unspecified) before anything
            // else touches this observation. An ad-blocking hosts file pins
            // ad/tracker domains to 127.0.0.1 / 0.0.0.0; such a mapping must
            // never enter the FQDN cache, become a /32 route, or be flagged
            // as collateral (real logs: `musical.ly → 127.0.0.1`). If nothing
            // routable remains the ADDRESS is inert; whether the observation
            // itself still means something is decided just below.
            let routable: Vec<Ipv4Addr> = obs
                .ipv4s
                .iter()
                .copied()
                .filter(|ip| !is_non_routable_v4(ip))
                .collect();
            if routable.is_empty() {
                // Two very different reasons the address list can vanish, and
                // they must not be conflated. Under Mode B our own resolver
                // answers a rule host with a fake-pool address, so the ONLY
                // thing missing is a real address — the resolution itself is
                // genuine evidence that the user is on that site. Discarding it
                // silently starved companion learning of every anchor (observed
                // : 24 minutes of Mode B, zero anchors). A real
                // loopback/unspecified pin carries no such meaning: an
                // ad-blocking hosts file made it up, so it must keep going
                // nowhere — not into the cache, not into a route, and never
                // into a suggestion.
                if contains_fake_pool_addr(&obs.ipv4s) {
                    // Name-only learning: no address is passed on, so nothing
                    // virtual can reach the cache, a /32, or the census. The
                    // rule match runs only when a principal actually collects
                    // (`learning` is `None` when the mode is off), so this costs
                    // nothing on the default path.
                    if let Some(batch) = learning.as_mut() {
                        let in_secondary =
                            rule_set_matches(&obs.hostname, &snapshot.rule_book.secondary);
                        let in_primary =
                            rule_set_matches(&obs.hostname, &snapshot.rule_book.primary);
                        batch.observe(
                            batch_ms,
                            &obs.hostname,
                            crate::auto_rules::AutoRulesEngine::classify(in_primary, in_secondary),
                        );
                    }
                    tracing::debug!(
                        target: "nrr::dns-observe",
                        hostname = %obs.hostname,
                        "observed hostname answered from our own fake-IP pool (Mode B interception) — no real address to cache or route",
                    );
                } else {
                    tracing::debug!(
                        target: "nrr::dns-observe",
                        hostname = %obs.hostname,
                        "observed hostname pinned to loopback/unspecified (hosts file?) — not cached or routed",
                    );
                }
                continue;
            }
            let in_secondary = rule_set_matches(&obs.hostname, &snapshot.rule_book.secondary);
            let in_primary = rule_set_matches(&obs.hostname, &snapshot.rule_book.primary);
            // Feed companion learning BEFORE the keep/discard branch below: a
            // hostname that matches no rule is discarded from the cache by
            // design, and those discarded names are exactly the ones a routed
            // site may be missing. Reuses the two match results just computed,
            // so learning adds no matching work. Hosts pinned to loopback by an
            // ad-blocking hosts file never reach here (the `routable` filter
            // above already dropped them) and so can never be suggested.
            if let Some(batch) = learning.as_mut() {
                batch.observe(
                    batch_ms,
                    &obs.hostname,
                    crate::auto_rules::AutoRulesEngine::classify(in_primary, in_secondary),
                );
            }
            if in_primary || in_secondary {
                if self.upsert(&obs.hostname, &routable, now, StorageResolutionSource::Dns) {
                    summary.matched = summary.matched.saturating_add(1);
                }
            } else {
                summary.ignored = summary.ignored.saturating_add(1);
            }
            // Collateral: a host that should egress the PRIMARY link (matches
            // a primary rule, or no rule at all) yet resolves to an IP a
            // SECONDARY rule already routes out the secondary/VPN link. The
            // secondary rule's `/32` is more specific than our primary
            // counter-overlay, so this host silently rides the secondary
            // route — IP-level routing cannot separate two hostnames sharing
            // one IP. Pure-secondary hosts are skipped (they belong there).
            if !in_secondary {
                let owners = secondary_owners.get_or_insert_with(|| {
                    build_secondary_ip_owners(
                        &snapshot.rule_book.secondary,
                        self.fqdn_lookup.as_ref(),
                    )
                });
                for ip in &routable {
                    let Some(owner) = owners.get(ip) else {
                        continue;
                    };
                    if owner == &obs.hostname {
                        continue;
                    }
                    // record this direct (non-secondary) host
                    // as a co-tenant of the shared IP so the shared-IP policy can
                    // count `direct_on_ip`. Idempotent upsert; done every
                    // observation (refreshes recency), independent of the
                    // once-per-lifetime WARN dedup below.
                    //
                    // A tenant a MAIN-route rule claims is recorded as such:
                    // pinning its address to the additional route cannot divert
                    // it there, because the user's own rule sends it the other
                    // way — the two orders cancel and the host dies instead.
                    let primary_ruled =
                        match_specificity(&obs.hostname, &snapshot.rule_book.primary).is_some();
                    self.record_direct_tenant(&obs.hostname, *ip, now, primary_ruled);
                    if self.note_collateral_once(&obs.hostname, *ip) {
                        summary.collateral = summary.collateral.saturating_add(1);
                        //  — while the secondary is UNUSABLE
                        // (unresolved / probe-dead / block-all armed) the
                        // shared IP is NOT pinned to it: the compile side skips
                        // the pin (see `secondary_ip_policy` + the orchestrator
                        // exemption sets), so the direct host stays on the
                        // primary link. Say so at info instead of warning that
                        // it "egresses the secondary" — during the
                        // run that WARN described a pin onto a dead link while
                        // the host was actually being blocked to death.
                        let secondary_usable =
                            *secondary_usable_memo.get_or_insert_with(|| (self.secondary_usable)());
                        if !secondary_usable {
                            tracing::info!(
                                target: "nrr::dns-observe",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral pin skipped — secondary unusable: the shared IP is not pinned to a link that cannot carry traffic, so this direct host stays on the primary; the pin re-arms on the next observation/reconcile once the secondary recovers",
                            );
                        }
                        // While fake-IP is live the collateral is being steered
                        // onto the primary by name (a virtual address), so the
                        // shared IP no longer forces this host out the secondary
                        // link — downgrade the WARN to a debug line.
                        else if (self.fake_ip_running)() {
                            tracing::debug!(
                                target: "nrr::dns-observe",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral shared IP detected, but fake-IP is live and steers this host onto the primary by name — no action needed",
                            );
                        } else {
                            tracing::warn!(
                                target: "nrr::dns-observe",
                                direct_host = %obs.hostname,
                                shared_ip = %ip,
                                secondary_rule_host = %owner,
                                "collateral: a direct host shares its IP with a secondary rule, so it egresses the secondary (VPN) link, not the primary. IP routing cannot separate two hostnames on one IP — narrow the secondary rule or use per-host routing.",
                            );
                        }
                    }
                }
            }
        }
        summary
    }

    /// `true` the first time a `(direct_host, ip)` collateral pair is seen,
    /// `false` on repeats — the observe tick re-sees the same resolutions
    /// every few seconds, so this keeps the WARN to one line per pair.
    fn note_collateral_once(&self, direct_host: &str, ip: Ipv4Addr) -> bool {
        self.collateral_warned
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(format!("{direct_host}|{ip}"))
    }

    fn is_pending_companion(&self, hostname: &str) -> bool {
        self.auto_rules
            .as_ref()
            .is_some_and(|e| e.covers_pending_secondary_host(hostname))
    }

    /// Drop `hostname` from the shared-IP census, once per process. The
    /// once-only guard is not an optimisation: this runs on the observe tick,
    /// which sees the same host every few seconds while a page is open.
    fn forget_direct_tenant(&self, hostname: &str) {
        {
            let Ok(mut purged) = self.census_purged.lock() else {
                return;
            };
            if !purged.insert(hostname.to_ascii_lowercase()) {
                return;
            }
        }
        let Ok(guard) = self.cache.lock() else {
            return;
        };
        match guard.forget_shared_ip_direct_host(hostname) {
            Ok(0) => {}
            Ok(rows) => tracing::info!(
                target: "nrr::dns-observe",
                host = %hostname,
                rows,
                "host is a parked suggestion for the additional route — dropped it from the shared-IP census so its addresses stay pinned there",
            ),
            Err(e) => tracing::debug!(
                target: "nrr::dns-observe",
                error = %e,
                "shared-IP census purge failed (heuristic only)",
            ),
        }
    }

    /// persist a `(direct_host, shared_ip)` observation to the
    /// shared-IP census so the codegen's shared-IP policy can count
    /// `direct_on_ip`. Best-effort: a census write failure never blocks the
    /// observe path (it only weakens the heuristic, never routing correctness).
    fn record_direct_tenant(
        &self,
        direct_host: &str,
        ip: Ipv4Addr,
        now: SystemTime,
        primary_ruled: bool,
    ) {
        // A host already parked as a suggestion for the additional route is NOT
        // a direct tenant, whatever it looks like from here: we suspect it is
        // part of a site the user routes there. Counting it as one marks its
        // addresses "shared" and the smart kill-switch then exempts them from
        // pinning, so the host takes the default route — the CDN of a routed
        // site loading over the primary, which is the page that "opens but has
        // no pictures". Rows written before the suggestion existed are dropped
        // once, here, rather than left to age out.
        if self.is_pending_companion(direct_host) {
            self.forget_direct_tenant(direct_host);
            return;
        }
        let now_ms = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Err(e) = guard.record_shared_ip_direct_host(ip, direct_host, now_ms, primary_ruled) {
            tracing::debug!(
                target: "nrr::dns-observe",
                error = %e,
                "record shared-IP direct-host census failed (heuristic only)",
            );
        }
    }

    fn upsert(
        &self,
        hostname: &str,
        ips: &[Ipv4Addr],
        now: SystemTime,
        source: StorageResolutionSource,
    ) -> bool {
        let entry = ResolutionEntry {
            canonical_hostname: hostname.to_string(),
            raw_hostname_sample: None,
            resolved_ips: ips.to_vec(),
            ttl_seconds: None,
            source,
            resolved_at: now,
            active_revision_id: None,
        };
        let guard = match self.cache.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        if let Err(e) = guard.upsert_resolution(entry) {
            tracing::warn!(
                target: "nrr::dns-observe",
                error = %e,
                "upsert_resolution failed for observed hostname",
            );
            return false;
        }
        true
    }

    /// seed the FQDN cache from the OS resolver cache.
    ///
    /// Reads what the OS has already resolved (via the injected
    /// [`DnsCacheReadPort`]) and caches the rule-matching hosts with source
    /// [`StorageResolutionSource::OsCacheSeed`]. This closes the observability
    /// gap where a rule host (e.g. a `.ru` zone member) was resolved *before*
    /// the service started, or served straight from the OS cache so no wire
    /// query fired and the ETW observer never saw it — leaving its zone permit
    /// uncompiled and the host blocked under a catch-all.
    ///
    /// Same keep-logic as [`consume`](Self::consume): active-SID gate,
    /// active-rules match (primary OR secondary), and the `is_non_routable_v4`
    /// filter (an ad-blocked `127.0.0.1` pin in the OS cache must never become a
    /// `/32`). Collateral detection is intentionally NOT run here — that is a
    /// property of live observation, not of a cache snapshot. Best-effort: a
    /// read error is logged at debug and yields an empty summary.
    pub fn seed_from_os_cache(&self, now: SystemTime) -> ConsumeSummary {
        let mut summary = ConsumeSummary::default();
        let Some(sid) = (self.active_sid)() else {
            return summary;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return summary;
        };
        let entries = match self.dns_cache_read.read_resolver_cache() {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(
                    target: "nrr::dns-observe",
                    error = ?e,
                    "OS resolver-cache read failed — skipping seed this tick",
                );
                return summary;
            }
        };
        for entry in entries {
            let routable: Vec<Ipv4Addr> = entry
                .addresses
                .iter()
                .copied()
                .filter(|ip| !is_non_routable_v4(ip))
                .collect();
            if routable.is_empty() {
                continue;
            }
            let matches = rule_set_matches(&entry.canonical_hostname, &snapshot.rule_book.primary)
                || rule_set_matches(&entry.canonical_hostname, &snapshot.rule_book.secondary);
            if !matches {
                summary.ignored = summary.ignored.saturating_add(1);
                continue;
            }
            if self.upsert(
                &entry.canonical_hostname,
                &routable,
                now,
                StorageResolutionSource::OsCacheSeed,
            ) {
                summary.matched = summary.matched.saturating_add(1);
            }
        }
        if summary.matched > 0 {
            tracing::info!(
                target: "nrr::dns-observe",
                matched = summary.matched,
                ignored = summary.ignored,
                "seeded FQDN cache from OS resolver cache (rule-matching hosts the observer missed)",
            );
        }
        summary
    }

    /// cache an FCrDNS-confirmed
    /// `(hostname, addresses)` fact learned from an NRR block drop. Same keep-logic
    /// as [`seed_from_os_cache`](Self::seed_from_os_cache): active-SID gate,
    /// active-rules match (primary OR secondary), `is_non_routable_v4` filter —
    /// but recorded with source [`StorageResolutionSource::ReverseConfirmed`] so
    /// diagnostics distinguish it. Returns `true` iff the host matched a rule and
    /// was cached (the [`crate::fcrdns_learner::ConfirmedHostSink`] contract). The
    /// caller has ALREADY forward-confirmed the name against the dropped IP; this
    /// only applies the rule gate + upsert.
    pub fn learn_reverse_confirmed(
        &self,
        hostname: &str,
        addresses: &[Ipv4Addr],
        now: SystemTime,
    ) -> bool {
        let Some(sid) = (self.active_sid)() else {
            return false;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return false;
        };
        let routable: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !is_non_routable_v4(ip))
            .collect();
        if routable.is_empty() {
            return false;
        }
        let in_primary = rule_set_matches(hostname, &snapshot.rule_book.primary);
        let in_secondary = rule_set_matches(hostname, &snapshot.rule_book.secondary);
        if !in_primary && !in_secondary {
            return false;
        }
        // A name the user routes over the PRIMARY, found on an address the
        // kill-switch has pinned to the secondary, is the shared-IP census's
        // subject — it just arrived by reverse lookup instead of by watching a
        // query. Without this the census can only learn from resolutions we
        // saw, so a browser on DoH keeps the address pinned and keeps getting
        // blocked: exactly the "google.com is in my primary rules and still
        // will not open" report. A suffix rule (`*.google.com`) has no address
        // of its own to seed, which is why the drop is the only evidence there
        // will ever be.
        if in_primary && !in_secondary {
            // Reaching here means a main-route rule claims this host, which is
            // exactly what `primary_ruled` records.
            for ip in &routable {
                self.record_direct_tenant(hostname, *ip, now, true);
            }
        }
        // Memo gate: only pairs not confirmed within the TTL survive. Without
        // this a blocked burst re-learns the same facts per drop and each
        // acceptance re-arms a reconcile.
        let novel = self.note_reverse_confirmed(hostname, &routable, now);
        if novel.is_empty() {
            return false;
        }
        let kept = self.upsert(
            hostname,
            &novel,
            now,
            StorageResolutionSource::ReverseConfirmed,
        );
        if kept {
            tracing::info!(
                target: "nrr::dns-observe",
                hostname = %hostname,
                addresses = novel.len(),
                "cached a reverse-confirmed rule host learned from an NRR drop (browser-cache/DoH blind spot)",
            );
        }
        kept
    }

    /// Filter `addresses` down to the pairs not seen within
    /// [`REVERSE_CONFIRM_MEMO_TTL`], recording the survivors at `now`. Expired
    /// entries are pruned on the way; a memo past
    /// [`REVERSE_CONFIRM_MEMO_MAX`] is dropped wholesale rather than managed.
    fn note_reverse_confirmed(
        &self,
        hostname: &str,
        addresses: &[Ipv4Addr],
        now: SystemTime,
    ) -> Vec<Ipv4Addr> {
        let mut memo = self
            .reverse_confirm_memo
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        memo.retain(|_, seen_at| {
            now.duration_since(*seen_at)
                .map_or(true, |age| age < REVERSE_CONFIRM_MEMO_TTL)
        });
        if memo.len() > REVERSE_CONFIRM_MEMO_MAX {
            memo.clear();
        }
        // After the retain pass every surviving entry is fresh, so a present
        // key means "confirmed within the TTL" — only absent keys are novel.
        addresses
            .iter()
            .copied()
            .filter(|ip| memo.insert((hostname.to_string(), *ip), now).is_none())
            .collect()
    }

    /// register an FCrDNS-confirmed `(hostname, addresses)`
    /// fact whose name matches NO active rule as a known-DIRECT destination.
    /// The inverse gate of [`learn_reverse_confirmed`](Self::learn_reverse_confirmed):
    /// same active-SID + routable filters, but the host must match NEITHER rule
    /// set — a rule match here means the rule path should have kept it, so the
    /// direct claim is refused. Feeds the known-direct registry (NOT the FQDN
    /// cache — the cache is rule-matching by design); the block-all exemption
    /// compiles on the next reconcile. Returns `true` iff at least one new
    /// address was registered.
    pub fn learn_reverse_confirmed_direct(&self, hostname: &str, addresses: &[Ipv4Addr]) -> bool {
        let Some(registry) = self.known_direct.as_ref() else {
            return false;
        };
        let Some(sid) = (self.active_sid)() else {
            return false;
        };
        let Some(snapshot) = self.rules_provider.active_rules_for(&sid) else {
            return false;
        };
        if rule_set_matches(hostname, &snapshot.rule_book.primary)
            || rule_set_matches(hostname, &snapshot.rule_book.secondary)
        {
            return false;
        }
        let routable: Vec<Ipv4Addr> = addresses
            .iter()
            .copied()
            .filter(|ip| !is_non_routable_v4(ip))
            .collect();
        if routable.is_empty() {
            return false;
        }
        let added = registry.register(&routable);
        if added > 0 {
            tracing::info!(
                target: "nrr::dns-observe",
                hostname = %hostname,
                addresses = added,
                "registered a reverse-confirmed DIRECT host from an NRR drop — block-all exemption compiles on the next reconcile",
            );
        }
        added > 0
    }
}

/// Build a map of every IPv4 currently routed out the secondary link by an
/// enabled secondary rule → the rule host (or literal IP) that owns it.
/// Mirrors how [`crate::route_codegen::generate_secondary_routes`] fans rules
/// out to `/32`s, but yields the source name so a collateral hit can be
/// attributed to a specific rule. Reads the same FQDN cache the codegen does.
/// `pub(crate)`: the conn-trace handler reuses this map to stamp
/// `expected_route` on trace rows (decision-vs-actual-egress mismatch flag).
pub(crate) fn build_secondary_ip_owners(
    secondary: &CanonicalRuleSet,
    fqdn: &dyn FqdnCacheLookup,
) -> HashMap<Ipv4Addr, String> {
    /// Cap suffix/zone fan-out to match the codegen's bound.
    const SUFFIX_FANOUT_LIMIT: usize = 1024;
    let mut owners: HashMap<Ipv4Addr, String> = HashMap::new();
    for rule in secondary.rules().iter().filter(|r| r.enabled) {
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                owners.entry(*ip).or_insert_with(|| ip.to_string());
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                for ip in fqdn.ips_for_hostname(host) {
                    owners.entry(ip).or_insert_with(|| host.clone());
                }
            }
            // The apex belongs to a `*.suffix` rule but not to a zone — mirror
            // the codegen split so `expected_route` attribution matches what
            // was actually enforced.
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                claim_hosts(
                    &fqdn.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_LIMIT),
                    fqdn,
                    &mut owners,
                );
            }
            Some(CanonicalAddressMatch::Zone(zone)) => {
                claim_hosts(
                    &fqdn.hostnames_under_suffix(zone, SUFFIX_FANOUT_LIMIT),
                    fqdn,
                    &mut owners,
                );
            }
            _ => {}
        }
    }
    owners
}

/// Attribute every cached IP of `hosts` to the first host that claims it.
fn claim_hosts(
    hosts: &[String],
    fqdn: &dyn FqdnCacheLookup,
    owners: &mut HashMap<Ipv4Addr, String>,
) {
    for host in hosts {
        for ip in fqdn.ips_for_hostname(host) {
            owners.entry(ip).or_insert_with(|| host.clone());
        }
    }
}

/// `true` when `hostname` matches an enabled rule in `set` (exact FQDN, or a
/// suffix/zone match). Reused by the resolver's `RuleHostOracle`
/// (block 16.HW-0708 Mode B) so name→rule matching has a single source of truth.
pub(crate) fn rule_set_matches(hostname: &str, set: &CanonicalRuleSet) -> bool {
    set.rules()
        .iter()
        .filter(|r| r.enabled)
        .any(|r| match &r.address_match {
            Some(CanonicalAddressMatch::ExactFqdn(h)) => h == hostname,
            // `*.s` covers the apex `s` and every subdomain; a zone rule covers
            // subdomains only. Both helpers live in `nrr-domain` so this gate
            // and the decision engine can never disagree.
            Some(CanonicalAddressMatch::SuffixDomain(s)) => match_suffix_domain(hostname, s),
            Some(CanonicalAddressMatch::Zone(z)) => match_zone(hostname, z),
            _ => false,
        })
}

/// the KIND of the strongest enabled address rule covering
/// `(hostname, ip)`, walked along the runtime priority ladder (exact-fqdn >
/// subdomain > zone > exact-ip). `SuffixDomain` and `Zone` share match
/// semantics but are reported distinctly: the cache viewer sorts zone-derived
/// entries below direct rule matches. `None` when no address rule matches
/// (app-only rules carry no address match by definition).
pub(crate) fn rule_set_match_kind(
    hostname: &str,
    ip: Option<std::net::Ipv4Addr>,
    set: &CanonicalRuleSet,
) -> Option<&'static str> {
    let mut best: Option<(u8, &'static str)> = None;
    let mut consider = |tier: u8, kind: &'static str| {
        if best.is_none_or(|(t, _)| tier < t) {
            best = Some((tier, kind));
        }
    };
    for rule in set.rules().iter().filter(|r| r.enabled) {
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactFqdn(h)) if h == hostname => {
                consider(0, "exact-fqdn");
            }
            Some(CanonicalAddressMatch::SuffixDomain(s)) if match_suffix_domain(hostname, s) => {
                consider(1, "subdomain");
            }
            Some(CanonicalAddressMatch::Zone(z)) if match_zone(hostname, z) => {
                consider(2, "zone");
            }
            Some(CanonicalAddressMatch::ExactIp(rule_ip)) if ip == Some(*rule_ip) => {
                consider(3, "exact-ip");
            }
            _ => {}
        }
    }
    best.map(|(_, kind)| kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleBook};
    use nrr_domain::{RouteBehaviorMode, RuleId};
    use std::net::Ipv4Addr;

    use crate::fqdn_cache_lookup::{FqdnCacheLookup, MockFqdnCacheLookup, SqliteFqdnCacheLookup};
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;

    #[allow(clippy::expect_used)]
    fn in_memory_cache() -> (
        Arc<Mutex<dyn CacheRepository + Send>>,
        Arc<SqliteFqdnCacheLookup>,
    ) {
        use nrr_domain::decision_lookup::FreshnessThresholds;
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        use nrr_storage::store::SqliteCacheStore;
        use rusqlite::Connection;
        let conn = Connection::open_in_memory().expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let thresholds = FreshnessThresholds::default_production();
        let store = SqliteCacheStore::new(runner.into_connection(), thresholds.clone());
        let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
        let lookup = Arc::new(SqliteFqdnCacheLookup::new(Arc::clone(&cache), thresholds));
        (cache, lookup)
    }

    struct FakeRules {
        primary: CanonicalRuleSet,
        secondary: CanonicalRuleSet,
    }
    impl RulesProvider for FakeRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            self.active_rules_for("__baseline__")
        }
        fn active_rules_for(&self, _p: &str) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: self.primary.clone(),
                    secondary: self.secondary.clone(),
                },
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn suffix_rule(id: &str, s: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(s.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn zone_rule(id: &str, z: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(z.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn active_sid(sid: &'static str) -> ActiveSidFn {
        Arc::new(move || Some(sid.to_string()))
    }

    fn obs(host: &str, ip: [u8; 4]) -> DnsObservation {
        DnsObservation {
            hostname: host.into(),
            ipv4s: vec![Ipv4Addr::from(ip)],
        }
    }

    fn exact_fqdn_rule(id: &str, h: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(h.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn consumer(
        secondary: Vec<CanonicalRule>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        sid: ActiveSidFn,
    ) -> DnsObservationConsumer {
        consumer_with_primary(Vec::new(), secondary, cache, fqdn, sid)
    }

    fn consumer_with_primary(
        primary: Vec<CanonicalRule>,
        secondary: Vec<CanonicalRule>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn: Arc<dyn FqdnCacheLookup>,
        sid: ActiveSidFn,
    ) -> DnsObservationConsumer {
        DnsObservationConsumer::new(
            Arc::new(FakeRules {
                primary: CanonicalRuleSet::from_rules(primary),
                secondary: CanonicalRuleSet::from_rules(secondary),
            }) as Arc<dyn RulesProvider>,
            cache,
            fqdn,
            sid,
        )
    }

    ///  — a consumer wired to a live companion-learning engine over
    /// the SAME rule book, so the observation feed can be checked end to end
    /// (what the engine learned is only observable through its proposals).
    fn consumer_with_learning(
        secondary: Vec<CanonicalRule>,
        cache: Arc<Mutex<dyn CacheRepository + Send>>,
        fqdn: Arc<dyn FqdnCacheLookup>,
    ) -> (
        DnsObservationConsumer,
        Arc<crate::auto_rules::AutoRulesEngine>,
    ) {
        use crate::auto_rules::{
            AutoRulesEngine, AutoRulesModeFn, DismissalStore, InMemoryDismissalStore,
            InMemoryPendingStore,
        };
        use nrr_storage::auto_rules::AutoRulesMode;
        let rules = Arc::new(FakeRules {
            primary: CanonicalRuleSet::from_rules(vec![]),
            secondary: CanonicalRuleSet::from_rules(secondary),
        });
        let mode: AutoRulesModeFn = Arc::new(|_: &str| AutoRulesMode::Suggest);
        let engine = Arc::new(AutoRulesEngine::new(
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            mode,
            Arc::new(InMemoryDismissalStore::new()) as Arc<dyn DismissalStore>,
            Arc::new(InMemoryPendingStore::new()),
            SystemTime::UNIX_EPOCH,
        ));
        let consumer = DnsObservationConsumer::new(
            rules as Arc<dyn RulesProvider>,
            cache,
            fqdn,
            active_sid("S-A"),
        )
        .with_auto_rules(Arc::clone(&engine));
        (consumer, engine)
    }

    fn at_ms(ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(ms)
    }

    #[test]
    fn fake_pool_answers_still_anchor_companion_learning() {
        // Under Mode B our own resolver answers every rule host with a fake-pool
        // address, so the rule host's observation carries no real IP. It must
        // still reach the learner — that observation is the ANCHOR which opens
        // the co-activity window, and without it nothing is ever proposed (real
        // run: 24 minutes of Mode B, zero anchors). The virtual address itself
        // still goes nowhere: caching it would build a bogus /32.
        let (cache, lookup) = in_memory_cache();
        let (c, engine) = consumer_with_learning(
            vec![exact_fqdn_rule("r1", "site.example")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        );
        // Two visits — the minimum distinct-window evidence the learner accepts.
        for visit in [0_u64, 100_000] {
            let sum = c.consume(
                &[
                    obs("site.example", [198, 18, 0, 7]),
                    obs("cdn.example", [93, 184, 216, 34]),
                ],
                at_ms(visit),
            );
            assert_eq!(sum.matched, 0, "a fake-pool address is never cached");
        }
        assert!(
            lookup.ips_for_hostname("site.example").is_empty(),
            "the virtual address must never enter the cache or become a /32"
        );

        let summary = engine.tick("S-A", at_ms(150_000));
        assert_eq!(
            summary.parked, 1,
            "the fake-pool answer must have anchored the window"
        );
        let candidates = engine.candidates("S-A");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].anchor, "site.example");
        assert_eq!(candidates[0].proposed_match, "cdn.example");
    }

    #[test]
    fn loopback_pinned_hosts_never_anchor_companion_learning() {
        // The inverse guard: a loopback/unspecified pin is fabricated by an
        // ad-blocking hosts file, not by us. It must keep going nowhere — the
        // cache, a route, and now also the learner, where it would anchor a
        // visit the user never made and drag companions onto that rule's route.
        let (cache, lookup) = in_memory_cache();
        let (c, engine) = consumer_with_learning(
            vec![
                exact_fqdn_rule("r1", "site.example"),
                exact_fqdn_rule("r2", "other.example"),
            ],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        );
        for visit in [0_u64, 100_000] {
            let sum = c.consume(
                &[
                    obs("site.example", [127, 0, 0, 1]),
                    obs("other.example", [0, 0, 0, 0]),
                    obs("cdn.example", [93, 184, 216, 34]),
                ],
                at_ms(visit),
            );
            assert_eq!(sum.matched, 0, "a pinned host is never cached");
        }
        assert!(lookup.ips_for_hostname("site.example").is_empty());
        assert!(lookup.ips_for_hostname("other.example").is_empty());

        let summary = engine.tick("S-A", at_ms(150_000));
        assert_eq!(summary.parked, 0);
        assert!(
            engine.candidates("S-A").is_empty(),
            "a hosts-file pin must not open a co-activity window"
        );
    }

    #[test]
    fn caches_subdomain_matching_a_suffix_rule() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        // cdn-17.example.com is an unknowable subdomain — only observation
        // reveals it. It matches `*.example.com`.
        let sum = c.consume(
            &[obs("cdn-17.example.com", [93, 184, 216, 34])],
            SystemTime::now(),
        );
        assert_eq!(sum.matched, 1);
        assert!(sum.made_progress());
        assert_eq!(
            lookup.ips_for_hostname("cdn-17.example.com"),
            vec![Ipv4Addr::new(93, 184, 216, 34)]
        );
        // And the suffix fan-out now finds it.
        assert_eq!(
            lookup.hostnames_under_suffix("example.com", 16),
            vec!["cdn-17.example.com".to_string()]
        );
    }

    #[test]
    fn seed_from_os_cache_caches_rule_matches_skips_others_and_loopback() {
        use nrr_platform_api::dns::{MockDnsCacheRead, OsCachedResolution};
        let (cache, lookup) = in_memory_cache();
        let reader = Arc::new(MockDnsCacheRead::new());
        reader.set_entries(vec![
            // Matches the `.ru` zone rule → seeded.
            OsCachedResolution {
                canonical_hostname: "avito.ru".into(),
                addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
            },
            // No rule → ignored.
            OsCachedResolution {
                canonical_hostname: "google.com".into(),
                addresses: vec![Ipv4Addr::new(8, 8, 8, 8)],
            },
            // Matches the zone name but is an ad-block loopback pin → dropped
            // before it can become a /32 (mirrors the observe path).
            OsCachedResolution {
                canonical_hostname: "ads.ru".into(),
                addresses: vec![Ipv4Addr::new(127, 0, 0, 1)],
            },
        ]);
        let c = consumer(
            vec![zone_rule("r1", "ru")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        )
        .with_dns_cache_read(reader);

        let sum = c.seed_from_os_cache(SystemTime::now());
        assert_eq!(
            sum.matched, 1,
            "only avito.ru is a rule match with a routable IP"
        );
        assert_eq!(sum.ignored, 1, "google.com matched no rule");
        assert_eq!(
            lookup.ips_for_hostname("avito.ru"),
            vec![Ipv4Addr::new(1, 2, 3, 4)]
        );
        assert!(lookup.ips_for_hostname("google.com").is_empty());
        assert!(
            lookup.ips_for_hostname("ads.ru").is_empty(),
            "loopback pin must never enter the cache"
        );
        // The zone fan-out now sees the seeded host.
        assert_eq!(
            lookup.hostnames_under_suffix("ru", 16),
            vec!["avito.ru".to_string()]
        );
    }

    #[test]
    fn seed_from_os_cache_noop_reader_caches_nothing() {
        let (cache, lookup) = in_memory_cache();
        // Default reader is NoopDnsCacheRead (empty snapshot).
        let c = consumer(
            vec![zone_rule("r1", "ru")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        let sum = c.seed_from_os_cache(SystemTime::now());
        assert_eq!(sum.matched, 0);
        assert_eq!(sum.ignored, 0);
    }

    #[test]
    fn caches_host_matching_a_zone_rule() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![zone_rule("r1", "ru")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        let sum = c.consume(&[obs("site.example.ru", [5, 5, 5, 5])], SystemTime::now());
        assert_eq!(sum.matched, 1);
        assert_eq!(
            lookup.ips_for_hostname("site.example.ru"),
            vec![Ipv4Addr::new(5, 5, 5, 5)]
        );
    }

    #[test]
    fn ignores_host_matching_no_rule() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        let sum = c.consume(&[obs("unrelated.org", [1, 1, 1, 1])], SystemTime::now());
        assert_eq!(sum.matched, 0);
        assert_eq!(sum.ignored, 1);
        assert!(lookup.ips_for_hostname("unrelated.org").is_empty());
    }

    #[test]
    fn apex_matches_suffix_rule() {
        //  — `*.example.com` covers the apex `example.com`, so the
        // observer must cache it like any other rule host. (A `Zone` rule still
        // excludes its own bare label — see `match_zone`.)
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        let sum = c.consume(&[obs("example.com", [2, 2, 2, 2])], SystemTime::now());
        assert_eq!(sum.matched, 1);
        assert!(!lookup.ips_for_hostname("example.com").is_empty());
    }

    #[test]
    fn no_active_user_caches_nothing() {
        let (cache, lookup) = in_memory_cache();
        let none_sid: ActiveSidFn = Arc::new(|| None);
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            none_sid,
        );
        let sum = c.consume(&[obs("a.example.com", [1, 2, 3, 4])], SystemTime::now());
        assert_eq!(sum.matched, 0);
        assert_eq!(sum.ignored, 1);
        assert!(lookup.ips_for_hostname("a.example.com").is_empty());
    }

    #[test]
    fn secondary_ip_owners_maps_ips_to_their_rule_host() {
        let fqdn = MockFqdnCacheLookup::new();
        fqdn.set_ips("openai.com", vec![Ipv4Addr::new(1, 2, 3, 4)]);
        fqdn.set_ips("cdn.example.com", vec![Ipv4Addr::new(9, 9, 9, 9)]);
        let secondary = CanonicalRuleSet::from_rules(vec![
            exact_fqdn_rule("r1", "openai.com"),
            suffix_rule("r2", "example.com"),
        ]);
        let owners = build_secondary_ip_owners(&secondary, &fqdn);
        assert_eq!(
            owners.get(&Ipv4Addr::new(1, 2, 3, 4)).map(String::as_str),
            Some("openai.com")
        );
        assert_eq!(
            owners.get(&Ipv4Addr::new(9, 9, 9, 9)).map(String::as_str),
            Some("cdn.example.com")
        );
    }

    #[test]
    fn detects_collateral_when_direct_host_shares_a_secondary_ip() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        // A secondary host resolves and is cached (→ /32 out the secondary adapter).
        let s1 = c.consume(&[obs("cdn.example.com", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s1.matched, 1);
        assert_eq!(s1.collateral, 0);
        // A DIRECT host (matches no secondary rule) resolves to the SAME IP →
        // collateral: it silently rides the secondary /32 out the secondary adapter. This is
        // exactly the "2ip.ru shows the VPN address" case (2ip.ru is a primary
        // .ru host; here we use an unmatched host, same `!in_secondary` path).
        let s2 = c.consume(&[obs("victim.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s2.ignored, 1);
        assert_eq!(s2.collateral, 1);
        // Re-observing the same pair is deduped (one WARN per pair).
        let s3 = c.consume(&[obs("victim.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s3.collateral, 0);
        // A direct host on a different, unclaimed IP is not collateral.
        let s4 = c.consume(&[obs("clean.org", [10, 0, 0, 1])], SystemTime::now());
        assert_eq!(s4.collateral, 0);
    }

    #[test]
    fn collateral_with_unusable_secondary_still_counts_and_records_census() {
        //  — while the secondary is unusable the collateral event is
        // logged as "pin skipped" (info) instead of the "egresses the
        // secondary" WARN, but detection, the summary count, the dedup, and
        // the shared-IP census recording are all unchanged — the census is
        // exactly what keeps the shared IP exemptible under the block-all.
        use std::sync::atomic::{AtomicBool, Ordering};
        let (cache, lookup) = in_memory_cache();
        let usable = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&usable);
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        )
        .with_secondary_usable_gate(Arc::new(move || gate.load(Ordering::Relaxed)));
        // A secondary rule host resolves → its IP becomes secondary-owned.
        let s1 = c.consume(&[obs("cdn.example.com", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s1.matched, 1);
        // A direct host shares the IP while the secondary is UNUSABLE.
        let s2 = c.consume(&[obs("victim.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s2.collateral, 1, "detection still counts under the gate");
        {
            let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                guard
                    .direct_host_count_for_ip(Ipv4Addr::new(9, 9, 9, 9))
                    .unwrap_or(0)
                    >= 1,
                "census tenant recording must survive the gate"
            );
        }
        // Repeats stay deduped exactly as before.
        let s3 = c.consume(&[obs("victim.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s3.collateral, 0);
        // Recovery: with the secondary usable again a NEW collateral pair
        // takes the historic WARN path and is counted identically.
        usable.store(true, Ordering::Relaxed);
        let s4 = c.consume(&[obs("victim2.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s4.collateral, 1);
    }

    /// A host a MAIN-route rule claims keeps its census seat however wide that
    /// rule is, and is marked as main-route-claimed. Dropping it — the "narrower
    /// claim wins" posture — re-pinned the Google front-end addresses shared by
    /// `*.google.com` and a named `aistudio.google.com`, and search died in
    /// every browser: the pin cannot divert a host the user routed the other
    /// way, it can only cut it.
    #[test]
    fn a_host_claimed_by_a_wide_main_route_rule_stays_a_census_tenant() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer_with_primary(
            vec![suffix_rule("p1", "google.com")],
            vec![exact_fqdn_rule("s1", "aistudio.google.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        // The named secondary rule resolves → the address is secondary-owned.
        assert_eq!(
            c.consume(
                &[obs("aistudio.google.com", [9, 9, 9, 9])],
                SystemTime::now()
            )
            .matched,
            1
        );
        // A neighbour on the same address, held only by the wide primary rule.
        c.consume(
            &[obs("workspace.google.com", [9, 9, 9, 9])],
            SystemTime::now(),
        );
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            guard
                .direct_host_count_for_ip(Ipv4Addr::new(9, 9, 9, 9))
                .unwrap_or(0)
                >= 1,
            "a main-route-claimed host keeps its census seat"
        );
        assert!(
            guard
                .shared_ip_census_primary_ruled_ips()
                .unwrap_or_default()
                .contains(&Ipv4Addr::new(9, 9, 9, 9)),
            "and the address is flagged as main-route-claimed, so fail-closed spares it"
        );
    }

    /// The flag is per tenant, not per address: a bystander with no rule of its
    /// own marks the address shared but never main-route-claimed, so a
    /// fail-closed block still covers it (it rides the tunnel as collateral
    /// rather than dying).
    #[test]
    fn an_unclaimed_bystander_does_not_flag_the_address_main_route_claimed() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer_with_primary(
            Vec::new(),
            vec![exact_fqdn_rule("s1", "chatgpt.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        assert_eq!(
            c.consume(&[obs("chatgpt.com", [9, 9, 9, 9])], SystemTime::now())
                .matched,
            1
        );
        c.consume(
            &[obs("a.nel.cloudflare.com", [9, 9, 9, 9])],
            SystemTime::now(),
        );
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            guard
                .shared_ip_census_primary_ruled_ips()
                .unwrap_or_default()
                .is_empty(),
            "no main-route rule claims the bystander, so the leak hole stays shut"
        );
    }

    /// The other side of the same rule: a bystander with no rule of its own
    /// keeps its say. Letting one named secondary rule overrule every unclaimed
    /// neighbour would drag unrelated hosts into the tunnel, which is the whole
    /// thing the shared-IP census exists to prevent.
    #[test]
    fn a_neighbour_with_no_rule_of_its_own_stays_a_census_tenant() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer_with_primary(
            Vec::new(),
            vec![exact_fqdn_rule("s1", "chatgpt.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        assert_eq!(
            c.consume(&[obs("chatgpt.com", [9, 9, 9, 9])], SystemTime::now())
                .matched,
            1
        );
        c.consume(
            &[obs("a.nel.cloudflare.com", [9, 9, 9, 9])],
            SystemTime::now(),
        );
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            guard
                .direct_host_count_for_ip(Ipv4Addr::new(9, 9, 9, 9))
                .unwrap_or(0)
                >= 1,
            "an unclaimed bystander keeps its veto"
        );
    }

    /// Equal or narrower claim on the main route → the neighbour keeps its say.
    #[test]
    fn a_neighbour_claimed_as_narrowly_stays_a_census_tenant() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer_with_primary(
            vec![exact_fqdn_rule("p1", "workspace.google.com")],
            vec![exact_fqdn_rule("s1", "aistudio.google.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        assert_eq!(
            c.consume(
                &[obs("aistudio.google.com", [9, 9, 9, 9])],
                SystemTime::now()
            )
            .matched,
            1
        );
        c.consume(
            &[obs("workspace.google.com", [9, 9, 9, 9])],
            SystemTime::now(),
        );
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            guard
                .direct_host_count_for_ip(Ipv4Addr::new(9, 9, 9, 9))
                .unwrap_or(0)
                >= 1,
            "an equally specific claim is not outranked"
        );
    }

    #[test]
    fn fake_ip_gate_keeps_census_and_summary_but_only_changes_log_level() {
        // With fake-IP live the collateral WARN is downgraded to debug, but the
        // detection, the summary count, and the shared-IP census tenant record
        // must all still run — the smart kill-switch depends on that census on
        // the non-fake path too.
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        )
        .with_fake_ip_gate(Arc::new(|| true));
        let s1 = c.consume(&[obs("cdn.example.com", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s1.matched, 1);
        // The direct host on the shared IP is still counted as collateral (only
        // the log line's severity changed).
        let s2 = c.consume(&[obs("victim.org", [9, 9, 9, 9])], SystemTime::now());
        assert_eq!(s2.collateral, 1);
        // The tenant is still recorded in the census (direct_on_ip > 0).
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
        let tenants = guard
            .direct_host_count_for_ip(Ipv4Addr::new(9, 9, 9, 9))
            .unwrap_or(0);
        assert!(
            tenants >= 1,
            "census tenant recording must survive the gate"
        );
    }

    #[test]
    fn loopback_and_unspecified_observations_are_not_cached_or_collateral() {
        let (cache, lookup) = in_memory_cache();
        let c = consumer(
            vec![suffix_rule("r1", "example.com")],
            Arc::clone(&cache),
            Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
            active_sid("S-A"),
        );
        // A subdomain matching the secondary suffix rule, but the OS hosts
        // file pins it to loopback (ad-block). It must NOT enter the FQDN
        // cache — a /32 route to 127.0.0.1 out the secondary adapter is nonsensical.
        let s1 = c.consume(&[obs("ad.example.com", [127, 0, 0, 1])], SystemTime::now());
        assert_eq!(s1.matched, 0);
        assert_eq!(s1.collateral, 0);
        assert!(lookup.ips_for_hostname("ad.example.com").is_empty());

        // The classic `musical.ly → 127.0.0.1` case: a direct (unmatched)
        // host pinned to loopback must never be cached nor flagged collateral.
        let s2 = c.consume(&[obs("musical.ly", [127, 0, 0, 1])], SystemTime::now());
        assert_eq!(s2.matched, 0);
        assert_eq!(s2.collateral, 0);
        assert!(lookup.ips_for_hostname("musical.ly").is_empty());

        // Unspecified (0.0.0.0) is treated identically.
        let s3 = c.consume(
            &[obs("tracker.example.com", [0, 0, 0, 0])],
            SystemTime::now(),
        );
        assert_eq!(s3.matched, 0);
        assert!(lookup.ips_for_hostname("tracker.example.com").is_empty());

        // A mixed resolution caches ONLY the routable IP.
        let s4 = c.consume(
            &[DnsObservation {
                hostname: "mix.example.com".into(),
                ipv4s: vec![Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(8, 8, 4, 4)],
            }],
            SystemTime::now(),
        );
        assert_eq!(s4.matched, 1);
        assert_eq!(
            lookup.ips_for_hostname("mix.example.com"),
            vec![Ipv4Addr::new(8, 8, 4, 4)]
        );
    }
}

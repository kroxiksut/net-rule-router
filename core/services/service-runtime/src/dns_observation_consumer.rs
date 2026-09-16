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

use crate::bounded_set::BoundedRecentSet;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
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

/// The IPv4 half of a cache answer. Named rather than inlined so a grep finds
/// every place still tied to one family.
fn v4_only(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    }
}
use crate::per_sid_orchestrator::RulesProvider;

/// How many hostnames the "warn / purge once" memories keep.
///
/// Both are one-line-per-host guards against a tick that re-sees the same
/// resolutions every few seconds, and both used to grow for the life of the
/// process. Bounded and least-recently-seen first: an eviction means the host
/// has not been seen in a long time, and the worst it costs is one repeated log
/// line or one repeated census purge.
const WARNED_HOSTS_CAP: usize = 4096;

/// Returns the routing-active SID (Free single-active-user), or `None`.
pub type ActiveSidFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Outcome of consuming a batch of observations.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ConsumeSummary {
    /// Rule-matching observations whose cached ENFORCEABLE address set actually
    /// changed (new host, new/rotated IPs, or a stale entry back in the
    /// confirmation window). Only these are progress: the recompute hook
    /// re-derives routes + the full WFP filter set, and firing it for a pure
    /// recency refresh kept that cycle running for as long as any rule site
    /// stayed open in a browser.
    pub matched: u32,
    /// Rule-matching observations upserted for recency only — the enforceable
    /// address set is exactly what the codegen already sees. Not progress.
    pub refreshed: u32,
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
    collateral_warned: Mutex<BoundedRecentSet<String>>,
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
    census_purged: Mutex<BoundedRecentSet<String>>,
    /// Where the names of RULE-LESS hosts are remembered, so the connection
    /// observer can name a destination that fails on the main link. The
    /// observations this consumer discards are exactly the ones that index
    /// needs. `None` (default) leaves it unfed.
    observed_names: Option<Arc<crate::observed_host_names::ObservedHostNames>>,
}

/// How long a reverse-confirmed `(hostname, ip)` pair suppresses identical
/// re-confirmations. Long enough to collapse a blocked burst into one cache
/// write, short enough that `last_seen` ordering stays honest.
const REVERSE_CONFIRM_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Hard bound on the memo map. On overflow the whole memo is dropped (the
/// cost is one redundant cache write per pair, not correctness).
const REVERSE_CONFIRM_MEMO_MAX: usize = 8192;

mod consume;
mod seeding;
mod tenants;
mod wiring;

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
            Some(CanonicalAddressMatch::ExactIp(std::net::IpAddr::V4(ip))) => {
                owners.entry(*ip).or_insert_with(|| ip.to_string());
            }
            // An IPv4-keyed map, like the fan-out beside it.
            Some(CanonicalAddressMatch::ExactIp(std::net::IpAddr::V6(_))) => {}
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                for ip in fqdn.ips_for_hostname(host).into_iter().filter_map(v4_only) {
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
        for ip in fqdn.ips_for_hostname(host).into_iter().filter_map(v4_only) {
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
        .any(|r| rule_covers(r, hostname))
}

/// What a rule set has to say about one hostname, in a single walk.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RuleSetMatch {
    /// Some enabled rule covers the hostname.
    pub matched: bool,
    /// One of those rules is one the USER wrote.
    pub user_authored: bool,
}

/// Both facts about `hostname` at once: is it covered, and is it covered by a
/// rule the user wrote rather than one the app added for them.
///
/// Companion learning anchors on the second. An auto-added rule is a companion
/// somebody already accepted — usually a CDN or an API host — and letting its
/// own hosts anchor makes every accepted suggestion breed the next generation
/// (`*.githubusercontent.com` accepted, then `raw.githubusercontent.com`
/// proposing `github.com`).
pub(crate) fn rule_set_match_origin(hostname: &str, set: &CanonicalRuleSet) -> RuleSetMatch {
    let mut out = RuleSetMatch::default();
    for rule in set.rules().iter().filter(|r| r.enabled) {
        if !rule_covers(rule, hostname) {
            continue;
        }
        out.matched = true;
        if rule.origin.is_none() {
            out.user_authored = true;
            break;
        }
    }
    out
}

fn rule_covers(rule: &nrr_domain::canonical::CanonicalRule, hostname: &str) -> bool {
    match &rule.address_match {
        Some(CanonicalAddressMatch::ExactFqdn(h)) => h == hostname,
        // `*.s` covers the apex `s` and every subdomain; a zone rule covers
        // subdomains only. Both helpers live in `nrr-domain` so this gate
        // and the decision engine can never disagree.
        Some(CanonicalAddressMatch::SuffixDomain(s)) => match_suffix_domain(hostname, s),
        Some(CanonicalAddressMatch::Zone(z)) => match_zone(hostname, z),
        _ => false,
    }
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
            Some(CanonicalAddressMatch::ExactIp(rule_ip))
                if ip.map(std::net::IpAddr::V4) == Some(*rule_ip) =>
            {
                consider(3, "exact-ip");
            }
            _ => {}
        }
    }
    best.map(|(_, kind)| kind)
}

/// A few names plus how many were left out — enough to recognise what a batch
/// was about without printing a hundred hostnames.
fn name_sample(names: &BTreeSet<&str>) -> String {
    const SHOWN: usize = 5;
    let head = names
        .iter()
        .take(SHOWN)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    match names.len().checked_sub(SHOWN) {
        Some(rest) if rest > 0 => format!("{head} (+{rest} more)"),
        _ => head,
    }
}

#[cfg(test)]
mod tests;

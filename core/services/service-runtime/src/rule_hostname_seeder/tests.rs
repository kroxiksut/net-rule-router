use super::*;
use crate::per_sid_orchestrator::ActiveRulesSnapshot;
use nrr_domain::canonical::{CanonicalRule, CanonicalRuleBook};
use nrr_domain::{RouteBehaviorMode, RuleId};
use nrr_platform_api::dns::{MockDnsResolver, ResolvedRecord};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

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
        addresses: ips.iter().copied().map(IpAddr::V4).collect(),
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
            resolved_ips: vec![IpAddr::V4(ip)],
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
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8,
        )))),
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

/// While the guard blocks an unresolved link, an unresolvable rule host is
/// also an UNPROTECTED one: the guard can only block addresses it knows.
/// The calm minute of patience is what kept the hole open at logon
/// (HW-0830: assistant.example unprotected for the full 65 s backoff), so the
/// pacing drops to seconds and stops escalating early.
#[test]
fn the_backoff_tightens_while_the_guard_is_blocking() {
    let resolver = Arc::new(MockDnsResolver::new());
    let (cache, lookup) = in_memory_cache();
    let rules = Arc::new(FakeRules::new(empty(), empty()));
    let blocking = Arc::new(AtomicBool::new(true));
    let s = {
        let flag = Arc::clone(&blocking);
        seeder(resolver, cache, lookup, rules)
            .with_leak_guard_posture(Arc::new(move || flag.load(Ordering::Relaxed)))
    };

    assert_eq!(
        s.note_resolve_failed("cold.example.com"),
        SEED_RETRY_BACKOFF_MIN_UNPROTECTED,
    );
    // Escalation stops early too — a name that will not resolve must still
    // be re-tried within the minute while it has no protection.
    s.clear_resolve_failed("cold.example.com");
    let mut wait = s.note_resolve_failed("cold.example.com");
    for _ in 0..8 {
        s.expire_retry_gate_for_test("cold.example.com");
        wait = s.note_resolve_failed("cold.example.com");
    }
    assert_eq!(wait, SEED_RETRY_BACKOFF_MAX_UNPROTECTED);

    // Calm pacing returns with the link.
    blocking.store(false, Ordering::Relaxed);
    s.clear_resolve_failed("calm.example.com");
    assert_eq!(
        s.note_resolve_failed("calm.example.com"),
        SEED_RETRY_BACKOFF_MIN,
    );
}

/// The guard usually arms in the MIDDLE of a long wait (the tunnel drops,
/// or the link is not up yet at logon). Honouring that wait as scheduled
/// would leave the host unprotected for the rest of it, so an escalated
/// wait is re-read against the shorter ceiling instead.
#[test]
fn an_escalated_wait_is_re_read_against_the_shorter_ceiling_once_the_guard_arms() {
    let resolver = Arc::new(MockDnsResolver::new());
    let (cache, lookup) = in_memory_cache();
    let rules = Arc::new(FakeRules::new(empty(), empty()));
    let blocking = Arc::new(AtomicBool::new(false));
    let s = {
        let flag = Arc::clone(&blocking);
        seeder(resolver, cache, lookup, rules)
            .with_leak_guard_posture(Arc::new(move || flag.load(Ordering::Relaxed)))
    };

    // A ceiling-length wait, five minutes into its run.
    s.schedule_retry_for_test(
        "stale.example.com",
        SEED_RETRY_BACKOFF_MAX,
        Duration::from_secs(300),
    );
    assert!(
        s.retry_suppressed("stale.example.com"),
        "the calm wait holds while the link is fine"
    );

    blocking.store(true, Ordering::Relaxed);
    assert!(
        !s.retry_suppressed("stale.example.com"),
        "under the guard only the first minute of that wait may suppress a retry, and it is spent"
    );

    // A wait that is still inside the guarded ceiling keeps holding — the
    // tightening is a ceiling, not a reset.
    s.schedule_retry_for_test(
        "fresh.example.com",
        SEED_RETRY_BACKOFF_MAX,
        Duration::from_secs(5),
    );
    assert!(s.retry_suppressed("fresh.example.com"));
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
    // `*.cdn.example` names an apex that is a zone, not a host: the resolver
    // answers authoritatively "no address record" forever. After
    // `SEED_APEX_ABSENT_CONFIRMATIONS` such passes the apex leaves the
    // rotation — no more queries, and no more DNS-failure counts.
    let resolver = Arc::new(MockDnsResolver::new());
    resolver.set_error(
        "cdn.example",
        DnsResolverError::NxDomain {
            hostname: "cdn.example".into(),
        },
    );
    let (cache, lookup) = in_memory_cache();
    let rules = Arc::new(FakeRules::new(
        empty(),
        CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "cdn.example")]),
    ));
    let s = seeder(Arc::clone(&resolver), cache, lookup, rules);

    let confirming = run_passes(
        &s,
        &["cdn.example"],
        SEED_APEX_ABSENT_CONFIRMATIONS as usize - 1,
    );
    assert_eq!(confirming.failed, 1, "still inconclusive → a plain failure");
    assert_eq!(confirming.apex_absent, 0);
    assert!(!s.apex_absent("cdn.example"));

    let parking = s.seed_for_principal("S-A", SystemTime::now());
    assert_eq!(parking.apex_absent, 1);
    assert_eq!(
        parking.failed, 0,
        "a name with no address record is not a DNS failure"
    );
    assert!(s.apex_absent("cdn.example"));

    // Parked: subsequent passes report the outcome without querying.
    let queries_at_parking = resolver.observed_queries().len();
    let after = run_passes(&s, &["cdn.example"], 3);
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

/// Parks `cdn.example` behind a `*.cdn.example` rule and hands back the pieces.
fn parked_apex_fixture() -> (Arc<MockDnsResolver>, Arc<FakeRules>, RuleHostnameSeeder) {
    let resolver = Arc::new(MockDnsResolver::new());
    resolver.set_error(
        "cdn.example",
        DnsResolverError::NxDomain {
            hostname: "cdn.example".into(),
        },
    );
    let (cache, lookup) = in_memory_cache();
    let rules = Arc::new(FakeRules::new(
        empty(),
        CanonicalRuleSet::from_rules(vec![suffix_rule("r1", "cdn.example")]),
    ));
    let s = seeder(Arc::clone(&resolver), cache, lookup, Arc::clone(&rules));
    run_passes(
        &s,
        &["cdn.example"],
        SEED_APEX_ABSENT_CONFIRMATIONS as usize,
    );
    assert!(s.apex_absent("cdn.example"));
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
    let before = asked_for("cdn.example");

    rules.set_secondary(CanonicalRuleSet::from_rules(vec![
        suffix_rule("r1", "cdn.example"),
        fqdn_rule("r2", "api.example.com"),
    ]));
    let sum = s.seed_for_principal("S-A", SystemTime::now());

    assert!(s.apex_absent("cdn.example"));
    assert_eq!(sum.apex_absent, 1);
    assert_eq!(
        asked_for("cdn.example"),
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
        "cdn.example",
    )]));
    let sum = s.seed_for_principal("S-A", SystemTime::now());

    assert!(!s.apex_absent("cdn.example"));
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

/// A resolver that answers only once the test opens it — a tunnel that
/// swallows queries, made deterministic.
struct GatedResolver {
    inner: MockDnsResolver,
    open: Mutex<bool>,
    opened: std::sync::Condvar,
    entered: std::sync::atomic::AtomicUsize,
}

impl GatedResolver {
    fn new(inner: MockDnsResolver) -> Self {
        Self {
            inner,
            open: Mutex::new(false),
            opened: std::sync::Condvar::new(),
            entered: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.entered.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[allow(clippy::unwrap_used)]
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
}

impl DnsResolverPort for GatedResolver {
    #[allow(clippy::unwrap_used)]
    fn resolve(
        &self,
        hostname: &str,
        family: AddressFamily,
    ) -> Result<ResolvedRecord, DnsResolverError> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let guard = self.open.lock().unwrap();
        drop(self.opened.wait_while(guard, |open| !*open).unwrap());
        self.inner.resolve(hostname, family)
    }
}

fn gated_seeder() -> (Arc<GatedResolver>, Arc<RuleHostnameSeeder>) {
    let mock = MockDnsResolver::new();
    mock.set_response(
        "api.example.com",
        record("api.example.com", &[Ipv4Addr::new(1, 2, 3, 4)]),
    );
    let resolver = Arc::new(GatedResolver::new(mock));
    let (cache, lookup) = in_memory_cache();
    let rules = Arc::new(FakeRules::new(
        empty(),
        CanonicalRuleSet::from_rules(vec![fqdn_rule("r1", "api.example.com")]),
    ));
    let seeder = Arc::new(RuleHostnameSeeder::new(
        Arc::clone(&resolver) as Arc<dyn DnsResolverPort>,
        cache,
        lookup as Arc<dyn FqdnCacheLookup>,
        rules as Arc<dyn RulesProvider>,
    ));
    (resolver, seeder)
}

fn counting_hook() -> (
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<dyn Fn() + Send + Sync>,
) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook = {
        let calls = Arc::clone(&calls);
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
        }) as Arc<dyn Fn() + Send + Sync>
    };
    (calls, hook)
}

#[test]
fn a_seed_that_fits_the_budget_is_waited_for_and_recomputes_nothing_extra() {
    let (resolver, seeder) = gated_seeder();
    resolver.release();
    let (calls, hook) = counting_hook();
    let wait = seeder.seed_within(vec!["S-A".into()], Duration::from_secs(10), hook);
    assert_eq!(wait, SeedWait::Finished);
    assert_eq!(
        seeder.fqdn_lookup.ips_for_hostname("api.example.com"),
        vec![Ipv4Addr::new(1, 2, 3, 4)]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
#[allow(clippy::unwrap_used)]
fn a_stalled_seed_releases_the_caller_and_recomputes_once_it_lands() {
    let (resolver, seeder) = gated_seeder();
    let (calls, hook) = counting_hook();
    let started = Instant::now();
    let wait = seeder.seed_within(vec!["S-A".into()], Duration::from_millis(50), hook);
    assert_eq!(wait, SeedWait::Detached);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    resolver.release();
    let deadline = Instant::now() + Duration::from_secs(10);
    while calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        seeder.fqdn_lookup.ips_for_hostname("api.example.com"),
        vec![Ipv4Addr::new(1, 2, 3, 4)]
    );
}

#[test]
fn a_pass_already_in_flight_does_not_block_the_caller() {
    let (resolver, seeder) = gated_seeder();
    let (_, first) = counting_hook();
    assert_eq!(
        seeder.seed_within(vec!["S-A".into()], Duration::from_millis(20), first),
        SeedWait::Detached
    );
    resolver.wait_until_entered();
    let (second_calls, second) = counting_hook();
    let started = Instant::now();
    assert_eq!(
        seeder.seed_within(vec!["S-A".into()], Duration::from_secs(30), second),
        SeedWait::Detached
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    resolver.release();
    assert_eq!(second_calls.load(Ordering::SeqCst), 0);
}

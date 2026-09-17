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

#[test]
fn an_auto_added_rule_covers_a_host_without_making_it_an_anchor() {
    let mut auto = suffix_rule("r-auto", "githubusercontent.com");
    auto.origin = Some(nrr_domain::RuleOrigin::auto(
        nrr_domain::AutoRuleReason::UserConfirmed,
        "www.googletagmanager.com",
        "2026-08-11",
    ));
    let set = CanonicalRuleSet::from_rules(vec![auto, suffix_rule("r-user", "example.com")]);

    let auto_host = rule_set_match_origin("raw.githubusercontent.com", &set);
    assert!(auto_host.matched);
    assert!(!auto_host.user_authored);

    let user_host = rule_set_match_origin("www.example.com", &set);
    assert!(user_host.matched);
    assert!(user_host.user_authored);

    assert!(!rule_set_match_origin("elsewhere.test", &set).matched);
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

/// A consumer wired to a live companion-learning engine over
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

/// The case the user had to diagnose by hand: a site the provider answers
/// with an address nothing lives at. Nobody pulled it, so the companion
/// path never proposes it — the host has to be able to make the offer
/// itself.
#[test]
fn a_site_answered_with_a_placeholder_offers_itself_for_the_tunnel() {
    let (cache, lookup) = in_memory_cache();
    let (c, engine) = consumer_with_learning(
        vec![exact_fqdn_rule("r1", "site.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
    );

    // Documentation space: a resolver standing something in for the name.
    c.consume(&[obs("journal.example", [192, 0, 2, 1])], at_ms(0));

    let candidates = engine.candidates("S-A");
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert_eq!(candidates[0].anchor, "journal.example");
    assert_eq!(candidates[0].proposed_match, "journal.example");
    assert_eq!(
        candidates[0].signal,
        nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER,
    );
}

/// Positive control for the line between the two: a hosts-file pin looks
/// just as unusable and must never be offered — the user asked for it.
#[test]
fn a_hosts_file_pin_is_never_offered_for_the_tunnel() {
    let (cache, lookup) = in_memory_cache();
    let (c, engine) = consumer_with_learning(
        vec![exact_fqdn_rule("r1", "site.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
    );

    c.consume(&[obs("ads.example", [127, 0, 0, 1])], at_ms(0));

    assert!(engine.candidates("S-A").is_empty());
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
                obs("cdn.example", [23, 10, 20, 138]),
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
                obs("cdn.example", [23, 10, 20, 138]),
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
        &[obs("cdn-17.example.com", [23, 10, 20, 138])],
        SystemTime::now(),
    );
    assert_eq!(sum.matched, 1);
    assert!(sum.made_progress());
    assert_eq!(
        lookup.ips_for_hostname("cdn-17.example.com"),
        vec![Ipv4Addr::new(23, 10, 20, 138)]
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
        // Matches the `.example` zone rule → seeded.
        OsCachedResolution {
            canonical_hostname: "shop.example".into(),
            addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
        },
        // No rule → ignored.
        OsCachedResolution {
            canonical_hostname: "other.test".into(),
            addresses: vec![Ipv4Addr::new(8, 8, 8, 8)],
        },
        // Matches the zone name but is an ad-block loopback pin → dropped
        // before it can become a /32 (mirrors the observe path).
        OsCachedResolution {
            canonical_hostname: "ads.example".into(),
            addresses: vec![Ipv4Addr::new(127, 0, 0, 1)],
        },
    ]);
    let c = consumer(
        vec![zone_rule("r1", "example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    )
    .with_dns_cache_read(reader);

    let sum = c.seed_from_os_cache(SystemTime::now());
    assert_eq!(
        sum.matched, 1,
        "only shop.example is a rule match with a routable IP"
    );
    assert_eq!(sum.ignored, 1, "other.test matched no rule");
    assert_eq!(
        lookup.ips_for_hostname("shop.example"),
        vec![Ipv4Addr::new(1, 2, 3, 4)]
    );
    assert!(lookup.ips_for_hostname("other.test").is_empty());
    assert!(
        lookup.ips_for_hostname("ads.example").is_empty(),
        "loopback pin must never enter the cache"
    );
    // The zone fan-out now sees the seeded host.
    assert_eq!(
        lookup.hostnames_under_suffix("example", 16),
        vec!["shop.example".to_string()]
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
fn re_observing_an_unchanged_host_is_refresh_not_progress() {
    let (cache, lookup) = in_memory_cache();
    let c = consumer(
        vec![zone_rule("r1", "ru")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    );
    let first = c.consume(&[obs("site.example.ru", [5, 5, 5, 5])], SystemTime::now());
    assert_eq!(first.matched, 1);
    assert_eq!(first.refreshed, 0);
    // Same host, same address: recency is renewed but the enforceable set
    // is untouched — the recompute hook must stay silent, else an open
    // rule site keeps the full route/WFP re-derivation cycling forever.
    let second = c.consume(&[obs("site.example.ru", [5, 5, 5, 5])], SystemTime::now());
    assert_eq!(second.matched, 0);
    assert_eq!(second.refreshed, 1);
    assert!(!second.made_progress());
    // A new address IS progress — the codegen now derives a different set.
    let third = c.consume(&[obs("site.example.ru", [6, 6, 6, 6])], SystemTime::now());
    assert_eq!(third.matched, 1);
    assert!(third.made_progress());
}

#[test]
fn re_seeding_unchanged_os_cache_entries_is_not_progress() {
    use nrr_platform_api::dns::{MockDnsCacheRead, OsCachedResolution};
    let (cache, lookup) = in_memory_cache();
    let reader = Arc::new(MockDnsCacheRead::new());
    reader.set_entries(vec![OsCachedResolution {
        canonical_hostname: "shop.example".into(),
        addresses: vec![Ipv4Addr::new(1, 2, 3, 4)],
    }]);
    let c = consumer(
        vec![zone_rule("r1", "example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    )
    .with_dns_cache_read(reader);
    let first = c.seed_from_os_cache(SystemTime::now());
    assert_eq!(first.matched, 1);
    // The OS cache is re-read whole every seed tick; an unchanged snapshot
    // must not re-fire the recompute hook every 30 s.
    let second = c.seed_from_os_cache(SystemTime::now());
    assert_eq!(second.matched, 0);
    assert_eq!(second.refreshed, 1);
    assert!(!second.made_progress());
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
    // `*.example.com` covers the apex `example.com`, so the
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
    // While the secondary is unusable the collateral event is
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
/// `*.search.example` and a named `aistudio.search.example`, and search died in
/// every browser: the pin cannot divert a host the user routed the other
/// way, it can only cut it.
#[test]
fn a_host_claimed_by_a_wide_main_route_rule_stays_a_census_tenant() {
    let (cache, lookup) = in_memory_cache();
    let c = consumer_with_primary(
        vec![suffix_rule("p1", "search.example")],
        vec![exact_fqdn_rule("s1", "aistudio.search.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    );
    // The named secondary rule resolves → the address is secondary-owned.
    assert_eq!(
        c.consume(
            &[obs("aistudio.search.example", [9, 9, 9, 9])],
            SystemTime::now()
        )
        .matched,
        1
    );
    // A neighbour on the same address, held only by the wide primary rule.
    c.consume(
        &[obs("workspace.search.example", [9, 9, 9, 9])],
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
        vec![exact_fqdn_rule("s1", "assistant.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    );
    assert_eq!(
        c.consume(&[obs("assistant.example", [9, 9, 9, 9])], SystemTime::now())
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
        vec![exact_fqdn_rule("s1", "assistant.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    );
    assert_eq!(
        c.consume(&[obs("assistant.example", [9, 9, 9, 9])], SystemTime::now())
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
        vec![exact_fqdn_rule("p1", "workspace.search.example")],
        vec![exact_fqdn_rule("s1", "aistudio.search.example")],
        Arc::clone(&cache),
        Arc::clone(&lookup) as Arc<dyn FqdnCacheLookup>,
        active_sid("S-A"),
    );
    assert_eq!(
        c.consume(
            &[obs("aistudio.search.example", [9, 9, 9, 9])],
            SystemTime::now()
        )
        .matched,
        1
    );
    c.consume(
        &[obs("workspace.search.example", [9, 9, 9, 9])],
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

    // The classic `app.example → 127.0.0.1` case: a direct (unmatched)
    // host pinned to loopback must never be cached nor flagged collateral.
    let s2 = c.consume(&[obs("app.example", [127, 0, 0, 1])], SystemTime::now());
    assert_eq!(s2.matched, 0);
    assert_eq!(s2.collateral, 0);
    assert!(lookup.ips_for_hostname("app.example").is_empty());

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

/// The summary has to stay readable when a busy drain touches dozens of
/// names, and still name enough of them to be recognisable.
#[test]
fn a_name_sample_shows_a_few_names_and_counts_the_rest() {
    let few: BTreeSet<&str> = ["b.test", "a.test"].into_iter().collect();
    assert_eq!(
        name_sample(&few),
        "a.test, b.test",
        "sorted, nothing elided"
    );

    let many: BTreeSet<&str> = ["a", "b", "c", "d", "e", "f", "g"].into_iter().collect();
    assert_eq!(name_sample(&many), "a, b, c, d, e (+2 more)");
}

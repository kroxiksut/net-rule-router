use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};

use super::*;
use crate::conn_observation_consumer::ConnectionTraceRecord;
use crate::conn_trace_names::RemoteNames;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;

const ALICE: &str = "S-1-5-21-1-2-3-1001";
const BOB: &str = "S-1-5-21-1-2-3-1002";
const MAIN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const TUNNEL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

#[derive(Default)]
struct ManualRules(Mutex<crate::per_sid_orchestrator::ActiveRulesSnapshot>);
impl crate::per_sid_orchestrator::RulesProvider for ManualRules {
    fn active_rules(&self) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
        Some(self.0.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }
}

#[derive(Default)]
struct EnteredResolver(Mutex<Vec<(String, Duration)>>);
impl crate::dns_resolver::UpstreamResolver for EnteredResolver {
    fn resolve_within(
        &self,
        host: &str,
        _: nrr_platform_api::dns::AddressFamily,
        budget: Duration,
    ) -> Result<crate::dns_resolver::ResolvedAddresses, crate::dns_resolver::ResolveError> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((host.to_owned(), budget));
        Ok(crate::dns_resolver::ResolvedAddresses {
            addresses: vec![IpAddr::V4(ip(31))],
            ttl_seconds: 60,
        })
    }
}

#[derive(Default)]
struct PairedProbe(Mutex<Vec<(String, Option<Ipv4Addr>)>>);
impl PathProbe for PairedProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        panic!("manual host confirmation uses TLS");
    }
    fn probe_tls(
        &self,
        _: Ipv4Addr,
        host: &str,
        source: Option<Ipv4Addr>,
        _: Duration,
    ) -> PathVerdict {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((host.to_owned(), source));
        if source == Some(TUNNEL) {
            PathVerdict::Answered
        } else {
            PathVerdict::Silent
        }
    }
}

#[test]
fn an_explicit_uncached_name_can_be_confirmed_without_automatic_probe_consent() {
    use crate::auto_rules::{AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore};
    let rules = Arc::new(ManualRules::default());
    let engine = Arc::new(
        AutoRulesEngine::new(
            rules.clone(),
            Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
            Arc::new(InMemoryDismissalStore::new()),
            Arc::new(InMemoryPendingStore::new()),
            std::time::SystemTime::now(),
        )
        .with_primary_behavior_source(Arc::new(|sid, host| {
            crate::primary_stall_registry::global_primary_stalls().behavior_of_subtree(sid, host)
        })),
    );
    let resolver = Arc::new(EnteredResolver::default());
    let probe = Arc::new(PairedProbe::default());
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: probe.clone(),
        egress: Arc::new(Links(Some(MAIN), Some(TUNNEL))),
        cache: Arc::new(MockFqdnCacheLookup::new()),
        routes: covering(&[]),
        engine: Some(Arc::clone(&engine)),
        trace: None,
        https: None,
        traffic_held: None,
    });
    let resolve = Arc::clone(&resolver);
    checker.attach_manual(ManualSiteCheckWiring {
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        rules,
        primary_default: Arc::new(|_| true),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(move |_| Some(resolve.clone())),
    });
    let report = checker.check(ALICE, "manually-entered.example");
    assert_eq!(report.names[0].address, ip(31).to_string());
    assert_eq!(report.names[0].answer, "silent");
    assert_eq!(
        resolver.0.lock().unwrap_or_else(|p| p.into_inner()).len(),
        1,
        "only the entered literal is resolved"
    );
    assert_eq!(
        probe
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, source)| *source == Some(MAIN))
            .count(),
        3
    );
    assert_eq!(
        probe
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, source)| *source == Some(TUNNEL))
            .count(),
        1
    );
    let offers = engine.candidates(ALICE);
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].proposed_match, "manually-entered.example");
    assert_eq!(offers[0].secondary_reach, Some(true));
    assert!(engine.candidates(BOB).is_empty());
}

#[test]
fn reading_a_typed_os_cached_name_does_not_resolve_guessed_sign_in_names() {
    use nrr_platform_api::dns::{MockDnsCacheRead, OsCachedResolution};
    let f = Fixture::new();
    let checker = f.checker(covering(&[]));
    let reader = Arc::new(MockDnsCacheRead::new());
    reader.set_entries(vec![OsCachedResolution {
        canonical_hostname: "cached-literal.example".into(),
        addresses: vec![IpAddr::V4(ip(32))],
    }]);
    checker.attach_manual(ManualSiteCheckWiring {
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        rules: Arc::new(ManualRules::default()),
        primary_default: Arc::new(|_| true),
        os_cache: reader,
        resolver_for: Arc::new(|_| panic!("OS-cached typed literal needs no network DNS")),
    });
    let report = checker.check(ALICE, "cached-literal.example");
    assert_eq!(report.names[0].address, ip(32).to_string());
    assert_eq!(
        f.probe
            .asked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len(),
        1
    );
}

#[test]
fn manual_lookup_never_uses_a_primary_resolver_for_an_unseen_secondary_name() {
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
    let f = Fixture::new();
    let rules = Arc::new(ManualRules::default());
    rules
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .rule_book
        .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
        id: nrr_domain::RuleId("manual-secondary".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(
            "private-secondary.example".into(),
        )),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }]);
    let checker = f.checker(routes(&[("private-secondary.example", "secondary")]));
    checker.attach_manual(ManualSiteCheckWiring {
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        rules,
        primary_default: Arc::new(|_| true),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| {
            panic!("a secondary name must never reach the primary resolver")
        }),
    });
    let report = checker.check(ALICE, "private-secondary.example");
    assert_eq!(report.names[0].answer, "no-address");
    assert!(f
        .probe
        .asked
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
}

#[test]
fn a_possible_application_rule_prevents_an_exempt_manual_primary_probe() {
    use nrr_domain::canonical::{
        CanonicalAppMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleSet,
    };
    let f = Fixture::new();
    f.cache.set_ips("app-guarded-literal.example", vec![ip(33)]);
    let rules = Arc::new(ManualRules::default());
    rules
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .rule_book
        .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
        id: nrr_domain::RuleId("manual-app".into()),
        enabled: true,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact("browser.exe".into()),
            include_child_processes: false,
            override_requested: false,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }]);
    let checker = f.checker(covering(&[]));
    checker.attach_manual(ManualSiteCheckWiring {
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        rules,
        primary_default: Arc::new(|_| true),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| panic!("the cached literal needs no DNS")),
    });
    let report = checker.check(ALICE, "app-guarded-literal.example");
    assert_eq!(report.names[0].answer, "unclear");
    let wire = serde_json::to_value(&report).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        wire["names"][0]["not-run-reason"], "application-context-required",
        "a known IP withheld for policy safety must not be explained as an unknown address"
    );
    assert!(f
        .probe
        .asked
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
}

#[test]
fn a_manual_request_keeps_the_principals_timeout_and_target_limits() {
    struct TimedProbe(Mutex<Vec<Duration>>);
    impl PathProbe for TimedProbe {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            panic!("hostnames require TLS");
        }
        fn probe_tls(
            &self,
            _: Ipv4Addr,
            _: &str,
            _: Option<Ipv4Addr>,
            timeout: Duration,
        ) -> PathVerdict {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(timeout);
            PathVerdict::Answered
        }
    }
    let resolver = Arc::new(EnteredResolver::default());
    let probe = Arc::new(TimedProbe(Mutex::new(Vec::new())));
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: probe.clone(),
        egress: Arc::new(Links(Some(MAIN), Some(TUNNEL))),
        cache: Arc::new(MockFqdnCacheLookup::new()),
        routes: covering(&[]),
        engine: None,
        trace: None,
        https: None,
        traffic_held: None,
    });
    let resolve = Arc::clone(&resolver);
    checker.attach_manual(ManualSiteCheckWiring {
        rules: Arc::new(ManualRules::default()),
        primary_default: Arc::new(|_| true),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(move |_| Some(resolve.clone())),
        limits: Arc::new(|_| {
            crate::path_probe::ProbeLimits::new(
                Duration::from_millis(300),
                1,
                Duration::from_secs(30),
            )
        }),
    });
    let report = checker.check(ALICE, "bounded-manual.example");
    assert_eq!(report.names.len(), 1);
    let attempts = probe.0.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(attempts.len(), 1);
    assert!(attempts
        .iter()
        .all(|timeout| *timeout <= Duration::from_millis(300)));
    let resolutions = resolver.0.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(resolutions.len(), 1);
    assert!(resolutions[0].1 <= Duration::from_millis(300));
}

/// Answers per target address; anything unlisted answers.
#[derive(Default)]
struct ScriptedProbe {
    by_target: HashMap<Ipv4Addr, PathVerdict>,
    asked: Mutex<Vec<(Ipv4Addr, String, Option<Ipv4Addr>)>>,
}

impl PathProbe for ScriptedProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        PathVerdict::Indeterminate
    }

    fn probe_tls(
        &self,
        target: Ipv4Addr,
        server_name: &str,
        source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PathVerdict {
        self.asked.lock().unwrap_or_else(|p| p.into_inner()).push((
            target,
            server_name.to_owned(),
            source,
        ));
        self.by_target
            .get(&target)
            .copied()
            .unwrap_or(PathVerdict::Answered)
    }
}

struct Links(Option<Ipv4Addr>, Option<Ipv4Addr>);

impl EgressSources for Links {
    fn egress_source_ips(&self, _sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (self.0, self.1)
    }
}

/// Routes by exact name; everything else takes the main route. `covered`
/// names the hosts the caller's own rules cover, `None` for every host.
#[derive(Default)]
struct Routes(HashMap<String, String>, Option<Vec<String>>);

impl SiteRoutes for Routes {
    fn route_for(&self, _sid: &str, name: &str, _address: Option<Ipv4Addr>) -> String {
        self.0
            .get(name)
            .cloned()
            .unwrap_or_else(|| "none".to_owned())
    }

    fn covers(&self, _sid: &str, name: &str) -> bool {
        self.1
            .as_ref()
            .is_none_or(|covered| covered.iter().any(|n| n == name))
    }
}

fn routes(pairs: &[(&str, &str)]) -> Arc<Routes> {
    Arc::new(Routes(
        pairs
            .iter()
            .map(|(n, r)| ((*n).to_owned(), (*r).to_owned()))
            .collect(),
        None,
    ))
}

/// No rule of the caller's names any host but `covered`.
fn covering(covered: &[&str]) -> Arc<Routes> {
    Arc::new(Routes(
        HashMap::new(),
        Some(covered.iter().map(|n| (*n).to_owned()).collect()),
    ))
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(203, 0, 113, last)
}

struct Fixture {
    cache: Arc<MockFqdnCacheLookup>,
    probe: Arc<ScriptedProbe>,
    trace: Option<Arc<ConnectionTraceRing>>,
    https: Option<Arc<dyn HttpsHead>>,
    links: (Option<Ipv4Addr>, Option<Ipv4Addr>),
    traffic_held: Option<TrafficHeld>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            cache: Arc::new(MockFqdnCacheLookup::new()),
            probe: Arc::new(ScriptedProbe::default()),
            trace: None,
            https: None,
            links: (Some(MAIN), Some(TUNNEL)),
            traffic_held: None,
        }
    }

    fn checker(&self, routes: Arc<Routes>) -> SiteChecker {
        SiteChecker::new(SiteCheckWiring {
            probe: Arc::clone(&self.probe) as Arc<dyn PathProbe>,
            egress: Arc::new(Links(self.links.0, self.links.1)),
            cache: Arc::clone(&self.cache) as Arc<dyn FqdnCacheLookup>,
            routes,
            engine: None,
            trace: self.trace.clone(),
            https: self.https.clone(),
            traffic_held: self.traffic_held.clone(),
        })
    }
}

fn names(report: &SiteCheckReport) -> Vec<(&str, &str, &str)> {
    report
        .names
        .iter()
        .map(|n| (n.name.as_str(), n.route.as_str(), n.answer.as_str()))
        .collect()
}

#[test]
fn nov10_https_capability_does_not_claim_an_answer_was_read_when_the_route_is_down() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.https = Some(Arc::new(Redirecting));
    f.links = (Some(MAIN), None);
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_ROUTE_DOWN);
    assert!(
        !report.reads_answer,
        "having an HTTP adapter is not a measurement"
    );
    assert!(f
        .probe
        .asked
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_empty());
}

#[test]
fn nov10_a_policy_guard_explains_why_a_known_address_was_not_checked() {
    a_possible_application_rule_prevents_an_exempt_manual_primary_probe();
}

#[test]
fn nov10_known_real_addresses_do_not_repeat_non_adjacent_cache_entries() {
    let f = Fixture::new();
    f.cache
        .set_ips("site.example", vec![ip(1), ip(2), ip(1), ip(3)]);
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(
        report.names[0].real_addresses,
        [ip(1).to_string(), ip(2).to_string(), ip(3).to_string()]
    );
}

#[test]
fn nov10_a_redirect_cannot_escape_the_application_rule_guard() {
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
        CanonicalRuleSet,
    };
    struct GuardedRedirect;
    impl HttpsHead for GuardedRedirect {
        fn fetch(
            &self,
            target: Ipv4Addr,
            _: &str,
            _: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            assert_eq!(
                target,
                ip(1),
                "redirect needs application context; do not send it on the main link"
            );
            Ok(b"HTTP/1.1 302 Found\r\nLocation: https://passport.site.example/\r\n\r\n".to_vec())
        }
    }
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("passport.site.example", vec![ip(2)]);
    f.https = Some(Arc::new(GuardedRedirect));
    let rules = Arc::new(ManualRules::default());
    {
        let mut snapshot = rules.0.lock().unwrap_or_else(|p| p.into_inner());
        snapshot.rule_book.primary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
            id: nrr_domain::RuleId("entered-primary".into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn("site.example".into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }]);
        snapshot.rule_book.secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
            id: nrr_domain::RuleId("browser-secondary".into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("browser.exe".into()),
                include_child_processes: false,
                override_requested: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }]);
    }
    let checker = f.checker(routes(&[]));
    checker.attach_manual(ManualSiteCheckWiring {
        rules,
        primary_default: Arc::new(|_| true),
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| panic!("known addresses need no lookup")),
    });
    let report = checker.check(ALICE, "site.example");
    assert_eq!(report.names[0].status, Some(302));
}

#[test]
fn nov10_a_tls_answer_followed_by_http_reset_still_produces_a_reviewable_site_offer() {
    use crate::auto_rules::{AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore};
    struct ResetOnMain(Mutex<Vec<Ipv4Addr>>);
    impl HttpsHead for ResetOnMain {
        fn fetch(
            &self,
            _: Ipv4Addr,
            _: &str,
            source: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(source);
            if source == TUNNEL {
                Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
            } else {
                Err(HeadFailure::NoAnswer)
            }
        }
    }
    let rules = Arc::new(ManualRules::default());
    let engine = Arc::new(AutoRulesEngine::new(
        rules.clone(),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        std::time::SystemTime::now(),
    ));
    let f = Fixture::new();
    let host = "manual-http-reset.example";
    f.cache.set_ips(host, vec![ip(1)]);
    let https = Arc::new(ResetOnMain(Mutex::new(Vec::new())));
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: f.probe.clone(),
        egress: Arc::new(Links(Some(MAIN), Some(TUNNEL))),
        cache: f.cache.clone(),
        routes: covering(&[]),
        engine: Some(engine.clone()),
        trace: None,
        https: Some(https.clone()),
        traffic_held: None,
    });
    checker.attach_manual(ManualSiteCheckWiring {
        rules,
        primary_default: Arc::new(|_| true),
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| panic!("cached")),
    });
    let report = checker.check(ALICE, host);
    assert_eq!(report.verdict, "not-answering");
    let offers = engine.candidates(ALICE);
    assert!(
        offers.iter().any(|c| c.proposed_match == host
            && c.signal == "http-path-reachability"
            && c.secondary_reach == Some(true)),
        "a TLS handshake must not suppress the confirmed HTTP path difference: {offers:?}"
    );
    assert!(engine.candidates(BOB).is_empty());
    let calls = https.0.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        calls.iter().filter(|ip| **ip == MAIN).count() <= 2,
        "TLS plus HTTP may not exceed three primary connections"
    );
    assert_eq!(calls.iter().filter(|ip| **ip == TUNNEL).count(), 1);
}

#[test]
fn sign_in_names_are_the_sites_own_with_a_sign_in_label() {
    let root = site_root("www.site.example");
    assert_eq!(root, "site.example");
    for yes in [
        "login.site.example",
        "id2.site.example",
        "auth-new.site.example",
    ] {
        assert!(is_sign_in(root, yes), "{yes}");
    }
    for no in [
        "idea.site.example",
        "login.other.example",
        "cdn.site.example",
    ] {
        assert!(!is_sign_in(root, no), "{no}");
    }
    assert!(
        is_sign_in("brand.example", "id.brand.net"),
        "the same brand in another zone is still the site"
    );
}

#[test]
fn the_plan_puts_the_site_first_and_stays_bounded() {
    let traced: Vec<String> = (0..20).map(|i| format!("n{i}.site.example")).collect();
    let plan = plan_names("site.example", &traced, &["login.site.example".to_owned()]);
    assert_eq!(plan[0].role, Role::Site);
    assert_eq!(plan[1].name, "login.site.example");
    assert!(plan[1].observed);
    assert!(plan
        .iter()
        .any(|p| p.name == "id.site.example" && !p.observed));
    assert_eq!(plan.len(), SITE_CHECK_MAX_NAMES);
}

#[test]
fn a_healthy_site_on_its_route_is_fine_and_unused_guesses_are_left_out() {
    let f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_FINE);
    assert_eq!(names(&report), [("site.example", "primary", "answered")]);
    assert!(!report.reads_answer);
    assert_eq!(
        f.probe.asked.lock().unwrap().as_slice(),
        [(ip(1), "site.example".to_owned(), Some(MAIN))],
        "asked over the main link, by the site's own name"
    );
}

#[test]
fn a_sign_in_on_another_route_is_the_split_and_is_offered_to_move() {
    let f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("login.site.example", vec![ip(2)]);
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_SIGN_IN_SPLIT);
    assert_eq!(report.site_route, "secondary");
    assert_eq!(report.move_names, ["login.site.example"]);
    let asked = f.probe.asked.lock().unwrap().clone();
    assert!(asked.contains(&(ip(1), "site.example".to_owned(), Some(TUNNEL))));
    assert!(asked.contains(&(ip(2), "login.site.example".to_owned(), Some(MAIN))));
}

#[test]
fn a_down_route_a_silent_site_and_a_deny_rule_each_say_so() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.links = (Some(MAIN), None);
    let down = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(down.verdict, SITE_CHECK_VERDICT_ROUTE_DOWN);

    let mut silent = Fixture::new();
    silent.cache.set_ips("site.example", vec![ip(1)]);
    silent.probe = Arc::new(ScriptedProbe {
        by_target: HashMap::from([(ip(1), PathVerdict::Silent)]),
        ..ScriptedProbe::default()
    });
    let report = silent.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_NOT_ANSWERING);

    let blocked = Fixture::new();
    let report = blocked
        .checker(routes(&[("site.example", "blocked")]))
        .check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_BLOCKED);
    assert!(
        blocked.probe.asked.lock().unwrap().is_empty(),
        "nothing is sent"
    );
}

#[test]
fn nothing_known_about_the_site_is_unclear_not_a_failure() {
    let f = Fixture::new();
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_UNCLEAR);
    assert_eq!(report.names[0].answer, "no-address");
    assert!(f.probe.asked.lock().unwrap().is_empty());
}

fn row(owner: &str, last: u8, names: &[&str]) -> ConnectionTraceRecord {
    ConnectionTraceRecord {
        process_path: Some(r"C:\Apps\browser.exe".to_owned()),
        user_sid: Some(owner.to_owned()),
        protocol: TransportProtocol::Tcp,
        local: SocketAddr::new(IpAddr::V4(MAIN), 50_000),
        remote: SocketAddr::new(IpAddr::V4(ip(last)), 443),
        egress: EgressInterface {
            ifindex: 2,
            role: EgressRole::Primary,
        },
        verdict: ConnectionVerdict::Permit,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        nrr_block_reason: None,
        observed_unix_ms: Some(1),
        remote_names: Some(Arc::new(RemoteNames {
            names: names.iter().map(|n| (*n).to_owned()).collect(),
            total: names.len() as u32,
            fake_ip: false,
        })),
    }
}

#[test]
fn only_the_callers_own_traffic_names_the_sites_sign_in() {
    let mut f = Fixture::new();
    let ring = Arc::new(ConnectionTraceRing::new(16));
    ring.push(row(ALICE, 1, &["site.example"]));
    ring.push(row(ALICE, 3, &["sso2.cdn.example", "id.site.example"]));
    ring.push(row(BOB, 9, &["auth.site.example"]));
    f.trace = Some(ring);
    let checker = f.checker(routes(&[("site.example", "secondary")]));

    let report = checker.check(ALICE, "site.example");

    let listed: Vec<&str> = report.names.iter().map(|n| n.name.as_str()).collect();
    assert!(listed.contains(&"id.site.example"));
    assert!(
        !report
            .names
            .iter()
            .any(|n| n.name == "auth.site.example" && n.address == ip(9).to_string()),
        "another user's connection is not this caller's evidence"
    );
    let id = report
        .names
        .iter()
        .find(|n| n.name == "id.site.example")
        .expect("listed");
    assert_eq!(id.address, ip(3).to_string(), "the address the caller used");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_SIGN_IN_SPLIT);
    assert_eq!(report.move_names, ["id.site.example"]);
}

/// Answers by host: a redirect from the site to its sign-in, then a page.
struct Redirecting;

impl HttpsHead for Redirecting {
    fn fetch(
        &self,
        target: Ipv4Addr,
        _server_name: &str,
        _source: Ipv4Addr,
        request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        Ok(if target == ip(1) {
            b"HTTP/1.1 302 Found\r\nLocation: https://passport.site.example/x?t=secret\r\n\r\n"
                .to_vec()
        } else {
            b"HTTP/1.1 200 OK\r\n\r\n".to_vec()
        })
    }
}

#[test]
fn where_the_site_sends_a_visitor_counts_as_its_sign_in() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("passport.site.example", vec![ip(2)]);
    f.https = Some(Arc::new(Redirecting));
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert!(report.reads_answer);
    assert_eq!(report.names[0].status, Some(302));
    assert_eq!(report.names[0].redirects, ["passport.site.example"]);
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_SIGN_IN_SPLIT);
    assert_eq!(report.move_names, ["passport.site.example"]);
}

/// The site and its sign-in send a visitor to each other for ever.
struct Looping;

impl HttpsHead for Looping {
    fn fetch(
        &self,
        target: Ipv4Addr,
        _server_name: &str,
        _source: Ipv4Addr,
        _request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        Ok(if target == ip(1) {
            b"HTTP/1.1 302 Found\r\nLocation: https://login.site.example/\r\n\r\n".to_vec()
        } else {
            b"HTTP/1.1 302 Found\r\nLocation: https://site.example/\r\n\r\n".to_vec()
        })
    }
}

/// A redirect loop while both names answer on one route is the site's own
/// doing: the network is fine, and the loop is shown once, not followed on.
#[test]
fn a_redirect_loop_on_one_working_route_is_the_site_not_the_network() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("login.site.example", vec![ip(2)]);
    f.https = Some(Arc::new(Looping));
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_FINE);
    assert!(report.move_names.is_empty());
    assert_eq!(report.names[0].status, Some(302));
    assert_eq!(
        report.names[0].redirects,
        ["login.site.example", "site.example"],
        "the loop ends where it closes"
    );
    assert!(names(&report).contains(&("login.site.example", "primary", "answered")));
}

/// Something on the route answers with a certificate the roots do not know.
struct Intercepted;

impl HttpsHead for Intercepted {
    fn fetch(
        &self,
        _target: Ipv4Addr,
        _server_name: &str,
        _source: Ipv4Addr,
        _request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        Err(HeadFailure::Untrusted)
    }
}

#[test]
fn a_certificate_that_does_not_verify_is_its_own_answer_and_nothing_more_is_read() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.https = Some(Arc::new(Intercepted));
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    assert_eq!(report.verdict, SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED);
    assert_eq!(report.names[0].answer, "certificate-untrusted");
    assert_eq!(report.names[0].status, None);
    assert!(report.names[0].redirects.is_empty());
}

#[test]
fn a_check_runs_once_per_caller_at_a_time_and_its_result_is_the_callers() {
    let f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    let checker = Arc::new(f.checker(routes(&[])));
    assert_eq!(checker.status(ALICE).state, SITE_CHECK_STATE_IDLE);

    let started = checker
        .start(ALICE, "site.example".to_owned())
        .expect("started");
    assert_eq!(started.state, SITE_CHECK_STATE_RUNNING);
    let deadline = Instant::now() + Duration::from_secs(10);
    while checker.status(ALICE).state != SITE_CHECK_STATE_DONE {
        assert!(Instant::now() < deadline, "the check never finished");
        std::thread::sleep(Duration::from_millis(5));
    }
    let done = checker.status(ALICE);
    assert_eq!(done.host, "site.example");
    assert_eq!(
        done.report.map(|r| r.verdict).as_deref(),
        Some(SITE_CHECK_VERDICT_FINE)
    );
    assert_eq!(
        checker.status(BOB).state,
        SITE_CHECK_STATE_IDLE,
        "another caller sees nothing of it"
    );
}

#[test]
fn a_second_start_while_running_is_refused() {
    let f = Fixture::new();
    let checker = Arc::new(f.checker(routes(&[])));
    checker.latest.lock().unwrap().insert(
        ALICE.to_owned(),
        SiteCheckStatus {
            state: SITE_CHECK_STATE_RUNNING.to_owned(),
            host: "site.example".to_owned(),
            report: None,
        },
    );
    assert_eq!(
        checker.start(ALICE, "other.example".to_owned()),
        Err(StartRefused::Busy)
    );
}

#[test]
fn only_a_dotted_host_name_is_checked() {
    assert_eq!(
        normalise_host(" Site.Example. ").as_deref(),
        Some("site.example")
    );
    for pasted in [
        "https://site.example/feed?x=1",
        "site.example:443",
        "//site.example#top",
    ] {
        assert_eq!(
            normalise_host(pasted).as_deref(),
            Some("site.example"),
            "{pasted}"
        );
    }
    assert_eq!(normalise_host("https://user@site.example/"), None);
    let long = "a".repeat(300);
    for bad in ["", "localhost", "203.0.113.1", "a b.example", long.as_str()] {
        assert_eq!(normalise_host(bad), None, "{bad}");
    }
}

#[test]
fn held_traffic_is_not_answered_for_by_the_services_own_socket() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("login.site.example", vec![ip(2)]);
    f.https = Some(Arc::new(Redirecting));
    f.traffic_held = Some(Arc::new(|sid: &str| sid == ALICE) as TrafficHeld);

    let report = f.checker(routes(&[])).check(ALICE, "site.example");

    assert_eq!(report.verdict, SITE_CHECK_VERDICT_ROUTE_DOWN);
    assert!(
        f.probe.asked.lock().unwrap().is_empty(),
        "nothing leaves while the caller's traffic is held"
    );
    assert!(
        report.names[0].redirects.is_empty(),
        "no HTTPS request either"
    );

    let other = f.checker(routes(&[])).check(BOB, "site.example");
    assert_eq!(
        other.verdict, SITE_CHECK_VERDICT_FINE,
        "only the held user's"
    );
}

#[test]
fn the_shared_cache_answers_only_for_names_the_callers_rules_or_traffic_name() {
    let mut f = Fixture::new();
    // Another user signed in here: the machine's cache knows their names.
    f.cache.set_ips("bank.example", vec![ip(1)]);
    f.cache.set_ips("login.bank.example", vec![ip(2)]);
    f.cache.set_ips("own.example", vec![ip(3)]);
    f.cache.set_ips("cdn.own.example", vec![ip(4)]);
    let ring = Arc::new(ConnectionTraceRing::new(16));
    ring.push(row(BOB, 2, &["login.bank.example"]));
    let mut v6 = row(ALICE, 9, &["cdn.own.example"]);
    v6.remote = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 443);
    ring.push(v6);
    f.trace = Some(ring);

    let report = f.checker(covering(&[])).check(ALICE, "bank.example");
    assert_eq!(report.names[0].answer, "no-address");
    assert!(
        report.names.iter().all(|n| n.address.is_empty()),
        "no address from somebody else's visit: {:?}",
        names(&report)
    );
    assert!(
        !report.names.iter().any(|n| n.name == "login.bank.example"),
        "a guessed sign-in nobody of the caller's used stays out"
    );
    assert!(f.probe.asked.lock().unwrap().is_empty());

    let report = f
        .checker(covering(&["own.example"]))
        .check(ALICE, "own.example");
    let address = |name: &str| {
        report
            .names
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.address.clone())
    };
    assert_eq!(
        address("own.example"),
        Some(ip(3).to_string()),
        "a rule names it"
    );
    assert_eq!(
        address("cdn.own.example"),
        Some(ip(4).to_string()),
        "the caller's own traffic named it"
    );
}

#[test]
fn only_a_rule_on_the_name_itself_counts_as_covering_it() {
    for yes in ["exact-fqdn", "suffix-domain", "zone"] {
        assert!(rule_matched_reason(&format!(
            "diag.explain.reason.rule-matched-{yes}"
        )));
    }
    for no in [
        "diag.explain.reason.rule-matched-exact-ip",
        "diag.explain.reason.rule-matched-subnet",
        "diag.explain.reason.blocked-by-ip-rule",
        "diag.explain.reason.no-rule-match",
        "diag.explain.reason.rules-paused",
        "diag.explain.reason.rule-shape-not-enforced",
        "diag.explain.reason.rule-withheld",
    ] {
        assert!(!rule_matched_reason(no), "{no}");
    }
}

#[test]
fn a_redirect_to_a_denied_name_never_sends_a_request_on_the_primary_link() {
    struct DeniedRedirect;
    impl HttpsHead for DeniedRedirect {
        fn fetch(
            &self,
            target: Ipv4Addr,
            _: &str,
            _: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            assert_eq!(target, ip(1), "a denied redirect must never be fetched");
            Ok(b"HTTP/1.1 302 Found\r\nLocation: https://passport.site.example/\r\n\r\n".to_vec())
        }
    }
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.cache.set_ips("passport.site.example", vec![ip(2)]);
    f.https = Some(Arc::new(DeniedRedirect));
    let report = f
        .checker(routes(&[
            ("site.example", "secondary"),
            ("passport.site.example", "blocked"),
        ]))
        .check(ALICE, "site.example");
    assert!(report
        .names
        .iter()
        .any(|n| n.name == "passport.site.example" && n.answer == "blocked"));
}

#[test]
fn cached_addresses_are_reported_without_claiming_a_fresh_dns_success() {
    let f = Fixture::new();
    f.cache.set_addresses(
        "site.example",
        vec![IpAddr::V4(ip(1)), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
    );
    let report = f.checker(routes(&[])).check(ALICE, "site.example");
    let value = serde_json::to_value(report).expect("wire report");
    assert_eq!(value["names"][0]["dns"], "cached");
    assert_eq!(
        value["names"][0]["real-addresses"],
        serde_json::json!([ip(1).to_string(), "::1"])
    );
}

#[test]
fn a_virtual_address_in_the_callers_trace_is_never_probed_as_a_real_destination() {
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    let ring = Arc::new(ConnectionTraceRing::new(16));
    let mut rec = row(ALICE, 1, &["site.example"]);
    rec.remote = SocketAddr::from(([198, 18, 0, 7], 443));
    ring.push(rec);
    f.trace = Some(ring);
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(report.names[0].address, ip(1).to_string());
    assert!(f
        .probe
        .asked
        .lock()
        .unwrap()
        .iter()
        .all(|(target, _, source)| *target == ip(1) && *source == Some(TUNNEL)));
}

#[test]
fn an_unknown_policy_never_falls_back_to_a_primary_probe() {
    let f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    let report = f
        .checker(routes(&[("site.example", "unknown")]))
        .check(ALICE, "site.example");
    assert!(f.probe.asked.lock().unwrap().is_empty());
    assert_eq!(report.names[0].answer, "unclear");
}

#[test]
fn a_server_failure_is_not_reported_as_a_healthy_site() {
    struct FailedServer;
    impl HttpsHead for FailedServer {
        fn fetch(
            &self,
            _: Ipv4Addr,
            _: &str,
            _: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            Ok(b"HTTP/1.1 503 Service Unavailable\r\n\r\n".to_vec())
        }
    }
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.https = Some(Arc::new(FailedServer));
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(report.verdict, "server-error");
    assert_eq!(report.names[0].status, Some(503));
}

#[test]
fn nov10_http_forbidden_is_an_access_refusal_not_a_healthy_page_or_network_silence() {
    struct Forbidden;
    impl HttpsHead for Forbidden {
        fn fetch(
            &self,
            _: Ipv4Addr,
            _: &str,
            _: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            Ok(b"HTTP/1.1 403 Forbidden\r\n\r\n".to_vec())
        }
    }
    let mut f = Fixture::new();
    f.cache.set_ips("site.example", vec![ip(1)]);
    f.https = Some(Arc::new(Forbidden));
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert_eq!(report.verdict, "http-refused");
    assert_eq!(report.names[0].status, Some(403));
    assert_eq!(report.names[0].route, "secondary");
    assert!(report.reads_answer);
    assert!(f
        .probe
        .asked
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .all(|(_, _, source)| *source == Some(TUNNEL)));
}

#[test]
fn nov10_a_local_bind_failure_is_not_counted_as_a_remote_https_silence() {
    struct CannotBind;
    impl PathProbe for CannotBind {
        fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
            PathVerdict::Indeterminate
        }
        fn connect_stream(
            &self,
            _: Ipv4Addr,
            _: u16,
            _: Ipv4Addr,
            _: Duration,
        ) -> Result<std::net::TcpStream, PathVerdict> {
            Err(PathVerdict::Indeterminate)
        }
    }
    let head = https_head::RustlsHttpsHead::new(Arc::new(CannotBind))
        .unwrap_or_else(|| panic!("TLS configuration"));
    let answer = head.fetch(
        ip(1),
        "site.example",
        MAIN,
        b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n",
        Duration::from_millis(100),
    );
    assert_eq!(
        format!("{:?}", answer.err()),
        "Some(Unavailable)",
        "a source-bind/setup failure gives no evidence of the site's behavior on that route"
    );
}

fn manual_http_guard_case(change_policy: bool) -> (SiteCheckReport, Vec<Ipv4Addr>) {
    use crate::auto_rules::{AutoRulesEngine, InMemoryDismissalStore, InMemoryPendingStore};
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};
    struct Heads {
        rules: Arc<ManualRules>,
        change_policy: bool,
        calls: Mutex<Vec<Ipv4Addr>>,
    }
    impl HttpsHead for Heads {
        fn fetch(
            &self,
            _: Ipv4Addr,
            host: &str,
            source: Ipv4Addr,
            _: &[u8],
            _: Duration,
        ) -> Result<Vec<u8>, HeadFailure> {
            let count = {
                let mut calls = self.calls.lock().unwrap_or_else(|p| p.into_inner());
                calls.push(source);
                calls.len()
            };
            if count == 1 || !self.change_policy {
                return Err(HeadFailure::NoAnswer);
            }
            self.rules
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .rule_book
                .secondary = CanonicalRuleSet::from_rules(vec![CanonicalRule {
                id: nrr_domain::RuleId("changed-to-secondary".into()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            }]);
            Ok(b"HTTP/1.1 200 OK\r\n\r\n".to_vec())
        }
    }
    let rules = Arc::new(ManualRules::default());
    let engine = Arc::new(AutoRulesEngine::new(
        rules.clone(),
        Arc::new(|_| nrr_storage::auto_rules::AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        std::time::SystemTime::now(),
    ));
    let f = Fixture::new();
    let host = if change_policy {
        "manual-policy-guard.example"
    } else {
        "manual-source-guard.example"
    };
    f.cache.set_ips(host, vec![ip(1)]);
    let https = Arc::new(Heads {
        rules: rules.clone(),
        change_policy,
        calls: Mutex::new(Vec::new()),
    });
    let checker = SiteChecker::new(SiteCheckWiring {
        probe: f.probe.clone(),
        egress: Arc::new(Links(
            Some(MAIN),
            Some(if change_policy { TUNNEL } else { MAIN }),
        )),
        cache: f.cache.clone(),
        routes: covering(&[]),
        engine: Some(engine),
        trace: None,
        https: Some(https.clone()),
        traffic_held: None,
    });
    checker.attach_manual(ManualSiteCheckWiring {
        rules,
        primary_default: Arc::new(|_| true),
        limits: Arc::new(|_| crate::path_probe::ProbeLimits::default()),
        os_cache: Arc::new(nrr_platform_api::dns::NoopDnsCacheRead),
        resolver_for: Arc::new(|_| panic!("cached")),
    });
    let report = checker.check(ALICE, host);
    let calls = https
        .calls
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    (report, calls)
}

#[test]
fn nov10_manual_http_guard_never_relabels_the_primary_source_as_an_additional_channel() {
    let (_, calls) = manual_http_guard_case(false);
    assert_eq!(calls,[MAIN],"equal source addresses cannot establish an additional path; no comparison requests are sent");
}

#[test]
fn nov10_manual_http_guard_discards_a_retry_result_after_the_rule_changes_to_secondary() {
    let (report, calls) = manual_http_guard_case(true);
    assert!(
        report.names[0].status.is_none(),
        "a result whose policy changed during the request cannot be credited to the current route"
    );
    assert_eq!(
        calls,
        [MAIN, MAIN],
        "no further comparison is allowed after the rule changes"
    );
}

#[test]
fn nov10_a_required_secondary_route_is_not_probed_with_an_ambiguous_primary_source() {
    let mut f = Fixture::new();
    f.links = (Some(MAIN), Some(MAIN));
    f.cache.set_ips("site.example", vec![ip(1)]);
    let report = f
        .checker(routes(&[("site.example", "secondary")]))
        .check(ALICE, "site.example");
    assert!(
        f.probe
            .asked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty(),
        "a required additional route must never fall back to an indistinguishable primary source"
    );
    assert_eq!(report.verdict, "route-down");
}

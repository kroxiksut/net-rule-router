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

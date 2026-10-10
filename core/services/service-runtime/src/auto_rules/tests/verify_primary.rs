//! `?` rules: checked on the link they are written for, only after the user
//! used a destination; a verdict is offered, enforced until restart, and
//! written only when the user accepts it.
//!
//! Tests that read the enforcement overlay use their own principal: it is
//! process-wide.

use super::*;
use crate::path_probe::{PathProbe, PathVerdict};
use crate::production_auto_rule_probe::EgressSources;
use nrr_shared::RuleOrigin;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const MAIN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ADDITIONAL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const HOST_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);

/// Answers per source link; records every probe.
struct LinkProbe {
    main: PathVerdict,
    additional: PathVerdict,
    tls: Mutex<Vec<(String, Ipv4Addr)>>,
    tcp: Mutex<Vec<(Ipv4Addr, u16, Ipv4Addr)>>,
}

impl LinkProbe {
    fn new(main: PathVerdict, additional: PathVerdict) -> Arc<Self> {
        Arc::new(Self {
            main,
            additional,
            tls: Mutex::new(Vec::new()),
            tcp: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, Ipv4Addr)> {
        self.tls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn tcp_calls(&self) -> Vec<(Ipv4Addr, u16, Ipv4Addr)> {
        self.tcp.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn answer(&self, source: Ipv4Addr) -> PathVerdict {
        if source == MAIN {
            self.main
        } else {
            self.additional
        }
    }
}

impl PathProbe for LinkProbe {
    fn probe(
        &self,
        target: Ipv4Addr,
        port: u16,
        source: Option<Ipv4Addr>,
        _: Duration,
    ) -> PathVerdict {
        let source = source.expect("a check always names its link");
        self.tcp
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((target, port, source));
        self.answer(source)
    }

    fn probe_tls(
        &self,
        _target: Ipv4Addr,
        server_name: &str,
        source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PathVerdict {
        let source = source.expect("a check always names its link");
        self.tls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((server_name.to_owned(), source));
        self.answer(source)
    }
}

struct BothLinks;

impl EgressSources for BothLinks {
    fn egress_source_ips(&self, _sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        (Some(MAIN), Some(ADDITIONAL))
    }
}

fn verify_rule(suffix: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(format!("r-verify-{suffix}")),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix.into())),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Verify,
        origin: None,
    }
}

fn verify_ip(ip: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(format!("r-verify-{ip}")),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Verify,
        origin: None,
    }
}

/// A book with `primary` on the main route and `secondary` on the other one.
fn book_with(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> Arc<FixedRules> {
    let rules = FixedRules::with_secondary(secondary);
    rules.book.lock().unwrap_or_else(|p| p.into_inner()).primary =
        CanonicalRuleSet::from_rules(primary);
    rules
}

/// The bundled shape: `?` rules on the main route.
fn main_route_book() -> Arc<FixedRules> {
    book_with(
        vec![
            verify_rule("proton.example"),
            CanonicalRule {
                action: RuleAction::Verify,
                ..exact_rule("site.example")
            },
        ],
        vec![exact_rule("chat.example")],
    )
}

struct Setup {
    rules: Arc<FixedRules>,
    engine: AutoRulesEngine,
    probe: Arc<LinkProbe>,
    author: Arc<RecordingAuthor>,
    reapplied: Arc<Mutex<Vec<String>>>,
    bus: Arc<EventBus>,
    subscription: String,
}

impl Setup {
    fn pushed_counts(&self) -> Vec<u64> {
        self.bus
            .peek_pending_for(&self.subscription, 100)
            .into_iter()
            .filter_map(|e| match e.event {
                StatusUpdateEvent::VerifyVerdictsChanged { pending_count, .. } => {
                    Some(pending_count)
                }
                _ => None,
            })
            .collect()
    }

    fn reapplied(&self) -> usize {
        self.reapplied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

fn setup_over(
    sid: &str,
    rules: Arc<dyn RulesProvider>,
    book: Arc<FixedRules>,
    probe: Arc<LinkProbe>,
    egress: Arc<dyn EgressSources>,
    subdomains: bool,
) -> Setup {
    let bus = Arc::new(EventBus::new());
    let subscription = bus
        .subscribe_as("test-client".to_string(), Some(sid.to_string()), None)
        .subscription_id;
    let engine = AutoRulesEngine::new(
        rules,
        mode_fn(AutoRulesMode::Off),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));
    let author = RecordingAuthor::new(Arc::clone(&book));
    engine.attach_author(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>);
    let reapplied = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&reapplied);
    engine.attach_verify_primary(crate::auto_rules::VerifyPrimaryWiring {
        probe: Arc::clone(&probe) as Arc<dyn PathProbe>,
        egress,
        include_subdomains: Arc::new(move |_sid: &str| subdomains),
        reapply: Some(Arc::new(move |sid: &str| {
            log.lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(sid.to_owned());
        })),
    });
    // The first tick reads the `?` rules; queries are only noted after it.
    engine.tick(sid, later());
    Setup {
        rules: book,
        engine,
        probe,
        author,
        reapplied,
        bus,
        subscription,
    }
}

fn setup(sid: &str, book: Arc<FixedRules>, main: PathVerdict, additional: PathVerdict) -> Setup {
    let probe = LinkProbe::new(main, additional);
    setup_over(
        sid,
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        book,
        probe,
        Arc::new(BothLinks),
        true,
    )
}

/// The rule with `id` and the route it stands on.
fn find(rules: &FixedRules, id: &str) -> Option<(RouteRole, CanonicalRule)> {
    let book = rules.book.lock().unwrap_or_else(|p| p.into_inner());
    for (role, set) in [
        (RouteRole::Primary, &book.primary),
        (RouteRole::Secondary, &book.secondary),
    ] {
        if let Some(rule) = set.rules().iter().find(|r| r.id.0 == id) {
            return Some((role, rule.clone()));
        }
    }
    None
}

fn after(secs: u64) -> SystemTime {
    later() + Duration::from_secs(secs)
}

fn moved_ids(sid: &str) -> Vec<String> {
    crate::verify_overlay::moved_for(sid)
        .1
        .iter()
        .map(|id| id.0.clone())
        .collect()
}

// ── Verdicts ─────────────────────────────────────────────────────────────────

#[test]
fn a_main_route_rule_that_does_not_open_there_gets_a_verdict_not_a_rewrite() {
    let sid = "S-verify-main";
    let s = setup(
        sid,
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    s.engine
        .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);

    s.engine.tick(sid, later());
    assert!(
        s.engine.verify_verdicts(sid).is_empty(),
        "one lost hello is not a verdict"
    );
    s.engine.tick(sid, later());
    assert_eq!(
        s.probe.calls(),
        vec![
            ("mail.proton.example".to_string(), MAIN),
            ("mail.proton.example".to_string(), MAIN),
            ("mail.proton.example".to_string(), ADDITIONAL),
        ]
    );
    let verdicts = s.engine.verify_verdicts(sid);
    assert_eq!(verdicts.len(), 1);
    let v = &verdicts[0];
    assert_eq!(v.rule_id, "r-verify-proton.example");
    assert_eq!(v.value, "*.proton.example");
    assert_eq!(v.kind, "domain");
    assert_eq!(
        (v.from_route.as_str(), v.to_route.as_str()),
        ("primary", "secondary")
    );
    assert_eq!(v.host, "mail.proton.example");
    assert!(!v.dismissed);

    let (role, rule) = find(&s.rules, "r-verify-proton.example").expect("rule kept");
    assert_eq!(role, RouteRole::Primary, "nothing is written silently");
    assert_eq!(rule.action, RuleAction::Verify);
    assert_eq!(moved_ids(sid), ["r-verify-proton.example"]);
    assert_eq!(s.reapplied(), 1, "the move takes effect now");
    assert_eq!(s.pushed_counts(), [1]);
}

#[test]
fn the_service_tick_checks_every_present_user() {
    // Linux names each logged-in user; a tick bound to one console user left
    // every `?` rule there unchecked.
    let users = ["S-verify-tick-a", "S-verify-tick-b"];
    let s = setup(
        users[0],
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    for sid in users {
        s.engine
            .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);
    }
    let engine = Arc::new(s.engine);
    let mut task = crate::service_tasks::build_auto_rules_task(
        Arc::clone(&engine),
        Arc::new(move || users.iter().map(|u| (*u).to_owned()).collect()),
        None,
    );
    let stop = crate::lifecycle::StopToken::new();
    for _ in 0..2 {
        (task.tick)(&stop);
    }
    for sid in users {
        assert_eq!(engine.verify_verdicts(sid).len(), 1, "{sid}");
    }
}

#[test]
fn an_additional_route_rule_is_checked_there_and_offered_the_main_one() {
    let sid = "S-verify-additional";
    let s = setup(
        sid,
        book_with(Vec::new(), vec![verify_rule("proton.example")]),
        PathVerdict::Answered,
        PathVerdict::Silent,
    );
    s.engine
        .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(sid, later());
    s.engine.tick(sid, later());
    assert_eq!(
        s.probe.calls(),
        vec![
            ("mail.proton.example".to_string(), ADDITIONAL),
            ("mail.proton.example".to_string(), ADDITIONAL),
            ("mail.proton.example".to_string(), MAIN),
        ]
    );
    let verdicts = s.engine.verify_verdicts(sid);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(
        (
            verdicts[0].from_route.as_str(),
            verdicts[0].to_route.as_str()
        ),
        ("secondary", "primary")
    );
}

/// The GUI's "domain" type is stored as an exact rule that covers subdomains
/// through the user's setting; the check must see `www.` under it the same way.
#[test]
fn an_exact_rule_covers_its_subdomains_when_the_user_routes_them() {
    let on = setup(
        "S-verify-sub-on",
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    on.engine
        .note_verify_candidate("S-verify-sub-on", "www.site.example", &[HOST_IP]);
    on.engine.tick("S-verify-sub-on", later());
    on.engine.tick("S-verify-sub-on", later());
    let verdicts = on.engine.verify_verdicts("S-verify-sub-on");
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].rule_id, "r-site.example");

    let book = main_route_book();
    let off = setup_over(
        "S-verify-sub-off",
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        book,
        LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered),
        Arc::new(BothLinks),
        false,
    );
    off.engine
        .note_verify_candidate("S-verify-sub-off", "www.site.example", &[HOST_IP]);
    off.engine.tick("S-verify-sub-off", later());
    off.engine.tick("S-verify-sub-off", later());
    assert!(off.engine.verify_verdicts("S-verify-sub-off").is_empty());
    assert!(off.probe.calls().is_empty(), "not a host the rule routes");
}

/// A query that arrives before the `?` rules are read is not lost: it counts
/// as soon as they are.
#[test]
fn a_query_before_the_rules_are_read_still_counts() {
    let rules = book_with(vec![verify_rule("proton.example")], Vec::new());
    let engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Off),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    engine.attach_author(RecordingAuthor::new(Arc::clone(&rules)) as Arc<dyn AutoRuleAuthor>);
    let probe = LinkProbe::new(PathVerdict::Answered, PathVerdict::Answered);
    engine.attach_verify_primary(crate::auto_rules::VerifyPrimaryWiring {
        probe: Arc::clone(&probe) as Arc<dyn PathProbe>,
        egress: Arc::new(BothLinks),
        include_subdomains: Arc::new(|_sid: &str| true),
        reapply: None,
    });
    // No tick yet: the rules have not been read.
    engine.note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    engine.tick(SID, later());
    assert_eq!(
        probe.calls(),
        vec![("mail.proton.example".to_string(), MAIN)]
    );
}

#[test]
fn a_host_down_on_both_links_gets_no_verdict() {
    let s = setup(
        SID,
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Silent,
    );
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine.tick(SID, later());
    assert!(s.engine.verify_verdicts(SID).is_empty());
    assert_eq!(s.probe.calls().len(), 3);
}

#[test]
fn a_host_its_route_reaches_is_not_asked_again_soon() {
    let s = setup(
        SID,
        main_route_book(),
        PathVerdict::Answered,
        PathVerdict::Answered,
    );
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    assert!(s.engine.verify_verdicts(SID).is_empty());
    assert_eq!(s.probe.calls().len(), 1, "remembered for this link");
}

#[test]
fn only_hosts_under_a_question_mark_rule_are_ever_probed() {
    let s = setup(
        SID,
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    s.engine
        .note_verify_candidate(SID, "chat.example", &[HOST_IP]);
    s.engine
        .note_verify_candidate(SID, "other.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine.tick(SID, later());
    assert!(s.probe.calls().is_empty());
}

#[test]
fn a_destination_with_a_live_verdict_is_not_probed_again() {
    let sid = "S-verify-no-reprobe";
    let s = setup(
        sid,
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    s.engine
        .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(sid, after(1));
    s.engine.tick(sid, after(2));
    assert_eq!(s.probe.calls().len(), 3);
    s.engine
        .note_verify_candidate(sid, "imap.proton.example", &[HOST_IP]);
    s.engine.tick(sid, after(120));
    assert_eq!(s.probe.calls().len(), 3, "the rule already has its answer");
}

#[test]
fn a_disabled_question_mark_rule_is_never_checked() {
    let s = setup(
        SID,
        book_with(
            vec![
                verify_rule("proton.example"),
                CanonicalRule {
                    enabled: false,
                    ..verify_rule("mail.proton.example")
                },
            ],
            Vec::new(),
        ),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, after(1));
    s.engine.tick(SID, after(2));
    let ids: Vec<String> = s
        .engine
        .verify_verdicts(SID)
        .into_iter()
        .map(|v| v.rule_id)
        .collect();
    assert_eq!(ids, ["r-verify-proton.example"]);
}

// ── Answers ──────────────────────────────────────────────────────────────────

fn with_verdict(sid: &str, book: Arc<FixedRules>) -> Setup {
    let s = setup(sid, book, PathVerdict::Silent, PathVerdict::Answered);
    s.engine
        .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(sid, after(1));
    s.engine.tick(sid, after(2));
    assert_eq!(s.engine.verify_verdicts(sid).len(), 1, "fixture: a verdict");
    s
}

#[test]
fn accepting_moves_the_rule_to_the_other_route_with_its_id_and_origin() {
    let sid = "S-verify-accept";
    let origin = RuleOrigin::auto(
        AutoRuleReason::SiteCompanion,
        "proton.example",
        "2026-07-31",
    );
    let s = with_verdict(
        sid,
        book_with(
            vec![CanonicalRule {
                origin: Some(origin.clone()),
                ..verify_rule("proton.example")
            }],
            Vec::new(),
        ),
    );
    let moved = s
        .engine
        .accept_verify_verdicts(sid, &["r-verify-proton.example".to_string()], after(3))
        .expect("accepted");
    assert_eq!(moved, 1);
    let (role, rule) = find(&s.rules, "r-verify-proton.example").expect("rule kept");
    assert_eq!(role, RouteRole::Secondary);
    assert_eq!(rule.action, RuleAction::Route);
    assert_eq!(rule.origin, Some(origin));
    assert!(s.engine.verify_verdicts(sid).is_empty());
    assert!(moved_ids(sid).is_empty());
    assert_eq!(s.pushed_counts(), [1, 0]);
}

#[test]
fn accepting_next_to_a_plain_twin_drops_the_question_mark_copy() {
    let sid = "S-verify-twin";
    let twin = CanonicalRule {
        id: RuleId("r-plain".into()),
        ..CanonicalRule {
            action: RuleAction::Route,
            ..verify_rule("proton.example")
        }
    };
    let s = with_verdict(
        sid,
        book_with(vec![verify_rule("proton.example")], vec![twin]),
    );
    let moved = s
        .engine
        .accept_verify_verdicts(sid, &["r-verify-proton.example".to_string()], after(3))
        .expect("accepted");
    assert_eq!(moved, 1);
    assert!(find(&s.rules, "r-verify-proton.example").is_none());
    let book = s.rules.book.lock().unwrap_or_else(|p| p.into_inner());
    assert!(book.primary.is_empty());
    assert_eq!(book.secondary.len(), 1);
}

#[test]
fn a_refused_accept_keeps_the_verdict() {
    let sid = "S-verify-refused";
    let s = with_verdict(sid, main_route_book());
    s.author.fail("rules-locked");
    let err = s
        .engine
        .accept_verify_verdicts(sid, &["r-verify-proton.example".to_string()], after(3))
        .expect_err("refused");
    assert_eq!(err.code, "rules-locked");
    assert_eq!(s.engine.verify_verdicts(sid).len(), 1);
    assert_eq!(moved_ids(sid), ["r-verify-proton.example"]);
    let (role, _) = find(&s.rules, "r-verify-proton.example").expect("rule kept");
    assert_eq!(role, RouteRole::Primary);
}

#[test]
fn not_now_keeps_the_move_and_clears_the_count() {
    let sid = "S-verify-dismiss";
    let s = with_verdict(sid, main_route_book());
    let ids = ["r-verify-proton.example".to_string()];
    assert_eq!(s.engine.dismiss_verify_verdicts(sid, &ids), 1);
    assert_eq!(
        s.engine.dismiss_verify_verdicts(sid, &ids),
        0,
        "already said"
    );
    let verdicts = s.engine.verify_verdicts(sid);
    assert_eq!(verdicts.len(), 1);
    assert!(verdicts[0].dismissed);
    assert_eq!(moved_ids(sid), ["r-verify-proton.example"]);
    assert_eq!(s.pushed_counts(), [1, 0]);
    assert_eq!(s.reapplied(), 1, "nothing enforced changed");
}

// ── Rule edits ───────────────────────────────────────────────────────────────

/// A provider that names its stored book and counts how often it is decoded.
struct NamedRules {
    book: Arc<FixedRules>,
    revision: Mutex<String>,
    reads: std::sync::atomic::AtomicUsize,
}

impl NamedRules {
    fn new(book: Arc<FixedRules>) -> Arc<Self> {
        Arc::new(Self {
            book,
            revision: Mutex::new("rev-1".into()),
            reads: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// The user saved `rules` on the main route as a new revision.
    fn save(&self, rules: Vec<CanonicalRule>, revision: &str) {
        self.book
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .primary = CanonicalRuleSet::from_rules(rules);
        *self.revision.lock().unwrap_or_else(|p| p.into_inner()) = revision.into();
    }
}

impl RulesProvider for NamedRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        self.book.active_rules()
    }

    fn stored_rules_for(&self, _principal: &str) -> Option<ActiveRulesSnapshot> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.book.active_rules()
    }

    fn stored_revision_for(&self, _principal: &str) -> Option<String> {
        Some(
            self.revision
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone(),
        )
    }
}

fn named_setup(
    sid: &str,
    book: Arc<FixedRules>,
    egress: Arc<dyn EgressSources>,
) -> (Setup, Arc<NamedRules>) {
    let named = NamedRules::new(Arc::clone(&book));
    let s = setup_over(
        sid,
        Arc::clone(&named) as Arc<dyn RulesProvider>,
        book,
        LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered),
        egress,
        true,
    );
    (s, named)
}

#[test]
fn editing_the_rule_drops_its_verdict_and_the_move() {
    let sid = "S-verify-edit";
    let (s, named) = named_setup(
        sid,
        book_with(vec![verify_rule("proton.example")], Vec::new()),
        Arc::new(BothLinks),
    );
    s.engine
        .note_verify_candidate(sid, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(sid, after(1));
    s.engine.tick(sid, after(2));
    assert_eq!(moved_ids(sid), ["r-verify-proton.example"]);

    // Same id, another value.
    named.save(
        vec![CanonicalRule {
            address_match: Some(CanonicalAddressMatch::SuffixDomain("mail.example".into())),
            ..verify_rule("proton.example")
        }],
        "rev-2",
    );
    s.engine.tick(sid, after(3));
    assert!(s.engine.verify_verdicts(sid).is_empty());
    assert!(moved_ids(sid).is_empty());
    assert_eq!(s.reapplied(), 2, "back where it is written, now");
    assert_eq!(s.pushed_counts(), [1, 0]);
}

// ── Addresses ────────────────────────────────────────────────────────────────

#[test]
fn an_address_rule_is_checked_on_the_port_its_connection_used() {
    let sid = "S-verify-ip";
    let s = setup(
        sid,
        book_with(vec![verify_ip(HOST_IP)], Vec::new()),
        PathVerdict::Silent,
        PathVerdict::Answered,
    );
    let remote = SocketAddr::new(IpAddr::V4(HOST_IP), 8443);
    s.engine.note_verify_connection(sid, remote);
    // Another address and another user are no candidates.
    s.engine
        .note_verify_connection(sid, SocketAddr::new(IpAddr::V4(MAIN), 443));
    s.engine.note_verify_connection("S-verify-other", remote);
    s.engine.tick(sid, after(1));
    s.engine.note_verify_connection(sid, remote);
    s.engine.tick(sid, after(2));
    assert_eq!(
        s.probe.tcp_calls(),
        vec![
            (HOST_IP, 8443, MAIN),
            (HOST_IP, 8443, MAIN),
            (HOST_IP, 8443, ADDITIONAL)
        ]
    );
    assert!(s.probe.calls().is_empty(), "an address has no name to send");
    let verdicts = s.engine.verify_verdicts(sid);
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0].kind, "ip");
    assert_eq!(verdicts[0].value, "203.0.113.5");
    assert_eq!(moved_ids(sid), ["r-verify-203.0.113.5"]);
}

// ── What a step costs, and how often a destination is asked ─────────────────

/// Link addresses with a read counter; `additional` says whether the
/// additional link is up.
struct CountedLinks {
    additional: bool,
    reads: std::sync::atomic::AtomicUsize,
}

impl CountedLinks {
    fn new(additional: bool) -> Arc<Self> {
        Arc::new(Self {
            additional,
            reads: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl EgressSources for CountedLinks {
    fn egress_source_ips(&self, _sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
        self.reads.fetch_add(1, Ordering::SeqCst);
        (Some(MAIN), self.additional.then_some(ADDITIONAL))
    }
}

#[test]
fn with_no_question_mark_rule_a_step_reads_no_link_and_decodes_the_book_once() {
    let links = CountedLinks::new(true);
    let (s, named) = named_setup(
        SID,
        book_with(vec![exact_rule("chat.example")], Vec::new()),
        Arc::clone(&links) as Arc<dyn EgressSources>,
    );
    s.engine
        .note_verify_candidate(SID, "chat.example", &[HOST_IP]);
    s.engine
        .note_verify_connection(SID, SocketAddr::new(IpAddr::V4(HOST_IP), 443));
    for secs in [10, 20, 120] {
        s.engine.tick(SID, after(secs));
    }
    assert_eq!(named.reads(), 1, "the unchanged book is not decoded again");
    assert_eq!(links.reads(), 0, "nothing waits, so no link is read");

    // Positive control: a saved `?` rule is read at once, and its host checked.
    named.save(vec![verify_rule("proton.example")], "rev-2");
    s.engine.tick(SID, after(130));
    assert_eq!(named.reads(), 2);
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, after(140));
    assert_eq!(links.reads(), 1);
    assert_eq!(s.probe.calls().len(), 1);
}

/// The cheap path: a principal with no `?` rule keeps no buffer of its
/// queries, so one made before the rule was saved does not count for it.
#[test]
fn a_principal_without_question_mark_rules_keeps_no_query_buffer() {
    let (s, named) = named_setup(
        SID,
        book_with(vec![exact_rule("chat.example")], Vec::new()),
        Arc::new(BothLinks),
    );
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    named.save(vec![verify_rule("proton.example")], "rev-2");
    s.engine.tick(SID, after(10));
    assert!(s.probe.calls().is_empty());
}

#[test]
fn a_check_that_settles_nothing_waits_and_the_wait_doubles() {
    let s = setup(
        SID,
        main_route_book(),
        PathVerdict::Silent,
        PathVerdict::Silent,
    );
    let host = "mail.proton.example";
    s.engine.note_verify_candidate(SID, host, &[HOST_IP]);
    s.engine.tick(SID, after(0));
    s.engine.tick(SID, after(1));
    assert_eq!(s.probe.calls().len(), 3, "two misses and the control");

    // Queried again at once: not probed while the first minute runs.
    s.engine.note_verify_candidate(SID, host, &[HOST_IP]);
    s.engine.tick(SID, after(2));
    assert_eq!(s.probe.calls().len(), 3);

    // Positive control: after the wait it is checked again.
    s.engine.note_verify_candidate(SID, host, &[HOST_IP]);
    s.engine.tick(SID, after(61));
    s.engine.tick(SID, after(62));
    assert_eq!(s.probe.calls().len(), 6);

    // Settled nothing twice: two minutes now.
    s.engine.note_verify_candidate(SID, host, &[HOST_IP]);
    s.engine.tick(SID, after(62 + 61));
    assert_eq!(s.probe.calls().len(), 6);
    s.engine.note_verify_candidate(SID, host, &[HOST_IP]);
    s.engine.tick(SID, after(62 + 120));
    assert_eq!(s.probe.calls().len(), 7);
}

#[test]
fn without_the_additional_link_nothing_is_probed() {
    let links = CountedLinks::new(false);
    let book = main_route_book();
    let s = setup_over(
        SID,
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        book,
        LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered),
        Arc::clone(&links) as Arc<dyn EgressSources>,
        true,
    );
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, after(1));
    s.engine.tick(SID, after(2));
    assert_eq!(links.reads(), 1, "read while the host waited");
    assert!(s.probe.calls().is_empty(), "no check could conclude");
}

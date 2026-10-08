//! `?host` rules: checked only after the user's DNS asked for a host, moved to
//! the additional route only on proof.

use super::*;
use crate::path_probe::{PathProbe, PathVerdict};
use crate::production_auto_rule_probe::EgressSources;
use std::net::Ipv4Addr;

const MAIN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ADDITIONAL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const HOST_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);

/// Answers per source link; records every TLS probe.
struct LinkProbe {
    main: PathVerdict,
    additional: PathVerdict,
    calls: Mutex<Vec<(String, Ipv4Addr)>>,
}

impl LinkProbe {
    fn new(main: PathVerdict, additional: PathVerdict) -> Arc<Self> {
        Arc::new(Self {
            main,
            additional,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, Ipv4Addr)> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl PathProbe for LinkProbe {
    fn probe(&self, _: Ipv4Addr, _: u16, _: Option<Ipv4Addr>, _: Duration) -> PathVerdict {
        PathVerdict::Indeterminate
    }

    fn probe_tls(
        &self,
        _target: Ipv4Addr,
        server_name: &str,
        source: Option<Ipv4Addr>,
        _timeout: Duration,
    ) -> PathVerdict {
        let source = source.expect("a check always names its link");
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((server_name.to_owned(), source));
        if source == MAIN {
            self.main
        } else {
            self.additional
        }
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
        action: RuleAction::VerifyPrimary,
        origin: None,
    }
}

struct Setup {
    rules: Arc<FixedRules>,
    engine: AutoRulesEngine,
    probe: Arc<LinkProbe>,
}

fn setup(main: PathVerdict, additional: PathVerdict) -> Setup {
    setup_with(main, additional, true)
}

fn setup_with(main: PathVerdict, additional: PathVerdict, subdomains: bool) -> Setup {
    let rules = FixedRules::with_secondary(vec![
        verify_rule("proton.example"),
        exact_rule("chat.example"),
        CanonicalRule {
            action: RuleAction::VerifyPrimary,
            ..exact_rule("site.example")
        },
    ]);
    let engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Off),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    engine.attach_author(RecordingAuthor::new(Arc::clone(&rules)) as Arc<dyn AutoRuleAuthor>);
    let probe = LinkProbe::new(main, additional);
    engine.attach_verify_primary(crate::auto_rules::VerifyPrimaryWiring {
        probe: Arc::clone(&probe) as Arc<dyn PathProbe>,
        egress: Arc::new(BothLinks),
        include_subdomains: Arc::new(move |_sid: &str| subdomains),
    });
    // The first tick reads the `?` rules; queries are only noted after it.
    engine.tick(SID, later());
    Setup {
        rules,
        engine,
        probe,
    }
}

fn action_of(rules: &FixedRules, suffix: &str) -> RuleAction {
    rules
        .book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .secondary
        .rules()
        .iter()
        .find(|r| r.id.0 == format!("r-verify-{suffix}"))
        .expect("rule present")
        .action
}

#[test]
fn a_host_the_main_link_cannot_reach_moves_its_rule_after_two_misses_and_a_control() {
    let s = setup(PathVerdict::Silent, PathVerdict::Answered);
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);

    s.engine.tick(SID, later());
    assert_eq!(
        action_of(&s.rules, "proton.example"),
        RuleAction::VerifyPrimary,
        "one lost hello is not a verdict"
    );
    s.engine.tick(SID, later());
    assert_eq!(action_of(&s.rules, "proton.example"), RuleAction::Route);
    assert_eq!(
        s.probe.calls(),
        vec![
            ("mail.proton.example".to_string(), MAIN),
            ("mail.proton.example".to_string(), MAIN),
            ("mail.proton.example".to_string(), ADDITIONAL),
        ]
    );
}

/// The GUI's "domain" type is stored as an exact rule that covers subdomains
/// through the user's setting; the check must see `www.` under it the same way.
#[test]
fn an_exact_rule_covers_its_subdomains_when_the_user_routes_them() {
    let action = |rules: &FixedRules| {
        rules
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .secondary
            .rules()
            .iter()
            .find(|r| r.id.0 == "r-site.example")
            .expect("rule present")
            .action
    };
    let on = setup_with(PathVerdict::Silent, PathVerdict::Answered, true);
    on.engine
        .note_verify_candidate(SID, "www.site.example", &[HOST_IP]);
    on.engine.tick(SID, later());
    on.engine.tick(SID, later());
    assert_eq!(action(&on.rules), RuleAction::Route);

    let off = setup_with(PathVerdict::Silent, PathVerdict::Answered, false);
    off.engine
        .note_verify_candidate(SID, "www.site.example", &[HOST_IP]);
    off.engine.tick(SID, later());
    off.engine.tick(SID, later());
    assert_eq!(action(&off.rules), RuleAction::VerifyPrimary);
    assert!(off.probe.calls().is_empty(), "not a host the rule routes");
}

/// A query that arrives before the `?` rules are read is not lost: it counts
/// as soon as they are.
#[test]
fn a_query_before_the_rules_are_read_still_counts() {
    let rules = FixedRules::with_secondary(vec![verify_rule("proton.example")]);
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
fn a_host_down_on_both_links_keeps_its_rule() {
    let s = setup(PathVerdict::Silent, PathVerdict::Silent);
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine.tick(SID, later());
    assert_eq!(
        action_of(&s.rules, "proton.example"),
        RuleAction::VerifyPrimary
    );
}

#[test]
fn a_host_the_main_link_reaches_stays_and_is_not_asked_again_soon() {
    let s = setup(PathVerdict::Answered, PathVerdict::Answered);
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine
        .note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    assert_eq!(
        action_of(&s.rules, "proton.example"),
        RuleAction::VerifyPrimary
    );
    assert_eq!(s.probe.calls().len(), 1, "remembered for this main link");
}

#[test]
fn only_hosts_under_a_question_mark_rule_are_ever_probed() {
    let s = setup(PathVerdict::Silent, PathVerdict::Answered);
    s.engine
        .note_verify_candidate(SID, "chat.example", &[HOST_IP]);
    s.engine
        .note_verify_candidate(SID, "other.example", &[HOST_IP]);
    s.engine.tick(SID, later());
    s.engine.tick(SID, later());
    assert!(s.probe.calls().is_empty());
}

// ── What a step costs, and how often a host is asked ─────────────────────────

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

    /// The user saved `rules` as a new revision.
    fn save(&self, rules: Vec<CanonicalRule>, revision: &str) {
        self.book
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .secondary = CanonicalRuleSet::from_rules(rules);
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

/// An engine over `rules`, its author writing into `book`, after the first
/// tick has read the `?` rules.
fn engine_over(
    rules: Arc<dyn RulesProvider>,
    book: &Arc<FixedRules>,
    probe: &Arc<LinkProbe>,
    egress: Arc<dyn EgressSources>,
) -> (AutoRulesEngine, Arc<RecordingAuthor>) {
    let engine = AutoRulesEngine::new(
        rules,
        mode_fn(AutoRulesMode::Off),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    let author = RecordingAuthor::new(Arc::clone(book));
    engine.attach_author(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>);
    engine.attach_verify_primary(crate::auto_rules::VerifyPrimaryWiring {
        probe: Arc::clone(probe) as Arc<dyn PathProbe>,
        egress,
        include_subdomains: Arc::new(|_sid: &str| true),
    });
    engine.tick(SID, later());
    (engine, author)
}

fn after(secs: u64) -> SystemTime {
    later() + Duration::from_secs(secs)
}

#[test]
fn with_no_question_mark_rule_a_step_reads_no_link_and_decodes_the_book_once() {
    let book = FixedRules::with_secondary(vec![exact_rule("chat.example")]);
    let named = NamedRules::new(Arc::clone(&book));
    let links = CountedLinks::new(true);
    let probe = LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered);
    let (engine, _) = engine_over(
        Arc::clone(&named) as Arc<dyn RulesProvider>,
        &book,
        &probe,
        Arc::clone(&links) as Arc<dyn EgressSources>,
    );
    engine.note_verify_candidate(SID, "chat.example", &[HOST_IP]);
    for secs in [10, 20, 120] {
        engine.tick(SID, after(secs));
    }
    assert_eq!(named.reads(), 1, "the unchanged book is not decoded again");
    assert_eq!(links.reads(), 0, "nothing waits, so no link is read");

    // Positive control: a saved `?` rule is read at once, and its host checked.
    named.save(vec![verify_rule("proton.example")], "rev-2");
    engine.tick(SID, after(130));
    assert_eq!(named.reads(), 2);
    engine.note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    engine.tick(SID, after(140));
    assert_eq!(links.reads(), 1);
    assert_eq!(probe.calls().len(), 1);
}

/// The cheap path: a principal with no `?` rule keeps no buffer of its
/// queries, so one made before the rule was saved does not count for it.
#[test]
fn a_principal_without_question_mark_rules_keeps_no_query_buffer() {
    let book = FixedRules::with_secondary(vec![exact_rule("chat.example")]);
    let named = NamedRules::new(Arc::clone(&book));
    let probe = LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered);
    let (engine, _) = engine_over(
        Arc::clone(&named) as Arc<dyn RulesProvider>,
        &book,
        &probe,
        Arc::new(BothLinks),
    );
    engine.note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    named.save(vec![verify_rule("proton.example")], "rev-2");
    engine.tick(SID, after(10));
    assert!(probe.calls().is_empty());
}

#[test]
fn a_check_that_settles_nothing_waits_and_the_wait_doubles() {
    let s = setup(PathVerdict::Silent, PathVerdict::Silent);
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
    let book = FixedRules::with_secondary(vec![verify_rule("proton.example")]);
    let links = CountedLinks::new(false);
    let probe = LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered);
    let (engine, _) = engine_over(
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        &book,
        &probe,
        Arc::clone(&links) as Arc<dyn EgressSources>,
    );
    engine.note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    engine.tick(SID, after(1));
    engine.tick(SID, after(2));
    assert_eq!(links.reads(), 1, "read while the host waited");
    assert!(probe.calls().is_empty(), "no check could conclude");
}

#[test]
fn a_disabled_question_mark_rule_is_not_moved_with_an_enabled_one() {
    let book = FixedRules::with_secondary(vec![
        verify_rule("proton.example"),
        CanonicalRule {
            enabled: false,
            ..verify_rule("mail.proton.example")
        },
    ]);
    let probe = LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered);
    let (engine, _) = engine_over(
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        &book,
        &probe,
        Arc::new(BothLinks),
    );
    engine.note_verify_candidate(SID, "mail.proton.example", &[HOST_IP]);
    engine.tick(SID, after(1));
    engine.tick(SID, after(2));
    assert_eq!(action_of(&book, "proton.example"), RuleAction::Route);
    assert_eq!(
        action_of(&book, "mail.proton.example"),
        RuleAction::VerifyPrimary,
        "never checked while disabled"
    );
}

#[test]
fn a_refused_move_rests_the_check_instead_of_probing_on() {
    let book = FixedRules::with_secondary(vec![verify_rule("proton.example")]);
    let probe = LinkProbe::new(PathVerdict::Silent, PathVerdict::Answered);
    let (engine, author) = engine_over(
        Arc::clone(&book) as Arc<dyn RulesProvider>,
        &book,
        &probe,
        Arc::new(BothLinks),
    );
    author.fail("rules-locked");
    let host = "mail.proton.example";
    engine.note_verify_candidate(SID, host, &[HOST_IP]);
    engine.tick(SID, after(1));
    engine.tick(SID, after(2));
    assert_eq!(probe.calls().len(), 3);
    assert_eq!(
        action_of(&book, "proton.example"),
        RuleAction::VerifyPrimary
    );

    engine.note_verify_candidate(SID, host, &[HOST_IP]);
    engine.tick(SID, after(60));
    assert_eq!(
        probe.calls().len(),
        3,
        "resting while the refusal may stand"
    );

    // Positive control: once the rest is over the host is checked again.
    *author.fail_with.lock().unwrap_or_else(|p| p.into_inner()) = None;
    engine.note_verify_candidate(SID, host, &[HOST_IP]);
    engine.tick(SID, after(2 + 10 * 60));
    engine.tick(SID, after(3 + 10 * 60));
    assert_eq!(action_of(&book, "proton.example"), RuleAction::Route);
}

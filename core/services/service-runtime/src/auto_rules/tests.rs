//! Behaviour tests for the companion-domain discovery engine.
//!
//! The learning algorithm itself is proven in `nrr_domain::companion_affinity`;
//! what is exercised here is the service-side contract around it — what each
//! mode is allowed to do, which findings are suppressed, and that a refusal
//! outlives a restart.

use super::*;
use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
use nrr_domain::companion_affinity::test_support::page_load;
use nrr_domain::{RouteBehaviorMode, RuleAction, RuleId};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::per_sid_orchestrator::ActiveRulesSnapshot;

const SID: &str = "S-A";

// ── Fixtures ─────────────────────────────────────────────────────────────────

/// Rules provider over a fixed book, mutable so a test can simulate the rule
/// set changing under the engine (which is what accepting a suggestion does).
struct FixedRules {
    book: Mutex<CanonicalRuleBook>,
    behavior_mode: Mutex<RouteBehaviorMode>,
}

impl FixedRules {
    fn with_secondary(rules: Vec<CanonicalRule>) -> Arc<Self> {
        Arc::new(Self {
            book: Mutex::new(CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(Vec::new()),
                secondary: CanonicalRuleSet::from_rules(rules),
            }),
            behavior_mode: Mutex::new(RouteBehaviorMode::PreferPrimary),
        })
    }

    /// Add secondary rules for hostnames a test drives as anchors. The
    /// proposal tick retires anchors the rule book does not recognise, so a
    /// test that feeds the ledger an anchor has to say it is one.
    fn also_route(&self, hosts: &[&str]) {
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        let mut rules = book.secondary.rules().to_vec();
        rules.extend(hosts.iter().map(|h| exact_rule(h)));
        book.secondary = CanonicalRuleSet::from_rules(rules);
    }

    /// Same, for a hostname a test drives as a PRIMARY-route anchor.
    fn also_route_primary(&self, hosts: &[&str]) {
        let mut book = self.book.lock().unwrap_or_else(|p| p.into_inner());
        let mut rules = book.primary.rules().to_vec();
        rules.extend(hosts.iter().map(|h| exact_rule(h)));
        book.primary = CanonicalRuleSet::from_rules(rules);
    }

    fn set_behavior_mode(&self, mode: RouteBehaviorMode) {
        *self.behavior_mode.lock().unwrap_or_else(|p| p.into_inner()) = mode;
    }
}

impl RulesProvider for FixedRules {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        Some(ActiveRulesSnapshot {
            rule_book: self.book.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            behavior_mode: *self.behavior_mode.lock().unwrap_or_else(|p| p.into_inner()),
        })
    }
}

/// Author that records what it was asked to write and folds it into the shared
/// rule book, so the exclusions see the world the real executor would leave.
struct RecordingAuthor {
    rules: Arc<FixedRules>,
    calls: Mutex<Vec<(AutoRuleReason, Vec<AuthoredRule>)>>,
    fail_with: Mutex<Option<AuthorError>>,
}

impl RecordingAuthor {
    fn new(rules: Arc<FixedRules>) -> Arc<Self> {
        Arc::new(Self {
            rules,
            calls: Mutex::new(Vec::new()),
            fail_with: Mutex::new(None),
        })
    }

    fn fail(&self, code: &str) {
        *self.fail_with.lock().unwrap_or_else(|p| p.into_inner()) = Some(AuthorError {
            code: code.to_string(),
            message: "refused".to_string(),
        });
    }

    fn calls(&self) -> Vec<(AutoRuleReason, Vec<AuthoredRule>)> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl AutoRuleAuthor for RecordingAuthor {
    fn author(
        &self,
        _principal: &str,
        reason: &AutoRuleReason,
        rules: &[AuthoredRule],
        _now: SystemTime,
        _correlation_id: &str,
    ) -> Result<u32, AuthorError> {
        if let Some(e) = self
            .fail_with
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            return Err(e);
        }
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((reason.clone(), rules.to_vec()));
        let mut book = self.rules.book.lock().unwrap_or_else(|p| p.into_inner());
        let mut secondary: Vec<CanonicalRule> = book.secondary.rules().to_vec();
        for rule in rules {
            secondary.push(CanonicalRule {
                id: RuleId(format!("authored-{}", rule.value)),
                enabled: true,
                address_match: Some(match rule.match_kind {
                    AuthoredMatchKind::ExactHost => {
                        CanonicalAddressMatch::ExactFqdn(rule.value.clone())
                    }
                    AuthoredMatchKind::SuffixDomain => {
                        CanonicalAddressMatch::SuffixDomain(rule.value.clone())
                    }
                }),
                app_match: None,
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            });
        }
        book.secondary = CanonicalRuleSet::from_rules(secondary);
        Ok(rules.len() as u32)
    }
}

fn exact_rule(host: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(format!("r-{host}")),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn mode_fn(mode: AutoRulesMode) -> AutoRulesModeFn {
    Arc::new(move |_sid: &str| mode)
}

struct Fixture {
    engine: AutoRulesEngine,
    rules: Arc<FixedRules>,
    author: Arc<RecordingAuthor>,
    dismissals: Arc<InMemoryDismissalStore>,
}

fn fixture(mode: AutoRulesMode) -> Fixture {
    fixture_with_store(mode, Arc::new(InMemoryDismissalStore::new()))
}

/// Fixture with [`AutoRulesEngine::with_isp_block_candidates`] armed — every
/// other fixture leaves it at its off-by-default value.
fn fixture_with_isp_block_candidates(mode: AutoRulesMode) -> Fixture {
    let rules = FixedRules::with_secondary(vec![exact_rule("site.example")]);
    let author = RecordingAuthor::new(Arc::clone(&rules));
    let dismissals = Arc::new(InMemoryDismissalStore::new());
    let engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(mode),
        Arc::clone(&dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()) as Arc<dyn PendingSuggestionStore>,
        SystemTime::UNIX_EPOCH,
    )
    .with_author(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>)
    .with_isp_block_candidates(true);
    Fixture {
        engine,
        rules,
        author,
        dismissals,
    }
}

fn fixture_with_store(mode: AutoRulesMode, dismissals: Arc<InMemoryDismissalStore>) -> Fixture {
    build_fixture(
        mode,
        dismissals,
        Arc::new(InMemoryPendingStore::new()),
        None,
    )
}

/// Fixture over a caller-supplied pending store, so a test can construct a
/// SECOND engine over the same store to simulate a restart.
fn fixture_with_pending_store(
    mode: AutoRulesMode,
    pending_store: Arc<InMemoryPendingStore>,
) -> Fixture {
    build_fixture(
        mode,
        Arc::new(InMemoryDismissalStore::new()),
        pending_store,
        None,
    )
}

/// Fixture over a caller-supplied evidence store, so a test can construct a
/// SECOND engine that starts from what the first one had learned.
fn fixture_with_evidence_store(evidence: Arc<InMemoryEvidenceStore>) -> Fixture {
    let mut f = build_fixture(
        AutoRulesMode::Suggest,
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        None,
    );
    f.engine = f
        .engine
        .with_evidence_store(evidence as Arc<dyn EvidenceStore>);
    f
}

/// Fixture whose eager delivery-name opt-in is read live from `opted_in`, so a
/// test can flip the setting the way the GUI does.
fn fixture_with_eager_delivery(opted_in: Arc<AtomicBool>) -> Fixture {
    build_fixture(
        AutoRulesMode::Suggest,
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        Some(Arc::new(move |_sid: &str| opted_in.load(Ordering::Relaxed))),
    )
}

fn build_fixture(
    mode: AutoRulesMode,
    dismissals: Arc<InMemoryDismissalStore>,
    pending_store: Arc<InMemoryPendingStore>,
    eager_delivery: Option<AutoRulesEagerDeliveryFn>,
) -> Fixture {
    let rules = FixedRules::with_secondary(vec![exact_rule("site.example")]);
    let author = RecordingAuthor::new(Arc::clone(&rules));
    let mut engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(mode),
        Arc::clone(&dismissals) as Arc<dyn DismissalStore>,
        Arc::clone(&pending_store) as Arc<dyn PendingSuggestionStore>,
        SystemTime::UNIX_EPOCH,
    )
    .with_author(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>);
    if let Some(source) = eager_delivery {
        engine = engine.with_eager_delivery_names(source);
    }
    Fixture {
        engine,
        rules,
        author,
        dismissals,
    }
}

/// Feeds the engine two visits to `site.example`, each pulling `companions`.
/// Two distinct windows is the minimum the learner accepts as evidence.
fn two_visits(engine: &AutoRulesEngine, companions: &[&str]) {
    two_visits_anchored(engine, RouteRole::Secondary, companions);
}

/// Same, with the anchor site routed over `role`.
fn two_visits_anchored(engine: &AutoRulesEngine, role: RouteRole, companions: &[&str]) {
    for at in [0_u64, 100_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            return;
        };
        // Route the fixture through the same classification the DNS consumer
        // uses, so the tests exercise the real anchor/candidate decision.
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            role,
            companions,
        );
    }
}

/// Reaches the ledger inside an open batch. Test-only: production code observes
/// through [`LedgerBatch::observe`], but the shared `page_load` fixture wants
/// the ledger itself.
fn batch_ledger<'b>(batch: &'b mut LedgerBatch<'_>) -> &'b mut CompanionAffinityLedger {
    let sid = batch.sid;
    &mut batch
        .ledgers
        .get_mut(sid)
        .unwrap_or_else(|| unreachable!("begin_batch inserts the ledger"))
        .ledger
}

/// Feeds the engine a single visit to `site.example` pulling `companions` —
/// exactly the evidence the delivery-name gate normally refuses to act on.
fn one_visit(engine: &AutoRulesEngine, companions: &[&str]) {
    one_visit_at(engine, 0, companions);
}

/// Same, with the visit landing at `at_ms` — two visits far enough apart are
/// two distinct windows, which is what a proposal needs.
fn one_visit_at(engine: &AutoRulesEngine, at_ms: u64, companions: &[&str]) {
    let Some(mut batch) = engine.begin_batch(SID) else {
        return;
    };
    page_load(
        batch_ledger(&mut batch),
        at_ms,
        "site.example",
        RouteRole::Secondary,
        companions,
    );
}

fn later() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(150_000)
}

// ── Collection and proposal ──────────────────────────────────────────────────

#[test]
fn a_dedicated_companion_seen_across_two_visits_becomes_a_pending_suggestion() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    assert_eq!(summary.pending, 1);

    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.anchor, "site.example");
    assert_eq!(c.proposed_match, "cdn.example");
    assert_eq!(c.match_kind, AUTO_RULE_MATCH_KIND_SUFFIX);
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.observations, Some(2));
    assert!(c.id.starts_with("arc-"));
    // Nothing was applied — `suggest` offers, it never writes.
    assert!(f.author.calls().is_empty());
}

/// The tray already withheld a third party the main route serves; the inbox
/// showed it like any other offer, so the same host read as "your site needs
/// this" in one surface and as "nothing to do here" in the other. The read path
/// now carries the same judgement, and it carries "is this the site's own name"
/// beside it — the user asked to tell those apart.
#[test]
fn the_inbox_carries_the_main_link_judgement_and_the_third_party_flag() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());

    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    // `cdn.example` under the anchor `site.example` is a different registrable
    // domain — a third party by construction.
    assert_eq!(
        candidates[0].third_party,
        Some(true),
        "a name outside the site's own domain is a third party"
    );
    // Nothing measured the main route yet, so nothing is settled: the flag must
    // not read as "served" merely because no probe has run.
    assert!(
        !candidates[0].served_by_main_link,
        "an unmeasured host is not a served one"
    );
}

#[test]
fn a_companion_of_a_site_on_the_default_route_is_never_offered() {
    // The user's own report: a metrics host on the primary route is a rule
    // host, so its companion under the same brand was offered as a primary rule
    // — a rule that only restates where uncovered traffic already goes.
    let f = fixture(AutoRulesMode::Suggest);
    two_visits_anchored(&f.engine, RouteRole::Primary, &["cdn.example"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 0);
    assert_eq!(summary.pending, 0);
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn the_dropped_side_follows_the_behavior_mode() {
    // Mirror of the case above: when unmatched traffic already takes the
    // secondary, it is the primary-route companions that carry information.
    let f = fixture(AutoRulesMode::Suggest);
    f.rules
        .set_behavior_mode(RouteBehaviorMode::PreferSecondaryWhenAvailable);
    two_visits_anchored(&f.engine, RouteRole::Primary, &["cdn.example"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].route, RouteRole::Primary.slug());
}

#[test]
fn a_host_seen_alongside_many_sites_is_never_suggested() {
    let f = fixture(AutoRulesMode::Suggest);
    // Dedicated companion plus a ubiquitous one.
    two_visits(&f.engine, &["cdn.example", "metrics.shared"]);
    // The ubiquitous host also shows up under two other routed sites, diluting
    // its affinity below the threshold.
    for (at, anchor) in [(200_000_u64, "b.example"), (300_000, "c.example")] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            anchor,
            RouteRole::Secondary,
            &["metrics.shared"],
        );
    }

    f.engine
        .tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    let values: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert!(
        !values.contains(&"metrics.shared".to_string()),
        "a host shared across sites must not be pinned to one of them"
    );
    assert!(values.contains(&"cdn.example".to_string()));
}

#[test]
fn platform_infrastructure_is_never_suggested() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["fonts.gstatic.com"]);

    f.engine.tick(SID, later());
    assert!(
        f.engine.candidates(SID).is_empty(),
        "shared platform hosts would drag unrelated traffic onto the route"
    );
}

#[test]
fn a_companion_an_existing_rule_already_covers_is_never_suggested() {
    let rules = FixedRules::with_secondary(vec![
        exact_rule("site.example"),
        CanonicalRule {
            address_match: Some(CanonicalAddressMatch::SuffixDomain("example".into())),
            ..exact_rule("covered")
        },
    ]);
    let engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    two_visits(&engine, &["cdn.example"]);

    engine.tick(SID, later());
    assert!(
        engine.candidates(SID).is_empty(),
        "`*.example` already routes cdn.example — there is nothing to add"
    );
}

// ── Modes ────────────────────────────────────────────────────────────────────

#[test]
fn mode_off_collects_nothing_and_offers_nothing() {
    let f = fixture(AutoRulesMode::Off);
    assert!(
        f.engine.begin_batch(SID).is_none(),
        "off must not even open a batch — collection is the cost we refuse to pay"
    );
    two_visits(&f.engine, &["cdn.example"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary, TickSummary::default());
    assert!(f.engine.candidates(SID).is_empty());
    assert!(f.author.calls().is_empty());
}

#[test]
fn mode_auto_authors_immediately_with_the_site_companion_reason() {
    let f = fixture(AutoRulesMode::Auto);
    two_visits(&f.engine, &["cdn.example"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.authored, 1);
    assert_eq!(summary.pending, 0, "auto applies, it does not park");

    let calls = f.author.calls();
    assert_eq!(calls.len(), 1);
    let (reason, rules) = &calls[0];
    assert_eq!(reason, &AutoRuleReason::SiteCompanion);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].value, "cdn.example");
    assert_eq!(rules[0].route, RouteRole::Secondary);
    assert_eq!(rules[0].match_kind, AuthoredMatchKind::SuffixDomain);
    assert_eq!(rules[0].anchor, "site.example");
    // The rule now exists in the book, so a further tick must not re-add it.
    let again = f.engine.tick(SID, later());
    assert_eq!(again.authored, 0);
    assert_eq!(f.author.calls().len(), 1);
}

// ── Accept ───────────────────────────────────────────────────────────────────

#[test]
fn accepting_authors_with_the_user_confirmed_reason_and_clears_the_offer() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();

    let outcome = f.engine.accept(SID, &ids, later()).expect("accept");
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.unknown, 0);
    assert_eq!(outcome.pending, 0);

    let calls = f.author.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, AutoRuleReason::UserConfirmed);

    // The accepted host is now a rule, so the exclusions must keep it out of
    // every later suggestion — no persisted "accepted" list required.
    let again = f.engine.tick(SID, later());
    assert_eq!(again.parked, 0);
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn a_host_whose_accepted_rule_the_user_deleted_is_offered_again() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    f.engine.accept(SID, &ids, later()).expect("accept");

    // The user edits their rules file and drops the rule they just accepted.
    *f.rules.book.lock().unwrap_or_else(|p| p.into_inner()) = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(Vec::new()),
        secondary: CanonicalRuleSet::from_rules(vec![exact_rule("site.example")]),
    };
    // Within the race window the acceptance still speaks for itself…
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 0);
    // …but it is a race guard, not a verdict: once it lapses, the rule book is
    // the only authority, and it no longer covers the host.
    f.engine.expire_authored_suppression();
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);
}

#[test]
fn accepting_an_unknown_id_is_reported_without_failing_the_call() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let mut ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    ids.push("arc-does-not-exist".to_string());

    let outcome = f.engine.accept(SID, &ids, later()).expect("accept");
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.unknown, 1);
}

#[test]
fn a_refused_write_reports_its_reason_and_leaves_the_offer_standing() {
    // The Free rule cap is the concrete case: the executor answers
    // `rule-cap-exceeded`, and the user must be told that rather than seeing the
    // suggestion silently vanish or the service panic.
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    f.author.fail("rule-cap-exceeded");

    let err = f
        .engine
        .accept(SID, &ids, later())
        .expect_err("the cap must refuse the write");
    assert_eq!(err.code, "rule-cap-exceeded");
    assert_eq!(
        f.engine.candidates(SID).len(),
        1,
        "the offer survives so the user can retry after making room"
    );
}

#[test]
fn accepting_without_an_author_wired_refuses_cleanly_and_keeps_the_offer() {
    let rules = FixedRules::with_secondary(vec![exact_rule("site.example")]);
    let engine = AutoRulesEngine::new(
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    two_visits(&engine, &["cdn.example"]);
    engine.tick(SID, later());
    let ids: Vec<String> = engine.candidates(SID).into_iter().map(|c| c.id).collect();

    let err = engine.accept(SID, &ids, later()).expect_err("no author");
    assert_eq!(err.code, "authoring-unavailable");
    assert_eq!(engine.candidates(SID).len(), 1);
}

// ── Dismiss ──────────────────────────────────────────────────────────────────

#[test]
fn a_refusal_survives_a_service_restart_and_suppresses_the_suggestion() {
    let store = Arc::new(InMemoryDismissalStore::new());
    let f = fixture_with_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(ids.len(), 1);

    let outcome = f.engine.dismiss(SID, &ids, later());
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.pending, 0);
    // Same process: the tick must not re-park it.
    f.engine.tick(SID, later());
    assert!(f.engine.candidates(SID).is_empty());

    // A restart is a brand-new engine over the SAME durable store, re-learning
    // the same evidence from scratch. The refusal must still hold.
    let restarted = fixture_with_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&restarted.engine, &["cdn.example"]);
    let summary = restarted.engine.tick(SID, later());
    assert_eq!(summary.parked, 0);
    assert!(
        restarted.engine.candidates(SID).is_empty(),
        "a suggestion the user declined must not come back after a restart"
    );
    assert!(store.load(SID).contains(&ids[0]));
}

#[test]
fn dismissing_an_unknown_id_is_reported_without_failing() {
    let f = fixture(AutoRulesMode::Suggest);
    let outcome = f.engine.dismiss(SID, &["arc-nope".to_string()], later());
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.unknown, 1);
}

#[test]
fn a_declined_suggestion_shows_up_in_the_review_list() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert!(f.engine.list_dismissed(SID).is_empty());

    f.engine.dismiss(SID, &ids, later());
    let dismissed = f.engine.list_dismissed(SID);
    assert_eq!(dismissed.len(), 1);
    assert_eq!(dismissed[0].candidate_id, ids[0]);
    assert_eq!(dismissed[0].proposed_match, "cdn.example");
    // Scoped like every other part of this feature — one user's refusal
    // review must not surface another user's.
    assert!(f.engine.list_dismissed("S-B").is_empty());
}

#[test]
fn restoring_a_declined_suggestion_lets_it_be_offered_again() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    f.engine.dismiss(SID, &ids, later());
    f.engine.tick(SID, later());
    assert!(f.engine.candidates(SID).is_empty(), "refusal suppresses it");

    let outcome = f.engine.restore_dismissed(SID, &ids, later());
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.unknown, 0);
    assert!(
        f.engine.list_dismissed(SID).is_empty(),
        "a restored refusal must not still show as declined"
    );

    // The next tick re-derives the same evidence and, with the suppression
    // lifted, offers it again.
    f.engine.tick(SID, later());
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

#[test]
fn restoring_survives_a_restart_because_it_edits_the_durable_record() {
    let store = Arc::new(InMemoryDismissalStore::new());
    let f = fixture_with_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    f.engine.dismiss(SID, &ids, later());

    f.engine.restore_dismissed(SID, &ids, later());
    assert!(!store.load(SID).contains(&ids[0]));

    let restarted = fixture_with_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&restarted.engine, &["cdn.example"]);
    let summary = restarted.engine.tick(SID, later());
    assert_eq!(
        summary.pending, 1,
        "a restored refusal must not still suppress the host after a restart"
    );
}

#[test]
fn restoring_puts_the_offer_back_on_the_list_at_once() {
    // The user's report: "allow again" and the row was simply gone. Waiting for
    // the observation feed to re-earn it is not an answer — its evidence has
    // usually aged out by then, which is why the refusal keeps the offer.
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let before = f.engine.candidates(SID);
    let ids: Vec<String> = before.iter().map(|c| c.id.clone()).collect();
    f.engine.dismiss(SID, &ids, later());
    assert!(f.engine.candidates(SID).is_empty());

    f.engine.restore_dismissed(SID, &ids, later());
    let after = f.engine.candidates(SID);
    assert_eq!(after.len(), 1, "back without waiting for another sighting");
    assert_eq!(after[0].proposed_match, before[0].proposed_match);
    assert_eq!(after[0].anchor, before[0].anchor);
    assert_eq!(
        after[0].observations, before[0].observations,
        "the evidence comes back with it, not a blank row"
    );
}

#[test]
fn forgetting_erases_the_answer_so_the_host_can_be_offered_again() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    f.engine.dismiss(SID, &ids, later());

    let outcome = f.engine.forget_candidates(SID, &ids, later());
    assert_eq!(outcome.applied, 1);
    assert!(
        f.engine.list_dismissed(SID).is_empty(),
        "the refusal is gone, not just lifted"
    );
    assert!(f.engine.candidates(SID).is_empty(), "and so is the offer");

    // Nothing suppresses it any more, so the next tick offers it afresh.
    f.engine.tick(SID, later());
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

#[test]
fn forgetting_drops_a_pending_offer_the_user_never_answered() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();

    let outcome = f.engine.forget_candidates(SID, &ids, later());
    assert_eq!(outcome.applied, 1);
    assert_eq!(outcome.pending, 0);
    assert!(
        f.engine.list_dismissed(SID).is_empty(),
        "erasing is not refusing — nothing must be recorded as declined"
    );
}

#[test]
fn restoring_an_unknown_id_is_reported_without_failing() {
    let f = fixture(AutoRulesMode::Suggest);
    let outcome = f
        .engine
        .restore_dismissed(SID, &["arc-nope".to_string()], later());
    assert_eq!(outcome.applied, 0);
    assert_eq!(outcome.unknown, 1);
}

// ── Pending durability ───────────────────────────────────────────────────────

/// A candidate DTO built directly, without going through the learner — for
/// tests that exercise the durable store rather than the discovery flow. Uses
/// the suffix form, matching what `to_candidate` now always writes.
fn candidate_dto(id: &str, affinity: f64, last_seen_unix_ms: i64) -> AutoRuleCandidateDto {
    AutoRuleCandidateDto {
        id: id.to_string(),
        anchor: "site.example".to_string(),
        proposed_match: format!("{id}.example"),
        match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.to_string(),
        route: RouteRole::Secondary.slug().to_string(),
        affinity,
        observations: Some(2),
        first_seen_unix_ms: last_seen_unix_ms,
        last_seen_unix_ms,
        signal: AUTO_RULE_SIGNAL_CO_ACTIVITY.to_string(),
        consumers: vec![AutoRuleConsumerDto {
            hostname: "site.example".to_string(),
            route: RouteRole::Secondary.slug().to_string(),
        }],
        consumers_changed_unix_ms: last_seen_unix_ms,
        primary_behavior: String::new(),
        anchor_refuses_main_link: false,
        observed_members: Vec::new(),
        served_by_main_link: false,
        third_party: None,
        secondary_reach: None,
    }
}

fn pending_record(dto: &AutoRuleCandidateDto) -> AutoRulePendingRecord {
    AutoRulePendingRecord {
        candidate_id: dto.id.clone(),
        route: dto.route.clone(),
        match_kind: dto.match_kind.clone(),
        dto_json: serde_json::to_string(dto).expect("serialize candidate dto"),
        parked_at: dto.last_seen_unix_ms,
    }
}

/// An engine over `pending_store`, with no learning behind it — for tests
/// that only care what construction restores.
fn engine_over(pending_store: Arc<InMemoryPendingStore>, now: SystemTime) -> AutoRulesEngine {
    AutoRulesEngine::new(
        FixedRules::with_secondary(Vec::new()) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::new(InMemoryDismissalStore::new()),
        pending_store as Arc<dyn PendingSuggestionStore>,
        now,
    )
}

#[test]
fn a_suggestion_the_rules_already_cover_is_withdrawn() {
    // The address the user accepted went on standing in the inbox with nothing
    // left to approve. An address becomes covered in ways this engine never
    // observes — a rule typed by hand, a preset import, a revision another
    // session activated — so the parked set is re-checked against the live rule
    // book on every read, not only when the offer was made.
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);
    assert_eq!(
        f.engine.candidates(SID).len(),
        1,
        "offer stands while uncovered"
    );

    f.rules.also_route(&["cdn.example"]);
    assert!(
        f.engine.candidates(SID).is_empty(),
        "an address a rule already covers must not stand as an offer",
    );
    // And it leaves the parked set, so the count the tray badge reads follows.
    assert_eq!(
        f.engine.tick(SID, later()).pending,
        0,
        "the withdrawn offer must stop being counted",
    );
}

#[test]
fn a_pending_suggestion_survives_a_service_restart() {
    let store = Arc::new(InMemoryPendingStore::new());
    let f = fixture_with_pending_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&f.engine, &["cdn.example"]);
    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let before: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(before.len(), 1);

    // A restart is a brand-new engine over the SAME durable store, with no
    // browsing behind it yet — the suggestion must already be there.
    let restarted = fixture_with_pending_store(AutoRulesMode::Suggest, Arc::clone(&store));
    let after: Vec<String> = restarted
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(after, before, "the pending offer must survive the restart");
}

#[test]
fn one_visit_before_a_restart_and_one_after_add_up_to_a_suggestion() {
    // The 0811 laptop: short visits, service restarted between them. Before
    // evidence was durable the count reset each time and nothing was ever
    // offered.
    let evidence = Arc::new(InMemoryEvidenceStore::new());
    let first = fixture_with_evidence_store(Arc::clone(&evidence));
    one_visit_at(&first.engine, 0, &["cdn.example"]);
    assert_eq!(first.engine.tick(SID, later()).parked, 0, "one window only");

    let restarted = fixture_with_evidence_store(Arc::clone(&evidence));
    one_visit_at(&restarted.engine, 100_000, &["cdn.example"]);
    assert_eq!(
        restarted.engine.tick(SID, later()).parked,
        1,
        "the window observed before the restart must still count"
    );
}

#[test]
fn turning_discovery_off_forgets_the_saved_evidence_too() {
    let evidence = Arc::new(InMemoryEvidenceStore::new());
    let f = fixture_with_evidence_store(Arc::clone(&evidence));
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    assert!(evidence.load(SID).is_some(), "evidence was saved");

    let off = build_fixture(
        AutoRulesMode::Off,
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        None,
    )
    .engine
    .with_evidence_store(Arc::clone(&evidence) as Arc<dyn EvidenceStore>);
    off.tick(SID, later());
    assert!(
        evidence.load(SID).is_none(),
        "a principal who turned discovery off keeps nothing on disk"
    );
}

#[test]
fn accepting_removes_the_persisted_pending_record() {
    let store = Arc::new(InMemoryPendingStore::new());
    let f = fixture_with_pending_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(store.load_all().get(SID).map(Vec::len), Some(1));

    f.engine
        .accept(SID, &ids, later())
        .expect("author is wired");
    assert!(
        store.load_all().get(SID).is_none_or(Vec::is_empty),
        "an accepted suggestion must not linger in the durable pending table"
    );
}

#[test]
fn dismissing_removes_the_persisted_pending_record() {
    let store = Arc::new(InMemoryPendingStore::new());
    let f = fixture_with_pending_store(AutoRulesMode::Suggest, Arc::clone(&store));
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let ids: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(store.load_all().get(SID).map(Vec::len), Some(1));

    f.engine.dismiss(SID, &ids, later());
    assert!(
        store.load_all().get(SID).is_none_or(Vec::is_empty),
        "a dismissed suggestion must not linger in the durable pending table \
         even though the refusal itself lives in a different table"
    );
}

#[test]
fn an_expired_pending_suggestion_is_not_restored() {
    let store = Arc::new(InMemoryPendingStore::new());
    let restart_at = SystemTime::UNIX_EPOCH + Duration::from_millis(PENDING_TTL_MS as u64 + 1);
    let stale = candidate_dto("arc-stale", 0.9, 0);
    let fresh = candidate_dto("arc-fresh", 0.9, unix_ms(restart_at));
    store.replace(SID, &[pending_record(&stale), pending_record(&fresh)]);

    let engine = engine_over(store, restart_at);
    let ids: Vec<String> = engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        vec!["arc-fresh".to_string()],
        "an offer nobody answered across a long outage must not come back, \
         same as it would not survive a live tick"
    );
}

#[test]
fn a_record_parked_in_the_retired_exact_form_does_not_survive_a_restart() {
    let store = Arc::new(InMemoryPendingStore::new());
    let now = later();
    let now_ms = unix_ms(now);
    let stale_exact = AutoRuleCandidateDto {
        match_kind: AUTO_RULE_MATCH_KIND_EXACT.to_string(),
        ..candidate_dto("arc-old-exact", 0.9, now_ms)
    };
    let live_suffix = candidate_dto("arc-new-suffix", 0.9, now_ms);
    store.replace(
        SID,
        &[pending_record(&stale_exact), pending_record(&live_suffix)],
    );

    let engine = engine_over(store, now);
    let ids: Vec<String> = engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        vec!["arc-new-suffix".to_string()],
        "a row written before offers switched to the suffix form must not sit \
         beside its own suffix twin after a restart"
    );
}

#[test]
fn the_restored_pending_set_is_capped_and_keeps_the_strongest() {
    let store = Arc::new(InMemoryPendingStore::new());
    let now = later();
    let now_ms = unix_ms(now);
    let total = MAX_PENDING_PER_PRINCIPAL + 5;
    let records: Vec<AutoRulePendingRecord> = (0..total)
        .map(|i| {
            let dto = candidate_dto(&format!("arc-{i:03}"), i as f64 / total as f64, now_ms);
            pending_record(&dto)
        })
        .collect();
    store.replace(SID, &records);

    let engine = engine_over(store, now);
    let restored = engine.candidates(SID);
    assert_eq!(restored.len(), MAX_PENDING_PER_PRINCIPAL);
    assert!(
        !restored.iter().any(|c| c.id == "arc-000"),
        "the weakest-evidence offer must be the one dropped at the cap"
    );
    assert!(restored
        .iter()
        .any(|c| c.id == format!("arc-{:03}", total - 1)));
}

// ── Ids, classification, publishing ──────────────────────────────────────────

#[test]
fn candidate_ids_are_stable_across_recomputation_and_scoped_to_the_principal() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    let first: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    // A second tick re-derives the same proposals; the ids must not renumber or
    // the tray's already-offered set and the persisted refusals both break.
    f.engine.tick(SID, later());
    let second: Vec<String> = f.engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(first, second);

    assert_ne!(
        candidate_id("S-A", AUTO_RULE_MATCH_KIND_EXACT, "cdn.example"),
        candidate_id("S-B", AUTO_RULE_MATCH_KIND_EXACT, "cdn.example"),
        "one user's refusal must not silence another's suggestion"
    );
}

#[test]
fn the_pending_set_is_capped_and_keeps_the_strongest() {
    let f = fixture(AutoRulesMode::Suggest);
    let sites: Vec<String> = (0..5).map(|s| format!("site{s}.example")).collect();
    f.rules
        .also_route(&sites.iter().map(String::as_str).collect::<Vec<_>>());
    // Several sites, each pulling its own companions: one site alone cannot
    // exceed the learner's per-anchor cap.
    for site in 0..5 {
        let hosts: Vec<String> = (0..16)
            .map(|i| format!("cdn{site}-{i:02}.example"))
            .collect();
        let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        for at in [0_u64, 100_000] {
            let Some(mut batch) = f.engine.begin_batch(SID) else {
                unreachable!("suggest mode collects")
            };
            page_load(
                batch_ledger(&mut batch),
                at,
                &format!("site{site}.example"),
                RouteRole::Secondary,
                &refs,
            );
        }
    }

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.pending, MAX_PENDING_PER_PRINCIPAL);
    assert!(summary.parked as usize <= MAX_PENDING_PER_PRINCIPAL);
}

#[test]
fn an_offer_nothing_refreshes_expires_instead_of_waiting_forever() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).pending, 1);

    // A day later with no further sighting: the offer is gone, and the learner
    // has forgotten the evidence too, so nothing re-parks it.
    let a_day_later = later() + Duration::from_millis(86_400_001);
    assert_eq!(f.engine.tick(SID, a_day_later).pending, 0);
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn one_address_is_one_offer_however_many_sites_pull_it() {
    // The user's report: `static.cdninsta.test` arrived twice — once next to
    // `insta.example`, once next to an unrelated site that happened to load at
    // the same time.
    let f = fixture(AutoRulesMode::Suggest);
    two_visits_anchored(&f.engine, RouteRole::Secondary, &["cdn.example"]);
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            200_000,
            "other.example",
            RouteRole::Secondary,
            &["cdn.example"],
        );
    }

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].proposed_match, "cdn.example");
    // And refusing it refuses the address, not one pairing.
    f.engine.dismiss(SID, &[candidates[0].id.clone()], later());
    assert_eq!(f.engine.tick(SID, later()).pending, 0);
}

// ── Consumers ────────────────────────────────────────────────────────────────

#[test]
fn a_shared_host_carries_every_consumer_strongest_first() {
    // Eager delivery-name suggestions skip the co-activity gate entirely, so
    // one hit already earns each anchor its own proposal for the same address
    // — the shape a real shared CDN produces.
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example", "site-b.example"]);
    // site-a pulls it on three separate visits, site-b on one: three visits
    // means three nearest-hits for site-a against a shared total, so its
    // evidence outranks site-b's and it signs the offer.
    for at in [0_u64, 100_000, 200_000] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site-a.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            300_000,
            "site-b.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }

    f.engine
        .tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1, "one address is one offer");
    let c = &candidates[0];
    assert_eq!(
        c.anchor, "site-a.example",
        "the strongest evidence signs it"
    );
    let names: Vec<&str> = c.consumers.iter().map(|x| x.hostname.as_str()).collect();
    assert_eq!(
        names,
        vec!["site-a.example", "site-b.example"],
        "winner first, then the rest by descending nearest_share"
    );
    assert!(c
        .consumers
        .iter()
        .all(|x| x.route == RouteRole::Secondary.slug()));
}

#[test]
fn a_repeated_tick_with_no_new_consumer_does_not_move_the_new_basis_clock() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example", "site-b.example"]);
    for (at, anchor) in [(0_u64, "site-a.example"), (100_000, "site-b.example")] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            anchor,
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }

    let first_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(200_000);
    f.engine.tick(SID, first_tick_at);
    let first = f.engine.candidates(SID);
    assert_eq!(first[0].consumers.len(), 2);
    let first_basis = first[0].consumers_changed_unix_ms;
    assert_eq!(
        first_basis,
        unix_ms(first_tick_at),
        "first appearance stamps now"
    );

    // Nothing new arrives — only a later tick re-deriving the same evidence.
    let second_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(300_000);
    f.engine.tick(SID, second_tick_at);
    let second = f.engine.candidates(SID);
    assert_eq!(
        second[0].consumers_changed_unix_ms, first_basis,
        "no new consumer arrived, so the clock must not move"
    );
}

#[test]
fn a_third_consumer_arriving_later_moves_the_new_basis_clock_forward() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules
        .also_route(&["site-a.example", "site-b.example", "site-c.example"]);
    for (at, anchor) in [(0_u64, "site-a.example"), (100_000, "site-b.example")] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            anchor,
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    let first_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(200_000);
    f.engine.tick(SID, first_tick_at);
    let first_basis = f.engine.candidates(SID)[0].consumers_changed_unix_ms;

    // A third site starts pulling the same host.
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            300_000,
            "site-c.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    let third_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(400_000);
    f.engine.tick(SID, third_tick_at);
    let after = f.engine.candidates(SID);
    assert_eq!(after[0].consumers.len(), 3);
    assert!(
        after[0].consumers_changed_unix_ms > first_basis,
        "a genuinely new consumer must move the clock forward"
    );
    assert_eq!(after[0].consumers_changed_unix_ms, unix_ms(third_tick_at));
}

/// The user's actual question when accepting a suggestion: "what else does
/// this affect?" A companion needed by a site already on the default route
/// gets no offer of its own — adding the rule would restate where its
/// traffic already goes — but the user must still be told, because accepting
/// the OTHER offer pulls that site's traffic into the tunnel too.
#[test]
fn a_consumer_on_the_default_route_still_appears_even_though_its_own_offer_is_inert() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example"]);
    f.rules.also_route_primary(&["site-b.example"]);
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            0,
            "site-a.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        // FixedRules defaults to PreferPrimary, so Primary is the default
        // route and this anchor's own proposal is inert.
        page_load(
            batch_ledger(&mut batch),
            100_000,
            "site-b.example",
            RouteRole::Primary,
            &["sharedcdn.example"],
        );
    }

    f.engine
        .tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(200_000));
    let candidates = f.engine.candidates(SID);
    assert_eq!(
        candidates.len(),
        1,
        "the inert primary anchor must not become its own offer"
    );
    let c = &candidates[0];
    assert_eq!(c.route, RouteRole::Secondary.slug());
    let names: Vec<&str> = c.consumers.iter().map(|x| x.hostname.as_str()).collect();
    assert!(names.contains(&"site-a.example"));
    assert!(
        names.contains(&"site-b.example"),
        "the default-route consumer must still be visible: {names:?}"
    );
    let on_primary = c
        .consumers
        .iter()
        .find(|x| x.hostname == "site-b.example")
        .expect("site-b is a consumer");
    assert_eq!(on_primary.route, RouteRole::Primary.slug());
}

#[test]
fn classification_prefers_the_secondary_route_and_defaults_to_candidate() {
    assert_eq!(
        AutoRulesEngine::classify(false, true),
        CoActivityKind::Anchor {
            route: RouteRole::Secondary
        }
    );
    assert_eq!(
        AutoRulesEngine::classify(true, false),
        CoActivityKind::Anchor {
            route: RouteRole::Primary
        }
    );
    // A host matching both sets anchors the secondary — that is the route whose
    // companions break when they are missing.
    assert_eq!(
        AutoRulesEngine::classify(true, true),
        CoActivityKind::Anchor {
            route: RouteRole::Secondary
        }
    );
    assert_eq!(
        AutoRulesEngine::classify(false, false),
        CoActivityKind::Candidate
    );
}

/// A bus with `SID`'s client already subscribed. An announcement is only
/// worth recording once somebody can receive it, so every publish test
/// needs a listener — see the audience check in `publish`.
fn subscribed_bus() -> Arc<EventBus> {
    let bus = Arc::new(EventBus::new());
    bus.subscribe_as("test-client".to_string(), Some(SID.to_string()), None);
    bus
}

/// The service and the tray start together and the service usually wins. An
/// offer announced into that gap reached nobody, yet counted as announced —
/// and the tray, whose subscription begins at the CURRENT head, never learned
/// of it. The field case: the tray connected 20 seconds after the offer was
/// published, and no window ever opened.
#[test]
fn an_offer_announced_before_anyone_is_listening_is_announced_again_later() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = Arc::new(EventBus::new());
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        !engine.tick(SID, later()).published,
        "nothing is listening, so nothing was announced",
    );

    // The tray connects.
    bus.subscribe_as("tray".to_string(), Some(SID.to_string()), None);
    assert!(
        engine.tick(SID, later()).published,
        "the offer still has its news to deliver",
    );
    // And it is not repeated once it has actually been delivered.
    assert!(!engine.tick(SID, later()).published);
}

#[test]
fn a_growing_pending_set_is_announced_once_not_on_every_tick() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        engine.tick(SID, later()).published,
        "first finding announces"
    );
    // A further tick within the quiet window must stay silent even though the
    // set grew — the tray opens a window per event. The two visits sit one idle
    // window apart so they count as distinct sessions, and the tick that reaps
    // them still lands inside the announcement gap.
    for at in [151_000_u64, 168_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let second = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(169_000));
    assert!(second.parked > 0, "the finding is still parked");
    assert!(!second.published, "but it does not re-prompt");
}

/// Accepting a suggestion lowers the pending total, so "more pending than last
/// time" would mute every later arrival that stays under the session's
/// high-water mark — which is how a whole browsing session can go unoffered.
#[test]
fn a_suggestion_arriving_after_an_acceptance_is_still_announced() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_author(Arc::clone(&f.author) as Arc<dyn AutoRuleAuthor>)
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        engine.tick(SID, later()).published,
        "first finding announces"
    );

    let accepted: Vec<String> = engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(accepted.len(), 1);
    engine
        .accept(SID, &accepted, later())
        .expect("the offer is accepted");
    assert!(engine.candidates(SID).is_empty(), "and stops being pending");

    for at in [200_000_u64, 300_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let next = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(350_000));
    assert!(next.parked > 0, "the next companion is parked");
    assert!(next.published, "and the tray is told about it");
}

/// A suggestion that lands inside the quiet gap must be announced by a later
/// tick on its own — waiting for the next arrival can mean waiting forever.
#[test]
fn a_suggestion_muted_by_the_quiet_gap_is_announced_by_a_later_tick() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(engine.tick(SID, later()).published);

    for at in [151_000_u64, 168_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let muted = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(169_000));
    assert!(muted.parked > 0 && !muted.published, "gap holds it back");

    // Nothing new arrives — only time passes.
    let later_tick = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(200_000));
    assert_eq!(later_tick.parked, 0, "no new finding");
    assert!(later_tick.published, "yet the waiting offer is announced");
}

/// A host that already completes connections on the main route needs no
/// tunnel, so it earns no popup — but it must stay in the tray's count: that
/// number promises "everything waiting for an answer", not "everything worth
/// waking you up for". And once every offer in the set has settled that way,
/// there is nothing left worth a popup at all.
#[test]
fn a_settled_offer_is_counted_but_only_an_unsettled_one_earns_a_popup() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    two_visits(&engine, &["cdn.example", "assets.example"]);
    engine.note_primary_health(SID, "cdn.example", PrimaryHealthEvent::Completed);

    // assets.example is still unsettled, so the set as a whole is worth surfacing.
    let mixed = engine.tick(SID, later());
    assert_eq!(mixed.pending, 2, "both offers stay parked, settled or not");
    assert!(mixed.published, "the still-open offer earns a popup");

    let published = bus.peek_pending_for(&sub.subscription_id, 10);
    assert_eq!(published.len(), 1, "exactly one event went out so far");
    match &published[0].event {
        StatusUpdateEvent::AutoRuleCandidatesChanged { pending_count, .. } => {
            assert_eq!(
                *pending_count, 2,
                "the tray's number covers everything waiting, not just what popped"
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // The remaining companion settles too, well outside the quiet gap — nothing
    // is left worth a popup, so this tick must stay silent on its own terms.
    engine.note_primary_health(SID, "assets.example", PrimaryHealthEvent::Completed);
    let settled = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    assert_eq!(settled.pending, 2, "still both parked");
    assert!(
        !settled.published,
        "everything answers on primary, so no popup"
    );

    let after = bus.peek_pending_for(&sub.subscription_id, 10);
    assert_eq!(after.len(), 1, "no second event was published");
}

/// A site the user marked as refusing main-link addresses is the one case where
/// "it answers on the main route" proves nothing — answering with a refusal is
/// still answering. Its companions keep being offered.
#[test]
fn a_site_marked_as_refusing_keeps_its_companions_on_offer() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus))
    .with_refusing_anchors(Arc::new(|_sid: &str| vec!["site.example".to_string()]));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    // A third-party neighbour that answers on the main route: normally quietened.
    two_visits(&engine, &["cdn.example"]);
    engine.note_primary_health(SID, "cdn.example", PrimaryHealthEvent::Completed);

    let summary = engine.tick(SID, later());
    assert_eq!(summary.pending, 1);
    assert!(
        summary.published,
        "the anchor refuses main-link addresses, so its companions are still worth asking about"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

/// While the additional route is down, everything already travels the main
/// link and works — so an offer to move addresses onto a route that does not
/// exist right now is noise. The findings are kept and offered once it is back.
#[test]
fn suggestions_wait_for_the_additional_route_and_arrive_when_it_returns() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let up = Arc::new(AtomicBool::new(false));
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus))
    .with_secondary_ready({
        let up = Arc::clone(&up);
        Arc::new(move |_sid: &str| up.load(Ordering::Relaxed))
    });
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    two_visits(&engine, &["assets.site.example"]);
    let while_down = engine.tick(SID, later());
    assert_eq!(while_down.pending, 1, "the finding is kept");
    assert!(
        !while_down.published,
        "nothing pops while the route is down"
    );
    assert!(bus.peek_pending_for(&sub.subscription_id, 10).is_empty());

    up.store(true, Ordering::Relaxed);
    let when_back = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    assert!(
        when_back.published,
        "what was learned while the route was down is offered once it is up"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

/// "It answers on the main route" settles a third-party neighbour, never an
/// address of the routed site itself: a site can complete the connection and
/// still serve a refusal to a main-link address, which is the exact case the
/// user routes it for.
#[test]
fn an_address_of_the_site_itself_still_pops_even_when_the_main_route_answers() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    // Same registrable domain as the anchor `site.example` → brand-related.
    two_visits(&engine, &["assets.site.example"]);
    engine.note_primary_health(SID, "assets.site.example", PrimaryHealthEvent::Completed);

    let summary = engine.tick(SID, later());
    assert_eq!(summary.pending, 1);
    assert!(
        summary.published,
        "an address belonging to the routed site is not settled by a completed connection"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

// ── Eager delivery-name suggestions (per-SID opt-in) ─────────────────────────

/// A delivery-shaped host normally has to earn its suggestion: one page load is
/// not evidence that the CDN belongs to this site rather than to everyone.
#[test]
fn a_delivery_named_host_is_not_suggested_from_one_visit_by_default() {
    let f = fixture(AutoRulesMode::Suggest);
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 0);
    assert!(f.engine.candidates(SID).is_empty());
}

/// With the opt-in on, the same single visit is enough — and the offer says why
/// it was made, which is the class the setting's warning is about.
#[test]
fn the_eager_opt_in_reaches_the_learner_and_offers_from_the_first_visit() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    // A delivery name generalizes to its domain, so what the user is offered
    // covers the whole CDN rather than the one host seen so far.
    assert_eq!(candidates[0].proposed_match, "edgefarm.net");
    assert_eq!(candidates[0].match_kind, AUTO_RULE_MATCH_KIND_SUFFIX);
    assert_eq!(candidates[0].signal, AUTO_RULE_SIGNAL_DELIVERY_NAME);
}

/// The collateral rescue asks this before steering a host onto the primary. An
/// offer covers its subdomains whatever its match kind, because accepting it
/// writes a rule that does — `CanonicalRuleSet` expands every exact rule into a
/// suffix one. Reading it narrower sent `static.cdninsta.test` to the primary
/// while `cdninsta.test` sat in the offer.
#[test]
fn a_parked_offer_covers_the_subdomains_of_what_it_proposes() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);
    let offered = &f.engine.candidates(SID)[0];
    assert_eq!(offered.proposed_match, "cdn.example");

    assert!(f.engine.covers_pending_secondary_host("cdn.example"));
    assert!(f.engine.covers_pending_secondary_host("static.cdn.example"));
    assert!(f
        .engine
        .covers_pending_secondary_host("STATIC.CDN.EXAMPLE."));
    // Not a subdomain — a shared suffix is not a shared name.
    assert!(!f.engine.covers_pending_secondary_host("evilcdn.example"));
    assert!(!f.engine.covers_pending_secondary_host("example"));
}

/// The learner takes its configuration once and keeps it, so turning the setting
/// on mid-session has to reach a ledger that already exists.
#[test]
fn flipping_the_opt_in_reconfigures_the_live_ledger() {
    let opted_in = Arc::new(AtomicBool::new(false));
    let f = fixture_with_eager_delivery(Arc::clone(&opted_in));
    one_visit(&f.engine, &["assets.edgefarm.net"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 0, "gated while off");

    opted_in.store(true, Ordering::Relaxed);
    f.engine.expire_settings_memo();
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1, "the new setting reached the ledger");
    assert_eq!(
        f.engine.candidates(SID)[0].signal,
        AUTO_RULE_SIGNAL_DELIVERY_NAME
    );
}

/// Every offer carries its evidence class, not just the delivery-named ones.
#[test]
fn a_co_activity_suggestion_reports_that_signal() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["helper.unrelated"]);

    assert_eq!(f.engine.tick(SID, later()).parked, 1);
    assert_eq!(
        f.engine.candidates(SID)[0].signal,
        AUTO_RULE_SIGNAL_CO_ACTIVITY
    );
}

// ── One clock for every observation source ───────────────────────────────────
//
// The ledger compares timestamps from three sources — the DNS consumer, the
// relay's flow observer, and the reverse-lookup learner — against one another
// and against the proposal tick. Two of them once reported "millis since this
// observer started", which sits in 1970 next to the wall-clock the other two
// use: every window those sources opened was invisible to the rest, and every
// candidate they reported landed outside all of them. The API takes a
// `SystemTime` so the mistake cannot be spelled; these tests keep it dead.

/// A realistic wall-clock instant — a monotonic "since start" value could never
/// be confused for one.
fn wall_clock() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(1_786_000_000_000)
}

#[test]
fn a_relayed_flow_opens_a_window_the_dns_path_can_see() {
    let f = fixture(AutoRulesMode::Suggest);
    // The browser answered from its own cache, so the only sign the user is on
    // the site is the relayed flow. Two visits, because a delivery-named
    // companion the caller did not see in use needs two windows.
    for visit in [0_u64, 100] {
        let opened = wall_clock() + Duration::from_secs(visit);
        f.engine.note_flow(SID, "site.example", opened);
        // A companion resolved through us a second later, on the DNS clock.
        let at = unix_ms(opened + Duration::from_secs(1)).max(0) as u64;
        if let Some(mut batch) = f.engine.begin_batch(SID) {
            batch.observe(at, "cdn.example", CoActivityKind::Candidate);
        }
    }

    let summary = f.engine.tick(SID, wall_clock() + Duration::from_secs(120));
    assert_eq!(
        summary.parked, 1,
        "a window opened by a flow must accept a candidate seen by DNS"
    );
}

#[test]
fn a_host_named_only_by_reverse_lookup_lands_inside_the_open_window() {
    let f = fixture(AutoRulesMode::Suggest);
    // The site itself resolved through us — the anchor window is DNS-opened.
    let at = unix_ms(wall_clock()).max(0) as u64;
    if let Some(mut batch) = f.engine.begin_batch(SID) {
        batch.observe(
            at,
            "site.example",
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            },
        );
    }
    // Its CDN never crossed our DNS path (DoH); we only have the name because
    // a blocked connection was resolved backwards.
    f.engine
        .note_candidate_in_use(SID, "cdn.example", wall_clock() + Duration::from_secs(1));

    let summary = f.engine.tick(SID, wall_clock() + Duration::from_secs(2));
    assert_eq!(
        summary.parked, 1,
        "a reverse-confirmed name must reach the offer from one visit"
    );
}

// ── ISP notice-page candidates — gated on the verdict, not the observation ──

#[test]
fn an_isp_block_page_finding_is_silent_while_the_flag_is_off() {
    // Default fixture: the flag is off, so recognising the page must not be
    // enough on its own to reach the journal.
    let f = fixture(AutoRulesMode::Suggest);
    assert!(!f
        .engine
        .note_isp_blocked_host(SID, "blocked.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn an_isp_block_page_finding_parks_exactly_one_candidate_once_armed() {
    let f = fixture_with_isp_block_candidates(AutoRulesMode::Suggest);
    assert!(f
        .engine
        .note_isp_blocked_host(SID, "Blocked.Example.", wall_clock()));
    // A second sighting of the same host refreshes the existing offer rather
    // than duplicating it — one host, one candidate.
    assert!(f.engine.note_isp_blocked_host(
        SID,
        "blocked.example",
        wall_clock() + Duration::from_secs(60)
    ));

    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(
        c.anchor, "blocked.example",
        "normalised: lowercased, no trailing dot"
    );
    assert_eq!(c.proposed_match, "blocked.example");
    assert_eq!(c.match_kind, AUTO_RULE_MATCH_KIND_SUFFIX);
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_ISP_BLOCK_PAGE);
}

#[test]
fn a_host_already_covered_by_a_rule_is_never_offered_as_an_isp_block_candidate() {
    let f = fixture_with_isp_block_candidates(AutoRulesMode::Suggest);
    // The fixture's own rule book already covers `site.example`.
    assert!(!f
        .engine
        .note_isp_blocked_host(SID, "site.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

// ── Placeholder answers — the host says the main link cannot carry it ───────

/// Not behind a flag, unlike the notice-page signal: this one reads addresses,
/// not a page, and an address nothing can be reached at is a fact.
#[test]
fn a_placeholder_answer_parks_one_candidate_signed_by_the_host_itself() {
    let f = fixture(AutoRulesMode::Suggest);
    assert!(f
        .engine
        .note_placeholder_answer_host(SID, "Journal.Example.", wall_clock()));
    // Seeing it again refreshes the same offer instead of stacking another.
    assert!(f.engine.note_placeholder_answer_host(
        SID,
        "journal.example",
        wall_clock() + Duration::from_secs(60)
    ));

    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.anchor, "journal.example", "normalised, and signs itself");
    assert_eq!(c.proposed_match, "journal.example");
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER);
}

#[test]
fn a_host_already_covered_by_a_rule_is_never_offered_for_a_placeholder_answer() {
    let f = fixture(AutoRulesMode::Suggest);
    // The fixture's own rule book already covers `site.example`.
    assert!(!f
        .engine
        .note_placeholder_answer_host(SID, "site.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn a_placeholder_answer_is_silent_while_suggestions_are_off() {
    let f = fixture(AutoRulesMode::Off);
    assert!(!f
        .engine
        .note_placeholder_answer_host(SID, "journal.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

// ── A host that fails on the main link signs its own offer ──────────────────

/// A fixture whose main-link verdicts come from a map a test can write, which
/// is what the stall registry is to production.
fn fixture_with_main_link_verdicts(
    verdicts: Arc<Mutex<HashMap<String, PrimaryBehavior>>>,
) -> Fixture {
    let mut f = build_fixture(
        AutoRulesMode::Suggest,
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        None,
    );
    f.engine = f
        .engine
        // Merged over the subtree, exactly as the production source does: an
        // offer is written as a suffix, so its verdict is about everything
        // the rule would carry, not about the bare name.
        .with_primary_behavior_source(Arc::new(move |name: &str| {
            let suffix = format!(".{name}");
            verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|(host, _)| host.as_str() == name || host.ends_with(&suffix))
                .map(|(_, behavior)| *behavior)
                .fold(PrimaryBehavior::Unknown, PrimaryBehavior::merge)
        }));
    f
}

fn set_verdict(
    verdicts: &Arc<Mutex<HashMap<String, PrimaryBehavior>>>,
    host: &str,
    behavior: PrimaryBehavior,
) {
    verdicts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(host.to_string(), behavior);
}

/// The field case: connections complete their handshake on the main link and
/// are then dropped, keyed on the name. Nothing about the address says so — the
/// failures do.
#[test]
fn a_host_that_keeps_failing_on_the_main_link_is_offered_the_other_route() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);

    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "Forum.Talk.Example.", wall_clock()));
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.proposed_match, "forum.talk.example");
    assert_eq!(c.anchor, c.proposed_match, "the host signs its own offer");
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED);
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.primary_behavior, AUTO_RULE_PRIMARY_BEHAVIOR_STALLS);
}

/// "Whose name is this" is answerable only where a site pulled the name in.
/// A self-signed offer IS its own anchor, so the comparison used to return
/// "the site's own name" for every ad host that failed on the main link — the
/// inbox stated as fact the opposite of the fact. Both sides are asserted
/// here: an absent answer for the self-signed offer proves nothing unless the
/// companion beside it still gets one.
#[test]
fn only_an_offer_with_a_real_anchor_says_whose_name_it_is() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "ads.tracker.example", wall_clock()));

    let candidates = f.engine.candidates(SID);
    let companion = candidates
        .iter()
        .find(|c| c.proposed_match == "cdn.example")
        .expect("the companion offer");
    assert_eq!(
        companion.third_party,
        Some(true),
        "a site pulled this name in, so the question has an answer"
    );
    let self_signed = candidates
        .iter()
        .find(|c| c.proposed_match == "ads.tracker.example")
        .expect("the self-signed offer");
    assert_eq!(
        self_signed.anchor, self_signed.proposed_match,
        "the host signs its own offer — there is no site to be third-party to"
    );
    assert_eq!(
        self_signed.third_party, None,
        "with no anchor site the question was never posed"
    );
}

/// A visit count is a fact about a PAIR — this host beside that site, across
/// distinct visits. An offer a host signs about itself has no pair, and the 1
/// it used to carry made the inbox say "seen in 1 visit" about a host whose
/// evidence is three failed connections in a row.
///
/// The count also ranks the list, so the second half of this test is the one
/// that matters: making it optional must not move anything.
#[test]
fn a_self_signed_offer_counts_no_visits_and_keeps_its_place_in_the_list() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "ads.tracker.example", wall_clock()));

    let candidates = f.engine.candidates(SID);
    let companion = candidates
        .iter()
        .find(|c| c.proposed_match == "cdn.example")
        .expect("the companion offer");
    assert_eq!(
        companion.observations,
        Some(2),
        "a pair seen across two visits still says so"
    );
    let self_signed = candidates
        .iter()
        .find(|c| c.proposed_match == "ads.tracker.example")
        .expect("the self-signed offer");
    assert_eq!(
        self_signed.observations, None,
        "no pair means no visits to count"
    );
    // Evidence-first ordering, unchanged: the companion carries an affinity and
    // the self-signed offer carries none, so the companion leads.
    let order: Vec<&str> = candidates
        .iter()
        .map(|c| c.proposed_match.as_str())
        .collect();
    assert_eq!(
        order,
        vec!["cdn.example", "ads.tracker.example"],
        "an optional count must not reorder the inbox"
    );
}

/// The offer is "move this into the tunnel". When the tunnel turns out not to
/// reach the host either, the move would trade one route that cannot carry it
/// for another that cannot — that is somebody else's outage, not a suggestion.
///
/// The check that matters is the third case: an offer nobody probed must be
/// untouched, because "not measured" and "measured as useless" are different
/// facts and only one of them is a reason to stay silent.
#[test]
fn an_offer_the_additional_route_cannot_help_is_withdrawn_and_an_unchecked_one_is_not() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    set_verdict(&verdicts, "chat.other.example", PrimaryBehavior::Stalls);
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", wall_clock()));
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "chat.other.example", wall_clock()));
    assert_eq!(f.engine.candidates(SID).len(), 2, "both start out offered");

    // Measured: the tunnel reaches neither better nor at all.
    f.engine
        .note_secondary_reach(SID, "forum.talk.example", false, wall_clock());

    let after: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(
        after,
        vec!["chat.other.example".to_string()],
        "the one the tunnel cannot help is gone; the unchecked one stays",
    );

    // And the positive control for the gate itself: a host the tunnel DOES
    // reach keeps its offer, so the rule is about the answer and not about
    // having been probed at all.
    f.engine
        .note_secondary_reach(SID, "chat.other.example", true, wall_clock());
    let reach = f
        .engine
        .candidates(SID)
        .into_iter()
        .find(|c| c.proposed_match == "chat.other.example")
        .map(|c| c.secondary_reach);
    assert_eq!(
        reach,
        Some(Some(true)),
        "a reachable host keeps the offer and carries what was found",
    );
}

/// A self-signed offer describes the network as it was minutes ago, so it goes
/// stale faster than a companion offer, which describes which hosts belong
/// together. Both halves are asserted: a shorter life is only meaningful if the
/// longer one is still longer.
#[test]
fn a_self_signed_offer_goes_stale_sooner_than_a_companion_one() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    // Both offers are stamped from the same clock, or "older" would only mean
    // "created on a different timeline".
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "ads.tracker.example", later()));
    assert_eq!(
        f.engine.candidates(SID).len(),
        2,
        "both are offered at first"
    );

    // Six hours on: past the self-signed horizon, well inside the companion one.
    let six_hours = later() + Duration::from_secs(6 * 60 * 60);
    f.engine.tick(SID, six_hours);

    let left: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(
        left,
        vec!["cdn.example".to_string()],
        "the self-signed offer expired and the companion one did not",
    );
}

/// The whole of the user-facing rule: a site the main link carries is never
/// offered the additional route. Not "offered and greyed out" — not offered.
#[test]
fn a_host_the_main_link_carries_is_never_offered_at_all() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "cdn.tracker.example", PrimaryBehavior::Responds);

    for signal_call in [
        AutoRulesEngine::note_main_link_blocked_host
            as fn(&AutoRulesEngine, &str, &str, SystemTime) -> bool,
        AutoRulesEngine::note_placeholder_answer_host,
    ] {
        assert!(!signal_call(
            &f.engine,
            SID,
            "cdn.tracker.example",
            wall_clock()
        ));
    }
    assert!(f.engine.candidates(SID).is_empty());
}

/// Positive control for the test above: the SAME calls with the SAME host park
/// an offer as soon as the main link stops answering for it. Without this the
/// test above would also pass if the signals were simply dead.
#[test]
fn the_same_host_is_offered_once_the_main_link_stops_answering() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "cdn.tracker.example", PrimaryBehavior::Stalls);
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "cdn.tracker.example", wall_clock()));
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

/// An offer parked while the host was failing is withdrawn once it works —
/// from the list a person reads AND from the parked set the badge counts.
#[test]
fn an_offer_is_withdrawn_when_the_main_link_starts_carrying_the_host() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", wall_clock()));
    assert_eq!(f.engine.candidates(SID).len(), 1);
    assert_eq!(f.engine.pending_count(SID), 1);

    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Responds);
    assert!(
        f.engine.candidates(SID).is_empty(),
        "the reason for the offer stopped being true",
    );
    f.engine.tick(SID, wall_clock() + Duration::from_secs(60));
    assert_eq!(
        f.engine.pending_count(SID),
        0,
        "and the badge stops counting it",
    );
}

/// A self-signed offer states what the network is doing now, and nothing
/// behind it survives a restart — so it must not come back asserting a
/// condition nobody has re-checked. A companion offer, which rests on evidence
/// that IS restored, still does: without that control this test would pass on
/// an engine that simply lost its parked set.
#[test]
fn a_self_signed_offer_does_not_come_back_after_a_restart_but_a_companion_does() {
    let store = Arc::new(InMemoryPendingStore::new());
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    {
        let mut f = build_fixture(
            AutoRulesMode::Suggest,
            Arc::new(InMemoryDismissalStore::new()),
            Arc::clone(&store),
            None,
        );
        let v = Arc::clone(&verdicts);
        f.engine = f
            .engine
            .with_primary_behavior_source(Arc::new(move |host: &str| {
                v.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(host)
                    .copied()
                    .unwrap_or(PrimaryBehavior::Unknown)
            }));
        set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
        assert!(f
            .engine
            .note_main_link_blocked_host(SID, "forum.talk.example", wall_clock()));
        two_visits(&f.engine, &["cdn.example"]);
        f.engine.tick(SID, later());
        let parked: Vec<String> = f
            .engine
            .candidates(SID)
            .into_iter()
            .map(|c| c.proposed_match)
            .collect();
        assert!(
            parked.contains(&"forum.talk.example".to_string()),
            "{parked:?}"
        );
        assert!(parked.contains(&"cdn.example".to_string()), "{parked:?}");
    }

    let restarted = fixture_with_pending_store(AutoRulesMode::Suggest, store);
    let after: Vec<String> = restarted
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert!(
        !after.contains(&"forum.talk.example".to_string()),
        "a self-signed offer must re-earn itself: {after:?}",
    );
    assert!(
        after.contains(&"cdn.example".to_string()),
        "a companion offer still survives the restart: {after:?}",
    );
}

/// An ad or telemetry endpoint the provider cuts is not a site anyone was
/// trying to open, and it belongs to everybody — routing it would drag
/// unrelated traffic along. The four names are the ones a live run actually
/// offered; every one of them was measured as genuinely cut on the main link,
/// so the measurement is not what disqualifies them.
#[test]
fn shared_ad_and_telemetry_endpoints_are_never_offered_however_badly_they_fail() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    for host in [
        "ads.googlesyndication.com",
        "pubads.g.doubleclick.net",
        "stats.g.doubleclick.net",
        "www.googletagservices.com",
    ] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(
            !f.engine
                .note_main_link_blocked_host(SID, host, wall_clock()),
            "{host}",
        );
    }
    assert!(f.engine.candidates(SID).is_empty());

    // Positive control: a site host failing the same way IS offered, so the
    // test above cannot pass on a detector that simply stopped working.
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", wall_clock()));
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

/// One failing name is one question. The field case says why it must not
/// become a question about the whole domain: a failing subdomain was cut
/// while the apex and `www` answered normally on the main link.
#[test]
fn one_failing_subdomain_is_offered_by_its_own_name() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", wall_clock()));
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["forum.talk.example".to_string()]);
}

/// A SECOND failing name under the same domain is evidence the domain is what
/// is being cut, so the two questions collapse into one and the names they
/// replace are withdrawn.
#[test]
fn a_second_failing_name_under_one_domain_collapses_into_one_offer() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    for host in ["a.blocked.example", "b.blocked.example"] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(f
            .engine
            .note_main_link_blocked_host(SID, host, wall_clock()));
    }
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["blocked.example".to_string()], "{offered:?}");
}

/// The field case, both halves. Two names under one domain fail while the
/// apex answers — and the offer is still about the domain, because two cut
/// names prove the domain is what is being cut. One site, one question; the
/// apex travels with the site it belongs to.
#[test]
fn two_failing_names_roll_up_even_though_the_apex_still_answers() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "talk.example", PrimaryBehavior::Responds);
    for host in ["forum.talk.example", "test.talk.example"] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(f
            .engine
            .note_main_link_blocked_host(SID, host, wall_clock()));
    }
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["talk.example".to_string()], "{offered:?}");
}

/// The pass probes addresses out of the FQDN cache, and a self-signed offer is
/// about a host nothing cached. Holding it until an answer that cannot arrive
/// would silence it for good — the exact defect this whole change is about.
#[test]
fn a_self_signed_offer_is_never_held_waiting_for_a_pass_that_cannot_answer() {
    let mut dto = main_link_dto(
        "forum.talk.example",
        "forum.talk.example",
        AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED,
        "",
    );
    assert!(!awaiting_the_main_link(&dto, true));
    // A companion with no verdict yet IS held while the pass can still answer.
    dto.anchor = "site.example".to_string();
    dto.proposed_match = "cdn.other.example".to_string();
    dto.signal = AUTO_RULE_SIGNAL_CO_ACTIVITY.to_string();
    assert!(awaiting_the_main_link(&dto, true));
}

/// A companion offer is judged differently on purpose: a routed site's OWN
/// delivery name can complete a connection and still serve a refusal, so
/// "it answers" does not settle it. Only the self-signed offers are silenced.
#[test]
fn a_main_link_answer_does_not_silence_a_companion_of_the_same_brand() {
    let responding = main_link_dto(
        "site.example",
        "cdn.site.example",
        AUTO_RULE_SIGNAL_CO_ACTIVITY,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(!settled_self_signed(&responding));
    assert!(!settled_by_the_main_link(&responding));

    let mut self_signed = responding.clone();
    self_signed.anchor = "cdn.site.example".to_string();
    self_signed.signal = AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED.to_string();
    assert!(settled_self_signed(&self_signed));
    assert!(settled_by_the_main_link(&self_signed));
}

// ── "It already works on the main link" ──────────────────────────────────────

/// A parked candidate around one DTO — the suffix form the flow always writes.
fn pending_candidate(dto: AutoRuleCandidateDto) -> PendingCandidate {
    PendingCandidate {
        dto,
        route: RouteRole::Secondary,
        match_kind: AuthoredMatchKind::SuffixDomain,
    }
}

/// One candidate, spelled the way the discovery flow spells it.
fn main_link_dto(
    anchor: &str,
    proposed: &str,
    signal: &str,
    behavior: &str,
) -> AutoRuleCandidateDto {
    AutoRuleCandidateDto {
        id: format!("{anchor}|{proposed}"),
        anchor: anchor.to_string(),
        proposed_match: proposed.to_string(),
        match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.to_string(),
        route: RouteRole::Secondary.slug().to_string(),
        affinity: 0.9,
        observations: Some(3),
        first_seen_unix_ms: 1,
        last_seen_unix_ms: 2,
        signal: signal.to_string(),
        consumers: Vec::new(),
        consumers_changed_unix_ms: 2,
        primary_behavior: behavior.to_string(),
        anchor_refuses_main_link: false,
        observed_members: Vec::new(),
        served_by_main_link: false,
        third_party: None,
        secondary_reach: None,
    }
}

/// The reported case, one step earlier than the check that was supposed to
/// cover it: nothing had measured `cdnjs` yet, and an unmeasured host reads
/// exactly like an unreachable one. `news.example` hit it after `assistant.example` did,
/// because the fix had been aimed at the verdict, not at its absence.
#[test]
fn a_third_party_with_no_verdict_yet_waits_instead_of_asking() {
    let unmeasured = main_link_dto(
        "news.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        "", // the pass has not answered for it yet
    );
    assert!(
        awaiting_the_main_link(&unmeasured, true),
        "with an answer still coming, the question waits for it"
    );

    // With the pass switched off no answer is coming, and holding the question
    // forever would retire the feature behind the user's back.
    assert!(
        !awaiting_the_main_link(&unmeasured, false),
        "no pass, nothing to wait for"
    );
}

/// What must NOT be held: the routed site's own names, and anything the pass
/// has already answered for. Without this the hold would swallow the very
/// suggestions the feature exists to make.
#[test]
fn the_hold_releases_the_sites_own_names_and_answered_hosts() {
    let own = main_link_dto(
        "news.example",
        "cdn.news.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        "",
    );
    assert!(
        !awaiting_the_main_link(&own, true),
        "the site's own delivery name is asked about regardless"
    );

    let brand = main_link_dto(
        "news.example",
        "news.example.org",
        AUTO_RULE_SIGNAL_BRAND_RELATED,
        "",
    );
    assert!(
        !awaiting_the_main_link(&brand, true),
        "the brand tier never waits on connectivity"
    );

    for behavior in [
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
        AUTO_RULE_PRIMARY_BEHAVIOR_CUT,
    ] {
        let answered = main_link_dto(
            "news.example",
            "cdnjs.cloudflare.com",
            AUTO_RULE_SIGNAL_DELIVERY_NAME,
            behavior,
        );
        assert!(
            !awaiting_the_main_link(&answered, true),
            "behavior {behavior:?} is an answer; the wait is over"
        );
    }
}

#[test]
fn a_shared_cdn_that_answers_on_the_main_link_is_not_worth_asking_about() {
    // The reported case: cdnjs answers perfectly well without the tunnel, and
    // the tray kept offering it because delivery names skipped the check that
    // co-activity names already had.
    let cdn = main_link_dto(
        "assistant.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(settled_by_the_main_link(&cdn));

    let ad = main_link_dto(
        "assistant.example",
        "casalemedia.com",
        AUTO_RULE_SIGNAL_CO_ACTIVITY,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(settled_by_the_main_link(&ad));
}

#[test]
fn the_sites_own_name_keeps_its_question_even_when_it_answers() {
    // Answering is not serving: ChatGPT answers main-link addresses with a
    // refusal, so its own names stay on offer whatever the connectivity says.
    let own = main_link_dto(
        "assistant.example",
        "cdn.assistant.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(!settled_by_the_main_link(&own));

    let brand = main_link_dto(
        "assistant.example",
        "chatgpt.io",
        AUTO_RULE_SIGNAL_BRAND_RELATED,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(
        !settled_by_the_main_link(&brand),
        "brand tier is never settled by connectivity"
    );
}

#[test]
fn a_host_that_fails_on_the_main_link_is_still_asked_about() {
    for behavior in [
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
        AUTO_RULE_PRIMARY_BEHAVIOR_CUT,
        "",
    ] {
        let dto = main_link_dto(
            "assistant.example",
            "cdnjs.cloudflare.com",
            AUTO_RULE_SIGNAL_DELIVERY_NAME,
            behavior,
        );
        assert!(
            !settled_by_the_main_link(&dto),
            "behavior {behavior:?} is not an answer"
        );
    }
}

#[test]
fn a_settled_candidate_does_not_hold_the_host_on_the_additional_route() {
    // The pair that has to agree: what the tray will not ask about must not
    // keep steering traffic as if the user had already said yes.
    let engine = engine_over(
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    let settled = main_link_dto(
        "assistant.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    let open = main_link_dto(
        "assistant.example",
        "assets.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    engine.park(
        SID,
        vec![pending_candidate(settled), pending_candidate(open)],
        10,
    );

    assert!(
        !engine.covers_pending_secondary_host("cdnjs.cloudflare.com"),
        "a host the tray will not ask about must not be pinned as if accepted"
    );
    assert!(engine.covers_pending_secondary_host("assets.example"));
}

/// The dropped-companion line is deduped on the SELECTION, not on the event —
/// otherwise a steady set writes the same names every ten seconds, which is how
/// a log stops being read.
#[test]
fn an_unchanged_dropped_set_is_not_worth_a_second_line() {
    let note = QuietNote {
        inert: 2,
        sample: vec!["ozonru.me (www.ozon.ru)".to_string()],
    };
    assert!(
        quiet_note_is_news(None, &note),
        "the first sighting is always news"
    );
    assert!(!quiet_note_is_news(Some(&note), &note));

    // One companion swapped for another keeps the count — the sample is what
    // tells them apart, so it has to count as news.
    let swapped = QuietNote {
        inert: 2,
        sample: vec!["cdnjs.cloudflare.com (www.ozon.ru)".to_string()],
    };
    assert!(quiet_note_is_news(Some(&note), &swapped));

    // …and a set that grew past what the sample shows is news too.
    let grown = QuietNote {
        inert: 3,
        sample: note.sample.clone(),
    };
    assert!(quiet_note_is_news(Some(&note), &grown));
}

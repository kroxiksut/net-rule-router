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
                address_match: match rule.match_kind {
                    AuthoredMatchKind::ExactHost => {
                        Some(CanonicalAddressMatch::ExactFqdn(rule.value.clone()))
                    }
                    AuthoredMatchKind::SuffixDomain => {
                        Some(CanonicalAddressMatch::SuffixDomain(rule.value.clone()))
                    }
                    AuthoredMatchKind::Application => None,
                },
                app_match: matches!(rule.match_kind, AuthoredMatchKind::Application).then(|| {
                    nrr_domain::canonical::CanonicalAppMatch {
                        pattern: nrr_domain::canonical::CanonicalAppPattern::Exact(
                            rule.value.clone(),
                        ),
                        include_child_processes: false,
                    }
                }),
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

// ── Fixtures shared by more than one theme ───────────────────────────────

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
/// A realistic wall-clock instant — a monotonic "since start" value could never
/// be confused for one.
fn wall_clock() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(1_786_000_000_000)
}

mod accept_dismiss;
mod consumers;
mod durability;
mod main_link_works;
mod offer_signals;
mod proposal;

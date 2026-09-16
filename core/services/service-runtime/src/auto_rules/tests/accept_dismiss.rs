use super::*;

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

use super::*;

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

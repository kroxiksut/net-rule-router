use super::*;

// ── Less certain offers: asked in `suggest`, never written unasked ───────────

/// Carries the anchor's brand (`site.example`), is not delivery-named and not
/// under the anchor's own domain: one visit leaves only the single-window
/// brand fallback able to offer it.
const LOOK_ALIKE: &str = "login.site.test";

/// A fixture whose mode the test can switch, as the settings screen does.
fn switchable(mode: &Arc<Mutex<AutoRulesMode>>) -> Fixture {
    let mut f = fixture(AutoRulesMode::Suggest);
    let read = Arc::clone(mode);
    f.engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        Arc::new(move |_sid: &str| *read.lock().unwrap_or_else(|p| p.into_inner())),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_author(Arc::clone(&f.author) as Arc<dyn AutoRuleAuthor>);
    f
}

#[test]
fn suggest_offers_a_single_sighting_of_the_sites_name_marked_less_certain() {
    let f = fixture(AutoRulesMode::Suggest);
    one_visit(&f.engine, &[LOOK_ALIKE]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.proposed_match, LOOK_ALIKE);
    assert_eq!(c.anchor, "site.example");
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_BRAND_RELATED);
    assert_eq!(c.less_certain, AUTO_RULE_LESS_CERTAIN_BRAND_SEEN_ONCE);
    assert_eq!(c.observations, Some(1));
    assert!(f.author.calls().is_empty());
}

#[test]
fn auto_never_writes_a_single_sighting_of_the_sites_name() {
    let f = fixture(AutoRulesMode::Auto);
    one_visit(&f.engine, &[LOOK_ALIKE]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.authored, 0);
    assert!(f.author.calls().is_empty());
    assert!(f.engine.candidates(SID).is_empty());
}

/// The offer was parked while a person decided; switching to `auto` does not
/// turn it into a rule. Only full evidence — a second visit — does, and then
/// it is a certain finding of its own.
#[test]
fn a_less_certain_offer_is_not_written_after_switching_to_auto() {
    let mode = Arc::new(Mutex::new(AutoRulesMode::Suggest));
    let f = switchable(&mode);
    one_visit(&f.engine, &[LOOK_ALIKE]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);

    *mode.lock().unwrap_or_else(|p| p.into_inner()) = AutoRulesMode::Auto;
    f.engine.expire_settings_memo();
    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.authored, 0);
    assert!(f.author.calls().is_empty());
    let still_asked = f.engine.candidates(SID);
    assert_eq!(still_asked.len(), 1, "the person can still answer it");
    assert_eq!(
        still_asked[0].less_certain,
        AUTO_RULE_LESS_CERTAIN_BRAND_SEEN_ONCE
    );

    one_visit_at(&f.engine, 100_000, &[LOOK_ALIKE]);
    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.authored, 1);
    let calls = f.author.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, AutoRuleReason::SiteCompanion);
    assert_eq!(calls[0].1[0].value, LOOK_ALIKE);
}

/// The one place a rule is written unasked holds the line itself, whatever
/// hands it a less certain offer.
#[test]
fn the_unasked_writer_parks_a_less_certain_offer_instead_of_writing_it() {
    let f = fixture(AutoRulesMode::Auto);
    let mut dto = main_link_dto(
        "site.example",
        LOOK_ALIKE,
        AUTO_RULE_SIGNAL_BRAND_RELATED,
        "",
    );
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, LOOK_ALIKE);
    dto.less_certain = AUTO_RULE_LESS_CERTAIN_BRAND_SEEN_ONCE.to_string();
    let Some(weak) = PendingCandidate::from_dto(dto) else {
        unreachable!("the fixture DTO names a known route and match kind")
    };

    assert_eq!(f.engine.author_now(SID, &[weak], later()), 0);
    assert!(f.author.calls().is_empty());
    assert_eq!(parked(&f.engine), 1);
}

/// A name a reverse lookup produced is whatever the owner of the address chose
/// to call it. `auto` asks a person about it instead of writing it into the
/// user's rules.
#[test]
fn auto_parks_a_companion_named_by_reverse_lookup() {
    let f = fixture(AutoRulesMode::Auto);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.note_reverse_named_in_use(
        SID,
        "edge.cdn.example",
        SystemTime::UNIX_EPOCH + Duration::from_millis(100_500),
    );

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.authored, 0, "nothing is written unasked");
    assert!(f.author.calls().is_empty());
    assert!(parked(&f.engine) >= 1, "the person is asked instead");

    let other = fixture(AutoRulesMode::Auto);
    two_visits(&other.engine, &["cdn.example"]);
    assert_eq!(
        other.engine.tick(SID, later()).authored,
        1,
        "the same companion seen only in lookups is still written"
    );
}

/// Until a person says yes, a less certain offer does not change where any
/// traffic goes.
#[test]
fn a_less_certain_offer_does_not_hold_its_host_off_the_main_route() {
    let f = fixture(AutoRulesMode::Suggest);
    one_visit(&f.engine, &[LOOK_ALIKE]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);

    assert!(!f.engine.covers_pending_secondary_host(LOOK_ALIKE));
}

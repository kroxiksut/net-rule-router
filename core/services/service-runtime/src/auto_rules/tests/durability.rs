use super::*;

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

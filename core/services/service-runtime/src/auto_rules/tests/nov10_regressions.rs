use super::*;

fn pending(dto: AutoRuleCandidateDto, kind: AuthoredMatchKind) -> PendingCandidate {
    PendingCandidate {
        dto,
        route: RouteRole::Secondary,
        match_kind: kind,
    }
}

#[test]
fn nov10_the_running_service_is_not_offered_as_an_application_route() {
    let own = crate::app_observation_lookup::own_process_key();
    assert!(
        !own.is_empty(),
        "the test process has a real executable identity"
    );
    for resolver in [false, true] {
        let f = fixture(AutoRulesMode::Suggest);
        let addresses = ["203.0.113.1", "203.0.113.2", "203.0.113.3"].map(|ip| {
            ip.parse()
                .unwrap_or_else(|error| panic!("address: {error}"))
        });
        let offered = if resolver {
            f.engine
                .note_app_own_resolver(SID, own, &addresses, wall_clock())
        } else {
            f.engine
                .note_app_main_link_blocked(SID, own, &addresses, wall_clock())
        };
        assert!(
            !offered,
            "the routing mechanism cannot be offered a route through itself (resolver={resolver})"
        );
        assert!(f.engine.candidates(SID).is_empty());
    }
}

#[test]
fn nov10_a_previously_parked_service_offer_is_hidden_and_durably_retired() {
    let store = Arc::new(InMemoryPendingStore::new());
    let f = fixture_with_pending_store(AutoRulesMode::Suggest, Arc::clone(&store));
    let own = crate::app_observation_lookup::own_process_key();
    let mut dto = main_link_dto(
        own,
        own,
        nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    dto.id = candidate_id(
        SID,
        nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION,
        own,
    );
    dto.match_kind = nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION.into();
    f.engine.park(
        SID,
        vec![pending(dto, AuthoredMatchKind::Application)],
        unix_ms(wall_clock()),
    );
    assert!(
        f.engine.candidates(SID).is_empty(),
        "old own-process offers must disappear from the read path immediately"
    );
    f.engine.tick(SID, wall_clock());
    assert_eq!(
        parked(&f.engine),
        0,
        "the timer must retire the parked offer too"
    );
    assert!(
        store.load_all().get(SID).is_none_or(Vec::is_empty),
        "it must not return after restart"
    );
    assert!(f.author.calls().is_empty());
}

#[test]
fn nov10_two_failed_siblings_do_not_claim_the_healthy_apex_or_each_other() {
    let mut f = fixture(AutoRulesMode::Suggest);
    f.engine = f.engine.with_primary_behavior_source(Arc::new(|_, host| {
        if host == "scoped-failure.example" {
            PrimaryBehavior::Responds
        } else {
            PrimaryBehavior::Stalls
        }
    }));
    let hosts = [
        "forum.scoped-failure.example",
        "test.scoped-failure.example",
    ];
    for host in hosts {
        assert!(f.engine.note_main_link_blocked_host(
            SID,
            host,
            HostCounts::default(),
            wall_clock()
        ));
    }
    let rows = f.engine.candidates(SID);
    let mut actual: Vec<_> = rows.iter().map(|row| row.proposed_match.as_str()).collect();
    actual.sort_unstable();
    assert_eq!(
        actual, hosts,
        "two independent host failures do not prove a domain-wide failure"
    );
    assert!(
        rows.iter()
            .all(|row| row.match_kind == AUTO_RULE_MATCH_KIND_EXACT),
        "a measured host does not authorize unmeasured descendants"
    );
    let ids: Vec<_> = rows.iter().map(|row| row.id.clone()).collect();
    f.engine
        .accept(SID, &ids, false, wall_clock())
        .unwrap_or_else(|error| panic!("accept: {error:?}"));
    assert!(f
        .author
        .calls()
        .iter()
        .flat_map(|(_, rules)| rules)
        .all(|rule| hosts.contains(&rule.value.as_str())
            && matches!(rule.match_kind, AuthoredMatchKind::ExactHost)));

    let fresh = fixture(AutoRulesMode::Suggest);
    let obsolete: Vec<_> = (0..128)
        .map(|n| {
            let host = format!("obsolete-wide-{n}.example");
            let mut dto = main_link_dto("site.example", &host, AUTO_RULE_SIGNAL_CO_ACTIVITY, "");
            dto.match_kind = AUTO_RULE_MATCH_KIND_SUFFIX.into();
            pending(dto, AuthoredMatchKind::SuffixDomain)
        })
        .collect();
    fresh.engine.park(SID, obsolete, unix_ms(wall_clock()));
    assert!(fresh.engine.note_placeholder_answer_host(
        SID,
        "new-actual-host.example",
        wall_clock()
    ));
    assert!(
        fresh
            .engine
            .candidates(SID)
            .iter()
            .any(|row| row.proposed_match == "new-actual-host.example"),
        "obsolete broad rows cannot occupy every pending slot and discard a new exact finding"
    );
}

#[test]
fn nov10_a_refusing_anchor_does_not_overrule_an_actual_third_party_host_response() {
    let mut f = fixture(AutoRulesMode::Suggest);
    f.engine = f
        .engine
        .with_refusing_anchors(Arc::new(|_| vec!["site.example".into()]));
    let host = "fe-static.unrelated.example";
    let mut dto = main_link_dto(
        "site.example",
        host,
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    let candidate = pending(dto, AuthoredMatchKind::ExactHost);
    f.engine
        .park(SID, vec![candidate.clone()], unix_ms(wall_clock()));
    let rows = f.engine.candidates(SID);
    assert_eq!(
        rows.len(),
        1,
        "the measured correlation may remain inspectable"
    );
    assert!(
        rows[0].served_by_main_link,
        "the actual host's own successful primary evidence outranks anchor correlation"
    );
    assert_eq!(shown_by_default_count(&rows), 0);
    assert!(!f.engine.covers_pending_secondary_host(host));
    assert_eq!(f.engine.author_now(SID, &[candidate], wall_clock()), 0, "an actual responding host is not silently forced onto the anchor's route in automatic mode");
    assert!(f.author.calls().is_empty());
}

#[test]
fn nov10_an_independent_http_finding_is_exact_review_only_even_in_automatic_mode() {
    let f = fixture(AutoRulesMode::Auto);
    let host = "independent-http-review.example";
    let mut dto = main_link_dto(
        host,
        host,
        "http-path-reachability",
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    dto.id = candidate_id(SID, AUTO_RULE_MATCH_KIND_EXACT, host);
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    dto.secondary_reach = Some(true);
    let candidate = pending(dto, AuthoredMatchKind::ExactHost);
    assert_eq!(
        f.engine
            .author_now(SID, std::slice::from_ref(&candidate), wall_clock()),
        0,
        "HTTP route contrast is a review finding, never automatic authorization"
    );
    assert!(f.author.calls().is_empty());
    f.engine.park(SID, vec![candidate], unix_ms(wall_clock()));
    assert!(!f.engine.covers_pending_secondary_host(host));
}

#[test]
fn nov10_two_companion_names_do_not_authorize_the_unobserved_parent() {
    let f = fixture(AutoRulesMode::Suggest);
    let names = [
        "one.narrow-companion.example",
        "two.narrow-companion.example",
    ];
    two_visits(&f.engine, &names);
    f.engine.tick(SID, later());
    let rows = f.engine.candidates(SID);
    let mut hosts: Vec<_> = rows.iter().map(|row| row.proposed_match.as_str()).collect();
    hosts.sort_unstable();
    assert_eq!(
        hosts, names,
        "presentation grouping cannot become authority for an unobserved apex"
    );
    assert!(rows
        .iter()
        .all(|row| row.match_kind == AUTO_RULE_MATCH_KIND_EXACT));
}

#[test]
fn nov10_narrower_offer_shapes_do_not_reset_a_previously_declined_host() {
    let host = "declined-before-exact-shape.example";
    let f = fixture(AutoRulesMode::Suggest);
    let id = candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, host);
    f.dismissals.record(
        SID,
        &[AutoRuleDismissal {
            candidate_id: id.clone(),
            anchor: host.into(),
            proposed_match: host.into(),
            dto_json: String::new(),
        }],
        unix_ms(wall_clock()),
    );
    assert!(
        !f.engine
            .note_placeholder_answer_host(SID, host, wall_clock()),
        "a kind migration is not a new user decision"
    );
    assert!(f.engine.candidates(SID).is_empty());
    assert_eq!(
        f.dismissals.list(SID)[0].candidate_id,
        id,
        "the original refusal is preserved verbatim"
    );
}

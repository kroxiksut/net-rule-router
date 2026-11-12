use super::*;

#[test]
fn a_www_failure_offers_and_accepts_the_site_without_losing_the_observed_host() {
    let f = fixture(AutoRulesMode::Suggest);
    f.rules.also_route(&["www.manual.example"]);
    let manual_suffix = CanonicalRule {
        address_match: Some(CanonicalAddressMatch::SuffixDomain(
            "www.manual-suffix.example".into(),
        )),
        ..exact_rule("www.manual-suffix.example")
    };
    {
        let mut book = f.rules.book.lock().expect("rules");
        let mut rules = book.secondary.rules().to_vec();
        rules.push(manual_suffix.clone());
        book.secondary = CanonicalRuleSet::from_rules(rules);
    }
    assert!(f
        .engine
        .note_placeholder_answer_host(SID, "WWW.Patreon.COM.", wall_clock()));
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].proposed_match, "www.patreon.com");
    assert_eq!(candidates[0].anchor, "www.patreon.com");
    assert_eq!(
        candidates[0].id,
        candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, "www.patreon.com")
    );
    f.engine
        .accept(SID, &[candidates[0].id.clone()], false, wall_clock())
        .expect("accept suggestion");
    let calls = f.author.calls();
    assert_eq!(calls[0].1[0].value, "patreon.com");
    assert_eq!(calls[0].1[0].anchor, "www.patreon.com");
    assert_eq!(calls[0].1[0].match_kind, AuthoredMatchKind::SuffixDomain);
    let book = f.rules.active_rules().expect("rules").rule_book;
    assert!(book.secondary.rules().iter().any(|rule| {
        rule.address_match == Some(CanonicalAddressMatch::SuffixDomain("patreon.com".into()))
    }));
    assert!(book.secondary.rules().iter().any(|rule| {
        rule.address_match
            == Some(CanonicalAddressMatch::ExactFqdn(
                "www.manual.example".into(),
            ))
    }));
    assert!(book.secondary.rules().contains(&manual_suffix));
}

#[test]
fn a_www_companion_is_written_automatically_for_the_site() {
    let f = fixture(AutoRulesMode::Auto);
    let proposal = CompanionProposal {
        anchor_hostname: "site.example".into(),
        proposed: nrr_domain::companion_affinity::ProposedCompanionMatch::ExactHost(
            "www.patreon.com".into(),
        ),
        route: RouteRole::Secondary,
        signal: CompanionSignal::CoActivity,
        affinity: 1.0,
        nearest_share: 1.0,
        distinct_windows: 3,
        first_seen_ms: 1,
        last_seen_ms: 2,
        primary_behavior: PrimaryBehavior::Unknown,
        observed_members: Vec::new(),
        less_certain: None,
    };
    let candidate = to_candidate(
        &proposal,
        candidate_id(SID, AUTO_RULE_MATCH_KIND_SUFFIX, "www.patreon.com"),
    );
    assert_eq!(candidate.dto.proposed_match, "www.patreon.com");
    assert_eq!(f.engine.author_now(SID, &[candidate], wall_clock()), 1);
    let calls = f.author.calls();
    assert_eq!(calls[0].1[0].value, "patreon.com");
    assert_eq!(calls[0].1[0].anchor, "site.example");
    let book = f.rules.active_rules().expect("rules").rule_book;
    assert!(book.secondary.rules().iter().any(|rule| {
        rule.address_match == Some(CanonicalAddressMatch::SuffixDomain("patreon.com".into()))
    }));
}

#[test]
fn an_older_www_suggestion_normalizes_only_its_automatic_suffix() {
    let mut dto = main_link_dto(
        "www.patreon.com",
        "www.patreon.com",
        AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    dto.match_kind = AUTO_RULE_MATCH_KIND_SUFFIX.into();
    let suffix = PendingCandidate::from_dto(dto.clone()).expect("stored suffix");
    assert_eq!(suffix.authored_rule().value, "patreon.com");
    assert_eq!(suffix.authored_rule().anchor, "www.patreon.com");
    dto.match_kind = AUTO_RULE_MATCH_KIND_EXACT.into();
    let exact = PendingCandidate::from_dto(dto).expect("stored exact host");
    assert_eq!(exact.authored_rule().value, "www.patreon.com");
    for host in [
        "www.com",
        "www.co.uk",
        "www.github.io",
        "cdn.www.patreon.com",
    ] {
        let dto = main_link_dto(
            host,
            host,
            AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER,
            AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
        );
        let candidate = PendingCandidate::from_dto(dto).expect("stored suffix");
        assert_eq!(candidate.authored_rule().value, host);
    }
}

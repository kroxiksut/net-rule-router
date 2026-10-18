use super::*;

// ── The evidence bar by who acts on the offer ────────────────────────────

const REVIEW: ProposalUse = ProposalUse::OfferedForReview;
const UNASKED: ProposalUse = ProposalUse::AuthoredUnasked;

fn offered(
    ledger: &CompanionAffinityLedger,
    now: u64,
    use_: ProposalUse,
) -> Vec<CompanionProposal> {
    ledger.proposals_for(now, &NoExclusions, use_)
}

#[test]
fn one_window_of_a_shared_name_is_asked_about_but_never_written_unasked() {
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "chatapp.example",
        SECONDARY,
        &["login.chatapp.test"],
    );

    assert!(offered(&ledger, 10_000, UNASKED).is_empty());
    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());

    let asked = offered(&ledger, 10_000, REVIEW);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].proposed,
        ProposedCompanionMatch::ExactHost("login.chatapp.test".to_string())
    );
    assert_eq!(asked[0].signal, CompanionSignal::BrandRelated);
    assert_eq!(asked[0].less_certain, Some(LessCertainBasis::BrandSeenOnce));
    assert_eq!(asked[0].distinct_windows, 1);
}

#[test]
fn a_second_window_removes_the_mark_and_both_uses_agree() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "chatapp.example", &["login.chatapp.test"]);

    let asked = offered(&ledger, 150_000, REVIEW);
    assert_eq!(asked, offered(&ledger, 150_000, UNASKED));
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].less_certain, None);
}

#[test]
fn look_alikes_seen_once_never_widen_to_their_domain() {
    // Two named hosts would widen to `*.chatapp.test` on full evidence; seen
    // once each, they stay the two hosts they are.
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "chatapp.example",
        SECONDARY,
        &["static.chatapp.test", "media.chatapp.test"],
    );

    let asked = offered(&ledger, 10_000, REVIEW);
    let mut values: Vec<&ProposedCompanionMatch> = asked.iter().map(|p| &p.proposed).collect();
    values.sort_by(|a, b| a.value().cmp(b.value()));
    assert_eq!(
        values,
        vec![
            &ProposedCompanionMatch::ExactHost("media.chatapp.test".to_string()),
            &ProposedCompanionMatch::ExactHost("static.chatapp.test".to_string()),
        ]
    );
    assert!(asked
        .iter()
        .all(|p| p.less_certain == Some(LessCertainBasis::BrandSeenOnce)));
    assert!(offered(&ledger, 10_000, UNASKED).is_empty());
}

#[test]
fn a_less_certain_host_a_certain_suffix_covers_is_not_listed_again() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "chatapp.example",
        &["static.chatapp.test", "media.chatapp.test"],
    );
    page_load(
        &mut ledger,
        200_000,
        "chatapp.example",
        SECONDARY,
        &["login.chatapp.test"],
    );

    let asked = offered(&ledger, 250_000, REVIEW);
    assert_eq!(asked, offered(&ledger, 250_000, UNASKED));
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].proposed,
        ProposedCompanionMatch::SuffixDomain("chatapp.test".to_string())
    );
}

#[test]
fn review_adds_rows_and_leaves_every_certain_row_as_it_was() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    page_load(
        &mut ledger,
        300_000,
        "feed.example",
        SECONDARY,
        &["login.feed.test"],
    );

    let unasked = offered(&ledger, 350_000, UNASKED);
    let asked = offered(&ledger, 350_000, REVIEW);
    let certain: Vec<CompanionProposal> = asked
        .iter()
        .filter(|p| p.less_certain.is_none())
        .cloned()
        .collect();
    assert_eq!(certain, unasked);
    assert!(asked.iter().any(|p| p.anchor_hostname == "feed.example"
        && p.proposed.value() == "login.feed.test"
        && p.less_certain == Some(LessCertainBasis::BrandSeenOnce)));
    assert!(unasked.iter().all(|p| p.less_certain.is_none()));
}

#[test]
fn a_full_evidence_tier_wins_over_the_single_window_fallback() {
    // Seen carrying traffic: the delivery tier stands on that alone, so the
    // offer is certain even though the name is also the site's.
    let mut ledger = defaults();
    ledger.observe(
        0,
        "chatapp.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    ledger.observe(1_000, "static.chatapp.test", CoActivityKind::CandidateInUse);

    let asked = offered(&ledger, 10_000, REVIEW);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].signal, CompanionSignal::DeliveryName);
    assert_eq!(asked[0].less_certain, None);
}

/// Another page's fetch is never credited, however few windows are asked for.
#[test]
fn review_still_refuses_a_fetch_made_by_another_page() {
    let mut ledger = defaults();
    ledger.observe(
        0,
        "web.chatapp.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    ledger.observe(1_000, "elsewhere.test", CoActivityKind::Candidate);
    ledger.observe(2_000, "static.chatapp.test", CoActivityKind::Candidate);

    for use_ in [UNASKED, REVIEW] {
        assert!(
            offered(&ledger, 10_000, use_)
                .iter()
                .all(|p| !p.proposed.value().contains("chatapp.test")),
            "{use_:?} credited the other page's fetch"
        );
    }
}

/// The hostile page of `a_hostile_page_cannot_plant_a_brand_companion`, in
/// both uses: its look-alike is never offered, let alone as `*.apex`.
#[test]
fn a_hostile_page_plants_nothing_in_either_use() {
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    let mut ledger = defaults();
    for start in [0_u64, 100_000, 200_000] {
        ledger.observe(start, "www.attacker.test", CoActivityKind::Candidate);
        ledger.observe(start + 1_000, "login.mybank.example", anchor);
        ledger.observe(
            start + 2_000,
            "x.mybank-cdn.test",
            CoActivityKind::Candidate,
        );
    }
    for use_ in [UNASKED, REVIEW] {
        let proposals = offered(&ledger, 250_000, use_);
        assert!(
            proposals
                .iter()
                .all(|p| !p.proposed.value().contains("mybank-cdn")),
            "{use_:?}: {:?}",
            proposals
                .iter()
                .map(|p| p.proposed.value())
                .collect::<Vec<_>>()
        );
    }

    // Seen once on the rule host's own page: a person is asked about the one
    // host, marked; nothing is written unasked and the domain is never offered.
    let mut once = defaults();
    once.observe(0, "login.mybank.example", anchor);
    once.observe(1_000, "x.mybank-cdn.test", CoActivityKind::Candidate);
    assert!(offered(&once, 50_000, UNASKED).is_empty());
    let asked = offered(&once, 50_000, REVIEW);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].proposed,
        ProposedCompanionMatch::ExactHost("x.mybank-cdn.test".to_string())
    );
    assert_eq!(asked[0].less_certain, Some(LessCertainBasis::BrandSeenOnce));
}

#[test]
fn the_cap_drops_less_certain_offers_before_certain_ones() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_proposals_per_anchor: 1,
        ..CompanionAffinityConfig::default()
    });
    two_visits(&mut ledger, "chatapp.example", &["login.chatapp.test"]);
    page_load(
        &mut ledger,
        200_000,
        "chatapp.example",
        SECONDARY,
        &["help.chatapp.test"],
    );

    let asked = offered(&ledger, 250_000, REVIEW);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].proposed.value(), "login.chatapp.test");
    assert_eq!(asked[0].less_certain, None);
}

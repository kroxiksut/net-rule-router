use super::*;

// ── Tier 3: co-activity only ─────────────────────────────────────────────

#[test]
fn a_plain_named_companion_still_needs_the_strict_affinity_threshold() {
    let mut ledger = defaults();
    // Neither brand-related nor delivery-shaped: only the conservative tier
    // applies, and two anchors sharing the host put it at 0.5.
    for (at, anchor) in [(0_u64, "a.test"), (100_000, "b.test")] {
        page_load(&mut ledger, at, anchor, SECONDARY, &["helper.other"]);
        page_load(
            &mut ledger,
            at + 30_000,
            anchor,
            SECONDARY,
            &["helper.other"],
        );
    }
    assert!(ledger.proposals(200_000, &NoExclusions).is_empty());

    // Further visits to one site alone lift it to the threshold (8/10).
    for at in [200_000, 300_000, 400_000, 500_000, 600_000, 700_000] {
        page_load(&mut ledger, at, "a.test", SECONDARY, &["helper.other"]);
    }
    let proposals = ledger.proposals(550_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].anchor_hostname, "a.test");
    assert_eq!(proposals[0].signal, CompanionSignal::CoActivity);
}

// ── Window mechanics ─────────────────────────────────────────────────────

#[test]
fn anchor_activity_extends_a_window_instead_of_opening_a_new_one() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    // Anchor keeps firing every 10 s: same window while under the hard cap.
    ledger.observe(0, "site.example", anchor);
    ledger.observe(10_000, "site.example", anchor);
    ledger.observe(20_000, "site.example", anchor);
    // Candidate hits at both ends of the extended window: one window only.
    ledger.observe(1_000, "cdn.example", CoActivityKind::Candidate);
    ledger.observe(30_000, "cdn.example", CoActivityKind::Candidate);

    // Only one distinct window so far => below the minimum, no proposal.
    assert!(ledger.proposals(40_000, &NoExclusions).is_empty());

    // A later visit opens a second window and unlocks the proposal.
    page_load(
        &mut ledger,
        200_000,
        "site.example",
        SECONDARY,
        &["cdn.example"],
    );
    let proposals = ledger.proposals(250_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].distinct_windows, 2);
}

#[test]
fn continuous_browsing_of_one_site_proposes_within_a_single_visit() {
    // Product rule: the proposal must appear during the user's first
    // normal visit (open the site, click into a video) — it must NOT
    // require the user to leave and reload the site by hand. The hard
    // window cap guarantees continuous activity still closes windows.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    // ~2.5 minutes of continuous activity with NO idle gap: anchor and
    // candidate keep firing every 5 s.
    let mut t: u64 = 0;
    while t <= 150_000 {
        ledger.observe(t, "site.example", anchor);
        ledger.observe(t + 1_000, "cdn.example", CoActivityKind::Candidate);
        t += 5_000;
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    let p = &proposals[0];
    assert_eq!(p.proposed.value(), "cdn.example");
    assert!(
        p.distinct_windows >= 2,
        "hard window cap must split continuous browsing into windows, got {}",
        p.distinct_windows
    );
    assert!((p.affinity - 1.0).abs() < f64::EPSILON);
}

// ── Suffix generalization ────────────────────────────────────────────────

#[test]
fn two_distinct_subdomains_generalize_to_a_suffix_proposal() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "site.example",
        &["di.cdn-relay.example", "ev-h.cdn-relay.example"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::SuffixDomain("cdn-relay.example".to_string())
    );
    assert_eq!(proposals[0].distinct_windows, 2);
    assert_eq!(proposals[0].first_seen_ms, 1);
    assert_eq!(proposals[0].last_seen_ms, 100_002);
}

#[test]
fn a_single_co_active_subdomain_stays_an_exact_host_proposal() {
    let mut ledger = defaults();
    // Neither branded after the anchor nor delivery-named: it only ever
    // loaded at the same time, which says nothing about its siblings.
    two_visits(&mut ledger, "site.example", &["one.partner.test"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::ExactHost("one.partner.test".to_string())
    );
}

#[test]
fn one_delivery_named_subdomain_is_enough_to_generalize() {
    let mut ledger = defaults();
    // The user's case: seeing `static.cdninsta.test` should offer the
    // whole CDN, not one host of it that the next page load replaces.
    two_visits(&mut ledger, "site.example", &["di.cdn-relay.example"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::SuffixDomain("cdn-relay.example".to_string())
    );
}

#[test]
fn the_apex_itself_does_not_count_toward_suffix_generalization() {
    let mut ledger = defaults();
    // Apex + one co-active subdomain is not enough evidence to generalize
    // to `*.apex` — one observed subdomain stays one observed subdomain, so
    // both remain exact proposals.
    two_visits(
        &mut ledger,
        "site.example",
        &["partner.test", "one.partner.test"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(values, vec!["one.partner.test", "partner.test"]);
    assert!(proposals
        .iter()
        .all(|p| matches!(p.proposed, ProposedCompanionMatch::ExactHost(_))));
}

#[test]
fn a_suffix_proposal_absorbs_the_apex_instead_of_duplicating_it() {
    let mut ledger = defaults();
    // Apex + two subdomains: the suffix proposal fires and, since it now
    // covers the apex too, the apex must NOT also appear as an exact
    // proposal — that would be a redundant row in the review list.
    two_visits(
        &mut ledger,
        "site.example",
        &[
            "cdn-relay.example",
            "di.cdn-relay.example",
            "ev-h.cdn-relay.example",
        ],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>(),
        vec![ProposedCompanionMatch::SuffixDomain(
            "cdn-relay.example".to_string()
        )]
    );
}

/// The background-client shape: a client's plain-named hosts under one
/// apex, seen beside the anchor because it is open all day. Two of them
/// used to earn `*.apex` — a whole third-party domain on the tunnel from
/// evidence that says only "these loaded at the same time".
#[test]
fn co_activity_alone_never_generalizes_to_a_suffix() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "site.example",
        &["ledger.other.example", "airdrop.other.example"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        !proposals
            .iter()
            .any(|p| matches!(p.proposed, ProposedCompanionMatch::SuffixDomain(_))),
        "co-activity generalized: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
    // The hosts themselves are still proposed — one at a time, which is
    // what the evidence actually covers.
    assert_eq!(proposals.len(), 2);
}

/// A suffix offer reaches every name under the apex; the user can only
/// judge it against the names that were actually seen.
#[test]
fn a_suffix_proposal_carries_the_hostnames_the_evidence_covers() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "site.example",
        &["media.cdnexample.net", "static.cdnexample.net"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let suffix = proposals
        .iter()
        .find(|p| matches!(p.proposed, ProposedCompanionMatch::SuffixDomain(_)))
        .expect("the delivery apex generalizes");
    assert_eq!(
        suffix.observed_members,
        vec![
            "media.cdnexample.net".to_string(),
            "static.cdnexample.net".to_string()
        ]
    );
    // An exact offer covers itself; listing it would be noise.
    let mut exact = proposals
        .iter()
        .filter(|p| matches!(p.proposed, ProposedCompanionMatch::ExactHost(_)));
    assert!(exact.all(|p| p.observed_members.is_empty()));
}

#[test]
fn a_suffix_covering_the_anchor_itself_is_never_proposed() {
    let mut ledger = defaults();
    // The anchor lives under the apex, so `*.search.example` would put the
    // whole corporation on the route on the strength of one site. The
    // companions stay as exact proposals instead.
    two_visits(
        &mut ledger,
        "aistudio.search.example",
        &[
            "search.example",
            "accounts.search.example",
            "content.googleapis.com",
        ],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        !proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "search.example")),
        "the anchor's own umbrella was proposed: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_short_shared_token_never_generalizes_to_the_apex() {
    // `q.example` and `q.test` share the token `t`. That is one letter and one
    // registrar away from coincidence, so it may buy the exact hosts and
    // nothing wider — otherwise two subdomains hand somebody else's whole
    // domain to the additional route.
    let mut ledger = defaults();
    two_visits(&mut ledger, "q.example", &["cdn.q.test", "img.q.test"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        !proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "q.test")),
        "a one-letter token generalized to the apex: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
    // Positive control for the assertion above: the kinship itself is NOT
    // what was refused — the exact hosts are still proposed.
    assert!(
        proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::ExactHost(h) if h == "cdn.q.test")),
        "the exact host must survive: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_named_brand_still_generalizes_to_the_apex() {
    // The other side of the rule above, so "no apex" cannot be reached by
    // switching the counting off altogether: a token long enough to name an
    // operator still carries the whole delivery domain.
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "insta.example",
        &["static.cdninsta.test", "scontent.cdninsta.test"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "cdninsta.test")),
        "a named brand stopped generalizing: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_apex_the_anchor_does_not_live_under_still_generalizes() {
    let mut ledger = defaults();
    // The guard above is about the anchor's OWN umbrella. A third-party
    // delivery domain is unaffected: two subdomains still earn `*.apex`.
    two_visits(
        &mut ledger,
        "aistudio.search.example",
        &["static.cdnexample.net", "media.cdnexample.net"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "cdnexample.net")),
        "a third-party apex stopped generalizing: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_brand_related_sibling_under_the_anchors_own_apex_stays_exact() {
    let mut ledger = defaults();
    // `rt.site.com` shares a brand with `www.site.com` only because they
    // share a domain — the same trivial equality that would fire for any
    // sibling of `aistudio.search.example`. It must earn only itself, not
    // `*.site.com`, on one window's evidence — this is the shape behind
    // any two same-domain subdomains reached via trivial brand equality
    // in the companion-affinity trace study.
    two_visits(&mut ledger, "www.site.com", &["rt.site.com"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::ExactHost("rt.site.com".to_string())
    );
}

#[test]
fn a_delivery_looking_sibling_under_the_anchors_own_apex_stays_exact() {
    let mut ledger = defaults();
    // `static.site.com` looks like a CDN host, but sharing the anchor's
    // own registrable domain means brand equality (the trivial "same
    // domain" branch of `is_brand_related`) always wins the tier race
    // before the delivery-name check runs — so this can never reach
    // `CompanionSignal::DeliveryName` in the first place, and the same
    // swallow guard applies regardless of which tier accepted it.
    two_visits(&mut ledger, "www.site.com", &["static.site.com"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::ExactHost("static.site.com".to_string())
    );
}

#[test]
fn excluded_suffix_apex_falls_back_to_exact_host_proposals() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "site.example",
        &["di.cdn-relay.example", "ev-h.cdn-relay.example"],
    );

    let mut exclusions = StaticExclusions::default();
    exclusions
        .matched_by_existing_rule
        .insert("cdn-relay.example".to_string());
    let proposals = ledger.proposals(150_000, &exclusions);
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(
        values,
        vec!["di.cdn-relay.example", "ev-h.cdn-relay.example"]
    );
}

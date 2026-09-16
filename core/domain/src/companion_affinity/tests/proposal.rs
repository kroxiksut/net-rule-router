use super::*;

// ── Core proposal flow ───────────────────────────────────────────────────

#[test]
fn dedicated_cdn_across_two_page_loads_is_proposed() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    let p = &proposals[0];
    assert_eq!(p.anchor_hostname, "site.example");
    assert_eq!(
        p.proposed,
        ProposedCompanionMatch::ExactHost("cdn.example".to_string())
    );
    assert_eq!(p.route, SECONDARY);
    assert_eq!(p.distinct_windows, 2);
    assert!((p.affinity - 1.0).abs() < f64::EPSILON);
    assert_eq!(p.first_seen_ms, 1);
    assert_eq!(p.last_seen_ms, 100_001);
}

// ── Primary-route behaviour ──────────────────────────────────────────────

#[test]
fn a_host_whose_connections_completed_is_reported_as_working_without_the_tunnel() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    health(&mut ledger, "cdn.example", PrimaryHealthEvent::Completed, 1);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Responds);
}

#[test]
fn one_stall_is_not_enough_to_call_a_host_broken() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    health(&mut ledger, "cdn.example", PrimaryHealthEvent::Stalled, 1);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
}

#[test]
fn repeated_stalls_with_nothing_completing_report_the_host_as_stalling() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    health(
        &mut ledger,
        "cdn.example",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Stalls);
}

#[test]
fn evidence_pointing_both_ways_yields_no_verdict() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    health(
        &mut ledger,
        "cdn.example",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );
    health(&mut ledger, "cdn.example", PrimaryHealthEvent::Completed, 1);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
}

#[test]
fn an_untracked_host_is_not_created_by_a_health_report() {
    let mut ledger = defaults();
    health(
        &mut ledger,
        "stranger.example",
        PrimaryHealthEvent::Stalled,
        5,
    );

    assert_eq!(ledger.candidate_count(), 0);
    assert!(!ledger.is_tracking_candidate("stranger.example"));
}

#[test]
fn single_page_load_is_never_proposed() {
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

#[test]
fn repeat_hits_inside_one_window_count_as_one_window() {
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
    // A page load fires the same candidate many times in one window.
    for i in 0..50 {
        ledger.observe(100 + i, "cdn.example", CoActivityKind::Candidate);
    }
    page_load(
        &mut ledger,
        100_000,
        "site.example",
        SECONDARY,
        &["cdn.example"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    // 50 hits in window 1 + 1 hit in window 2 => exactly 2 distinct windows.
    assert_eq!(proposals[0].distinct_windows, 2);
    assert!((proposals[0].affinity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn ubiquitous_candidate_falls_below_affinity_threshold() {
    let mut ledger = defaults();
    // Dedicated companion: only ever seen with anchor a.
    two_visits(&mut ledger, "a.example", &["only-a.cdn", "metrics.shared"]);
    // The shared host also shows up under two other anchors.
    page_load(
        &mut ledger,
        200_000,
        "b.example",
        SECONDARY,
        &["metrics.shared"],
    );
    page_load(
        &mut ledger,
        300_000,
        "c.example",
        SECONDARY,
        &["metrics.shared"],
    );

    let proposals = ledger.proposals(400_000, &NoExclusions);
    // metrics.shared: 2 windows with a / 4 total = 0.5 < 0.8 => suppressed.
    assert!(proposals
        .iter()
        .all(|p| p.proposed.value() != "metrics.shared"));
    // The dedicated companion still qualifies (2/2 = 1.0).
    assert!(proposals
        .iter()
        .any(|p| p.anchor_hostname == "a.example" && p.proposed.value() == "only-a.cdn"));
}

#[test]
fn candidate_outside_any_window_is_not_tracked() {
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
    // Long after the window (and its hard cap) closed.
    ledger.observe(500_000, "stray.example", CoActivityKind::Candidate);

    assert!(!ledger.is_tracking_candidate("stray.example"));
    assert_eq!(ledger.candidate_count(), 0);
}

// ── Tier 1: brand relation ───────────────────────────────────────────────

#[test]
fn a_brand_related_companion_is_proposed_once_the_relation_repeats() {
    // A brand-related subdomain generalizes to its domain; a candidate that
    // IS the domain has no subdomain to generalize from and stays exact.
    // `ab` is two letters: the relation holds, the reach does not — see
    // `a_short_brand_token_earns_the_host_but_not_the_apex`.
    for (anchor, candidate, expected) in [
        (
            "web.chatapp.example",
            "crashlogs.chatapp.test",
            "chatapp.test",
        ),
        ("ab.example", "login.ab.test", "login.ab.test"),
        ("tiktok.com", "tiktokv.com", "tiktokv.com"),
    ] {
        let mut ledger = defaults();
        two_visits(&mut ledger, anchor, &[candidate]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1, "{candidate} should be proposed");
        assert_eq!(proposals[0].proposed.value(), expected);
        assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
        assert_eq!(proposals[0].distinct_windows, 2);
    }
}

#[test]
fn a_brand_related_name_that_rides_along_with_everything_is_not_proposed() {
    // The operator's advertising and asset domains carry the brand as
    // plainly as the host a page cannot render without. What separates them
    // is that they accompany every site, not this one.
    let mut ledger = defaults();
    // Every site of the same operator pulls it once; none of them owns it.
    for i in 0..20_u64 {
        page_load(
            &mut ledger,
            i * 100_000,
            &format!("site-{i}.brand.example"),
            SECONDARY,
            &["brandsyndication.example"],
        );
    }

    assert!(ledger.proposals(2_000_000, &NoExclusions).is_empty());
}

#[test]
fn a_brand_buried_inside_a_longer_word_is_not_a_relation() {
    // `istu` sits in the middle of `aistudio`. Reading that as kinship
    // proposed an unrelated domain as a companion of the AI studio host.
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "aistudio.search.example",
        SECONDARY,
        &["istu.test"],
    );

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

#[test]
fn a_brand_at_a_label_edge_is_still_a_relation() {
    // The shapes operators actually register: prefix, suffix, dashed label.
    for (anchor, candidate) in [
        ("feed.example", "static.feedinfra.example"),
        ("insta.example", "static.cdninsta.test"),
        ("example.com", "assets.example-cdn.net"),
    ] {
        let mut ledger = defaults();
        two_visits(&mut ledger, anchor, &[candidate]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1, "{candidate} should be proposed");
        assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
    }
}

#[test]
fn a_bystander_whose_window_merely_overlapped_does_not_claim_the_host() {
    let mut ledger = defaults();
    for visit in [0_u64, 100_000] {
        // A chatty rule host speaks first and keeps its window open next to
        // whatever the user browses afterwards.
        ledger.observe(
            visit,
            "hub.example",
            CoActivityKind::Anchor { route: SECONDARY },
        );
        page_load(
            &mut ledger,
            visit + 10,
            "site.example",
            SECONDARY,
            &["cdn.example"],
        );
    }

    let proposals = ledger.proposals(200_000, &NoExclusions);
    // Only the site that fetched it proposes: sharing every window halves
    // each anchor's affinity, and the bystander has no other evidence —
    // it was never what the address was fetched for.
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].anchor_hostname, "site.example");
    assert_eq!(proposals[0].nearest_share, 1.0);
}

#[test]
fn an_unrelated_name_is_not_mistaken_for_a_brand_relation() {
    let mut ledger = defaults();
    // Single visit, so only the ungated brand tier could fire.
    page_load(
        &mut ledger,
        0,
        "web.chatapp.example",
        SECONDARY,
        &["telemetry.othervendor.net"],
    );

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

#[test]
fn a_brand_sitting_in_someone_elses_subdomain_is_not_a_relation() {
    // From a live run: a Fastly machine named after its customer offered to
    // move all of mozilla.org onto the additional link.
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "mozilla.map.fastly.net",
        SECONDARY,
        &["mozilla.org"],
    );

    assert!(
        ledger.proposals(10_000, &NoExclusions).is_empty(),
        "the brand names Fastly's customer, not Fastly's kin"
    );
}

#[test]
fn a_brand_in_the_registrable_domain_is_still_a_relation() {
    // The shape the rule must keep: the brand is in the apex itself.
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "user-images.githubusercontent.com",
        &["github.com"],
    );

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
}

#[test]
fn a_name_that_cannot_be_a_rule_never_becomes_a_candidate() {
    // Resolver artifacts ("..localmachine" — empty labels) were observed
    // in the wild squatting slots in the bounded candidate set.
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.test", &["..localmachine"]);
    assert!(
        ledger
            .snapshot()
            .candidates
            .iter()
            .all(|c| c.hostname != "..localmachine"),
        "an unwritable name must be dropped at the door"
    );
    assert!(ledger.proposals(150_000, &NoExclusions).is_empty());
}

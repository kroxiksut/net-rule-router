use super::*;

// ── Bounds and eviction ──────────────────────────────────────────────────

#[test]
fn exceeding_the_candidate_cap_evicts_the_least_recently_seen() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_candidates: 2,
        ..CompanionAffinityConfig::default()
    });
    page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
    ledger.observe(1_000, "old.cdn", CoActivityKind::Candidate);
    ledger.observe(2_000, "mid.cdn", CoActivityKind::Candidate);
    ledger.observe(3_000, "new.cdn", CoActivityKind::Candidate);

    assert_eq!(ledger.candidate_count(), 2);
    assert!(!ledger.is_tracking_candidate("old.cdn"));
    assert!(ledger.is_tracking_candidate("mid.cdn"));
    assert!(ledger.is_tracking_candidate("new.cdn"));
}

#[test]
fn exceeding_the_anchor_cap_evicts_and_sweeps_pair_statistics() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_anchors: 2,
        ..CompanionAffinityConfig::default()
    });
    // The candidate earns a qualifying score with the oldest anchor.
    page_load(&mut ledger, 0, "a.example", SECONDARY, &["shared.cdn"]);
    page_load(
        &mut ledger,
        100_000,
        "a.example",
        SECONDARY,
        &["shared.cdn"],
    );
    page_load(&mut ledger, 200_000, "b.example", SECONDARY, &[]);
    // Third anchor exceeds the cap: a.example (least recent) is evicted.
    page_load(&mut ledger, 300_000, "c.example", SECONDARY, &[]);

    assert_eq!(ledger.anchor_count(), 2);
    // The swept pair can no longer produce a proposal for the evicted anchor.
    let proposals = ledger.proposals(350_000, &NoExclusions);
    assert!(proposals.iter().all(|p| p.anchor_hostname != "a.example"));
}

#[test]
fn zero_caps_disable_tracking_without_panicking() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_anchors: 0,
        max_candidates: 0,
        ..CompanionAffinityConfig::default()
    });
    page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);

    assert_eq!(ledger.anchor_count(), 0);
    assert_eq!(ledger.candidate_count(), 0);
    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

#[test]
fn proposals_per_anchor_are_capped() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_proposals_per_anchor: 2,
        ..CompanionAffinityConfig::default()
    });
    // Three qualifying candidates with equal affinity: the cap keeps the
    // first two in deterministic (name ascending) order.
    two_visits(&mut ledger, "site.example", &["a.one", "b.two", "c.three"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(values, vec!["a.one", "b.two"]);
}

// ── Determinism and ordering ─────────────────────────────────────────────

#[test]
fn identical_event_streams_produce_identical_proposals() {
    let feed = |ledger: &mut CompanionAffinityLedger| {
        two_visits(ledger, "b.site", &["video.bcdn.net", "img.bcdn.net"]);
        page_load(ledger, 200_000, "a.site", PRIMARY, &["solo.cdn"]);
        page_load(
            ledger,
            300_000,
            "a.site",
            PRIMARY,
            &["solo.cdn", "late.cdn"],
        );
        page_load(ledger, 400_000, "a.site", PRIMARY, &["late.cdn"]);
    };
    let mut first = defaults();
    let mut second = defaults();
    feed(&mut first);
    feed(&mut second);

    let a = first.proposals(450_000, &NoExclusions);
    let b = second.proposals(450_000, &NoExclusions);
    assert_eq!(a, b);
    assert!(!a.is_empty());
}

#[test]
fn proposals_are_ordered_by_anchor_then_affinity_then_name() {
    let mut ledger = defaults();
    // Anchor "b.site" gets two equal-affinity companions (tie broken by name).
    two_visits(&mut ledger, "b.site", &["m.host", "n.host"]);
    // Anchor "a.site": "pure.cdn" reaches affinity 1.0 (4/4); "mixed.cdn"
    // is diluted by one extra window under "b.site" (4/5 = 0.8, exactly at
    // the threshold) but its name sorts before "pure.cdn" — affinity must
    // win over name. Every candidate here qualifies through the same tier,
    // so the signal key does not participate.
    for t in [200_000, 300_000, 400_000, 500_000] {
        page_load(
            &mut ledger,
            t,
            "a.site",
            PRIMARY,
            &["pure.cdn", "mixed.cdn"],
        );
    }
    page_load(&mut ledger, 600_000, "b.site", SECONDARY, &["mixed.cdn"]);

    let proposals = ledger.proposals(650_000, &NoExclusions);
    let shape: Vec<(&str, &str)> = proposals
        .iter()
        .map(|p| (p.anchor_hostname.as_str(), p.proposed.value()))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("a.site", "pure.cdn"),
            ("a.site", "mixed.cdn"),
            ("b.site", "m.host"),
            ("b.site", "n.host"),
        ]
    );
    assert!(proposals[0].affinity > proposals[1].affinity);
}

#[test]
fn a_stronger_signal_outranks_a_higher_affinity() {
    let mut ledger = defaults();
    for start in [0_u64, 100_000, 200_000, 300_000] {
        page_load(
            &mut ledger,
            start,
            "web.chatapp.example",
            SECONDARY,
            &["helper.other", "crashlogs.chatapp.test"],
        );
    }
    // A second site pulls the brand-related host too, diluting its affinity
    // below the plain co-activity companion's.
    page_load(
        &mut ledger,
        400_000,
        "b.test",
        SECONDARY,
        &["crashlogs.chatapp.test"],
    );

    let proposals = ledger.proposals(450_000, &NoExclusions);
    let shape: Vec<(&str, CompanionSignal)> = proposals
        .iter()
        .map(|p| (p.proposed.value(), p.signal))
        .collect();
    assert_eq!(
        shape,
        vec![
            ("chatapp.test", CompanionSignal::BrandRelated),
            ("helper.other", CompanionSignal::CoActivity),
        ]
    );
    assert!(proposals[0].affinity < proposals[1].affinity);
}

// ── Exclusions ───────────────────────────────────────────────────────────

#[test]
fn each_exclusion_predicate_suppresses_a_proposal() {
    let build = || {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        ledger
    };
    let cases: [fn(&mut StaticExclusions); 3] = [
        |e| {
            e.rule_hosts.insert("cdn.example".to_string());
        },
        |e| {
            e.matched_by_existing_rule.insert("cdn.example".to_string());
        },
        |e| {
            e.platform_infrastructure.insert("cdn.example".to_string());
        },
    ];
    for case in cases {
        let ledger = build();
        let mut exclusions = StaticExclusions::default();
        case(&mut exclusions);
        assert!(ledger.proposals(150_000, &exclusions).is_empty());
    }
    // Sanity: without exclusions the same evidence does propose.
    assert_eq!(build().proposals(150_000, &NoExclusions).len(), 1);
}

/// Shared infrastructure is held back — until the main link is measured
/// to fail for it. The product must not decide which hosts a person may
/// reach, so the exception keys on the measurement, never on what the
/// host appears to be.
#[test]
fn shared_infrastructure_is_proposed_only_once_the_main_link_is_measured_to_fail() {
    let build = || {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        ledger
    };
    let mut exclusions = StaticExclusions::default();
    exclusions
        .platform_infrastructure
        .insert("cdn.example".to_string());

    // Nothing measured: held back, as before.
    assert!(build().proposals(150_000, &exclusions).is_empty());

    // Measured as working on the main link: still held back — the site
    // loads, and moving a shared host would drag everyone else with it.
    let mut working = build();
    health(
        &mut working,
        "cdn.example",
        PrimaryHealthEvent::Completed,
        1,
    );
    assert!(working.proposals(150_000, &exclusions).is_empty());

    // Measured as failing: the site needs it and cannot reach it.
    let mut failing = build();
    health(
        &mut failing,
        "cdn.example",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );
    let proposals = failing.proposals(150_000, &exclusions);
    assert_eq!(proposals.len(), 1, "{proposals:?}");
    assert_eq!(proposals[0].proposed.value(), "cdn.example");
    assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Stalls);

    // A rule already covering it still wins over everything above: the
    // measurement widens ONE door, not all of them.
    let mut covered = StaticExclusions::default();
    covered
        .platform_infrastructure
        .insert("cdn.example".to_string());
    covered
        .matched_by_existing_rule
        .insert("cdn.example".to_string());
    let mut failing = build();
    health(
        &mut failing,
        "cdn.example",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );
    assert!(failing.proposals(150_000, &covered).is_empty());
}

#[test]
fn a_hostname_promoted_to_anchor_stops_being_a_candidate() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    // The user adds a rule for the companion; the caller now reports it
    // as an anchor. Its candidate evidence must disappear.
    ledger.observe(
        200_000,
        "cdn.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );

    assert!(!ledger.is_tracking_candidate("cdn.example"));
    assert!(ledger.proposals(250_000, &NoExclusions).is_empty());
}

#[test]
fn an_active_anchor_is_never_recorded_as_a_candidate() {
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
    // Defensive backstop: a mislabeled event for a live anchor is ignored.
    ledger.observe(1_000, "site.example", CoActivityKind::Candidate);

    assert!(!ledger.is_tracking_candidate("site.example"));
}

// ── Evidence freshness ───────────────────────────────────────────────────

#[test]
fn stale_evidence_is_skipped_and_revives_on_a_new_sighting() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "site.example", &["cdn.example"]);
    let last_seen = 100_001;

    // At the horizon edge the proposal is still visible.
    let at_edge = last_seen + DEFAULT_EVIDENCE_TTL_MS;
    assert_eq!(ledger.proposals(at_edge, &NoExclusions).len(), 1);
    // One millisecond past the horizon it is skipped.
    assert!(ledger.proposals(at_edge + 1, &NoExclusions).is_empty());

    // A fresh sighting revives the accumulated evidence.
    page_load(
        &mut ledger,
        at_edge + 10_000,
        "site.example",
        SECONDARY,
        &["cdn.example"],
    );
    let revived = ledger.proposals(at_edge + 20_000, &NoExclusions);
    assert_eq!(revived.len(), 1);
    assert_eq!(revived[0].distinct_windows, 3);
}

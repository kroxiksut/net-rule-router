use super::*;

// ── Tier 2: delivery names ───────────────────────────────────────────────

#[test]
fn a_delivery_named_companion_needs_a_second_window() {
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "site.test",
        SECONDARY,
        &["img.edgefarm.net"],
    );
    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());

    page_load(
        &mut ledger,
        100_000,
        "site.test",
        SECONDARY,
        &["img.edgefarm.net"],
    );
    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].proposed.value(), "edgefarm.net");
    assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
}

#[test]
fn observed_traffic_stands_in_for_the_second_visit() {
    // The user's report: opened the site once, nothing was offered. The
    // second visit was only ever a proxy for "this is real" — a connection
    // says it outright, during the visit that needed the address.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    ledger.observe(0, "site.test", anchor);
    ledger.observe(1_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);

    let proposals = ledger.proposals(10_000, &NoExclusions);
    assert_eq!(proposals.len(), 1, "one visit was enough");
    assert_eq!(proposals[0].proposed.value(), "edgefarm.net");
    assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
}

#[test]
fn observed_traffic_does_not_promote_a_host_this_site_does_not_own() {
    // Two sites open, the delivery host belongs to neither in particular
    // (nearest_share 0.5). Seeing traffic to it does not make it this
    // anchor's companion — the ownership gate still has to pass.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    ledger.observe(0, "other.test", anchor);
    ledger.observe(1_000, "site.test", anchor);
    ledger.observe(2_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
    ledger.observe(3_000, "other.test", anchor);
    ledger.observe(4_000, "img.edgefarm.net", CoActivityKind::Candidate);

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

/// The defect this criterion exists for, four times reported: the user
/// searches on a rule host, follows a link to an unrelated site, and that
/// site's CDN is offered under the rule host — `ypncdn.com` under
/// `www.search.test`, `cdninsta.test` under `cdn.openai.com`.
#[test]
fn a_cdn_fetched_by_another_sites_page_is_not_offered_under_the_open_anchor() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        // The rule host is the page the user came from, and stays open.
        ledger.observe(start, "search.test", anchor);
        // Then they navigate to a site of their own, which fetches its CDN.
        ledger.observe(start + 1_000, "elsewhere.test", CoActivityKind::Candidate);
        ledger.observe(
            start + 2_000,
            "img.cdn-elsewhere.test",
            CoActivityKind::CandidateInUse,
        );
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let offered: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert!(
        !offered.iter().any(|v| v.contains("cdn-elsewhere")),
        "the CDN belongs to the page that fetched it, not to the open anchor: {offered:?}"
    );
}

/// The other half of the same criterion: an anchor's OWN delivery endpoint
/// must still be offered, including when the user has been elsewhere in the
/// same window — otherwise the fix would silence the suggestions the product
/// exists to make.
#[test]
fn a_cdn_fetched_by_the_anchors_own_page_is_still_offered() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "elsewhere.test", CoActivityKind::Candidate);
        // Back on the anchor's page; what follows is its own fetch.
        ledger.observe(start + 1_000, "site.test", anchor);
        ledger.observe(
            start + 2_000,
            "img.cdn-site.test",
            CoActivityKind::CandidateInUse,
        );
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals
            .iter()
            .any(|p| p.anchor_hostname == "site.test" && p.proposed.value().contains("cdn-site")),
        "the anchor's own delivery endpoint must survive the criterion: {:?}",
        proposals
            .iter()
            .map(|p| (p.anchor_hostname.as_str(), p.proposed.value()))
            .collect::<Vec<_>>()
    );
}

/// The look-back and the foreign-parent test arrived together and cancelled
/// each other out. The look-back runs from inside `observe_anchor`, before
/// `observe` records the page that just opened, so every sighting it raises
/// was judged against the PREVIOUS page — foreign by construction. One
/// foreign hit against one near hit is already "mostly someone else's", so
/// the pair was dropped and the CDN the look-back exists to catch was never
/// offered.
#[test]
fn a_companion_raised_by_the_look_back_is_not_blamed_on_the_previous_page() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        // A page of somebody else's, which is what `last_document` holds
        // when the next window opens.
        ledger.observe(start, "elsewhere.test", CoActivityKind::Candidate);
        // The browser opens the CDN connection BEFORE the one to the page —
        // parked, because no window is open yet.
        ledger.observe(
            start + 1_000,
            "assets.thirdparty-delivery.test",
            CoActivityKind::CandidateInUse,
        );
        // Now the page itself: this opens the window and replays the park.
        ledger.observe(start + 2_000, "site.test", anchor);
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals.iter().any(|p| p.anchor_hostname == "site.test"
            && p.proposed.value().contains("thirdparty-delivery")),
        "the look-back's whole purpose is this sighting: {:?}",
        proposals
            .iter()
            .map(|p| (p.anchor_hostname.as_str(), p.proposed.value()))
            .collect::<Vec<_>>()
    );
}

/// Equal brand tokens below the length containment demands (`q.test`/`q.example`,
/// `x.com`/`x.ai`) are kinship one registrar away from coincidence. They
/// still earn the host they name; they must not earn the apex.
#[test]
fn a_short_brand_token_earns_the_host_but_not_the_apex() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "q.test", &["img.q.example"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
    assert_eq!(
        proposals[0].proposed,
        ProposedCompanionMatch::ExactHost("img.q.example".to_string())
    );
}

/// The other half: a token long enough to name an operator still speaks for
/// the whole apex on its own, which is what the tier is for.
#[test]
fn a_full_brand_token_still_speaks_for_the_apex() {
    let mut ledger = defaults();
    two_visits(&mut ledger, "chatapp.example", &["static.chatapp.test"]);

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "chatapp.test")),
        "a named brand stopped generalizing: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.clone())
            .collect::<Vec<_>>()
    );
}

/// Shared branding outranks the page context: `static.chatapp.test` is
/// ChatApp's whoever's page happened to be loading.
#[test]
fn brand_relation_is_not_overruled_by_the_page_context() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "web.chatapp.example", anchor);
        ledger.observe(start + 1_000, "elsewhere.test", CoActivityKind::Candidate);
        ledger.observe(
            start + 2_000,
            "static.chatapp.test",
            CoActivityKind::Candidate,
        );
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert!(
        proposals
            .iter()
            .any(|p| p.signal == CompanionSignal::BrandRelated
                && p.proposed.value().contains("chatapp.test")),
        "a brand match states ownership and needs no page context: {:?}",
        proposals
            .iter()
            .map(|p| p.proposed.value())
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_delivery_named_companion_goes_to_the_site_that_owns_its_observations() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    // Both sites are open; "near.test" is always the one just active, so
    // every observation of the delivery host is attributed to it.
    for start in [0_u64, 100_000] {
        ledger.observe(start, "far.test", anchor);
        ledger.observe(start + 1_000, "near.test", anchor);
        ledger.observe(start + 2_000, "img.edgefarm.net", CoActivityKind::Candidate);
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].anchor_hostname, "near.test");
    assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
    // "far.test" saw it in just as many windows, but never owned it.
    assert!((proposals[0].affinity - 0.5).abs() < f64::EPSILON);
}

#[test]
fn one_sighting_publishes_only_when_no_other_site_was_active_alongside() {
    // Field case: the user opened one site, a second one re-resolved 0.8 s
    // later purely because its TTL expired, and that lead was enough to
    // sign the CDN of the first site with the second one's name. One
    // sighting cannot carry an offer when two sites are in play.
    let mut contested = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    contested.observe(0, "opened-by-the-user.test", anchor);
    contested.observe(800, "chatty-ttl.test", anchor);
    contested.observe(1_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
    assert!(contested.proposals(10_000, &NoExclusions).is_empty());

    // The same sighting with the rival long quiet still publishes at once —
    // that shortcut is what makes a half-broken page fixable on the spot.
    let mut clear = defaults();
    clear.observe(0, "chatty-ttl.test", anchor);
    clear.observe(30_000, "opened-by-the-user.test", anchor);
    clear.observe(31_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
    let proposals = clear.proposals(40_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].anchor_hostname, "opened-by-the-user.test");
}

#[test]
fn a_contested_sighting_still_counts_once_the_evidence_repeats() {
    // Refusing the one-sighting shortcut must not silence the offer for
    // good: the ordinary two-window path is untouched.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "opened-by-the-user.test", anchor);
        ledger.observe(start + 800, "chatty-ttl.test", anchor);
        ledger.observe(
            start + 1_000,
            "img.edgefarm.net",
            CoActivityKind::CandidateInUse,
        );
    }
    assert!(!ledger.proposals(150_000, &NoExclusions).is_empty());
}

#[test]
fn a_family_of_fourth_level_names_collapses_to_the_level_they_share() {
    // The user's report: ten fourth-level names of one service, each its own
    // row to answer. The registrable domain is unreachable here — the anchor
    // lives under it — but `disk.example.md` names the service exactly.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "mail.example.md", anchor);
        for (i, host) in [
            "a.disk.example.md",
            "b.disk.example.md",
            "c.disk.example.md",
        ]
        .iter()
        .enumerate()
        {
            ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
        }
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(values, vec!["disk.example.md"], "one row, not three");
    assert!(matches!(
        proposals[0].proposed,
        ProposedCompanionMatch::SuffixDomain(_)
    ));
}

#[test]
fn the_shared_level_never_swallows_the_site_it_was_found_next_to() {
    // Same shape, except the anchor sits INSIDE the level the companions
    // share. Collapsing there would write a rule over the anchor itself, so
    // the individual names stand.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "disk.example.md", anchor);
        for (i, host) in ["a.disk.example.md", "b.disk.example.md"]
            .iter()
            .enumerate()
        {
            ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
        }
    }

    let values: Vec<String> = ledger
        .proposals(150_000, &NoExclusions)
        .into_iter()
        .map(|p| p.proposed.value().to_string())
        .collect();
    assert_eq!(values, vec!["a.disk.example.md", "b.disk.example.md"]);
}

#[test]
fn two_families_under_one_domain_collapse_separately() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "mail.example.md", anchor);
        for (i, host) in [
            "a.disk.example.md",
            "b.disk.example.md",
            "a.upd.example.md",
            "b.upd.example.md",
        ]
        .iter()
        .enumerate()
        {
            ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
        }
    }

    let mut values: Vec<String> = ledger
        .proposals(150_000, &NoExclusions)
        .into_iter()
        .map(|p| p.proposed.value().to_string())
        .collect();
    values.sort();
    assert_eq!(values, vec!["disk.example.md", "upd.example.md"]);
}

#[test]
fn one_lonely_fourth_level_name_is_not_a_family() {
    // Two hosts is the same bar the apex generalization uses; one host says
    // nothing about its siblings.
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for start in [0_u64, 100_000] {
        ledger.observe(start, "mail.example.md", anchor);
        ledger.observe(start + 1, "only.disk.example.md", CoActivityKind::Candidate);
    }

    let values: Vec<String> = ledger
        .proposals(150_000, &NoExclusions)
        .into_iter()
        .map(|p| p.proposed.value().to_string())
        .collect();
    assert_eq!(values, vec!["only.disk.example.md"]);
}

#[test]
fn a_hostname_that_spells_out_an_address_is_not_a_companion() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    ledger.observe(0, "site.test", anchor);
    // Reverse lookup named the machine behind a shared CDN address. Its
    // apex serves the whole internet, so proposing it routes strangers.
    ledger.observe(
        1_000,
        "a23-213-41-17.deploy.static.akamaitechnologies.com",
        CoActivityKind::CandidateInUse,
    );

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    assert_eq!(
        ledger.candidate_count(),
        0,
        "never tracked in the first place"
    );
}

#[test]
fn machine_names_are_told_apart_from_service_names() {
    // Every shape here was observed in the wild, reaching the ledger
    // through the reverse-lookup learner.
    for machine in [
        "a23-213-41-17.deploy.static.akamaitechnologies.com",
        "ec2-18-97-36-79.compute-1.amazonaws.com",
        "ec2-3-233-36-186.compute-1.amazonaws.com",
        "140.206.0.34.bc.googleusercontent.com",
        "server-13-32-45-67.fra6.r.example.net",
    ] {
        assert!(names_one_machine(machine), "{machine}");
    }
    for service in [
        "static.cdninsta.test",
        "xx-socialcdn-shv-02-fra3.socialcdn.test",
        "rr5---sn-2o25g5-55.videocdn.test",
        "ei.phncdn.com",
        // Four groups, but 2026 is no octet.
        "build-2026-01-02-03.example.com",
    ] {
        assert!(!names_one_machine(service), "{service}");
    }
}

#[test]
fn only_the_explicit_shard_form_counts_as_a_delivery_name() {
    assert!(is_delivery_named("rr5---sn-ajaig5-5a.videocdn.test"));
    assert!(is_delivery_named("static.chatapp.test"));
    assert!(is_delivery_named("i.cdn.example"));
    // A short alphanumeric label is NOT a shard marker: ordinary update and
    // telemetry infrastructure is named that way, and admitting it was
    // measured to bury the real companions in noise.
    assert!(!is_delivery_named("s07.upd3.antivirus.example"));
    assert!(!is_delivery_named("p13.upd3.antivirus.example"));
    assert!(!is_delivery_named("api.example.com"));
}

#[test]
fn a_delivery_name_under_a_services_own_domain_stays_exact() {
    // From a live run: one asset host offered to move the whole service —
    // sign-in included — onto the additional link.
    let mut ledger = defaults();
    for at in [0_u64, 100_000] {
        page_load(&mut ledger, at, "site.test", SECONDARY, &["cdn.auth0.com"]);
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1);
    assert_eq!(
        proposals[0].proposed.value(),
        "cdn.auth0.com",
        "an asset host under a service's own apex is evidence about itself only"
    );
}

#[test]
fn a_shard_shaped_name_is_proposed_but_a_numbered_label_is_not() {
    let mut ledger = defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    // Two sites open, "site.test" always the most recent one. Affinity is
    // 0.5 for both candidates, so only the delivery tier can propose.
    for start in [0_u64, 100_000] {
        ledger.observe(start, "other.test", anchor);
        ledger.observe(start + 1_000, "site.test", anchor);
        for (i, host) in [
            "rr5---sn-ajaig5-5a.videocdn.test",
            "s07.upd3.antivirus.example",
        ]
        .iter()
        .enumerate()
        {
            ledger.observe(start + 2_000 + i as u64, host, CoActivityKind::Candidate);
        }
    }

    let proposals = ledger.proposals(150_000, &NoExclusions);
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(values, vec!["videocdn.test"]);
    assert_eq!(proposals[0].anchor_hostname, "site.test");
}

// ── Evidence that survives a restart ─────────────────────────────────────

#[test]
fn a_restored_ledger_proposes_on_the_visit_that_would_have_been_the_second() {
    // The restart is the whole point: one visit before it, one after, and
    // the pair adds up exactly as two visits in one session would.
    let mut before = defaults();
    page_load(&mut before, 0, "site.example", SECONDARY, &["cdn.example"]);
    assert!(before.proposals(10_000, &NoExclusions).is_empty());

    let mut after =
        CompanionAffinityLedger::restored(CompanionAffinityConfig::default(), before.snapshot());
    page_load(
        &mut after,
        100_000,
        "site.example",
        SECONDARY,
        &["cdn.example"],
    );

    let proposals = after.proposals(150_000, &NoExclusions);
    assert_eq!(proposals.len(), 1, "the window before the restart counted");
    assert_eq!(proposals[0].anchor_hostname, "site.example");
}

#[test]
fn a_snapshot_round_trips_unchanged() {
    let mut ledger = defaults();
    two_visits(
        &mut ledger,
        "site.example",
        &["cdn.example", "helper.other"],
    );
    health(&mut ledger, "cdn.example", PrimaryHealthEvent::Stalled, 2);
    let snapshot = ledger.snapshot();

    let restored =
        CompanionAffinityLedger::restored(CompanionAffinityConfig::default(), snapshot.clone());
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(
        restored.proposals(150_000, &NoExclusions),
        ledger.proposals(150_000, &NoExclusions),
        "restored evidence must produce the same offers"
    );
}

#[test]
fn restoring_never_reissues_an_anchor_id() {
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "a.test", SECONDARY, &["cdn.example"]);
    let snapshot = ledger.snapshot();
    let highest = snapshot.anchors.iter().map(|a| a.id).max().expect("anchor");

    let mut restored =
        CompanionAffinityLedger::restored(CompanionAffinityConfig::default(), snapshot);
    page_load(&mut restored, 100_000, "b.test", SECONDARY, &[]);
    let ids: Vec<u32> = restored.snapshot().anchors.iter().map(|a| a.id).collect();
    assert!(
        ids.iter().filter(|id| **id == highest).count() == 1,
        "a fresh anchor must not take an id that is already in use: {ids:?}"
    );
}

#[test]
fn restoring_more_than_the_caps_allow_truncates_to_the_freshest() {
    let config = CompanionAffinityConfig {
        max_anchors: 1,
        max_candidates: 1,
        ..CompanionAffinityConfig::default()
    };
    let mut roomy = defaults();
    page_load(&mut roomy, 0, "old.test", SECONDARY, &["old-cdn.example"]);
    page_load(
        &mut roomy,
        50_000,
        "new.test",
        SECONDARY,
        &["new-cdn.example"],
    );

    let tight = CompanionAffinityLedger::restored(config, roomy.snapshot());
    assert_eq!(tight.anchor_count(), 1);
    assert_eq!(tight.candidate_count(), 1);
    let kept = tight.snapshot();
    assert_eq!(kept.anchors[0].hostname, "new.test");
    assert_eq!(kept.candidates[0].hostname, "new-cdn.example");
    assert!(
        kept.candidates[0]
            .pairs
            .iter()
            .all(|p| p.anchor_id == kept.anchors[0].id),
        "pairs of dropped anchors must not survive them"
    );
}

#[test]
fn a_delivery_name_with_one_owner_that_failed_on_the_main_route_needs_no_second_visit() {
    // The 0811 case: images of the site the user is reading do not load,
    // the visit is short, the service restarts before a second one. One
    // anchor, nobody else, and the address failing on the main route is
    // everything the offer needs.
    let mut ledger = defaults();
    page_load(
        &mut ledger,
        0,
        "site.test",
        SECONDARY,
        &["img.edgefarm.net"],
    );
    assert!(
        ledger.proposals(10_000, &NoExclusions).is_empty(),
        "no failure observed yet — nothing to offer"
    );
    health(
        &mut ledger,
        "img.edgefarm.net",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );

    let proposals = ledger.proposals(10_000, &NoExclusions);
    assert_eq!(proposals.len(), 1, "one visit is enough now");
    assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
    assert_eq!(proposals[0].anchor_hostname, "site.test");
}

#[test]
fn a_failing_delivery_name_shared_with_a_second_site_still_waits() {
    // Ownership has to be undivided: a name two open sites both asked for
    // says nothing about which of them it belongs to, however badly it
    // behaves.
    let mut ledger = defaults();
    page_load(&mut ledger, 0, "a.test", SECONDARY, &["img.edgefarm.net"]);
    page_load(
        &mut ledger,
        1_000,
        "b.test",
        SECONDARY,
        &["img.edgefarm.net"],
    );
    health(
        &mut ledger,
        "img.edgefarm.net",
        PrimaryHealthEvent::Stalled,
        PRIMARY_STALL_CONFIRMATIONS,
    );

    assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
}

#[test]
fn the_delivery_bypass_option_proposes_on_first_sight_and_touches_nothing_else() {
    let feed = |ledger: &mut CompanionAffinityLedger| {
        page_load(
            ledger,
            0,
            "site.test",
            SECONDARY,
            &["assets.edgefarm.net", "helper.other"],
        );
    };

    let mut gated = defaults();
    feed(&mut gated);
    assert!(
        gated.proposals(10_000, &NoExclusions).is_empty(),
        "the gate is on by default"
    );

    let mut ungated = CompanionAffinityLedger::new(CompanionAffinityConfig {
        propose_delivery_names_without_co_activity: true,
        ..CompanionAffinityConfig::default()
    });
    feed(&mut ungated);
    let proposals = ungated.proposals(10_000, &NoExclusions);
    // Only the delivery-shaped name is released; the plain one still has to
    // earn its proposal through the co-activity tier.
    let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
    assert_eq!(values, vec!["edgefarm.net"]);
    assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
}

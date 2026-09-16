use super::*;

// ── Registrable-domain heuristic ─────────────────────────────────────────

#[test]
fn registrable_domain_heuristic_cases() {
    // Plain two-label host: itself.
    assert_eq!(registrable_domain("example.com"), Some("example.com"));
    // Deep subdomain: last two labels.
    assert_eq!(
        registrable_domain("ev-h.cdn-relay.example"),
        Some("cdn-relay.example")
    );
    // Multi-part public suffix: last three labels.
    assert_eq!(
        registrable_domain("a.b.example.co.uk"),
        Some("example.co.uk")
    );
    assert_eq!(registrable_domain("www.foo.com.br"), Some("foo.com.br"));
    assert_eq!(registrable_domain("foo.com.br"), Some("foo.com.br"));
    // Bare multi-part suffix: nothing registrable.
    assert_eq!(registrable_domain("co.uk"), None);
    // Single label: nothing registrable.
    assert_eq!(registrable_domain("localhost"), None);
    // Case-insensitive suffix table match.
    assert_eq!(registrable_domain("www.foo.CO.UK"), Some("foo.CO.UK"));
}

// ── A rule the user deleted ──────────────────────────────────────────────

#[test]
fn a_host_that_stopped_being_a_rule_can_become_a_companion() {
    // The exact gesture a user makes to test the feature: delete the CDN
    // rules, reload the site, expect them offered back.
    let mut ledger = CompanionAffinityLedger::with_defaults();
    ledger.observe(
        0,
        "cdn.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    ledger.observe(
        10,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    assert!(!ledger.is_tracking_candidate("cdn.example"));

    // The user deletes the CDN rule; the next tick tells the ledger which
    // hostnames the rule book still calls rule hosts.
    assert_eq!(ledger.retain_anchors(|host| host == "site.example"), 1);

    ledger.observe(
        100_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    ledger.observe(100_100, "cdn.example", CoActivityKind::Candidate);

    assert!(
        ledger.is_tracking_candidate("cdn.example"),
        "a deleted rule must stop being an anchor, or it can never be proposed again"
    );
}

#[test]
fn retiring_an_anchor_drops_the_evidence_gathered_under_it() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);
    assert!(ledger.is_tracking_candidate("cdn.example"));

    ledger.retain_anchors(|_| false);

    assert_eq!(ledger.anchor_count(), 0);
    assert!(
        !ledger.is_tracking_candidate("cdn.example"),
        "evidence about a companion of a site that is no longer routed says nothing"
    );
}

#[test]
fn retaining_every_anchor_changes_nothing() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);

    assert_eq!(ledger.retain_anchors(|_| true), 0);
    assert_eq!(ledger.anchor_count(), 1);
    assert!(ledger.is_tracking_candidate("cdn.example"));
}

// ── A clock that moved ───────────────────────────────────────────────────

/// Every timestamp here is wall-clock. An NTP correction, a resumed VM or a
/// service that started before the clock was set leaves the ledger holding
/// a window that starts in a future which has not happened — and the state
/// is persisted, so a restart inherits it. Untreated it is permanent: the
/// anchor attributes nothing, its window is extended rather than reopened,
/// and LRU eviction never picks it because `last_seen_ms` never moves down.
#[test]
fn an_anchor_stamped_in_the_future_recovers_when_the_clock_comes_back() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    let future = 5_000_000_000_u64;

    // Seen while the clock was wrong.
    ledger.observe(future, "site.test", anchor);

    // The clock is corrected; the same page loads again, now with its CDN.
    ledger.observe(1_000, "site.test", anchor);
    ledger.observe(
        2_000,
        "assets.thirdparty-delivery.test",
        CoActivityKind::Candidate,
    );
    assert!(
        ledger.is_tracking_candidate("assets.thirdparty-delivery.test"),
        "an anchor whose window sits in the future attributes nothing at all"
    );

    let snapshot = ledger.snapshot();
    let stored = snapshot
        .anchors
        .iter()
        .find(|a| a.hostname == "site.test")
        .expect("the anchor is still tracked");
    assert!(
        stored.last_seen_ms <= 2_000,
        "a future `last_seen_ms` hides the anchor from LRU eviction for good",
    );
}

/// The buffer of parked sightings is read as ordered by time from both
/// ends: the prefix clean-up stops at the first entry that is still young,
/// and the overflow drops the FRONT. Refreshing an entry where it sat put a
/// young timestamp in front of old ones, so the overflow threw away the
/// sighting that had just been refreshed — the most recent evidence in the
/// buffer — while the stale ones behind it stayed.
#[test]
fn refreshing_a_parked_sighting_moves_it_to_the_back() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    // Fill the park to its cap; the first host is at the front.
    for i in 0..MAX_UNATTRIBUTED {
        ledger.observe(
            1_000 + i as u64,
            &format!("host{i}.delivery.test"),
            CoActivityKind::Candidate,
        );
    }
    // The oldest is seen again — it is now the newest evidence there is.
    ledger.observe(9_000, "host0.delivery.test", CoActivityKind::Candidate);
    // One more host overflows the buffer by one.
    ledger.observe(9_100, "extra.delivery.test", CoActivityKind::Candidate);

    // A window opens and claims everything the look-back still holds.
    ledger.observe(
        9_200,
        "site.test",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    assert!(
        ledger.is_tracking_candidate("host0.delivery.test"),
        "the refreshed sighting must survive an overflow, not be its victim",
    );
    assert!(
        !ledger.is_tracking_candidate("host1.delivery.test"),
        "the genuinely oldest entry is the one the overflow drops",
    );
}

/// Dropping an anchor takes its pairs with it; a candidate left with none
/// describes nothing and must not hold a slot in the bounded set. This is
/// what `retain_anchors` already did and eviction did not.
#[test]
fn evicting_an_anchor_drops_the_candidates_it_leaves_empty() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        max_anchors: 1,
        ..CompanionAffinityConfig::default()
    });
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    ledger.observe(1_000, "first.test", anchor);
    ledger.observe(
        1_100,
        "assets.thirdparty-delivery.test",
        CoActivityKind::Candidate,
    );
    assert_eq!(ledger.candidate_count(), 1);

    // The cap is one, so this evicts `first.test`.
    ledger.observe(2_000, "second.test", anchor);
    assert_eq!(ledger.anchor_count(), 1);
    assert_eq!(
        ledger.candidate_count(),
        0,
        "the candidate's only pair went with the evicted anchor",
    );
}

/// The module promises a byte-deterministic snapshot. Pairs were appended
/// in `HashMap` iteration order, which differs per process, so two runs
/// over the same events could serialise the same evidence differently.
#[test]
fn snapshot_pairs_are_ordered_by_anchor_id() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    let anchor = CoActivityKind::Anchor { route: SECONDARY };
    for (i, name) in ["a.test", "b.test", "c.test", "d.test"].iter().enumerate() {
        ledger.observe(1_000 + i as u64, name, anchor);
    }
    ledger.observe(
        1_500,
        "assets.thirdparty-delivery.test",
        CoActivityKind::Candidate,
    );

    let snapshot = ledger.snapshot();
    for candidate in &snapshot.candidates {
        let ids: Vec<u32> = candidate.pairs.iter().map(|p| p.anchor_id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "pairs must serialise in a fixed order");
    }
}

// ── Look-back on an opening window ───────────────────────────────────────

#[test]
fn a_companion_seen_just_before_the_page_is_still_attributed_to_it() {
    // The order a browser actually uses often enough: the CDN connection
    // opens a second ahead of the one to the page.
    let mut ledger = CompanionAffinityLedger::with_defaults();
    ledger.observe(1_000, "static.cdn.example", CoActivityKind::Candidate);
    ledger.observe(
        2_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );

    assert!(
        ledger.is_tracking_candidate("static.cdn.example"),
        "a sighting one second before the anchor must not be thrown away"
    );
}

#[test]
fn a_companion_seen_long_before_the_page_is_not_claimed_by_it() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    ledger.observe(0, "unrelated.cdn.example", CoActivityKind::Candidate);
    ledger.observe(
        DEFAULT_RETRO_WINDOW_MS + 5_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );

    assert!(
        !ledger.is_tracking_candidate("unrelated.cdn.example"),
        "the look-back must not reach into earlier browsing"
    );
}

#[test]
fn the_look_back_can_be_switched_off() {
    let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
        retro_window_ms: 0,
        ..CompanionAffinityConfig::default()
    });
    ledger.observe(1_000, "static.cdn.example", CoActivityKind::Candidate);
    ledger.observe(
        2_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );

    assert!(!ledger.is_tracking_candidate("static.cdn.example"));
}

#[test]
fn a_replayed_companion_counts_once_however_many_times_it_was_seen() {
    let mut ledger = CompanionAffinityLedger::with_defaults();
    for at in [500_u64, 700, 900, 1_100] {
        ledger.observe(at, "static.cdn.example", CoActivityKind::Candidate);
    }
    ledger.observe(
        2_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );
    // A second window must not re-claim what the first one already took.
    ledger.observe(
        120_000,
        "site.example",
        CoActivityKind::Anchor { route: SECONDARY },
    );

    assert_eq!(ledger.candidate_count(), 1);
}

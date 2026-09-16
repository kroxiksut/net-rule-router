use super::*;

// ── "It already works on the main link" ──────────────────────────────────────

/// A parked candidate around one DTO — the suffix form the flow always writes.
fn pending_candidate(dto: AutoRuleCandidateDto) -> PendingCandidate {
    PendingCandidate {
        dto,
        route: RouteRole::Secondary,
        match_kind: AuthoredMatchKind::SuffixDomain,
    }
}

/// The reported case, one step earlier than the check that was supposed to
/// cover it: nothing had measured `cdnjs` yet, and an unmeasured host reads
/// exactly like an unreachable one. `news.example` hit it after `assistant.example` did,
/// because the fix had been aimed at the verdict, not at its absence.
#[test]
fn a_third_party_with_no_verdict_yet_waits_instead_of_asking() {
    let unmeasured = main_link_dto(
        "news.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        "", // the pass has not answered for it yet
    );
    assert!(
        awaiting_the_main_link(&unmeasured, true),
        "with an answer still coming, the question waits for it"
    );

    // With the pass switched off no answer is coming, and holding the question
    // forever would retire the feature behind the user's back.
    assert!(
        !awaiting_the_main_link(&unmeasured, false),
        "no pass, nothing to wait for"
    );
}

/// What must NOT be held: the routed site's own names, and anything the pass
/// has already answered for. Without this the hold would swallow the very
/// suggestions the feature exists to make.
#[test]
fn the_hold_releases_the_sites_own_names_and_answered_hosts() {
    let own = main_link_dto(
        "news.example",
        "cdn.news.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        "",
    );
    assert!(
        !awaiting_the_main_link(&own, true),
        "the site's own delivery name is asked about regardless"
    );

    let brand = main_link_dto(
        "news.example",
        "news.example.org",
        AUTO_RULE_SIGNAL_BRAND_RELATED,
        "",
    );
    assert!(
        !awaiting_the_main_link(&brand, true),
        "the brand tier never waits on connectivity"
    );

    for behavior in [
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    ] {
        let answered = main_link_dto(
            "news.example",
            "cdnjs.cloudflare.com",
            AUTO_RULE_SIGNAL_DELIVERY_NAME,
            behavior,
        );
        assert!(
            !awaiting_the_main_link(&answered, true),
            "behavior {behavior:?} is an answer; the wait is over"
        );
    }
}

#[test]
fn a_shared_cdn_that_answers_on_the_main_link_is_not_worth_asking_about() {
    // The reported case: cdnjs answers perfectly well without the tunnel, and
    // the tray kept offering it because delivery names skipped the check that
    // co-activity names already had.
    let cdn = main_link_dto(
        "assistant.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(settled_by_the_main_link(&cdn));

    let ad = main_link_dto(
        "assistant.example",
        "casalemedia.com",
        AUTO_RULE_SIGNAL_CO_ACTIVITY,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(settled_by_the_main_link(&ad));
}

#[test]
fn the_sites_own_name_keeps_its_question_even_when_it_answers() {
    // Answering is not serving: ChatGPT answers main-link addresses with a
    // refusal, so its own names stay on offer whatever the connectivity says.
    let own = main_link_dto(
        "assistant.example",
        "cdn.assistant.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(!settled_by_the_main_link(&own));

    let brand = main_link_dto(
        "assistant.example",
        "chatgpt.io",
        AUTO_RULE_SIGNAL_BRAND_RELATED,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(
        !settled_by_the_main_link(&brand),
        "brand tier is never settled by connectivity"
    );
}

#[test]
fn a_host_that_fails_on_the_main_link_is_still_asked_about() {
    for behavior in [AUTO_RULE_PRIMARY_BEHAVIOR_STALLS, ""] {
        let dto = main_link_dto(
            "assistant.example",
            "cdnjs.cloudflare.com",
            AUTO_RULE_SIGNAL_DELIVERY_NAME,
            behavior,
        );
        assert!(
            !settled_by_the_main_link(&dto),
            "behavior {behavior:?} is not an answer"
        );
    }
}

#[test]
fn a_settled_candidate_does_not_hold_the_host_on_the_additional_route() {
    // The pair that has to agree: what the tray will not ask about must not
    // keep steering traffic as if the user had already said yes.
    let engine = engine_over(
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    );
    let settled = main_link_dto(
        "assistant.example",
        "cdnjs.cloudflare.com",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    let open = main_link_dto(
        "assistant.example",
        "assets.example",
        AUTO_RULE_SIGNAL_DELIVERY_NAME,
        AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    );
    engine.park(
        SID,
        vec![pending_candidate(settled), pending_candidate(open)],
        10,
    );

    assert!(
        !engine.covers_pending_secondary_host("cdnjs.cloudflare.com"),
        "a host the tray will not ask about must not be pinned as if accepted"
    );
    assert!(engine.covers_pending_secondary_host("assets.example"));
}

/// The dropped-companion line is deduped on the SELECTION, not on the event —
/// otherwise a steady set writes the same names every ten seconds, which is how
/// a log stops being read.
#[test]
fn an_unchanged_dropped_set_is_not_worth_a_second_line() {
    let note = QuietNote {
        inert: 2,
        sample: vec!["ozonru.me (www.ozon.ru)".to_string()],
    };
    assert!(
        quiet_note_is_news(None, &note),
        "the first sighting is always news"
    );
    assert!(!quiet_note_is_news(Some(&note), &note));

    // One companion swapped for another keeps the count — the sample is what
    // tells them apart, so it has to count as news.
    let swapped = QuietNote {
        inert: 2,
        sample: vec!["cdnjs.cloudflare.com (www.ozon.ru)".to_string()],
    };
    assert!(quiet_note_is_news(Some(&note), &swapped));

    // …and a set that grew past what the sample shows is news too.
    let grown = QuietNote {
        inert: 3,
        sample: note.sample.clone(),
    };
    assert!(quiet_note_is_news(Some(&note), &grown));
}

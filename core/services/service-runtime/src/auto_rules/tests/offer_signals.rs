use super::*;

// ── Placeholder answers — the host says the main link cannot carry it ───────

#[test]
fn a_placeholder_answer_parks_one_candidate_signed_by_the_host_itself() {
    let f = fixture(AutoRulesMode::Suggest);
    assert!(f
        .engine
        .note_placeholder_answer_host(SID, "Journal.Example.", wall_clock()));
    // Seeing it again refreshes the same offer instead of stacking another.
    assert!(f.engine.note_placeholder_answer_host(
        SID,
        "journal.example",
        wall_clock() + Duration::from_secs(60)
    ));

    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.anchor, "journal.example", "normalised, and signs itself");
    assert_eq!(c.proposed_match, "journal.example");
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER);
}

#[test]
fn a_host_already_covered_by_a_rule_is_never_offered_for_a_placeholder_answer() {
    let f = fixture(AutoRulesMode::Suggest);
    // The fixture's own rule book already covers `site.example`.
    assert!(!f
        .engine
        .note_placeholder_answer_host(SID, "site.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

#[test]
fn a_placeholder_answer_is_silent_while_suggestions_are_off() {
    let f = fixture(AutoRulesMode::Off);
    assert!(!f
        .engine
        .note_placeholder_answer_host(SID, "journal.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

// ── A host that fails on the main link signs its own offer ──────────────────

/// A fixture whose main-link verdicts come from a map a test can write, which
/// is what the stall registry is to production.
fn fixture_with_main_link_verdicts(
    verdicts: Arc<Mutex<HashMap<String, PrimaryBehavior>>>,
) -> Fixture {
    let mut f = build_fixture(
        AutoRulesMode::Suggest,
        Arc::new(InMemoryDismissalStore::new()),
        Arc::new(InMemoryPendingStore::new()),
        None,
    );
    f.engine = f
        .engine
        // Merged over the subtree, exactly as the production source does: an
        // offer is written as a suffix, so its verdict is about everything
        // the rule would carry, not about the bare name.
        .with_primary_behavior_source(Arc::new(move |name: &str| {
            let suffix = format!(".{name}");
            verdicts
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|(host, _)| host.as_str() == name || host.ends_with(&suffix))
                .map(|(_, behavior)| *behavior)
                .fold(PrimaryBehavior::Unknown, PrimaryBehavior::merge)
        }));
    f
}

fn set_verdict(
    verdicts: &Arc<Mutex<HashMap<String, PrimaryBehavior>>>,
    host: &str,
    behavior: PrimaryBehavior,
) {
    verdicts
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(host.to_string(), behavior);
}

/// The field case: connections complete their handshake on the main link and
/// are then dropped, keyed on the name. Nothing about the address says so — the
/// failures do.
#[test]
fn a_host_that_keeps_failing_on_the_main_link_is_offered_the_other_route() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);

    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "Forum.Talk.Example.",
        HostCounts::default(),
        wall_clock()
    ));
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    let c = &candidates[0];
    assert_eq!(c.proposed_match, "forum.talk.example");
    assert_eq!(c.anchor, c.proposed_match, "the host signs its own offer");
    assert_eq!(c.signal, AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED);
    assert_eq!(c.route, RouteRole::Secondary.slug());
    assert_eq!(c.primary_behavior, AUTO_RULE_PRIMARY_BEHAVIOR_STALLS);
}

/// A program the main link carries none of is offered whole, as an application
/// rule on the additional route; once one of its connections completes there
/// the offer goes.
#[test]
fn a_program_the_main_link_does_not_carry_is_offered_and_withdrawn() {
    let f = fixture(AutoRulesMode::Suggest);
    let stalled: Vec<std::net::IpAddr> = (1..=3)
        .map(|last| std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, last)))
        .collect();
    assert!(f
        .engine
        .note_app_main_link_blocked(SID, "Messenger.exe", &stalled, wall_clock()));
    let offered = f.engine.candidates(SID);
    assert_eq!(offered.len(), 1);
    let c = &offered[0];
    assert_eq!(c.proposed_match, "messenger.exe");
    assert_eq!(
        c.match_kind,
        nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION
    );
    assert_eq!(
        c.signal,
        nrr_shared::ipc_payloads::AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED
    );
    assert_eq!(c.primary_behavior, AUTO_RULE_PRIMARY_BEHAVIOR_STALLS);
    assert_eq!(c.observed_members.len(), 3);

    f.engine
        .withdraw_app_offer(SID, "messenger.exe", wall_clock());
    assert!(f.engine.candidates(SID).is_empty());
}

/// A program an application rule already names is not offered again.
#[test]
fn a_program_already_named_by_a_rule_is_not_offered() {
    let f = fixture(AutoRulesMode::Suggest);
    f.rules
        .book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .secondary = CanonicalRuleSet::from_rules(vec![
        exact_rule("site.example"),
        CanonicalRule {
            id: RuleId("app-1".into()),
            enabled: true,
            address_match: None,
            app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                pattern: nrr_domain::canonical::CanonicalAppPattern::Exact("messenger.exe".into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        },
    ]);
    let stalled: Vec<std::net::IpAddr> = (1..=3)
        .map(|last| std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, last)))
        .collect();
    assert!(!f
        .engine
        .note_app_main_link_blocked(SID, "messenger.exe", &stalled, wall_clock()));
}

/// Neither link reaches the host: the offer is withheld, and the notice list
/// says why — once, however many probes come back empty. A host the tunnel
/// does reach says nothing.
#[test]
fn an_offer_neither_link_can_carry_is_withheld_and_said_once() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let mut f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    let bus = Arc::new(EventBus::new());
    let sub = bus.subscribe_as("tray".to_string(), Some(SID.to_string()), None);
    f.engine = f.engine.with_event_bus(Arc::clone(&bus));
    for host in ["down.example", "up.example"] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(f.engine.note_main_link_blocked_host(
            SID,
            host,
            HostCounts::default(),
            wall_clock()
        ));
    }

    f.engine
        .note_secondary_reach(SID, "down.example", false, wall_clock());
    f.engine
        .note_secondary_reach(SID, "down.example", false, wall_clock());
    f.engine
        .note_secondary_reach(SID, "up.example", true, wall_clock());

    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["up.example".to_string()]);
    let told: Vec<String> = bus
        .peek_pending_for(&sub.subscription_id, 64)
        .into_iter()
        .filter_map(|e| match e.event {
            StatusUpdateEvent::HostUnreachableOnBothRoutes { host, .. } => Some(host),
            _ => None,
        })
        .collect();
    assert_eq!(told, vec!["down.example".to_string()]);
}

/// "Whose name is this" is answerable only where a site pulled the name in.
/// A self-signed offer IS its own anchor, so the comparison used to return
/// "the site's own name" for every ad host that failed on the main link — the
/// inbox stated as fact the opposite of the fact. Both sides are asserted
/// here: an absent answer for the self-signed offer proves nothing unless the
/// companion beside it still gets one.
#[test]
fn only_an_offer_with_a_real_anchor_says_whose_name_it_is() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "ads.tracker.example",
        HostCounts::default(),
        wall_clock()
    ));

    let candidates = f.engine.candidates(SID);
    let companion = candidates
        .iter()
        .find(|c| c.proposed_match == "cdn.example")
        .expect("the companion offer");
    assert_eq!(
        companion.third_party,
        Some(true),
        "a site pulled this name in, so the question has an answer"
    );
    let self_signed = candidates
        .iter()
        .find(|c| c.proposed_match == "ads.tracker.example")
        .expect("the self-signed offer");
    assert_eq!(
        self_signed.anchor, self_signed.proposed_match,
        "the host signs its own offer — there is no site to be third-party to"
    );
    assert_eq!(
        self_signed.third_party, None,
        "with no anchor site the question was never posed"
    );
}

/// A visit count is a fact about a PAIR — this host beside that site, across
/// distinct visits. An offer a host signs about itself has no pair, and the 1
/// it used to carry made the inbox say "seen in 1 visit" about a host whose
/// evidence is three failed connections in a row.
///
/// The count also ranks the list, so the second half of this test is the one
/// that matters: making it optional must not move anything.
#[test]
fn a_self_signed_offer_counts_no_visits_and_keeps_its_place_in_the_list() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "ads.tracker.example",
        HostCounts::default(),
        wall_clock()
    ));

    let candidates = f.engine.candidates(SID);
    let companion = candidates
        .iter()
        .find(|c| c.proposed_match == "cdn.example")
        .expect("the companion offer");
    assert_eq!(
        companion.observations,
        Some(2),
        "a pair seen across two visits still says so"
    );
    let self_signed = candidates
        .iter()
        .find(|c| c.proposed_match == "ads.tracker.example")
        .expect("the self-signed offer");
    assert_eq!(
        self_signed.observations, None,
        "no pair means no visits to count"
    );
    // Evidence-first ordering, unchanged: the companion carries an affinity and
    // the self-signed offer carries none, so the companion leads.
    let order: Vec<&str> = candidates
        .iter()
        .map(|c| c.proposed_match.as_str())
        .collect();
    assert_eq!(
        order,
        vec!["cdn.example", "ads.tracker.example"],
        "an optional count must not reorder the inbox"
    );
}

/// The offer is "move this into the tunnel". When the tunnel turns out not to
/// reach the host either, the move would trade one route that cannot carry it
/// for another that cannot — that is somebody else's outage, not a suggestion.
///
/// The check that matters is the third case: an offer nobody probed must be
/// untouched, because "not measured" and "measured as useless" are different
/// facts and only one of them is a reason to stay silent.
#[test]
fn an_offer_the_additional_route_cannot_help_is_withdrawn_and_an_unchecked_one_is_not() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    set_verdict(&verdicts, "chat.other.example", PrimaryBehavior::Stalls);
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "forum.talk.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "chat.other.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert_eq!(f.engine.candidates(SID).len(), 2, "both start out offered");

    // Measured: the tunnel reaches neither better nor at all.
    f.engine
        .note_secondary_reach(SID, "forum.talk.example", false, wall_clock());

    let after: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(
        after,
        vec!["chat.other.example".to_string()],
        "the one the tunnel cannot help is gone; the unchecked one stays",
    );

    // And the positive control for the gate itself: a host the tunnel DOES
    // reach keeps its offer, so the rule is about the answer and not about
    // having been probed at all.
    f.engine
        .note_secondary_reach(SID, "chat.other.example", true, wall_clock());
    let reach = f
        .engine
        .candidates(SID)
        .into_iter()
        .find(|c| c.proposed_match == "chat.other.example")
        .map(|c| c.secondary_reach);
    assert_eq!(
        reach,
        Some(Some(true)),
        "a reachable host keeps the offer and carries what was found",
    );
}

/// A self-signed offer describes the network as it was minutes ago, so it goes
/// stale faster than a companion offer, which describes which hosts belong
/// together. Both halves are asserted: a shorter life is only meaningful if the
/// longer one is still longer.
#[test]
fn a_self_signed_offer_goes_stale_sooner_than_a_companion_one() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    f.engine.tick(SID, later());
    // Both offers are stamped from the same clock, or "older" would only mean
    // "created on a different timeline".
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "ads.tracker.example",
        HostCounts::default(),
        later()
    ));
    assert_eq!(
        f.engine.candidates(SID).len(),
        2,
        "both are offered at first"
    );

    // Six hours on: past the self-signed horizon, well inside the companion one.
    let six_hours = later() + Duration::from_secs(6 * 60 * 60);
    f.engine.tick(SID, six_hours);

    let left: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(
        left,
        vec!["cdn.example".to_string()],
        "the self-signed offer expired and the companion one did not",
    );
}

/// The whole of the user-facing rule: a site the main link carries is never
/// offered the additional route. Not "offered and greyed out" — not offered.
#[test]
fn a_host_the_main_link_carries_is_never_offered_at_all() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "cdn.tracker.example", PrimaryBehavior::Responds);

    assert!(!f.engine.note_main_link_blocked_host(
        SID,
        "cdn.tracker.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert!(!f
        .engine
        .note_placeholder_answer_host(SID, "cdn.tracker.example", wall_clock()));
    assert!(f.engine.candidates(SID).is_empty());
}

/// Positive control for the test above: the SAME calls with the SAME host park
/// an offer as soon as the main link stops answering for it. Without this the
/// test above would also pass if the signals were simply dead.
#[test]
fn the_same_host_is_offered_once_the_main_link_stops_answering() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "cdn.tracker.example", PrimaryBehavior::Stalls);
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "cdn.tracker.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

/// An offer parked while the host was failing is withdrawn once it works —
/// from the list a person reads AND from the parked set the badge counts.
#[test]
fn an_offer_is_withdrawn_when_the_main_link_starts_carrying_the_host() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "forum.talk.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert_eq!(f.engine.candidates(SID).len(), 1);
    assert_eq!(f.engine.pending_count(SID), 1);

    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Responds);
    assert!(
        f.engine.candidates(SID).is_empty(),
        "the reason for the offer stopped being true",
    );
    f.engine.tick(SID, wall_clock() + Duration::from_secs(60));
    assert_eq!(
        f.engine.pending_count(SID),
        0,
        "and the badge stops counting it",
    );
}

/// A self-signed offer states what the network is doing now, and nothing
/// behind it survives a restart — so it must not come back asserting a
/// condition nobody has re-checked. A companion offer, which rests on evidence
/// that IS restored, still does: without that control this test would pass on
/// an engine that simply lost its parked set.
#[test]
fn a_self_signed_offer_does_not_come_back_after_a_restart_but_a_companion_does() {
    let store = Arc::new(InMemoryPendingStore::new());
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    {
        let mut f = build_fixture(
            AutoRulesMode::Suggest,
            Arc::new(InMemoryDismissalStore::new()),
            Arc::clone(&store),
            None,
        );
        let v = Arc::clone(&verdicts);
        f.engine = f
            .engine
            .with_primary_behavior_source(Arc::new(move |host: &str| {
                v.lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(host)
                    .copied()
                    .unwrap_or(PrimaryBehavior::Unknown)
            }));
        set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
        assert!(f.engine.note_main_link_blocked_host(
            SID,
            "forum.talk.example",
            HostCounts::default(),
            wall_clock()
        ));
        two_visits(&f.engine, &["cdn.example"]);
        f.engine.tick(SID, later());
        let parked: Vec<String> = f
            .engine
            .candidates(SID)
            .into_iter()
            .map(|c| c.proposed_match)
            .collect();
        assert!(
            parked.contains(&"forum.talk.example".to_string()),
            "{parked:?}"
        );
        assert!(parked.contains(&"cdn.example".to_string()), "{parked:?}");
    }

    let restarted = fixture_with_pending_store(AutoRulesMode::Suggest, store);
    let after: Vec<String> = restarted
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert!(
        !after.contains(&"forum.talk.example".to_string()),
        "a self-signed offer must re-earn itself: {after:?}",
    );
    assert!(
        after.contains(&"cdn.example".to_string()),
        "a companion offer still survives the restart: {after:?}",
    );
}

/// An ad or telemetry endpoint the provider cuts is not a site anyone was
/// trying to open, and it belongs to everybody — routing it would drag
/// unrelated traffic along. The four names are the ones a live run actually
/// offered; every one of them was measured as genuinely cut on the main link,
/// so the measurement is not what disqualifies them.
#[test]
fn shared_ad_and_telemetry_endpoints_are_never_offered_however_badly_they_fail() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    for host in [
        "ads.googlesyndication.com",
        "pubads.g.doubleclick.net",
        "stats.g.doubleclick.net",
        "www.googletagservices.com",
    ] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(
            !f.engine
                .note_main_link_blocked_host(SID, host, HostCounts::default(), wall_clock()),
            "{host}",
        );
    }
    assert!(f.engine.candidates(SID).is_empty());

    // Positive control: a site host failing the same way IS offered, so the
    // test above cannot pass on a detector that simply stopped working.
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "forum.talk.example",
        HostCounts::default(),
        wall_clock()
    ));
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

/// A host every measured sighting of which came inside another page's burst —
/// an ad, a widget — is not offered however badly it fails: nobody went there.
#[test]
fn a_host_only_ever_pulled_in_by_other_pages_is_not_offered() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    let pulled_in = HostCounts {
        companions: 3,
        ..HostCounts::default()
    };
    assert!(!f.engine.note_main_link_blocked_host(
        SID,
        "forum.talk.example",
        pulled_in,
        wall_clock()
    ));
    assert!(f.engine.candidates(SID).is_empty());

    // Positive control: the same host, once reached on its own, is offered.
    let opened = HostCounts {
        companions: 3,
        solo: 1,
        ..HostCounts::default()
    };
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", opened, wall_clock()));
    assert_eq!(f.engine.candidates(SID).len(), 1);
}

/// A process the measure cannot read proves nothing either way, so the hosts it
/// reached keep their offer.
#[test]
fn a_host_the_measure_is_blind_to_is_still_offered() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    let blind = HostCounts {
        unmeasured: 5,
        ..HostCounts::default()
    };
    assert!(f
        .engine
        .note_main_link_blocked_host(SID, "forum.talk.example", blind, wall_clock()));
}

/// One failing name is one question. The field case says why it must not
/// become a question about the whole domain: a failing subdomain was cut
/// while the apex and `www` answered normally on the main link.
#[test]
fn one_failing_subdomain_is_offered_by_its_own_name() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "forum.talk.example", PrimaryBehavior::Stalls);
    assert!(f.engine.note_main_link_blocked_host(
        SID,
        "forum.talk.example",
        HostCounts::default(),
        wall_clock()
    ));
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["forum.talk.example".to_string()]);
}

/// A SECOND failing name under the same domain is evidence the domain is what
/// is being cut, so the two questions collapse into one and the names they
/// replace are withdrawn.
#[test]
fn a_second_failing_name_under_one_domain_collapses_into_one_offer() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    for host in ["a.blocked.example", "b.blocked.example"] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(f.engine.note_main_link_blocked_host(
            SID,
            host,
            HostCounts::default(),
            wall_clock()
        ));
    }
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["blocked.example".to_string()], "{offered:?}");
}

/// The field case, both halves. Two names under one domain fail while the
/// apex answers — and the offer is still about the domain, because two cut
/// names prove the domain is what is being cut. One site, one question; the
/// apex travels with the site it belongs to.
#[test]
fn two_failing_names_roll_up_even_though_the_apex_still_answers() {
    let verdicts = Arc::new(Mutex::new(HashMap::new()));
    let f = fixture_with_main_link_verdicts(Arc::clone(&verdicts));
    set_verdict(&verdicts, "talk.example", PrimaryBehavior::Responds);
    for host in ["forum.talk.example", "test.talk.example"] {
        set_verdict(&verdicts, host, PrimaryBehavior::Stalls);
        assert!(f.engine.note_main_link_blocked_host(
            SID,
            host,
            HostCounts::default(),
            wall_clock()
        ));
    }
    let offered: Vec<String> = f
        .engine
        .candidates(SID)
        .into_iter()
        .map(|c| c.proposed_match)
        .collect();
    assert_eq!(offered, vec!["talk.example".to_string()], "{offered:?}");
}

/// The pass may find no address for a self-signed offer — the name memory it
/// falls back to is short-lived — and holding it until an answer that may never
/// arrive would silence it for good.
#[test]
fn a_self_signed_offer_is_never_held_waiting_for_a_pass_that_cannot_answer() {
    let mut dto = main_link_dto(
        "forum.talk.example",
        "forum.talk.example",
        AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED,
        "",
    );
    assert!(!awaiting_the_main_link(&dto, true));
    // A companion with no verdict yet IS held while the pass can still answer.
    dto.anchor = "site.example".to_string();
    dto.proposed_match = "cdn.other.example".to_string();
    dto.signal = AUTO_RULE_SIGNAL_CO_ACTIVITY.to_string();
    assert!(awaiting_the_main_link(&dto, true));
}

/// A companion offer is judged differently on purpose: a routed site's OWN
/// delivery name can complete a connection and still serve a refusal, so
/// "it answers" does not settle it. Only the self-signed offers are silenced.
#[test]
fn a_main_link_answer_does_not_silence_a_companion_of_the_same_brand() {
    let responding = main_link_dto(
        "site.example",
        "cdn.site.example",
        AUTO_RULE_SIGNAL_CO_ACTIVITY,
        AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    );
    assert!(!settled_self_signed(&responding));
    assert!(!settled_by_the_main_link(&responding));

    let mut self_signed = responding.clone();
    self_signed.anchor = "cdn.site.example".to_string();
    self_signed.signal = AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED.to_string();
    assert!(settled_self_signed(&self_signed));
    assert!(settled_by_the_main_link(&self_signed));
}

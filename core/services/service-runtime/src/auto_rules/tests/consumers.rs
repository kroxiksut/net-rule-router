use super::*;

// ── Consumers ────────────────────────────────────────────────────────────────

#[test]
fn a_shared_host_carries_every_consumer_strongest_first() {
    // Eager delivery-name suggestions skip the co-activity gate entirely, so
    // one hit already earns each anchor its own proposal for the same address
    // — the shape a real shared CDN produces.
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example", "site-b.example"]);
    // site-a pulls it on three separate visits, site-b on one: three visits
    // means three nearest-hits for site-a against a shared total, so its
    // evidence outranks site-b's and it signs the offer.
    for at in [0_u64, 100_000, 200_000] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site-a.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            300_000,
            "site-b.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }

    f.engine
        .tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1, "one address is one offer");
    let c = &candidates[0];
    assert_eq!(
        c.anchor, "site-a.example",
        "the strongest evidence signs it"
    );
    let names: Vec<&str> = c.consumers.iter().map(|x| x.hostname.as_str()).collect();
    assert_eq!(
        names,
        vec!["site-a.example", "site-b.example"],
        "winner first, then the rest by descending nearest_share"
    );
    assert!(c
        .consumers
        .iter()
        .all(|x| x.route == RouteRole::Secondary.slug()));
}

#[test]
fn a_repeated_tick_with_no_new_consumer_does_not_move_the_new_basis_clock() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example", "site-b.example"]);
    for (at, anchor) in [(0_u64, "site-a.example"), (100_000, "site-b.example")] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            anchor,
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }

    let first_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(200_000);
    f.engine.tick(SID, first_tick_at);
    let first = f.engine.candidates(SID);
    assert_eq!(first[0].consumers.len(), 2);
    let first_basis = first[0].consumers_changed_unix_ms;
    assert_eq!(
        first_basis,
        unix_ms(first_tick_at),
        "first appearance stamps now"
    );

    // Nothing new arrives — only a later tick re-deriving the same evidence.
    let second_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(300_000);
    f.engine.tick(SID, second_tick_at);
    let second = f.engine.candidates(SID);
    assert_eq!(
        second[0].consumers_changed_unix_ms, first_basis,
        "no new consumer arrived, so the clock must not move"
    );
}

#[test]
fn a_third_consumer_arriving_later_moves_the_new_basis_clock_forward() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules
        .also_route(&["site-a.example", "site-b.example", "site-c.example"]);
    for (at, anchor) in [(0_u64, "site-a.example"), (100_000, "site-b.example")] {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            anchor,
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    let first_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(200_000);
    f.engine.tick(SID, first_tick_at);
    let first_basis = f.engine.candidates(SID)[0].consumers_changed_unix_ms;

    // A third site starts pulling the same host.
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            300_000,
            "site-c.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    let third_tick_at = SystemTime::UNIX_EPOCH + Duration::from_millis(400_000);
    f.engine.tick(SID, third_tick_at);
    let after = f.engine.candidates(SID);
    assert_eq!(after[0].consumers.len(), 3);
    assert!(
        after[0].consumers_changed_unix_ms > first_basis,
        "a genuinely new consumer must move the clock forward"
    );
    assert_eq!(after[0].consumers_changed_unix_ms, unix_ms(third_tick_at));
}

/// The user's actual question when accepting a suggestion: "what else does
/// this affect?" A companion needed by a site already on the default route
/// gets no offer of its own — adding the rule would restate where its
/// traffic already goes — but the user must still be told, because accepting
/// the OTHER offer pulls that site's traffic into the tunnel too.
#[test]
fn a_consumer_on_the_default_route_still_appears_even_though_its_own_offer_is_inert() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    f.rules.also_route(&["site-a.example"]);
    f.rules.also_route_primary(&["site-b.example"]);
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            0,
            "site-a.example",
            RouteRole::Secondary,
            &["sharedcdn.example"],
        );
    }
    {
        let Some(mut batch) = f.engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        // FixedRules defaults to PreferPrimary, so Primary is the default
        // route and this anchor's own proposal is inert.
        page_load(
            batch_ledger(&mut batch),
            100_000,
            "site-b.example",
            RouteRole::Primary,
            &["sharedcdn.example"],
        );
    }

    f.engine
        .tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(200_000));
    let candidates = f.engine.candidates(SID);
    assert_eq!(
        candidates.len(),
        1,
        "the inert primary anchor must not become its own offer"
    );
    let c = &candidates[0];
    assert_eq!(c.route, RouteRole::Secondary.slug());
    let names: Vec<&str> = c.consumers.iter().map(|x| x.hostname.as_str()).collect();
    assert!(names.contains(&"site-a.example"));
    assert!(
        names.contains(&"site-b.example"),
        "the default-route consumer must still be visible: {names:?}"
    );
    let on_primary = c
        .consumers
        .iter()
        .find(|x| x.hostname == "site-b.example")
        .expect("site-b is a consumer");
    assert_eq!(on_primary.route, RouteRole::Primary.slug());
}

#[test]
fn classification_prefers_the_secondary_route_and_defaults_to_candidate() {
    assert_eq!(
        AutoRulesEngine::classify(false, true),
        CoActivityKind::Anchor {
            route: RouteRole::Secondary
        }
    );
    assert_eq!(
        AutoRulesEngine::classify(true, false),
        CoActivityKind::Anchor {
            route: RouteRole::Primary
        }
    );
    // A host matching both sets anchors the secondary — that is the route whose
    // companions break when they are missing.
    assert_eq!(
        AutoRulesEngine::classify(true, true),
        CoActivityKind::Anchor {
            route: RouteRole::Secondary
        }
    );
    assert_eq!(
        AutoRulesEngine::classify(false, false),
        CoActivityKind::Candidate
    );
}

/// A bus with `SID`'s client already subscribed. An announcement is only
/// worth recording once somebody can receive it, so every publish test
/// needs a listener — see the audience check in `publish`.
fn subscribed_bus() -> Arc<EventBus> {
    let bus = Arc::new(EventBus::new());
    bus.subscribe_as("test-client".to_string(), Some(SID.to_string()), None);
    bus
}

/// The service and the tray start together and the service usually wins. An
/// offer announced into that gap reached nobody, yet counted as announced —
/// and the tray, whose subscription begins at the CURRENT head, never learned
/// of it. The field case: the tray connected 20 seconds after the offer was
/// published, and no window ever opened.
#[test]
fn an_offer_announced_before_anyone_is_listening_is_announced_again_later() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = Arc::new(EventBus::new());
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        !engine.tick(SID, later()).published,
        "nothing is listening, so nothing was announced",
    );

    // The tray connects.
    bus.subscribe_as("tray".to_string(), Some(SID.to_string()), None);
    assert!(
        engine.tick(SID, later()).published,
        "the offer still has its news to deliver",
    );
    // And it is not repeated once it has actually been delivered.
    assert!(!engine.tick(SID, later()).published);
}

#[test]
fn a_growing_pending_set_is_announced_once_not_on_every_tick() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        engine.tick(SID, later()).published,
        "first finding announces"
    );
    // A further tick within the quiet window must stay silent even though the
    // set grew — the tray opens a window per event. The two visits sit one idle
    // window apart so they count as distinct sessions, and the tick that reaps
    // them still lands inside the announcement gap.
    for at in [151_000_u64, 168_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let second = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(169_000));
    assert!(second.parked > 0, "the finding is still parked");
    assert!(!second.published, "but it does not re-prompt");
}

/// Accepting a suggestion lowers the pending total, so "more pending than last
/// time" would mute every later arrival that stays under the session's
/// high-water mark — which is how a whole browsing session can go unoffered.
#[test]
fn a_suggestion_arriving_after_an_acceptance_is_still_announced() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_author(Arc::clone(&f.author) as Arc<dyn AutoRuleAuthor>)
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(
        engine.tick(SID, later()).published,
        "first finding announces"
    );

    let accepted: Vec<String> = engine.candidates(SID).into_iter().map(|c| c.id).collect();
    assert_eq!(accepted.len(), 1);
    engine
        .accept(SID, &accepted, later())
        .expect("the offer is accepted");
    assert!(engine.candidates(SID).is_empty(), "and stops being pending");

    for at in [200_000_u64, 300_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let next = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(350_000));
    assert!(next.parked > 0, "the next companion is parked");
    assert!(next.published, "and the tray is told about it");
}

/// A suggestion that lands inside the quiet gap must be announced by a later
/// tick on its own — waiting for the next arrival can mean waiting forever.
#[test]
fn a_suggestion_muted_by_the_quiet_gap_is_announced_by_a_later_tick() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));

    two_visits(&engine, &["cdn.example"]);
    assert!(engine.tick(SID, later()).published);

    for at in [151_000_u64, 168_000] {
        let Some(mut batch) = engine.begin_batch(SID) else {
            unreachable!("suggest mode collects")
        };
        page_load(
            batch_ledger(&mut batch),
            at,
            "site.example",
            RouteRole::Secondary,
            &["other.example"],
        );
    }
    let muted = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(169_000));
    assert!(muted.parked > 0 && !muted.published, "gap holds it back");

    // Nothing new arrives — only time passes.
    let later_tick = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(200_000));
    assert_eq!(later_tick.parked, 0, "no new finding");
    assert!(later_tick.published, "yet the waiting offer is announced");
}

/// A host that already completes connections on the main route needs no
/// tunnel, so it earns no popup — but it must stay in the tray's count: that
/// number promises "everything waiting for an answer", not "everything worth
/// waking you up for". And once every offer in the set has settled that way,
/// there is nothing left worth a popup at all.
#[test]
fn a_settled_offer_is_counted_but_only_an_unsettled_one_earns_a_popup() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    two_visits(&engine, &["cdn.example", "assets.example"]);
    engine.note_primary_health(SID, "cdn.example", PrimaryHealthEvent::Completed);

    // assets.example is still unsettled, so the set as a whole is worth surfacing.
    let mixed = engine.tick(SID, later());
    assert_eq!(mixed.pending, 2, "both offers stay parked, settled or not");
    assert!(mixed.published, "the still-open offer earns a popup");

    let published = bus.peek_pending_for(&sub.subscription_id, 10);
    assert_eq!(published.len(), 1, "exactly one event went out so far");
    match &published[0].event {
        StatusUpdateEvent::AutoRuleCandidatesChanged { pending_count, .. } => {
            assert_eq!(
                *pending_count, 2,
                "the tray's number covers everything waiting, not just what popped"
            );
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // The remaining companion settles too, well outside the quiet gap — nothing
    // is left worth a popup, so this tick must stay silent on its own terms.
    engine.note_primary_health(SID, "assets.example", PrimaryHealthEvent::Completed);
    let settled = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    assert_eq!(settled.pending, 2, "still both parked");
    assert!(
        !settled.published,
        "everything answers on primary, so no popup"
    );

    let after = bus.peek_pending_for(&sub.subscription_id, 10);
    assert_eq!(after.len(), 1, "no second event was published");
}

/// A site the user marked as refusing main-link addresses is the one case where
/// "it answers on the main route" proves nothing — answering with a refusal is
/// still answering. Its companions keep being offered.
#[test]
fn a_site_marked_as_refusing_keeps_its_companions_on_offer() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus))
    .with_refusing_anchors(Arc::new(|_sid: &str| vec!["site.example".to_string()]));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    // A third-party neighbour that answers on the main route: normally quietened.
    two_visits(&engine, &["cdn.example"]);
    engine.note_primary_health(SID, "cdn.example", PrimaryHealthEvent::Completed);

    let summary = engine.tick(SID, later());
    assert_eq!(summary.pending, 1);
    assert!(
        summary.published,
        "the anchor refuses main-link addresses, so its companions are still worth asking about"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

/// While the additional route is down, everything already travels the main
/// link and works — so an offer to move addresses onto a route that does not
/// exist right now is noise. The findings are kept and offered once it is back.
#[test]
fn suggestions_wait_for_the_additional_route_and_arrive_when_it_returns() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let up = Arc::new(AtomicBool::new(false));
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus))
    .with_secondary_ready({
        let up = Arc::clone(&up);
        Arc::new(move |_sid: &str| up.load(Ordering::Relaxed))
    });
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    two_visits(&engine, &["assets.site.example"]);
    let while_down = engine.tick(SID, later());
    assert_eq!(while_down.pending, 1, "the finding is kept");
    assert!(
        !while_down.published,
        "nothing pops while the route is down"
    );
    assert!(bus.peek_pending_for(&sub.subscription_id, 10).is_empty());

    up.store(true, Ordering::Relaxed);
    let when_back = engine.tick(SID, SystemTime::UNIX_EPOCH + Duration::from_millis(400_000));
    assert!(
        when_back.published,
        "what was learned while the route was down is offered once it is up"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

/// "It answers on the main route" settles a third-party neighbour, never an
/// address of the routed site itself: a site can complete the connection and
/// still serve a refusal to a main-link address, which is the exact case the
/// user routes it for.
#[test]
fn an_address_of_the_site_itself_still_pops_even_when_the_main_route_answers() {
    let f = fixture(AutoRulesMode::Suggest);
    let bus = subscribed_bus();
    let engine = AutoRulesEngine::new(
        Arc::clone(&f.rules) as Arc<dyn RulesProvider>,
        mode_fn(AutoRulesMode::Suggest),
        Arc::clone(&f.dismissals) as Arc<dyn DismissalStore>,
        Arc::new(InMemoryPendingStore::new()),
        SystemTime::UNIX_EPOCH,
    )
    .with_event_bus(Arc::clone(&bus));
    let sub = bus.subscribe_as("client".into(), Some(SID.to_string()), None);

    // Same registrable domain as the anchor `site.example` → brand-related.
    two_visits(&engine, &["assets.site.example"]);
    engine.note_primary_health(SID, "assets.site.example", PrimaryHealthEvent::Completed);

    let summary = engine.tick(SID, later());
    assert_eq!(summary.pending, 1);
    assert!(
        summary.published,
        "an address belonging to the routed site is not settled by a completed connection"
    );
    assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
}

// ── Eager delivery-name suggestions (per-SID opt-in) ─────────────────────────

/// A delivery-shaped host normally has to earn its suggestion: one page load is
/// not evidence that the CDN belongs to this site rather than to everyone.
#[test]
fn a_delivery_named_host_is_not_suggested_from_one_visit_by_default() {
    let f = fixture(AutoRulesMode::Suggest);
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 0);
    assert!(f.engine.candidates(SID).is_empty());
}

/// With the opt-in on, the same single visit is enough — and the offer says why
/// it was made, which is the class the setting's warning is about.
#[test]
fn the_eager_opt_in_reaches_the_learner_and_offers_from_the_first_visit() {
    let f = fixture_with_eager_delivery(Arc::new(AtomicBool::new(true)));
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1);
    let candidates = f.engine.candidates(SID);
    assert_eq!(candidates.len(), 1);
    // A delivery name generalizes to its domain, so what the user is offered
    // covers the whole CDN rather than the one host seen so far.
    assert_eq!(candidates[0].proposed_match, "edgefarm.net");
    assert_eq!(candidates[0].match_kind, AUTO_RULE_MATCH_KIND_SUFFIX);
    assert_eq!(candidates[0].signal, AUTO_RULE_SIGNAL_DELIVERY_NAME);
}

/// The collateral rescue asks this before steering a host onto the primary. An
/// offer covers its subdomains whatever its match kind, because accepting it
/// writes a rule that does — `CanonicalRuleSet` expands every exact rule into a
/// suffix one. Reading it narrower sent `static.cdninsta.test` to the primary
/// while `cdninsta.test` sat in the offer.
#[test]
fn a_parked_offer_covers_the_subdomains_of_what_it_proposes() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["cdn.example"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 1);
    let offered = &f.engine.candidates(SID)[0];
    assert_eq!(offered.proposed_match, "cdn.example");

    assert!(f.engine.covers_pending_secondary_host("cdn.example"));
    assert!(f.engine.covers_pending_secondary_host("static.cdn.example"));
    assert!(f
        .engine
        .covers_pending_secondary_host("STATIC.CDN.EXAMPLE."));
    // Not a subdomain — a shared suffix is not a shared name.
    assert!(!f.engine.covers_pending_secondary_host("evilcdn.example"));
    assert!(!f.engine.covers_pending_secondary_host("example"));
}

/// The learner takes its configuration once and keeps it, so turning the setting
/// on mid-session has to reach a ledger that already exists.
#[test]
fn flipping_the_opt_in_reconfigures_the_live_ledger() {
    let opted_in = Arc::new(AtomicBool::new(false));
    let f = fixture_with_eager_delivery(Arc::clone(&opted_in));
    one_visit(&f.engine, &["assets.edgefarm.net"]);
    assert_eq!(f.engine.tick(SID, later()).parked, 0, "gated while off");

    opted_in.store(true, Ordering::Relaxed);
    f.engine.expire_settings_memo();
    one_visit(&f.engine, &["assets.edgefarm.net"]);

    let summary = f.engine.tick(SID, later());
    assert_eq!(summary.parked, 1, "the new setting reached the ledger");
    assert_eq!(
        f.engine.candidates(SID)[0].signal,
        AUTO_RULE_SIGNAL_DELIVERY_NAME
    );
}

/// Every offer carries its evidence class, not just the delivery-named ones.
#[test]
fn a_co_activity_suggestion_reports_that_signal() {
    let f = fixture(AutoRulesMode::Suggest);
    two_visits(&f.engine, &["helper.unrelated"]);

    assert_eq!(f.engine.tick(SID, later()).parked, 1);
    assert_eq!(
        f.engine.candidates(SID)[0].signal,
        AUTO_RULE_SIGNAL_CO_ACTIVITY
    );
}

// ── One clock for every observation source ───────────────────────────────────
//
// The ledger compares timestamps from three sources — the DNS consumer, the
// relay's flow observer, and the reverse-lookup learner — against one another
// and against the proposal tick. Two of them once reported "millis since this
// observer started", which sits in 1970 next to the wall-clock the other two
// use: every window those sources opened was invisible to the rest, and every
// candidate they reported landed outside all of them. The API takes a
// `SystemTime` so the mistake cannot be spelled; these tests keep it dead.

#[test]
fn a_relayed_flow_opens_a_window_the_dns_path_can_see() {
    let f = fixture(AutoRulesMode::Suggest);
    // The browser answered from its own cache, so the only sign the user is on
    // the site is the relayed flow. Two visits, because a delivery-named
    // companion the caller did not see in use needs two windows.
    for visit in [0_u64, 100] {
        let opened = wall_clock() + Duration::from_secs(visit);
        f.engine.note_flow(SID, "site.example", opened);
        // A companion resolved through us a second later, on the DNS clock.
        let at = unix_ms(opened + Duration::from_secs(1)).max(0) as u64;
        if let Some(mut batch) = f.engine.begin_batch(SID) {
            batch.observe(at, "cdn.example", CoActivityKind::Candidate);
        }
    }

    let summary = f.engine.tick(SID, wall_clock() + Duration::from_secs(120));
    assert_eq!(
        summary.parked, 1,
        "a window opened by a flow must accept a candidate seen by DNS"
    );
}

#[test]
fn a_host_named_only_by_reverse_lookup_lands_inside_the_open_window() {
    let f = fixture(AutoRulesMode::Suggest);
    // The site itself resolved through us — the anchor window is DNS-opened.
    let at = unix_ms(wall_clock()).max(0) as u64;
    if let Some(mut batch) = f.engine.begin_batch(SID) {
        batch.observe(
            at,
            "site.example",
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            },
        );
    }
    // Its CDN never crossed our DNS path (DoH); we only have the name because
    // a blocked connection was resolved backwards.
    f.engine
        .note_candidate_in_use(SID, "cdn.example", wall_clock() + Duration::from_secs(1));

    let summary = f.engine.tick(SID, wall_clock() + Duration::from_secs(2));
    assert_eq!(
        summary.parked, 1,
        "a reverse-confirmed name must reach the offer from one visit"
    );
}

use super::*;

#[test]
fn effective_routing_sid_prefers_registry_then_console_under_service_driven() {
    // 1. A connected-tray SID always wins, regardless of scope/console.
    let api = Arc::new(MockWindowsApi::new());
    api.set_console_user_sid(Some("S-CONSOLE"));
    let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
    assert_eq!(
        coord_app.effective_routing_sid(&["S-TRAY".to_string()]),
        Some("S-TRAY".to_string()),
    );

    // 2. No tray + app-driven scope → None (the console is never consulted).
    assert_eq!(coord_app.effective_routing_sid(&[]), None);

    // 3. No tray + service-driven scope + a console session → the console user.
    let coord_sd = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);
    assert_eq!(
        coord_sd.effective_routing_sid(&[]),
        Some("S-CONSOLE".to_string()),
    );

    // 4. No tray + service-driven scope + no console session → None.
    let api_no_console = Arc::new(MockWindowsApi::new());
    let coord_sd2 = coordinator_with_scope(api_no_console, Arc::new(FakeRules::new()), true);
    assert_eq!(coord_sd2.effective_routing_sid(&[]), None);
}

#[test]
fn effective_enforcement_sids_serve_trays_and_signed_in_users() {
    // the WFP orchestrator's SID set.
    let api = Arc::new(MockWindowsApi::new());
    api.set_console_user_sid(Some("S-CONSOLE"));
    let coord = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), true);

    // 1. Connected trays first (incl. multi-tray), then the signed-in user
    //    who has no tray: service-driven scope serves them too.
    let trays = vec!["S-TRAY-1".to_string(), "S-TRAY-2".to_string()];
    assert_eq!(
        coord.effective_enforcement_sids(&trays),
        vec![
            "S-TRAY-1".to_string(),
            "S-TRAY-2".to_string(),
            "S-CONSOLE".to_string()
        ],
    );
    // App-driven scope serves the trays alone.
    let coord_app_trays =
        coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
    assert_eq!(coord_app_trays.effective_enforcement_sids(&trays), trays);

    // 2. No tray + service-driven scope → the console user.
    assert_eq!(
        coord.effective_enforcement_sids(&[]),
        vec!["S-CONSOLE".to_string()],
    );

    // 3. No tray + app-driven scope → empty (nothing to enforce).
    let coord_app = coordinator_with_scope(Arc::clone(&api), Arc::new(FakeRules::new()), false);
    assert!(coord_app.effective_enforcement_sids(&[]).is_empty());

    // 4. No tray + service-driven + no console session → empty.
    let coord_no_console = coordinator_with_scope(
        Arc::new(MockWindowsApi::new()),
        Arc::new(FakeRules::new()),
        true,
    );
    assert!(coord_no_console.effective_enforcement_sids(&[]).is_empty());
}

#[test]
fn note_heal_once_dedups_until_mapping_changes() {
    let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
    let sid = "S-1-5-21-x-1001";
    // First sighting of a stale→healed mapping logs.
    assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
    // Same mapping repeats → silent (the heal re-fires every reconcile).
    assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new}"));
    // Healed id changes (adapter reinstalled again) → logs once more.
    assert!(coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
    assert!(!coord.note_heal_once(sid, "secondary", "win-adapter:{old}", "win-adapter:{new2}"));
    // A different role under the same sid is tracked independently.
    assert!(coord.note_heal_once(sid, "primary", "win-adapter:{old}", "win-adapter:{new2}"));
}

#[test]
fn note_not_usable_once_dedups_until_cleared_or_changed() {
    let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
    let sid = "S-1-5-21-x-1002";
    // First sighting of the not-usable state logs.
    assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // Same not-usable spell (adapter still down) repeats → silent.
    assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    assert!(!coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // Adapter resolves usable again → re-arm.
    coord.clear_not_usable(sid, "secondary");
    // Next not-usable transition for the SAME adapter logs again.
    assert!(coord.note_not_usable_once(sid, "secondary", "win-adapter:{tap}"));
    // A different role under the same sid is tracked independently.
    assert!(coord.note_not_usable_once(sid, "primary", "win-adapter:{tap}"));
}

/// How many `msg_key` lines `run` writes to the operational log.
fn count_logged(msg_key: &str, run: impl FnOnce()) -> usize {
    use tracing_subscriber::layer::SubscriberExt;

    let dir = tempfile::TempDir::new().expect("temp dir");
    let writer = Arc::new(nrr_diagnostics::LogWriter::open(
        nrr_diagnostics::LogWriterConfig::new(dir.path()),
    ));
    let subscriber =
        tracing_subscriber::registry().with(nrr_diagnostics::NdjsonTracingLayer::new(writer));
    tracing::subscriber::with_default(subscriber, run);
    let wanted = format!("diag.event.{msg_key}");
    let mut count = 0;
    for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
        let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
        count += text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("ndjson"))
            .filter(|line| line["message_key"] == wanted.as_str())
            .count();
    }
    count
}

/// Before the first run writes a policy every resolve finds none; the log says
/// so once per spell and per user, not at reconcile cadence.
#[test]
fn no_policy_is_logged_once_per_spell_and_again_after_a_policy_came_and_went() {
    let policy = Arc::new(FakePolicy::new());
    let coord = coordinator_with_policy(
        Arc::new(MockWindowsApi::new()),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    let key = "route-no-policy-for-user";

    let first_spell = count_logged(key, || {
        for _ in 0..5 {
            let _ = coord.resolve("S-NOPOL");
        }
    });
    assert_eq!(first_spell, 1, "repeated passes without a policy log once");

    let other_user = count_logged(key, || {
        let _ = coord.resolve("S-OTHER");
        let _ = coord.resolve("S-NOPOL");
    });
    assert_eq!(
        other_user, 1,
        "another user is its own spell; the first stays quiet"
    );

    policy.bind_secondary("S-NOPOL", "win-adapter:{tunnel}");
    let with_policy = count_logged(key, || {
        let _ = coord.resolve("S-NOPOL");
    });
    assert_eq!(with_policy, 0);

    policy.unbind("S-NOPOL");
    let second_spell = count_logged(key, || {
        for _ in 0..5 {
            let _ = coord.resolve("S-NOPOL");
        }
    });
    assert_eq!(
        second_spell, 1,
        "losing the policy again is a new state and logs again"
    );
}

/// A policy with no additional link ("choose later") is the same steady state:
/// said once per spell, and again only after a binding came and went.
#[test]
fn no_secondary_is_logged_once_per_spell_and_again_after_a_binding_came_and_went() {
    let policy = Arc::new(FakePolicy::new());
    let coord = coordinator_with_policy(
        Arc::new(MockWindowsApi::new()),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    let key = "route-no-secondary-bound";
    policy.bind_without_secondary("S-LATER");

    let first_spell = count_logged(key, || {
        for _ in 0..5 {
            let _ = coord.resolve("S-LATER");
        }
    });
    assert_eq!(
        first_spell, 1,
        "repeated passes without a secondary log once"
    );

    policy.bind_secondary("S-LATER", "win-adapter:{tunnel}");
    let bound = count_logged(key, || {
        let _ = coord.resolve("S-LATER");
    });
    assert_eq!(bound, 0);

    policy.bind_without_secondary("S-LATER");
    let second_spell = count_logged(key, || {
        for _ in 0..5 {
            let _ = coord.resolve("S-LATER");
        }
    });
    assert_eq!(second_spell, 1, "losing the binding again is a new state");
}

/// The derived next-hop is the answer to a question asked on every resolve, so
/// only a CHANGED answer is news — and a reconnect that lands on a new peer
/// must still say so.
#[test]
fn note_derived_next_hop_speaks_only_when_the_answer_changes() {
    let coord = coordinator(Arc::new(MockWindowsApi::new()), Arc::new(FakeRules::new()));
    let peer = std::net::Ipv4Addr::new(10, 88, 0, 1);
    let after_reconnect = std::net::Ipv4Addr::new(10, 88, 1, 1);

    assert!(
        coord.note_derived_next_hop(24, peer),
        "first derive is news"
    );
    assert!(!coord.note_derived_next_hop(24, peer));
    assert!(!coord.note_derived_next_hop(24, peer));
    assert!(
        coord.note_derived_next_hop(24, after_reconnect),
        "a tunnel that came back on another peer must be said out loud",
    );
    assert!(
        coord.note_derived_next_hop(25, peer),
        "another adapter is its own answer",
    );
}

#[test]
fn auto_heal_persists_corrected_binding_once() {
    // The stored secondary id is stale (adapter reinstalled → new GUID) but
    // the saved name still matches exactly one live adapter → auto-heal +
    // persist the corrected id, ONCE per distinct mapping.
    let api = Arc::new(MockWindowsApi::new());
    // Live adapter: new name/GUID "newguid", description "desc newguid",
    // up + IPv4 + gateway → Available and usable.
    let live = adapter("newguid", 59, true, true, Some([10, 0, 0, 1]));
    api.set_adapter_infos(vec![live]);

    let policy = Arc::new(FakePolicy::new());
    // Stale stored id; saved name "desc newguid" is a token-subset of the
    // live description, so the heal matches it.
    policy.bind_secondary_named("S-HEAL", "win-adapter:{oldguid}", "desc newguid");

    // Capture each persist as one "sid|role|id|name" line (a flat Vec keeps
    // the closure type simple for clippy::type_complexity).
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    )
    .with_binding_heal_persist(Arc::new(move |sid, role, id, name| {
        cap.lock()
            .unwrap()
            .push(format!("{sid}|{role}|{id}|{name}"));
    }));

    // First resolution heals and persists exactly once.
    let r1 = coord.resolve("S-HEAL");
    assert!(r1.secondary.is_some(), "heal should yield a usable target");
    {
        let c = captured.lock().unwrap();
        assert_eq!(c.len(), 1, "persist fires once on first heal");
        assert_eq!(
            c[0], "S-HEAL|secondary|win-adapter:newguid|desc newguid",
            "healed id + name persisted for the secondary role"
        );
    }
    // Re-resolving the SAME stale→healed mapping must NOT persist again
    // (note_heal_once dedup) — no per-reconcile write storm.
    let _ = coord.resolve("S-HEAL");
    assert_eq!(
        captured.lock().unwrap().len(),
        1,
        "repeated heal of the same mapping does not re-persist"
    );
}

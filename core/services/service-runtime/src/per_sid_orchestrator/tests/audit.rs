use super::*;

// ── Audit + multi-user fixture tests ────────────────────────────────

#[test]
fn install_emits_applied_audit_record() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sid, "A");
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[0].filter_count, (2 + EXEMPT) as u32);
    assert_eq!(records[0].message, "ok");
}

#[test]
fn second_install_for_same_sid_emits_updated_kind() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));
    orch.install_for_sid("A").unwrap();
    // Same SID, different policy → next install is "Updated".
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[1].kind, PerSidApplyAuditKind::Updated);
    assert_eq!(records[1].filter_count, (2 + EXEMPT) as u32);
}

#[test]
fn a_second_install_deletes_the_filters_the_new_set_supersedes() {
    // A full-replace install only ADDS. Without an explicit delete pass the
    // filters the new set drops stay live in the engine while leaving our
    // accounting — they keep dropping traffic that no recompute explains
    // and no teardown reaches (observed in the field as a pinned address
    // still being blocked long after its rule was gone).
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    rules.set(rules_with_n_primary_ips(3));
    orch.install_for_sid("A").unwrap();
    let after_wide = api.wfp_filters.lock().unwrap().len();

    // Narrower rule set: some of the previous filters are no longer wanted.
    rules.set(rules_with_n_primary_ips(1));
    orch.install_for_sid("A").unwrap();

    let live = api.wfp_filters.lock().unwrap().len();
    assert!(
        live < after_wide,
        "the narrower set must leave fewer filters live, got {live} vs {after_wide}"
    );
    // The invariant that actually matters: what the engine holds for this
    // SID is exactly what we think we installed.
    // The destinations the narrower set dropped must be gone from the
    // engine, not merely gone from our bookkeeping. (`filter_count_for` is
    // not comparable here: the mock re-adds an identical id instead of
    // answering FWP_E_ALREADY_EXISTS the way the real engine does.)
    let live_ips: Vec<Option<Ipv4Addr>> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.remote_ip)
        .collect();
    for dropped in [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)] {
        assert!(
            !live_ips.contains(&Some(dropped)),
            "{dropped} left the rule set, so its filter must not survive in the engine; live: {live_ips:?}"
        );
    }
}

#[test]
fn losing_the_policy_takes_down_the_filters_the_sid_was_carrying() {
    // `NoPolicy` / `NoActiveRules` used to record an empty set while
    // leaving every installed filter alive.
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    rules.set(rules_with_n_primary_ips(2));
    orch.install_for_sid("A").unwrap();
    assert!(!api.wfp_filters.lock().unwrap().is_empty());

    rules.set(rules_with_n_primary_ips(0));
    orch.install_for_sid("A").unwrap();
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "no active rules must leave nothing behind in the engine"
    );
    assert_eq!(orch.filter_count_for("A"), 0);
}

/// A fresh install: the SID is tracked, no revision is active yet, and the
/// first adapter binding recompiles it. That recompile took the SID's apply
/// lock a second time and never returned, so every later binding and apply
/// queued behind it for good.
#[test]
fn recompiling_a_tracked_sid_with_no_active_rules_returns() {
    let (api, orch, src, rules, _audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    rules.clear();

    let (tx, rx) = std::sync::mpsc::channel();
    let worker = Arc::clone(&orch);
    std::thread::spawn(move || {
        let _ = tx.send(worker.recompile_for_sid("A").map(|_| ()));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("recompile never returned: the SID's apply lock was taken twice");
    outcome.expect("recompile");
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn remove_emits_withdrawn_audit_record() {
    let (_api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("A").unwrap();
    orch.remove_for_sid("A").unwrap();
    let records = audit.snapshot();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, PerSidApplyAuditKind::Withdrawn);
    assert_eq!(records[1].filter_count, (2 + EXEMPT) as u32);
}

#[test]
fn audit_kind_slugs_are_stable_for_telemetry() {
    // Slugs are part of the audit wire contract — locking them in
    // prevents accidental rename in future cleanup.
    assert_eq!(
        PerSidApplyAuditKind::Applied.slug(),
        "per-sid-policy-applied"
    );
    assert_eq!(
        PerSidApplyAuditKind::Updated.slug(),
        "per-sid-policy-updated"
    );
    assert_eq!(
        PerSidApplyAuditKind::Withdrawn.slug(),
        "per-sid-policy-withdrawn"
    );
    assert_eq!(PerSidApplyAuditKind::Failed.slug(), "per-sid-policy-failed");
}

/// Multi-user scenario: User A and User B simultaneously have GUI
/// connections; their filters live in the same WFP session,
/// distinguished by `user_sid`. When User A submits
/// `RoutePolicyUpdate`, only A's filters are recompiled.
#[test]
fn two_users_concurrent_with_independent_recompile() {
    let (api, orch, src, _rules, audit) = fixture();
    src.set("A", snap_primary_only("Wi-Fi"));
    src.set("B", snap_full("Ethernet", "TAP-B"));
    orch.install_for_sid("A").unwrap();
    orch.install_for_sid("B").unwrap();
    assert_eq!(orch.installed_sids(), vec!["A", "B"]);
    // 2 rule-driven filters per SID, regardless
    // of bindings. B (snap_full) additionally carries the VPN-exempt permits.
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 4 + EXEMPT);

    // User A's recompile pass: bindings change but rules stay,
    // so the rule-driven filter set is unchanged. The lifecycle
    // path (remove + install) still runs end-to-end; what we
    // verify here is that B's filter set isn't disturbed.
    src.set("A", snap_full("Wi-Fi", "TAP-A"));
    orch.recompile_for_sid("A").unwrap();

    let filters = api.wfp_filters.lock().unwrap();
    let a_count = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("A"))
        .count();
    let b_count = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("B"))
        .count();
    assert_eq!(a_count, 2 + EXEMPT, "A's filters after recompile");
    assert_eq!(
        b_count,
        2 + EXEMPT,
        "B's filters preserved during A's recompile"
    );

    // Audit chain: a recompile of an already-installed SID is the
    // window-free MAKE-then-BREAK diff, so it surfaces as a
    // single `Updated` record — never a Withdrawn/Applied pair, because
    // the old filter set is no longer torn down before the new one lands.
    let records = audit.snapshot();
    let kinds: Vec<_> = records.iter().map(|r| (r.sid.as_str(), r.kind)).collect();
    assert_eq!(
        kinds,
        vec![
            ("A", PerSidApplyAuditKind::Applied),
            ("B", PerSidApplyAuditKind::Applied),
            ("A", PerSidApplyAuditKind::Updated),
        ],
    );
}

/// RDP simulation: a user disconnects (their session goes idle) →
/// orchestrator removes their filter set. Reconnect → reinstall.
/// Validates the production lifecycle when an RDP user signs in,
/// works for a while, signs out, and a different user signs in.
#[test]
fn rdp_user_lifecycle_install_remove_install_different_user() {
    use nrr_shared::ipc::IpcClientProfile;
    let (api, orch, src, _rules, audit) = fixture();
    src.set("RDP-USER-1", snap_primary_only("Wi-Fi"));
    src.set("RDP-USER-2", snap_full("Ethernet", "TAP"));

    let registry = ActiveSidRegistry::new();
    wire_orchestrator_to_registry(Arc::clone(&orch), &registry);

    // RDP-USER-1 connects. Filter count is rule-driven (fixture
    // = 2 ExactIp rules) regardless of `snap_primary_only`'s
    // binding shape.
    registry.on_connect("RDP-USER-1", IpcClientProfile::TrayLightweight);
    assert_eq!(orch.installed_sids(), vec!["RDP-USER-1".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2);

    // RDP-USER-1 disconnects.
    registry.on_disconnect("RDP-USER-1", IpcClientProfile::TrayLightweight);
    assert!(orch.installed_sids().is_empty());
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);

    // RDP-USER-2 connects from a different RDP session.
    registry.on_connect("RDP-USER-2", IpcClientProfile::TrayLightweight);
    assert_eq!(orch.installed_sids(), vec!["RDP-USER-2".to_string()]);
    // RDP-USER-2 = snap_full → armed None branch → +VPN-exempt permits.
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
    let filters = api.wfp_filters.lock().unwrap();
    assert!(filters
        .iter()
        .all(|f| f.user_sid.as_deref() == Some("RDP-USER-2")));
    drop(filters);

    // Audit shows the full lifecycle.
    let records = audit.snapshot();
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Applied));
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-1" && r.kind == PerSidApplyAuditKind::Withdrawn));
    assert!(records
        .iter()
        .any(|r| r.sid == "RDP-USER-2" && r.kind == PerSidApplyAuditKind::Applied));
}

/// Performance smoke at modest scale: 10 SIDs × 2 filters each.
/// Validates the orchestrator does not silently drop filters when
/// many users are active simultaneously, and that audit records
/// every SID. Production performance ceiling (50 RDP × 100 rules
/// = 5000 filters) is documented in TASKS_RU; smaller smoke test
/// here confirms the linear scaling is correct at least at the
/// small end.
#[test]
fn smoke_ten_sids_each_with_two_filters() {
    let (api, orch, src, _rules, audit) = fixture();
    for i in 0..10 {
        let sid = format!("S-1-5-21-{i:02}");
        src.set(&sid, snap_full("Wi-Fi", "TAP"));
        orch.install_for_sid(&sid).unwrap();
    }
    assert_eq!(orch.installed_sids().len(), 10);
    // 10 SIDs × snap_full (armed None branch) = 10 × (2 rule filters + VPN exempt).
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 10 * (2 + EXEMPT));
    // Every WFP filter has a non-None user_sid.
    assert!(api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .all(|f| f.user_sid.is_some()));
    // Every audit record is `Applied` (no failures, no updates).
    let records = audit.snapshot();
    assert_eq!(records.len(), 10);
    assert!(records
        .iter()
        .all(|r| r.kind == PerSidApplyAuditKind::Applied));
}

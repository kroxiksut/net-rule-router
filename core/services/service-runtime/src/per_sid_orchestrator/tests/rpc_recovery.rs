use super::*;

fn live_ids(api: &MockWindowsApi) -> HashSet<u64> {
    api.wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|record| record.id.raw)
        .collect()
}

#[test]
fn a_precommit_failure_keeps_the_published_snapshot_but_cannot_hide_a_lost_abort() {
    let (api, orch, source, rules, audit) = fixture();
    let sid = "S-1-5-21-rpc-abort";
    source.set(sid, snap_primary_only("Wi-Fi"));
    orch.install_for_sid(sid).unwrap();
    let previous = orch.installed_filter_ids(sid);
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 85)));
    api.set_fail_delete(&[previous[0].raw]);
    api.drop_next_wfp_abort_request();
    assert!(orch.reconcile_secondary_coverage(sid).is_err());
    assert_eq!(
        orch.installed_filter_ids(sid),
        previous,
        "an uncommitted attempt is not an installed policy"
    );
    api.set_fail_delete(&[]);
    rules.set(rules_with_n_primary_ips(2));
    assert!(
        orch.reconcile_secondary_coverage(sid).is_err(),
        "a still-open transaction cannot be hidden by a rollback no-op"
    );
    assert!(matches!(
        audit.snapshot().last().unwrap().kind,
        PerSidApplyAuditKind::Failed
    ));
}

#[test]
fn a_lost_replacement_reply_cannot_turn_rollback_into_a_successful_noop() {
    for committed in [false, true] {
        for periodic in [false, true] {
            let (api, orch, source, rules, audit) = fixture();
            let sid = "S-1-5-21-rpc-rollback";
            let other = "S-1-5-21-rpc-other";
            source.set(sid, snap_primary_only("Wi-Fi"));
            source.set(other, snap_primary_only("Wi-Fi"));
            orch.install_for_sid(sid).unwrap();
            orch.install_for_sid(other).unwrap();
            let before = live_ids(&api);
            rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 73)));
            api.lose_next_commit_response(committed);
            let outcome = if periodic {
                orch.reconcile_secondary_coverage(sid)
            } else {
                orch.install_for_sid(sid)
            };
            assert!(outcome.is_err());
            assert!(matches!(
                audit.snapshot().last().unwrap().kind,
                PerSidApplyAuditKind::Failed
            ));
            rules.set(rules_with_n_primary_ips(2));
            api.hide_wfp_enumeration(true);
            orch.reconcile_secondary_coverage(sid).unwrap();
            assert_eq!(
                live_ids(&api),
                before,
                "committed={committed}, periodic={periodic}: rollback left missing guards or stale permits"
            );
            api.record_wfp_history();
            orch.reconcile_secondary_coverage(sid).unwrap();
            assert!(api.wfp_history().is_empty(), "settled policy must be quiet");
        }
    }
}

#[test]
fn repeated_unknown_commits_converge_to_a_third_policy_without_claiming_foreign_ids() {
    let (api, orch, source, rules, _) = fixture();
    let sid = "S-1-5-21-rpc-third";
    source.set(sid, snap_primary_only("Wi-Fi"));
    orch.install_for_sid(sid).unwrap();
    // A same-SID record outside this owner's accounting must not be swept
    // merely because enumeration reports the same security principal.
    let mut foreign = api.wfp_filters.lock().unwrap()[0].clone();
    foreign.id = WfpFilterId { raw: u64::MAX - 15 };
    api.wfp_filters.lock().unwrap().push(foreign.clone());
    for ip in [73, 74] {
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, ip)));
        api.lose_next_commit_response(true);
        assert!(orch.reconcile_secondary_coverage(sid).is_err());
    }
    rules.set(rules_with_n_primary_ips(1));
    let ComputedFilterSet::Install(plan) = orch
        .compute_filters_for_sid(sid, false, None, ComputeIntent::Preview)
        .unwrap()
    else {
        panic!("the restored policy must install");
    };
    let expected: HashSet<_> = plan
        .filters
        .iter()
        .map(|spec| spec.id.raw)
        .chain([foreign.id.raw])
        .collect();
    api.hide_wfp_enumeration(true);
    orch.reconcile_secondary_coverage(sid).unwrap();
    assert_eq!(
        live_ids(&api),
        expected,
        "recovery must use attempted keys and preserve unrelated ownership"
    );
}

#[test]
fn a_skipped_permit_during_recovery_remains_retryable_until_the_desired_set_changes() {
    for install in [false, true] {
        let (api, orch, source, rules, _) = fixture();
        let sid = "S-1-5-21-rpc-skipped";
        source.set(sid, snap_primary_only("Wi-Fi"));
        orch.install_for_sid(sid).unwrap();
        let original = orch.installed_filter_ids(sid);
        let (kept, skipped) = {
            let live = api.wfp_filters.lock().unwrap();
            let id_for = |last| {
                let ip = Ipv4Addr::new(10, 0, 0, last);
                live.iter()
                    .find(|record| record.covers_v4(ip) || record.remote_subnet == Some((ip, 32)))
                    .expect("the primary host must have its own permit")
                    .id
            };
            (id_for(0), id_for(1))
        };
        assert_ne!(kept, skipped, "the fixture needs independent permits");
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 75)));
        api.lose_next_commit_response(true);
        assert!(orch.reconcile_secondary_coverage(sid).is_err());
        rules.set(rules_with_n_primary_ips(2));
        api.set_fail_add_unmaterializable(&[skipped.raw]);
        for _ in 0..2 {
            let result = if install {
                orch.install_for_sid(sid)
            } else {
                orch.reconcile_secondary_coverage(sid)
            };
            assert!(
                result.is_ok(),
                "best effort must still install the remaining permit"
            );
            assert_eq!(live_ids(&api), HashSet::from([kept.raw]));
        }
        // Removing the still-unmaterializable permit settles the new desired
        // set; recovery must not block the remaining permitted address.
        rules.set(rules_with_n_primary_ips(1));
        orch.reconcile_secondary_coverage(sid).unwrap();
        assert_eq!(live_ids(&api), HashSet::from([kept.raw]));
        api.set_fail_add_unmaterializable(&[]);
        api.record_wfp_history();
        orch.reconcile_secondary_coverage(sid).unwrap();
        assert!(
            api.wfp_history().is_empty(),
            "settled recovery must become quiet"
        );
        rules.set(rules_with_n_primary_ips(2));
        orch.reconcile_secondary_coverage(sid).unwrap();
        assert_eq!(live_ids(&api), original.iter().map(|id| id.raw).collect());
    }
}

#[test]
fn no_policy_finishes_retrying_an_empty_best_effort_recovery() {
    let (api, orch, source, rules, _) = fixture();
    let sid = "S-1-5-21-rpc-empty";
    source.set(sid, snap_primary_only("Wi-Fi"));
    orch.install_for_sid(sid).unwrap();
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 76)));
    api.lose_next_commit_response(true);
    assert!(orch.reconcile_secondary_coverage(sid).is_err());
    let fresh = CanonicalRule {
        id: RuleId("fresh-permit".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, 250,
        )))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![fresh]),
            secondary: CanonicalRuleSet::default(),
        },
    });
    let ComputedFilterSet::Install(plan) = orch
        .compute_filters_for_sid(sid, false, None, ComputeIntent::Preview)
        .unwrap()
    else {
        panic!("a fresh permit must be desired");
    };
    api.set_fail_add_unmaterializable(
        &plan
            .filters
            .iter()
            .map(|spec| spec.id.raw)
            .collect::<Vec<_>>(),
    );
    orch.reconcile_secondary_coverage(sid).unwrap();
    assert!(live_ids(&api).is_empty());
    rules.clear();
    source.per_sid.lock().unwrap().remove(sid);
    orch.reconcile_secondary_coverage(sid).unwrap();
    // Membership does not need another policy read for a confirmed empty set.
    source.fail_reads_of(sid);
    assert!(
        orch.reconcile(&[sid.to_string()]).is_ok(),
        "NoPolicy left empty recovery pending forever"
    );
}

#[test]
fn persist_cleanup_leaves_no_late_blocks_from_an_inflight_apply() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    let (api, orch, source, rules, _) = fixture();
    let sid = "S-1-5-21-rpc-persist";
    source.set(sid, snap_full("Wi-Fi", "TAP"));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 83)));
    orch.install_for_sid(sid).unwrap();
    let stopping = Arc::new(AtomicBool::new(false));
    let checks = AtomicUsize::new(0);
    let (ready_tx, ready_rx) = mpsc::channel();
    let gate_flag = stopping.clone();
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .ok()
            .unwrap()
            .with_teardown_gate(Arc::new(move || {
                let refused = gate_flag.load(Ordering::SeqCst);
                if checks.fetch_add(1, Ordering::SeqCst) == 1 {
                    let _ = ready_tx.send(());
                }
                refused
            })),
    );
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Mutex::new(release_rx);
    api.on_next_wfp_enumeration(Arc::new(move || {
        entered_tx.send(()).unwrap();
        release_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
    }));
    let sweep_orch = orch.clone();
    let sweep = std::thread::spawn(move || sweep_orch.cleanup_wfp_blocks_only());
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 84)));
    let apply_orch = orch.clone();
    let apply = std::thread::spawn(move || apply_orch.install_for_sid(sid));
    // A serialized cleanup holds the apply before its final latch read.
    let _ = ready_rx.recv_timeout(Duration::from_secs(2));
    stopping.store(true, Ordering::SeqCst);
    release_tx.send(()).unwrap();
    sweep.join().unwrap().unwrap();
    apply.join().unwrap().unwrap();
    assert!(
        api.wfp_filters
            .lock()
            .unwrap()
            .iter()
            .all(|record| record.action != WfpAction::Block),
        "an apply left live blocks after persist cleanup confirmed completion"
    );
}

#[test]
fn membership_replays_unknown_sets_before_retiring_inherited_guards() {
    for committed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(crate::wfp_filter_ledger::WfpFilterLedger::new(
            dir.path().join("wfp.ledger"),
        ));
        let (api, old, source, rules, audit) = fixture();
        let old = Arc::try_unwrap(old)
            .ok()
            .unwrap()
            .with_filter_ledger(ledger.clone());
        let sid = "S-1-5-21-rpc-adoption";
        source.set(sid, snap_full("Wi-Fi", "TAP"));
        let previous = rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 81));
        rules.set(previous.clone());
        old.install_for_sid(sid).unwrap();
        let inherited = live_ids(&api);
        assert!(api
            .wfp_filters
            .lock()
            .unwrap()
            .iter()
            .any(|f| f.action == WfpAction::Block));
        drop(old);
        let orch = PerSidApplyOrchestrator::new(
            Arc::new(WfpSession::open(api.clone()).unwrap()),
            source.clone(),
            rules.clone(),
            Arc::new(MockFqdnCacheLookup::new()),
            audit,
        )
        .with_filter_ledger(ledger.clone());
        orch.defer_orphans_to_first_pass();
        if committed {
            orch.install_for_sid(sid).unwrap();
        }
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 82)));
        api.lose_next_commit_response(committed);
        assert!(orch.install_for_sid(sid).is_err());
        if committed {
            rules.set(previous);
            orch.reconcile(&[sid.to_string()]).unwrap();
            assert_eq!(
                live_ids(&api),
                inherited,
                "membership adopted an unconfirmed set as ready"
            );
        } else {
            let ComputedFilterSet::Install(plan) = orch
                .compute_filters_for_sid(sid, false, None, ComputeIntent::Preview)
                .unwrap()
            else {
                panic!("replacement guards must be present");
            };
            let guard = plan
                .filters
                .iter()
                .find(|spec| spec.guards_traffic())
                .unwrap();
            api.set_fail_add_unmaterializable(&[guard.id.raw]);
            let result = orch.reconcile(&[sid.to_string()]);
            assert_eq!(
                live_ids(&api),
                inherited,
                "unconfirmed new guards cannot retire inherited protection"
            );
            assert!(result.is_err());
            api.set_fail_add_unmaterializable(&[]);
            orch.reconcile(&[sid.to_string()]).unwrap();
            assert_eq!(
                live_ids(&api),
                plan.filters
                    .iter()
                    .map(|spec| spec.id.raw)
                    .collect::<HashSet<_>>()
            );
        }
        assert_eq!(
            ledger.read().into_iter().collect::<HashSet<_>>(),
            live_ids(&api)
        );
    }
}

#[test]
fn a_lost_initial_reply_is_still_owned_by_the_departing_sid() {
    let (api, orch, source, _, _) = fixture();
    let sid = "S-1-5-21-rpc-first";
    let other = "S-1-5-21-rpc-other";
    source.set(sid, snap_primary_only("Wi-Fi"));
    source.set(other, snap_primary_only("Wi-Fi"));
    orch.install_for_sid(other).unwrap();
    let others = live_ids(&api);
    api.lose_next_commit_response(true);
    assert!(orch.install_for_sid(sid).is_err());
    assert!(live_ids(&api).len() > others.len());
    orch.remove_for_sid(sid).unwrap();
    assert_eq!(
        live_ids(&api),
        others,
        "departure orphaned the unacknowledged set"
    );
}

#[test]
fn no_policy_withdraws_both_possible_sets_after_a_lost_reply() {
    for committed in [false, true] {
        let (api, orch, source, rules, _) = fixture();
        let sid = "S-1-5-21-rpc-withdraw";
        source.set(sid, snap_primary_only("Wi-Fi"));
        orch.install_for_sid(sid).unwrap();
        rules.set(rules_with_secondary_ip(Ipv4Addr::new(192, 0, 2, 74)));
        api.lose_next_commit_response(committed);
        assert!(orch.reconcile_secondary_coverage(sid).is_err());
        rules.clear();
        source.per_sid.lock().unwrap().remove(sid);
        orch.reconcile_secondary_coverage(sid).unwrap();
        assert!(
            live_ids(&api).is_empty(),
            "NoPolicy orphaned the attempted set"
        );
        assert!(orch.installed_filter_ids(sid).is_empty());
    }
}

#[test]
fn a_lost_withdrawal_reply_requires_reinstalling_the_restored_policy() {
    let (api, orch, source, rules, _) = fixture();
    let sid = "S-1-5-21-rpc-restore";
    source.set(sid, snap_primary_only("Wi-Fi"));
    orch.install_for_sid(sid).unwrap();
    let before = live_ids(&api);
    rules.clear();
    source.per_sid.lock().unwrap().remove(sid);
    api.lose_next_commit_response(true);
    assert!(orch.reconcile_secondary_coverage(sid).is_err());
    assert!(live_ids(&api).is_empty());
    source.set(sid, snap_primary_only("Wi-Fi"));
    rules.set(rules_with_n_primary_ips(2));
    orch.reconcile_secondary_coverage(sid).unwrap();
    assert_eq!(
        live_ids(&api),
        before,
        "restored policy was mistaken for installed"
    );
}

#[test]
fn an_unconfirmed_cleanup_keeps_its_tracking_and_crash_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(crate::wfp_filter_ledger::WfpFilterLedger::new(
        dir.path().join("wfp.ledger"),
    ));
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(api.clone()).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let sid = "S-1-5-21-rpc-cleanup";
    source.set(sid, snap_primary_only("Wi-Fi"));
    rules.set(rules_with_n_primary_ips(2));
    let orch = PerSidApplyOrchestrator::new(
        session,
        source,
        rules,
        Arc::new(MockFqdnCacheLookup::new()),
        Arc::new(CollectAudit::default()),
    )
    .with_filter_ledger(ledger.clone());
    orch.install_for_sid(sid).unwrap();
    let before = live_ids(&api);
    api.hide_wfp_enumeration(true);
    api.lose_next_commit_response(false);
    assert!(
        orch.cleanup_wfp().is_err(),
        "an empty enumeration cannot acknowledge a failed delete"
    );
    assert!(!orch.installed_filter_ids(sid).is_empty());
    assert_eq!(ledger.read().into_iter().collect::<HashSet<_>>(), before);
    orch.cleanup_wfp().unwrap();
    assert!(live_ids(&api).is_empty());
    assert!(ledger.read().is_empty());
}

#[test]
fn withdrawing_one_owner_keeps_a_shared_filter_for_the_other_owner() {
    for no_policy in [false, true] {
        let (api, orch, source, rules, _) = fixture();
        let first = "S-1-5-21-rpc-share-a";
        let second = "S-1-5-21-rpc-share-b";
        source.set(first, snap_primary_only("Wi-Fi"));
        let ComputedFilterSet::Install(plan) = orch
            .compute_filters_for_sid(first, false, None, ComputeIntent::Preview)
            .unwrap()
        else {
            panic!("fixture must provide filters");
        };
        let mut shared = plan.filters[0].clone();
        shared.user_sid = None;
        for sid in [first, second] {
            orch.reconcile_to_desired(
                sid,
                Vec::new(),
                vec![shared.clone()],
                false,
                "shared guard",
                false,
            )
            .unwrap();
        }
        if no_policy {
            rules.clear();
            source.per_sid.lock().unwrap().remove(first);
            orch.reconcile_secondary_coverage(first).unwrap();
        } else {
            orch.remove_for_sid(first).unwrap();
        }
        assert!(
            live_ids(&api).contains(&shared.id.raw),
            "one owner removed another owner's shared guard"
        );
        assert_eq!(orch.installed_filter_ids(second), vec![shared.id]);
        orch.remove_for_sid(second).unwrap();
        assert!(live_ids(&api).is_empty());
    }
}

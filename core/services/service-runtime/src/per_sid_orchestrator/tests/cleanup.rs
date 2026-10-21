use super::*;

// ── WFP cleanup (persist-on-stop feature) ───────────────────────────────

/// Build an orchestrator that shares `session` with the caller so a test
/// can seed the live WFP table directly (as an orphaned prior instance
/// would leave it) and then exercise the cleanup entrypoints.
fn orch_sharing_session(session: Arc<WfpSession>) -> Arc<PerSidApplyOrchestrator> {
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    Arc::new(PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ))
}

#[test]
fn only_permitted_addresses_are_published_as_enforced() {
    let spec = |action: WfpAction, ip: Option<Ipv4Addr>, set: Vec<Ipv4Addr>| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action,
        remote_ip: ip,
        remote_ip_set: set,
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: 0,
        id: WfpFilterId { raw: 1 },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    };
    let permitted = Ipv4Addr::new(203, 0, 113, 158);
    let packed = Ipv4Addr::new(203, 0, 113, 142);
    let doh_blocked = Ipv4Addr::new(198, 51, 100, 4);
    let sid = "S-1-5-21-publish-test";

    PerSidApplyOrchestrator::publish_enforced_addresses(
        sid,
        &[
            spec(WfpAction::Permit, Some(permitted), Vec::new()),
            // The packed form: one filter guarding a whole address set.
            spec(WfpAction::Permit, None, vec![packed]),
            // The DoH lockdown names ~85 addresses it BLOCKS. Answering a
            // client with one of them would be the opposite of enforced.
            spec(WfpAction::Block, Some(doh_blocked), Vec::new()),
            // A catch-all carries no address and contributes nothing.
            spec(WfpAction::Permit, None, Vec::new()),
        ],
    );

    let register = crate::enforced_addresses::global_enforced_addresses();
    assert!(register.is_enforced(sid, permitted));
    assert!(register.is_enforced(sid, packed), "packed sets count too");
    assert!(!register.is_enforced(sid, doh_blocked));
    assert_eq!(register.snapshot(sid).len(), 2);
}

fn seeded_block_permit_block(session: &WfpSession, api: &MockWindowsApi) {
    let block = |raw: u64| WfpFilterSpec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: Some(Ipv4Addr::new(9, 9, 9, raw as u8)),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: 0x10_0000 + raw,
        id: WfpFilterId { raw },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    };
    let permit = |raw: u64| WfpFilterSpec {
        action: WfpAction::Permit,
        ..block(raw)
    };
    session
        .execute_wfp_plan(&[
            WfpFilterAction::AddFilter(block(1)),
            WfpFilterAction::AddFilter(permit(2)),
            WfpFilterAction::AddFilter(block(3)),
        ])
        .unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
}

#[test]
fn cleanup_wfp_blocks_only_strips_blocks_and_keeps_permits() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp_blocks_only().unwrap();
    assert_eq!(removed, 2, "only the two block filters must be stripped");
    let remaining = api.wfp_filters.lock().unwrap().clone();
    assert_eq!(remaining.len(), 1, "the permit filter must survive");
    assert_eq!(remaining[0].action, WfpAction::Permit);
}

/// Leak protection on: a dead instance's blocks hold through the start, and
/// the first pass over a present user deletes only what it did not claim.
#[test]
fn deferred_orphans_hold_until_the_first_pass_then_the_unclaimed_go() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    orch.defer_orphans_to_first_pass();
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        3,
        "nothing comes off before the first pass"
    );
    assert_eq!(
        orch.adopt_orphans_after_pass(),
        Some(3),
        "a pass that claimed nothing settles all three"
    );
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert_eq!(
        orch.adopt_orphans_after_pass(),
        None,
        "adoption happens once per start"
    );
}

/// The pass that adopts: a user whose set re-adds an inherited id keeps it;
/// what the set does not name is deleted after the pass, never before it.
#[test]
fn the_first_reconcile_keeps_what_it_re_adds_and_drops_the_rest() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let orch = Arc::new(PerSidApplyOrchestrator::new(
        Arc::clone(&session),
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ));
    // The dead instance's leftovers: an orphan block nobody will claim.
    seeded_block_permit_block(&session, &api);
    orch.defer_orphans_to_first_pass();

    // A present user with two pinned hosts: their ids are deterministic, so
    // the pass re-adds over whatever the dead instance left under them.
    source.set("S-A", snap_full("primary-1", "secondary-1"));
    rules.set(rules_with_n_primary_ips(2));
    orch.reconcile(&["S-A".to_string()]).unwrap();

    let remaining: Vec<u64> = api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .map(|f| f.id.raw)
        .collect();
    let tracked: Vec<u64> = orch
        .installed_filter_ids("S-A")
        .into_iter()
        .map(|id| id.raw)
        .collect();
    assert!(!tracked.is_empty(), "the pass installed the user's set");
    for raw in &remaining {
        assert!(
            tracked.contains(raw),
            "filter {raw} survived the pass unclaimed"
        );
    }
}

/// A slow engine at start: passes before it answers touch nothing and settle
/// nothing, so the dead instance's blocks hold until a pass really runs.
#[test]
fn passes_before_the_engine_opens_keep_inherited_blocks_and_install_nothing() {
    let api = Arc::new(MockWindowsApi::new());
    let crashed = WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap();
    seeded_block_permit_block(&crashed, &api);
    api.set_force_error(Some(nrr_platform_api::error::PlatformError::Transient {
        operation: "wfp_engine_open",
        detail: "engine busy".to_string(),
    }));
    let session = Arc::new(WfpSession::unopened(
        Arc::clone(&api) as Arc<dyn WindowsApiPort>
    ));
    assert!(session.ensure_open().is_err());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let orch = Arc::new(PerSidApplyOrchestrator::new(
        Arc::clone(&session),
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ));
    orch.defer_orphans_to_first_pass();
    source.set("S-A", snap_full("primary-1", "secondary-1"));
    rules.set(rules_with_n_primary_ips(2));

    orch.reconcile(&["S-A".to_string()]).unwrap();
    orch.recompile_for_sid("S-A").unwrap();
    assert_eq!(orch.strip_inherited_now(), 0);
    assert!(orch.installed_sids().is_empty());
    assert!(
        audit.snapshot().is_empty(),
        "a pass with no engine is not a refusal"
    );
    api.set_force_error(None);
    assert_eq!(
        api.wfp_filters.lock().unwrap().len(),
        3,
        "inherited filters hold while the engine is not open"
    );

    session.ensure_open().unwrap();
    orch.reconcile(&["S-A".to_string()]).unwrap();
    let tracked: Vec<u64> = orch
        .installed_filter_ids("S-A")
        .into_iter()
        .map(|id| id.raw)
        .collect();
    assert!(!tracked.is_empty(), "the first real pass installs the set");
    for f in api.wfp_filters.lock().unwrap().iter() {
        assert!(
            tracked.contains(&f.id.raw),
            "{} survived unclaimed",
            f.id.raw
        );
    }
}

fn engine_busy() -> nrr_platform_api::error::PlatformError {
    nrr_platform_api::error::PlatformError::Transient {
        operation: "wfp_engine_open",
        detail: "engine busy".to_string(),
    }
}

/// A start whose engine never answered, then a stop: the inherited ids stay
/// on disk for the next start, which finds them whatever enumerate reports.
#[test]
fn a_stop_before_the_engine_opens_keeps_the_inherited_ids_on_disk() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("wfp-filters.ledger");
    crate::wfp_filter_ledger::WfpFilterLedger::new(path.clone())
        .record(&[WfpFilterId { raw: 1 }, WfpFilterId { raw: 3 }]);
    let api = Arc::new(MockWindowsApi::new());
    api.set_force_error(Some(engine_busy()));
    let session = Arc::new(WfpSession::unopened(
        Arc::clone(&api) as Arc<dyn WindowsApiPort>
    ));
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            Arc::clone(&session),
            Arc::new(ScriptedSource::default()) as Arc<dyn RoutePolicySource>,
            Arc::new(ScriptedRules::default()) as Arc<dyn RulesProvider>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
        )
        .with_filter_ledger(Arc::new(crate::wfp_filter_ledger::WfpFilterLedger::new(
            path.clone(),
        ))),
    );
    orch.defer_orphans_to_first_pass();

    assert!(orch.cleanup_wfp().is_err(), "no engine, nothing stripped");
    let next_start = crate::wfp_filter_ledger::WfpFilterLedger::new(path);
    assert_eq!(next_start.read(), vec![1, 3]);
}

/// The engine answers only when the stop asks: the stop strips the dead
/// instance's filters rather than reporting zero.
#[test]
fn a_stop_opens_a_late_engine_and_strips_what_was_inherited() {
    let api = Arc::new(MockWindowsApi::new());
    let crashed = WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap();
    seeded_block_permit_block(&crashed, &api);
    api.set_force_error(Some(engine_busy()));
    let session = Arc::new(WfpSession::unopened(
        Arc::clone(&api) as Arc<dyn WindowsApiPort>
    ));
    assert!(session.ensure_open().is_err());
    let orch = orch_sharing_session(Arc::clone(&session));
    orch.defer_orphans_to_first_pass();
    api.set_force_error(None);

    assert_eq!(orch.cleanup_wfp().unwrap(), 3);
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

/// A start that may lift a dead instance's filters at once deletes them by
/// id, and the ledger then holds only what this process installs.
#[test]
fn an_immediate_strip_goes_by_the_inherited_ids_and_resets_the_ledger() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("wfp-filters.ledger");
    let api = Arc::new(MockWindowsApi::new());
    let crashed = WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap();
    seeded_block_permit_block(&crashed, &api);
    crate::wfp_filter_ledger::WfpFilterLedger::new(path.clone()).record(&[
        WfpFilterId { raw: 1 },
        WfpFilterId { raw: 2 },
        WfpFilterId { raw: 3 },
    ]);
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            Arc::clone(&session),
            Arc::new(ScriptedSource::default()) as Arc<dyn RoutePolicySource>,
            Arc::new(ScriptedRules::default()) as Arc<dyn RulesProvider>,
            Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
            Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
        )
        .with_filter_ledger(Arc::new(crate::wfp_filter_ledger::WfpFilterLedger::new(
            path.clone(),
        ))),
    );
    orch.defer_orphans_to_first_pass();

    assert_eq!(orch.strip_inherited_now(), 3);
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert!(crate::wfp_filter_ledger::WfpFilterLedger::new(path)
        .read()
        .is_empty());
    assert_eq!(
        orch.adopt_orphans_after_pass(),
        None,
        "nothing is left deferred"
    );
}

/// Without a deferral the start strips at once and the pass adopts nothing.
#[test]
fn a_start_that_stripped_at_once_has_nothing_to_adopt() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    assert_eq!(orch.cleanup_wfp_blocks_only().unwrap(), 2);
    assert_eq!(orch.adopt_orphans_after_pass(), None);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 1, "the permit stays");
}

/// The stop sweep waits for a transaction in flight under a user's apply
/// lock, so nothing lands behind the sweep with its ledger line erased.
#[test]
fn cleanup_wfp_waits_for_an_apply_in_flight() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let lock = orch.apply_lock_for("S-A");
    let guard = lock.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let sweeper = {
        let orch = Arc::clone(&orch);
        std::thread::spawn(move || {
            let n = orch.cleanup_wfp().unwrap();
            let _ = tx.send(n);
        })
    };
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "the sweep ran while the apply lock was held"
    );
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 3);
    drop(guard);
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
        3
    );
    sweeper.join().unwrap();
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn cleanup_wfp_strips_all_filters_and_clears_state() {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let orch = orch_sharing_session(Arc::clone(&session));
    seeded_block_permit_block(&session, &api);

    let removed = orch.cleanup_wfp().unwrap();
    assert_eq!(removed, 3, "cleanup_wfp strips block AND permit filters");
    assert!(api.wfp_filters.lock().unwrap().is_empty());
    assert!(
        orch.installed_sids().is_empty(),
        "cleanup_wfp must clear the in-memory SID→filter map"
    );
}

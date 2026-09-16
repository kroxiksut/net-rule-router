use super::*;

// ── Route before block ─────────────────────────────────────

/// Fixture whose route-sync hook records how many filters were live in WFP
/// at the instant it ran. A recorded `0` therefore proves the route pass
/// ran BEFORE any pin reached the engine — the ordering under test, without
/// a real route table or a real WFP engine.
#[allow(clippy::type_complexity)]
fn fixture_with_route_sync(
    resolution: Option<KillSwitchResolution>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
    Arc<Mutex<Vec<usize>>>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let observed: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let hook = {
        let api = Arc::clone(&api);
        let observed = Arc::clone(&observed);
        let hook: RouteSyncHook = Arc::new(move || {
            let live = api
                .wfp_filters
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len();
            observed
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(live);
        });
        hook
    };
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_| resolution.clone()))
        .with_route_sync(hook),
    );
    (api, orch, source, rules, observed)
}

#[test]
fn route_sync_runs_before_a_cold_install_lands_destination_pins() {
    let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();

    let live = api.wfp_filters.lock().unwrap().clone();
    assert!(
        live.iter().any(record_is_destination_block),
        "the install must have landed at least one destination-scoped block",
    );
    let calls = observed.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![0],
        "the route pass ran, and ran on an empty engine"
    );
}

#[test]
fn route_sync_is_skipped_when_nothing_destination_scoped_is_blocked() {
    // A primary-only policy emits rule permits and no leak-guard at all —
    // no destination block, so the ordering hook must not fire and the
    // steady state costs nothing.
    let (_api, orch, src, rules, observed) = fixture_with_route_sync(None);
    rules.set(rules_with_n_primary_ips(1));
    src.set("S-1-5-21-A", snap_primary_only("Wi-Fi"));

    orch.install_for_sid("S-1-5-21-A").unwrap();

    assert!(
        observed.lock().unwrap().is_empty(),
        "no new destination block ⇒ no route sync",
    );
}

#[test]
fn route_sync_runs_before_a_reconcile_pins_a_newly_covered_destination() {
    let (api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ips(&[Ipv4Addr::new(203, 0, 113, 10)]));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_install = api.wfp_filters.lock().unwrap().len();
    observed.lock().unwrap().clear();

    // The FQDN/app stores growing a destination is what the reconcile sees;
    // a second rule address is the deterministic stand-in for it.
    rules.set(rules_with_secondary_ips(&[
        Ipv4Addr::new(203, 0, 113, 10),
        Ipv4Addr::new(203, 0, 113, 11),
    ]));
    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    assert!(added > 0, "the reconcile must have grown the pin set");
    let calls = observed.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![after_install],
        "the route pass ran exactly once, before the new pins reached the engine",
    );
}

#[test]
fn route_sync_is_skipped_when_a_reconcile_changes_nothing() {
    let (_api, orch, src, rules, observed) = fixture_with_route_sync(Some(full_ks_resolution()));
    rules.set(rules_with_secondary_ip(Ipv4Addr::new(203, 0, 113, 10)));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    observed.lock().unwrap().clear();

    let added = orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();

    assert_eq!(added, 0, "coverage is unchanged");
    assert!(
        observed.lock().unwrap().is_empty(),
        "an unchanged reconcile must not drive the route pass",
    );
}

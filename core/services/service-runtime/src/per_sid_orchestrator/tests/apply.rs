use super::*;

#[test]
fn compute_records_unresolved_app_rules_into_status() {
    // an app rule whose exe resolves to no path (the
    // default NoopAppPathResolver) must publish the app pattern into the
    // shared `AppEnforcementStatus` for the GUI banner, while still
    // computing a (possibly empty) filter set.
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    source.set("S-1-5-21-APP", snap_primary_only("Wi-Fi"));
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_one_app("ab.exe"));
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let status = crate::app_enforcement_status::AppEnforcementStatus::new();
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_enforcement_status(status.clone());

    // Empty before any compute.
    assert!(status.unresolved().is_empty());

    orch.compute_filters_for_sid("S-1-5-21-APP", true, None, ComputeIntent::Apply)
        .unwrap();

    assert_eq!(status.unresolved(), vec!["ab.exe".to_string()]);
}

#[test]
fn doh_lockdown_emits_blocks_when_enabled_and_in_scope() {
    use nrr_storage::doh_lockdown::DohLockdownScope;
    let build = |scope: DohLockdownScope, kill_switch: bool| {
        let api = Arc::new(MockWindowsApi::new());
        let session =
            Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
        let source = Arc::new(ScriptedSource::default());
        let mut snap = snap_primary_only("Wi-Fi");
        snap.doh_lockdown_enabled = true;
        snap.doh_lockdown_scope = scope;
        snap.kill_switch_enabled = kill_switch;
        snap.doh_resolver_ips = vec![
            Ipv4Addr::new(198, 51, 100, 8).into(),
            Ipv4Addr::new(198, 51, 100, 1).into(),
            "2001:db8::53".parse().expect("v6"),
        ];
        source.set("S-1-5-21-DOH", snap);
        let rules = Arc::new(ScriptedRules::default());
        rules.set(rules_with_n_primary_ips(1));
        let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
        let audit = Arc::new(CollectAudit::default());
        let orch = PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        );
        let set = orch
            .compute_filters_for_sid("S-1-5-21-DOH", false, None, ComputeIntent::Apply)
            .unwrap();
        let plan = match set {
            ComputedFilterSet::Install(plan) => plan,
            _ => panic!("expected Install filter set"),
        };
        plan.filters
            .iter()
            .filter(|f| f.remote_port == Some(443) || f.remote_port == Some(853))
            .count()
    };
    // Always scope → blocks regardless of the kill-switch. IPv4: two packed
    // chunks × (443 TCP+UDP) + DoT (853 TCP+UDP) = 6; IPv6: one chunk + DoT = 4.
    assert_eq!(build(DohLockdownScope::Always, false), 10);
    // Leak-protection-only + kill-switch ON → applies.
    assert_eq!(build(DohLockdownScope::LeakProtectionOnly, true), 10);
    // Leak-protection-only + kill-switch OFF → does NOT apply.
    assert_eq!(build(DohLockdownScope::LeakProtectionOnly, false), 0);
}

/// A resolver drop must be explainable as the lockdown that caused it. The
/// notice path can only tell it from a rule by id, so the band has to be
/// published — and published SEPARATELY: landing in `all` would role-verify
/// it and report a working tunnel as unavailable.
#[test]
fn doh_lockdown_blocks_are_published_in_their_own_band() {
    use nrr_storage::doh_lockdown::DohLockdownScope;
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let mut snap = snap_full("Wi-Fi", "TAP");
    snap.doh_lockdown_enabled = true;
    snap.doh_lockdown_scope = DohLockdownScope::Always;
    snap.doh_resolver_ips = vec![
        Ipv4Addr::new(198, 51, 100, 4).into(),
        "2001:db8::53".parse().expect("v6"),
    ];
    source.set("S-1-5-21-DOHBAND", snap);
    let rules = Arc::new(ScriptedRules::default());
    rules.set(rules_with_n_primary_ips(1));
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let registry = Arc::new(crate::killswitch_drop_registry::KillswitchBlockFilterRegistry::new());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_kill_switch_resolver(Arc::new(|_, _| Some(full_ks_resolution())))
    .with_killswitch_drop_registry(Arc::clone(&registry));

    let set = orch
        .compute_filters_for_sid("S-1-5-21-DOHBAND", false, None, ComputeIntent::Apply)
        .unwrap();
    let plan = match set {
        ComputedFilterSet::Install(plan) => plan,
        _ => panic!("expected Install filter set"),
    };
    let doh_blocks: Vec<u64> = plan
        .filters
        .iter()
        .filter(|f| {
            f.action == WfpAction::Block
                && (f.remote_port == Some(443) || f.remote_port == Some(853))
        })
        .map(|f| f.id.raw)
        .collect();
    assert!(
        !doh_blocks.is_empty(),
        "the lockdown must have emitted blocks"
    );
    for id in doh_blocks {
        assert!(registry.is_dns_lockdown(id), "id {id} is not in the band");
        assert!(
            !registry.contains(id),
            "a resolver drop must not role-verify the tunnel"
        );
    }
}

/// The neutral pipeline must describe the same enforcement as the one that
/// actually installs — measured through the orchestrator's own compute, not
/// a hand-built plan.
///
/// The oracle tests in `enforcement_planner` already compare the two over
/// rule books written for the purpose. This one asks the question the way it
/// will be asked in production: whatever the orchestrator just computed for
/// this SID, does the plan agree with it? That is the check that has to hold
/// before the neutral path may take over the apply.
// Windows-only for the same reason the comparison is: it measures against a
// WFP filter set, and off-Windows there is none to measure against.
#[cfg(windows)]
#[test]
fn the_neutral_plan_agrees_with_the_filters_the_orchestrator_computes() {
    let (_api, orch, src, rules, _audit) = fixture();
    let sid = "S-1-5-21-NEUTRAL";
    src.set(sid, snap_full("Wi-Fi", "TAP"));
    let book = rules_with_n_primary_ips(3);
    rules.set(book.clone());

    // Drive the real compute, then compare against what it produced.
    let computed = orch
        .compute_filters_for_sid(sid, true, None, ComputeIntent::Preview)
        .expect("compute succeeds");
    let live = match computed {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => unreachable!("the fixture's rule book is installable"),
    };

    let verdict = orch
        .neutral_plan_verdict(
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            &live,
        )
        .expect("a well-formed SID yields a verdict");

    assert!(
        verdict.same_set,
        "neutral plan installs a different filter set: live={} neutral={}",
        verdict.live, verdict.neutral
    );
    assert!(
        verdict.same_order,
        "neutral plan installs the same filters in a different arbitration order — \
         WFP resolves overlaps by weight, so that is a different policy"
    );
}

/// The comparison re-derives the whole plan and lowers it, on a path that
/// fires every 30 s and that DNS answers queue behind. On input it has already
/// evidenced it must not do that work again — and it must resume the moment the
/// input really changes, or the evidence stops arriving.
// Windows-only for the same reason the comparison is: off-Windows there is
// no WFP filter set to compare against.
#[cfg(windows)]
#[test]
fn the_shadow_compare_runs_once_per_distinct_input() {
    let (_api, orch, src, rules, _audit) = fixture();
    let book = rules_with_n_primary_ips(3);
    rules.set(book.clone());
    let mode = nrr_domain::RouteBehaviorMode::PreferPrimary;

    // A real filter set to compare against. Computing it also runs the compare
    // for THIS sid — the periodic path does exactly that — so the sid under
    // test below is a different, not-yet-evidenced one.
    let seed_sid = "S-1-5-21-NEUTRAL-SEED";
    src.set(seed_sid, snap_full("Wi-Fi", "TAP"));
    let live = match orch
        .compute_filters_for_sid(seed_sid, true, None, ComputeIntent::Preview)
        .expect("compute succeeds")
    {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => unreachable!("the fixture's rule book is installable"),
    };
    assert!(
        !orch.shadow_compare_neutral_plan(
            seed_sid,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            &live,
        ),
        "computing the filters already compared this input — the periodic pass must not pay for it twice"
    );

    let sid = "S-1-5-21-NEUTRAL";
    assert!(
        orch.shadow_compare_neutral_plan(
            sid,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            &live
        ),
        "the first sighting of an input has to be compared"
    );
    assert!(
        !orch.shadow_compare_neutral_plan(
            sid,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            &live
        ),
        "the same input yields the same verdict — recomputing it buys nothing"
    );

    // A changed filter set inside the sampling window waits for the window.
    let narrower = &live[..live.len().saturating_sub(1)];
    assert!(
        !orch.shadow_compare_neutral_plan(
            sid,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            narrower
        ),
        "a change inside the window is sampled later, not compared on the spot"
    );

    // Positive control: once the window has passed, changed input is compared
    // again. Without this the test would pass on a compare that never reruns.
    {
        let mut seen = orch
            .shadow_compare_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let entry = seen.get_mut(sid).expect("the first compare was recorded");
        entry.1 = std::time::Instant::now()
            .checked_sub(super::super::shadow_compare::SHADOW_COMPARE_EVERY)
            .expect("the clock is past one window");
    }
    assert!(
        orch.shadow_compare_neutral_plan(
            sid,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            narrower
        ),
        "a different filter set after the window must be compared again"
    );
}

/// A separate user is separate evidence: folding both into one fingerprint
/// would let the second SID inherit the first one's "already compared".
// Windows-only for the same reason the comparison is: off-Windows there is
// no WFP filter set to compare against.
#[cfg(windows)]
#[test]
fn the_shadow_compare_is_remembered_per_user() {
    let (_api, orch, src, rules, _audit) = fixture();
    let book = rules_with_n_primary_ips(3);
    rules.set(book.clone());
    let mode = nrr_domain::RouteBehaviorMode::PreferPrimary;

    let seed_sid = "S-1-5-21-PER-USER-SEED";
    src.set(seed_sid, snap_full("Wi-Fi", "TAP"));
    let live = match orch
        .compute_filters_for_sid(seed_sid, true, None, ComputeIntent::Preview)
        .expect("compute succeeds")
    {
        ComputedFilterSet::Install(plan) => plan.filters,
        _ => unreachable!("the fixture's rule book is installable"),
    };

    let first = "S-1-5-21-NEUTRAL-A";
    assert!(orch.shadow_compare_neutral_plan(
        first,
        mode,
        &book.rule_book,
        orch.fqdn_cache.as_ref(),
        &std::collections::HashSet::new(),
        &live
    ));
    assert!(!orch.shadow_compare_neutral_plan(
        first,
        mode,
        &book.rule_book,
        orch.fqdn_cache.as_ref(),
        &std::collections::HashSet::new(),
        &live
    ));

    let second = "S-1-5-21-NEUTRAL-B";
    assert!(
        orch.shadow_compare_neutral_plan(
            second,
            mode,
            &book.rule_book,
            orch.fqdn_cache.as_ref(),
            &std::collections::HashSet::new(),
            &live
        ),
        "another user has not been evidenced yet, whatever the first one's input was"
    );
}

#[test]
fn install_for_sid_with_no_policy_records_empty_state() {
    let (api, orch, _src, _rules, _audit) = fixture();
    let count = orch.install_for_sid("S-1-5-21-X").unwrap();
    assert_eq!(count, 0);
    assert_eq!(orch.installed_sids(), vec!["S-1-5-21-X".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 0);
}

#[test]
fn install_for_sid_refuses_the_baseline_principal() {
    // the baseline is a per-user default, never a
    // routable per-SID target of its own. Refused with no side effects.
    let (api, orch, src, _rules, _audit) = fixture();
    src.set(
        nrr_domain::user_principal::BASELINE_PRINCIPAL,
        snap_full("Wi-Fi", "TAP"),
    );
    let err = orch
        .install_for_sid(nrr_domain::user_principal::BASELINE_PRINCIPAL)
        .expect_err("baseline must not be routable");
    assert!(matches!(err, OrchestratorError::BaselineNotRoutable));
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

#[test]
fn m1_no_active_user_means_no_enforcement_and_no_baseline_floor() {
    // when nobody is logged in the active-SID set
    // is empty: nothing is installed (routing is passthrough), and the
    // baseline is NOT applied as a machine-wide floor.
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    // Empty active set on a fresh orchestrator → nothing installed.
    orch.reconcile(&[]).unwrap();
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());

    // A user's tray connects → their filters appear.
    orch.reconcile(&["S-1-5-21-A".to_string()]).unwrap();
    assert_eq!(orch.installed_sids(), vec!["S-1-5-21-A".to_string()]);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);

    // Everyone logs off (empty set again) → filters torn down; no
    // baseline floor is left enforcing on the wire.
    orch.reconcile(&[]).unwrap();
    assert!(orch.installed_sids().is_empty());
    assert!(api.wfp_filters.lock().unwrap().is_empty());
}

/// The stop strips the filter set and then the process exits. Our WFP session
/// is not dynamic, so a filter added after the strip stays in the engine with
/// no service left to lift it — which is how a stopped service went on
/// blocking traffic. Deletes must keep working under the same latch.
#[test]
fn no_filter_is_installed_once_the_stop_teardown_has_begun() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (api, orch, src, _rules, _audit) = fixture();
    let stopping = Arc::new(AtomicBool::new(false));
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_teardown_gate({
                let stopping = Arc::clone(&stopping);
                Arc::new(move || stopping.load(Ordering::SeqCst))
            }),
    );
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);

    stopping.store(true, Ordering::SeqCst);
    orch.cleanup_wfp()
        .expect("the strip still runs while stopping");
    assert!(api.wfp_filters.lock().unwrap().is_empty());

    assert_eq!(orch.install_for_sid("S-1-5-21-A").unwrap(), 0);
    assert_eq!(orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap(), 0);
    assert!(
        api.wfp_filters.lock().unwrap().is_empty(),
        "a pass landing after the strip must not put filters back",
    );
}

#[test]
fn install_for_sid_with_policy_pushes_filters_to_wfp() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 2 + EXEMPT);
    let filters = api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2 + EXEMPT);
    // The v6 packet layer has no ALE_USER_ID, so those filters are
    // machine-wide by construction; everything else is this SID's.
    assert!(filters
        .iter()
        .filter(|f| f.layer != nrr_platform_api::types::WfpLayerKey::OutboundIpPacketV6)
        .all(|f| f.user_sid.as_deref() == Some("S-1-5-21-A")));
}

/// A socket opened before the rule keeps its interface for life, so an
/// activation has to break the connections to the destinations it just
/// started enforcing — otherwise the page the user added a rule for
/// finishes over the old link and only a manual reload fixes it.
#[test]
fn activation_tears_down_connections_to_the_destinations_it_starts_enforcing() {
    let (_api, orch, src, _rules, _audit) = fixture();
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_stale_flow_reset(Arc::clone(&reset)
                as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>),
    );
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        !reset.queried().is_empty(),
        "the destinations of a first install are all newly enforced"
    );

    // Re-applying the same policy must NOT tear the same connections down
    // again — those are the ones the first teardown just re-established.
    let before = reset.queried().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.queried().len(),
        before,
        "an unchanged destination set is not re-torn-down"
    );
}

/// A coverage reconcile maintains the SAME record an install does. It used
/// to leave the coverage fields alone, so the destinations it started
/// enforcing were never swept — the sockets already running to them
/// finished on the old link — and the next install then saw them as new and
/// swept connections that had already been re-established.
#[test]
fn a_coverage_reconcile_records_and_sweeps_what_it_starts_covering() {
    let first_ip = Ipv4Addr::new(203, 0, 113, 9);
    let second_ip = Ipv4Addr::new(203, 0, 113, 10);
    let (_api, orch, src, rules) = fixture_with_luid(Some(0x0001_0000_0000_0007));
    rules.set(rules_with_secondary_ip(first_ip));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let orch = Arc::new(
        Arc::try_unwrap(orch)
            .unwrap_or_else(|_| panic!("sole owner"))
            .with_stale_flow_reset(Arc::clone(&reset)
                as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>),
    );

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_install = reset.queried();
    assert!(after_install.contains(&first_ip));

    // A rule appears between passes; the coverage reconcile is what installs
    // its filters, so it is also what must break the flows already running
    // to that address.
    rules.set(rules_with_secondary_ips(&[first_ip, second_ip]));
    orch.reconcile_secondary_coverage("S-1-5-21-A").unwrap();
    let swept = reset.queried();
    assert!(
        swept.contains(&second_ip),
        "the address this pass started enforcing must be swept by it"
    );

    // And the install that follows must not re-sweep what the reconcile
    // already recorded as covered.
    let before = reset.queried().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.queried().len(),
        before,
        "an unchanged coverage set is not re-torn-down"
    );
}

/// The tunnel coming up changes no address, so the "only new destinations"
/// rule would sweep nothing — and every socket the browser opened while the
/// link was down would finish on the main link. The edge itself has to
/// count as a reason to sweep, but only for what the link now carries: a
/// destination of the main link, or a connection on a tunnel the user runs
/// beside ours, has nowhere new to go.
#[test]
fn the_additional_link_coming_up_sweeps_what_is_steered_onto_it_and_nothing_else() {
    use nrr_platform_api::fake_ip::stale_flows::{EstablishedFlow, FlowLinks};
    use std::net::SocketAddrV4;
    let tunnel_ip = Ipv4Addr::new(203, 0, 113, 9);
    let direct_ip = Ipv4Addr::new(203, 0, 113, 20);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    // The adapter appears between the two installs, exactly as a tunnel
    // that finishes connecting does.
    let live = Arc::new(Mutex::new(None::<KillSwitchResolution>));
    let resolver_state = Arc::clone(&live);
    let reset = Arc::new(nrr_platform_api::fake_ip::stale_flows::MockStaleFlowReset::new());
    let main_link = Ipv4Addr::new(192, 0, 2, 7);
    let corporate_link = Ipv4Addr::new(172, 16, 0, 150);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&src) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_, _| {
            resolver_state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }))
        .with_flow_links_resolver(Arc::new(move |_, _| {
            FlowLinks::new(
                vec![
                    (IpAddr::V4(main_link), 23),
                    (IpAddr::V4(corporate_link), 20),
                ],
                Some(23),
                Some(28),
            )
        }))
        .with_stale_flow_reset(
            Arc::clone(&reset) as Arc<dyn nrr_platform_api::fake_ip::stale_flows::StaleFlowReset>
        ),
    );
    let mut book = rules_with_secondary_ip(tunnel_ip);
    book.rule_book.primary =
        CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-pri", direct_ip)]);
    rules.set(book);
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let after_first = reset.queried().len();

    let flow = |local: Ipv4Addr, remote: Ipv4Addr, port: u16| EstablishedFlow {
        local: SocketAddrV4::new(local, port),
        remote: SocketAddrV4::new(remote, 443),
        owner: Some("S-1-5-21-A".to_owned()),
        pid: None,
        image: None,
    };
    let stranded = flow(main_link, tunnel_ip, 50_001);
    reset.set_flows(vec![
        stranded.clone(),
        flow(corporate_link, tunnel_ip, 50_002),
        flow(main_link, direct_ip, 50_003),
    ]);
    *live.lock().unwrap_or_else(|p| p.into_inner()) = Some(full_ks_resolution());
    orch.install_for_sid("S-1-5-21-A").unwrap();

    let swept: Vec<Ipv4Addr> = reset.queried().into_iter().skip(after_first).collect();
    assert!(
        swept.contains(&tunnel_ip),
        "the destination was pinned before and after, so only the up-edge can explain sweeping it: {swept:?}"
    );
    assert!(
        !swept.contains(&direct_ip),
        "the main link's destination has nowhere new to go: {swept:?}"
    );
    assert_eq!(reset.reset_flows(), vec![stranded]);

    // Steady state afterwards: the same install must not keep tearing the
    // reconnected sockets down.
    let before_third = reset.queried().len();
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(
        reset.queried().len(),
        before_third,
        "an unchanged, already-up link sweeps nothing"
    );
}

/// A host a rule just pinned to the main link, reached over a corporate
/// tunnel the user runs beside ours (an RD gateway, say), stays connected:
/// none of our routes moves it. One already on the main link stays too; one
/// on the additional link is off course and goes.
#[test]
fn a_new_destination_spares_connections_on_another_link_and_on_course() {
    use nrr_platform_api::fake_ip::stale_flows::{
        EstablishedFlow, FlowLinks, MockStaleFlowReset, StaleFlowReset,
    };
    use std::net::SocketAddrV4;
    const OWNER: &str = "S-1-5-21-A";
    let gateway = Ipv4Addr::new(203, 0, 113, 25);
    let main_link = Ipv4Addr::new(192, 0, 2, 7);
    let tunnel_link = Ipv4Addr::new(198, 51, 100, 41);
    let corporate_link = Ipv4Addr::new(172, 16, 0, 150);
    let flow = |local: Ipv4Addr, port: u16| EstablishedFlow {
        local: SocketAddrV4::new(local, port),
        remote: SocketAddrV4::new(gateway, 443),
        owner: Some(OWNER.to_owned()),
        pid: None,
        image: None,
    };
    let off_course = flow(tunnel_link, 50_003);
    let reset = Arc::new(MockStaleFlowReset::new());
    reset.set_flows(vec![
        flow(corporate_link, 50_001),
        flow(main_link, 50_002),
        off_course.clone(),
    ]);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let rules = Arc::new(ScriptedRules::default());
    let src = Arc::new(ScriptedSource::default());
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        Arc::new(SharedCensus(Default::default())) as Arc<dyn FqdnCacheLookup>,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_flow_links_resolver(Arc::new(move |_, _| {
        FlowLinks::new(
            vec![
                (IpAddr::V4(main_link), 23),
                (IpAddr::V4(tunnel_link), 28),
                (IpAddr::V4(corporate_link), 20),
            ],
            Some(23),
            Some(28),
        )
    }))
    .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);
    rules.set(ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![primary_ip_rule("r-pri", gateway)]),
            secondary: CanonicalRuleSet::default(),
        },
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    });
    src.set(OWNER, snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid(OWNER).unwrap();

    assert!(
        reset.queried().contains(&gateway),
        "the address is newly enforced"
    );
    assert_eq!(reset.reset_flows(), vec![off_course]);
}

/// A cache whose only answer is the shared-address census.
struct SharedCensus(std::collections::HashSet<Ipv4Addr>);

impl FqdnCacheLookup for SharedCensus {
    fn ips_for_hostname(&self, _hostname: &str) -> Vec<IpAddr> {
        Vec::new()
    }

    fn hostnames_under_suffix(&self, _suffix: &str, _limit: usize) -> Vec<String> {
        Vec::new()
    }

    fn shared_direct_ips(&self) -> std::collections::HashSet<Ipv4Addr> {
        self.0.clone()
    }
}

/// These filters are one user's, so the activation edge tears down that
/// user's connections only: another user's, an unattributed one and one to an
/// address a direct host shares all stay up.
#[test]
fn activation_tears_down_only_the_owners_connections_off_shared_addresses() {
    use nrr_platform_api::fake_ip::stale_flows::{
        EstablishedFlow, MockStaleFlowReset, StaleFlowReset,
    };
    use std::net::SocketAddrV4;
    const OWNER: &str = "S-1-5-21-A";
    let routed = Ipv4Addr::new(203, 0, 113, 9);
    let shared = Ipv4Addr::new(203, 0, 113, 10);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let src = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(SharedCensus([shared].into_iter().collect()));
    let reset = Arc::new(MockStaleFlowReset::new());
    let flow = |remote: Ipv4Addr, port: u16, owner: Option<&str>| EstablishedFlow {
        local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), port),
        remote: SocketAddrV4::new(remote, 443),
        owner: owner.map(str::to_owned),
        pid: None,
        image: None,
    };
    let owners = flow(routed, 50_001, Some("s-1-5-21-a"));
    reset.set_flows(vec![
        owners.clone(),
        flow(routed, 50_002, Some("S-1-5-21-B")),
        flow(routed, 50_003, None),
        flow(shared, 50_004, Some(OWNER)),
    ]);
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&src) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);
    rules.set(rules_with_secondary_ips(&[routed, shared]));
    src.set(OWNER, snap_full("Wi-Fi", "TAP"));

    orch.install_for_sid(OWNER).unwrap();

    let queried = reset.queried();
    assert!(
        queried.contains(&routed) && queried.contains(&shared),
        "both addresses are new destinations, so both are candidates: {queried:?}"
    );
    assert_eq!(reset.reset_flows(), vec![owners]);
}

/// Without the port wired, the activation edge is silent and the reactive
/// path in the connection observer stays the only repair — no panic, no
/// difference in what installs.
#[test]
fn an_unwired_flow_reset_changes_nothing_about_the_install() {
    let (api, orch, src, _rules, _audit) = fixture();
    src.set("S-1-5-21-A", snap_full("Wi-Fi", "TAP"));
    let count = orch.install_for_sid("S-1-5-21-A").unwrap();
    assert_eq!(count, 2 + EXEMPT);
    assert_eq!(api.wfp_filters.lock().unwrap().len(), 2 + EXEMPT);
}

/// A network a rule just started pinning is swept for its owner alone, and
/// only once: re-listing it would cut the connections the first sweep let
/// reconnect.
#[test]
fn a_new_rule_network_tears_down_only_the_owners_connections_inside_it() {
    use nrr_platform_api::fake_ip::stale_flows::{
        EstablishedFlow, MockStaleFlowReset, StaleFlowReset,
    };
    use nrr_shared::ip_block::IpBlock;
    use std::net::SocketAddrV4;
    const OWNER: &str = "S-1-5-21-A";
    let net = IpBlock::parse("198.51.100.0/24").unwrap();
    let flow = |remote: Ipv4Addr, port: u16, owner: &str| EstablishedFlow {
        local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 7), port),
        remote: SocketAddrV4::new(remote, 443),
        owner: Some(owner.to_owned()),
        pid: None,
        image: None,
    };
    let inside = Ipv4Addr::new(198, 51, 100, 77);
    let owners = flow(inside, 50_001, OWNER);
    let reset = Arc::new(MockStaleFlowReset::new());
    reset.set_flows(vec![
        owners.clone(),
        flow(inside, 50_002, "S-1-5-21-B"),
        flow(Ipv4Addr::new(203, 0, 113, 5), 50_003, OWNER),
    ]);
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(SharedCensus(Default::default()));
    let orch = PerSidApplyOrchestrator::new(
        session,
        Arc::new(ScriptedSource::default()) as Arc<dyn RoutePolicySource>,
        Arc::new(ScriptedRules::default()) as Arc<dyn RulesProvider>,
        cache,
        Arc::new(CollectAudit::default()) as Arc<dyn PerSidApplyAudit>,
    )
    .with_stale_flow_reset(Arc::clone(&reset) as Arc<dyn StaleFlowReset>);

    orch.tear_down_flows_to_new_destinations(OWNER, &[], &[], &[net], false);
    assert_eq!(reset.queried_networks(), vec![net]);
    assert_eq!(reset.reset_flows(), vec![owners]);

    orch.upsert_state_with_destinations(OWNER, Vec::new(), Vec::new(), vec![net], false);
    orch.tear_down_flows_to_new_destinations(OWNER, &[], &[], &[net], false);
    assert_eq!(
        reset.queried_networks(),
        vec![net],
        "a network already enforced is not swept again"
    );
}

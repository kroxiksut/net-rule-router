use super::*;

#[test]
fn recompute_applies_active_users_secondary_routes() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            ip_rule("r1", 198, 51, 100, 1),
            ip_rule("r2", 198, 51, 100, 2),
        ]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    let delta = coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(delta.added, 2);
    assert_eq!(
        table_dests(&api),
        HashSet::from([
            Ipv4Addr::new(198, 51, 100, 1),
            Ipv4Addr::new(198, 51, 100, 2)
        ])
    );
}

#[test]
fn switching_active_user_replaces_the_route_table() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 198, 51, 100, 1)]),
    );
    rules.set_secondary(
        "S-PETROV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r2", 198, 51, 100, 2)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 1)])
    );

    // Petrov logs in (becomes active) → Ivanov's routes torn down,
    // Petrov's installed. The machine-wide table follows the active user.
    coord
        .recompute_for("S-PETROV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 2)])
    );
}

#[test]
fn no_secondary_target_tears_down_routes() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 198, 51, 100, 1)]),
    );
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(coord.owned_count(), 1);

    // Secondary goes away (unbound / adapter down) → routes removed.
    let delta = coord.recompute_for("S-IVANOV", &res(None)).unwrap();
    assert_eq!(delta.removed, 1);
    assert!(table_dests(&api).is_empty());
}

/// An admin edits the shared baseline while the user has a tray connected.
/// The user has not diverged, so the baseline IS their rule book — and the
/// route half must follow, not wait for the periodic safety recompute.
#[test]
fn a_baseline_edit_re_drives_routes_with_a_tray_connected() {
    use crate::ipc_handlers::providers::RoutePolicyApplyTrigger;

    #[derive(Default)]
    struct CountingInner(std::sync::atomic::AtomicUsize);
    impl RoutePolicyApplyTrigger for CountingInner {
        fn on_policy_changed(&self, _sid: &str) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let api = Arc::new(MockWindowsApi::new());
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 198, 51, 100, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);
    let coord = Arc::new(coordinator_with_policy(
        Arc::clone(&api),
        Arc::clone(&rules),
        policy,
    ));

    // A tray is connected: the registry is NOT empty.
    let registry = Arc::new(crate::active_sid_registry::ActiveSidRegistry::new());
    registry.on_connect(
        "S-IVANOV",
        nrr_shared::ipc::IpcClientProfile::TrayLightweight,
    );
    assert!(!registry.active_sids().is_empty());

    let inner = Arc::new(CountingInner::default());
    let trigger = RouteAndFilterApplyTrigger::new(
        Arc::clone(&inner) as Arc<dyn RoutePolicyApplyTrigger>,
        Arc::clone(&coord),
        registry,
    );
    trigger.on_policy_changed(nrr_domain::user_principal::BASELINE_PRINCIPAL);

    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 1)]),
        "the baseline edit must reach the route table, not stop at the filters"
    );
    assert_eq!(inner.0.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn recompute_active_tears_down_when_effective_sid_paused() {
    // Safe-disable ROUTE-half — when the pause predicate reports the
    // effective routing SID paused, `recompute_active` returns a clear()
    // delta and installs no routes, even though rules + a usable secondary
    // would otherwise produce a /32. The gate sits in the single re-drive
    // choke point (recompute_active), so every trigger honours it.
    use std::sync::atomic::{AtomicBool, Ordering};
    let api = Arc::new(MockWindowsApi::new());
    // A live, usable secondary adapter so resolve() yields a route target.
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 198, 51, 100, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);

    let paused = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&paused);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
        .with_pause_state(Arc::new(move |_sid: &str| {
            if flag.load(Ordering::SeqCst) {
                PausedRouteDisposition::ClearAll
            } else {
                PausedRouteDisposition::Active
            }
        }));

    // Not paused → the /32 secondary route installs.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(coord.owned_count(), 1);
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 1)])
    );

    // Pause the effective routing user (teardown policy) → the next recompute
    // (via ANY re-drive path) tears the route table down instead of
    // reinstalling.
    paused.store(true, Ordering::SeqCst);
    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.removed, 1);
    assert_eq!(coord.owned_count(), 0);
    assert!(table_dests(&api).is_empty());
}

#[test]
fn recompute_active_keeps_slash32_when_paused_persist() {
    // Safe-disable ROUTE-half — when the paused user's stop-policy is
    // Persist, the recompute gate must KEEP the
    // /32 secondary rule-routes (it drops only overlays), NOT full-clear them.
    // Before the fix the 30 s safety tick returned clear() unconditionally,
    // silently deleting the /32s `teardown_routes` deliberately kept and
    // defeating the Persist opt-in within ~30 s of pausing.
    use std::sync::atomic::{AtomicBool, Ordering};
    let api = Arc::new(MockWindowsApi::new());
    let live = adapter("vpn", 7, true, true, Some([10, 0, 0, 1]));
    let bind_id = format!("win-adapter:{}", live.adapter_name);
    api.set_adapter_infos(vec![live]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 198, 51, 100, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bind_id);

    let paused = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&paused);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy)
        .with_pause_state(Arc::new(move |_sid: &str| {
            if flag.load(Ordering::SeqCst) {
                PausedRouteDisposition::KeepSecondaryHosts
            } else {
                PausedRouteDisposition::Active
            }
        }));

    // Not paused → the /32 secondary route installs.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(coord.owned_count(), 1);

    // Pause with Persist policy → the safety-tick recompute KEEPS the /32.
    paused.store(true, Ordering::SeqCst);
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(
        coord.owned_count(),
        1,
        "Persist keeps the /32 rule-route across a paused re-drive"
    );
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 1)]),
        "the matched host still egresses the secondary under Persist pause"
    );
}

/// A pass wedged at the stop does not hold the routes hostage: past the wait
/// our signed rows go straight from the table, a foreign row stays, and the
/// keep-rule-routes stop takes only the overlays.
#[test]
fn a_wedged_pass_does_not_keep_the_stop_from_removing_our_routes() {
    use nrr_platform_api::route_signature::{NETWORK_ROUTE_METRIC, SECONDARY_ROUTE_METRIC};
    let row = |d: [u8; 4], prefix: u8, metric: u32| RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(d)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        interface_index: 7,
        metric,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    let host = row([198, 51, 100, 1], 32, SECONDARY_ROUTE_METRIC);
    let network = row([10, 20, 0, 0], 16, NETWORK_ROUTE_METRIC);
    let overlay = row([0, 0, 0, 0], 2, SECONDARY_ROUTE_METRIC);
    let foreign = row([0, 0, 0, 0], 1, 1);
    let wait = std::time::Duration::from_millis(50);

    let api = Arc::new(MockWindowsApi::new());
    let coord = coordinator(Arc::clone(&api), Arc::new(FakeRules::new()));
    api.set_route_table(vec![
        host.clone(),
        network.clone(),
        overlay.clone(),
        foreign.clone(),
    ]);
    {
        let _wedged = coord.pass_lock.lock().unwrap();
        let delta = coord.teardown_keep_rule_routes_within(wait).unwrap();
        assert_eq!(delta.removed, 1);
    }
    let left: Vec<(IpAddr, u8)> = api
        .get_ip_forward_table()
        .unwrap()
        .iter()
        .map(|r| (r.destination, r.prefix_length))
        .collect();
    assert!(!left.contains(&(overlay.destination, 2)), "{left:?}");
    assert!(left.contains(&(host.destination, 32)), "{left:?}");
    assert!(left.contains(&(network.destination, 16)), "{left:?}");

    api.set_route_table(vec![host, network, overlay, foreign.clone()]);
    let began = std::time::Instant::now();
    {
        let _wedged = coord.pass_lock.lock().unwrap();
        let delta = coord.teardown_within(wait).unwrap();
        assert_eq!(delta.removed, 3);
    }
    assert!(began.elapsed() < std::time::Duration::from_secs(5));
    let left: Vec<(IpAddr, u8)> = api
        .get_ip_forward_table()
        .unwrap()
        .iter()
        .map(|r| (r.destination, r.prefix_length))
        .collect();
    assert_eq!(left, vec![(foreign.destination, 1)]);
}

fn name_rule(id: &str, host: &str) -> CanonicalRule {
    CanonicalRule {
        address_match: Some(CanonicalAddressMatch::ExactFqdn(host.into())),
        ..ip_rule(id, 0, 0, 0, 0)
    }
}

fn coordinator_with_dns_setting(
    api: Arc<MockWindowsApi>,
    rules: Arc<FakeRules>,
    setting_on: bool,
) -> SecondaryRouteCoordinator {
    coordinator(api, rules)
        .with_dns_via_secondary(Arc::new(std::sync::atomic::AtomicBool::new(setting_on)))
}

/// With "DNS through the tunnel" off the service still asks the additional
/// link's rule hosts through the tunnel, which needs exactly one resolver's
/// route there: a wider set would move other programs' lookups into it.
#[test]
fn with_the_dns_setting_off_one_resolver_rides_the_tunnel_while_a_rule_names_a_host() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![
            name_rule("r1", "tunnel.example"),
            ip_rule("r2", 198, 51, 100, 1),
        ]),
    );
    let coord = coordinator_with_dns_setting(Arc::clone(&api), Arc::clone(&rules), false);

    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([
            Ipv4Addr::new(198, 51, 100, 1),
            crate::dns_egress::RULE_HOST_RESOLVER
        ])
    );
    let resolver_route = api
        .get_ip_forward_table()
        .unwrap()
        .into_iter()
        .find(|r| r.destination == IpAddr::V4(crate::dns_egress::RULE_HOST_RESOLVER))
        .expect("the resolver route");
    assert_eq!(
        (resolver_route.prefix_length, resolver_route.interface_index),
        (32, target().interface_index),
        "via the additional link"
    );

    // The last name rule goes: nothing is asked there any more.
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r2", 198, 51, 100, 1)]),
    );
    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        HashSet::from([Ipv4Addr::new(198, 51, 100, 1)])
    );
}

#[test]
fn with_the_dns_setting_on_the_public_resolvers_ride_the_tunnel_instead() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![name_rule("r1", "tunnel.example")]),
    );
    let coord = coordinator_with_dns_setting(Arc::clone(&api), Arc::clone(&rules), true);

    coord
        .recompute_for("S-IVANOV", &res(Some(target())))
        .unwrap();
    assert_eq!(
        table_dests(&api),
        crate::dns_egress::PUBLIC_DNS_SERVERS
            .iter()
            .copied()
            .collect::<HashSet<_>>()
    );
}

/// Settings but no rule revision ("Start empty", a reset with no baseline)
/// route exactly as an emptied book: the additional connection still carries
/// what its default route promises, rather than every route coming down.
#[test]
fn no_rule_revision_routes_as_an_emptied_book() {
    let table_for = |rules: Arc<FakeRules>| {
        let api = Arc::new(MockWindowsApi::new());
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary("S-IVANOV", "vpn");
        policy.set_mode(
            "S-IVANOV",
            crate::per_sid_orchestrator::PerSidBehaviorMode::PreferSecondaryWhenAvailable,
        );
        let coord = coordinator_with_policy(Arc::clone(&api), rules, policy);
        let resolution = RouteResolution {
            mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            primary: None,
            secondary: Some(target()),
        };
        coord.recompute_for("S-IVANOV", &resolution).unwrap();
        table_dests(&api)
    };
    let emptied = Arc::new(FakeRules::new());
    emptied.set_secondary("S-IVANOV", CanonicalRuleSet::from_rules(vec![]));
    let emptied = table_for(emptied);
    assert!(
        !emptied.is_empty(),
        "fixture: an emptied book routes the overlay"
    );
    assert_eq!(table_for(Arc::new(FakeRules::new())), emptied);
}

/// A book that cannot be read is not "no rules": the routes a crashed run
/// left and this one adopted stay until it reads, as the filters do.
#[test]
fn an_unreadable_book_keeps_the_routes_adopted_after_a_crash() {
    struct Unreadable;
    impl RulesProvider for Unreadable {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            None
        }
        fn rules_read_for(&self, _principal: &str) -> crate::per_sid_orchestrator::RulesRead {
            crate::per_sid_orchestrator::RulesRead::Unreadable("database is locked".into())
        }
    }
    let api = Arc::new(MockWindowsApi::new());
    let ours = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        prefix_length: 32,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        interface_index: 9,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    api.set_route_table(vec![ours]);
    let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
    let sec_id = sec.stable_id();
    api.set_adapter_infos(vec![sec]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &sec_id);
    let coord = SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::new(Unreadable) as Arc<dyn RulesProvider>,
        policy as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        Arc::new(|| false) as RuleScopeProvider,
    );
    coord.adopt_orphans_from_table();
    assert_eq!(coord.owned_count(), 1, "fixture: the orphan is adopted");

    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert!(
        table_dests(&api).contains(&Ipv4Addr::new(198, 51, 100, 1)),
        "an unreadable book took down the routes it could not judge"
    );
}

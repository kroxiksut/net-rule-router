use super::*;
use nrr_platform_api::types::{WfpFilterRecord, SERVICE_ACCOUNTS_PRINCIPAL};

const OWN_EXE: &str = r"C:\Program Files\NetRuleRouter\nrr-service.exe";
const RULE_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 8);

/// The route-table owners, switchable mid-test.
type Owner = Arc<Mutex<Vec<String>>>;

#[allow(clippy::type_complexity)]
fn fixture_with_service_accounts(
    resolution: Option<KillSwitchResolution>,
    owner: &Owner,
    primary_dns: Vec<IpAddr>,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
) {
    fixture_with_routed_elsewhere(resolution, owner, primary_dns, Arc::new(|_, _| false))
}

#[allow(clippy::type_complexity)]
fn fixture_with_routed_elsewhere(
    resolution: Option<KillSwitchResolution>,
    owner: &Owner,
    primary_dns: Vec<IpAddr>,
    routed_elsewhere: crate::per_sid_orchestrator::RoutedElsewhereFn,
) -> (
    Arc<MockWindowsApi>,
    Arc<PerSidApplyOrchestrator>,
    Arc<ScriptedSource>,
    Arc<ScriptedRules>,
) {
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>).unwrap());
    let source = Arc::new(ScriptedSource::default());
    let rules = Arc::new(ScriptedRules::default());
    let cache: Arc<dyn FqdnCacheLookup> = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(CollectAudit::default());
    let owner = Arc::clone(owner);
    let orch = Arc::new(
        PerSidApplyOrchestrator::new(
            session,
            Arc::clone(&source) as Arc<dyn RoutePolicySource>,
            Arc::clone(&rules) as Arc<dyn RulesProvider>,
            cache,
            Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
        )
        .with_kill_switch_resolver(Arc::new(move |_, _| resolution.clone()))
        .with_service_accounts(ServiceAccountWiring {
            routing_owners: Arc::new(move || owner.lock().unwrap().clone()),
            routed_elsewhere,
            own_executable: Some(OWN_EXE.to_string()),
            primary_dns: Arc::new(move || primary_dns.clone()),
        }),
    );
    (api, orch, source, rules)
}

fn owner_is(sid: Option<&str>) -> Owner {
    Arc::new(Mutex::new(sid.map(str::to_string).into_iter().collect()))
}

fn service_filters(api: &MockWindowsApi) -> Vec<WfpFilterRecord> {
    api.wfp_filters
        .lock()
        .unwrap()
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some(SERVICE_ACCOUNTS_PRINCIPAL))
        .cloned()
        .collect()
}

fn covers(f: &WfpFilterRecord, ip: Ipv4Addr) -> bool {
    f.remote_ip == Some(ip) || f.remote_ip_set.contains(&ip)
}

/// No service-account filter is a blanket block: each names a destination,
/// or is a permit for one program.
fn assert_addresses_only(filters: &[WfpFilterRecord]) {
    for f in filters {
        let names_destination = f.remote_ip.is_some()
            || !f.remote_ip_set.is_empty()
            || !f.remote_ip_set_v6.is_empty()
            || f.remote_subnet.is_some()
            || f.remote_subnet_v6.is_some();
        assert!(
            names_destination || (f.action == WfpAction::Permit && f.app_pattern.is_some()),
            "a blanket service-account filter: {f:?}"
        );
        assert!(f.layer.supports_ale_scoping(), "{f:?}");
    }
}

#[test]
fn the_route_table_owner_shares_its_pins_with_the_service_accounts() {
    let owner = owner_is(Some("S-1-5-21-A"));
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let service = service_filters(&api);
    assert!(
        service.iter().any(|f| f.action == WfpAction::Permit
            && f.local_interface_luid == Some(KS_LUID)
            && covers(f, RULE_HOST)),
        "the pin's permit through the tunnel: {service:?}"
    );
    assert!(
        service
            .iter()
            .any(|f| f.action == WfpAction::Block && covers(f, RULE_HOST)),
        "the pin's block off the tunnel: {service:?}"
    );
    assert!(
        service
            .iter()
            .any(|f| f.action == WfpAction::Permit && f.app_pattern.as_deref() == Some(OWN_EXE)),
        "our own executable leaves by whichever link it picks: {service:?}"
    );
    assert_addresses_only(&service);
}

#[test]
fn a_user_who_does_not_own_the_table_gives_the_service_accounts_nothing() {
    let owner = owner_is(Some("S-1-5-21-B"));
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(service_filters(&api).is_empty());
    let no_owner = owner_is(None);
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &no_owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(service_filters(&api).is_empty(), "no user, no service set");
}

#[test]
fn an_owner_change_moves_the_set_and_never_doubles_it() {
    let owner = owner_is(Some("S-1-5-21-A"));
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    src.set("S-1-5-21-B", snap_block("Wi-Fi", "TAP"));
    let both = ["S-1-5-21-A".to_string(), "S-1-5-21-B".to_string()];

    orch.reconcile(&both).unwrap();
    let one_set = service_filters(&api).len();
    assert!(one_set > 0);

    *owner.lock().unwrap() = vec!["S-1-5-21-B".into()];
    orch.reconcile(&both).unwrap();
    let moved = service_filters(&api);
    assert_eq!(moved.len(), one_set, "one set, not two and not none");

    // The new owner leaves: the set leaves with it.
    *owner.lock().unwrap() = vec!["S-1-5-21-A".into()];
    orch.reconcile(&["S-1-5-21-A".to_string()]).unwrap();
    assert_eq!(service_filters(&api).len(), one_set);

    owner.lock().unwrap().clear();
    orch.reconcile(&["S-1-5-21-A".to_string()]).unwrap();
    assert!(service_filters(&api).is_empty(), "nobody owns the table");
}

/// Two signed-in users both own the table: each one's share is in force, and
/// one leaving takes only theirs.
#[test]
fn every_served_user_shares_their_pins_and_a_departure_takes_only_theirs() {
    let owner: Owner = Arc::new(Mutex::new(vec![
        "S-1-5-21-1-2-3-1001".to_string(),
        "S-1-5-21-1-2-3-1002".to_string(),
    ]));
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-1-2-3-1001", snap_block("Wi-Fi", "TAP"));
    orch.reconcile(&["S-1-5-21-1-2-3-1001".to_string()])
        .unwrap();
    let one_set = service_filters(&api).len();
    assert!(one_set > 0);

    src.set("S-1-5-21-1-2-3-1002", snap_block("Wi-Fi", "TAP"));
    let both = [
        "S-1-5-21-1-2-3-1001".to_string(),
        "S-1-5-21-1-2-3-1002".to_string(),
    ];
    orch.reconcile(&both).unwrap();
    assert_eq!(service_filters(&api).len(), 2 * one_set, "one set per user");

    *owner.lock().unwrap() = vec!["S-1-5-21-1-2-3-1001".to_string()];
    orch.reconcile(&["S-1-5-21-1-2-3-1001".to_string()])
        .unwrap();
    assert_eq!(service_filters(&api).len(), one_set);
}

/// A destination the table sends through another user's link is not pinned
/// to this user's tunnel for system services: their traffic follows the route.
#[test]
fn a_destination_routed_for_another_user_stays_out_of_the_share() {
    const OTHER_HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);
    let owner: Owner = Arc::new(Mutex::new(vec![
        "S-1-5-21-1-2-3-1001".to_string(),
        "S-1-5-21-1-2-3-1002".to_string(),
    ]));
    let (api, orch, src, rules) = fixture_with_routed_elsewhere(
        Some(full_ks_resolution()),
        &owner,
        Vec::new(),
        Arc::new(|sid: &str, block: nrr_shared::ip_block::IpBlock| {
            sid == "S-1-5-21-1-2-3-1002" && block.contains(IpAddr::V4(RULE_HOST))
        }),
    );
    rules.set(rules_with_secondary_ips(&[RULE_HOST, OTHER_HOST]));
    src.set("S-1-5-21-1-2-3-1002", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-1-2-3-1002").unwrap();
    let service = service_filters(&api);
    assert!(service.iter().any(|f| covers(f, OTHER_HOST)), "{service:?}");
    assert!(service.iter().all(|f| !covers(f, RULE_HOST)), "{service:?}");
    // The user's own pin is untouched: their traffic to it is still blocked
    // off their tunnel.
    assert!(api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .any(|f| f.user_sid.as_deref() == Some("S-1-5-21-1-2-3-1002")
            && f.action == WfpAction::Block
            && covers(f, RULE_HOST)));
}

#[test]
fn a_down_tunnel_blocks_the_service_accounts_only_when_the_owner_fails_closed() {
    let owner = owner_is(Some("S-1-5-21-A"));
    let (api, orch, src, rules) = fixture_with_service_accounts(None, &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let service = service_filters(&api);
    assert!(
        service.iter().any(|f| f.action == WfpAction::Block
            && f.local_interface_luid.is_none()
            && covers(f, RULE_HOST)),
        "fail-closed: the address is blocked outright: {service:?}"
    );
    assert!(service.iter().all(|f| f.local_interface_luid.is_none()));
    assert_addresses_only(&service);

    let (api, orch, src, rules) = fixture_with_service_accounts(None, &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    let mut fail_open = snap_block("Wi-Fi", "TAP");
    fail_open.kill_switch_fail_closed = false;
    src.set("S-1-5-21-A", fail_open);
    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(service_filters(&api).is_empty(), "fail-open guards nobody");
}

#[test]
fn the_tunnel_default_modes_never_give_the_service_accounts_a_blanket_block() {
    let owner = owner_is(Some("S-1-5-21-A"));
    for resolution in [Some(full_ks_resolution()), None] {
        let (api, orch, src, rules) = fixture_with_service_accounts(resolution, &owner, Vec::new());
        rules.set(rules_with_secondary_ip(RULE_HOST));
        src.set("S-1-5-21-A", snap_block_mode_b("Wi-Fi", "TAP"));

        orch.install_for_sid("S-1-5-21-A").unwrap();
        let service = service_filters(&api);
        assert!(
            service
                .iter()
                .any(|f| f.action == WfpAction::Block && covers(f, RULE_HOST)),
            "{service:?}"
        );
        assert_addresses_only(&service);
    }
}

#[test]
fn a_main_link_dns_server_a_rule_names_stays_open_for_the_service_accounts() {
    let owner = owner_is(Some("S-1-5-21-A"));
    let (api, orch, src, rules) = fixture_with_service_accounts(
        Some(full_ks_resolution()),
        &owner,
        vec![IpAddr::V4(RULE_HOST)],
    );
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    assert!(
        service_filters(&api).iter().all(|f| !covers(f, RULE_HOST)),
        "the main link's resolver is not pinned for system services"
    );
    // The owner's own pin is untouched.
    assert!(api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .any(|f| f.user_sid.as_deref() == Some("S-1-5-21-A")
            && f.action == WfpAction::Block
            && covers(f, RULE_HOST)));
}

#[test]
fn a_tunnel_server_is_never_pinned_for_the_service_accounts() {
    let owner = owner_is(Some("S-1-5-21-A"));
    let server = Ipv4Addr::new(203, 0, 113, 7);
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ips(&[RULE_HOST, server]));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));

    orch.install_for_sid("S-1-5-21-A").unwrap();
    let service = service_filters(&api);
    assert!(service.iter().any(|f| covers(f, RULE_HOST)));
    assert!(service.iter().all(|f| !covers(f, server)), "{service:?}");
}

/// One TCP connect as the ALE layer sees it: the token's SIDs (user and
/// groups), the program, the destination and the interface the route picked.
struct Connect<'a> {
    token: &'a [&'a str],
    app: Option<&'a str>,
    remote: Ipv4Addr,
    luid: u64,
}

/// WFP's arbitration over the installed set, for one connect: of the ALE
/// filters whose every condition matches, the heaviest decides; none leaves
/// the connect to the default (permitted).
fn verdict_for(filters: &[WfpFilterRecord], connect: &Connect<'_>) -> WfpAction {
    use nrr_platform_api::types::SERVICE_ACCOUNT_SIDS;
    let user_matches = |f: &WfpFilterRecord| match f.user_sid.as_deref() {
        None => true,
        Some(SERVICE_ACCOUNTS_PRINCIPAL) => SERVICE_ACCOUNT_SIDS
            .iter()
            .any(|sid| connect.token.contains(sid)),
        Some(sid) => connect.token.contains(&sid),
    };
    let destination_matches = |f: &WfpFilterRecord| {
        let named =
            f.remote_ip.is_some() || !f.remote_ip_set.is_empty() || f.remote_subnet.is_some();
        !named
            || covers(f, connect.remote)
            || f.remote_subnet.is_some_and(|(net, len)| {
                let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
                u32::from(net) & mask == u32::from(connect.remote) & mask
            })
    };
    filters
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .filter(|f| user_matches(f))
        .filter(|f| f.app_pattern.is_none() || f.app_pattern.as_deref() == connect.app)
        .filter(|f| {
            f.local_interface_luid
                .is_none_or(|luid| luid == connect.luid)
        })
        .filter(|f| f.ip_protocol.is_none() || f.ip_protocol == Some(6))
        .filter(|f| f.remote_port.is_none() || f.remote_port == Some(443))
        .filter(|f| destination_matches(f))
        .max_by_key(|f| f.weight)
        .map_or(WfpAction::Permit, |f| f.action)
}

/// The behaviour the whole feature exists for, read off the installed set:
/// a system service cannot reach a secondary-rule host over the main link,
/// can through the tunnel, our own service is never caught, and a user who
/// does not own the table sees no change.
#[test]
fn system_traffic_to_a_pinned_host_leaves_only_through_the_tunnel() {
    const MAIN_LUID: u64 = 0x0001_0000_0000_0042;
    let owner = owner_is(Some("S-1-5-21-A"));
    let (api, orch, src, rules) =
        fixture_with_service_accounts(Some(full_ks_resolution()), &owner, Vec::new());
    rules.set(rules_with_secondary_ip(RULE_HOST));
    src.set("S-1-5-21-A", snap_block("Wi-Fi", "TAP"));
    orch.install_for_sid("S-1-5-21-A").unwrap();
    let filters = api.wfp_filters.lock().unwrap().clone();

    let system: &[&str] = &["S-1-5-18", "S-1-5-6"];
    let connect = |token, app, luid| Connect {
        token,
        app,
        remote: RULE_HOST,
        luid,
    };
    assert_eq!(
        verdict_for(&filters, &connect(system, None, MAIN_LUID)),
        WfpAction::Block,
        "a service bound to the main link"
    );
    assert_eq!(
        verdict_for(&filters, &connect(system, None, KS_LUID)),
        WfpAction::Permit,
        "a service through the tunnel"
    );
    assert_eq!(
        verdict_for(&filters, &connect(system, Some(OWN_EXE), MAIN_LUID)),
        WfpAction::Permit,
        "our own relay and probes"
    );
    assert_eq!(
        verdict_for(&filters, &connect(&["S-1-5-21-B"], None, MAIN_LUID)),
        WfpAction::Permit,
        "a user who does not own the table is untouched"
    );
    assert_eq!(
        verdict_for(&filters, &connect(&["S-1-5-21-A"], None, MAIN_LUID)),
        WfpAction::Block,
        "the owner's own pin still holds"
    );
}

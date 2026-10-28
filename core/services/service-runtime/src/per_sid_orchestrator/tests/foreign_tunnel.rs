use super::*;
use crate::killswitch_codegen::ForeignTunnelNetwork;
use nrr_platform_api::types::WfpFilterRecord;
use nrr_shared::ip_block::IpBlock;
use std::net::Ipv6Addr;

// A corporate tunnel beside ours keeps the networks it carries under every
// posture that blocks, and nothing beyond them; the user's own Blocks still
// bind it.

const FOREIGN: u64 = 0x00AB_CDEF_0000_0007;
const SID: &str = "S-1-5-21-A";
const APP: &str = r"C:\Apps\tg.exe";
const DENIED_APP: &str = r"C:\Apps\deny.exe";

/// Inside the corporate tunnel's own `10.77.0.0/16`, and routed by a rule.
const CORP_HOST: Ipv4Addr = Ipv4Addr::new(10, 77, 1, 5);
/// Inside the same network and named by no rule of the user's.
const CORP_OTHER: Ipv4Addr = Ipv4Addr::new(10, 77, 2, 2);
const CORP_OTHER_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 6);
/// Inside `10.77.0.0/16`, blocked by the user.
const CORP_BLOCKED: Ipv4Addr = Ipv4Addr::new(10, 77, 9, 9);
/// Outside every corporate network, routed by a rule.
const PUBLIC_HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const CORP_HOST_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 5);
const CORP_BLOCKED_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x77, 0, 0, 0, 0, 0, 9);

fn corp_networks() -> Vec<ForeignTunnelNetwork> {
    ["10.77.0.0/16", "fd00:77::/48"]
        .into_iter()
        .map(|text| ForeignTunnelNetwork {
            luid: FOREIGN,
            network: IpBlock::parse(text).expect("network"),
        })
        .collect()
}

fn resolution_with_foreign() -> KillSwitchResolution {
    KillSwitchResolution {
        foreign_tunnel_luids: vec![FOREIGN],
        foreign_tunnel_networks: corp_networks(),
        ..full_ks_resolution()
    }
}

/// A tunnel whose routes are only a default or a redirect pair: foreign, but
/// carrying no network of its own.
fn resolution_with_full_tunnel() -> KillSwitchResolution {
    KillSwitchResolution {
        foreign_tunnel_luids: vec![FOREIGN],
        foreign_tunnel_networks: Vec::new(),
        ..full_ks_resolution()
    }
}

fn unresolved_exemptions() -> FailClosedExemptions {
    FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 7)],
        foreign_tunnel_luids: vec![FOREIGN],
        foreign_tunnel_networks: corp_networks(),
        ..FailClosedExemptions::default()
    }
}

fn orchestrator(
    resolution: Option<KillSwitchResolution>,
    fail_closed: Option<FailClosedExemptions>,
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
    let apps = nrr_platform_api::MockAppPathResolver::new()
        .with("tg.exe", vec![std::path::PathBuf::from(APP)])
        .with("deny.exe", vec![std::path::PathBuf::from(DENIED_APP)]);
    let mut orch = PerSidApplyOrchestrator::new(
        session,
        Arc::clone(&source) as Arc<dyn RoutePolicySource>,
        Arc::clone(&rules) as Arc<dyn RulesProvider>,
        cache,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    )
    .with_app_resolver(Arc::new(apps))
    .with_kill_switch_resolver(Arc::new(move |_, _| resolution.clone()))
    .with_ipv6_guard_resolver(Arc::new(|_, _| {
        crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes
    }));
    if let Some(exemptions) = fail_closed {
        orch = orch.with_fail_closed_exemptions_resolver(Arc::new(move |_, _| exemptions.clone()));
    }
    (api, Arc::new(orch), source, rules)
}

fn rule(id: &str, address: Option<IpAddr>, app: Option<&str>, block: bool) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: address.map(CanonicalAddressMatch::ExactIp),
        app_match: app.map(|name| nrr_domain::canonical::CanonicalAppMatch {
            pattern: nrr_domain::canonical::CanonicalAppPattern::Exact(name.into()),
            include_child_processes: false,
            override_requested: false,
        }),
        comment: String::new(),
        action: if block {
            nrr_domain::RuleAction::Block
        } else {
            nrr_domain::RuleAction::Route
        },
        origin: None,
    }
}

/// Secondary rules for a corporate host and a public one in both families,
/// plus the user's own Blocks: a corporate address, its v6 twin and a program.
fn book() -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule("deny-ip", Some(IpAddr::V4(CORP_BLOCKED)), None, true),
                rule("deny-ip6", Some(IpAddr::V6(CORP_BLOCKED_V6)), None, true),
                rule("deny-app", None, Some("deny.exe"), true),
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![
                rule("corp", Some(IpAddr::V4(CORP_HOST)), None, false),
                rule("corp6", Some(IpAddr::V6(CORP_HOST_V6)), None, false),
                rule("public", Some(IpAddr::V4(PUBLIC_HOST)), None, false),
            ]),
        },
    }
}

fn app_book() -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![rule("app", None, Some("tg.exe"), false)]),
        },
    }
}

/// One connection or packet as the engine sees it.
#[derive(Clone, Copy)]
struct Flow<'a> {
    layer: WfpLayerKey,
    dst: IpAddr,
    egress: u64,
    app: Option<&'a str>,
}

fn proto_of(layer: WfpLayerKey) -> u8 {
    match layer {
        WfpLayerKey::OutboundTransportV4 | WfpLayerKey::OutboundIpPacketV4 => 1,
        WfpLayerKey::OutboundIpPacketV6 | WfpLayerKey::OutboundTransportV6 => 58,
        _ => 6,
    }
}

fn matches(f: &WfpFilterRecord, flow: Flow<'_>) -> bool {
    let in_subnet = |net: IpAddr, prefix: u8| {
        IpBlock::new(net, prefix).is_some_and(|block| block.contains(flow.dst))
    };
    // OR'd subnet conditions: any member matching is enough.
    let in_set = |f: &WfpFilterRecord| {
        f.remote_subnet_set.is_empty()
            || f.remote_subnet_set
                .iter()
                .any(|(net, prefix)| in_subnet(*net, *prefix))
    };
    let dst = match flow.dst {
        IpAddr::V4(ip) => {
            f.remote_ip.is_none_or(|r| r == ip)
                && (f.remote_ip_set.is_empty() || f.remote_ip_set.contains(&ip))
                && f.remote_subnet
                    .is_none_or(|(net, p)| in_subnet(IpAddr::V4(net), p))
                && f.remote_ip_set_v6.is_empty()
                && f.remote_subnet_v6.is_none()
                && in_set(f)
        }
        IpAddr::V6(ip) => {
            f.remote_ip.is_none()
                && f.remote_ip_set.is_empty()
                && f.remote_subnet.is_none()
                && (f.remote_ip_set_v6.is_empty() || f.remote_ip_set_v6.contains(&ip))
                && f.remote_subnet_v6
                    .is_none_or(|(net, p)| in_subnet(IpAddr::V6(net), p))
                && in_set(f)
        }
    };
    dst && f.layer == flow.layer
        && f.local_interface_luid.is_none_or(|l| l == flow.egress)
        && f.app_pattern.as_deref().is_none_or(|a| Some(a) == flow.app)
        && f.ip_protocol.is_none_or(|p| p == proto_of(flow.layer))
        && f.remote_port.is_none_or(|p| p == 443)
}

/// The heaviest matching filter decides; nothing matching lets it through.
fn verdict(filters: &[WfpFilterRecord], flow: Flow<'_>) -> WfpAction {
    filters
        .iter()
        .filter(|f| matches(f, flow))
        .max_by_key(|f| (f.weight, f.action == WfpAction::Block))
        .map_or(WfpAction::Permit, |f| f.action)
}

fn via_foreign(layer: WfpLayerKey, dst: IpAddr) -> Flow<'static> {
    Flow {
        layer,
        dst,
        egress: FOREIGN,
        app: None,
    }
}

/// Is a guard or the mode blocking anything at `layer`? The user's Blocks sit
/// at `BASE_BLOCK` and above.
fn posture_blocks(filters: &[WfpFilterRecord], layer: WfpLayerKey) -> bool {
    let ceiling = match layer {
        WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
            crate::wfp_bands::CATCHALL_EXEMPT_BASE
        }
        WfpLayerKey::OutboundTransportV4 => crate::wfp_bands::PACKET_EXEMPT_BASE,
        WfpLayerKey::OutboundTransportV6 => crate::wfp_bands::PACKET_V6_EXEMPT_BASE,
        _ => crate::wfp_bands::BASE_BLOCK,
    };
    filters
        .iter()
        .any(|f| f.layer == layer && f.action == WfpAction::Block && f.weight < ceiling)
}

const LAYERS: [WfpLayerKey; 4] = [
    WfpLayerKey::AleAuthConnectV4,
    WfpLayerKey::OutboundTransportV4,
    WfpLayerKey::AleAuthConnectV6,
    WfpLayerKey::OutboundTransportV6,
];

fn corp_host_of(layer: WfpLayerKey) -> IpAddr {
    match layer {
        WfpLayerKey::AleAuthConnectV6
        | WfpLayerKey::OutboundIpPacketV6
        | WfpLayerKey::OutboundTransportV6 => IpAddr::V6(CORP_OTHER_V6),
        _ => IpAddr::V4(CORP_OTHER),
    }
}

/// On every layer a posture blocks, a corporate host no rule names still leaves
/// through the corporate tunnel; and the user's Blocks still hold there.
fn assert_corp_spared_and_user_blocks_hold(api: &MockWindowsApi, posture: &str) {
    let filters = api.wfp_filters.lock().unwrap().clone();
    let mut checked = 0;
    for layer in LAYERS {
        if !posture_blocks(&filters, layer) {
            continue;
        }
        assert_eq!(
            verdict(&filters, via_foreign(layer, corp_host_of(layer))),
            WfpAction::Permit,
            "{posture}: the corporate host must leave through its tunnel at {layer:?}",
        );
        checked += 1;
    }
    assert!(checked > 0, "{posture}: nothing blocks");
    // At the connect layer, the one that carries the user: a Block is that
    // user's own, never a packet-layer cut for every account.
    for (layer, dst) in [
        (WfpLayerKey::AleAuthConnectV4, IpAddr::V4(CORP_BLOCKED)),
        (WfpLayerKey::AleAuthConnectV6, IpAddr::V6(CORP_BLOCKED_V6)),
    ] {
        assert_eq!(
            verdict(&filters, via_foreign(layer, dst)),
            WfpAction::Block,
            "{posture}: the user's literal Block must beat the foreign permit at {layer:?}",
        );
    }
    let denied_app = app_pattern_of(&filters, "deny.exe")
        .unwrap_or_else(|| panic!("{posture}: the program deny must install"));
    let denied = Flow {
        app: Some(&denied_app),
        ..via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(CORP_OTHER))
    };
    assert_eq!(
        verdict(&filters, denied),
        WfpAction::Block,
        "{posture}: a denied program stays denied through the corporate tunnel",
    );
}

/// The app id a rule for `exe` was installed with, as the engine holds it.
fn app_pattern_of(filters: &[WfpFilterRecord], exe: &str) -> Option<String> {
    filters
        .iter()
        .filter_map(|f| f.app_pattern.clone())
        .find(|p| p.to_ascii_lowercase().ends_with(exe))
}

fn installed(
    resolution: Option<KillSwitchResolution>,
    fail_closed: Option<FailClosedExemptions>,
    snapshot: PerSidPolicySnapshot,
    rules_book: ActiveRulesSnapshot,
) -> Arc<MockWindowsApi> {
    let (api, orch, src, rules) = orchestrator(resolution, fail_closed);
    rules.set(rules_book);
    src.set(SID, snapshot);
    orch.install_for_sid(SID).unwrap();
    api
}

#[test]
fn per_destination_pins_spare_only_the_corporate_networks() {
    let api = installed(
        Some(resolution_with_foreign()),
        None,
        snap_block("Wi-Fi", "TAP"),
        book(),
    );
    assert_corp_spared_and_user_blocks_hold(&api, "per-destination pins");
    let filters = api.wfp_filters.lock().unwrap().clone();
    assert_eq!(
        verdict(
            &filters,
            via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(CORP_HOST))
        ),
        WfpAction::Block,
        "an address a rule routes into our tunnel does not leave through the corporate one",
    );
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
    ] {
        assert_eq!(
            verdict(&filters, via_foreign(layer, IpAddr::V4(PUBLIC_HOST))),
            WfpAction::Block,
            "a protected public host must not leave through the corporate tunnel at {layer:?}",
        );
    }
    assert!(
        filters
            .iter()
            .all(|f| f.local_interface_luid != Some(FOREIGN)
                || f.action != WfpAction::Permit
                || f.remote_subnet.is_some()
                || f.remote_subnet_v6.is_some()
                || !f.remote_subnet_set.is_empty()),
        "no permit for everything the corporate tunnel sends",
    );
}

#[test]
fn a_tunnel_that_carries_only_a_default_route_gets_no_permit() {
    let api = installed(
        Some(resolution_with_full_tunnel()),
        None,
        snap_block("Wi-Fi", "TAP"),
        book(),
    );
    let filters = api.wfp_filters.lock().unwrap().clone();
    assert!(filters
        .iter()
        .all(|f| f.local_interface_luid != Some(FOREIGN)));
    assert_eq!(
        verdict(
            &filters,
            via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(PUBLIC_HOST))
        ),
        WfpAction::Block,
    );
}

#[test]
fn per_destination_pins_without_a_foreign_tunnel_add_nothing() {
    let api = installed(
        Some(full_ks_resolution()),
        None,
        snap_block("Wi-Fi", "TAP"),
        book(),
    );
    assert!(api
        .wfp_filters
        .lock()
        .unwrap()
        .iter()
        .all(|f| f.local_interface_luid != Some(FOREIGN)));
}

#[test]
fn an_app_kill_switch_spares_the_corporate_networks_only() {
    let api = installed(
        Some(resolution_with_foreign()),
        None,
        snap_block("Wi-Fi", "TAP"),
        app_book(),
    );
    let filters = api.wfp_filters.lock().unwrap().clone();
    let pattern =
        app_pattern_of(&filters, "tg.exe").expect("the app rule must arm its kill switch");
    assert!(filters.iter().any(
        |f| f.action == WfpAction::Block && f.app_pattern.as_deref() == Some(pattern.as_str())
    ));
    let app = |dst| Flow {
        app: Some(pattern.as_str()),
        ..via_foreign(WfpLayerKey::AleAuthConnectV4, dst)
    };
    assert_eq!(
        verdict(&filters, app(IpAddr::V4(CORP_HOST))),
        WfpAction::Permit,
        "the app reaches the corporate network through its tunnel",
    );
    assert_eq!(
        verdict(&filters, app(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)))),
        WfpAction::Block,
        "anything else the app sends through that tunnel stays cut",
    );
}

#[test]
fn the_prefer_secondary_catch_all_spares_a_foreign_tunnel() {
    let api = installed(
        Some(resolution_with_foreign()),
        None,
        snap_block_mode_b("Wi-Fi", "TAP"),
        book(),
    );
    assert_corp_spared_and_user_blocks_hold(&api, "prefer-secondary catch-all");
}

/// A corporate tunnel that also holds a default route never becomes the way
/// out for what protection holds: with ours down (or, under the catch-all,
/// up), a routed host and an unrouted one stay cut through it, while the
/// networks it carries by its own routes keep working. Asked of every cell of
/// the table that blocks anything.
#[test]
fn a_corporate_tunnel_with_a_default_route_carries_no_protected_traffic() {
    use nrr_domain::LeakProtection::{Everything, Sites};
    use PerSidBehaviorMode::{PreferPrimary as Main, PreferSecondaryWhenAvailable as Additional};
    const UNROUTED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    for (mode, protection, tunnel_up, blanket) in [
        (Main, Sites, false, false),
        (Main, Everything, false, true),
        (Additional, Everything, false, true),
        (Additional, Everything, true, true),
    ] {
        let cell = format!("{mode:?}/{protection}/tunnel up = {tunnel_up}");
        let api = installed(
            tunnel_up.then(resolution_with_foreign),
            Some(unresolved_exemptions()),
            snap_with("Wi-Fi", "TAP", mode, protection),
            book(),
        );
        assert_corp_spared_and_user_blocks_hold(&api, &cell);
        let filters = api.wfp_filters.lock().unwrap().clone();
        assert!(
            filters
                .iter()
                .all(|f| f.local_interface_luid != Some(FOREIGN)
                    || f.action != WfpAction::Permit
                    || f.remote_subnet.is_some()
                    || f.remote_subnet_v6.is_some()
                    || !f.remote_subnet_set.is_empty()),
            "{cell}: no permit for everything the corporate tunnel sends",
        );
        for layer in [
            WfpLayerKey::AleAuthConnectV4,
            WfpLayerKey::OutboundTransportV4,
        ] {
            assert_eq!(
                verdict(&filters, via_foreign(layer, IpAddr::V4(PUBLIC_HOST))),
                WfpAction::Block,
                "{cell}: a routed host must not leave through the corporate tunnel at {layer:?}",
            );
        }
        if blanket {
            assert_eq!(
                verdict(
                    &filters,
                    via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(UNROUTED))
                ),
                WfpAction::Block,
                "{cell}: under a blanket, an unrouted host does not escape through it either",
            );
        }
    }
}

#[test]
fn the_unresolved_tunnel_block_all_spares_a_foreign_tunnel() {
    let api = installed(
        None,
        Some(unresolved_exemptions()),
        snap_block_mode_b("Wi-Fi", "TAP"),
        book(),
    );
    assert_corp_spared_and_user_blocks_hold(&api, "unresolved tunnel, block-all");
}

#[test]
fn the_unresolved_tunnel_per_destination_block_spares_only_the_corporate_networks() {
    let api = installed(
        None,
        Some(unresolved_exemptions()),
        snap_block("Wi-Fi", "TAP"),
        book(),
    );
    assert_corp_spared_and_user_blocks_hold(&api, "unresolved tunnel, per destination");
    let filters = api.wfp_filters.lock().unwrap().clone();
    assert_eq!(
        verdict(
            &filters,
            via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(CORP_HOST))
        ),
        WfpAction::Block,
        "a pinned address stays cut through the corporate tunnel",
    );
    assert_eq!(
        verdict(
            &filters,
            via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(PUBLIC_HOST))
        ),
        WfpAction::Block,
        "with our tunnel down, a protected public host must not leave through the corporate one",
    );
}

fn full_tunnel_exemptions() -> FailClosedExemptions {
    FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 7)],
        foreign_tunnel_luids: vec![FOREIGN],
        foreign_tunnel_networks: Vec::new(),
        ..FailClosedExemptions::default()
    }
}

/// An application rule beside the address rules makes the guard emit the
/// destination-less floor; that floor must not carry an any-destination permit
/// for a corporate full tunnel, or every protected address leaves through it.
#[test]
fn an_unresolved_tunnel_with_an_app_rule_does_not_open_a_full_foreign_tunnel() {
    let mixed = ActiveRulesSnapshot {
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![
                rule("corp", Some(IpAddr::V4(CORP_HOST)), None, false),
                rule("public", Some(IpAddr::V4(PUBLIC_HOST)), None, false),
                rule("app", None, Some("tg.exe"), false),
            ]),
        },
    };
    let api = installed(
        None,
        Some(full_tunnel_exemptions()),
        snap_block("Wi-Fi", "TAP"),
        mixed,
    );
    let filters = api.wfp_filters.lock().unwrap().clone();
    assert!(
        filters
            .iter()
            .all(|f| f.local_interface_luid != Some(FOREIGN)),
        "no permit at all for a tunnel that carries no network of its own",
    );
    for dst in [PUBLIC_HOST, CORP_HOST] {
        assert_eq!(
            verdict(
                &filters,
                via_foreign(WfpLayerKey::AleAuthConnectV4, IpAddr::V4(dst))
            ),
            WfpAction::Block,
            "{dst} must not leave through the foreign full tunnel",
        );
    }
}

/// A DoH/DoT server inside a corporate network.
const CORP_RESOLVER: Ipv4Addr = Ipv4Addr::new(10, 77, 7, 7);

/// The lockdown is the user's own protection: a resolver the corporate tunnel
/// routes is cut through that tunnel too, while the rest of the corporate
/// network stays reachable and the lockdown keeps its place on every other link.
#[test]
fn the_dns_lockdown_still_binds_a_resolver_the_corporate_tunnel_routes() {
    use nrr_storage::doh_lockdown::DohLockdownScope;
    let mut snap = snap_block("Wi-Fi", "TAP");
    snap.doh_lockdown_enabled = true;
    snap.doh_lockdown_scope = DohLockdownScope::Always;
    snap.doh_resolver_ips = vec![IpAddr::V4(CORP_RESOLVER)];
    let api = installed(Some(resolution_with_foreign()), None, snap, book());
    let filters = api.wfp_filters.lock().unwrap().clone();
    let ale = WfpLayerKey::AleAuthConnectV4;
    assert_eq!(
        verdict(&filters, via_foreign(ale, IpAddr::V4(CORP_RESOLVER))),
        WfpAction::Block,
        "the resolver stays cut through the corporate tunnel",
    );
    assert_eq!(
        verdict(&filters, via_foreign(ale, IpAddr::V4(CORP_OTHER))),
        WfpAction::Permit,
        "the rest of the corporate network is untouched",
    );
    let elsewhere = Flow {
        egress: 0x42,
        ..via_foreign(ale, IpAddr::V4(CORP_RESOLVER))
    };
    assert_eq!(
        verdict(&filters, elsewhere),
        WfpAction::Block,
        "the lockdown itself still holds on any other link",
    );
}

/// Every network a corporate tunnel carries rides one filter per layer, so a
/// large split-include list costs no more standing filters than a small one.
#[test]
fn a_tunnel_with_many_networks_installs_one_permit_per_layer() {
    let mut resolution = resolution_with_foreign();
    resolution.foreign_tunnel_networks = (1..=100u32)
        .map(|n| ForeignTunnelNetwork {
            luid: FOREIGN,
            network: IpBlock::parse(&format!("10.{n}.0.0/16")).expect("network"),
        })
        .collect();
    let api = installed(Some(resolution), None, snap_block("Wi-Fi", "TAP"), book());
    let filters = api.wfp_filters.lock().unwrap().clone();
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
    ] {
        let permits = filters
            .iter()
            .filter(|f| {
                f.layer == layer
                    && f.action == WfpAction::Permit
                    && f.local_interface_luid == Some(FOREIGN)
            })
            .count();
        assert_eq!(permits, 1, "{layer:?}");
        assert_eq!(
            verdict(
                &filters,
                via_foreign(layer, IpAddr::V4(Ipv4Addr::new(10, 99, 3, 4)))
            ),
            WfpAction::Permit,
            "{layer:?}: a network deep in the list is carried",
        );
        assert_eq!(
            verdict(&filters, via_foreign(layer, IpAddr::V4(PUBLIC_HOST))),
            WfpAction::Block,
            "{layer:?}: nothing beyond the listed networks",
        );
    }
}

//! Which links keep their egress under a block-all as somebody else's tunnel.
//!
//! A permit on the link the machine's own traffic leaves by turns the
//! kill-switch off, so the uplink must never qualify, whatever it is called.

use super::*;
use crate::killswitch_codegen::{fail_closed_block_all_filters, KillSwitchProtocols};
use nrr_platform_api::windows_api::mock_luid_for_index;

const SID: &str = "S-1-5-21-PPPOE";
const PRIMARY: u32 = 12;
const OURS: u32 = 78;
const WIREGUARD: u32 = 40;
const L2TP: u32 = 41;
const PPP: u32 = 42;

fn named(seed: &str, index: u32, description: &str, friendly: &str) -> AdapterInfo {
    let mut a = adapter(seed, index, true, true, None);
    a.description = description.into();
    a.friendly_name = friendly.into();
    a
}

fn route(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], ifindex: u32) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(dest)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
        interface_index: ifindex,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

/// A machine whose internet is `primary`, with our tunnel, a WireGuard link
/// and an L2TP link beside it. The table carries the uplink's default route,
/// our tunnel's server route and the uplink's own subnet.
fn machine(primary: AdapterInfo) -> (Arc<MockWindowsApi>, SecondaryRouteCoordinator) {
    let ours = named("ours", OURS, "Wintun Userspace Tunnel", "Our VPN");
    let primary_id = primary.stable_id();
    let ours_id = ours.stable_id();
    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![
        primary,
        ours,
        named("wg", WIREGUARD, "WireGuard Tunnel", "Work"),
        named("l2tp", L2TP, "WAN Miniport (L2TP)", "Branch office"),
    ]);
    api.set_route_table(vec![
        route([0, 0, 0, 0], 0, [0, 0, 0, 0], PRIMARY),
        route([203, 0, 113, 7], 32, [0, 0, 0, 0], PRIMARY),
        route([100, 64, 0, 0], 24, [0, 0, 0, 0], PRIMARY),
        route([0, 0, 0, 0], 1, [10, 91, 192, 1], OURS),
        route([128, 0, 0, 0], 1, [10, 91, 192, 1], OURS),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary(SID, &primary_id);
    policy.bind_secondary(SID, &ours_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);
    (api, coord)
}

fn luids(indexes: &[u32]) -> Vec<u64> {
    indexes.iter().map(|i| mock_luid_for_index(*i)).collect()
}

/// A Linux PPPoE link is `ppp0` — a name the tunnel list must keep, since
/// PPTP and a dial-up modem are `ppp0` too. Only its role can clear it.
#[test]
fn a_pppoe_primary_is_never_a_foreign_tunnel_but_a_wireguard_beside_it_is() {
    let (_, coord) = machine(named("ppp0", PRIMARY, "ppp0", "ppp0"));
    let foreign = coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_luids;
    assert_eq!(foreign, luids(&[WIREGUARD, L2TP]));
    let resolution = coord
        .kill_switch_exemptions(SID, &coord.read_machine())
        .expect("the fixture resolves");
    assert_eq!(resolution.foreign_tunnel_luids, luids(&[WIREGUARD, L2TP]));
}

#[test]
fn a_windows_pppoe_primary_is_never_a_foreign_tunnel() {
    let (_, coord) = machine(named(
        "pppoe",
        PRIMARY,
        "WAN Miniport (PPPOE)",
        "High-speed connection",
    ));
    assert!(!coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_luids
        .contains(&mock_luid_for_index(PRIMARY)));
}

/// Somebody binds a link called "OpenVPN" as their internet: the binding
/// says what it is, not the name.
#[test]
fn a_primary_with_a_tunnel_name_is_never_a_foreign_tunnel() {
    let (api, coord) = machine(named(
        "ovpn",
        PRIMARY,
        "OpenVPN Data Channel Offload",
        "OpenVPN",
    ));
    // Even without its default route the binding alone decides.
    api.set_route_table(vec![route([100, 64, 0, 0], 24, [0, 0, 0, 0], PRIMARY)]);
    assert!(!coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_luids
        .contains(&mock_luid_for_index(PRIMARY)));
}

/// The sole holder of the default route is the uplink: a permit on it is no
/// kill-switch at all, bound or not. Here the user bound the Ethernet the
/// PPPoE session rides on, and `ppp0` holds the only default.
#[test]
fn the_sole_default_route_holder_is_never_a_foreign_tunnel_even_unbound() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "eth0"));
    let mut adapters = api.get_adapter_infos().expect("mock adapters");
    adapters.push(named("ppp0", PPP, "ppp0", "ppp0"));
    api.set_adapter_infos(adapters);
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.retain(|r| !(r.interface_index == PRIMARY && r.prefix_length == 0));
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], PPP));
    api.set_route_table(table);
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// A corporate full tunnel holds a real `/0` while the physical link keeps
/// its own: two holders, so the table cannot name the uplink and the tunnel
/// keeps its permit by name, as it always did.
#[test]
fn a_full_tunnel_beside_a_physical_default_stays_foreign() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], L2TP));
    api.set_route_table(table);
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// Each address family names its own uplink: a tunnel holding the only IPv6
/// default is the v6 uplink even though the v4 default sits elsewhere.
#[test]
fn ipv4_and_ipv6_defaults_are_counted_separately() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(v6_default(WIREGUARD));
    api.set_route_table(table.clone());
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[L2TP]),
        "the sole v6 default holder is the v6 uplink",
    );

    // A second v6 holder makes the v6 family ambiguous; the v4 default on the
    // Ethernet does not count toward it.
    table.push(v6_default(L2TP));
    api.set_route_table(table);
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// A home internet delivered over L2TP, left unbound (the common setup binds
/// only the additional route), beside our bound WireGuard full tunnel. Our
/// tunnel's default says nothing about the uplink: the L2TP link is the uplink,
/// never foreign, and the main link is derived from it.
#[test]
fn an_unbound_l2tp_uplink_beside_our_full_tunnel_is_the_uplink() {
    let our_full_tunnel = vec![route([0, 0, 0, 0], 0, [10, 91, 192, 1], OURS)];
    let our_redirect_pair = vec![
        route([0, 0, 0, 0], 1, [10, 91, 192, 1], OURS),
        route([128, 0, 0, 0], 1, [10, 91, 192, 1], OURS),
    ];
    for ours_routes in [our_full_tunnel, our_redirect_pair] {
        let isp = named("isp", L2TP, "WAN Miniport (L2TP)", "Home internet");
        let ours = named("ours", OURS, "WireGuard Tunnel", "Our VPN");
        let ours_id = ours.stable_id();
        let api = Arc::new(MockWindowsApi::new());
        api.set_adapter_infos(vec![isp, ours]);
        let mut table = vec![
            route([0, 0, 0, 0], 0, [0, 0, 0, 0], L2TP),
            route([203, 0, 113, 7], 32, [0, 0, 0, 0], L2TP),
        ];
        table.extend(ours_routes);
        api.set_route_table(table);
        let policy = Arc::new(FakePolicy::new());
        policy.bind_secondary(SID, &ours_id);
        let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

        assert_eq!(coord.resolve_primary_interface_index(SID), Some(L2TP));
        let resolution = coord
            .kill_switch_exemptions(SID, &coord.read_machine())
            .expect("the fixture resolves");
        assert!(
            resolution.foreign_tunnel_luids.is_empty(),
            "{:?}",
            resolution.foreign_tunnel_luids
        );
        let fail_closed = coord.fail_closed_exemptions(SID, &coord.read_machine());
        assert!(fail_closed.foreign_tunnel_luids.is_empty());
        assert!(fail_closed.foreign_tunnel_networks.is_empty());
    }
}

/// Our tunnel's default leaves the count, our bound primary's does not: a
/// corporate L2TP holding a default beside the bound Ethernet stays foreign
/// with our full tunnel up too.
#[test]
fn a_corporate_full_tunnel_beside_a_bound_primary_stays_foreign_with_ours_full() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], L2TP));
    table.push(route([0, 0, 0, 0], 0, [10, 91, 192, 1], OURS));
    api.set_route_table(table);
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// Our full tunnel replaced the provider's default, so the unbound L2TP uplink
/// holds none. It still carries the route to our tunnel's server, which names
/// it the uplink: no egress is opened on it.
#[test]
fn an_l2tp_uplink_whose_default_our_tunnel_replaced_is_still_the_uplink() {
    let isp = named("isp", L2TP, "WAN Miniport (L2TP)", "Home internet");
    let ours = named("ours", OURS, "WireGuard Tunnel", "Our VPN");
    let ours_id = ours.stable_id();
    let api = Arc::new(MockWindowsApi::new());
    api.set_adapter_infos(vec![isp, ours]);
    api.set_route_table(vec![
        route([0, 0, 0, 0], 0, [10, 91, 192, 1], OURS),
        route([203, 0, 113, 7], 32, [0, 0, 0, 0], L2TP),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary(SID, &ours_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

    let fail_closed = coord.fail_closed_exemptions(SID, &coord.read_machine());
    assert!(
        fail_closed.foreign_tunnel_luids.is_empty(),
        "{:?}",
        fail_closed.foreign_tunnel_luids
    );
    assert!(fail_closed.foreign_tunnel_networks.is_empty());
}

const OWN_TUN: u32 = 55;

/// Our fake-IP adapter reads as a tunnel by its driver name, but it carries
/// traffic back into us: never foreign and its pool never a corporate
/// network, under our name or renamed.
#[test]
fn our_fake_ip_adapter_is_never_a_foreign_tunnel() {
    for (adapter_name, friendly) in [
        ("{tun}", nrr_shared::product_identity::TUN_ADAPTER_NAME),
        (
            "{7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5F31}",
            "Renamed by the user",
        ),
    ] {
        let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
        let mut tun = named("tun", OWN_TUN, "NetRuleRouter Tunnel", friendly);
        tun.adapter_name = adapter_name.into();
        let mut adapters = api.get_adapter_infos().expect("mock adapters");
        adapters.push(tun);
        api.set_adapter_infos(adapters);
        let mut table = api.get_ip_forward_table().expect("mock table");
        table.push(RouteEntry {
            metric: 50,
            ..route([198, 18, 0, 0], 15, [0, 0, 0, 0], OWN_TUN)
        });
        api.set_route_table(table);

        let exemptions = coord.fail_closed_exemptions(SID, &coord.read_machine());
        assert_eq!(
            exemptions.foreign_tunnel_luids,
            luids(&[WIREGUARD, L2TP]),
            "{friendly}"
        );
        assert!(exemptions
            .foreign_tunnel_networks
            .iter()
            .all(|n| n.luid != mock_luid_for_index(OWN_TUN)));
    }
}

fn v6_default(ifindex: u32) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        prefix_length: 0,
        next_hop: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        interface_index: ifindex,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

/// Not knowing who carries the default route is doubt, and doubt exempts
/// nothing: a missing permit breaks a corporate VPN, a wrong one the
/// kill-switch.
#[test]
fn an_unreadable_route_table_exempts_no_foreign_tunnel() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_luids
        .is_empty());
}

/// End to end: the block-all built from what the coordinator resolved holds
/// no egress permit on a PPPoE uplink, nor an any-destination one on the
/// corporate tunnel: that tunnel keeps only the networks it carries, permitted
/// per network beside the block.
#[test]
fn the_block_all_opens_no_egress_on_a_pppoe_primary() {
    let (_, coord) = machine(named("ppp0", PRIMARY, "ppp0", "ppp0"));
    let exemptions = coord.fail_closed_exemptions(SID, &coord.read_machine());
    let permits: Vec<u64> =
        fail_closed_block_all_filters(SID, &exemptions, KillSwitchProtocols::ALL)
            .iter()
            .filter_map(|f| f.local_interface_luid)
            .collect();
    assert!(
        !permits.contains(&mock_luid_for_index(PRIMARY)),
        "an egress permit on the uplink turns the kill-switch off: {permits:?}",
    );
    assert!(
        !permits.contains(&mock_luid_for_index(WIREGUARD)),
        "a default route through a foreign tunnel would carry the protected traffic: {permits:?}",
    );
}

/// Linux names a WireGuard or OpenVPN link `wg0` / `tun0` and reports it as a
/// tunnel by type, with no VPN word anywhere: the type alone makes it somebody
/// else's tunnel, while a tunnel-typed link we own, or one that is down, is not.
#[test]
fn a_tunnel_typed_link_with_a_bare_name_is_a_foreign_tunnel() {
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    let (api, coord) = machine(named("eth", PRIMARY, "e1000e", "eth0"));
    let mut infos = nrr_platform_api::route_table::RouteTablePort::get_adapter_infos(api.as_ref())
        .expect("fixture adapters");
    infos.retain(|a| a.index != WIREGUARD && a.index != L2TP);
    let tunnel = |seed: &str, index: u32, name: &str, up: bool| {
        let mut a = named(seed, index, name, name);
        a.interface_type = InterfaceType::Tunnel;
        if !up {
            a.oper_status = IfOperStatus::Down;
        }
        a
    };
    infos.push(tunnel("wg0", WIREGUARD, "wg0", true));
    infos.push(tunnel("tun0", L2TP, "tun0", true));
    infos.push(tunnel("tun1", PPP, "tun1", false));
    for ours in infos.iter_mut().filter(|a| a.index == OURS) {
        ours.interface_type = InterfaceType::Tunnel;
    }
    api.set_adapter_infos(infos);
    let foreign = coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_luids;
    assert_eq!(foreign, luids(&[WIREGUARD, L2TP]));
}

/// An LTE modem in raw-IP mode (`wwan0`, as Linux types it) up beside the
/// bound Wi-Fi, both holding a default: two holders name no uplink, and the
/// modem must still not become somebody else's tunnel, while `wg0` does.
#[test]
fn an_unbound_lte_modem_beside_a_bound_wifi_is_not_a_foreign_tunnel() {
    use nrr_platform_api::adapters::InterfaceType;
    const WWAN: u32 = 43;
    let mut wifi = named("wlan0", PRIMARY, "iwlwifi", "wlan0");
    wifi.interface_type = InterfaceType::Wireless;
    let (api, coord) = machine(wifi);
    let mut infos = nrr_platform_api::route_table::RouteTablePort::get_adapter_infos(api.as_ref())
        .expect("fixture adapters");
    infos.retain(|a| a.index != WIREGUARD && a.index != L2TP);
    let mut wg = named("wg0", WIREGUARD, "wg0", "wg0");
    wg.interface_type = InterfaceType::Tunnel;
    infos.push(wg);
    let mut modem = named("wwan0", WWAN, "qmi_wwan", "wwan0");
    modem.interface_type = InterfaceType::Other(65534);
    infos.push(modem);
    api.set_adapter_infos(infos);
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(RouteEntry {
        metric: 700,
        ..route([0, 0, 0, 0], 0, [0, 0, 0, 0], WWAN)
    });
    api.set_route_table(table);
    assert_eq!(
        coord
            .fail_closed_exemptions(SID, &coord.read_machine())
            .foreign_tunnel_luids,
        luids(&[WIREGUARD]),
    );
}

fn block(text: &str) -> nrr_shared::ip_block::IpBlock {
    nrr_shared::ip_block::IpBlock::parse(text).expect("block")
}

/// A foreign tunnel is spared for the networks its own routes carry, never for
/// a default or a redirect pair: those would carry the user's protected
/// traffic once ours is down.
#[test]
fn a_foreign_tunnel_is_named_with_its_own_networks_only() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    // The L2TP link holds a second default (not the sole holder) and a
    // corporate network; the WireGuard link only a def1 redirect pair.
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], L2TP));
    // Not at our route metric, so nothing reads it as a route of ours.
    table.push(RouteEntry {
        metric: 50,
        ..route([10, 77, 0, 0], 16, [0, 0, 0, 0], L2TP)
    });
    table.push(route([0, 0, 0, 0], 1, [0, 0, 0, 0], WIREGUARD));
    table.push(route([128, 0, 0, 0], 1, [0, 0, 0, 0], WIREGUARD));
    api.set_route_table(table);
    let networks = coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_networks;
    assert_eq!(
        networks,
        vec![crate::killswitch_codegen::ForeignTunnelNetwork {
            luid: mock_luid_for_index(L2TP),
            network: block("10.77.0.0/16"),
        }],
    );
}

#[test]
fn an_unreadable_route_table_names_no_foreign_network() {
    let (api, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .foreign_tunnel_networks
        .is_empty());
}

/// A bound link is the user's whether or not it resolved this pass, matched
/// by its identity or by the name saved with the binding; an empty saved name
/// names nothing.
#[test]
fn a_bound_link_is_ours_even_unresolved() {
    let work = named("wg", WIREGUARD, "WireGuard Tunnel", "Work");
    let branch = named("l2tp", L2TP, "WAN Miniport (L2TP)", "Branch office");
    let unnamed = named("x", 77, "OpenVPN", "");
    let binding =
        |stable_id: String, display_name: &str| crate::per_sid_orchestrator::PerSidBinding {
            stable_id,
            display_name: display_name.into(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        };
    let bindings = [
        binding(work.stable_id(), ""),
        binding("gone".into(), "Branch office"),
    ];
    let adapters = [work, branch, unnamed];
    assert_eq!(
        crate::route_coordinator::own_link_indexes(&adapters, &[], &bindings),
        vec![WIREGUARD, L2TP],
    );
}

/// A pass that returns before reading the machine (a paused user) still names
/// the user's bound VPN as theirs: doubt keeps a link ours, so the DNS scope
/// never takes it for a corporate tunnel.
#[test]
fn a_paused_users_bound_vpn_stays_ours_without_a_pass() {
    let (_, coord) = machine(named("eth", PRIMARY, "Ethernet Controller", "Ethernet"));
    let ours = coord.links_kept_as_ours(Vec::new(), &[SID.to_string()]);
    assert!(ours.contains(&OURS), "the bound tunnel is ours: {ours:?}");
    assert!(
        !ours.contains(&WIREGUARD) && !ours.contains(&L2TP),
        "a link nobody bound is not made ours: {ours:?}"
    );
    let kept = coord.links_kept_as_ours(vec![WIREGUARD], &[]);
    assert!(
        kept.contains(&WIREGUARD),
        "what was published stays: {kept:?}"
    );
}

/// One pass loads a user's policy once however many questions it asks.
#[test]
fn a_pass_loads_the_users_policy_once() {
    let api = Arc::new(MockWindowsApi::new());
    let mut vpn = adapter("vpn", 7, true, true, Some([10, 8, 0, 1]));
    vpn.description = "WireGuard Tunnel".into();
    api.set_adapter_infos(vec![
        adapter("eth", 2, true, true, Some([192, 168, 1, 1])),
        vpn.clone(),
    ]);
    api.set_route_table(vec![route([0, 0, 0, 0], 0, [192, 168, 1, 1], 2)]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-ONCE", &vpn.stable_id());
    let coord = coordinator_with_policy(api, Arc::new(FakeRules::new()), Arc::clone(&policy));

    let resolution = coord.resolve("S-ONCE");
    let before = policy.loads();
    coord
        .recompute_for("S-ONCE", &resolution)
        .expect("the pass runs");
    assert_eq!(policy.loads() - before, 1);

    let before = policy.loads();
    coord
        .recompute_served(&["S-ONCE".to_string(), "S-TWO".to_string()])
        .expect("the pass runs");
    // The resolve of each user is the other load.
    assert!(
        policy.loads() - before <= 4,
        "two users cost at most two loads each, saw {}",
        policy.loads() - before
    );
}

/// A transient unreadable table must not turn the link a binding resolved to
/// into somebody else's tunnel: the stale id heals to it again. A tunnel the
/// binding never resolved to is still not adopted on a guess.
#[test]
fn an_unreadable_table_keeps_the_last_resolved_link_through_a_rename() {
    const NAME: &str = "TAP-Windows Adapter V9";
    let api = Arc::new(MockWindowsApi::new());
    let mut tap = adapter("tap", 2, true, true, Some([10, 9, 0, 1]));
    tap.description = NAME.into();
    tap.friendly_name = "Corp Connection".into();
    api.set_adapter_infos(vec![tap.clone()]);
    api.set_route_table(Vec::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary_named("S-RENAME", &tap.stable_id(), NAME);
    let coord = coordinator_with_policy(
        Arc::clone(&api),
        Arc::new(FakeRules::new()),
        Arc::clone(&policy),
    );
    let first = coord.resolve("S-RENAME");
    assert_eq!(first.secondary.map(|t| t.interface_index), Some(2));
    coord
        .recompute_for("S-RENAME", &first)
        .expect("the pass runs");

    policy.bind_secondary_named("S-RENAME", "win-adapter:gone", NAME);
    api.set_route_table_read_error(Some("enumeration failed"));
    assert_eq!(
        coord
            .resolve("S-RENAME")
            .secondary
            .map(|t| t.interface_index),
        Some(2),
        "the link it resolved to is still the user's"
    );

    let stranger = coordinator_with_policy(api, Arc::new(FakeRules::new()), policy);
    assert!(
        stranger.resolve("S-RENAME").secondary.is_none(),
        "with nothing resolved before, a tunnel-looking link is not adopted on a guess"
    );
}

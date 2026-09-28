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
    let foreign = coord.fail_closed_exemptions(SID).foreign_tunnel_luids;
    assert_eq!(foreign, luids(&[WIREGUARD, L2TP]));
    let resolution = coord
        .kill_switch_exemptions(SID)
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
        .fail_closed_exemptions(SID)
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
        .fail_closed_exemptions(SID)
        .foreign_tunnel_luids
        .contains(&mock_luid_for_index(PRIMARY)));
}

/// The sole holder of the default route is the uplink: a permit on it is no
/// kill-switch at all, bound or not. Here the user bound the Ethernet the
/// PPPoE session rides on, and `ppp0` holds the only default.
#[test]
fn the_sole_default_route_holder_is_never_a_foreign_tunnel_even_unbound() {
    let (api, coord) = machine(named("eth", PRIMARY, "Intel(R) Ethernet", "eth0"));
    let mut adapters = api.get_adapter_infos().expect("mock adapters");
    adapters.push(named("ppp0", PPP, "ppp0", "ppp0"));
    api.set_adapter_infos(adapters);
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.retain(|r| !(r.interface_index == PRIMARY && r.prefix_length == 0));
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], PPP));
    api.set_route_table(table);
    assert_eq!(
        coord.fail_closed_exemptions(SID).foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// A corporate full tunnel holds a real `/0` while the physical link keeps
/// its own: two holders, so the table cannot name the uplink and the tunnel
/// keeps its permit by name, as it always did.
#[test]
fn a_full_tunnel_beside_a_physical_default_stays_foreign() {
    let (api, coord) = machine(named("eth", PRIMARY, "Intel(R) Ethernet", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], L2TP));
    api.set_route_table(table);
    assert_eq!(
        coord.fail_closed_exemptions(SID).foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
}

/// Each address family names its own uplink: a tunnel holding the only IPv6
/// default is the v6 uplink even though the v4 default sits elsewhere.
#[test]
fn ipv4_and_ipv6_defaults_are_counted_separately() {
    let (api, coord) = machine(named("eth", PRIMARY, "Intel(R) Ethernet", "Ethernet"));
    let mut table = api.get_ip_forward_table().expect("mock table");
    table.push(v6_default(WIREGUARD));
    api.set_route_table(table.clone());
    assert_eq!(
        coord.fail_closed_exemptions(SID).foreign_tunnel_luids,
        luids(&[L2TP]),
        "the sole v6 default holder is the v6 uplink",
    );

    // A second v6 holder makes the v6 family ambiguous; the v4 default on the
    // Ethernet does not count toward it.
    table.push(v6_default(L2TP));
    api.set_route_table(table);
    assert_eq!(
        coord.fail_closed_exemptions(SID).foreign_tunnel_luids,
        luids(&[WIREGUARD, L2TP]),
    );
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
    let (api, coord) = machine(named("eth", PRIMARY, "Intel(R) Ethernet", "Ethernet"));
    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(coord
        .fail_closed_exemptions(SID)
        .foreign_tunnel_luids
        .is_empty());
}

/// End to end: the block-all built from what the coordinator resolved holds
/// no egress permit on a PPPoE uplink, and keeps the corporate tunnel's.
#[test]
fn the_block_all_opens_no_egress_on_a_pppoe_primary() {
    let (_, coord) = machine(named("ppp0", PRIMARY, "ppp0", "ppp0"));
    let exemptions = coord.fail_closed_exemptions(SID);
    let permits: Vec<u64> =
        fail_closed_block_all_filters(SID, &exemptions, KillSwitchProtocols::ALL)
            .iter()
            .filter_map(|f| f.local_interface_luid)
            .collect();
    assert!(
        !permits.contains(&mock_luid_for_index(PRIMARY)),
        "an egress permit on the uplink turns the kill-switch off: {permits:?}",
    );
    assert!(permits.contains(&mock_luid_for_index(WIREGUARD)));
}

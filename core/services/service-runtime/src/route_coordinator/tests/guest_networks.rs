//! Which adapters are the host side of a guest network, the interfaces the
//! forwarded blanket keeps open for replies into a guest.
//!
//! A permit keyed on the link the guests' traffic leaves by would let every
//! guest out, so a way out must never qualify, whatever it is called.

use super::*;
use crate::route_coordinator::exemptions::guest_network_indexes;
use nrr_domain::ipv4_network::Ipv4Network;
use nrr_platform_api::adapters::InterfaceType;
use nrr_platform_api::windows_api::mock_luid_for_index;

const SID: &str = "S-1-5-21-GUEST";
const PRIMARY: u32 = 12;
const VPN: u32 = 78;
const WSL: u32 = 31;

fn hyper_v(seed: &str, index: u32, friendly: &str, gw: Option<[u8; 4]>) -> AdapterInfo {
    let mut a = adapter(seed, index, true, true, gw);
    a.description = "Hyper-V Virtual Ethernet Adapter".into();
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

const WSL_NET: ([u8; 4], u8) = ([172, 23, 208, 0], 20);

/// The main link, our tunnel and the WSL switch, with the user's refusal of the
/// WSL network when `refuse` is set.
fn machine(refuse: bool) -> (Arc<MockWindowsApi>, SecondaryRouteCoordinator) {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("examplevpn", VPN, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", PRIMARY, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![
        eth,
        vpn,
        hyper_v("wslswitch", WSL, "vEthernet (WSL)", None),
    ]);
    api.set_route_table(vec![
        route([0, 0, 0, 0], 0, [192, 168, 1, 1], PRIMARY),
        route([192, 168, 1, 0], 24, [0, 0, 0, 0], PRIMARY),
        route([0, 0, 0, 0], 1, [10, 91, 192, 1], VPN),
        route(WSL_NET.0, WSL_NET.1, [0, 0, 0, 0], WSL),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary(SID, &eth_id);
    policy.bind_secondary(SID, &vpn_id);
    let mut coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);
    if refuse {
        let refused = Ipv4Network::new(Ipv4Addr::from(WSL_NET.0), WSL_NET.1).expect("network");
        coord = coord.with_local_network_policy(Arc::new(move |_: &str| LocalNetworkPolicy {
            refused: vec![refused],
            ..LocalNetworkPolicy::default()
        }));
    }
    (api, coord)
}

/// The refusal closes the WSL network to the machine's own traffic and leaves
/// its adapter named, so replies forwarded into the guest still arrive.
#[test]
fn a_refused_wsl_network_still_names_its_adapter_for_the_replies() {
    let wsl_net = (Ipv4Addr::from(WSL_NET.0), WSL_NET.1);
    let (_, open) = machine(false);
    let accepted = open.fail_closed_exemptions(SID, &open.read_machine());
    assert!(accepted.local_subnets.contains(&wsl_net));
    assert_eq!(accepted.guest_network_luids, vec![mock_luid_for_index(WSL)]);

    let (_, closed) = machine(true);
    let refused = closed.fail_closed_exemptions(SID, &closed.read_machine());
    assert!(
        !refused.local_subnets.contains(&wsl_net),
        "the refusal holds"
    );
    assert_eq!(refused.guest_network_luids, vec![mock_luid_for_index(WSL)]);
}

/// Doubt names nothing: with the table unreadable no uplink can be told apart.
#[test]
fn an_unreadable_route_table_names_no_guest_network() {
    let (api, coord) = machine(false);
    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(coord
        .fail_closed_exemptions(SID, &coord.read_machine())
        .guest_network_luids
        .is_empty());
}

/// An external virtual switch IS the internet link: bound, holding the default
/// route or the gateway, it is never a guest network.
#[test]
fn a_virtual_switch_the_machine_leaves_by_is_never_a_guest_network() {
    let external = hyper_v("external", PRIMARY, "vEthernet (External)", None);
    let wsl = hyper_v("wslswitch", WSL, "vEthernet (WSL)", None);
    let lan = route([192, 168, 1, 0], 24, [0, 0, 0, 0], PRIMARY);
    let wsl_net = route(WSL_NET.0, WSL_NET.1, [0, 0, 0, 0], WSL);
    let default = route([0, 0, 0, 0], 0, [192, 168, 1, 1], PRIMARY);
    let adapters = vec![external.clone(), wsl.clone()];

    let both = vec![lan.clone(), wsl_net.clone()];
    assert_eq!(
        guest_network_indexes(&adapters, &both, &[]),
        vec![PRIMARY, WSL]
    );
    // Bound by the user.
    assert_eq!(
        guest_network_indexes(&adapters, &both, &[PRIMARY]),
        vec![WSL]
    );
    // The default route.
    let routed = vec![default, lan, wsl_net];
    assert_eq!(guest_network_indexes(&adapters, &routed, &[]), vec![WSL]);
    // A gateway.
    let mut gated = external;
    gated.gateways = vec![Ipv4Addr::new(192, 168, 1, 1)];
    assert_eq!(guest_network_indexes(&[gated, wsl], &both, &[]), vec![WSL]);
}

/// A tunnel, our own adapter and a link that is down never qualify, even on a
/// hypervisor's driver.
#[test]
fn tunnels_and_dead_links_are_never_guest_networks() {
    let mut tunnel = hyper_v("t", 40, "vEthernet (WSL)", None);
    tunnel.interface_type = InterfaceType::Tunnel;
    let vpn_named = hyper_v("v", 41, "Corporate VPN", None);
    let mut down = hyper_v("d", 42, "vEthernet (Default Switch)", None);
    down.oper_status = nrr_platform_api::adapters::IfOperStatus::Down;
    let mut plain = adapter("eth", 43, true, true, None);
    plain.description = "Ethernet Controller".into();
    let routes: Vec<RouteEntry> = [40, 41, 42, 43]
        .iter()
        .map(|i| route([172, 16, *i as u8, 0], 24, [0, 0, 0, 0], *i))
        .collect();
    assert!(guest_network_indexes(&[tunnel, vpn_named, down, plain], &routes, &[]).is_empty());
}

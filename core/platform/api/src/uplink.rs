//! Which link is the machine's way out, read off the route table.
//!
//! A name cannot tell an uplink from a tunnel: providers deliver the internet
//! itself over PPPoE, L2TP and PPTP, and a user may call their Ethernet
//! "OpenVPN". The table can. Every reader that has to tell the two apart asks
//! here — the route coordinator's foreign tunnels, the namespace classifier,
//! the main-link suggestion — so they cannot disagree.

use std::net::IpAddr;

use nrr_shared::ip_block::IpBlock;
use nrr_shared::product_identity::TUN_ADAPTER_NAME;

use crate::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use crate::fake_ip::{FakeIpPoolConfig, OWN_TUN_ADAPTER_GUID};
use crate::types::RouteEntry;

/// Our own fake-IP adapter: the name we create it under, or the fixed identity
/// a rename cannot change. It carries traffic back into us, so it is never the
/// uplink and never somebody else's tunnel.
#[must_use]
pub fn is_own_fake_ip_adapter(info: &AdapterInfo) -> bool {
    is_own_fake_ip_name(&info.friendly_name)
        || is_own_fake_ip_name(&info.adapter_name)
        || guid_value(&info.adapter_name) == Some(OWN_TUN_ADAPTER_GUID)
}

/// [`is_own_fake_ip_adapter`] for a reader that holds only the connection name.
#[must_use]
pub fn is_own_fake_ip_name(name: &str) -> bool {
    name.trim() == TUN_ADAPTER_NAME
}

/// A braced adapter GUID as a number; `None` for anything else. The text is
/// the OS's, and another program names its own adapters, so it is bounded and
/// never trusted to be well formed.
fn guid_value(text: &str) -> Option<u128> {
    let hex = text.trim().strip_prefix('{')?.strip_suffix('}')?;
    if hex.len() != 36 {
        return None;
    }
    let mut value: u128 = 0;
    for (i, byte) in hex.bytes().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
            continue;
        }
        value = (value << 4) | u128::from(char::from(byte).to_digit(16)?);
    }
    Some(value)
}

/// A link that may stand for the way out: up, addressed, not loopback, not our
/// fake-IP adapter and not one the caller leaves out. Typed tunnels and
/// hypervisor switches count: an external Hyper-V switch carries the host's
/// own uplink, and a tunnel can be the only way out there is.
fn may_be_the_way_out(info: &AdapterInfo, left_out: &[u32]) -> bool {
    info.oper_status == IfOperStatus::Up
        && (info.has_ipv4_address() || !info.ipv6_addresses.is_empty())
        && info.interface_type != InterfaceType::Loopback
        && !left_out.contains(&info.index)
        && !is_own_fake_ip_adapter(info)
}

/// The links holding a default route of their own in the family, each once.
/// One we installed holds nothing, and neither does one in a table only
/// another program's own rule leads to (wg-quick, Tailscale).
fn default_route_holders(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    v6: bool,
    left_out: &[u32],
) -> Vec<u32> {
    let mut holders: Vec<u32> = adapters
        .iter()
        .filter(|a| may_be_the_way_out(a, left_out))
        .map(|a| a.index)
        .filter(|index| {
            routes.iter().any(|r| {
                r.interface_index == *index
                    && r.prefix_length == 0
                    && !r.is_ours
                    && r.table == crate::enforcement::RouteTableRef::Main
                    && r.destination.is_ipv6() == v6
            })
        })
        .collect();
    holders.sort_unstable();
    holders.dedup();
    holders
}

/// The one link holding a default route of its own in the family: the
/// machine's uplink by structure, whatever it is called. `None` with none or
/// with two: then the table cannot say which one is the uplink.
///
/// `left_out` are links whose default says nothing about which link is the
/// uplink — a user's additional route, whose full tunnel holds a default beside
/// it. Our fake-IP adapter never counts.
#[must_use]
pub fn sole_default_route_holder(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    v6: bool,
    left_out: &[u32],
) -> Option<u32> {
    match default_route_holders(adapters, routes, v6, left_out).as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// The links the table names the way out, both families: the sole default
/// holder of each; in a family where no link holds a default at all (a full
/// tunnel of ours replaced the provider's), every link carrying a tunnel's
/// route to its server. A client sends that route through the link its
/// encrypted traffic leaves by, which is the uplink. Two holders name nothing.
///
/// Calling a link the way out only ever spares it from being somebody else's
/// tunnel, so a corporate tunnel caught by the server-route reading loses its
/// exemption rather than gaining one.
#[must_use]
pub fn structural_uplinks(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    left_out: &[u32],
) -> Vec<u32> {
    let mut out = Vec::new();
    for v6 in [false, true] {
        match default_route_holders(adapters, routes, v6, left_out).as_slice() {
            [only] => out.push(*only),
            [] => out.extend(server_route_carriers(adapters, routes, v6, left_out)),
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Links carrying a host route to a public address that no wider route of the
/// same link already covers: a tunnel's route to its server. The link's own
/// addresses, its subnet's broadcast and a full tunnel's host routes inside its
/// own catch-alls are all covered or private, and a route we installed is ours,
/// not a client's.
fn server_route_carriers(
    adapters: &[AdapterInfo],
    routes: &[RouteEntry],
    v6: bool,
    left_out: &[u32],
) -> Vec<u32> {
    adapters
        .iter()
        .filter(|a| may_be_the_way_out(a, left_out))
        .filter(|a| {
            let own = |ip: IpAddr| match ip {
                IpAddr::V4(addr) => a.ipv4_addresses.contains(&addr),
                IpAddr::V6(addr) => a.ipv6_addresses.contains(&addr),
            };
            routes.iter().any(|r| {
                r.interface_index == a.index
                    && !r.is_ours
                    && r.destination.is_ipv6() == v6
                    && r.is_host_route()
                    && is_public(r.destination)
                    && !own(r.destination)
                    && !covered_on_link(routes, a.index, r.destination)
            })
        })
        .map(|a| a.index)
        .collect()
}

/// Does a wider route of link `index` already hold `ip`?
fn covered_on_link(routes: &[RouteEntry], index: u32, ip: IpAddr) -> bool {
    routes.iter().any(|r| {
        r.interface_index == index
            && !r.is_host_route()
            && IpBlock::new(r.destination, r.prefix_length).is_some_and(|net| net.contains(ip))
    })
}

/// An address on the internet: not private, shared, link-local, reserved or
/// inside our fake-IP pool.
fn is_public(ip: IpAddr) -> bool {
    use nrr_domain::ip_network_policy::{is_private, reserved_overlap, touches_link_local};
    let host = if ip.is_ipv4() { 32 } else { 128 };
    let Some(block) = IpBlock::new(ip, host) else {
        return false;
    };
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && reserved_overlap(block).is_none()
        && !touches_link_local(block)
        && !is_private(block)
        && !FakeIpPoolConfig::default().contains(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::RouteTableRef;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn link(index: u32, name: &str) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: format!("{{0000000{index}-0000-0000-0000-000000000000}}"),
            description: format!("driver {index}"),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, index as u8)],
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    fn route(dest: [u8; 4], prefix: u8, next_hop: [u8; 4], index: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
            interface_index: index,
            metric: 25,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    #[test]
    fn our_adapter_is_known_by_name_or_by_its_fixed_identity() {
        let mut tun = link(9, TUN_ADAPTER_NAME);
        assert!(is_own_fake_ip_adapter(&tun));
        tun.friendly_name = "Renamed by the user".into();
        tun.adapter_name = "{7a3e1c55-0b6d-4f82-9e14-2d6c8b0a5f31}".into();
        assert!(is_own_fake_ip_adapter(&tun), "a rename keeps the identity");
        tun.adapter_name = "{7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5F32}".into();
        assert!(!is_own_fake_ip_adapter(&tun));
        for hostile in [
            "{}",
            "{7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5F3}",
            "{7A3E1C55+0B6D-4F82-9E14-2D6C8B0A5F31}",
            "{7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5FЖ}",
            "7A3E1C55-0B6D-4F82-9E14-2D6C8B0A5F31",
        ] {
            tun.adapter_name = hostile.into();
            assert!(!is_own_fake_ip_adapter(&tun), "{hostile}");
        }
    }

    #[test]
    fn a_left_out_link_and_our_adapter_hold_no_default_that_counts() {
        let adapters = [
            link(3, "Home internet"),
            link(7, "Our tunnel"),
            link(9, TUN_ADAPTER_NAME),
        ];
        let routes = [
            route([0, 0, 0, 0], 0, [192, 168, 1, 1], 3),
            route([0, 0, 0, 0], 0, [0, 0, 0, 0], 7),
            route([0, 0, 0, 0], 0, [0, 0, 0, 0], 9),
        ];
        assert_eq!(
            sole_default_route_holder(&adapters, &routes, false, &[]),
            None
        );
        assert_eq!(
            sole_default_route_holder(&adapters, &routes, false, &[7]),
            Some(3)
        );
        assert_eq!(structural_uplinks(&adapters, &routes, &[7]), vec![3]);
    }

    /// Our full tunnel replaced the provider's default: the L2TP uplink holds
    /// none, but it carries the route to our tunnel's server.
    #[test]
    fn with_no_default_left_the_link_carrying_the_server_route_is_the_uplink() {
        let adapters = [link(3, "Home internet"), link(7, "Our tunnel")];
        let routes = [
            route([0, 0, 0, 0], 0, [0, 0, 0, 0], 7),
            route([203, 0, 113, 7], 32, [0, 0, 0, 0], 3),
            route([10, 9, 0, 0], 16, [0, 0, 0, 0], 3),
        ];
        assert_eq!(structural_uplinks(&adapters, &routes, &[7]), vec![3]);
        assert_eq!(
            structural_uplinks(&adapters, &routes, &[]),
            vec![7],
            "counted, our tunnel would be the sole holder"
        );
    }

    /// The host routes every link carries name no server: its own address, its
    /// subnet's broadcast, private and reserved ones, one we installed and one
    /// inside a wider route of the same link.
    #[test]
    fn furniture_host_routes_name_no_uplink() {
        let mut uplink = link(3, "Home internet");
        uplink.ipv4_addresses = vec![Ipv4Addr::new(198, 51, 100, 10)];
        let adapters = [uplink, link(7, "Our tunnel")];
        let mut ours = route([198, 51, 100, 77], 32, [0, 0, 0, 0], 3);
        ours.is_ours = true;
        let routes = [
            route([0, 0, 0, 0], 0, [0, 0, 0, 0], 7),
            route([198, 51, 100, 10], 32, [0, 0, 0, 0], 3),
            route([203, 0, 113, 0], 24, [0, 0, 0, 0], 3),
            route([203, 0, 113, 255], 32, [0, 0, 0, 0], 3),
            route([192, 168, 1, 255], 32, [0, 0, 0, 0], 3),
            route([255, 255, 255, 255], 32, [0, 0, 0, 0], 3),
            route([198, 18, 0, 1], 32, [0, 0, 0, 0], 3),
            ours,
        ];
        assert!(structural_uplinks(&adapters, &routes, &[7]).is_empty());
    }

    /// A server route says nothing while a link still holds a default: that
    /// link is the uplink, and two holders stay ambiguous.
    #[test]
    fn a_server_route_does_not_outvote_a_default() {
        let adapters = [link(3, "Ethernet"), link(5, "Corp"), link(7, "Our tunnel")];
        let mut routes = vec![
            route([0, 0, 0, 0], 0, [192, 168, 1, 1], 3),
            route([203, 0, 113, 7], 32, [0, 0, 0, 0], 5),
        ];
        assert_eq!(structural_uplinks(&adapters, &routes, &[7]), vec![3]);
        routes.push(route([0, 0, 0, 0], 0, [0, 0, 0, 0], 5));
        assert!(structural_uplinks(&adapters, &routes, &[7]).is_empty());
    }

    #[test]
    fn each_family_names_its_own_uplink() {
        let mut v6_link = link(5, "Mobile");
        v6_link.ipv6_addresses = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)];
        let adapters = [link(3, "Ethernet"), v6_link];
        let routes = [
            route([0, 0, 0, 0], 0, [192, 168, 1, 1], 3),
            RouteEntry {
                destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_length: 0,
                next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                interface_index: 5,
                metric: 5,
                is_ours: false,
                table: RouteTableRef::Main,
            },
        ];
        assert_eq!(structural_uplinks(&adapters, &routes, &[]), vec![3, 5]);
        assert_eq!(
            sole_default_route_holder(&adapters, &routes, true, &[]),
            Some(5)
        );
    }

    /// A PPPoE uplink beside wg-quick or a Tailscale exit node: the tunnel's
    /// default sits in its own table, which only its own rule leads to. Counted
    /// as a second holder, it made the uplink one more foreign tunnel.
    #[test]
    fn a_default_in_another_programs_table_does_not_unseat_the_uplink() {
        let mut ppp = link(3, "ppp0");
        ppp.interface_type = InterfaceType::Tunnel;
        let adapters = [ppp, link(7, "wg0")];
        let mut tunnel_default = route([0, 0, 0, 0], 0, [0, 0, 0, 0], 7);
        tunnel_default.table = RouteTableRef::Tagged(51820);
        let routes = [route([0, 0, 0, 0], 0, [0, 0, 0, 0], 3), tunnel_default];
        assert_eq!(
            sole_default_route_holder(&adapters, &routes, false, &[]),
            Some(3)
        );
        assert_eq!(structural_uplinks(&adapters, &routes, &[]), vec![3]);
    }

    #[test]
    fn a_link_that_is_down_holds_nothing() {
        let mut down = link(5, "Old Wi-Fi");
        down.oper_status = IfOperStatus::Down;
        let adapters = [link(3, "Ethernet"), down];
        let routes = [
            route([0, 0, 0, 0], 0, [192, 168, 1, 1], 3),
            route([0, 0, 0, 0], 0, [192, 168, 2, 1], 5),
        ];
        assert_eq!(
            sole_default_route_holder(&adapters, &routes, false, &[]),
            Some(3)
        );
    }
}

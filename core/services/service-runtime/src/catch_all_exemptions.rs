//! What a blanket block must never cut.
//!
//! The catch-all kill-switch blocks everything that is not on the tunnel. Two
//! things must escape it or the block is a trap rather than a guard: the
//! addresses of the tunnel's own server — block those and the tunnel can never
//! reconnect, so the outage that armed the guard becomes permanent — and the
//! subnets the machine is directly attached to, which carry the LAN, the local
//! router and DHCP renewal and never reach a provider at all.
//!
//! Both are read off the ROUTE TABLE rather than guessed. A VPN client installs
//! a host route to each server endpoint via the real gateway (its own encrypted
//! traffic has to leave outside the tunnel), and a directly-attached subnet is
//! an on-link route with no next hop. The derivations themselves already existed
//! for the Windows path and are pure functions over
//! [`RouteEntry`][nrr_platform_api::types::RouteEntry] — what was missing was a
//! caller that reads the facts on a platform where the route table is a port.

use std::net::Ipv4Addr;

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::types::RouteEntry;

use crate::route_reconciler::{
    bootstrap_server_ips, primary_local_subnets, virtual_machine_local_subnets,
};

/// The escapes a blanket block grants, for one principal's bindings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatchAllExemptions {
    /// Tunnel-server endpoints, from the bootstrap host routes.
    pub server_ips: Vec<Ipv4Addr>,
    /// Subnets this machine is directly attached to over the primary link, plus
    /// the private segments of its own virtual-machine adapters.
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
}

impl CatchAllExemptions {
    /// Whether a blanket block may be armed at all.
    ///
    /// Without a server address the block would hold the tunnel's own reconnect
    /// shut, and nothing inside the machine could lift it. Refusing to arm is
    /// the lesser failure: traffic leaks, and the user is told.
    #[must_use]
    pub fn can_arm(&self) -> bool {
        !self.server_ips.is_empty()
    }
}

/// Derive the exemptions from a pass's facts and one principal's bindings.
///
/// `primary_name` / `secondary_name` are the display names the user bound, the
/// same ones the enforcer resolves links by. `None` for either — an unbound or
/// currently absent link — yields no exemptions, and therefore no arming: a
/// block-all planned without knowing which link is which is a block on
/// everything.
#[must_use]
pub fn collect_exemptions(
    routes: &[RouteEntry],
    adapters: &[AdapterInfo],
    primary_name: Option<&str>,
    secondary_name: Option<&str>,
) -> CatchAllExemptions {
    let (Some(primary), Some(secondary)) = (
        primary_name.and_then(|n| adapter_by_name(adapters, n)),
        secondary_name.and_then(|n| adapter_by_name(adapters, n)),
    ) else {
        return CatchAllExemptions::default();
    };
    // The gateway of the link that reaches the provider. A primary with no
    // gateway is a machine with no way out, and a bootstrap route cannot be
    // recognised without one.
    let Some(primary_gateway) = primary.gateways.first().copied() else {
        return CatchAllExemptions::default();
    };

    let mut local_subnets = primary_local_subnets(routes, primary.index);
    for subnet in virtual_machine_local_subnets(routes, adapters, Some(secondary.index)) {
        if !local_subnets.contains(&subnet) {
            local_subnets.push(subnet);
        }
    }

    CatchAllExemptions {
        server_ips: bootstrap_server_ips(routes, secondary.index, Some(primary_gateway)),
        local_subnets,
    }
}

/// Match a bound name against what the machine calls its links now — the link
/// name first, the OS-level name second, exactly as the route applier does.
fn adapter_by_name<'a>(adapters: &'a [AdapterInfo], name: &str) -> Option<&'a AdapterInfo> {
    adapters
        .iter()
        .find(|a| a.friendly_name == name || a.adapter_name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::adapters::{IfOperStatus, InterfaceType};
    use nrr_platform_api::RouteTableRef;

    fn adapter(index: u32, name: &str, gateways: Vec<Ipv4Addr>) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: format!("dev{index}"),
            description: String::new(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: InterfaceType::Ethernet,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 168, 1, 10)],
            gateways,
        }
    }

    fn route(dst: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr, index: u32) -> RouteEntry {
        RouteEntry {
            destination: dst,
            prefix_length: prefix,
            next_hop,
            interface_index: index,
            metric: 0,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    /// The shape a real machine has with a tunnel up: a connected LAN subnet on
    /// the primary and a host route to the server via the primary gateway.
    fn machine() -> (Vec<RouteEntry>, Vec<AdapterInfo>) {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        (
            vec![
                route(Ipv4Addr::new(192, 168, 1, 0), 24, Ipv4Addr::UNSPECIFIED, 2),
                route(Ipv4Addr::new(203, 0, 113, 7), 32, gw, 2),
                route(Ipv4Addr::UNSPECIFIED, 0, gw, 2),
            ],
            vec![adapter(2, "eth0", vec![gw]), adapter(5, "tun0", Vec::new())],
        )
    }

    #[test]
    fn the_server_route_and_the_lan_become_exemptions() {
        let (routes, adapters) = machine();
        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));

        assert_eq!(ex.server_ips, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
        assert!(ex.can_arm());
    }

    /// The failure that matters: with no server address the guard would seal the
    /// tunnel's own reconnect, so it must refuse to arm rather than arm blind.
    #[test]
    fn without_a_server_route_the_block_must_not_arm() {
        let (mut routes, adapters) = machine();
        routes.retain(|r| r.prefix_length != 32);

        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));

        assert!(ex.server_ips.is_empty());
        assert!(!ex.can_arm());
    }

    #[test]
    fn an_unbound_link_yields_nothing() {
        let (routes, adapters) = machine();
        assert!(!collect_exemptions(&routes, &adapters, Some("eth0"), None).can_arm());
        assert!(!collect_exemptions(&routes, &adapters, None, Some("tun0")).can_arm());
    }

    /// A primary with no gateway cannot produce a bootstrap route, and calling
    /// anything a server on that machine would be a guess.
    #[test]
    fn a_primary_without_a_gateway_yields_nothing() {
        let (routes, mut adapters) = machine();
        adapters[0].gateways.clear();

        assert!(!collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0")).can_arm());
    }
}

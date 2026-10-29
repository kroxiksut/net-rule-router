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

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nrr_platform_api::adapters::AdapterInfo;
use nrr_platform_api::types::RouteEntry;
use nrr_shared::ip_block::IpBlock;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

use crate::ipc_handlers::event_bus::EventBus;

use crate::route_reconciler::{
    bootstrap_server_ips, bootstrap_server_ips_v6, exemptible_local_subnets, primary_gateway_v6,
    virtual_machine_local_subnets,
};

/// The escapes a blanket block grants, for one principal's bindings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatchAllExemptions {
    /// Tunnel-server endpoints, from the bootstrap host routes.
    pub server_ips: Vec<Ipv4Addr>,
    /// The private part of the subnets this machine is directly attached to
    /// over the primary link, plus the private segments of its own
    /// virtual-machine adapters.
    pub local_subnets: Vec<(Ipv4Addr, u8)>,
    /// Tunnel-server endpoints reached over IPv6, from the `/128` bootstrap
    /// routes. Empty on a machine with no v6 — which is not a reason to refuse
    /// to arm, because the tunnel then bootstraps over v4.
    pub server_ips_v6: Vec<Ipv6Addr>,
    /// The private part of the prefixes the primary link is directly attached
    /// to over IPv6.
    pub local_subnets_v6: Vec<(Ipv6Addr, u8)>,
    /// Segments the primary link reported that are too wide to be a local
    /// network. Nothing of them is exempt; the caller tells the user
    /// (`StatusUpdateEvent::LocalNetworkTooWide`), named by the primary's
    /// display name.
    pub too_wide: Vec<IpBlock>,
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
    let Some((primary, secondary, primary_gateway)) =
        resolve_links(adapters, primary_name, secondary_name)
    else {
        return CatchAllExemptions::default();
    };

    let attached = exemptible_local_subnets(routes, primary.index);
    let mut local_subnets = attached.v4;
    for subnet in virtual_machine_local_subnets(routes, adapters, secondary.map(|s| s.index)) {
        if !local_subnets.contains(&subnet) {
            local_subnets.push(subnet);
        }
    }
    // A tunnel that removes its link on disconnect leaves no route on it to set
    // apart; no interface is numbered 0 on either OS.
    let tunnel = secondary.map_or(0, |s| s.index);

    CatchAllExemptions {
        server_ips: bootstrap_server_ips(routes, tunnel, primary_gateway),
        local_subnets,
        server_ips_v6: bootstrap_server_ips_v6(
            routes,
            tunnel,
            primary_gateway_v6(routes, primary.index),
        ),
        local_subnets_v6: attached.v6,
        too_wide: attached.too_wide,
    }
}

/// The tunnels the user runs beside the bound ones, by the name the egress pin
/// uses, each with the networks its own routes carry. Which links are foreign
/// is the route coordinator's definition, and so is which links are ours.
///
/// `routes` is `None` when the table could not be read. Then nothing is
/// foreign: without the table the uplink cannot be told from a tunnel by name,
/// and a PPPoE uplink spared as a "tunnel" is a block-all with a hole in it.
#[must_use]
pub fn foreign_tunnel_links(
    routes: Option<&[RouteEntry]>,
    adapters: &[AdapterInfo],
    primary: Option<&crate::per_sid_orchestrator::PerSidBinding>,
    secondary: Option<&crate::per_sid_orchestrator::PerSidBinding>,
) -> Vec<crate::enforcement_planner::ForeignTunnelLink> {
    let Some(routes) = routes else {
        return Vec::new();
    };
    let ours = crate::route_coordinator::own_link_indexes(
        adapters,
        &[],
        primary.into_iter().chain(secondary),
    );
    let additional = crate::route_coordinator::own_link_indexes(adapters, &[], secondary);
    let foreign =
        crate::route_coordinator::foreign_tunnel_indexes(adapters, &ours, &additional, routes);
    adapters
        .iter()
        .filter(|a| foreign.contains(&a.index))
        .map(|a| crate::enforcement_planner::ForeignTunnelLink {
            name: if a.friendly_name.is_empty() {
                a.adapter_name.clone()
            } else {
                a.friendly_name.clone()
            },
            networks: crate::route_codegen::network_routes::foreign_tunnel_blocks(
                routes,
                &[a.index],
            ),
        })
        .collect()
}

/// How often one user hears about one too-wide segment: the passes run at
/// reconcile cadence, and the network does not change its mind between them.
pub const TOO_WIDE_NOTICE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Tells a user that the main link reports a segment too wide to be a local
/// network — half the internet, on a hostile access point — and that leak
/// protection keeps blocking it. One latch per `sid|adapter|network`, shared
/// by both backends' publishers so the user hears it once either way.
#[derive(Default)]
pub struct TooWideLocalNetworkNotices {
    notified: Mutex<HashMap<String, Instant>>,
}

impl TooWideLocalNetworkNotices {
    /// Log and push every segment of `too_wide` whose latch is open at `now`;
    /// returns how many were published.
    pub fn publish(
        &self,
        bus: &EventBus,
        sid: &str,
        adapter_name: &str,
        too_wide: &[IpBlock],
        now: Instant,
    ) -> usize {
        let mut published = 0;
        for segment in too_wide {
            let network = segment.to_string();
            let key = format!("{sid}|{adapter_name}|{network}");
            {
                let mut seen = self.notified.lock().unwrap_or_else(|p| p.into_inner());
                if seen
                    .get(&key)
                    .is_some_and(|last| now.duration_since(*last) < TOO_WIDE_NOTICE_WINDOW)
                {
                    continue;
                }
                seen.insert(key, now);
            }
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "route-local-network-too-wide",
                sid = %sid,
                adapter = %adapter_name,
                network = %network,
                "the main link reports a connected network too wide to be local; it is not exempted from leak protection",
            );
            bus.publish_for(
                sid,
                StatusUpdateEvent::LocalNetworkTooWide {
                    sid: sid.to_string(),
                    adapter_name: adapter_name.to_string(),
                    network,
                },
            );
            published += 1;
        }
        published
    }
}

/// Whether [`collect_exemptions`] can read anything for these bindings: the
/// primary present and a tunnel bound, present or not — the LAN
/// is read off the primary alone.
#[must_use]
pub fn links_resolve(
    adapters: &[AdapterInfo],
    primary_name: Option<&str>,
    secondary_name: Option<&str>,
) -> bool {
    resolve_links(adapters, primary_name, secondary_name).is_some()
}

/// The bound links and the primary's gateway. A primary without an IPv4 next
/// hop still carries traffic (a PPP link routes on-link, OpenVPN without `def1`
/// moves the default onto the tunnel), so it resolves; only the bootstrap
/// routes, which are recognised by that next hop, go unread.
fn resolve_links<'a>(
    adapters: &'a [AdapterInfo],
    primary_name: Option<&str>,
    secondary_name: Option<&str>,
) -> Option<(&'a AdapterInfo, Option<&'a AdapterInfo>, Option<Ipv4Addr>)> {
    let primary = primary_name.and_then(|n| adapter_by_name(adapters, n))?;
    let secondary = adapter_by_name(adapters, secondary_name?);
    Some((primary, secondary, primary.gateways.first().copied()))
}

/// The adapter a bound display name refers to, matched the way the route
/// applier matches it: the link name first, the OS-level name second.
#[must_use]
pub fn bound_adapter<'a>(
    adapters: &'a [AdapterInfo],
    name: Option<&str>,
) -> Option<&'a AdapterInfo> {
    name.and_then(|n| adapter_by_name(adapters, n))
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
    use std::net::IpAddr;

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
            ipv6_addresses: Vec::new(),
            gateways,
        }
    }

    fn route(dst: Ipv4Addr, prefix: u8, next_hop: Ipv4Addr, index: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(dst),
            prefix_length: prefix,
            next_hop: IpAddr::V4(next_hop),
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
    }

    /// libvirt, Podman, LXD and Docker Compose bridges carry no driver name on
    /// Linux, only the link name. Under "everything" the user's own virtual
    /// machines and containers stay reachable, as on Windows.
    #[test]
    fn a_linux_bridge_for_local_machines_is_a_local_network() {
        let (mut routes, mut adapters) = machine();
        for (index, name, net) in [
            (7, "virbr0", Ipv4Addr::new(192, 168, 122, 0)),
            (8, "br-3f2a9c1d", Ipv4Addr::new(172, 18, 0, 0)),
        ] {
            let mut bridge = adapter(index, name, Vec::new());
            let octets = net.octets();
            bridge.ipv4_addresses = vec![Ipv4Addr::new(octets[0], octets[1], octets[2], 1)];
            adapters.push(bridge);
            routes.push(route(
                net,
                if index == 7 { 24 } else { 16 },
                Ipv4Addr::UNSPECIFIED,
                index,
            ));
        }
        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));
        assert!(
            ex.local_subnets
                .contains(&(Ipv4Addr::new(192, 168, 122, 0), 24)),
            "{:?}",
            ex.local_subnets
        );
        assert!(
            ex.local_subnets
                .contains(&(Ipv4Addr::new(172, 18, 0, 0), 16)),
            "{:?}",
            ex.local_subnets
        );
    }

    #[test]
    fn without_a_server_route_the_block_must_not_arm() {
        let (mut routes, adapters) = machine();
        routes.retain(|r| r.prefix_length != 32);

        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));

        assert!(ex.server_ips.is_empty());
    }

    #[test]
    fn an_unbound_link_yields_nothing() {
        let (routes, adapters) = machine();
        let none = CatchAllExemptions::default();
        assert_eq!(
            collect_exemptions(&routes, &adapters, Some("eth0"), None),
            none
        );
        assert_eq!(
            collect_exemptions(&routes, &adapters, None, Some("tun0")),
            none
        );
    }

    /// WireGuard and AmneziaWG remove their link on disconnect. The LAN comes
    /// off the primary, so the guard keeps its holes while the tunnel is gone.
    #[test]
    fn a_tunnel_whose_link_is_gone_still_exempts_the_lan_and_the_server() {
        let (routes, mut adapters) = machine();
        adapters.retain(|a| a.friendly_name != "tun0");

        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));

        assert_eq!(ex.server_ips, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
        assert!(links_resolve(&adapters, Some("eth0"), Some("tun0")));
        assert!(!links_resolve(&adapters, None, Some("tun0")));
    }

    /// The café access point hands the main link a `/1`. The blanket block
    /// keeps it blocked — only the real private segment is let through — and
    /// the refused segment is reported for the user to hear about.
    #[test]
    fn a_half_internet_segment_is_not_exempted_and_is_reported() {
        let (mut routes, adapters) = machine();
        routes.push(route(Ipv4Addr::UNSPECIFIED, 1, Ipv4Addr::UNSPECIFIED, 2));
        routes.push(route(
            Ipv4Addr::new(128, 0, 0, 0),
            1,
            Ipv4Addr::UNSPECIFIED,
            2,
        ));

        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));

        assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
        assert_eq!(
            ex.too_wide,
            vec![
                IpBlock::parse("0.0.0.0/1").expect("block"),
                IpBlock::parse("128.0.0.0/1").expect("block"),
            ]
        );
    }

    fn bound(name: &str) -> crate::per_sid_orchestrator::PerSidBinding {
        crate::per_sid_orchestrator::PerSidBinding {
            stable_id: format!("linux-link:{name}"),
            display_name: name.to_owned(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        }
    }

    /// `foreign_tunnel_links` for `eth0` bound as the primary and `tun0` as
    /// the additional route.
    fn foreign_beside_bound(
        routes: Option<&[RouteEntry]>,
        adapters: &[AdapterInfo],
    ) -> Vec<crate::enforcement_planner::ForeignTunnelLink> {
        foreign_tunnel_links(routes, adapters, Some(&bound("eth0")), Some(&bound("tun0")))
    }

    fn route_on(dest: [u8; 4], prefix: u8, ifindex: u32) -> RouteEntry {
        RouteEntry {
            destination: IpAddr::V4(Ipv4Addr::from(dest)),
            prefix_length: prefix,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: ifindex,
            metric: 50,
            is_ours: false,
            table: RouteTableRef::Main,
        }
    }

    /// A corporate tunnel beside the bound ones is named with the networks its
    /// own routes carry; the bound tunnel and the uplink never are, and a
    /// redirect pair is no network of the tunnel's.
    #[test]
    fn a_tunnel_beside_the_bound_ones_is_named_as_foreign() {
        let (mut routes, mut adapters) = machine();
        adapters.push(adapter(7, "OpenVPN corp", Vec::new()));
        routes.push(route_on([10, 77, 0, 0], 16, 7));
        routes.push(route_on([0, 0, 0, 0], 1, 7));
        routes.push(route_on([128, 0, 0, 0], 1, 7));

        let links = foreign_beside_bound(Some(&routes), &adapters);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name, "OpenVPN corp");
        assert_eq!(
            links[0].networks,
            vec![IpBlock::parse("10.77.0.0/16").expect("block")]
        );
    }

    /// An ISP tunnel that also holds a default route beside the uplink is
    /// foreign, but only the networks it names itself are its own: the default
    /// route is no network to spare.
    #[test]
    fn a_default_holder_beside_the_uplink_is_named_with_its_specific_networks_only() {
        let (mut routes, mut adapters) = machine();
        adapters.push(adapter(7, "l2tp-isp", Vec::new()));
        routes.push(route_on([0, 0, 0, 0], 0, 7));
        routes.push(route_on([10, 9, 0, 0], 24, 7));

        let links = foreign_beside_bound(Some(&routes), &adapters);
        assert!(
            links.iter().any(|l| l.name == "l2tp-isp"),
            "the tunnel is named: {links:?}"
        );
        for link in &links {
            assert!(link.networks.iter().all(|n| n.prefix_len() > 0), "{link:?}");
        }
        assert!(links
            .iter()
            .filter(|l| l.name == "l2tp-isp")
            .all(|l| l.networks == vec![IpBlock::parse("10.9.0.0/24").expect("block")]));
    }

    /// Without the route table no link can be told apart from the uplink, so
    /// none is foreign: a PPPoE uplink spared as a tunnel would open the
    /// block-all.
    #[test]
    fn an_unreadable_route_table_names_no_foreign_tunnel() {
        let (_, mut adapters) = machine();
        adapters.push(adapter(7, "ppp0", Vec::new()));
        adapters.push(adapter(8, "OpenVPN corp", Vec::new()));

        assert!(foreign_beside_bound(None, &adapters).is_empty());
    }

    /// A home uplink delivered over PPP, left unbound, beside our bound full
    /// tunnel: both hold a default, but ours says nothing about the uplink, so
    /// `ppp0` is the uplink and no egress is opened on it.
    #[test]
    fn an_unbound_ppp_uplink_beside_our_full_tunnel_is_not_foreign() {
        let gw = Ipv4Addr::new(100, 64, 0, 1);
        let adapters = vec![adapter(3, "ppp0", vec![gw]), adapter(5, "tun0", Vec::new())];
        for ours in [
            vec![route_on([0, 0, 0, 0], 0, 5)],
            vec![route_on([0, 0, 0, 0], 1, 5), route_on([128, 0, 0, 0], 1, 5)],
        ] {
            let mut routes = vec![
                route(Ipv4Addr::UNSPECIFIED, 0, gw, 3),
                route(Ipv4Addr::new(203, 0, 113, 7), 32, gw, 3),
            ];
            routes.extend(ours);
            let links = foreign_tunnel_links(Some(&routes), &adapters, None, Some(&bound("tun0")));
            assert!(links.is_empty(), "{links:?}");
            // Our tunnel replaced the provider's default: the route to its
            // server still names `ppp0` the uplink.
            routes.retain(|r| !(r.interface_index == 3 && r.prefix_length == 0));
            let links = foreign_tunnel_links(Some(&routes), &adapters, None, Some(&bound("tun0")));
            assert!(links.is_empty(), "provider default replaced: {links:?}");
        }
    }

    /// A primary with no gateway cannot produce a bootstrap route, and calling
    /// anything a server on that machine would be a guess. Its LAN is still
    /// read, so the guard that arms there does not cut it.
    #[test]
    fn a_primary_without_a_gateway_names_no_server_but_keeps_its_lan() {
        let (routes, mut adapters) = machine();
        adapters[0].gateways.clear();

        let ex = collect_exemptions(&routes, &adapters, Some("eth0"), Some("tun0"));
        assert!(ex.server_ips.is_empty());
        assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
        assert!(links_resolve(&adapters, Some("eth0"), Some("tun0")));
    }
}

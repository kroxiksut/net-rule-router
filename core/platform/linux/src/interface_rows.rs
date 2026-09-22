//! The Linux live enumeration behind the "Interfaces & routes" screen.
//!
//! Mirror of `nrr_platform_windows::interface_rows`, and deliberately as thin:
//! the row type and every judgement about a row live in
//! [`nrr_platform_api::interface_rows`]. What is here is only where this OS
//! keeps the facts — links from `/sys/class/net` (via [`crate::adapters`]), the
//! route table from rtnetlink, per-link resolvers from `resolvectl`.
//!
//! Until this existed the service answered every interfaces request with the
//! deterministic placeholder set, so a Linux user picked their routes from a
//! list of adapters their machine does not have.

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use nrr_platform_api::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
use nrr_platform_api::interface_rows::{
    apply_external_ip_probes, build_derived_assessment, build_observed_facts,
    derive_forwarding_next_hop, fallback_rows, is_bluetooth_like_interface,
    preferred_display_address, unknown_recommendation, BasicAvailabilityStatus, InterfaceRouteRow,
    InterfacesDataSource,
};
use nrr_shared::RouteSelectionState;

/// Enumerate the machine's links and enrich each into an [`InterfaceRouteRow`].
///
/// `probe_external_ip` decides whether each adapter is additionally asked for
/// the address the outside world sees behind it — opt-in, because the probe
/// sends a datagram to a third party. Every background refresh passes `false`
/// and stays network-silent.
///
/// An empty or unreadable enumeration answers with the deterministic
/// placeholder set, tagged as such: rows the GUI presents as this machine's
/// adapters must be this machine's adapters.
pub fn collect_interfaces_rows(
    probe_external_ip: bool,
) -> (InterfacesDataSource, Vec<InterfaceRouteRow>) {
    let adapters = match crate::adapters::collect_adapter_infos() {
        Ok(adapters) if !adapters.is_empty() => adapters,
        Ok(_) => {
            tracing::warn!(
                target: "nrr::interface-rows",
                "/sys/class/net listed no interfaces — answering with the placeholder set",
            );
            return (InterfacesDataSource::FallbackMock, fallback_rows());
        }
        Err(error) => {
            tracing::warn!(
                target: "nrr::interface-rows",
                %error,
                "the link enumeration failed — answering with the placeholder set",
            );
            return (InterfacesDataSource::FallbackMock, fallback_rows());
        }
    };

    let mut rows = build_rows(&adapters, &link_dns_servers(), forwarding_capable_indexes());
    rows.sort_by(|left, right| {
        left.adapter_name
            .to_ascii_lowercase()
            .cmp(&right.adapter_name.to_ascii_lowercase())
    });
    if probe_external_ip {
        apply_external_ip_probes(&mut rows);
    }
    (InterfacesDataSource::LinuxLive, rows)
}

/// The pure half: links plus the two lookups in, rows out. Free of the OS so
/// the mapping is tested on any host — the readers below are the only part that
/// needs a Linux to run on.
fn build_rows(
    adapters: &[AdapterInfo],
    dns_by_link: &HashMap<String, String>,
    forwarding: Option<HashSet<u32>>,
) -> Vec<InterfaceRouteRow> {
    adapters
        .iter()
        // No route can leave through it, so it is no candidate for either role.
        .filter(|adapter| adapter.interface_type != InterfaceType::Loopback)
        .map(|adapter| row_for(adapter, dns_by_link, forwarding.as_ref()))
        .collect()
}

fn row_for(
    adapter: &AdapterInfo,
    dns_by_link: &HashMap<String, String>,
    forwarding: Option<&HashSet<u32>>,
) -> InterfaceRouteRow {
    let name = match adapter.friendly_name.trim() {
        "" => adapter.adapter_name.trim(),
        named => named,
    };
    let availability = availability_of(adapter.oper_status);
    let addresses = adapter
        .ipv4_addresses
        .iter()
        .map(|v4| IpAddr::V4(*v4))
        .chain(adapter.ipv6_addresses.iter().map(|v6| IpAddr::V6(*v6)))
        .collect::<Vec<_>>();
    let local_ip = preferred_display_address(&addresses).unwrap_or_else(|| "-".to_string());
    let gateway = adapter
        .gateways
        .first()
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "-".to_string());
    let dns_servers = dns_by_link
        .get(name)
        .cloned()
        .unwrap_or_else(|| "-".to_string());
    // The same reading as the Windows side: to the enumeration, "has a default
    // route" means a gateway is present. Whether traffic can actually leave is
    // `has_forwarding_path` below, which is what the gateway-less tunnel needs.
    let has_default_route = !adapter.gateways.is_empty();
    let interface_type = type_slug(adapter.interface_type);
    let observed_facts = build_observed_facts(availability, &local_ip, &gateway);
    let derived_assessment = build_derived_assessment(
        name,
        interface_type,
        &adapter.description,
        name,
        &gateway,
        &local_ip,
        has_default_route,
        observed_facts.connectivity_state,
    );

    InterfaceRouteRow {
        persistent_id: persistent_id(name, adapter),
        adapter_name: name.to_string(),
        // The field is named for the OS it was born on. Here the link name is
        // both the stable name and the one the user sees, so it fills both.
        windows_name: name.to_string(),
        interface_description: adapter.description.clone(),
        interface_type: interface_type.to_string(),
        is_bluetooth_like: is_bluetooth_like_interface(name, &adapter.description, name),
        local_ip,
        gateway,
        dns_servers,
        has_default_route,
        has_forwarding_path: forwarding
            .map(|indexes| has_default_route || indexes.contains(&adapter.index)),
        // The addresses arrive with the links, from the same read: there is no
        // second source here that could have failed on its own.
        runtime_data_unavailable: false,
        availability_status: availability,
        observed_facts,
        derived_assessment,
        recommendation: unknown_recommendation(),
        selected_role: None,
        route_state: RouteSelectionState::NotSelected,
    }
}

/// What a saved route binding is keyed on. The link name leads: it is what the
/// user renames deliberately and what every other tool on this OS calls the
/// interface. The ifindex+MAC pair is the fallback for a link with no name.
fn persistent_id(name: &str, adapter: &AdapterInfo) -> String {
    if !name.is_empty() {
        return format!("linux-link:{name}");
    }
    match adapter.mac {
        Some(mac) => format!(
            "linux-ifindex-mac:{}:{}",
            adapter.index,
            mac.iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join("-")
        ),
        None => format!("linux-ifindex:{}", adapter.index),
    }
}

fn availability_of(status: IfOperStatus) -> BasicAvailabilityStatus {
    match status {
        IfOperStatus::Up => BasicAvailabilityStatus::Available,
        IfOperStatus::Down | IfOperStatus::NotPresent | IfOperStatus::LowerLayerDown => {
            BasicAvailabilityStatus::Unavailable
        }
        // Testing / dormant / unknown are not "down": something is there and it
        // may carry traffic in a moment. That is what the third bucket is for.
        IfOperStatus::Testing | IfOperStatus::Dormant | IfOperStatus::Unknown => {
            BasicAvailabilityStatus::RequiresCheck
        }
    }
}

/// The slug the GUI localises (`interface.type.*`). Shared with the Windows
/// enumeration on purpose: one vocabulary, or the same Wi-Fi card reads as two
/// different kinds of device depending on which OS enumerated it.
fn type_slug(interface_type: InterfaceType) -> &'static str {
    match interface_type {
        InterfaceType::Ethernet => "ethernet",
        InterfaceType::Wireless => "wireless",
        InterfaceType::Loopback => "loopback",
        InterfaceType::Tunnel => "tunnel",
        InterfaceType::Other(_) => "other",
    }
}

/// Which links can actually forward traffic out, by ifindex.
///
/// `None` when the route table could not be read at all — then every row
/// reports "not evaluated" rather than a false "cannot forward", which is what
/// a gateway-less WireGuard link would otherwise be labelled.
fn forwarding_capable_indexes() -> Option<HashSet<u32>> {
    use nrr_platform_api::route_table::RouteTablePort;

    let routes = match crate::LinuxApi.get_ip_forward_table() {
        Ok(routes) => routes,
        Err(error) => {
            tracing::warn!(
                target: "nrr::interface-rows",
                %error,
                "route table unreadable — forwarding capability stays unevaluated for every link",
            );
            return None;
        }
    };
    let candidates = routes
        .iter()
        .map(|route| route.interface_index)
        .collect::<HashSet<_>>();
    Some(
        candidates
            .into_iter()
            .filter(|index| derive_forwarding_next_hop(&routes, *index).is_some())
            .collect(),
    )
}

/// Per-link resolvers, link name -> servers as the row displays them.
///
/// `resolvectl` is the only interface-aware answer on this OS: `/etc/resolv.conf`
/// is machine-wide, and attributing its servers to one link would be a guess the
/// user cannot check. A machine without systemd-resolved therefore shows no DNS
/// rather than an invented one.
fn link_dns_servers() -> HashMap<String, String> {
    let Ok(out) = crate::command::output_with_timeout(
        "resolvectl",
        &["dns"],
        crate::command::DEFAULT_COMMAND_TIMEOUT,
    ) else {
        return HashMap::new();
    };
    if !out.status.success() {
        return HashMap::new();
    }
    parse_resolvectl_dns(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `resolvectl dns`: `Link 3 (wlp3s0): 192.0.2.1 192.0.2.2`. A link with
/// no servers is left out entirely — an empty string would render as a column
/// that says nothing, which is what a missing entry already renders as.
fn parse_resolvectl_dns(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("Link ") else {
            continue;
        };
        let (Some(open), Some(close)) = (rest.find('('), rest.find(')')) else {
            continue;
        };
        if close <= open + 1 {
            continue;
        }
        let name = rest[open + 1..close].trim().to_string();
        let servers = rest[close + 1..]
            .trim_start()
            .strip_prefix(':')
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(", ");
        if !name.is_empty() && !servers.is_empty() {
            out.insert(name, servers);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn adapter(name: &str, index: u32) -> AdapterInfo {
        AdapterInfo {
            index,
            adapter_name: name.to_string(),
            description: "iwlwifi".to_string(),
            friendly_name: name.to_string(),
            mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            interface_type: InterfaceType::Wireless,
            oper_status: IfOperStatus::Up,
            ipv4_addresses: vec![Ipv4Addr::new(192, 0, 2, 10)],
            ipv6_addresses: vec![],
            gateways: vec![Ipv4Addr::new(192, 0, 2, 1)],
        }
    }

    #[test]
    fn a_live_link_becomes_a_row_carrying_its_own_facts() {
        let dns = HashMap::from([("wlan0".to_string(), "192.0.2.1".to_string())]);
        let rows = build_rows(&[adapter("wlan0", 3)], &dns, Some(HashSet::from([3])));
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.adapter_name, "wlan0");
        assert_eq!(row.persistent_id, "linux-link:wlan0");
        assert_eq!(row.interface_type, "wireless");
        assert_eq!(row.local_ip, "192.0.2.10");
        assert_eq!(row.gateway, "192.0.2.1");
        assert_eq!(row.dns_servers, "192.0.2.1");
        assert!(row.has_default_route);
        assert_eq!(row.has_forwarding_path, Some(true));
        assert!(!row.runtime_data_unavailable);
        assert_eq!(row.availability_status, BasicAvailabilityStatus::Available);
    }

    /// The gateway-less tunnel: nothing to show in the gateway column, and the
    /// route table is what says traffic still leaves through it.
    #[test]
    fn a_gatewayless_link_is_still_forwarding_when_the_routes_say_so() {
        let mut tunnel = adapter("wg0", 7);
        tunnel.interface_type = InterfaceType::Tunnel;
        tunnel.gateways.clear();
        let rows = build_rows(&[tunnel], &HashMap::new(), Some(HashSet::from([7])));
        assert_eq!(rows[0].gateway, "-");
        assert!(!rows[0].has_default_route);
        assert_eq!(rows[0].has_forwarding_path, Some(true));
        assert_eq!(rows[0].dns_servers, "-");
    }

    /// An unreadable route table must not label a healthy link unusable.
    #[test]
    fn an_unreadable_route_table_leaves_forwarding_unevaluated() {
        let rows = build_rows(&[adapter("eth0", 2)], &HashMap::new(), None);
        assert_eq!(rows[0].has_forwarding_path, None);
    }

    #[test]
    fn loopback_is_no_candidate_for_a_route() {
        let mut lo = adapter("lo", 1);
        lo.interface_type = InterfaceType::Loopback;
        assert!(build_rows(&[lo], &HashMap::new(), None).is_empty());
    }

    #[test]
    fn a_link_with_only_a_v6_address_still_shows_one() {
        let mut v6_only = adapter("eth0", 2);
        v6_only.ipv4_addresses.clear();
        v6_only.ipv6_addresses = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
        let rows = build_rows(&[v6_only], &HashMap::new(), None);
        assert_eq!(rows[0].local_ip, "2001:db8::1");
    }

    #[test]
    fn resolvectl_links_are_read_per_interface() {
        let parsed = parse_resolvectl_dns(
            "Global:\nLink 2 (enp4s0f1):\nLink 3 (wlp3s0): 192.0.2.1 192.0.2.2\n",
        );
        assert_eq!(
            parsed.get("wlp3s0").map(String::as_str),
            Some("192.0.2.1, 192.0.2.2")
        );
        // A link with no servers is absent, not present-and-empty.
        assert!(!parsed.contains_key("enp4s0f1"));
        assert!(!parsed.contains_key("Global"));
    }
}

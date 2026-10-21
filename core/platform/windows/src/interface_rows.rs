//! The Windows live enumeration behind [`InterfaceRowsPort`]: the stable
//! identity snapshot (`crate::interface_manager::adapters_snapshot`) merged
//! with per-adapter runtime IP/gateway/DNS data from the same `GetAdaptersAddresses`
//! walker (`crate::win32_ffi::adapters`). The row type and every judgement about a row are the neutral ones re-exported
//! below.

pub use nrr_platform_api::interface_rows::*;

#[cfg(windows)]
use nrr_shared::RouteSelectionState;

/// This host's adapters, enumerated live.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsInterfaceRows;

impl InterfaceRowsPort for WindowsInterfaceRows {
    /// Off Windows, or when the live enumeration is empty, the placeholder set.
    fn collect_rows(
        &self,
        probe_external_ip: bool,
    ) -> (InterfacesDataSource, Vec<InterfaceRouteRow>) {
        let snapshot = crate::interface_manager::adapters_snapshot();
        #[cfg(windows)]
        if matches!(
            snapshot.data_source,
            nrr_shared::AdapterSnapshotDataSource::WindowsLive
        ) {
            let rows = collect_windows_rows_from_snapshot(snapshot.adapters, probe_external_ip);
            if !rows.is_empty() {
                return (InterfacesDataSource::WindowsLive, rows);
            }
        }

        // The placeholder set is offline by contract: there is no real adapter
        // behind it to probe.
        #[cfg(not(windows))]
        let _ = (probe_external_ip, snapshot);

        (InterfacesDataSource::FallbackMock, fallback_rows())
    }
}

#[cfg(windows)]
fn collect_windows_rows_from_snapshot(
    adapters: Vec<nrr_shared::AdapterSnapshotEntry>,
    probe_external_ip: bool,
) -> Vec<InterfaceRouteRow> {
    // An IP Helper failure leaves every row without IP/gateway/DNS. There is no
    // second source to repair it from, so the rows say so instead: the failure
    // is carried on the row as `runtime_data_unavailable`, and a consumer that
    // blocks on a missing local IP can tell it from a real one.
    let mut runtime_data_unavailable = false;
    let runtime_by_adapter = match collect_windows_runtime_data() {
        Ok(items) => items
            .into_iter()
            .map(|item| {
                (
                    item.adapter_name.to_ascii_lowercase(),
                    (
                        item.local_ip,
                        item.gateway,
                        item.dns_servers,
                        item.has_default_route,
                    ),
                )
            })
            .collect::<std::collections::HashMap<_, _>>(),
        Err(error) => {
            runtime_data_unavailable = true;
            tracing::warn!(
                target: "nrr::interface-rows",
                msg_key = "win-iface-runtime-data-unavailable",
                %error,
                "adapter runtime data (IP/gateway/DNS) could not be read — every row will report no local IP, which is NOT the same as the machine having no usable adapter",
            );
            std::collections::HashMap::new()
        }
    };

    // Unreadable, every row claims no kind rather than a guessed one.
    let kind_facts =
        crate::win32_ffi::interface_counters::read_interface_kind_facts().unwrap_or_default();

    // Which adapters can actually forward traffic out: a classic gateway, or a
    // default-style route with a real next-hop (the gateway-less OpenVPN /
    // WireGuard shape). Computed here, where the route table is available,
    // because the GUI cannot tell that case apart from a host-only virtual
    // adapter using the enumerated fields alone. `None` when the route table
    // could not be read at all — then every row reports "not evaluated" rather
    // than a false "cannot forward", which consumers must not warn on.
    let forwarding_capable = forwarding_capable_adapter_names();
    let forwarding_known = forwarding_capable.is_some();
    let forwarding_by_adapter = forwarding_capable.unwrap_or_default();

    let mut rows = adapters
        .into_iter()
        // No route can leave through it, so it is no candidate for either role.
        .filter(|adapter| {
            adapter.interface_type != crate::interface_manager::LOOPBACK_INTERFACE_TYPE
        })
        .map(|adapter| {
            let oper_status = adapter.oper_status.to_ascii_lowercase();
            let availability_status = if oper_status.contains("up") {
                BasicAvailabilityStatus::Available
            } else if oper_status.contains("down") {
                BasicAvailabilityStatus::Unavailable
            } else {
                BasicAvailabilityStatus::RequiresCheck
            };

            let adapter_name_key = adapter.identity.adapter_name.to_ascii_lowercase();
            let (local_ip, gateway, dns_servers, has_default_route) = runtime_by_adapter
                .get(&adapter_name_key)
                .cloned()
                .unwrap_or_else(|| ("-".to_string(), "-".to_string(), "-".to_string(), false));
            let observed_facts = build_observed_facts(availability_status, &local_ip, &gateway);
            let derived_assessment = build_derived_assessment(
                &adapter.name,
                &adapter.interface_type,
                &adapter.interface_description,
                &adapter.identity.adapter_name,
                &gateway,
                &local_ip,
                has_default_route,
                observed_facts.connectivity_state,
            );
            let device_technology =
                crate::adapter_kind::device_technology(&adapter.interface_description);
            let kind = kind_facts
                .get(&adapter_name_key)
                .map_or(AdapterKind::Other, |facts| classify_adapter_kind(*facts));
            // The medium the OS reports catches a Bluetooth link with a neutral name.
            let is_bluetooth_like = kind == AdapterKind::Bluetooth
                || is_bluetooth_like_interface(
                    &adapter.name,
                    &adapter.interface_description,
                    &adapter.identity.adapter_name,
                );

            InterfaceRouteRow {
                persistent_id: adapter.identity.persistent_id,
                adapter_name: adapter.identity.adapter_name,
                name: adapter.name,
                interface_description: adapter.interface_description,
                interface_type: adapter.interface_type,
                kind,
                device_technology,
                is_bluetooth_like,
                local_ip,
                gateway,
                dns_servers,
                has_default_route,
                has_forwarding_path: forwarding_known.then(|| {
                    has_default_route || forwarding_by_adapter.contains(&adapter_name_key)
                }),
                runtime_data_unavailable,
                availability_status,
                observed_facts,
                derived_assessment,
                recommendation: unknown_recommendation(),
                selected_role: None,
                route_state: RouteSelectionState::NotSelected,
            }
        })
        .collect::<Vec<_>>();

    rows.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });

    if probe_external_ip {
        apply_external_ip_probes(&mut rows);
    }
    rows
}

#[cfg(windows)]
fn forwarding_capable_adapter_names() -> Option<std::collections::HashSet<String>> {
    use nrr_platform_api::interface_rows::derive_forwarding_next_hop;
    use nrr_platform_api::route_table::RouteTablePort;

    let api = crate::windows_api::ProductionWindowsApi;
    let (Ok(routes), Ok(infos)) = (api.get_ip_forward_table(), api.get_adapter_infos()) else {
        tracing::warn!(
            target: "nrr::interface-rows",
            msg_key = "win-iface-forwarding-unevaluated",
            "route table or adapter list unreadable — forwarding capability stays unevaluated for every adapter",
        );
        return None;
    };
    Some(
        infos
            .into_iter()
            .filter(|info| derive_forwarding_next_hop(&routes, info.index).is_some())
            .map(|info| info.adapter_name.trim().to_ascii_lowercase())
            .collect(),
    )
}

#[cfg(windows)]
fn collect_windows_runtime_data() -> Result<Vec<WindowsRuntimeInterfaceData>, String> {
    Ok(crate::win32_ffi::adapters::enumerate_adapter_details()
        .map_err(|error| error.to_string())?
        .iter()
        .map(runtime_data)
        .collect())
}

#[cfg(windows)]
fn runtime_data(
    adapter: &crate::win32_ffi::adapters::AdapterDetails,
) -> WindowsRuntimeInterfaceData {
    use nrr_platform_api::interface_rows::preferred_display_address;
    use std::net::IpAddr;

    // The pick ranks the addresses itself, so the family split costs nothing.
    let unicast = adapter
        .info
        .ipv4_addresses
        .iter()
        .copied()
        .map(IpAddr::V4)
        .chain(adapter.info.ipv6_addresses.iter().copied().map(IpAddr::V6))
        .collect::<Vec<_>>();
    let local_ip = preferred_display_address(&unicast).unwrap_or_else(|| "-".to_string());
    let gateway = preferred_display_address(&adapter.gateways).unwrap_or_else(|| "-".to_string());
    let dns_servers = if adapter.dns_servers.is_empty() {
        "-".to_string()
    } else {
        adapter
            .dns_servers
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };

    WindowsRuntimeInterfaceData {
        adapter_name: adapter.info.adapter_name.trim().to_string(),
        has_default_route: gateway != "-",
        local_ip,
        gateway,
        dns_servers,
    }
}

#[cfg(windows)]
struct WindowsRuntimeInterfaceData {
    adapter_name: String,
    local_ip: String,
    gateway: String,
    dns_servers: String,
    has_default_route: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collected_rows_are_never_empty() {
        let (_source, rows) = WindowsInterfaceRows.collect_rows(false);
        assert!(!rows.is_empty());
    }

    #[cfg(windows)]
    mod runtime_mapping {
        use super::super::runtime_data;
        use crate::adapters::{AdapterInfo, IfOperStatus, InterfaceType};
        use crate::win32_ffi::adapters::AdapterDetails;
        use std::net::IpAddr;

        fn ip(text: &str) -> IpAddr {
            text.parse().expect("ip literal")
        }

        fn details(unicast: &[&str], gateways: &[&str], dns: &[&str]) -> AdapterDetails {
            let unicast: Vec<IpAddr> = unicast.iter().map(|text| ip(text)).collect();
            AdapterDetails {
                info: AdapterInfo {
                    index: 7,
                    adapter_name: " {0000-AAAA} ".to_string(),
                    description: String::new(),
                    friendly_name: String::new(),
                    mac: None,
                    interface_type: InterfaceType::Ethernet,
                    oper_status: IfOperStatus::Up,
                    ipv4_addresses: unicast
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(v4) => Some(*v4),
                            IpAddr::V6(_) => None,
                        })
                        .collect(),
                    ipv6_addresses: unicast
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V6(v6) => Some(*v6),
                            IpAddr::V4(_) => None,
                        })
                        .collect(),
                    gateways: Vec::new(),
                },
                ipv6_if_index: 12,
                physical_address: Vec::new(),
                if_type: 6,
                gateways: gateways.iter().map(|text| ip(text)).collect(),
                dns_servers: dns.iter().map(|text| ip(text)).collect(),
            }
        }

        #[test]
        fn the_row_shows_the_routable_address_and_every_dns_server_in_order() {
            let data = runtime_data(&details(
                &["fe80::1", "169.254.3.4", "2001:db8::20", "192.168.1.20"],
                &["fe80::fe", "192.168.1.1"],
                &["2001:db8::53", "192.168.1.1"],
            ));
            assert_eq!(data.adapter_name, "{0000-AAAA}");
            assert_eq!(data.local_ip, "192.168.1.20");
            assert_eq!(data.gateway, "192.168.1.1");
            assert_eq!(data.dns_servers, "2001:db8::53, 192.168.1.1");
            assert!(data.has_default_route);
        }

        #[test]
        fn an_ipv6_only_gateway_still_counts_as_a_default_route() {
            let data = runtime_data(&details(&["2001:db8::20"], &["fe80::fe"], &[]));
            assert_eq!(data.local_ip, "2001:db8::20");
            assert_eq!(data.gateway, "fe80::fe");
            assert!(data.has_default_route);
        }

        #[test]
        fn an_adapter_without_addresses_reads_as_dashes() {
            let data = runtime_data(&details(&[], &[], &[]));
            assert_eq!(data.local_ip, "-");
            assert_eq!(data.gateway, "-");
            assert_eq!(data.dns_servers, "-");
            assert!(!data.has_default_route);
        }
    }
}

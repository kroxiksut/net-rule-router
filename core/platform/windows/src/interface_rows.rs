//! The neutral adapter rich-row types + enrichment live
//! in `nrr_platform_api::interface_rows` (re-exported below for source
//! compatibility, so `crate::interface_rows::*` and the crate-root re-exports
//! in `lib.rs` keep resolving unchanged). What remains here is the Windows-only
//! live enumeration: [`collect_interfaces_rows`] merges the stable identity
//! snapshot (`crate::interface_manager::adapters_snapshot`) with per-adapter
//! runtime IP/gateway/DNS data via the `ipconfig` crate. Off Windows the
//! callers use the neutral `fallback_rows` instead.

pub use nrr_platform_api::interface_rows::*;

// Only the live Windows enumeration builds rows; off Windows this module is
// the neutral re-export plus the fallback dataset.
#[cfg(windows)]
use nrr_shared::RouteSelectionState;

/// Enumerate adapters live and enrich each into an [`InterfaceRouteRow`].
///
/// On Windows this merges the stable identity snapshot
/// ([`crate::interface_manager::adapters_snapshot`]) with per-adapter
/// runtime IP/gateway/DNS data; off Windows (or when the live
/// enumeration is empty) it returns the deterministic fallback dataset.
///
/// `probe_external_ip` decides whether each adapter is additionally asked for
/// the address the outside world sees behind it. It is opt-in because the
/// probe sends a datagram to a third-party server: only a path where the user
/// explicitly asked for the check may pass `true`. Every routine or background
/// enumeration passes `false` and stays network-silent, so a plain refresh can
/// never block on the network.
pub fn collect_interfaces_rows(
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

    // The fallback dataset is deterministic and offline by contract: there is
    // no real adapter behind those rows to probe, and nothing off Windows reads
    // the snapshot the live path merges.
    #[cfg(not(windows))]
    let _ = (probe_external_ip, snapshot);

    (InterfacesDataSource::FallbackMock, fallback_rows())
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
                %error,
                "adapter runtime data (IP/gateway/DNS) could not be read — every row will report no local IP, which is NOT the same as the machine having no usable adapter",
            );
            std::collections::HashMap::new()
        }
    };

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
                &adapter.windows_name,
                &adapter.interface_type,
                &adapter.interface_description,
                &adapter.identity.adapter_name,
                &gateway,
                &local_ip,
                has_default_route,
                observed_facts.connectivity_state,
            );
            let is_bluetooth_like = is_bluetooth_like_interface(
                &adapter.windows_name,
                &adapter.interface_description,
                &adapter.identity.adapter_name,
            );

            InterfaceRouteRow {
                persistent_id: adapter.identity.persistent_id,
                adapter_name: adapter.identity.adapter_name,
                windows_name: adapter.windows_name,
                interface_description: adapter.interface_description,
                interface_type: adapter.interface_type,
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
        left.windows_name
            .to_ascii_lowercase()
            .cmp(&right.windows_name.to_ascii_lowercase())
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
    use nrr_platform_api::interface_rows::preferred_display_address;

    let adapters = ipconfig::get_adapters().map_err(|error| error.to_string())?;
    Ok(adapters
        .into_iter()
        .map(|adapter| {
            let local_ip = preferred_display_address(adapter.ip_addresses())
                .unwrap_or_else(|| "-".to_string());
            let gateway =
                preferred_display_address(adapter.gateways()).unwrap_or_else(|| "-".to_string());

            let dns_values = adapter
                .dns_servers()
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>();
            let dns_servers = if dns_values.is_empty() {
                "-".to_string()
            } else {
                dns_values.join(", ")
            };

            WindowsRuntimeInterfaceData {
                adapter_name: adapter.adapter_name().trim().to_string(),
                local_ip,
                gateway: gateway.clone(),
                dns_servers,
                has_default_route: gateway != "-",
            }
        })
        .collect::<Vec<_>>())
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
    fn collect_interfaces_rows_never_empty() {
        let (_source, rows) = collect_interfaces_rows(false);
        assert!(!rows.is_empty());
    }
}

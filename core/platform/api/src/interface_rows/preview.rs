// Deterministic adapter dataset for previews and off-Windows builds.

use super::*;

/// Persistent ids this dataset hands out. Declared next to the rows that carry
/// them so the two cannot drift, and public because a binding naming one of
/// them points at no adapter of this machine: the service refuses it instead of
/// storing a route that can never apply.
pub const PREVIEW_ETHERNET_PERSISTENT_ID: &str = "win-adapter:ethernet-fallback";
pub const PREVIEW_WIFI_PERSISTENT_ID: &str = "win-adapter:wifi-fallback";
pub const PREVIEW_VPN_PERSISTENT_ID: &str = "win-adapter:vpn-fallback";
pub const PREVIEW_BLUETOOTH_PAN_PERSISTENT_ID: &str = "win-adapter:bluetooth-pan-fallback";

/// Every id [`fallback_rows`] produces.
pub const PREVIEW_PERSISTENT_IDS: [&str; 4] = [
    PREVIEW_ETHERNET_PERSISTENT_ID,
    PREVIEW_WIFI_PERSISTENT_ID,
    PREVIEW_VPN_PERSISTENT_ID,
    PREVIEW_BLUETOOTH_PAN_PERSISTENT_ID,
];

/// Whether `persistent_id` came from the placeholder dataset rather than a live
/// enumeration.
#[must_use]
pub fn is_preview_persistent_id(persistent_id: &str) -> bool {
    PREVIEW_PERSISTENT_IDS.contains(&persistent_id)
}

/// Deterministic adapter dataset used when no live Windows enumeration is
/// available (off-Windows builds, dev/test, empty enumeration).
pub fn fallback_rows() -> Vec<InterfaceRouteRow> {
    let mut ethernet_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "192.168.1.20",
        "192.168.1.1",
    );
    // NOT `Resolved`: this dataset is a placeholder, and no probe ran. Claiming
    // a resolved external address made the adapter-check panel print an invented
    // one ("203.0.113.10") as the result of a successful lookup — the live path
    // never produces `Resolved` without an actual probe.
    ethernet_observed.external_ip_status = ExternalIpStatus::NotChecked;
    ethernet_observed.external_ip = None;
    ethernet_observed.external_probe_attempted = false;
    ethernet_observed.external_probe_note =
        "No external probe runs in the deterministic fallback dataset.".to_string();
    let ethernet_derived = build_derived_assessment(
        "Ethernet",
        "Ethernet",
        "Fallback Ethernet adapter",
        "{FAKE-ETHERNET-ADAPTER}",
        "192.168.1.1",
        "192.168.1.20",
        true,
        ethernet_observed.connectivity_state,
    );

    let wifi_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "10.10.0.15",
        "10.10.0.1",
    );
    let wifi_derived = build_derived_assessment(
        "Wi-Fi",
        "Wireless",
        "Fallback Wi-Fi adapter",
        "{FAKE-WIFI-ADAPTER}",
        "10.10.0.1",
        "10.10.0.15",
        true,
        wifi_observed.connectivity_state,
    );

    let vpn_observed = build_observed_facts(BasicAvailabilityStatus::RequiresCheck, "-", "-");
    let vpn_derived = build_derived_assessment(
        "VPN",
        "Tunnel",
        "Fallback VPN tunnel",
        "{FAKE-VPN-ADAPTER}",
        "-",
        "-",
        false,
        vpn_observed.connectivity_state,
    );
    let bluetooth_observed = build_observed_facts(
        BasicAvailabilityStatus::Available,
        "172.20.10.5",
        "172.20.10.1",
    );
    let bluetooth_derived = build_derived_assessment(
        "Bluetooth PAN",
        "Wireless",
        "Bluetooth Personal Area Network",
        "{FAKE-BLUETOOTH-PAN-ADAPTER}",
        "172.20.10.1",
        "172.20.10.5",
        true,
        bluetooth_observed.connectivity_state,
    );

    vec![
        InterfaceRouteRow {
            persistent_id: PREVIEW_ETHERNET_PERSISTENT_ID.to_string(),
            adapter_name: "{FAKE-ETHERNET-ADAPTER}".to_string(),
            windows_name: "Ethernet".to_string(),
            interface_description: "Fallback Ethernet adapter".to_string(),
            interface_type: "Ethernet".to_string(),
            is_bluetooth_like: false,
            local_ip: "192.168.1.20".to_string(),
            gateway: "192.168.1.1".to_string(),
            dns_servers: "1.1.1.1, 8.8.8.8".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            runtime_data_unavailable: false,
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: ethernet_observed,
            derived_assessment: ethernet_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
        InterfaceRouteRow {
            persistent_id: PREVIEW_WIFI_PERSISTENT_ID.to_string(),
            adapter_name: "{FAKE-WIFI-ADAPTER}".to_string(),
            windows_name: "Wi-Fi".to_string(),
            interface_description: "Fallback Wi-Fi adapter".to_string(),
            interface_type: "Wireless".to_string(),
            is_bluetooth_like: false,
            local_ip: "10.10.0.15".to_string(),
            gateway: "10.10.0.1".to_string(),
            dns_servers: "9.9.9.9".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            runtime_data_unavailable: false,
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: wifi_observed,
            derived_assessment: wifi_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
        InterfaceRouteRow {
            persistent_id: PREVIEW_VPN_PERSISTENT_ID.to_string(),
            adapter_name: "{FAKE-VPN-ADAPTER}".to_string(),
            windows_name: "VPN".to_string(),
            interface_description: "Fallback VPN tunnel".to_string(),
            interface_type: "Tunnel".to_string(),
            is_bluetooth_like: false,
            local_ip: "-".to_string(),
            gateway: "-".to_string(),
            dns_servers: "-".to_string(),
            has_default_route: false,
            has_forwarding_path: Some(false),
            runtime_data_unavailable: false,
            availability_status: BasicAvailabilityStatus::RequiresCheck,
            observed_facts: vpn_observed,
            derived_assessment: vpn_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::RequiresVerification,
        },
        InterfaceRouteRow {
            persistent_id: PREVIEW_BLUETOOTH_PAN_PERSISTENT_ID.to_string(),
            adapter_name: "{FAKE-BLUETOOTH-PAN-ADAPTER}".to_string(),
            windows_name: "Bluetooth PAN".to_string(),
            interface_description: "Bluetooth Personal Area Network".to_string(),
            interface_type: "Wireless".to_string(),
            is_bluetooth_like: true,
            local_ip: "172.20.10.5".to_string(),
            gateway: "172.20.10.1".to_string(),
            dns_servers: "8.8.4.4".to_string(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            runtime_data_unavailable: false,
            availability_status: BasicAvailabilityStatus::Available,
            observed_facts: bluetooth_observed,
            derived_assessment: bluetooth_derived,
            recommendation: unknown_recommendation(),
            selected_role: None,
            route_state: RouteSelectionState::NotSelected,
        },
    ]
}

// ── Wire-DTO mapping ──────────────────────────────────────────────────────────

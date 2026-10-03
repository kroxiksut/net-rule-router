//! `MIB_IF_ROW2` facts -> the neutral [`AdapterKindFacts`] the shared
//! classifier reads.
//!
//! The connection name the user renames never counts. The driver description
//! does: the OS reports it per driver, and it is the existing tunnel signal for
//! the adapters whose IfType hides one (a TAP-Windows adapter presents as
//! plain Ethernet).

// The one caller is the Windows-only row enumeration.
#![cfg_attr(not(windows), allow(dead_code))]

use nrr_platform_api::adapters::text_indicates_vpn_tunnel;
use nrr_platform_api::interface_rows::{AdapterKindFacts, DeviceTechnology, LinkMedium};

const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
/// Proprietary virtual: what user-mode tunnel drivers (Wintun) register as.
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_IEEE80211: u32 = 71;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_TYPE_WWANPP: u32 = 243;
const IF_TYPE_WWANPP2: u32 = 244;

const NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN: i32 = 8;
const NDIS_PHYSICAL_MEDIUM_NATIVE_802_11: i32 = 9;
const NDIS_PHYSICAL_MEDIUM_BLUETOOTH: i32 = 10;

/// The fields of one `MIB_IF_ROW2` the kind is decided from.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WindowsIfFacts<'a> {
    /// `Type` (IANA ifType).
    pub(crate) if_type: u32,
    /// `PhysicalMediumType` (`NDIS_PHYSICAL_MEDIUM`).
    pub(crate) physical_medium: i32,
    /// `InterfaceAndOperStatusFlags.HardwareInterface`.
    pub(crate) hardware_interface: bool,
    /// `Description` — the driver's name for the device.
    pub(crate) description: &'a str,
}

pub(crate) fn kind_facts(facts: &WindowsIfFacts<'_>) -> AdapterKindFacts {
    let medium = match (facts.if_type, facts.physical_medium) {
        (IF_TYPE_SOFTWARE_LOOPBACK, _) => LinkMedium::Loopback,
        (_, NDIS_PHYSICAL_MEDIUM_BLUETOOTH) => LinkMedium::Bluetooth,
        (IF_TYPE_WWANPP | IF_TYPE_WWANPP2, _) | (_, NDIS_PHYSICAL_MEDIUM_WIRELESS_WAN) => {
            LinkMedium::Cellular
        }
        (IF_TYPE_IEEE80211, _) | (_, NDIS_PHYSICAL_MEDIUM_NATIVE_802_11) => LinkMedium::Wireless,
        (IF_TYPE_ETHERNET_CSMACD, _) => LinkMedium::Ethernet,
        (IF_TYPE_PPP | IF_TYPE_TUNNEL, _) => LinkMedium::PointToPoint,
        _ => LinkMedium::Unknown,
    };
    let tunnel = matches!(facts.if_type, IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL)
        || text_indicates_vpn_tunnel(facts.description);
    AdapterKindFacts {
        medium,
        tunnel,
        hardware: Some(facts.hardware_interface),
    }
}

/// The tun/tap driver behind an adapter, from its driver description. Only the
/// two drivers whose layer is certain are named: Wintun is layer 3, TAP-Windows
/// layer 2. Anything else (WireGuardNT, DCO, Hyper-V) stays unnamed, as on Linux.
pub(crate) fn device_technology(description: &str) -> Option<DeviceTechnology> {
    let text = description.to_ascii_lowercase();
    if text.contains("wintun") {
        Some(DeviceTechnology::Tun)
    } else if ["tap-windows", "tap0901", "tap-win32"]
        .iter()
        .any(|marker| text.contains(marker))
    {
        Some(DeviceTechnology::Tap)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::interface_rows::{classify_adapter_kind, AdapterKind};

    #[test]
    fn tun_and_tap_are_named_only_by_their_known_drivers() {
        assert_eq!(
            device_technology("Wintun Userspace Tunnel"),
            Some(DeviceTechnology::Tun)
        );
        assert_eq!(
            device_technology("TAP-Windows Adapter V9"),
            Some(DeviceTechnology::Tap)
        );
        assert_eq!(
            device_technology("Example TAP0901 Device"),
            Some(DeviceTechnology::Tap)
        );
        for other in [
            "WireGuard Tunnel",
            "OpenVPN Data Channel Offload",
            "Hyper-V Virtual Ethernet Adapter",
            "Example Gigabit Controller",
            "",
        ] {
            assert_eq!(device_technology(other), None, "{other}");
        }
    }

    fn kind(if_type: u32, physical_medium: i32, hardware: bool, description: &str) -> AdapterKind {
        classify_adapter_kind(kind_facts(&WindowsIfFacts {
            if_type,
            physical_medium,
            hardware_interface: hardware,
            description,
        }))
    }

    #[test]
    fn hardware_nics_read_by_their_medium() {
        assert_eq!(
            kind(6, 14, true, "Example Gigabit Controller"),
            AdapterKind::Ethernet
        );
        assert_eq!(
            kind(71, 9, true, "Example Wireless Adapter"),
            AdapterKind::Wifi
        );
        // A Wi-Fi driver that reports Ethernet framing is still a radio.
        assert_eq!(
            kind(6, 9, true, "Example Wireless Adapter"),
            AdapterKind::Wifi
        );
    }

    #[test]
    fn tunnels_are_found_by_type_and_by_the_driver_behind_them() {
        assert_eq!(kind(131, 0, false, "Example Tunnel"), AdapterKind::Tunnel);
        assert_eq!(
            kind(53, 0, false, "Example Userspace Adapter"),
            AdapterKind::Tunnel
        );
        // TAP-Windows presents as Ethernet; only its driver says otherwise.
        assert_eq!(
            kind(6, 0, false, "TAP-Windows Adapter V9"),
            AdapterKind::Tunnel
        );
    }

    #[test]
    fn a_software_ethernet_adapter_is_virtual() {
        assert_eq!(
            kind(6, 14, false, "Example Virtual Ethernet Adapter"),
            AdapterKind::Virtual
        );
        assert_eq!(
            kind(6, 0, false, "Example Host-Only Adapter"),
            AdapterKind::Virtual
        );
    }

    #[test]
    fn uplinks_that_are_neither_cable_nor_wifi_nor_bluetooth_read_as_other() {
        // PPPoE: an uplink as often as a VPN, so its type alone says nothing.
        assert_eq!(kind(23, 0, false, "Example Provider"), AdapterKind::Other);
        assert_eq!(
            kind(243, 8, true, "Example Mobile Broadband"),
            AdapterKind::Other
        );
        assert_eq!(
            kind(6, 10, true, "Example Personal Area Network"),
            AdapterKind::Bluetooth
        );
        assert_eq!(
            kind(24, 0, false, "Software Loopback Interface 1"),
            AdapterKind::Other
        );
    }
}

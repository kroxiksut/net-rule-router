//! Sysfs facts -> the neutral [`AdapterKindFacts`] the shared classifier reads.
//!
//! Only what the kernel says about the device counts here, never the link
//! name: `wg0`, `enp4s0f1` and `home` are all names someone chose.

// The one caller is the Linux-only row enumeration.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use nrr_platform_api::interface_rows::{AdapterKindFacts, DeviceTechnology, LinkMedium};

use crate::interface_traffic::{
    SysfsFacts, ARPHRD_ETHER, ARPHRD_LOOPBACK, ARPHRD_NONE, ARPHRD_PPP, ARPHRD_SIT, ARPHRD_TUNNEL,
    ARPHRD_TUNNEL6,
};

/// `ARPHRD_IPGRE` / `ARPHRD_IP6GRE`: layer-3 GRE tunnels.
const ARPHRD_IPGRE: u32 = 778;
const ARPHRD_IP6GRE: u32 = 823;

/// Hardware classes that are a layer-3 tunnel whatever drives them.
const L3_TUNNEL_ARPHRDS: &[u32] = &[
    ARPHRD_TUNNEL,
    ARPHRD_TUNNEL6,
    ARPHRD_SIT,
    ARPHRD_IPGRE,
    ARPHRD_IP6GRE,
];

/// Kernel device types of VPN tunnels.
const TUNNEL_DEVTYPES: &[&str] = &["wireguard", "amneziawg"];

/// Software devices stacked on a physical link: the link below them is the
/// medium, so the absence of a bus device says nothing here.
const STACKED_DEVTYPES: &[&str] = &["bond", "vlan", "team"];

pub(crate) fn kind_facts(facts: &SysfsFacts) -> AdapterKindFacts {
    let devtype = facts.devtype.as_deref();
    let medium = match (facts.arphrd, devtype) {
        (Some(ARPHRD_LOOPBACK), _) => LinkMedium::Loopback,
        (_, Some("wlan")) => LinkMedium::Wireless,
        _ if facts.is_wireless => LinkMedium::Wireless,
        // Raw-IP modems share ARPHRD_NONE with tunnels; DEVTYPE tells them apart.
        (_, Some("wwan")) => LinkMedium::Cellular,
        (_, Some("bluetooth")) => LinkMedium::Bluetooth,
        (Some(ARPHRD_ETHER), _) => LinkMedium::Ethernet,
        (Some(ARPHRD_PPP | ARPHRD_NONE), _) => LinkMedium::PointToPoint,
        (Some(class), _) if L3_TUNNEL_ARPHRDS.contains(&class) => LinkMedium::PointToPoint,
        _ => LinkMedium::Unknown,
    };
    let is_ppp = facts.arphrd == Some(ARPHRD_PPP);
    // A tap enslaved to a bridge is a VM's port; a standalone one is a VPN's.
    let tun_tap_tunnel = facts.is_tun_device && !(facts.is_tap && facts.has_master);
    let tunnel = !matches!(medium, LinkMedium::Loopback | LinkMedium::Cellular)
        && (tun_tap_tunnel
            || devtype.is_some_and(|d| TUNNEL_DEVTYPES.contains(&d))
            || facts
                .arphrd
                .is_some_and(|class| class == ARPHRD_NONE || L3_TUNNEL_ARPHRDS.contains(&class))
            // PPP is point-to-point too, and as often a PPPoE uplink as a VPN.
            || (facts.point_to_point && !is_ppp));
    let hardware = if devtype.is_some_and(|d| STACKED_DEVTYPES.contains(&d)) {
        None
    } else {
        facts.has_device
    };
    AdapterKindFacts {
        medium,
        tunnel,
        hardware,
    }
}

/// The tun/tap device behind a link, for the details line.
pub(crate) fn device_technology(facts: &SysfsFacts) -> Option<DeviceTechnology> {
    match (facts.is_tun_device, facts.is_tap) {
        (false, _) => None,
        (true, false) => Some(DeviceTechnology::Tun),
        (true, true) => Some(DeviceTechnology::Tap),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::interface_rows::{classify_adapter_kind, AdapterKind};

    fn link(arphrd: u32, has_device: bool) -> SysfsFacts {
        SysfsFacts {
            arphrd: Some(arphrd),
            has_device: Some(has_device),
            ..SysfsFacts::default()
        }
    }

    fn kind(facts: &SysfsFacts) -> AdapterKind {
        classify_adapter_kind(kind_facts(facts))
    }

    #[test]
    fn a_nic_is_wired_and_a_radio_is_wifi() {
        assert_eq!(kind(&link(ARPHRD_ETHER, true)), AdapterKind::Ethernet);
        let mut radio = link(ARPHRD_ETHER, true);
        radio.is_wireless = true;
        assert_eq!(kind(&radio), AdapterKind::Wifi);
        let mut by_devtype = link(ARPHRD_ETHER, true);
        by_devtype.devtype = Some("wlan".to_string());
        assert_eq!(kind(&by_devtype), AdapterKind::Wifi);
    }

    #[test]
    fn vpn_devices_are_tunnels() {
        let mut wg = link(ARPHRD_NONE, false);
        wg.devtype = Some("wireguard".to_string());
        wg.point_to_point = true;
        assert_eq!(kind(&wg), AdapterKind::Tunnel);

        let mut awg = link(ARPHRD_NONE, false);
        awg.devtype = Some("amneziawg".to_string());
        assert_eq!(kind(&awg), AdapterKind::Tunnel);

        let mut tun = link(ARPHRD_NONE, false);
        tun.is_tun_device = true;
        assert_eq!(kind(&tun), AdapterKind::Tunnel);

        assert_eq!(kind(&link(778, false)), AdapterKind::Tunnel);
        assert_eq!(kind(&link(ARPHRD_SIT, false)), AdapterKind::Tunnel);
    }

    #[test]
    fn software_ethernet_is_virtual() {
        for devtype in [Some("bridge"), Some("veth"), None] {
            let mut sw = link(ARPHRD_ETHER, false);
            sw.devtype = devtype.map(str::to_string);
            assert_eq!(kind(&sw), AdapterKind::Virtual, "{devtype:?}");
        }
    }

    fn tap() -> SysfsFacts {
        let mut tap = link(ARPHRD_ETHER, false);
        tap.is_tun_device = true;
        tap.is_tap = true;
        tap
    }

    #[test]
    fn a_standalone_tap_is_a_tunnel_and_a_bridged_one_a_vm_port() {
        assert_eq!(kind(&tap()), AdapterKind::Tunnel);
        let mut bridged = tap();
        bridged.has_master = true;
        assert_eq!(kind(&bridged), AdapterKind::Virtual);
        // A master says nothing about a tun: it carries no Ethernet to bridge.
        let mut tun = link(ARPHRD_NONE, false);
        tun.is_tun_device = true;
        tun.has_master = true;
        assert_eq!(kind(&tun), AdapterKind::Tunnel);
    }

    #[test]
    fn the_details_line_names_tun_and_tap_and_nothing_else() {
        let mut tun = link(ARPHRD_NONE, false);
        tun.is_tun_device = true;
        assert_eq!(device_technology(&tun), Some(DeviceTechnology::Tun));
        let mut bridged = tap();
        bridged.has_master = true;
        assert_eq!(device_technology(&bridged), Some(DeviceTechnology::Tap));
        let mut wg = link(ARPHRD_NONE, false);
        wg.devtype = Some("wireguard".to_string());
        assert_eq!(device_technology(&wg), None);
        assert_eq!(device_technology(&link(ARPHRD_ETHER, true)), None);
    }

    #[test]
    fn a_bond_or_vlan_rides_the_wire_below_it() {
        for devtype in ["bond", "vlan"] {
            let mut stacked = link(ARPHRD_ETHER, false);
            stacked.devtype = Some(devtype.to_string());
            assert_eq!(kind(&stacked), AdapterKind::Ethernet, "{devtype}");
        }
    }

    #[test]
    fn uplinks_that_only_look_like_tunnels_are_not_called_one() {
        let mut pppoe = link(ARPHRD_PPP, false);
        pppoe.point_to_point = true;
        assert_eq!(kind(&pppoe), AdapterKind::Other);

        let mut modem = link(ARPHRD_NONE, true);
        modem.devtype = Some("wwan".to_string());
        modem.point_to_point = true;
        assert_eq!(kind(&modem), AdapterKind::Other);

        let mut pan = link(ARPHRD_ETHER, true);
        pan.devtype = Some("bluetooth".to_string());
        assert_eq!(kind(&pan), AdapterKind::Bluetooth);
    }

    #[test]
    fn loopback_and_unread_sysfs_claim_nothing() {
        assert_eq!(kind(&link(ARPHRD_LOOPBACK, false)), AdapterKind::Other);
        assert_eq!(kind(&SysfsFacts::default()), AdapterKind::Other);
    }
}

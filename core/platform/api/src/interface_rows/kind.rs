// What an adapter is, in the words a user picks a connection by.
//
// Decided from what the OS reports about the device, never from its name: a
// name is whatever the user or a VPN client typed, so `Ethernet 3` can be a
// tunnel and `wg-home` a bridge. Each OS backend translates its own codes into
// [`AdapterKindFacts`]; the decision below is the one every OS shares.

/// The human kind shown next to the system name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AdapterKind {
    Wifi,
    Ethernet,
    /// VPN or any other tunnel.
    Tunnel,
    /// Software-only adapter: a VM or container network, a bridge, a switch.
    Virtual,
    Bluetooth,
    #[default]
    Other,
}

impl AdapterKind {
    /// Wire and locale slug (`interfaces.kind.<slug>`).
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::Ethernet => "ethernet",
            Self::Tunnel => "tunnel",
            Self::Virtual => "virtual",
            Self::Bluetooth => "bluetooth",
            Self::Other => "other",
        }
    }

    /// Unknown or absent spellings read as [`Self::Other`]: a sender that
    /// predates the field must not get a kind it never claimed.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "wifi" => Self::Wifi,
            "ethernet" => Self::Ethernet,
            "tunnel" => Self::Tunnel,
            "virtual" => Self::Virtual,
            "bluetooth" => Self::Bluetooth,
            _ => Self::Other,
        }
    }
}

/// The software device behind a link, named on the details line and never as
/// the kind: a tap is a VPN's port as often as a VM's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeviceTechnology {
    Tun,
    Tap,
}

impl DeviceTechnology {
    /// Wire and locale slug (`interfaces.device-technology.<slug>`).
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Tun => "tun",
            Self::Tap => "tap",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "tun" => Some(Self::Tun),
            "tap" => Some(Self::Tap),
            _ => None,
        }
    }
}

/// The medium the OS says the link runs over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum LinkMedium {
    Ethernet,
    Wireless,
    /// PPP and other links without a link layer of their own.
    PointToPoint,
    Cellular,
    Bluetooth,
    Loopback,
    #[default]
    Unknown,
}

/// OS facts the kind is decided from. Every field is an observation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AdapterKindFacts {
    pub medium: LinkMedium,
    /// The OS marks the device as a tunnel endpoint.
    pub tunnel: bool,
    /// Backed by a physical device; `None` when the OS does not say.
    pub hardware: Option<bool>,
}

/// Decide the kind. PPP stays `Other`: it is a provider's PPPoE uplink as
/// often as a VPN, and calling an uplink a tunnel invites the wrong role.
#[must_use]
pub fn classify_adapter_kind(facts: AdapterKindFacts) -> AdapterKind {
    match facts.medium {
        LinkMedium::Loopback => AdapterKind::Other,
        _ if facts.tunnel => AdapterKind::Tunnel,
        LinkMedium::Wireless => AdapterKind::Wifi,
        LinkMedium::Ethernet if facts.hardware == Some(false) => AdapterKind::Virtual,
        LinkMedium::Ethernet => AdapterKind::Ethernet,
        LinkMedium::Unknown if facts.hardware == Some(false) => AdapterKind::Virtual,
        LinkMedium::Bluetooth => AdapterKind::Bluetooth,
        LinkMedium::PointToPoint | LinkMedium::Cellular | LinkMedium::Unknown => AdapterKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(medium: LinkMedium, tunnel: bool, hardware: Option<bool>) -> AdapterKindFacts {
        AdapterKindFacts {
            medium,
            tunnel,
            hardware,
        }
    }

    #[test]
    fn hardware_media_read_as_themselves() {
        let wired = facts(LinkMedium::Ethernet, false, Some(true));
        assert_eq!(classify_adapter_kind(wired), AdapterKind::Ethernet);
        let wifi = facts(LinkMedium::Wireless, false, Some(true));
        assert_eq!(classify_adapter_kind(wifi), AdapterKind::Wifi);
    }

    #[test]
    fn a_tunnel_mark_outranks_the_medium() {
        // A TAP device presents as Ethernet; the OS's tunnel mark decides.
        let tap = facts(LinkMedium::Ethernet, true, Some(false));
        assert_eq!(classify_adapter_kind(tap), AdapterKind::Tunnel);
        let l3 = facts(LinkMedium::PointToPoint, true, None);
        assert_eq!(classify_adapter_kind(l3), AdapterKind::Tunnel);
    }

    #[test]
    fn a_software_ethernet_is_virtual_and_an_unsaid_one_is_wired() {
        let bridge = facts(LinkMedium::Ethernet, false, Some(false));
        assert_eq!(classify_adapter_kind(bridge), AdapterKind::Virtual);
        let unknown = facts(LinkMedium::Ethernet, false, None);
        assert_eq!(classify_adapter_kind(unknown), AdapterKind::Ethernet);
        let odd = facts(LinkMedium::Unknown, false, Some(false));
        assert_eq!(classify_adapter_kind(odd), AdapterKind::Virtual);
    }

    #[test]
    fn uplinks_that_are_not_a_cable_or_wifi_read_as_other() {
        for medium in [
            LinkMedium::PointToPoint,
            LinkMedium::Cellular,
            LinkMedium::Unknown,
        ] {
            assert_eq!(
                classify_adapter_kind(facts(medium, false, Some(true))),
                AdapterKind::Other,
                "{medium:?}"
            );
        }
        let lo = facts(LinkMedium::Loopback, true, Some(false));
        assert_eq!(classify_adapter_kind(lo), AdapterKind::Other);
    }

    #[test]
    fn bluetooth_is_its_own_kind_unless_marked_a_tunnel() {
        let pan = facts(LinkMedium::Bluetooth, false, Some(true));
        assert_eq!(classify_adapter_kind(pan), AdapterKind::Bluetooth);
        let tunnelled = facts(LinkMedium::Bluetooth, true, None);
        assert_eq!(classify_adapter_kind(tunnelled), AdapterKind::Tunnel);
    }

    #[test]
    fn slugs_round_trip_and_unknown_reads_as_other() {
        for kind in [
            AdapterKind::Wifi,
            AdapterKind::Ethernet,
            AdapterKind::Tunnel,
            AdapterKind::Virtual,
            AdapterKind::Bluetooth,
            AdapterKind::Other,
        ] {
            assert_eq!(AdapterKind::from_slug(kind.slug()), kind);
        }
        assert_eq!(AdapterKind::from_slug(""), AdapterKind::Other);
        assert_eq!(AdapterKind::from_slug("wireless"), AdapterKind::Other);
    }

    #[test]
    fn device_technology_slugs_round_trip() {
        for tech in [DeviceTechnology::Tun, DeviceTechnology::Tap] {
            assert_eq!(DeviceTechnology::from_slug(tech.slug()), Some(tech));
        }
        assert_eq!(DeviceTechnology::from_slug(""), None);
    }
}

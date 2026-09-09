//! What kind of address is this, and — when it is a well-known service group —
//! which service.
//!
//! Two questions the block-notice path asks of every destination before it
//! announces one. A link-local multicast group is not a site: nobody chose to
//! visit `ff02::fb`, so a notice naming it sends the user hunting for a rule
//! that cannot exist. The same holds for broadcast, link-local and the
//! unspecified address — traffic the operating system generates on its own.
//!
//! Pure and table-driven on purpose: the classification is the same fact for
//! enforcement, for the notice surface and for the diagnostic line, and a
//! second copy of it would drift.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Address kinds that change how a destination should be talked about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressClass {
    /// A destination someone could have meant — the only class worth naming.
    Routable,
    Loopback,
    /// `169.254.0.0/16` / `fe80::/10`.
    LinkLocal,
    /// `224.0.0.0/4` / `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// `0.0.0.0` / `::`.
    Unspecified,
}

impl AddressClass {
    /// Traffic the machine generates for itself — discovery, neighbour upkeep,
    /// address configuration. There is no site behind it and no rule the user
    /// could write about it.
    #[must_use]
    pub fn is_local_housekeeping(self) -> bool {
        !matches!(self, Self::Routable)
    }
}

/// Is this endpoint the machine keeping house on its own network?
///
/// [`AddressClass::is_local_housekeeping`] answers it from the address alone,
/// which is enough for multicast and for the all-ones broadcast. It is NOT
/// enough for a subnet-directed broadcast: `192.168.1.255` is the broadcast of
/// a /24 and an ordinary host in a /23, and one address cannot say which. So a
/// dropped NetBIOS-NS or WS-Discovery datagram to it counted as a real
/// destination and raised a notice about an address no rule can name.
///
/// The port answers the question the address cannot. These are name resolution,
/// discovery and address configuration: within a private network they are the
/// machine talking to its own segment, whatever shape the destination address
/// takes. The drop still reaches the trace line — only the notice is withheld.
///
/// Deliberately NOT covered: BitTorrent local peer discovery (6771). It is
/// discovery too, but it is the user's own application announcing itself, and
/// silence about a blocked P2P announcement is not ours to choose for them.
#[must_use]
pub fn is_local_housekeeping_endpoint(ip: IpAddr, port: u16) -> bool {
    classify(ip).is_local_housekeeping() || (is_private(ip) && is_housekeeping_port(port))
}

/// Ports whose traffic is the machine keeping its own segment in order.
fn is_housekeeping_port(port: u16) -> bool {
    matches!(port, 137 | 138 | 546 | 547 | 1900 | 3702 | 5353 | 5355)
}

/// An address inside a private network — RFC1918 for v4, unique-local
/// (`fc00::/7`) for v6. Deliberately narrow: the rule above must not quieten
/// anything reachable on the open internet.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Classify one destination address.
#[must_use]
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_broadcast() {
        AddressClass::Broadcast
    } else if ip.is_multicast() {
        AddressClass::Multicast
    } else if ip.is_link_local() {
        AddressClass::LinkLocal
    } else {
        AddressClass::Routable
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_multicast() {
        AddressClass::Multicast
    } else if is_v6_link_local(ip) {
        AddressClass::LinkLocal
    } else {
        AddressClass::Routable
    }
}

/// `fe80::/10`. `Ipv6Addr::is_unicast_link_local` is still unstable, so the
/// prefix test lives here rather than waiting for it.
#[must_use]
pub fn is_v6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// `ff02::/16` — the link-local multicast scope: neighbour discovery, MLD,
/// mDNS, LLMNR, DHCPv6. Never leaves the link by definition, which is why
/// enforcement exempts it instead of cutting it with the rest of IPv6.
#[must_use]
pub fn is_v6_link_local_multicast(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0xff02
}

/// The service behind a well-known address, as a stable slug. `None` when the
/// address carries no recognised meaning — the caller then shows the address
/// itself. Today's consumer is the drop-trace line, where `ff02::fb` alone is
/// unreadable.
///
/// `port` disambiguates the transient groups applications invent for
/// themselves (`ff15::efc0:988f` is recognisable as BitTorrent only by its
/// port), so it is consulted after the fixed group addresses and before the
/// generic class fallback.
#[must_use]
pub fn well_known_purpose(ip: IpAddr, port: u16) -> Option<&'static str> {
    let class = classify(ip);
    let fixed = match ip {
        IpAddr::V4(v4) => fixed_group_v4(v4),
        IpAddr::V6(v6) => fixed_group_v6(v6),
    };
    fixed
        .or_else(|| {
            // Same widening as `is_local_housekeeping_endpoint`, for the same
            // reason: a subnet-directed broadcast is not recognisable by its
            // address, so a NetBIOS datagram to it used to print as a bare
            // address in the trace — withheld from the notice AND unexplained
            // in the diagnostic, which is the worst of both.
            let named_by_port = matches!(class, AddressClass::Multicast | AddressClass::Broadcast)
                || is_private(ip);
            named_by_port.then(|| port_purpose(port)).flatten()
        })
        .or(match class {
            AddressClass::Multicast => Some("multicast"),
            AddressClass::Broadcast => Some("broadcast"),
            AddressClass::LinkLocal => Some("link-local"),
            _ => None,
        })
}

fn fixed_group_v4(ip: Ipv4Addr) -> Option<&'static str> {
    match ip.octets() {
        [224, 0, 0, 1] => Some("all-nodes"),
        [224, 0, 0, 2] => Some("all-routers"),
        [224, 0, 0, 22] => Some("igmp"),
        [224, 0, 0, 251] => Some("mdns"),
        [224, 0, 0, 252] => Some("llmnr"),
        [239, 255, 255, 250] => Some("ssdp"),
        _ => None,
    }
}

fn fixed_group_v6(ip: Ipv6Addr) -> Option<&'static str> {
    // Solicited-node `ff02::1:ff00:0/104` — one group per neighbour address,
    // so it is a prefix test rather than a table entry.
    let seg = ip.segments();
    if seg[..6] == [0xff02, 0, 0, 0, 0, 1] && (seg[6] & 0xff00) == 0xff00 {
        return Some("ndp");
    }
    match seg {
        [0xff02, 0, 0, 0, 0, 0, 0, 1] => Some("all-nodes"),
        [0xff02, 0, 0, 0, 0, 0, 0, 2] => Some("all-routers"),
        [0xff02, 0, 0, 0, 0, 0, 0, 0xc] => Some("ssdp"),
        [0xff02, 0, 0, 0, 0, 0, 0, 0x16] => Some("mld"),
        [0xff02, 0, 0, 0, 0, 0, 0, 0xfb] | [0xff05, 0, 0, 0, 0, 0, 0, 0xfb] => Some("mdns"),
        [0xff02, 0, 0, 0, 0, 0, 1, 2] | [0xff05, 0, 0, 0, 0, 0, 1, 3] => Some("dhcpv6"),
        [0xff02, 0, 0, 0, 0, 0, 1, 3] => Some("llmnr"),
        _ => None,
    }
}

/// Applications that pick their own multicast group but keep a fixed port.
fn port_purpose(port: u16) -> Option<&'static str> {
    match port {
        137 | 138 => Some("netbios"),
        546 | 547 => Some("dhcpv6"),
        1900 => Some("ssdp"),
        3702 => Some("ws-discovery"),
        5353 => Some("mdns"),
        5355 => Some("llmnr"),
        6771 => Some("bittorrent-lpd"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("address literal")
    }

    #[test]
    fn multicast_broadcast_and_link_local_are_housekeeping() {
        for addr in [
            "ff02::fb",
            "ff15::efc0:988f",
            "fe80::1",
            "224.0.0.251",
            "255.255.255.255",
            "169.254.10.1",
        ] {
            assert!(
                classify(ip(addr)).is_local_housekeeping(),
                "{addr} should be housekeeping"
            );
        }
    }

    /// The case the address alone cannot answer: a subnet-directed broadcast
    /// looks exactly like a host address, so a dropped NetBIOS-NS to it raised
    /// a notice about a destination no rule can name. The port settles it.
    #[test]
    fn a_discovery_port_inside_a_private_network_is_housekeeping() {
        for (addr, port) in [
            ("192.168.1.255", 137), // NetBIOS-NS to a /24 broadcast
            ("192.168.0.255", 138), // NetBIOS datagram service
            ("10.0.0.255", 3702),   // WS-Discovery
            ("172.16.5.4", 5353),   // mDNS to a specific private host
            ("192.168.1.7", 5355),  // LLMNR
            ("fd00::1", 5353),      // unique-local v6
        ] {
            assert!(
                is_local_housekeeping_endpoint(ip(addr), port),
                "{addr}:{port} should be housekeeping"
            );
        }
    }

    /// What the widening must NOT swallow. A public address keeps its notice
    /// whatever the port, an ordinary private destination keeps its notice on
    /// an ordinary port, and BitTorrent's local peer discovery is left alone on
    /// purpose — that is the user's own application announcing itself.
    #[test]
    fn the_port_rule_does_not_quieten_anything_else() {
        for (addr, port) in [
            ("8.8.8.8", 5353),       // public resolver, not our segment
            ("23.10.20.138", 137),   // public host on a discovery port
            ("192.168.1.10", 443),   // private host, ordinary traffic
            ("192.168.1.255", 6771), // BitTorrent LPD — deliberately not ours
            ("100.64.0.1", 5353),    // CGNAT is not a private network
        ] {
            assert!(
                !is_local_housekeeping_endpoint(ip(addr), port),
                "{addr}:{port} must keep its notice"
            );
        }
    }

    /// Withholding the notice must not also withhold the explanation: the drop
    /// still reaches the trace, and the trace has to name the protocol instead
    /// of printing a bare address.
    #[test]
    fn a_private_discovery_endpoint_is_named_in_the_trace() {
        assert_eq!(
            well_known_purpose(ip("192.168.1.255"), 137),
            Some("netbios")
        );
        assert_eq!(
            well_known_purpose(ip("10.0.0.255"), 3702),
            Some("ws-discovery")
        );
        // A public address is still described by class alone — no invented label.
        assert_eq!(well_known_purpose(ip("8.8.8.8"), 137), None);
    }

    #[test]
    fn ordinary_destinations_stay_routable() {
        for addr in ["8.8.8.8", "192.168.0.10", "2606:4700::1111"] {
            assert_eq!(classify(ip(addr)), AddressClass::Routable, "{addr}");
        }
    }

    #[test]
    fn the_v6_groups_seen_in_the_field_are_named() {
        assert_eq!(well_known_purpose(ip("ff02::fb"), 5353), Some("mdns"));
        assert_eq!(well_known_purpose(ip("ff02::16"), 0), Some("mld"));
        assert_eq!(well_known_purpose(ip("ff02::1:2"), 547), Some("dhcpv6"));
        assert_eq!(well_known_purpose(ip("ff02::2"), 0), Some("all-routers"));
        assert_eq!(well_known_purpose(ip("ff02::1:ff3a:1b2c"), 0), Some("ndp"));
    }

    #[test]
    fn a_transient_group_is_named_by_its_port() {
        assert_eq!(
            well_known_purpose(ip("ff15::efc0:988f"), 6771),
            Some("bittorrent-lpd")
        );
        assert_eq!(
            well_known_purpose(ip("239.192.152.143"), 6771),
            Some("bittorrent-lpd")
        );
    }

    #[test]
    fn an_unrecognised_group_still_says_what_class_it_is() {
        assert_eq!(
            well_known_purpose(ip("ff15::1234"), 40000),
            Some("multicast")
        );
        assert_eq!(
            well_known_purpose(ip("169.254.7.7"), 80),
            Some("link-local")
        );
    }

    #[test]
    fn a_routable_destination_has_no_purpose_label() {
        assert_eq!(well_known_purpose(ip("8.8.8.8"), 53), None);
        assert_eq!(well_known_purpose(ip("2606:4700::1111"), 443), None);
    }

    #[test]
    fn the_v6_prefix_tests_hold_at_their_edges() {
        let v6 = |s: &str| match ip(s) {
            IpAddr::V6(a) => a,
            IpAddr::V4(_) => unreachable!("v6 literal"),
        };
        assert!(is_v6_link_local(v6("fe80::1")));
        assert!(is_v6_link_local(v6("febf:ffff::1")));
        assert!(!is_v6_link_local(v6("fec0::1")));
        assert!(is_v6_link_local_multicast(v6("ff02::fb")));
        assert!(!is_v6_link_local_multicast(v6("ff05::fb")));
    }
}

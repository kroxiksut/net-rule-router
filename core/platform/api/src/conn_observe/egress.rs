//! Pure egress-interface derivation.
//!
//! Neither a WFP net event nor an ETW-TCPIP connection event carries the
//! egress interface index. But the OS picks a *local source address* for
//! every outbound connection by routing to the destination, so that source
//! address uniquely identifies the interface the flow left through: a flow
//! out a VPN tunnel is bound to the tunnel adapter's address (e.g. `10.x`),
//! a direct flow to the LAN address (e.g. `192.168.0.x`).
//!
//! This module maps that local address back to an interface index using a
//! snapshot of the host's unicast addresses (e.g. from
//! `GetUnicastIpAddressTable`), then classifies the index against the active
//! primary/secondary routing bindings. Everything here is pure and injected —
//! no OS calls — so it is exhaustively unit-testable; the live table read
//! happens in the wiring layer.

use std::net::IpAddr;

/// The role an egress interface plays relative to the active routing binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressRole {
    /// The primary (provider / direct) interface.
    Primary,
    /// The secondary (e.g. VPN) interface.
    Secondary,
    /// A local loopback flow (127.0.0.0/8 or ::1) — benign local traffic that
    /// never leaves the host and is never routable. Classified as its own role
    /// so the trace does not mislabel localhost as "Other".
    Loopback,
    /// A live interface that is neither the bound primary nor secondary
    /// (another adapter, …).
    Other,
    /// The local address did not map to any known interface.
    Unknown,
}

/// Resolved egress interface for an observed connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EgressInterface {
    /// Interface index the connection's local address belongs to, or `0` when
    /// unresolved (paired with [`EgressRole::Unknown`]).
    pub ifindex: u32,
    pub role: EgressRole,
}

/// Map a connection's local (source) address to the interface index that owns
/// it, using a snapshot of `(unicast address → ifindex)` pairs. Returns `None`
/// when no interface claims the address (e.g. the address was reassigned
/// between connect and observation, the source is unspecified, or — for an
/// IPv6 source — the snapshot only holds IPv4 addresses, in which case the
/// caller reports the egress as unknown: the IPv6-leak signal NRR routes none
/// of in Free).
pub fn ifindex_for_local_addr(local: IpAddr, unicast: &[(IpAddr, u32)]) -> Option<u32> {
    if local.is_unspecified() {
        return None;
    }
    unicast
        .iter()
        .find(|(addr, _)| *addr == local)
        .map(|(_, idx)| *idx)
}

/// Classify an interface index against the active primary/secondary bindings.
/// An index equal to neither (and any index when a binding is absent) is
/// [`EgressRole::Other`].
pub fn classify_role(
    ifindex: u32,
    primary_ifindex: Option<u32>,
    secondary_ifindex: Option<u32>,
) -> EgressRole {
    if primary_ifindex == Some(ifindex) {
        EgressRole::Primary
    } else if secondary_ifindex == Some(ifindex) {
        EgressRole::Secondary
    } else {
        EgressRole::Other
    }
}

/// Full resolution: local address → interface index → role. Yields
/// `EgressInterface { ifindex: 0, role: Unknown }` when the address maps to no
/// interface in the snapshot.
pub fn resolve_egress(
    local: IpAddr,
    unicast: &[(IpAddr, u32)],
    primary_ifindex: Option<u32>,
    secondary_ifindex: Option<u32>,
) -> EgressInterface {
    // A loopback source (127.0.0.0/8 or ::1) is local traffic
    // that never egresses a real link. The unicast table includes the loopback
    // pseudo-interface, so without this short-circuit it resolves to a real
    // ifindex that equals neither binding and is mislabelled `Other`. Classify
    // it explicitly before the generic primary/secondary/other logic. `local`
    // is in scope here, so this does not depend on the snapshot containing the
    // loopback entry (falls back to ifindex 0 if absent).
    if local.is_loopback() {
        return EgressInterface {
            ifindex: ifindex_for_local_addr(local, unicast).unwrap_or(0),
            role: EgressRole::Loopback,
        };
    }
    match ifindex_for_local_addr(local, unicast) {
        Some(ifindex) => EgressInterface {
            ifindex,
            role: classify_role(ifindex, primary_ifindex, secondary_ifindex),
        },
        None => EgressInterface {
            ifindex: 0,
            role: EgressRole::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ETHERNET: u32 = 16;
    const SECONDARY: u32 = 20;
    const WIFI: u32 = 12;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn table() -> Vec<(IpAddr, u32)> {
        vec![
            (v4(192, 168, 0, 50), ETHERNET),
            (v4(10, 8, 0, 6), SECONDARY),
            (v4(192, 168, 1, 77), WIFI),
        ]
    }

    #[test]
    fn maps_secondary_source_address_to_secondary() {
        let e = resolve_egress(v4(10, 8, 0, 6), &table(), Some(ETHERNET), Some(SECONDARY));
        assert_eq!(e.ifindex, SECONDARY);
        assert_eq!(e.role, EgressRole::Secondary);
    }

    #[test]
    fn maps_lan_source_address_to_primary() {
        let e = resolve_egress(
            v4(192, 168, 0, 50),
            &table(),
            Some(ETHERNET),
            Some(SECONDARY),
        );
        assert_eq!(e.ifindex, ETHERNET);
        assert_eq!(e.role, EgressRole::Primary);
    }

    #[test]
    fn live_interface_that_is_neither_binding_is_other() {
        let e = resolve_egress(
            v4(192, 168, 1, 77),
            &table(),
            Some(ETHERNET),
            Some(SECONDARY),
        );
        assert_eq!(e.ifindex, WIFI);
        assert_eq!(e.role, EgressRole::Other);
    }

    #[test]
    fn unknown_local_address_is_unresolved() {
        let e = resolve_egress(
            v4(203, 0, 113, 9),
            &table(),
            Some(ETHERNET),
            Some(SECONDARY),
        );
        assert_eq!(e.ifindex, 0);
        assert_eq!(e.role, EgressRole::Unknown);
    }

    #[test]
    fn loopback_source_is_classified_loopback_not_other() {
        // 127.0.0.1 is in the unicast table on ifindex 1, which
        // equals neither binding; without the loopback short-circuit it would
        // fall through to `Other`. Both v4 and v6 loopback must classify.
        let mut t = table();
        t.push((v4(127, 0, 0, 1), 1));
        let e = resolve_egress(v4(127, 0, 0, 1), &t, Some(ETHERNET), Some(SECONDARY));
        assert_eq!(e.role, EgressRole::Loopback);
        assert_eq!(e.ifindex, 1);
        // v6 loopback with no table entry still classifies (ifindex falls to 0).
        let e6 = resolve_egress(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            &table(),
            Some(ETHERNET),
            Some(SECONDARY),
        );
        assert_eq!(e6.role, EgressRole::Loopback);
        assert_eq!(e6.ifindex, 0);
    }

    #[test]
    fn ipv6_source_against_ipv4_only_table_is_unknown() {
        // Free does not route v6; a v6 source never matches the v4 unicast
        // snapshot, so it surfaces as Unknown — the v6-leak signal.
        let e = resolve_egress(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            &table(),
            Some(ETHERNET),
            Some(SECONDARY),
        );
        assert_eq!(e.role, EgressRole::Unknown);
    }

    #[test]
    fn unspecified_source_never_resolves() {
        assert_eq!(
            ifindex_for_local_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), &table()),
            None
        );
        assert_eq!(
            ifindex_for_local_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), &table()),
            None
        );
    }

    #[test]
    fn classify_without_bindings_is_other() {
        assert_eq!(classify_role(SECONDARY, None, None), EgressRole::Other);
        assert_eq!(
            classify_role(SECONDARY, Some(ETHERNET), None),
            EgressRole::Other
        );
    }
}

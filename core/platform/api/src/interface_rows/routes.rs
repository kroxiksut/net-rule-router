// Reading the local route table: display address and forwarding next hop.

use super::*;

/// Pick the one address a row shows out of everything an adapter holds.
///
/// Two properties the naive "first IPv4" pick lacked. It is DETERMINISTIC — the
/// OS returns addresses in an order it never promised, so the displayed IP
/// could change between two calls with nothing changed on the machine — and it
/// falls back to IPv6, without which an IPv6-only adapter reads as having no
/// address at all and is refused as a route.
///
/// Rank order: a routable IPv4, then a link-local IPv4 (169.254, an adapter
/// that failed DHCP — worth showing, and the caller's own heuristics judge it),
/// then a routable IPv6, then a link-local IPv6. Ties inside a rank go to the
/// numerically smallest, which is arbitrary but stable.
#[must_use]
pub fn preferred_display_address(addresses: &[std::net::IpAddr]) -> Option<String> {
    fn rank(addr: &std::net::IpAddr) -> u8 {
        match addr {
            std::net::IpAddr::V4(v4) if v4.is_link_local() => 1,
            std::net::IpAddr::V4(_) => 0,
            std::net::IpAddr::V6(v6) if v6.is_unicast_link_local() => 3,
            std::net::IpAddr::V6(_) => 2,
        }
    }
    addresses
        .iter()
        .min_by_key(|addr| (rank(addr), **addr))
        .map(std::string::ToString::to_string)
}

/// Derive the next-hop traffic would leave `ifindex` through, for an adapter
/// that exposes **no** classic default gateway.
///
/// OpenVPN / WireGuard TUN links commonly install split-default routes
/// (`0.0.0.0/1` + `128.0.0.0/1`, or a plain `0.0.0.0/0`) pointing at the
/// tunnel **peer** instead of setting a gateway on the adapter, so
/// `GetAdaptersAddresses` reports an empty gateway list even though the link
/// is up and routing fine. Preference order, then lowest metric within a rank
/// (ties broken by the numerically-lowest next-hop, for determinism):
///
/// 1. a real default (`0.0.0.0/0`);
/// 2. a redirect-gateway split half (`0.0.0.0/1` / `128.0.0.0/1`);
/// 3. ANY other route with a real (non-unspecified, non-loopback) next-hop —
///    a last resort: with the catch-alls absent (VPN client
///    still installing them right after media-up, or stripped once the
///    routing layer owns the table and the service restarted, losing its
///    in-memory next-hop cache) the interface often still carries
///    gateway-style host routes through the SAME tunnel peer — including
///    routes this product installed earlier, whose next-hop was that peer.
///    On a point-to-point tunnel every gateway-style route names the one
///    peer, so recovering it from any of them is sound.
///
/// 4. `Some(0.0.0.0)` — **on-link forwarding**. A Wintun/WireGuard link has
///    no peer address at all: its client covers the internet with a set of
///    on-link prefixes (`0.0.0.0/5`, `8.0.0.0/7`, `16.0.0.0/4`, …,
///    `224.0.0.0/3`, or a plain `0.0.0.0/0`), and the tunnel encapsulates
///    whatever is handed to the interface. Routes installed through such a
///    link carry an unspecified next-hop — that is how the client's own
///    routes look, and how the OS expects an interface route to be spelled.
///    Recognised when the on-link prefixes on the interface cover at least
///    half the address space ([`ON_LINK_INTERNET_COVERAGE`]): a host-only
///    `/24` never gets near that, a redirect set always does.
///
/// `None` means there is genuinely nowhere to forward to — an adapter whose
/// routes are all narrow on-link subnets (the host-only virtual-adapter shape,
/// and a freshly connected tunnel before its client has installed any route).
///
/// Single source of truth: both the routing layer (which installs overlays
/// through this next-hop) and the interface enumeration (which reports
/// [`InterfaceRouteRow::has_forwarding_path`]) call this one function, so the
/// GUI can never describe an adapter as unusable that the router would happily
/// route through.
pub fn derive_forwarding_next_hop(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv4Addr> {
    let mut best: Option<(u8, u32, u32)> = None;
    let mut on_link_coverage: u64 = 0;
    for r in routes {
        if r.interface_index != ifindex {
            continue;
        }
        // This block answers "which IPv4 gateway does this interface use";
        // an IPv6 route says nothing about that.
        let (IpAddr::V4(dst), IpAddr::V4(nh_v4)) = (r.destination, r.next_hop) else {
            continue;
        };
        if nh_v4.is_loopback() {
            continue;
        }
        if nh_v4.is_unspecified() {
            on_link_coverage += on_link_internet_coverage(r);
            continue;
        }
        // Rank by how "default" the route is (see the doc comment).
        let pref = match (dst, r.prefix_length) {
            (d, 0) if d.is_unspecified() => 0u8,
            (d, 1) if d.is_unspecified() => 1, // 0.0.0.0/1
            (d, 1) if d == Ipv4Addr::new(128, 0, 0, 0) => 1, // 128.0.0.0/1
            _ => 2,                            // any other gateway-style route
        };
        let cand = (pref, r.metric, u32::from(nh_v4));
        best = Some(match best {
            Some(b) if b <= cand => b,
            _ => cand,
        });
    }
    best.map(|(_, _, nh)| Ipv4Addr::from(nh)).or_else(|| {
        (on_link_coverage >= ON_LINK_INTERNET_COVERAGE).then_some(Ipv4Addr::UNSPECIFIED)
    })
}

/// The IPv6 twin of [`derive_forwarding_next_hop`].
///
/// Same four cases in the same order, in v6 spelling: the default is `::/0`,
/// the redirect halves a client installs are `::/1` and `8000::/1`, and a
/// peerless tunnel is recognised the same way — by on-link prefixes covering
/// at least half the space.
///
/// The scopes that say nothing about forwarding are skipped: `fe80::/10` is on
/// every interface whether or not the network offers IPv6 at all, and
/// `ff00::/8` is multicast. Counting either would call a link routable on the
/// strength of what the OS puts there by default.
///
/// `None` means this interface has no IPv6 forwarding path, which is the
/// answer that keeps a `/128` from being installed through a link that cannot
/// deliver it.
#[must_use]
pub fn derive_forwarding_next_hop_v6(routes: &[RouteEntry], ifindex: u32) -> Option<Ipv6Addr> {
    let mut best: Option<(u8, u32, Ipv6Addr)> = None;
    let mut on_link_coverage: u128 = 0;
    for r in routes {
        if r.interface_index != ifindex {
            continue;
        }
        let (IpAddr::V6(dst), IpAddr::V6(nh)) = (r.destination, r.next_hop) else {
            continue;
        };
        if nh.is_loopback() {
            continue;
        }
        if nh.is_unspecified() {
            on_link_coverage = on_link_coverage.saturating_add(on_link_internet_coverage_v6(r));
            continue;
        }
        let pref = match (dst.segments()[0], r.prefix_length) {
            (_, 0) if dst.is_unspecified() => 0u8,
            (0x0000, 1) => 1, // ::/1
            (0x8000, 1) => 1, // 8000::/1
            _ => 2,           // any other gateway-style route
        };
        let cand = (pref, r.metric, nh);
        best = Some(match best {
            Some(b) if (b.0, b.1) <= (cand.0, cand.1) => b,
            _ => cand,
        });
    }
    best.map(|(_, _, nh)| nh).or_else(|| {
        (on_link_coverage >= ON_LINK_INTERNET_COVERAGE_V6).then_some(Ipv6Addr::UNSPECIFIED)
    })
}

/// Half the IPv6 address space, for the same reason the IPv4 twin uses half of
/// its own.
const ON_LINK_INTERNET_COVERAGE_V6: u128 = 1u128 << 127;

/// How many addresses an on-link IPv6 route contributes towards "covers the
/// internet". A `/128` is the interface's own address; the link-local and
/// multicast scopes are furniture every interface carries.
fn on_link_internet_coverage_v6(r: &RouteEntry) -> u128 {
    let IpAddr::V6(dst) = r.destination else {
        return 0;
    };
    let head = dst.segments()[0];
    if r.prefix_length >= 128 || (head & 0xffc0) == 0xfe80 || (head & 0xff00) == 0xff00 {
        return 0;
    }
    // `1 << 128` does not exist; a `/0` IS the whole space.
    if r.prefix_length == 0 {
        return u128::MAX;
    }
    1u128 << (128 - u32::from(r.prefix_length))
}

/// Half the IPv4 address space. A redirect set on a peerless tunnel covers
/// well over this; the widest thing a host-only or NAT adapter ever carries is
/// a `/8`, which is 1/256 of it.
const ON_LINK_INTERNET_COVERAGE: u64 = 1 << 31;

/// How many addresses an on-link route contributes towards "covers the
/// internet". Host routes and the multicast/reserved top of the space count
/// for nothing: a `/32` is the adapter's own address, and `224.0.0.0/3` is
/// installed on every interface that carries multicast.
fn on_link_internet_coverage(r: &RouteEntry) -> u64 {
    let IpAddr::V4(dst) = r.destination else {
        return 0; // an IPv4 gateway is never learned from an IPv6 route
    };
    if r.prefix_length >= 32 || dst.octets()[0] >= 224 {
        return 0;
    }
    1u64 << (32 - u32::from(r.prefix_length))
}

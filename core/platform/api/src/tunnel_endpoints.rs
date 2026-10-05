//! The servers the machine's tunnels are configured to reach.
//!
//! A tunnel that encapsulates in the kernel (WireGuard and its forks) installs
//! no host route to its server: its socket is steered by a firewall mark
//! instead. So the route table — where every other tunnel's server shows up —
//! never names it, and a plan that only reads routes cannot tell a network rule
//! covering that server from any other one. Each backend answers from the
//! tunnel's own configuration, which keeps stating the peer while the
//! handshake is failing.
//!
//! Windows has no implementation: its client-side tunnels install host routes,
//! and its route coordinator learns the rest from blocked connections.

use std::net::{IpAddr, SocketAddr};

/// Where the machine's kernel tunnels send their encapsulated traffic.
pub trait TunnelEndpointSource: Send + Sync {
    /// The configured peer addresses of every kernel tunnel present now,
    /// deduplicated. Empty when there are none or they cannot be read — the
    /// caller falls back on what it remembered, so a failed read must not
    /// pass for an answer.
    fn tunnel_endpoints(&self) -> Vec<IpAddr>;
}

/// The address of one `host:port` endpoint as tunnel tools print it
/// (`203.0.113.7:51820`, `[2001:db8::1]:51820`); `None` for the `(none)` of a
/// peer that never had one, or anything else that is not an address.
#[must_use]
pub fn parse_endpoint(text: &str) -> Option<IpAddr> {
    text.trim()
        .parse::<SocketAddr>()
        .ok()
        .map(|addr| addr.ip())
        .filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_families_parse_and_a_missing_peer_does_not() {
        assert_eq!(
            parse_endpoint("203.0.113.7:51820"),
            Some("203.0.113.7".parse().expect("ip"))
        );
        assert_eq!(
            parse_endpoint("[2001:db8::1]:51820"),
            Some("2001:db8::1".parse().expect("ip"))
        );
        assert_eq!(parse_endpoint("(none)"), None);
        assert_eq!(parse_endpoint("0.0.0.0:51820"), None);
        assert_eq!(parse_endpoint("203.0.113.7"), None);
    }
}

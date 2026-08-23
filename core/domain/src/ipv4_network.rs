//! One spelling of an IPv4 network, and one place that parses it.
//!
//! Networks reach the product as text the user typed (`10.0.2.0/24`) and as
//! `(address, prefix)` pairs read from the route table. A rule about a network
//! only works if both sides agree on what the network IS — `10.0.2.7/24` and
//! `10.0.2.0/24` name the same one, and a comparison that treats them as
//! different silently drops the user's decision.

use std::net::Ipv4Addr;

/// An IPv4 network in canonical form: the address is already masked, so two
/// values are equal exactly when they name the same network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Network {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Network {
    /// Masks `address` to `prefix_len`. `None` for a prefix over 32.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        let mask: u32 = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        };
        Some(Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix_len,
        })
    }

    /// Parses `a.b.c.d/len`. `None` on anything else — a bare address included:
    /// a network without a prefix is an ambiguity, not a default.
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.trim().split_once('/')?;
        Self::new(address.trim().parse().ok()?, prefix.trim().parse().ok()?)
    }

    pub fn network(self) -> Ipv4Addr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Is `address` inside this network?
    pub fn contains(self, address: Ipv4Addr) -> bool {
        Self::new(address, self.prefix_len) == Some(self)
    }

    /// Canonical text, the same form [`Self::parse`] accepts.
    pub fn to_cidr_string(self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_inside_a_network_names_that_network() {
        let typed = Ipv4Network::parse("10.0.2.7/24").expect("parse");
        let from_route = Ipv4Network::new(Ipv4Addr::new(10, 0, 2, 0), 24).expect("build");
        assert_eq!(
            typed, from_route,
            "the host bits do not change which network it is"
        );
        assert_eq!(typed.to_cidr_string(), "10.0.2.0/24");
    }

    #[test]
    fn containment_follows_the_prefix() {
        let net = Ipv4Network::parse("10.88.0.0/10").expect("parse");
        assert!(net.contains(Ipv4Addr::new(10, 117, 0, 1)), "inside a /10");
        assert!(!net.contains(Ipv4Addr::new(10, 200, 0, 1)), "outside a /10");
        let host = Ipv4Network::parse("192.168.0.5/32").expect("parse");
        assert!(host.contains(Ipv4Addr::new(192, 168, 0, 5)));
        assert!(!host.contains(Ipv4Addr::new(192, 168, 0, 6)));
    }

    #[test]
    fn a_bare_address_is_refused_rather_than_assumed_to_be_a_host_route() {
        assert_eq!(Ipv4Network::parse("10.0.2.7"), None);
    }

    #[test]
    fn nonsense_is_refused() {
        assert_eq!(Ipv4Network::parse(""), None);
        assert_eq!(Ipv4Network::parse("10.0.2.0/33"), None);
        assert_eq!(Ipv4Network::parse("hello/24"), None);
        assert_eq!(Ipv4Network::parse("10.0.2.0/x"), None);
    }

    #[test]
    fn the_edges_of_the_prefix_range_work() {
        let all = Ipv4Network::parse("1.2.3.4/0").expect("parse");
        assert_eq!(all.to_cidr_string(), "0.0.0.0/0");
        let host = Ipv4Network::parse("1.2.3.4/32").expect("parse");
        assert_eq!(host.to_cidr_string(), "1.2.3.4/32");
    }
}

//! When a program looks names up past the system resolver.
//!
//! Rules by name only see what the service's own DNS answers. A program that
//! asks an encrypted resolver of its own reaches addresses no answer we saw
//! explains, so a site rule never applies to it; only an application rule
//! does. Two facts together say so: it talked to a resolver other than ours
//! (encrypted DNS, or plain DNS to a server of its own), and most of the
//! addresses it then reached carry no name.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Distinct unnamed addresses a program must reach before it is judged to
/// resolve on its own. A single unnamed address is a cached answer or a
/// hard-coded endpoint; three is a pattern.
pub const OWN_RESOLVER_UNNAMED_CONFIRMATIONS: usize = 3;

/// Plain DNS: ours answers on the loopback, so a lookup anywhere else on this
/// port is one we never see (`nslookup <server>`, c-ares with its own servers,
/// a hypervisor's NAT relaying its guests).
pub const PLAIN_DNS_PORT: u16 = 53;

/// DNS over TLS has a port of its own, so a connection there is a resolver
/// whoever answers it.
pub const DNS_OVER_TLS_PORT: u16 = 853;

/// DNS over HTTPS shares the web's port; only a known resolver address or name
/// tells it apart from a site.
pub const DNS_OVER_HTTPS_PORT: u16 = 443;

/// One program's connections over the watching window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OwnResolverEvidence {
    /// It reached a resolver other than ours, allowed or not.
    pub resolver_contacted: bool,
    /// Distinct public addresses it reached that no DNS answer we saw named.
    pub unnamed_addresses: usize,
    /// Distinct public addresses it reached that the service's DNS named.
    pub named_addresses: usize,
}

/// The program resolves names itself: it spoke to a resolver of its own and
/// most of where it went is invisible to rules by name.
///
/// A browser that only probes a resolver but takes its answers from the system
/// keeps naming its destinations, so it never qualifies.
#[must_use]
pub fn resolves_names_itself(evidence: OwnResolverEvidence) -> bool {
    evidence.resolver_contacted
        && evidence.unnamed_addresses >= OWN_RESOLVER_UNNAMED_CONFIRMATIONS
        && evidence.unnamed_addresses > evidence.named_addresses
}

/// Is a connection to `remote` a lookup past our resolver? `known_resolver`
/// says the address, or a name it was answered for, is a listed resolver.
#[must_use]
pub fn is_resolver_contact(remote: SocketAddr, known_resolver: bool) -> bool {
    match remote.port() {
        PLAIN_DNS_PORT => !remote.ip().is_loopback(),
        DNS_OVER_TLS_PORT => true,
        DNS_OVER_HTTPS_PORT => known_resolver,
        _ => false,
    }
}

/// Can an address count as a destination a DNS answer would have named?
/// Only public IPv4: a private, shared or virtual address is never in a public
/// answer, and IPv6 rows carry no name to compare against.
#[must_use]
pub fn is_nameable_destination(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_multicast()
        || in_prefix(v4, Ipv4Addr::new(100, 64, 0, 0), 10)
        || in_prefix(v4, Ipv4Addr::new(198, 18, 0, 0), 15)
        || v4.octets()[0] >= 240)
}

fn in_prefix(ip: Ipv4Addr, base: Ipv4Addr, len: u32) -> bool {
    let mask = u32::MAX << (32 - len);
    u32::from(ip) & mask == u32::from(base) & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(contacted: bool, unnamed: usize, named: usize) -> OwnResolverEvidence {
        OwnResolverEvidence {
            resolver_contacted: contacted,
            unnamed_addresses: unnamed,
            named_addresses: named,
        }
    }

    #[test]
    fn a_resolver_contact_followed_by_unnamed_addresses_is_its_own_lookup() {
        assert!(resolves_names_itself(evidence(true, 3, 0)));
        assert!(resolves_names_itself(evidence(true, 5, 4)));
    }

    #[test]
    fn unnamed_addresses_without_a_resolver_say_nothing() {
        assert!(!resolves_names_itself(evidence(false, 30, 0)));
    }

    #[test]
    fn a_program_that_still_names_most_destinations_uses_the_system() {
        assert!(!resolves_names_itself(evidence(true, 4, 4)));
        assert!(!resolves_names_itself(evidence(true, 3, 12)));
    }

    #[test]
    fn two_unnamed_addresses_are_not_enough() {
        assert!(!resolves_names_itself(evidence(true, 2, 0)));
    }

    #[test]
    fn the_tls_port_is_a_resolver_and_the_web_port_only_when_listed() {
        let at = |port| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port);
        assert!(is_resolver_contact(at(853), false));
        assert!(is_resolver_contact(at(443), true));
        assert!(!is_resolver_contact(at(443), false));
        assert!(!is_resolver_contact(at(80), true));
    }

    /// A program asking a DNS server of its own by plain DNS resolves past us
    /// as surely as one using DoH; asking ours on the loopback is the system's
    /// way.
    #[test]
    fn plain_dns_to_any_server_but_ours_is_a_resolver_contact() {
        let router = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
        let ours = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
        let ours_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 53);
        assert!(is_resolver_contact(router, false));
        assert!(is_resolver_contact(public, false));
        assert!(!is_resolver_contact(ours, false));
        assert!(!is_resolver_contact(ours_v6, false));
    }

    #[test]
    fn only_public_ipv4_counts_as_a_destination() {
        for local in [
            "10.0.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.5",
            "224.0.0.251",
            "255.255.255.255",
            "::1",
            "2001:db8::1",
        ] {
            let ip: IpAddr = local.parse().expect("address literal");
            assert!(!is_nameable_destination(ip), "{local}");
        }
        assert!(is_nameable_destination(IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 9
        ))));
    }
}

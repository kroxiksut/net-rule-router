//! Non-routable IPv4 filtering shared across the route/cache pipeline.
//!
//! An ad-blocking OS `hosts` file commonly pins ad/tracker domains to the
//! loopback address (`musical.ly 127.0.0.1`) or the unspecified address
//! (`0.0.0.0`). NetRuleRouter observes DNS / seeds rule hostnames, caches
//! those resolutions, and fans them out into `/32` secondary routes. A
//! loopback/unspecified destination must never travel that pipeline:
//!
//! - routing it to the secondary (VPN) link is nonsensical — loopback never
//!   leaves the box;
//! - caching it pollutes the FQDN/IP cache with a bogus mapping;
//! - it produces a spurious "collateral: a direct host shares its IP with a
//!   secondary rule" warning (real logs: `musical.ly → 127.0.0.1`).
//!
//! The fake-IP pool is filtered here for the same reason: those addresses are
//! virtual (they exist only inside the userspace TUN stack), so caching one as
//! a hostname's "real" resolution, fanning it out into a `/32` route, or
//! counting it in the shared-IP census corrupts the model of the real network.
//!
//! Free is IPv4-only — both [`nrr_storage::dto::ResolutionEntry::resolved_ips`]
//! and [`nrr_platform_api::dns_observe::DnsObservation::ipv4s`] carry
//! `Vec<Ipv4Addr>` — so a single IPv4 predicate covers every ingestion and
//! codegen site.

use std::net::{IpAddr, Ipv4Addr};

use nrr_platform_api::fake_ip::FakeIpPoolConfig;

/// `true` when `ip` must never be cached, routed, or flagged as collateral:
/// an address nothing can be reached at (loopback, the unspecified prefix,
/// link-local, multicast, the reserved top of the space — see
/// [`crate::dns_address_sanity::is_unreachable_v4`]) or a fake-IP pool address
/// (virtual — never a real endpoint).
///
/// Screening unreachable space here, at the one predicate every ingestion and
/// codegen site already funnels through, keeps a placeholder out of the
/// pipeline whatever fed it — resolver, seeder, refresh or observer.
///
/// Takes `&Ipv4Addr` so it drops straight into `Iterator::filter` /
/// `Vec::retain` closures, which borrow their items.
#[inline]
pub(crate) fn is_non_routable_v4(ip: &Ipv4Addr) -> bool {
    crate::dns_address_sanity::is_unreachable_v4(ip)
        || FakeIpPoolConfig::is_default_pool_addr(IpAddr::V4(*ip))
}

/// `true` when at least one address comes from the fake-IP pool. Under Mode B
/// the OS resolver path is intercepted by our own resolver, so a system-level
/// re-resolution of a hostname returns OUR virtual address back to us. Such an
/// answer says nothing about the host (it is not a hosts-file pin and not a
/// provider poisoning) — callers use this to skip the answer WITHOUT walking
/// their hosts-file backoff ladder.
#[inline]
pub(crate) fn contains_fake_pool_addr(ips: &[Ipv4Addr]) -> bool {
    ips.iter()
        .any(|ip| FakeIpPoolConfig::is_default_pool_addr(IpAddr::V4(*ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_non_routable() {
        assert!(is_non_routable_v4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(127, 255, 255, 254)));
        assert!(is_non_routable_v4(&Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn unspecified_is_non_routable() {
        assert!(is_non_routable_v4(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_non_routable_v4(&Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn public_and_private_are_routable() {
        assert!(!is_non_routable_v4(&Ipv4Addr::new(93, 184, 216, 34)));
        assert!(!is_non_routable_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_non_routable_v4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_non_routable_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    /// Unreachable space reaches every pinning site through this predicate.
    #[test]
    fn unreachable_space_is_non_routable() {
        assert!(is_non_routable_v4(&Ipv4Addr::new(0, 1, 2, 3)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(169, 254, 10, 1)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(224, 0, 0, 251)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(255, 255, 255, 255)));
        // Documentation prefixes are screened on the DNS-answer path only —
        // elsewhere they are ordinary addresses (and common test fixtures).
        assert!(!is_non_routable_v4(&Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn fake_ip_pool_is_non_routable() {
        assert!(is_non_routable_v4(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(198, 18, 0, 35)));
        assert!(is_non_routable_v4(&Ipv4Addr::new(198, 19, 255, 254)));
        // Neighbours of the /15 stay routable.
        assert!(!is_non_routable_v4(&Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_non_routable_v4(&Ipv4Addr::new(198, 20, 0, 1)));
    }
}

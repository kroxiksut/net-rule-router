//! What the fail-closed posture must never do, and the two pieces of it that
//! are actually shared.
//!
//! ## Invariant
//!
//! Traffic destined for a secondary-route destination **must never silently
//! fall back to the primary** when the secondary adapter is unavailable. It is
//! blocked locally instead. The invariant holds for three secondary states:
//! `PresentNoIp` (configured but no IPv4 address - the critical one, since the
//! traffic would otherwise route via the primary against the user's intent),
//! `PresentDown`, and `Absent`.
//!
//! ## What lives here
//!
//! Two things the enforcement path shares: [`BlockReason`], which names why a
//! block happened for the audit trail, and [`is_exempt_from_blocking`], the one
//! answer to "may this address ever be cut" (loopback and link-local: never).
//!
//! The filter COMPUTATION that used to live here was a second, earlier
//! implementation of the kill-switch with no production caller - the live path
//! is `service-runtime`'s `killswitch_codegen` plus `per_sid_orchestrator`,
//! which have since grown per-SID scoping, weight bands, packet-layer mirrors,
//! IPv6 and the address-ownership arbiter. Keeping a divergent copy green under
//! its own acceptance gate was worse than not having one: the tests passed on
//! mocks while the shipped behaviour was decided elsewhere. Removed 26.08 along
//! with `platform/windows/{apply,verify,rollback}`, which had no callers either.
//!
//! ## Existing connections
//!
//! WFP-block filters apply to **new** connection attempts
//! (`ALE_AUTH_CONNECT`); already-established flows are not terminated.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::adapters::AdapterAvailability;

// ── BlockReason ───────────────────────────────────────────────────────────────

/// Why Fail-Closed blocking is being applied. Surfaced in audit events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockReason {
    /// Secondary adapter is present and up but has no IPv4 address.
    SecondaryPresentNoIp,
    /// Secondary adapter interface is down or disconnected.
    SecondaryDown,
    /// Secondary adapter not found in the system.
    SecondaryAbsent,
}

impl BlockReason {
    /// Classify based on adapter availability.
    pub fn from_availability(avail: AdapterAvailability) -> Option<Self> {
        match avail {
            AdapterAvailability::Available => None,
            AdapterAvailability::PresentNoIp => Some(Self::SecondaryPresentNoIp),
            AdapterAvailability::PresentDown => Some(Self::SecondaryDown),
            AdapterAvailability::Absent => Some(Self::SecondaryAbsent),
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::SecondaryPresentNoIp => "secondary adapter has no IPv4 address",
            Self::SecondaryDown => "secondary adapter is down",
            Self::SecondaryAbsent => "secondary adapter not found",
        }
    }
}

// ── Exemption checks ──────────────────────────────────────────────────────────

/// Returns `true` if this address must never be blocked (loopback or
/// link-local), in either family.
///
/// - `127.0.0.0/8` — loopback; system services, IPC, mDNS stub resolvers
/// - `169.254.0.0/16` — APIPA / link-local; mDNS, LLMNR
/// - `::1/128` — the v6 loopback
/// - `fe80::/10` — the unicast half of SLAAC/NDP
/// - `ff02::/16` — link-local multicast: NDP, DAD, MLD, mDNS, LLMNR, DHCPv6 all
///   address the GROUP, so the unicast exemption above never covers them. It
///   cannot cross a router, so exempting it leaks nothing.
///
/// Takes anything that IS an address so one predicate answers for both
/// families: a second `_v6` spelling would be a second place to forget a case.
pub fn is_exempt_from_blocking(ip: impl Into<IpAddr>) -> bool {
    match ip.into() {
        IpAddr::V4(v4) => is_exempt_v4(v4),
        // One address in two spellings must get one answer.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_exempt_v4(v4),
            None => is_exempt_v6(v6),
        },
    }
}

fn is_exempt_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 127 || (o[0] == 169 && o[1] == 254)
}

fn is_exempt_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    ip == Ipv6Addr::LOCALHOST || (s[0] & 0xffc0) == 0xfe80 || s[0] == 0xff02
}

// ── Deterministic filter ID ───────────────────────────────────────────────────

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    // ── Exemptions ────────────────────────────────────────────────────────

    #[test]
    fn loopback_127_is_always_exempt() {
        assert!(is_exempt_from_blocking(ip(127, 0, 0, 1)));
        assert!(is_exempt_from_blocking(ip(127, 255, 255, 255)));
    }

    #[test]
    fn link_local_169_254_is_always_exempt() {
        assert!(is_exempt_from_blocking(ip(169, 254, 0, 1)));
        assert!(is_exempt_from_blocking(ip(169, 254, 99, 99)));
    }

    #[test]
    fn v6_loopback_and_link_local_scopes_are_exempt() {
        assert!(is_exempt_from_blocking(Ipv6Addr::LOCALHOST));
        assert!(is_exempt_from_blocking(
            "fe80::1".parse::<Ipv6Addr>().expect("literal")
        ));
        // The top of fe80::/10 — a /16 read of the prefix would miss it.
        assert!(is_exempt_from_blocking(
            "febf::1".parse::<Ipv6Addr>().expect("literal")
        ));
        assert!(is_exempt_from_blocking(
            "ff02::fb".parse::<Ipv6Addr>().expect("literal")
        ));
    }

    #[test]
    fn a_mapped_v4_answers_as_its_v4_self() {
        assert!(is_exempt_from_blocking(
            "::ffff:127.0.0.1".parse::<Ipv6Addr>().expect("literal")
        ));
        assert!(!is_exempt_from_blocking(
            "::ffff:8.8.8.8".parse::<Ipv6Addr>().expect("literal")
        ));
    }

    #[test]
    fn routable_v6_is_not_exempt() {
        // fec0::/10 was site-local and is now ordinary space: the /10 mask must
        // not swallow it.
        assert!(!is_exempt_from_blocking(
            "fec0::1".parse::<Ipv6Addr>().expect("literal")
        ));
        assert!(!is_exempt_from_blocking(
            "2001:db8::1".parse::<Ipv6Addr>().expect("literal")
        ));
        // Global multicast is not link-scoped.
        assert!(!is_exempt_from_blocking(
            "ff0e::1".parse::<Ipv6Addr>().expect("literal")
        ));
    }

    #[test]
    fn regular_ips_are_not_exempt() {
        assert!(!is_exempt_from_blocking(ip(10, 0, 0, 1)));
        assert!(!is_exempt_from_blocking(ip(192, 168, 1, 1)));
        assert!(!is_exempt_from_blocking(ip(8, 8, 8, 8)));
    }

    // ── Filter ID determinism ─────────────────────────────────────────────

    // ── compute_block_filters ─────────────────────────────────────────────

    // ── compute_unblock_filter_ids ────────────────────────────────────────

    // ── FailClosedPlan ────────────────────────────────────────────────────

    #[test]
    fn block_reason_from_availability_covers_all_variants() {
        assert!(BlockReason::from_availability(AdapterAvailability::Available).is_none());
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::PresentNoIp),
            Some(BlockReason::SecondaryPresentNoIp)
        );
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::PresentDown),
            Some(BlockReason::SecondaryDown)
        );
        assert_eq!(
            BlockReason::from_availability(AdapterAvailability::Absent),
            Some(BlockReason::SecondaryAbsent)
        );
    }
}

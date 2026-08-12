//! Can a resolved IPv4 address be a real destination at all?
//!
//! A filtering provider does not refuse a name it blocks — it answers it with
//! a placeholder. Field evidence: one router handed the very same pair of
//! addresses to two unrelated hosts, both octets ending in `.0`, with a TTL
//! that counted down honestly (it was a real cache entry upstream, not our
//! bug). We took it at face value and pinned it: routes and packet filters
//! built on an address nothing lives at.
//!
//! Enforcement is only as good as the addresses it is built from, so an answer
//! is screened before any of it is remembered. Two tiers, deliberately
//! different in confidence:
//!
//! - **Reserved ranges** are a fact, not a guess: loopback, link-local,
//!   documentation/benchmark space, multicast, the reserved top of the address
//!   space. An answer claiming a host lives there is synthetic, so the address
//!   is dropped unconditionally.
//! - **A `.0` last octet** is a heuristic. It is the base address of any prefix
//!   of `/24` or narrower — the classic shape of a synthetic placeholder — but
//!   a host in a `/23` or wider prefix may legitimately hold it. So it only
//!   ever costs an answer its *enforcement*, and only when nothing else in that
//!   answer survives; next to a normal address it is simply dropped and the
//!   rest is used.
//!
//! Private space (`10/8`, `172.16/12`, `192.168/16`) passes untouched: routing
//! internal names to an internal address is a product feature, not a defect.
//!
//! Everything here is pure and allocation-free on the clean path — it runs on
//! every resolver answer.

use std::net::Ipv4Addr;

/// Why an address cannot be trusted as a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressDefect {
    /// A reserved / special-purpose range — never a reachable host.
    Reserved,
    /// Last octet `0` — the base address of a `/24`-or-narrower prefix.
    NetworkBase,
}

impl AddressDefect {
    /// Stable, log-friendly wording.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved-range",
            Self::NetworkBase => "network-base",
        }
    }
}

/// `true` when nothing can ever be reached at `ip`, in any context.
///
/// Pure integer comparison on the octets — no allocation, no table lookup.
/// Deliberately excludes private space, which is legitimately routable here.
#[inline]
#[must_use]
pub(crate) fn is_unreachable_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    match a {
        // "This network" — a source-only prefix, and the ad-block `0.0.0.0` pin.
        0 => true,
        // Loopback: never leaves the box.
        127 => true,
        // Link-local autoconfiguration.
        169 => b == 254,
        // Multicast, the reserved top of the space, and the broadcast address.
        224..=255 => true,
        _ => false,
    }
}

/// `true` when `ip` has no business appearing in a public DNS answer:
/// [unreachable](is_unreachable_v4), or one of the prefixes reserved for
/// documentation and benchmarking — a shape only a synthetic answer produces.
///
/// Narrower in scope than [`is_unreachable_v4`] on purpose. The documentation
/// prefixes are ordinary routable bit-patterns; what disqualifies them is the
/// context (an answer claiming a real host lives there), so the rule belongs to
/// the answer path and not to every place that handles an address.
#[inline]
#[must_use]
pub(crate) fn is_reserved_answer_address_v4(ip: &Ipv4Addr) -> bool {
    if is_unreachable_v4(ip) {
        return true;
    }
    let [a, b, c, _] = ip.octets();
    match a {
        // TEST-NET-1.
        192 => b == 0 && c == 2,
        // Benchmark prefix (also the fake-address pool) and TEST-NET-2.
        198 => b == 18 || b == 19 || (b == 51 && c == 100),
        // TEST-NET-3.
        203 => b == 0 && c == 113,
        _ => false,
    }
}

/// `true` when `ip` ends in `.0`. Suspicious, not disqualifying — see the
/// module header for why this is never applied on its own.
#[inline]
#[must_use]
pub(crate) fn is_network_base_v4(ip: &Ipv4Addr) -> bool {
    ip.octets()[3] == 0
}

/// The defect of a single address, worst first. `None` = usable as is.
#[inline]
#[must_use]
pub(crate) fn address_defect(ip: &Ipv4Addr) -> Option<AddressDefect> {
    if is_reserved_answer_address_v4(ip) {
        Some(AddressDefect::Reserved)
    } else if is_network_base_v4(ip) {
        Some(AddressDefect::NetworkBase)
    } else {
        None
    }
}

/// What a whole answer is worth to the enforcement pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnswerSanity {
    /// Every address can be a destination — use the answer unchanged.
    Clean,
    /// Some addresses cannot be. `keep` is what is left and is still enough to
    /// enforce the host.
    Sanitized { keep: Vec<Ipv4Addr> },
    /// Nothing usable survives: the answer is a placeholder, not a resolution.
    /// The host must not be pinned on the strength of it.
    Unusable,
}

/// Screen an answer's addresses. Allocates only when something has to be
/// dropped; the overwhelmingly common clean answer costs one pass.
#[must_use]
pub(crate) fn classify_answer(addresses: &[Ipv4Addr]) -> AnswerSanity {
    let mut usable = 0usize;
    for ip in addresses {
        if address_defect(ip).is_none() {
            usable += 1;
        }
    }
    if usable == 0 {
        return AnswerSanity::Unusable;
    }
    if usable == addresses.len() {
        return AnswerSanity::Clean;
    }
    AnswerSanity::Sanitized {
        keep: addresses
            .iter()
            .copied()
            .filter(|ip| address_defect(ip).is_none())
            .collect(),
    }
}

/// `address (reason)` for every address [`classify_answer`] refuses. Cold path
/// — called only to build a diagnostic line, never to decide anything.
#[must_use]
pub(crate) fn rejected_addresses(addresses: &[Ipv4Addr]) -> Vec<String> {
    addresses
        .iter()
        .filter_map(|ip| address_defect(ip).map(|d| format!("{ip} ({})", d.as_str())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn reserved_ranges_are_rejected() {
        // (address, first-or-last member of the range it stands for)
        let reserved = [
            ip(0, 0, 0, 0),
            ip(0, 255, 255, 255),
            ip(127, 0, 0, 1),
            ip(127, 255, 255, 254),
            ip(169, 254, 0, 1),
            ip(169, 254, 255, 255),
            ip(192, 0, 2, 1),
            ip(192, 0, 2, 255),
            ip(198, 18, 0, 1),
            ip(198, 19, 255, 254),
            ip(198, 51, 100, 7),
            ip(203, 0, 113, 7),
            ip(224, 0, 0, 1),
            ip(239, 255, 255, 255),
            ip(240, 0, 0, 1),
            ip(255, 255, 255, 255),
        ];
        for addr in reserved {
            assert!(
                is_reserved_answer_address_v4(&addr),
                "{addr} should be reserved"
            );
        }
    }

    /// The documentation prefixes are routable bit-patterns — only an ANSWER
    /// claiming a host there is synthetic. Everything else keeps handling them.
    #[test]
    fn documentation_prefixes_are_answer_scoped_only() {
        for addr in [ip(192, 0, 2, 1), ip(198, 51, 100, 7), ip(203, 0, 113, 7)] {
            assert!(is_reserved_answer_address_v4(&addr), "{addr} in an answer");
            assert!(!is_unreachable_v4(&addr), "{addr} is not unreachable");
        }
        // The genuinely unreachable ones hold in both.
        for addr in [ip(0, 0, 0, 1), ip(127, 0, 0, 1), ip(224, 0, 0, 251)] {
            assert!(is_unreachable_v4(&addr), "{addr} is unreachable");
        }
    }

    #[test]
    fn neighbours_of_the_reserved_ranges_stay_usable() {
        let usable = [
            ip(1, 1, 1, 1),
            ip(126, 255, 255, 255),
            ip(128, 0, 0, 1),
            ip(169, 253, 255, 255),
            ip(169, 255, 0, 1),
            ip(192, 0, 1, 1),
            ip(192, 0, 3, 1),
            ip(198, 17, 255, 255),
            ip(198, 20, 0, 1),
            ip(198, 51, 99, 1),
            ip(198, 51, 101, 1),
            ip(203, 0, 112, 1),
            ip(203, 0, 114, 1),
            ip(223, 255, 255, 254),
        ];
        for addr in usable {
            assert!(
                !is_reserved_answer_address_v4(&addr),
                "{addr} should stay usable"
            );
        }
    }

    /// Internal names must keep resolving to internal addresses — routing them
    /// is the product's job.
    #[test]
    fn private_space_is_never_rejected() {
        for addr in [
            ip(10, 0, 0, 1),
            ip(10, 255, 255, 254),
            ip(172, 16, 0, 1),
            ip(172, 31, 255, 254),
            ip(192, 168, 1, 1),
            ip(100, 64, 0, 1),
        ] {
            assert!(!is_reserved_answer_address_v4(&addr), "{addr} is private");
            assert_eq!(address_defect(&addr), None);
        }
    }

    #[test]
    fn a_trailing_zero_is_suspicious_but_not_reserved() {
        let addr = ip(8, 47, 69, 0);
        assert!(!is_reserved_answer_address_v4(&addr));
        assert!(is_network_base_v4(&addr));
        assert_eq!(address_defect(&addr), Some(AddressDefect::NetworkBase));
    }

    #[test]
    fn an_ordinary_answer_is_clean() {
        assert_eq!(
            classify_answer(&[ip(142, 250, 74, 78), ip(10, 0, 0, 5)]),
            AnswerSanity::Clean
        );
    }

    /// Next to a normal address the suspicious one is simply dropped — the
    /// heuristic never costs the host its enforcement here.
    #[test]
    fn a_suspicious_address_beside_a_normal_one_is_dropped() {
        assert_eq!(
            classify_answer(&[ip(8, 47, 69, 0), ip(142, 250, 74, 78)]),
            AnswerSanity::Sanitized {
                keep: vec![ip(142, 250, 74, 78)]
            }
        );
    }

    /// The observed provider placeholder: two unrelated hosts, one pair, every
    /// octet ending in `.0`.
    #[test]
    fn an_all_trailing_zero_answer_is_unusable() {
        assert_eq!(
            classify_answer(&[ip(8, 47, 69, 0), ip(8, 6, 112, 0)]),
            AnswerSanity::Unusable
        );
    }

    #[test]
    fn an_all_reserved_answer_is_unusable() {
        assert_eq!(classify_answer(&[ip(127, 0, 0, 1)]), AnswerSanity::Unusable);
        assert_eq!(classify_answer(&[]), AnswerSanity::Unusable);
    }

    #[test]
    fn rejections_carry_their_reason() {
        assert_eq!(
            rejected_addresses(&[ip(127, 0, 0, 1), ip(8, 47, 69, 0), ip(1, 1, 1, 1)]),
            vec![
                "127.0.0.1 (reserved-range)".to_string(),
                "8.47.69.0 (network-base)".to_string(),
            ]
        );
    }
}

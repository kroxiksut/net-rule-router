//! Can a resolved IPv4 address be a real destination at all?
//!
//! Enforcement is only as good as the addresses it is built from, so an answer
//! is screened before any of it is remembered: an address nothing can live at
//! must never become a route or a packet filter.
//!
//! Only facts qualify. Loopback, link-local, "this network", multicast, the
//! reserved top of the space, and the prefixes set aside for documentation and
//! benchmarking — an answer claiming a host lives there is synthetic, and the
//! address is dropped unconditionally.
//!
//! Private space (`10/8`, `172.16/12`, `192.168/16`) passes untouched: routing
//! internal names to an internal address is a product feature, not a defect.
//!
//! ## Why a trailing `.0` is not treated as synthetic
//!
//! A last octet of `.0` looks like the base address of a subnet and therefore
//! like a synthetic placeholder, but measured against live answers that rule
//! has no true positives: every address it would reject completes a TLS
//! handshake and presents a valid certificate for the queried name — CDN,
//! anti-bot, STUN, telemetry and large-retail front ends alike assign it to an
//! ordinary host. Treating it as synthetic would also cost that host both its
//! enforcement and any suggested route, all on the same false signal.
//!
//! A site the main link cannot carry is real to detect from the connection
//! failing, not from the shape of the address.
//!
//! Everything here is pure and allocation-free on the clean path — it runs on
//! every resolver answer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why an address cannot be trusted as a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AddressDefect {
    /// A reserved / special-purpose range — never a reachable host.
    Reserved,
}

impl AddressDefect {
    /// Stable, log-friendly wording.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved-range",
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

/// `true` when nothing can ever be reached at `ip`, in any context — the IPv6
/// half of [`is_unreachable_v4`].
///
/// Defers to the domain classifier for the four classes it already names
/// (unspecified, loopback, multicast, link-local) rather than restating their
/// prefixes here, and adds the two an address CLASSIFIER has no reason to model
/// because they are not about how a destination is talked about:
///
/// - `::ffff:0:0/96` — an IPv4 address wearing IPv6 clothes. Admitting it would
///   give one address two spellings, and the rule that matches one would miss
///   the other. It belongs on the v4 path, canonicalised, or nowhere.
/// - `100::/64` — the discard prefix (RFC 6666). Traffic to it is dropped by
///   definition, so a name answering with it answers with nothing.
///
/// Unique-local `fc00::/7` is deliberately ALLOWED, mirroring the v4 rule that
/// lets private space through: on this product's own network it is a perfectly
/// good destination.
#[inline]
#[must_use]
pub(crate) fn is_unreachable_v6(ip: &Ipv6Addr) -> bool {
    use nrr_domain::address_class::{classify, AddressClass};

    if !matches!(classify(IpAddr::V6(*ip)), AddressClass::Routable) {
        return true;
    }
    if ip.to_ipv4_mapped().is_some() {
        return true;
    }
    let s = ip.segments();
    // 100::/64
    s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0
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

/// The defect of a single address. `None` = usable as is.
#[inline]
#[must_use]
pub(crate) fn address_defect(ip: &Ipv4Addr) -> Option<AddressDefect> {
    is_reserved_answer_address_v4(ip).then_some(AddressDefect::Reserved)
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

/// `true` when an answer is a PROVIDER placeholder rather than a local block.
///
/// Two things look alike in the addresses alone and mean opposite things: an
/// ad-blocking hosts file pins a name to `127.0.0.1` / `0.0.0.0` because the
/// USER asked for it, while a resolver standing in for a site it will not carry
/// answers with documentation space. The first must never become a suggestion;
/// the second is a site the user cannot open.
///
/// So: nothing in the answer can be a destination, AND at least one address is
/// not one of the unreachable-by-definition ranges a local block uses. Narrow
/// on purpose — the shape of an address is weak evidence, and the module header
/// records what happened when it was stretched.
#[must_use]
pub(crate) fn is_provider_placeholder_answer(addresses: &[Ipv4Addr]) -> bool {
    !addresses.is_empty()
        && matches!(classify_answer(addresses), AnswerSanity::Unusable)
        && addresses.iter().any(|ip| !is_unreachable_v4(ip))
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

    /// The two ways an answer can be useless mean opposite things, and only one
    /// of them is a site the user cannot open.
    #[test]
    fn a_provider_placeholder_is_told_apart_from_a_local_block() {
        // Documentation space in a public answer: nobody lives there.
        assert!(is_provider_placeholder_answer(&[ip(192, 0, 2, 1)]));
        assert!(is_provider_placeholder_answer(&[
            ip(198, 51, 100, 7),
            ip(203, 0, 113, 7)
        ]));

        // An ad-blocking hosts file: the USER asked for this, never suggest it.
        assert!(!is_provider_placeholder_answer(&[ip(127, 0, 0, 1)]));
        assert!(!is_provider_placeholder_answer(&[ip(0, 0, 0, 0)]));
        assert!(!is_provider_placeholder_answer(&[
            ip(127, 0, 0, 1),
            ip(0, 0, 0, 0)
        ]));

        // A working answer, and one carrying documentation space beside a real
        // address — the real one settles it.
        assert!(!is_provider_placeholder_answer(&[ip(104, 20, 33, 106)]));
        assert!(!is_provider_placeholder_answer(&[
            ip(192, 0, 2, 1),
            ip(104, 20, 33, 106)
        ]));
        assert!(!is_provider_placeholder_answer(&[]));
    }

    /// Positive control for addresses a trailing-zero rule would reject. Each
    /// was measured against the live internet: it completed a TLS handshake
    /// and presented a certificate for the queried name, so none of them may
    /// cost its host either enforcement or a suggestion.
    #[test]
    fn a_trailing_zero_is_an_ordinary_address() {
        // Documentation space is out of the question here: this module rejects
        // it by design, so the control needs ordinary public bit-patterns.
        let live = [
            // One anycast pair serving a CDN and an anti-bot front end.
            ip(23, 10, 20, 0),
            ip(45, 60, 70, 0),
            // A STUN endpoint.
            ip(104, 30, 40, 0),
            // A telemetry ingest host and a large retailer, on shared front ends.
            ip(141, 101, 90, 0),
        ];
        for addr in live {
            assert_eq!(address_defect(&addr), None, "{addr} is a real host");
            assert!(!is_provider_placeholder_answer(&[addr]), "{addr}");
        }
        assert_eq!(classify_answer(&live), AnswerSanity::Clean);
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
    fn an_ordinary_answer_is_clean() {
        assert_eq!(
            classify_answer(&[ip(23, 10, 20, 78), ip(10, 0, 0, 5)]),
            AnswerSanity::Clean
        );
    }

    /// Next to a normal address the synthetic one is simply dropped — screening
    /// never costs the host its enforcement here.
    #[test]
    fn a_synthetic_address_beside_a_normal_one_is_dropped() {
        assert_eq!(
            classify_answer(&[ip(192, 0, 2, 1), ip(23, 10, 20, 78)]),
            AnswerSanity::Sanitized {
                keep: vec![ip(23, 10, 20, 78)]
            }
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
            rejected_addresses(&[ip(127, 0, 0, 1), ip(192, 0, 2, 1), ip(1, 1, 1, 1)]),
            vec![
                "127.0.0.1 (reserved-range)".to_string(),
                "192.0.2.1 (reserved-range)".to_string(),
            ]
        );
    }
}

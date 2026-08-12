//! Telling a service name apart from a machine name in a PTR answer.
//!
//! Reverse DNS answers two different kinds of names. `dzen.ru` names a service:
//! learning it from a dropped packet is exactly the point of reverse-learning.
//! `1.80.190.35.bc.googleusercontent.com` names a machine — the operator
//! generated it from the address, it forward-confirms just as well, and it says
//! nothing about who the address serves. Treating the second kind as a service
//! name lets one wide rule (`*.googleusercontent.com`) adopt every machine in
//! the provider's fleet and drag unrelated traffic with it.
//!
//! The tell is that the name spells the address out. Pure and total: no I/O.

use std::net::Ipv4Addr;

/// True when `hostname` embeds `ip`'s four octets as consecutive labels or
/// dash-separated tokens, in either order — the shape every cloud operator uses
/// to auto-generate reverse records (`ec2-3-5-7-9.compute.amazonaws.com`,
/// `95-108-213-1.spider.example.com`, `1.80.190.35.bc.example.com`).
///
/// Deliberately anchored on the address the lookup started from: a name that
/// merely contains four numbers is not suspicious, a name that recites *this*
/// address is generated from it.
pub fn is_address_derived(hostname: &str, ip: Ipv4Addr) -> bool {
    let tokens: Vec<Option<u8>> = hostname
        .trim_end_matches('.')
        .split(['.', '-'])
        .map(parse_octet)
        .collect();
    if tokens.len() < 4 {
        return false;
    }
    let octets = ip.octets();
    let reversed = [octets[3], octets[2], octets[1], octets[0]];
    tokens.windows(4).any(|window| {
        let seen: Option<Vec<u8>> = window.iter().copied().collect();
        seen.is_some_and(|seen| seen == octets || seen == reversed)
    })
}

/// A token counts as an octet only if it is nothing but digits (leading zeros
/// allowed — `003` appears in padded reverse records) and fits in a `u8`.
fn parse_octet(token: &str) -> Option<u8> {
    if token.is_empty() || token.len() > 3 || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn a_reversed_octet_prefix_is_address_derived() {
        assert!(is_address_derived(
            "1.80.190.35.bc.googleusercontent.com",
            ip(35, 190, 80, 1)
        ));
    }

    #[test]
    fn a_dashed_forward_prefix_is_address_derived() {
        assert!(is_address_derived(
            "ec2-3-5-7-9.eu-west-1.compute.amazonaws.com",
            ip(3, 5, 7, 9)
        ));
        assert!(is_address_derived(
            "95-108-213-1.spider.example.com",
            ip(95, 108, 213, 1)
        ));
    }

    #[test]
    fn padded_octets_still_read_as_the_address() {
        assert!(is_address_derived(
            "static.003.005.007.009.clients.example.net",
            ip(3, 5, 7, 9)
        ));
    }

    #[test]
    fn a_service_name_is_not_address_derived() {
        assert!(!is_address_derived("dzen.ru", ip(87, 250, 250, 242)));
        assert!(!is_address_derived(
            "lh3.googleusercontent.com",
            ip(142, 250, 74, 33)
        ));
    }

    #[test]
    fn numbers_belonging_to_another_address_do_not_count() {
        assert!(!is_address_derived(
            "1.2.3.4.example.com",
            ip(35, 190, 80, 1)
        ));
    }

    #[test]
    fn octets_must_be_consecutive() {
        assert!(!is_address_derived(
            "3.5.host.7.9.example.com",
            ip(3, 5, 7, 9)
        ));
    }
}

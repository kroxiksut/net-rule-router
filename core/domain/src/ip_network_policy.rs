//! Which networks a rule may name, and how wide is "wide".
//!
//! One place for the widths every layer reads: validation refuses a network
//! past [`widest_rule_prefix`], warns past [`fail_closed_widest_prefix`], and
//! Fail-Closed holds only networks within the latter. Each family has its own
//! numbers: an IPv6 `/16` is not the share of anything an IPv4 `/16` is.

use std::net::IpAddr;

use nrr_shared::ip_block::{IpBlock, IpRange};

use crate::address_class::AddressClass;

/// A rule network wider than this prefix is refused. IPv4: `10.0.0.0/8` is the
/// widest corporate network a router has to carry. IPv6: `/16`, far wider than
/// any one organisation's allocation.
#[must_use]
pub const fn widest_rule_prefix(is_ipv4: bool) -> u8 {
    if is_ipv4 {
        8
    } else {
        16
    }
}

/// Fail-Closed holds a network with the tunnel down only up to this width;
/// a wider one stays unblocked, and validation says so. IPv6 `/48` is one
/// organisation's site.
#[must_use]
pub const fn fail_closed_widest_prefix(is_ipv4: bool) -> u8 {
    if is_ipv4 {
        16
    } else {
        48
    }
}

/// Wider than a rule may name.
pub fn wider_than_rule_allows(block: IpBlock) -> bool {
    block.prefix_len() < widest_rule_prefix(block.network().is_ipv4())
}

/// What a written address value is, by its shape alone. Section is type, so a
/// value under the wrong heading is answered with the one it belongs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpValueKind {
    Address,
    Subnet,
    Range,
}

impl IpValueKind {
    /// `None` for anything that is not an address, a network or a range.
    pub fn of(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.parse::<IpAddr>().is_ok() {
            Some(Self::Address)
        } else if IpBlock::parse(text).is_some() {
            Some(Self::Subnet)
        } else if IpRange::parse(text).is_some() {
            Some(Self::Range)
        } else {
            None
        }
    }

    /// The rule-type slug of the rules table and the Add dialog.
    pub const fn rule_type_slug(self) -> &'static str {
        match self {
            Self::Address => "exact-ip",
            Self::Subnet => "subnet",
            Self::Range => "ip-range",
        }
    }
}

/// The prefix of a block as wide as `width_bits` in `block`'s family.
pub fn prefix_of_width(is_ipv4: bool, width_bits: u32) -> u32 {
    let bits = if is_ipv4 { 32 } else { 128 };
    bits - width_bits.min(bits)
}

pub use nrr_shared::ip_block::canonical_block;

/// Address classes no rule network may touch: routing them breaks the machine
/// itself rather than reaching a site.
const RESERVED: &[(&str, AddressClass)] = &[
    ("0.0.0.0/8", AddressClass::ThisNetwork),
    ("127.0.0.0/8", AddressClass::Loopback),
    ("224.0.0.0/4", AddressClass::Multicast),
    ("255.255.255.255/32", AddressClass::Broadcast),
    ("::/128", AddressClass::Unspecified),
    ("::1/128", AddressClass::Loopback),
    ("ff00::/8", AddressClass::Multicast),
];

/// Kept with a warning, as an exact link-local address is.
const LINK_LOCAL: &[&str] = &["169.254.0.0/16", "fe80::/10"];

/// RFC 1918, shared address space (CGNAT, where many tunnels number their
/// clients) and unique-local IPv6.
const PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
];

/// A table's networks; every entry parses, which a test holds.
fn networks(texts: &'static [&'static str]) -> impl Iterator<Item = IpBlock> {
    texts.iter().filter_map(|text| IpBlock::parse(text))
}

/// The reserved class `block` touches, if any.
pub fn reserved_overlap(block: IpBlock) -> Option<AddressClass> {
    RESERVED
        .iter()
        .find(|(net, _)| IpBlock::parse(net).is_some_and(|net| net.overlaps(block)))
        .map(|(_, class)| *class)
}

pub fn touches_link_local(block: IpBlock) -> bool {
    networks(LINK_LOCAL).any(|net| net.overlaps(block))
}

/// Is every address of `block` inside a private network?
pub fn is_private(block: IpBlock) -> bool {
    networks(PRIVATE).any(|net| net.covers(block))
}

/// Wider than Fail-Closed holds.
pub fn wider_than_fail_closed(block: IpBlock) -> bool {
    block.prefix_len() < fail_closed_widest_prefix(block.network().is_ipv4())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(text: &str) -> IpBlock {
        IpBlock::parse(text).expect("block")
    }

    #[test]
    fn every_table_entry_parses() {
        for net in RESERVED
            .iter()
            .map(|(n, _)| *n)
            .chain(LINK_LOCAL.iter().copied())
            .chain(PRIVATE.iter().copied())
        {
            assert!(IpBlock::parse(net).is_some(), "{net}");
        }
    }

    #[test]
    fn shape_decides_the_kind() {
        assert_eq!(IpValueKind::of("192.0.2.1"), Some(IpValueKind::Address));
        assert_eq!(IpValueKind::of("2001:db8::/32"), Some(IpValueKind::Subnet));
        assert_eq!(
            IpValueKind::of("10.0.0.1 - 10.0.0.9"),
            Some(IpValueKind::Range)
        );
        assert_eq!(IpValueKind::of("example.com"), None);
        assert_eq!(IpValueKind::of("10.0.0.0/33"), None);
    }

    #[test]
    fn a_mapped_network_is_its_ipv4_network() {
        assert_eq!(
            canonical_block(block("::ffff:10.0.0.0/104")),
            block("10.0.0.0/8")
        );
        assert_eq!(
            canonical_block(block("2001:db8::/32")),
            block("2001:db8::/32")
        );
    }

    #[test]
    fn reserved_and_private_follow_the_tables() {
        assert_eq!(
            reserved_overlap(block("127.0.0.0/16")),
            Some(AddressClass::Loopback)
        );
        assert_eq!(
            reserved_overlap(block("224.0.0.0/8")),
            Some(AddressClass::Multicast)
        );
        assert_eq!(reserved_overlap(block("10.0.0.0/8")), None);
        assert!(touches_link_local(block("169.254.10.0/24")));
        assert!(is_private(block("10.20.0.0/16")));
        assert!(is_private(block("100.72.0.0/16")));
        assert!(!is_private(block("8.0.0.0/8")));
        assert!(wider_than_fail_closed(block("10.0.0.0/15")));
        assert!(!wider_than_fail_closed(block("10.0.0.0/16")));
    }

    /// Each family has its own limits: IPv4 keeps `/8` and `/16`, IPv6 refuses
    /// past `/16` and holds up to one site, `/48`.
    #[test]
    fn limits_follow_the_address_family() {
        assert!(wider_than_rule_allows(block("10.0.0.0/7")));
        assert!(!wider_than_rule_allows(block("10.0.0.0/8")));
        assert!(wider_than_rule_allows(block("2001::/15")));
        assert!(!wider_than_rule_allows(block("2001::/16")));

        assert!(wider_than_fail_closed(block("2001:db8::/47")));
        assert!(!wider_than_fail_closed(block("2001:db8::/48")));
        // An IPv6 /16 is no longer "narrow enough" just because IPv4 says so.
        assert!(wider_than_fail_closed(block("2001::/16")));
    }
}

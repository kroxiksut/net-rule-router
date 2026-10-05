//! Networks and address ranges, one definition for every surface.
//!
//! A subnet rule (`10.0.0.0/8`) and a range rule (`10.0.0.5-10.0.0.40`) reach
//! the product as text, and every consumer — the rule matcher, the overlap
//! screen, the address-ownership arbiter, the filter and route planners — has to
//! agree on which addresses they name. A range is decomposed into the minimal
//! set of aligned blocks once, at construction; past that point the pipeline
//! sees blocks only, so there is no second reading of a range anywhere.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network in canonical form: the address is already masked, so two values
/// are equal exactly when they name the same network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpBlock {
    network: IpAddr,
    prefix_len: u8,
}

impl IpBlock {
    /// Masks `address` to `prefix_len`. `None` for a prefix longer than the
    /// family allows.
    pub fn new(address: IpAddr, prefix_len: u8) -> Option<Self> {
        let bits = family_bits(address);
        if u32::from(prefix_len) > bits {
            return None;
        }
        Some(Self {
            network: from_bits(address, to_bits(address) & mask(prefix_len, bits)),
            prefix_len,
        })
    }

    /// Parses `address/len`. A bare address is refused: a network without a
    /// prefix is an ambiguity, not a default.
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.trim().split_once('/')?;
        let prefix = prefix.trim();
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Self::new(address.trim().parse().ok()?, prefix.parse().ok()?)
    }

    pub fn network(self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    pub fn is_ipv4(self) -> bool {
        self.network.is_ipv4()
    }

    /// The longest prefix of the block's family: 32 or 128.
    pub fn max_prefix_len(self) -> u8 {
        if self.is_ipv4() {
            32
        } else {
            128
        }
    }

    /// One address, written as a network.
    pub fn is_single_address(self) -> bool {
        self.prefix_len == self.max_prefix_len()
    }

    /// The last address inside the block.
    pub fn last(self) -> IpAddr {
        let bits = family_bits(self.network);
        from_bits(
            self.network,
            to_bits(self.network) | !mask(self.prefix_len, bits) & full(bits),
        )
    }

    /// Is `address` inside the block? An address of the other family never is.
    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.is_ipv4()
            && Self::new(address, self.prefix_len).is_some_and(|b| b == self)
    }

    /// Is every address of `other` inside this block?
    pub fn covers(self, other: Self) -> bool {
        other.prefix_len >= self.prefix_len && self.contains(other.network)
    }

    /// Do the two blocks share any address? Aligned blocks either nest or are
    /// disjoint, so sharing one address means one covers the other.
    pub fn overlaps(self, other: Self) -> bool {
        self.covers(other) || other.covers(self)
    }
}

impl fmt::Display for IpBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

/// An inclusive address range of one family, carried together with its minimal
/// block decomposition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IpRange {
    first: IpAddr,
    last: IpAddr,
    blocks: Vec<IpBlock>,
}

impl IpRange {
    /// `None` when the bounds are of different families or out of order.
    pub fn new(first: IpAddr, last: IpAddr) -> Option<Self> {
        if first.is_ipv4() != last.is_ipv4() || to_bits(first) > to_bits(last) {
            return None;
        }
        Some(Self {
            first,
            last,
            blocks: decompose(first, last),
        })
    }

    /// Parses `first-last`; spaces around either bound are allowed.
    pub fn parse(text: &str) -> Option<Self> {
        let (first, last) = text.trim().split_once('-')?;
        Self::new(first.trim().parse().ok()?, last.trim().parse().ok()?)
    }

    pub fn first(&self) -> IpAddr {
        self.first
    }

    pub fn last(&self) -> IpAddr {
        self.last
    }

    pub fn is_ipv4(&self) -> bool {
        self.first.is_ipv4()
    }

    /// The minimal aligned blocks that cover exactly this range, ascending.
    pub fn blocks(&self) -> &[IpBlock] {
        &self.blocks
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        address.is_ipv4() == self.is_ipv4()
            && (to_bits(self.first)..=to_bits(self.last)).contains(&to_bits(address))
    }

    /// Base-2 logarithm of the address count, rounded up: the prefix width of
    /// the smallest block that could hold the range. A range is only as wide as
    /// a `/N` network when this equals `max_prefix - N`.
    pub fn width_bits(&self) -> u32 {
        let span = to_bits(self.last) - to_bits(self.first);
        if span == 0 {
            0
        } else {
            u128::BITS - span.leading_zeros()
        }
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.first, self.last)
    }
}

fn decompose(first: IpAddr, last: IpAddr) -> Vec<IpBlock> {
    let bits = family_bits(first);
    let (mut cur, end) = (to_bits(first), to_bits(last));
    let mut out = Vec::new();
    loop {
        let align = if cur == 0 {
            bits
        } else {
            cur.trailing_zeros().min(bits)
        };
        // Largest power of two not exceeding `end - cur + 1`; the `+ 1` can
        // only overflow for the whole IPv6 space, which is one block.
        let fit = match (end - cur).checked_add(1) {
            Some(count) => u128::BITS - 1 - count.leading_zeros(),
            None => u128::BITS,
        };
        let size_bits = align.min(fit);
        out.push(IpBlock {
            network: from_bits(first, cur),
            prefix_len: (bits - size_bits) as u8,
        });
        let block_last = if size_bits >= u128::BITS {
            u128::MAX
        } else {
            cur + ((1u128 << size_bits) - 1)
        };
        if block_last >= end {
            return out;
        }
        cur = block_last + 1;
    }
}

fn family_bits(address: IpAddr) -> u32 {
    if address.is_ipv4() {
        32
    } else {
        128
    }
}

fn full(bits: u32) -> u128 {
    if bits >= u128::BITS {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn mask(prefix_len: u8, bits: u32) -> u128 {
    let host_bits = bits - u32::from(prefix_len);
    if host_bits >= u128::BITS {
        0
    } else {
        full(bits) & !((1u128 << host_bits) - 1)
    }
}

fn to_bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// `value` in the family of `like`; a v4 value is always below 2^32 here.
fn from_bits(like: IpAddr, value: u128) -> IpAddr {
    match like {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::from(value as u32)),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::from(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(text: &str) -> IpBlock {
        IpBlock::parse(text).expect("block")
    }

    fn texts(range: &IpRange) -> Vec<String> {
        range.blocks().iter().map(ToString::to_string).collect()
    }

    #[test]
    fn host_bits_do_not_change_which_network_it_is() {
        assert_eq!(block("10.0.2.7/24"), block("10.0.2.0/24"));
        assert_eq!(block("10.0.2.7/24").to_string(), "10.0.2.0/24");
        assert_eq!(block("2001:db8::7/32").to_string(), "2001:db8::/32");
    }

    #[test]
    fn a_bare_address_or_nonsense_is_refused() {
        for bad in [
            "10.0.2.7",
            "10.0.2.0/33",
            "::/129",
            "10.0.2.0/",
            "10.0.2.0/+8",
            "x/8",
        ] {
            assert_eq!(IpBlock::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn containment_follows_the_prefix_and_the_family() {
        let net = block("10.88.0.0/10");
        assert!(net.contains("10.117.0.1".parse().expect("ip")));
        assert!(!net.contains("10.200.0.1".parse().expect("ip")));
        assert!(
            !net.contains("::a58:1".parse().expect("ip")),
            "other family"
        );
        assert_eq!(net.last().to_string(), "10.127.255.255");
        assert_eq!(block("0.0.0.0/0").last().to_string(), "255.255.255.255");
        assert_eq!(
            block("::/0").last().to_string(),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        );
    }

    #[test]
    fn nested_blocks_overlap_and_siblings_do_not() {
        assert!(block("10.0.0.0/8").covers(block("10.1.0.0/16")));
        assert!(!block("10.1.0.0/16").covers(block("10.0.0.0/8")));
        assert!(block("10.1.0.0/16").overlaps(block("10.0.0.0/8")));
        assert!(!block("10.1.0.0/16").overlaps(block("10.2.0.0/16")));
    }

    #[test]
    fn a_range_decomposes_into_the_minimal_aligned_blocks() {
        let r = IpRange::parse("10.0.0.5 - 10.0.0.40").expect("range");
        assert_eq!(
            texts(&r),
            [
                "10.0.0.5/32",
                "10.0.0.6/31",
                "10.0.0.8/29",
                "10.0.0.16/28",
                "10.0.0.32/29",
                "10.0.0.40/32"
            ]
        );
        let aligned = IpRange::parse("10.0.0.0-10.0.255.255").expect("range");
        assert_eq!(texts(&aligned), ["10.0.0.0/16"]);
        let one = IpRange::parse("192.0.2.9-192.0.2.9").expect("range");
        assert_eq!(texts(&one), ["192.0.2.9/32"]);
    }

    #[test]
    fn the_whole_space_is_one_block() {
        let v4 = IpRange::parse("0.0.0.0-255.255.255.255").expect("range");
        assert_eq!(texts(&v4), ["0.0.0.0/0"]);
        let v6 = IpRange::parse("::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").expect("range");
        assert_eq!(texts(&v6), ["::/0"]);
    }

    #[test]
    fn decomposed_blocks_tile_the_range_exactly() {
        let r = IpRange::parse("2001:db8::ff-2001:db8::1:3").expect("range");
        let mut next = to_bits(r.first());
        for b in r.blocks() {
            assert_eq!(to_bits(b.network()), next, "no gap, no overlap");
            next = to_bits(b.last()) + 1;
        }
        assert_eq!(next - 1, to_bits(r.last()));
    }

    #[test]
    fn a_range_out_of_order_or_across_families_is_refused() {
        assert_eq!(IpRange::parse("10.0.0.9-10.0.0.1"), None);
        assert_eq!(IpRange::parse("10.0.0.1-::1"), None);
        assert_eq!(IpRange::parse("10.0.0.1"), None);
    }

    #[test]
    fn range_width_is_the_smallest_block_that_holds_it() {
        let w = |t: &str| IpRange::parse(t).expect("range").width_bits();
        assert_eq!(w("10.0.0.1-10.0.0.1"), 0);
        assert_eq!(w("10.0.0.0-10.0.0.255"), 8);
        assert_eq!(w("10.0.0.0-10.0.1.0"), 9);
        assert_eq!(w("10.0.0.0-10.255.255.255"), 24);
        assert!(IpRange::parse("10.0.0.1-10.0.0.50")
            .expect("range")
            .contains("10.0.0.50".parse().expect("ip")));
    }
}

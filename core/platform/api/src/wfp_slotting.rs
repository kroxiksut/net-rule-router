//! Slot-packing of address sets into few WFP filters.
//!
//! WFP joins multiple conditions on the SAME field within one filter with OR,
//! so one filter can guard a whole set of remote addresses. The per-address
//! filter form let the standing filter count grow linearly with resolved rule
//! addresses (thousands), which the BFE host demonstrably does not survive for
//! hours. Packing bounds the standing count by slots, not addresses.
//!
//! The partition must be a pure function of the address SET and must localize
//! change: adding one address may only rewrite the chunk it lands in. Sorted
//! chunking fails that (one insert shifts every boundary), so addresses are
//! hash-partitioned into a fixed number of slots; members are sorted within a
//! slot only for a canonical digest and condition order.
//!
//! Both families pack the same way. `FWPM_CONDITION_IP_REMOTE_ADDRESS` is one
//! field whichever family the layer is, so an unpacked IPv6 half would have
//! reintroduced exactly the linear growth the v4 half was packed to stop.
//!
//! Both Windows lowerings (the production spec codegen and the neutral-plan
//! `lower_windows`) MUST call this module — the behavioral oracle compares
//! their outputs key-for-key, and two hand-kept copies of the partition is
//! exactly the drift it exists to catch.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Fixed slot count. Small enough that a fully populated set stays at tens of
/// filters, large enough that one slot rewrite touches ~1/16 of the addresses.
pub const SLOT_COUNT: u8 = 16;

/// Cap of OR'd address conditions per filter. Conservative: Windows Firewall
/// itself lowers multi-address rules into single filters with dozens of
/// conditions, but the ceiling is undocumented — the HW probe validates this
/// value before it is trusted. A slot past the cap splits into parts.
pub const SET_MAX_CONDITIONS: usize = 64;

/// An address the partition can hash and order. Implemented for both families
/// and nothing else; the octets ARE the hash input, so the mapping is fixed by
/// the address itself rather than by a per-family spelling of it.
pub trait SlotAddr: Copy + Ord {
    /// Fixed-width big-endian octets — no ambiguity in the digest.
    type Octets: IntoIterator<Item = u8>;
    fn slot_octets(self) -> Self::Octets;
}

impl SlotAddr for Ipv4Addr {
    type Octets = [u8; 4];
    fn slot_octets(self) -> [u8; 4] {
        self.octets()
    }
}

impl SlotAddr for Ipv6Addr {
    type Octets = [u8; 16];
    fn slot_octets(self) -> [u8; 16] {
        self.octets()
    }
}

/// One packed chunk: every address of one hash slot (or one part of an
/// overflowing slot), sorted, with a digest that changes iff the membership
/// changes — the digest goes into the filter id, so a membership change mints
/// a new id and the reconcile replaces the filter make-before-break.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotChunk<A> {
    pub slot: u8,
    pub part: u16,
    pub members: Vec<A>,
    digest: u64,
}

/// The IPv4 packing (the historic spelling, kept because it reads at the call
/// site where the family is already known).
pub type V4SlotChunk = SlotChunk<Ipv4Addr>;
/// The IPv6 packing.
pub type V6SlotChunk = SlotChunk<Ipv6Addr>;

impl<A> SlotChunk<A> {
    /// FNV-1a over the sorted members (fixed-width octets — no ambiguity).
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Stable filter-id segment: `set-s<slot>-p<part>-<digest>`. The digest
    /// makes the id content-addressed; slot/part keep colliding digests of
    /// different chunks apart.
    ///
    /// The family is NOT in the segment: the digest is taken over octets of a
    /// fixed width per family, and the id the segment feeds already carries the
    /// layer's own kind tag.
    pub fn id_seg(&self) -> String {
        format!(
            "set-s{:02}-p{:02}-{:016x}",
            self.slot, self.part, self.digest
        )
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: impl IntoIterator<Item = u8>, seed: u64) -> u64 {
    let mut hash = seed;
    for b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Which slot an address belongs to. Pure; the partition contract both
/// lowerings share.
pub fn slot_of<A: SlotAddr>(ip: A) -> u8 {
    (fnv1a(ip.slot_octets(), FNV_OFFSET) % u64::from(SLOT_COUNT)) as u8
}

/// Partition `ips` into packed chunks, ordered by `(slot, part)`. Duplicates
/// collapse; an empty input packs to no chunks. Deterministic in the set —
/// input order never matters.
pub fn pack<A: SlotAddr>(ips: impl IntoIterator<Item = A>) -> Vec<SlotChunk<A>> {
    let mut slots: Vec<Vec<A>> = vec![Vec::new(); usize::from(SLOT_COUNT)];
    for ip in ips {
        slots[usize::from(slot_of(ip))].push(ip);
    }
    let mut chunks = Vec::new();
    for (slot, mut members) in slots.into_iter().enumerate() {
        if members.is_empty() {
            continue;
        }
        members.sort_unstable();
        members.dedup();
        for (part, part_members) in members.chunks(SET_MAX_CONDITIONS).enumerate() {
            let digest = fnv1a(
                part_members.iter().flat_map(|ip| ip.slot_octets()),
                FNV_OFFSET,
            );
            chunks.push(SlotChunk {
                slot: slot as u8,
                part: part as u16,
                members: part_members.to_vec(),
                digest,
            });
        }
    }
    chunks
}

/// [`pack`] over IPv4.
pub fn pack_v4(ips: impl IntoIterator<Item = Ipv4Addr>) -> Vec<V4SlotChunk> {
    pack(ips)
}

/// [`pack`] over IPv6.
pub fn pack_v6(ips: impl IntoIterator<Item = Ipv6Addr>) -> Vec<V6SlotChunk> {
    pack(ips)
}

/// One packed chunk of either family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FamilyChunk {
    V4(V4SlotChunk),
    V6(V6SlotChunk),
}

impl FamilyChunk {
    /// The chunk's filter-id segment, family included so the two families'
    /// chunks can never mint the same id.
    pub fn id_seg(&self) -> String {
        match self {
            Self::V4(c) => c.id_seg(),
            Self::V6(c) => format!("v6-{}", c.id_seg()),
        }
    }
}

/// A mixed-family address set, packed: every IPv4 chunk, then every IPv6 one.
///
/// The ORDER is a contract, not a detail. A chunk's position here becomes its
/// within-band weight ordinal, and both Windows pipelines — the production spec
/// codegen and the neutral-plan lowering — derive that ordinal from this
/// function, so the behavioural oracle compares the same policy at the same
/// weight. Splitting v4 first also keeps a machine with no IPv6 bit-for-bit on
/// the weights it had before the family existed.
pub fn pack_both(ips: impl IntoIterator<Item = std::net::IpAddr>) -> Vec<FamilyChunk> {
    let (v4, v6): (Vec<_>, Vec<_>) = ips.into_iter().partition(|ip| ip.is_ipv4());
    let v4 = v4.into_iter().filter_map(|ip| match ip {
        std::net::IpAddr::V4(a) => Some(a),
        std::net::IpAddr::V6(_) => None,
    });
    let v6 = v6.into_iter().filter_map(|ip| match ip {
        std::net::IpAddr::V6(a) => Some(a),
        std::net::IpAddr::V4(_) => None,
    });
    pack_v4(v4)
        .into_iter()
        .map(FamilyChunk::V4)
        .chain(pack_v6(v6).into_iter().map(FamilyChunk::V6))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn sample(n: u16) -> Vec<Ipv4Addr> {
        (0..n)
            .map(|i| ip(203, 0, (i >> 8) as u8, (i & 0xFF) as u8))
            .collect()
    }

    #[test]
    fn input_order_never_matters() {
        let mut shuffled = sample(300);
        shuffled.reverse();
        shuffled.swap(0, 150);
        assert_eq!(pack_v4(sample(300)), pack_v4(shuffled));
    }

    #[test]
    fn duplicates_collapse() {
        let mut doubled = sample(50);
        doubled.extend(sample(50));
        assert_eq!(pack_v4(sample(50)), pack_v4(doubled));
    }

    #[test]
    fn insertion_rewrites_exactly_one_chunk() {
        let base = pack_v4(sample(300));
        let extra = ip(198, 51, 100, 7);
        let grown = pack_v4(sample(300).into_iter().chain([extra]));
        // No slot overflows at this size, so chunk count is stable and every
        // chunk except the landing slot's is bit-identical.
        assert_eq!(base.len(), grown.len());
        let changed: Vec<_> = base.iter().zip(&grown).filter(|(a, b)| a != b).collect();
        assert_eq!(changed.len(), 1);
        let (before, after) = changed[0];
        assert_eq!(before.slot, slot_of(extra));
        assert_ne!(before.digest(), after.digest());
        assert!(after.members.contains(&extra));
    }

    #[test]
    fn overflowing_slot_splits_into_parts() {
        // Same slot for every member: force it by filtering a large pool.
        let pool: Vec<Ipv4Addr> = (0..40_000u32)
            .map(|i| Ipv4Addr::from(0xCB00_0000 + i))
            .filter(|ip| slot_of(*ip) == 3)
            .take(SET_MAX_CONDITIONS + 5)
            .collect();
        assert_eq!(pool.len(), SET_MAX_CONDITIONS + 5);
        let chunks = pack_v4(pool);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].part, 0);
        assert_eq!(chunks[0].members.len(), SET_MAX_CONDITIONS);
        assert_eq!(chunks[1].part, 1);
        assert_eq!(chunks[1].members.len(), 5);
        assert_ne!(chunks[0].digest(), chunks[1].digest());
    }

    #[test]
    fn chunks_are_sorted_and_id_segs_distinct() {
        let chunks = pack_v4(sample(500));
        let mut segs: Vec<String> = chunks.iter().map(V4SlotChunk::id_seg).collect();
        for pair in chunks.windows(2) {
            assert!((pair[0].slot, pair[0].part) < (pair[1].slot, pair[1].part));
        }
        for c in &chunks {
            assert!(c.members.windows(2).all(|w| w[0] < w[1]));
        }
        segs.sort_unstable();
        segs.dedup();
        assert_eq!(segs.len(), chunks.len());
    }

    #[test]
    fn empty_input_packs_to_nothing() {
        assert!(pack_v4(std::iter::empty()).is_empty());
    }

    // ── IPv6 packs by the same contract ───────────────────────────────────

    fn sample_v6(n: u16) -> Vec<Ipv6Addr> {
        (0..n)
            .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, i >> 8, i & 0xFF))
            .collect()
    }

    #[test]
    fn v6_input_order_never_matters() {
        let mut shuffled = sample_v6(300);
        shuffled.reverse();
        shuffled.swap(0, 150);
        assert_eq!(pack_v6(sample_v6(300)), pack_v6(shuffled));
    }

    #[test]
    fn v6_insertion_rewrites_exactly_one_chunk() {
        let base = pack_v6(sample_v6(300));
        let extra = Ipv6Addr::new(0x2001, 0xdb8, 9, 9, 9, 9, 9, 9);
        let grown = pack_v6(sample_v6(300).into_iter().chain([extra]));
        assert_eq!(base.len(), grown.len());
        let changed: Vec<_> = base.iter().zip(&grown).filter(|(a, b)| a != b).collect();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].0.slot, slot_of(extra));
        assert!(changed[0].1.members.contains(&extra));
    }

    #[test]
    fn v6_overflowing_slot_splits_into_parts() {
        let pool: Vec<Ipv6Addr> = (0..40_000u32)
            .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, (i >> 16) as u16, i as u16))
            .filter(|ip| slot_of(*ip) == 3)
            .take(SET_MAX_CONDITIONS + 5)
            .collect();
        assert_eq!(pool.len(), SET_MAX_CONDITIONS + 5);
        let chunks = pack_v6(pool);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].members.len(), SET_MAX_CONDITIONS);
        assert_eq!(chunks[1].members.len(), 5);
    }

    #[test]
    fn the_two_families_do_not_share_a_partition() {
        // Same numeric value, different family: nothing about the v4 packing
        // may be reused to reason about the v6 one.
        let v4 = pack_v4([ip(203, 0, 113, 5)]);
        let v6 = pack_v6([Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xcb00, 0x7105)]);
        assert_eq!(v4.len(), 1);
        assert_eq!(v6.len(), 1);
        assert_ne!(v4[0].digest(), v6[0].digest());
    }
}

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
//! Both Windows lowerings (the production spec codegen and the neutral-plan
//! `lower_windows`) MUST call this module — the behavioral oracle compares
//! their outputs key-for-key, and two hand-kept copies of the partition is
//! exactly the drift it exists to catch.

use std::net::Ipv4Addr;

/// Fixed slot count. Small enough that a fully populated set stays at tens of
/// filters, large enough that one slot rewrite touches ~1/16 of the addresses.
pub const V4_SLOT_COUNT: u8 = 16;

/// Cap of OR'd address conditions per filter. Conservative: Windows Firewall
/// itself lowers multi-address rules into single filters with dozens of
/// conditions, but the ceiling is undocumented — the HW probe validates this
/// value before it is trusted. A slot past the cap splits into parts.
pub const V4_SET_MAX_CONDITIONS: usize = 64;

/// One packed chunk: every address of one hash slot (or one part of an
/// overflowing slot), sorted, with a digest that changes iff the membership
/// changes — the digest goes into the filter id, so a membership change mints
/// a new id and the reconcile replaces the filter make-before-break.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V4SlotChunk {
    pub slot: u8,
    pub part: u16,
    pub members: Vec<Ipv4Addr>,
    digest: u64,
}

impl V4SlotChunk {
    /// FNV-1a over the sorted members (fixed 4-byte encoding — no ambiguity).
    pub fn digest(&self) -> u64 {
        self.digest
    }

    /// Stable filter-id segment: `set-s<slot>-p<part>-<digest>`. The digest
    /// makes the id content-addressed; slot/part keep colliding digests of
    /// different chunks apart.
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
pub fn v4_slot_of(ip: Ipv4Addr) -> u8 {
    (fnv1a(ip.octets(), FNV_OFFSET) % u64::from(V4_SLOT_COUNT)) as u8
}

/// Partition `ips` into packed chunks, ordered by `(slot, part)`. Duplicates
/// collapse; an empty input packs to no chunks. Deterministic in the set —
/// input order never matters.
pub fn pack_v4(ips: impl IntoIterator<Item = Ipv4Addr>) -> Vec<V4SlotChunk> {
    let mut slots: Vec<Vec<Ipv4Addr>> = vec![Vec::new(); usize::from(V4_SLOT_COUNT)];
    for ip in ips {
        slots[usize::from(v4_slot_of(ip))].push(ip);
    }
    let mut chunks = Vec::new();
    for (slot, mut members) in slots.into_iter().enumerate() {
        if members.is_empty() {
            continue;
        }
        members.sort_unstable();
        members.dedup();
        for (part, part_members) in members.chunks(V4_SET_MAX_CONDITIONS).enumerate() {
            let digest = fnv1a(part_members.iter().flat_map(|ip| ip.octets()), FNV_OFFSET);
            chunks.push(V4SlotChunk {
                slot: slot as u8,
                part: part as u16,
                members: part_members.to_vec(),
                digest,
            });
        }
    }
    chunks
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
        assert_eq!(before.slot, v4_slot_of(extra));
        assert_ne!(before.digest(), after.digest());
        assert!(after.members.contains(&extra));
    }

    #[test]
    fn overflowing_slot_splits_into_parts() {
        // Same slot for every member: force it by filtering a large pool.
        let pool: Vec<Ipv4Addr> = (0..40_000u32)
            .map(|i| Ipv4Addr::from(0xCB00_0000 + i))
            .filter(|ip| v4_slot_of(*ip) == 3)
            .take(V4_SET_MAX_CONDITIONS + 5)
            .collect();
        assert_eq!(pool.len(), V4_SET_MAX_CONDITIONS + 5);
        let chunks = pack_v4(pool);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].part, 0);
        assert_eq!(chunks[0].members.len(), V4_SET_MAX_CONDITIONS);
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
}

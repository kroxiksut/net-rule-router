//! Which of the additional link's networks Fail-Closed holds, and what it must
//! leave open inside them.
//!
//! A held network is blocked off the tunnel, but "the narrower rule wins" still
//! holds: a main-link address or network inside it stays reachable, and so do
//! the tunnel's own server and the attached LANs. Both mechanisms read this one
//! answer, so the Windows filters and the neutral plan cannot hold different
//! things.
//!
//! The shape is two layers that never need a within-band order: holds are
//! blocks, cut-outs are permits that outrank every hold. A cut-out therefore
//! must not cover an additional-link destination; a main network around one is
//! split around it, so the narrower additional rule inside stays held.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use nrr_domain::address_class::canonical_ip;
use nrr_domain::ip_network_policy::{
    canonical_block, fail_closed_widest_prefix, reserved_overlap, touches_link_local,
    wider_than_fail_closed,
};
use nrr_platform_api::enforcement::DstMatch;
use nrr_shared::ip_block::IpBlock;

use crate::address_ownership::{AddressOwnership, Link};
pub use crate::wfp_bands::{NETWORK_CUT_OUT_MAX, NETWORK_HOLD_MAX};

/// Where network holds and cut-outs start in their classes' ordinal space; the
/// WFP lowering's network windows start at the same index (`wfp_bands`, which
/// also asserts it fits).
pub(crate) const NETWORK_ORDINAL_BASE: u32 = crate::wfp_bands::NETWORK_INDEX_BASE as u32;

/// What the hold is computed from. Every set is the arbiter's answer, not a
/// re-derivation: the networks must be the ones the routes actually carry, or a
/// network the tunnel never routes would be blocked on the main link.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkHoldInput<'a> {
    /// The additional link's enforced route networks; a range arrives as its blocks.
    pub additional_networks: &'a [IpBlock],
    /// The main link's enforced route networks.
    pub main_networks: &'a [IpBlock],
    /// Every address a main-link rule names (`AddressOwnership::main_named`):
    /// a named address is never blocked.
    pub main_addresses: &'a [IpAddr],
    /// The per-address pin set: additional-link addresses a main cut-out must
    /// not reopen.
    pub pinned: &'a [IpAddr],
    /// Never blocked whatever the rules say: the tunnel servers, the attached
    /// subnets, the liveness-probe targets.
    pub never_block: &'a [IpBlock],
}

/// The hold, ready for either mechanism. Every list is sorted (IPv4 first:
/// `IpAddr` orders the families that way).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkHolds {
    /// Blocked off the tunnel; none covers another.
    pub held: Vec<IpBlock>,
    /// Open inside a held network; none covers another, none covers an
    /// additional-link destination unless it is a never-block exemption.
    pub cut_outs: Vec<IpBlock>,
    /// Wider than Fail-Closed holds, left open (validation warns about these).
    pub too_wide: Vec<IpBlock>,
    /// Left open because a held network may not touch them: inside a LAN or a
    /// reserved range, or named by the main link as a whole.
    pub spared: Vec<IpBlock>,
    /// Left open because the hold or its cut-outs would pass a cap.
    pub over_cap: Vec<IpBlock>,
}

impl NetworkHolds {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    #[must_use]
    pub fn compute(input: &NetworkHoldInput<'_>) -> Self {
        let main_networks = canonical_set(input.main_networks);
        let never_block = canonical_set(input.never_block);
        let mut out = Self::default();

        let mut eligible = Vec::new();
        for net in canonical_set(input.additional_networks) {
            if wider_than_fail_closed(net) {
                out.too_wide.push(net);
            } else if reserved_overlap(net).is_some()
                || touches_link_local(net)
                // A tie goes to the main link, as an address both name does.
                || main_networks.contains(&net)
                || never_block.iter().any(|keep| keep.covers(net))
            {
                out.spared.push(net);
            } else {
                eligible.push(net);
            }
        }
        // A cut-out never reopens these: they are what a narrower additional
        // rule inside a main network still holds.
        let mut additional_items = eligible.clone();
        additional_items.extend(input.pinned.iter().copied().filter_map(single_address));

        let maximal: Vec<IpBlock> = eligible
            .iter()
            .copied()
            .filter(|net| {
                !eligible
                    .iter()
                    .any(|other| other != net && other.covers(*net))
            })
            .collect();
        let mut main_addresses: Vec<IpBlock> = input
            .main_addresses
            .iter()
            .copied()
            .filter_map(single_address)
            .collect();
        main_addresses.sort_unstable();

        for hold in maximal {
            let mut cuts: Vec<IpBlock> = never_block
                .iter()
                .copied()
                .filter(|keep| hold.covers(*keep))
                .collect();
            // A zone can name tens of thousands of addresses: range, not scan.
            let start = main_addresses.partition_point(|a| a.network() < hold.network());
            cuts.extend(
                main_addresses[start..]
                    .iter()
                    .take_while(|a| a.network() <= hold.last()),
            );
            for main in main_networks.iter().filter(|m| hold.covers(**m)) {
                let holes: Vec<IpBlock> = additional_items
                    .iter()
                    .copied()
                    .filter(|item| item.prefix_len() > main.prefix_len() && main.covers(*item))
                    .collect();
                subtract(*main, &holes, &mut cuts);
            }
            let cuts = without_covered(cuts);
            if out.held.len() >= NETWORK_HOLD_MAX
                || out.cut_outs.len() + cuts.len() > NETWORK_CUT_OUT_MAX
            {
                out.over_cap.push(hold);
                continue;
            }
            out.held.push(hold);
            out.cut_outs.extend(cuts);
        }
        out.cut_outs.sort_unstable();
        out
    }

    /// The hold one pass arms, from the arbiter's networks. A book naming no
    /// additional-link network costs one empty probe and never reads
    /// `never_block`, which is every book while networks are not enforced.
    #[must_use]
    pub fn for_pass(
        ownership: &AddressOwnership,
        pinned: &[IpAddr],
        never_block: impl FnOnce() -> Vec<IpBlock>,
    ) -> Self {
        let additional_networks: Vec<IpBlock> = ownership.networks(Link::Additional).collect();
        if additional_networks.is_empty() {
            return Self::default();
        }
        let main_networks: Vec<IpBlock> = ownership.networks(Link::Main).collect();
        let main_addresses: Vec<IpAddr> = ownership.main_named().iter().copied().collect();
        Self::compute(&NetworkHoldInput {
            additional_networks: &additional_networks,
            main_networks: &main_networks,
            main_addresses: &main_addresses,
            pinned,
            never_block: &never_block(),
        })
    }

    fn left_open(&self) -> LeftOpen<'_> {
        LeftOpen {
            too_wide: &self.too_wide,
            spared: &self.spared,
            over_cap: &self.over_cap,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct LeftOpen<'a> {
    too_wide: &'a [IpBlock],
    spared: &'a [IpBlock],
    over_cap: &'a [IpBlock],
}

impl LeftOpen<'_> {
    fn is_empty(&self) -> bool {
        self.too_wide.is_empty() && self.spared.is_empty() && self.over_cap.is_empty()
    }
}

/// What each principal's hold left open, logged once per change: a pass runs
/// every few seconds and the answer rarely moves.
#[derive(Debug, Default)]
pub struct NetworkHoldLog {
    last: Mutex<HashMap<String, [Vec<IpBlock>; 3]>>,
}

impl NetworkHoldLog {
    /// Log what `holds` leaves open for `sid` unless that was the last thing
    /// logged for it. Nothing left open re-arms the latch.
    pub fn note(&self, sid: &str, holds: &NetworkHolds) {
        let now = holds.left_open();
        {
            let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
            if now.is_empty() {
                last.remove(sid);
                return;
            }
            let unchanged = last.get(sid).is_some_and(|[too_wide, spared, over_cap]| {
                now == LeftOpen {
                    too_wide: too_wide.as_slice(),
                    spared: spared.as_slice(),
                    over_cap: over_cap.as_slice(),
                }
            });
            if unchanged {
                return;
            }
            last.insert(
                sid.to_string(),
                [
                    now.too_wide.to_vec(),
                    now.spared.to_vec(),
                    now.over_cap.to_vec(),
                ],
            );
        }
        if let Some(sample) = now.too_wide.first() {
            tracing::warn!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-network-too-wide",
                sid,
                count = now.too_wide.len(),
                widest_prefix = fail_closed_widest_prefix(sample.network().is_ipv4()),
                sample = %sample,
                "additional-link networks wider than Fail-Closed holds are not leak-protected: while that link is down they leave over the main one",
            );
        }
        if let Some(sample) = now.over_cap.first() {
            tracing::warn!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-network-over-cap",
                sid,
                count = now.over_cap.len(),
                sample = %sample,
                "additional-link networks past the leak-protection limit are not held",
            );
        }
        if let Some(sample) = now.spared.first() {
            tracing::info!(
                target: "nrr::enforcement",
                msg_key = "persid-plan-network-spared",
                sid,
                count = now.spared.len(),
                sample = %sample,
                "additional-link networks left open: they cover a local network, a reserved range or the tunnel server, or the main link names them too",
            );
        }
    }

    /// Drop `sid`'s latch.
    pub fn forget(&self, sid: &str) {
        self.last
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }
}

fn canonical_set(blocks: &[IpBlock]) -> Vec<IpBlock> {
    let mut out: Vec<IpBlock> = blocks.iter().copied().map(canonical_block).collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn single_address(ip: IpAddr) -> Option<IpBlock> {
    let ip = canonical_ip(ip);
    IpBlock::new(ip, if ip.is_ipv4() { 32 } else { 128 })
}

/// Drop every block another one covers, sorted.
fn without_covered(mut blocks: Vec<IpBlock>) -> Vec<IpBlock> {
    blocks.sort_unstable();
    blocks.dedup();
    let mut kept: Vec<IpBlock> = Vec::with_capacity(blocks.len());
    for block in blocks {
        // Sorted by network then width, so a covering block precedes what it
        // covers and is the last one kept whenever it covers anything.
        if !kept.last().is_some_and(|last| last.covers(block)) {
            kept.push(block);
        }
    }
    kept
}

/// Append `block` minus `holes` as aligned blocks. Each hole costs at most one
/// block per prefix bit between the two, never one per address.
fn subtract(block: IpBlock, holes: &[IpBlock], out: &mut Vec<IpBlock>) {
    if holes.iter().any(|hole| hole.covers(block)) {
        return;
    }
    if !holes.iter().any(|hole| block.covers(*hole)) {
        out.push(block);
        return;
    }
    if let Some((low, high)) = halves(block) {
        subtract(low, holes, out);
        subtract(high, holes, out);
    }
}

fn halves(block: IpBlock) -> Option<(IpBlock, IpBlock)> {
    if block.is_single_address() {
        return None;
    }
    let len = block.prefix_len() + 1;
    let host_bit = u32::from(block.max_prefix_len() - len);
    let high = match block.network() {
        IpAddr::V4(net) => IpAddr::V4((u32::from(net) | (1u32 << host_bit)).into()),
        IpAddr::V6(net) => IpAddr::V6((u128::from(net) | (1u128 << host_bit)).into()),
    };
    Some((
        IpBlock::new(block.network(), len)?,
        IpBlock::new(high, len)?,
    ))
}

/// A block as a plan destination; one address stays a host match.
pub(crate) fn block_match(block: IpBlock) -> DstMatch {
    let prefix = block.prefix_len();
    match block.network() {
        IpAddr::V4(net) if block.is_single_address() => DstMatch::HostV4(net),
        IpAddr::V6(net) if block.is_single_address() => DstMatch::HostV6(net),
        IpAddr::V4(net) => DstMatch::SubnetV4 { net, prefix },
        IpAddr::V6(net) => DstMatch::SubnetV6 { net, prefix },
    }
}

/// The never-block set from what the machine reading already holds.
#[must_use]
pub fn never_blocked_networks(
    servers: impl IntoIterator<Item = IpAddr>,
    subnets: impl IntoIterator<Item = (IpAddr, u8)>,
) -> Vec<IpBlock> {
    servers
        .into_iter()
        .filter_map(single_address)
        .chain(
            subnets
                .into_iter()
                .filter_map(|(net, len)| IpBlock::new(net, len)),
        )
        .collect()
}

#[cfg(test)]
mod tests;

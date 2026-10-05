//! Address rules of the two routes whose addresses intersect: exact addresses,
//! subnets and ranges.
//!
//! The same invariant decides as for names: an exact address beats any network
//! and a longer prefix beats a shorter one, piece by piece. Aligned blocks
//! either nest or are disjoint, so every intersecting piece has one narrower
//! side — or both are the same block, a tie the name pass settles the same way.

use std::collections::BTreeMap;
use std::net::IpAddr;

use super::{RouteOverlap, RouteOverlapKind, PRIMARY, SECONDARY};
use crate::ip_block::{IpBlock, IpRange};
use crate::rules_json::{AddressMatchDto, RuleAction, RuleDto};

/// An exact address outranks every network prefix.
const EXACT_STRENGTH: u16 = 256;

struct AddressRule<'a> {
    rule: &'a RuleDto,
    route: &'static str,
    written_type: &'static str,
    written_value: String,
    blocks: Vec<IpBlock>,
    exact: bool,
}

impl AddressRule<'_> {
    fn strength(&self, block: IpBlock) -> u16 {
        if self.exact {
            EXACT_STRENGTH
        } else {
            u16::from(block.prefix_len())
        }
    }

    fn blocks(&self) -> bool {
        self.rule.action == RuleAction::Block
    }

    fn side(&self) -> super::OverlapRule {
        super::OverlapRule {
            rule_id: self.rule.id.clone(),
            route: self.route.to_string(),
            rule_type: self.written_type.to_string(),
            value: self.written_value.clone(),
        }
    }

    fn key_part(&self) -> String {
        format!(
            "{}:{}:{}",
            self.route, self.written_type, self.written_value
        )
    }

    fn size(&self) -> u128 {
        self.blocks
            .iter()
            .map(|b| block_size(*b))
            .fold(0, u128::saturating_add)
    }
}

/// Every intersecting pair of enabled address rules across the two routes.
pub(super) fn find(primary: &[RuleDto], secondary: &[RuleDto]) -> Vec<RouteOverlap> {
    let p = address_rules(primary, PRIMARY);
    let s = address_rules(secondary, SECONDARY);
    if p.is_empty() || s.is_empty() {
        return Vec::new();
    }
    // Pieces of each (primary, secondary) pair: (primary wins, addresses).
    let mut pieces: BTreeMap<(usize, usize), Vec<(bool, u128)>> = BTreeMap::new();
    for (pi, sj, pb, sb) in intersecting_blocks(&p, &s) {
        let (pr, sr) = (&p[pi], &s[sj]);
        let primary_wins = match pr.strength(pb).cmp(&sr.strength(sb)) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            // A Block wins a tie against a route, else the main route does.
            std::cmp::Ordering::Equal => pr.blocks() || !sr.blocks(),
        };
        let shared = block_size(pb).min(block_size(sb));
        pieces
            .entry((pi, sj))
            .or_default()
            .push((primary_wins, shared));
    }
    pieces
        .into_iter()
        .map(|((pi, sj), pieces)| overlap(&p[pi], &s[sj], &pieces))
        .collect()
}

fn overlap(p: &AddressRule<'_>, s: &AddressRule<'_>, pieces: &[(bool, u128)]) -> RouteOverlap {
    let (mut won_by_primary, mut shared) = (0u128, 0u128);
    for (primary_wins, size) in pieces {
        shared = shared.saturating_add(*size);
        if *primary_wins {
            won_by_primary = won_by_primary.saturating_add(*size);
        }
    }
    // Two ranges can split the shared addresses; the side holding most of
    // them is named, and the matcher still decides each address on its own.
    let primary_wins = won_by_primary.saturating_mul(2) >= shared;
    let (winner, loser) = if primary_wins { (p, s) } else { (s, p) };
    let same = p.exact == s.exact && p.blocks == s.blocks;
    let kind = if same {
        RouteOverlapKind::Duplicate
    } else if shared == p.size() || shared == s.size() {
        RouteOverlapKind::Nested
    } else {
        RouteOverlapKind::Intersecting
    };
    let one_blocks = p.blocks() != s.blocks();
    RouteOverlap {
        key: format!("{}>{}", winner.key_part(), loser.key_part()),
        kind,
        winner: winner.side(),
        loser: loser.side(),
        block_wins_tie: one_blocks && kind == RouteOverlapKind::Duplicate,
        // The main route's address inside the additional route's network: it
        // keeps its own link whatever happens to the additional one.
        main_stays_when_additional_down: kind != RouteOverlapKind::Duplicate
            && won_by_primary > 0
            && !p.blocks()
            && !s.blocks()
            && !s.exact,
    }
}

/// `(primary index, secondary index, primary block, secondary block)` for every
/// pair of blocks sharing an address. A sweep over blocks sorted by their first
/// address: nested blocks keep each side's open set a short chain.
fn intersecting_blocks(
    p: &[AddressRule<'_>],
    s: &[AddressRule<'_>],
) -> Vec<(usize, usize, IpBlock, IpBlock)> {
    #[derive(Clone, Copy)]
    struct Span {
        primary: bool,
        rule: usize,
        block: IpBlock,
    }
    let spans = |rules: &[AddressRule<'_>], primary: bool| -> Vec<Span> {
        rules
            .iter()
            .enumerate()
            .flat_map(|(rule, r)| {
                r.blocks.iter().map(move |block| Span {
                    primary,
                    rule,
                    block: *block,
                })
            })
            .collect()
    };
    let mut all = spans(p, true);
    all.extend(spans(s, false));
    // Wider first at an equal start, so a block opens before those it holds.
    all.sort_by_key(|span| (span.block.network(), span.block.prefix_len()));

    let mut out = Vec::new();
    let (mut open_p, mut open_s): (Vec<Span>, Vec<Span>) = (Vec::new(), Vec::new());
    for span in all {
        let start = span.block.network();
        for open in [&mut open_p, &mut open_s] {
            open.retain(|o| o.block.contains(start));
        }
        let (mine, theirs) = if span.primary {
            (&mut open_p, &open_s)
        } else {
            (&mut open_s, &open_p)
        };
        for other in theirs {
            if span.primary {
                out.push((span.rule, other.rule, span.block, other.block));
            } else {
                out.push((other.rule, span.rule, other.block, span.block));
            }
        }
        mine.push(span);
    }
    out
}

fn address_rules<'a>(rules: &'a [RuleDto], route: &'static str) -> Vec<AddressRule<'a>> {
    rules
        .iter()
        .filter(|rule| rule.enabled && rule.app_match.is_none())
        .filter_map(|rule| {
            let (written_type, written_value, blocks, exact) = match rule.address_match.as_ref()? {
                AddressMatchDto::ExactIpv4 { address } | AddressMatchDto::ExactIpv6 { address } => {
                    let addr: IpAddr = address.trim().parse().ok()?;
                    let host = IpBlock::new(addr, if addr.is_ipv4() { 32 } else { 128 })?;
                    ("exact-ip", address.trim().to_string(), vec![host], true)
                }
                AddressMatchDto::Subnet { network } => {
                    let block = IpBlock::parse(network)?;
                    ("subnet", block.to_string(), vec![block], false)
                }
                AddressMatchDto::IpRange { first, last } => {
                    let range =
                        IpRange::new(first.trim().parse().ok()?, last.trim().parse().ok()?)?;
                    (
                        "ip-range",
                        range.to_string(),
                        range.blocks().to_vec(),
                        false,
                    )
                }
                _ => return None,
            };
            Some(AddressRule {
                rule,
                route,
                written_type,
                written_value,
                blocks,
                exact,
            })
        })
        .collect()
}

fn block_size(block: IpBlock) -> u128 {
    let host_bits = u32::from(block.max_prefix_len() - block.prefix_len());
    1u128.checked_shl(host_bits).unwrap_or(u128::MAX)
}

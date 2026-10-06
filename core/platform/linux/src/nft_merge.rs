//! Folding per-address rules into anonymous sets.
//!
//! The output chain is walked by EVERY packet the machine sends, one rule after
//! another, and nothing short-cuts an established flow. A plan states one rule
//! per address — a rule host's addresses, the encrypted-DNS resolvers, the pins
//! — so a few hundred addresses meant a few hundred comparisons per packet:
//! measured on a laptop at ~0.24 µs a rule, the chain cost more than the send
//! itself. Rules that differ only in their destination fold into one rule over
//! an anonymous set, which the kernel answers with one lookup.
//!
//! Folding moves rules, and in a first-match chain order is meaning. A rule may
//! join an earlier rule's set only when no rule it overtakes could have
//! decided one of its packets differently: an overtaken rule with the same
//! verdict changes nothing, and one with a different verdict must not share a
//! destination with it. Anything else starts a new set further down.
//!
//! Rules of different bands never share a set even when their verdicts agree:
//! the comment names the band, and a live table has to read back against the
//! plan — a main-link accept and a tunnel accept are the same verdict here but
//! not the same decision.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use nrr_shared::ip_block::IpBlock;

use crate::nft_ir::{NftMatch, NftRule, NftVerdict};

/// The rules in the same order of meaning, with every foldable run folded.
pub fn fold_into_sets(rules: Vec<NftRule>) -> Vec<NftRule> {
    let mut out = Vec::with_capacity(rules.len());
    let mut run = Run::default();
    for rule in rules {
        match Foldable::of(&rule) {
            Some(foldable) => run.place(foldable, rule),
            None => {
                // No single destination: it may decide any packet, so nothing
                // moves past it in either direction.
                out.extend(std::mem::take(&mut run).finish());
                out.push(rule);
            }
        }
    }
    out.extend(run.finish());
    out
}

/// A rule's destination and everything else that identifies its set.
struct Foldable {
    dst: IpBlock,
    /// Position of the destination among the rule's matches; the folded rule
    /// puts the set back there, so a rule keeps its shape whether folded or not.
    dst_at: usize,
    rest: Vec<NftMatch>,
}

impl Foldable {
    fn of(rule: &NftRule) -> Option<Self> {
        let mut found = None;
        for (at, m) in rule.matches.iter().enumerate() {
            let block = match m {
                NftMatch::DstV4 { net, prefix } => IpBlock::new(IpAddr::V4(*net), *prefix),
                NftMatch::DstV6 { net, prefix } => IpBlock::new(IpAddr::V6(*net), *prefix),
                NftMatch::DstSetV4(_) | NftMatch::DstSetV6(_) => return None,
                _ => continue,
            };
            if found.is_some() {
                return None;
            }
            found = Some((at, block?));
        }
        let (dst_at, dst) = found?;
        let mut rest = rule.matches.clone();
        rest.remove(dst_at);
        Some(Self { dst, dst_at, rest })
    }
}

struct Group {
    band: String,
    rest: Vec<NftMatch>,
    dst_at: usize,
    is_ipv4: bool,
    verdict: NftVerdict,
    dsts: Vec<IpBlock>,
    first_comment: String,
}

impl Group {
    fn same_set(&self, f: &Foldable, verdict: NftVerdict, band: &str) -> bool {
        self.verdict == verdict
            && self.band == band
            && self.dst_at == f.dst_at
            && self.is_ipv4 == f.dst.is_ipv4()
            && self.rest == f.rest
    }

    fn into_rule(self) -> NftRule {
        let count = self.dsts.len();
        let dsts = without_covered(self.dsts);
        let dst = match dsts.as_slice() {
            [one] => single(*one),
            _ if self.is_ipv4 => NftMatch::DstSetV4(dsts),
            _ => NftMatch::DstSetV6(dsts),
        };
        let mut matches = self.rest;
        matches.insert(self.dst_at, dst);
        NftRule {
            matches,
            verdict: self.verdict,
            comment: if count > 1 {
                format!("{} +{}", self.first_comment, count - 1)
            } else {
                self.first_comment
            },
        }
    }
}

/// The groups of one run, and where each destination placed so far went.
/// Single addresses are indexed by address: a plan is mostly hosts, and a scan
/// over every earlier rule per rule would make lowering quadratic.
#[derive(Default)]
struct Run {
    groups: Vec<Group>,
    hosts: HashMap<IpAddr, Vec<(NftVerdict, usize)>>,
    networks: Vec<(IpBlock, NftVerdict, usize)>,
}

impl Run {
    fn place(&mut self, f: Foldable, rule: NftRule) {
        let verdict = rule.verdict;
        let band = band_of(&rule.comment);
        // The latest rule overtaken that could decide one of this rule's
        // packets the other way; joining a set before it would let this rule
        // win instead.
        let must_follow = self.latest_conflict(f.dst, verdict);
        let target = self
            .groups
            .iter()
            .rposition(|g| g.same_set(&f, verdict, band))
            .filter(|&at| must_follow.is_none_or(|after| at > after));
        let at = match target {
            Some(at) => at,
            None => {
                self.groups.push(Group {
                    band: band.to_owned(),
                    rest: f.rest,
                    dst_at: f.dst_at,
                    is_ipv4: f.dst.is_ipv4(),
                    verdict,
                    dsts: Vec::new(),
                    first_comment: rule.comment,
                });
                self.groups.len() - 1
            }
        };
        self.groups[at].dsts.push(f.dst);
        if f.dst.is_single_address() {
            self.hosts
                .entry(f.dst.network())
                .or_default()
                .push((verdict, at));
        } else {
            self.networks.push((f.dst, verdict, at));
        }
    }

    /// The latest group holding a rule with another verdict that shares an
    /// address with `dst`.
    fn latest_conflict(&self, dst: IpBlock, verdict: NftVerdict) -> Option<usize> {
        let other = |v: &NftVerdict| *v != verdict;
        let from_networks = self
            .networks
            .iter()
            .filter(|(net, v, _)| other(v) && net.overlaps(dst))
            .map(|(_, _, g)| *g);
        let from_hosts: Box<dyn Iterator<Item = usize> + '_> = if dst.is_single_address() {
            Box::new(
                self.hosts
                    .get(&dst.network())
                    .into_iter()
                    .flatten()
                    .filter(|(v, _)| other(v))
                    .map(|(_, g)| *g),
            )
        } else {
            Box::new(
                self.hosts
                    .iter()
                    .filter(|(addr, _)| dst.contains(**addr))
                    .flat_map(|(_, placed)| placed.iter())
                    .filter(|(v, _)| other(v))
                    .map(|(_, g)| *g),
            )
        };
        from_networks.chain(from_hosts).max()
    }

    fn finish(self) -> Vec<NftRule> {
        self.groups.into_iter().map(Group::into_rule).collect()
    }
}

/// The band a rule's comment names: everything before its ordinal.
fn band_of(comment: &str) -> &str {
    comment.split('#').next().unwrap_or(comment)
}

/// A set may not hold overlapping intervals, and inside one set a block that
/// another covers adds nothing.
fn without_covered(mut dsts: Vec<IpBlock>) -> Vec<IpBlock> {
    dsts.sort_by_key(|b| (b.prefix_len(), *b));
    let mut networks: Vec<IpBlock> = Vec::new();
    let mut seen = HashSet::new();
    let mut kept = Vec::with_capacity(dsts.len());
    for block in dsts {
        if !seen.insert(block) || networks.iter().any(|n| n.covers(block)) {
            continue;
        }
        if !block.is_single_address() {
            networks.push(block);
        }
        kept.push(block);
    }
    kept.sort();
    kept
}

fn single(block: IpBlock) -> NftMatch {
    match block.network() {
        IpAddr::V4(net) => NftMatch::DstV4 {
            net,
            prefix: block.prefix_len(),
        },
        IpAddr::V6(net) => NftMatch::DstV6 {
            net,
            prefix: block.prefix_len(),
        },
    }
}

#[cfg(test)]
mod tests;

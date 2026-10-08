//! What a network rule's filters cover.
//!
//! A subnet filter covers every address inside it, and one sub-layer has no
//! "continue" verdict, so a narrower rule inside a network cannot be expressed
//! as a higher weight in every posture: the block-all sits BETWEEN the two
//! route bands, so a main-link network outranks a tunnel host inside it exactly
//! where that host must stay below the block. The narrower rule is therefore
//! carved OUT of the network instead: a network filter covers the addresses its
//! rule wins and nothing else, which is the invariant the address rules already
//! keep through the arbiter. Both enforcement planners read this one carving.
//!
//! What is carved, per block of the rule:
//! - a Block network leaves out every narrower ROUTE claim inside it (the
//!   matcher gives a network Block no veto);
//! - a route network leaves out the narrower claims the OTHER link wins inside
//!   it. Same-link claims carry the same verdict and stay covered; Block claims
//!   inside a route network win by band and need no hole.
//!
//! "Narrower" is the matcher's order: an exact address and a hostname or suffix
//! name beat any network, a zone beats one only when zones are evaluated ahead
//! of addresses, and between networks the longer prefix wins (a tie goes to a
//! Block, then to the main link).

use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::rule_shape::{rule_verdict, RuleShapeSupport};
use nrr_domain::RuleAction;
use nrr_shared::ip_block::IpBlock;

use crate::address_ownership::{AddressOwnership, Link, ZoneVsIpOrder};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::wfp_codegen::SUFFIX_FANOUT_BACKSTOP;

use super::{capped_for_host, FamilyScope};

/// Pieces one network rule may cover before carving is abandoned. One per
/// weight slot, so no two pieces of a rule share a weight; a worst-case IPv6
/// range (254 blocks) still fits uncarved.
pub const NETWORK_PIECE_CAP: usize = super::SLOTS_PER_RULE as usize;

/// The narrower claims every network rule is carved against, indexed once per
/// pass.
#[derive(Debug, Default)]
pub struct NetworkCarving {
    /// Addresses an address rule holds against any network, by the link that
    /// actually steers them.
    main_addresses: BTreeSet<IpAddr>,
    additional_addresses: BTreeSet<IpAddr>,
    /// Route networks, by link.
    main_networks: Vec<IpBlock>,
    additional_networks: Vec<IpBlock>,
}

/// One network rule's coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkPieces {
    /// The blocks its filters carry, in address order per rule block.
    pub pieces: Vec<IpBlock>,
    /// `Some(n)` when carving would have needed more than
    /// [`NETWORK_PIECE_CAP`] pieces: the rule then covers its own blocks
    /// uncarved and narrower rules inside it lose to it.
    pub over_cap: Option<usize>,
}

impl NetworkCarving {
    /// Index `rule_book`. Costs nothing when the book has no network rule
    /// enforcement carries, which is the common case: the name sweep below
    /// repeats the arbiter's, and only a network needs it.
    #[must_use]
    pub fn index(
        rule_book: &CanonicalRuleBook,
        cache: &dyn FqdnCacheLookup,
        ownership: &AddressOwnership,
        order: ZoneVsIpOrder,
        shapes: RuleShapeSupport,
        secondary_ip_denylist: &HashSet<Ipv4Addr>,
    ) -> Self {
        let main_networks = route_networks(&rule_book.primary, shapes);
        let additional_networks = route_networks(&rule_book.secondary, shapes);
        let any_network = !main_networks.is_empty()
            || !additional_networks.is_empty()
            || has_network_block(rule_book, shapes);
        if !any_network {
            return Self::default();
        }
        let mut out = Self {
            main_networks,
            additional_networks,
            ..Self::default()
        };
        for (set, link) in [
            (&rule_book.primary, Link::Main),
            (&rule_book.secondary, Link::Additional),
        ] {
            for ip in network_beating_claims(set, cache, order, shapes) {
                // The arbiter decides which link steers a contested address;
                // a claim that lost it emits no filter, so it carves nothing.
                if ownership.owner_of(ip) != Some(link) {
                    continue;
                }
                match link {
                    Link::Main => out.main_addresses.insert(ip),
                    // A shared address the policy kept off the tunnel has no
                    // tunnel filter either.
                    Link::Additional => match ip {
                        IpAddr::V4(v4) if secondary_ip_denylist.contains(&v4) => continue,
                        _ => out.additional_addresses.insert(ip),
                    },
                };
            }
        }
        out
    }

    /// What a network rule on `link` with `action` covers of `blocks`, limited
    /// to the families this pass names.
    #[must_use]
    pub fn pieces(
        &self,
        blocks: &[IpBlock],
        link: Link,
        action: RuleAction,
        families: FamilyScope,
    ) -> NetworkPieces {
        let blocks: Vec<IpBlock> = blocks
            .iter()
            .copied()
            .filter(|b| families.admits(b.network()))
            .collect();
        let mut pieces = Vec::new();
        for block in &blocks {
            let holes = self.holes(*block, link, action);
            if !carve(*block, &holes, &mut pieces, NETWORK_PIECE_CAP) {
                let needed = pieces.len();
                return NetworkPieces {
                    pieces: blocks,
                    over_cap: Some(needed),
                };
            }
        }
        NetworkPieces {
            pieces,
            over_cap: None,
        }
    }

    /// The narrower claims inside `block` its rule must leave alone.
    fn holes(&self, block: IpBlock, link: Link, action: RuleAction) -> Vec<IpBlock> {
        let mut holes = Vec::new();
        let mut take_addresses = |set: &BTreeSet<IpAddr>| {
            holes.extend(
                set.range(block.network()..=block.last())
                    .filter_map(|ip| IpBlock::new(*ip, host_prefix(*ip))),
            );
        };
        match (action, link) {
            (RuleAction::Block, _) => {
                take_addresses(&self.main_addresses);
                take_addresses(&self.additional_addresses);
            }
            (RuleAction::Route | RuleAction::VerifyPrimary, Link::Main) => {
                take_addresses(&self.additional_addresses)
            }
            (RuleAction::Route | RuleAction::VerifyPrimary, Link::Additional) => {
                take_addresses(&self.main_addresses)
            }
        }
        let narrower = |other: &IpBlock, tie_carves: bool| {
            block.covers(*other)
                && (other.prefix_len() > block.prefix_len() || (tie_carves && *other == block))
        };
        match (action, link) {
            (RuleAction::Block, _) => holes.extend(
                self.main_networks
                    .iter()
                    .chain(&self.additional_networks)
                    .filter(|n| narrower(n, false)),
            ),
            (RuleAction::Route | RuleAction::VerifyPrimary, Link::Main) => holes.extend(
                self.additional_networks
                    .iter()
                    .filter(|n| narrower(n, false)),
            ),
            // The main link wins a tie between two route networks.
            (RuleAction::Route | RuleAction::VerifyPrimary, Link::Additional) => {
                holes.extend(self.main_networks.iter().filter(|n| narrower(n, true)));
            }
        }
        holes
    }
}

/// Route networks of `set` that enforcement carries.
fn route_networks(set: &CanonicalRuleSet, shapes: RuleShapeSupport) -> Vec<IpBlock> {
    set.rules()
        .iter()
        .filter(|r| r.enabled && r.action == RuleAction::Route && r.app_match.is_none())
        .filter(|r| rule_verdict(r, shapes).is_supported())
        .filter_map(|r| r.address_match.as_ref().and_then(|m| m.ip_blocks()))
        .flatten()
        .copied()
        .collect()
}

fn has_network_block(rule_book: &CanonicalRuleBook, shapes: RuleShapeSupport) -> bool {
    rule_book
        .primary
        .rules()
        .iter()
        .chain(rule_book.secondary.rules())
        .any(|r| {
            r.enabled
                && r.action == RuleAction::Block
                && r.address_match
                    .as_ref()
                    .and_then(|m| m.ip_blocks())
                    .is_some()
                && rule_verdict(r, shapes).is_supported()
        })
}

/// Addresses `set`'s route rules name in a way that beats any network.
fn network_beating_claims(
    set: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
    order: ZoneVsIpOrder,
    shapes: RuleShapeSupport,
) -> BTreeSet<IpAddr> {
    let mut out = BTreeSet::new();
    let hosts = |names: Vec<String>, out: &mut BTreeSet<IpAddr>| {
        for host in names {
            out.extend(capped_for_host(cache, &host, FamilyScope::Both));
        }
    };
    for rule in set.rules() {
        if !rule.enabled
            || rule.action != RuleAction::Route
            || rule.app_match.is_some()
            || !rule_verdict(rule, shapes).is_supported()
        {
            continue;
        }
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                out.insert(*ip);
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => hosts(vec![host.clone()], &mut out),
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => hosts(
                cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP),
                &mut out,
            ),
            Some(CanonicalAddressMatch::Zone(zone)) if order == ZoneVsIpOrder::ZoneFirst => hosts(
                cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP),
                &mut out,
            ),
            _ => {}
        }
    }
    out
}

fn host_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv4() {
        32
    } else {
        128
    }
}

/// Append `block` minus `holes` to `out` as aligned blocks, in address order.
/// `false` once `out` would grow past `cap`.
fn carve(block: IpBlock, holes: &[IpBlock], out: &mut Vec<IpBlock>, cap: usize) -> bool {
    if holes.iter().any(|h| h.covers(block)) {
        return true;
    }
    let inside: Vec<IpBlock> = holes.iter().copied().filter(|h| block.covers(*h)).collect();
    if inside.is_empty() {
        out.push(block);
        return out.len() <= cap;
    }
    // A hole strictly inside means the block has room to split.
    let Some((low, high)) = halves(block) else {
        return true;
    };
    carve(low, &inside, out, cap) && carve(high, &inside, out, cap)
}

/// The two halves of `block`, `None` for a single address.
fn halves(block: IpBlock) -> Option<(IpBlock, IpBlock)> {
    if block.is_single_address() {
        return None;
    }
    let len = block.prefix_len() + 1;
    let high = match block.network() {
        IpAddr::V4(net) => IpAddr::V4(Ipv4Addr::from(
            u32::from(net) | (1u32 << (32 - u32::from(len))),
        )),
        IpAddr::V6(net) => IpAddr::V6(Ipv6Addr::from(
            u128::from(net) | (1u128 << (128 - u32::from(len))),
        )),
    };
    Some((
        IpBlock::new(block.network(), len)?,
        IpBlock::new(high, len)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(text: &str) -> IpBlock {
        IpBlock::parse(text).expect("valid block")
    }

    fn carved(b: &str, holes: &[&str]) -> Vec<String> {
        let holes: Vec<IpBlock> = holes.iter().map(|h| block(h)).collect();
        let mut out = Vec::new();
        assert!(carve(block(b), &holes, &mut out, usize::MAX));
        out.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_block_without_holes_is_itself() {
        assert_eq!(carved("10.0.0.0/8", &[]), vec!["10.0.0.0/8"]);
        assert_eq!(carved("10.0.0.0/8", &["192.0.2.0/24"]), vec!["10.0.0.0/8"]);
    }

    #[test]
    fn one_address_out_of_a_slash_24_leaves_eight_pieces() {
        let out = carved("192.0.2.0/24", &["192.0.2.7/32"]);
        assert_eq!(out.len(), 8);
        assert_eq!(out[0], "192.0.2.0/30");
        assert!(!out
            .iter()
            .any(|p| block(p).contains("192.0.2.7".parse().expect("ip"))));
        assert!(out
            .iter()
            .any(|p| block(p).contains("192.0.2.6".parse().expect("ip"))));
    }

    #[test]
    fn a_covering_hole_leaves_nothing() {
        assert!(carved("10.1.0.0/16", &["10.0.0.0/8"]).is_empty());
        assert!(carved("10.1.0.0/16", &["10.1.0.0/16"]).is_empty());
    }

    #[test]
    fn an_ipv6_hole_carves_the_same_way() {
        let out = carved("2001:db8::/32", &["2001:db8:8000::/33"]);
        assert_eq!(out, vec!["2001:db8::/33"]);
    }

    #[test]
    fn carving_stops_at_the_cap() {
        let holes = [block("10.0.0.1/32")];
        let mut out = Vec::new();
        assert!(!carve(block("10.0.0.0/8"), &holes, &mut out, 4));
    }
}

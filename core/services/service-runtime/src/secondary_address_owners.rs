//! Which addresses policy sends over the additional link, and the rule that
//! sends each — for the readers that ask after the fact: the connection trace
//! (where a flow was expected to egress) and the resolver's direct-answer
//! steering (which addresses a direct host should not be handed).
//!
//! Host and literal claims come from the secondary rule fan-out the DNS
//! observer already builds; networks come from the arbiter's own
//! longest-prefix table, so a network decides here exactly as it does in
//! enforcement. Built once per rules snapshot; every question is a hash lookup
//! plus one probe per distinct prefix length.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::rule_shape::{rule_verdict, RuleShapeSupport};
use nrr_domain::RuleAction;
use nrr_shared::ip_block::IpBlock;

use crate::address_ownership::Link;
use crate::dns_observation_consumer::secondary_ip_claims;
use crate::enforcement_planner::{capped_for_host, FamilyScope};
use crate::fake_ip::RuleNetworkIndex;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::wfp_codegen::SUFFIX_FANOUT_BACKSTOP;

/// Where the additional link's rules send each address, narrower rule first.
#[derive(Debug, Default)]
pub struct SecondaryAddressOwners {
    /// Literal and host claims, each with the host (or literal) that owns it.
    named: HashMap<Ipv4Addr, String>,
    /// `named` addresses some rule names more closely than a zone.
    closer_than_zone: HashSet<Ipv4Addr>,
    networks: RuleNetworkIndex,
    /// The additional link's networks as the user wrote them, by block: a range
    /// is listed under each of its pieces.
    network_labels: HashMap<IpBlock, String>,
    /// Addresses inside an additional network that a main-link rule names more
    /// closely — literally, or through an exact or suffix name.
    main_closer: HashSet<IpAddr>,
}

impl SecondaryAddressOwners {
    /// Against the shape support this service enforces.
    #[must_use]
    pub fn build(rule_book: &CanonicalRuleBook, fqdn: &dyn FqdnCacheLookup) -> Self {
        Self::build_with_support(
            rule_book,
            fqdn,
            crate::wfp_codegen::current_rule_shape_support(),
        )
    }

    #[must_use]
    pub fn build_with_support(
        rule_book: &CanonicalRuleBook,
        fqdn: &dyn FqdnCacheLookup,
        support: RuleShapeSupport,
    ) -> Self {
        let claims = secondary_ip_claims(&rule_book.secondary, fqdn);
        let networks = RuleNetworkIndex::from_book_with_support(rule_book, support);
        let network_labels = network_labels(&rule_book.secondary, support);
        let main_closer = if network_labels.is_empty() {
            HashSet::new()
        } else {
            main_closer_inside(&rule_book.primary, fqdn, &networks)
        };
        Self {
            named: claims.owners,
            closer_than_zone: claims.closer_than_zone,
            networks,
            network_labels,
            main_closer,
        }
    }

    /// Literal and host claims only, for callers and tests without networks.
    #[must_use]
    pub fn from_named(named: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        let named: HashMap<Ipv4Addr, String> =
            named.into_iter().map(|ip| (ip, ip.to_string())).collect();
        Self {
            closer_than_zone: named.keys().copied().collect(),
            named,
            ..Self::default()
        }
    }

    /// Nothing is sent over the additional link by address.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.named.is_empty() && self.network_labels.is_empty()
    }

    /// The host, literal or network that sends `ip` over the additional link,
    /// or `None` when policy keeps it elsewhere.
    #[must_use]
    pub fn owner_of(&self, ip: IpAddr) -> Option<Cow<'_, str>> {
        if let IpAddr::V4(v4) = ip {
            if let Some(holder) = self.named.get(&v4) {
                // A network outranks a zone: a main one takes a zone-only claim.
                let main_network_wins = !self.closer_than_zone.contains(&v4)
                    && self.networks.winner(ip) == Some(Link::Main);
                return (!main_network_wins).then_some(Cow::Borrowed(holder.as_str()));
            }
        }
        let net = self.network_owner(ip)?;
        Some(self.network_labels.get(&net).map_or_else(
            || Cow::Owned(net.to_string()),
            |l| Cow::Borrowed(l.as_str()),
        ))
    }

    /// Whether policy sends `ip` over the additional link. Borrows like
    /// `HashSet::contains`, which is what its callers had before networks.
    #[must_use]
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        self.owner_of(IpAddr::V4(*ip)).is_some()
    }

    /// Whether only a network sends `ip` over the additional link: no host or
    /// literal of the additional link names it.
    #[must_use]
    pub fn owned_by_network_only(&self, ip: &Ipv4Addr) -> bool {
        !self.named.contains_key(ip) && self.network_owner(IpAddr::V4(*ip)).is_some()
    }

    /// The additional network holding `ip` most narrowly, unless a narrower
    /// main-link rule names the address.
    fn network_owner(&self, ip: IpAddr) -> Option<IpBlock> {
        if self.network_labels.is_empty() || self.main_closer.contains(&ip) {
            return None;
        }
        self.networks.additional_network_of(ip)
    }
}

/// Route rules of `set` that enforcement steers by network.
fn route_networks(
    set: &CanonicalRuleSet,
    support: RuleShapeSupport,
) -> impl Iterator<Item = &CanonicalAddressMatch> {
    set.rules()
        .iter()
        .filter(move |r| {
            r.enabled
                && r.app_match.is_none()
                && !matches!(r.action, RuleAction::Block)
                && rule_verdict(r, support).is_supported()
        })
        .filter_map(|r| r.address_match.as_ref())
        .filter(|m| m.ip_blocks().is_some())
}

fn network_labels(set: &CanonicalRuleSet, support: RuleShapeSupport) -> HashMap<IpBlock, String> {
    let mut labels: HashMap<IpBlock, String> = HashMap::new();
    for m in route_networks(set, support) {
        for net in m.ip_blocks().into_iter().flatten() {
            labels.entry(*net).or_insert_with(|| m.to_display_string());
        }
    }
    labels
}

/// The main link's literal and exact/suffix-named addresses that lie in an
/// additional network. A zone is left out: a network outranks it.
fn main_closer_inside(
    primary: &CanonicalRuleSet,
    fqdn: &dyn FqdnCacheLookup,
    networks: &RuleNetworkIndex,
) -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    let mut keep = |ip: IpAddr| {
        if networks.additional_network_of(ip).is_some() {
            out.insert(ip);
        }
    };
    let rules = primary
        .rules()
        .iter()
        .filter(|r| r.enabled && r.app_match.is_none() && !matches!(r.action, RuleAction::Block));
    for rule in rules {
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => keep(*ip),
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                capped_for_host(fqdn, host, FamilyScope::Both).for_each(&mut keep);
            }
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                for host in fqdn.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP) {
                    capped_for_host(fqdn, &host, FamilyScope::Both).for_each(&mut keep);
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests;

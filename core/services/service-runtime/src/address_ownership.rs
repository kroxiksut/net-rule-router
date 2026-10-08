//! Who owns an address, answered once for every mechanism that asks.
//!
//! One policy is carried out by several mechanisms — routes, connect-layer
//! filters, packet filters, the kill-switch. Each of them, at some point, has to
//! know whether a given address already belongs to a link the user named. When
//! they work that out separately, they eventually work it out differently, and
//! the result is not one of the behaviours the user asked for: an address routed
//! one way and dropped on the other is dead for every process on the machine.
//!
//! That happened. An application rule on the additional link had been observed
//! connecting to the address of a site the user had explicitly routed over the
//! main link. The route side knew not to take it over; the filter side did not,
//! pinned it, and the kill-switch then blocked it. The site was unreachable in
//! every browser while both of the user's rules were, individually, being
//! honoured.
//!
//! So ownership is decided here, and the mechanisms ask.
//!
//! ## The order, and why it is this way round
//!
//! 1. **An address rule beats an application rule.** A rule that names an
//!    address (literally, by hostname, by suffix or by zone) is a statement
//!    about that destination. An application rule is a statement about a
//!    program, and its destinations are LEARNED by watching it — anything the
//!    program happens to touch. A route cannot be scoped to a process, so
//!    honouring the app rule would move every other process talking to the same
//!    address, against a rule the user wrote for that very host.
//! 2. **A named address is never blocked.** When two of the user's rules point
//!    one address in opposite directions, blocking is not one of the two
//!    outcomes — it is a third one nobody asked for, and the worst of the three.
//!    This holds in every mode, strict included: strictness governs whether
//!    SHARED addresses are pinned, not whether an explicit rule can be overruled.
//! 3. **Block rules claim nothing.** They drop their destination rather than
//!    steering it, so they never make an address "owned" for the purposes above.
//! 4. **A Block yields to a narrower rule.** Blocks enter the same specificity
//!    contest the engine runs: a zone Block does not drop an address an exact
//!    route names, and an exact Block still drops what a zone route carries.
//!    A literal-IP Block is the exception: it names the address itself and
//!    vetoes every route on it. A network Block is not: it yields like a zone.
//! 5. **Networks claim by longest prefix.** An exact address beats any network
//!    holding it, a longer prefix beats a shorter one, a name beats the network
//!    its address falls into, and a network beats a zone. Networks are never
//!    expanded into addresses: every answer about one is a lookup.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::rule_shape::{rule_verdict, RuleShapeSupport};
use nrr_domain::RuleAction;
use nrr_shared::ip_block::IpBlock;

use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;

// The fan-out caps come from the filter codegen rather than being restated
// here: ownership must cover exactly the addresses enforcement can act on, and a
// second copy of a cap is a second thing to keep in step.
use crate::enforcement_planner::FamilyScope;
use crate::wfp_codegen::{PER_HOSTNAME_IP_CAP, SUFFIX_FANOUT_BACKSTOP};

/// Which link a rule set claims an address for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    Main,
    Additional,
}

/// The addresses each link's ADDRESS rules name, resolved through the cache.
///
/// Built once per compute and consulted by the route codegen, the filter codegen
/// and the kill-switch, so all three answer "whose address is this" identically.
#[derive(Clone, Debug, Default)]
pub struct AddressOwnership {
    main: HashSet<IpAddr>,
    additional: HashSet<IpAddr>,
    /// Every address the MAIN link's rules name, whether or not it won the
    /// steering contest.
    ///
    /// Separate from `main` because the two questions are different: who steers
    /// the address, and whether blocking it is one of the outcomes the user
    /// asked for. Once a literal rule on the additional link could take an
    /// address off the main link, reading `main` for the second question said
    /// "yes, block it" about an address the main link still names — the third
    /// outcome rule 2 exists to forbid.
    main_claimed: HashSet<IpAddr>,
    /// The strongest claim any ROUTE rule, on either link, holds on each
    /// address — what a Block rule is measured against (rule 4).
    route_rank: HashMap<IpAddr, ClaimRank>,
    /// Who holds each `route_rank` entry: the host, or the address itself for
    /// a literal rule. Named in the conflict a yielded Block reports.
    route_holder: HashMap<IpAddr, String>,
    /// The strongest route claim on each HOST, to tell a host a narrower rule
    /// names from one that merely shares its address.
    host_route_rank: HashMap<String, ClaimRank>,
    /// Addresses an enabled literal-IP Block names, with the rule id.
    literal_blocks: HashMap<IpAddr, String>,
    /// Both links' route networks.
    networks: NetworkClaims,
    /// Addresses each link holds through a zone and nothing closer, under the
    /// default order: a network on the other link outranks those. Empty when
    /// no network is claimed.
    main_zone_only: HashSet<IpAddr>,
    additional_zone_only: HashSet<IpAddr>,
    /// `route_rank`'s addresses in address order, built on the first interior
    /// query so a compute that never asks pays nothing.
    explicit_sorted: OnceLock<Vec<IpAddr>>,
    order: ZoneVsIpOrder,
}

impl AddressOwnership {
    /// Resolve both sides of a rule book under the default tier order.
    #[must_use]
    pub fn resolve(rule_book: &CanonicalRuleBook, cache: &dyn FqdnCacheLookup) -> Self {
        Self::resolve_with_order(rule_book, cache, ZoneVsIpOrder::default())
    }

    /// Resolve both sides of a rule book.
    ///
    /// The two sides are resolved TOGETHER, not one set at a time, because a
    /// host can be named by both and only the more specific rule actually
    /// carries it: with `*.search.example` on the main link and
    /// `docs.search.example` on the additional one, resolving each set alone
    /// puts docs's addresses on both sides and the main link — which wins
    /// ties — would swallow a rule the user wrote and can see.
    ///
    /// The contest is per HOST, and an address a main-link host still holds
    /// stays with the main link even when the other side named that host more
    /// specifically. The asymmetry is deliberate: steering a SHARED address
    /// into the tunnel drags every other host on it along, and those break in a
    /// way no rule of the user's explains.
    ///
    /// `order` settles the one contest the host stage cannot see: a rule naming
    /// an address LITERALLY has no host to contest with, so its side is decided
    /// directly against the main link's strongest claim rather than through the
    /// per-host stage above. A literal address beats a main-link claim that is a
    /// ZONE and nothing more — matching the rule model's default (exact IP
    /// overrides zone) and the switch in Settings -> Routing; anything the main
    /// link named more closely than that still keeps it, so the collateral
    /// argument above is untouched.
    #[must_use]
    pub fn resolve_with_order(
        rule_book: &CanonicalRuleBook,
        cache: &dyn FqdnCacheLookup,
        order: ZoneVsIpOrder,
    ) -> Self {
        Self::resolve_with_support(
            rule_book,
            cache,
            order,
            crate::wfp_codegen::current_rule_shape_support(),
        )
    }

    /// [`Self::resolve_with_order`] against an explicit shape support: a rule
    /// enforcement skips for its shape claims and vetoes nothing.
    #[must_use]
    pub fn resolve_with_support(
        rule_book: &CanonicalRuleBook,
        cache: &dyn FqdnCacheLookup,
        order: ZoneVsIpOrder,
        support: RuleShapeSupport,
    ) -> Self {
        let main_claims = name_claims(&rule_book.primary, cache, support);
        let additional_claims = name_claims(&rule_book.secondary, cache, support);
        let networks = NetworkClaims::new(&main_claims.networks, &additional_claims.networks);
        let (main_names, main_literal) = (main_claims.names, main_claims.literal);
        let (additional_names, additional_literal) =
            (additional_claims.names, additional_claims.literal);

        let mut main: HashSet<IpAddr> = main_literal.clone();
        let mut additional: HashSet<IpAddr> = additional_literal.clone();
        // The strongest claim the main link holds on each address it carries,
        // which is what the literal contest below compares against.
        let mut main_claim: HashMap<IpAddr, NameClaim> = HashMap::new();
        let mut additional_claim: HashMap<IpAddr, NameClaim> = HashMap::new();
        let strongest = |claims: &mut HashMap<IpAddr, NameClaim>, ips: &[IpAddr], c: NameClaim| {
            for ip in ips {
                claims
                    .entry(*ip)
                    .and_modify(|best| {
                        if c > *best {
                            *best = c;
                        }
                    })
                    .or_insert(c);
            }
        };
        let mut route_rank: HashMap<IpAddr, ClaimRank> = HashMap::new();
        let mut route_holder: HashMap<IpAddr, String> = HashMap::new();
        let mut host_route_rank: HashMap<String, ClaimRank> = HashMap::new();
        let mut raise = |ip: IpAddr, rank: ClaimRank, holder: &str| match route_rank.get(&ip) {
            Some(best) if *best >= rank => {}
            _ => {
                route_rank.insert(ip, rank);
                route_holder.insert(ip, holder.to_string());
            }
        };
        let mut literals: Vec<&IpAddr> = main_literal.union(&additional_literal).collect();
        literals.sort_unstable();
        for ip in literals {
            raise(*ip, literal_rank(order), &ip.to_string());
        }

        let mut hosts: Vec<&str> = main_names
            .keys()
            .chain(additional_names.keys())
            .map(String::as_str)
            .collect();
        hosts.sort_unstable();
        hosts.dedup();

        for host in hosts {
            // The same per-family view of the host the codegens pin, so the
            // arbiter and the emitters cannot disagree about which addresses a
            // rule covers. BOTH families unconditionally: the ledger answers
            // "whose address is this", and that answer does not depend on
            // whether this machine can currently carry the family — a caller
            // that cannot simply never asks about a v6 address.
            let ips: Vec<IpAddr> =
                crate::enforcement_planner::capped_for_host(cache, host, FamilyScope::Both)
                    .collect();
            if let Some(best) = main_names.get(host).max(additional_names.get(host)) {
                let rank = host_rank(*best, order);
                host_route_rank.insert(host.to_string(), rank);
                for ip in &ips {
                    raise(*ip, rank, host);
                }
            }
            match (main_names.get(host), additional_names.get(host)) {
                // A tie goes to the main link -- see `owner_of`.
                (Some(m), Some(a)) if a > m => {
                    strongest(&mut additional_claim, &ips, *a);
                    additional.extend(ips);
                }
                (Some(m), _) => {
                    strongest(&mut main_claim, &ips, *m);
                    main.extend(ips);
                }
                (None, Some(a)) => {
                    strongest(&mut additional_claim, &ips, *a);
                    additional.extend(ips);
                }
                (None, None) => continue,
            }
        }

        let main_claimed = main.clone();
        if order == ZoneVsIpOrder::ExactIpFirst {
            for ip in &additional_literal {
                let main_named_it_closer = main_literal.contains(ip)
                    || matches!(main_claim.get(ip), Some(c) if !matches!(c, NameClaim::Zone(_)));
                if !main_named_it_closer {
                    main.remove(ip);
                }
            }
        }

        // A network outranks a zone only in the default order; with zones
        // first the zone keeps the address, so nothing is weak.
        let zone_only = |held: &HashSet<IpAddr>,
                         literal: &HashSet<IpAddr>,
                         claims: &HashMap<IpAddr, NameClaim>| {
            if order != ZoneVsIpOrder::ExactIpFirst || networks.is_empty() {
                return HashSet::new();
            }
            claims
                .iter()
                .filter(|(ip, c)| {
                    matches!(c, NameClaim::Zone(_)) && held.contains(ip) && !literal.contains(ip)
                })
                .map(|(ip, _)| *ip)
                .collect()
        };
        let main_zone_only = zone_only(&main, &main_literal, &main_claim);
        let additional_zone_only = zone_only(&additional, &additional_literal, &additional_claim);

        Self {
            main,
            additional,
            main_claimed,
            route_rank,
            route_holder,
            host_route_rank,
            literal_blocks: literal_blocks(rule_book, support),
            networks,
            main_zone_only,
            additional_zone_only,
            explicit_sorted: OnceLock::new(),
            order,
        }
    }

    /// Build from already-resolved sets. For callers that hold one side only
    /// (and for tests that want an exact shape without a cache).
    #[must_use]
    pub fn from_sets(main: HashSet<IpAddr>, additional: HashSet<IpAddr>) -> Self {
        Self {
            main_claimed: main.clone(),
            main,
            additional,
            ..Self::default()
        }
    }

    /// Which link's address rules name `ip`, if any. `Main` wins a tie: an
    /// address both sides name is reachable on the main link, which is the
    /// outcome a user can still see and correct — the reverse is a site that
    /// works only while the tunnel is up.
    ///
    /// A network decides only what no closer claim holds: an address held
    /// through a zone alone goes to the other link's network (rule 5).
    #[must_use]
    pub fn owner_of(&self, ip: IpAddr) -> Option<Link> {
        let network = || self.networks.winner(ip);
        if self.main.contains(&ip) {
            if self.main_zone_only.contains(&ip) && network() == Some(Link::Additional) {
                return Some(Link::Additional);
            }
            Some(Link::Main)
        } else if self.additional.contains(&ip) {
            if self.additional_zone_only.contains(&ip) && network() == Some(Link::Main) {
                return Some(Link::Main);
            }
            Some(Link::Additional)
        } else {
            network()
        }
    }

    /// Whether an APPLICATION rule on `for_link` may take this address.
    ///
    /// Yes when nobody named it, and yes when the address rule that named it
    /// points at the SAME link — the app rule then adds nothing to argue with.
    /// No when the other link's address rules name it: see rule 1 in the module
    /// doc. The check is symmetric on purpose, because the failure is: a program
    /// on one link touches an address the user routed over the other, and the
    /// address follows the program instead of the rule written for it.
    #[must_use]
    pub fn app_rule_may_claim(&self, ip: IpAddr, for_link: Link) -> bool {
        match self.owner_of(ip) {
            None => true,
            Some(owner) => owner == for_link,
        }
    }

    /// Whether an ADDRESS rule on `for_link` may steer this address.
    ///
    /// Rules name HOSTS; routes and filters act on ADDRESSES, and one address
    /// carries many hosts. When both links' rules name the same address,
    /// steering it to the additional link takes every other host on it along —
    /// the ones the user routed over the main link then work only while the
    /// tunnel is up, and break in a way no rule of theirs explains. So the main
    /// link keeps it, which is the same tie-break `owner_of` applies.
    ///
    /// This is not the app-rule question ([`Self::app_rule_may_claim`]): there,
    /// an address rule outranks an application rule whichever link it is on.
    /// Here both claims are address rules, and the specificity contest between
    /// them was already settled per host in [`Self::resolve`] — what is left is
    /// genuinely one address wanted in two directions.
    ///
    /// Symmetric, and the same answer as [`Self::owner_of`]: a main-link zone
    /// host inside an additional-link network, or under an additional literal,
    /// is the narrower rule's, so a mode that pins main-link hosts must not pin
    /// it back. Every mode then sends it where the carving does.
    #[must_use]
    pub fn address_rule_may_steer(&self, ip: IpAddr, for_link: Link) -> bool {
        let other = match for_link {
            Link::Main => Link::Additional,
            Link::Additional => Link::Main,
        };
        self.owner_of(ip) != Some(other)
    }

    /// Whether enforcement may install a BLOCK for this address. See rule 2.
    ///
    /// Reads what the main link NAMES, not what it won: an address whose
    /// steering went to the additional link because the user named it there
    /// literally is still an address a main-link rule points at, and blocking
    /// it is the outcome neither of their rules asked for. A main-link network
    /// names every address inside it in the same sense.
    #[must_use]
    pub fn may_block(&self, ip: IpAddr) -> bool {
        !self.main_claimed.contains(&ip) && !self.networks.names(ip, Link::Main)
    }

    /// Whether `link`'s address rules name `ip` — literally, through a host or
    /// through a network. For the main link this is `!may_block(ip)`.
    #[must_use]
    pub fn named_by(&self, ip: IpAddr, link: Link) -> bool {
        let explicit = match link {
            Link::Main => self.main_claimed.contains(&ip),
            Link::Additional => self.additional.contains(&ip),
        };
        explicit || self.networks.names(ip, link)
    }

    /// Whether a Block rule matching `block` must leave `ip` alone because a
    /// narrower route rule names it. See rule 4; a tie keeps the block.
    ///
    /// Per ADDRESS, like every other answer here: a zone Block over a host
    /// that shares its address with a narrowly routed one leaves the address
    /// open, the same trade rule 2 makes for a contested address. A network
    /// Block outside `ip` does not apply to it and keeps nothing open.
    #[must_use]
    pub fn block_yields(&self, ip: IpAddr, block: &CanonicalAddressMatch) -> bool {
        block_rank(block, ip, self.order).is_some_and(|own| self.outranked(ip, own))
    }

    /// When a Block covering `host` leaves `ip` open although no narrower rule
    /// names `host` itself: the holder of the narrower claim on the address —
    /// the host, or the literal address, whose route kept it open. `None` when
    /// the block holds, or when `host` is narrowly routed in its own right.
    ///
    /// This is the leak rule 4 accepts per address: every other tenant of a
    /// shared address stays reachable under a Block written for it.
    #[must_use]
    pub fn block_leak(
        &self,
        host: &str,
        ip: IpAddr,
        block: &CanonicalAddressMatch,
    ) -> Option<&str> {
        let own = block_rank(block, ip, self.order)?;
        if !self.outranked(ip, own) || self.host_route_rank.get(host).is_some_and(|h| *h > own) {
            return None;
        }
        let explicit = self.route_rank.get(&ip).copied();
        match self.networks.longest(ip) {
            Some((net, claim)) if Some(subnet_rank(net.prefix_len(), self.order)) > explicit => {
                Some(claim.label.as_str())
            }
            _ => self.route_holder.get(&ip).map(String::as_str),
        }
    }

    /// The literal-IP Block rule naming `ip`, if any: its filter drops the
    /// address whatever route a tenant of it carries.
    #[must_use]
    pub fn literal_block_of(&self, ip: IpAddr) -> Option<&str> {
        self.literal_blocks.get(&ip).map(String::as_str)
    }

    fn outranked(&self, ip: IpAddr, own: ClaimRank) -> bool {
        let network = self
            .networks
            .longest(ip)
            .map(|(net, _)| subnet_rank(net.prefix_len(), self.order));
        self.route_rank.get(&ip).copied().max(network) > Some(own)
    }

    /// The main link's named addresses, for callers that need the set itself
    /// (subtracting it from a protected set, reporting it).
    ///
    /// Everything the main link's rules name, for the same reason
    /// [`Self::may_block`] reads that set: a rescue permit exists so a
    /// main-named address keeps working, and that need does not disappear when
    /// the steering contest went the other way. Networks are not in it — see
    /// [`Self::networks`].
    #[must_use]
    pub fn main_named(&self) -> &HashSet<IpAddr> {
        &self.main_claimed
    }

    /// The additional link's named addresses; networks are not in it.
    #[must_use]
    pub fn additional_named(&self) -> &HashSet<IpAddr> {
        &self.additional
    }

    /// The networks `link`'s route rules name, in address order. A network
    /// both links name is listed for both.
    pub fn networks(&self, link: Link) -> impl Iterator<Item = IpBlock> + '_ {
        self.networks
            .sorted
            .iter()
            .filter(move |net| self.networks.claim(**net).is_some_and(|c| c.has(link)))
            .copied()
    }

    /// The narrowest network of `link`'s holding `ip`.
    #[must_use]
    pub fn network_of(&self, ip: IpAddr, link: Link) -> Option<IpBlock> {
        self.networks
            .holding(ip)
            .find(|(_, claim)| claim.has(link))
            .map(|(net, _)| net)
    }

    /// The addresses route rules name literally or through a host that lie
    /// inside `network`, in address order — what an emitter carving `network`
    /// asks [`Self::owner_of`] or [`Self::block_yields`] about, without walking
    /// the network itself.
    #[must_use]
    pub fn explicit_inside(&self, network: IpBlock) -> &[IpAddr] {
        let sorted = self.explicit_sorted.get_or_init(|| {
            let mut ips: Vec<IpAddr> = self.route_rank.keys().copied().collect();
            ips.sort_unstable();
            ips
        });
        let start = sorted.partition_point(|ip| *ip < network.network());
        let end = sorted.partition_point(|ip| *ip <= network.last());
        &sorted[start..end]
    }

    /// Route networks strictly narrower than `network` and inside it, each
    /// with the link that wins it (the main one on a tie).
    pub fn networks_inside(&self, network: IpBlock) -> impl Iterator<Item = (IpBlock, Link)> + '_ {
        self.networks
            .inside(network)
            .map(|(net, claim)| (net, claim.winner()))
    }

    /// Addresses of `candidates` an application rule on `for_link` may not take
    /// over, in input order and deduplicated — what a caller reports as "these
    /// stayed where the address rule put them".
    #[must_use]
    pub fn refused_for_app(&self, candidates: &[Ipv4Addr], for_link: Link) -> Vec<Ipv4Addr> {
        let mut seen = HashSet::new();
        candidates
            .iter()
            .copied()
            .filter(|ip| !self.app_rule_may_claim(IpAddr::V4(*ip), for_link))
            .filter(|ip| seen.insert(*ip))
            .collect()
    }
}

/// How specifically a rule names a host.
///
/// The order is the engine's evaluation order — exact FQDN, then suffix, then
/// zone — so the link whose rule is more specific carries the host. Within a
/// kind, more labels is more specific: `corp.intra` beats `intra`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum NameClaim {
    Zone(usize),
    Suffix(usize),
    ExactFqdn,
}

/// Where an exact-IP rule sits against a zone rule.
///
/// The rule model lists Zone above Exact IP but states the DEFAULT the other way
/// round ("Exact IP wins — more specific overrides zone") and lets the user swap
/// the two. Nothing else in the tier list is configurable, so this is the whole
/// of the setting, stored per principal as
/// `secondary_block_policy.zone_priority_over_ip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ZoneVsIpOrder {
    /// `zone_priority_over_ip = false` (default): an exact address beats a zone.
    #[default]
    ExactIpFirst,
    /// `zone_priority_over_ip = true`: a zone beats an exact address.
    ZoneFirst,
}

impl ZoneVsIpOrder {
    #[must_use]
    pub fn from_zone_priority_over_ip(zone_first: bool) -> Self {
        if zone_first {
            Self::ZoneFirst
        } else {
            Self::ExactIpFirst
        }
    }
}

/// A claim's place in the engine's tier order, with the literal address and
/// the network slotted where [`ZoneVsIpOrder`] puts them against a zone.
/// Compared, never shown.
type ClaimRank = (u8, usize);

fn host_rank(claim: NameClaim, order: ZoneVsIpOrder) -> ClaimRank {
    match claim {
        NameClaim::Zone(labels) => match order {
            ZoneVsIpOrder::ExactIpFirst => (0, labels),
            ZoneVsIpOrder::ZoneFirst => (2, labels),
        },
        NameClaim::Suffix(labels) => (3, labels),
        NameClaim::ExactFqdn => (4, 0),
    }
}

/// Below an exact address in either order; the longer prefix is narrower.
fn subnet_rank(prefix_len: u8, order: ZoneVsIpOrder) -> ClaimRank {
    match order {
        ZoneVsIpOrder::ExactIpFirst => (1, usize::from(prefix_len)),
        ZoneVsIpOrder::ZoneFirst => (0, usize::from(prefix_len)),
    }
}

/// A Block's own place in the contest at `ip`; `None` for a literal one, which
/// never yields, and for a network that does not hold `ip`. A range ranks by
/// its piece around the address, as the engine scores it.
fn block_rank(
    block: &CanonicalAddressMatch,
    ip: IpAddr,
    order: ZoneVsIpOrder,
) -> Option<ClaimRank> {
    let own = match block {
        CanonicalAddressMatch::ExactIp(_) => return None,
        CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_) => {
            let piece = block.ip_blocks()?.iter().find(|net| net.contains(ip))?;
            return Some(subnet_rank(piece.prefix_len(), order));
        }
        CanonicalAddressMatch::ExactFqdn(_) => NameClaim::ExactFqdn,
        CanonicalAddressMatch::SuffixDomain(s) => NameClaim::Suffix(label_count(s)),
        CanonicalAddressMatch::Zone(z) => NameClaim::Zone(label_count(z)),
    };
    Some(host_rank(own, order))
}

/// Enabled literal-IP Blocks on either link, the smallest rule id per address.
/// A Block enforcement skips for its shape vetoes nothing.
fn literal_blocks(
    rule_book: &CanonicalRuleBook,
    support: RuleShapeSupport,
) -> HashMap<IpAddr, String> {
    let mut out: HashMap<IpAddr, String> = HashMap::new();
    for rule in rule_book
        .primary
        .rules()
        .iter()
        .chain(rule_book.secondary.rules())
    {
        if !rule.enabled
            || !matches!(rule.action, RuleAction::Block)
            || !rule_verdict(rule, support).is_supported()
        {
            continue;
        }
        if let Some(CanonicalAddressMatch::ExactIp(ip)) = &rule.address_match {
            let id = rule.id.as_str();
            match out.get(ip) {
                Some(best) if best.as_str() <= id => {}
                _ => {
                    out.insert(*ip, id.to_string());
                }
            }
        }
    }
    out
}

fn literal_rank(order: ZoneVsIpOrder) -> ClaimRank {
    match order {
        ZoneVsIpOrder::ExactIpFirst => (2, 0),
        ZoneVsIpOrder::ZoneFirst => (1, 0),
    }
}

fn label_count(name: &str) -> usize {
    name.split('.').filter(|l| !l.is_empty()).count()
}

/// What one rule set's route rules claim.
struct SetClaims {
    /// Each host named, with the strongest claim on it.
    names: HashMap<String, NameClaim>,
    literal: HashSet<IpAddr>,
    /// Network blocks, a range as its pieces.
    networks: Vec<IpBlock>,
}

/// Application rules and Block rules contribute nothing — see rules 1 and 3 in
/// the module doc — and neither does a network enforcement cannot carry.
fn name_claims(
    rules: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
    support: RuleShapeSupport,
) -> SetClaims {
    let mut names: HashMap<String, NameClaim> = HashMap::new();
    let mut literal: HashSet<IpAddr> = HashSet::new();
    let mut networks: Vec<IpBlock> = Vec::new();
    let claim = |names: &mut HashMap<String, NameClaim>, host: String, c: NameClaim| {
        names
            .entry(host)
            .and_modify(|best| {
                if c > *best {
                    *best = c;
                }
            })
            .or_insert(c);
    };
    for rule in rules.rules() {
        if !rule.enabled || rule.app_match.is_some() || matches!(rule.action, RuleAction::Block) {
            continue;
        }
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                literal.insert(*ip);
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                claim(&mut names, host.clone(), NameClaim::ExactFqdn);
            }
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                let c = NameClaim::Suffix(label_count(suffix));
                for sub in cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP) {
                    claim(&mut names, sub, c);
                }
            }
            Some(CanonicalAddressMatch::Zone(zone)) => {
                let c = NameClaim::Zone(label_count(zone));
                for sub in cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP) {
                    claim(&mut names, sub, c);
                }
            }
            Some(m @ (CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_))) => {
                if rule_verdict(rule, support).is_supported() {
                    networks.extend(m.ip_blocks().into_iter().flatten().copied());
                }
            }
            None => {}
        }
    }
    SetClaims {
        names,
        literal,
        networks,
    }
}

/// Which links' route rules name one network.
#[derive(Clone, Debug, Default)]
struct NetworkClaim {
    main: bool,
    additional: bool,
    /// The network as written in a conflict report.
    label: String,
}

impl NetworkClaim {
    fn has(&self, link: Link) -> bool {
        match link {
            Link::Main => self.main,
            Link::Additional => self.additional,
        }
    }

    /// The same network on both links goes to the main one, as the engine's
    /// tie-break does.
    fn winner(&self) -> Link {
        if self.main {
            Link::Main
        } else {
            Link::Additional
        }
    }
}

/// Both links' route networks, asked by longest prefix.
///
/// Aligned blocks either nest or are disjoint, so the networks holding an
/// address are exactly its masks at the prefix lengths in use: a probe is one
/// hash lookup per distinct length, never a walk of a network.
#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkClaims {
    by_block: HashMap<IpBlock, NetworkClaim>,
    /// Distinct prefix lengths per family, longest first.
    v4_lens: Vec<u8>,
    v6_lens: Vec<u8>,
    /// Every claimed block in address order, for interior queries.
    sorted: Vec<IpBlock>,
}

impl NetworkClaims {
    /// Both links' route networks alone, without resolving a single name.
    pub(crate) fn of_book(rule_book: &CanonicalRuleBook, support: RuleShapeSupport) -> Self {
        let networks = |rules: &CanonicalRuleSet| -> Vec<IpBlock> {
            rules
                .rules()
                .iter()
                .filter(|r| {
                    r.enabled
                        && r.app_match.is_none()
                        && !matches!(r.action, RuleAction::Block)
                        && rule_verdict(r, support).is_supported()
                })
                .filter_map(|r| r.address_match.as_ref()?.ip_blocks())
                .flatten()
                .copied()
                .collect()
        };
        Self::new(
            &networks(&rule_book.primary),
            &networks(&rule_book.secondary),
        )
    }

    fn new(main: &[IpBlock], additional: &[IpBlock]) -> Self {
        let mut by_block: HashMap<IpBlock, NetworkClaim> = HashMap::new();
        let tagged = main
            .iter()
            .map(|net| (net, Link::Main))
            .chain(additional.iter().map(|net| (net, Link::Additional)));
        for (net, link) in tagged {
            let claim = by_block.entry(*net).or_insert_with(|| NetworkClaim {
                label: net.to_string(),
                ..NetworkClaim::default()
            });
            match link {
                Link::Main => claim.main = true,
                Link::Additional => claim.additional = true,
            }
        }
        let mut sorted: Vec<IpBlock> = by_block.keys().copied().collect();
        sorted.sort_unstable();
        let lens = |v4: bool| {
            let mut lens: Vec<u8> = sorted
                .iter()
                .filter(|net| net.is_ipv4() == v4)
                .map(|net| net.prefix_len())
                .collect();
            lens.sort_unstable_by(|a, b| b.cmp(a));
            lens.dedup();
            lens
        };
        Self {
            v4_lens: lens(true),
            v6_lens: lens(false),
            by_block,
            sorted,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_block.is_empty()
    }

    /// Every claimed block in address order.
    pub(crate) fn blocks(&self) -> &[IpBlock] {
        &self.sorted
    }

    fn claim(&self, net: IpBlock) -> Option<&NetworkClaim> {
        self.by_block.get(&net)
    }

    /// Every claimed network holding `ip`, narrowest first.
    fn holding(&self, ip: IpAddr) -> impl Iterator<Item = (IpBlock, &NetworkClaim)> + '_ {
        let lens = if ip.is_ipv4() {
            &self.v4_lens
        } else {
            &self.v6_lens
        };
        lens.iter().filter_map(move |len| {
            let net = IpBlock::new(ip, *len)?;
            self.by_block.get(&net).map(|claim| (net, claim))
        })
    }

    fn longest(&self, ip: IpAddr) -> Option<(IpBlock, &NetworkClaim)> {
        self.holding(ip).next()
    }

    /// The link whose network holds `ip` most narrowly.
    pub(crate) fn winner(&self, ip: IpAddr) -> Option<Link> {
        self.narrowest(ip).map(|(_, link)| link)
    }

    /// The narrowest network holding `ip`, with the link that wins it.
    pub(crate) fn narrowest(&self, ip: IpAddr) -> Option<(IpBlock, Link)> {
        self.longest(ip).map(|(net, claim)| (net, claim.winner()))
    }

    fn names(&self, ip: IpAddr, link: Link) -> bool {
        self.holding(ip).any(|(_, claim)| claim.has(link))
    }

    /// Claimed networks strictly inside `outer`.
    fn inside(&self, outer: IpBlock) -> impl Iterator<Item = (IpBlock, &NetworkClaim)> + '_ {
        let start = self
            .sorted
            .partition_point(|net| net.network() < outer.network());
        self.sorted[start..]
            .iter()
            .take_while(move |net| net.network() <= outer.last())
            .filter(move |net| net.prefix_len() > outer.prefix_len() && outer.covers(**net))
            .filter_map(move |net| self.by_block.get(net).map(|claim| (*net, claim)))
    }
}

/// The addresses one rule set names, with hostnames expanded through the cache.
///
/// Application rules and Block rules contribute nothing — see rules 1 and 3 in
/// the module doc. Public because the route codegen has always exposed this
/// shape; new callers should prefer [`AddressOwnership`], which answers the
/// question the callers actually have.
#[must_use]
pub fn address_rule_ips(
    rules: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
) -> HashSet<Ipv4Addr> {
    let mut out: HashSet<Ipv4Addr> = HashSet::new();
    for rule in rules.rules() {
        if !rule.enabled || rule.app_match.is_some() || matches!(rule.action, RuleAction::Block) {
            continue;
        }
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip))) => {
                out.insert(*ip);
            }
            Some(CanonicalAddressMatch::ExactIp(IpAddr::V6(_))) => {}
            // Never expanded: see `address_rule_networks`.
            Some(CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_)) => {}
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                out.extend(
                    crate::dns_wire::only_v4(&cache.ips_for_hostname(host))
                        .into_iter()
                        .take(PER_HOSTNAME_IP_CAP),
                );
            }
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                for sub in cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP) {
                    out.extend(
                        crate::dns_wire::only_v4(&cache.ips_for_hostname(&sub))
                            .into_iter()
                            .take(PER_HOSTNAME_IP_CAP),
                    );
                }
            }
            Some(CanonicalAddressMatch::Zone(zone)) => {
                for sub in cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP) {
                    out.extend(
                        crate::dns_wire::only_v4(&cache.ips_for_hostname(&sub))
                            .into_iter()
                            .take(PER_HOSTNAME_IP_CAP),
                    );
                }
            }
            None => {}
        }
    }
    out
}

/// The networks one rule set's route rules name, a range as its pieces, in
/// address order and deduplicated — the counterpart of [`address_rule_ips`]
/// for what cannot be listed address by address. Shape support is the
/// caller's to check, as it is for every rule an emitter reads.
#[must_use]
pub fn address_rule_networks(rules: &CanonicalRuleSet) -> Vec<IpBlock> {
    let mut out: Vec<IpBlock> = rules
        .rules()
        .iter()
        .filter(|r| r.enabled && r.app_match.is_none() && !matches!(r.action, RuleAction::Block))
        .filter_map(|r| r.address_match.as_ref()?.ip_blocks())
        .flatten()
        .copied()
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Why an application rule was refused a destination it was observed using.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppDestinationRefusal {
    /// The other link's address rules name it — rule 1 in the module doc.
    ClaimedByAddressRule,
    /// A process none of the rule set's own application rules name is already
    /// using it, and a host route moves every process on the address.
    UsedByOtherProcess,
}

/// Destinations one application rule may take, and the ones it may not.
///
/// `refused` keeps the reason so each caller can raise its own diagnostic: the
/// two mechanisms word it differently, but they must never DECIDE it
/// differently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppDestinations {
    pub admitted: Vec<Ipv4Addr>,
    pub refused: Vec<(Ipv4Addr, AppDestinationRefusal)>,
}

/// The single gate between an application rule's observed destinations and any
/// mechanism that pins or blocks them.
///
/// Route codegen, filter codegen and the neutral planner must not reach for
/// [`AppObservationLookup::ips_for_app`] directly and apply their own subset of
/// checks — that divergence is what the incident in the module doc costs. The
/// observations are reachable through this type only, and `tests/ownership_gate.rs`
/// holds the other end: no production call site outside this module may query
/// them directly.
pub struct AppDestinationGate<'a> {
    ownership: &'a AddressOwnership,
    observations: &'a dyn AppObservationLookup,
    /// Every application this rule set routes — not just the rule being
    /// compiled. A destination two routed applications share is not somebody
    /// else's, and one route serves both identically.
    friendly: Vec<String>,
}

impl<'a> AppDestinationGate<'a> {
    /// Gate for one rule set, with `friendly` derived from it.
    #[must_use]
    pub fn for_rule_set(
        ownership: &'a AddressOwnership,
        observations: &'a dyn AppObservationLookup,
        rules: &CanonicalRuleSet,
    ) -> Self {
        Self {
            ownership,
            observations,
            friendly: crate::app_destination_memory::routed_app_patterns(rules)
                .into_iter()
                .collect(),
        }
    }

    /// Destinations `pattern`'s rule on `for_link` may take, in observation
    /// order, with a reason recorded for every one held back.
    ///
    /// Order matters: ownership first, because "the user's other rule names
    /// this host" is a statement about the address itself, while the census
    /// answers a question about who else happens to be on it.
    #[must_use]
    pub fn admit(&self, pattern: &str, for_link: Link) -> AppDestinations {
        let mut out = AppDestinations::default();
        for ip in self.observations.ips_for_app(pattern) {
            if !self.ownership.app_rule_may_claim(IpAddr::V4(ip), for_link) {
                out.refused
                    .push((ip, AppDestinationRefusal::ClaimedByAddressRule));
            } else if self
                .observations
                .destination_used_outside(&self.friendly, ip)
            {
                out.refused
                    .push((ip, AppDestinationRefusal::UsedByOtherProcess));
            } else {
                out.admitted.push(ip);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern, CanonicalRule};
    use nrr_domain::RuleId;

    const NAMED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 68);
    const OTHER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn address_rule(id: &str, m: CanonicalAddressMatch, action: RuleAction) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action,
            origin: None,
        }
    }

    fn app_rule(id: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact("helper.exe".into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    fn cache() -> MockFqdnCacheLookup {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("blog.example", vec![NAMED]);
        cache
    }

    /// The live case: `*.search.example` on the main link, `docs.search.example`
    /// on the additional one, and a CDN hands both hosts the SAME address.
    /// Pinning it into the tunnel takes translate.search.example with it, which the
    /// user routed over the main link and which then breaks whenever the tunnel
    /// misbehaves.
    #[test]
    fn a_shared_address_stays_on_the_main_link() {
        let shared = Ipv4Addr::new(203, 0, 113, 161);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("translate.search.example", vec![shared]);
        cache.set_ips("docs.search.example", vec![shared]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::SuffixDomain("search.example".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactFqdn("docs.search.example".into()),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(shared)), Some(Link::Main));
        assert!(!ownership.address_rule_may_steer(IpAddr::V4(shared), Link::Additional));
        assert!(ownership.address_rule_may_steer(IpAddr::V4(shared), Link::Main));
        // And it is still never blocked — rule 2 of the module doc.
        assert!(!ownership.may_block(IpAddr::V4(shared)));
    }

    /// The other half of the same case, and the reason the two sets are
    /// resolved together: an address ONLY the additional link's host has is
    /// still that link's, even though the main link's suffix rule covers the
    /// host by name. Resolving each set alone put it on both sides and the
    /// tie-break then swallowed the rule the user wrote.
    #[test]
    fn a_more_specific_rule_keeps_the_address_only_its_host_has() {
        let private = Ipv4Addr::new(203, 0, 113, 150);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("docs.search.example", vec![private]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::SuffixDomain("search.example".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactFqdn("docs.search.example".into()),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(
            ownership.owner_of(IpAddr::V4(private)),
            Some(Link::Additional)
        );
        assert!(ownership.address_rule_may_steer(IpAddr::V4(private), Link::Additional));
    }

    /// Specificity decides between the two sets, not which set is read first:
    /// the longer suffix carries the host.
    #[test]
    fn the_longer_suffix_carries_the_host() {
        let ip = Ipv4Addr::new(198, 51, 100, 7);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.corp.intra", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::SuffixDomain("intra".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::SuffixDomain("corp.intra".into()),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Additional));
    }

    /// Equal claims are a tie, and a tie goes to the main link.
    #[test]
    fn an_equally_named_host_goes_to_the_main_link() {
        let ip = Ipv4Addr::new(198, 51, 100, 8);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("shop.example.com", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::ExactFqdn("shop.example.com".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactFqdn("shop.example.com".into()),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Main));
    }

    /// A zone rule is the weakest claim; an exact FQDN on the other link wins.
    #[test]
    fn an_exact_name_beats_a_zone_on_the_other_link() {
        let ip = Ipv4Addr::new(198, 51, 100, 9);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("mirror.example.ru", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::Zone("ru".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactFqdn("mirror.example.ru".into()),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Additional));
    }

    /// The incident, stated as a question to the arbiter: the app rule asks for
    /// an address the main link names, and is told no.
    #[test]
    fn an_app_rule_may_not_claim_what_the_main_link_names() {
        let book = book(
            vec![address_rule(
                "r-main",
                CanonicalAddressMatch::ExactFqdn("blog.example".into()),
                RuleAction::Route,
            )],
            vec![app_rule("r-app")],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert!(!ownership.app_rule_may_claim(IpAddr::V4(NAMED), Link::Additional));
        assert!(!ownership.may_block(IpAddr::V4(NAMED)));
        assert_eq!(ownership.owner_of(IpAddr::V4(NAMED)), Some(Link::Main));
        // Nothing else is affected: an address nobody named stays claimable.
        assert!(ownership.app_rule_may_claim(IpAddr::V4(OTHER), Link::Additional));
        assert!(ownership.may_block(IpAddr::V4(OTHER)));
        assert_eq!(ownership.owner_of(IpAddr::V4(OTHER)), None);
    }

    /// A rule the user turned off, and a rule that blocks rather than routes,
    /// claim nothing: neither steers traffic anywhere.
    #[test]
    fn disabled_and_blocking_rules_claim_nothing() {
        let mut disabled = address_rule(
            "r-off",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(NAMED)),
            RuleAction::Route,
        );
        disabled.enabled = false;
        let blocking = address_rule(
            "r-block",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(OTHER)),
            RuleAction::Block,
        );
        let book = book(vec![disabled, blocking], Vec::new());

        let ownership = AddressOwnership::resolve(&book, &cache());

        assert!(ownership.app_rule_may_claim(IpAddr::V4(NAMED), Link::Additional));
        assert!(ownership.app_rule_may_claim(IpAddr::V4(OTHER), Link::Additional));
    }

    /// The additional link's own address rules are recorded too — an app rule
    /// asking for one of those is not a conflict, and the arbiter must not
    /// confuse "already ours" with "somebody else's".
    #[test]
    fn the_additional_links_own_addresses_are_not_a_conflict() {
        let book = book(
            Vec::new(),
            vec![address_rule(
                "r-sec",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(OTHER)),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert_eq!(
            ownership.owner_of(IpAddr::V4(OTHER)),
            Some(Link::Additional)
        );
        // An app rule on the SAME link adds nothing to argue with...
        assert!(ownership.app_rule_may_claim(IpAddr::V4(OTHER), Link::Additional));
        // ...and one on the other link may not take it: the address rule is the
        // statement about that destination, whichever link it names.
        assert!(!ownership.app_rule_may_claim(IpAddr::V4(OTHER), Link::Main));
        assert!(ownership.may_block(IpAddr::V4(OTHER)));
    }

    /// An address both sides name goes to the main link. The other way round is
    /// a site that only works while the tunnel is up — a failure the user
    /// experiences as intermittent and cannot attribute.
    #[test]
    fn an_address_both_links_name_belongs_to_the_main_one() {
        let book = book(
            vec![address_rule(
                "r-main",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(NAMED)),
                RuleAction::Route,
            )],
            vec![address_rule(
                "r-sec",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(NAMED)),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert_eq!(ownership.owner_of(IpAddr::V4(NAMED)), Some(Link::Main));
        assert!(!ownership.may_block(IpAddr::V4(NAMED)));
    }

    #[test]
    fn refused_for_app_lists_what_stayed_on_the_main_link() {
        let book = book(
            vec![address_rule(
                "r-main",
                CanonicalAddressMatch::ExactFqdn("blog.example".into()),
                RuleAction::Route,
            )],
            vec![app_rule("r-app")],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert_eq!(
            ownership.refused_for_app(&[OTHER, NAMED, NAMED], Link::Additional),
            vec![NAMED],
        );
    }

    /// The rule model's default: an exact address outranks a zone, so a literal
    /// address rule on one link wins even against a zone claim on the other.
    #[test]
    fn an_exact_address_beats_a_zone_on_the_other_link() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("shop.example.com", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::Zone("com".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Additional));
        assert!(ownership.address_rule_may_steer(IpAddr::V4(ip), Link::Additional));
        // Still never blocked — rule 2 of the module doc holds either way.
        assert!(!ownership.may_block(IpAddr::V4(ip)));
    }

    /// And the switch actually switches: with `zone_priority_over_ip` the same
    /// two rules resolve the other way.
    #[test]
    fn the_zone_priority_setting_reverses_that_contest() {
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("shop.example.com", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::Zone("com".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve_with_order(
            &book,
            &cache,
            ZoneVsIpOrder::from_zone_priority_over_ip(true),
        );
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Main));
    }

    /// The collateral guarantee is untouched: a SUFFIX is a closer claim than a
    /// zone, so an address the main link holds through one keeps it even
    /// against a literal rule on the other side. Steering it would take every
    /// other host under that suffix into the tunnel with it.
    #[test]
    fn a_suffix_on_the_main_link_still_keeps_an_address_named_literally_opposite() {
        let ip = Ipv4Addr::new(203, 0, 113, 8);
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("shop.example.com", vec![ip]);
        let book = book(
            vec![address_rule(
                "p1",
                CanonicalAddressMatch::SuffixDomain("example.com".into()),
                RuleAction::Route,
            )],
            vec![address_rule(
                "s1",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(ip)),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(IpAddr::V4(ip)), Some(Link::Main));
        assert!(!ownership.address_rule_may_steer(IpAddr::V4(ip), Link::Additional));
    }

    /// Rule 4 at its edges: only a STRICTLY narrower route makes a Block
    /// yield, the zone-vs-literal contest follows the setting, and a literal
    /// Block is never overruled.
    #[test]
    fn a_block_yields_only_to_a_strictly_narrower_route() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("a.corp.example", vec![Ipv4Addr::new(192, 0, 2, 10)]);
        let zone = |z: &str| CanonicalAddressMatch::Zone(z.into());
        let exact = CanonicalAddressMatch::ExactFqdn("a.corp.example".into());
        let literal = CanonicalAddressMatch::ExactIp(ip);
        let routed =
            |m: CanonicalAddressMatch| book(vec![], vec![address_rule("s1", m, RuleAction::Route)]);

        let by_zone = AddressOwnership::resolve(&routed(zone("example")), &cache);
        // A tie keeps the block; a longer zone is narrower.
        assert!(!by_zone.block_yields(ip, &zone("example")));
        let by_longer_zone = AddressOwnership::resolve(&routed(zone("corp.example")), &cache);
        assert!(by_longer_zone.block_yields(ip, &zone("example")));
        assert!(!by_longer_zone.block_yields(ip, &exact));

        let by_exact = AddressOwnership::resolve(&routed(exact.clone()), &cache);
        assert!(by_exact.block_yields(ip, &zone("corp.example")));
        assert!(by_exact.block_yields(
            ip,
            &CanonicalAddressMatch::SuffixDomain("corp.example".into())
        ));
        assert!(!by_exact.block_yields(ip, &exact));
        assert!(!by_exact.block_yields(ip, &literal));

        let by_literal = AddressOwnership::resolve(&routed(literal.clone()), &cache);
        assert!(by_literal.block_yields(ip, &zone("example")));
        assert!(!by_literal.block_yields(ip, &exact));
        let zone_first = AddressOwnership::resolve_with_order(
            &routed(literal),
            &cache,
            ZoneVsIpOrder::ZoneFirst,
        );
        assert!(!zone_first.block_yields(ip, &zone("example")));

        // Nothing routes an unnamed address, so nothing overrules its block.
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        assert!(!by_exact.block_yields(other, &zone("example")));
    }

    mod networks {
        use super::*;
        use nrr_domain::decision_engine_input::match_sample;
        use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
        use nrr_domain::{RouteBehaviorMode, RouteRole};
        use nrr_shared::ip_block::IpRange;

        /// Enforcement carries networks here whatever the shipped flag says.
        fn with_networks() -> RuleShapeSupport {
            RuleShapeSupport {
                network_destination: true,
                ..crate::wfp_codegen::current_rule_shape_support()
            }
        }

        fn resolve(book: &CanonicalRuleBook, cache: &dyn FqdnCacheLookup) -> AddressOwnership {
            resolve_in(book, cache, ZoneVsIpOrder::ExactIpFirst)
        }

        fn resolve_in(
            book: &CanonicalRuleBook,
            cache: &dyn FqdnCacheLookup,
            order: ZoneVsIpOrder,
        ) -> AddressOwnership {
            AddressOwnership::resolve_with_support(book, cache, order, with_networks())
        }

        fn ip(text: &str) -> IpAddr {
            text.parse().expect("address")
        }

        fn subnet(text: &str) -> CanonicalAddressMatch {
            CanonicalAddressMatch::Subnet(IpBlock::parse(text).expect("subnet"))
        }

        fn range(text: &str) -> CanonicalAddressMatch {
            CanonicalAddressMatch::ip_range(IpRange::parse(text).expect("range"))
        }

        fn literal(text: &str) -> CanonicalAddressMatch {
            CanonicalAddressMatch::ExactIp(ip(text))
        }

        fn route(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
            address_rule(id, m, RuleAction::Route)
        }

        fn link_of(role: RouteRole) -> Link {
            match role {
                RouteRole::Primary => Link::Main,
                RouteRole::Secondary => Link::Additional,
            }
        }

        /// The engine's answer for a bare address: the oracle every address-only
        /// book here must agree with.
        fn engine_owner(book: &CanonicalRuleBook, at: IpAddr) -> Option<Link> {
            match match_sample(
                book,
                None,
                Some(at),
                None,
                ZonePriorityPolicy::default(),
                RouteBehaviorMode::PreferPrimary,
            ) {
                RequestedRouteDecision::MatchedRoute { candidate } => {
                    Some(link_of(candidate.route_role))
                }
                _ => None,
            }
        }

        fn assert_agrees(book: &CanonicalRuleBook, probes: &[&str]) {
            let ownership = resolve(book, &MockFqdnCacheLookup::new());
            for probe in probes {
                let at = ip(probe);
                assert_eq!(
                    ownership.owner_of(at),
                    engine_owner(book, at),
                    "arbiter and engine disagree at {probe}"
                );
            }
        }

        #[test]
        fn an_exact_address_beats_a_subnet_on_the_other_link() {
            let book = book(
                vec![route("p1", literal("10.1.2.3"))],
                vec![route("s1", subnet("10.1.0.0/16"))],
            );
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            assert_eq!(ownership.owner_of(ip("10.1.2.3")), Some(Link::Main));
            assert_eq!(ownership.owner_of(ip("10.1.2.4")), Some(Link::Additional));
            assert!(!ownership.address_rule_may_steer(ip("10.1.2.3"), Link::Additional));
            assert!(ownership.address_rule_may_steer(ip("10.1.2.4"), Link::Additional));
            assert_eq!(ownership.owner_of(ip("10.2.0.1")), None);
            assert_agrees(&book, &["10.1.2.3", "10.1.2.4", "10.2.0.1"]);

            let mirrored = book_swapped(&book);
            let ownership = resolve(&mirrored, &MockFqdnCacheLookup::new());
            assert_eq!(ownership.owner_of(ip("10.1.2.3")), Some(Link::Additional));
            assert_eq!(ownership.owner_of(ip("10.1.2.4")), Some(Link::Main));
            assert_agrees(&mirrored, &["10.1.2.3", "10.1.2.4"]);
        }

        fn book_swapped(b: &CanonicalRuleBook) -> CanonicalRuleBook {
            CanonicalRuleBook {
                primary: b.secondary.clone(),
                secondary: b.primary.clone(),
            }
        }

        #[test]
        fn the_longer_prefix_wins_across_links() {
            let book = book(
                vec![route("p1", subnet("10.0.0.0/16"))],
                vec![route("s1", subnet("10.0.5.0/24"))],
            );
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            assert_eq!(ownership.owner_of(ip("10.0.5.9")), Some(Link::Additional));
            assert_eq!(ownership.owner_of(ip("10.0.6.1")), Some(Link::Main));
            assert!(ownership.address_rule_may_steer(ip("10.0.5.9"), Link::Additional));
            assert!(!ownership.address_rule_may_steer(ip("10.0.6.1"), Link::Additional));
            // The main /16 still names the narrower network's addresses.
            assert!(!ownership.may_block(ip("10.0.5.9")));
            assert!(ownership.named_by(ip("10.0.5.9"), Link::Additional));
            assert_agrees(&book, &["10.0.5.9", "10.0.6.1", "10.0.5.0", "10.0.255.255"]);
            assert_agrees(&book_swapped(&book), &["10.0.5.9", "10.0.6.1"]);
        }

        #[test]
        fn the_same_network_on_both_links_goes_to_the_main_one() {
            let book = book(
                vec![route("p1", subnet("10.0.0.0/24"))],
                vec![route("s1", subnet("10.0.0.0/24"))],
            );
            assert_agrees(&book, &["10.0.0.1"]);
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            assert_eq!(ownership.owner_of(ip("10.0.0.1")), Some(Link::Main));
        }

        #[test]
        fn a_name_on_the_main_link_keeps_its_address_inside_an_additional_subnet() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("intranet.corp.example", vec![Ipv4Addr::new(10, 0, 0, 7)]);
            let book = book(
                vec![route(
                    "p1",
                    CanonicalAddressMatch::ExactFqdn("intranet.corp.example".into()),
                )],
                vec![route("s1", subnet("10.0.0.0/8"))],
            );
            let ownership = resolve(&book, &cache);
            assert_eq!(ownership.owner_of(ip("10.0.0.7")), Some(Link::Main));
            assert!(!ownership.address_rule_may_steer(ip("10.0.0.7"), Link::Additional));
            assert_eq!(ownership.owner_of(ip("10.0.0.8")), Some(Link::Additional));

            // And the other way round: a name on the additional link inside a
            // main-link network is that link's.
            let ownership = resolve(&book_swapped(&book), &cache);
            assert_eq!(ownership.owner_of(ip("10.0.0.7")), Some(Link::Additional));
            assert!(ownership.address_rule_may_steer(ip("10.0.0.7"), Link::Additional));
            assert_eq!(ownership.owner_of(ip("10.0.0.8")), Some(Link::Main));
        }

        /// A network beats a zone in the default order and loses to one with
        /// zones first, the same as an exact address does.
        #[test]
        fn a_network_beats_a_zone_only_in_the_default_order() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("files.corp.intra", vec![Ipv4Addr::new(10, 0, 0, 9)]);
            let zone_main = book(
                vec![route("p1", CanonicalAddressMatch::Zone("intra".into()))],
                vec![route("s1", subnet("10.0.0.0/8"))],
            );
            let at = ip("10.0.0.9");
            assert_eq!(
                resolve(&zone_main, &cache).owner_of(at),
                Some(Link::Additional)
            );
            assert_eq!(
                resolve_in(&zone_main, &cache, ZoneVsIpOrder::ZoneFirst).owner_of(at),
                Some(Link::Main)
            );
            let zone_additional = book_swapped(&zone_main);
            assert_eq!(
                resolve(&zone_additional, &cache).owner_of(at),
                Some(Link::Main)
            );
            assert!(!resolve(&zone_additional, &cache).address_rule_may_steer(at, Link::Additional));
            // The main zone may not steer what the additional network won.
            assert!(!resolve(&zone_main, &cache).address_rule_may_steer(at, Link::Main));
            assert!(resolve(&zone_main, &cache).address_rule_may_steer(at, Link::Additional));
            assert!(resolve_in(&zone_main, &cache, ZoneVsIpOrder::ZoneFirst)
                .address_rule_may_steer(at, Link::Main));
            assert_eq!(
                resolve_in(&zone_additional, &cache, ZoneVsIpOrder::ZoneFirst).owner_of(at),
                Some(Link::Additional)
            );
        }

        #[test]
        fn an_app_rule_may_not_claim_inside_the_other_links_network() {
            let book = book(
                vec![route("p1", subnet("192.0.2.0/24"))],
                vec![app_rule("s-app")],
            );
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            assert!(!ownership.app_rule_may_claim(ip("192.0.2.77"), Link::Additional));
            assert!(ownership.app_rule_may_claim(ip("192.0.2.77"), Link::Main));
            assert!(ownership.app_rule_may_claim(ip("198.51.100.1"), Link::Additional));
        }

        #[test]
        fn a_blocked_subnet_yields_to_a_narrower_rule_inside_it() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("wiki.corp.example", vec![Ipv4Addr::new(10, 0, 1, 1)]);
            cache.set_ips("x.corp.intra", vec![Ipv4Addr::new(10, 0, 3, 3)]);
            let blocked = subnet("10.0.0.0/16");
            let book = book(
                vec![address_rule("p-block", blocked.clone(), RuleAction::Block)],
                vec![
                    route(
                        "s-name",
                        CanonicalAddressMatch::ExactFqdn("wiki.corp.example".into()),
                    ),
                    route("s-ip", literal("10.0.2.2")),
                    route("s-24", subnet("10.0.4.0/24")),
                    route("s-zone", CanonicalAddressMatch::Zone("intra".into())),
                ],
            );
            let ownership = resolve(&book, &cache);
            assert!(ownership.block_yields(ip("10.0.1.1"), &blocked), "a name");
            assert!(
                ownership.block_yields(ip("10.0.2.2"), &blocked),
                "an exact address"
            );
            assert!(
                ownership.block_yields(ip("10.0.4.4"), &blocked),
                "a longer prefix"
            );
            // A zone is wider than a network.
            assert!(!ownership.block_yields(ip("10.0.3.3"), &blocked));
            assert!(
                !ownership.block_yields(ip("10.0.9.9"), &blocked),
                "nothing routes it"
            );
            // A network Block is no veto: the name's route is untouched.
            assert_eq!(ownership.literal_block_of(ip("10.0.1.1")), None);
            assert!(ownership.address_rule_may_steer(ip("10.0.1.1"), Link::Additional));
            // Outside the network the Block does not apply at all.
            assert!(!ownership.block_yields(ip("10.1.0.1"), &blocked));

            // The same network routed is a tie, and a tie keeps the block.
            let same = book_with_secondary(vec![route("s-16", subnet("10.0.0.0/16"))]);
            assert!(!resolve(&same, &cache).block_yields(ip("10.0.9.9"), &blocked));
            let wider = book_with_secondary(vec![route("s-8", subnet("10.0.0.0/8"))]);
            let ownership = resolve(&wider, &cache);
            assert!(
                !ownership.block_yields(ip("10.0.9.9"), &blocked),
                "a wider route"
            );
        }

        fn book_with_secondary(secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
            book(Vec::new(), secondary)
        }

        /// A zone Block over a host whose address a network routes: the network
        /// is narrower, the address stays open, and the conflict names it.
        #[test]
        fn a_zone_block_reports_the_network_that_kept_an_address_open() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("shop.example.ru", vec![Ipv4Addr::new(203, 0, 113, 5)]);
            let zone = CanonicalAddressMatch::Zone("ru".into());
            let book = book(
                vec![address_rule("p-block", zone.clone(), RuleAction::Block)],
                vec![route("s1", subnet("203.0.113.0/24"))],
            );
            let ownership = resolve(&book, &cache);
            let at = ip("203.0.113.5");
            assert!(ownership.block_yields(at, &zone));
            assert_eq!(
                ownership.block_leak("shop.example.ru", at, &zone),
                Some("203.0.113.0/24")
            );
        }

        #[test]
        fn ipv6_networks_claim_by_longest_prefix() {
            let book = book(
                vec![route("p1", subnet("2001:db8:1::/48"))],
                vec![route("s1", subnet("2001:db8::/32"))],
            );
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            assert_eq!(ownership.owner_of(ip("2001:db8:1::5")), Some(Link::Main));
            assert_eq!(
                ownership.owner_of(ip("2001:db8:2::5")),
                Some(Link::Additional)
            );
            assert_eq!(ownership.owner_of(ip("2001:db9::1")), None);
            // A v4 address never falls into a v6 network.
            assert_eq!(ownership.owner_of(ip("32.1.13.184")), None);
            assert_agrees(&book, &["2001:db8:1::5", "2001:db8:2::5", "2001:db9::1"]);
        }

        /// A range is as narrow as its piece around the address, so it beats a
        /// /24 at the addresses it holds and leaves the rest to it.
        #[test]
        fn a_range_claims_through_its_pieces() {
            let book = book(
                vec![route("p1", subnet("10.0.0.0/24"))],
                vec![route("s1", range("10.0.0.5-10.0.0.40"))],
            );
            let ownership = resolve(&book, &MockFqdnCacheLookup::new());
            for inside in ["10.0.0.5", "10.0.0.9", "10.0.0.31", "10.0.0.40"] {
                assert_eq!(
                    ownership.owner_of(ip(inside)),
                    Some(Link::Additional),
                    "{inside}"
                );
            }
            for outside in ["10.0.0.4", "10.0.0.41", "10.0.0.200"] {
                assert_eq!(
                    ownership.owner_of(ip(outside)),
                    Some(Link::Main),
                    "{outside}"
                );
            }
            assert_agrees(
                &book,
                &["10.0.0.4", "10.0.0.5", "10.0.0.9", "10.0.0.40", "10.0.0.41"],
            );

            // A blocked range yields to a narrower piece of route, not to an
            // equal one.
            let blocked = range("10.0.0.5-10.0.0.40");
            let routed = |m| book_with_secondary(vec![route("s1", m)]);
            let narrower = resolve(&routed(subnet("10.0.0.16/30")), &MockFqdnCacheLookup::new());
            assert!(narrower.block_yields(ip("10.0.0.17"), &blocked));
            let equal = resolve(&routed(subnet("10.0.0.16/28")), &MockFqdnCacheLookup::new());
            assert!(!equal.block_yields(ip("10.0.0.17"), &blocked));
        }

        #[test]
        fn a_network_enforcement_cannot_carry_claims_nothing() {
            let book = book(Vec::new(), vec![route("s1", subnet("10.0.0.0/8"))]);
            let ownership = AddressOwnership::resolve_with_support(
                &book,
                &MockFqdnCacheLookup::new(),
                ZoneVsIpOrder::ExactIpFirst,
                RuleShapeSupport::NONE,
            );
            assert_eq!(ownership.owner_of(ip("10.0.0.1")), None);
            assert_eq!(ownership.networks(Link::Additional).count(), 0);
        }

        #[test]
        fn interior_queries_answer_without_walking_the_network() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("a.example", vec![Ipv4Addr::new(10, 1, 0, 1)]);
            let book = book(
                vec![
                    route(
                        "p-name",
                        CanonicalAddressMatch::ExactFqdn("a.example".into()),
                    ),
                    route("p-24", subnet("10.2.3.0/24")),
                    route("p-out", literal("11.0.0.1")),
                ],
                vec![
                    route("s-8", subnet("10.0.0.0/8")),
                    route("s-ip", literal("10.9.9.9")),
                ],
            );
            let ownership = resolve(&book, &cache);
            let outer = IpBlock::parse("10.0.0.0/8").expect("block");
            assert_eq!(
                ownership.explicit_inside(outer),
                &[ip("10.1.0.1"), ip("10.9.9.9")]
            );
            assert_eq!(
                ownership.networks_inside(outer).collect::<Vec<_>>(),
                vec![(IpBlock::parse("10.2.3.0/24").expect("block"), Link::Main)]
            );
            assert_eq!(
                ownership.network_of(ip("10.2.3.4"), Link::Additional),
                IpBlock::parse("10.0.0.0/8")
            );
            assert_eq!(
                ownership.networks(Link::Main).collect::<Vec<_>>(),
                vec![IpBlock::parse("10.2.3.0/24").expect("block")]
            );
            // What the carve-out of the additional /8 needs, asked per address.
            let carved: Vec<IpAddr> = ownership
                .explicit_inside(outer)
                .iter()
                .copied()
                .filter(|at| ownership.owner_of(*at) == Some(Link::Main))
                .collect();
            assert_eq!(carved, vec![ip("10.1.0.1")]);
        }

        #[test]
        fn address_rule_networks_lists_route_networks_only() {
            let mut off = route("s-off", subnet("10.9.0.0/16"));
            off.enabled = false;
            let set = CanonicalRuleSet::from_rules(vec![
                route("s-24", subnet("10.0.0.0/24")),
                route("s-dup", subnet("10.0.0.0/24")),
                route("s-range", range("10.1.0.0-10.1.0.2")),
                address_rule("s-block", subnet("10.2.0.0/16"), RuleAction::Block),
                off,
            ]);
            let nets: Vec<String> = address_rule_networks(&set)
                .iter()
                .map(ToString::to_string)
                .collect();
            assert_eq!(nets, vec!["10.0.0.0/24", "10.1.0.0/31", "10.1.0.2/32"]);
        }
    }
}

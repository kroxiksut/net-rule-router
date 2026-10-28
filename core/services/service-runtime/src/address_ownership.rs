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
//!
//!    A per-user setting inverts this for programs: an application rule then
//!    takes every address its program uses, the other link's address rules
//!    notwithstanding. The price is the one above — the address goes the
//!    program's route for every program on the machine. A literal-IP Block
//!    still vetoes, two programs on different links leave a shared address
//!    with the main link, and rule 2 is untouched.
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
use nrr_domain::decision_matching::zone_ranks_as_suffix;
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
    /// Private addresses the additional link holds only through a public
    /// top-level zone: no name there takes them into the tunnel
    /// (`nrr_domain::public_zone`).
    zone_refused: HashSet<IpAddr>,
    /// Addresses application rules took from the address rules, by the link
    /// whose program uses them. Empty unless `app_takeover` is set.
    app_taken: HashMap<IpAddr, Link>,
    /// Rule 1 inverted for programs: see the module doc.
    app_takeover: bool,
    /// `route_rank`'s and `app_taken`'s addresses in address order, built on
    /// the first interior query so a compute that never asks pays nothing.
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
    /// argument above is untouched. The mirror holds too: a main-link literal
    /// yields to an additional-link name the engine evaluates first.
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

        let mut zone_learned: HashSet<IpAddr> = HashSet::new();
        let mut additional_vouched: HashSet<IpAddr> = additional_literal.clone();
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
            if let Some(claim) = additional_names.get(host) {
                // Held only by a public top-level zone: a stranger's name.
                if *claim == NameClaim::Zone(1) {
                    zone_learned.extend(ips.iter().copied().filter(|ip| {
                        !nrr_domain::public_zone::admits_zone_learned_address(host, *ip)
                    }));
                } else {
                    additional_vouched.extend(ips.iter().copied());
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

        let zone_refused: HashSet<IpAddr> = zone_learned
            .into_iter()
            .filter(|ip| !additional_vouched.contains(ip) && !networks.names(*ip, Link::Additional))
            .collect();
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
        // The mirror contest: a main literal yields to an additional NAME the
        // engine evaluates ahead of it (a host or suffix always, a zone only
        // with zones first). A main host on the address keeps it, as above.
        for ip in &main_literal {
            let additional_named_it_closer = !additional_literal.contains(ip)
                && !main_claim.contains_key(ip)
                && match additional_claim.get(ip) {
                    Some(NameClaim::Zone(_)) => order == ZoneVsIpOrder::ZoneFirst,
                    Some(_) => true,
                    None => false,
                };
            if additional_named_it_closer {
                main.remove(ip);
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
            zone_refused,
            app_taken: HashMap::new(),
            app_takeover: false,
            explicit_sorted: OnceLock::new(),
            order,
        }
    }

    /// Resolve under a principal's settings. Every mechanism that holds the
    /// app observations builds its arbiter here, so none of them can apply the
    /// takeover differently from the others.
    #[must_use]
    pub fn resolve_for(
        rule_book: &CanonicalRuleBook,
        cache: &dyn FqdnCacheLookup,
        settings: OwnershipSettings,
        support: RuleShapeSupport,
        observations: &dyn AppObservationLookup,
    ) -> Self {
        let ownership = Self::resolve_with_support(rule_book, cache, settings.order, support);
        if settings.app_takeover {
            ownership.with_app_takeover(rule_book, observations)
        } else {
            ownership
        }
    }

    /// Hand every address each link's application rules were observed using to
    /// that link, ahead of any address rule — the setting that inverts rule 1.
    ///
    /// The main link is walked first, so an address programs on both links use
    /// stays with it, the tie-break [`Self::owner_of`] applies everywhere else.
    /// A literal-IP Block's address is never taken.
    #[must_use]
    pub fn with_app_takeover(
        mut self,
        rule_book: &CanonicalRuleBook,
        observations: &dyn AppObservationLookup,
    ) -> Self {
        for (set, link) in [
            (&rule_book.primary, Link::Main),
            (&rule_book.secondary, Link::Additional),
        ] {
            for pattern in crate::app_destination_memory::routed_app_patterns(set) {
                for ip in observations.ips_for_app(&pattern) {
                    let ip = IpAddr::V4(ip);
                    if !self.literal_blocks.contains_key(&ip) {
                        self.app_taken.entry(ip).or_insert(link);
                    }
                }
            }
        }
        self.app_takeover = true;
        self.explicit_sorted = OnceLock::new();
        self
    }

    /// Whether application rules take their addresses from the address rules.
    #[must_use]
    pub fn app_takeover(&self) -> bool {
        self.app_takeover
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
    /// through a zone alone goes to the other link's network (rule 5). An
    /// address a program took under the takeover setting is its link's before
    /// any of that.
    #[must_use]
    pub fn owner_of(&self, ip: IpAddr) -> Option<Link> {
        self.app_taken
            .get(&ip)
            .copied()
            .or_else(|| self.address_owner(ip))
    }

    /// [`Self::owner_of`] as the address rules alone settle it.
    fn address_owner(&self, ip: IpAddr) -> Option<Link> {
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
    /// address follows the program instead of the rule written for it. Under
    /// the takeover setting the program's own claim decides, so the answer is
    /// no only when a program on the main link uses the address too.
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
            Link::Additional => {
                if self.zone_refused.contains(&ip) {
                    return false;
                }
                Link::Main
            }
        };
        self.owner_of(ip) != Some(other)
    }

    /// Whether no name brings `ip` into the tunnel: a private address the
    /// additional link holds only through a public top-level zone.
    #[must_use]
    pub fn keeps_out_of_tunnel(&self, ip: IpAddr) -> bool {
        self.zone_refused.contains(&ip)
    }

    /// Whether an ADDRESS rule's FILTER on `for_link` may act on this address:
    /// [`Self::address_rule_may_steer`], except that the main link's permit
    /// stays on an address a program on the additional link took. A filter
    /// steers nothing, and with the tunnel gone every other program must still
    /// reach the address directly — rule 2 with the takeover setting on.
    #[must_use]
    pub fn address_rule_may_permit(&self, ip: IpAddr, for_link: Link) -> bool {
        match (for_link, self.app_taken.get(&ip)) {
            (Link::Main, Some(Link::Additional)) => {
                self.address_owner(ip) != Some(Link::Additional)
            }
            _ => self.address_rule_may_steer(ip, for_link),
        }
    }

    /// Whether enforcement may install a BLOCK for this address. See rule 2.
    ///
    /// Reads what the main link NAMES, not what it won: an address whose
    /// steering went to the additional link because the user named it there
    /// literally is still an address a main-link rule points at, and blocking
    /// it is the outcome neither of their rules asked for. A main-link network
    /// names every address inside it in the same sense — except one an
    /// additional-link rule names more closely (a host, or a literal address):
    /// the narrower rule carries it, so the pin is its only guard while the
    /// tunnel is gone. A narrower additional NETWORK inside it is held as a
    /// network, not pinned per address.
    #[must_use]
    pub fn may_block(&self, ip: IpAddr) -> bool {
        if self.main_claimed.contains(&ip) {
            return false;
        }
        !self.networks.names(ip, Link::Main)
            || (self.additional.contains(&ip) && self.address_owner(ip) == Some(Link::Additional))
    }

    /// Whether `link`'s address rules name `ip` — literally, through a host or
    /// through a network.
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

    /// Addresses programs took under the takeover setting, with the link that
    /// took each, in no particular order.
    pub fn app_taken(&self) -> impl Iterator<Item = (IpAddr, Link)> + '_ {
        self.app_taken.iter().map(|(ip, link)| (*ip, *link))
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

    /// Whether a rule names anything inside `block`: an address, literally or
    /// through a host, an address a Block names, or a network that meets it.
    /// A local network holding one would carry that rule's traffic past it.
    #[must_use]
    pub fn names_inside(&self, block: IpBlock) -> bool {
        !self.explicit_inside(block).is_empty()
            || self.literal_blocks.keys().any(|ip| block.contains(*ip))
            || self.networks.sorted.iter().any(|net| net.overlaps(block))
    }

    /// The narrowest network of `link`'s holding `ip`.
    #[must_use]
    pub fn network_of(&self, ip: IpAddr, link: Link) -> Option<IpBlock> {
        self.networks
            .holding(ip)
            .find(|(_, claim)| claim.has(link))
            .map(|(net, _)| net)
    }

    /// The addresses route rules name literally or through a host, and those
    /// programs took, that lie inside `network`, in address order — what an
    /// emitter carving `network` asks [`Self::owner_of`] or
    /// [`Self::block_yields`] about, without walking the network itself.
    #[must_use]
    pub fn explicit_inside(&self, network: IpBlock) -> &[IpAddr] {
        let sorted = self.explicit_sorted.get_or_init(|| {
            let mut ips: Vec<IpAddr> = self
                .route_rank
                .keys()
                .chain(self.app_taken.keys())
                .copied()
                .collect();
            ips.sort_unstable();
            ips.dedup();
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameClaim {
    Zone(usize),
    Suffix(usize),
    /// A zone of several labels: a suffix without its apex, so narrower than
    /// an equally long suffix and wider than a longer one.
    SiteZone(usize),
    ExactFqdn,
}

impl NameClaim {
    fn key(self) -> (u8, usize) {
        match self {
            Self::Zone(labels) => (0, labels),
            Self::Suffix(labels) => (1, 2 * labels),
            Self::SiteZone(labels) => (1, 2 * labels + 1),
            Self::ExactFqdn => (2, 0),
        }
    }
}

impl Ord for NameClaim {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for NameClaim {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
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

/// A principal's stored settings the arbiter reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct OwnershipSettings {
    pub order: ZoneVsIpOrder,
    /// `app_rules_take_all_addresses`: rule 1 inverted for programs.
    pub app_takeover: bool,
}

impl OwnershipSettings {
    /// From the stored `zone_priority_over_ip` and `app_rules_take_all_addresses`.
    #[must_use]
    pub fn from_policy(zone_priority_over_ip: bool, app_rules_take_all_addresses: bool) -> Self {
        Self {
            order: ZoneVsIpOrder::from_zone_priority_over_ip(zone_priority_over_ip),
            app_takeover: app_rules_take_all_addresses,
        }
    }
}

impl From<ZoneVsIpOrder> for OwnershipSettings {
    fn from(order: ZoneVsIpOrder) -> Self {
        Self {
            order,
            app_takeover: false,
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
        NameClaim::Suffix(labels) => (3, 2 * labels),
        NameClaim::SiteZone(labels) => (3, 2 * labels + 1),
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
        CanonicalAddressMatch::Zone(z) => zone_claim(z, None),
        // Carried by its `*.site.<zone>` twins (`any_zone_sites`).
        CanonicalAddressMatch::AnyZoneDomain(_) => return None,
    };
    Some(host_rank(own, order))
}

/// The addresses the takeover setting never hands to a program: those an
/// enabled literal-IP Block names, as [`AddressOwnership::with_app_takeover`]
/// skips them. For readers that hold a program's addresses without an arbiter.
#[must_use]
pub fn app_takeover_vetoes(
    rule_book: &CanonicalRuleBook,
    support: RuleShapeSupport,
) -> HashSet<IpAddr> {
    literal_blocks(rule_book, support).into_keys().collect()
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

/// A zone of several labels claims its subtree as a suffix rule does, less
/// its apex — unless its own set (when known) holds `*.` of its name, which
/// claims the same hosts.
fn zone_claim(
    zone: &str,
    own: Option<(
        &CanonicalRuleSet,
        &Option<nrr_domain::canonical::CanonicalAppMatch>,
    )>,
) -> NameClaim {
    if !zone_ranks_as_suffix(zone) {
        return NameClaim::Zone(label_count(zone));
    }
    match own {
        Some((set, app)) if set.holds_suffix(zone, app) => NameClaim::Suffix(label_count(zone)),
        _ => NameClaim::SiteZone(label_count(zone)),
    }
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
                let c = zone_claim(zone, Some((rules, &rule.app_match)));
                for sub in cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP) {
                    claim(&mut names, sub, c);
                }
            }
            Some(m @ (CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_))) => {
                if rule_verdict(rule, support).is_supported() {
                    networks.extend(m.ip_blocks().into_iter().flatten().copied());
                }
            }
            // Carried by its `*.site.<zone>` twins (`any_zone_sites`).
            Some(CanonicalAddressMatch::AnyZoneDomain(_)) | None => {}
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

/// The addresses one address rule did not act on, by why, so a codegen
/// reports the cause that fired: the other link's claim, or a public zone's
/// private address kept out of the tunnel. One example and a count each.
pub(crate) struct HeldBack<'a> {
    ownership: &'a AddressOwnership,
    /// A route rule of the additional link: the only one a zone refusal binds.
    tunnel_route: bool,
    pub(crate) claimed: Option<(IpAddr, usize)>,
    pub(crate) outside_tunnel: Option<(IpAddr, usize)>,
}

impl<'a> HeldBack<'a> {
    pub(crate) fn new(ownership: &'a AddressOwnership, link: Link, action: RuleAction) -> Self {
        Self {
            ownership,
            tunnel_route: link == Link::Additional && !matches!(action, RuleAction::Block),
            claimed: None,
            outside_tunnel: None,
        }
    }

    pub(crate) fn note(&mut self, ip: IpAddr) {
        let slot = if self.tunnel_route && self.ownership.keeps_out_of_tunnel(ip) {
            &mut self.outside_tunnel
        } else {
            &mut self.claimed
        };
        match slot {
            Some((_, count)) => *count += 1,
            None => *slot = Some((ip, 1)),
        }
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
            // Carried by its `*.site.<zone>` twins (`any_zone_sites`).
            Some(CanonicalAddressMatch::AnyZoneDomain(_)) | None => {}
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
    /// Shared with a direct host, and the shared-address policy keeps it off
    /// the additional link. That policy reports it.
    DeclinedShared,
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

/// Why an application rule whose program is found carries none of its traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppTrafficElsewhere {
    /// The user's address rules name the addresses it uses, and they win.
    NamedByAddressRules,
    /// Other programs or sites use the same addresses, so moving them would
    /// move those too.
    SharedWithOthers,
}

impl AppTrafficElsewhere {
    /// The wire slug of `unrouted-app-rules`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::NamedByAddressRules => "addresses-named-by-rules",
            Self::SharedWithOthers => "addresses-shared",
        }
    }
}

impl AppDestinations {
    /// Why the rule takes none of the program's traffic: it was seen using
    /// addresses and every one went elsewhere. `None` while the rule takes any
    /// address, or before the program was seen. The user's own address rules
    /// are named first: that is the reason they can act on.
    #[must_use]
    pub fn none_taken(&self) -> Option<AppTrafficElsewhere> {
        if !self.admitted.is_empty() || self.refused.is_empty() {
            return None;
        }
        let named = self
            .refused
            .iter()
            .any(|(_, why)| *why == AppDestinationRefusal::ClaimedByAddressRule);
        Some(if named {
            AppTrafficElsewhere::NamedByAddressRules
        } else {
            AppTrafficElsewhere::SharedWithOthers
        })
    }
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
    /// Shared addresses the policy keeps off the additional link: routes and
    /// filters must give them the same answer.
    declined: Option<&'a std::collections::HashSet<Ipv4Addr>>,
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
            declined: None,
        }
    }

    /// The shared addresses the policy declined for the additional link.
    #[must_use]
    pub fn with_declined(mut self, declined: &'a std::collections::HashSet<Ipv4Addr>) -> Self {
        self.declined = Some(declined);
        self
    }

    /// Tell the observations where the rule by path spelled `key` really is,
    /// so its programs are recognised there too.
    pub fn note_path_places(&self, key: &str, places: &[nrr_shared::app_path::AppPath]) {
        self.observations.note_path_places(key, places);
    }

    /// Of `admitted`, the destinations that also get per-destination filters:
    /// the [`PER_HOSTNAME_IP_CAP`] the program used most recently, so a busy
    /// program keeps its current servers rather than its lowest addresses.
    /// One answer for the filter codegen and the neutral planner; routes take
    /// every admitted address.
    #[must_use]
    pub fn mirrored(&self, pattern: &str, admitted: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
        self.observations
            .latest_of(pattern, admitted, PER_HOSTNAME_IP_CAP)
    }

    /// Whether `pattern`'s rule learnt `ip` from a script its folder holds
    /// (see [`AppObservationLookup::learnt_from_scripts`]).
    #[must_use]
    pub fn learnt_from_scripts(&self, pattern: &str, ip: Ipv4Addr) -> bool {
        self.observations.learnt_from_scripts(pattern, ip)
    }

    /// Destinations `pattern`'s rule on `for_link` may take, in observation
    /// order, with a reason recorded for every one held back.
    ///
    /// Order matters: ownership first, because "the user's other rule names
    /// this host" is a statement about the address itself, while the census
    /// answers a question about who else happens to be on it. Under the
    /// takeover setting the census is not asked: other programs following the
    /// address is the price the user accepted.
    #[must_use]
    pub fn admit(&self, pattern: &str, for_link: Link) -> AppDestinations {
        let mut out = AppDestinations::default();
        for ip in self.observations.ips_for_app(pattern) {
            if !self.ownership.app_rule_may_claim(IpAddr::V4(ip), for_link) {
                out.refused
                    .push((ip, AppDestinationRefusal::ClaimedByAddressRule));
            } else if for_link == Link::Additional
                && self.declined.is_some_and(|declined| declined.contains(&ip))
            {
                out.refused
                    .push((ip, AppDestinationRefusal::DeclinedShared));
            } else if !self.ownership.app_takeover
                && self
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

    /// "Not routed" is said only when the rule takes nothing, and the reason
    /// the user can act on (their own address rules) is the one named.
    #[test]
    fn a_rule_takes_none_of_a_program_only_when_every_seen_address_went_elsewhere() {
        let a = Ipv4Addr::new(192, 0, 2, 1);
        let b = Ipv4Addr::new(192, 0, 2, 2);
        let refused = |why: &[AppDestinationRefusal]| AppDestinations {
            admitted: Vec::new(),
            refused: why.iter().map(|w| (a, *w)).collect(),
        };
        assert_eq!(AppDestinations::default().none_taken(), None, "never seen");
        assert_eq!(
            AppDestinations {
                admitted: vec![b],
                ..refused(&[AppDestinationRefusal::ClaimedByAddressRule])
            }
            .none_taken(),
            None,
            "one address taken is a working rule"
        );
        assert_eq!(
            refused(&[
                AppDestinationRefusal::UsedByOtherProcess,
                AppDestinationRefusal::DeclinedShared
            ])
            .none_taken(),
            Some(AppTrafficElsewhere::SharedWithOthers)
        );
        assert_eq!(
            refused(&[
                AppDestinationRefusal::UsedByOtherProcess,
                AppDestinationRefusal::ClaimedByAddressRule
            ])
            .none_taken(),
            Some(AppTrafficElsewhere::NamedByAddressRules)
        );
    }

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
                override_requested: false,
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

    /// Programs take every address they use: rule 1 inverted by the setting.
    mod takeover {
        use super::*;
        use crate::app_observation_lookup::MockAppObservationLookup;

        fn program_rule(id: &str, exe: &str) -> CanonicalRule {
            CanonicalRule {
                app_match: Some(CanonicalAppMatch {
                    pattern: CanonicalAppPattern::Exact(exe.into()),
                    include_child_processes: false,
                    override_requested: false,
                }),
                ..app_rule(id)
            }
        }

        fn observed(exe: &str, ips: Vec<Ipv4Addr>) -> MockAppObservationLookup {
            let obs = MockAppObservationLookup::new();
            obs.set_ips(exe, ips);
            obs
        }

        /// The main link names blog.example, a program on the additional link
        /// is seen using its address.
        fn contested() -> CanonicalRuleBook {
            book(
                vec![address_rule(
                    "p1",
                    CanonicalAddressMatch::ExactFqdn("blog.example".into()),
                    RuleAction::Route,
                )],
                vec![app_rule("s1")],
            )
        }

        fn resolve(
            book: &CanonicalRuleBook,
            obs: &dyn AppObservationLookup,
            on: bool,
        ) -> AddressOwnership {
            AddressOwnership::resolve_for(
                book,
                &cache(),
                OwnershipSettings::from_policy(false, on),
                crate::wfp_codegen::current_rule_shape_support(),
                obs,
            )
        }

        #[test]
        fn a_program_takes_an_address_the_other_links_rule_names() {
            let obs = observed("helper.exe", vec![NAMED]);
            let ownership = resolve(&contested(), &obs, true);
            let ip = IpAddr::V4(NAMED);

            assert_eq!(ownership.owner_of(ip), Some(Link::Additional));
            assert!(ownership.app_rule_may_claim(ip, Link::Additional));
            assert!(ownership
                .refused_for_app(&[NAMED], Link::Additional)
                .is_empty());
            // The main rule does not steer it back...
            assert!(!ownership.address_rule_may_steer(ip, Link::Main));
            // ...but keeps its permit and is never blocked: rule 2.
            assert!(ownership.address_rule_may_permit(ip, Link::Main));
            assert!(!ownership.may_block(ip));
            assert!(ownership.main_named().contains(&ip));
            assert!(ownership.named_by(ip, Link::Main));
        }

        #[test]
        fn off_leaves_the_address_rule_in_charge() {
            let obs = observed("helper.exe", vec![NAMED]);
            let ownership = resolve(&contested(), &obs, false);
            let ip = IpAddr::V4(NAMED);

            assert_eq!(ownership.owner_of(ip), Some(Link::Main));
            assert!(!ownership.app_rule_may_claim(ip, Link::Additional));
            assert!(ownership.address_rule_may_steer(ip, Link::Main));
            assert_eq!(ownership.app_taken().count(), 0);
            assert!(!ownership.app_takeover());
        }

        #[test]
        fn a_literal_block_is_never_taken() {
            let mut book = contested();
            book.secondary = CanonicalRuleSet::from_rules(vec![
                app_rule("s1"),
                address_rule(
                    "b1",
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(OTHER)),
                    RuleAction::Block,
                ),
            ]);
            let obs = observed("helper.exe", vec![OTHER]);
            let ownership = resolve(&book, &obs, true);

            assert_eq!(ownership.owner_of(IpAddr::V4(OTHER)), None);
            assert_eq!(ownership.app_taken().count(), 0);
            assert_eq!(ownership.literal_block_of(IpAddr::V4(OTHER)), Some("b1"));
        }

        #[test]
        fn programs_on_both_links_leave_the_address_with_the_main_one() {
            let book = book(
                vec![program_rule("p1", "browser.exe")],
                vec![app_rule("s1")],
            );
            let obs = observed("helper.exe", vec![OTHER]);
            obs.set_ips("browser.exe", vec![OTHER]);
            let ownership = resolve(&book, &obs, true);
            let ip = IpAddr::V4(OTHER);

            assert_eq!(ownership.owner_of(ip), Some(Link::Main));
            assert!(!ownership.app_rule_may_claim(ip, Link::Additional));
            assert!(ownership.app_rule_may_claim(ip, Link::Main));
        }

        #[test]
        fn a_taken_address_is_one_a_network_carving_asks_about() {
            let obs = observed("helper.exe", vec![NAMED]);
            let ownership = resolve(&contested(), &obs, true);
            let net = IpBlock::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)), 24).expect("net");

            assert_eq!(ownership.explicit_inside(net), &[IpAddr::V4(NAMED)]);
        }

        #[test]
        fn the_gate_admits_what_the_program_took() {
            let obs = observed("helper.exe", vec![NAMED]);
            let book = contested();

            let on = resolve(&book, &obs, true);
            let admitted = AppDestinationGate::for_rule_set(&on, &obs, &book.secondary)
                .admit("helper.exe", Link::Additional);
            assert_eq!(admitted.admitted, vec![NAMED]);
            assert!(admitted.refused.is_empty());

            let off = resolve(&book, &obs, false);
            let refused = AppDestinationGate::for_rule_set(&off, &obs, &book.secondary)
                .admit("helper.exe", Link::Additional);
            assert!(refused.admitted.is_empty());
            assert_eq!(
                refused.refused,
                vec![(NAMED, AppDestinationRefusal::ClaimedByAddressRule)]
            );
        }

        /// Other programs following the address is the price the user
        /// accepted, so the census does not get a say.
        #[test]
        fn the_census_is_skipped_only_under_the_takeover() {
            let book = book(Vec::new(), vec![app_rule("s1")]);
            let obs = observed("helper.exe", vec![OTHER]);
            obs.set_used_outside(OTHER);

            let off = resolve(&book, &obs, false);
            let gate = AppDestinationGate::for_rule_set(&off, &obs, &book.secondary);
            assert_eq!(
                gate.admit("helper.exe", Link::Additional).refused,
                vec![(OTHER, AppDestinationRefusal::UsedByOtherProcess)]
            );

            let on = resolve(&book, &obs, true);
            let gate = AppDestinationGate::for_rule_set(&on, &obs, &book.secondary);
            assert_eq!(
                gate.admit("helper.exe", Link::Additional).admitted,
                vec![OTHER]
            );
        }
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

        /// For address-only books: this oracle asks without a hostname over an
        /// empty cache, so a name rule would be invisible to both sides alike.
        fn assert_agrees(book: &CanonicalRuleBook, probes: &[&str]) {
            let named = book
                .primary
                .rules()
                .iter()
                .chain(book.secondary.rules())
                .find(|r| {
                    r.address_match.as_ref().is_some_and(|m| {
                        !matches!(
                            m,
                            CanonicalAddressMatch::ExactIp(_)
                                | CanonicalAddressMatch::Subnet(_)
                                | CanonicalAddressMatch::IpRange(..)
                        )
                    })
                });
            assert!(
                named.is_none(),
                "a name rule needs the hostname-aware oracle (engine_owner_for): {named:?}"
            );
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

        /// The engine's answer for `host` at `at` under `order`.
        fn engine_owner_for(
            book: &CanonicalRuleBook,
            host: &str,
            at: IpAddr,
            order: ZoneVsIpOrder,
        ) -> Option<Link> {
            match match_sample(
                book,
                Some(host),
                Some(at),
                None,
                ZonePriorityPolicy {
                    prefer_ip: order == ZoneVsIpOrder::ExactIpFirst,
                },
                RouteBehaviorMode::PreferPrimary,
            ) {
                RequestedRouteDecision::MatchedRoute { candidate } => {
                    Some(link_of(candidate.route_role))
                }
                _ => None,
            }
        }

        /// A main literal against an additional name for the same address:
        /// the arbiter gives it to whichever rule the engine picks for the
        /// host, in both orders.
        #[test]
        fn a_main_literal_yields_to_an_additional_name_the_engine_picks() {
            let at = ip("203.0.113.5");
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("api.corp.example", vec![Ipv4Addr::new(203, 0, 113, 5)]);
            let named = |m: CanonicalAddressMatch| {
                book(
                    vec![route("p1", literal("203.0.113.5"))],
                    vec![route("s1", m)],
                )
            };
            let cases = [
                (
                    CanonicalAddressMatch::ExactFqdn("api.corp.example".into()),
                    ZoneVsIpOrder::ExactIpFirst,
                    Link::Additional,
                ),
                (
                    CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                    ZoneVsIpOrder::ExactIpFirst,
                    Link::Additional,
                ),
                (
                    CanonicalAddressMatch::Zone("example".into()),
                    ZoneVsIpOrder::ExactIpFirst,
                    Link::Main,
                ),
                (
                    CanonicalAddressMatch::Zone("example".into()),
                    ZoneVsIpOrder::ZoneFirst,
                    Link::Additional,
                ),
            ];
            for (m, order, want) in cases {
                let book = named(m.clone());
                let ownership = resolve_in(&book, &cache, order);
                assert_eq!(ownership.owner_of(at), Some(want), "{m:?} {order:?}");
                assert_eq!(
                    engine_owner_for(&book, "api.corp.example", at, order),
                    Some(want),
                    "engine {m:?} {order:?}"
                );
                assert_eq!(
                    ownership.address_rule_may_steer(at, Link::Additional),
                    want == Link::Additional
                );
                // The main literal still names it: never blocked.
                assert!(!ownership.may_block(at));
            }

            // A main host on the same address keeps it, whatever the literal.
            cache.set_ips("www.other", vec![Ipv4Addr::new(203, 0, 113, 5)]);
            let shared = book(
                vec![
                    route("p1", literal("203.0.113.5")),
                    route("p2", CanonicalAddressMatch::ExactFqdn("www.other".into())),
                ],
                vec![route(
                    "s1",
                    CanonicalAddressMatch::ExactFqdn("api.corp.example".into()),
                )],
            );
            assert_eq!(
                resolve(&shared, &cache).owner_of(at),
                Some(Link::Main),
                "a shared address stays with the main link"
            );
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

        /// Narrow beats wide in protection too: a host the additional link
        /// names inside a main-link network is the tunnel's, and the pin is
        /// all that holds it when the tunnel is gone. The rest of the network
        /// stays unblockable, and a zone the network outranks does not pin.
        #[test]
        fn a_host_of_the_additional_link_inside_a_main_network_is_pinned() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("secret.example", vec![Ipv4Addr::new(203, 0, 113, 5)]);
            let rules = book(
                vec![route("p-net", subnet("203.0.113.0/24"))],
                vec![
                    route(
                        "s-host",
                        CanonicalAddressMatch::ExactFqdn("secret.example".into()),
                    ),
                    route("s-ip", literal("203.0.113.6")),
                ],
            );
            let ownership = resolve(&rules, &cache);
            assert!(ownership.may_block(ip("203.0.113.5")), "a name");
            assert!(ownership.may_block(ip("203.0.113.6")), "a literal");
            assert!(!ownership.may_block(ip("203.0.113.9")), "the network's own");
            assert!(ownership.named_by(ip("203.0.113.5"), Link::Main));

            cache.set_ips("files.corp.intra", vec![Ipv4Addr::new(203, 0, 113, 7)]);
            let zoned = book(
                vec![route("p-net", subnet("203.0.113.0/24"))],
                vec![route("s-zone", CanonicalAddressMatch::Zone("intra".into()))],
            );
            assert!(!resolve(&zoned, &cache).may_block(ip("203.0.113.7")));
            assert!(
                resolve_in(&zoned, &cache, ZoneVsIpOrder::ZoneFirst).may_block(ip("203.0.113.7"))
            );
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

        /// A zone of several labels is a subdomain rule without its apex: it
        /// takes its hosts from a wider suffix, an exact address and a network
        /// on the other link, where a single-label zone yields to all three.
        #[test]
        fn a_zone_of_several_labels_wins_its_hosts_like_a_suffix() {
            let cache = MockFqdnCacheLookup::new();
            cache.set_ips("db.corp.example.com", vec![Ipv4Addr::new(10, 0, 0, 9)]);
            let at = ip("10.0.0.9");
            let zone = || {
                route(
                    "s-zone",
                    CanonicalAddressMatch::Zone("corp.example.com".into()),
                )
            };
            for main in [
                route(
                    "p-wide",
                    CanonicalAddressMatch::SuffixDomain("example.com".into()),
                ),
                route("p-ip", literal("10.0.0.9")),
                route("p-net", subnet("10.0.0.0/8")),
                route(
                    "p-same",
                    CanonicalAddressMatch::SuffixDomain("corp.example.com".into()),
                ),
            ] {
                let label = main.id.as_str().to_string();
                let rules = book(vec![main], vec![zone()]);
                let ownership = resolve(&rules, &cache);
                assert_eq!(ownership.owner_of(at), Some(Link::Additional), "{label}");
                assert!(
                    ownership.address_rule_may_steer(at, Link::Additional),
                    "{label}"
                );
            }

            // Bare names covering subdomains: the zone is `*.` of its name,
            // the same rule on both links, and the main link keeps it.
            let same = book(
                vec![route(
                    "p-same",
                    CanonicalAddressMatch::SuffixDomain("corp.example.com".into()),
                )],
                vec![zone()],
            )
            .with_subdomain_coverage();
            assert_eq!(resolve(&same, &cache).owner_of(at), Some(Link::Main));

            cache.set_ips("db.corp.intra", vec![Ipv4Addr::new(10, 0, 0, 10)]);
            let top_level = book(
                vec![route("p-ip", literal("10.0.0.10"))],
                vec![route("s-zone", CanonicalAddressMatch::Zone("intra".into()))],
            );
            assert_eq!(
                resolve(&top_level, &cache).owner_of(ip("10.0.0.10")),
                Some(Link::Main)
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

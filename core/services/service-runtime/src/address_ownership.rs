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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::RuleAction;

use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;

// The fan-out caps come from the filter codegen rather than being restated
// here: ownership must cover exactly the addresses enforcement can act on, and a
// second copy of a cap is a second thing to keep in step.
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
    main: HashSet<Ipv4Addr>,
    additional: HashSet<Ipv4Addr>,
    /// Every address the MAIN link's rules name, whether or not it won the
    /// steering contest.
    ///
    /// Separate from `main` because the two questions are different: who steers
    /// the address, and whether blocking it is one of the outcomes the user
    /// asked for. Once a literal rule on the additional link could take an
    /// address off the main link, reading `main` for the second question said
    /// "yes, block it" about an address the main link still names — the third
    /// outcome rule 2 exists to forbid.
    main_claimed: HashSet<Ipv4Addr>,
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
    /// `order` settles the one contest the host stage cannot see. A rule naming
    /// an address LITERALLY has no host to contest with, and used to be written
    /// into its side unconditionally — so a zone on the main link silently
    /// outranked an exact-IP rule on the additional one, which is the opposite
    /// of what the rule model documents and of what the switch in
    /// Settings -> Routing says it does. A literal address now beats a main-link
    /// claim that is a ZONE and nothing more; anything the main link named more
    /// closely than that still keeps it, so the collateral argument above is
    /// untouched.
    #[must_use]
    pub fn resolve_with_order(
        rule_book: &CanonicalRuleBook,
        cache: &dyn FqdnCacheLookup,
        order: ZoneVsIpOrder,
    ) -> Self {
        let (main_names, main_literal) = name_claims(&rule_book.primary, cache);
        let (additional_names, additional_literal) = name_claims(&rule_book.secondary, cache);

        let mut main: HashSet<Ipv4Addr> = main_literal.clone();
        let mut additional: HashSet<Ipv4Addr> = additional_literal.clone();
        // The strongest claim the main link holds on each address it carries,
        // which is what the literal contest below compares against.
        let mut main_claim: HashMap<Ipv4Addr, NameClaim> = HashMap::new();

        let mut hosts: Vec<&str> = main_names
            .keys()
            .chain(additional_names.keys())
            .map(String::as_str)
            .collect();
        hosts.sort_unstable();
        hosts.dedup();

        for host in hosts {
            let ips: Vec<Ipv4Addr> = cache
                .ips_for_hostname(host)
                .into_iter()
                .take(PER_HOSTNAME_IP_CAP)
                .collect();
            match (main_names.get(host), additional_names.get(host)) {
                // A tie goes to the main link -- see `owner_of`.
                (Some(m), Some(a)) if a > m => additional.extend(ips),
                (Some(m), _) => {
                    for ip in &ips {
                        main_claim
                            .entry(*ip)
                            .and_modify(|best| {
                                if m > best {
                                    *best = *m;
                                }
                            })
                            .or_insert(*m);
                    }
                    main.extend(ips);
                }
                (None, Some(_)) => additional.extend(ips),
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

        Self {
            main,
            additional,
            main_claimed,
        }
    }

    /// Build from already-resolved sets. For callers that hold one side only
    /// (and for tests that want an exact shape without a cache).
    #[must_use]
    pub fn from_sets(main: HashSet<Ipv4Addr>, additional: HashSet<Ipv4Addr>) -> Self {
        Self {
            main_claimed: main.clone(),
            main,
            additional,
        }
    }

    /// Which link's address rules name `ip`, if any. `Main` wins a tie: an
    /// address both sides name is reachable on the main link, which is the
    /// outcome a user can still see and correct — the reverse is a site that
    /// works only while the tunnel is up.
    #[must_use]
    pub fn owner_of(&self, ip: Ipv4Addr) -> Option<Link> {
        if self.main.contains(&ip) {
            Some(Link::Main)
        } else if self.additional.contains(&ip) {
            Some(Link::Additional)
        } else {
            None
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
    pub fn app_rule_may_claim(&self, ip: Ipv4Addr, for_link: Link) -> bool {
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
    #[must_use]
    pub fn address_rule_may_steer(&self, ip: Ipv4Addr, for_link: Link) -> bool {
        match for_link {
            Link::Main => true,
            Link::Additional => !self.main.contains(&ip),
        }
    }

    /// Whether enforcement may install a BLOCK for this address. See rule 2.
    ///
    /// Reads what the main link NAMES, not what it won: an address whose
    /// steering went to the additional link because the user named it there
    /// literally is still an address a main-link rule points at, and blocking
    /// it is the outcome neither of their rules asked for.
    #[must_use]
    pub fn may_block(&self, ip: Ipv4Addr) -> bool {
        !self.main_claimed.contains(&ip)
    }

    /// The main link's named addresses, for callers that need the set itself
    /// (subtracting it from a protected set, reporting it).
    ///
    /// Everything the main link's rules name, for the same reason
    /// [`Self::may_block`] reads that set: a rescue permit exists so a
    /// main-named address keeps working, and that need does not disappear when
    /// the steering contest went the other way.
    #[must_use]
    pub fn main_named(&self) -> &HashSet<Ipv4Addr> {
        &self.main_claimed
    }

    /// The additional link's named addresses.
    #[must_use]
    pub fn additional_named(&self) -> &HashSet<Ipv4Addr> {
        &self.additional
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
            .filter(|ip| !self.app_rule_may_claim(*ip, for_link))
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

fn label_count(name: &str) -> usize {
    name.split('.').filter(|l| !l.is_empty()).count()
}

/// The hosts one rule set names (with the strongest claim on each) and the
/// addresses it names literally.
///
/// Application rules and Block rules contribute nothing — see rules 1 and 3 in
/// the module doc.
fn name_claims(
    rules: &CanonicalRuleSet,
    cache: &dyn FqdnCacheLookup,
) -> (HashMap<String, NameClaim>, HashSet<Ipv4Addr>) {
    let mut names: HashMap<String, NameClaim> = HashMap::new();
    let mut literal: HashSet<Ipv4Addr> = HashSet::new();
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
            None => {}
        }
    }
    (names, literal)
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
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                out.insert(*ip);
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                out.extend(
                    cache
                        .ips_for_hostname(host)
                        .into_iter()
                        .take(PER_HOSTNAME_IP_CAP),
                );
            }
            Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                for sub in cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP) {
                    out.extend(
                        cache
                            .ips_for_hostname(&sub)
                            .into_iter()
                            .take(PER_HOSTNAME_IP_CAP),
                    );
                }
            }
            Some(CanonicalAddressMatch::Zone(zone)) => {
                for sub in cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP) {
                    out.extend(
                        cache
                            .ips_for_hostname(&sub)
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
/// Route codegen, filter codegen and the neutral planner each used to reach for
/// [`AppObservationLookup::ips_for_app`] and then apply whichever subset of the
/// checks its author remembered. They diverged, and the incident in the module
/// doc is what that costs. The observations are reachable through this type
/// only, and `tests/ownership_gate.rs` holds the other end: no production call
/// site outside this module may query them directly.
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
            if !self.ownership.app_rule_may_claim(ip, for_link) {
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
    /// on the additional one, and Google hands both hosts the SAME address.
    /// Pinning it into the tunnel takes translate.search.example with it, which the
    /// user routed over the main link and which then breaks whenever the tunnel
    /// misbehaves.
    #[test]
    fn a_shared_address_stays_on_the_main_link() {
        let shared = Ipv4Addr::new(23, 10, 20, 161);
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
        assert_eq!(ownership.owner_of(shared), Some(Link::Main));
        assert!(!ownership.address_rule_may_steer(shared, Link::Additional));
        assert!(ownership.address_rule_may_steer(shared, Link::Main));
        // And it is still never blocked — rule 2 of the module doc.
        assert!(!ownership.may_block(shared));
    }

    /// The other half of the same case, and the reason the two sets are
    /// resolved together: an address ONLY the additional link's host has is
    /// still that link's, even though the main link's suffix rule covers the
    /// host by name. Resolving each set alone put it on both sides and the
    /// tie-break then swallowed the rule the user wrote.
    #[test]
    fn a_more_specific_rule_keeps_the_address_only_its_host_has() {
        let private = Ipv4Addr::new(23, 10, 20, 150);
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
        assert_eq!(ownership.owner_of(private), Some(Link::Additional));
        assert!(ownership.address_rule_may_steer(private, Link::Additional));
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
        assert_eq!(ownership.owner_of(ip), Some(Link::Additional));
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
        assert_eq!(ownership.owner_of(ip), Some(Link::Main));
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
        assert_eq!(ownership.owner_of(ip), Some(Link::Additional));
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

        assert!(!ownership.app_rule_may_claim(NAMED, Link::Additional));
        assert!(!ownership.may_block(NAMED));
        assert_eq!(ownership.owner_of(NAMED), Some(Link::Main));
        // Nothing else is affected: an address nobody named stays claimable.
        assert!(ownership.app_rule_may_claim(OTHER, Link::Additional));
        assert!(ownership.may_block(OTHER));
        assert_eq!(ownership.owner_of(OTHER), None);
    }

    /// A rule the user turned off, and a rule that blocks rather than routes,
    /// claim nothing: neither steers traffic anywhere.
    #[test]
    fn disabled_and_blocking_rules_claim_nothing() {
        let mut disabled = address_rule(
            "r-off",
            CanonicalAddressMatch::ExactIp(NAMED),
            RuleAction::Route,
        );
        disabled.enabled = false;
        let blocking = address_rule(
            "r-block",
            CanonicalAddressMatch::ExactIp(OTHER),
            RuleAction::Block,
        );
        let book = book(vec![disabled, blocking], Vec::new());

        let ownership = AddressOwnership::resolve(&book, &cache());

        assert!(ownership.app_rule_may_claim(NAMED, Link::Additional));
        assert!(ownership.app_rule_may_claim(OTHER, Link::Additional));
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
                CanonicalAddressMatch::ExactIp(OTHER),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert_eq!(ownership.owner_of(OTHER), Some(Link::Additional));
        // An app rule on the SAME link adds nothing to argue with...
        assert!(ownership.app_rule_may_claim(OTHER, Link::Additional));
        // ...and one on the other link may not take it: the address rule is the
        // statement about that destination, whichever link it names.
        assert!(!ownership.app_rule_may_claim(OTHER, Link::Main));
        assert!(ownership.may_block(OTHER));
    }

    /// An address both sides name goes to the main link. The other way round is
    /// a site that only works while the tunnel is up — a failure the user
    /// experiences as intermittent and cannot attribute.
    #[test]
    fn an_address_both_links_name_belongs_to_the_main_one() {
        let book = book(
            vec![address_rule(
                "r-main",
                CanonicalAddressMatch::ExactIp(NAMED),
                RuleAction::Route,
            )],
            vec![address_rule(
                "r-sec",
                CanonicalAddressMatch::ExactIp(NAMED),
                RuleAction::Route,
            )],
        );
        let ownership = AddressOwnership::resolve(&book, &cache());

        assert_eq!(ownership.owner_of(NAMED), Some(Link::Main));
        assert!(!ownership.may_block(NAMED));
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

    /// The rule model says an exact address outranks a zone by default, and the
    /// arbiter used to say the opposite: a literal address went into its side
    /// unconditionally, the main link then won every overlap, and the user's
    /// exact-IP rule on the additional link was dead.
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
                CanonicalAddressMatch::ExactIp(ip),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(ip), Some(Link::Additional));
        assert!(ownership.address_rule_may_steer(ip, Link::Additional));
        // Still never blocked — rule 2 of the module doc holds either way.
        assert!(!ownership.may_block(ip));
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
                CanonicalAddressMatch::ExactIp(ip),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve_with_order(
            &book,
            &cache,
            ZoneVsIpOrder::from_zone_priority_over_ip(true),
        );
        assert_eq!(ownership.owner_of(ip), Some(Link::Main));
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
                CanonicalAddressMatch::ExactIp(ip),
                RuleAction::Route,
            )],
        );

        let ownership = AddressOwnership::resolve(&book, &cache);
        assert_eq!(ownership.owner_of(ip), Some(Link::Main));
        assert!(!ownership.address_rule_may_steer(ip, Link::Additional));
    }
}

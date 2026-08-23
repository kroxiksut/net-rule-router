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

use std::collections::HashSet;
use std::net::Ipv4Addr;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::RuleAction;

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
}

impl AddressOwnership {
    /// Resolve both sides of a rule book.
    #[must_use]
    pub fn resolve(rule_book: &CanonicalRuleBook, cache: &dyn FqdnCacheLookup) -> Self {
        Self {
            main: address_rule_ips(&rule_book.primary, cache),
            additional: address_rule_ips(&rule_book.secondary, cache),
        }
    }

    /// Build from already-resolved sets. For callers that hold one side only
    /// (and for tests that want an exact shape without a cache).
    #[must_use]
    pub fn from_sets(main: HashSet<Ipv4Addr>, additional: HashSet<Ipv4Addr>) -> Self {
        Self { main, additional }
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

    /// Whether enforcement may install a BLOCK for this address. See rule 2.
    #[must_use]
    pub fn may_block(&self, ip: Ipv4Addr) -> bool {
        !self.main.contains(&ip)
    }

    /// The main link's named addresses, for callers that need the set itself
    /// (subtracting it from a protected set, reporting it).
    #[must_use]
    pub fn main_named(&self) -> &HashSet<Ipv4Addr> {
        &self.main
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern, CanonicalRule};
    use nrr_domain::RuleId;

    const NAMED: Ipv4Addr = Ipv4Addr::new(178, 248, 237, 68);
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
                pattern: CanonicalAppPattern::Exact("claude.exe".into()),
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
        cache.set_ips("habr.com", vec![NAMED]);
        cache
    }

    /// The incident, stated as a question to the arbiter: the app rule asks for
    /// an address the main link names, and is told no.
    #[test]
    fn an_app_rule_may_not_claim_what_the_main_link_names() {
        let book = book(
            vec![address_rule(
                "r-main",
                CanonicalAddressMatch::ExactFqdn("habr.com".into()),
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
                CanonicalAddressMatch::ExactFqdn("habr.com".into()),
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
}

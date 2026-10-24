//! Questions several features ask of a rule book, answered once.

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook};
use nrr_domain::RuleAction;

/// Does the user send anything down the additional route? A disabled or
/// blocking rule sends nothing.
#[must_use]
pub fn has_secondary_rules(book: &CanonicalRuleBook) -> bool {
    book.secondary
        .rules()
        .iter()
        .any(|rule| rule.enabled && rule.action != RuleAction::Block)
}

/// Does the book hold an enabled deny? A deny needs no route, so it is the one
/// kind of rule that is enforced for a user who bound no connection.
#[must_use]
pub fn has_deny_rules(book: &CanonicalRuleBook) -> bool {
    book.primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .any(|rule| rule.enabled && rule.action == RuleAction::Block)
}

/// Does applying the book depend on seeing the site names a program resolves?
/// A rule sending sites off the default route by name does, and so does a
/// block by name; a resolver answering past ours (browser DoH) defeats both.
/// `secondary_by_default` is the "prefer the additional route" mode, where the
/// main-route rules are the exceptions. Any additional-route rule counts, as it
/// always has.
#[must_use]
pub fn needs_names_seen(book: &CanonicalRuleBook, secondary_by_default: bool) -> bool {
    let names_a_site = |rule: &nrr_domain::canonical::CanonicalRule| {
        rule.enabled
            && matches!(
                rule.address_match,
                Some(
                    CanonicalAddressMatch::ExactFqdn(_)
                        | CanonicalAddressMatch::SuffixDomain(_)
                        | CanonicalAddressMatch::AnyZoneDomain(_)
                        | CanonicalAddressMatch::Zone(_)
                )
            )
    };
    let blocks_a_name = book
        .primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .any(|rule| rule.action == RuleAction::Block && names_a_site(rule));
    let named_exception = secondary_by_default
        && book
            .primary
            .rules()
            .iter()
            .any(|rule| rule.action != RuleAction::Block && names_a_site(rule));
    has_secondary_rules(book) || named_exception || blocks_a_name
}

/// Every host or domain name an enabled rule of either route names, as the
/// rule stores it. Zones and addresses are not names.
#[must_use]
pub fn rule_host_names(book: &CanonicalRuleBook) -> Vec<String> {
    let mut names: Vec<String> = book
        .primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .filter(|rule| rule.enabled)
        .filter_map(|rule| match &rule.address_match {
            Some(CanonicalAddressMatch::ExactFqdn(name))
            | Some(CanonicalAddressMatch::SuffixDomain(name)) => Some(name.clone()),
            _ => None,
        })
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
    use nrr_domain::RuleId;
    use std::net::{IpAddr, Ipv4Addr};

    fn rule(id: &str, address: CanonicalAddressMatch, enabled: bool) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: Some(address),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    fn blocking(mut rule: CanonicalRule) -> CanonicalRule {
        rule.action = RuleAction::Block;
        rule
    }

    fn fqdn(name: &str) -> CanonicalAddressMatch {
        CanonicalAddressMatch::ExactFqdn(name.to_string())
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    #[test]
    fn only_an_enabled_routing_rule_counts_as_a_secondary_rule() {
        let primary_only = book(vec![rule("p", fqdn("a.example"), true)], vec![]);
        assert!(!has_secondary_rules(&primary_only));
        let disabled = book(vec![], vec![rule("s", fqdn("b.example"), false)]);
        assert!(!has_secondary_rules(&disabled));
        let blocks = book(vec![], vec![blocking(rule("s", fqdn("b.example"), true))]);
        assert!(!has_secondary_rules(&blocks));
        let routes = book(vec![], vec![rule("s", fqdn("b.example"), true)]);
        assert!(has_secondary_rules(&routes));
    }

    #[test]
    fn only_an_enabled_deny_counts_as_a_deny() {
        assert!(!has_deny_rules(&book(
            vec![rule("p", fqdn("a.example"), true)],
            vec![]
        )));
        assert!(!has_deny_rules(&book(
            vec![blocking(rule("p", fqdn("a.example"), false))],
            vec![]
        )));
        assert!(has_deny_rules(&book(
            vec![],
            vec![blocking(rule("s", fqdn("a.example"), true))]
        )));
    }

    /// Browser DoH hides the name from us. Under "prefer the additional route"
    /// the main-route exceptions then take the tunnel, and a block by name
    /// lets the site through; an address block needs no name.
    #[test]
    fn exceptions_off_the_default_and_blocks_by_name_need_the_names() {
        let exception = book(vec![rule("p", fqdn("bank.example"), true)], vec![]);
        assert!(
            !needs_names_seen(&exception, false),
            "the main route is the default"
        );
        assert!(needs_names_seen(&exception, true));
        let by_address = CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)));
        let address_exception = book(vec![rule("p", by_address, true)], vec![]);
        assert!(
            !needs_names_seen(&address_exception, true),
            "an address needs no name"
        );

        let named_block = book(vec![blocking(rule("b", fqdn("ads.example"), true))], vec![]);
        assert!(needs_names_seen(&named_block, false));
        let address = CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)));
        let address_block = book(vec![blocking(rule("b", address, true))], vec![]);
        assert!(!needs_names_seen(&address_block, false));
        let off = book(
            vec![blocking(rule("b", fqdn("ads.example"), false))],
            vec![],
        );
        assert!(!needs_names_seen(&off, true));

        let routed = book(vec![], vec![rule("s", fqdn("video.example"), true)]);
        assert!(needs_names_seen(&routed, false));
        assert!(needs_names_seen(&routed, true), "as before");
    }

    #[test]
    fn names_come_from_both_routes_without_zones_or_addresses() {
        let address = CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let names = rule_host_names(&book(
            vec![
                rule(
                    "p1",
                    CanonicalAddressMatch::SuffixDomain("video.example".into()),
                    true,
                ),
                rule("p2", CanonicalAddressMatch::Zone("ru".into()), true),
                rule("p3", address, true),
            ],
            vec![
                rule("s1", fqdn("git.corp.example"), true),
                rule("s2", fqdn("off.example"), false),
                blocking(rule("s3", fqdn("git.corp.example"), true)),
            ],
        ));
        assert_eq!(names, ["git.corp.example", "video.example"]);
    }
}

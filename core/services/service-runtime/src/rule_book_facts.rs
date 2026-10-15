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

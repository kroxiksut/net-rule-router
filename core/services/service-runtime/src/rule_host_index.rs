//! Which of a rule set's rules can name a hostname, without walking them all.
//!
//! The rule-host check runs on every DNS query. The index only narrows the
//! rules handed to the one matcher (`dns_observation_consumer::rule_covers`),
//! which stays the judge: a rule left out is one that cannot cover the name.

use std::collections::HashMap;

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleSet};

/// Positions of a set's rules by the name they are written with.
pub(crate) struct RuleHostIndex {
    /// Exact hosts, `*.` suffixes and zones. Each covers a name only when it
    /// is the name itself or the part after one of its dots, so a name asks
    /// for those parts and nothing else.
    by_name: HashMap<Box<str>, Vec<usize>>,
    /// `base.*` rules: where one reaches depends on the name's zone, so every
    /// name asks them.
    any_zone: Vec<usize>,
}

impl RuleHostIndex {
    pub(crate) fn build(set: &CanonicalRuleSet) -> Self {
        let mut by_name: HashMap<Box<str>, Vec<usize>> = HashMap::new();
        let mut any_zone = Vec::new();
        for (at, rule) in set.rules().iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            // Exhaustive: a new kind of name rule must say how it is found.
            match &rule.address_match {
                Some(
                    CanonicalAddressMatch::ExactFqdn(name)
                    | CanonicalAddressMatch::SuffixDomain(name)
                    | CanonicalAddressMatch::Zone(name),
                ) => by_name.entry(name.as_str().into()).or_default().push(at),
                Some(CanonicalAddressMatch::AnyZoneDomain(_)) => any_zone.push(at),
                Some(
                    CanonicalAddressMatch::ExactIp(_)
                    | CanonicalAddressMatch::Subnet(_)
                    | CanonicalAddressMatch::IpRange(_),
                )
                | None => {}
            }
        }
        Self { by_name, any_zone }
    }

    /// Some enabled rule of the set names a host, so a name can be a rule host.
    pub(crate) fn names_any_host(&self) -> bool {
        !self.by_name.is_empty() || !self.any_zone.is_empty()
    }

    /// A query that could belong to a secondary rule may take the primary path
    /// only when a primary route wins for the name. DNS has no app identity.
    pub(crate) fn requires_secondary(
        &self,
        hostname: &str,
        book: &nrr_domain::canonical::CanonicalRuleBook,
        primary: &Self,
    ) -> bool {
        use crate::dns_observation_consumer::{any_rule_covers, rule_covers};
        use nrr_domain::canonical::CanonicalRuleBook;
        use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
        use nrr_domain::{RouteBehaviorMode, RouteRole, RuleAction};

        let secondary = || self.candidates(hostname, &book.secondary);
        if !any_rule_covers(hostname, secondary()) {
            return false;
        }
        let main = || primary.candidates(hostname, &book.primary);
        if !any_rule_covers(hostname, main()) {
            return true;
        }

        // A query carries no process identity. A possible app-scoped secondary
        // rule must stay protected until we can establish who owns the query.
        if secondary().any(|rule| rule.app_match.is_some() && rule_covers(rule, hostname)) {
            return true;
        }
        let candidates = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(main().cloned().collect()),
            secondary: CanonicalRuleSet::from_rules(secondary().cloned().collect()),
        };
        let winner = nrr_domain::decision_engine_input::match_sample(
            &candidates,
            Some(hostname),
            None,
            None,
            ZonePriorityPolicy::default(),
            RouteBehaviorMode::PreferPrimary,
        );
        !matches!(
            winner,
            RequestedRouteDecision::MatchedRoute { candidate }
                if candidate.route_role == RouteRole::Primary && candidate.action == RuleAction::Route
        )
    }

    /// The rules of `set`, the set this index was built from, that may cover
    /// `hostname`; every other rule cannot.
    pub(crate) fn candidates<'s>(
        &'s self,
        hostname: &'s str,
        set: &'s CanonicalRuleSet,
    ) -> impl Iterator<Item = &'s CanonicalRule> + 's {
        let parts = std::iter::once(hostname).chain(
            hostname
                .match_indices('.')
                .map(move |(dot, _)| &hostname[dot + 1..]),
        );
        parts
            .filter_map(|part| self.by_name.get(part))
            .flatten()
            .chain(&self.any_zone)
            .filter_map(|&at| set.rules().get(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_observation_consumer::{
        any_rule_covers, held_only_by_public_zone, held_only_by_public_zone_among, rule_set_matches,
    };
    use nrr_domain::RuleId;

    fn rule(id: usize, address: Option<CanonicalAddressMatch>, enabled: bool) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(format!("r{id}")),
            enabled,
            address_match: address,
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn a_primary_exception_inside_a_secondary_zone_keeps_its_own_dns_path() {
        use crate::dns_resolver::RuleHostOracle;
        use crate::dns_resolver_ports::ActiveRuleHostOracle;
        use crate::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};
        use nrr_domain::canonical::CanonicalRuleBook;
        use std::sync::Arc;

        struct Rules(CanonicalRuleBook);
        impl RulesProvider for Rules {
            fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
                Some(ActiveRulesSnapshot {
                    rule_book: self.0.clone(),
                })
            }
        }

        use CanonicalAddressMatch::{ExactFqdn, SuffixDomain, Zone};
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule(1, Some(ExactFqdn("login.example.test".into())), true),
                rule(2, Some(SuffixDomain("corp.example.test".into())), true),
            ]),
            secondary: CanonicalRuleSet::from_rules(vec![
                rule(3, Some(Zone("test".into())), true),
                rule(4, Some(ExactFqdn("vpn.corp.example.test".into())), true),
            ]),
        };
        let oracle =
            ActiveRuleHostOracle::new(Arc::new(Rules(book)), Arc::new(|| Some("test".into())));
        assert!(oracle.is_rule_host("other.example.test"));
        assert!(oracle.is_rule_host("vpn.corp.example.test"));
        assert!(!oracle.is_rule_host("login.example.test"));
        assert!(!oracle.is_rule_host("host.corp.example.test"));
    }

    /// Names a hostile or careless writer can put in a rule or a query: case,
    /// trailing and doubled dots, punycode, empty labels, wildcards left in,
    /// zones of several labels, country second levels.
    const NAMES: &[&str] = &[
        "",
        ".",
        "..",
        "ru",
        "RU",
        "ru.",
        "xn--p1ai",
        "com",
        "co.uk",
        "intra",
        "corp.intra",
        "example",
        "example.com",
        "Example.com",
        "example.com.",
        "*.example.com",
        "*",
        "www.example.com",
        "www..example.com",
        "a.b.c.example.com",
        "notexample.com",
        "example.co.uk",
        "www.example.co.uk",
        "example.com.attacker.net",
        "site.xn--p1ai",
        "a.site.xn--p1ai",
        "msk.ru",
        "shop.msk.ru",
        "server.corp.intra",
        "xn--80ak6aa92e.com",
        "-.example.com",
        "a.b",
        "b",
    ];

    fn every_kind_of_rule() -> CanonicalRuleSet {
        let mut rules = Vec::new();
        for (i, name) in NAMES.iter().enumerate() {
            let name = (*name).to_owned();
            for (k, address) in [
                CanonicalAddressMatch::ExactFqdn(name.clone()),
                CanonicalAddressMatch::SuffixDomain(name.clone()),
                CanonicalAddressMatch::Zone(name.clone()),
                CanonicalAddressMatch::AnyZoneDomain(name),
            ]
            .into_iter()
            .enumerate()
            {
                rules.push(rule(i * 8 + k, Some(address), true));
            }
        }
        rules.push(rule(
            10_000,
            Some(CanonicalAddressMatch::ExactIp(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(203, 0, 113, 1),
            ))),
            true,
        ));
        rules.push(rule(10_001, None, true));
        rules.push(rule(
            10_002,
            Some(CanonicalAddressMatch::ExactFqdn("disabled.example".into())),
            false,
        ));
        CanonicalRuleSet::from_rules(rules)
    }

    /// The index changes no answer: for every name against every kind of
    /// rule, the narrowed rules say what the whole set says, for the rule-host
    /// check and the public-zone question alike.
    #[test]
    fn the_index_answers_every_name_as_the_whole_set_does() {
        let full = every_kind_of_rule();
        let mut queries: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
        queries.extend(["disabled.example".to_owned(), "203.0.113.1".to_owned()]);
        for name in NAMES {
            queries.push(format!("www.{name}"));
            queries.push(format!("{name}."));
            queries.push(name.to_uppercase());
        }
        // One rule at a time as well: a set where only one kind is present
        // must not lean on another kind to be found.
        let singles: Vec<CanonicalRuleSet> = full
            .rules()
            .iter()
            .map(|r| CanonicalRuleSet::from_rules(vec![r.clone()]))
            .collect();
        for set in std::iter::once(&full).chain(&singles) {
            let index = RuleHostIndex::build(set);
            for query in &queries {
                assert_eq!(
                    any_rule_covers(query, index.candidates(query, set)),
                    rule_set_matches(query, set),
                    "rule host {query:?} in {:?}",
                    set.rules()
                        .iter()
                        .map(|r| &r.address_match)
                        .collect::<Vec<_>>(),
                );
                assert_eq!(
                    held_only_by_public_zone_among(query, index.candidates(query, set)),
                    held_only_by_public_zone(query, set),
                    "public zone {query:?}",
                );
            }
        }
    }
}

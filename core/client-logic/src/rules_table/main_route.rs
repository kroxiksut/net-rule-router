//! The main-route check over the rules table: which rules it asks about, and
//! how its verdicts order the list.

use std::collections::HashSet;

use super::{RuleRow, RuleType, TargetRoute};

/// Sort rank of a main-route verdict (`mainRouteRank`): what the main route
/// does not reach first, a rule never checked last.
pub fn main_route_rank(slug: &str) -> u8 {
    match slug {
        "silent" => 0,
        "answered" => 1,
        "unclear" => 2,
        "no-address" => 3,
        _ => 4,
    }
}

/// The hosts "Check the main route" asks about (`mainRouteCheckHosts`): the
/// enabled host rules of the additional route, in ACE form when the row
/// carries it, without a leading `*.`, lower-cased, each once in first-seen
/// order. A zone names no single address to try.
pub fn main_route_check_hosts<'a>(
    rows: impl IntoIterator<Item = (&'a RuleRow, Option<&'a str>)>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut hosts = Vec::new();
    for (row, ace) in rows {
        let host_rule = matches!(
            row.rule_type,
            RuleType::Domain | RuleType::SuffixDomain | RuleType::ExactFqdn
        );
        if !host_rule || !row.enabled || row.target_route != TargetRoute::Secondary {
            continue;
        }
        let value = ace.filter(|a| !a.is_empty()).unwrap_or(&row.match_value);
        let host = value
            .strip_prefix("*.")
            .unwrap_or(value)
            .trim()
            .to_lowercase();
        if !host.is_empty() && seen.insert(host.clone()) {
            hosts.push(host);
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(rule_type: RuleType, value: &str, route: TargetRoute, enabled: bool) -> RuleRow {
        RuleRow {
            id: String::new(),
            enabled,
            rule_type,
            match_value: value.into(),
            target_route: route,
            verify: false,
            comment: String::new(),
            origin: None,
        }
    }

    #[test]
    fn unreached_first_and_unchecked_last() {
        let ranks: Vec<u8> = ["silent", "answered", "unclear", "no-address", "", "later"]
            .into_iter()
            .map(main_route_rank)
            .collect();
        assert_eq!(ranks, [0, 1, 2, 3, 4, 4]);
    }

    #[test]
    fn only_enabled_additional_route_hosts_are_asked_about_once() {
        let rows = [
            row(
                RuleType::Domain,
                "*.Example.COM",
                TargetRoute::Secondary,
                true,
            ),
            row(
                RuleType::ExactFqdn,
                "example.com",
                TargetRoute::Secondary,
                true,
            ),
            row(RuleType::Domain, "пример.рф", TargetRoute::Secondary, true),
            row(RuleType::Zone, "ru", TargetRoute::Secondary, true),
            row(RuleType::Domain, "main.example", TargetRoute::Primary, true),
            row(
                RuleType::Domain,
                "off.example",
                TargetRoute::Secondary,
                false,
            ),
            row(RuleType::Domain, "ads.example", TargetRoute::Block, true),
            row(RuleType::ExactIp, "192.0.2.1", TargetRoute::Secondary, true),
        ];
        let ace = [
            None,
            None,
            Some("xn--e1afmkfd.xn--p1ai"),
            None,
            None,
            None,
            None,
            None,
        ];
        let hosts = main_route_check_hosts(rows.iter().zip(ace));
        assert_eq!(hosts, ["example.com", "xn--e1afmkfd.xn--p1ai"]);
    }
}

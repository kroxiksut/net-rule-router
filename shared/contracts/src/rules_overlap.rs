//! Overlapping-rule detection over the canonical rules-json DTO.
//!
//! A `SuffixDomain` rule covers the apex itself and every subdomain of it
//! (see `nrr_domain::decision_rules_matching`), so an `ExactFqdn` rule under
//! the same apex on the same route is usually a leftover the user forgot
//! about. It is not always redundant, though: one with a different action or
//! an app filter is a deliberate exception.
//!
//! [`find_overlaps`] reports both, split by [`OverlapPair::redundant`]: the
//! cleanup UI offers the redundant ones for removal and leaves the deliberate
//! ones alone. The decision lives here rather than in QML so the rule that
//! decides "safe to delete" is one testable function, shared by every surface.
//! Pairs across the two routes are [`find_route_overlaps`]'s: the Overlaps
//! screen owns them.
//!
//! The risk-scoring counterpart in `nrr_domain::review` answers a different
//! question — "does THIS change create an overlap" — and is scoped to a diff.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::rules_json::{folded_rule_name, AddressMatchDto, CanonicalRulesJsonV1, RuleDto};

mod across_routes;

pub use across_routes::{find_route_overlaps, OverlapRule, RouteOverlap, RouteOverlapKind};

/// One exact rule covered by a suffix rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OverlapPair {
    /// Apex of the covering suffix rule (`example.com` for `*.example.com`).
    pub apex: String,
    /// Route the suffix rule lives in: `"primary"` / `"secondary"`.
    pub apex_route: String,
    /// Id of the covering suffix rule.
    pub apex_rule_id: String,
    /// Hostname of the covered exact rule.
    pub covered_host: String,
    /// Route the covered exact rule lives in.
    pub covered_route: String,
    /// Id of the covered exact rule — what a cleanup deletes.
    pub covered_rule_id: String,
    /// The exact rule changes nothing: same route, same action, and the
    /// suffix rule is enabled, so removing it leaves routing identical.
    pub redundant: bool,
}

/// Every exact rule covered by a suffix rule of the same route, in a
/// deterministic order (by apex, then by covered host).
pub fn find_overlaps(dto: &CanonicalRulesJsonV1) -> Vec<OverlapPair> {
    let suffixes = collect(dto, |m| match m {
        AddressMatchDto::SuffixDomain { suffix } => Some(suffix.as_str()),
        _ => None,
    });
    let exacts = collect(dto, |m| match m {
        AddressMatchDto::ExactFqdn { value } => Some(value.as_str()),
        _ => None,
    });
    let suffixes_by_name = index_by_name(&suffixes, |s| s.name.as_str());

    let mut out: Vec<OverlapPair> = Vec::new();
    for covered in &exacts {
        for apex in ancestors_in(&covered.name, &suffixes_by_name) {
            if apex.route != covered.route {
                continue;
            }
            // An app filter narrows a rule to one process, so the two never
            // describe the same traffic and neither one is spare.
            let same_app = apex.rule.app_match == covered.rule.app_match;
            // Written values, not folded names: the pair key a user kept is
            // stored in these spellings.
            out.push(OverlapPair {
                apex: apex.written.to_string(),
                apex_route: apex.route.to_string(),
                apex_rule_id: apex.rule.id.clone(),
                covered_host: covered.written.to_string(),
                covered_route: covered.route.to_string(),
                covered_rule_id: covered.rule.id.clone(),
                redundant: same_app
                    && apex.rule.action == covered.rule.action
                    && apex.rule.enabled
                    && covered.rule.enabled,
            });
        }
    }
    out.sort_by(|a, b| {
        a.apex
            .cmp(&b.apex)
            .then_with(|| a.covered_host.cmp(&b.covered_host))
            .then_with(|| a.covered_rule_id.cmp(&b.covered_rule_id))
    });
    out
}

/// Rules grouped by their folded name, so an ancestor walk finds the rules
/// covering a host in one lookup per label.
fn index_by_name<'r, T>(
    items: &'r [T],
    name: impl Fn(&'r T) -> &'r str,
) -> HashMap<&'r str, Vec<&'r T>> {
    let mut by_name: HashMap<&str, Vec<&T>> = HashMap::new();
    for item in items {
        by_name.entry(name(item)).or_default().push(item);
    }
    by_name
}

/// Entries named `name` itself or one of its parent domains.
fn ancestors_in<'r, T>(name: &str, by_name: &HashMap<&'r str, Vec<&'r T>>) -> Vec<&'r T> {
    let mut found = Vec::new();
    let mut current = Some(name);
    while let Some(candidate) = current {
        if let Some(items) = by_name.get(candidate) {
            found.extend(items.iter().copied());
        }
        current = candidate.split_once('.').map(|(_, parent)| parent);
    }
    found
}

/// One name rule as the same-route pass sees it.
struct Named<'a> {
    rule: &'a RuleDto,
    route: &'static str,
    written: &'a str,
    name: String,
}

/// Rules of one address kind across both routes, with an empty name dropped.
fn collect<'a, F>(dto: &'a CanonicalRulesJsonV1, pick: F) -> Vec<Named<'a>>
where
    F: Fn(&'a AddressMatchDto) -> Option<&'a str>,
{
    let mut out = Vec::new();
    for (route, rules) in [("primary", &dto.primary), ("secondary", &dto.secondary)] {
        for rule in rules {
            let Some(address) = rule.address_match.as_ref() else {
                continue;
            };
            let Some(written) = pick(address) else {
                continue;
            };
            // Rules on screen may not be canonical yet.
            let name = folded_rule_name(address).unwrap_or_default();
            if !name.is_empty() {
                out.push(Named {
                    rule,
                    route,
                    written,
                    name,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_json::{RuleAction, RULES_JSON_SCHEMA_VERSION};

    fn rule(id: &str, address: AddressMatchDto) -> RuleDto {
        RuleDto {
            id: id.to_string(),
            enabled: true,
            address_match: Some(address),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    fn exact(id: &str, host: &str) -> RuleDto {
        rule(
            id,
            AddressMatchDto::ExactFqdn {
                value: host.to_string(),
            },
        )
    }

    fn suffix(id: &str, apex: &str) -> RuleDto {
        rule(
            id,
            AddressMatchDto::SuffixDomain {
                suffix: apex.to_string(),
            },
        )
    }

    fn book(primary: Vec<RuleDto>, secondary: Vec<RuleDto>) -> CanonicalRulesJsonV1 {
        CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary,
            secondary,
        }
    }

    #[test]
    fn apex_covered_by_its_own_wildcard_in_the_same_route_is_redundant() {
        let dto = book(
            vec![],
            vec![suffix("r-1", "blog.example"), exact("r-2", "blog.example")],
        );
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].covered_rule_id, "r-2");
        assert_eq!(found[0].apex, "blog.example");
        assert!(found[0].redundant);
    }

    #[test]
    fn subdomain_covered_by_the_wildcard_is_reported_too() {
        let dto = book(
            vec![],
            vec![
                suffix("r-1", "example.com"),
                exact("r-2", "api.example.com"),
            ],
        );
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].covered_host, "api.example.com");
        assert!(found[0].redundant);
    }

    #[test]
    fn a_pair_across_the_routes_belongs_to_the_overlaps_screen() {
        let dto = book(
            vec![exact("r-2", "api.example.com")],
            vec![suffix("r-1", "example.com")],
        );
        assert!(find_overlaps(&dto).is_empty());
        assert_eq!(find_route_overlaps(&dto, false).len(), 1);
    }

    #[test]
    fn a_different_action_is_a_deliberate_carve_out() {
        let mut blocked = exact("r-2", "ads.example.com");
        blocked.action = RuleAction::Block;
        let dto = book(vec![], vec![suffix("r-1", "example.com"), blocked]);
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert!(!found[0].redundant);
    }

    #[test]
    fn a_disabled_wildcard_does_not_make_the_exact_rule_spare() {
        let mut off = suffix("r-1", "example.com");
        off.enabled = false;
        let dto = book(vec![], vec![off, exact("r-2", "api.example.com")]);
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert!(!found[0].redundant);
    }

    #[test]
    fn an_app_filter_on_one_side_keeps_both_rules() {
        use crate::rules_json::{AppMatchDto, AppPatternDto};
        let mut scoped = exact("r-2", "api.example.com");
        scoped.app_match = Some(AppMatchDto {
            pattern: AppPatternDto::Exact {
                value: "chrome.exe".to_string(),
            },
            include_child_processes: false,
        });
        let dto = book(vec![], vec![suffix("r-1", "example.com"), scoped]);
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert!(!found[0].redundant);
    }

    #[test]
    fn unrelated_apexes_do_not_pair() {
        let dto = book(
            vec![],
            vec![suffix("r-1", "bar.com"), exact("r-2", "api.foo.com")],
        );
        assert!(find_overlaps(&dto).is_empty());
    }

    #[test]
    fn a_longer_label_ending_in_the_apex_text_is_not_a_subdomain() {
        let dto = book(
            vec![],
            vec![suffix("r-1", "example.com"), exact("r-2", "notexample.com")],
        );
        assert!(find_overlaps(&dto).is_empty());
    }

    /// The spellings a rule on screen may still carry before the service
    /// canonicalises it; the Overlaps pass has always folded them.
    #[test]
    fn case_wildcard_and_dots_are_folded_as_the_route_pass_folds_them() {
        for (apex, host) in [
            ("Example.COM", "api.example.com"),
            ("*.example.com", "api.example.com"),
            (".example.com", "API.Example.com."),
            ("example.com.", "example.com"),
        ] {
            let dto = book(vec![], vec![suffix("r-1", apex), exact("r-2", host)]);
            let found = find_overlaps(&dto);
            assert_eq!(found.len(), 1, "{apex} / {host}");
            assert!(found[0].redundant);
            assert_eq!(found[0].apex, apex, "the written spelling keys a kept pair");
            assert_eq!(found[0].covered_host, host);

            let across = book(vec![exact("r-2", host)], vec![suffix("r-1", apex)]);
            assert!(find_overlaps(&across).is_empty());
            assert_eq!(
                find_route_overlaps(&across, false).len(),
                1,
                "{apex} / {host}"
            );
        }
    }

    /// The drift hash and both overlap passes read one folding: two spellings
    /// name the same host to all three, or to none. Pairs that only a looser
    /// folding would join are here too — the matcher keeps them apart.
    #[test]
    fn every_comparison_folds_a_name_the_same_way() {
        type Make = fn(&str, &str) -> RuleDto;
        let cases: [(Make, &str, &str, bool); 9] = [
            (suffix, "Example.COM.", "example.com", true),
            (suffix, " *.example.com ", "example.com", true),
            (suffix, ".example.com", "example.com", true),
            (suffix, "*.*.example.com", "example.com", false),
            (suffix, "..example.com", "example.com", false),
            (
                suffix,
                "\u{041F}\u{0420}.example",
                "\u{043F}\u{0440}.example",
                true,
            ),
            (exact, "API.Example.com.", "api.example.com", true),
            (exact, ".api.example.com", "api.example.com", false),
            (exact, "*.api.example.com", "api.example.com", false),
        ];
        for (make, a, b, same) in cases {
            let folded = |value: &str| {
                let mut dto = book(vec![], vec![make("r", value)]);
                crate::rules_json::fold_for_comparison(&mut dto);
                dto
            };
            assert_eq!(folded(a) == folded(b), same, "drift hash: {a} / {b}");

            let across = book(vec![make("r-1", a)], vec![make("r-2", b)]);
            let duplicate = find_route_overlaps(&across, false)
                .iter()
                .any(|o| o.kind == RouteOverlapKind::Duplicate);
            assert_eq!(duplicate, same, "route pass: {a} / {b}");

            let within = book(vec![], vec![suffix("r-1", a), exact("r-2", b)]);
            let names_b = folded_rule_name(&AddressMatchDto::ExactFqdn {
                value: b.to_string(),
            });
            let names_a = folded_rule_name(&AddressMatchDto::SuffixDomain {
                suffix: a.to_string(),
            });
            assert_eq!(
                !find_overlaps(&within).is_empty(),
                names_a == names_b,
                "same-route pass: {a} / {b}"
            );
        }
    }

    #[test]
    fn an_empty_name_pairs_with_nothing() {
        let dto = book(
            vec![],
            vec![suffix("r-1", "*."), exact("r-2", "example.com")],
        );
        assert!(find_overlaps(&dto).is_empty());
    }

    #[test]
    fn output_order_is_deterministic() {
        let dto = book(
            vec![],
            vec![
                suffix("r-1", "b.com"),
                exact("r-2", "x.b.com"),
                suffix("r-3", "a.com"),
                exact("r-4", "y.a.com"),
                exact("r-5", "a.a.com"),
            ],
        );
        let apexes: Vec<String> = find_overlaps(&dto)
            .iter()
            .map(|p| format!("{}/{}", p.apex, p.covered_host))
            .collect();
        assert_eq!(
            apexes,
            vec!["a.com/a.a.com", "a.com/y.a.com", "b.com/x.b.com"]
        );
    }
}

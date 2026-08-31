//! Overlapping-rule detection over the canonical rules-json DTO.
//!
//! A `SuffixDomain` rule covers the apex itself and every subdomain of it
//! (see `nrr_domain::decision_rules_matching`), so an `ExactFqdn` rule under
//! the same apex is usually a leftover the user forgot about. It is not always
//! redundant, though: the engine evaluates `ExactFqdn` first, so an exact rule
//! in the OTHER route set — or with a different action — is the user
//! deliberately carving one host out of a wildcard.
//!
//! [`find_overlaps`] reports both, split by [`OverlapPair::redundant`]: the
//! cleanup UI offers the redundant ones for removal and leaves the deliberate
//! ones alone. The decision lives here rather than in QML so the rule that
//! decides "safe to delete" is one testable function, shared by every surface.
//!
//! The risk-scoring counterpart in `nrr_domain::review` answers a different
//! question — "does THIS change create an overlap" — and is scoped to a diff.

use serde::{Deserialize, Serialize};

use crate::rules_json::{AddressMatchDto, CanonicalRulesJsonV1, RuleAction, RuleDto};

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

/// Every exact rule covered by a suffix rule, in a deterministic order
/// (by apex, then by covered host).
///
/// Both routes are scanned as one set: a wildcard in one route covering an
/// exact rule in the other is exactly the case the user must SEE, because it
/// is the one that changes where traffic goes.
pub fn find_overlaps(dto: &CanonicalRulesJsonV1) -> Vec<OverlapPair> {
    let suffixes: Vec<(&RuleDto, &str, &str)> = collect(dto, |m| match m {
        AddressMatchDto::SuffixDomain { suffix } => Some(suffix.as_str()),
        _ => None,
    });
    let exacts: Vec<(&RuleDto, &str, &str)> = collect(dto, |m| match m {
        AddressMatchDto::ExactFqdn { value } => Some(value.as_str()),
        _ => None,
    });

    let mut out: Vec<OverlapPair> = Vec::new();
    for (apex_rule, apex_route, apex) in &suffixes {
        let dotted = format!(".{apex}");
        for (covered_rule, covered_route, host) in &exacts {
            if host != apex && !host.ends_with(&dotted) {
                continue;
            }
            // An app filter narrows a rule to one process, so the two never
            // describe the same traffic and neither one is spare.
            let same_app = apex_rule.app_match == covered_rule.app_match;
            out.push(OverlapPair {
                apex: (*apex).to_string(),
                apex_route: (*apex_route).to_string(),
                apex_rule_id: apex_rule.id.clone(),
                covered_host: (*host).to_string(),
                covered_route: (*covered_route).to_string(),
                covered_rule_id: covered_rule.id.clone(),
                redundant: same_app
                    && apex_route == covered_route
                    && action_of(apex_rule) == action_of(covered_rule)
                    && apex_rule.enabled
                    && covered_rule.enabled,
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

fn action_of(rule: &RuleDto) -> RuleAction {
    rule.action
}

/// Rules of one address kind across both routes, each paired with its route
/// slug and the matched value.
fn collect<'a, F>(dto: &'a CanonicalRulesJsonV1, pick: F) -> Vec<(&'a RuleDto, &'a str, &'a str)>
where
    F: Fn(&'a AddressMatchDto) -> Option<&'a str>,
{
    let mut out = Vec::new();
    for (route, rules) in [("primary", &dto.primary), ("secondary", &dto.secondary)] {
        for rule in rules {
            let Some(address) = rule.address_match.as_ref() else {
                continue;
            };
            if let Some(value) = pick(address) {
                out.push((rule, route, value));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_json::RULES_JSON_SCHEMA_VERSION;

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
            vec![suffix("r-1", "habr.com"), exact("r-2", "habr.com")],
        );
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].covered_rule_id, "r-2");
        assert_eq!(found[0].apex, "habr.com");
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
    fn an_exact_rule_in_the_other_route_is_a_deliberate_carve_out() {
        let dto = book(
            vec![exact("r-2", "api.example.com")],
            vec![suffix("r-1", "example.com")],
        );
        let found = find_overlaps(&dto);
        assert_eq!(found.len(), 1);
        assert!(!found[0].redundant, "a cross-route pair changes routing");
        assert_eq!(found[0].apex_route, "secondary");
        assert_eq!(found[0].covered_route, "primary");
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

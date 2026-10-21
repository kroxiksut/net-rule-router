//! Application groups and virtual machines put on a route: which application
//! rules go, which change and which are added.
//!
//! Port of `planAppRouteAssignments` in `pure.js`. Primary is the default
//! route, so it creates no rule and removes every application rule whose
//! pattern covers the program. Secondary retargets the rule that names the
//! program (an exact spelling beats a pattern that merely covers it) and
//! enables it when it was off; a new rule is added only when none covers it.
//! [`group_route`] reads the route a group has now.

use nrr_shared::glob::{fold_str, glob_match};

/// An application rule of the open rule set.
#[derive(Clone, Copy, Debug)]
pub struct AppRule<'a> {
    pub value: &'a str,
    pub route: &'a str,
    pub enabled: bool,
}

/// One program and the route it should take: `primary` or `secondary`.
#[derive(Clone, Copy, Debug)]
pub struct Assignment<'a> {
    pub value: &'a str,
    pub route: &'a str,
}

/// What to do to the rule set. Indexes point into the rules passed in.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AppRoutePlan {
    /// Rules to delete, ascending.
    pub remove: Vec<usize>,
    /// Rules to set to `secondary` and enable, in the order first needed.
    pub retarget: Vec<usize>,
    /// Match values of new `secondary` rules, in order.
    pub add: Vec<String>,
}

struct Entry<'a> {
    /// `None` for a rule this plan adds.
    index: Option<usize>,
    value: &'a str,
    ready: bool,
}

/// Plans `assignments` over `rules`. The caller applies the limit on rule
/// count to `add`.
#[must_use]
pub fn plan_app_route_assignments(
    rules: &[AppRule<'_>],
    assignments: &[Assignment<'_>],
) -> AppRoutePlan {
    let mut plan = AppRoutePlan::default();
    let mut removed = vec![false; rules.len()];
    for a in assignments
        .iter()
        .filter(|a| a.route == "primary" && !a.value.is_empty())
    {
        for (i, rule) in rules.iter().enumerate() {
            if !removed[i] && glob_match(rule.value, a.value) {
                removed[i] = true;
            }
        }
    }
    plan.remove = (0..rules.len()).filter(|&i| removed[i]).collect();

    let mut entries: Vec<Entry<'_>> = rules
        .iter()
        .enumerate()
        .filter(|(i, _)| !removed[*i])
        .map(|(i, r)| Entry {
            index: Some(i),
            value: r.value,
            ready: r.route == "secondary" && r.enabled,
        })
        .collect();
    for a in assignments
        .iter()
        .filter(|a| a.route == "secondary" && !a.value.is_empty())
    {
        let wanted = fold_str(a.value);
        let mut found = None;
        for (k, e) in entries.iter().enumerate() {
            if fold_str(e.value) == wanted {
                found = Some(k);
                break;
            }
            if found.is_none() && glob_match(e.value, a.value) {
                found = Some(k);
            }
        }
        match found {
            Some(k) => {
                let e = &mut entries[k];
                if !e.ready {
                    e.ready = true;
                    if let Some(i) = e.index {
                        plan.retarget.push(i);
                    }
                }
            }
            None => {
                plan.add.push(a.value.to_owned());
                entries.push(Entry {
                    index: None,
                    value: a.value,
                    ready: true,
                });
            }
        }
    }
    plan
}

/// The route the enabled application rules give `program`: the first rule
/// that covers it decides, `primary` when none does.
#[must_use]
pub fn app_route_of<'a>(rules: &[AppRule<'a>], program: &str) -> &'a str {
    rules
        .iter()
        .find(|rule| rule.enabled && glob_match(rule.value, program))
        .map_or("primary", |rule| rule.route)
}

/// The route of a group of programs: the one they all have, `mixed` when
/// they differ, `primary` for a group with no program.
#[must_use]
pub fn group_route<'a>(rules: &[AppRule<'a>], programs: &[&str]) -> &'a str {
    let mut routes = programs.iter().map(|p| app_route_of(rules, p));
    let Some(first) = routes.next() else {
        return "primary";
    };
    if routes.all(|route| route == first) {
        first
    } else {
        "mixed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule<'a>(value: &'a str, route: &'a str, enabled: bool) -> AppRule<'a> {
        AppRule {
            value,
            route,
            enabled,
        }
    }

    fn go(route: &'static str, value: &'static str) -> Assignment<'static> {
        Assignment { value, route }
    }

    #[test]
    fn primary_removes_every_rule_that_covers_the_program() {
        let rules = [
            rule("vbox*.exe", "secondary", true),
            rule("other.exe", "secondary", true),
            rule("VBoxHeadless.exe", "block", false),
        ];
        let plan = plan_app_route_assignments(&rules, &[go("primary", "vboxheadless.exe")]);
        assert_eq!(plan.remove, vec![0, 2]);
        assert!(plan.retarget.is_empty() && plan.add.is_empty());
    }

    #[test]
    fn secondary_prefers_the_exact_spelling_over_a_covering_pattern() {
        let rules = [
            rule("vbox*.exe", "primary", true),
            rule("VBoxHeadless.EXE", "primary", true),
        ];
        let plan = plan_app_route_assignments(&rules, &[go("secondary", "vboxheadless.exe")]);
        assert_eq!(plan.retarget, vec![1]);
        assert!(plan.add.is_empty());
    }

    #[test]
    fn secondary_enables_a_disabled_rule_already_on_secondary() {
        let rules = [rule("a.exe", "secondary", false)];
        let plan = plan_app_route_assignments(&rules, &[go("secondary", "a.exe")]);
        assert_eq!(plan.retarget, vec![0]);
    }

    #[test]
    fn a_rule_already_in_place_is_left_alone() {
        let rules = [rule("a.exe", "secondary", true)];
        let plan = plan_app_route_assignments(&rules, &[go("secondary", "A.EXE")]);
        assert_eq!(plan, AppRoutePlan::default());
    }

    #[test]
    fn a_group_has_the_route_its_programs_share_or_is_mixed() {
        let rules = [
            rule("vbox*.exe", "secondary", true),
            rule("off.exe", "secondary", false),
        ];
        assert_eq!(group_route(&rules, &["VBoxHeadless.exe"]), "secondary");
        assert_eq!(group_route(&rules, &["off.exe"]), "primary");
        assert_eq!(group_route(&rules, &["vboxsvc.exe", "other.exe"]), "mixed");
        assert_eq!(group_route(&rules, &[]), "primary");
    }

    #[test]
    fn a_missing_program_is_added_once() {
        let plan =
            plan_app_route_assignments(&[], &[go("secondary", "a.exe"), go("secondary", "A.exe")]);
        assert_eq!(plan.add, vec!["a.exe".to_owned()]);
    }
}

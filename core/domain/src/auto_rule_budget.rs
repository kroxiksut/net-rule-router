//! How many rules the app may keep for the user, and which ones go first.
//!
//! App-authored rules do not spend the user's allowance
//! (`nrr_shared::rules_json::user_rule_count`), which leaves them needing a
//! ceiling of their own — an unbounded set still becomes routes and filters,
//! and "it grew until something broke" is not a limit.
//!
//! Eviction is self-healing rather than lossy: the companion engine re-proposes
//! whatever a routed site still needs, so dropping the oldest either drops
//! something the user stopped visiting, or costs one re-offer.
//!
//! Pure: no clock, no I/O. The caller decides when to apply the verdict.

use crate::canonical::{CanonicalRule, CanonicalRuleBook};
use crate::{RuleId, RuleOrigin};

/// Ceiling on app-authored rules across both routes.
///
/// Sized from observation: one browsing session's acceptance run produced ~100
/// companions, so this holds months of ordinary use while staying far below a
/// set size that would show up in enforcement.
pub const MAX_AUTO_RULES: usize = 2_000;

/// Ids of the app-authored rules to drop so `book` fits `budget`, oldest first.
///
/// Empty when the book is within budget. Only rules the app authored are
/// candidates — the user's own rules are never evicted to make room for
/// suggestions.
///
/// Order is total and stable: by the `added` date (`YYYY-MM-DD`, so a string
/// compare is chronological), then by position, so two runs over the same book
/// evict exactly the same rules.
pub fn auto_rules_over_budget(book: &CanonicalRuleBook, budget: usize) -> Vec<RuleId> {
    let mut authored: Vec<(&str, usize, &RuleId)> = book
        .primary
        .rules()
        .iter()
        .chain(book.secondary.rules().iter())
        .enumerate()
        .filter_map(|(seq, rule)| added_date(rule).map(|added| (added, seq, &rule.id)))
        .collect();
    let over = authored.len().saturating_sub(budget);
    if over == 0 {
        return Vec::new();
    }
    authored.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(&b.1)));
    authored
        .into_iter()
        .take(over)
        .map(|(_, _, id)| id.clone())
        .collect()
}

/// The date an app-authored rule was added; `None` for a user's own rule.
fn added_date(rule: &CanonicalRule) -> Option<&str> {
    match rule.origin.as_ref()? {
        RuleOrigin::Auto { added, .. } => Some(added.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{CanonicalAddressMatch, CanonicalRuleSet};
    use crate::AutoRuleReason;
    use crate::RuleAction;

    fn user_rule(id: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(format!("{id}.test"))),
            app_match: None,
            comment: String::new(),
            action: RuleAction::Route,
            origin: None,
        }
    }

    fn authored(id: &str, added: &str) -> CanonicalRule {
        CanonicalRule {
            origin: Some(RuleOrigin::auto(
                AutoRuleReason::SiteCompanion,
                "site.example",
                added,
            )),
            ..user_rule(id)
        }
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    #[test]
    fn a_book_within_budget_evicts_nothing() {
        let b = book(vec![authored("a1", "2026-01-01")], vec![user_rule("u1")]);
        assert!(auto_rules_over_budget(&b, 2).is_empty());
        assert!(auto_rules_over_budget(&b, 1).is_empty());
    }

    #[test]
    fn the_oldest_authored_rules_go_first() {
        let b = book(
            vec![
                authored("new", "2026-08-04"),
                authored("old", "2026-01-01"),
                authored("mid", "2026-05-05"),
            ],
            vec![],
        );
        assert_eq!(
            auto_rules_over_budget(&b, 1),
            vec![RuleId("old".into()), RuleId("mid".into())]
        );
    }

    #[test]
    fn the_users_own_rules_are_never_evicted() {
        let b = book(
            vec![user_rule("u1"), user_rule("u2"), user_rule("u3")],
            vec![authored("a1", "2026-01-01")],
        );
        // Budget 0: everything the app authored goes, nothing else does.
        assert_eq!(auto_rules_over_budget(&b, 0), vec![RuleId("a1".into())]);
    }

    #[test]
    fn rules_added_the_same_day_evict_in_a_stable_order() {
        let b = book(
            vec![
                authored("first", "2026-08-04"),
                authored("second", "2026-08-04"),
            ],
            vec![authored("third", "2026-08-04")],
        );
        let once = auto_rules_over_budget(&b, 1);
        assert_eq!(
            once,
            vec![RuleId("first".into()), RuleId("second".into())],
            "position breaks the tie, and both routes are one sequence"
        );
        assert_eq!(once, auto_rules_over_budget(&b, 1), "and it does not vary");
    }
}

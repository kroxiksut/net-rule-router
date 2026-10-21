//! Programs put on a route as application rules, from the Application routes
//! screen: the GUI's `_applyAppGroupRoutes`. The decision (which rules go,
//! switch or appear) is `nrr_client_logic::app_routes`; this carries it out on
//! the working copy, which is reviewed and applied like any other edit.

use nrr_client_logic::app_routes::{plan_app_route_assignments, AppRule, Assignment};
use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
use nrr_shared::rules_json::FREE_MAX_RULES;

use super::table::{Row, Verdict};
use crate::state::AppState;

/// How an assignment ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assigned {
    Changed,
    /// The rules already were as asked.
    Unchanged,
    /// Some programs could not be added: the free rules limit is reached.
    Limit,
}

/// The application rules of the working copy that `programs` should follow
/// `route` (`primary` or `secondary`) in. `comment` is the note a new rule
/// gets.
pub fn assign(app: &mut AppState, programs: &[String], route: &str, comment: &str) -> Assigned {
    let table = &mut app.rules.table;
    let (at, slugs): (Vec<usize>, Vec<String>) = table
        .rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.rule.rule_type == RuleType::Application)
        .map(|(i, row)| (i, row.rule.target_route.as_str().to_owned()))
        .unzip();
    let rules: Vec<AppRule<'_>> = at
        .iter()
        .zip(&slugs)
        .map(|(&i, slug)| AppRule {
            value: &table.rows[i].rule.match_value,
            route: slug,
            enabled: table.rows[i].rule.enabled,
        })
        .collect();
    let assignments: Vec<Assignment<'_>> = programs
        .iter()
        .map(|value| Assignment { value, route })
        .collect();
    let plan = plan_app_route_assignments(&rules, &assignments);
    drop(rules);

    let mut changed = false;
    for &k in &plan.retarget {
        let row = &mut table.rows[at[k]];
        row.rule.target_route = TargetRoute::Secondary;
        row.rule.enabled = true;
        row.verdict = Verdict::for_route(
            &row.rule.rule_type,
            &row.rule.match_value,
            &row.rule.target_route,
        );
        changed = true;
    }
    // Highest first, so an earlier removal shifts no later one.
    for &k in plan.remove.iter().rev() {
        table.rows.remove(at[k]);
        changed = true;
    }
    let mut limit = false;
    for value in plan.add {
        if table.user_rule_count() >= FREE_MAX_RULES {
            limit = true;
            break;
        }
        let rule = RuleRow {
            id: table.next_free_id(),
            enabled: true,
            rule_type: RuleType::Application,
            match_value: value,
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: comment.to_owned(),
            origin: None,
        };
        table.rows.push(Row::new(rule));
        changed = true;
    }
    if changed {
        table.clamp_cursor();
        super::overlaps::refresh(app);
    }
    if limit {
        Assigned::Limit
    } else if changed {
        Assigned::Changed
    } else {
        Assigned::Unchanged
    }
}

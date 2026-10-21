#![allow(clippy::expect_used)]

//! App groups and virtual machines put on a route: the same plan from
//! `pure.js` and from `nrr_client_logic::app_routes`.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::app_routes::{group_route, plan_app_route_assignments, AppRule, Assignment};
use serde_json::{json, Value};

fn items<'a>(input: &'a Value, key: &str) -> &'a [Value] {
    input
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

#[test]
fn app_route_plan_matches_js() {
    check(
        "app_routes",
        &mut JsLib::pure(),
        |input| {
            format!(
                "planAppRouteAssignments({}, {})",
                arg(input, "rules"),
                arg(input, "assignments")
            )
        },
        |input| {
            let rules: Vec<AppRule<'_>> = items(input, "rules")
                .iter()
                .map(|r| AppRule {
                    value: text(r, "value"),
                    route: text(r, "route"),
                    enabled: r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                })
                .collect();
            let assignments: Vec<Assignment<'_>> = items(input, "assignments")
                .iter()
                .map(|a| Assignment {
                    value: text(a, "value"),
                    route: text(a, "route"),
                })
                .collect();
            let plan = plan_app_route_assignments(&rules, &assignments);
            json!({ "remove": plan.remove, "retarget": plan.retarget, "add": plan.add })
        },
    );
}

#[test]
fn group_route_matches_js() {
    check(
        "group_route",
        &mut JsLib::pure(),
        |input| {
            format!(
                "groupRouteOf({}, {})",
                arg(input, "rules"),
                arg(input, "programs")
            )
        },
        |input| {
            let rules: Vec<AppRule<'_>> = items(input, "rules")
                .iter()
                .map(|r| AppRule {
                    value: text(r, "value"),
                    route: text(r, "route"),
                    enabled: r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                })
                .collect();
            let programs: Vec<&str> = items(input, "programs")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            json!(group_route(&rules, &programs))
        },
    );
}

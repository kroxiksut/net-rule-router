#![allow(clippy::expect_used)]

//! "Restore my settings": what a confirmed write records, what the service
//! holds otherwise, the one write that brings it back and the mutes it lost —
//! the same answers from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, check_cases, load_vectors, Case, JsLib};
use nrr_client_logic::restore::{
    mutes_to_restore, record_route_policy, restore_plan, route_policy_divergence, RestorePlan,
};
use serde_json::{json, Map, Value};

fn object(input: &Value, key: &str) -> Map<String, Value> {
    input[key].as_object().cloned().unwrap_or_default()
}

fn strings(input: &Value, key: &str) -> Vec<String> {
    input[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn route_policy_intent_after_write_matches_js() {
    check(
        "route_policy_intent_after_write",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routePolicyIntentAfterWrite({}, {}, {})",
                arg(input, "intent"),
                arg(input, "request"),
                arg(input, "keys")
            )
        },
        |input| {
            let next = record_route_policy(
                &object(input, "intent"),
                &object(input, "request"),
                &strings(input, "keys"),
            );
            Value::Object(next)
        },
    );
}

#[test]
fn route_policy_intent_divergence_matches_js() {
    check(
        "route_policy_intent_divergence",
        &mut JsLib::pure(),
        |input| {
            format!(
                "routePolicyIntentDivergence({}, {})",
                arg(input, "intent"),
                arg(input, "service")
            )
        },
        |input| {
            let keys = route_policy_divergence(&object(input, "intent"), &object(input, "service"));
            Value::from(keys)
        },
    );
}

fn plan_of(input: &Value) -> RestorePlan {
    let present = strings(input, "present");
    let present: Vec<&str> = present.iter().map(String::as_str).collect();
    restore_plan(
        &object(input, "intent"),
        &object(input, "service"),
        &present,
    )
}

fn plan_js(input: &Value) -> String {
    format!(
        "routePolicyRestorePlan({}, {}, {})",
        arg(input, "intent"),
        arg(input, "service"),
        arg(input, "present")
    )
}

/// What the vectors spell out: the keys, the missing adapters and the values
/// the request carries for the keys it restores.
#[test]
fn route_policy_restore_plan_matches_js() {
    check(
        "route_policy_restore_plan",
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (p) {{ var v = null; if (p.request) {{ v = {{}}; \
                 for (var i = 0; i < p.keys.length; i += 1) v[p.keys[i]] = p.request[p.keys[i]] }} \
                 return {{ keys: p.keys, missing: p.missing, values: v, \
                 applyOnly: p.request ? p.request[\"apply-only\"] : null }} }})({})",
                plan_js(input)
            )
        },
        |input| {
            let plan = plan_of(input);
            let missing: Vec<Value> = plan
                .missing
                .iter()
                .map(|m| json!({ "role": m.role, "name": m.name }))
                .collect();
            let values = plan.request.as_ref().map(|request| {
                let picked: Map<String, Value> = plan
                    .keys
                    .iter()
                    .filter_map(|key| request.get(key).map(|v| (key.clone(), v.clone())))
                    .collect();
                Value::Object(picked)
            });
            let apply_only = plan
                .request
                .as_ref()
                .and_then(|request| request.get("apply-only").cloned());
            json!({
                "keys": plan.keys,
                "missing": missing,
                "values": values,
                "applyOnly": apply_only,
            })
        },
    );
}

/// The whole request, field for field: the row it is built on travels too.
#[test]
fn route_policy_restore_request_matches_js_whole() {
    let (_, cases) = load_vectors("route_policy_restore_plan");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            expected: None,
            ..case
        })
        .collect();
    check_cases(
        "route_policy_restore_plan",
        &cases,
        &mut JsLib::pure(),
        |input| format!("{}.request", plan_js(input)),
        |input| plan_of(input).request.map_or(Value::Null, Value::Object),
    );
}

#[test]
fn notice_mutes_to_restore_matches_js() {
    check(
        "notice_mutes_to_restore",
        &mut JsLib::pure(),
        |input| {
            format!(
                "noticeMutesToRestore({}, {}, {})",
                arg(input, "intent"),
                arg(input, "service"),
                arg(input, "now")
            )
        },
        |input| {
            let now = input["now"].as_i64().expect("now");
            Value::from(mutes_to_restore(&input["intent"], &input["service"], now))
        },
    );
}

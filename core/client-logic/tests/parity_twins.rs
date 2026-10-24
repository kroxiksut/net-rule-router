#![allow(clippy::expect_used)]

//! Twins that had no vector of their own: the leak-protection settle every
//! policy write passes through, the IPv6-literal test behind the `?` marker,
//! the rule-set folder containment and the overlaps one rule takes part in.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, check_cases, load_vectors, merged, text, Case, JsLib};
use nrr_client_logic::route_policy;
use nrr_client_logic::rule_sets::is_path_under_dir;
use nrr_client_logic::rules_overlaps::overlaps_of_rule;
use nrr_client_logic::rules_table::{value_is_ipv6_literal, RuleType};
use nrr_shared::rules_overlap::RouteOverlap;
use serde_json::{json, Value};

#[test]
fn settle_leak_protection_matches_js() {
    check(
        "settle_leak_protection",
        &mut JsLib::pure(),
        |input| format!("settleLeakProtection({})", arg(input, "request")),
        |input| {
            let mut request = input["request"].as_object().cloned().unwrap_or_default();
            route_policy::settle_leak_protection(&mut request);
            Value::Object(request)
        },
    );
}

#[test]
fn value_is_ipv6_literal_matches_js() {
    check(
        "value_is_ipv6_literal",
        &mut JsLib::rules(),
        |input| {
            format!(
                "valueIsIpv6Literal({}, {})",
                arg(input, "ruleType"),
                arg(input, "value")
            )
        },
        |input| {
            Value::from(value_is_ipv6_literal(
                &RuleType::from_slug(text(input, "ruleType")),
                text(input, "value"),
            ))
        },
    );
}

#[test]
fn is_path_under_dir_matches_js() {
    check(
        "is_path_under_dir",
        &mut JsLib::pure(),
        |input| {
            format!(
                "isPathUnderDir({}, {})",
                arg(input, "path"),
                arg(input, "dir")
            )
        },
        |input| Value::from(is_path_under_dir(text(input, "path"), text(input, "dir"))),
    );
}

#[test]
fn overlaps_of_rule_matches_js() {
    let (document, cases) = load_vectors("overlaps_of_rule");
    let shared = json!({ "overlaps": document["overlaps"].clone() });
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            input: merged(&shared, &case.input),
            ..case
        })
        .collect();
    // Compared by key: the JS hands back its own objects, Rust borrowed ones.
    check_cases(
        "overlaps_of_rule",
        &cases,
        &mut JsLib::rules(),
        |input| {
            format!(
                "overlapsOfRule({}, {}).map(function (o) {{ return o.key }})",
                arg(input, "overlaps"),
                arg(input, "id")
            )
        },
        |input| {
            let overlaps: Vec<RouteOverlap> =
                serde_json::from_value(input["overlaps"].clone()).expect("overlaps decode");
            let keys: Vec<&str> = overlaps_of_rule(&overlaps, text(input, "id"))
                .map(|o| o.key.as_str())
                .collect();
            json!(keys)
        },
    );
}

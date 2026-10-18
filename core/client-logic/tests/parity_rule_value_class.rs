#![allow(clippy::expect_used)]

//! What kind of rule a value is, and the section a misplaced one belongs in —
//! the same answer from `rules.js` and from `nrr_shared::rule_value_class`,
//! which the service's validation reads.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::rule_value_class::{
    app_value_form, classify_rule_value, misplaced_rule_type, misplaced_target_type,
    rule_value_max_length,
};
use serde_json::Value;

#[test]
fn rule_value_class_matches_js() {
    check(
        "rule_value_class",
        &mut JsLib::rules(),
        |input| format!("ruleValueClass({})", arg(input, "value")),
        |input| Value::from(classify_rule_value(text(input, "value")).as_str()),
    );
}

#[test]
fn misplaced_rule_type_matches_js() {
    check(
        "misplaced_rule_type",
        &mut JsLib::rules(),
        |input| {
            format!(
                "misplacedRuleType({}, {}, {})",
                arg(input, "type"),
                arg(input, "value"),
                arg(input, "os")
            )
        },
        |input| {
            Value::from(
                misplaced_rule_type(text(input, "type"), text(input, "value"), text(input, "os"))
                    .unwrap_or(""),
            )
        },
    );
}

#[test]
fn misplaced_target_type_matches_js() {
    check(
        "misplaced_target_type",
        &mut JsLib::rules(),
        |input| format!("misplacedTargetType({})", arg(input, "key")),
        |input| Value::from(misplaced_target_type(text(input, "key")).unwrap_or("")),
    );
}

#[test]
fn app_value_form_matches_js() {
    check(
        "app_value_form",
        &mut JsLib::rules(),
        |input| {
            format!(
                "appValueForm({}, {})",
                arg(input, "value"),
                arg(input, "os")
            )
        },
        |input| Value::from(app_value_form(text(input, "value"), text(input, "os"))),
    );
}

#[test]
fn rule_value_max_length_matches_js() {
    check(
        "rule_value_max_length",
        &mut JsLib::rules(),
        |input| format!("ruleValueMaxLength({})", arg(input, "type")),
        |input| Value::from(rule_value_max_length(text(input, "type"))),
    );
}

/// The JS bounds are the shared constants, not copies that may drift.
#[test]
fn the_js_value_bounds_are_the_shared_ones() {
    let mut js = JsLib::rules();
    assert_eq!(
        js.eval_json("PATH_VALUE_MAX_BYTES"),
        Value::from(nrr_shared::app_path::MAX_PATH_VALUE_BYTES)
    );
    assert_eq!(
        js.eval_json("RULE_VALUE_MAX_BYTES"),
        Value::from(nrr_shared::rule_value_class::MAX_RULE_VALUE_BYTES)
    );
}

#![allow(clippy::expect_used)]

//! The «Recent» filter of the rules list — the same periods and the same
//! times from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::recent_changes::{
    recent_change_stamp, recent_change_time, recent_period_since, RecentPeriod,
};
use serde_json::Value;

fn number(input: &Value, key: &str) -> i64 {
    input.get(key).and_then(Value::as_i64).unwrap_or(0)
}

#[test]
fn recent_change_time_matches_js() {
    check(
        "recent_change_time",
        &mut JsLib::pure(),
        |input| {
            format!(
                "recentChangeTime({}, {}, {}, {}, {})",
                arg(input, "at"),
                arg(input, "at-offset"),
                arg(input, "now"),
                arg(input, "now-offset"),
                arg(input, "yesterday")
            )
        },
        |input| {
            Value::from(recent_change_time(
                number(input, "at"),
                number(input, "at-offset"),
                number(input, "now"),
                number(input, "now-offset"),
                text(input, "yesterday"),
            ))
        },
    );
}

#[test]
fn recent_change_stamp_matches_js() {
    check(
        "recent_change_stamp",
        &mut JsLib::pure(),
        |input| {
            format!(
                "recentChangeStamp({}, {})",
                arg(input, "at"),
                arg(input, "offset")
            )
        },
        |input| {
            Value::from(recent_change_stamp(
                number(input, "at"),
                number(input, "offset"),
            ))
        },
    );
}

#[test]
fn recent_period_since_matches_js() {
    check(
        "recent_period_since",
        &mut JsLib::pure(),
        |input| {
            format!(
                "recentPeriodSince({}, {}, {})",
                arg(input, "period"),
                arg(input, "now"),
                arg(input, "offset")
            )
        },
        |input| {
            let period = RecentPeriod::from_slug(text(input, "period")).unwrap_or_default();
            Value::from(recent_period_since(
                period,
                number(input, "now"),
                number(input, "offset"),
            ))
        },
    );
}

#[test]
fn rule_value_key_matches_js() {
    check(
        "rule_value_key",
        &mut JsLib::rules(),
        |input| format!("ruleValueKey({})", input),
        |input| {
            let row = nrr_client_logic::rules_table::RuleRow {
                id: String::new(),
                enabled: true,
                rule_type: nrr_client_logic::rules_table::RuleType::from_slug(text(
                    input, "ruleType",
                )),
                match_value: text(input, "matchValue").to_owned(),
                target_route: nrr_client_logic::rules_table::TargetRoute::Primary,
                verify: false,
                comment: String::new(),
                origin: None,
            };
            Value::from(row.value_key())
        },
    );
}

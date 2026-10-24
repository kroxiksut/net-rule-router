#![allow(clippy::expect_used)]

//! The tray's "add rule" (`planRuleAddition` in `rules.js`) treats a program
//! with `+override` or `+children` as the program it names. Keyed with the
//! flag, `Telegram.exe +override` next to an existing `Telegram.exe` was a new
//! rule: two lines for one program, and the service's duplicate removal kept
//! the plain one, so the request vanished.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;

fn plan(existing_route: &str, value: &str, route: &str) -> serde_json::Value {
    let mut rules = JsLib::rules();
    rules.eval_json(&format!(
        "planRuleAddition([{{ ruleType: 'application', matchValue: 'Telegram.exe', \
         targetRoute: '{existing_route}' }}], [{{ ruleType: 'application', matchValue: '{value}', \
         targetRoute: '{route}' }}], false)"
    ))
}

#[test]
fn an_override_on_the_same_route_is_the_rule_already_there() {
    let out = plan("secondary", "Telegram.exe +override", "secondary");
    assert_eq!(out["added"], 0, "{out}");
    assert_eq!(out["duplicates"].as_array().map(Vec::len), Some(1), "{out}");
}

#[test]
fn an_override_on_another_route_is_the_same_program_elsewhere() {
    let out = plan("secondary", "Telegram.exe +override", "primary");
    assert_eq!(out["added"], 0, "{out}");
    assert_eq!(out["elsewhere"].as_array().map(Vec::len), Some(1), "{out}");
}

#[test]
fn children_on_the_same_route_is_the_rule_already_there() {
    let out = plan("secondary", "telegram.exe +children", "secondary");
    assert_eq!(out["added"], 0, "{out}");
    assert_eq!(out["duplicates"].as_array().map(Vec::len), Some(1), "{out}");
}

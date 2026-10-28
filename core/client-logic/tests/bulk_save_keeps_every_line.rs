#![allow(clippy::expect_used)]

//! "Several rules" is planned while the user types, against the rules of that
//! moment; the rules may change before Save (the tray's form re-reads them from
//! the service on Save, and another client may have written in between). What
//! is saved is planned again against the rules at Save (`planBulkSubmission`
//! in `rules.js`), so every line is either applied, already there, or back in
//! the field with the form's own explanation. Planned against the old rules, a
//! line whose value had meanwhile appeared on another route was neither added
//! nor given back.

#[allow(dead_code)]
mod js_harness;

use js_harness::{lit, JsLib};
use serde_json::{json, Value};

fn row(value: &str, route: &str) -> Value {
    json!({ "ruleType": "domain", "matchValue": value, "targetRoute": route,
            "enabled": true, "verify": false, "comment": "" })
}

/// The form's input for `text` on the primary route, every value judged valid.
fn input(text: &str, choices: Value) -> Value {
    let verdicts: serde_json::Map<String, Value> = text
        .lines()
        .map(|v| (format!("domain|{v}"), json!({ "status": "valid" })))
        .collect();
    json!({ "text": text, "route": "primary", "os": "windows", "apps": true,
            "choices": choices, "verdicts": verdicts, "room": -1 })
}

fn save(rules: &mut JsLib, input: &Value, rows_at_save: &Value) -> Value {
    rules.eval_json(&format!(
        "planBulkSubmission({}, {})",
        lit(input),
        lit(rows_at_save)
    ))
}

fn values_with(plan: &Value, action: &str) -> Vec<String> {
    plan["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|r| r["action"] == action)
        .map(|r| r["value"].as_str().unwrap_or_default().to_owned())
        .collect()
}

#[test]
fn a_value_that_appeared_on_another_route_comes_back_into_the_field() {
    let mut rules = JsLib::rules();
    let typed = input("x.example\ny.example", json!({}));
    // Planned while typing: nothing stood in the way.
    let typing = rules.eval_json(&format!("planBulkRules({})", lit(&typed)));
    assert_eq!(values_with(&typing, "add"), ["x.example", "y.example"]);

    let plan = save(&mut rules, &typed, &json!([row("x.example", "secondary")]));
    assert_eq!(values_with(&plan, "add"), ["y.example"], "{plan}");
    assert_eq!(plan["remaining"], "x.example", "{plan}");
    let kept = &plan["rows"][0];
    assert_eq!(
        kept["key"], "rules.paste.on-other-route",
        "the form's own reason"
    );
}

#[test]
fn a_move_whose_rule_has_gone_is_added() {
    let mut rules = JsLib::rules();
    let typed = input("z.example", json!({ "1": { "move": true } }));
    let typing = rules.eval_json(&format!(
        "planBulkRules({})",
        lit(&json!({ "text": typed["text"], "route": "primary", "os": "windows",
                     "choices": typed["choices"], "verdicts": typed["verdicts"],
                     "existing": [{ "type": "domain", "value": "z.example", "route": "secondary" }] }))
    ));
    assert_eq!(values_with(&typing, "move"), ["z.example"]);

    let plan = save(&mut rules, &typed, &json!([]));
    assert_eq!(values_with(&plan, "add"), ["z.example"], "{plan}");
    assert_eq!(plan["remaining"], "", "{plan}");
}

#[test]
fn a_rule_already_there_at_save_is_not_added_twice() {
    let mut rules = JsLib::rules();
    let typed = input("w.example\nv.example", json!({}));
    let plan = save(&mut rules, &typed, &json!([row("W.Example", "primary")]));
    assert_eq!(values_with(&plan, "add"), ["v.example"], "{plan}");
    assert_eq!(values_with(&plan, "drop"), ["w.example"], "{plan}");
    assert_eq!(plan["remaining"], "", "{plan}");
}

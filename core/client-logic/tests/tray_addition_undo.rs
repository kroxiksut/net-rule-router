#![allow(clippy::expect_used)]

//! The tray's "Add rule…" (`planRuleAddition`) and the "Undo" on its notice
//! (`additionUndoRecord`, `planAdditionUndo` in `rules.js`) each send the whole
//! rule book back to the service. Whatever they get wrong is a rule of the
//! user's lost or changed without their asking: the undo takes back exactly
//! what the add did, and when the user has touched any of it since, nothing.

#[allow(dead_code)]
mod js_harness;

use js_harness::{lit, JsLib};
use serde_json::{json, Value};

fn rule(rule_type: &str, value: &str, route: &str) -> Value {
    json!({ "ruleType": rule_type, "matchValue": value, "targetRoute": route,
            "enabled": true, "verify": false, "comment": "" })
}

/// The add as the tray makes it: the plan and the record of it.
fn add(rules: &mut JsLib, rows: &Value, items: &Value, move_elsewhere: bool) -> (Value, Value) {
    let plan = rules.eval_json(&format!(
        "planRuleAddition({}, {}, {move_elsewhere})",
        lit(rows),
        lit(items)
    ));
    let record = rules.eval_json(&format!("additionUndoRecord({})", lit(&plan)));
    (plan, record)
}

fn undo(rules: &mut JsLib, rows: &Value, record: &Value) -> Value {
    rules.eval_json(&format!("planAdditionUndo({}, {})", lit(rows), lit(record)))
}

/// The rules as they come back from the service after the add: another order.
fn reread(plan: &Value) -> Value {
    let mut rows = plan["rows"].as_array().cloned().expect("plan rows");
    rows.reverse();
    Value::Array(rows)
}

/// The add itself sends the whole book too: every rule already there goes
/// back as it was, but for the one the user chose to move.
#[test]
fn the_add_keeps_every_rule_already_there() {
    let mut rules = JsLib::rules();
    let mut off = rule("subnet", "198.51.100.0/24", "secondary");
    off["enabled"] = json!(false);
    off["comment"] = json!("lab");
    let before = json!([
        rule("domain", "first.example", "primary"),
        rule("domain", "moved.example", "primary"),
        off,
    ]);
    let items = json!([
        rule("domain", "first.example", "primary"),
        rule("domain", "moved.example", "secondary"),
        rule("domain", "new.example", "secondary"),
    ]);
    let (plan, _) = add(&mut rules, &before, &items, true);

    let mut expected = before.as_array().cloned().expect("rows");
    expected[1]["targetRoute"] = json!("secondary");
    expected.push(rule("domain", "new.example", "secondary"));
    assert_eq!(plan["rows"], Value::Array(expected), "{plan}");
}

#[test]
fn undo_removes_the_added_rule_and_keeps_every_other_rule_as_it_was() {
    let mut rules = JsLib::rules();
    let mut kept_off = rule("domain", "kept.example", "primary");
    kept_off["enabled"] = json!(false);
    kept_off["comment"] = json!("mine");
    let before = json!([kept_off, rule("application", "Telegram.exe", "secondary")]);
    let (plan, record) = add(
        &mut rules,
        &before,
        &json!([rule("domain", "new.example", "secondary")]),
        false,
    );
    let after = reread(&plan);

    let out = undo(&mut rules, &after, &record);
    assert_eq!(out["conflict"], false, "{out}");
    assert_eq!(out["removed"], 1, "{out}");
    let mut left = out["rows"].as_array().cloned().expect("rows");
    left.reverse();
    assert_eq!(
        Value::Array(left),
        before,
        "every other rule exactly as it was"
    );
}

#[test]
fn undo_puts_a_moved_rule_back_on_its_route() {
    let mut rules = JsLib::rules();
    let mut checked = rule("domain", "moved.example", "primary");
    checked["verify"] = json!(true);
    checked["comment"] = json!("work");
    let before = json!([checked, rule("domain", "other.example", "secondary")]);
    let (plan, record) = add(
        &mut rules,
        &before,
        &json!([rule("domain", "moved.example", "secondary")]),
        true,
    );
    assert_eq!(plan["changed"], 1, "{plan}");

    let out = undo(&mut rules, &plan["rows"], &record);
    assert_eq!(out["conflict"], false, "{out}");
    assert_eq!(out["restored"], 1, "{out}");
    assert_eq!(out["removed"], 0, "a moved rule is not a new one: {out}");
    assert_eq!(
        out["rows"], before,
        "back on its route, `?` and comment kept"
    );
}

#[test]
fn a_rule_changed_since_is_left_alone() {
    let mut rules = JsLib::rules();
    let before = json!([rule("domain", "moved.example", "primary")]);
    let items = json!([
        rule("domain", "new.example", "secondary"),
        rule("domain", "moved.example", "secondary"),
    ]);
    let (plan, record) = add(&mut rules, &before, &items, true);
    let after = plan["rows"].as_array().cloned().expect("rows");
    let at = |value: &str| {
        after
            .iter()
            .position(|r| r["matchValue"] == value)
            .expect("rule in the plan")
    };

    let mut switched_off = after.clone();
    switched_off[at("new.example")]["enabled"] = json!(false);
    let mut rerouted = after.clone();
    rerouted[at("new.example")]["targetRoute"] = json!("primary");
    let mut moved_again = after.clone();
    moved_again[at("moved.example")]["targetRoute"] = json!("block");
    let mut deleted = after.clone();
    deleted.remove(at("new.example"));

    for (what, rows) in [
        ("the new rule switched off", switched_off),
        ("the new rule on another route", rerouted),
        ("the moved rule moved again", moved_again),
        ("the new rule deleted", deleted),
    ] {
        let rows = Value::Array(rows);
        let out = undo(&mut rules, &rows, &record);
        assert_eq!(out["conflict"], true, "{what}: {out}");
        assert_eq!(out["rows"], rows, "{what}: nothing touched");
    }
}

#[test]
fn a_pasted_list_is_undone_whole() {
    let mut rules = JsLib::rules();
    let before = json!([rule("domain", "old.example", "primary")]);
    let items = json!([
        rule("domain", "one.example", "secondary"),
        rule("domain", "two.example", "secondary"),
        rule("subnet", "192.0.2.0/24", "secondary"),
    ]);
    let (plan, record) = add(&mut rules, &before, &items, false);

    let out = undo(&mut rules, &reread(&plan), &record);
    assert_eq!(out["removed"], 3, "{out}");
    assert_eq!(out["rows"], before, "{out}");
}

/// The add put `site.example` in as a domain; an exact name of the same
/// spelling, the user's own, stands first in the list on the same route.
#[test]
fn a_rule_the_add_did_not_make_is_never_removed() {
    let mut rules = JsLib::rules();
    let own = rule("exact-fqdn", "site.example", "secondary");
    let before = json!([own, rule("application", "Site.example", "secondary")]);
    let (plan, record) = add(
        &mut rules,
        &before,
        &json!([rule("domain", "Site.Example", "secondary")]),
        false,
    );
    assert_eq!(plan["added"], 1, "{plan}");

    let out = undo(&mut rules, &plan["rows"], &record);
    assert_eq!(out["removed"], 1, "{out}");
    assert_eq!(out["rows"], before, "only the rule the add made left");
}

/// Comments are kept per route: the add wrote the moved rule's comment under
/// its new route, and the window's sweep may since have dropped the one under
/// the old route. Undo writes it back there.
#[test]
fn undo_gives_a_moved_rule_its_comment_back_under_the_old_route() {
    let mut rules = JsLib::rules();
    let mut noted = rule("domain", "moved.example", "primary");
    noted["comment"] = json!("work laptop");
    let before = json!([noted, rule("domain", "bare.example", "primary")]);
    let (plan, record) = add(
        &mut rules,
        &before,
        &json!([
            rule("domain", "moved.example", "secondary"),
            rule("domain", "bare.example", "secondary"),
        ]),
        true,
    );

    let out = undo(&mut rules, &plan["rows"], &record);
    assert_eq!(out["rows"], before, "{out}");
    assert_eq!(
        out["comments"],
        json!([{ "ruleType": "domain", "matchValue": "moved.example",
                 "targetRoute": "primary", "comment": "work laptop" }]),
        "only a comment there was, so nothing is cleared: {out}"
    );
}

/// A comment the user wrote or changed after the add is their change too: the
/// undo leaves the rule, its comment and everything else alone.
#[test]
fn a_comment_changed_since_leaves_everything_alone() {
    let mut rules = JsLib::rules();
    let mut noted = rule("domain", "moved.example", "primary");
    noted["comment"] = json!("work laptop");
    let before = json!([noted]);
    let (plan, record) = add(
        &mut rules,
        &before,
        &json!([
            rule("domain", "moved.example", "secondary"),
            rule("domain", "new.example", "secondary"),
        ]),
        true,
    );
    let after = plan["rows"].as_array().cloned().expect("rows");
    for (at, what) in [
        (0, "the moved rule's comment"),
        (1, "the new rule's comment"),
    ] {
        let mut rows = after.clone();
        rows[at]["comment"] = json!("mine now");
        let rows = Value::Array(rows);
        let out = undo(&mut rules, &rows, &record);
        assert_eq!(out["conflict"], true, "{what} changed: {out}");
        assert_eq!(out["rows"], rows, "{what} changed: nothing touched");
        assert_eq!(
            out["comments"].as_array().map(Vec::len).unwrap_or(0),
            0,
            "{what} changed: no comment written: {out}"
        );
    }
}

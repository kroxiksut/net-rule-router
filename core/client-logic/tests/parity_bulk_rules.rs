#![allow(clippy::expect_used)]

//! Many rules pasted into the Add form: the same plan from `rules.js` and from
//! `nrr_client_logic::bulk_rules`, line for line.

#[allow(dead_code)]
mod js_harness;

use std::collections::{BTreeMap, HashMap};

use js_harness::{check_cases, lit, load_vectors, text, Case, JsLib};
use nrr_client_logic::bulk_rules::{
    plan_bulk_rules, BulkInput, BulkPlan, BulkRow, ExistingRule, LineChoice, LineVerdict,
    RowAction, VerdictLevel,
};
use serde_json::{json, Map, Value};

/// `String(x)` in JS: a string as it is, anything else as its JSON text.
fn js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn args_of(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), js_string(v))).collect())
        .unwrap_or_default()
}

/// The plan for one vector's input, through the crate.
fn rust_plan(input: &Value) -> BulkPlan {
    let existing_rows: Vec<(String, String, String)> = input
        .get("existing")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|r| {
                    (
                        text(r, "type").to_owned(),
                        text(r, "value").to_owned(),
                        text(r, "route").to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let existing: Vec<ExistingRule<'_>> = existing_rows
        .iter()
        .map(|(rule_type, value, route)| ExistingRule {
            rule_type,
            value,
            route,
        })
        .collect();
    let choices: HashMap<usize, LineChoice> = input
        .get("choices")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(line, c)| {
                    let choice = LineChoice {
                        rule_type: c.get("type").and_then(Value::as_str).map(str::to_owned),
                        move_elsewhere: c.get("move").and_then(Value::as_bool) == Some(true),
                    };
                    Some((line.parse().ok()?, choice))
                })
                .collect()
        })
        .unwrap_or_default();
    let verdicts: HashMap<String, LineVerdict> = input
        .get("verdicts")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(key, v)| {
                    let verdict = LineVerdict {
                        level: VerdictLevel::from_slug(text(v, "status")),
                        message_key: text(v, "message-key").to_owned(),
                        args: args_of(v.get("args")),
                    };
                    (key.clone(), verdict)
                })
                .collect()
        })
        .unwrap_or_default();
    plan_bulk_rules(&BulkInput {
        text: text(input, "text"),
        route: text(input, "route"),
        os: text(input, "os"),
        apps: input.get("apps").and_then(Value::as_bool) != Some(false),
        existing: &existing,
        choices: &choices,
        verdicts: &verdicts,
        room: input
            .get("room")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok()),
    })
}

fn row_json(row: &BulkRow) -> Value {
    let args: Map<String, Value> = row
        .args
        .iter()
        .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
        .collect();
    json!({
        "line": row.line,
        "text": row.text,
        "section": row.section,
        "type": row.rule_type,
        "options": row.options,
        "value": row.value,
        "enabled": row.enabled,
        "route": row.route,
        "verify": row.verify,
        "comment": row.comment,
        "status": row.status.as_str(),
        "key": row.message_key,
        "args": args,
        "existing": row.existing.map_or(-1, |i| i64::try_from(i).unwrap_or(-1)),
        "otherRoute": row.other_route,
        "sameLine": row.same_line.unwrap_or(0),
        "move": row.move_elsewhere,
        "action": row.action.as_str(),
        "verdictKey": row.verdict_key,
        "originReason": row.origin_reason,
        "originAnchor": row.origin_anchor,
        "originAdded": row.origin_added,
    })
}

fn plan_json(plan: &BulkPlan) -> Value {
    json!({
        "rows": plan.rows.iter().map(row_json).collect::<Vec<_>>(),
        "lines": plan.lines,
        "excess": plan.excess,
        "bound": plan.bound.map_or("", |b| b.as_str()),
        "add": plan.count(RowAction::Add),
        "move": plan.count(RowAction::Move),
        "keep": plan.count(RowAction::Keep),
        "drop": plan.count(RowAction::Drop),
        "remaining": plan.remaining,
    })
}

/// `reason/anchor/added` of an app-authored row, `-` for the user's own.
fn origin(row: &Value) -> String {
    match text(row, "originReason") {
        "" => "-".to_owned(),
        reason => format!(
            "{reason}/{}/{}",
            text(row, "originAnchor"),
            text(row, "originAdded")
        ),
    }
}

/// The vectors' digest, as `expected` spells it: one line per row, and the
/// plan's totals. The vectors were written from the JS side.
fn digest(plan: &Value) -> Value {
    let field = |row: &Value, name: &str| -> String {
        match row.get(name) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::String(_)) | None => "-".to_owned(),
            Some(other) => other.to_string(),
        }
    };
    let rows: Vec<Value> = plan["rows"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|row| {
            let args = row["args"]
                .as_object()
                .map(|m| {
                    let mut pairs: Vec<String> = m
                        .iter()
                        .map(|(k, v)| format!("{k}={}", js_string(v)))
                        .collect();
                    pairs.sort();
                    pairs.join(",")
                })
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "-".to_owned());
            let flag = |name: &str, on: &str, off: &str| {
                if row[name].as_bool() == Some(true) {
                    on.to_owned()
                } else {
                    off.to_owned()
                }
            };
            Value::from(
                [
                    field(row, "line"),
                    field(row, "type"),
                    text(row, "status").to_owned(),
                    text(row, "action").to_owned(),
                    text(row, "route").to_owned(),
                    flag("enabled", "on", "off"),
                    flag("verify", "?", "-"),
                    field(row, "key"),
                    args,
                    origin(row),
                    match text(row, "comment") {
                        "" => "-".to_owned(),
                        note => format!("#{note}"),
                    },
                    text(row, "value").to_owned(),
                ]
                .join(" "),
            )
        })
        .collect();
    let count = |name: &str| plan[name].as_u64().unwrap_or(0).to_string();
    let counts = [count("add"), count("move"), count("keep"), count("drop")].join("/");
    json!({
        "rows": rows,
        "lines": plan["lines"],
        "excess": plan["excess"],
        "bound": plan["bound"],
        "counts": counts,
        "remaining": plan["remaining"],
    })
}

#[test]
fn bulk_plan_digest_is_what_the_vectors_expect() {
    let (_, cases) = load_vectors("bulk_rules");
    let mut failures = Vec::new();
    for case in &cases {
        let got = digest(&plan_json(&rust_plan(&case.input)));
        if case.expected.as_ref() != Some(&got) {
            failures.push(format!(
                "bulk_rules / {}:\n  got:      {got}\n  expected: {:?}",
                case.name, case.expected
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The whole plan, every field, from both sides; the digest above is what the
/// vectors pin.
#[test]
fn bulk_plan_matches_js_field_for_field() {
    let (_, cases) = load_vectors("bulk_rules");
    let cases: Vec<Case> = cases
        .into_iter()
        .map(|case| Case {
            expected: None,
            ..case
        })
        .collect();
    check_cases(
        "bulk_rules",
        &cases,
        &mut JsLib::rules(),
        |input| format!("planBulkRules({})", lit(input)),
        |input| plan_json(&rust_plan(input)),
    );
}

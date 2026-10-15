#![allow(clippy::expect_used)]

//! Whether WSL runs and when to ask about it — the same answer from `pure.js`
//! and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::forwarded::{forwarding_present, notice_step};
use serde_json::{json, Value};

fn answer(input: &Value) -> &str {
    input["answer"].as_str().unwrap_or("")
}

#[test]
fn forwarding_present_matches_js() {
    check(
        "forwarded_present",
        &mut JsLib::pure(),
        |input| format!("forwardingPresent({})", arg(input, "rows")),
        |input| {
            let rows = input["rows"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default();
            Value::Bool(forwarding_present(
                rows.iter()
                    .filter_map(|row| row.get("name").and_then(Value::as_str)),
            ))
        },
    );
}

#[test]
fn forwarded_notice_step_matches_js() {
    check(
        "forwarded_notice_step",
        &mut JsLib::pure(),
        |input| {
            format!(
                "forwardedNoticeStep({}, {}, {}, {})",
                arg(input, "wasRaised"),
                arg(input, "present"),
                arg(input, "routed"),
                arg(input, "answer")
            )
        },
        |input| {
            let step = notice_step(
                input["wasRaised"] == Value::Bool(true),
                input["present"] == Value::Bool(true),
                input["routed"] == Value::Bool(true),
                answer(input),
            );
            json!({ "raise": step.raise, "raised": step.raised })
        },
    );
}

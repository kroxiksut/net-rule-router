#![allow(clippy::expect_used)]

//! What a safe-rollback dry run answered — the same verdict from `pure.js`
//! and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::rollback::rollback_verdict;
use serde_json::{json, Value};

#[test]
fn rollback_verdict_matches_js() {
    check(
        "rollback_verdict",
        &mut JsLib::pure(),
        |input| {
            format!(
                "rollbackDryRunVerdict({}, {}, {})",
                arg(input, "ok"),
                arg(input, "answer"),
                arg(input, "code")
            )
        },
        |input| {
            let verdict = rollback_verdict(
                input["ok"].as_bool().unwrap_or(false),
                input.get("answer").unwrap_or(&Value::Null),
                input.get("code").and_then(Value::as_str),
            );
            json!({
                "phase": verdict.phase.as_str(),
                "token": verdict.token,
                "target": verdict.target.map_or(Value::Null, |t| {
                    serde_json::to_value(t).expect("target encodes")
                }),
                "code": verdict.code,
            })
        },
    );
}

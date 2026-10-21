#![allow(clippy::expect_used)]

//! When the service stopped on its own and which recoveries to offer — the same
//! answer from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::service_loss::step;
use serde_json::{json, Value};

#[test]
fn service_loss_step_matches_js() {
    check(
        "service_loss_step",
        &mut JsLib::pure(),
        |input| {
            format!(
                "serviceLossStep({}, {}, {}, {}, {})",
                arg(input, "wasRaised"),
                arg(input, "status"),
                arg(input, "wasRunning"),
                arg(input, "stopExpected"),
                arg(input, "canRestore")
            )
        },
        |input| {
            let flag = |key: &str| input[key] == Value::Bool(true);
            let status = input["status"].as_str().unwrap_or("");
            let out = step(
                flag("wasRaised"),
                status,
                flag("wasRunning"),
                flag("stopExpected"),
                flag("canRestore"),
            );
            json!({ "raise": out.raise, "raised": out.raised, "actions": out.actions })
        },
    );
}

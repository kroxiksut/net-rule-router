#![allow(clippy::expect_used)]

//! The order of a full reset and what each step decides — the same answer
//! from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::full_reset::{next, Next, Outcome, Step};
use serde_json::{json, Value};

#[test]
fn full_reset_next_matches_js() {
    check(
        "full_reset_next",
        &mut JsLib::pure(),
        |input| {
            format!(
                "fullResetNext({}, {})",
                arg(input, "canElevate"),
                arg(input, "done")
            )
        },
        |input| {
            let done: Vec<(Step, Outcome)> = input["done"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|d| {
                    (
                        Step::parse(d["step"].as_str().unwrap_or("")).expect("a known step"),
                        Outcome::parse(d["result"].as_str().unwrap_or("")),
                    )
                })
                .collect();
            let out = next(input["canElevate"] == Value::Bool(true), &done);
            match out {
                Next::Run(step) => json!({
                    "action": "run", "step": step.as_str(), "cleared": false,
                    "restarted": false, "why": ""
                }),
                Next::Finish { cleared, restarted } => json!({
                    "action": "finish", "step": "", "cleared": cleared,
                    "restarted": restarted, "why": ""
                }),
                Next::NeedsElevation { step } => json!({
                    "action": "stop", "step": step.as_str(), "cleared": false,
                    "restarted": false, "why": "needs-elevation"
                }),
            }
        },
    );
}

#![allow(clippy::expect_used)]

//! Whether the service holds the last applied rules because a stored book
//! could not be read — the same answer from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::diagnostics::{rules_book_notice_step, rules_book_unreadable};
use serde_json::{json, Value};

#[test]
fn rules_book_unreadable_matches_js() {
    check(
        "rules_book_unreadable",
        &mut JsLib::pure(),
        |input| format!("rulesBookUnreadable({})", arg(input, "health")),
        |input| Value::Bool(rules_book_unreadable(&input["health"])),
    );
}

#[test]
fn rules_book_notice_step_matches_js() {
    check(
        "rules_book_notice_step",
        &mut JsLib::pure(),
        |input| {
            format!(
                "rulesBookNoticeStep({}, {})",
                arg(input, "wasRaised"),
                arg(input, "unreadable")
            )
        },
        |input| {
            let step = rules_book_notice_step(
                input["wasRaised"] == Value::Bool(true),
                input["unreadable"] == Value::Bool(true),
            );
            json!({ "raise": step.raise, "raised": step.raised })
        },
    );
}

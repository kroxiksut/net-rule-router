#![allow(clippy::expect_used)]

//! Whether the system DNS was left redirected, and when to say so — the same
//! answer from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::system_dns::{not_restored, notice_step};
use serde_json::{json, Value};

#[test]
fn system_dns_not_restored_matches_js() {
    check(
        "system_dns_not_restored",
        &mut JsLib::pure(),
        |input| format!("systemDnsNotRestored({})", arg(input, "health")),
        |input| Value::Bool(not_restored(&input["health"])),
    );
}

#[test]
fn system_dns_notice_step_matches_js() {
    check(
        "system_dns_notice_step",
        &mut JsLib::pure(),
        |input| {
            format!(
                "systemDnsNoticeStep({}, {})",
                arg(input, "wasRaised"),
                arg(input, "notRestored")
            )
        },
        |input| {
            let step = notice_step(
                input["wasRaised"] == Value::Bool(true),
                input["notRestored"] == Value::Bool(true),
            );
            json!({ "raise": step.raise, "raised": step.raised })
        },
    );
}

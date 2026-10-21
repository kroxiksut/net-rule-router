//! The rule form reads a typed value exactly as the GUI's `pure.js` does.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::rule_form::form_rule_value;
use serde_json::Value;

#[test]
fn form_rule_value_matches_js() {
    check(
        "form_rule_value",
        &mut JsLib::pure(),
        |input| {
            format!(
                "formRuleValue({}, {})",
                arg(input, "type"),
                arg(input, "value")
            )
        },
        |input| Value::from(form_rule_value(text(input, "type"), text(input, "value"))),
    );
}

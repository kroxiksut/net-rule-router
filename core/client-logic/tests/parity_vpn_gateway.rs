#![allow(clippy::expect_used)]

//! The rule that lets a VPN reach its gateway — the same draft from
//! `rules.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::vpn_gateway::gateway_rule_draft;
use nrr_client_logic::Route;
use serde_json::{json, Value};

#[test]
fn vpn_gateway_rule_draft_matches_js() {
    check(
        "vpn_gateway_rule_draft",
        &mut JsLib::rules(),
        |input| {
            format!(
                "vpnGatewayRuleDraft({}, {}, {}, {})",
                arg(input, "input"),
                arg(input, "program"),
                arg(input, "route"),
                arg(input, "template")
            )
        },
        |input| {
            let Some(route) = Route::from_slug(text(input, "route")) else {
                return Value::Null;
            };
            gateway_rule_draft(
                text(input, "input"),
                text(input, "program"),
                route,
                text(input, "template"),
            )
            .map_or(Value::Null, |draft| {
                json!({
                    "rule-type": draft.rule_type.as_str(),
                    "value": draft.value,
                    "route": draft.route.as_str(),
                    "comment": draft.comment,
                })
            })
        },
    );
}

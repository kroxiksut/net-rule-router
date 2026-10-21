#![allow(clippy::expect_used)]

//! The contract-skew banner reads the same from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{check, lit, JsLib};
use nrr_client_logic::contract::skew;
use serde_json::Value;

#[test]
fn contract_skew_matches_js() {
    check(
        "contract_skew",
        &mut JsLib::pure(),
        |input| format!("contractSkew({}, {})", lit(&input["info"]), input["own"]),
        |input| {
            let field = |key: &str| {
                u32::try_from(input["info"][key].as_u64().unwrap_or(0)).expect("a small revision")
            };
            let own = u32::try_from(input["own"].as_u64().expect("own")).expect("a small revision");
            Value::from(skew(
                field("service-protocol"),
                field("gui-contract"),
                field("service-contract"),
                own,
            ))
        },
    );
}

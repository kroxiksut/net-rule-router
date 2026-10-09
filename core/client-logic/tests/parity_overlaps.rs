#![allow(clippy::expect_used)]

//! Which route overlaps a rule saved from the rule form settles by itself —
//! the same answer from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::rules_overlaps::confirmed_by_own_edit;
use nrr_shared::rules_overlap::RouteOverlap;
use serde_json::Value;

#[test]
fn overlaps_confirmed_by_own_edit_matches_js() {
    check(
        "overlaps_confirmed_by_own_edit",
        &mut JsLib::pure(),
        |input| {
            format!(
                "overlapsConfirmedByOwnEdit({}, {})",
                arg(input, "overlaps"),
                arg(input, "ids")
            )
        },
        |input| {
            let overlaps: Vec<RouteOverlap> =
                serde_json::from_value(input["overlaps"].clone()).expect("overlaps decode");
            let ids: Vec<&str> = input["ids"]
                .as_array()
                .expect("ids")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            Value::from(confirmed_by_own_edit(&overlaps, &ids))
        },
    );
}

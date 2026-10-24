#![allow(clippy::expect_used)]

//! Whether the rules applying again is worth a line — the same answer from
//! `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::enforcement_notice::{restore_is_news, secondary_down_body_key};
use serde_json::json;

#[test]
fn enforcement_restore_is_news_matches_js() {
    check(
        "enforcement_restore_is_news",
        &mut JsLib::pure(),
        |input| format!("enforcementRestoreIsNews({})", arg(input, "previous")),
        |input| json!(restore_is_news(input["previous"].as_str().unwrap_or(""))),
    );
}

#[test]
fn enforcement_secondary_down_body_key_matches_js() {
    check(
        "enforcement_secondary_down_body_key",
        &mut JsLib::pure(),
        |input| format!("enforcementSecondaryDownBodyKey({})", arg(input, "level")),
        |input| {
            json!(secondary_down_body_key(
                input["level"].as_str().unwrap_or("")
            ))
        },
    );
}

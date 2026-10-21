#![allow(clippy::expect_used)]

//! Whether the rules applying again is worth a line — the same answer from
//! `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::enforcement_notice::restore_is_news;
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

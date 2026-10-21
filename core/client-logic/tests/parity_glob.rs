#![allow(clippy::expect_used)]

//! Application patterns: the same answer from `pure.js` and from
//! `nrr_shared::glob::glob_match`, which the engine and enforcement use.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_shared::glob::glob_match;
use serde_json::Value;

#[test]
fn glob_match_matches_js() {
    check(
        "glob_match",
        &mut JsLib::pure(),
        |input| {
            format!(
                "globMatch({}, {})",
                arg(input, "pattern"),
                arg(input, "text")
            )
        },
        |input| Value::from(glob_match(text(input, "pattern"), text(input, "text"))),
    );
}

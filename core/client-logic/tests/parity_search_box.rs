#![allow(clippy::expect_used)]

//! The rules list's search box: a URL pasted from a browser comes down to its
//! host in the window and in the terminal alike, and a subnet, an IPv6 address
//! or a comment stays as typed in both.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::rules_table::search_box_text;
use serde_json::Value;

#[test]
fn search_box_text_matches_js() {
    check(
        "search_box_text",
        &mut JsLib::rules(),
        |input| format!("searchBoxText({})", arg(input, "text")),
        |input| Value::from(search_box_text(text(input, "text"))),
    );
}

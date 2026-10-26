#![allow(clippy::expect_used)]

//! A rules file rewrite keeps the sections this build does not apply exactly
//! as the GUI's `pure.js` merges them, a section written twice included.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, JsLib};
use nrr_client_logic::passthrough::merge_passthrough_blocks;
use serde_json::Value;

#[test]
fn merge_passthrough_blocks_matches_js() {
    check(
        "merge_passthrough_blocks",
        &mut JsLib::pure(),
        |input| format!("mergePassthroughBlocks({})", arg(input, "blocks")),
        |input| {
            let blocks: Vec<(String, String)> = input["blocks"]
                .as_array()
                .map(|blocks| {
                    blocks
                        .iter()
                        .map(|b| {
                            let field = |key: &str| b[key].as_str().unwrap_or_default().to_owned();
                            (field("section-name"), field("raw-text"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            serde_json::to_value(merge_passthrough_blocks(&blocks)).unwrap_or(Value::Null)
        },
    );
}

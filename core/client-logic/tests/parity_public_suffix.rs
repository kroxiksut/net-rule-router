#![allow(clippy::expect_used)]

//! The rule form's public-suffix warning answers as the GUI's `pure.js` does,
//! over one table of suffixes.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use std::collections::BTreeSet;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::public_suffix::{is_public_suffix_value, MULTI_LABEL_SUFFIXES};
use serde_json::Value;

#[test]
fn is_public_suffix_value_matches_js() {
    check(
        "is_public_suffix_value",
        &mut JsLib::pure(),
        |input| format!("isPublicSuffixValue({})", arg(input, "value")),
        |input| Value::from(is_public_suffix_value(text(input, "value"))),
    );
}

/// A suffix added to one table only would warn in one client and stay silent
/// in the other, and group suggestions differently too.
#[test]
fn both_clients_hold_the_same_suffix_table() {
    let from_js: BTreeSet<String> = serde_json::from_value(
        JsLib::pure().eval_json("Object.keys(AUTO_RULE_MULTI_LABEL_SUFFIXES)"),
    )
    .expect("a list of names");
    let from_rust: BTreeSet<String> = MULTI_LABEL_SUFFIXES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        from_js.difference(&from_rust).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "in pure.js only"
    );
    assert_eq!(
        from_rust.difference(&from_js).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "in Rust only"
    );
}

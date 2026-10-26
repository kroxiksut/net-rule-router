#![allow(clippy::expect_used)]

//! "A site does not open": the running tray paces the card and words its way
//! out as the service and the terminal do.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::site_notice::{
    site_notice_due, site_offer_reach, SAME_SITE_GAP_MS, SITE_NOTICE_GAP_MS,
};
use serde_json::Value;

fn stamp(input: &Value, key: &str) -> Option<i64> {
    input[key].as_i64()
}

#[test]
fn site_notice_due_matches_js() {
    check(
        "site_notice_due",
        &mut JsLib::pure(),
        |input| {
            format!(
                "siteNoticeDue({}, {}, {}, {}, {})",
                arg(input, "muted"),
                arg(input, "lastAny"),
                arg(input, "siteShown"),
                arg(input, "answered"),
                arg(input, "now")
            )
        },
        |input| {
            Value::from(site_notice_due(
                input["muted"].as_bool().expect("muted"),
                stamp(input, "lastAny"),
                stamp(input, "siteShown"),
                input["answered"].as_bool().expect("answered"),
                input["now"].as_i64().expect("now"),
            ))
        },
    );
}

#[test]
fn site_offer_reach_matches_js() {
    check(
        "site_offer_reach",
        &mut JsLib::pure(),
        |input| {
            format!(
                "siteOfferReach({}, {})",
                arg(input, "signal"),
                arg(input, "reach")
            )
        },
        |input| {
            Value::from(
                site_offer_reach(text(input, "signal"), input["reach"].as_bool()).unwrap_or(""),
            )
        },
    );
}

/// A gap changed on one side only would let one surface tell what the other
/// holds back.
#[test]
fn both_sides_hold_the_same_gaps() {
    let mut js = JsLib::pure();
    assert_eq!(
        js.eval_json("SITE_NOTICE_GAP_MS"),
        Value::from(SITE_NOTICE_GAP_MS)
    );
    assert_eq!(
        js.eval_json("SAME_SITE_GAP_MS"),
        Value::from(SAME_SITE_GAP_MS)
    );
}

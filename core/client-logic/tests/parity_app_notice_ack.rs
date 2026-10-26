#![allow(clippy::expect_used)]

//! "Don't show" on the application-rule notice holds per program and problem,
//! the same in the window and here.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::app_notice_ack::{app_notice_ack_union, app_notice_covered_by_ack};
use serde_json::Value;

fn names(input: &Value, key: &str) -> Vec<String> {
    input[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn js_call(function: &str, input: &Value) -> String {
    format!(
        "{function}({}, {}, {})",
        arg(input, "ack"),
        arg(input, "notFound"),
        arg(input, "unrouted")
    )
}

#[test]
fn app_notice_covered_by_ack_matches_js() {
    check(
        "app_notice_covered_by_ack",
        &mut JsLib::pure(),
        |input| js_call("appNoticeCoveredByAck", input),
        |input| {
            Value::from(app_notice_covered_by_ack(
                text(input, "ack"),
                &names(input, "notFound"),
                &names(input, "unrouted"),
            ))
        },
    );
}

#[test]
fn app_notice_ack_union_matches_js() {
    check(
        "app_notice_ack_union",
        &mut JsLib::pure(),
        |input| js_call("appNoticeAckUnion", input),
        |input| {
            Value::from(app_notice_ack_union(
                text(input, "ack"),
                &names(input, "notFound"),
                &names(input, "unrouted"),
            ))
        },
    );
}

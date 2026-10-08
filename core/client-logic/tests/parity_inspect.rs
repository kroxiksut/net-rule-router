#![allow(clippy::expect_used)]

//! Parity for the trace filters and the diagnostics page's reading of service
//! answers: the Rust port answers every vector exactly as `pure.js` does.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::conn_trace::{is_ipv6_endpoint, is_non_internet_address};
use nrr_client_logic::diagnostics::{alert_ack_outcome, security_alert_items, AlertItem};
use serde_json::{json, Value};

fn member(input: &Value, key: &str) -> Value {
    input.get(key).cloned().unwrap_or(Value::Null)
}

fn item_json(item: &AlertItem) -> Value {
    json!({
        "alert_id": item.alert_id,
        "kind": item.kind,
        "state": item.state,
        "reason_code": item.reason_code,
        "raised_file": item.raised_file,
        "requires_action": item.requires_action,
    })
}

#[test]
fn is_ipv6_endpoint_matches_js() {
    check(
        "is_ipv6_endpoint",
        &mut JsLib::pure(),
        |input| format!("isIpv6Endpoint({})", arg(input, "endpoint")),
        |input| Value::from(is_ipv6_endpoint(text(input, "endpoint"))),
    );
}

#[test]
fn is_non_internet_address_matches_js() {
    check(
        "is_non_internet_address",
        &mut JsLib::pure(),
        |input| format!("isNonInternetAddress({})", arg(input, "remote")),
        |input| Value::from(is_non_internet_address(text(input, "remote"))),
    );
}

#[test]
fn security_alert_items_match_js() {
    check(
        "security_alert_items",
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (s) {{ var r = securityAlertItemsFromStatus(s); \
                 return r === null ? null : r.map(function (a) {{ return {{ \
                 alert_id: a.alertId, kind: a.kind, state: a.state, \
                 reason_code: a.reasonCode, raised_file: a.raisedFile, \
                 requires_action: a.requiresAction }} }}) }})({})",
                arg(input, "status")
            )
        },
        |input| {
            security_alert_items(&member(input, "status")).map_or(Value::Null, |items| {
                Value::Array(items.iter().map(item_json).collect())
            })
        },
    );
}

#[test]
fn alert_ack_outcome_matches_js() {
    check(
        "alert_ack_outcome",
        &mut JsLib::pure(),
        |input| {
            format!(
                "alertAckOutcome({}, {}, {})",
                arg(input, "status"),
                arg(input, "alertId"),
                arg(input, "code")
            )
        },
        |input| {
            Value::from(alert_ack_outcome(
                &member(input, "status"),
                text(input, "alertId"),
                text(input, "code"),
            ))
        },
    );
}

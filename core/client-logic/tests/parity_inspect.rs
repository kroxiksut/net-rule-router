#![allow(clippy::expect_used)]

//! Parity for the trace filters and the diagnostics page's reading of service
//! answers: the Rust port answers every vector exactly as `pure.js` does.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::conn_trace::{
    group_trace_rows, is_ipv6_endpoint, is_non_internet_address, TraceGroup, TraceGrouping,
    TraceRowRef,
};
use nrr_client_logic::diagnostics::{alert_ack_outcome, security_alert_items, AlertItem};
use nrr_client_logic::rule_value_class::path_style_for_os;
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

fn group_json(group: &TraceGroup) -> Value {
    json!({
        "kind": group.kind.slug(),
        "key": group.key,
        "label": group.label,
        "ruleValue": group.rule_value,
        "rows": group.rows,
        "programs": group.programs,
        "header": group.header,
    })
}

#[test]
fn conn_trace_groups_match_js() {
    check(
        "conn_trace_groups",
        &mut JsLib::pure(),
        |input| {
            format!(
                "connTraceGroups({}, {}, {})",
                arg(input, "rows"),
                arg(input, "grouping"),
                arg(input, "os")
            )
        },
        |input| {
            let rows: Vec<TraceRowRef<'_>> = input["rows"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|row| TraceRowRef {
                    process: text(row, "process"),
                    process_path: text(row, "process_path"),
                })
                .collect();
            let grouping =
                TraceGrouping::from_slug(text(input, "grouping")).unwrap_or(TraceGrouping::None);
            let style = path_style_for_os(text(input, "os"));
            let groups = group_trace_rows(&rows, grouping, style);
            Value::from(groups.iter().map(group_json).collect::<Vec<_>>())
        },
    );
}

#[test]
fn conn_trace_grouping_default_matches_js() {
    check(
        "conn_trace_grouping",
        &mut JsLib::pure(),
        |input| format!("connTraceGroupingOrDefault({})", arg(input, "slug")),
        |input| {
            let grouping = TraceGrouping::from_slug(text(input, "slug")).unwrap_or_default();
            Value::from(grouping.slug())
        },
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

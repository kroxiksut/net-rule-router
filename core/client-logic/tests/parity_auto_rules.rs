#![allow(clippy::expect_used)]

//! The suggestions pipeline answers every vector exactly as the GUI's
//! `pure.js` does: same groups, same order, same counts.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, check_cases, lit, load_vectors, merged, text, Case, JsLib};
use nrr_client_logic::auto_rules::{
    any_zone_site, count_dismissed_hosts, count_served_by_main_link, count_shown_pending_hosts,
    filter_by_consumer, filter_by_status, filter_served_by_main_link, group_rows,
    is_self_signed_row, main_route_rank, notice_due, notice_kind, registrable_domain,
    rows_shown_by_default, search, sort_groups, SortMode, SuggestionGroup, SuggestionHost,
};
use nrr_shared::ipc_payloads::{
    AutoRuleCandidateDto, AutoRuleDismissedEntryDto, StatusUpdateEvent,
};
use serde_json::{json, Map, Value};

#[test]
fn registrable_domain_matches_js() {
    check(
        "registrable_domain",
        &mut JsLib::pure(),
        |input| format!("registrableDomain({})", arg(input, "host")),
        |input| Value::from(registrable_domain(text(input, "host"))),
    );
}

/// `JSON.stringify` writes an integral number without a fraction.
fn number(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9_007_199_254_740_992.0 {
        Value::from(n as i64)
    } else {
        Value::from(n)
    }
}

/// A host in the JS object shape; an absent `thirdParty` is left out, as
/// `JSON.stringify` drops `undefined`.
fn host_shape(host: &SuggestionHost) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), Value::from(host.id.as_str()));
    out.insert("status".into(), Value::from(host.status.as_str()));
    out.insert("match".into(), Value::from(host.match_value.as_str()));
    out.insert("matchKind".into(), Value::from(host.match_kind.as_str()));
    out.insert("anchor".into(), Value::from(host.anchor.as_str()));
    out.insert("route".into(), Value::from(host.route.as_str()));
    out.insert("consumers".into(), json!(host.consumers));
    out.insert("affinity".into(), number(host.affinity));
    out.insert("observations".into(), Value::from(host.observations));
    out.insert("signal".into(), Value::from(host.signal.as_str()));
    out.insert(
        "primaryBehavior".into(),
        Value::from(host.primary_behavior.as_str()),
    );
    out.insert(
        "anchorRefusesMainLink".into(),
        Value::from(host.anchor_refuses_main_link),
    );
    out.insert(
        "servedByMainLink".into(),
        Value::from(host.served_by_main_link),
    );
    if let Some(third_party) = host.third_party {
        out.insert("thirdParty".into(), Value::from(third_party));
    }
    out.insert("observedMembers".into(), json!(host.observed_members));
    out.insert("timestampMs".into(), Value::from(host.timestamp_ms));
    out.insert(
        "anyZoneSite".into(),
        Value::from(host.any_zone_site.as_str()),
    );
    out.insert(
        "lessCertain".into(),
        Value::from(host.less_certain.as_str()),
    );
    Value::Object(out)
}

fn group_shape(group: &SuggestionGroup) -> Value {
    json!({
        "domain": group.domain,
        "isApp": group.is_app,
        "hosts": group.hosts.iter().map(host_shape).collect::<Vec<_>>(),
        "pendingIds": group.pending_ids,
        "dismissedIds": group.dismissed_ids,
        "consumers": group.consumers,
        "latestMs": group.latest_ms,
        "rank": main_route_rank(group),
        "shownPending": count_shown_pending_hosts(group),
        "anyZoneSite": any_zone_site(group),
    })
}

const PIPELINE: &str = "(function (c, d, showDismissed, showServed, consumer, query, sort) { \
    var merged = groupAutoRuleRows(c, d); \
    var byStatus = filterAutoRuleGroupsByStatus(merged, showDismissed); \
    var byMainLink = filterAutoRuleGroupsServedByMainLink(byStatus, showServed); \
    var byConsumer = filterAutoRuleGroups(byMainLink, consumer); \
    var shown = sortAutoRuleGroups(searchAutoRuleGroups(byConsumer, query), sort); \
    return { \
        dismissed: countDismissedAutoRuleHosts(merged), \
        served: countAutoRuleHostsServedByMainLink(byStatus), \
        offered: autoRuleRowsShownByDefault(c).map(function (r) { return r.id }), \
        groups: shown.map(function (g) { return { \
            domain: g.domain, isApp: g.isApp, hosts: g.hosts, pendingIds: g.pendingIds, \
            dismissedIds: g.dismissedIds, consumers: g.consumers, latestMs: g.latestMs, \
            rank: autoRuleGroupMainRouteRank(g), shownPending: countShownPendingAutoRuleHosts(g), \
            anyZoneSite: autoRuleGroupAnyZoneSite(g) \
        } }) \
    } })";

#[test]
fn suggestion_groups_match_js() {
    let (document, raw) = load_vectors("auto_rule_groups");
    let base = &document["base-candidate"];
    // Each candidate patch is laid over the base before either side sees it.
    let cases: Vec<Case> = raw
        .into_iter()
        .map(|case| {
            let mut input = case.input;
            let candidates: Vec<Value> = input["candidates"]
                .as_array()
                .expect("candidates is an array")
                .iter()
                .map(|patch| merged(base, patch))
                .collect();
            input["candidates"] = Value::from(candidates);
            Case { input, ..case }
        })
        .collect();
    check_cases(
        "auto_rule_groups",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "{PIPELINE}({}, {}, {}, {}, {}, {}, {})",
                lit(&input["candidates"]),
                lit(&input["dismissed"]),
                arg(input, "show-dismissed"),
                arg(input, "show-served"),
                lit(&json!(text(input, "consumer"))),
                arg(input, "query"),
                arg(input, "sort")
            )
        },
        |input| {
            let candidates: Vec<AutoRuleCandidateDto> =
                serde_json::from_value(input["candidates"].clone()).expect("candidate rows");
            let dismissed: Vec<AutoRuleDismissedEntryDto> =
                serde_json::from_value(input["dismissed"].clone()).expect("dismissed rows");
            let show_dismissed = input["show-dismissed"].as_bool().unwrap_or(false);
            let show_served = input["show-served"].as_bool().unwrap_or(false);
            let merged_groups = group_rows(&candidates, &dismissed);
            let by_status = filter_by_status(&merged_groups, show_dismissed);
            let by_main_link = filter_served_by_main_link(&by_status, show_served);
            let by_consumer = filter_by_consumer(&by_main_link, text(input, "consumer"));
            let shown = sort_groups(
                &search(&by_consumer, text(input, "query")),
                SortMode::from_slug(text(input, "sort")),
            );
            json!({
                "dismissed": count_dismissed_hosts(&merged_groups),
                "served": count_served_by_main_link(&by_status),
                "offered": rows_shown_by_default(&candidates)
                    .iter()
                    .map(|row| row.id.as_str())
                    .collect::<Vec<_>>(),
                "groups": shown.iter().map(group_shape).collect::<Vec<_>>(),
            })
        },
    );
}

/// The TUI reads the typed push, the GUI the raw one; both decide alike,
/// including for a service that predates the `announces` flag.
#[test]
fn notice_due_matches_js() {
    let (document, raw) = load_vectors("auto_rule_notice_due");
    let base = &document["base-event"];
    let cases: Vec<Case> = raw
        .into_iter()
        .map(|case| {
            let mut input = case.input;
            input["event"] = merged(base, &input["event"]);
            Case { input, ..case }
        })
        .collect();
    check_cases(
        "auto_rule_notice_due",
        &cases,
        &mut JsLib::pure(),
        |input| format!("autoRuleNoticeDue({})", lit(&input["event"])),
        |input| {
            let event: StatusUpdateEvent =
                serde_json::from_value(input["event"].clone()).expect("a suggestions push");
            let StatusUpdateEvent::AutoRuleCandidatesChanged {
                announces,
                pending_count,
                ..
            } = event
            else {
                panic!("the vector holds a suggestions push")
            };
            Value::from(notice_due(announces, pending_count))
        },
    );
}

#[test]
fn notice_kind_matches_js() {
    let (document, raw) = load_vectors("auto_rule_notice_kind");
    let base = &document["base-candidate"];
    let cases: Vec<Case> = raw
        .into_iter()
        .map(|case| {
            let mut input = case.input;
            let rows: Vec<Value> = input["rows"]
                .as_array()
                .expect("rows is an array")
                .iter()
                .map(|patch| merged(base, patch))
                .collect();
            input["rows"] = Value::from(rows);
            Case { input, ..case }
        })
        .collect();
    check_cases(
        "auto_rule_notice_kind",
        &cases,
        &mut JsLib::pure(),
        |input| {
            format!(
                "(function (rows) {{ return {{ kind: autoRuleNoticeKind(rows), \
                 selfSigned: rows.map(autoRuleIsSelfSigned) }} }})({})",
                lit(&input["rows"])
            )
        },
        |input| {
            let rows: Vec<AutoRuleCandidateDto> =
                serde_json::from_value(input["rows"].clone()).expect("candidate rows");
            json!({
                "kind": notice_kind(&rows).as_str(),
                "selfSigned": rows.iter().map(is_self_signed_row).collect::<Vec<_>>(),
            })
        },
    );
}

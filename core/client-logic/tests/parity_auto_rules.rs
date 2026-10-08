#![allow(clippy::expect_used)]

//! The suggestions pipeline answers every vector exactly as the GUI's
//! `pure.js` does: same groups, same order, same counts.

// Shared with `parity.rs`, which uses the parts this file does not.
#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, check_cases, lit, load_vectors, merged, text, Case, JsLib};
use nrr_client_logic::auto_rules::{
    count_dismissed_hosts, count_served_by_main_link, count_shown_pending_hosts, filter_by_status,
    filter_served_by_main_link, group_rows, main_route_rank, registrable_domain,
    rows_shown_by_default, search, sort_groups, SortMode, SuggestionGroup, SuggestionHost,
};
use nrr_shared::ipc_payloads::{AutoRuleCandidateDto, AutoRuleDismissedEntryDto};
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
    })
}

const PIPELINE: &str = "(function (c, d, showDismissed, showServed, query, sort) { \
    var merged = groupAutoRuleRows(c, d); \
    var byStatus = filterAutoRuleGroupsByStatus(merged, showDismissed); \
    var byMainLink = filterAutoRuleGroupsServedByMainLink(byStatus, showServed); \
    var shown = sortAutoRuleGroups(searchAutoRuleGroups(byMainLink, query), sort); \
    return { \
        dismissed: countDismissedAutoRuleHosts(merged), \
        served: countAutoRuleHostsServedByMainLink(byStatus), \
        offered: autoRuleRowsShownByDefault(c).map(function (r) { return r.id }), \
        groups: shown.map(function (g) { return { \
            domain: g.domain, isApp: g.isApp, hosts: g.hosts, pendingIds: g.pendingIds, \
            dismissedIds: g.dismissedIds, consumers: g.consumers, latestMs: g.latestMs, \
            rank: autoRuleGroupMainRouteRank(g), shownPending: countShownPendingAutoRuleHosts(g) \
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
                "{PIPELINE}({}, {}, {}, {}, {}, {})",
                lit(&input["candidates"]),
                lit(&input["dismissed"]),
                arg(input, "show-dismissed"),
                arg(input, "show-served"),
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
            let shown = sort_groups(
                &search(&by_main_link, text(input, "query")),
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

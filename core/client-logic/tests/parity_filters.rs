#![allow(clippy::expect_used)]

//! Parity for the list filters both clients apply over loaded rows: the cache
//! list's three filters and the rules table's filters and order.

#[allow(dead_code)]
mod js_harness;

use std::cmp::Ordering;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::cache_view::{cache_entry_passes, CacheFilters};
use nrr_client_logic::rules_table::{
    compare_rule_rows, rule_passes_filters, RouteFilter, RowOrigin, RuleRow, RuleRowView, RuleType,
    RulesFilters, SortBy, SortDir, StatusFilter, TargetRoute,
};
use serde_json::Value;

fn row_from_js(value: &Value) -> RuleRow {
    let has_origin = ["originReason", "originAnchor", "originAdded"]
        .iter()
        .any(|key| value.get(*key).is_some());
    RuleRow {
        id: text(value, "id").to_owned(),
        enabled: value["enabled"].as_bool().unwrap_or(false),
        rule_type: RuleType::from_slug(text(value, "ruleType")),
        match_value: text(value, "matchValue").to_owned(),
        target_route: TargetRoute::from_slug(text(value, "targetRoute")),
        verify: value["verify"].as_bool().unwrap_or(false),
        comment: text(value, "comment").to_owned(),
        origin: has_origin.then(|| RowOrigin {
            reason: text(value, "originReason").to_owned(),
            anchor: text(value, "originAnchor").to_owned(),
            added: text(value, "originAdded").to_owned(),
        }),
    }
}

/// The row as the window holds it: absent fields read as the window reads them.
fn view_of<'a>(rule: &'a RuleRow, item: &'a Value, ace_lower: &'a str) -> RuleRowView<'a> {
    let status = text(item, "validationStatus");
    RuleRowView {
        rule,
        ace_lower,
        validation_status: if status.is_empty() { "valid" } else { status },
        main_route: text(item, "mainRoute"),
    }
}

#[test]
fn cache_entry_passes_matches_js() {
    check(
        "cache_entry_passes",
        &mut JsLib::pure(),
        |input| {
            format!(
                "cacheEntryPassesFilters({}, {}, {}, {})",
                arg(input, "entry"),
                arg(input, "source"),
                arg(input, "freshness"),
                arg(input, "route")
            )
        },
        |input| {
            let entry = &input["entry"];
            let filters = CacheFilters {
                source: text(input, "source"),
                freshness: text(input, "freshness"),
                route: text(input, "route"),
            };
            Value::from(cache_entry_passes(
                text(entry, "source"),
                text(entry, "freshness"),
                text(entry, "expected_route"),
                &filters,
            ))
        },
    );
}

#[test]
fn rule_passes_filters_matches_js() {
    check(
        "rule_passes_filters",
        &mut JsLib::rules(),
        |input| {
            format!(
                "rulePassesFilters({}, {}, function () {{ return {} }}, \
                 function () {{ return {} }})",
                arg(input, "item"),
                arg(input, "filters"),
                arg(input, "overridden"),
                arg(input, "recent")
            )
        },
        |input| {
            let item = &input["item"];
            let given = &input["filters"];
            let rule = row_from_js(item);
            let ace_lower = text(item, "aceMatchValue").to_lowercase();
            let filters = RulesFilters {
                status: StatusFilter::from_slug(text(given, "status")).unwrap_or_default(),
                rule_type: text(given, "type"),
                route: RouteFilter::from_slug(text(given, "route")).unwrap_or_default(),
                auto_only: given["autoOnly"].as_bool().unwrap_or(false),
                recent_only: given["recentOnly"].as_bool().unwrap_or(false),
                search: text(given, "search"),
            };
            Value::from(rule_passes_filters(
                &view_of(&rule, item, &ace_lower),
                &filters,
                || input["overridden"].as_bool().unwrap_or(false),
                || input["recent"].as_bool().unwrap_or(false),
            ))
        },
    );
}

#[test]
fn compare_rule_rows_matches_js() {
    check(
        "compare_rule_rows",
        &mut JsLib::rules(),
        |input| {
            format!(
                "Math.sign(compareRuleRows({}, {}, {}, {}))",
                arg(input, "a"),
                arg(input, "b"),
                arg(input, "sortBy"),
                arg(input, "sortDir")
            )
        },
        |input| {
            let (a, b) = (row_from_js(&input["a"]), row_from_js(&input["b"]));
            let sort = SortBy::from_slug(text(input, "sortBy")).unwrap_or_default();
            let dir = if text(input, "sortDir") == "desc" {
                SortDir::Desc
            } else {
                SortDir::Asc
            };
            let ordering = compare_rule_rows(
                &view_of(&a, &input["a"], ""),
                &view_of(&b, &input["b"], ""),
                sort,
                dir,
            );
            Value::from(match ordering {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            })
        },
    );
}

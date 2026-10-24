#![allow(clippy::expect_used)]

//! The rules list's filters offer the same choices in the window and in the
//! terminal, and the type filter offers every rule type a user can write: a
//! type missing from the list is a rule nobody can find by filtering.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use nrr_client_logic::rules_table::{RouteFilter, StatusFilter, TYPE_FILTERS};
use nrr_shared::FreeRuleType;
use serde_json::Value;

fn js_list(rules: &mut JsLib, name: &str) -> Vec<String> {
    match rules.eval_json(name) {
        Value::Array(items) => items
            .into_iter()
            .map(|v| v.as_str().expect("a slug").to_owned())
            .collect(),
        other => panic!("{name} is not a list: {other}"),
    }
}

#[test]
fn the_window_offers_the_terminals_filters() {
    let mut rules = JsLib::rules();
    assert_eq!(js_list(&mut rules, "RULES_TYPE_FILTERS"), TYPE_FILTERS);
    assert_eq!(
        js_list(&mut rules, "RULES_STATUS_FILTERS"),
        StatusFilter::ALL.map(StatusFilter::slug)
    );
    assert_eq!(
        js_list(&mut rules, "RULES_ROUTE_FILTERS"),
        RouteFilter::ALL.map(RouteFilter::slug)
    );
}

#[test]
fn every_rule_type_can_be_filtered_for() {
    for rule_type in FreeRuleType::ALL {
        assert!(
            TYPE_FILTERS.contains(&rule_type.slug()),
            "the type filter does not offer `{}`",
            rule_type.slug()
        );
    }
}

#![allow(clippy::expect_used)]

//! One-question twins (a name, a path, a flag in a status) that had no
//! vectors: each answers the same in `pure.js`/`rules.js` and in Rust.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::app_routes::{app_route_of, AppRule};
use serde_json::{json, Value};

#[test]
fn app_route_of_matches_js() {
    check(
        "app_route_of",
        &mut JsLib::pure(),
        |input| {
            format!(
                "appRouteOf({}, {})",
                arg(input, "rules"),
                arg(input, "program")
            )
        },
        |input| {
            let rules: Vec<AppRule<'_>> = input
                .get("rules")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .map(|r| AppRule {
                    value: text(r, "value"),
                    route: text(r, "route"),
                    enabled: r.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                })
                .collect();
            json!(app_route_of(&rules, text(input, "program")))
        },
    );
}

#[test]
fn is_forwarding_adapter_name_matches_js() {
    check(
        "is_forwarding_adapter_name",
        &mut JsLib::pure(),
        |input| format!("isForwardingAdapterName({})", arg(input, "name")),
        |input| {
            json!(nrr_client_logic::forwarded::is_forwarding_adapter_name(
                text(input, "name")
            ))
        },
    );
}

#[test]
fn present_adapter_ids_match_js() {
    check(
        "present_adapter_ids",
        &mut JsLib::pure(),
        |input| format!("presentAdapterIds({})", arg(input, "snapshot")),
        |input| {
            json!(nrr_client_logic::restore::present_adapter_ids(
                input.get("snapshot").unwrap_or(&Value::Null)
            ))
        },
    );
}

#[test]
fn value_is_any_zone_matches_js() {
    check(
        "value_is_any_zone",
        &mut JsLib::rules(),
        |input| format!("valueIsAnyZone({})", arg(input, "value")),
        |input| {
            json!(nrr_client_logic::rules_table::value_is_any_zone(text(
                input, "value"
            )))
        },
    );
}

#[test]
fn is_usable_set_name_matches_js() {
    check(
        "is_usable_set_name",
        &mut JsLib::pure(),
        |input| format!("isUsableSetName({})", arg(input, "name")),
        |input| {
            json!(nrr_client_logic::rule_sets::is_usable_set_name(text(
                input, "name"
            )))
        },
    );
}

#[test]
fn rules_file_folder_matches_js() {
    check(
        "rules_file_folder",
        &mut JsLib::pure(),
        |input| format!("rulesFileFolder({})", arg(input, "path")),
        |input| {
            json!(nrr_client_logic::rule_sets::rules_file_folder(text(
                input, "path"
            )))
        },
    );
}

#[test]
fn first_run_country_matches_js() {
    check(
        "first_run_country",
        &mut JsLib::pure(),
        |input| {
            format!(
                "firstRunCountry({}, {})",
                arg(input, "region"),
                arg(input, "locales")
            )
        },
        |input| {
            let locales: Vec<String> = input
                .get("locales")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice)
                .iter()
                .filter_map(|l| l.as_str().map(str::to_owned))
                .collect();
            json!(nrr_client_logic::first_run::first_run_country(
                text(input, "region"),
                &locales
            ))
        },
    );
}

#[test]
fn security_alerts_unreadable_matches_js() {
    check(
        "security_alerts_unreadable",
        &mut JsLib::pure(),
        |input| format!("securityAlertsUnreadable({})", arg(input, "status")),
        |input| {
            json!(nrr_client_logic::diagnostics::security_alerts_unreadable(
                input.get("status").unwrap_or(&Value::Null)
            ))
        },
    );
}

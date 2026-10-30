#![allow(clippy::expect_used)]

//! The set on screen moving into the user's rule-set folder: its name, whether
//! it already lives there, and the numbered name a taken one gets — the same
//! answers from `pure.js` and from the crate.

#[allow(dead_code)]
mod js_harness;

use js_harness::{arg, check, text, JsLib};
use nrr_client_logic::rule_sets::{
    adopted_set_name, numbered_set_name, rule_set_offer_due, rules_live_in_folder, RouteFiles,
    RuleSetOffer, ServiceState,
};
use serde_json::Value;

/// The two routes' remembered files out of a GUI-shaped `prefs` object.
fn routes(prefs: &Value) -> [RouteFiles<'_>; 2] {
    let field = |key: &str| text(prefs, key);
    [
        RouteFiles {
            saved: field("lastSavedPathPrimary"),
            loaded: field("lastLoadedPathPrimary"),
            auto_open: field("autoOpenOnLaunchPathPrimary"),
        },
        RouteFiles {
            saved: field("lastSavedPathSecondary"),
            loaded: field("lastLoadedPathSecondary"),
            auto_open: field("autoOpenOnLaunchPathSecondary"),
        },
    ]
}

#[test]
fn adopted_set_name_matches_js() {
    check(
        "adopted_set_name",
        &mut JsLib::pure(),
        |input| {
            format!(
                "adoptedSetName({}, {})",
                arg(input, "prefs"),
                arg(input, "fallback")
            )
        },
        |input| {
            let prefs = &input["prefs"];
            let selected = text(prefs, "selectedPresetSet");
            Value::from(adopted_set_name(
                &routes(prefs),
                selected,
                text(input, "fallback"),
            ))
        },
    );
}

#[test]
fn rules_live_in_folder_matches_js() {
    check(
        "rules_live_in_folder",
        &mut JsLib::pure(),
        |input| {
            format!(
                "rulesLiveInFolder({}, {})",
                arg(input, "prefs"),
                arg(input, "folder")
            )
        },
        |input| {
            let live = rules_live_in_folder(&routes(&input["prefs"]), text(input, "folder"));
            Value::from(live)
        },
    );
}

#[test]
fn numbered_set_name_matches_js() {
    check(
        "numbered_set_name",
        &mut JsLib::pure(),
        |input| {
            format!(
                "numberedSetName({}, function (n) {{ return {} || {}.indexOf(n) >= 0 }})",
                arg(input, "base"),
                arg(input, "all-taken"),
                arg(input, "taken")
            )
        },
        |input| {
            let all = input["all-taken"].as_bool().expect("all-taken");
            let taken: Vec<&str> = input["taken"]
                .as_array()
                .expect("taken")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let name = numbered_set_name(text(input, "base"), |n| all || taken.contains(&n));
            Value::from(name)
        },
    );
}

#[test]
fn rule_set_offer_due_matches_js() {
    check(
        "rule_set_offer_due",
        &mut JsLib::pure(),
        |input| format!("ruleSetOfferDue({})", arg(input, "state")),
        |input| {
            let state = &input["state"];
            let flag = |key: &str| state[key].as_bool().expect(key);
            let count = |key: &str| state[key].as_i64().expect(key);
            Value::from(rule_set_offer_due(&RuleSetOffer {
                first_run_done: flag("firstRunDone"),
                service: ServiceState::from_slug(text(state, "service")),
                service_rules: usize::try_from(count("serviceRules")).ok(),
                local_rules: usize::try_from(count("localRules")).expect("localRules"),
                user_bound: flag("userBound"),
                set_name: text(state, "setName"),
                answered: flag("answered"),
                edits_locked: flag("editsLocked"),
            }))
        },
    );
}

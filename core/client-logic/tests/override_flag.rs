#![allow(clippy::expect_used)]

//! `+override` makes a program rule wait for the user's confirmation. If the
//! window and the service read the flag differently, the tray reports "added"
//! for a rule that waits, or the service holds a rule the window never asked to
//! hold. Each value below is a way to make the two readings drift.

#[allow(dead_code)]
mod js_harness;

use js_harness::JsLib;
use nrr_shared::preset_parser::split_rule_flags;
use serde_json::Value;

fn window_says(rules: &mut JsLib, rule_type: &str, value: &str) -> bool {
    let call = format!(
        "ruleValueAsksOverride({}, {})",
        serde_json::to_string(rule_type).expect("json"),
        serde_json::to_string(value).expect("json")
    );
    rules.eval_json(&call) == Value::Bool(true)
}

#[test]
fn the_window_and_the_service_read_the_flag_alike() {
    let mut rules = JsLib::rules();
    let cases: &[(&str, bool)] = &[
        (r#""C:\Windows\System32\curl.exe" +override"#, true),
        ("curl +children +override", true),
        ("curl +override +children", true),
        ("curl\t+override", true),
        ("curl  +override  ", true),
        ("curl", false),
        ("+override", false),
        ("curl +overrides", false),
        ("curl +OVERRIDE", false),
        ("curl+override", false),
        ("", false),
    ];
    for &(value, expected) in cases {
        let (_, flags) = split_rule_flags(value);
        assert_eq!(
            flags.override_requested, expected,
            "the service reads {value:?} wrong"
        );
        assert_eq!(
            window_says(&mut rules, "application", value),
            expected,
            "the window reads {value:?} wrong"
        );
    }
}

/// The flag means something on a program only; on any other rule the window
/// never reports a wait.
#[test]
fn only_a_program_rule_waits() {
    let mut rules = JsLib::rules();
    for rule_type in ["domain", "subdomain", "ip", "subnet", "zone", ""] {
        assert!(
            !window_says(&mut rules, rule_type, "example.test +override"),
            "{rule_type:?} never waits"
        );
    }
}

//! Numbers the QML shell restates from `nrr-shared`.
//!
//! A limit the user meets in the GUI and a limit the service enforces have to
//! be the same number, and the GUI cannot read Rust constants — it carries its
//! own literal. Every such literal is a copy, and a copy with nothing holding it
//! drifts: the file that declares the cap even says "the GUI mirrors this as
//! `freeRulesMaxCount`", which described the intent and enforced nothing.
//!
//! Drift here is not cosmetic. Too low, and the app refuses a rule the service
//! would have taken; too high, and the user writes rules that are accepted in
//! the window and rejected on apply, after the work is done.

use std::path::{Path, PathBuf};

fn qml(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The integer assigned to `name` in a QML `readonly property int` line.
fn qml_int_property(source: &str, name: &str) -> i64 {
    let needle = format!("property int {name}:");
    let line = source
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| panic!("no `property int {name}` in the QML shell"));
    let value = line
        .split(':')
        .next_back()
        .unwrap_or_default()
        .trim()
        .trim_end_matches(&[';', ','][..]);
    value
        .parse()
        .unwrap_or_else(|e| panic!("`{name}` is not an integer literal ({value:?}): {e}"))
}

#[test]
fn the_free_rule_cap_in_qml_equals_the_shared_constant() {
    let main = qml("apps/desktop/qml/Main.qml");
    assert_eq!(
        qml_int_property(&main, "freeRulesMaxCount"),
        nrr_shared::rules_json::FREE_MAX_RULES as i64,
        "the window's cap and the service's cap must be one number"
    );
}

#[test]
fn the_reader_actually_reads_the_literal() {
    // Positive control for the parser above: a wrong name must fail loudly
    // rather than quietly return a default that matches anything.
    let source = "    readonly property int demoCap: 4242\n";
    assert_eq!(qml_int_property(source, "demoCap"), 4242);
}

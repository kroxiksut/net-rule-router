#![allow(clippy::expect_used)]

//! What an open window and the tray make of the user's settings file changed
//! by another client (the terminal, the other surface), run on the real
//! `pure.js`. Each case is a way to lose the user's own choice, or to write
//! the user's rules into a file they no longer use.

#[allow(dead_code)]
mod js_harness;

use js_harness::{lit, JsLib};
use serde_json::{json, Value};

fn adoption(pure: &mut JsLib, prefs: Value, snapshot: Value, incoming: Value) -> Value {
    let buffered = json!({ "mergeConflictPolicy": true, "language": true });
    pure.eval_json(&format!(
        "userSettingsAdoption({}, {}, {}, {})",
        lit(&prefs),
        lit(&snapshot),
        lit(&buffered),
        lit(&incoming)
    ))
}

/// The terminal bound other files: the window takes them, and nothing waits
/// for Apply because of it.
#[test]
fn a_change_made_elsewhere_is_taken_as_it_is() {
    let mut pure = JsLib::pure();
    let step = adoption(
        &mut pure,
        json!({ "userPresetsDir": "/old", "lastSavedPathPrimary": null, "language": "en" }),
        Value::Null,
        json!({ "userPresetsDir": "/terminal", "lastSavedPathPrimary": "/terminal/a.txt" }),
    );
    assert_eq!(step["changed"], true);
    assert_eq!(
        step["take"],
        json!({ "userPresetsDir": "/terminal", "lastSavedPathPrimary": "/terminal/a.txt" })
    );
    assert_eq!(step["rebase"], json!({}), "nothing waits for Apply");
}

/// The user picked a merge policy in Settings and has not pressed Apply when
/// the terminal sets another one: the user's pick stays on screen, and Cancel
/// goes back to the terminal's choice rather than to a value nobody holds.
#[test]
fn a_choice_waiting_for_apply_is_not_replaced() {
    let mut pure = JsLib::pure();
    let step = adoption(
        &mut pure,
        json!({ "mergeConflictPolicy": "file-wins", "userPresetsDir": "/old" }),
        json!({ "mergeConflictPolicy": "union", "userPresetsDir": "/old" }),
        json!({ "mergeConflictPolicy": "service-wins", "userPresetsDir": "/terminal" }),
    );
    assert_eq!(step["take"], json!({ "userPresetsDir": "/terminal" }));
    assert_eq!(
        step["rebase"],
        json!({ "mergeConflictPolicy": "service-wins", "userPresetsDir": "/terminal" })
    );

    // Pending edits elsewhere: an untouched buffered key follows the file.
    let step = adoption(
        &mut pure,
        json!({ "mergeConflictPolicy": "union", "language": "ru" }),
        json!({ "mergeConflictPolicy": "union", "language": "en" }),
        json!({ "mergeConflictPolicy": "service-wins" }),
    );
    assert_eq!(
        step["take"],
        json!({ "mergeConflictPolicy": "service-wins" })
    );
}

/// "Not now" in the terminal closes the window's offer of a rule set while
/// the window is open, and nothing waits for Apply because of it.
#[test]
fn the_terminals_answer_to_the_rule_set_offer_reaches_an_open_window() {
    let mut pure = JsLib::pure();
    let step = adoption(
        &mut pure,
        json!({ "ruleSetOfferAnswered": false }),
        Value::Null,
        json!({ "ruleSetOfferAnswered": true }),
    );
    assert_eq!(
        step["take"],
        json!({ "ruleSetOfferAnswered": true }),
        "{step}"
    );
}

/// Only the fields the file carries are taken; an answer naming anything else
/// cannot reach the rest of the window's preferences.
#[test]
fn only_the_shared_fields_are_taken() {
    let mut pure = JsLib::pure();
    let step = adoption(
        &mut pure,
        json!({ "language": "en", "selectedPresetSet": "user:a" }),
        Value::Null,
        json!({ "language": "ru", "themeMode": "dark", "selectedPresetSet": "user:a" }),
    );
    assert_eq!(step["changed"], false, "{step}");
    assert_eq!(step["take"], json!({}));
}

fn tray_paths(pure: &mut JsLib, snap: Value, bound: Value) -> Value {
    pure.eval_json(&format!("trayRulesPaths({}, {})", lit(&snap), lit(&bound)))
}

/// The window is closed and the terminal moved the primary route to another
/// set: the tray writes the new file, never the old set's.
#[test]
fn with_the_window_gone_the_tray_follows_a_binding_made_elsewhere() {
    let mut pure = JsLib::pure();
    let snap = json!({
        "windowRunning": false,
        "rulesPathPrimary": "C:\\Sets\\home\\rules_primary.txt",
        "rulesPathSecondary": "C:\\Sets\\home\\rules_secondary.txt",
        "boundPrimary": "C:\\Sets\\home\\rules_primary.txt",
        "boundSecondary": "C:\\Sets\\home\\rules_secondary.txt",
    });
    let paths = tray_paths(
        &mut pure,
        snap.clone(),
        json!({ "primary": "C:/Sets/work/rules_primary.txt", "secondary": "C:/Sets/home/rules_secondary.txt" }),
    );
    assert_eq!(paths["primary"], "C:/Sets/work/rules_primary.txt");
    assert_eq!(
        paths["secondary"], "C:\\Sets\\home\\rules_secondary.txt",
        "the same file in the file's spelling is the window's answer"
    );

    // Unbound elsewhere: nothing to write for that route.
    let paths = tray_paths(
        &mut pure,
        snap,
        json!({ "primary": "", "secondary": "C:/Sets/home/rules_secondary.txt" }),
    );
    assert_eq!(paths["primary"], "");
}

/// While the window runs it answers; an unknown shared file, or a presence
/// file from a window that did not publish its binding, leaves the window's
/// answer as it is.
#[test]
fn the_windows_answer_stands_while_it_runs_or_nothing_is_known() {
    let mut pure = JsLib::pure();
    let bound = json!({ "primary": "/elsewhere/rules_primary.txt", "secondary": "" });
    let running = json!({
        "windowRunning": true,
        "rulesPathPrimary": "/home/rules_primary.txt",
        "boundPrimary": "/home/rules_primary.txt",
        "boundSecondary": "",
    });
    assert_eq!(
        tray_paths(&mut pure, running, bound.clone())["primary"],
        "/home/rules_primary.txt"
    );
    let gone = json!({
        "windowRunning": false,
        "rulesPathPrimary": "/home/rules_primary.txt",
        "boundPrimary": "/home/rules_primary.txt",
    });
    assert_eq!(
        tray_paths(&mut pure, gone, Value::Null)["primary"],
        "/home/rules_primary.txt"
    );
    let older = json!({ "windowRunning": false, "rulesPathPrimary": "/home/rules_primary.txt" });
    assert_eq!(
        tray_paths(&mut pure, older, bound)["primary"],
        "/home/rules_primary.txt"
    );
}

fn damage_notice(pure: &mut JsLib, answer: Value, current: &str, now_ms: i64) -> String {
    pure.eval_json(&format!(
        "userSettingsDamageNoticeId({}, {}, {now_ms})",
        lit(&answer),
        lit(&json!(current))
    ))
    .as_str()
    .expect("an id")
    .to_owned()
}

/// The file is damaged while the window runs: the user is told once for the
/// episode, an answer that did not look again keeps the card, and the card
/// goes once the file reads. A damage after that is a new episode, so an
/// earlier dismissal does not silence it.
#[test]
fn a_damaged_settings_file_is_told_once_per_episode() {
    let mut pure = JsLib::pure();
    let damaged = json!({ "stamp": "s2", "changed": false, "unreadable": true, "damaged": true });
    let raised = damage_notice(&mut pure, damaged.clone(), "", 1000);
    assert!(!raised.is_empty(), "the damage is not told");
    assert_eq!(
        damage_notice(&mut pure, damaged.clone(), &raised, 4000),
        raised,
        "the same episode is told again"
    );
    let unchanged = json!({ "stamp": "s2", "changed": false });
    assert_eq!(damage_notice(&mut pure, unchanged, &raised, 7000), raised);
    // A lock or a moment's I/O error is not damage.
    let locked = json!({ "stamp": "s3", "changed": false, "unreadable": true });
    assert_eq!(damage_notice(&mut pure, locked.clone(), "", 8000), "");
    assert_eq!(damage_notice(&mut pure, locked, &raised, 8000), raised);

    let read = json!({ "stamp": "s4", "changed": true, "preferences": {} });
    assert_eq!(
        damage_notice(&mut pure, read, &raised, 10_000),
        "",
        "a file that reads again still shows the card"
    );
    let again = damage_notice(&mut pure, damaged, "", 13_000);
    assert!(!again.is_empty());
    assert_ne!(again, raised, "a dismissed episode silences the next one");
}

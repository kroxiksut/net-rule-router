//! The tray's "Add rule…": with the main window shown, the window's own form
//! takes the rule; with the window closed to the tray, the tray's small form
//! does, and the hidden window re-reads its table and files when that rule
//! lands. Deciding by "the window runs" instead brought back a window the user
//! had closed, and a hidden window that missed the tray's apply later offered
//! to push its stale table over the new rule.

use std::path::{Path, PathBuf};

fn qml(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The body of `function <name>(` in `source`, up to the first line that
/// closes it at the function's own indent.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let head = format!("function {name}(");
    let start = source.find(&head).unwrap_or_else(|| panic!("no `{head}`"));
    let indent = source[..start]
        .rsplit('\n')
        .next()
        .map_or(0, |line| line.len());
    let close = format!("\n{}}}", " ".repeat(indent));
    let end = source[start..]
        .find(&close)
        .map_or(source.len(), |at| start + at);
    &source[start..end]
}

/// Why the tray's hand-off to the window would not follow what the user sees.
fn hand_off_fault(tray: &str) -> Option<&'static str> {
    let body = function_body(tray, "openAddRule");
    if body.contains("windowRunning") {
        return Some("decides by a running window, which may be hidden");
    }
    if !body.contains(".windowVisible") {
        return Some("does not look at whether the window is shown");
    }
    if !body.contains("triggerAction(\"add-rule\")") {
        return Some("never hands the rule to the window");
    }
    None
}

#[test]
fn the_window_takes_the_rule_only_while_the_user_sees_it() {
    let tray = qml("Tray.qml");
    assert_eq!(hand_off_fault(&tray), None);

    let mut mutated = tray.clone();
    if let Some(at) = mutated.find("guiPresence.read().windowVisible") {
        mutated.replace_range(at..at + 32, "guiPresence.read().windowRunning");
    }
    assert!(
        hand_off_fault(&mutated).is_some(),
        "the check does not see a hand-off by a running window"
    );
}

#[test]
fn a_hidden_window_follows_a_rule_the_tray_added() {
    // The tray's form applies under its own origins.
    let window = qml("components/TrayRuleWindow.qml");
    let origins: Vec<&str> = window
        .match_indices("submitter.applyNow(json, \"")
        .map(|(at, head)| {
            let rest = &window[at + head.len()..];
            &rest[..rest.find('"').unwrap_or(0)]
        })
        .collect();
    assert_eq!(origins.len(), 2, "the add and its undo: {origins:?}");
    for origin in &origins {
        assert!(
            origin.starts_with("tray-add-rule"),
            "`{origin}` escapes what the window listens for"
        );
    }
    let pure = qml("lib/pure.js");
    assert!(
        function_body(&pure, "newCorrelationId").contains("\"rules-update-\" + origin"),
        "the correlation id no longer starts with its origin"
    );

    // The window, shown or hidden, re-reads on those applies.
    let main = qml("Main.qml");
    let listens = main.find("mpCorr.indexOf(\"rules-update-tray-add-rule-\") === 0");
    let follows = main.find("boundFilesController.handleRulesAddedFromTray()");
    assert!(
        matches!((listens, follows), (Some(a), Some(b)) if a < b && b - a < 200),
        "the window does not re-read when the tray's form applies"
    );
}

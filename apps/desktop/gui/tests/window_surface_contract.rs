//! Every `root.X` a flow controller reaches for must exist on the window.
//!
//! The QML shell was decomposed into controllers that receive the
//! ApplicationWindow as `property var root`. QML resolves `root.X` at RUN time
//! and answers `undefined` for a name that is not there — so a controller
//! calling a helper the window never exposed compiles, lints and installs
//! cleanly, and fails only when a user reaches that screen.
//!
//! That is not hypothetical: one decomposition shipped a GUI that would not
//! start, with five defects of exactly this shape, and neither the build nor
//! `qmllint` caught a single one. This test walks the reachable surface
//! instead.
//!
//! ## Only `flows/`
//!
//! A controller there declares `property var root` and means the window by it.
//! In `components/` the same word is usually the file's OWN `id`, so scanning
//! those would drown the real defects in false positives — the check is scoped
//! to the files where `root` provably means the window.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn qml_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("apps/desktop/qml")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Strip `//` comments so a name mentioned in prose is not mistaken for a use.
/// Block comments are left alone: the tree does not use them for code, and a
/// half-correct stripper is worse than an honest one.
fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| match line.find("//") {
            // Not inside a string literal — the QML in this tree never has a
            // `//` inside one on a line that also declares a member.
            Some(at) if line[..at].matches('"').count() % 2 == 0 => &line[..at],
            _ => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Members `ApplicationWindow` inherits from Qt rather than declaring here.
///
/// A controller calling `root.close()` is correct; the window simply never
/// writes that member down, because Qt already did. Kept short and explicit —
/// a broad allowance ("anything short", "anything lowercase") would swallow
/// the very typos this test exists to catch.
const INHERITED_FROM_QT: &[&str] = &[
    "close",
    "show",
    "hide",
    "showNormal",
    "showMaximized",
    "showMinimized",
    "raise",
    "requestActivate",
    "visible",
    "visibility",
    "active",
    "width",
    "height",
    "x",
    "y",
    "title",
    "opacity",
    "palette",
    "font",
    "contentItem",
    "activeFocusItem",
    "screen",
];

/// Names the ApplicationWindow exposes: properties, aliases, functions,
/// signals, and the ids of its direct children (reachable as `root.<id>` only
/// when aliased, which is why aliases are collected too).
fn window_surface() -> BTreeSet<String> {
    let main = without_line_comments(&read(&qml_root().join("Main.qml")));
    let mut names: BTreeSet<String> = INHERITED_FROM_QT.iter().map(|s| (*s).to_string()).collect();
    for line in main.lines() {
        let line = line.trim();
        let declared = declared_name(line);
        if let Some(name) = declared {
            names.insert(name);
        }
    }
    names
}

/// The member a declaration line introduces, if it introduces one.
///
/// Four shapes, and the separator is what tells them apart:
///   `property var prefs: (…)`   → head `var prefs`  → the LAST token names it
///   `property var root`          → head `var root`   → same
///   `property alias rulesModel: rulesModel` (after `alias ` is stripped)
///                                → head `rulesModel` → the ONLY token
///   `function tr(key, fallback)` → head `tr`         → the only token
fn declared_name(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("readonly property ")
        .or_else(|| line.strip_prefix("property "))
        .or_else(|| line.strip_prefix("function "))
        .or_else(|| line.strip_prefix("signal "))?;
    let rest = rest.strip_prefix("alias ").unwrap_or(rest);
    // Everything before the value or the argument list is the declaration head.
    let head = rest.split([':', '(', '{']).next()?.trim();
    let name = head.split_whitespace().next_back()?;
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .then(|| name.to_string())
}

/// `flows/*.qml` files that take the window as `root`.
fn window_scoped_flows() -> Vec<PathBuf> {
    let dir = qml_root().join("flows");
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read dir {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "qml") {
            continue;
        }
        if read(&path).contains("property var root") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// Every `root.<name>` a file reaches for.
fn root_uses(source: &str) -> BTreeSet<String> {
    let text = without_line_comments(source);
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(at) = text[from..].find("root.") {
        let start = from + at;
        from = start + "root.".len();
        // `myRoot.` / `ownerRoot.` are different objects.
        if start > 0 {
            let before = bytes[start - 1] as char;
            if before.is_alphanumeric() || before == '_' || before == '.' {
                continue;
            }
        }
        let name: String = text[from..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

#[test]
fn every_root_reference_in_a_flow_exists_on_the_window() {
    let surface = window_surface();
    assert!(
        surface.contains("prefs") && surface.contains("uiTheme"),
        "the surface scraper found nothing recognisable — it is broken, not the tree"
    );

    let mut missing: Vec<String> = Vec::new();
    for path in window_scoped_flows() {
        for name in root_uses(&read(&path)) {
            if !surface.contains(&name) {
                missing.push(format!("{}: root.{name}", path.display()));
            }
        }
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "these controllers reach for names the window does not expose — QML answers \
         `undefined` at run time, so nothing fails until a user opens the screen:\n  {}",
        missing.join("\n  ")
    );
}

/// Positive control: the scraper must actually be able to MISS a name, or the
/// test above passes by being blind rather than by the tree being correct.
#[test]
fn a_name_the_window_does_not_expose_is_detected() {
    let surface = window_surface();
    let invented = root_uses("something(root.thisMemberDoesNotExistOnTheWindow)");
    assert_eq!(invented.len(), 1, "the use scraper found no reference");
    assert!(
        !surface.contains("thisMemberDoesNotExistOnTheWindow"),
        "the surface scraper claims a name that was never declared"
    );
}

/// The use scraper must not count a DIFFERENT object's `root`.
#[test]
fn another_objects_root_is_not_the_window() {
    let uses = root_uses("ownerRoot.foo + myRoot.bar + root.realOne");
    assert_eq!(uses.into_iter().collect::<Vec<_>>(), vec!["realOne"]);
}

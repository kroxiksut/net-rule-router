//! A risk signal's text may name a value twice ("*.{apex} already covers
//! {apex} itself"). `String.replace` with a string pattern fills only the
//! first, and the review window showed a raw `{apex}`. The dialog fills its
//! signals through `Pure.fillPlaceholders`, which replaces every occurrence.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn review_signals_are_filled_through_the_shared_filler() {
    let dialog = repo_file("apps/desktop/qml/components/ReviewDiffDialog.qml");
    let start = dialog
        .find("function renderSignal(")
        .unwrap_or_else(|| panic!("renderSignal is gone"));
    let rest = &dialog[start..];
    let body = &rest[..rest[1..]
        .find("\n    function ")
        .map_or(rest.len(), |at| at + 1)];
    assert!(
        body.contains("Pure.fillPlaceholders("),
        "risk signals must be filled by the shared filler"
    );
    assert!(
        !body.contains(".replace(\"{"),
        "a single-string replace fills only the first occurrence of a placeholder"
    );
}

#[test]
fn the_overlap_signal_really_names_its_apex_twice() {
    let ru = repo_file("locales/ru.json");
    let line = ru
        .lines()
        .find(|l| l.trim_start().starts_with("\"overlapping-rules\""))
        .unwrap_or_else(|| panic!("risk.signal.overlapping-rules is gone"));
    assert!(
        line.matches("{apex}").count() >= 2,
        "the case this guards against: one placeholder used twice"
    );
}

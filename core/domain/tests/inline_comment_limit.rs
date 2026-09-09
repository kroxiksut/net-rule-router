//! One number for "how long may a rule's label be", in the two places that
//! hold it.
//!
//! The rules-file validator rejects an entry whose inline comment runs past
//! `MAX_INLINE_COMMENT_CHARS`; the edit dialog stops typing at its own literal
//! `200`. QML cannot read Rust constants, so that literal is a real copy, and a
//! copy with nothing holding it drifts. Drift here is not cosmetic in either
//! direction: raise the dialog's number and the user writes a label that the
//! import then refuses; lower it and the dialog forbids a label the format
//! accepts.

#![allow(clippy::expect_used)]

use nrr_domain::preset_validation::MAX_INLINE_COMMENT_CHARS;

/// The integer assigned to `name` in a QML `readonly property int` line.
fn qml_int_property(source: &str, name: &str) -> i64 {
    let needle = format!("property int {name}:");
    let line = source
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| panic!("no `property int {name}` in the QML source"));
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
fn the_edit_dialog_and_the_validator_agree_on_the_comment_limit() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/desktop/qml/components/RuleEditDialog.qml");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert_eq!(
        qml_int_property(&source, "commentMaxLength"),
        MAX_INLINE_COMMENT_CHARS as i64,
        "the dialog's cap and the format's cap must be one number"
    );
}

#[test]
fn the_qml_reader_actually_reads_the_literal() {
    // Positive control: a wrong name must fail loudly rather than quietly
    // return a default that would match anything.
    assert_eq!(
        qml_int_property("    readonly property int demoCap: 4242\n", "demoCap"),
        4242
    );
}

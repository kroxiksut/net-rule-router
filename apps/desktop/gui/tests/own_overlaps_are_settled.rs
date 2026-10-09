//! An overlap the user made on purpose is not asked about again: a rule saved
//! from the rule dialog settles the exceptions it makes, while a pasted list,
//! an import or a suggestion does not. The dialog says what the rule overlaps
//! in the overlaps table's own words. The decision itself is pinned by the
//! vectors in `core/client-logic` (`overlapsConfirmedByOwnEdit`).
#![allow(clippy::expect_used)]

use std::path::Path;

fn qml(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of `function <name>(` up to the next top-level `function `.
fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let head = format!("function {name}(");
    let at = source
        .find(&head)
        .unwrap_or_else(|| panic!("no function {name}"));
    let rest = &source[at + head.len()..];
    let end = rest.find("\n    function ").unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn only_the_rule_dialog_save_notes_an_own_edit() {
    let main = qml("Main.qml");
    assert!(
        function_body(&main, "saveRule").contains("ruleOverlapsController.noteOwnEdit(item.id)"),
        "a rule saved from the dialog must settle the exceptions it makes"
    );
    assert!(
        !function_body(&main, "saveRuleList").contains("noteOwnEdit"),
        "a pasted list is not an exception the user wrote one by one"
    );
    assert_eq!(
        main.matches("noteOwnEdit(").count(),
        1,
        "imports, presets and suggestions must not settle overlaps"
    );
}

#[test]
fn a_stale_pass_does_not_settle_an_edit_it_has_not_read() {
    let main = qml("Main.qml");
    assert!(main.contains("ok && !_rulesOverlapStale)"));
    let controller = qml("flows/RuleOverlapsController.qml");
    let update = function_body(&controller, "update");
    assert!(update.contains("fresh === false"));
    assert!(update.contains("Pure.overlapsConfirmedByOwnEdit(overlaps, _ownEdits)"));
}

#[test]
fn the_dialog_and_the_table_say_a_pair_in_one_sentence() {
    let dialog = qml("components/RuleEditDialog.qml");
    assert!(dialog.contains("root.ruleOverlapsController.explain(pairs[i], candidate)"));
    let section = qml("sections/RuleOverlapsSection.qml");
    assert!(section.contains("section.controller.explain(overlap)"));
    assert!(
        !section.contains("\"rules.overlaps.nested\""),
        "the sentence is built once, in the controller"
    );
}

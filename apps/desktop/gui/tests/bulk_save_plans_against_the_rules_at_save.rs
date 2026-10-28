//! "Several rules" saves what the rules at Save make of the text, not the plan
//! drawn while typing: the tray's form re-reads the rules from the service on
//! Save, and a line planned against the old ones — its value meanwhile on
//! another route — was neither added nor given back. How the plan treats such
//! a line is tested on the real `rules.js` in
//! `core/client-logic/tests/bulk_save_keeps_every_line.rs`; this holds the two
//! forms to calling it, and the tray to giving the lines back.

use std::path::{Path, PathBuf};

fn qml(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The body of `function <name>(` (or the `onAccepted:` handler) in `source`,
/// up to the line that closes it at its own indent.
fn block<'a>(source: &'a str, head: &str) -> &'a str {
    let start = source.find(head).unwrap_or_else(|| panic!("no `{head}`"));
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

/// Why `dialog` and `tray` would save a plan drawn against old rules, or drop
/// the lines the save did not take.
fn fault(dialog: &str, tray: &str) -> Option<&'static str> {
    let accept = block(dialog, "onAccepted: {");
    if !accept.contains("Rules.planBulkSubmission(bulkPlanInput(), root.rulesModel)")
        || !accept.contains("root.saveBulkRules(plan)")
    {
        return Some("the form saves the plan it drew while the user typed");
    }
    let submit = block(tray, "function _submitBulk(");
    let reread = submit.find("_loadRows(").unwrap_or(usize::MAX);
    let planned = submit
        .find("Rules.planBulkSubmission(ruleDialog.bulkPlanInput(), trayRuleWindow._rows)")
        .unwrap_or(0);
    if planned < reread {
        return Some("the tray does not plan again against the rules it re-read");
    }
    if !submit.contains("_giveBackRemaining()")
        || !block(tray, "function _succeeded(").contains("_giveBackRemaining()")
    {
        return Some("the tray does not give back the lines it did not take");
    }
    if block(tray, "function _giveBackRemaining(").contains("&& visible") {
        return Some("the lines are given back only while the window is up");
    }
    None
}

#[test]
fn both_forms_save_what_the_rules_at_save_make_of_the_text() {
    let dialog = qml("components/RuleEditDialog.qml");
    let tray = qml("components/TrayRuleWindow.qml");
    assert_eq!(fault(&dialog, &tray), None);

    let old_dialog = dialog.replace(
        "var plan = Rules.planBulkSubmission(bulkPlanInput(), root.rulesModel)",
        "var plan = bulkPlan",
    );
    assert!(
        fault(&old_dialog, &tray).is_some(),
        "the check misses a form saving its old plan"
    );
}

#[test]
fn undo_writes_the_restored_comments() {
    let tray = qml("components/TrayRuleWindow.qml");
    let undo = block(&tray, "function undoAddition(");
    assert!(
        undo.contains("support.writeComment(plan.comments[c])"),
        "a moved rule goes back without its comment under the old route"
    );
}

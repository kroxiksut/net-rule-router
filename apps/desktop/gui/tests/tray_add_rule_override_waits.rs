//! A program added from the tray with `+override` is held by the protection
//! of system programs until the user confirms it in the window's rules list:
//! the tray's outcome says so and offers the way there, instead of "added".
//! How the flag is read is tested on the real `rules.js` against the service's
//! parser in `core/client-logic/tests/override_flag.rs`.

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
fn the_tray_outcome_names_the_confirmation_and_opens_the_rules() {
    let window = repo_file("apps/desktop/qml/components/TrayRuleWindow.qml");
    assert!(
        window.contains("Rules.ruleValueAsksOverride(rows[i].ruleType, rows[i].matchValue)"),
        "the outcome no longer looks at the +override flag"
    );
    assert!(
        window.contains("tr(\"tray.add-rule.added-awaits-confirmation\","),
        "a held rule is reported as plainly added"
    );
    assert!(
        window.contains("Rules.additionUndoRecord(plan), _awaitsConfirmation(plan))"),
        "the notice is not told that the rule waits"
    );
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(tray.contains("function noteAddRuleOutcome(bodyText, undo, awaitsConfirmation)"));
    assert!(
        tray.matches("\"tray-add-rule-open-rules\"").count() >= 2,
        "the way to the rules list is offered but not handled"
    );
    for locale in ["locales/en.json", "locales/ru.json"] {
        assert!(
            repo_file(locale).contains("\"added-awaits-confirmation\":"),
            "{locale} lacks tray.add-rule.added-awaits-confirmation"
        );
    }
}

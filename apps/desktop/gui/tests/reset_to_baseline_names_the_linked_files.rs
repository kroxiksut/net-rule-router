//! "Reset to baseline" drops the user's own rules, and the window (or the tray,
//! with the window closed) then writes the baseline into the linked rules
//! files. The review says so before the user agrees, whenever a file is linked.

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_reset_review_says_the_linked_files_take_the_baseline() {
    let dialog = repo_file("apps/desktop/qml/components/ReviewDiffDialog.qml");
    let reset = dialog
        .find("reset-to-baseline;")
        .map(|at| &dialog[at..])
        .and_then(|rest| {
            rest.find("// The service's apply-plan")
                .map(|end| &rest[..end])
        })
        .expect("the reset branch of diffSummaryText");
    assert!(
        reset.contains("dialog.review-diff.reset-files") && reset.contains("_linkedRulesFiles()"),
        "the reset review is silent about the linked files it rewrites: {reset}"
    );
    let linked = dialog
        .find("function _linkedRulesFiles()")
        .map(|at| &dialog[at..])
        .expect("_linkedRulesFiles");
    assert!(
        linked.contains("lastSavedPathPrimary") && linked.contains("lastSavedPathSecondary"),
        "both routes' linked files count"
    );
    for locale in ["locales/en.json", "locales/ru.json"] {
        assert!(
            repo_file(locale).contains("\"reset-files\""),
            "{locale} lacks the line"
        );
    }
}

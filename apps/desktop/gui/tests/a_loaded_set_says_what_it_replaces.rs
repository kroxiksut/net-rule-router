#![allow(clippy::expect_used)]

//! "Load" on the rule-set row replaces the user's own rules on the routes the
//! set covers, and the review said so only by listing them under Removed. The
//! review says it in words, with the count, before the user agrees; a merge
//! and every other kind of review say nothing of the sort.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

#[test]
fn a_replacing_load_counts_the_rules_it_takes_away() {
    let output = js::run_js(&format!(
        "{}\n\
         var removed = {{ 'rules-removed': [{{}}, {{}}, {{}}] }};\n\
         console.log(rulesReplacedByLoad('preset-import', {{ mode: 'replace' }}, removed));\n\
         console.log(rulesReplacedByLoad('preset-import', {{ mode: 'merge' }}, removed));\n\
         console.log(rulesReplacedByLoad('rules-update', {{ mode: 'replace' }}, removed));\n\
         console.log(rulesReplacedByLoad('preset-import', {{ mode: 'replace' }}, {{ 'rules-removed': [] }}));",
        qml_functions::pure()
    ));
    assert_eq!(output, "3\n0\n0\n0\n");
}

#[test]
fn the_review_says_it_before_the_user_agrees() {
    let dialog = qml_functions::read("components/ReviewDiffDialog.qml");
    assert!(
        dialog.contains("Pure.rulesReplacedByLoad(root.ownerRoot._activeReviewKind"),
        "the review does not say that the load replaces the user's rules"
    );
    assert!(
        dialog.contains("\"dialog.review-diff.replaces-own.\""),
        "the warning has no words of its own"
    );
}

//! The rules table showed "Main ?" for a rule the program checks on its
//! route: the rules file's `?` means nothing to someone who never wrote one.
//! Every screen says it in a word after the route, "Main (checking)".

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

use std::path::Path;

/// Lines of `source` that put a bare `?` after a route.
fn bare_marks(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or_default();
            code.contains("\" ?\"")
        })
        .map(|(at, _)| at + 1)
        .collect()
}

#[test]
fn no_screen_marks_a_route_with_a_bare_question_mark() {
    let mut faults = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "qml") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                for line in bare_marks(&source) {
                    faults.push(format!("{}:{line}", path.display()));
                }
            }
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn the_merge_review_says_checking_after_the_route() {
    let program = [
        "function tr(key, fallback) { return fallback }",
        &qml_functions::functions(
            "components/MergeReviewDialog.qml",
            &["_routeLabel", "_itemRouteLabel"],
        ),
        "console.log(_itemRouteLabel({ route: 'primary', action: 'verify-primary' }));",
        "console.log(_itemRouteLabel({ route: 'secondary', action: '' }));",
    ]
    .join("\n");
    let output = js::run_js(&program);
    assert_eq!(output, "Main (checking)\nAdditional\n");
}

#[test]
fn a_bare_mark_is_caught() {
    assert_eq!(
        bare_marks("text: label + (unsure ? \" ?\" : \"\")\n"),
        vec![1]
    );
}

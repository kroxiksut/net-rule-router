//! A translated log line fills its placeholders once: a value that itself
//! reads like a placeholder or a `String.replace` pattern stays literal, and a
//! translation left with a hole gives way to the English source line.
//! Runs the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_logs_view_formats_through_the_one_pass_helper() {
    let source = repo_file("apps/desktop/qml/sections/LogsSection.qml");
    assert!(
        source.contains("Pure.formatLogLine("),
        "LogsSection.qml no longer fills placeholders through pure.js"
    );
}

#[test]
fn placeholders_are_filled_in_one_pass() {
    let harness = format!(
        "{source}\n\
         console.log(formatLogLine('{{a}} and {{a}}, {{b}}', 'src', {{ a: '{{b}}', b: 'x' }}, []));\n\
         console.log(formatLogLine('corr {{0}} / {{1}} / {{0}}', 'src', {{}}, [\"$& $' $$\", 'k']));\n\
         console.log(formatLogLine('{{n}}', 'src', {{ n: 0 }}, undefined));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let output = js::run_js(&harness);
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines,
        ["{b} and {b}, x", "corr $& $' $$ / k / $& $' $$", "0",],
        "{output}"
    );
}

#[test]
fn a_translation_with_an_unfilled_placeholder_shows_the_english_source() {
    let harness = format!(
        "{source}\n\
         console.log(formatLogLine('{{missing}} {{2}}', 'apply failed: {{raw}}', null, ['only']));\n\
         console.log(formatLogLine('{{host}}: {{gone}}', 'probe failed', {{ host: 'h.example' }}, []));\n\
         console.log(formatLogLine('plain text', 'plain text', {{}}, []));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let output = js::run_js(&harness);
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines,
        ["apply failed: {raw}", "probe failed", "plain text"],
        "{output}"
    );
}

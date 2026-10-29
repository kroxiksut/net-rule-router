//! A keyboard user who Tabs into a list sees that the list holds focus and
//! which row the arrows are on. The rules list starts with no current row, so
//! Tab landed in it with nothing on screen changing.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

fn qml_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn qml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("list qml dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            qml_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("qml") {
            out.push(path);
        }
    }
}

/// The text of the object opened by the `{` on `line`, braces balanced.
fn block_from(lines: &[&str], line: usize) -> String {
    let mut depth = 0usize;
    let mut out = String::new();
    for text in &lines[line..] {
        out.push_str(text);
        out.push('\n');
        depth += text.matches('{').count();
        depth = depth.saturating_sub(text.matches('}').count());
        if depth == 0 {
            break;
        }
    }
    out
}

/// Lists in `source` the arrow keys move through, and what each fails to show.
fn list_faults(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut faults = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if line.trim() != "ListView {" {
            continue;
        }
        let block = block_from(&lines, at);
        if !block.contains("keyNavigationEnabled: true") {
            continue;
        }
        let Some(id) = block
            .lines()
            .find_map(|l| l.trim().strip_prefix("id: "))
            .map(str::trim)
        else {
            faults.push(format!("line {}: a keyboard list without an id", at + 1));
            continue;
        };
        let focus = format!("{id}.activeFocus");
        if !source.contains(&focus) {
            faults.push(format!(
                "line {}: {id} draws nothing when it takes focus",
                at + 1
            ));
        }
        let starts_empty = block.lines().any(|l| l.trim() == "currentIndex: -1");
        let no_row = format!("{id}.currentIndex < 0");
        if starts_empty
            && !source
                .lines()
                .any(|l| l.contains(&focus) && l.contains(&no_row))
        {
            faults.push(format!(
                "line {}: {id} shows no focus before a row is current",
                at + 1
            ));
        }
    }
    faults
}

#[test]
fn every_keyboard_list_shows_where_focus_is() {
    let mut files = Vec::new();
    qml_files(&qml_dir(), &mut files);
    let mut faults = Vec::new();
    let mut seen = 0;
    for file in files {
        let source = std::fs::read_to_string(&file)
            .expect("read qml")
            .replace("\r\n", "\n");
        seen += source.matches("keyNavigationEnabled: true").count();
        for fault in list_faults(&source) {
            faults.push(format!("{}: {fault}", file.display()));
        }
    }
    assert!(
        seen >= 3,
        "the rules list and the dialog lists were not found"
    );
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn a_list_that_starts_without_a_row_and_shows_no_focus_is_caught() {
    let source =
        "ListView {\n    id: rows\n    keyNavigationEnabled: true\n    currentIndex: -1\n}\n";
    assert_eq!(list_faults(source).len(), 2);
}

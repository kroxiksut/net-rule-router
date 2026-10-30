//! A scrollbar beside a page that fits reads as "there is more below" and
//! sends the user looking for it. The style hides an idle bar by itself, but
//! a bar that draws its own handle or track is shown by nobody but its own
//! `visible`: the welcome window's bar stood beside every page that fitted.

use std::path::{Path, PathBuf};

fn qml_files() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "qml") {
                let source = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
                    .replace("\r\n", "\n");
                files.push((path, source));
            }
        }
    }
    files
}

/// Lines of scrollbars that draw their own parts and are not hidden when
/// their content fits.
fn always_drawn_bars(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if !line.trim_end().ends_with("ScrollBar {") {
            continue;
        }
        let mut depth = 0i32;
        let mut drawn = false;
        let mut hidden = false;
        for body in &lines[at..] {
            let trimmed = body.trim_start();
            if depth == 1 {
                drawn |= trimmed.starts_with("contentItem:") || trimmed.starts_with("background:");
                hidden |= trimmed.starts_with("visible:")
                    && ["contentHeight", "contentWidth", "size"]
                        .iter()
                        .any(|measure| trimmed.contains(measure));
            }
            depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
            if depth <= 0 {
                break;
            }
        }
        if drawn && !hidden {
            found.push(at + 1);
        }
    }
    found
}

#[test]
fn a_scrollbar_drawn_by_the_app_shows_only_when_there_is_something_to_scroll() {
    let mut faults = Vec::new();
    for (path, source) in qml_files() {
        for line in always_drawn_bars(&source) {
            faults.push(format!("{}:{line}", path.display()));
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn a_bar_with_its_own_handle_and_no_visibility_is_caught() {
    let bar = "ScrollView {\n    ScrollBar.vertical: ScrollBar {\n        policy: ScrollBar.AsNeeded\n        contentItem: Rectangle { implicitWidth: 8 }\n    }\n}\n";
    assert_eq!(always_drawn_bars(bar), vec![2]);
    let hidden = "ScrollBar.vertical: ScrollBar {\n    visible: view.contentHeight > view.height\n    contentItem: Rectangle {}\n}\n";
    assert!(always_drawn_bars(hidden).is_empty());
}

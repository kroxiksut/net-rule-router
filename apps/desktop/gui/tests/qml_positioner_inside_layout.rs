//! A `Flow`/`Row`/`Column`/`Grid` placed straight inside a `*Layout` reports a
//! single-row implicit size, so the card holding it is sized for one row and a
//! wrapped second row draws over whatever follows (LESSONS_LEARNED, recipe
//! 32). The fix is an `Item` the layout sees, holding the positioner anchored
//! to its width. This test keeps bare positioners out of every layout.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

const POSITIONERS: [&str; 4] = ["Flow", "Row", "Column", "Grid"];

fn qml_root() -> PathBuf {
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

/// The type an object opens with: `Type {` or `name: Type {`.
fn opened_type(before: &str) -> Option<String> {
    let text = before.trim();
    let text = text.rsplit(':').next().unwrap_or(text).trim();
    let first = text.chars().next()?;
    (first.is_ascii_uppercase()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.'))
    .then(|| text.to_string())
}

/// Lines where a positioner opens directly inside a `*Layout`. Strings and
/// comments are skipped so a brace inside them does not move the scope.
fn bare_positioners(source: &str) -> Vec<usize> {
    let mut scopes: Vec<Option<String>> = Vec::new();
    let mut found = Vec::new();
    let mut in_block_comment = false;
    for (index, line) in source.lines().enumerate() {
        let chars: Vec<char> = line.chars().collect();
        let mut quote: Option<char> = None;
        let mut segment_start = 0;
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if in_block_comment {
                if c == '*' && next == Some('/') {
                    i += 1;
                    in_block_comment = false;
                    segment_start = i + 1;
                }
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            match c {
                '"' | '\'' | '`' => quote = Some(c),
                '/' if next == Some('/') => break,
                '/' if next == Some('*') => {
                    in_block_comment = true;
                    i += 1;
                }
                '{' => {
                    let before: String = chars[segment_start.min(i)..i].iter().collect();
                    let opened = opened_type(&before);
                    let parent_is_layout = scopes
                        .last()
                        .and_then(Option::as_deref)
                        .is_some_and(|t| t.ends_with("Layout"));
                    if parent_is_layout
                        && opened.as_deref().is_some_and(|t| POSITIONERS.contains(&t))
                    {
                        found.push(index + 1);
                    }
                    scopes.push(opened);
                    segment_start = i + 1;
                }
                '}' => {
                    scopes.pop();
                    segment_start = i + 1;
                }
                ';' => segment_start = i + 1,
                _ => {}
            }
            i += 1;
        }
    }
    found
}

#[test]
fn no_new_positioner_sits_bare_in_a_layout() {
    let root = qml_root();
    let mut files = Vec::new();
    qml_files(&root, &mut files);
    assert!(files.len() > 20, "the QML tree was found");
    let mut offences = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .expect("read qml")
            .replace("\r\n", "\n");
        let relative = file
            .strip_prefix(&root)
            .expect("under the qml root")
            .to_string_lossy()
            .replace('\\', "/");
        let lines = bare_positioners(&text);
        if !lines.is_empty() {
            offences.push(format!(
                "{relative}: bare positioner inside a layout at line(s) {lines:?} \
                 (wrap it in an Item, LESSONS_LEARNED recipe 32)"
            ));
        }
    }
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// Positive control: the scanner flags the shape that overlapped the next
/// notification card, and leaves alone a wrapped positioner and a string.
#[test]
fn the_scanner_finds_a_bare_positioner_and_only_that() {
    let bare = "ColumnLayout {\n    Flow {\n        Layout.fillWidth: true\n    }\n}\n";
    assert_eq!(bare_positioners(bare), vec![2]);

    let wrapped = "ColumnLayout {\n    Item {\n        Layout.fillWidth: true\n        Flow {\n            id: f\n        }\n    }\n    property string s: \"Flow {\"\n    // Flow {\n}\n";
    assert!(bare_positioners(wrapped).is_empty());

    let named = "RowLayout {\n    delegate: Row {\n    }\n}\n";
    assert_eq!(bare_positioners(named), vec![2]);
}

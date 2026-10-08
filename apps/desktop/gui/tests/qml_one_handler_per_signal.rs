//! Two `onX:` handlers in one QML object make the object fail to load
//! ("Property value set multiple times"), and a component that fails takes
//! every file using it down — one duplicated handler in the rule dialog left
//! the main window unable to open at all. qmllint does not report it, so this
//! test reads every QML file for it.

#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};

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

/// `(line, handler)` for every handler named twice in the same `{ }` scope.
/// Strings and comments are skipped so a brace inside them does not move the
/// scope.
fn duplicate_handlers(source: &str) -> Vec<(usize, String)> {
    let mut scopes: Vec<HashSet<String>> = vec![HashSet::new()];
    let mut found = Vec::new();
    let mut in_block_comment = false;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        if !in_block_comment {
            if let Some(name) = handler_name(trimmed) {
                let scope = scopes.last_mut().expect("a scope is always open");
                if !scope.insert(name.clone()) {
                    found.push((index + 1, name));
                }
            }
        }
        let mut chars = line.chars().peekable();
        let mut quote: Option<char> = None;
        while let Some(c) = chars.next() {
            if in_block_comment {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            match quote {
                Some(q) => {
                    if c == '\\' {
                        chars.next();
                    } else if c == q {
                        quote = None;
                    }
                }
                None => match c {
                    '"' | '\'' | '`' => quote = Some(c),
                    '/' if chars.peek() == Some(&'/') => break,
                    '/' if chars.peek() == Some(&'*') => {
                        chars.next();
                        in_block_comment = true;
                    }
                    '{' => scopes.push(HashSet::new()),
                    '}' => {
                        if scopes.len() > 1 {
                            scopes.pop();
                        }
                    }
                    _ => {}
                },
            }
        }
    }
    found
}

/// `onSomething` when the line starts a handler binding (`onSomething:`).
fn handler_name(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("on")?;
    let first = rest.chars().next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }
    let name_len = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    rest[name_len..]
        .trim_start()
        .starts_with(':')
        .then(|| format!("on{}", &rest[..name_len]))
}

#[test]
fn no_qml_object_handles_a_signal_twice() {
    let mut files = Vec::new();
    qml_files(&qml_root(), &mut files);
    assert!(files.len() > 20, "the QML tree was found");
    let mut offences = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read qml");
        for (line, name) in duplicate_handlers(&text) {
            offences.push(format!("{}:{line}: second {name}", file.display()));
        }
    }
    assert!(offences.is_empty(), "{}", offences.join("\n"));
}

/// Positive control: the scanner sees the shape that broke the window, and
/// leaves alone the same name in a nested object, a string or a comment.
#[test]
fn the_scanner_finds_a_second_handler_and_only_that() {
    let broken =
        "Dialog {\n    onOpened: a()\n    property string s: \"{\"\n    onOpened: b()\n}\n";
    assert_eq!(
        duplicate_handlers(broken),
        vec![(4, "onOpened".to_string())]
    );

    let fine = "Dialog {\n    onOpened: a()\n    // onOpened: old()\n    Item {\n        onOpened: c()\n    }\n}\n";
    assert!(duplicate_handlers(fine).is_empty());
}

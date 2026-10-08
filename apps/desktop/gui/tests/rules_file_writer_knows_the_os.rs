//! The rules-file writer puts application rules under the section of the OS
//! it runs on, and only that OS's parser applies them. A caller that leaves
//! the OS out gets the Windows section, so on Linux the app rules would come
//! back as inert text. Every QML call passes it.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

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

/// Top-level argument count of each `Rules.buildCanonicalRulesText(` call.
fn writer_call_arities(source: &str) -> Vec<usize> {
    let marker = "Rules.buildCanonicalRulesText(";
    let mut arities = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find(marker) {
        rest = &rest[at + marker.len()..];
        let (mut depth, mut commas, mut any) = (0usize, 0usize, false);
        for c in rest.chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => break,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => commas += 1,
                c if !c.is_whitespace() => any = true,
                _ => {}
            }
        }
        arities.push(if any { commas + 1 } else { 0 });
    }
    arities
}

#[test]
fn the_scan_counts_top_level_arguments() {
    assert_eq!(
        writer_call_arities("Rules.buildCanonicalRulesText(m, f(a, b), [1, 2], x)"),
        [4]
    );
    assert_eq!(
        writer_call_arities(
            "Rules.buildCanonicalRulesText(\n m, r, s,\n c, root.platformProfile.os)"
        ),
        [5]
    );
}

#[test]
fn every_qml_writer_call_names_the_os() {
    let qml = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    let mut files = Vec::new();
    qml_files(&qml, &mut files);
    let mut calls = 0;
    let mut short = Vec::new();
    for file in files {
        let source = std::fs::read_to_string(&file).expect("read qml");
        for arity in writer_call_arities(&source) {
            calls += 1;
            if arity != 5 {
                short.push(format!("{} ({arity} arguments)", file.display()));
            }
        }
    }
    assert!(calls > 0, "no writer call found: the scan is broken");
    assert!(short.is_empty(), "calls without the OS: {short:?}");
}

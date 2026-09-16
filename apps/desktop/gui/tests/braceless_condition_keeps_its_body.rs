//! A braceless `if` / `for` / `while` / `else` in the QML shell governs the next
//! statement — whatever that statement is.
//!
//! A block pasted between the condition and its body compiled, passed qmllint
//! and ran: the tray's "re-subscribe only while not subscribed" guard ended up
//! guarding the pasted lines, and the subscribe ran every ten seconds for days.
//! What gives such a paste away is its shape, so the shape is what is checked:
//! the body sits on the very next line, indented deeper, with no comment
//! between it and its condition.

use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "qml" || e == "js") {
            out.push(path);
        }
    }
}

/// `true` when the line is nothing but a condition (or a bare `else`).
fn is_bare_condition(line: &str) -> bool {
    let mut rest = line.trim_start();
    rest = rest.strip_prefix('}').map_or(rest, str::trim_start);
    if rest.trim_end() == "else" {
        return true;
    }
    rest = rest.strip_prefix("else").map_or(rest, str::trim_start);
    let Some(after_keyword) = ["if", "for", "while"]
        .iter()
        .find_map(|k| rest.strip_prefix(k))
        .map(str::trim_start)
    else {
        return false;
    };
    if !after_keyword.starts_with('(') {
        return false;
    }
    let mut depth = 0usize;
    for (i, c) in after_keyword.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return after_keyword[i + 1..].trim().is_empty();
                }
            }
            _ => {}
        }
    }
    false
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

fn detached_bodies(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !is_bare_condition(line) {
            continue;
        }
        let Some(next) = lines.get(i + 1) else {
            continue;
        };
        if next.trim_start().starts_with("//") || indent(next) <= indent(line) {
            found.push((i + 1, line.trim().to_string()));
        }
    }
    found
}

#[test]
fn a_braceless_condition_is_followed_directly_by_its_body() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(!files.is_empty(), "no QML found under {}", root.display());
    let mut offences = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (line, condition) in detached_bodies(&text) {
            offences.push(format!("{}:{line}: {condition}", file.display()));
        }
    }
    assert!(
        offences.is_empty(),
        "a braceless condition is not followed by its body:\n{}",
        offences.join("\n")
    );
}

#[test]
fn the_pasted_block_that_hid_the_tray_subscribe_is_recognised() {
    let pasted = "            if (!subscribed && bridgeAvailable)\n                // themed from a snapshot\n            if (typeof bridge.changed !== \"undefined\") {\n            }\n            subscribe()\n";
    assert_eq!(detached_bodies(pasted).len(), 1);
    let healthy = "            if (!subscribed && bridgeAvailable)\n                subscribe()\n            else\n                log()\n            if (a) { b() }\n";
    assert!(detached_bodies(healthy).is_empty());
}

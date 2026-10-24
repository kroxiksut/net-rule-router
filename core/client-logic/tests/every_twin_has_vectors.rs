#![allow(clippy::expect_used)]

//! Every client-logic `pub fn` whose camelCase name is a function in the GUI's
//! `pure.js` / `rules.js` is a twin, and a twin no `parity*.rs` test calls can
//! drift from its JavaScript unnoticed.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Twins without a vector today. Shrink only: a new twin gets its vector in
/// the same change instead of a line here.
const KNOWN_GAPS: &[&str] = &[
    "app_route_of",
    "is_forwarding_adapter_name",
    "present_adapter_ids",
    "value_is_any_zone",
    "is_usable_set_name",
    "rules_file_folder",
    "security_alerts_unreadable",
];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// The identifier right after `prefix` at the start of each trimmed line.
fn names_after(source: &str, prefix: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix(prefix))
        .map(|rest| {
            rest.chars()
                .take_while(|c| is_ident(*c))
                .collect::<String>()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

fn camel_case(snake: &str) -> String {
    let mut out = String::with_capacity(snake.len());
    let mut upper = false;
    for c in snake.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn mentions_word(haystack: &str, word: &str) -> bool {
    haystack.match_indices(word).any(|(at, _)| {
        let before = haystack[..at].chars().next_back();
        let after = haystack[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

#[test]
fn every_twin_is_called_by_a_parity_test() {
    let lib = crate_dir().join("../../apps/desktop/qml/lib");
    let js_functions: BTreeSet<String> = ["pure.js", "rules.js"]
        .iter()
        .flat_map(|file| names_after(&read(&lib.join(file)), "function "))
        .collect();

    let mut sources = Vec::new();
    rust_files(&crate_dir().join("src"), &mut sources);
    let twins: BTreeSet<String> = sources
        .iter()
        .flat_map(|path| names_after(&read(path), "pub fn "))
        .filter(|name| js_functions.contains(&camel_case(name)))
        .collect();
    assert!(!twins.is_empty(), "no twins found: the scan is broken");

    let tests: String = std::fs::read_dir(crate_dir().join("tests"))
        .expect("read tests")
        .map(|entry| entry.expect("tests entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n| n.starts_with("parity") && n.ends_with(".rs"))
        })
        .map(|path| read(&path))
        .collect();

    let missing: Vec<&str> = twins
        .iter()
        .map(String::as_str)
        .filter(|name| !mentions_word(&tests, name) && !KNOWN_GAPS.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "twins with no parity test (add a vector file and a parity test): {missing:?}"
    );

    let stale: Vec<&str> = KNOWN_GAPS
        .iter()
        .copied()
        .filter(|name| !twins.contains(*name) || mentions_word(&tests, name))
        .collect();
    assert!(
        stale.is_empty(),
        "no longer gaps, drop them from KNOWN_GAPS: {stale:?}"
    );
}

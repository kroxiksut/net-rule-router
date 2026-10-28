#![allow(clippy::expect_used)]

//! A `tr("key", "fallback")` fallback is what the user reads when the locale
//! is missing or a key is absent from a dropped-in language, so it must say
//! what `locales/en.json` says. A fallback that drifted shows an older promise
//! (a button that is gone, an action that no longer exists).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn english() -> BTreeMap<String, String> {
    fn flatten(node: &Value, prefix: &str, out: &mut BTreeMap<String, String>) {
        match node {
            Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    flatten(v, &key, out);
                }
            }
            Value::String(s) => {
                out.insert(prefix.to_owned(), s.clone());
            }
            _ => {}
        }
    }
    let text = std::fs::read_to_string(repo_root().join("locales/en.json")).expect("en.json");
    let json: Value = serde_json::from_str(&text).expect("en.json parses");
    let mut out = BTreeMap::new();
    flatten(&json, "", &mut out);
    out
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "qml" || e == "js") {
            out.push(path);
        }
    }
}

/// A JS string literal starting at `at` (on its quote): its value and the
/// index just past it. `None` for anything that is not a closed literal.
fn literal(src: &[char], at: usize) -> Option<(String, usize)> {
    let quote = *src.get(at)?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    let mut i = at + 1;
    while let Some(&c) = src.get(i) {
        match c {
            '\\' => {
                let next = *src.get(i + 1)?;
                match next {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = src.get(i + 2..i + 6)?.iter().collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                        i += 4;
                    }
                    other => out.push(other),
                }
                i += 2;
            }
            '\n' => return None,
            c if c == quote => return Some((out, i + 1)),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    None
}

fn skip_space(src: &[char], mut i: usize) -> usize {
    while src.get(i).is_some_and(|c| c.is_whitespace()) {
        i += 1;
    }
    i
}

/// Every `tr("key", "lit" + "lit"...)` call whose fallback is literals only.
fn fallbacks(source: &str) -> Vec<(String, String)> {
    let src: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= src.len() {
        let is_call = src[i] == 't'
            && src[i + 1] == 'r'
            && src[i + 2] == '('
            && !(i > 0 && (src[i - 1].is_alphanumeric() || src[i - 1] == '_'));
        if !is_call {
            i += 1;
            continue;
        }
        i += 3;
        let Some((key, after_key)) = literal(&src, skip_space(&src, i)) else {
            continue;
        };
        let comma = skip_space(&src, after_key);
        if src.get(comma) != Some(&',') {
            continue;
        }
        let mut at = skip_space(&src, comma + 1);
        let mut text = String::new();
        let mut pure = false;
        while let Some((part, next)) = literal(&src, at) {
            text.push_str(&part);
            pure = true;
            at = skip_space(&src, next);
            if src.get(at) == Some(&'+') {
                at = skip_space(&src, at + 1);
                pure = false;
            } else {
                break;
            }
        }
        if pure && src.get(at) == Some(&')') {
            out.push((key, text));
        }
        i = at;
    }
    out
}

fn mismatches() -> BTreeSet<String> {
    let english = english();
    let root = repo_root();
    let mut files = Vec::new();
    sources(&root.join("apps/desktop/qml"), &mut files);
    let mut out = BTreeSet::new();
    for file in files {
        let source = std::fs::read_to_string(&file).expect("read QML");
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        for (key, fallback) in fallbacks(&source) {
            if english.get(&key).is_some_and(|en| *en != fallback) {
                out.insert(format!("{relative} {key}"));
            }
        }
    }
    out
}

#[test]
fn every_qml_fallback_says_what_english_says() {
    let found = mismatches();
    assert!(
        found.is_empty(),
        "these tr() fallbacks differ from locales/en.json; copy the English text:\n{}",
        found
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_scan_reads_split_fallbacks_and_skips_computed_ones() {
    let src = "root.tr(\"a.b\",\n  \"one \" +\n  \"two\") + tr('c.d', \"x\" + n) + qsTr(\"e\", \"f\") + tr(\"g.h\", \"it\\'s \\u2026\")";
    assert_eq!(
        fallbacks(src),
        vec![
            ("a.b".to_owned(), "one two".to_owned()),
            ("g.h".to_owned(), "it's \u{2026}".to_owned()),
        ]
    );
}

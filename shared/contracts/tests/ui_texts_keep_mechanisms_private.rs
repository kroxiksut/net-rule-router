//! Every locale text can reach a screen (the Logs view translates tagged log
//! lines, the cache shows its source column) and from there a screenshot.
//! Texts name what the user gets, never the closed mechanisms behind it:
//! how addresses are learned from blocked connections, which sites are let
//! through a block, the internal name of the resolver mode, or a threshold.

use serde_json::Value;
use std::path::Path;

/// Words that name a closed mechanism, per language, lower-cased.
const CLOSED: &[(&str, &[&str])] = &[
    (
        "en",
        &[
            "mode b",
            "reverse lookup",
            "reverse-dns",
            "reverse-confirmed",
            "collateral",
            "direct host",
            "directly-visited",
            "{threshold}",
        ],
    ),
    (
        "ru",
        &[
            "режим б",
            "обратным dns",
            "обратного разрешения",
            "обратного подтвержд",
            "обратное подтвержд",
            "прямой узел",
            "прямыми узлами",
            "побочн",
            "{threshold}",
        ],
    ),
];

fn texts(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                texts(child, &next, out);
            }
        }
        Value::String(text) => out.push((path.to_owned(), text.to_lowercase())),
        _ => {}
    }
}

#[test]
fn locale_texts_do_not_name_closed_mechanisms() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../locales");
    let mut found = Vec::new();
    for (lang, words) in CLOSED {
        let mut all = Vec::new();
        for file in [format!("{lang}.json"), format!("tray/{lang}.json")] {
            let path = root.join(file);
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let document: Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            texts(&document, "", &mut all);
        }
        for (key, text) in &all {
            if key.starts_with("metadata.") {
                continue;
            }
            for word in *words {
                if text.contains(word) {
                    found.push(format!("{lang}: {key} names \"{word}\""));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

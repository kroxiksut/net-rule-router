#![allow(clippy::expect_used)]

//! The application-rule note told the user to "enable «Connection observation»
//! in Settings → Diagnostics" for the rule to work. No such switch exists:
//! the service observes connections whatever the settings say. Every setting
//! the note names in «…» must be one the Settings screen shows.

use std::path::Path;

fn flatten(node: &serde_json::Value, at: &str, out: &mut Vec<(String, String)>) {
    match node {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let key = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                flatten(v, &key, out);
            }
        }
        serde_json::Value::String(s) => out.push((at.to_owned(), s.clone())),
        _ => {}
    }
}

#[test]
fn the_app_rule_note_names_only_settings_that_exist() {
    for locale in ["en", "ru"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(format!("locales/{locale}.json"));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("locale")).expect("JSON");
        let mut all = Vec::new();
        flatten(&json, "", &mut all);
        let labels: Vec<&str> = all
            .iter()
            .filter(|(k, _)| k.starts_with("settings.") && k.ends_with(".label"))
            .map(|(_, v)| v.as_str())
            .collect();
        for (key, text) in all
            .iter()
            .filter(|(k, _)| k.starts_with("rules.application-routing-note"))
        {
            for named in text.split('«').skip(1) {
                let name = named.split('»').next().unwrap_or_default();
                assert!(
                    labels.contains(&name),
                    "{locale} {key} sends the user to «{name}», which Settings does not show"
                );
            }
        }
    }
}

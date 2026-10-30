#![allow(clippy::expect_used)]

//! One action, one wording; one thing, one name. The Russian screens called
//! the main route and the main connection «основной канал» in some places and
//! «маршрут»/«подключение» in others, and the same "send it over this route"
//! action read «Маршрут «…»» on one screen and «Направить через «…»» on the
//! next. A user reading two names takes them for two things.

use std::path::{Path, PathBuf};

fn locale(relative: &str) -> serde_json::Value {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn texts(value: &serde_json::Value, at: &str, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                texts(child, &path, out);
            }
        }
        serde_json::Value::String(s) => out.push((at.to_owned(), s.clone())),
        _ => {}
    }
}

/// Texts where «канал» is a channel in its own right: a news channel, a build
/// channel, the window-to-service control channel, a kernel event channel.
const REAL_CHANNELS: &[&str] = &[
    "action.open-telegram-channel",
    "label.build-channel",
    "label.telegram-channel",
    "settings.service.pipe-path-label",
    "settings.diagnostics.service-stability.",
    "app-groups.footer-note",
    "diag.explain.bridge-unavailable",
    "diag.archive.bridge-unavailable",
    "diag.event.svc-ipc-",
    "diag.event.linux-rtnetlink-",
];

#[test]
fn russian_names_a_route_or_a_connection_never_a_channel() {
    for file in ["locales/ru.json", "locales/tray/ru.json"] {
        let mut all = Vec::new();
        texts(&locale(file), "", &mut all);
        let wrong: Vec<String> = all
            .iter()
            .filter(|(key, text)| {
                text.to_lowercase().contains("канал")
                    && !REAL_CHANNELS.iter().any(|real| key.starts_with(real))
            })
            .map(|(key, text)| format!("{key}: {text}"))
            .collect();
        assert!(wrong.is_empty(), "{file}:\n{}", wrong.join("\n"));
    }
}

#[test]
fn sending_over_a_route_is_one_wording() {
    let qml_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
    for file in [
        "sections/RuleOverlapsSection.qml",
        "sections/RuleSuggestionsSection.qml",
    ] {
        let source = std::fs::read_to_string(qml_root.join(file)).expect("qml");
        assert!(
            source.contains("root.tr(\"rules.action.send-over\""),
            "{file} words the send-over action its own way"
        );
        assert!(
            !source.contains("rules.overlaps.send-over\""),
            "{file} words the send-over action its own way"
        );
    }
}

//! A user whose saved rules cannot be read is told by the window and the tray.
//!
//! The service pushes the change to that user alone and repeats the standing
//! state in the snapshot. These tests hold the QML to the wire names both ends
//! share, and to an action that leads to the details.

use std::path::{Path, PathBuf};

use nrr_shared::diagnostics_dto::DiagnosticsStatusDto;
use nrr_shared::ipc_payloads::{SnapshotInitialResponse, StatusUpdateEvent};
use serde_json::{json, Value};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The push's `type` and the member that carries the state.
fn push_wire() -> (String, Vec<String>) {
    let event = serde_json::to_value(StatusUpdateEvent::RulesBookUnreadable {
        sid: "S-1-5-21-0".into(),
        unreadable: true,
    })
    .unwrap_or_else(|e| panic!("event serialises: {e}"));
    let kind = event["type"].as_str().unwrap_or_default().to_owned();
    let members = event
        .as_object()
        .map(|o| {
            o.keys()
                .filter(|k| *k != "type" && *k != "sid")
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    (kind, members)
}

/// The snapshot member that carries the standing state.
fn snapshot_key() -> String {
    let mut snapshot: SnapshotInitialResponse = serde_json::from_value(json!({
        "health": { "service-state": "running", "worst-severity": "ok", "components": [] },
        "adapters": { "data-source": "windows-live", "adapters": [], "rows": [] },
        "diagnostics": serde_json::to_value(DiagnosticsStatusDto::unavailable())
            .unwrap_or(Value::Null),
        "active-alerts-count": 0
    }))
    .unwrap_or_else(|e| panic!("snapshot parses: {e}"));
    let quiet = serde_json::to_value(&snapshot).unwrap_or_else(|e| panic!("{e}"));
    snapshot.rules_book_unreadable = true;
    let told = serde_json::to_value(&snapshot).unwrap_or_else(|e| panic!("{e}"));
    let added: Vec<String> = told
        .as_object()
        .map(|o| {
            o.keys()
                .filter(|k| quiet.get(k.as_str()).is_none())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(added.len(), 1, "one member carries the state: {added:?}");
    added[0].clone()
}

#[test]
fn the_window_and_the_tray_read_the_push_and_the_snapshot_by_their_wire_names() {
    let (kind, members) = push_wire();
    assert_eq!(members, vec!["unreadable".to_owned()]);
    let key = snapshot_key();
    for (file, payload) in [
        ("apps/desktop/qml/Main.qml", "p"),
        ("apps/desktop/qml/Tray.qml", "payload"),
    ] {
        let source = repo_file(file);
        assert!(
            source.contains(&format!("case \"{kind}\":")),
            "{file} does not dispatch `{kind}`"
        );
        assert!(
            source.contains("_onRulesBookReading(event.unreadable === true)"),
            "{file} does not read the push's `unreadable`"
        );
        assert!(
            source.contains(&format!(
                "_onRulesBookReading({payload}[\"{key}\"] === true)"
            )),
            "{file} does not read the snapshot's `{key}`"
        );
        assert!(
            source.contains("Pure.rulesBookNoticeStep("),
            "{file} decides on its own instead of through the shared step"
        );
    }
}

#[test]
fn the_notice_leads_to_diagnostics() {
    let main = repo_file("apps/desktop/qml/Main.qml");
    assert!(main.contains("\"actionKey\": \"open-diagnostics\""));
    let controller = repo_file("apps/desktop/qml/flows/NotificationsController.qml");
    assert!(
        controller.contains("actionKey === \"open-diagnostics\") root.section = \"diagnostics\""),
        "the window's action does not open Diagnostics"
    );
    let tray = repo_file("apps/desktop/qml/Tray.qml");
    assert!(tray.contains("actionId: \"rules-book-open-diagnostics\""));
    let handler = tray
        .split_once("action === \"rules-book-open-diagnostics\")")
        .and_then(|(_, rest)| rest.split_once("return").map(|(body, _)| body))
        .unwrap_or_else(|| panic!("the tray does not handle its action"));
    assert!(
        handler.contains("triggerAction(\"diagnostics\")"),
        "the tray's action does not open Diagnostics: {handler}"
    );
}

#[test]
fn every_text_of_the_notice_is_in_both_locale_files() {
    for language in ["en", "ru"] {
        let raw = repo_file(&format!("locales/{language}.json"));
        let root: Value = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
            .unwrap_or_else(|e| panic!("parse {language}.json: {e}"));
        for id in [
            "notifications.rules-book-unreadable.title",
            "notifications.rules-book-unreadable.body",
            "action.open-diagnostics",
        ] {
            let found = id
                .split('.')
                .try_fold(&root, |node, part| node.get(part))
                .and_then(Value::as_str);
            assert!(found.is_some(), "{language}.json lacks {id}");
        }
    }
}

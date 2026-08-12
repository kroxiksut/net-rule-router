//! End-to-end test of the import → sidecar → export bridge — block
//! 16.QoL+1 Phase 7.
//!
//! Verifies the path the GUI takes during a preset import:
//!
//! 1. `nrr_shared::preset_parser::parse_canonical_rules` reads the
//!    file and surfaces rules + passthrough.
//! 2. The launcher's `sidecar.passthrough.write` handler persists
//!    those passthrough blocks per-route in a tempfile sidecar.
//! 3. The launcher's `sidecar.passthrough.read` handler returns the
//!    same data, ready for the GUI's canonical-txt writer to stitch
//!    back into an export file.
//!
//! What this test does NOT cover:
//! * The QML async-callback chain (`registerRpcCallback`) is JS code
//!   that doesn't have a Rust equivalent — verified via manual smoke
//!   below.
//! * The actual export file content — that's assembled in QML's
//!   `_buildCanonicalRulesText`; a Rust mirror would duplicate logic
//!   without testable value. See P7 manual-smoke checklist for the
//!   real round-trip verification.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use nrr_launcher::sidecar_handlers::{handle_sidecar_request, SidecarHandle};
use nrr_shared::preset_parser::{parse_canonical_rules, PassthroughBlock};
use nrr_storage_sidecar::SidecarDb;
use serde_json::{json, Value};

/// Build a sidecar handle pre-initialised against a tempfile path.
/// The launcher would normally open the DB lazily on first
/// `sidecar.*` request, but tests want deterministic setup.
fn fresh_sidecar(tmp: &tempfile::TempDir) -> SidecarHandle {
    let path = tmp.path().join("sidecar.db");
    let db = SidecarDb::open(&path).expect("open sidecar");
    Arc::new(Mutex::new(Some(db)))
}

/// Convert parser passthrough blocks into the `{name: text}` shape
/// the `sidecar.passthrough.write` handler expects. Mirrors the
/// transformation `Main.qml::_writeImportedPassthrough` does.
fn to_sections_object(blocks: &[PassthroughBlock]) -> Value {
    let mut map = serde_json::Map::new();
    for block in blocks {
        map.insert(
            block.section_name.clone(),
            Value::String(block.raw_text.clone()),
        );
    }
    Value::Object(map)
}

#[test]
fn linux_section_survives_parse_then_sidecar_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // Realistic mixed-OS preset shape: rules in known sections plus
    // foreign-OS blocks that go into passthrough.
    let preset = "--- Zones\nru\n\n--- Domains\nvk.com\nya.ru\n\n--- IP\n\n--- Windows\ntelegram.exe\n\n--- Linux\n# (reserved - not applied on Windows)\nfirefox\nchromium\n\n--- MacOS\nSafari\nVivaldi\n";

    // 1. Parse.
    let parsed = parse_canonical_rules(preset);
    assert!(!parsed.rules.is_empty(), "known sections produce rules");
    assert_eq!(parsed.passthrough.len(), 2);

    // 2. Write passthrough to sidecar via the same handler path the
    //    QML bridge uses.
    let sections = to_sections_object(&parsed.passthrough);
    let write_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections }),
    )
    .expect("write");
    assert_eq!(write_resp["saved"], parsed.passthrough.len());

    // 3. Read it back.
    let read_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    let read_sections = read_resp["sections"].as_object().expect("sections object");

    // Both Linux and MacOS blocks survived byte-identical.
    assert_eq!(
        read_sections.get("Linux").and_then(Value::as_str),
        Some("# (reserved - not applied on Windows)\nfirefox\nchromium\n"),
    );
    assert_eq!(
        read_sections.get("MacOS").and_then(Value::as_str),
        Some("Safari\nVivaldi\n"),
    );
}

#[test]
fn passthrough_isolated_per_route() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // Primary preset has Linux only; secondary has MacOS only.
    let primary_text = "--- Domains\nprim.example\n--- Linux\nfirefox\n";
    let secondary_text = "--- Domains\nsec.example\n--- MacOS\nSafari\n";

    for (route, text) in [("primary", primary_text), ("secondary", secondary_text)] {
        let parsed = parse_canonical_rules(text);
        let sections = to_sections_object(&parsed.passthrough);
        handle_sidecar_request(
            &handle,
            "sidecar.passthrough.write",
            &json!({ "route": route, "sections": sections }),
        )
        .expect("write");
    }

    // Primary has Linux but not MacOS.
    let primary_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    let primary_sections = primary_resp["sections"].as_object().expect("obj");
    assert!(primary_sections.contains_key("Linux"));
    assert!(!primary_sections.contains_key("MacOS"));

    // Secondary has MacOS but not Linux.
    let secondary_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "secondary" }),
    )
    .expect("read");
    let secondary_sections = secondary_resp["sections"].as_object().expect("obj");
    assert!(secondary_sections.contains_key("MacOS"));
    assert!(!secondary_sections.contains_key("Linux"));
}

#[test]
fn empty_passthrough_write_clears_previous_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // First import: has Linux passthrough.
    let parsed = parse_canonical_rules("--- Domains\nvk.com\n--- Linux\nfirefox\n");
    let sections = to_sections_object(&parsed.passthrough);
    handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections }),
    )
    .expect("write 1");

    // Second import: no foreign-OS sections. The atomic-replace
    // semantics means the previous Linux block must be cleared.
    let parsed2 = parse_canonical_rules("--- Domains\nya.ru\n");
    assert!(parsed2.passthrough.is_empty());
    let sections2 = to_sections_object(&parsed2.passthrough);
    handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections2 }),
    )
    .expect("write 2");

    let read = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    assert!(
        read["sections"].as_object().expect("obj").is_empty(),
        "second import with empty passthrough must clear previous state",
    );
}

#[test]
fn cyrillic_passthrough_content_survives_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // Hypothetical custom section with Cyrillic content.
    let preset = "--- Domains\nvk.com\n--- Заметки\n# Это пользовательская секция\nпривет\n";
    let parsed = parse_canonical_rules(preset);
    assert_eq!(parsed.passthrough.len(), 1);
    assert_eq!(parsed.passthrough[0].section_name, "Заметки");

    let sections = to_sections_object(&parsed.passthrough);
    handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections }),
    )
    .expect("write");

    let read = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    let stored = read["sections"]["Заметки"]
        .as_str()
        .expect("Cyrillic section name preserved");
    assert!(stored.contains("привет"));
    assert!(stored.contains("Это пользовательская секция"));
}

#[test]
fn known_section_rules_do_not_leak_into_passthrough() {
    // Regression guard: only sections the parser doesn't classify go
    // into passthrough. Known sections (Zones, Domains, IP, Windows)
    // must produce rules, not passthrough blocks.
    let preset =
        "--- Zones\nru\n--- Domains\nvk.com\n--- IP\n203.0.113.7\n--- Windows\ntelegram.exe\n";
    let parsed = parse_canonical_rules(preset);
    assert!(
        parsed.passthrough.is_empty(),
        "known-only preset must not produce passthrough blocks, got {:?}",
        parsed
            .passthrough
            .iter()
            .map(|b| &b.section_name)
            .collect::<Vec<_>>(),
    );
    assert_eq!(parsed.rules.len(), 4);
}

#[test]
fn passthrough_preview_uses_btreemap_order_for_export_determinism() {
    // The sidecar handler returns `sections` as a JSON object sorted
    // by name (BTreeMap iteration order). The export writer relies on
    // this for deterministic file output.
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    let mut sections = BTreeMap::new();
    sections.insert("MacOS".to_string(), Value::String("Safari\n".into()));
    sections.insert("Linux".to_string(), Value::String("firefox\n".into()));
    sections.insert("Cidr".to_string(), Value::String("10.0.0.0/8\n".into()));
    let sections_val = Value::Object(sections.into_iter().collect::<serde_json::Map<_, _>>());

    handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections_val }),
    )
    .expect("write");

    let read = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    let obj = read["sections"].as_object().expect("obj");
    let keys: Vec<&String> = obj.keys().collect();
    // serde_json::Map preserves insertion order; sidecar returns
    // BTreeMap-sorted. Verify the alphabetical order.
    assert_eq!(
        keys.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        vec!["Cidr", "Linux", "MacOS"],
    );
}

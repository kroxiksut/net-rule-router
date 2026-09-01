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

/// The application section this build parses as rules.
///
/// Which of the three it is depends on where the test runs, and spelling it
/// `Windows` assumed a Windows runner: on a Linux one the roles swap and every
/// assertion about passthrough inverts.
fn native_app_section() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else if cfg!(target_os = "macos") {
        "MacOS"
    } else {
        "Windows"
    }
}

/// The two application sections this build carries through untouched — what the
/// sidecar exists to preserve.
fn foreign_app_sections() -> [&'static str; 2] {
    match native_app_section() {
        "Windows" => ["Linux", "MacOS"],
        "Linux" => ["Windows", "MacOS"],
        _ => ["Windows", "Linux"],
    }
}

#[test]
fn foreign_os_sections_survive_parse_then_sidecar_round_trip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // Realistic mixed-OS preset shape: rules in known sections plus
    // foreign-OS blocks that go into passthrough.
    let native = native_app_section();
    let [first, second] = foreign_app_sections();
    let preset = format!(
        "--- Zones\nru\n\n--- Domains\nvk.com\nya.ru\n\n--- IP\n\n--- {native}\ntelegram.exe\n\n\
         --- {first}\n# (reserved - not applied on this host)\nfirefox\nchromium\n\n\
         --- {second}\nSafari\nVivaldi\n"
    );

    // 1. Parse.
    let parsed = parse_canonical_rules(&preset);
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

    // Both foreign blocks survived byte-identical.
    assert_eq!(
        read_sections.get(first).and_then(Value::as_str),
        Some("# (reserved - not applied on this host)\nfirefox\nchromium\n"),
    );
    assert_eq!(
        read_sections.get(second).and_then(Value::as_str),
        Some("Safari\nVivaldi\n"),
    );
}

#[test]
fn passthrough_isolated_per_route() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // Primary preset carries one foreign section, secondary the other.
    let [first, second] = foreign_app_sections();
    let primary_text = format!("--- Domains\nprim.example\n--- {first}\nfirefox\n");
    let secondary_text = format!("--- Domains\nsec.example\n--- {second}\nSafari\n");

    for (route, text) in [
        ("primary", primary_text.as_str()),
        ("secondary", secondary_text.as_str()),
    ] {
        let parsed = parse_canonical_rules(text);
        let sections = to_sections_object(&parsed.passthrough);
        handle_sidecar_request(
            &handle,
            "sidecar.passthrough.write",
            &json!({ "route": route, "sections": sections }),
        )
        .expect("write");
    }

    // Primary carries the first foreign section, not the second.
    let primary_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "primary" }),
    )
    .expect("read");
    let primary_sections = primary_resp["sections"].as_object().expect("obj");
    assert!(primary_sections.contains_key(first));
    assert!(!primary_sections.contains_key(second));

    // Secondary carries the second, not the first.
    let secondary_resp = handle_sidecar_request(
        &handle,
        "sidecar.passthrough.read",
        &json!({ "route": "secondary" }),
    )
    .expect("read");
    let secondary_sections = secondary_resp["sections"].as_object().expect("obj");
    assert!(secondary_sections.contains_key(second));
    assert!(!secondary_sections.contains_key(first));
}

#[test]
fn empty_passthrough_write_clears_previous_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let handle = fresh_sidecar(&tmp);

    // First import: carries a foreign-OS section into passthrough.
    let foreign = foreign_app_sections()[0];
    let parsed = parse_canonical_rules(&format!("--- Domains\nvk.com\n--- {foreign}\nfirefox\n"));
    let sections = to_sections_object(&parsed.passthrough);
    handle_sidecar_request(
        &handle,
        "sidecar.passthrough.write",
        &json!({ "route": "primary", "sections": sections }),
    )
    .expect("write 1");

    // Second import: no foreign-OS sections. The atomic-replace
    // semantics means the previous block must be cleared.
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
    // into passthrough. Known sections (Zones, Domains, IP, and THIS host's
    // application section) must produce rules, not passthrough blocks.
    let native = native_app_section();
    let preset = format!(
        "--- Zones\nru\n--- Domains\nvk.com\n--- IP\n203.0.113.7\n--- {native}\ntelegram.exe\n"
    );
    let parsed = parse_canonical_rules(&preset);
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

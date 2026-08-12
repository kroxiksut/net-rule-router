//! `route.policy.update` — the wire contract shared with the QML shell.
//!
//! The operation has no sparse update: a field the request leaves out falls
//! back to its serde default on the service and silently resets whatever the
//! user had configured. The GUI therefore has to send EVERY field on every
//! write, with the same defaults this crate declares.
//!
//! Two failure modes followed from that, and both shipped more than once:
//!   * a QML builder forgot a field (the route-binding clobber), and
//!   * a default was spelled out on both sides and the two spellings drifted
//!     (the routing panel displayed `allow-dns-over-primary` as ON while every
//!     unrelated policy write pushed `false`).
//!
//! The QML side now declares each wire key and its default exactly once, in
//! `apps/desktop/qml/lib/pure.js`. These tests pin that table against the DTOs
//! here, so a contract change that is not mirrored fails `cargo test` instead
//! of a hardware run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nrr_shared::ipc_payloads::{RoutePolicyDto, RoutePolicyUpdateRequest};
use serde_json::{json, Map, Value};

/// Request fields the QML defaults table deliberately does NOT carry:
/// the two binding slots are copied from the live snapshot (or from the user's
/// adapter selection), and `binding-source` is stamped by the writer rather
/// than preserved — echoing a snapshot's `recovery` / `migrated-from-preferences`
/// back would misattribute a user edit.
const KEYS_NOT_IN_DEFAULTS_TABLE: [&str; 3] = ["primary", "secondary", "binding-source"];

/// Fields with no wire default at all (required in every request), so the QML
/// table's entry for them is a GUI-side fallback for an empty snapshot rather
/// than a mirror of a Rust value. Presence is pinned; the value is not.
const KEYS_WITHOUT_WIRE_DEFAULT: [&str; 2] = ["mode", "block-secondary-when-unavailable"];

fn qml_pure_js() -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/desktop/qml/lib/pure.js")
        .to_path_buf();
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Extract a `var <name> = <literal>` declaration from the JS source and parse
/// the literal as JSON. Both declarations are written as plain JSON literals
/// precisely so this stays a parse rather than a regex guess.
fn parse_js_literal(source: &str, name: &str, open: char, close: char) -> Value {
    let decl = format!("var {name} = ");
    let start = source
        .find(&decl)
        .unwrap_or_else(|| panic!("`{name}` declaration missing from lib/pure.js"))
        + decl.len();
    let body = &source[start..];
    assert_eq!(
        body.chars().next(),
        Some(open),
        "`{name}` must be declared as a plain {open}…{close} literal"
    );
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in body.char_indices() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                end = Some(idx + ch.len_utf8());
                break;
            }
        }
    }
    let end = end.unwrap_or_else(|| panic!("unbalanced literal in `{name}`"));
    serde_json::from_str(&body[..end])
        .unwrap_or_else(|e| panic!("`{name}` is not a JSON-parsable literal: {e}"))
}

fn qml_field_defaults() -> Map<String, Value> {
    match parse_js_literal(&qml_pure_js(), "ROUTE_POLICY_FIELD_DEFAULTS", '{', '}') {
        Value::Object(map) => map,
        other => panic!("ROUTE_POLICY_FIELD_DEFAULTS must be an object, got {other}"),
    }
}

fn qml_snapshot_only_keys() -> Vec<String> {
    match parse_js_literal(&qml_pure_js(), "ROUTE_POLICY_SNAPSHOT_ONLY_KEYS", '[', ']') {
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::String(s) => s,
                other => panic!("snapshot-only keys must be strings, got {other}"),
            })
            .collect(),
        other => panic!("ROUTE_POLICY_SNAPSHOT_ONLY_KEYS must be an array, got {other}"),
    }
}

/// A request in which every OPTIONAL field was omitted by the peer, so each one
/// carries exactly the serde default this crate declares.
fn request_at_wire_defaults() -> Map<String, Value> {
    let minimal = json!({
        "mode": "prefer-primary",
        "block-secondary-when-unavailable": false,
        "binding-source": "user-assigned",
    });
    let parsed: RoutePolicyUpdateRequest =
        serde_json::from_value(minimal).unwrap_or_else(|e| panic!("minimal request: {e}"));
    match serde_json::to_value(parsed).unwrap_or_else(|e| panic!("request serialises: {e}")) {
        Value::Object(map) => map,
        other => panic!("request must serialise to an object, got {other}"),
    }
}

fn dto_keys() -> Vec<String> {
    let minimal = json!({
        "mode": "prefer-primary",
        "block-secondary-when-unavailable": false,
        "binding-source": "user-assigned",
    });
    let parsed: RoutePolicyDto =
        serde_json::from_value(minimal).unwrap_or_else(|e| panic!("minimal DTO: {e}"));
    match serde_json::to_value(parsed).unwrap_or_else(|e| panic!("DTO serialises: {e}")) {
        Value::Object(map) => map.keys().cloned().collect(),
        other => panic!("DTO must serialise to an object, got {other}"),
    }
}

/// The list the GUI builds its payload from must be exactly the request's own
/// field list. A field added here and forgotten there is the clobber bug: the
/// GUI keeps sending complete-looking payloads that quietly drop it.
#[test]
fn qml_route_policy_table_covers_every_update_request_field() {
    let expected: Vec<String> = request_at_wire_defaults()
        .keys()
        .filter(|key| !KEYS_NOT_IN_DEFAULTS_TABLE.contains(&key.as_str()))
        .cloned()
        .collect();
    let declared: Vec<String> = qml_field_defaults().keys().cloned().collect();
    let missing: Vec<&String> = expected.iter().filter(|k| !declared.contains(k)).collect();
    let unknown: Vec<&String> = declared.iter().filter(|k| !expected.contains(k)).collect();
    assert!(
        missing.is_empty(),
        "ROUTE_POLICY_FIELD_DEFAULTS in apps/desktop/qml/lib/pure.js is missing {missing:?}; \
         every builder derives from it, so the field would be dropped from every \
         route.policy.update the GUI sends and reset to its serde default"
    );
    assert!(
        unknown.is_empty(),
        "ROUTE_POLICY_FIELD_DEFAULTS declares {unknown:?}, which RoutePolicyUpdateRequest \
         does not accept"
    );
}

/// The GUI's default for a field must be the value the service would have
/// chosen anyway. When the two disagree, the panel renders one value and the
/// next unrelated write pushes the other.
#[test]
fn qml_route_policy_defaults_match_the_wire_defaults() {
    let wire = request_at_wire_defaults();
    let declared = qml_field_defaults();
    let mut diverged: BTreeMap<String, (Value, Value)> = BTreeMap::new();
    for (key, qml_value) in &declared {
        if KEYS_WITHOUT_WIRE_DEFAULT.contains(&key.as_str()) {
            continue;
        }
        let wire_value = wire
            .get(key)
            .unwrap_or_else(|| panic!("`{key}` is absent from a serialised request"));
        if wire_value != qml_value {
            diverged.insert(key.clone(), (wire_value.clone(), qml_value.clone()));
        }
    }
    assert!(
        diverged.is_empty(),
        "default declared twice and drifted (wire, qml): {diverged:?} — the Rust side is \
         normative; fix ROUTE_POLICY_FIELD_DEFAULTS in apps/desktop/qml/lib/pure.js"
    );
}

/// Keys the snapshot carries but the request does not have to be dropped when
/// the GUI echoes a snapshot back, or the service rejects the payload.
#[test]
fn qml_snapshot_only_keys_are_exactly_the_snapshot_minus_request_fields() {
    let request_keys = request_at_wire_defaults();
    let mut expected: Vec<String> = dto_keys()
        .into_iter()
        .filter(|key| !request_keys.contains_key(key))
        .collect();
    expected.sort();
    let mut declared = qml_snapshot_only_keys();
    declared.sort();
    assert_eq!(
        declared, expected,
        "ROUTE_POLICY_SNAPSHOT_ONLY_KEYS in apps/desktop/qml/lib/pure.js must list every key \
         RoutePolicyDto reports that RoutePolicyUpdateRequest cannot accept"
    );
}

/// `binding-source` is stamped by the writer, never preserved from a snapshot —
/// pinned here because putting it in the defaults table would silently echo a
/// service-owned `recovery` value back as if the user had chosen it.
#[test]
fn qml_binding_source_is_stamped_not_defaulted() {
    assert!(
        !qml_field_defaults().contains_key("binding-source"),
        "binding-source must not be in ROUTE_POLICY_FIELD_DEFAULTS"
    );
    assert!(
        qml_pure_js().contains(r#"req["binding-source"] = "user-assigned""#),
        "buildFullRoutePolicyReq must stamp binding-source on every payload"
    );
}

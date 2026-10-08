//! `snapshot.initial.get` — the standing enforcement reports.
//!
//! The push about whether a role's rules are in force fires on change only; a
//! client that connects later reads the same report from the snapshot and feeds
//! it to the handler it already has for the push. These tests pin the field's
//! wire shape to the push's, and that peers on either side of the change still
//! decode each other.

use nrr_shared::diagnostics_dto::DiagnosticsStatusDto;
use nrr_shared::ipc_payloads::{EnforcementStatusDto, SnapshotInitialResponse, StatusUpdateEvent};
use serde_json::{json, Value};

/// A snapshot as a service without the field sends it.
fn snapshot_without_enforcement() -> Value {
    json!({
        "health": {
            "service-state": "running",
            "worst-severity": "ok",
            "components": [],
            "degraded-modes": []
        },
        "adapters": { "data-source": "windows-live", "adapters": [], "rows": [] },
        "diagnostics": serde_json::to_value(DiagnosticsStatusDto::unavailable())
            .unwrap_or(Value::Null),
        "active-alerts-count": 0
    })
}

fn parse(v: Value) -> SnapshotInitialResponse {
    serde_json::from_value(v).unwrap_or_else(|e| panic!("snapshot must parse: {e}"))
}

#[test]
fn an_older_service_snapshot_decodes_with_no_reports() {
    assert!(parse(snapshot_without_enforcement())
        .enforcement_status
        .is_empty());
}

#[test]
fn no_reports_are_left_off_the_wire() {
    let wire = serde_json::to_value(parse(snapshot_without_enforcement()))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("enforcement-status").is_none(), "{wire}");
}

#[test]
fn reports_round_trip_under_their_wire_key() {
    let mut v = snapshot_without_enforcement();
    v["enforcement-status"] = json!([
        { "status": "secondary-down", "role": "secondary" },
        { "status": "adapter-gone", "role": "primary", "candidates": ["Ethernet"] }
    ]);
    let parsed = parse(v);
    assert_eq!(
        parsed.enforcement_status,
        vec![
            EnforcementStatusDto {
                status: "secondary-down".into(),
                role: "secondary".into(),
                candidates: Vec::new(),
            },
            EnforcementStatusDto {
                status: "adapter-gone".into(),
                role: "primary".into(),
                candidates: vec!["Ethernet".into()],
            },
        ]
    );
    let wire = serde_json::to_value(&parsed).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire["enforcement-status"][1]["candidates"][0], "Ethernet");
}

/// The GUI hands a snapshot entry to its push handler unchanged, so every key
/// that handler reads must be spelled the same in both.
#[test]
fn a_report_has_the_push_events_shape() {
    let event = StatusUpdateEvent::EnforcementStatusChanged {
        sid: "S-1-5-21-0".into(),
        status: "adapter-choice-needed".into(),
        role: "secondary".into(),
        candidates: vec!["Example Tunnel".into(), "Example Tunnel".into()],
    };
    let mut pushed = serde_json::to_value(&event).unwrap_or_else(|e| panic!("{e}"));
    let fields = pushed
        .as_object_mut()
        .unwrap_or_else(|| panic!("an event is an object"));
    fields.remove("type");
    fields.remove("sid");
    let report = EnforcementStatusDto {
        status: "adapter-choice-needed".into(),
        role: "secondary".into(),
        candidates: vec!["Example Tunnel".into(), "Example Tunnel".into()],
    };
    assert_eq!(
        serde_json::to_value(&report).unwrap_or_else(|e| panic!("{e}")),
        pushed
    );
}

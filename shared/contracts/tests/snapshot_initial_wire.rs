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
                since_unix_ms: None,
            },
            EnforcementStatusDto {
                status: "adapter-gone".into(),
                role: "primary".into(),
                candidates: vec!["Ethernet".into()],
                since_unix_ms: None,
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
        since_unix_ms: Some(1_700_000_000_000),
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
        since_unix_ms: Some(1_700_000_000_000),
    };
    assert_eq!(
        serde_json::to_value(&report).unwrap_or_else(|e| panic!("{e}")),
        pushed
    );
}

#[test]
fn since_travels_under_its_kebab_key_and_is_left_off_when_unknown() {
    let report = EnforcementStatusDto {
        status: "secondary-down".into(),
        role: "secondary".into(),
        candidates: Vec::new(),
        since_unix_ms: Some(1_700_000_000_000),
    };
    let wire = serde_json::to_value(&report).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire["since-unix-ms"], 1_700_000_000_000_i64);
    let back: EnforcementStatusDto = serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, report);

    let unknown = EnforcementStatusDto {
        since_unix_ms: None,
        ..report
    };
    let wire = serde_json::to_value(&unknown).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("since-unix-ms").is_none(), "{wire}");
}

/// A push from a service that predates the field still decodes.
#[test]
fn an_older_push_decodes_with_no_since() {
    let event: StatusUpdateEvent = serde_json::from_value(json!({
        "type": "enforcement-status-changed",
        "sid": "S-1-5-21-0",
        "status": "secondary-down",
        "role": "secondary"
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    match event {
        StatusUpdateEvent::EnforcementStatusChanged { since_unix_ms, .. } => {
            assert_eq!(since_unix_ms, None);
        }
        other => panic!("unexpected event {other:?}"),
    }
}

//! `conn-trace.outage-blocks.list` — what leak protection blocked during the
//! caller's last outage. The GUI and the terminal read these keys by name, so
//! the wire spelling is pinned here, together with what an older or newer peer
//! leaves out.

use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    ConnTraceOutageBlocksRequest, ConnTraceOutageBlocksResponse, OutageBlockDto, OutageEpisodeDto,
    OutageUnresolvedNameDto,
};
use serde_json::json;

fn entry() -> OutageBlockDto {
    OutageBlockDto {
        process: "browser.exe".into(),
        process_path: "C:\\Apps\\browser.exe".into(),
        remote_ip: "192.0.2.10".into(),
        remote_port: 443,
        host: "site.example".into(),
        rule_host: "site.example".into(),
        first_seen_ms: 1_700_000_000_000,
        last_seen_ms: 1_700_000_005_000,
        attempts: 3,
    }
}

#[test]
fn the_operation_travels_under_its_slug() {
    let op = IpcOperationName::ConnTraceOutageBlocksList;
    assert_eq!(op.slug(), "conn-trace.outage-blocks.list");
    assert_eq!(IpcOperationName::from_slug(op.slug()), Some(op));
}

#[test]
fn the_request_is_an_empty_object() {
    let wire = serde_json::to_value(ConnTraceOutageBlocksRequest::default())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire, json!({}));
    let back: ConnTraceOutageBlocksRequest =
        serde_json::from_value(json!({})).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, ConnTraceOutageBlocksRequest::default());
}

#[test]
fn a_response_round_trips_under_kebab_keys() {
    let response = ConnTraceOutageBlocksResponse {
        episode: Some(OutageEpisodeDto {
            since_unix_ms: 1_700_000_000_000,
            until_unix_ms: Some(1_700_000_060_000),
        }),
        entries: vec![entry()],
        omitted: 2,
        redacted: false,
        unresolved_names: vec![OutageUnresolvedNameDto {
            name: "chat.example.com".into(),
            first_seen_ms: 1_700_000_001_000,
            last_seen_ms: 1_700_000_004_000,
            attempts: 4,
        }],
        observer_active: true,
        gui_stream_enabled: true,
    };
    let wire = serde_json::to_value(&response).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire["episode"]["since-unix-ms"], 1_700_000_000_000_i64);
    assert_eq!(wire["episode"]["until-unix-ms"], 1_700_000_060_000_i64);
    let row = &wire["entries"][0];
    for key in [
        "process",
        "process-path",
        "remote-ip",
        "remote-port",
        "host",
        "rule-host",
        "first-seen-ms",
        "last-seen-ms",
        "attempts",
    ] {
        assert!(row.get(key).is_some(), "{key} missing from {row}");
    }
    assert_eq!(wire["omitted"], 2);
    let name = &wire["unresolved-names"][0];
    for key in ["name", "first-seen-ms", "last-seen-ms", "attempts"] {
        assert!(name.get(key).is_some(), "{key} missing from {name}");
    }
    assert_eq!(wire["observer-active"], true);
    assert_eq!(wire["gui-stream-enabled"], true);
    let back: ConnTraceOutageBlocksResponse =
        serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, response);
}

#[test]
fn an_ongoing_outage_has_no_until_and_no_outage_has_no_episode() {
    let ongoing = ConnTraceOutageBlocksResponse {
        episode: Some(OutageEpisodeDto {
            since_unix_ms: 1,
            until_unix_ms: None,
        }),
        entries: Vec::new(),
        omitted: 0,
        redacted: false,
        unresolved_names: Vec::new(),
        observer_active: true,
        gui_stream_enabled: true,
    };
    let wire = serde_json::to_value(&ongoing).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire["episode"].get("until-unix-ms").is_none(), "{wire}");

    let none = ConnTraceOutageBlocksResponse {
        episode: None,
        ..ongoing
    };
    let wire = serde_json::to_value(&none).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("episode").is_none(), "{wire}");
}

/// The flags a peer may not send read as "watching, shown": silence is the
/// safer reading than a false alarm, as for the connection trace.
#[test]
fn a_minimal_response_decodes_with_the_safe_defaults() {
    let parsed: ConnTraceOutageBlocksResponse =
        serde_json::from_value(json!({ "redacted": false })).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.episode, None);
    assert!(parsed.entries.is_empty());
    assert_eq!(parsed.omitted, 0);
    assert!(
        parsed.unresolved_names.is_empty(),
        "an older service sends no names"
    );
    assert!(parsed.observer_active);
    assert!(parsed.gui_stream_enabled);
}

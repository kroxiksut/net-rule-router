//! `vpn.gateway-candidates.list` — where one program connected lately. The GUI
//! and the terminal read these keys by name, so the wire spelling is pinned
//! here, together with what an older or newer peer leaves out.

use nrr_shared::ipc::{ipc_operation_spec, IpcClientProfile, IpcOperationName};
use nrr_shared::ipc_payloads::{
    VpnGatewayCandidateDto, VpnGatewayCandidatesRequest, VpnGatewayCandidatesResponse,
};
use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};
use serde_json::json;

#[test]
fn the_operation_travels_under_its_slug_as_a_read() {
    let op = IpcOperationName::VpnGatewayCandidatesList;
    assert_eq!(op.slug(), "vpn.gateway-candidates.list");
    assert_eq!(IpcOperationName::from_slug(op.slug()), Some(op));
    let spec = ipc_operation_spec(op).unwrap_or_else(|| panic!("in the catalog"));
    assert!(!spec.requires_service_mutation_privilege);
    for profile in [IpcClientProfile::GuiInteractive, IpcClientProfile::Tui] {
        assert!(spec.allowed_clients.contains(&profile), "{profile:?}");
    }
    assert!(
        !spec
            .allowed_clients
            .contains(&IpcClientProfile::AdminConsole),
        "the console only reads diagnostics"
    );
    assert_eq!(
        canonical_operation_class(op, &json!({ "program": "corpvpn.exe" })),
        IpcOperationClass::ReadSnapshot
    );
}

#[test]
fn the_request_names_the_program() {
    let wire = serde_json::to_value(VpnGatewayCandidatesRequest {
        program: "corpvpn.exe".into(),
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire, json!({ "program": "corpvpn.exe" }));
    let empty: VpnGatewayCandidatesRequest =
        serde_json::from_value(json!({})).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(empty.program, "");
}

#[test]
fn a_response_round_trips_under_kebab_keys() {
    let response = VpnGatewayCandidatesResponse {
        program: "corpvpn.exe".into(),
        candidates: vec![VpnGatewayCandidateDto {
            address: "203.0.113.10".into(),
            hostname: "gw.corp.example".into(),
            ports: vec![500, 4500],
            protocols: vec!["udp".into()],
            connections: 3,
            last_seen_ms: 1_700_000_000_000,
        }],
        omitted: 2,
        observer_active: true,
    };
    let wire = serde_json::to_value(&response).unwrap_or_else(|e| panic!("{e}"));
    let row = &wire["candidates"][0];
    for key in [
        "address",
        "hostname",
        "ports",
        "protocols",
        "connections",
        "last-seen-ms",
    ] {
        assert!(row.get(key).is_some(), "{key} missing from {row}");
    }
    assert_eq!(wire["omitted"], 2);
    assert_eq!(wire["observer-active"], true);
    let back: VpnGatewayCandidatesResponse =
        serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, response);
}

/// An older service sends less: missing lists read empty, and a missing
/// observer flag reads as watching rather than raising a false alarm.
#[test]
fn what_a_peer_leaves_out_reads_as_nothing_to_show() {
    let back: VpnGatewayCandidatesResponse = serde_json::from_value(json!({
        "candidates": [{ "address": "198.51.100.7", "connections": 1, "last-seen-ms": 0 }]
    }))
    .unwrap_or_else(|e| panic!("{e}"));
    assert!(back.observer_active);
    assert_eq!(back.omitted, 0);
    assert_eq!(back.program, "");
    let row = &back.candidates[0];
    assert!(row.hostname.is_empty() && row.ports.is_empty() && row.protocols.is_empty());
}

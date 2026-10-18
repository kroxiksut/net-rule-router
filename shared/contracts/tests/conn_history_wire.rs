//! `conn-history.{list,clear,settings.set}` — the caller's connection history.
//! The GUI and the terminal read these keys by name, so the wire spelling is
//! pinned here, together with what an older or newer peer leaves out.

use nrr_shared::ipc::{ipc_operation_spec, IpcInteractionClass, IpcOperationName};
use nrr_shared::ipc_payloads::{
    ConnHistoryClearRequest, ConnHistoryEntryDto, ConnHistoryListRequest, ConnHistoryListResponse,
    ConnHistorySettingsSetRequest, ConnHistorySettingsSetResponse,
};
use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};
use nrr_shared::pagination::PageResult;
use serde_json::json;

#[test]
fn the_operations_travel_under_their_slugs() {
    for (op, slug) in [
        (IpcOperationName::ConnHistoryList, "conn-history.list"),
        (IpcOperationName::ConnHistoryClear, "conn-history.clear"),
        (
            IpcOperationName::ConnHistorySettingsSet,
            "conn-history.settings.set",
        ),
    ] {
        assert_eq!(op.slug(), slug);
        assert_eq!(IpcOperationName::from_slug(slug), Some(op));
    }
}

#[test]
fn reading_is_a_query_and_the_writes_are_the_callers_own_configuration() {
    let spec = |op| ipc_operation_spec(op).unwrap_or_else(|| panic!("{op:?} catalogued"));
    assert_eq!(
        spec(IpcOperationName::ConnHistoryList).class,
        IpcInteractionClass::Query
    );
    for op in [
        IpcOperationName::ConnHistoryClear,
        IpcOperationName::ConnHistorySettingsSet,
    ] {
        assert_eq!(spec(op).class, IpcInteractionClass::Command);
        assert!(!spec(op).requires_service_mutation_privilege);
        assert_eq!(
            canonical_operation_class(op, &json!({})),
            IpcOperationClass::UserScopedConfiguration
        );
    }
}

#[test]
fn a_bare_list_request_reads_everything_kept() {
    let back: ConnHistoryListRequest =
        serde_json::from_value(json!({})).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back.from_unix_ms, 0);
    assert!(back.to_unix_ms.is_none() && back.program.is_none() && back.verdict.is_none());
    let wire = serde_json::to_value(ConnHistoryListRequest {
        from_unix_ms: 5,
        to_unix_ms: Some(9),
        program: Some("browser".into()),
        verdict: Some("block".into()),
        ..ConnHistoryListRequest::default()
    })
    .unwrap_or_else(|e| panic!("{e}"));
    for key in [
        "from-unix-ms",
        "to-unix-ms",
        "program",
        "verdict",
        "pagination",
    ] {
        assert!(wire.get(key).is_some(), "{key} missing from {wire}");
    }
}

#[test]
fn a_list_response_round_trips_under_kebab_keys() {
    let response = ConnHistoryListResponse {
        page: PageResult::single_page(vec![ConnHistoryEntryDto {
            process: "browser.exe".into(),
            process_path: "C:\\Apps\\browser.exe".into(),
            host: "site.example".into(),
            remote_ip: "192.0.2.10".into(),
            route: "secondary".into(),
            verdict: "permit".into(),
            blocked_by: String::new(),
            block_reason: String::new(),
            first_seen_ms: 1_700_000_000_000,
            last_seen_ms: 1_700_000_005_000,
            attempts: 12,
        }]),
        enabled: true,
        retention_days: 7,
        max_retention_days: 30,
        available: true,
        removed: 3,
        skipped: 0,
    };
    let wire = serde_json::to_value(&response).unwrap_or_else(|e| panic!("{e}"));
    for key in [
        "enabled",
        "retention-days",
        "max-retention-days",
        "available",
        "removed",
        "skipped",
    ] {
        assert!(wire.get(key).is_some(), "{key} missing from {wire}");
    }
    let row = &wire["page"]["items"][0];
    for key in [
        "process",
        "process-path",
        "host",
        "remote-ip",
        "route",
        "verdict",
        "blocked-by",
        "block-reason",
        "first-seen-ms",
        "last-seen-ms",
        "attempts",
    ] {
        assert!(row.get(key).is_some(), "{key} missing from {row}");
    }
    let back: ConnHistoryListResponse =
        serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back.page.items, response.page.items);
}

#[test]
fn the_write_requests_name_only_what_changes() {
    let clear =
        serde_json::to_value(ConnHistoryClearRequest::default()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(clear, json!({}));
    let off: ConnHistorySettingsSetRequest =
        serde_json::from_value(json!({ "enabled": false })).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(off.enabled, Some(false));
    assert_eq!(off.retention_days, None, "an absent field keeps its value");
    let reply = serde_json::to_value(ConnHistorySettingsSetResponse {
        enabled: false,
        retention_days: 7,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(reply, json!({ "enabled": false, "retention-days": 7 }));
}

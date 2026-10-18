//! `rules.recent-changes.list` — what the caller changed in their rules
//! lately. The GUI and the terminal read these keys by name, so the wire
//! spelling is pinned here.

use nrr_shared::ipc::{ipc_operation_spec, IpcClientProfile, IpcOperationName};
use nrr_shared::ipc_payloads::{
    RecentRuleChangeDto, RecentRuleChangeKind, RecentRulePreviousDto, RuleRowEntry,
    RulesRecentChangesRequest, RulesRecentChangesResponse,
};
use nrr_shared::ipc_transport::{canonical_operation_class, IpcOperationClass};
use serde_json::json;

fn row(value: &str, route: &str) -> RuleRowEntry {
    RuleRowEntry {
        id: "r-0001".into(),
        rule_type: "domain".into(),
        match_value: value.into(),
        target_route: route.into(),
        verify: false,
        comment: Some("note".into()),
        enabled: true,
        validation_status: "ok".into(),
        main_route: None,
        validation_message_key: None,
        hosts_override: None,
        origin: None,
        pinned_destinations: None,
        pinned_destinations_total: None,
    }
}

#[test]
fn the_operation_travels_under_its_slug_as_a_read() {
    let op = IpcOperationName::RulesRecentChangesList;
    assert_eq!(op.slug(), "rules.recent-changes.list");
    assert_eq!(IpcOperationName::from_slug(op.slug()), Some(op));
    let spec = ipc_operation_spec(op).unwrap_or_else(|| panic!("in the catalog"));
    assert!(!spec.requires_service_mutation_privilege);
    for profile in [IpcClientProfile::GuiInteractive, IpcClientProfile::Tui] {
        assert!(spec.allowed_clients.contains(&profile), "{profile:?}");
    }
    assert!(!spec
        .allowed_clients
        .contains(&IpcClientProfile::AdminConsole));
    assert_eq!(
        canonical_operation_class(op, &json!({ "since": 1_700_000_000 })),
        IpcOperationClass::ReadSnapshot
    );
}

#[test]
fn the_request_names_a_moment() {
    let wire = serde_json::to_value(RulesRecentChangesRequest { since: 42 })
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire, json!({ "since": 42 }));
    let empty: RulesRecentChangesRequest =
        serde_json::from_value(json!({})).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(empty.since, 0);
}

#[test]
fn a_response_round_trips_under_kebab_keys() {
    let response = RulesRecentChangesResponse {
        changes: vec![
            RecentRuleChangeDto {
                kind: RecentRuleChangeKind::Changed,
                at: 1_700_000_100,
                rule: Some(row("site.example", "secondary")),
                previous: Some(RecentRulePreviousDto {
                    target_route: "primary".into(),
                    enabled: true,
                    verify: false,
                }),
                exists_now: false,
                count: 0,
                members: Vec::new(),
            },
            RecentRuleChangeDto {
                kind: RecentRuleChangeKind::Deleted,
                at: 1_700_000_050,
                rule: Some(row("gone.example", "primary")),
                previous: None,
                exists_now: true,
                count: 0,
                members: Vec::new(),
            },
            RecentRuleChangeDto {
                kind: RecentRuleChangeKind::Replaced,
                at: 1_700_000_000,
                rule: None,
                previous: None,
                exists_now: false,
                count: 2,
                members: vec![row("a.example", "primary"), row("b.example", "block")],
            },
        ],
        history_starts_at: Some(1_699_999_000),
        truncated: true,
    };
    let wire = serde_json::to_value(&response).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire["changes"][0]["kind"], "changed");
    assert_eq!(wire["changes"][0]["previous"]["target-route"], "primary");
    assert_eq!(wire["changes"][0]["rule"]["match-value"], "site.example");
    assert_eq!(wire["changes"][1]["kind"], "deleted");
    assert_eq!(wire["changes"][1]["exists-now"], true);
    assert_eq!(wire["changes"][2]["kind"], "replaced");
    assert_eq!(wire["changes"][2]["count"], 2);
    assert!(wire["changes"][2].get("rule").is_none());
    assert_eq!(wire["history-starts-at"], 1_699_999_000);
    assert_eq!(wire["truncated"], true);
    let back: RulesRecentChangesResponse =
        serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(back, response);
}

#[test]
fn what_a_peer_leaves_out_reads_as_nothing_to_show() {
    let back: RulesRecentChangesResponse =
        serde_json::from_value(json!({})).unwrap_or_else(|e| panic!("{e}"));
    assert!(back.changes.is_empty());
    assert_eq!(back.history_starts_at, None);
    assert!(!back.truncated);
}

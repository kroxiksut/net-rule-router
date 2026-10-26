//! `snapshot.initial.get` — the standing enforcement reports.
//!
//! The push about whether a role's rules are in force fires on change only; a
//! client that connects later reads the same report from the snapshot and feeds
//! it to the handler it already has for the push. These tests pin the field's
//! wire shape to the push's, and that peers on either side of the change still
//! decode each other.

use nrr_shared::diagnostics_dto::DiagnosticsStatusDto;
use nrr_shared::ipc_payloads::{
    EnforcementStatusDto, RoutesHeldDto, SnapshotInitialResponse, StatusUpdateEvent,
    TrafficCarriedDto,
};
use serde_json::{json, Value};

/// A snapshot as a service without the field sends it.
fn snapshot_without_enforcement() -> Value {
    json!({
        "health": {
            "service-state": "running",
            "worst-severity": "ok",
            "components": []
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
                quiet: false,
            },
            EnforcementStatusDto {
                status: "adapter-gone".into(),
                role: "primary".into(),
                candidates: vec!["Ethernet".into()],
                since_unix_ms: None,
                quiet: false,
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
        quiet: false,
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
        quiet: false,
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
        quiet: false,
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

#[test]
fn quiet_travels_only_when_set_and_an_older_report_reads_as_loud() {
    let report = EnforcementStatusDto {
        status: "secondary-down".into(),
        role: "secondary".into(),
        candidates: Vec::new(),
        since_unix_ms: None,
        quiet: true,
    };
    let wire = serde_json::to_value(&report).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wire["quiet"], true);
    let loud = EnforcementStatusDto {
        quiet: false,
        ..report
    };
    let wire = serde_json::to_value(&loud).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("quiet").is_none(), "{wire}");
    let back: EnforcementStatusDto = serde_json::from_value(wire).unwrap_or_else(|e| panic!("{e}"));
    assert!(!back.quiet);
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

/// Destinations held by another signed-in user: absent when there are none,
/// and shaped like the push so the client feeds both to one handler.
#[test]
fn routes_held_by_another_user_is_optional_and_shaped_like_its_push() {
    let older = parse(snapshot_without_enforcement());
    assert_eq!(older.routes_held_by_another_user, None);
    let wire = serde_json::to_value(&older).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("routes-held-by-another-user").is_none(), "{wire}");

    let mut v = snapshot_without_enforcement();
    v["routes-held-by-another-user"] = json!({ "count": 3, "sample": ["198.51.100.1"] });
    let held = parse(v)
        .routes_held_by_another_user
        .unwrap_or_else(|| panic!("the report must decode"));
    assert_eq!(
        held,
        RoutesHeldDto {
            count: 3,
            sample: vec!["198.51.100.1".into()],
        }
    );

    let mut pushed = serde_json::to_value(StatusUpdateEvent::RoutesHeldByAnotherUser {
        sid: "S-1-5-21-0".into(),
        count: 3,
        sample: vec!["198.51.100.1".into()],
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let fields = pushed
        .as_object_mut()
        .unwrap_or_else(|| panic!("an event is an object"));
    fields.remove("type");
    fields.remove("sid");
    assert_eq!(
        serde_json::to_value(&held).unwrap_or_else(|e| panic!("{e}")),
        pushed
    );
}

/// Traffic carried through another user's tunnel: absent while it is not, and
/// shaped like the push so the client feeds both to one handler.
#[test]
fn traffic_carried_by_another_user_is_optional_and_shaped_like_its_push() {
    let older = parse(snapshot_without_enforcement());
    assert_eq!(older.traffic_carried_by_another_user, None);
    let wire = serde_json::to_value(&older).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        wire.get("traffic-carried-by-another-user").is_none(),
        "{wire}"
    );

    let mut v = snapshot_without_enforcement();
    v["traffic-carried-by-another-user"] = json!({ "carried": true, "link": "Example Tunnel" });
    let carried = parse(v)
        .traffic_carried_by_another_user
        .unwrap_or_else(|| panic!("the report must decode"));
    assert_eq!(
        carried,
        TrafficCarriedDto {
            carried: true,
            link: "Example Tunnel".into(),
        }
    );

    let mut pushed = serde_json::to_value(StatusUpdateEvent::TrafficCarriedByAnotherUser {
        sid: "S-1-5-21-0".into(),
        carried: true,
        link: "Example Tunnel".into(),
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let fields = pushed
        .as_object_mut()
        .unwrap_or_else(|| panic!("an event is an object"));
    fields.remove("type");
    fields.remove("sid");
    assert_eq!(
        serde_json::to_value(&carried).unwrap_or_else(|e| panic!("{e}")),
        pushed
    );
}

/// The start of a first save: absent from an older service's snapshot, and
/// spelled in the route-policy slugs where it is sent.
#[test]
fn the_first_policy_is_optional_and_spelled_in_policy_slugs() {
    use nrr_shared::ipc_payloads::{BehaviorModeDto, FirstPolicyDto, LeakProtectionDto};
    let older = parse(snapshot_without_enforcement());
    assert_eq!(older.first_policy, None);
    let wire = serde_json::to_value(&older).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("first-policy").is_none(), "{wire}");

    let mut v = snapshot_without_enforcement();
    v["first-policy"] = json!({
        "mode": "prefer-secondary-when-available",
        "leak-protection-at-least": "everything"
    });
    assert_eq!(
        parse(v).first_policy,
        Some(FirstPolicyDto {
            mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
            leak_protection_at_least: LeakProtectionDto::Everything,
        })
    );
}

/// The caller's unreadable rule book: absent while it reads, `true` while not.
#[test]
fn rules_book_unreadable_is_optional_and_omitted_while_false() {
    let older = parse(snapshot_without_enforcement());
    assert!(!older.rules_book_unreadable);
    let wire = serde_json::to_value(&older).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("rules-book-unreadable").is_none(), "{wire}");

    let mut v = snapshot_without_enforcement();
    v["rules-book-unreadable"] = json!(true);
    assert!(parse(v).rules_book_unreadable);
}

/// A found program whose rule carries none of its traffic rides its own key,
/// so an older service (key absent) leaves only today's "not found" list and
/// a client that does not know the key never reads it as a missing program.
#[test]
fn unrouted_app_rules_are_optional_and_kept_apart_from_missing_programs() {
    let older = parse(snapshot_without_enforcement());
    assert!(older.unrouted_app_rules.is_empty());
    let wire = serde_json::to_value(&older).unwrap_or_else(|e| panic!("{e}"));
    assert!(wire.get("unrouted-app-rules").is_none(), "{wire}");

    let mut v = snapshot_without_enforcement();
    v["unrouted-app-rules"] = json!({ "helper.exe": "addresses-named-by-rules" });
    let parsed = parse(v);
    assert_eq!(
        parsed
            .unrouted_app_rules
            .get("helper.exe")
            .map(String::as_str),
        Some("addresses-named-by-rules")
    );
    assert!(parsed.unenforced_app_rules.is_empty());
}

#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc_payloads::StatusUpdateEvent;
use serde_json::{json, Value};

use super::*;
use crate::backend::{BackendEvent, PushEvent};
use crate::link::Link;
use crate::testing::{app_at, missing_from_locales, snapshot_json, texts_en, FakeService, Fixture};

const PROGRAM: &str = r"C:\Program Files\Corp\corp-vpn.exe";

fn dto(address: &str, program: &str) -> VpnGatewayDto {
    VpnGatewayDto {
        address: address.to_owned(),
        program: program.to_owned(),
    }
}

fn push(gateways: Vec<VpnGatewayDto>) -> BackendEvent {
    BackendEvent::Push(PushEvent::Status(Box::new(
        StatusUpdateEvent::VpnGatewayAwaitingConfirmation {
            sid: "S".into(),
            gateways,
        },
    )))
}

fn run(app: &mut AppState, service: &FakeService) {
    for job in app.outbox.take() {
        (job(service).0)(app);
    }
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

/// The snapshot carries both lists for a later connect.
#[test]
fn the_snapshot_brings_the_pending_and_the_allowed_gateways() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot["pending-vpn-gateways"] = json!([{ "address": "203.0.113.20", "program": PROGRAM }]);
    snapshot["confirmed-vpn-gateways"] = json!([{ "address": "198.51.100.7", "program": "" }]);
    app.apply(
        BackendEvent::Snapshot(Box::new(
            serde_json::from_value(snapshot).expect("fixture snapshot must parse"),
        )),
        &texts_en(),
        Instant::now(),
    );
    assert_eq!(
        app.vpn_gateway_trust.pending,
        vec![dto("203.0.113.20", PROGRAM)]
    );
    assert_eq!(
        app.vpn_gateway_trust.confirmed,
        vec![dto("198.51.100.7", "")]
    );
}

/// The push replaces the pending list and says so once; an empty one
/// withdraws the question without news and reads the snapshot again.
#[test]
fn a_push_replaces_the_pending_list_and_an_empty_one_withdraws_it() {
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let before = app.notices.len();
    app.apply(
        push(vec![dto("203.0.113.20", PROGRAM)]),
        &texts,
        Instant::now(),
    );
    assert_eq!(app.vpn_gateway_trust.pending.len(), 1);
    assert_eq!(app.notices.len(), before + 1);
    let notice = app.notices.last().expect("a notice");
    assert_eq!(notice.title, "Let this VPN connect?");
    assert!(
        notice.body.contains("corp-vpn.exe") && notice.body.contains("203.0.113.20"),
        "{notice:?}"
    );

    let effects = app.apply(push(Vec::new()), &texts, Instant::now());
    assert!(app.vpn_gateway_trust.pending.is_empty());
    assert_eq!(
        app.notices.len(),
        before + 1,
        "a withdrawn question is not news"
    );
    assert!(effects.contains(&Effect::Refresh), "{effects:?}");
}

/// Allowing writes what the service already holds plus every pending
/// gateway, takes the stored list back and announces the address.
#[test]
fn allowing_sends_the_stored_list_with_the_pending_gateways_added() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::SnapshotInitialGet,
        json!({ "confirmed-vpn-gateways": [{ "address": "198.51.100.7", "program": "" }] }),
    );
    let stored = json!({ "gateways": [
        { "address": "198.51.100.7", "program": "" },
        { "address": "203.0.113.20", "program": PROGRAM }
    ] });
    fake.answer(IpcOperationName::RouteVpnGatewaysSet, stored.clone());

    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.vpn_gateway_trust.pending = vec![
        dto("203.0.113.20", PROGRAM),
        dto("203.0.113.20", ""),
        dto("198.51.100.7", ""),
    ];
    assert!(allow_pending(&mut app));
    run(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RouteVpnGatewaysSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0], stored, "existing first, each address once");
    assert!(!app.vpn_gateway_trust.busy);
    assert!(app.vpn_gateway_trust.pending.is_empty());
    assert_eq!(app.vpn_gateway_trust.confirmed.len(), 2);

    let texts = texts_en();
    announce(&mut app, &texts, Instant::now());
    let notice = app.notices.last().expect("the outcome");
    assert!(
        notice.body.contains("203.0.113.20") && notice.body.contains("198.51.100.7"),
        "{notice:?}"
    );
}

/// A write the service did not take keeps the question and says why.
#[test]
fn a_refused_write_keeps_the_question_and_warns() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::SnapshotInitialGet,
        Value::Object(Default::default()),
    );
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.vpn_gateway_trust.pending = vec![dto("203.0.113.20", "")];
    assert!(allow_pending(&mut app));
    run(&mut app, &fake);
    assert_eq!(app.vpn_gateway_trust.pending.len(), 1);
    announce(&mut app, &texts_en(), Instant::now());
    let notice = app.notices.last().expect("the outcome");
    assert_eq!(notice.level, NoticeLevel::Warning);
}

#[test]
fn nothing_is_sent_while_offline_or_with_nothing_pending() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    assert!(!allow_pending(&mut app));
    app.vpn_gateway_trust.pending = vec![dto("203.0.113.20", "")];
    app.link = Link::Offline;
    assert!(!allow_pending(&mut app));
    assert!(app.outbox.take().is_empty());
}

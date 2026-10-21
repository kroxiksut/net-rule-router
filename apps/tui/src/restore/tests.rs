#![allow(clippy::expect_used)]

use std::time::Instant;

use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::user_settings::{UserSettingsStore, USER_SETTINGS_FILE_NAME};
use serde_json::{json, Value};

use super::*;
use crate::backend::BackendEvent;
use crate::link::Link;
use crate::screens::suggestions::tests::drain;
use crate::screens::{screen, ScreenId};
use crate::testing::{
    missing_from_locales, snapshot_json, texts_en, FakeService, Fixture, Scratch,
};

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

/// A healthy service that lost the user's settings: its own defaults, no mutes.
fn wiped_service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::SnapshotInitialGet,
        snapshot_json(&Fixture::healthy()),
    );
    fake.answer(
        IpcOperationName::BlockNoticeMutesList,
        json!({ "mutes": [] }),
    );
    fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
    fake.answer(
        IpcOperationName::BlockNoticeMutesSet,
        json!({ "mutes": [{ "scope": { "kind": "all" } }] }),
    );
    fake
}

fn settings_file(dir: &Scratch) -> PathBuf {
    dir.path().join(USER_SETTINGS_FILE_NAME)
}

/// The Status screen right after a connect, with `intent` recorded in the
/// user's settings file (`None`: a session without one, as under `sudo`).
fn connected(file: Option<PathBuf>, intent: Value, fake: &FakeService) -> AppState {
    if let Some(file) = &file {
        UserSettingsStore::at(file.clone())
            .update(|settings| {
                for (namespace, value) in intent.as_object().into_iter().flatten() {
                    settings.set_intent(namespace, value.clone());
                }
            })
            .expect("seed");
    }
    let mut app = AppState::new(ScreenId::Status, false);
    app.rules.settings_file = file;
    let texts = texts_en();
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let snapshot = Box::new(Fixture::healthy().snapshot());
    app.apply(BackendEvent::Snapshot(snapshot), &texts, Instant::now());
    drain(&mut app, fake);
    app
}

fn last_notice(app: &AppState) -> String {
    app.notices
        .last()
        .map(|n| format!("{}: {}", n.title, n.body))
        .unwrap_or_default()
}

fn recorded(file: &Path) -> Value {
    let settings = UserSettingsStore::at(file.to_path_buf())
        .load()
        .expect("read")
        .unwrap_or_default();
    Value::Object(settings.service_intent)
}

#[test]
fn a_lost_setting_is_offered_on_the_feed_and_nothing_is_sent() {
    let dir = Scratch::new("restore-offer");
    let fake = wiped_service();
    let intent = json!({ "route-policy": { "include-subdomains": false } });
    let app = connected(Some(settings_file(&dir)), intent, &fake);

    assert_eq!(
        app.restore.offer,
        Some(Offer {
            keys: vec!["include-subdomains".into()],
            mutes: 0
        })
    );
    let said = last_notice(&app);
    assert!(
        said.starts_with("The service does not have your settings"),
        "{said}"
    );
    assert!(said.contains("Also cover subdomains"), "{said}");
    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
}

#[test]
fn r_restores_with_one_apply_only_write_and_records_it_again() {
    let dir = Scratch::new("restore-write");
    let fake = wiped_service();
    let intent = json!({ "route-policy": { "include-subdomains": false } });
    let mut app = connected(Some(settings_file(&dir)), intent, &fake);

    assert!(screen(ScreenId::Status).on_line(&mut app, "r"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["include-subdomains"]));
    assert_eq!(sent[0]["include-subdomains"], json!(false));
    assert_eq!(app.restore.offer, None);
    assert!(last_notice(&app).contains("Your settings were restored."));
    assert_eq!(
        recorded(&settings_file(&dir))["route-policy"],
        json!({ "include-subdomains": false })
    );
}

/// Protection the record holds on goes back on at the connect, unasked, and
/// the feed says so; it is never part of the offer.
#[test]
fn lost_protection_is_switched_back_on_at_once_and_said() {
    let dir = Scratch::new("restore-protection");
    let fake = wiped_service();
    let intent = json!({ "route-policy": {
        "leak-protection": "sites",
        "include-subdomains": false
    } });
    let app = connected(Some(settings_file(&dir)), intent, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["leak-protection"]));
    assert_eq!(sent[0]["leak-protection"], json!("sites"));
    assert_eq!(
        app.restore.offer,
        Some(Offer {
            keys: vec!["include-subdomains".into()],
            mutes: 0
        })
    );
    let said: Vec<String> = app.notices.iter().map(|n| n.title.clone()).collect();
    assert!(
        said.iter()
            .any(|t| t == "Protection restored after a service failure"),
        "{said:?}"
    );
}

/// A record that holds protection weaker than the service never lowers it
/// unasked.
#[test]
fn a_record_of_weaker_protection_is_only_offered() {
    let dir = Scratch::new("restore-protection-off");
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot["route-policy"]["leak-protection"] = json!("everything");
    fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
    fake.answer(
        IpcOperationName::BlockNoticeMutesList,
        json!({ "mutes": [] }),
    );
    let intent = json!({ "route-policy": { "leak-protection": "sites" } });
    let app = connected(Some(settings_file(&dir)), intent, &fake);

    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
    assert_eq!(
        app.restore.offer.as_ref().map(|o| o.keys.clone()),
        Some(vec!["leak-protection".to_string()])
    );
}

/// A record written before leak protection was one choice still protects
/// after the service lost its data: the strict mode comes back as everything
/// at once, and its additional default route is offered.
#[test]
fn a_record_of_retired_settings_restores_what_it_protected() {
    let dir = Scratch::new("restore-retired");
    let fake = wiped_service();
    let intent = json!({ "route-policy": {
        "mode": "strict-secondary-fail-closed",
        "kill-switch-enabled": true,
        "kill-switch-fail-closed": true,
        "kill-switch-block-all": true
    } });
    let app = connected(Some(settings_file(&dir)), intent, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["leak-protection"]));
    assert_eq!(sent[0]["leak-protection"], json!("everything"));
    assert!(sent[0].get("kill-switch-enabled").is_none());
    assert_eq!(
        app.restore.offer,
        Some(Offer {
            keys: vec!["mode".into()],
            mutes: 0
        })
    );
}

#[test]
fn a_binding_whose_adapter_is_gone_is_reported_not_sent() {
    let dir = Scratch::new("restore-missing");
    let fake = wiped_service();
    let intent = json!({ "route-policy": { "secondary": {
        "stable-id": "{00000000-0000-0000-0000-0000000000ff}",
        "display-name": "Old Tunnel",
        "user-confirmed": true
    }}});
    let mut app = connected(Some(settings_file(&dir)), intent, &fake);
    assert!(app.restore.offer.is_some());

    assert!(screen(ScreenId::Status).on_line(&mut app, "r"));
    drain(&mut app, &fake);

    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
    let said = last_notice(&app);
    assert!(
        said.contains("Not restored: the adapter Old Tunnel is not on this computer now."),
        "{said}"
    );
}

#[test]
fn a_lost_mute_is_brought_back() {
    let dir = Scratch::new("restore-mute");
    let fake = wiped_service();
    let intent = json!({ "notice-mutes": [{ "scope": { "kind": "all" } }] });
    let mut app = connected(Some(settings_file(&dir)), intent, &fake);
    assert_eq!(app.restore.offer.as_ref().map(|o| o.mutes), Some(1));

    assert!(screen(ScreenId::Status).on_line(&mut app, "r"));
    drain(&mut app, &fake);

    let set = fake.sent(IpcOperationName::BlockNoticeMutesSet);
    assert_eq!(set, [json!({ "scope": { "kind": "all" } })]);
    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
}

#[test]
fn nothing_lost_offers_nothing() {
    let dir = Scratch::new("restore-same");
    let fake = wiped_service();
    let intent = json!({ "route-policy": { "mode": "prefer-primary" } });
    let mut app = connected(Some(settings_file(&dir)), intent, &fake);
    assert_eq!(app.restore.offer, None);
    assert!(!screen(ScreenId::Status).on_line(&mut app, "r"));
}

#[test]
fn under_sudo_nothing_is_compared_or_recorded() {
    let fake = wiped_service();
    let mut app = connected(None, json!({}), &fake);
    assert_eq!(app.restore.offer, None);
    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeMutesList).len(),
        1,
        "only the feed's own read: no comparison without a settings file of the user's own"
    );
    let named = json!({ "mode": "x", "apply-only": ["mode"] });
    record_route_policy(&app, named.as_object().expect("object"));
    assert!(!screen(ScreenId::Status).on_line(&mut app, "r"));
}

#[test]
fn a_confirmed_write_records_only_the_keys_it_named() {
    let dir = Scratch::new("restore-record");
    let mut app = AppState::new(ScreenId::Status, false);
    app.rules.settings_file = Some(settings_file(&dir));
    let request = json!({
        "mode": "prefer-primary",
        "leak-protection": "everything",
        "apply-only": ["leak-protection"]
    });
    record_route_policy(&app, request.as_object().expect("object"));
    assert_eq!(
        recorded(&settings_file(&dir)),
        json!({ "route-policy": { "leak-protection": "everything" } })
    );

    let mutes = vec![BlockNoticeMuteDto {
        scope: nrr_shared::ipc_payloads::BlockNoticeMuteScopeDto::All,
        until_unix_ms: None,
    }];
    record_mutes(&app, &mutes);
    assert_eq!(
        recorded(&settings_file(&dir))["notice-mutes"],
        json!([{ "scope": { "kind": "all" } }])
    );
}

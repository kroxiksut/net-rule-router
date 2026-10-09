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
    let intent = json!({ "route-policy": { "kill-switch-enabled": true } });
    let app = connected(Some(settings_file(&dir)), intent, &fake);

    assert_eq!(
        app.restore.offer,
        Some(Offer {
            keys: vec!["kill-switch-enabled".into()],
            mutes: 0
        })
    );
    let said = last_notice(&app);
    assert!(
        said.starts_with("The service does not have your settings"),
        "{said}"
    );
    assert!(said.contains("Enable leak protection"), "{said}");
    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
}

#[test]
fn r_restores_with_one_apply_only_write_and_records_it_again() {
    let dir = Scratch::new("restore-write");
    let fake = wiped_service();
    let intent = json!({ "route-policy": { "kill-switch-enabled": true } });
    let mut app = connected(Some(settings_file(&dir)), intent, &fake);

    assert!(screen(ScreenId::Status).on_line(&mut app, "r"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["kill-switch-enabled"]));
    assert_eq!(sent[0]["kill-switch-enabled"], json!(true));
    assert_eq!(app.restore.offer, None);
    assert!(last_notice(&app).contains("Your settings were restored."));
    assert_eq!(
        recorded(&settings_file(&dir))["route-policy"],
        json!({ "kill-switch-enabled": true })
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
    assert!(
        fake.sent(IpcOperationName::BlockNoticeMutesList).is_empty(),
        "no comparison without a settings file of the user's own"
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
        "kill-switch-enabled": true,
        "apply-only": ["kill-switch-enabled"]
    });
    record_route_policy(&app, request.as_object().expect("object"));
    assert_eq!(
        recorded(&settings_file(&dir)),
        json!({ "route-policy": { "kill-switch-enabled": true } })
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

#![allow(clippy::expect_used)]

use crossterm::event::KeyCode;
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::user_settings::{UserSettingsStore, USER_SETTINGS_FILE_NAME};
use serde_json::json;

use super::items::{ItemId, PrefField};
use super::*;
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::suggestions::tests::{drain, press, render};
use crate::screens::{screen, ScreenId};
use crate::testing::{
    app_at, assert_snapshot, missing_from_locales, snapshot_json, texts_en, FakeService, Fixture,
    Scratch,
};

const NOW_MS: i64 = 1_700_000_000_000;

fn fixed_now() -> i64 {
    NOW_MS
}

fn utc(_: i64) -> i32 {
    0
}

fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::SnapshotInitialGet,
        snapshot_json(&Fixture::healthy()),
    );
    fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
    fake.answer(
        IpcOperationName::BlockNoticeMutesList,
        json!({ "mutes": [] }),
    );
    fake
}

/// The Settings screen with the service up and the clock fixed.
fn on_settings() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.settings.clock = Clock {
        now_ms: fixed_now,
        utc_offset: utc,
    };
    app.open(ScreenId::Settings);
    app
}

fn answer(app: &mut AppState, line: &str) {
    assert!(screen(ScreenId::Settings).on_line(app, line), "{line:?}");
}

/// The line-mode number of the row that stands for `id` in `category`.
fn row_of(app: &AppState, category: Category, id: ItemId) -> usize {
    items::items(app, category)
        .iter()
        .filter(|item| item.selectable())
        .position(|item| item.id == id)
        .unwrap_or_else(|| panic!("no row for {id:?}"))
        + 1
}

fn said(app: &AppState) -> String {
    app.settings
        .message
        .as_ref()
        .map(|m| m.words.resolve(&texts_en()))
        .unwrap_or_default()
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&text::all());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn zero_lists_the_sections() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    press(&mut app, KeyCode::Char('0'));
    let picture = render(&app, 80, 24);
    assert!(picture.contains("Settings sections"), "{picture}");
    assert!(picture.contains("c9. Terminal"), "{picture}");
    assert_snapshot("settings-80x24", &picture);
}

#[test]
fn a_routing_switch_names_only_its_own_key_and_is_recorded() {
    let dir = Scratch::new("settings-routing");
    let file = dir.path().join(USER_SETTINGS_FILE_NAME);
    let fake = service();
    let mut app = on_settings();
    app.rules.settings_file = Some(file.clone());
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    if !app.settings.supports.kill_switch {
        return;
    }
    let row = row_of(
        &app,
        Category::Routing,
        ItemId::Policy("kill-switch-enabled"),
    );
    answer(&mut app, &format!("i{row}"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["kill-switch-enabled"]));
    assert_eq!(sent[0]["kill-switch-enabled"], json!(true));
    assert_eq!(said(&app), texts_en().get(text::SAVED));
    let recorded = UserSettingsStore::at(file)
        .load()
        .expect("read")
        .expect("recorded");
    assert_eq!(
        recorded.intent("route-policy"),
        Some(&json!({ "kill-switch-enabled": true }))
    );
}

#[test]
fn programs_taking_all_their_traffic_is_a_routing_switch_off_by_default() {
    let fake = service();
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    let id = ItemId::Policy("app-rules-take-all-addresses");
    let row = row_of(&app, Category::Routing, id);
    let item = items::items(&app, Category::Routing)
        .into_iter()
        .find(|item| item.id == id)
        .expect("the switch is listed");
    assert_eq!(item.kind, items::Kind::Toggle(false));
    answer(&mut app, &format!("i{row}"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0]["apply-only"],
        json!(["app-rules-take-all-addresses"])
    );
    assert_eq!(sent[0]["app-rules-take-all-addresses"], json!(true));
}

/// The row is there whatever the adapters are called, says so when
/// unanswered, and picking an answer writes that key alone.
#[test]
fn forwarded_traffic_is_answered_in_routing_with_no_guest_named() {
    let fake = service();
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    if !app.settings.supports.forwarded_traffic_guard {
        return;
    }
    let id = ItemId::Policy("forwarded-outage");
    let listed = |app: &AppState| {
        items::items(app, Category::Routing)
            .into_iter()
            .find(|item| item.id == id)
    };
    let item = listed(&app).expect("the row, with no WSL adapter up");
    assert_eq!(
        item.value().map(|v| v.resolve(&texts_en())),
        Some(texts_en().get(text::FWD_UNANSWERED))
    );
    let row = row_of(&app, Category::Routing, id);
    answer(&mut app, &format!("i{row} 2"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["forwarded-outage"]));
    assert_eq!(sent[0]["forwarded-outage"], json!("unprotected"));
}

#[test]
fn hiding_a_notice_kind_for_a_week_sends_its_deadline() {
    let fake = service();
    fake.answer(
        IpcOperationName::BlockNoticeMutesSet,
        json!({ "mutes": [{
            "scope": { "kind": "notice", "notice": "rules-drift" },
            "until-unix-ms": NOW_MS + 7 * 86_400_000
        }] }),
    );
    let mut app = on_settings();
    answer(&mut app, "c1");
    drain(&mut app, &fake);
    let row = row_of(
        &app,
        Category::Notifications,
        ItemId::HideKind("rules-drift"),
    );
    // Options: show, a day, 7 days, …
    answer(&mut app, &format!("i{row} 3"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::BlockNoticeMutesSet);
    assert_eq!(
        sent,
        [json!({
            "scope": { "kind": "notice", "notice": "rules-drift" },
            "until-unix-ms": NOW_MS + 7 * 86_400_000
        })]
    );
    let mutes = app.settings.data.mutes.ready().expect("mutes");
    assert_eq!(mutes.len(), 1);
}

#[test]
fn a_change_without_the_service_is_refused_in_words() {
    let fake = service();
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    let texts = texts_en();
    app.apply(
        crate::backend::BackendEvent::Link(Link::Stopped),
        &texts,
        std::time::Instant::now(),
    );
    let row = row_of(
        &app,
        Category::Routing,
        ItemId::Policy("include-subdomains"),
    );
    answer(&mut app, &format!("i{row}"));
    assert_eq!(said(&app), texts.get(text::OFFLINE));
    assert!(fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty());
}

#[test]
fn an_export_needs_a_file_name_first() {
    let mut app = on_settings();
    answer(&mut app, "c5");
    let row = row_of(&app, Category::Presets, ItemId::ExportRun);
    answer(&mut app, &format!("i{row}"));
    assert_eq!(said(&app), texts_en().get(text::EXPORT_NEED_PATH));
}

#[test]
fn the_terminals_own_options_are_saved_to_its_file() {
    let dir = Scratch::new("settings-prefs");
    let path = dir.path().join("tui.json");
    let mut app = on_settings();
    app.settings.prefs_path = Some(path.clone());
    answer(&mut app, "c9");
    let row = row_of(&app, Category::Terminal, ItemId::Pref(PrefField::Ascii));
    answer(&mut app, &format!("i{row}"));
    assert!(app.settings.prefs.ascii);
    assert!(prefs::load(&path).ascii);
    assert_eq!(said(&app), texts_en().get(text::PREF_SAVED));
}

#[test]
fn a_fine_mute_is_named_by_what_it_hides() {
    let texts = texts_en();
    let host = BlockNoticeMuteScopeDto::Host {
        host: "ads.example".into(),
    };
    assert!(items::scope_label(&host, &texts).contains("ads.example"));
}

#[test]
fn line_mode_walks_the_sections_by_code() {
    let texts = texts_en();
    let mut app = on_settings();
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    session.input("0", &mut app, &texts).expect("open");
    session.input("c9", &mut app, &texts).expect("terminal");
    session.input("i7", &mut app, &texts).expect("no such row");
    session.input("b", &mut app, &texts).expect("back");
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(text.contains("Settings sections"), "{text}");
    assert!(text.contains("c9. Terminal"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_snapshot("settings-plain", &text);
}

/// Where no TUN adapter opens, fake-IP is named and explained, never offered,
/// even on a service that applies the rest of the stability row.
#[test]
fn fake_ip_is_not_offered_where_the_platform_lacks_it() {
    let mut app = on_settings();
    app.settings.data.policy = Loadable::Ready(
        json!({ "kill-switch-enabled": true })
            .as_object()
            .cloned()
            .expect("an object"),
    );
    app.settings.data.stability = Loadable::Ready(
        json!({ "enforcement-mode": "resolver", "fake-ip-enabled": true })
            .as_object()
            .cloned()
            .expect("an object"),
    );
    const KEYS: [&str; 3] = [
        "fake-ip-enabled",
        "fake-ip-udp-relay",
        "fake-ip-instant-rst",
    ];
    let fake_ip_rows = |app: &AppState| {
        items::items(app, Category::Routing)
            .into_iter()
            .filter(|item| KEYS.iter().any(|&key| item.id == ItemId::Stability(key)))
            .count()
    };

    let mut with_it = PlatformProfile::windows().supports;
    with_it.fake_ip = true;
    app.settings.supports = with_it;
    assert_eq!(fake_ip_rows(&app), 3);

    let mut without = with_it;
    without.fake_ip = false;
    app.settings.supports = without;
    assert_eq!(fake_ip_rows(&app), 0);
    let texts = texts_en();
    let unsupported = texts.get(text::UNSUPPORTED);
    assert!(
        items::items(&app, Category::Routing)
            .iter()
            .any(|item| item.label.resolve(&texts).contains(&unsupported)),
        "the setting is not explained"
    );
}

/// The local networks list answers row by row, as the window does: a row that
/// no answer can open stays a line of text with its reason.
#[test]
fn a_local_network_is_answered_by_its_row() {
    let fake = service();
    let networks = json!([
        { "cidr": "192.168.1.0/24", "kind": "main-link", "adapter": "Ethernet",
          "allowed": true, "decided-by-user": true },
        { "cidr": "2001:db8:5:7::/64", "kind": "main-link", "adapter": "Ethernet",
          "allowed": false, "decided-by-user": false },
        { "cidr": "0.0.0.0/1", "kind": "main-link", "adapter": "Ethernet",
          "allowed": false, "decided-by-user": true, "reason": "too-wide" }
    ]);
    fake.answer(
        IpcOperationName::LocalNetworksGet,
        json!({ "networks": networks.clone() }),
    );
    fake.answer(
        IpcOperationName::LocalNetworksSet,
        json!({ "networks": networks, "rejected": [] }),
    );
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    if !app.settings.supports.local_network_exceptions {
        return;
    }
    let listed = items::items(&app, Category::Routing);
    let wide = listed
        .iter()
        .find(|item| item.label.resolve(&texts_en()).starts_with("0.0.0.0/1"))
        .expect("the too-wide segment is listed");
    assert!(!wide.selectable());
    assert!(wide.label.resolve(&texts_en()).contains("too wide"));

    let row = row_of(&app, Category::Routing, ItemId::LocalNetwork(1));
    answer(&mut app, &format!("i{row}"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::LocalNetworksSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(
        sent[0]["decisions"],
        json!([{ "cidr": "2001:db8:5:7::/64", "allowed": true }])
    );
    assert_eq!(said(&app), texts_en().get(text::SAVED));
}

#[test]
fn the_service_section_offers_network_recovery_in_both_states() {
    use nrr_platform_api::service_control::{ServiceRunState, ServiceStatusReport};
    let lines = |run_state| {
        let mut app = on_settings();
        app.settings.data.service = Loadable::Ready(ServiceInfo::Registered(ServiceStatusReport {
            run_state,
            start_mode: None,
            binary_path: None,
            running_since: None,
        }));
        items::items(&app, Category::Service)
            .iter()
            .map(|item| item.label.resolve(&texts_en()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let running = lines(ServiceRunState::Running);
    assert!(
        running.contains("reset-network --confirm --stop-service"),
        "{running}"
    );
    let stopped = lines(ServiceRunState::Stopped);
    assert!(stopped.contains("reset-network --confirm"), "{stopped}");
    assert!(!stopped.contains("--stop-service"), "{stopped}");
}

fn history_service() -> FakeService {
    let fake = service();
    fake.answer(
        IpcOperationName::ConnHistoryList,
        json!({
            "page": { "items": [], "next_cursor": null, "total_count": null, "stale": false },
            "enabled": true, "retention-days": 7, "max-retention-days": 30, "available": true,
            "removed": 0, "skipped": 0
        }),
    );
    fake.answer(
        IpcOperationName::ConnHistorySettingsSet,
        json!({ "enabled": false, "retention-days": 7 }),
    );
    fake.answer(IpcOperationName::ConnHistoryClear, json!({ "erased": 4 }));
    fake
}

#[test]
fn the_connection_history_is_switched_kept_and_cleared_from_logs() {
    let fake = history_service();
    let mut app = on_settings();
    answer(&mut app, "c6");
    drain(&mut app, &fake);
    assert_eq!(fake.sent(IpcOperationName::ConnHistoryList).len(), 1);

    let keep = row_of(&app, Category::Logs, ItemId::HistoryEnabled);
    answer(&mut app, &format!("i{keep}"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::ConnHistorySettingsSet),
        vec![json!({ "enabled": false })],
        "only the switch travels"
    );

    let days = row_of(&app, Category::Logs, ItemId::HistoryRetention);
    answer(&mut app, &format!("i{days} 31"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::ConnHistorySettingsSet).len(),
        1,
        "a period past the longest is refused before it is sent"
    );
    answer(&mut app, &format!("i{days} 3"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::ConnHistorySettingsSet)[1],
        json!({ "retention-days": 3 })
    );

    let clear = row_of(&app, Category::Logs, ItemId::HistoryClear);
    answer(&mut app, &format!("i{clear}"));
    drain(&mut app, &fake);
    assert!(
        fake.sent(IpcOperationName::ConnHistoryClear).is_empty(),
        "erasing asks first"
    );
    answer(&mut app, "y");
    drain(&mut app, &fake);
    assert_eq!(fake.sent(IpcOperationName::ConnHistoryClear).len(), 1);
    assert!(said(&app).contains('4'), "{}", said(&app));
}

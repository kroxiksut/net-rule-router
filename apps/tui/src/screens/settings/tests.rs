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
fn a_leak_protection_choice_names_only_its_own_key_and_is_recorded() {
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
    let row = row_of(&app, Category::Routing, ItemId::Policy("leak-protection"));
    // Options under the main connection: off, routed sites, everything.
    answer(&mut app, &format!("i{row} 2"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["apply-only"], json!(["leak-protection"]));
    assert_eq!(sent[0]["leak-protection"], json!("sites"));
    for retired in [
        "kill-switch-enabled",
        "kill-switch-fail-closed",
        "kill-switch-block-all",
        "mode-a-coverage-strategy",
    ] {
        assert!(sent[0].get(retired).is_none(), "{retired} was sent");
    }
    assert_eq!(said(&app), texts_en().get(text::SAVED));
    let recorded = UserSettingsStore::at(file)
        .load()
        .expect("read")
        .expect("recorded");
    assert_eq!(
        recorded.intent("route-policy"),
        Some(&json!({ "leak-protection": "sites" }))
    );
}

/// "Everything" while the additional connection is down stops the internet at
/// once, so the pick waits for a yes, as in the window and the tray; with the
/// connection up it is written straight away.
#[test]
fn everything_while_the_additional_connection_is_down_waits_for_a_yes() {
    for (availability, asks) in [("unavailable", true), ("available", false)] {
        let mut fixture = Fixture::healthy();
        if let Some(bound) = fixture.secondary.as_mut() {
            bound.availability = Some(availability);
        }
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::SnapshotInitialGet,
            snapshot_json(&fixture),
        );
        fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
        fake.answer(
            IpcOperationName::BlockNoticeMutesList,
            json!({ "mutes": [] }),
        );
        let mut app = app_at(Link::Connected, Some(&fixture));
        app.settings.clock = Clock {
            now_ms: fixed_now,
            utc_offset: utc,
        };
        app.open(ScreenId::Settings);
        answer(&mut app, "c2");
        drain(&mut app, &fake);
        if !app.settings.supports.kill_switch {
            return;
        }
        let row = row_of(&app, Category::Routing, ItemId::Policy("leak-protection"));
        answer(&mut app, &format!("i{row} 3"));
        drain(&mut app, &fake);
        if asks {
            assert!(
                fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty(),
                "nothing is sent before the yes"
            );
            assert_eq!(
                app.settings.mode,
                Mode::ConfirmingPick {
                    slug: "everything",
                    why: route_policy::LeakProtectionConfirm::HoldsNow,
                }
            );
            answer(&mut app, "yes");
            drain(&mut app, &fake);
        }
        let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
        assert_eq!(sent.len(), 1, "{availability}: {sent:?}");
        assert_eq!(sent[0]["leak-protection"], json!("everything"));
    }
}

/// Moving the default route to the additional connection raises "Routed
/// sites" to "Everything" in the same write, so with that connection down it
/// asks the same yes; a route change that raises nothing is written at once.
#[test]
fn a_default_route_that_raises_protection_while_the_additional_connection_is_down_waits_for_a_yes()
{
    for (availability, level, asks) in [
        ("unavailable", "sites", true),
        ("available", "sites", false),
        ("unavailable", "off", false),
    ] {
        let mut fixture = Fixture::healthy();
        if let Some(bound) = fixture.secondary.as_mut() {
            bound.availability = Some(availability);
        }
        let mut snapshot = snapshot_json(&fixture);
        snapshot["route-policy"]["leak-protection"] = json!(level);
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
        fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
        fake.answer(
            IpcOperationName::BlockNoticeMutesList,
            json!({ "mutes": [] }),
        );
        let mut app = app_at(Link::Connected, Some(&fixture));
        app.settings.clock = Clock {
            now_ms: fixed_now,
            utc_offset: utc,
        };
        app.open(ScreenId::Settings);
        answer(&mut app, "c2");
        drain(&mut app, &fake);
        let row = row_of(&app, Category::Routing, ItemId::Policy("mode"));
        // Options: the main connection, then the additional one.
        answer(&mut app, &format!("i{row} 2"));
        drain(&mut app, &fake);
        let case = format!("{availability} / {level}");
        if asks {
            assert!(
                fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty(),
                "{case}: nothing is sent before the yes"
            );
            assert_eq!(
                app.settings.mode,
                Mode::ConfirmingPick {
                    slug: "prefer-secondary-when-available",
                    why: route_policy::LeakProtectionConfirm::HoldsNow,
                },
                "{case}"
            );
            answer(&mut app, "yes");
            drain(&mut app, &fake);
        } else {
            assert_eq!(app.settings.mode, Mode::Browse, "{case}");
        }
        let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
        assert_eq!(sent.len(), 1, "{case}: {sent:?}");
        assert_eq!(
            sent[0]["mode"],
            json!("prefer-secondary-when-available"),
            "{case}"
        );
        let settled = if level == "off" { "off" } else { "everything" };
        assert_eq!(sent[0]["leak-protection"], json!(settled), "{case}");
    }
}

fn policy_of(value: serde_json::Value) -> Map<String, Value> {
    value.as_object().cloned().expect("an object")
}

fn leak_row(app: &AppState) -> Option<items::Item> {
    items::items(app, Category::Routing)
        .into_iter()
        .find(|item| item.id == ItemId::Policy("leak-protection"))
}

fn offered(item: &items::Item) -> Vec<&'static str> {
    match &item.kind {
        items::Kind::Choice { options, .. } => options.iter().map(|o| o.slug).collect(),
        other => panic!("not a choice: {other:?}"),
    }
}

/// "Routed sites" is offered only while unmatched traffic stays on the main
/// connection; a level the route does not offer shows as the one it means.
#[test]
fn routed_sites_are_offered_only_under_the_main_connection() {
    let mut app = on_settings();
    if !app.settings.supports.kill_switch {
        return;
    }
    app.settings.data.policy = Loadable::Ready(policy_of(json!({
        "mode": "prefer-primary", "leak-protection": "sites"
    })));
    let item = leak_row(&app).expect("the choice");
    assert_eq!(offered(&item), ["off", "sites", "everything"]);
    assert_eq!(
        item.value().map(|v| v.resolve(&texts_en())),
        Some(texts_en().get(text::LEAK_SITES))
    );

    app.settings.data.policy = Loadable::Ready(policy_of(json!({
        "mode": "prefer-secondary-when-available", "leak-protection": "sites"
    })));
    let item = leak_row(&app).expect("the choice");
    assert_eq!(offered(&item), ["off", "everything"]);
    assert_eq!(
        item.value().map(|v| v.resolve(&texts_en())),
        Some(texts_en().get(text::LEAK_EVERYTHING))
    );
}

/// Switching the default route to the additional connection while "Routed
/// sites" is chosen moves the choice to "Everything" in the same write.
#[test]
fn the_additional_default_route_takes_routed_sites_to_everything() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot["route-policy"]["leak-protection"] = json!("sites");
    fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
    fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
    fake.answer(
        IpcOperationName::BlockNoticeMutesList,
        json!({ "mutes": [] }),
    );
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    let row = row_of(&app, Category::Routing, ItemId::Policy("mode"));
    answer(&mut app, &format!("i{row} 2"));
    drain(&mut app, &fake);

    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["mode"], json!("prefer-secondary-when-available"));
    assert_eq!(sent[0]["leak-protection"], json!("everything"));
    assert_eq!(sent[0]["apply-only"], json!(["leak-protection", "mode"]));
}

/// The refinements show only where they act: none while protection is off,
/// name lookups over the main connection only under "Everything".
#[test]
fn leak_protection_refinements_follow_the_level() {
    let mut app = on_settings();
    if !app.settings.supports.kill_switch {
        return;
    }
    let listed = |app: &AppState, id: ItemId| {
        items::items(app, Category::Routing)
            .iter()
            .any(|item| item.id == id)
    };
    let dns = ItemId::Policy("allow-dns-over-primary");
    let strict = ItemId::Policy("kill-switch-strict-shared-ips");
    let tcp = ItemId::Protocol(1);
    for (level, protocols, dns_shown, strict_shown) in [
        ("off", false, false, false),
        ("sites", true, false, true),
        ("everything", true, true, true),
    ] {
        app.settings.data.policy = Loadable::Ready(policy_of(json!({
            "mode": "prefer-primary", "leak-protection": level
        })));
        assert_eq!(listed(&app, tcp), protocols, "{level}: protocols");
        assert_eq!(listed(&app, dns), dns_shown, "{level}: name lookups");
        assert_eq!(
            listed(&app, strict),
            strict_shown,
            "{level}: shared addresses"
        );
    }
    assert!(!listed(&app, ItemId::Policy("kill-switch-block-all")));
    assert!(!listed(&app, ItemId::Policy("mode-a-coverage-strategy")));
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

/// The window's "check the external address on connect", off by default, and
/// turning it on writes that key alone.
#[test]
fn the_external_address_check_on_connect_is_a_routing_switch_off_by_default() {
    let fake = service();
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    let id = ItemId::Policy("external-address-auto-check");
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
        json!(["external-address-auto-check"])
    );
    assert_eq!(sent[0]["external-address-auto-check"], json!(true));
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
        json!({ "leak-protection": "sites" })
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

fn routing_with(app: &mut AppState, policy: serde_json::Value, stability: serde_json::Value) {
    app.settings.data.policy = Loadable::Ready(policy.as_object().cloned().expect("an object"));
    app.settings.data.stability =
        Loadable::Ready(stability.as_object().cloned().expect("an object"));
}

fn unbind_secondary(app: &mut AppState) {
    app.snapshot
        .as_mut()
        .and_then(|s| s.route_policy.as_mut())
        .expect("the fixture carries a policy")
        .secondary = None;
}

/// The routing rows the screen shows, named as `routing_settings::offered`
/// names them.
fn shown_routing_rows(app: &AppState) -> Vec<&'static str> {
    use nrr_client_logic::routing_settings as rs;
    const STABILITY_ROWS: [&str; 7] = [
        rs::ENFORCEMENT_MODE,
        rs::DNS_VIA_SECONDARY,
        rs::DNS_FAST_ANSWERS,
        rs::FAKE_IP_ENABLED,
        rs::FAKE_IP_UDP_RELAY,
        rs::FAKE_IP_INSTANT_RST,
        rs::LIVENESS_WINDOW,
    ];
    let texts = texts_en();
    let fake_ip = texts.get(text::FAKE_IP);
    let unsupported = texts.get(text::UNSUPPORTED);
    let mut rows: Vec<&'static str> = Vec::new();
    for item in items::items(app, Category::Routing) {
        let row = match item.id {
            ItemId::Protocol(_) => Some("kill-switch-protocols"),
            ItemId::Policy(key)
                if [
                    rs::ALLOW_DNS_OVER_PRIMARY,
                    rs::SHARED_IP_POLICY,
                    rs::STRICT_SHARED_IPS,
                ]
                .contains(&key) =>
            {
                Some(key)
            }
            ItemId::Stability(key) if STABILITY_ROWS.contains(&key) => Some(key),
            ItemId::Policy("local-networks-auto-accept") => Some(rs::LOCAL_NETWORKS),
            ItemId::None => {
                let label = item.label.resolve(&texts);
                if label == format!("{fake_ip}: {unsupported}") {
                    Some(rs::FAKE_IP_UNAVAILABLE)
                } else if label == unsupported {
                    Some(rs::STABILITY_UNAVAILABLE)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(row) = row {
            if rows.last() != Some(&row) {
                rows.push(row);
            }
        }
    }
    rows
}

/// The terminal shows exactly the rows the shared decision names, the one the
/// window's `offeredRoutingSettings` is held to by vectors: same inputs, same
/// rows in both clients.
#[test]
fn the_routing_rows_are_the_shared_decision() {
    use nrr_client_logic::routing_settings::{self, RoutingContext};
    let mut app = on_settings();
    let healthy = app.snapshot.clone();
    for (fake_ip_platform, stability_platform) in [(true, true), (false, true), (true, false)] {
        let mut supports = PlatformProfile::windows().supports;
        supports.fake_ip = fake_ip_platform;
        supports.service_stability_config = stability_platform;
        app.settings.supports = supports;
        let supports_map = match serde_json::to_value(supports) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => panic!("the capability map is an object"),
        };
        for level in ["off", "sites", "everything"] {
            for mode in ["resolver", "reactive"] {
                for fake_ip in [true, false] {
                    for bound in [true, false] {
                        app.snapshot = healthy.clone();
                        if !bound {
                            unbind_secondary(&mut app);
                        }
                        routing_with(
                            &mut app,
                            json!({ "leak-protection": level }),
                            json!({ "enforcement-mode": mode, "fake-ip-enabled": fake_ip }),
                        );
                        let expected = routing_settings::offered(&RoutingContext {
                            supports: Some(&supports_map),
                            enforcement_mode: mode,
                            leak_protection: level,
                            secondary_bound: bound,
                            fake_ip_enabled: fake_ip,
                        });
                        assert_eq!(
                            shown_routing_rows(&app),
                            expected,
                            "{level} / {mode} / fake-IP {fake_ip} / bound {bound} / \
                             TUN {fake_ip_platform} / row {stability_platform}"
                        );
                    }
                }
            }
        }
    }
}

/// With leak protection off the routing refinements stay offered: the service
/// honours them at every level. "DNS through the tunnel" waits for a bound
/// additional connection instead, in either enforcement mode.
#[test]
fn routing_refinements_do_not_wait_for_leak_protection() {
    let mut app = on_settings();
    app.settings.supports = PlatformProfile::windows().supports;
    routing_with(
        &mut app,
        json!({ "leak-protection": "off" }),
        json!({ "enforcement-mode": "resolver", "fake-ip-enabled": true }),
    );
    let rows = shown_routing_rows(&app);
    for row in [
        "enforcement-mode",
        "dns-via-secondary",
        "dns-fast-answers",
        "fake-ip-enabled",
        "shared-ip-policy",
        "local-networks",
    ] {
        assert!(rows.contains(&row), "{row} hidden: {rows:?}");
    }
    assert!(!rows.contains(&"kill-switch-protocols"), "{rows:?}");

    routing_with(
        &mut app,
        json!({ "leak-protection": "sites" }),
        json!({ "enforcement-mode": "reactive" }),
    );
    assert!(shown_routing_rows(&app).contains(&"dns-via-secondary"));
    unbind_secondary(&mut app);
    assert!(!shown_routing_rows(&app).contains(&"dns-via-secondary"));
}

/// A stability write the row already holds is not sent: the Set would still
/// ask for an administrator, for a change that is not one.
#[test]
fn a_stability_write_that_changes_nothing_is_not_sent() {
    let fake = service();
    let row = json!({ "enforcement-mode": "resolver", "dns-fast-answers": true });
    fake.answer(IpcOperationName::ServiceStabilityConfigGet, row.clone());
    fake.answer(IpcOperationName::ServiceStabilityConfigSet, row);
    let mut app = on_settings();
    app.settings.supports = PlatformProfile::windows().supports;
    answer(&mut app, "c2");
    drain(&mut app, &fake);

    let mode = row_of(
        &app,
        Category::Routing,
        ItemId::Stability("enforcement-mode"),
    );
    answer(&mut app, &format!("i{mode} 1"));
    drain(&mut app, &fake);
    assert!(
        fake.sent(IpcOperationName::ServiceStabilityConfigSet)
            .is_empty(),
        "the held mode was written again"
    );

    let fast = row_of(
        &app,
        Category::Routing,
        ItemId::Stability("dns-fast-answers"),
    );
    answer(&mut app, &format!("i{fast}"));
    drain(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::ServiceStabilityConfigSet);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["config"]["dns-fast-answers"], json!(false));
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

#[test]
fn the_service_section_names_the_commands_the_terminal_cannot_run() {
    use nrr_platform_api::service_control::{
        ServiceRunState, ServiceStartMode, ServiceStatusReport,
    };
    let lines = |run_state| {
        let mut app = on_settings();
        app.settings.data.service = Loadable::Ready(ServiceInfo::Registered(ServiceStatusReport {
            run_state,
            start_mode: Some(ServiceStartMode::WithWindows),
            binary_path: None,
            running_since: None,
        }));
        items::items(&app, Category::Service)
            .iter()
            .map(|item| item.label.resolve(&texts_en()))
            .collect::<Vec<_>>()
            .join(
                "
",
            )
    };
    let running = lines(ServiceRunState::Running);
    assert!(running.contains("uninstall"), "{running}");
    assert!(running.contains("reinstall"), "{running}");
    assert!(running.contains("--start-mode=on-demand"), "{running}");
    assert!(running.contains("Reason (required)"), "{running}");
    let stopped = lines(ServiceRunState::Stopped);
    assert!(
        !stopped.contains("Reason (required)"),
        "safe disable needs a live service:
{stopped}"
    );
}

#[test]
fn a_safe_disable_without_a_reason_sends_nothing() {
    let mut app = on_settings();
    app.settings.data.service = Loadable::Ready(ServiceInfo::Registered(
        nrr_platform_api::service_control::ServiceStatusReport {
            run_state: nrr_platform_api::service_control::ServiceRunState::Running,
            start_mode: None,
            binary_path: None,
            running_since: None,
        },
    ));
    app.settings.open = Some(Category::Service);
    let row = row_of(&app, Category::Service, ItemId::SafeDisableRun);
    let before = app.outbox.len();
    answer(&mut app, &format!("i{row} y"));
    assert_eq!(said(&app), texts_en().get(text::SAFE_DISABLE_NEED_REASON));
    assert_eq!(app.outbox.len(), before);
}

#[test]
fn a_safe_rollback_names_what_it_restores_and_spends_the_token_once_confirmed() {
    let fake = service();
    fake.answer(
        IpcOperationName::RollbackRequest,
        json!({
            "confirmation-token": "tok-1",
            "target": { "revision-id": "rev-3", "activated-at": 1_000, "rule-count": 7 }
        }),
    );
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    assert!(
        !items::items(&app, Category::Routing)
            .iter()
            .any(|i| i.id == ItemId::RollbackRun),
        "nothing to confirm before the lookup"
    );
    let lookup = row_of(&app, Category::Routing, ItemId::RollbackLookup);
    answer(&mut app, &format!("i{lookup}"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::RollbackRequest),
        vec![json!({ "dry-run": true })]
    );
    let run = row_of(&app, Category::Routing, ItemId::RollbackRun);
    answer(&mut app, &format!("i{run}"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::RollbackRequest).len(),
        1,
        "rolling back asks first"
    );
    answer(&mut app, "y");
    drain(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RollbackRequest);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[1]["dry-run"], json!(false));
    assert_eq!(sent[1]["_envelope_confirmation_token"], json!("tok-1"));
    assert!(
        !items::items(&app, Category::Routing)
            .iter()
            .any(|i| i.id == ItemId::RollbackRun),
        "the token is spent"
    );
}

#[test]
fn a_safe_rollback_with_nothing_earlier_offers_no_rollback() {
    let fake = service();
    fake.answer(IpcOperationName::RollbackRequest, json!({}));
    let mut app = on_settings();
    answer(&mut app, "c2");
    drain(&mut app, &fake);
    let lookup = row_of(&app, Category::Routing, ItemId::RollbackLookup);
    answer(&mut app, &format!("i{lookup}"));
    drain(&mut app, &fake);
    assert_eq!(app.settings.rollback, super::RollbackOffer::Nothing);
    assert!(!items::items(&app, Category::Routing)
        .iter()
        .any(|i| i.id == ItemId::RollbackRun));
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

#[test]
fn revision_retention_resets_to_the_service_defaults_and_says_when_it_last_ran() {
    let fake = service();
    let tight = json!({
        "superseded-days": 7, "superseded-count-cap": 20, "rejected-days": 1,
        "rolledback-days": 1, "rolledback-count-cap": 5, "pin-lkg": false,
        "last-cleanup-at": 1_700_000_000u64, "updated-at": 1_700_000_000u64
    });
    fake.answer(IpcOperationName::RetentionSettingsGet, tight.clone());
    fake.answer(IpcOperationName::RetentionSettingsSet, tight);
    let mut app = on_settings();
    answer(&mut app, "c6");
    drain(&mut app, &fake);

    let stamp = items::Words::Fill(
        text::LAST_CLEANUP,
        vec![("timestamp", "2023-11-14 22:13".to_string())],
    );
    assert!(
        items::items(&app, Category::Logs)
            .iter()
            .any(|i| i.label == stamp),
        "the last cleanup is not shown in local time"
    );

    let reset = row_of(&app, Category::Logs, ItemId::RevisionsReset);
    answer(&mut app, &format!("i{reset}"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::RetentionSettingsSet),
        vec![serde_json::to_value(RetentionSettingsSetRequest::DEFAULT).expect("encode")],
        "the reset sends the service's own defaults"
    );
}

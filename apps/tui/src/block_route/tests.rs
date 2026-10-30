#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::StatusUpdateEvent;
use nrr_shared::user_settings::{UserSettingsStore, USER_SETTINGS_FILE_NAME};
use serde_json::json;

use super::*;
use crate::backend::{BackendEvent, PushEvent};
use crate::link::Link;
use crate::screens::{screen, ScreenId};
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, Fixture, Scratch};

const SITE: &str = "news.example";

fn blocked(destination: &str, reason: &str) -> BackendEvent {
    BackendEvent::Push(PushEvent::Status(Box::new(
        StatusUpdateEvent::BlockNoticeRaised {
            sid: "S".into(),
            destination: destination.into(),
            app: "browser.exe".into(),
            reason: reason.into(),
            attempts: 2,
            launched_by: Vec::new(),
        },
    )))
}

fn press(app: &mut AppState, code: KeyCode) {
    crate::full::handle_key(app, KeyEvent::new(code, KeyModifiers::NONE), &texts_en());
}

/// Every queued job against the fake service, the replies' own jobs too.
fn drain(app: &mut AppState, service: &FakeService) {
    let texts = texts_en();
    for _ in 0..10 {
        let jobs = app.outbox.take();
        if jobs.is_empty() {
            return;
        }
        for job in jobs {
            let reply = job(service as &dyn IpcClient);
            app.apply(BackendEvent::Reply(reply), &texts, Instant::now());
        }
    }
    panic!("jobs keep queueing more jobs");
}

/// The Status screen's text, panel by panel.
fn status_text(app: &AppState) -> String {
    let view = screen(ScreenId::Status).view(app, &texts_en());
    let mut out = String::new();
    for panel in &view.panels {
        for line in &panel.lines {
            out.push_str(&line.plain_text());
            out.push('\n');
        }
    }
    out
}

/// The service after the rule was written: it routes the site and holds it.
fn routing_service(authored: bool) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::BlockNoticeRouteToSecondary,
        json!({ "authored": authored }),
    );
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [{
                "id": "1",
                "rule-type": "suffix-domain",
                "match-value": SITE,
                "target-route": "secondary",
                "enabled": true,
                "validation-status": "ok"
            }],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    fake
}

/// The Status screen, connected, with nothing queued yet.
fn on_status() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.outbox.take();
    app
}

/// The feed line the last write left.
fn result(app: &AppState) -> &crate::state::Notice {
    app.notices
        .iter()
        .rev()
        .find(|n| n.title == "Through additional")
        .expect("the result is in the feed")
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(&keys());
    assert!(missing.is_empty(), "{missing:?}");
}

/// The tray's path: the offer stands under the state, `v` asks, `y` has the
/// service write the rule, the bound file follows and the feed says so.
#[test]
fn a_routeable_block_is_routed_after_a_yes_and_the_bound_file_follows() {
    let dir = Scratch::new("block-route-writes");
    let fake = routing_service(true);
    let mut app = on_status();
    let settings = dir.path().join(USER_SETTINGS_FILE_NAME);
    let set = dir.path().join("sets").join("mine");
    std::fs::create_dir_all(&set).expect("set folder");
    let bound = set.join("rules_secondary.txt");
    UserSettingsStore::at(settings.clone())
        .update(|s| s.set_secondary_file(&bound.display().to_string()))
        .expect("bind the file");
    app.rules.settings_file = Some(settings);

    app.apply(
        blocked(SITE, "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    let shown = status_text(&app);
    assert!(
        shown.contains("news.example was blocked. v: send it over the additional connection."),
        "{shown}"
    );

    press(&mut app, KeyCode::Char('v'));
    assert!(
        fake.sent(IpcOperationName::BlockNoticeRouteToSecondary)
            .is_empty(),
        "v only asks"
    );
    let asked = status_text(&app);
    assert!(
        asked.contains("Send news.example through the additional connection (e.g. VPN)?"),
        "{asked}"
    );
    assert!(asked.contains("y: yes   n: no"), "{asked}");

    press(&mut app, KeyCode::Char('y'));
    drain(&mut app, &fake);

    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeRouteToSecondary),
        vec![json!({ "destination": SITE })]
    );
    let written = std::fs::read_to_string(&bound).expect("the bound file is written");
    assert!(written.contains(SITE), "{written}");
    let told = result(&app);
    assert_eq!(told.level, NoticeLevel::Info);
    assert_eq!(told.title, "Through additional");
    assert_eq!(
        told.body,
        "news.example now goes over the additional connection. You can undo it in Rules."
    );
    assert!(app.block_route.offered.is_empty(), "the offer is answered");
    assert!(!status_text(&app).contains("v: send it"));
}

/// A no, by key or by Esc, writes nothing and answers the offer.
#[test]
fn a_no_writes_nothing_and_answers_the_offer() {
    for answer in [KeyCode::Char('n'), KeyCode::Esc] {
        let fake = routing_service(true);
        let mut app = on_status();
        app.apply(blocked(SITE, "unattributed"), &texts_en(), Instant::now());
        press(&mut app, KeyCode::Char('v'));
        press(&mut app, answer);
        drain(&mut app, &fake);
        assert!(
            fake.operations().is_empty(),
            "{answer:?}: {:?}",
            fake.operations()
        );
        assert!(app.block_route.offered.is_empty(), "{answer:?}");
        assert!(!block_route_open(&app), "{answer:?}");
    }
}

fn block_route_open(app: &AppState) -> bool {
    asking(app) || status_text(app).contains("additional link?")
}

/// The blocks a rule cannot answer offer nothing, and the key does nothing.
#[test]
fn a_block_a_rule_cannot_answer_has_no_action() {
    let fake = routing_service(true);
    let mut app = on_status();
    let before = app.notices.len();
    for reason in ["route-unavailable", "ipv6-blocked", "dns-lockdown"] {
        app.apply(blocked(SITE, reason), &texts_en(), Instant::now());
    }
    assert_eq!(
        app.notices.len(),
        before + 3,
        "each is still told in the feed"
    );
    assert!(app.block_route.offered.is_empty());
    assert!(!status_text(&app).contains("v: send it"));
    assert!(!ask(&mut app), "v has nothing to ask about");
    press(&mut app, KeyCode::Char('v'));
    drain(&mut app, &fake);
    assert!(fake.operations().is_empty(), "{:?}", fake.operations());
}

/// The summary of blocks kept while no surface was open offers no route, as
/// the tray's does not.
#[test]
fn the_backlog_summary_offers_no_route() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::BlockNoticeJournalList,
        json!({ "entries": [{
            "id": 1,
            "raised-at-unix-ms": 1,
            "destination": SITE,
            "app": "",
            "reason": "blocked-by-rule",
            "attempts": 1
        }] }),
    );
    fake.answer(
        IpcOperationName::BlockNoticeJournalAck,
        json!({ "acknowledged": 1 }),
    );
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(
        BackendEvent::Link(Link::Connected),
        &texts_en(),
        Instant::now(),
    );
    drain(&mut app, &fake);
    assert!(
        app.notices
            .iter()
            .any(|n| n.title == "Blocked while the app was closed"),
        "{:?}",
        app.notices
    );
    assert!(app.block_route.offered.is_empty());
}

/// An equivalent rule already there: said so, and no file is rewritten.
#[test]
fn a_site_already_routed_is_said_and_nothing_is_reread() {
    let fake = routing_service(false);
    let mut app = on_status();
    app.apply(
        blocked(SITE, "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    assert!(ask(&mut app));
    assert!(answer(&mut app, true));
    drain(&mut app, &fake);
    assert_eq!(
        result(&app).body,
        "news.example already goes over the additional connection; nothing was added."
    );
    assert!(!fake.operations().contains(&IpcOperationName::RulesList));
}

/// A refusal reaches the feed as a warning; nothing is read back.
#[test]
fn a_refused_write_is_a_warning_in_the_feed() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut app = on_status();
    app.apply(
        blocked(SITE, "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    assert!(ask(&mut app));
    assert!(answer(&mut app, true));
    drain(&mut app, &fake);
    let told = result(&app);
    assert_eq!(told.level, NoticeLevel::Warning);
    assert!(
        told.body
            .starts_with("Could not send news.example over the additional connection: "),
        "{}",
        told.body
    );
    assert!(!fake.operations().contains(&IpcOperationName::RulesList));
    assert!(!app.block_route.busy);
}

/// Line mode: `v`, then `y`, as the keys.
#[test]
fn line_mode_asks_and_answers_the_same_way() {
    let fake = routing_service(true);
    let mut app = on_status();
    app.apply(
        blocked(SITE, "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    let status = screen(ScreenId::Status);
    assert!(status.on_line(&mut app, "v"));
    assert!(status.captures_keys(&app), "the answer is read first");
    assert!(status.on_line(&mut app, "y"));
    drain(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::BlockNoticeRouteToSecondary),
        vec![json!({ "destination": SITE })]
    );
}

/// The newest block leads; a repeat moves up rather than doubling, and the
/// list keeps as many as the tray's notice lists.
#[test]
fn the_newest_block_leads_and_the_offer_is_bounded() {
    let mut app = on_status();
    for i in 0..7 {
        app.apply(
            blocked(&format!("site{i}.example"), "blocked-by-rule"),
            &texts_en(),
            Instant::now(),
        );
    }
    app.apply(
        blocked("site4.example", "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    app.apply(
        blocked("   ", "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    app.apply(
        blocked(&"a".repeat(300), "blocked-by-rule"),
        &texts_en(),
        Instant::now(),
    );
    assert_eq!(
        app.block_route.offered,
        [
            "site4.example",
            "site6.example",
            "site5.example",
            "site3.example",
            "site2.example"
        ]
    );
    let shown = status_text(&app);
    assert!(shown.contains("site4.example was blocked."), "{shown}");
    assert!(
        shown.contains("Blocked sites waiting after it: 4."),
        "{shown}"
    );

    app.link = Link::Offline;
    assert!(!status_text(&app).contains("was blocked. v:"));
    assert!(!ask(&mut app), "nothing is asked while the service is away");
}

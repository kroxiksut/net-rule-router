#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use serde_json::{json, Value};

use super::*;
use crate::backend::{BackendEvent, PushEvent};
use crate::full::{draw, handle_key, RenderOptions};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::testing::{app_at, assert_snapshot, snapshot_json, texts_en, FakeService, Fixture};

const COLOUR: RenderOptions = RenderOptions {
    colour: true,
    ascii: false,
};

/// The full-screen picture as text, one row per line.
pub(crate) fn render(app: &AppState, width: u16, height: u16) -> String {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| draw(frame, app, &texts, COLOUR, Instant::now()))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        let row: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

/// Runs every queued job against the fake service, the replies' own jobs too.
pub(crate) fn drain(app: &mut AppState, service: &FakeService) {
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

/// Keys missing from either locale file.
pub(crate) fn missing_in_locales(keys: &[Key]) -> Vec<String> {
    let mut missing = Vec::new();
    for language in ["en", "ru"] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../locales")
            .join(format!("{language}.json"));
        let raw = std::fs::read_to_string(&path).expect("locale file");
        let root: Value =
            serde_json::from_str(raw.trim_start_matches('\u{feff}')).expect("locale JSON");
        for k in keys {
            let found =
                k.id.split('.')
                    .try_fold(&root, |node, part| node.get(part))
                    .and_then(Value::as_str)
                    .is_some();
            if !found {
                missing.push(format!("{language}: {}", k.id));
            }
        }
    }
    missing
}

pub(crate) fn press(app: &mut AppState, code: KeyCode) {
    handle_key(app, KeyEvent::new(code, KeyModifiers::NONE), &texts_en());
}

fn candidate(id: &str, host: &str, extra: Value) -> Value {
    let mut row = json!({
        "id": id,
        "anchor": "news.example",
        "proposed-match": host,
        "match-kind": "suffix",
        "route": "secondary",
        "affinity": 0.75,
        "observations": 4,
        "first-seen-unix-ms": 1000,
        "last-seen-unix-ms": 2000,
        "signal": "co-activity",
        "consumers": [ { "hostname": "news.example", "route": "secondary" } ]
    });
    if let (Some(row), Some(extra)) = (row.as_object_mut(), extra.as_object()) {
        row.extend(extra.clone());
    }
    row
}

fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::AutoRuleCandidatesList,
        json!({
            "candidates": [
                candidate("c1", "cdn.example.com", json!({ "primary-behavior": "responds", "third-party": true })),
                candidate("c2", "img.example.com", json!({ "observed-members": ["a.img.example.com", "b.img.example.com"] })),
                candidate("c3", "video.example.org", json!({
                    "primary-behavior": "stalls",
                    "consumers": [
                        { "hostname": "news.example", "route": "secondary" },
                        { "hostname": "shop.example", "route": "primary" }
                    ]
                })),
                candidate("c4", "served.example.net", json!({ "served-by-main-link": true })),
            ],
            "pending-count": 3,
            "inert-dropped": 0,
            "inert-sample": []
        }),
    );
    fake.answer(
        IpcOperationName::AutoRuleDismissedList,
        json!({ "dismissed": [ {
            "candidate-id": "d1", "anchor": "news.example",
            "proposed-match": "ads.example.com", "dismissed-at-unix-ms": 500
        } ] }),
    );
    fake.answer(
        IpcOperationName::AutoRuleCandidatesAccept,
        json!({ "applied": 1, "unknown": 0, "pending": 2, "anchor-skipped": true }),
    );
    fake.answer(
        IpcOperationName::AutoRuleCandidatesDismiss,
        json!({ "applied": 2, "unknown": 0, "pending": 1 }),
    );
    fake.answer(
        IpcOperationName::AutoRuleDismissedRestore,
        json!({ "restored": 1, "unknown": 0 }),
    );
    fake.answer(
        IpcOperationName::AutoRuleCandidatesProbe,
        json!({ "accepted": 3, "over-limit": 0 }),
    );
    fake.answer(
        IpcOperationName::SnapshotInitialGet,
        snapshot_json(&Fixture::healthy()),
    );
    fake.answer(IpcOperationName::RoutePolicyUpdate, json!({}));
    fake
}

fn on_screen(fake: &FakeService) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Suggestions);
    drain(&mut app, fake);
    app
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_in_locales(&keys::all());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn the_list_groups_by_domain_with_the_main_route_verdict() {
    let fake = service();
    let app = on_screen(&fake);
    assert_eq!(
        fake.operations(),
        vec![
            IpcOperationName::AutoRuleCandidatesList,
            IpcOperationName::AutoRuleDismissedList
        ]
    );
    let wide = render(&app, 160, 60);
    // A stall sorts first; the address the main route already serves stays
    // behind its toggle; answered ones are counted, not listed.
    let stalls = wide.find("1. example.org").expect("stalling group first");
    let other = wide.find("2. example.com").expect("then the rest");
    assert!(stalls < other, "{wide}");
    assert!(
        wide.contains("connections to it stall on the main route"),
        "{wide}"
    );
    assert!(
        wide.contains("the main route reaches it; a third-party"),
        "{wide}"
    );
    assert!(
        wide.contains("Needed by: news.example, shop.example"),
        "{wide}"
    );
    assert!(
        wide.contains("Seen so far: a.img.example.com, b.img.example.com."),
        "{wide}"
    );
    assert!(!wide.contains("served.example.net"), "{wide}");
    assert!(wide.contains("Show answered (1): No"), "{wide}");
    assert_snapshot("suggestions-80x24", &render(&app, 80, 24));
}

#[test]
fn the_rows_counted_for_scrolling_are_the_rows_drawn() {
    let fake = service();
    let mut app = on_screen(&fake);
    app.suggestions.show_dismissed = true;
    app.suggestions.show_served = true;
    let texts = texts_en();
    for (i, group) in app.suggestions.shown().iter().enumerate() {
        assert_eq!(
            group_line_count(group),
            group_lines(group, i, false, &texts).len(),
            "{}",
            group.domain
        );
    }
}

#[test]
fn keys_answer_the_chosen_group() {
    let fake = service();
    let mut app = on_screen(&fake);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.focus, Focus::Feed);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.suggestions.selected, 1);
    press(&mut app, KeyCode::Char('a'));
    drain(&mut app, &fake);
    let ops = fake.operations();
    assert!(
        ops.contains(&IpcOperationName::AutoRuleCandidatesAccept),
        "{ops:?}"
    );
    // The answer is followed by a fresh read, never a local patch.
    assert_eq!(ops.last(), Some(&IpcOperationName::AutoRuleDismissedList));
    let wide = render(&app, 160, 60);
    assert!(wide.contains("Added to your rules: 1."), "{wide}");
    assert!(wide.contains("Reload the page you were on"), "{wide}");
}

#[test]
fn automatic_mode_asks_first_and_cancel_changes_nothing() {
    let fake = service();
    let mut app = on_screen(&fake);
    press(&mut app, KeyCode::Char('m'));
    assert!(app.suggestions.confirm.is_some());
    let asked = render(&app, 160, 60);
    assert!(asked.contains("Turn on “Apply automatically”?"), "{asked}");
    let before = fake.operations().len();
    press(&mut app, KeyCode::Esc);
    drain(&mut app, &fake);
    assert_eq!(fake.operations().len(), before, "a cancel sends nothing");
    assert!(render(&app, 160, 60).contains("Nothing was changed."));

    press(&mut app, KeyCode::Char('m'));
    press(&mut app, KeyCode::Enter);
    drain(&mut app, &fake);
    let ops = fake.operations()[before..].to_vec();
    assert_eq!(
        &ops[..3],
        &[
            IpcOperationName::SnapshotInitialGet,
            IpcOperationName::RoutePolicyUpdate,
            IpcOperationName::AutoRuleCandidatesAccept
        ],
        "the policy is read whole, written whole, then the items added"
    );
    let wide = render(&app, 160, 60);
    assert!(wide.contains("Mode: Apply automatically"), "{wide}");
}

#[test]
fn a_push_rereads_and_points_to_the_screen_when_more_wait() {
    let fake = service();
    let mut app = on_screen(&fake);
    let texts = texts_en();
    let push = |count: u64| {
        BackendEvent::Push(PushEvent::Status(Box::new(
            nrr_shared::ipc_payloads::StatusUpdateEvent::AutoRuleCandidatesChanged {
                sid: "S".into(),
                pending_count: count,
                top_anchor: "news.example".into(),
            },
        )))
    };
    app.apply(push(5), &texts, Instant::now());
    assert_eq!(app.outbox.take().len(), 1, "the list is read again");
    let notice = app.notices.last().expect("more offers wait");
    assert!(notice.body.contains("news.example"), "{}", notice.body);
    assert!(notice.body.contains("screen 6"), "{}", notice.body);
    let before = app.notices.len();
    app.apply(push(2), &texts, Instant::now());
    assert_eq!(app.notices.len(), before, "fewer waiting is not news");
}

#[test]
fn line_mode_offers_the_same_answers_by_number() {
    let fake = service();
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    session.input("6", &mut app, &texts).expect("open");
    drain(&mut app, &fake);
    session.input("", &mut app, &texts).expect("read again");
    session.input("n 2", &mut app, &texts).expect("never");
    drain(&mut app, &fake);
    session.changed(&app, &texts).expect("answered");
    session
        .input("a 9", &mut app, &texts)
        .expect("no such item");
    session.input("m 1", &mut app, &texts).expect("ask");
    session.input("n", &mut app, &texts).expect("cancel");
    session.input("c", &mut app, &texts).expect("check");
    drain(&mut app, &fake);
    session.changed(&app, &texts).expect("checked");
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(text.contains("1. example.org"), "{text}");
    assert!(text.contains("Will not be suggested again: 2."), "{text}");
    assert!(text.contains("There is no item 9 in the list."), "{text}");
    assert!(
        text.contains("y: turn it on and add item 1. n: cancel."),
        "{text}"
    );
    assert!(text.contains("Nothing was changed."), "{text}");
    assert!(
        text.contains("Checking 3 addresses over the main connection..."),
        "{text}"
    );
    assert!(
        text.contains("a and an item number"),
        "the commands are listed:\n{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_snapshot("suggestions-plain", &text);
}

#[test]
fn without_the_service_nothing_is_sent() {
    let fake = service();
    let mut app = on_screen(&fake);
    let texts = texts_en();
    app.apply(BackendEvent::Link(Link::Stopped), &texts, Instant::now());
    let before = fake.operations().len();
    press(&mut app, KeyCode::Char('a'));
    press(&mut app, KeyCode::Char('c'));
    drain(&mut app, &fake);
    assert_eq!(fake.operations().len(), before);
    let picture = render(&app, 160, 60);
    assert!(picture.contains("Status data may be outdated"), "{picture}");
    assert!(picture.contains("Service not connected"), "{picture}");
}

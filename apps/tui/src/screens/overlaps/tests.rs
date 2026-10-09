#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::KeyCode;
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use serde_json::{json, Value};

use super::*;
use crate::backend::BackendEvent;
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::suggestions::tests::{drain, missing_in_locales, press, render};
use crate::testing::{app_at, assert_snapshot, texts_en, FakeService, Fixture};

fn row(id: &str, rule_type: &str, value: &str, route: &str) -> Value {
    json!({
        "id": id,
        "rule-type": rule_type,
        "match-value": value,
        "target-route": route,
        "enabled": true,
        "validation-status": "ok"
    })
}

fn unsure(id: &str, rule_type: &str, value: &str, route: &str) -> Value {
    let mut entry = row(id, rule_type, value, route);
    entry["verify"] = Value::Bool(true);
    entry
}

fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [
                row("R-1", "suffix-domain", "example.com", "primary"),
                row("R-2", "exact-fqdn", "video.example.com", "secondary"),
                row("R-3", "exact-fqdn", "dup.test", "primary"),
                row("R-4", "exact-fqdn", "dup.test", "secondary"),
                unsure("R-5", "suffix-domain", "chat.test", "secondary"),
                row("R-6", "exact-fqdn", "api.chat.test", "primary"),
                row("R-7", "exact-fqdn", "ads.example.net", "block"),
                row("R-8", "exact-fqdn", "ads.example.net", "primary"),
            ],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    fake
}

fn on_screen(fake: &FakeService) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Overlaps);
    drain(&mut app, fake);
    app
}

fn winners(app: &AppState) -> Vec<String> {
    app.overlaps
        .shown()
        .iter()
        .map(|p| p.winner.value.clone())
        .collect()
}

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_in_locales(&keys::all());
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn pairs_say_which_route_the_sites_take() {
    let fake = service();
    let app = on_screen(&fake);
    assert_eq!(fake.operations(), vec![IpcOperationName::RulesList]);
    assert_eq!(
        winners(&app),
        [
            "ads.example.net",
            "api.chat.test",
            "dup.test",
            "video.example.com"
        ]
    );
    let wide = render(&app, 200, 60);
    assert!(wide.contains("4 overlap(s) not confirmed"), "{wide}");
    assert!(
        wide.contains(
            "video.example.com (Domain) goes over Additional: it is narrower than *.example.com (Domain) on Primary."
        ),
        "{wide}"
    );
    assert!(
        wide.contains("dup.test (Domain) is set on both routes. It goes over Primary"),
        "{wide}"
    );
    assert!(
        wide.contains("They are blocked: on a tie a block wins"),
        "{wide}"
    );
    assert!(
        wide.contains("A block rule is part of this pair; change it in the rules list."),
        "{wide}"
    );
    assert!(
        wide.contains("than *.chat.test (Domain) on Additional."),
        "a ? rule is a rule of its route: {wide}"
    );
    assert!(wide.contains("Decision: Not confirmed"), "{wide}");
    assert_snapshot("overlaps-80x24", &render(&app, 80, 24));
}

#[test]
fn the_rows_counted_for_scrolling_are_the_rows_drawn() {
    let fake = service();
    let app = on_screen(&fake);
    let texts = texts_en();
    for (i, pair) in app.overlaps.shown().iter().enumerate() {
        assert_eq!(
            pair_line_count(&app, pair),
            pair_item_lines(&app, pair, i, false, &texts).len(),
            "{}",
            pair.key
        );
    }
}

#[test]
fn a_confirmed_pair_leaves_the_list_until_asked_for() {
    let fake = service();
    let mut app = on_screen(&fake);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('c'));
    assert_eq!(app.overlaps.pending_count(), 3);
    assert_eq!(winners(&app)[0], "api.chat.test");
    press(&mut app, KeyCode::Char('s'));
    assert_eq!(
        winners(&app).last().map(String::as_str),
        Some("ads.example.net"),
        "confirmed pairs come last"
    );
    assert!(render(&app, 200, 60).contains("Decision: Confirmed"));
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Char('u'));
    assert_eq!(app.overlaps.pending_count(), 4);
    press(&mut app, KeyCode::Char('C'));
    assert_eq!(app.overlaps.pending_count(), 0);
    assert_eq!(fake.operations().len(), 1, "confirming is local");
}

#[test]
fn sending_over_edits_the_rules_and_waits_for_apply() {
    let fake = service();
    let mut app = on_screen(&fake);
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::End);
    press(&mut app, KeyCode::Char('o'));
    let moved = app
        .rules
        .table
        .rules()
        .find(|r| r.match_value == "video.example.com")
        .expect("video.example.com");
    assert_eq!(moved.target_route, TargetRoute::Primary);
    assert!(rules::holds_unapplied(&app), "the Rules screen applies it");
    assert!(!winners(&app).contains(&"video.example.com".to_string()));
    let wide = render(&app, 200, 60);
    assert!(
        wide.contains("Rule changes take effect only after you review and apply them."),
        "{wide}"
    );
    assert!(wide.contains("on screen 4, Rules"), "{wide}");

    // Of a duplicate the winning copy is switched off.
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('o'));
    let copy = app
        .rules
        .table
        .rules()
        .find(|r| r.id == "R-0003")
        .expect("R-0003");
    assert!(!copy.enabled);

    // A `?` rule is a rule of its route: its pair trades places too.
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Char('o'));
    let api = app
        .rules
        .table
        .rules()
        .find(|r| r.match_value == "api.chat.test")
        .expect("api.chat.test");
    assert_eq!(api.target_route, TargetRoute::Secondary);

    // A block side cannot.
    press(&mut app, KeyCode::Home);
    press(&mut app, KeyCode::Char('o'));
    assert!(render(&app, 200, 60).contains("cannot be sent over the other route here"));

    // Coming back does not throw the edit away with a re-read.
    app.open(ScreenId::Status);
    app.open(ScreenId::Overlaps);
    assert!(app.outbox.take().is_empty());
    assert_eq!(fake.operations(), vec![IpcOperationName::RulesList]);
}

#[test]
fn the_pairs_follow_an_edit_on_the_rules_screen() {
    let fake = service();
    let mut app = on_screen(&fake);
    assert!(winners(&app).contains(&"video.example.com".to_string()));
    assert!(!render(&app, 200, 60).contains("Rule changes take effect only after"));

    // Rule 2 of the list is video.example.com; switching it off on the Rules
    // screen ends its pair here, before anything is applied.
    app.open(ScreenId::Rules);
    assert!(crate::screens::screen(ScreenId::Rules).on_line(&mut app, "t 2"));
    app.open(ScreenId::Overlaps);
    assert!(!winners(&app).contains(&"video.example.com".to_string()));
    assert_eq!(app.overlaps.pending_count(), 3);
    let wide = render(&app, 200, 60);
    assert!(
        wide.contains("Rule changes take effect only after you review and apply them."),
        "{wide}"
    );
    assert_eq!(fake.operations(), vec![IpcOperationName::RulesList]);
}

#[test]
fn conflicts_in_the_applied_rules_are_worded() {
    let fake = service();
    let mut app = on_screen(&fake);
    let conflict: RuleConflictDto = serde_json::from_value(json!({
        "kind": "block-leaks-shared-address",
        "rule-id": "R-9",
        "rule-value": "*.tracker.example",
        "ip": "192.0.2.7",
        "count": 3,
        "host": "pixel.tracker.example",
        "via-host": "cdn.example.com"
    }))
    .expect("conflict");
    if let Some(snapshot) = app.snapshot.as_mut() {
        snapshot.rule_conflicts.push(conflict);
    }
    let wide = render(&app, 260, 60);
    assert!(wide.contains("Conflicts in the applied rules"), "{wide}");
    assert!(
        wide.contains(
            "*.tracker.example does not block pixel.tracker.example: it shares 192.0.2.7 with cdn.example.com"
        ),
        "{wide}"
    );
    assert!(
        wide.contains("Addresses affected besides this one: 2."),
        "{wide}"
    );
}

#[test]
fn line_mode_offers_the_same_answers_by_number() {
    let fake = service();
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    session.input("5", &mut app, &texts).expect("open");
    drain(&mut app, &fake);
    session.input("", &mut app, &texts).expect("read again");
    session.input("c 1", &mut app, &texts).expect("confirm");
    session
        .input("o 9", &mut app, &texts)
        .expect("no such item");
    session.input("o 3", &mut app, &texts).expect("send over");
    session
        .input("c all", &mut app, &texts)
        .expect("confirm all");
    session.input("s", &mut app, &texts).expect("show resolved");
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(text.contains("4 overlap(s) not confirmed"), "{text}");
    assert!(text.contains("There is no item 9 in the list."), "{text}");
    assert!(text.contains("on screen 4, Rules"), "{text}");
    assert!(text.contains("Show resolved: Yes"), "{text}");
    assert!(text.contains("c all: confirm every item"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert_snapshot("overlaps-plain", &text);
}

#[test]
fn a_failed_read_says_why() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Overlaps);
    drain(&mut app, &fake);
    let picture = render(&app, 200, 40);
    assert!(picture.contains("Could not read your rules"), "{picture}");
    let texts = texts_en();
    app.apply(BackendEvent::Link(Link::Stopped), &texts, Instant::now());
    assert!(render(&app, 200, 40).contains("No data from the service yet"));
}

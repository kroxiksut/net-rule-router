#![allow(clippy::expect_used)]

use std::time::Instant;

use super::*;
use crate::link::Link;
use crate::testing::{app_at, assert_snapshot, enforcement, texts_en, Fixture};

fn transcript(session: PlainSession<Vec<u8>>) -> String {
    String::from_utf8(session.into_inner()).expect("line mode writes UTF-8")
}

#[test]
fn a_session_reads_as_a_transcript() {
    let texts = texts_en();
    let mut app = app_at(Link::Connecting, None);
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");

    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    app.apply(
        BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
        &texts,
        Instant::now(),
    );
    session.changed(&app, &texts).expect("connected");

    app.apply(
        enforcement("secondary-down", "secondary"),
        &texts,
        Instant::now(),
    );
    session.changed(&app, &texts).expect("limited");

    for answer in ["4", "h", "w", "", "q"] {
        session.input(answer, &mut app, &texts).expect("answer");
    }
    assert!(app.quit);
    let text = transcript(session);

    // Each change is a line of its own, after what was already printed.
    let connected = text
        .find("Service: OK")
        .expect("the connection is announced");
    let limited = text
        .find("Routing state: Routing limited")
        .expect("the routing change is announced with its panel");
    let notice = text
        .find("Warning: The additional connection is not up")
        .expect("the notice is printed with its level in words");
    assert!(connected < limited && notice < limited, "{text}");
    assert!(text.contains("  4. Rules"), "the menu is numbered:\n{text}");
    assert!(text.contains("Not understood: w"), "{text}");
    assert!(
        !text.contains('\u{1b}'),
        "line mode never moves the cursor or styles text:\n{text}"
    );
    assert_snapshot("plain-session", &text);
}

#[test]
fn an_unchanged_state_prints_nothing_new() {
    let texts = texts_en();
    let app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    let before = session.out.len();
    session.changed(&app, &texts).expect("no change");
    assert_eq!(session.out.len(), before);
}

#[test]
fn control_characters_from_the_service_never_reach_the_terminal() {
    assert_eq!(
        strip_controls("a\u{1b}[2Jb\u{8}c\rd\te"),
        "a[2Jbcd e",
        "escape, backspace and carriage return are dropped, a tab is a space"
    );
}

#[test]
fn an_ended_input_says_that_unapplied_edits_are_gone() {
    use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut session = PlainSession::new(Vec::new());
    session.input_ended(&app, &texts).expect("clean end");
    assert!(session.out.is_empty(), "nothing to lose, nothing said");

    app.rules.table.import(
        vec![RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: "example.org".into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }],
        true,
    );
    session.input_ended(&app, &texts).expect("dirty end");
    assert!(transcript(session).contains("were not applied"));
}

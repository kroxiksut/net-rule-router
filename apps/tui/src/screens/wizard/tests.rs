#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use serde_json::{json, Value};

use super::*;
use crate::backend::BackendEvent;
use crate::full::{draw, handle_key, RenderOptions};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::testing::{
    app_at, assert_snapshot, missing_from_locales, snapshot_json, texts_en, FakeService, Fixture,
};

/// A first start: the service knows the adapters, the user has named none.
fn unbound() -> Fixture {
    Fixture {
        primary: None,
        secondary: None,
        ..Fixture::healthy()
    }
}

/// The healthy machine's adapters with no binding in the policy.
fn first_start() -> Value {
    let mut snapshot = snapshot_json(&Fixture::healthy());
    let policy = snapshot["route-policy"]
        .as_object_mut()
        .expect("fixture policy");
    policy.remove("primary");
    policy.remove("secondary");
    snapshot
}

fn app_on_wizard() -> AppState {
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.wizard.locale = vec!["ru_RU.UTF-8".into()];
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let parsed = serde_json::from_value(first_start()).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app
}

fn service() -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    let snapshot = first_start();
    fake.answer(
        IpcOperationName::RoutePolicyUpdate,
        snapshot["route-policy"].clone(),
    );
    fake.answer(IpcOperationName::SnapshotInitialGet, snapshot);
    fake
}

fn run_jobs(app: &mut AppState, fake: &FakeService) -> usize {
    let jobs = app.outbox.take();
    let count = jobs.len();
    for job in jobs {
        let reply = job(fake);
        (reply.0)(app);
    }
    count
}

/// Take the answer `wanted` on the current step, by its number, as line mode does.
fn take(app: &mut AppState, wanted: &Action) {
    let index = actions(app)
        .iter()
        .position(|a| a == wanted)
        .unwrap_or_else(|| panic!("{wanted:?} is not offered: {:?}", actions(app)));
    assert!(WizardScreen.on_line(app, &(index + 1).to_string()));
}

fn render(app: &AppState, width: u16, height: u16) -> String {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    let options = RenderOptions {
        colour: true,
        ascii: false,
    };
    terminal
        .draw(|frame| draw(frame, app, &texts, options, Instant::now()))
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

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(k::ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

#[test]
fn it_opens_by_itself_only_for_a_user_with_no_connections() {
    assert_eq!(
        app_at(Link::Connected, Some(&unbound())).screen,
        ScreenId::Wizard
    );
    assert_eq!(
        app_at(Link::Connected, Some(&Fixture::healthy())).screen,
        ScreenId::Status
    );
    let mut asked = AppState::new(ScreenId::Wizard, false);
    asked.wizard.opened_by_request();
    let texts = texts_en();
    asked.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    asked.apply(
        BackendEvent::Snapshot(Box::new(unbound().snapshot())),
        &texts,
        Instant::now(),
    );
    assert_eq!(asked.screen, ScreenId::Wizard);
}

#[test]
fn a_language_answer_asks_the_loop_to_switch() {
    let mut app = app_on_wizard();
    take(&mut app, &Action::Language("ru".into()));
    assert_eq!(app.language_change.as_deref(), Some("ru"));
}

#[test]
fn the_walk_binds_the_main_connection_sends_protection_once_and_hands_over() {
    let fake = service();
    let mut app = app_on_wizard();
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Primary);
    take(
        &mut app,
        &Action::Assign(
            Route::Primary,
            "{00000000-0000-0000-0000-000000000001}".into(),
        ),
    );
    assert_eq!(run_jobs(&mut app, &fake), 1);
    let binding_write = &fake.sent(IpcOperationName::RoutePolicyUpdate)[0];
    assert_eq!(
        binding_write["primary"]["stable-id"],
        json!("{00000000-0000-0000-0000-000000000001}")
    );
    assert!(matches!(app.wizard.outcome, Some(Outcome::Role(_))));

    take(&mut app, &Action::Next);
    take(&mut app, &Action::Later);
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Protection);
    take(&mut app, &Action::ToggleDohLockdown);
    take(&mut app, &Action::Next);
    assert_eq!(run_jobs(&mut app, &fake), 1, "protection is one write");
    let protection = &fake.sent(IpcOperationName::RoutePolicyUpdate)[1];
    assert_eq!(protection["kill-switch-enabled"], json!(true));
    assert_eq!(protection["doh-lockdown-enabled"], json!(false));

    take(&mut app, &Action::StartEmpty);
    run_jobs(&mut app, &fake);
    assert_eq!(
        fake.sent(IpcOperationName::RoutePolicyUpdate).len(),
        2,
        "protection already went"
    );
    assert_eq!(
        app.screen,
        ScreenId::Interfaces,
        "the first-run contract's first section"
    );
    assert_eq!(app.wizard.step, Step::Language, "a next run starts over");
}

#[test]
fn closing_early_still_applies_the_protection_answers() {
    let fake = service();
    let mut app = app_on_wizard();
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1);
    let protection = &sent[0];
    assert_eq!(protection["kill-switch-enabled"], json!(true));
    assert_eq!(protection["doh-lockdown-enabled"], json!(true));
}

#[test]
fn the_country_set_is_previewed_then_applied_with_its_token() {
    let fake = service();
    fake.answer(
        IpcOperationName::MutationSubmit,
        json!({
            "review-summary": { "rules-added": [{}, {}, {}] },
            "confirmation-token": "tok-1",
            "operation-id": "op-1"
        }),
    );
    fake.answer(
        IpcOperationName::OperationStatusGet,
        json!({ "state": "completed" }),
    );
    let mut app = app_on_wizard();
    app.wizard.go(Step::Rules);
    let home = regional_indexes(&app)
        .into_iter()
        .find(|&i| !app.wizard.packs()[i].abroad)
        .expect("the ru set is offered for a ru locale");
    take(&mut app, &Action::Pack(home));
    assert_eq!(app.wizard.step, Step::Review);
    run_jobs(&mut app, &fake);
    let preview = app.wizard.preview.clone().expect("a preview");
    assert_eq!(preview.added, 3);
    let picture = render(&app, 140, 40);
    assert!(picture.contains("Added: 3"), "{picture}");

    take(&mut app, &Action::Apply);
    run_jobs(&mut app, &fake);
    let submits = fake.sent(IpcOperationName::MutationSubmit);
    assert_eq!(submits[0]["dry-run"], json!(true));
    assert_eq!(submits[0]["mutation-kind"], json!("preset-import"));
    assert_eq!(submits[1]["dry-run"], json!(false));
    assert_eq!(submits[1]["_envelope_confirmation_token"], json!("tok-1"));
    assert_eq!(
        submits[0]["payload"], submits[1]["payload"],
        "the confirmation carries what was previewed"
    );
    assert!(submits[0]["payload"]["primary-bytes-b64"].is_string());
    assert_eq!(app.screen, ScreenId::Interfaces);
}

#[test]
fn a_typed_path_that_cannot_be_read_is_said_in_words() {
    let mut app = app_on_wizard();
    app.wizard.go(Step::Files);
    take(&mut app, &Action::EditPath(0));
    assert!(WizardScreen.on_line(&mut app, "\"/no/such/dir/rules_primary.txt\""));
    assert_eq!(app.wizard.paths[0], "/no/such/dir/rules_primary.txt");
    take(&mut app, &Action::ImportFiles);
    assert!(matches!(
        app.wizard.outcome,
        Some(Outcome::FileError { .. })
    ));
    assert!(app.outbox.take().is_empty(), "nothing was sent");
}

#[test]
fn full_screen_keys_type_a_path_and_numbers_still_open_screens() {
    let texts = texts_en();
    let mut app = app_on_wizard();
    app.wizard.go(Step::Files);
    app.focus = Focus::Feed;
    let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
    handle_key(&mut app, key(KeyCode::Enter), &texts);
    assert!(app.wizard.editing.is_some());
    for c in "a q1".chars() {
        handle_key(&mut app, key(KeyCode::Char(c)), &texts);
    }
    handle_key(&mut app, key(KeyCode::Enter), &texts);
    assert_eq!(app.wizard.paths[0], "a q1", "typed text takes every letter");
    assert!(!app.quit);
    handle_key(&mut app, key(KeyCode::Char('3')), &texts);
    assert_eq!(app.screen, ScreenId::Interfaces);
}

#[test]
fn wizard_screen_snapshot_and_line_mode_transcript() {
    let texts = texts_en();
    let mut app = app_on_wizard();
    assert_eq!(app.screen, ScreenId::Wizard);
    let wide = render(&app, 140, 40);
    assert!(wide.contains("Step 1 of 5: Language"), "{wide}");
    assert_snapshot("wizard-language-80x24", &render(&app, 80, 24));

    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    let next = actions(&app)
        .iter()
        .position(|a| *a == Action::Next)
        .expect("next is offered")
        + 1;
    session
        .input(&next.to_string(), &mut app, &texts)
        .expect("answer");
    assert_eq!(app.wizard.step, Step::Primary);
    session.input("q", &mut app, &texts).expect("quit");
    assert!(app.quit, "q still quits");
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(text.contains("Step 2 of 5: Main connection"), "{text}");
    assert!(text.contains("Type the number of your answer"), "{text}");
    assert_snapshot("wizard-plain", &text);
}

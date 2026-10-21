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
    Scratch,
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
    assert_eq!(
        run_jobs(&mut app, &fake),
        1 + usize::from(super::stability::offers_logs()),
        "protection is one write, the machine-wide answers another"
    );
    let protection = &fake.sent(IpcOperationName::RoutePolicyUpdate)[1];
    assert_eq!(protection["leak-protection"], json!("sites"));
    assert_eq!(protection["doh-lockdown-enabled"], json!(false));
    assert_eq!(protection["doh-lockdown-auto"], json!(false));

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
    assert_eq!(protection["leak-protection"], json!("sites"));
    assert_eq!(protection["doh-lockdown-enabled"], json!(true));
}

/// The three-way choice offers "Routed sites" only under the main connection,
/// and a pick sends that level alone among the protection keys.
#[test]
fn leak_protection_is_one_choice_of_the_levels_the_route_offers() {
    let fake = service();
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    let levels: Vec<Action> = actions(&app)
        .into_iter()
        .filter(|a| matches!(a, Action::LeakProtection(_)))
        .collect();
    assert_eq!(
        levels,
        [
            Action::LeakProtection("off"),
            Action::LeakProtection("sites"),
            Action::LeakProtection("everything"),
        ]
    );
    take(&mut app, &Action::LeakProtection("everything"));
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["leak-protection"], json!("everything"));
    assert!(sent[0].get("kill-switch-enabled").is_none());

    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot["route-policy"]["mode"] = json!("prefer-secondary-when-available");
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts_en(),
        Instant::now(),
    );
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Protection);
    assert!(!actions(&app).contains(&Action::LeakProtection("sites")));
}

/// "Everything" while the additional connection is not available stops the
/// internet as soon as it applies: the step says so under the choice, with
/// the window's words, and nowhere else.
#[test]
fn everything_with_the_additional_connection_down_is_noted_under_the_choice() {
    let texts = texts_en();
    let note = texts.get(k::LEAK_HOLDS_NOW);
    for (availability, level, noted) in [
        ("unavailable", "everything", true),
        ("available", "everything", false),
        ("unavailable", "sites", false),
        ("unavailable", "off", false),
    ] {
        let mut fixture = Fixture::healthy();
        if let Some(bound) = fixture.secondary.as_mut() {
            bound.availability = Some(availability);
        }
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
        let parsed = serde_json::from_value(snapshot_json(&fixture)).expect("snapshot parses");
        app.apply(
            BackendEvent::Snapshot(Box::new(parsed)),
            &texts,
            Instant::now(),
        );
        app.outbox.take();
        app.open(ScreenId::Wizard);
        app.wizard.go(Step::Protection);
        take(&mut app, &Action::LeakProtection(level));
        let lines: Vec<String> = step_lines(&app, &texts)
            .iter()
            .map(ViewLine::plain_text)
            .collect();
        assert_eq!(
            lines.contains(&note),
            noted,
            "{availability} / {level}: {lines:?}"
        );
    }
}

/// A user with no policy yet is offered the start the administrator chose at
/// install time: its default route, and no level below its floor.
#[test]
fn a_new_user_starts_from_the_install_time_route_and_floor() {
    let texts = texts_en();
    let mut snapshot = first_start();
    snapshot
        .as_object_mut()
        .expect("snapshot")
        .remove("route-policy");
    snapshot["first-policy"] = json!({
        "mode": "prefer-secondary-when-available",
        "leak-protection-at-least": "everything"
    });
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Protection);
    let levels: Vec<Action> = actions(&app)
        .into_iter()
        .filter(|a| matches!(a, Action::LeakProtection(_)))
        .collect();
    assert_eq!(levels, [Action::LeakProtection("everything")]);
    assert_eq!(default_route(&app), "prefer-secondary-when-available");
    assert_eq!(shown_level(&app), "everything");
    let lines: Vec<String> = step_lines(&app, &texts)
        .iter()
        .map(ViewLine::plain_text)
        .collect();
    assert!(lines.contains(&texts.get(k::LEAK_HOLDS_NOW)), "{lines:?}");
}

/// The preselected "Routed sites" means "Everything" once the default route
/// is the additional connection, and the note follows what is shown.
#[test]
fn the_offer_raised_by_the_additional_route_is_noted_too() {
    let texts = texts_en();
    let mut fixture = Fixture::healthy();
    if let Some(bound) = fixture.secondary.as_mut() {
        bound.availability = Some("unavailable");
    }
    let mut snapshot = snapshot_json(&fixture);
    let policy = snapshot["route-policy"]
        .as_object_mut()
        .expect("fixture policy");
    policy.insert("mode".into(), json!("prefer-secondary-when-available"));
    policy.remove("primary");
    policy.remove("secondary");
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Protection);
    assert_eq!(app.wizard.leak_protection, "sites");
    assert_eq!(shown_level(&app), "everything");
    let lines: Vec<String> = step_lines(&app, &texts)
        .iter()
        .map(ViewLine::plain_text)
        .collect();
    assert!(lines.contains(&texts.get(k::LEAK_HOLDS_NOW)), "{lines:?}");
}

#[test]
fn leaving_the_setup_keeps_the_protection_of_a_user_already_set_up() {
    let fake = service();
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    // The healthy fixture has both connections bound and both protections off.
    let mut snapshot = snapshot_json(&Fixture::healthy());
    let policy = snapshot["route-policy"].as_object_mut().expect("policy");
    policy.insert("leak-protection".into(), json!("off"));
    policy.insert("doh-lockdown-enabled".into(), json!(false));
    policy.insert("doh-lockdown-auto".into(), json!(false));
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app.open(ScreenId::Wizard);
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    assert!(
        fake.sent(IpcOperationName::RoutePolicyUpdate).is_empty(),
        "nothing changed, nothing written"
    );

    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::LeakProtection("sites"));
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["leak-protection"], json!("sites"));
    assert_eq!(sent[0]["doh-lockdown-enabled"], json!(false));
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

fn gated(file: Option<std::path::PathBuf>, requested: bool) -> AppState {
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.rules.settings_file = file;
    app.wizard.locale = vec!["ru_RU.UTF-8".into()];
    if requested {
        app.wizard.opened_by_request();
    }
    app.wizard.at_startup(0, "en", None);
    if app.wizard.licence_pending() {
        app.screen = ScreenId::Wizard;
    }
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let snapshot = if requested {
        first_start()
    } else {
        snapshot_json(&Fixture::healthy())
    };
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app
}

fn recorded(file: &std::path::Path) -> u32 {
    nrr_shared::user_settings::UserSettingsStore::at(file.to_path_buf())
        .load()
        .expect("readable")
        .map_or(0, |settings| settings.accepted_eula)
}

#[test]
fn the_agreement_comes_first_and_shuts_every_other_screen() {
    let dir = Scratch::new("licence-first");
    let mut app = gated(Some(dir.path().join("user-settings.json")), false);
    assert_eq!(app.screen, ScreenId::Wizard);
    assert_eq!(app.wizard.step, Step::Licence);
    app.open(ScreenId::Rules);
    assert_eq!(app.screen, ScreenId::Wizard, "no way around the agreement");
    let texts = texts_en();
    let shown = render(&app, 120, 40);
    assert!(shown.contains("License agreement"), "{shown}");
    let offered = actions(&app);
    assert!(offered.contains(&Action::Accept) && offered.contains(&Action::Decline));
    assert!(!offered.contains(&Action::Close));
    assert!(label(&Action::Accept, &app, &texts).contains("Accept"));
}

#[test]
fn declining_the_agreement_leaves_the_program() {
    let dir = Scratch::new("licence-decline");
    let file = dir.path().join("user-settings.json");
    let mut app = gated(Some(file.clone()), false);
    take(&mut app, &Action::Decline);
    assert!(app.quit);
    assert_eq!(recorded(&file), 0, "nothing is recorded for a refusal");
}

#[test]
fn accepting_records_the_version_where_the_window_reads_it() {
    let dir = Scratch::new("licence-accept");
    let file = dir.path().join("user-settings.json");
    let mut app = gated(Some(file.clone()), false);
    take(&mut app, &Action::Accept);
    assert_eq!(recorded(&file), nrr_shared::eula::CURRENT_EULA_VERSION);
    assert!(!app.wizard.licence_pending());
    assert_eq!(
        app.screen,
        ScreenId::Status,
        "a user already set up goes back to where the program started"
    );
    app.open(ScreenId::Rules);
    assert_eq!(app.screen, ScreenId::Rules);
}

#[test]
fn accepting_when_the_setup_was_asked_for_goes_on_to_the_questions() {
    let dir = Scratch::new("licence-requested");
    let file = dir.path().join("user-settings.json");
    let mut app = gated(Some(file), true);
    take(&mut app, &Action::Accept);
    assert_eq!(app.screen, ScreenId::Wizard);
    assert_eq!(app.wizard.step, Step::Language);
}

#[test]
fn a_user_with_no_connections_is_taken_to_the_setup_after_the_agreement() {
    let dir = Scratch::new("licence-then-setup");
    let file = dir.path().join("user-settings.json");
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.rules.settings_file = Some(file);
    app.wizard.at_startup(0, "en", None);
    app.screen = ScreenId::Wizard;
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let parsed = serde_json::from_value(first_start()).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    take(&mut app, &Action::Accept);
    assert_eq!(app.screen, ScreenId::Wizard);
    assert_eq!(app.wizard.step, Step::Language);
}

#[test]
fn an_accepted_agreement_is_not_asked_again() {
    let mut app = AppState::new(ScreenId::Status, false);
    app.wizard
        .at_startup(nrr_shared::eula::CURRENT_EULA_VERSION, "en", None);
    assert!(!app.wizard.licence_pending());
    assert_eq!(app.wizard.step, Step::Language);
}

#[test]
fn a_session_with_nowhere_to_record_asks_every_time() {
    let mut app = gated(None, false);
    take(&mut app, &Action::Accept);
    assert!(!app.wizard.licence_pending(), "this session is through");
    assert_eq!(
        app.wizard.outcome, None,
        "no file of the user's own, so nothing was lost"
    );
}

#[test]
fn an_unwritable_settings_file_says_the_acceptance_was_not_kept() {
    let dir = Scratch::new("licence-unsaved");
    let file = dir.path().join("user-settings.json");
    std::fs::write(&file, "{ not json").expect("damage");
    let mut app = gated(Some(file.clone()), true);
    take(&mut app, &Action::Accept);
    assert_eq!(app.wizard.outcome, Some(Outcome::LicenceNotSaved));
    assert_eq!(
        std::fs::read_to_string(&file).expect("still there"),
        "{ not json",
        "a damaged file is never overwritten"
    );
}

#[test]
fn the_agreement_is_read_a_part_at_a_time() {
    let dir = Scratch::new("licence-pages");
    let mut app = gated(Some(dir.path().join("user-settings.json")), false);
    assert!(!actions(&app).contains(&Action::PreviousPage));
    take(&mut app, &Action::NextPage);
    assert_eq!(app.wizard.licence_page, 1);
    assert!(actions(&app).contains(&Action::PreviousPage));
    take(&mut app, &Action::PreviousPage);
    assert_eq!(app.wizard.licence_page, 0);
    let last = licence_pages(&app).len() - 1;
    app.wizard.licence_page = last;
    assert!(!actions(&app).contains(&Action::NextPage));
}

fn with_sheet(json: &str) -> AppState {
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.wizard.locale = vec!["ru_RU.UTF-8".into()];
    let sheet = nrr_shared::first_run_sheet::parse_sheet(json.as_bytes()).expect("sheet");
    app.wizard
        .at_startup(nrr_shared::eula::CURRENT_EULA_VERSION, "en", Some(sheet));
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

#[test]
fn the_installers_protection_answers_start_a_new_user_off_the_offer() {
    let mut app = with_sheet(r#"{"leak-protection":"off","doh-lockdown":true}"#);
    assert_eq!(app.wizard.leak_protection, "off");
    assert!(app.wizard.doh_lockdown);
    let fake = service();
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent[0]["leak-protection"], json!("off"));
}

#[test]
fn the_installers_level_is_taken_as_written() {
    let mut app = with_sheet(r#"{"leak-protection":"everything"}"#);
    assert_eq!(app.wizard.leak_protection, "everything");
    let fake = service();
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = fake.sent(IpcOperationName::RoutePolicyUpdate);
    assert_eq!(sent[0]["leak-protection"], json!("everything"));
}

#[test]
fn the_installers_connection_and_rule_set_answers_move_the_cursor_only() {
    let mut app = with_sheet(r#"{"rule-set":"none"}"#);
    app.wizard.go(Step::Rules);
    preselect(&mut app);
    let at = actions(&app)
        .iter()
        .position(|a| *a == Action::StartEmpty)
        .expect("offered");
    assert_eq!(app.wizard.cursor, at);
    assert!(app.outbox.take().is_empty(), "nothing is sent for the user");

    let rows = adapters(&app, false);
    let second = rows.get(1).expect("two adapters").name.clone();
    let json = format!(r#"{{"primary-connection":{}}}"#, json!(second));
    let mut app = with_sheet(&json);
    app.wizard.go(Step::Primary);
    preselect(&mut app);
    let wanted = Action::Assign(
        Route::Primary,
        super::super::binding::row_key(&adapters(&app, false)[1]),
    );
    assert_eq!(actions(&app)[app.wizard.cursor], wanted);
}

#[test]
fn a_sheet_that_names_nothing_here_changes_nothing() {
    let mut app = with_sheet(r#"{"primary-connection":"No Such Link","language":"xx"}"#);
    app.wizard.go(Step::Primary);
    preselect(&mut app);
    assert_eq!(app.wizard.cursor, 0);
    app.wizard.go(Step::Language);
    preselect(&mut app);
    assert_eq!(app.wizard.cursor, 0);
}

#[test]
fn the_sheet_is_mentioned_on_the_first_question() {
    let app = with_sheet(r#"{"leak-protection":"sites"}"#);
    let shown = render(&app, 120, 40);
    assert!(shown.contains("supplied before the first start"), "{shown}");
}

fn stability_service() -> FakeService {
    let fake = service();
    fake.answer(IpcOperationName::ServiceStabilityConfigGet, json!({}));
    fake.answer(IpcOperationName::ServiceStabilityConfigSet, json!({}));
    fake
}

fn stability_sent(fake: &FakeService) -> Vec<Value> {
    fake.sent(IpcOperationName::ServiceStabilityConfigSet)
}

/// Fake-IP on, as the window offers it, and a log window when asked for: one
/// write of the stability row when the protection step is left.
#[test]
fn the_machine_wide_answers_go_to_the_service_once() {
    let fake = stability_service();
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    if !super::stability::offers_logs() {
        assert!(!actions(&app).contains(&Action::DiagnosticLogs));
        assert!(!actions(&app).contains(&Action::ToggleFakeIp));
        return;
    }
    take(&mut app, &Action::DiagnosticLogs);
    take(&mut app, &Action::DiagnosticLogs);
    let label = label(&Action::DiagnosticLogs, &app, &texts_en());
    assert!(label.ends_with("Verbose for 4 hours"), "{label}");
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    let sent = stability_sent(&fake);
    assert_eq!(sent.len(), 1);
    let config = &sent[0]["config"];
    assert_eq!(config["verbose-logging-change"], json!("four-hours"));
    assert_eq!(config["conn-trace-ndjson-change"], json!("four-hours"));
    if super::stability::offers_fake_ip() {
        assert_eq!(config["fake-ip-enabled"], json!(true));
    }

    take(&mut app, &Action::StartEmpty);
    run_jobs(&mut app, &fake);
    assert_eq!(stability_sent(&fake).len(), 1, "already sent this run");
}

#[test]
fn the_installers_fake_ip_answer_is_the_one_sent() {
    if !super::stability::offers_fake_ip() {
        return;
    }
    let fake = stability_service();
    fake.answer(
        IpcOperationName::ServiceStabilityConfigGet,
        json!({ "fake-ip-enabled": true }),
    );
    let mut app = with_sheet(r#"{"fake-ip":false}"#);
    app.open(ScreenId::Wizard);
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let sent = stability_sent(&fake);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["config"]["fake-ip-enabled"], json!(false));
}

/// A failed write is told in the feed after the setup handed over, once.
#[test]
fn a_machine_wide_answer_that_was_not_saved_is_told_in_the_feed() {
    if !super::stability::offers_logs() {
        return;
    }
    let fake = service();
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    let before = app.notice_count;
    super::announce(&mut app, &texts_en(), Instant::now());
    assert_eq!(app.notice_count, before + 1);
    assert!(
        app.notices
            .iter()
            .any(|n| n.title == "A setup answer was not saved"),
        "{:?}",
        app.notices
    );
    super::announce(&mut app, &texts_en(), Instant::now());
    assert_eq!(app.notice_count, before + 1, "once");
}

/// A user already set up keeps the service's machine-wide settings unless
/// they were changed here.
#[test]
fn a_user_already_set_up_keeps_the_machine_wide_settings() {
    let fake = stability_service();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Wizard);
    take(&mut app, &Action::Close);
    run_jobs(&mut app, &fake);
    assert!(stability_sent(&fake).is_empty());
}

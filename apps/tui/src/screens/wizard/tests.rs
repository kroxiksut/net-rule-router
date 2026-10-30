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

/// A first start as the service reports it: the machine's adapters, and no
/// policy until the user's first save.
fn first_start() -> Value {
    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot
        .as_object_mut()
        .expect("fixture snapshot")
        .remove("route-policy");
    snapshot
}

/// The policy the first save stores: the healthy one with no binding.
fn first_saved_policy() -> Value {
    let mut snapshot = snapshot_json(&Fixture::healthy());
    let policy = snapshot["route-policy"]
        .as_object_mut()
        .expect("fixture policy");
    policy.remove("primary");
    policy.remove("secondary");
    snapshot["route-policy"].take()
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
    fake.answer(IpcOperationName::RoutePolicyUpdate, first_saved_policy());
    fake.answer(IpcOperationName::SnapshotInitialGet, first_start());
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
    // The starting rules come right after the connections, as in the window.
    assert_eq!(app.wizard.step, Step::Rules);
    take(&mut app, &Action::StartEmpty);
    assert_eq!(app.wizard.step, Step::Protection, "the setup goes on");
    assert_eq!(
        run_jobs(&mut app, &fake),
        0,
        "nothing sent before the answers"
    );
    take(&mut app, &Action::ToggleDohLockdown);
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Summary);
    run_jobs(&mut app, &fake);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    let protection = &fake.sent(IpcOperationName::RoutePolicyUpdate)[1];
    assert_eq!(protection["leak-protection"], json!("sites"));
    assert_eq!(protection["doh-lockdown-enabled"], json!(false));
    assert_eq!(protection["doh-lockdown-auto"], json!(false));
    assert_eq!(
        fake.sent(IpcOperationName::RoutePolicyUpdate).len(),
        2,
        "protection went once"
    );
    assert_eq!(
        app.screen,
        ScreenId::Interfaces,
        "the first-run contract's first section"
    );
    assert_eq!(app.wizard.step, Step::Language, "a next run starts over");
}

/// The window's five steps with its numbers and names: main connection,
/// additional connection, starting rules, protection and options, summary.
/// The session language comes first and is not counted, as the agreement.
/// Back retraces the same path.
#[test]
fn the_steps_come_in_the_windows_order() {
    let texts = texts_en();
    let fake = service();
    let mut app = app_on_wizard();
    let heading = |app: &AppState| WizardScreen.view(app, &texts).panels[0].title.clone();
    let numbered = |number: usize, name: Key| {
        texts.fill(
            k::STEP,
            &[
                ("number", number.to_string()),
                ("total", "5".to_string()),
                ("name", texts.get(name)),
            ],
        )
    };
    let next_label = |app: &AppState| label(&Action::Next, app, &texts);

    assert_eq!(heading(&app), texts.get(k::LANGUAGE_TITLE));
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Primary);
    assert_eq!(heading(&app), numbered(1, common::ROLE_PRIMARY));
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Secondary);
    assert_eq!(heading(&app), numbered(2, common::ROLE_SECONDARY));
    assert_eq!(next_label(&app), texts.get(k::NEXT));
    take(&mut app, &Action::Next);
    assert_eq!(
        app.wizard.step,
        Step::Rules,
        "the rules follow the connections"
    );
    assert_eq!(heading(&app), numbered(3, k::RULES_STEP));

    take(&mut app, &Action::Back);
    assert_eq!(app.wizard.step, Step::Secondary);
    take(&mut app, &Action::Next);
    take(&mut app, &Action::OtherCountries);
    assert_eq!(heading(&app), numbered(3, k::RULES_STEP));
    take(&mut app, &Action::Back);
    assert_eq!(app.wizard.step, Step::Rules);
    take(&mut app, &Action::OwnFiles);
    assert_eq!(heading(&app), numbered(3, k::RULES_STEP));
    take(&mut app, &Action::Back);
    assert_eq!(app.wizard.step, Step::Rules);

    take(&mut app, &Action::StartEmpty);
    assert_eq!(app.wizard.step, Step::Protection);
    assert_eq!(heading(&app), numbered(4, k::OPTIONS_STEP));
    assert_eq!(next_label(&app), texts.get(k::NEXT));
    take(&mut app, &Action::Back);
    assert_eq!(app.wizard.step, Step::Rules, "Back retraces the walk");
    take(&mut app, &Action::StartEmpty);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    assert_eq!(app.wizard.step, Step::Summary, "the summary comes last");
    assert_eq!(heading(&app), numbered(5, k::SUMMARY_STEP));
    assert_eq!(next_label(&app), texts.get(k::FINISH));
    take(&mut app, &Action::Back);
    assert_eq!(app.wizard.step, Step::Protection);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    take(&mut app, &Action::Next);
    assert_eq!(
        app.screen,
        after_setup(),
        "the summary's answer closes the setup"
    );
}

/// What the service said about the protection is told on the summary; once
/// the setup closed it must not greet the next run.
#[test]
fn a_finished_run_leaves_nothing_to_say_to_the_next_one() {
    let fake = service();
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    assert_eq!(fake.sent(IpcOperationName::RoutePolicyUpdate).len(), 1);
    app.open(ScreenId::Wizard);
    assert_eq!(app.wizard.step, Step::Language);
    assert_eq!(app.wizard.outcome, None, "the last run's outcome is shown");
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

/// The first run says the site notice holds with the tray closed, where the
/// service can start the tray; elsewhere it promises nothing.
#[test]
fn the_protection_step_tells_of_the_site_notice_only_where_it_exists() {
    let texts = texts_en();
    let note = texts.get(k::SITE_NOTICE_NOTE);
    for (supported, told) in [(true, true), (false, false)] {
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
        let parsed =
            serde_json::from_value(snapshot_json(&Fixture::healthy())).expect("snapshot parses");
        app.apply(
            BackendEvent::Snapshot(Box::new(parsed)),
            &texts,
            Instant::now(),
        );
        app.settings.supports.site_notice_without_tray = supported;
        app.open(ScreenId::Wizard);
        app.wizard.go(Step::Protection);
        let lines: Vec<String> = step_lines(&app, &texts)
            .iter()
            .map(ViewLine::plain_text)
            .collect();
        assert_eq!(lines.contains(&note), told, "{supported}: {lines:?}");
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
    // A new user: no policy yet, the install-time default route.
    let mut snapshot = snapshot_json(&fixture);
    snapshot
        .as_object_mut()
        .expect("snapshot")
        .remove("route-policy");
    snapshot["first-policy"] = json!({
        "mode": "prefer-secondary-when-available",
        "leak-protection-at-least": "off"
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

/// A user who chose "Everything" in the window and closed its setup before
/// binding a connection: the terminal's setup opens by itself, and closing it
/// must not write "only sites" and lockdown on over that choice.
#[test]
fn closing_the_setup_keeps_a_saved_policy_with_no_connection_bound() {
    let fake = service();
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let mut snapshot = snapshot_json(&Fixture::healthy());
    let policy = snapshot["route-policy"].as_object_mut().expect("policy");
    policy.remove("primary");
    policy.remove("secondary");
    policy.insert("leak-protection".into(), json!("everything"));
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
        "closing the setup wrote over the saved policy: {:?}",
        fake.sent(IpcOperationName::RoutePolicyUpdate)
    );
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

    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Protection, "the protection follows");
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    take(&mut app, &Action::Next);
    while run_jobs(&mut app, &fake) > 0 {}
    let submits = fake.sent(IpcOperationName::MutationSubmit);
    let confirm = submits
        .iter()
        .position(|s| s["dry-run"] == json!(false))
        .expect("the set was confirmed");
    assert_eq!(submits[confirm - 1]["dry-run"], json!(true));
    assert_eq!(submits[confirm]["mutation-kind"], json!("preset-import"));
    assert_eq!(
        submits[confirm]["_envelope_confirmation_token"],
        json!("tok-1")
    );
    assert_eq!(
        submits[confirm - 1]["payload"],
        submits[confirm]["payload"],
        "the confirmation carries what was previewed"
    );
    assert!(submits[confirm]["payload"]["primary-bytes-b64"].is_string());
    assert_eq!(app.screen, ScreenId::Interfaces);
    // The applied set is told in the feed, named and counted, as the window's
    // message box.
    crate::rule_set_load::announce(&mut app, &texts_en(), Instant::now());
    let told = app.notices.last().expect("the applied set is told");
    assert_eq!(
        told.title,
        texts_en().get(crate::rule_set_load::APPLIED_TITLE)
    );
    assert!(told.body.contains("now in use"), "{}", told.body);
}

/// Choosing a set over a stopped service did nothing but say "not
/// connected": the set is applied in the same action, so the service is
/// started first and the preview follows once it answers.
#[test]
fn a_set_chosen_over_a_stopped_service_starts_it_then_previews() {
    let fake = service();
    fake.answer(
        IpcOperationName::PrincipalDataCount,
        json!({ "other-principals": 0 }),
    );
    fake.answer(
        IpcOperationName::MutationSubmit,
        json!({ "review-summary": { "rules-added": [{}] }, "confirmation-token": "t" }),
    );
    let mut app = app_on_wizard();
    app.apply(
        BackendEvent::Link(Link::Stopped),
        &texts_en(),
        Instant::now(),
    );
    app.outbox.take();
    app.settings.service_probe = crate::testing::stopped_service;
    app.wizard.go(Step::Rules);
    let home = regional_indexes(&app)
        .into_iter()
        .find(|&i| !app.wizard.packs()[i].abroad)
        .expect("the ru set is offered for a ru locale");
    take(&mut app, &Action::Pack(home));
    assert_ne!(app.wizard.outcome, Some(Outcome::NeedsService));
    run_jobs(&mut app, &fake);
    run_jobs(&mut app, &fake);
    assert_eq!(app.wizard.preview.as_ref().map(|p| p.added), Some(1));
    assert_eq!(
        fake.operations()[0],
        IpcOperationName::PrincipalDataCount,
        "the service answered before the set went"
    );
}

#[test]
fn a_set_whose_service_cannot_be_started_says_why_in_the_feed() {
    let fake = service();
    let mut app = app_on_wizard();
    app.apply(
        BackendEvent::Link(Link::Stopped),
        &texts_en(),
        Instant::now(),
    );
    app.outbox.take();
    app.settings.service_probe = crate::testing::stopped_service_refusing;
    app.wizard.go(Step::Rules);
    let home = regional_indexes(&app)
        .into_iter()
        .find(|&i| !app.wizard.packs()[i].abroad)
        .expect("the ru set is offered for a ru locale");
    take(&mut app, &Action::Pack(home));
    run_jobs(&mut app, &fake);
    assert!(app.wizard.preview.is_none());
    assert_eq!(app.wizard.busy, None, "the step is free again");
    crate::rule_set_load::announce(&mut app, &texts_en(), Instant::now());
    let told = app.notices.last().expect("the failure is told");
    assert_eq!(
        told.title,
        texts_en().get(crate::rule_set_load::NOT_APPLIED_TITLE)
    );
}

/// An English system set to Russia: the language says nothing about the
/// country, the region does.
#[test]
fn the_country_set_follows_the_system_region_not_its_language() {
    let mut app = app_on_wizard();
    app.wizard.locale = vec!["en-US".into()];
    app.wizard.region = Some("RU".into());
    app.wizard.go(Step::Rules);
    let offered: Vec<&str> = regional_indexes(&app)
        .into_iter()
        .map(|i| app.wizard.packs()[i].country.as_str())
        .collect();
    assert!(offered.contains(&"ru"), "{offered:?}");
    // Every other set stays one answer away.
    assert!(actions(&app).contains(&Action::OtherCountries));
}

/// The region's set says "for your region"; another country's set in the list
/// of all of them must not, or every row claims to be the user's own.
#[test]
fn another_countrys_set_is_named_as_the_window_names_it() {
    let texts = texts_en();
    let mut app = app_on_wizard();
    app.wizard.go(Step::OtherCountries);
    let picture = render(&app, 160, 60);
    assert!(
        !picture.contains("for your region"),
        "another country's set claims the user's region:\n{picture}"
    );
    let ru = app
        .wizard
        .packs()
        .iter()
        .position(|p| p.country == "ru" && !p.abroad)
        .expect("the Russian set is bundled");
    assert_eq!(
        label(&Action::Pack(ru), &app, &texts),
        "Russia: local and foreign"
    );
}

#[test]
fn a_vpn_adapter_chosen_while_down_reads_as_chosen_not_connected_yet() {
    let fixture = Fixture {
        secondary: Some(crate::testing::Bound {
            id: "{00000000-0000-0000-0000-000000000002}",
            name: "Example Tunnel",
            availability: Some("unavailable"),
        }),
        ..Fixture::healthy()
    };
    let mut app = app_at(Link::Connected, Some(&fixture));
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Secondary);
    let picture = render(&app, 160, 40);
    assert!(picture.contains("Example Tunnel"), "{picture}");
    assert!(picture.contains("not connected yet"), "{picture}");
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
    assert!(wide.contains("Language"), "{wide}");
    assert!(!wide.contains("Step 1 of 5: Language"), "{wide}");
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
    assert!(text.contains("Step 1 of 5: Main connection"), "{text}");
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

/// What an installer recorded, and the account this terminal runs as.
struct Installer {
    recorded_by: &'static str,
    version: u32,
    running_as: &'static str,
}

impl nrr_platform_api::installer_agreement::InstallerAgreementPort for Installer {
    fn recorded(&self) -> Option<nrr_shared::eula::InstallerAcceptance> {
        nrr_shared::eula::InstallerAcceptance::new(self.version, self.recorded_by)
    }
    fn current_account(&self) -> Option<String> {
        Some(self.running_as.to_owned())
    }
}

const IVANOV: &str = "S-1-5-21-1-2-3-1001";
const PETROV: &str = "S-1-5-21-1-2-3-1002";

#[test]
fn the_account_that_accepted_in_the_installer_is_not_asked_and_it_is_kept() {
    let dir = Scratch::new("licence-installer");
    let file = dir.path().join("user-settings.json");
    let current = nrr_shared::eula::CURRENT_EULA_VERSION;
    let installer = Installer {
        recorded_by: IVANOV,
        version: current,
        running_as: IVANOV,
    };
    let accepted = accepted_with_installer(Some(&file), 0, &installer);
    assert_eq!(accepted, current);
    assert_eq!(recorded(&file), current, "the window reads it from here");
    let mut app = AppState::new(ScreenId::Status, false);
    app.wizard.at_startup(accepted, "en", None);
    assert!(!app.wizard.licence_pending());
}

#[test]
fn another_account_is_asked_after_someone_else_installed() {
    let dir = Scratch::new("licence-installer-other");
    let file = dir.path().join("user-settings.json");
    let installer = Installer {
        recorded_by: IVANOV,
        version: nrr_shared::eula::CURRENT_EULA_VERSION,
        running_as: PETROV,
    };
    assert_eq!(accepted_with_installer(Some(&file), 0, &installer), 0);
    assert!(!file.exists(), "nothing is recorded for Petrov");
    let older = Installer {
        recorded_by: IVANOV,
        version: nrr_shared::eula::CURRENT_EULA_VERSION - 1,
        running_as: IVANOV,
    };
    assert_eq!(accepted_with_installer(Some(&file), 0, &older), 0);
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
    assert_eq!(
        app.screen,
        ScreenId::Interfaces,
        "the last answer closes the setup"
    );
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

/// A user already set up who changes only the log window: fake-IP is shown
/// and kept as the service holds it, never switched on by the offer.
#[test]
fn a_changed_log_window_leaves_the_services_fake_ip_alone() {
    if !super::stability::offers_fake_ip() {
        return;
    }
    let fake = stability_service();
    fake.answer(
        IpcOperationName::ServiceStabilityConfigGet,
        json!({ "fake-ip-enabled": false }),
    );
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::DiagnosticLogs);
    run_jobs(&mut app, &fake);
    let label = label(&Action::ToggleFakeIp, &app, &texts_en());
    assert!(label.ends_with("No"), "{label}");
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    let sent = stability_sent(&fake);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["config"]["fake-ip-enabled"], json!(false));
    assert_eq!(
        sent[0]["config"]["verbose-logging-change"],
        json!("one-hour")
    );
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

/// A machine with a dozen idle VPN adapters next to its live links: the setup
/// lists the connected ones, names the live tunnel as the VPN, and shows the
/// idle ones only when asked.
#[test]
fn idle_vpn_adapters_do_not_bury_the_live_links() {
    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Status, false);
    app.apply(BackendEvent::Link(Link::Connected), &texts, Instant::now());
    let mut snapshot = first_start();
    let rows = snapshot["adapters"]["rows"]
        .as_array_mut()
        .expect("fixture rows");
    rows[1]["kind"] = json!("tunnel");
    rows[1]["recommendation"]["class"] = json!("preferred-secondary");
    let mut idle = rows[1].clone();
    idle["availability"] = json!("unavailable");
    for n in 10..13 {
        let mut row = idle.clone();
        row["persistent-id"] = json!(format!("{{00000000-0000-0000-0000-0000000000{n}}}"));
        row["adapter-name"] = row["persistent-id"].clone();
        row["name"] = json!(format!("Idle Tap {n}"));
        rows.insert(1, row);
    }
    let parsed = serde_json::from_value(snapshot).expect("snapshot parses");
    app.apply(
        BackendEvent::Snapshot(Box::new(parsed)),
        &texts,
        Instant::now(),
    );
    app.outbox.take();
    app.open(ScreenId::Wizard);
    app.wizard.go(Step::Secondary);

    let offered = |app: &AppState| -> Vec<String> {
        actions(app)
            .iter()
            .map(|a| label(a, app, &texts))
            .filter(|l| l.contains("Tap") || l.contains("Tunnel") || l.contains("Ethernet"))
            .collect()
    };
    let shown = offered(&app);
    assert!(
        shown.iter().any(|l| l.contains("Example Tunnel")),
        "{shown:?}"
    );
    assert!(!shown.iter().any(|l| l.contains("Idle Tap")), "{shown:?}");
    let picture = render(&app, 200, 50);
    assert!(
        picture.contains("Example Tunnel looks like a VPN connection"),
        "{picture}"
    );
    assert_eq!(
        actions(&app).first().map(|a| label(a, &app, &texts)),
        shown.iter().find(|l| l.contains("Example Tunnel")).cloned(),
        "the live tunnel is offered first"
    );

    take(&mut app, &Action::ShowAll);
    let all = offered(&app);
    assert!(all.iter().any(|l| l.contains("Idle Tap 11")), "{all:?}");
}

/// A service that answers a set's dry run with three new rules and confirms it.
fn set_service() -> FakeService {
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
    fake
}

/// The region's set chosen and previewed on the rules step.
fn with_a_set_chosen(fake: &FakeService) -> AppState {
    let mut app = app_on_wizard();
    app.wizard.go(Step::Rules);
    let home = regional_indexes(&app)
        .into_iter()
        .find(|&i| !app.wizard.packs()[i].abroad)
        .expect("the ru set is offered for a ru locale");
    take(&mut app, &Action::Pack(home));
    while run_jobs(&mut app, fake) > 0 {}
    app
}

fn confirmed(fake: &FakeService) -> bool {
    fake.sent(IpcOperationName::MutationSubmit)
        .iter()
        .any(|s| s["dry-run"] == json!(false))
}

/// Leak protection is off until the user's first save: rules confirmed before
/// it ran without it, and quitting on the protection step left them so. The
/// set goes only as the setup closes, after the protection was written.
#[test]
fn the_starting_rules_never_run_before_the_protection() {
    let fake = set_service();
    let mut app = with_a_set_chosen(&fake);
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Protection);
    while run_jobs(&mut app, &fake) > 0 {}
    assert!(
        !confirmed(&fake),
        "the rules are in force while the protection is still being chosen"
    );
    take(&mut app, &Action::LeakProtection("everything"));
    take(&mut app, &Action::Next);
    while run_jobs(&mut app, &fake) > 0 {}
    assert!(!confirmed(&fake), "the rules went before Finish");

    take(&mut app, &Action::Next);
    while run_jobs(&mut app, &fake) > 0 {}
    assert!(confirmed(&fake), "Finish applies the set");
    let operations = fake.operations();
    let protection = operations
        .iter()
        .position(|op| *op == IpcOperationName::RoutePolicyUpdate)
        .expect("the protection was written");
    let set = operations
        .iter()
        .rposition(|op| *op == IpcOperationName::MutationSubmit)
        .expect("the set was sent");
    assert!(protection < set, "{operations:?}");
    assert_eq!(
        fake.sent(IpcOperationName::RoutePolicyUpdate)[0]["leak-protection"],
        json!("everything")
    );
}

/// Closing the setup from the rules step still writes the protection before
/// the chosen set, as closing the window does.
#[test]
fn closing_early_applies_the_set_only_after_the_protection() {
    let fake = set_service();
    let mut app = with_a_set_chosen(&fake);
    let previewed = fake.operations().len();
    take(&mut app, &Action::Close);
    while run_jobs(&mut app, &fake) > 0 {}
    assert!(confirmed(&fake));
    let closing = &fake.operations()[previewed..];
    let protection = closing
        .iter()
        .position(|op| *op == IpcOperationName::RoutePolicyUpdate)
        .expect("the protection was written");
    assert!(
        !closing[..protection].contains(&IpcOperationName::MutationSubmit),
        "nothing of the set goes before the protection: {closing:?}"
    );
}

/// A protection write the service refused keeps the starting rules out, and
/// the feed says why.
#[test]
fn a_protection_that_was_not_saved_keeps_the_starting_rules_out() {
    let fake = set_service();
    fake.refuse(
        IpcOperationName::RoutePolicyUpdate,
        nrr_shared::ipc_transport::IpcErrorCode::Forbidden,
    );
    let mut app = with_a_set_chosen(&fake);
    take(&mut app, &Action::Close);
    while run_jobs(&mut app, &fake) > 0 {}
    assert!(!confirmed(&fake), "rules ran without the protection");
    crate::rule_set_load::announce(&mut app, &texts_en(), Instant::now());
    let told = app.notices.last().expect("the refusal is told");
    assert_eq!(
        told.title,
        texts_en().get(crate::rule_set_load::NOT_APPLIED_TITLE)
    );
    assert!(told.body.contains("leak protection"), "{}", told.body);
}

/// The healthy machine with only the main connection bound.
fn main_bound_only() -> AppState {
    let texts = texts_en();
    let mut snapshot = snapshot_json(&Fixture::healthy());
    snapshot["route-policy"]
        .as_object_mut()
        .expect("fixture policy")
        .remove("secondary");
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
    app.wizard.go(Step::Secondary);
    app
}

/// One adapter cannot carry both routes: the connection bound as the main one
/// is not offered for the additional route, the other one is.
#[test]
fn the_main_connection_is_not_offered_for_the_additional_route() {
    let app = main_bound_only();
    let offered: Vec<Action> = actions(&app)
        .into_iter()
        .filter(|a| matches!(a, Action::Assign(..)))
        .collect();
    assert_eq!(
        offered,
        [Action::Assign(
            Route::Secondary,
            "{00000000-0000-0000-0000-000000000002}".into()
        )]
    );
}

/// "I will choose it later" is not a one-way door.
#[test]
fn choosing_the_additional_connection_later_can_be_taken_back() {
    let mut app = main_bound_only();
    take(&mut app, &Action::Later);
    assert!(!actions(&app)
        .iter()
        .any(|a| matches!(a, Action::Assign(..))));
    take(&mut app, &Action::ChooseNow);
    assert!(!app.wizard.secondary_deferred);
    assert!(actions(&app)
        .iter()
        .any(|a| matches!(a, Action::Assign(Route::Secondary, _))));
}

fn summary(app: &AppState, texts: &Texts) -> Vec<String> {
    step_lines(app, texts)
        .iter()
        .map(ViewLine::plain_text)
        .collect()
}

/// The summary tells the protection the service holds once it answered the
/// write, and that the rules wait for a main connection when none is chosen.
#[test]
fn the_summary_tells_the_protection_in_force() {
    let texts = texts_en();
    let fake = service();
    let mut held = first_saved_policy();
    held["leak-protection"] = json!("sites");
    held["doh-lockdown-enabled"] = json!(true);
    held["doh-lockdown-auto"] = json!(true);
    fake.answer(IpcOperationName::RoutePolicyUpdate, held);
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::Next);
    assert_eq!(app.wizard.step, Step::Summary);
    let sites = || vec![("name", texts.get(k::LEAK_SITES))];
    let not_yet = texts.fill(k::REVIEW_LEAK_NOT_YET, &sites());
    let in_force = texts.fill(k::REVIEW_LEAK_IN_FORCE, &sites());
    assert!(
        summary(&app, &texts).contains(&not_yet),
        "{:?}",
        summary(&app, &texts)
    );
    run_jobs(&mut app, &fake);
    let lines = summary(&app, &texts);
    assert!(lines.contains(&in_force), "{lines:?}");
    assert!(
        lines.contains(&texts.get(k::REVIEW_NO_PRIMARY)),
        "{lines:?}"
    );
}

/// A write that failed keeps today's error on the summary, and the level is
/// not called in force.
#[test]
fn the_summary_says_a_protection_that_was_not_saved() {
    let texts = texts_en();
    let fake = service();
    fake.refuse(
        IpcOperationName::RoutePolicyUpdate,
        nrr_shared::ipc_transport::IpcErrorCode::Forbidden,
    );
    let mut app = app_on_wizard();
    app.wizard.go(Step::Protection);
    take(&mut app, &Action::Next);
    run_jobs(&mut app, &fake);
    let lines = summary(&app, &texts);
    let failed = texts.get(k::PROTECTION_FAILED);
    assert!(
        lines.iter().any(|l| l.starts_with(failed.trim_end())),
        "{lines:?}"
    );
    let in_force = texts.fill(
        k::REVIEW_LEAK_IN_FORCE,
        &[("name", texts.get(k::LEAK_SITES))],
    );
    assert!(!lines.contains(&in_force), "{lines:?}");
}

/// A VPN program brought up another copy of its driver than the one bound as
/// the additional connection: the step names the live copy, as the window
/// and the Interfaces screen do.
#[test]
fn a_dead_bound_copy_of_a_driver_names_its_live_sibling() {
    let texts = texts_en();
    let fixture = Fixture {
        secondary: Some(crate::testing::Bound {
            id: "{00000000-0000-0000-0000-000000000010}",
            name: "Ethernet 10",
            availability: Some("unavailable"),
        }),
        ..Fixture::healthy()
    };
    let mut snapshot = snapshot_json(&fixture);
    let rows = snapshot["adapters"]["rows"]
        .as_array_mut()
        .expect("fixture rows");
    rows[1]["interface-description"] = json!("TAP-Windows Adapter V9 #10");
    let mut live = rows[1].clone();
    live["persistent-id"] = json!("{00000000-0000-0000-0000-000000000015}");
    live["adapter-name"] = live["persistent-id"].clone();
    live["name"] = json!("Ethernet 15");
    live["interface-description"] = json!("TAP-Windows Adapter V9 #15");
    live["availability"] = json!("available");
    rows.push(live);
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
    app.wizard.go(Step::Secondary);
    let lines: Vec<String> = step_lines(&app, &texts)
        .iter()
        .map(ViewLine::plain_text)
        .collect();
    assert!(lines.iter().any(|l| l.contains("Ethernet 15")), "{lines:?}");
    app.wizard.go(Step::Primary);
    let lines: Vec<String> = step_lines(&app, &texts)
        .iter()
        .map(ViewLine::plain_text)
        .collect();
    assert!(
        !lines.iter().any(|l| l.contains("Ethernet 15")),
        "a connected main link warns of nothing: {lines:?}"
    );
}

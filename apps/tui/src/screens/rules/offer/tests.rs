#![allow(clippy::expect_used)]

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::user_settings::{UserSettings, UserSettingsStore, USER_SETTINGS_FILE_NAME};
use serde_json::json;

use super::super::Mode;
use crate::link::Link;
use crate::screens::suggestions::tests::drain;
use crate::screens::{screen, ScreenId};
use crate::state::AppState;
use crate::testing::{app_at, texts_en, FakeService, Fixture, Scratch};

const OFFER: &str = "No rules yet. Load the rule set «Russia: local and foreign»?";
const KEYS: &str = "l: Load. n: Not now.";
const EMPTY_LOAD: &str = "l: Load the rule set «Russia: local and foreign»";
const HOW: &str = "To load it, press l on the Rules screen";

fn service(rows: Vec<serde_json::Value>) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({ "rows": rows, "supported-rule-types": ["zone", "domain", "exact-ip"] }),
    );
    fake.answer(
        IpcOperationName::MutationSubmit,
        json!({
            "confirmation-token": "t",
            "review-summary": {
                "diff-summary": "",
                "provenance": "",
                "risk-level": "low",
                "requires-review": false,
                "changed-fields": ["rules"]
            }
        }),
    );
    fake
}

fn store(dir: &Scratch) -> UserSettingsStore {
    UserSettingsStore::at(dir.path().join(USER_SETTINGS_FILE_NAME))
}

/// A user in Russia after the setup, the settings file as `seed` leaves it,
/// on `at` with the service's rules read.
fn app(dir: &Scratch, fake: &FakeService, seed: impl FnOnce(&mut UserSettings)) -> AppState {
    store(dir).update(seed).expect("seed");
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.wizard.region = Some("RU".into());
    app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
    super::super::read_offer(&mut app);
    app.open(ScreenId::Rules);
    drain(&mut app, fake);
    app
}

fn shown(app: &AppState, id: ScreenId) -> String {
    screen(id)
        .view(app, &texts_en())
        .panels
        .iter()
        .flat_map(|panel| panel.lines.iter().map(|line| line.plain_text()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn press(app: &mut AppState, c: char) -> bool {
    screen(ScreenId::Rules).on_key(app, KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

fn answered(dir: &Scratch) -> bool {
    store(dir)
        .load()
        .expect("read")
        .expect("file")
        .rule_set_offer_answered
}

/// The start the window gives after an empty first run: the set is named
/// with the key that loads it, and nothing was loaded unasked.
#[test]
fn a_user_with_no_rules_is_offered_the_set_and_nothing_is_loaded_unasked() {
    let dir = Scratch::new("offer-shown");
    let fake = service(Vec::new());
    let app = app(&dir, &fake, |_| {});
    let rules = shown(&app, ScreenId::Rules);
    assert!(rules.contains(OFFER) && rules.contains(KEYS), "{rules}");
    assert!(rules.contains(EMPTY_LOAD), "{rules}");
    assert!(app.rules.table.rows.is_empty(), "a set was loaded unasked");
    assert!(matches!(app.rules.mode, Mode::List), "{:?}", app.rules.mode);
    let status = shown(&app, ScreenId::Status);
    assert!(status.contains(OFFER) && status.contains(HOW), "{status}");
    assert!(
        !status.contains("No rules are active"),
        "the offer says it once: {status}"
    );
}

/// `l` loads the set as picking it from the list does — on to the service's
/// review — and answers the offer for both clients.
#[test]
fn l_loads_the_offered_set_into_the_review_and_answers_the_offer() {
    let dir = Scratch::new("offer-load");
    let fake = service(Vec::new());
    let mut app = app(&dir, &fake, |_| {});
    assert!(press(&mut app, 'l'));
    drain(&mut app, &fake);
    assert!(
        matches!(app.rules.mode, Mode::Review(_)),
        "{:?}",
        app.rules.mode
    );
    assert!(
        !app.rules.table.rows.is_empty(),
        "the set's rules are listed"
    );
    assert!(answered(&dir), "the window would still offer it");
    let settings = store(&dir).load().expect("read").expect("file");
    assert_eq!(settings.selected_set, "bundled:ru_osnovnoy-i-zarubezh");
}

/// `n` is the window's "Not now": gone here, recorded for the window, and the
/// empty list still loads the set with one key.
#[test]
fn n_answers_the_offer_and_the_empty_list_still_loads_in_one_key() {
    let dir = Scratch::new("offer-not-now");
    let fake = service(Vec::new());
    let mut app = app(&dir, &fake, |_| {});
    assert!(press(&mut app, 'n'));
    assert!(answered(&dir));
    let rules = shown(&app, ScreenId::Rules);
    assert!(!rules.contains(OFFER), "{rules}");
    assert!(rules.contains(EMPTY_LOAD), "{rules}");
    assert!(!shown(&app, ScreenId::Status).contains(OFFER));
}

/// Answered in the window, a bound rules file, or rules of their own: no
/// offer.
#[test]
fn no_offer_once_answered_bound_or_holding_rules() {
    let answered_elsewhere = Scratch::new("offer-answered");
    let fake = service(Vec::new());
    let app1 = app(&answered_elsewhere, &fake, |s| {
        s.rule_set_offer_answered = true
    });
    assert!(!shown(&app1, ScreenId::Rules).contains(OFFER));

    let bound = Scratch::new("offer-bound");
    let app2 = app(&bound, &fake, |s| {
        s.set_primary_file("/home/me/sets/mine/rules_primary.txt")
    });
    let rules = shown(&app2, ScreenId::Rules);
    assert!(
        !rules.contains(OFFER) && !rules.contains(EMPTY_LOAD),
        "{rules}"
    );

    let holding = Scratch::new("offer-holding");
    let with_rules = service(vec![json!({
        "id": "1", "rule-type": "domain", "match-value": "example.com",
        "target-route": "secondary", "enabled": true, "validation-status": "ok"
    })]);
    let app3 = app(&holding, &with_rules, |_| {});
    assert!(!shown(&app3, ScreenId::Rules).contains(OFFER));
}

/// The run whose setup chose to start empty does not question that choice.
#[test]
fn the_offer_waits_for_the_run_after_the_setup() {
    let dir = Scratch::new("offer-setup");
    let fake = service(Vec::new());
    store(&dir).update(|_| {}).expect("seed");
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.wizard.region = Some("RU".into());
    app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
    super::super::read_offer(&mut app);
    app.open(ScreenId::Wizard);
    app.open(ScreenId::Rules);
    drain(&mut app, &fake);
    let rules = shown(&app, ScreenId::Rules);
    assert!(!rules.contains(OFFER), "{rules}");
    assert!(!press(&mut app, 'n') || !answered(&dir));
}

/// A service that is not running still gets the offer: loading starts it.
#[test]
fn a_stopped_service_and_nothing_bound_is_offered_too() {
    let dir = Scratch::new("offer-stopped");
    let fake = service(Vec::new());
    let mut app = app(&dir, &fake, |_| {});
    app.link = Link::Stopped;
    app.rules.table = Default::default();
    let rules = shown(&app, ScreenId::Rules);
    assert!(rules.contains(OFFER), "{rules}");
    assert!(rules.contains(EMPTY_LOAD), "{rules}");
}

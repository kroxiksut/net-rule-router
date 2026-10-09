#![allow(clippy::expect_used)]

use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
use nrr_ipc_client::ConnectionStatus;
use nrr_shared::ipc::IpcOperationName;
use serde_json::{json, Value};

use super::files::RuleSet;
use super::{apply, text, Mode};
use crate::link::Link;
use crate::plain::PlainSession;
use crate::screens::suggestions::tests::drain;
use crate::screens::{screen, ScreenId};
use crate::state::AppState;
use crate::testing::{app_at, missing_from_locales, texts_en, FakeService, Fixture};

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_from_locales(text::ALL);
    assert!(missing.is_empty(), "{missing:?}");
}

/// Under `sudo` the screen writes the administrator's baseline and says so;
/// otherwise the caller's own rules, unmarked.
#[test]
fn under_root_the_rules_go_to_the_baseline_and_the_title_says_so() {
    let pending = |admin_baseline| apply::Pending {
        rules_json: "{}".into(),
        content_hash: "h".into(),
        correlation_id: "c".into(),
        admin_baseline,
    };
    for baseline in [true, false] {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            IpcOperationName::MutationSubmit,
            json!({ "confirmation-token": "t", "review-summary": {} }),
        );
        let mut app = AppState::new(ScreenId::Rules, false);
        let reply = apply::preview_job(pending(baseline))(&fake);
        (reply.0)(&mut app);
        let sent = fake.sent(IpcOperationName::MutationSubmit);
        assert_eq!(
            sent[0]["payload"]
                .get("admin-baseline")
                .and_then(|v| v.as_bool()),
            baseline.then_some(true),
            "{sent:?}"
        );
    }

    let texts = texts_en();
    let mut app = AppState::new(ScreenId::Rules, false);
    app.rules.baseline = true;
    let view = super::render::view(&app, &texts);
    assert_eq!(view.title, texts.get(text::TITLE_BASELINE));
}

fn rule(id: &str, rule_type: &str, value: &str, route: &str) -> Value {
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
    let mut entry = rule(id, rule_type, value, route);
    entry["verify"] = Value::Bool(true);
    entry
}

fn service(rows: Vec<Value>) -> FakeService {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": rows,
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    fake
}

/// The Rules screen with the service's rules read.
fn on_rules(fake: &FakeService) -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Rules);
    drain(&mut app, fake);
    app
}

/// Line-mode answers, as `--plain` hands them to the screen.
fn answer(app: &mut AppState, lines: &[&str]) {
    for line in lines {
        assert!(screen(app.screen).on_line(app, line), "{line:?}");
    }
}

fn screen_text(app: &AppState, id: ScreenId) -> String {
    let view = screen(id).view(app, &texts_en());
    let mut out = String::new();
    for panel in &view.panels {
        out.push_str(&panel.title);
        out.push('\n');
        for line in &panel.lines {
            out.push_str(&line.plain_text());
            out.push('\n');
        }
    }
    out
}

fn overlaps_text(app: &mut AppState) -> String {
    app.open(ScreenId::Overlaps);
    screen_text(app, ScreenId::Overlaps)
}

/// Line mode's add: the form opens on the type, and an empty answer keeps
/// Domain.
const ADD_DOMAIN: [&str; 2] = ["a", ""];

#[test]
fn the_form_says_what_the_rule_overlaps_before_it_is_saved() {
    let fake = service(vec![rule("1", "suffix-domain", "example.com", "primary")]);
    let mut app = on_rules(&fake);
    answer(&mut app, &ADD_DOMAIN);
    answer(&mut app, &["news.example.com", "2"]);
    assert!(matches!(app.rules.mode, Mode::Form(_)), "still in the form");
    let form = screen_text(&app, ScreenId::Rules);
    assert!(form.contains("Overlaps:"), "{form}");
    assert!(
        form.contains(
            "news.example.com (Domain) goes over Additional: it is narrower than *.example.com (Domain) on Primary."
        ),
        "{form}"
    );

    // Saved switched off, the rule overlaps nothing.
    answer(&mut app, &["", "", "2"]);
    assert!(app.rules.table.rules().any(|r| !r.enabled), "saved off");
    answer(&mut app, &["e 2"]);
    assert!(matches!(app.rules.mode, Mode::Form(_)), "editing");
    assert!(!screen_text(&app, ScreenId::Rules).contains("Overlaps:"));
}

#[test]
fn the_form_names_three_overlaps_and_counts_the_rest() {
    let fake = service(vec![
        rule("1", "suffix-domain", "example.com", "primary"),
        rule("2", "suffix-domain", "c.example.com", "primary"),
        rule("3", "suffix-domain", "b.c.example.com", "primary"),
        rule("4", "exact-fqdn", "a.b.c.example.com", "primary"),
    ]);
    let mut app = on_rules(&fake);
    answer(&mut app, &ADD_DOMAIN);
    answer(&mut app, &["a.b.c.example.com", "2"]);
    let Mode::Form(form) = &app.rules.mode else {
        panic!("the form is open");
    };
    assert_eq!(form.overlaps.len(), 4);
    let text = screen_text(&app, ScreenId::Rules);
    assert!(text.contains("and 1 more"), "{text}");
    let sentences = text
        .lines()
        .filter(|l| l.starts_with("     ") && l.contains("(Domain)"))
        .count();
    assert_eq!(sentences, 3, "{text}");
}

#[test]
fn line_mode_prints_the_overlap_line() {
    let fake = service(vec![rule("1", "suffix-domain", "example.com", "primary")]);
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let mut session = PlainSession::new(Vec::new());
    session.start(&app, &texts).expect("start");
    session.input("4", &mut app, &texts).expect("open rules");
    drain(&mut app, &fake);
    for line in ["a", "", "news.example.com", "2"] {
        session.input(line, &mut app, &texts).expect("answer");
    }
    let text = String::from_utf8(session.into_inner()).expect("UTF-8");
    assert!(
        text.contains("news.example.com (Domain) goes over Additional"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
}

#[test]
fn an_exception_saved_from_the_form_is_not_asked_about() {
    let fake = service(vec![rule("1", "suffix-domain", "example.com", "primary")]);
    let mut app = on_rules(&fake);
    answer(&mut app, &ADD_DOMAIN);
    answer(&mut app, &["news.example.com", "2", "", "", "1"]);
    assert!(matches!(app.rules.mode, Mode::List), "saved");
    let overlaps = overlaps_text(&mut app);
    assert!(
        overlaps.contains("0 overlap(s) not confirmed"),
        "{overlaps}"
    );
    assert!(
        overlaps.contains("Every overlap is resolved."),
        "{overlaps}"
    );
}

#[test]
fn a_wide_rule_over_an_older_narrow_one_still_asks() {
    let fake = service(vec![rule(
        "1",
        "exact-fqdn",
        "video.example.com",
        "secondary",
    )]);
    let mut app = on_rules(&fake);
    answer(&mut app, &ADD_DOMAIN);
    answer(&mut app, &["*.example.com", "1", "", "", "1"]);
    assert!(matches!(app.rules.mode, Mode::List), "saved");
    let overlaps = overlaps_text(&mut app);
    assert!(
        overlaps.contains("1 overlap(s) not confirmed"),
        "{overlaps}"
    );
    assert!(
        overlaps.contains("video.example.com (Domain) goes over Additional"),
        "{overlaps}"
    );
}

/// "Unsure" is a mark on a rule of its route, offered for a name or an address
/// and never for a block; the list shows it after the route.
#[test]
fn an_unsure_rule_keeps_its_route_and_shows_its_mark() {
    let fake = service(Vec::new());
    let mut app = on_rules(&fake);
    answer(&mut app, &ADD_DOMAIN);
    answer(&mut app, &["shop.example.com", "1", "1", "", "1"]);
    assert!(matches!(app.rules.mode, Mode::List), "saved");
    let saved = app.rules.table.rules().next().expect("one rule");
    assert_eq!(saved.target_route, TargetRoute::Primary);
    assert!(saved.is_verify());
    let text = screen_text(&app, ScreenId::Rules);
    assert!(
        text.contains("shop.example.com \u{2014} Primary ?"),
        "{text}"
    );

    // A block takes no mark: the field is passed over.
    answer(&mut app, &["a", "", "ads.example.com", "3", "", "1"]);
    assert!(matches!(app.rules.mode, Mode::List), "saved");
    let block = app
        .rules
        .table
        .rules()
        .find(|r| r.match_value == "ads.example.com")
        .expect("ads.example.com");
    assert_eq!(block.target_route, TargetRoute::Block);
    assert!(!block.is_verify());
}

#[test]
fn imported_rules_are_not_confirmed_for_the_user() {
    let fake = service(vec![rule("1", "suffix-domain", "example.com", "primary")]);
    let mut app = on_rules(&fake);
    let set = RuleSet {
        rows: vec![RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: "news.example.com".into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }],
        files: 1,
        ..Default::default()
    };
    super::import(&mut app, set, "folder".into(), false);
    let overlaps = overlaps_text(&mut app);
    assert!(
        overlaps.contains("1 overlap(s) not confirmed"),
        "{overlaps}"
    );
}

// ── The rule-set folder ──────────────────────────────────────────────────────

mod rules_folder {
    use std::path::{Path, PathBuf};

    use nrr_shared::user_settings::{UserSettings, UserSettingsStore, USER_SETTINGS_FILE_NAME};

    use std::time::Instant;

    use nrr_shared::ipc::IpcOperationName;
    use nrr_shared::ipc_payloads::StatusUpdateEvent;
    use serde_json::json;

    use super::super::own_settings::{path_text, read};
    use super::{answer, drain, on_rules, rule, service};
    use crate::backend::{BackendEvent, PushEvent};
    use crate::screens::ScreenId;
    use crate::state::AppState;
    use crate::testing::{texts_en, FakeService, Scratch};

    /// The Rules screen over `rows`, with a settings file in `dir` and an
    /// empty `sets` folder beside it.
    fn rules_with_settings(dir: &Scratch, rows: Vec<serde_json::Value>) -> (AppState, PathBuf) {
        let mut app = on_rules(&service(rows));
        app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
        let sets = dir.path().join("sets");
        std::fs::create_dir_all(&sets).expect("sets folder");
        (app, sets)
    }

    fn one_rule() -> Vec<serde_json::Value> {
        vec![rule("1", "suffix-domain", "example.com", "primary")]
    }

    fn settings(app: &AppState) -> UserSettings {
        read(app.rules.settings_file.as_deref().expect("settings file")).expect("read")
    }

    fn seed(app: &AppState, change: impl FnOnce(&mut UserSettings)) {
        let file = app.rules.settings_file.clone().expect("settings file");
        UserSettingsStore::at(file).update(change).expect("seed");
    }

    fn choose(app: &mut AppState, folder: &Path) {
        answer(app, &["o", &folder.display().to_string()]);
    }

    fn note(app: &AppState) -> String {
        app.rules
            .note
            .as_ref()
            .map(|note| note.text(&texts_en()))
            .unwrap_or_default()
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("list")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn unbound_rules_are_saved_as_my_rules() {
        let dir = Scratch::new("folder-unbound");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        choose(&mut app, &sets);

        let set = sets.join("My rules");
        assert!(set.join("rules_primary.txt").is_file(), "{}", note(&app));
        let stored = settings(&app);
        assert_eq!(stored.rules_folder, path_text(&sets));
        assert_eq!(
            stored.rules_files.primary,
            path_text(&set.join("rules_primary.txt"))
        );
        let said = note(&app);
        assert!(said.contains("saved in your folder as a set"), "{said}");
        assert!(!said.contains("stay where they were"), "{said}");
    }

    #[test]
    fn rules_from_a_set_elsewhere_move_under_its_name() {
        let dir = Scratch::new("folder-elsewhere");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        let old = dir.path().join("old").join("work");
        std::fs::create_dir_all(&old).expect("old set");
        std::fs::write(old.join("rules_primary.txt"), "old").expect("old file");
        let old_file = path_text(&old.join("rules_primary.txt"));
        seed(&app, |s| s.set_primary_file(&old_file));

        choose(&mut app, &sets);

        let set = sets.join("work");
        assert!(set.join("rules_primary.txt").is_file(), "{}", note(&app));
        assert_eq!(
            settings(&app).rules_files.primary,
            path_text(&set.join("rules_primary.txt"))
        );
        let kept = std::fs::read_to_string(old.join("rules_primary.txt")).expect("old file");
        assert_eq!(kept, "old", "the old files are left as they were");
        let said = note(&app);
        assert!(said.contains("stay where they were"), "{said}");
        assert!(said.contains(&path_text(&old)), "{said}");
    }

    #[test]
    fn a_taken_name_gets_a_number_and_is_never_overwritten() {
        let dir = Scratch::new("folder-taken");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        let taken = sets.join("My rules");
        std::fs::create_dir_all(&taken).expect("taken set");
        std::fs::write(taken.join("rules_primary.txt"), "theirs").expect("taken file");

        choose(&mut app, &sets);

        assert!(sets
            .join("My rules (2)")
            .join("rules_primary.txt")
            .is_file());
        let theirs = std::fs::read_to_string(taken.join("rules_primary.txt")).expect("read");
        assert_eq!(theirs, "theirs");
    }

    #[test]
    fn rules_already_in_the_folder_stay_where_they_are() {
        let dir = Scratch::new("folder-inside");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        let home = path_text(&sets.join("home").join("rules_primary.txt"));
        seed(&app, |s| s.set_primary_file(&home));

        choose(&mut app, &sets);

        assert!(entries(&sets).is_empty(), "{:?}", entries(&sets));
        assert_eq!(settings(&app).rules_files.primary, home);
        assert!(note(&app).starts_with("Rule sets are now listed from"));
    }

    #[test]
    fn an_empty_list_writes_nothing() {
        let dir = Scratch::new("folder-empty");
        let (mut app, sets) = rules_with_settings(&dir, Vec::new());
        assert!(app.rules.table.rows.is_empty());

        choose(&mut app, &sets);

        assert!(entries(&sets).is_empty());
        assert_eq!(settings(&app).rules_folder, path_text(&sets));
    }

    #[test]
    fn a_dash_goes_back_to_the_shipped_sets() {
        let dir = Scratch::new("folder-clear");
        let (mut app, sets) = rules_with_settings(&dir, Vec::new());
        choose(&mut app, &sets);
        answer(&mut app, &["o", "-"]);
        assert_eq!(settings(&app).rules_folder, "");
    }

    #[test]
    fn a_folder_that_is_not_there_is_said_and_not_kept() {
        let dir = Scratch::new("folder-missing");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        choose(&mut app, &sets.join("nowhere"));
        assert!(
            note(&app).starts_with("There is no folder"),
            "{}",
            note(&app)
        );
        assert_eq!(settings(&app).rules_folder, "");
    }

    fn unsure_rule_and_its_verdict() -> FakeService {
        let fake = service(vec![
            rule("1", "suffix-domain", "example.com", "primary"),
            super::unsure("2", "exact-fqdn", "shop.example", "secondary"),
        ]);
        fake.answer(
            IpcOperationName::VerifyVerdictsList,
            json!({ "verdicts": [{
                "rule-id": "R-0002",
                "value": "shop.example",
                "kind": "domain",
                "from-route": "secondary",
                "to-route": "primary",
                "host": "shop.example",
                "since-unix-ms": 1,
                "dismissed": false
            }] }),
        );
        fake.answer(
            IpcOperationName::VerifyVerdictsAccept,
            json!({ "moved": 1 }),
        );
        fake.answer(
            IpcOperationName::VerifyVerdictsDismiss,
            json!({ "dismissed": 1 }),
        );
        fake
    }

    /// The verdict push, then the list it makes the screen read.
    fn verdicts_arrive(app: &mut AppState, fake: &FakeService) {
        let event = StatusUpdateEvent::VerifyVerdictsChanged {
            sid: "S".into(),
            pending_count: 1,
        };
        app.apply(
            BackendEvent::Push(PushEvent::Status(Box::new(event))),
            &texts_en(),
            Instant::now(),
        );
        drain(app, fake);
    }

    #[test]
    fn a_verdict_asks_once_and_points_at_this_screen() {
        let dir = Scratch::new("verdict-notice");
        let fake = unsure_rule_and_its_verdict();
        let mut app = on_rules(&fake);
        app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
        verdicts_arrive(&mut app, &fake);
        let text = super::screen_text(&app, ScreenId::Rules);
        assert!(
            text.contains("Addresses that do not open where they are written: 1"),
            "{text}"
        );
        assert!(text.contains("shop.example \u{2192} Primary"), "{text}");
        assert!(text.contains("m: Move. n: Not now."), "{text}");
        assert_eq!(app.notices.len(), 1, "{:?}", app.notices);
        assert!(app.notices[0].body.contains("open screen 4, Rules"));

        // The same list again says nothing new.
        verdicts_arrive(&mut app, &fake);
        assert_eq!(app.notices.len(), 1);
    }

    #[test]
    fn without_a_folder_move_asks_for_one_then_moves_and_writes_the_files() {
        let dir = Scratch::new("verdict-move");
        let fake = unsure_rule_and_its_verdict();
        let mut app = on_rules(&fake);
        app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
        let sets = dir.path().join("sets");
        std::fs::create_dir_all(&sets).expect("sets folder");
        verdicts_arrive(&mut app, &fake);

        answer(&mut app, &["m"]);
        assert!(matches!(
            app.rules.mode,
            super::super::Mode::Input(super::super::Input {
                purpose: super::super::InputPurpose::VerdictFolder,
                ..
            })
        ));
        answer(&mut app, &[&sets.display().to_string()]);
        drain(&mut app, &fake);

        assert_eq!(settings(&app).rules_folder, path_text(&sets));
        let moved = fake.sent(IpcOperationName::VerifyVerdictsAccept);
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0]["rule-ids"], json!(["R-0002"]));
        let primary = sets.join("My rules").join("rules_primary.txt");
        let written = std::fs::read_to_string(&primary).expect("bound file");
        assert!(written.contains("example.com"), "{written}");
        assert!(
            note(&app).contains("moved to the route where they work"),
            "{}",
            note(&app)
        );
    }

    #[test]
    fn not_now_and_an_empty_folder_answer_leave_the_rules_as_written() {
        let dir = Scratch::new("verdict-later");
        let fake = unsure_rule_and_its_verdict();
        let mut app = on_rules(&fake);
        app.rules.settings_file = Some(dir.path().join(USER_SETTINGS_FILE_NAME));
        verdicts_arrive(&mut app, &fake);

        answer(&mut app, &["m", ""]);
        drain(&mut app, &fake);
        answer(&mut app, &["n"]);
        drain(&mut app, &fake);

        let set_aside = fake.sent(IpcOperationName::VerifyVerdictsDismiss);
        assert_eq!(set_aside.len(), 2);
        assert_eq!(set_aside[1]["rule-ids"], json!(["R-0002"]));
        let moved = fake.sent(IpcOperationName::VerifyVerdictsAccept);
        assert!(moved.is_empty());
        assert_eq!(settings(&app).rules_folder, "");
    }

    #[test]
    fn without_a_settings_file_the_folder_cannot_be_chosen() {
        let mut app = on_rules(&service(one_rule()));
        answer(&mut app, &["o"]);
        assert!(note(&app).contains("baseline"), "{}", note(&app));
    }

    #[test]
    fn a_set_read_from_a_folder_becomes_the_bound_files() {
        let dir = Scratch::new("folder-import");
        let (mut app, sets) = rules_with_settings(&dir, Vec::new());
        let set = sets.join("trip");
        std::fs::create_dir_all(&set).expect("set");
        std::fs::write(
            set.join("rules_secondary.txt"),
            "--- Domains\nexample.org\n",
        )
        .expect("rules file");

        answer(&mut app, &["i", &set.display().to_string()]);

        let stored = settings(&app);
        assert_eq!(
            stored.rules_files.secondary,
            path_text(&set.join("rules_secondary.txt"))
        );
        assert_eq!(
            stored.rules_files.primary, "",
            "a route with no file keeps its own"
        );
    }
}

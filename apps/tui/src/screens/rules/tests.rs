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
    let missing = missing_from_locales(&text::file_hint_keys());
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
        base_revision: None,
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

/// The service and the GUI spell the content hash as fixed-width lowercase hex
/// of the rules sent; the terminal must not drift from them on a crypto-crate
/// upgrade.
#[test]
fn the_content_hash_spells_the_sent_bytes() {
    use sha2::{Digest, Sha256};
    let pending =
        apply::pending_from(&super::table::Table::default(), false, None).expect("pending");
    let expected: String = Sha256::digest(pending.rules_json.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(pending.content_hash, expected);
}

/// A value with a line break is never sent cleaned into another rule: the
/// apply stops with the error the GUI shows for it.
#[test]
fn a_rule_with_a_control_character_is_refused_before_it_is_sent() {
    let mut table = super::table::Table::default();
    table.import(
        vec![RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Application,
            match_value: "my\napp.exe +children".into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }],
        true,
    );
    assert_eq!(
        apply::pending_from(&table, false, None).err(),
        Some(apply::Failure::code("control-character"))
    );
}

/// The set the screen shows is the set every writer of the terminal writes:
/// `b` switches between the caller's own rules and the baseline, the list is
/// read from the one chosen, and a writer of the caller's own rules is refused
/// while the baseline is on screen.
#[test]
fn the_book_on_screen_is_the_book_written_and_b_switches_it() {
    let fake = service(vec![rule("r1", "domain", "example.com", "secondary")]);
    let mut app = on_rules(&fake);
    let baseline_asked = |fake: &FakeService| {
        fake.sent(IpcOperationName::RulesList)
            .last()
            .and_then(|sent| sent.get("baseline"))
            .and_then(Value::as_bool)
    };
    assert_eq!(baseline_asked(&fake), Some(false));

    answer(&mut app, &["b"]);
    assert!(app.rules.baseline);
    drain(&mut app, &fake);
    assert_eq!(baseline_asked(&fake), Some(true));
    let texts = texts_en();
    assert_eq!(
        super::render::view(&app, &texts).title,
        texts.get(text::TITLE_BASELINE)
    );
    assert!(!super::own_rules_on_screen(&mut app));

    answer(&mut app, &["t 1"]);
    answer(&mut app, &["b"]);
    assert!(
        app.rules.baseline,
        "edits made in the baseline stay with it"
    );

    // As after an apply: nothing on screen is the baseline's alone any more.
    app.rules.table.mark_applied();
    answer(&mut app, &["b"]);
    assert!(!app.rules.baseline);
    drain(&mut app, &fake);
    assert_eq!(baseline_asked(&fake), Some(false));
    assert!(super::own_rules_on_screen(&mut app));
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

/// Not in the table, so the screen has to say they exist and do nothing.
#[test]
fn rules_this_build_cannot_read_are_counted_on_screen() {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [rule("r1", "domain", "example.com", "secondary")],
            "supported-rule-types": ["domain"],
            "unrecognized": 2
        }),
    );
    let app = on_rules(&fake);
    assert!(
        screen_text(&app, ScreenId::Rules).contains("Rules this version cannot read: 2."),
        "{}",
        screen_text(&app, ScreenId::Rules)
    );

    let plain = on_rules(&service(vec![rule(
        "r1",
        "domain",
        "example.com",
        "secondary",
    )]));
    assert!(!screen_text(&plain, ScreenId::Rules).contains("cannot read"));
}

/// What an application rule holds on the additional link, with the service's
/// true count rather than the length of the capped list.
#[test]
fn the_chosen_application_rule_lists_the_addresses_it_holds() {
    let mut entry = rule("r1", "application", "client.exe", "secondary");
    entry["pinned-destinations"] = json!(["203.0.113.5", "198.51.100.7"]);
    entry["pinned-destinations-total"] = json!(40);
    let mut app = on_rules(&service(vec![
        entry,
        rule("r2", "domain", "example.com", "secondary"),
    ]));
    // The chosen row says the rest; the cursor starts on the first one.
    app.focus = crate::state::Focus::Feed;
    let text = screen_text(&app, ScreenId::Rules);
    assert!(
        text.contains("holds 40 addresses: 203.0.113.5, 198.51.100.7"),
        "{text}"
    );
    assert!(text.contains("EVERY program on this computer"), "{text}");
    assert_eq!(text.matches("holds ").count(), 1, "{text}");
}

/// A hostname the OS hosts file answers is marked on its row, as in the GUI.
#[test]
fn a_hostname_the_hosts_file_answers_is_marked() {
    let mut blocked = rule("r1", "domain", "ads.example.com", "secondary");
    blocked["hosts-override"] = json!({ "ip": "0.0.0.0", "blocking": true });
    let mut redirected = rule("r2", "domain", "intranet.example.com", "primary");
    redirected["hosts-override"] = json!({ "ip": "192.0.2.10", "blocking": false });
    let app = on_rules(&service(vec![
        blocked,
        redirected,
        rule("r3", "domain", "example.com", "secondary"),
    ]));
    let text = screen_text(&app, ScreenId::Rules);
    assert!(text.contains("Blocked in hosts"), "{text}");
    assert!(text.contains("Redirected by system → 192.0.2.10"), "{text}");
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
    assert!(overlaps.contains("0 overlaps not confirmed"), "{overlaps}");
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
    assert!(overlaps.contains("1 overlap not confirmed"), "{overlaps}");
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
    assert!(overlaps.contains("1 overlap not confirmed"), "{overlaps}");
}

// ── Discarding edits ─────────────────────────────────────────────────────────

/// "Show the rules the service applies" really drops the edits on screen.
#[test]
fn discarding_edits_brings_back_the_rules_in_force() {
    let fake = service(vec![rule("1", "domain", "example.com", "secondary")]);
    let mut app = on_rules(&fake);
    answer(&mut app, &["t 1"]);
    assert!(super::holds_unapplied(&app), "switched off on screen");
    answer(&mut app, &["r", "1"]);
    drain(&mut app, &fake);
    assert!(!super::holds_unapplied(&app));
    let kept = app.rules.table.rules().next().expect("the rule");
    assert!(kept.enabled, "the service's rule is back as it is applied");
}

// ── The chosen rule ──────────────────────────────────────────────────────────

fn chosen_value(app: &AppState) -> String {
    let master = app.rules.table.selected().expect("a chosen row");
    app.rules.table.rows[master].rule.match_value.clone()
}

fn press_key(app: &mut AppState, code: crossterm::event::KeyCode) {
    screen(ScreenId::Rules).on_key(
        app,
        crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE),
    );
}

/// The destructive answer is never the one Enter takes first.
#[test]
fn enter_on_the_delete_question_keeps_the_rule() {
    let fake = service(vec![rule("1", "domain", "a.example", "secondary")]);
    let mut app = on_rules(&fake);
    press_key(&mut app, crossterm::event::KeyCode::Delete);
    assert!(matches!(app.rules.mode, Mode::Choice(_)));
    press_key(&mut app, crossterm::event::KeyCode::Enter);
    assert_eq!(app.rules.table.rows.len(), 1);
    assert!(!matches!(app.rules.mode, Mode::Choice(_)));
}

/// A rule added elsewhere lands ahead of the chosen one: the cursor follows
/// its rule, not its row number, so the next toggle switches what was chosen.
#[test]
fn the_cursor_stays_on_its_rule_when_the_list_is_read_again() {
    let fake = service(vec![
        rule("1", "domain", "a.example", "secondary"),
        rule("2", "domain", "b.example", "secondary"),
        rule("3", "domain", "c.example", "secondary"),
    ]);
    let mut app = on_rules(&fake);
    app.focus = crate::state::Focus::Feed;
    press_key(&mut app, crossterm::event::KeyCode::Down);
    assert_eq!(chosen_value(&app), "b.example");

    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [
                rule("1", "domain", "new.example", "secondary"),
                rule("2", "domain", "a.example", "secondary"),
                rule("3", "domain", "b.example", "secondary"),
                rule("4", "domain", "c.example", "secondary"),
            ],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    super::on_revision_changed(&mut app);
    drain(&mut app, &fake);
    assert_eq!(app.rules.table.rows.len(), 4, "the list was read again");
    assert_eq!(chosen_value(&app), "b.example");
    assert_eq!(app.rules.table.cursor(), 2);

    press_key(&mut app, crossterm::event::KeyCode::Char(' '));
    let switched: Vec<&str> = app
        .rules
        .table
        .rules()
        .filter(|r| !r.enabled)
        .map(|r| r.match_value.as_str())
        .collect();
    assert_eq!(switched, ["b.example"]);
}

/// From the menu no row is marked, so a toggle there switches nothing yet.
#[test]
fn a_toggle_from_the_menu_first_shows_the_rule_it_would_switch() {
    let fake = service(vec![rule("1", "domain", "a.example", "secondary")]);
    let mut app = on_rules(&fake);
    app.focus = crate::state::Focus::Menu;
    press_key(&mut app, crossterm::event::KeyCode::Char('t'));
    assert!(
        app.rules.table.rules().all(|r| r.enabled),
        "nothing switched"
    );
    assert_eq!(app.focus, crate::state::Focus::Feed);
    press_key(&mut app, crossterm::event::KeyCode::Char('t'));
    assert!(app.rules.table.rules().all(|r| !r.enabled));
}

/// An open form keeps the row it edits: the re-read a revision asks for waits
/// until the form is closed, then happens.
#[test]
fn a_revision_while_a_form_is_open_is_read_once_it_closes() {
    let fake = service(vec![rule("1", "domain", "a.example", "secondary")]);
    let mut app = on_rules(&fake);
    answer(&mut app, &["e 1"]);
    assert!(matches!(app.rules.mode, Mode::Form(_)));

    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [
                rule("1", "domain", "new.example", "secondary"),
                rule("2", "domain", "a.example", "secondary"),
            ],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    super::on_revision_changed(&mut app);
    drain(&mut app, &fake);
    assert_eq!(app.rules.table.rows.len(), 1, "not under the open form");

    answer(&mut app, &["!"]);
    drain(&mut app, &fake);
    assert_eq!(app.rules.table.rows.len(), 2, "read once the form closed");
}

/// An apply refused because the rules changed elsewhere: the edits made here
/// go on top of the rules now in force — a switch, an addition and a removal
/// alike — and a rule added elsewhere stays.
#[test]
fn edits_go_on_top_of_the_rules_changed_elsewhere() {
    let fake = service(vec![
        rule("1", "domain", "a.example", "secondary"),
        rule("2", "domain", "b.example", "secondary"),
    ]);
    let mut app = on_rules(&fake);
    answer(&mut app, &["t 1"]);
    app.rules.table.rows.remove(1);
    let added = RuleRow {
        id: String::new(),
        enabled: true,
        rule_type: RuleType::from_slug("domain"),
        match_value: "mine.example".into(),
        target_route: TargetRoute::Secondary,
        verify: false,
        comment: String::new(),
        origin: None,
    };
    app.rules.table.import(vec![added], false);

    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [
                rule("1", "domain", "a.example", "secondary"),
                rule("2", "domain", "b.example", "secondary"),
                rule("3", "domain", "theirs.example", "secondary"),
            ],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    super::rebase_edits(&mut app);
    drain(&mut app, &fake);
    assert!(
        matches!(app.rules.mode, Mode::Merge(_)),
        "the edits are shown against the rules in force before anything is replaced"
    );
    answer(&mut app, &["y"]);
    drain(&mut app, &fake);

    let rules: Vec<(String, bool)> = app
        .rules
        .table
        .rules()
        .map(|r| (r.match_value.clone(), r.enabled))
        .collect();
    assert_eq!(
        rules,
        [
            ("a.example".to_owned(), false),
            ("theirs.example".to_owned(), true),
            ("mine.example".to_owned(), true),
        ]
    );
    assert!(super::holds_unapplied(&app));
}

// ── The main-route check ─────────────────────────────────────────────────────

mod main_route {
    use std::time::Instant;

    use nrr_shared::ipc::IpcOperationName;
    use serde_json::{json, Value};

    use super::super::main_route::POLL;
    use super::super::Mode;
    use super::{answer, on_rules, rule, screen_text, service, ADD_DOMAIN};
    use crate::backend::BackendEvent;
    use crate::link::Link;
    use crate::plain::PlainSession;
    use crate::screens::suggestions::tests::{drain, render};
    use crate::screens::ScreenId;
    use crate::state::{AppState, Focus};
    use crate::testing::{app_at, assert_snapshot, texts_en, FakeService, Fixture};

    fn marked(id: &str, rule_type: &str, value: &str, route: &str, verdict: &str) -> Value {
        let mut entry = rule(id, rule_type, value, route);
        entry["main-route"] = Value::from(verdict);
        entry
    }

    /// A row of every verdict, a zone, and two rules never asked about.
    fn every_verdict() -> Vec<Value> {
        vec![
            marked("1", "domain", "silent.example", "secondary", "silent"),
            marked("2", "domain", "answered.example", "secondary", "answered"),
            marked("3", "domain", "new.example", "secondary", "no-address"),
            marked("4", "domain", "odd.example", "secondary", "unclear"),
            rule("5", "zone", "ru", "secondary"),
            rule("6", "domain", "main.example", "primary"),
            rule("7", "domain", "later.example", "secondary"),
        ]
    }

    fn rules_list(rows: Vec<Value>, pending: u32) -> Value {
        json!({
            "rows": rows,
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"],
            "main-route-pending": pending
        })
    }

    /// Runs the polls the screen asked to have run later.
    fn run_later(app: &mut AppState, fake: &FakeService) {
        let later = app.outbox.take_delayed();
        assert!(!later.is_empty(), "a poll was asked for");
        for (delay, job) in later {
            assert_eq!(delay, POLL);
            let reply = job(fake);
            app.apply(BackendEvent::Reply(reply), &texts_en(), Instant::now());
        }
    }

    fn note(app: &AppState) -> String {
        app.rules
            .note
            .as_ref()
            .map(|note| note.text(&texts_en()))
            .unwrap_or_default()
    }

    #[test]
    fn the_column_names_every_verdict_and_the_zone() {
        let mut app = on_rules(&service(every_verdict()));
        let text = screen_text(&app, ScreenId::Rules);
        for expected in [
            "silent.example \u{2014} Additional \u{b7} Main route: does not reach",
            "answered.example \u{2014} Additional \u{b7} Main route: reaches",
            "new.example \u{2014} Additional \u{b7} Main route: not seen yet",
            "odd.example \u{2014} Additional \u{b7} Main route: could not check",
            "ru \u{2014} Additional \u{b7} Main route: not checked",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        for unmarked in [
            "main.example \u{2014} Primary\n",
            "later.example \u{2014} Additional\n",
        ] {
            assert!(text.contains(unmarked), "{unmarked}\n{text}");
        }

        // The chosen rule explains its word.
        app.focus = Focus::Feed;
        let chosen = screen_text(&app, ScreenId::Rules);
        assert!(
            chosen.contains("Nothing answered at this address over the main connection"),
            "{chosen}"
        );
        assert_snapshot("rules-main-route-80x24", &render(&app, 80, 24));
    }

    #[test]
    fn a_verdict_held_under_the_ace_spelling_marks_the_idn_rule() {
        let mut app = on_rules(&service(vec![rule(
            "1",
            "domain",
            "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}",
            "secondary",
        )]));
        let list: nrr_shared::ipc_payloads::RulesListResponse = serde_json::from_value(rules_list(
            vec![marked(
                "1",
                "domain",
                "xn--e1afmkfd.xn--p1ai",
                "secondary",
                "silent",
            )],
            0,
        ))
        .expect("a rules list");
        app.rules.table.merge_main_route(&list.rows);
        assert_eq!(
            app.rules.table.rows[0].main_route.as_deref(),
            Some("silent")
        );
    }

    #[test]
    fn without_a_verdict_or_a_check_the_list_has_no_column() {
        let app = on_rules(&service(vec![
            rule("1", "zone", "ru", "secondary"),
            rule("2", "domain", "example.com", "secondary"),
        ]));
        let text = screen_text(&app, ScreenId::Rules);
        assert!(!text.contains("Main route"), "{text}");
    }

    #[test]
    fn the_order_puts_what_the_main_route_does_not_reach_first() {
        let mut app = on_rules(&service(every_verdict()));
        answer(&mut app, &["O"]);
        let text = screen_text(&app, ScreenId::Rules);
        assert!(text.contains("Sort: Main route check"), "{text}");
        let order = [
            "silent.example",
            "answered.example",
            "odd.example",
            "new.example",
            "later.example",
            "main.example",
            "ru \u{2014}",
        ];
        let at: Vec<usize> = order
            .iter()
            .map(|value| {
                text.find(value)
                    .unwrap_or_else(|| panic!("{value}\n{text}"))
            })
            .collect();
        assert!(at.windows(2).all(|w| w[0] < w[1]), "{at:?}\n{text}");

        // `e 1` names the first rule as shown.
        answer(&mut app, &["e 1"]);
        let Mode::Form(form) = &app.rules.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.value, "silent.example");

        answer(&mut app, &["!", "O"]);
        assert!(!screen_text(&app, ScreenId::Rules).contains("Sort:"));
    }

    #[test]
    fn a_check_asks_about_additional_route_hosts_and_keeps_edits_on_screen() {
        let fake = service(vec![
            rule("1", "domain", "*.Video.example", "secondary"),
            rule("2", "domain", "shop.example", "secondary"),
            rule("3", "zone", "ru", "secondary"),
            rule("4", "domain", "main.example", "primary"),
        ]);
        fake.answer(
            IpcOperationName::AutoRuleCandidatesProbe,
            json!({ "accepted": 2 }),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &ADD_DOMAIN);
        answer(&mut app, &["added.example", "2", "", "", "1"]);
        assert!(matches!(app.rules.mode, Mode::List), "saved");
        assert!(super::super::holds_unapplied(&app), "an edit waits");

        answer(&mut app, &["c"]);
        assert!(screen_text(&app, ScreenId::Rules).contains("Checking..."));
        drain(&mut app, &fake);
        let asked = fake.sent(IpcOperationName::AutoRuleCandidatesProbe);
        assert_eq!(
            asked[0]["rule-hostnames"],
            json!(["video.example", "shop.example", "added.example"])
        );
        let text = screen_text(&app, ScreenId::Rules);
        assert!(
            text.contains("Checking 2 addresses over the main connection"),
            "{text}"
        );
        assert!(
            text.contains("ru \u{2014} Additional \u{b7} Main route: not checked"),
            "{text}"
        );

        fake.answer(
            IpcOperationName::RulesList,
            rules_list(
                vec![
                    marked("1", "domain", "*.video.example", "secondary", "answered"),
                    rule("2", "domain", "shop.example", "secondary"),
                ],
                1,
            ),
        );
        run_later(&mut app, &fake);
        let text = screen_text(&app, ScreenId::Rules);
        assert!(
            text.contains("Checking addresses over the main connection: 1 of 2"),
            "{text}"
        );

        // A second press while it runs starts nothing.
        answer(&mut app, &["c"]);
        drain(&mut app, &fake);
        assert_eq!(
            fake.sent(IpcOperationName::AutoRuleCandidatesProbe).len(),
            1
        );

        fake.answer(
            IpcOperationName::RulesList,
            rules_list(
                vec![
                    marked("1", "domain", "*.video.example", "secondary", "answered"),
                    marked("2", "domain", "shop.example", "secondary", "silent"),
                ],
                0,
            ),
        );
        run_later(&mut app, &fake);
        assert!(app.rules.main_route.check.is_none());
        assert!(app.outbox.take_delayed().is_empty(), "no more polls");
        assert_eq!(
            note(&app),
            "Main route check finished: reaches 1, does not reach 1, not checked 1."
        );
        let text = screen_text(&app, ScreenId::Rules);
        assert!(
            text.contains("shop.example \u{2014} Additional \u{b7} Main route: does not reach"),
            "{text}"
        );
        assert!(text.contains("added.example"), "the edit is still there");
        assert!(super::super::holds_unapplied(&app), "and still not applied");
    }

    #[test]
    fn nothing_to_ask_about_sends_nothing() {
        let fake = service(vec![
            rule("1", "zone", "ru", "secondary"),
            rule("2", "domain", "main.example", "primary"),
        ]);
        let mut app = on_rules(&fake);
        answer(&mut app, &["c"]);
        drain(&mut app, &fake);
        assert!(fake
            .sent(IpcOperationName::AutoRuleCandidatesProbe)
            .is_empty());
        assert_eq!(
            note(&app),
            "There are no additional-route address rules to check."
        );
    }

    #[test]
    fn a_check_the_service_takes_nothing_of_ends_at_once() {
        let fake = service(vec![rule("1", "domain", "shop.example", "secondary")]);
        fake.answer(
            IpcOperationName::AutoRuleCandidatesProbe,
            json!({ "accepted": 0 }),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["c"]);
        drain(&mut app, &fake);
        assert!(app.rules.main_route.check.is_none());
        assert!(app.outbox.take_delayed().is_empty());
        assert!(note(&app).starts_with("Nothing to check"), "{}", note(&app));
    }

    #[test]
    fn a_failed_read_is_tried_again_and_the_polling_is_bounded_as_the_windows_is() {
        use super::super::apply::Failure;
        use super::super::main_route::polled;
        let fake = service(vec![rule("1", "domain", "shop.example", "secondary")]);
        fake.answer(
            IpcOperationName::AutoRuleCandidatesProbe,
            json!({ "accepted": 1 }),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["c"]);
        drain(&mut app, &fake);
        assert!(app.rules.main_route.check.is_some());
        app.outbox.take_delayed();

        polled(&mut app, Err(Failure::code("timeout")));
        assert!(
            app.rules.main_route.check.is_some(),
            "one failed read ends nothing"
        );
        assert_eq!(app.outbox.take_delayed().len(), 1, "and it is asked again");

        for _ in 0..nrr_client_logic::rules_table::CHECK_MAX_POLLS {
            polled(&mut app, Err(Failure::code("timeout")));
        }
        assert!(app.rules.main_route.check.is_none(), "given up");
        assert!(note(&app).starts_with("Not done"), "{}", note(&app));
    }

    #[test]
    fn line_mode_reads_the_check_as_it_goes() {
        let fake = service(vec![
            rule("1", "domain", "shop.example", "secondary"),
            rule("2", "zone", "ru", "secondary"),
        ]);
        fake.answer(
            IpcOperationName::AutoRuleCandidatesProbe,
            json!({ "accepted": 1 }),
        );
        let texts = texts_en();
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let mut session = PlainSession::new(Vec::new());
        session.start(&app, &texts).expect("start");
        session.input("4", &mut app, &texts).expect("open rules");
        drain(&mut app, &fake);
        session.input("c", &mut app, &texts).expect("check");
        drain(&mut app, &fake);
        session.input("", &mut app, &texts).expect("read again");
        fake.answer(
            IpcOperationName::RulesList,
            rules_list(
                vec![marked("1", "domain", "shop.example", "secondary", "silent")],
                0,
            ),
        );
        run_later(&mut app, &fake);
        session.input("O", &mut app, &texts).expect("order");
        let text = String::from_utf8(session.into_inner()).expect("UTF-8");
        assert!(
            text.contains("c: check whether the main route reaches"),
            "{text}"
        );
        assert!(
            text.contains("shop.example \u{2014} Additional \u{b7} Main route: does not reach"),
            "{text}"
        );
        assert!(
            text.contains("Main route check finished: reaches 0, does not reach 1, not checked 0."),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
        assert_snapshot("rules-main-route-plain", &text);
    }
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
    #[test]
    fn an_apply_rewrites_the_bound_files() {
        let dir = Scratch::new("apply-writes-files");
        let (mut app, sets) = rules_with_settings(&dir, one_rule());
        let file = app.rules.settings_file.clone().expect("settings file");
        let set = sets.join("mine");
        std::fs::create_dir_all(&set).expect("set");
        super::super::own_settings::bind_written_set(&file, &set, None).expect("bind");
        let primary = set.join("rules_primary.txt");
        std::fs::write(
            &primary,
            "--- Domains
old.example
",
        )
        .expect("old file");
        // Its own earlier write is on record: the file is not hand-edited.
        super::super::own_settings::note_written(&file, std::slice::from_ref(&primary))
            .expect("note");

        super::super::finished(
            &mut app,
            super::super::apply::Finished::Applied { base: None },
        );

        let written = std::fs::read_to_string(&primary).expect("bound file");
        assert!(written.contains("example.com"), "{written}");
        assert!(!written.contains("old.example"), "{written}");
    }
}

/// `v`: a rule for a VPN's gateway, the window's "Other VPNs (corporate)".
mod gateway {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn with_candidates(rows: Vec<Value>, candidates: Value) -> FakeService {
        let fake = service(rows);
        fake.answer(IpcOperationName::VpnGatewayCandidatesList, candidates);
        fake
    }

    fn two_candidates() -> Value {
        json!({
            "program": "corpvpn.exe",
            "candidates": [
                {
                    "address": "203.0.113.5",
                    "hostname": "gw.corp.example",
                    "ports": [500, 4500],
                    "protocols": ["udp"],
                    "connections": 3,
                    "last-seen-ms": 1_757_000_000_000_i64
                },
                {
                    "address": "198.51.100.7",
                    "ports": [443],
                    "protocols": ["tcp"],
                    "connections": 1,
                    "last-seen-ms": 0
                }
            ],
            "omitted": 2,
            "observer-active": true
        })
    }

    fn note(app: &AppState) -> String {
        app.rules
            .note
            .as_ref()
            .map(|note| note.text(&texts_en()))
            .unwrap_or_default()
    }

    fn press(app: &mut AppState, code: KeyCode) {
        screen(ScreenId::Rules).on_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }

    #[test]
    fn a_number_adds_the_listed_address_over_the_chosen_channel() {
        let fake = with_candidates(Vec::new(), two_candidates());
        let mut app = on_rules(&fake);
        // A path is reduced to the program's file name; Enter alone keeps the
        // additional channel.
        answer(&mut app, &["v", "C:\\Apps\\Corp\\corpvpn.exe", ""]);
        drain(&mut app, &fake);

        assert_eq!(
            fake.sent(IpcOperationName::VpnGatewayCandidatesList),
            vec![json!({ "program": "corpvpn.exe" })]
        );
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(
            shown.contains(
                "1. 203.0.113.5 · ports 500, 4500 · last seen 2025-09-04 15:33 · By name: gw.corp.example"
            ),
            "{shown}"
        );
        assert!(
            shown.contains("2. 198.51.100.7 · ports 443 · last seen —"),
            "{shown}"
        );
        assert!(shown.contains("Addresses not shown: 2."), "{shown}");

        answer(&mut app, &["1"]);
        assert!(matches!(app.rules.mode, Mode::List));
        let row = app.rules.table.rows.last().expect("a rule was added");
        assert_eq!(row.rule.rule_type, RuleType::ExactIp);
        assert_eq!(row.rule.match_value, "203.0.113.5");
        assert_eq!(row.rule.target_route, TargetRoute::Secondary);
        assert_eq!(row.rule.comment, "VPN gateway: corpvpn.exe");
        assert!(app.rules.table.is_dirty(), "s applies it like any edit");
        assert!(note(&app).contains("Rule added"), "{}", note(&app));
    }

    #[test]
    fn a_typed_name_becomes_a_host_rule_on_the_main_channel() {
        let fake = with_candidates(Vec::new(), two_candidates());
        let mut app = on_rules(&fake);
        answer(&mut app, &["v", "corpvpn.exe", "1"]);
        drain(&mut app, &fake);
        answer(&mut app, &["https://GW.corp.example/login"]);

        let row = app.rules.table.rows.last().expect("a rule was added");
        assert_eq!(row.rule.rule_type, RuleType::Domain);
        assert_eq!(row.rule.match_value, "gw.corp.example");
        assert_eq!(row.rule.target_route, TargetRoute::Primary);
    }

    #[test]
    fn a_value_that_is_no_address_keeps_the_question_and_bang_cancels() {
        let fake = with_candidates(
            Vec::new(),
            json!({ "program": "corpvpn.exe", "candidates": [], "observer-active": false }),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["v", "corpvpn.exe", ""]);
        drain(&mut app, &fake);
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(
            shown.contains("cannot see where a program connects"),
            "an unwatched machine says so: {shown}"
        );

        answer(&mut app, &["not a host"]);
        assert!(matches!(app.rules.mode, Mode::Gateway(_)));
        assert!(screen_text(&app, ScreenId::Rules)
            .contains("This is neither an address nor a host name."),);
        answer(&mut app, &["!"]);
        assert!(matches!(app.rules.mode, Mode::List));
        assert!(app.rules.table.rows.is_empty());
    }

    #[test]
    fn an_address_already_in_the_list_is_not_added_twice() {
        let fake = with_candidates(
            vec![rule("1", "exact-ip", "203.0.113.5", "secondary")],
            two_candidates(),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["v", "corpvpn.exe", "2"]);
        drain(&mut app, &fake);
        answer(&mut app, &[""]);

        assert_eq!(app.rules.table.rows.len(), 1);
        assert!(
            note(&app).contains("Already in the list: 1."),
            "{}",
            note(&app)
        );
    }

    #[test]
    fn the_keys_walk_the_same_questions() {
        let fake = with_candidates(Vec::new(), two_candidates());
        let mut app = on_rules(&fake);
        press(&mut app, KeyCode::Char('v'));
        for c in "corpvpn.exe".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Enter);
        drain(&mut app, &fake);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Enter);

        let row = app.rules.table.rows.last().expect("a rule was added");
        assert_eq!(row.rule.match_value, "198.51.100.7");
        assert_eq!(row.rule.target_route, TargetRoute::Secondary);
    }
}

mod several_rules {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn note(app: &AppState) -> String {
        app.rules
            .note
            .as_ref()
            .map(|note| note.text(&texts_en()))
            .unwrap_or_default()
    }

    fn press(app: &mut AppState, code: KeyCode, modifiers: KeyModifiers) {
        screen(ScreenId::Rules).on_key(app, KeyEvent::new(code, modifiers));
    }

    /// The planner holds a comment to the length an import accepts.
    #[test]
    fn the_comment_bound_is_the_import_bound() {
        assert_eq!(
            nrr_client_logic::bulk_rules::COMMENT_MAX_CHARS,
            nrr_domain::preset_validation::MAX_INLINE_COMMENT_CHARS
        );
    }

    /// A pasted list goes into the list on screen in one step: new rules
    /// added, a rule found on another route moved only once asked, and a line
    /// that is no rule kept in the form. The service hears of none of it until
    /// the one apply.
    #[test]
    fn several_rules_go_in_at_once_and_the_rest_stays_in_the_form() {
        let fake = service(vec![rule("1", "domain", "moved.example", "primary")]);
        let mut app = on_rules(&fake);
        answer(
            &mut app,
            &[
                "A",
                "2",
                "one.example",
                "!ads.example.net  # ads",
                "moved.example",
                "not a rule",
                "",
            ],
        );
        let Mode::Bulk(form) = &app.rules.mode else {
            panic!("the several-rules form is open");
        };
        assert_eq!(
            form.plan
                .count(nrr_client_logic::bulk_rules::RowAction::Move),
            0
        );
        // Line 3 stands on Primary; it moves only when asked.
        answer(&mut app, &["m 3", "y"]);

        let rows: Vec<(String, TargetRoute)> = app
            .rules
            .table
            .rules()
            .map(|r| (r.match_value.clone(), r.target_route.clone()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("moved.example".to_owned(), TargetRoute::Secondary),
                ("one.example".to_owned(), TargetRoute::Secondary),
                ("ads.example.net".to_owned(), TargetRoute::Block),
            ]
        );
        assert_eq!(
            app.rules.table.rules().nth(2).map(|r| r.comment.as_str()),
            Some("ads")
        );
        assert!(app.rules.table.is_dirty(), "applied only by the one apply");
        let Mode::Bulk(form) = &app.rules.mode else {
            panic!("the form stays up with what was not taken");
        };
        assert_eq!(form.text, "not a rule");
        let said = note(&app);
        assert!(said.contains("Rules added: 2."), "{said}");
        assert!(said.contains("Moved to the chosen route: 1."), "{said}");
        assert!(said.contains("Left in the form to fix: 1."), "{said}");
    }

    /// One word asks for its type on its own row, and is added as that type.
    #[test]
    fn one_word_takes_the_type_the_user_picks() {
        let fake = service(Vec::new());
        let mut app = on_rules(&fake);
        answer(&mut app, &["A", "", "corp-internal", ""]);
        let Mode::Bulk(form) = &app.rules.mode else {
            panic!("the several-rules form is open");
        };
        assert_eq!(
            form.plan
                .count(nrr_client_logic::bulk_rules::RowAction::Add),
            0
        );
        answer(&mut app, &["t 1 1", "y"]);
        let added = app.rules.table.rules().next().expect("added");
        assert_eq!(added.rule_type, RuleType::Zone);
        assert_eq!(added.match_value, "corp-internal");
        assert!(matches!(app.rules.mode, Mode::List), "nothing left to fix");
    }

    /// The one-rule form offers the type its value is; it changes on the
    /// user's key only, in line mode and full-screen alike.
    #[test]
    fn the_form_switches_to_the_type_the_value_is() {
        let fake = service(Vec::new());
        let mut app = on_rules(&fake);
        answer(&mut app, &["a", "", "192.0.2.7"]);
        let Mode::Form(form) = &app.rules.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.rule_type, RuleType::Domain, "nothing moves on its own");
        assert!(screen_text(&app, ScreenId::Rules).contains("!t in line mode"));
        answer(&mut app, &["!t"]);
        let Mode::Form(form) = &app.rules.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.rule_type, RuleType::ExactIp);

        let mut app = on_rules(&fake);
        press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        for c in "192.0.2.8".chars() {
            press(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }
        press(&mut app, KeyCode::Char('t'), KeyModifiers::CONTROL);
        let Mode::Form(form) = &app.rules.mode else {
            panic!("the form is open");
        };
        assert_eq!(form.rule_type, RuleType::ExactIp);
    }

    /// Line mode moves a rule to the type its value is, one or all, as Shift+T
    /// and Shift+M do.
    #[test]
    fn line_mode_moves_a_rule_to_its_type() {
        let fake = service(vec![
            rule("1", "domain", "192.0.2.7", "primary"),
            rule("2", "domain", "198.51.100.0/24", "primary"),
        ]);
        let mut app = on_rules(&fake);
        answer(&mut app, &["T 1"]);
        let types: Vec<RuleType> = app
            .rules
            .table
            .rules()
            .map(|r| r.rule_type.clone())
            .collect();
        assert_eq!(types, vec![RuleType::ExactIp, RuleType::Domain]);
        answer(&mut app, &["M"]);
        assert_eq!(
            app.rules.table.rules().nth(1).map(|r| r.rule_type.clone()),
            Some(RuleType::Subnet)
        );
    }

    /// F2 takes the one-rule form's route and value into "several rules".
    #[test]
    fn f2_carries_the_form_into_several_rules() {
        let fake = service(Vec::new());
        let mut app = on_rules(&fake);
        press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        for c in "one.example".chars() {
            press(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }
        press(&mut app, KeyCode::F(2), KeyModifiers::NONE);
        let Mode::Bulk(form) = &app.rules.mode else {
            panic!("the several-rules form is open");
        };
        assert_eq!(form.text, "one.example");
        press(&mut app, KeyCode::Char('s'), KeyModifiers::CONTROL);
        assert_eq!(app.rules.table.rows.len(), 1);
    }
}

/// `R`: «Recent», the window's filter of the same name.
mod recent {
    use super::*;

    fn with_recent(rows: Vec<Value>, changes: Value) -> FakeService {
        let fake = service(rows);
        fake.answer(IpcOperationName::RulesRecentChangesList, changes);
        fake
    }

    fn entry(value: &str, route: &str) -> Value {
        rule("", "domain", value, route)
    }

    fn changes() -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "changes": [
                { "kind": "added", "at": now - 60, "rule": entry("new.example", "secondary") },
                {
                    "kind": "changed",
                    "at": now - 120,
                    "rule": entry("moved.example", "secondary"),
                    "previous": { "target-route": "primary", "enabled": true }
                },
                { "kind": "deleted", "at": now - 180, "rule": entry("gone.example", "primary") },
                { "kind": "replaced", "at": now - 240, "count": 7, "members": [entry("a.example", "primary")] }
            ],
            "history-starts-at": now - 3000
        })
    }

    #[test]
    fn the_rules_changed_lately_show_newest_first_with_what_they_were() {
        let fake = with_recent(
            vec![
                rule("r1", "domain", "old.example", "primary"),
                rule("r2", "domain", "moved.example", "secondary"),
                rule("r3", "domain", "new.example", "secondary"),
            ],
            changes(),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["R", "3"]);
        drain(&mut app, &fake);

        let sent = fake.sent(IpcOperationName::RulesRecentChangesList);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert!(sent[0]["since"].as_i64().is_some(), "{sent:?}");

        let visible: Vec<String> = app
            .rules
            .table
            .visible()
            .into_iter()
            .map(|i| app.rules.table.rows[i].rule.match_value.clone())
            .collect();
        assert_eq!(visible, ["new.example", "moved.example"]);

        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("Recent: Today"), "{shown}");
        assert!(
            shown.contains("new.example — Additional · added"),
            "{shown}"
        );
        assert!(
            shown.contains("moved.example — Additional · changed"),
            "{shown}"
        );
        assert!(
            shown.contains("Rule set replaced, rules in it: 7"),
            "{shown}"
        );
        assert!(shown.contains("Deleted"), "{shown}");
        assert!(
            shown.contains("U1. Domain  gone.example — Primary, deleted"),
            "{shown}"
        );
        assert!(shown.contains("History is kept from"), "{shown}");

        // Off again: every rule is back.
        answer(&mut app, &["R", "1"]);
        assert_eq!(app.rules.table.visible().len(), 3);
    }

    #[test]
    fn a_deleted_rule_goes_back_as_it_was_and_only_once() {
        let fake = with_recent(
            vec![rule("r1", "domain", "old.example", "primary")],
            changes(),
        );
        let mut app = on_rules(&fake);
        answer(&mut app, &["R", "3"]);
        drain(&mut app, &fake);

        answer(&mut app, &["U 1"]);
        let row = app.rules.table.rows.last().expect("put back");
        assert_eq!(row.rule.match_value, "gone.example");
        assert_eq!(row.rule.target_route, TargetRoute::Primary);
        assert!(row.rule.enabled);
        assert!(app.rules.table.is_dirty(), "s applies it like any edit");
        let count = app.rules.table.rows.len();

        // It is in the list now: a second time adds nothing.
        answer(&mut app, &["U 1"]);
        assert_eq!(app.rules.table.rows.len(), count);
    }

    #[test]
    fn nothing_is_asked_while_recent_is_off() {
        let fake = with_recent(
            vec![rule("r1", "domain", "old.example", "primary")],
            changes(),
        );
        let _app = on_rules(&fake);
        assert!(fake
            .sent(IpcOperationName::RulesRecentChangesList)
            .is_empty());
    }
}

// ── Paste ────────────────────────────────────────────────────────────────────

/// Pasted lines are text, never commands: outside a field they are dropped,
/// inside one only the first line is typed.
#[test]
fn a_paste_never_runs_as_commands() {
    let fake = service(vec![
        rule("1", "domain", "a.example", "secondary"),
        rule("2", "domain", "b.example", "secondary"),
    ]);
    let mut app = on_rules(&fake);
    app.focus = crate::state::Focus::Feed;
    crate::full::handle_paste(&mut app, "d\n\ny\no\n", &texts_en());
    assert!(matches!(app.rules.mode, Mode::List), "no question opened");
    assert_eq!(app.rules.table.rows.len(), 2);
    assert!(!super::holds_unapplied(&app));

    app.rules.mode = Mode::Input(super::Input {
        purpose: super::InputPurpose::Search,
        text: String::new(),
    });
    crate::full::handle_paste(&mut app, "first\nsecond\n", &texts_en());
    match &app.rules.mode {
        Mode::Input(input) => assert_eq!(input.text, "first"),
        other => panic!("{other:?}"),
    }
    assert_eq!(app.rules.table.rows.len(), 2);
}

/// Keys that merely arrive together are typing on a menu, and a Windows
/// burst of two lines into the search field is text.
#[test]
fn fast_keys_are_keys_and_a_burst_in_a_field_is_text() {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    let k = |c| Event::Key(KeyEvent::new(c, KeyModifiers::NONE));
    let typed = vec![
        k(KeyCode::Char('a')),
        k(KeyCode::Char('b')),
        k(KeyCode::Char('c')),
        k(KeyCode::Enter),
        k(KeyCode::Char('d')),
    ];
    assert!(crate::paste::group(typed, false)
        .iter()
        .all(|i| matches!(i, crate::paste::Input::Key(_))));

    let burst = vec![
        k(KeyCode::Char('x')),
        k(KeyCode::Enter),
        k(KeyCode::Char('y')),
        k(KeyCode::Enter),
    ];
    let inputs = crate::paste::group(burst, true);
    assert_eq!(inputs, vec![crate::paste::Input::Paste("x\ny\n".into())]);

    let fake = service(vec![rule("1", "domain", "a.example", "secondary")]);
    let mut app = on_rules(&fake);
    app.rules.mode = Mode::Input(super::Input {
        purpose: super::InputPurpose::Search,
        text: String::new(),
    });
    if let Some(crate::paste::Input::Paste(text)) = inputs.into_iter().next() {
        crate::full::handle_paste(&mut app, &text, &texts_en());
    }
    match &app.rules.mode {
        Mode::Input(input) => assert_eq!(input.text, "x"),
        other => panic!("{other:?}"),
    }
}

// ── The merge of edits and rules changed elsewhere ───────────────────────────

mod merge {
    use nrr_shared::ipc::IpcOperationName;
    use serde_json::json;

    use super::super::Mode;
    use super::{answer, on_rules, rule, screen_text, service};
    use crate::screens::suggestions::tests::drain;
    use crate::screens::ScreenId;
    use crate::state::AppState;
    use crate::testing::FakeService;

    /// `a.example` switched off here while it was moved to the main route
    /// elsewhere, `b.example` deleted here, `mine.example` added here.
    fn clashing() -> (AppState, FakeService) {
        let fake = service(vec![
            rule("1", "domain", "a.example", "secondary"),
            rule("2", "domain", "b.example", "secondary"),
        ]);
        let mut app = on_rules(&fake);
        app.rules.table.rows[0].rule.enabled = false;
        app.rules.table.rows.remove(1);
        app.rules.table.import(
            vec![nrr_client_logic::rules_table::RuleRow {
                id: String::new(),
                enabled: true,
                rule_type: nrr_client_logic::rules_table::RuleType::from_slug("domain"),
                match_value: "mine.example".into(),
                target_route: nrr_client_logic::rules_table::TargetRoute::Secondary,
                verify: false,
                comment: String::new(),
                origin: None,
            }],
            false,
        );
        fake.answer(
            IpcOperationName::RulesList,
            json!({
                "rows": [
                    rule("1", "domain", "a.example", "primary"),
                    rule("2", "domain", "b.example", "secondary"),
                    rule("3", "domain", "theirs.example", "secondary"),
                ],
                "base-revision": "rev-2",
                "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
            }),
        );
        super::super::rebase_edits(&mut app);
        drain(&mut app, &fake);
        (app, fake)
    }

    fn enabled_and_route(app: &AppState, value: &str) -> Option<(bool, String)> {
        app.rules
            .table
            .rules()
            .find(|r| r.match_value == value)
            .map(|r| (r.enabled, r.target_route.as_str().to_owned()))
    }

    #[test]
    fn the_buckets_and_the_conflict_are_shown_before_anything_is_replaced() {
        let (app, _) = clashing();
        assert!(matches!(app.rules.mode, Mode::Merge(_)));
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("Only in your edits (1)"), "{shown}");
        assert!(shown.contains("mine.example"), "{shown}");
        assert!(shown.contains("Deleted by you (1)"), "{shown}");
        assert!(shown.contains("b.example"), "{shown}");
        assert!(shown.contains("Conflicts (1)"), "{shown}");
        assert!(shown.contains("Your edit:"), "{shown}");
        assert!(shown.contains("In force:"), "{shown}");
        assert!(
            shown.contains("stays: Your edit"),
            "the user's version is the default"
        );
        assert_eq!(
            enabled_and_route(&app, "a.example"),
            Some((false, "secondary".into())),
            "the edits are still the list"
        );
        assert_eq!(
            app.rules.base_revision, None,
            "still standing on the old revision"
        );
    }

    #[test]
    fn merging_with_the_default_pick_keeps_the_users_version() {
        let (mut app, fake) = clashing();
        answer(&mut app, &["y"]);
        drain(&mut app, &fake);
        // A rule is named by its route too: the move elsewhere made the user's
        // switched-off rule a separate one, kept beside the rule in force.
        let on = |route: &str| {
            app.rules
                .table
                .rules()
                .find(|r| r.match_value == "a.example" && r.target_route.as_str() == route)
                .map(|r| r.enabled)
        };
        assert_eq!(on("secondary"), Some(false), "the user's version is kept");
        assert_eq!(on("primary"), Some(true), "the rule in force is untouched");
        assert!(enabled_and_route(&app, "b.example").is_none());
        assert!(enabled_and_route(&app, "theirs.example").is_some());
        assert!(enabled_and_route(&app, "mine.example").is_some());
        assert_eq!(app.rules.base_revision.as_deref(), Some("rev-2"));
        let sent = fake.sent(IpcOperationName::MutationSubmit);
        assert!(!sent.is_empty(), "the result goes to the ordinary review");
        assert!(
            sent[0].to_string().contains("rev-2"),
            "built on the revision just read: {}",
            sent[0]
        );
    }

    #[test]
    fn picking_the_rules_in_force_turns_that_conflict_round() {
        let (mut app, fake) = clashing();
        answer(&mut app, &["1"]);
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("stays: In force"), "{shown}");
        answer(&mut app, &["y"]);
        drain(&mut app, &fake);
        assert_eq!(
            enabled_and_route(&app, "a.example"),
            Some((true, "primary".into())),
            "the other side's version stays"
        );
        assert!(
            enabled_and_route(&app, "b.example").is_none(),
            "the deletion still goes through"
        );
    }

    #[test]
    fn leaving_changes_nothing() {
        let (mut app, _) = clashing();
        answer(&mut app, &["n"]);
        assert!(matches!(app.rules.mode, Mode::List));
        assert_eq!(
            enabled_and_route(&app, "a.example"),
            Some((false, "secondary".into()))
        );
        assert!(enabled_and_route(&app, "theirs.example").is_none());
        assert_eq!(app.rules.base_revision, None);
        assert!(super::super::holds_unapplied(&app));
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("Nothing was merged"), "{shown}");
    }

    #[test]
    fn nothing_to_pick_goes_straight_on() {
        let fake = service(vec![rule("1", "domain", "a.example", "secondary")]);
        let mut app = on_rules(&fake);
        fake.answer(
            IpcOperationName::RulesList,
            json!({
                "rows": [
                    rule("1", "domain", "a.example", "secondary"),
                    rule("2", "domain", "theirs.example", "secondary"),
                ],
                "base-revision": "rev-3",
                "supported-rule-types": ["domain"]
            }),
        );
        super::super::rebase_edits(&mut app);
        drain(&mut app, &fake);
        assert!(
            !matches!(app.rules.mode, Mode::Merge(_)),
            "no edits, nothing to pick"
        );
        assert_eq!(app.rules.base_revision.as_deref(), Some("rev-3"));
        assert!(enabled_and_route(&app, "theirs.example").is_some());
    }

    #[test]
    fn the_plain_prompt_names_the_merge_keys() {
        let (app, _) = clashing();
        let prompt = crate::screens::screen(ScreenId::Rules)
            .plain_prompt(&app)
            .expect("a prompt");
        assert_eq!(prompt, super::super::text::MERGE_PLAIN_PROMPT);
    }
}

// ── The bound files against the rules in force ───────────────────────────────

mod file_merge {
    use nrr_shared::ipc::IpcOperationName;
    use nrr_shared::user_settings::{UserSettingsStore, USER_SETTINGS_FILE_NAME};
    use serde_json::{json, Value};

    use super::super::own_settings::path_text;
    use super::super::{Busy, Mode};
    use super::{answer, drain, on_rules, rule, screen_text, service};
    use crate::screens::ScreenId;
    use crate::state::AppState;
    use crate::testing::{FakeService, Scratch};

    const FILE_TEXT: &str = "--- Domains\nonly-file.example\nshared.example\n";

    /// The rules screen with a primary file bound beside the settings file.
    fn bound(dir: &Scratch, fake: &FakeService) -> AppState {
        let mut app = on_rules(fake);
        let file = dir.path().join(USER_SETTINGS_FILE_NAME);
        app.rules.settings_file = Some(file.clone());
        let primary = dir.path().join("rules_primary.txt");
        std::fs::write(&primary, FILE_TEXT).expect("file");
        UserSettingsStore::at(file)
            .update(|s| s.rules_files.primary = path_text(&primary))
            .expect("bind");
        app
    }

    fn entry(value: &str) -> Value {
        json!({
            "value": value, "type-slug": "domain", "route": "primary", "enabled": true,
            "action": "route", "comment": "", "origin": "file-only", "was-conflict": false
        })
    }

    fn side(route: &str) -> Value {
        json!({ "route": route, "enabled": true, "action": "route", "comment": "" })
    }

    fn preview(file_only: Vec<Value>, conflicts: Vec<Value>, merged: &str) -> Value {
        json!({ "result": {
            "policy": "union", "noop": false, "unresolved": conflicts.len(),
            "file-only": file_only, "service-only": [{
                "value": "only-service.example", "type-slug": "domain", "route": "secondary",
                "enabled": true, "action": "route", "comment": "", "origin": "service-only",
                "was-conflict": false
            }],
            "conflicts": conflicts, "merged-rules-json": merged
        } })
    }

    fn clash() -> Value {
        json!({
            "identity-key": "k1", "value": "shared.example", "type-slug": "domain",
            "file": side("primary"), "service": side("secondary"), "resolved": "unresolved"
        })
    }

    fn rules() -> FakeService {
        service(vec![
            rule("1", "domain", "shared.example", "secondary"),
            rule("2", "domain", "only-service.example", "secondary"),
        ])
    }

    #[test]
    fn the_files_text_goes_to_the_service_and_the_buckets_are_shown() {
        let dir = Scratch::new("file-merge-show");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        fake.answer(
            IpcOperationName::RulesMergePreview,
            preview(vec![entry("only-file.example")], vec![clash()], "{}"),
        );
        answer(&mut app, &["F"]);
        assert_eq!(app.rules.busy, Some(Busy::Previewing));
        drain(&mut app, &fake);
        let sent = fake.sent(IpcOperationName::RulesMergePreview);
        assert_eq!(sent[0]["primary-text"], FILE_TEXT, "{sent:?}");
        assert_eq!(sent[0]["secondary-text"], "");
        assert_eq!(sent[0]["policy"], "union");
        assert!(matches!(app.rules.mode, Mode::Merge(_)));
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("Merge file and app rules"), "{shown}");
        assert!(shown.contains("Only in the file (1)"), "{shown}");
        assert!(shown.contains("only-file.example"), "{shown}");
        assert!(shown.contains("Only in the app (1)"), "{shown}");
        assert!(shown.contains("only-service.example"), "{shown}");
        assert!(shown.contains("Conflicts (1)"), "{shown}");
        assert!(shown.contains("File: "), "{shown}");
        assert!(shown.contains("App: "), "{shown}");
        assert!(
            shown.contains("stays: File"),
            "the file is the default: {shown}"
        );
    }

    #[test]
    fn the_picks_go_back_and_the_merged_rules_go_to_the_review() {
        let dir = Scratch::new("file-merge-confirm");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        fake.answer(
            IpcOperationName::RulesMergePreview,
            preview(
                vec![entry("only-file.example")],
                vec![clash()],
                "{\"merged\":1}",
            ),
        );
        answer(&mut app, &["F"]);
        drain(&mut app, &fake);
        answer(&mut app, &["1", "y"]);
        drain(&mut app, &fake);
        let sent = fake.sent(IpcOperationName::RulesMergePreview);
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(
            sent[1]["resolutions"],
            json!([{ "identity-key": "k1", "side": "service" }])
        );
        let review = fake.sent(IpcOperationName::MutationSubmit);
        assert_eq!(review[0]["dry-run"], true, "{review:?}");
        assert_eq!(review[0]["payload"]["rules-json"], "{\"merged\":1}");
        // Pinned: the service dedupes on this spelling of the merged bytes.
        assert_eq!(
            review[0]["payload"]["content-hash"],
            "3e704b1a4e1e07560025ab7c8a9efc46cfd7a0203271f8ba00e83c335597f87e"
        );
    }

    /// The rows on screen are not what the merge applied: they are read back,
    /// and the bound files are written from that read, not from the old rows.
    #[test]
    fn once_applied_the_rules_are_read_back_and_the_files_follow_them() {
        let dir = Scratch::new("file-merge-applied");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        app.rules.reload_after_apply = true;
        super::super::finished(
            &mut app,
            super::super::apply::Finished::Applied {
                base: Some("rev-9".into()),
            },
        );
        drain(&mut app, &fake);
        assert_eq!(fake.sent(IpcOperationName::RulesList).len(), 2);
        assert!(!app.rules.reload_after_apply);
        let written = std::fs::read_to_string(dir.path().join("rules_primary.txt")).expect("file");
        assert!(!written.contains("only-file.example"), "{written}");
    }

    fn nothing_to_show() -> Value {
        json!({ "result": {
            "policy": "union", "noop": false, "unresolved": 0, "file-only": [],
            "service-only": [], "conflicts": [], "merged-rules-json": "{}"
        } })
    }

    #[test]
    fn a_file_spelled_otherwise_is_rewritten_when_there_is_nothing_to_merge() {
        let dir = Scratch::new("file-merge-converge");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        fake.answer(IpcOperationName::RulesMergePreview, nothing_to_show());
        answer(&mut app, &["F"]);
        drain(&mut app, &fake);
        assert!(matches!(app.rules.mode, Mode::List));
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("brought up to date"), "{shown}");
        let written = std::fs::read_to_string(dir.path().join("rules_primary.txt")).expect("file");
        assert!(!written.contains("only-file.example"), "{written}");
    }

    #[test]
    fn merged_rules_equal_to_the_screen_converge_even_with_buckets_listed() {
        let dir = Scratch::new("file-merge-equal");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        let own = super::super::apply::pending_from(&app.rules.table, false, None)
            .expect("book")
            .rules_json;
        fake.answer(
            IpcOperationName::RulesMergePreview,
            preview(vec![entry("only-file.example")], Vec::new(), &own),
        );
        answer(&mut app, &["F"]);
        drain(&mut app, &fake);
        assert!(matches!(app.rules.mode, Mode::List));
        let written = std::fs::read_to_string(dir.path().join("rules_primary.txt")).expect("file");
        assert!(!written.contains("only-file.example"), "{written}");
    }

    #[test]
    fn a_file_already_in_line_is_left_alone_and_the_note_says_they_match() {
        let dir = Scratch::new("file-merge-match");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        let primary = dir.path().join("rules_primary.txt");
        let (table, hint) = (&app.rules.table, &app.rules.file_hint);
        super::super::files::write_route(
            &primary,
            nrr_client_logic::Route::Primary,
            table,
            hint,
            "2026-01-01T00:00:00Z",
        )
        .expect("write");
        let before = std::fs::read_to_string(&primary).expect("file");
        fake.answer(IpcOperationName::RulesMergePreview, nothing_to_show());
        answer(&mut app, &["F"]);
        drain(&mut app, &fake);
        assert_eq!(std::fs::read_to_string(&primary).expect("file"), before);
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("already match"), "{shown}");
    }

    #[test]
    fn unapplied_edits_are_asked_about_first() {
        let dir = Scratch::new("file-merge-dirty");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        app.rules.table.rows.remove(0);
        answer(&mut app, &["F"]);
        assert!(fake.sent(IpcOperationName::RulesMergePreview).is_empty());
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("before comparing the files"), "{shown}");
    }

    #[test]
    fn without_a_linked_file_there_is_nothing_to_compare() {
        let fake = rules();
        let mut app = on_rules(&fake);
        answer(&mut app, &["F"]);
        assert!(fake.sent(IpcOperationName::RulesMergePreview).is_empty());
        assert!(app.rules.busy.is_none());
    }

    #[test]
    fn a_hand_edited_file_that_says_something_else_is_pointed_out_after_a_read() {
        let dir = Scratch::new("file-merge-drift");
        let fake = rules();
        let mut app = bound(&dir, &fake);
        let file = app.rules.settings_file.clone().expect("settings file");
        let primary = dir.path().join("rules_primary.txt");
        // This program wrote the file once; what is there now is the user's.
        super::super::own_settings::note_written(&file, std::slice::from_ref(&primary))
            .expect("note");
        std::fs::write(&primary, format!("{FILE_TEXT}another.example\n")).expect("edit");
        app.rules.note = None;
        super::super::file_merge::check_drift(&mut app);
        let shown = screen_text(&app, ScreenId::Rules);
        assert!(shown.contains("you can compare and merge them"), "{shown}");
        assert!(shown.contains("Press F"), "{shown}");
    }
}

/// `C` removes the exact rules a wildcard of the same route already covers,
/// as the window's cleanup does; a host the other route names stays.
#[test]
fn c_removes_the_rules_a_wildcard_of_the_same_route_covers() {
    use crossterm::event::KeyCode;
    let fake = service(vec![
        rule("1", "suffix-domain", "example.com", "secondary"),
        rule("2", "domain", "example.com", "secondary"),
        rule("3", "domain", "www.example.com", "secondary"),
        rule("4", "domain", "mail.example.com", "primary"),
    ]);
    let mut app = on_rules(&fake);
    let shown = screen_text(&app, ScreenId::Rules);
    assert!(shown.contains("C: Remove covered rules (2)"), "{shown}");

    press_key(&mut app, KeyCode::Char('C'));
    let asked = screen_text(&app, ScreenId::Rules);
    assert!(
        asked.contains("www.example.com \u{2014} already covered by *.example.com"),
        "{asked}"
    );
    // The removal is listed first but never preselected.
    press_key(&mut app, KeyCode::Up);
    press_key(&mut app, KeyCode::Enter);
    let left: Vec<&str> = app
        .rules
        .table
        .rows
        .iter()
        .map(|r| r.rule.id.as_str())
        .collect();
    assert_eq!(left, ["R-0001", "R-0004"]);
    let note = app
        .rules
        .note
        .as_ref()
        .map(|n| n.text(&texts_en()))
        .unwrap_or_default();
    assert!(
        note.starts_with("2 rules removed as already covered"),
        "{note}"
    );
    assert!(!screen_text(&app, ScreenId::Rules).contains("Remove covered rules"));

    answer(&mut app, &["C"]);
    assert!(matches!(app.rules.mode, Mode::List));
    let note = app.rules.note.as_ref().map(|n| n.text(&texts_en()));
    assert_eq!(note.as_deref(), Some("Nothing is covered twice right now."));
}

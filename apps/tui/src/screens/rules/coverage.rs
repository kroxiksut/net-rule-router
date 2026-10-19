//! What a rule by program path covers for the user (the GUI's count under the
//! rule window's value): asked of the service once the value has rested,
//! never per keystroke, and kept with the value and route it answers.

use std::time::{Duration, Instant};

use nrr_client_logic::rule_value_class::app_value_form;
use nrr_client_logic::rules_table::RuleType;
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AppPathCoverageRequest, AppPathCoverageResponse, APP_PATH_COVERAGE_FOUND,
    APP_PATH_COVERAGE_MISSING, APP_PATH_COVERAGE_REFUSED, APP_PATH_COVERAGE_UNSUPPORTED,
};
use nrr_shared::platform_profile::PlatformProfile;

use super::form::Form;
use super::{text, Mode};
use crate::backend::{Job, Reply};
use crate::i18n::Texts;
use crate::state::AppState;
use crate::view::ViewLine;

/// Quiet after the last change before the service is asked.
pub const PAUSE: Duration = Duration::from_millis(400);

/// The form's count and what waits for it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// The answer, with the `value|route` it is for.
    answer: Option<(String, AppPathCoverageResponse)>,
    /// The `value|route` waiting for a pause, and when it last changed.
    wanted: Option<(String, Instant)>,
    /// A timer is out; there is one at a time.
    armed: bool,
}

fn is_path_form(form: &str) -> bool {
    matches!(form, "file" | "folder" | "folder-tree" | "file-or-folder")
}

/// What the count is asked for: an application rule written as a path.
fn key_of(form: &Form) -> Option<String> {
    if form.rule_type != RuleType::Application {
        return None;
    }
    let os = PlatformProfile::current().os;
    is_path_form(app_value_form(&form.value, os))
        .then(|| format!("{}|{}", form.value.trim(), form.route.as_str()))
}

/// After a change of the form: the count is asked once the value has rested.
pub fn schedule(app: &mut AppState, form: &mut Form) {
    let Some(key) = key_of(form) else {
        form.coverage.wanted = None;
        return;
    };
    let answered = form
        .coverage
        .answer
        .as_ref()
        .is_some_and(|(k, _)| *k == key);
    let waiting = form
        .coverage
        .wanted
        .as_ref()
        .is_some_and(|(k, _)| *k == key);
    if answered || waiting {
        return;
    }
    form.coverage.wanted = Some((key, Instant::now()));
    if !form.coverage.armed {
        form.coverage.armed = true;
        app.outbox.push_after(PAUSE, timer());
    }
}

fn timer() -> Job {
    Box::new(|_client: &dyn IpcClient| Reply::new(fire))
}

/// The pause is over: ask, or wait again when the value changed meanwhile.
fn fire(app: &mut AppState) {
    let connected = app.link.is_connected();
    let Mode::Form(form) = &mut app.rules.mode else {
        return;
    };
    form.coverage.armed = false;
    let Some((key, at)) = form.coverage.wanted.clone() else {
        return;
    };
    let rested = at.elapsed();
    if rested < PAUSE {
        form.coverage.armed = true;
        app.outbox.push_after(PAUSE - rested, timer());
        return;
    }
    form.coverage.wanted = None;
    if connected {
        let request = AppPathCoverageRequest {
            value: form.value.trim().to_owned(),
            route: form.route.as_str().to_owned(),
        };
        app.outbox.push(ask(key, request));
    }
}

fn ask(key: String, request: AppPathCoverageRequest) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let op = IpcOperationName::RulesAppPathCoverageGet;
        let answer = serde_json::to_value(&request)
            .ok()
            .and_then(|payload| client.call(op, payload, ipc_operation_timeout(op)).ok())
            .and_then(|v| serde_json::from_value::<AppPathCoverageResponse>(v).ok());
        Reply::new(move |app| answered(app, key, answer))
    })
}

/// An answer for a value the form no longer holds is dropped; a failed ask
/// shows nothing rather than a guess.
fn answered(app: &mut AppState, key: String, answer: Option<AppPathCoverageResponse>) {
    let Mode::Form(form) = &mut app.rules.mode else {
        return;
    };
    if key_of(form).as_deref() != Some(key.as_str()) {
        return;
    }
    if let Some(answer) = answer {
        form.coverage.answer = Some((key, answer));
    }
}

/// The answer for what the form holds now.
pub fn current(form: &Form) -> Option<&AppPathCoverageResponse> {
    let key = key_of(form)?;
    form.coverage
        .answer
        .as_ref()
        .filter(|(k, _)| *k == key)
        .map(|(_, answer)| answer)
}

/// The service refuses the path (another user's folder): the form cannot be
/// saved, as the GUI's OK stays off.
pub fn refused(form: &Form) -> bool {
    current(form).is_some_and(|a| a.outcome == APP_PATH_COVERAGE_REFUSED)
}

/// The lines under the value: the count, the service's refusal, the warnings.
/// `verdict_key` is the launcher-side verdict's key, not repeated here.
pub fn lines(form: &Form, verdict_key: Option<&str>, texts: &Texts) -> Vec<ViewLine> {
    if key_of(form).is_none() {
        return Vec::new();
    }
    let indent = |line: String| ViewLine::text(format!("     {line}"));
    let Some(answer) = current(form) else {
        return vec![indent(texts.get(text::PATH_COUNTING))];
    };
    let mut out = Vec::new();
    let count = answer.programs.to_string();
    let main = match answer.outcome.as_str() {
        APP_PATH_COVERAGE_FOUND if answer.truncated => {
            Some(texts.fill(text::PATH_COUNT_MORE, &[("count", count)]))
        }
        APP_PATH_COVERAGE_FOUND => Some(texts.fill(text::PATH_COUNT, &[("count", count)])),
        APP_PATH_COVERAGE_MISSING => Some(texts.get(text::PATH_MISSING)),
        APP_PATH_COVERAGE_UNSUPPORTED => Some(texts.get(text::PATH_UNSUPPORTED)),
        _ => None,
    };
    if let Some(mut main) = main {
        let from_profile = form.value.trim_start().starts_with(['%', '~']);
        if from_profile && !answer.place.is_empty() {
            main.push(' ');
            main.push_str(&texts.fill(text::PATH_PLACE, &[("place", display_text(&answer.place))]));
        }
        out.push(indent(main));
    }
    if answer.outcome == APP_PATH_COVERAGE_REFUSED {
        if verdict_key != Some(answer.refusal_key.as_str()) {
            out.push(indent(texts.dynamic(
                &answer.refusal_key,
                &texts.get(text::VALIDATION_ERROR),
            )));
        }
        return out;
    }
    if answer.anyone_can_write {
        out.push(indent(texts.get(text::PATH_ANYONE_CAN_WRITE)));
    }
    if !answer.warning_key.is_empty() && verdict_key != Some(answer.warning_key.as_str()) {
        out.push(indent(texts.dynamic(
            &answer.warning_key,
            &texts.get(text::VALIDATION_WARNING),
        )));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::backend::BackendEvent;
    use crate::link::Link;
    use crate::screens::{screen, ScreenId};
    use crate::testing::{app_at, texts_en, FakeService, Fixture};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use nrr_ipc_client::ConnectionStatus;
    use serde_json::json;

    const OP: IpcOperationName = IpcOperationName::RulesAppPathCoverageGet;

    fn folder() -> &'static str {
        match PlatformProfile::current().os {
            "linux" | "macos" => "/opt/tool/",
            _ => r"C:\Tools\",
        }
    }

    fn run(app: &mut AppState, fake: &FakeService, job: Job) {
        let reply = job(fake as &dyn IpcClient);
        app.apply(BackendEvent::Reply(reply), &texts_en(), Instant::now());
    }

    fn with_form(app: &mut AppState) {
        let mut form = Form::add();
        form.rule_type = RuleType::Application;
        app.rules.mode = Mode::Form(Box::new(form));
    }

    fn form_of(app: &AppState) -> &Form {
        match &app.rules.mode {
            Mode::Form(form) => form,
            other => panic!("the form is open: {other:?}"),
        }
    }

    fn rest(app: &mut AppState) {
        if let Mode::Form(form) = &mut app.rules.mode {
            if let Some((_, at)) = form.coverage.wanted.as_mut() {
                *at = at.checked_sub(PAUSE).unwrap_or(*at);
            }
        }
    }

    /// A burst of keystrokes asks the service once, after the pause, and the
    /// count shows under the value.
    #[test]
    fn typing_a_path_asks_once_after_a_pause_and_shows_the_count() {
        let fake = FakeService::new(ConnectionStatus::Connected);
        fake.answer(
            OP,
            json!({ "form": "folder", "outcome": "found", "programs": 3, "place": folder() }),
        );
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        app.open(ScreenId::Rules);
        // What opening the screen asked for is not this test's.
        let _ = app.outbox.take();
        let _ = app.outbox.take_delayed();
        with_form(&mut app);
        for c in folder().chars() {
            screen(ScreenId::Rules).on_key(
                &mut app,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            );
        }
        let timers = app.outbox.take_delayed();
        assert_eq!(timers.len(), 1, "one timer for the whole burst");
        assert!(fake.sent(OP).is_empty(), "nothing asked while typing");
        rest(&mut app);
        for (_, timer) in timers {
            run(&mut app, &fake, timer);
        }
        for job in app.outbox.take() {
            run(&mut app, &fake, job);
        }
        let sent = fake.sent(OP);
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0]["value"], folder());
        let form = form_of(&app);
        assert_eq!(current(form).map(|a| a.programs), Some(3));
        let shown: Vec<String> = lines(form, None, &texts_en())
            .iter()
            .map(ViewLine::plain_text)
            .collect();
        assert!(shown.iter().any(|l| l.contains('3')), "{shown:?}");
    }

    /// Another user's folder: the service's refusal shows and the form does
    /// not save.
    #[test]
    fn a_refused_path_is_shown_and_not_saved() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        app.open(ScreenId::Rules);
        let mut form = Form::add();
        form.rule_type = RuleType::Application;
        form.value = folder().to_owned();
        let key = key_of(&form).expect("a path");
        form.coverage.answer = Some((
            key,
            AppPathCoverageResponse {
                form: "folder".into(),
                outcome: APP_PATH_COVERAGE_REFUSED.into(),
                refusal_key: text::PATH_UNSUPPORTED.id.to_owned(),
                ..AppPathCoverageResponse::default()
            },
        ));
        assert!(refused(&form));
        let before = app.rules.table.rows.len();
        assert_eq!(
            form.save(&mut app.rules.table),
            super::super::form::Saved::Refused
        );
        assert_eq!(app.rules.table.rows.len(), before);
        let shown: Vec<String> = lines(&form, None, &texts_en())
            .iter()
            .map(ViewLine::plain_text)
            .collect();
        assert_eq!(shown.len(), 1, "{shown:?}");
    }

    /// Ctrl+F gives a folder rule its subfolders and takes them away, the
    /// rule flags kept where they stand.
    #[test]
    fn the_subfolders_switch_adds_and_removes_the_star() {
        let mut form = Form::add();
        form.rule_type = RuleType::Application;
        form.value = format!("{} +children", folder());
        assert!(form.names_folder());
        assert!(form.toggle_subfolders());
        assert!(form.with_subfolders());
        assert_eq!(form.value, format!("{}* +children", folder()));
        assert!(form.toggle_subfolders());
        assert_eq!(form.value, format!("{} +children", folder()));
        form.value = "tool.exe".into();
        assert!(!form.toggle_subfolders(), "a name has no subfolders");
    }
}

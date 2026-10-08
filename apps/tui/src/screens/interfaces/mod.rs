//! Interfaces and routes: every adapter the service sees, which one carries
//! the main and which the additional connection, and the role changes — one
//! role per adapter, the product's own tunnel never offered, an adapter with no
//! way out only after the GUI's warning.

pub mod keys;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::adapters::{display_name, held_other_role, role_hint, unroutable_reason};
use nrr_client_logic::Route;
use nrr_shared::ipc_payloads::InterfaceRowDto;

use self::keys as k;
use super::binding::{
    adapters, adapters_read, availability, binding, error_text, find, hint_text, holds,
    kill_switch_on, kind_text, positional, role_label, role_write, row_key, rows_are_live,
    unroutable_lines, RoleChange, WriteFailure,
};
use super::choice;
use super::Screen;
use crate::i18n::{Key, Texts};
use crate::keys as common;
use crate::state::AppState;
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};

pub struct InterfacesScreen;

#[derive(Debug, Default)]
pub struct InterfacesState {
    /// The chosen row of the adapter list.
    cursor: usize,
    show_bluetooth: bool,
    question: Option<Question>,
    /// The highlighted answer of the question.
    answer: usize,
    busy: Option<Busy>,
    outcome: Option<Outcome>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Question {
    /// Line mode's first step: which adapter.
    Adapter,
    Role {
        key: String,
    },
    /// The adapter has no way out; the GUI asks before binding it.
    Unroutable {
        key: String,
        change: RoleChange,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Busy {
    Saving,
    Checking,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Changed(RoleChange),
    Failed(WriteFailure),
    Exclusive,
    NeedsService,
    Placeholder,
    ProbeDone,
    ProbeFailed(String),
    Cancelled,
    /// The setup handed over; with the number of rules it imported, if any.
    SetupFinished(Option<usize>),
    /// The setup's protection answers did not reach the service.
    ProtectionFailed(WriteFailure),
    NotUnderstood(String),
}

/// What a role question's answers do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoleAnswer {
    Toggle(Route),
    Cancel,
}

const ROLE_ANSWERS: [RoleAnswer; 3] = [
    RoleAnswer::Toggle(Route::Primary),
    RoleAnswer::Toggle(Route::Secondary),
    RoleAnswer::Cancel,
];

/// The setup hands over here when it is done, as the GUI's first-run
/// contract opens this section first.
pub fn setup_finished(app: &mut AppState, imported_rules: Option<usize>) {
    app.interfaces.outcome = Some(Outcome::SetupFinished(imported_rules));
    app.interfaces.question = None;
}

pub fn protection_failed(app: &mut AppState, failure: WriteFailure) {
    app.interfaces.outcome = Some(Outcome::ProtectionFailed(failure));
}

fn rows(app: &AppState) -> Vec<InterfaceRowDto> {
    adapters(app, app.interfaces.show_bluetooth)
}

fn selected(app: &AppState) -> Option<InterfaceRowDto> {
    let rows = rows(app);
    let last = rows.len().checked_sub(1)?;
    rows.into_iter().nth(app.interfaces.cursor.min(last))
}

/// Give `key`'s adapter `route`, or take it away when it already holds it.
fn toggle(app: &mut AppState, key: &str, route: Route) {
    let rows = rows(app);
    let Some(row) = find(&rows, key) else {
        return;
    };
    let state = &app.interfaces;
    if state.busy == Some(Busy::Saving) {
        return;
    }
    let outcome = if !app.link.is_connected() {
        Some(Outcome::NeedsService)
    } else if !rows_are_live(app) {
        Some(Outcome::Placeholder)
    } else if holds(row, route) {
        start(app, RoleChange::Unassign { route });
        None
    } else if held_other_role(row, route).is_some() {
        Some(Outcome::Exclusive)
    } else if unroutable_reason(row).is_some() {
        app.interfaces.question = Some(Question::Unroutable {
            key: key.to_string(),
            change: RoleChange::assign(row, route),
        });
        app.interfaces.answer = 0;
        None
    } else {
        start(app, RoleChange::assign(row, route));
        None
    };
    if outcome.is_some() {
        app.interfaces.outcome = outcome;
    }
}

fn start(app: &mut AppState, change: RoleChange) {
    app.interfaces.busy = Some(Busy::Saving);
    app.interfaces.outcome = None;
    app.interfaces.question = None;
    app.outbox.push(role_write(change, |app, change, result| {
        let state = &mut app.interfaces;
        state.busy = None;
        state.outcome = Some(match result {
            Ok(()) => Outcome::Changed(change.clone()),
            Err(failure) => Outcome::Failed(failure),
        });
    }));
}

fn probe(app: &mut AppState) {
    if app.interfaces.busy.is_some() {
        return;
    }
    app.interfaces.busy = Some(Busy::Checking);
    app.interfaces.outcome = None;
    app.outbox.push(adapters_read(true, |app, result| {
        app.interfaces.busy = None;
        app.interfaces.outcome = Some(match result {
            Ok(()) => Outcome::ProbeDone,
            Err(code) => Outcome::ProbeFailed(code),
        });
    }));
}

fn refresh(app: &mut AppState) {
    // A plain re-read says nothing on success: arriving here is not a report.
    app.outbox.push(adapters_read(false, |_, _| {}));
}

fn answer_count(app: &AppState, question: &Question) -> usize {
    match question {
        Question::Adapter => rows(app).len(),
        Question::Role { .. } => ROLE_ANSWERS.len(),
        Question::Unroutable { .. } => 2,
    }
}

fn answer(app: &mut AppState, index: usize) {
    let Some(question) = app.interfaces.question.clone() else {
        return;
    };
    match question {
        Question::Adapter => {
            if let Some(row) = rows(app).get(index) {
                app.interfaces.cursor = index;
                app.interfaces.question = Some(Question::Role { key: row_key(row) });
                app.interfaces.answer = 0;
            }
        }
        Question::Role { key } => {
            app.interfaces.question = None;
            match ROLE_ANSWERS.get(index) {
                Some(RoleAnswer::Toggle(route)) => toggle(app, &key, *route),
                _ => cancel(app),
            }
        }
        Question::Unroutable { change, .. } => {
            if index == 0 {
                start(app, change);
            } else {
                cancel(app);
            }
        }
    }
}

fn cancel(app: &mut AppState) {
    app.interfaces.question = None;
    app.interfaces.outcome = Some(Outcome::Cancelled);
}

impl Screen for InterfacesScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        ScreenView {
            title: texts.get(common::SCREEN_INTERFACES),
            panels: panels(app, texts),
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            k::HELP_SELECT,
            k::HELP_PRIMARY,
            k::HELP_SECONDARY,
            k::HELP_CHECK,
            k::HELP_REFRESH,
            k::HELP_BLUETOOTH,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            k::PLAIN_ASSIGN,
            k::HELP_CHECK,
            k::HELP_REFRESH,
            k::HELP_BLUETOOTH,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        if app.link.is_connected() {
            refresh(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        app.interfaces.question.is_some()
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if let Some(question) = app.interfaces.question.clone() {
            let count = answer_count(app, &question);
            if let Some(next) = choice::moved(app.interfaces.answer, count, key.code) {
                app.interfaces.answer = next;
                return true;
            }
            return match key.code {
                KeyCode::Enter => {
                    answer(app, app.interfaces.answer);
                    true
                }
                KeyCode::Esc => {
                    cancel(app);
                    true
                }
                _ => false,
            };
        }
        let count = rows(app).len();
        if let Some(next) = choice::moved(app.interfaces.cursor.min(count), count, key.code) {
            app.interfaces.cursor = next;
            return true;
        }
        let KeyCode::Char(c) = key.code else {
            return false;
        };
        match c {
            'p' | 's' => {
                let route = if c == 'p' {
                    Route::Primary
                } else {
                    Route::Secondary
                };
                if let Some(row) = selected(app) {
                    toggle(app, &row_key(&row), route);
                }
            }
            'x' => probe(app),
            'r' => refresh(app),
            'b' => app.interfaces.show_bluetooth = !app.interfaces.show_bluetooth,
            _ => return false,
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if let Some(question) = app.interfaces.question.clone() {
            if line.is_empty() {
                cancel(app);
            } else if let Some(index) = choice::pick(line, answer_count(app, &question)) {
                answer(app, index);
            } else {
                app.interfaces.outcome = Some(Outcome::NotUnderstood(line.to_string()));
            }
            return true;
        }
        match line {
            "a" => {
                app.interfaces.question = Some(Question::Adapter);
                app.interfaces.answer = 0;
            }
            "x" => probe(app),
            "r" => refresh(app),
            "b" => app.interfaces.show_bluetooth = !app.interfaces.show_bluetooth,
            _ => return false,
        }
        true
    }

    fn plain_prompt(&self, app: &AppState) -> Option<Key> {
        app.interfaces.question.as_ref().map(|_| k::CHOICE_PROMPT)
    }
}

fn panels(app: &AppState, texts: &Texts) -> Vec<Panel> {
    let panel = |title: String, lines: Vec<ViewLine>| Panel {
        title,
        lines,
        feed: false,
    };
    if app.snapshot.is_none() {
        return vec![panel(
            texts.get(k::ADAPTERS_TITLE),
            vec![ViewLine::text(texts.get(common::NO_DATA))],
        )];
    }
    let rows = rows(app);
    let mut panels = Vec::new();
    if !rows_are_live(app) {
        panels.push(panel(
            texts.get(k::PLACEHOLDER_TITLE),
            vec![ViewLine::text(texts.get(k::PLACEHOLDER_BODY))],
        ));
    }
    let fail_closed = app
        .snapshot
        .as_ref()
        .and_then(|s| s.adapters.secondary.as_ref())
        .is_some_and(|s| s.fail_closed_active);
    let secondary_absent = binding(app, Route::Secondary).is_some()
        && !rows.iter().any(|row| holds(row, Route::Secondary));
    if fail_closed {
        panels.push(panel(
            texts.get(k::FAIL_CLOSED_TITLE),
            vec![ViewLine::text(texts.get(k::FAIL_CLOSED_BODY))],
        ));
    } else if secondary_absent {
        panels.push(panel(
            texts.get(k::ABSENT_TITLE),
            vec![ViewLine::text(texts.get(k::ABSENT_BODY))],
        ));
    }
    panels.push(panel(
        texts.get(common::ROLES_TITLE),
        role_lines(app, &rows, texts),
    ));
    if let Some(question) = &app.interfaces.question {
        let (title, lines) = question_lines(app, question, &rows, texts);
        panels.push(panel(title, lines));
    } else if let Some(line) = result_line(app, texts) {
        panels.push(panel(texts.get(k::RESULT_TITLE), vec![line]));
    }
    panels.push(panel(
        texts.get(k::ADAPTERS_TITLE),
        adapter_lines(app, &rows, texts),
    ));
    if let Some(row) = rows.get(app.interfaces.cursor.min(rows.len().saturating_sub(1))) {
        panels.push(panel(
            texts.fill(k::DETAILS_TITLE, &[("name", display_name(row))]),
            detail_lines(row, texts),
        ));
    }
    panels
}

fn role_lines(app: &AppState, rows: &[InterfaceRowDto], texts: &Texts) -> Vec<ViewLine> {
    let mut lines = vec![ViewLine::text(texts.get(k::ROLE_EXPLANATION))];
    for route in Route::ALL {
        let mut segments = vec![Segment::strong(format!(
            "{}: ",
            texts.get(role_label(route))
        ))];
        if let Some(row) = rows.iter().find(|row| holds(row, route)) {
            segments.push(Segment::plain(format!("{} — ", display_name(row))));
            segments.push(availability(row, texts));
        } else if let Some(bound) = binding(app, route) {
            segments.push(Segment::plain(format!("{} — ", bound.display_name)));
            segments.push(Segment::state(texts.get(k::REMEMBERED), StateTone::Caution));
        } else {
            segments.push(Segment::state(
                texts.get(common::NOT_SELECTED),
                StateTone::Caution,
            ));
        }
        lines.push(ViewLine::new(segments));
    }
    if !app.link.is_connected() {
        lines.push(ViewLine::text(texts.get(common::STALE)));
    }
    lines
}

fn adapter_lines(app: &AppState, rows: &[InterfaceRowDto], texts: &Texts) -> Vec<ViewLine> {
    if rows.is_empty() {
        return vec![ViewLine::text(texts.get(k::NO_ADAPTERS))];
    }
    let cursor = app.interfaces.cursor.min(rows.len() - 1);
    rows.iter()
        .enumerate()
        .map(|(i, row)| {
            let marker = if i == cursor { ">" } else { " " };
            let head = format!("{marker} {}. {}", i + 1, display_name(row));
            let mut segments = vec![if i == cursor {
                Segment::strong(head)
            } else {
                Segment::plain(head)
            }];
            if !row.kind.is_empty() {
                segments.push(Segment::plain(format!(" — {}", kind_text(row, texts))));
            }
            segments.push(Segment::plain(" — "));
            segments.push(availability(row, texts));
            if let Some(route) = Route::ALL.into_iter().find(|r| holds(row, *r)) {
                segments.push(Segment::strong(format!(
                    " — {}",
                    texts.get(role_label(route))
                )));
            }
            ViewLine::new(segments)
        })
        .collect()
}

fn detail_lines(row: &InterfaceRowDto, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    let mut what = Vec::new();
    if !row.kind.is_empty() {
        what.push(kind_text(row, texts));
    }
    if let Some(hint) = role_hint(row) {
        what.push(hint_text(hint.as_str(), texts));
    }
    if !what.is_empty() {
        lines.push(ViewLine::text(what.join(" · ")));
    }
    let mut device = Vec::new();
    if !row.interface_description.is_empty() && row.interface_description != row.name {
        device.push(row.interface_description.clone());
    }
    if let Some(tech) = row.device_technology.as_deref().filter(|t| !t.is_empty()) {
        device.push(texts.dynamic(&format!("interfaces.device-technology.{tech}"), tech));
    }
    if !device.is_empty() {
        lines.push(ViewLine::text(device.join(" · ")));
    }
    let kind = if row.kind.is_empty() {
        texts.dynamic(
            &format!("interfaces.type.{}", row.interface_type.to_lowercase()),
            &row.interface_type,
        )
    } else {
        kind_text(row, texts)
    };
    lines.push(ViewLine::text(positional(
        &texts.get(k::ROW_SUMMARY),
        &[&kind, &row.local_ip, &row.gateway],
    )));
    let default_route = texts.get(if row.has_default_route { k::YES } else { k::NO });
    lines.push(ViewLine::text(positional(
        &texts.get(k::ROW_SUMMARY_2),
        &[&row.dns_servers, &default_route],
    )));
    let facts = &row.observed_facts;
    let assessment = &row.derived_assessment;
    let mut seen = Vec::new();
    if !facts.connectivity_state.is_empty() {
        seen.push(texts.dynamic(
            &format!("interfaces.connectivity.{}", facts.connectivity_state),
            &facts.connectivity_state,
        ));
    }
    match facts.external_ip.as_deref().filter(|ip| !ip.is_empty()) {
        Some(ip) => seen.push(format!("{} {ip}", texts.get(k::EXTERNAL_PREFIX))),
        None if !facts.external_ip_status.is_empty() => seen.push(texts.dynamic(
            &format!("interfaces.external-ip.{}", facts.external_ip_status),
            &facts.external_ip_status,
        )),
        None => {}
    }
    if !assessment.classification.is_empty() {
        let slug = assessment
            .classification
            .to_lowercase()
            .replace([' ', '_'], "-");
        seen.push(format!(
            "{} {}%",
            texts.dynamic(
                &format!("interfaces.classification.{slug}"),
                &assessment.classification
            ),
            assessment.confidence_percent
        ));
    }
    if !seen.is_empty() {
        lines.push(ViewLine::text(seen.join(" • ")));
    }
    let class = &row.recommendation.class;
    if !class.is_empty() {
        lines.push(ViewLine::text(
            texts.dynamic(&format!("interfaces.recommendation.{class}"), class),
        ));
    }
    if let Some(reason) = unroutable_reason(row) {
        let slug = reason.as_str();
        lines.push(ViewLine::text(texts.dynamic(
            &format!("dialog.unroutable-secondary.reason-{slug}"),
            slug,
        )));
    }
    if row.selected_role.is_some() {
        lines.push(ViewLine::text(texts.get(k::EXCLUSIVE_NOTE)));
    }
    lines
}

fn question_lines(
    app: &AppState,
    question: &Question,
    rows: &[InterfaceRowDto],
    texts: &Texts,
) -> (String, Vec<ViewLine>) {
    let cursor = Some(app.interfaces.answer);
    let (title, mut lines, answers) = match question {
        Question::Adapter => (
            texts.get(k::PICK_ADAPTER),
            Vec::new(),
            rows.iter().map(display_name).collect::<Vec<_>>(),
        ),
        Question::Role { key } => {
            let row = find(rows, key);
            let name = row.map(display_name).unwrap_or_default();
            let answers = ROLE_ANSWERS
                .iter()
                .map(|answer| match answer {
                    RoleAnswer::Toggle(route) if row.is_some_and(|r| holds(r, *route)) => texts
                        .get(match route {
                            Route::Primary => k::UNASSIGN_PRIMARY,
                            Route::Secondary => k::UNASSIGN_SECONDARY,
                        }),
                    RoleAnswer::Toggle(route) => texts.get(role_label(*route)),
                    RoleAnswer::Cancel => texts.get(k::CANCEL),
                })
                .collect();
            (
                texts.fill(k::PICK_ROLE, &[("name", name)]),
                Vec::new(),
                answers,
            )
        }
        Question::Unroutable { key, change } => {
            let lines = find(rows, key)
                .map(|row| unroutable_lines(row, change.route(), kill_switch_on(app), texts))
                .unwrap_or_default();
            (
                texts.get(k::UNROUTABLE_TITLE),
                lines,
                vec![texts.get(k::UNROUTABLE_CONFIRM), texts.get(k::CANCEL)],
            )
        }
    };
    lines.extend(choice::lines(&answers, cursor));
    lines.push(ViewLine::text(texts.get(k::CHOICE_HINT)));
    (title, lines)
}

fn result_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let state = &app.interfaces;
    if let Some(busy) = state.busy {
        return Some(ViewLine::text(texts.get(match busy {
            Busy::Saving => k::SAVING,
            Busy::Checking => k::PROBE_BUSY,
        })));
    }
    let text = match state.outcome.as_ref()? {
        Outcome::Changed(change) => change.done_text(texts),
        Outcome::Failed(failure) => {
            return Some(ViewLine::new(vec![
                Segment::state(texts.get(common::LEVEL_WARNING), StateTone::Caution),
                Segment::plain(format!(": {}", failure.text(k::BINDING_FAILED, texts))),
            ]));
        }
        Outcome::Exclusive => texts.get(k::EXCLUSIVE_NOTE),
        Outcome::NeedsService => texts.get(k::NEEDS_SERVICE),
        Outcome::Placeholder => texts.get(k::PLACEHOLDER_BODY),
        Outcome::ProbeDone => texts.get(k::PROBE_DONE),
        Outcome::ProbeFailed(code) => {
            format!("{}{}", texts.get(k::PROBE_FAILED), error_text(code, texts))
        }
        Outcome::Cancelled => texts.get(k::CANCELLED),
        Outcome::SetupFinished(None) => texts.get(k::SETUP_FINISHED),
        Outcome::SetupFinished(Some(count)) => format!(
            "{} {}",
            texts.fill(k::IMPORT_DONE, &[("count", count.to_string())]),
            texts.get(k::SETUP_FINISHED)
        ),
        Outcome::ProtectionFailed(failure) => {
            failure.text(super::wizard::keys::PROTECTION_FAILED, texts)
        }
        Outcome::NotUnderstood(input) => texts.fill(common::PLAIN_UNKNOWN, &[("input", input)]),
    };
    Some(ViewLine::text(text))
}

#[cfg(test)]
mod tests;

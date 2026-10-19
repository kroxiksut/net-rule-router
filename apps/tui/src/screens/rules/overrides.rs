//! Rules applied despite the protection of system programs and folders: the
//! mark in the list with the term left, the filter by it, and `P` on a rule —
//! confirm one that asks (`+override`), or take a confirmation back. The
//! confirmation shows what the service says the rule would take, asks for the
//! rule's value typed in full and a term, as the window's does. Where the
//! service asks an administrator's password, this terminal shows the prompt.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::rules_table::{override_remaining, rule_override_key, RuleRow};
use nrr_domain::rule_value_validation::OVERRIDE_REQUESTED_KEY;
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    OverrideTerm, RuleOverrideDto, RuleOverrideGrantRequest, RuleOverrideGrantResponse,
    RuleOverridePreviewRequest, RuleOverridePreviewResponse, RuleOverrideRevokeRequest,
    RuleOverrideRevokeResponse, RULE_OVERRIDE_GRANTED, RULE_OVERRIDE_READY,
};
use nrr_shared::platform_profile::PlatformProfile;

use super::apply::Failure;
use super::table::Row;
use super::{text, Mode, Note};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::suggestions::{call, CallError};
use crate::state::{AppState, Effect, NoticeLevel};
use crate::view::{Segment, StateTone, ViewLine};

/// The rule a confirmation is for, waiting on the service's answer or shown.
#[derive(Debug)]
pub struct Confirm {
    pub preview: RuleOverridePreviewResponse,
    pub typed: String,
    /// Index into [`OverrideTerm::ALL`].
    pub term: usize,
    pub sending: bool,
    pub failure: Option<Failure>,
}

impl Confirm {
    fn ready(&self) -> bool {
        self.preview.status == RULE_OVERRIDE_READY || self.preview.status == RULE_OVERRIDE_GRANTED
    }

    fn term(&self) -> OverrideTerm {
        OverrideTerm::ALL
            .get(self.term)
            .copied()
            .unwrap_or_default()
    }

    /// The value typed names the rule, as the service compares them.
    fn typed_matches(&self) -> bool {
        let os = PlatformProfile::current().os;
        let key = |value: &str| rule_override_key("application", value, &self.preview.route, os);
        !self.typed.trim().is_empty() && key(&self.typed) == key(&self.preview.value)
    }
}

/// The key of a row as the confirmations are kept.
pub fn key_of(rule: &RuleRow) -> String {
    rule_override_key(
        &rule.rule_type.canonical_slug(),
        &rule.match_value,
        rule.target_route.as_str(),
        PlatformProfile::current().os,
    )
}

/// The snapshot came in: the confirmations it lists mark the rows.
pub fn on_snapshot(app: &mut AppState) {
    let os = PlatformProfile::current().os;
    let by_key: HashMap<String, RuleOverrideDto> = app
        .snapshot
        .as_ref()
        .map(|snapshot| {
            snapshot
                .rule_overrides
                .iter()
                .map(|grant| {
                    (
                        rule_override_key("application", &grant.value, &grant.route, os),
                        grant.clone(),
                    )
                })
                .filter(|(key, _)| !key.is_empty())
                .collect()
        })
        .unwrap_or_default();
    app.rules.table.overridden = by_key.keys().cloned().collect();
    app.rules.overrides = by_key;
}

/// Wall-clock UTC milliseconds, as the service's deadlines are.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The term left, in words.
pub fn left_text(until_ms: Option<i64>, texts: &Texts) -> String {
    let (kind, count) = override_remaining(until_ms, now_ms());
    let fallback = match kind {
        "minutes" => "{count} min left",
        "hours" => "{count} h left",
        "days" => "{count} d left",
        "ended" => "ended",
        _ => "until revoked",
    };
    texts
        .dynamic(&format!("rules.override.left.{kind}"), fallback)
        .replace("{count}", &count.to_string())
}

/// The mark a row carries: confirmed with its term, or waiting for one.
pub fn mark(app: &AppState, row: &Row, texts: &Texts) -> Option<Segment> {
    if let Some(grant) = app.rules.overrides.get(&key_of(&row.rule)) {
        let word = texts.fill(
            text::OVERRIDE_GRANTED_MARK,
            &[("left", left_text(grant.until_ms, texts))],
        );
        return Some(Segment::state(word, StateTone::Caution));
    }
    asks(row).then(|| Segment::state(texts.get(text::OVERRIDE_PENDING_MARK), StateTone::Caution))
}

/// The row asks to apply despite the protection and has no confirmation.
fn asks(row: &Row) -> bool {
    row.verdict.message_key == OVERRIDE_REQUESTED_KEY
}

/// Whether a confirmation stands for this row.
pub fn granted(app: &AppState, row: &Row) -> bool {
    app.rules.overrides.contains_key(&key_of(&row.rule))
}

/// `P` on a rule: take a confirmation back, or ask the service what
/// confirming would let the rule take.
pub fn start(app: &mut AppState, master: Option<usize>) -> bool {
    let Some(row) = master.and_then(|i| app.rules.table.rows.get(i)).cloned() else {
        return false;
    };
    if !app.link.is_connected() {
        app.rules.note = Some(Note::failed(
            text::OVERRIDE_FAILED,
            Failure::code("transport-disconnected"),
        ));
        return true;
    }
    let value = row.rule.match_value.clone();
    let route = row.rule.target_route.as_str().to_owned();
    if granted(app, &row) {
        app.outbox.push(Box::new(move |client: &dyn IpcClient| {
            let answer: Result<RuleOverrideRevokeResponse, _> = call(
                client,
                IpcOperationName::RulesOverrideRevoke,
                &RuleOverrideRevokeRequest {
                    value: value.clone(),
                    route,
                },
            );
            Reply::new(move |app| match answer {
                Ok(_) => {
                    app.rules.note = Some(Note::with(
                        text::OVERRIDE_REVOKED,
                        vec![("value", display_text(&value).into_owned())],
                    ));
                }
                Err(error) => app.rules.note = Some(failed(&error)),
            })
        }));
        return true;
    }
    if !asks(&row) {
        app.rules.note = Some(Note::new(text::OVERRIDE_NOTHING));
        return true;
    }
    app.rules.note = Some(Note::new(text::OVERRIDE_READING));
    app.outbox.push(Box::new(move |client: &dyn IpcClient| {
        let answer: Result<RuleOverridePreviewResponse, _> = call(
            client,
            IpcOperationName::RulesOverridePreview,
            &RuleOverridePreviewRequest { value, route },
        );
        Reply::new(move |app| match answer {
            Ok(preview) => {
                app.rules.note = None;
                let term = OverrideTerm::ALL
                    .iter()
                    .position(|t| *t == OverrideTerm::default())
                    .unwrap_or(0);
                app.rules.mode = Mode::Override(Box::new(Confirm {
                    preview,
                    typed: String::new(),
                    term,
                    sending: false,
                    failure: None,
                }));
            }
            Err(error) => app.rules.note = Some(failed(&error)),
        })
    }));
    true
}

/// A confirmation ended or was withdrawn: the feed says so and where to
/// confirm again. `cause` is the push's: empty for a term that ran out.
pub fn announce_ended(
    app: &mut AppState,
    expired: &[String],
    cause: &str,
    texts: &Texts,
    now: std::time::Instant,
) -> Vec<Effect> {
    if cause == "crash-loop" {
        return app.notify(
            NoticeLevel::Warning,
            texts.get(text::OVERRIDE_WITHDRAWN_TITLE),
            texts.get(text::OVERRIDE_WITHDRAWN_BODY),
            now,
        );
    }
    if expired.is_empty() {
        return Vec::new();
    }
    let (title, body) = if cause == "services-changed" {
        (text::OVERRIDE_RECHECK_TITLE, text::OVERRIDE_RECHECK_BODY)
    } else {
        (text::OVERRIDE_ENDED_TITLE, text::OVERRIDE_ENDED_BODY)
    };
    app.notify(
        NoticeLevel::Warning,
        texts.get(title),
        texts.fill(body, &[("rules", joined(expired))]),
        now,
    )
}

fn failed(error: &CallError) -> Note {
    Note::failed(text::OVERRIDE_FAILED, Failure::code(&error.code))
}

/// A key while the confirmation is shown.
pub fn on_key(app: &mut AppState, mut confirm: Box<Confirm>, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => return true,
        KeyCode::Enter if confirm.ready() => {
            send(app, confirm);
            return true;
        }
        KeyCode::Enter => return true,
        KeyCode::Left => {
            confirm.term = (confirm.term + OverrideTerm::ALL.len() - 1) % OverrideTerm::ALL.len();
        }
        KeyCode::Right | KeyCode::Tab => {
            confirm.term = (confirm.term + 1) % OverrideTerm::ALL.len();
        }
        KeyCode::Backspace => {
            confirm.typed.pop();
        }
        KeyCode::Char(c) => confirm.typed.push(c),
        _ => {}
    }
    app.rules.mode = Mode::Override(confirm);
    true
}

/// A line while the confirmation is shown (`--plain`): `1`-`4` choose the
/// term, anything else is the rule's value typed to confirm.
pub fn on_line(app: &mut AppState, mut confirm: Box<Confirm>, line: &str) {
    if let Ok(n) = line.trim().parse::<usize>() {
        if (1..=OverrideTerm::ALL.len()).contains(&n) {
            confirm.term = n - 1;
            app.rules.mode = Mode::Override(confirm);
            return;
        }
    }
    if !confirm.ready() {
        return;
    }
    confirm.typed = line.to_owned();
    send(app, confirm);
}

fn send(app: &mut AppState, mut confirm: Box<Confirm>) {
    if !confirm.typed_matches() {
        confirm.failure = None;
        app.rules.note = Some(Note::new(text::OVERRIDE_MISMATCH));
        app.rules.mode = Mode::Override(confirm);
        return;
    }
    confirm.sending = true;
    let request = RuleOverrideGrantRequest {
        token: confirm.preview.token.clone(),
        typed_value: confirm.typed.clone(),
        term: confirm.term(),
    };
    app.rules.mode = Mode::Override(confirm);
    app.outbox.push(Box::new(move |client: &dyn IpcClient| {
        let answer: Result<RuleOverrideGrantResponse, _> =
            call(client, IpcOperationName::RulesOverrideGrant, &request);
        Reply::new(move |app| {
            let Mode::Override(mut confirm) = std::mem::take(&mut app.rules.mode) else {
                return;
            };
            match answer {
                Ok(answer) => {
                    app.rules.note = Some(Note::with(
                        text::OVERRIDE_GRANTED,
                        vec![("value", display_text(&answer.granted.value).into_owned())],
                    ));
                }
                Err(error) => {
                    confirm.sending = false;
                    confirm.failure = Some(Failure::of_call(&error.code, &error.message));
                    app.rules.mode = Mode::Override(confirm);
                }
            }
        })
    }));
}

/// What the prompt line asks in `--plain`.
pub fn plain_prompt(confirm: &Confirm) -> Key {
    if confirm.ready() {
        text::OVERRIDE_PLAIN_PROMPT
    } else {
        text::PLAIN_CHOICE_PROMPT
    }
}

fn joined(items: &[String]) -> String {
    items
        .iter()
        .map(|item| display_text(item).into_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

fn account_text(account: &str, texts: &Texts) -> String {
    let (id, en) = match account {
        "S-1-5-18" => ("rules.override.account.system", "the system (SYSTEM)"),
        "S-1-5-19" => ("rules.override.account.local-service", "LOCAL SERVICE"),
        "S-1-5-20" => ("rules.override.account.network-service", "NETWORK SERVICE"),
        "unix:uid:0" => ("rules.override.account.root", "root"),
        other => return display_text(other).into_owned(),
    };
    texts.dynamic(id, en)
}

/// The confirmation, as the window's dialog says it.
pub fn lines(confirm: &Confirm, texts: &Texts) -> Vec<ViewLine> {
    let preview = &confirm.preview;
    let mut lines = vec![ViewLine::new(vec![Segment::strong(format!(
        "{} \u{2014} {}",
        display_text(&preview.value),
        preview.route
    ))])];
    if !confirm.ready() {
        let (id, en) = match preview.status.as_str() {
            "not-requested" => (
                "rules.override.status.not-requested",
                "Save the rule with +override after its value first; then confirm it here.",
            ),
            "not-protected" => (
                "rules.override.status.not-protected",
                "Nothing to confirm: the protection does not hold this rule.",
            ),
            "unavailable" => (
                "rules.override.status.unavailable",
                "The service cannot keep confirmations right now, so none can be given.",
            ),
            _ => (
                "rules.override.status.not-allowed",
                "This rule cannot be applied despite the protection.",
            ),
        };
        lines.push(ViewLine::text(texts.dynamic(id, en)));
        lines.push(ViewLine::text(texts.get(text::INPUT_HINT)));
        return lines;
    }
    if !preview.reason.is_empty() {
        lines.push(ViewLine::text(texts.dynamic(
            &format!(
                "rules.validation.match-value-invalid.protected-{}",
                preview.reason
            ),
            &preview.reason,
        )));
    }
    let programs = if preview.programs_over_cap {
        text::OVERRIDE_PROGRAMS_OVER_CAP
    } else {
        text::OVERRIDE_PROGRAMS
    };
    lines.push(ViewLine::text(
        texts.fill(programs, &[("count", preview.programs.to_string())]),
    ));
    if !preview.critical_processes.is_empty() {
        lines.push(ViewLine::new(vec![Segment::state(
            texts.fill(
                text::OVERRIDE_CRITICAL,
                &[("list", joined(&preview.critical_processes))],
            ),
            StateTone::Bad,
        )]));
    }
    if !preview.service_accounts.is_empty() {
        let accounts: Vec<String> = preview
            .service_accounts
            .iter()
            .map(|a| account_text(a, texts))
            .collect();
        lines.push(ViewLine::text(
            texts.fill(text::OVERRIDE_ACCOUNTS, &[("list", accounts.join(", "))]),
        ));
    }
    if preview.other_users > 0 {
        lines.push(ViewLine::text(texts.fill(
            text::OVERRIDE_OTHER_USERS,
            &[("count", preview.other_users.to_string())],
        )));
    }
    if !preview.breaks.is_empty() {
        let breaks: Vec<String> = preview
            .breaks
            .iter()
            .map(|slug| texts.dynamic(&format!("rules.override.breaks.{slug}"), slug))
            .collect();
        lines.push(ViewLine::new(vec![Segment::state(
            texts.fill(text::OVERRIDE_BREAKS, &[("list", breaks.join(", "))]),
            StateTone::Caution,
        )]));
    }
    if preview.needs_administrator {
        lines.push(ViewLine::text(texts.get(text::OVERRIDE_ADMINISTRATOR)));
    }
    let terms: Vec<String> = OverrideTerm::ALL
        .iter()
        .enumerate()
        .map(|(i, term)| {
            let label = texts.dynamic(&format!("rules.override.term.{}", term.slug()), term.slug());
            if i == confirm.term {
                format!("[{}] {label}", i + 1)
            } else {
                format!("{}. {label}", i + 1)
            }
        })
        .collect();
    lines.push(ViewLine::text(format!(
        "{}: {}",
        texts.get(text::OVERRIDE_TERM),
        terms.join("  ")
    )));
    lines.push(ViewLine::text(texts.fill(
        text::OVERRIDE_TYPE,
        &[("value", display_text(&preview.value).into_owned())],
    )));
    lines.push(ViewLine::text(format!("> {}", confirm.typed)));
    if confirm.sending {
        lines.push(ViewLine::text(texts.get(text::OVERRIDE_SENDING)));
    }
    if let Some(failure) = &confirm.failure {
        let shown = if matches!(failure, Failure::NeedsAdministrator) {
            failure.text(texts)
        } else {
            texts.fill(text::OVERRIDE_FAILED, &[("error", failure.text(texts))])
        };
        lines.push(ViewLine::new(vec![Segment::state(shown, StateTone::Bad)]));
    }
    lines.push(ViewLine::text(texts.get(text::OVERRIDE_KEYS)));
    lines
}

#[cfg(test)]
mod tests;

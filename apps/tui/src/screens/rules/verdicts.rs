//! The `?` rules the service found working only on the other route: one
//! question on this screen for all of them, `m` moves them, `n` leaves them as
//! written until the next restart, and a feed notice points here. The list is
//! the service's, read on connect and on every `verify-verdicts-changed` push.
//! A session without rules of its own (the baseline under `sudo`) has nothing
//! to answer here.
//!
//! Nobody else writes the user's rules files after a move made from the
//! terminal, so a move made here reads the rules back and writes the bound
//! files itself.

use std::path::Path;

use nrr_client_logic::verify_verdicts::{verdict_notice, VerdictNotice};
use nrr_client_logic::Route;
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    VerifyVerdictDto, VerifyVerdictsAcceptRequest, VerifyVerdictsAcceptResponse,
    VerifyVerdictsDismissRequest, VerifyVerdictsDismissResponse, VerifyVerdictsListResponse,
};
use serde_json::Map;

use super::apply::Failure;
use super::{files, own_settings, text, Input, InputPurpose, Mode, Note};
use crate::backend::Reply;
use crate::i18n::Texts;
use crate::screens::suggestions::{call, CallError};
use crate::screens::ScreenId;
use crate::state::{AppState, Effect, NoticeLevel};

#[derive(Debug, Default)]
pub struct Verdicts {
    list: Vec<VerifyVerdictDto>,
    loading: bool,
    /// A re-read asked for while one was in flight.
    owed: bool,
    /// Ids the feed was told about; a re-read that brings nothing new stays
    /// quiet.
    announced: Vec<String>,
    unannounced: bool,
    /// A move made here went through: once the rules are read back, the
    /// user's files are written from them.
    pub rewrite_files: bool,
}

/// What waits for an answer; `None` when nothing does.
pub fn notice(app: &AppState) -> Option<VerdictNotice> {
    verdict_notice(&app.rules.verdicts.list)
}

/// Re-read the list; a request while one is in flight is owed, not dropped.
pub fn load(app: &mut AppState) {
    if !app.link.is_connected() || app.rules.settings_file.is_none() {
        return;
    }
    let state = &mut app.rules.verdicts;
    if state.loading {
        state.owed = true;
        return;
    }
    state.loading = true;
    app.outbox.push(Box::new(|client: &dyn IpcClient| {
        let answer: Result<VerifyVerdictsListResponse, _> =
            call(client, IpcOperationName::VerifyVerdictsList, &Map::new());
        Reply::new(move |app| loaded(app, answer))
    }));
}

fn loaded(app: &mut AppState, answer: Result<VerifyVerdictsListResponse, CallError>) {
    let state = &mut app.rules.verdicts;
    state.loading = false;
    if let Ok(answer) = answer {
        state.list = answer.verdicts;
        match verdict_notice(&state.list) {
            None => state.announced.clear(),
            Some(waiting) => {
                if waiting
                    .rule_ids
                    .iter()
                    .any(|id| !state.announced.contains(id))
                {
                    state.unannounced = true;
                }
                state.announced = waiting.rule_ids;
            }
        }
    }
    if std::mem::take(&mut state.owed) {
        load(app);
    }
}

/// Says on the feed that rules wait for an answer, and where to give it.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    if !std::mem::take(&mut app.rules.verdicts.unannounced) {
        return Vec::new();
    }
    let Some(waiting) = notice(app) else {
        return Vec::new();
    };
    let screen = ScreenId::Rules;
    let body = format!(
        "{} {}",
        texts.get(text::VERDICTS_BODY),
        texts.fill(
            text::VERDICTS_WHERE,
            &[
                ("key", screen.hotkey().map(String::from).unwrap_or_default()),
                ("screen", texts.get(screen.title())),
            ],
        )
    );
    app.notify(NoticeLevel::Info, title(&waiting, texts), body, now)
}

pub fn title(waiting: &VerdictNotice, texts: &Texts) -> String {
    texts.fill(
        text::VERDICTS_TITLE,
        &[("count", waiting.rule_ids.len().to_string())],
    )
}

/// `m`: move every waiting rule. Without a rule-set folder the folder is
/// asked for first, as the window does; an empty answer is "not now".
pub fn move_all(app: &mut AppState) -> bool {
    if notice(app).is_none() {
        return false;
    }
    if !app.link.is_connected() {
        app.rules.note = Some(offline());
        return true;
    }
    let has_folder = app
        .rules
        .settings_file
        .as_deref()
        .and_then(own_settings::rules_folder)
        .is_some();
    if has_folder {
        accept(app);
    } else {
        app.rules.mode = Mode::Input(Input {
            purpose: InputPurpose::VerdictFolder,
            text: String::new(),
        });
    }
    true
}

/// The folder prompt's answer: the folder becomes the user's (the set on
/// screen moves in), then the rules move. Nothing typed is "not now".
pub fn folder_answered(app: &mut AppState, typed: &str) {
    if typed.trim().is_empty() {
        not_now(app);
        return;
    }
    super::folder::choose(app, typed);
    let chosen = app
        .rules
        .settings_file
        .as_deref()
        .and_then(own_settings::rules_folder)
        .is_some();
    if chosen {
        accept(app);
    }
}

fn accept(app: &mut AppState) {
    let Some(waiting) = notice(app) else {
        return;
    };
    app.outbox.push(Box::new(move |client: &dyn IpcClient| {
        let answer: Result<VerifyVerdictsAcceptResponse, _> = call(
            client,
            IpcOperationName::VerifyVerdictsAccept,
            &VerifyVerdictsAcceptRequest {
                rule_ids: waiting.rule_ids,
            },
        );
        Reply::new(move |app| accepted(app, answer))
    }));
}

fn accepted(app: &mut AppState, answer: Result<VerifyVerdictsAcceptResponse, CallError>) {
    match answer {
        Err(error) => app.rules.note = Some(failed(error)),
        Ok(_) => {
            app.rules.note = Some(Note::new(text::VERDICTS_MOVED));
            // Edits on screen are not dropped for it; the files then wait for
            // the next read, as in the window.
            let rules = &app.rules;
            if !rules.table.is_dirty() && rules.busy.is_none() {
                app.rules.verdicts.rewrite_files = true;
                super::load(app);
            }
        }
    }
    load(app);
}

/// `n`, or a folder prompt left empty: the rules stay as written; the move
/// holds until the next restart and the check repeats after it.
pub fn not_now(app: &mut AppState) -> bool {
    let Some(waiting) = notice(app) else {
        return false;
    };
    if !app.link.is_connected() {
        app.rules.note = Some(offline());
        return true;
    }
    app.outbox.push(Box::new(move |client: &dyn IpcClient| {
        let answer: Result<VerifyVerdictsDismissResponse, _> = call(
            client,
            IpcOperationName::VerifyVerdictsDismiss,
            &VerifyVerdictsDismissRequest {
                rule_ids: waiting.rule_ids,
            },
        );
        Reply::new(move |app| {
            if let Err(error) = answer {
                app.rules.note = Some(failed(error));
            }
            load(app);
        })
    }));
    true
}

fn offline() -> Note {
    Note::failed(
        text::VERDICTS_FAILED,
        Failure::code("transport-disconnected"),
    )
}

fn failed(error: CallError) -> Note {
    Note::failed(text::VERDICTS_FAILED, Failure::code(&error.code))
}

/// After the rules were read back from a move made here: each route bound to
/// a file gets it written from the rows now on screen.
pub fn write_bound_files(app: &mut AppState) {
    if !std::mem::take(&mut app.rules.verdicts.rewrite_files) {
        return;
    }
    let Some(file) = app.rules.settings_file.as_deref() else {
        return;
    };
    let Ok(settings) = own_settings::read(file) else {
        return;
    };
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let bound = [settings.rules_files.primary, settings.rules_files.secondary];
    for (route, path) in Route::ALL.into_iter().zip(bound) {
        if path.is_empty() {
            continue;
        }
        let table = &app.rules.table;
        let written = files::write_route(Path::new(&path), route, table, &exported_at);
        if let Err((path, error)) = written {
            let path = path.display().to_string();
            app.rules.note = Some(Note::with(
                text::WRITE_FAILED,
                vec![("path", path), ("error", error)],
            ));
            return;
        }
    }
}

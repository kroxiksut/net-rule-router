//! The Rules screen (the GUI's `RulesSection`, `RuleEditDialog` and review
//! flow): the list with its route filter and search; add, edit, delete,
//! switch on and off; the two rules files and the shipped rule sets; and the
//! apply through one "changes" view.

mod ace;
mod apply;
mod files;
mod form;
mod render;
mod table;
mod text;

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::rules_table::search_box_text;
use nrr_shared::ipc_payloads::RulesListResponse;
use nrr_shared::rules_json::FREE_MAX_RULES;

use self::apply::{Failure, Finished, Previewed, Review};
use self::files::{Preset, RuleSet};
use self::form::{Field, Form, Saved};
use self::table::{RouteFilter, Table, PAGE};
use super::{Screen, ScreenId};
use crate::i18n::{Key, Texts};
use crate::state::AppState;
use crate::view::ScreenView;

/// What the screen is doing besides showing the list.
#[derive(Debug, Default)]
pub enum Mode {
    #[default]
    List,
    Input(Input),
    Form(Box<Form>),
    Choice(Choice),
    Review(Box<Review>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPurpose {
    Search,
    Import,
    Export,
}

#[derive(Debug)]
pub struct Input {
    pub purpose: InputPurpose,
    pub text: String,
}

#[derive(Debug)]
pub enum ChoicePurpose {
    Filter,
    Delete(usize),
    Reload,
    Quit,
    ImportMode { set: Box<RuleSet>, path: String },
    Preset(Vec<Preset>),
    Overwrite(PathBuf),
}

#[derive(Debug)]
pub struct Choice {
    pub purpose: ChoicePurpose,
    pub cursor: usize,
}

/// A service call in flight; the list is locked while one runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Busy {
    Loading,
    Previewing,
    Applying {
        correlation_id: String,
        phase: Option<Phase>,
    },
}

/// The apply's progress, as `mutation-progress` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Phase {
    Started,
    Completed,
    Failed(Failure),
}

/// The last thing that happened, worded on screen; never a timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub key: Key,
    pub args: Vec<(&'static str, String)>,
    pub failure: Option<Failure>,
}

impl Note {
    fn new(key: Key) -> Self {
        Self {
            key,
            args: Vec::new(),
            failure: None,
        }
    }

    fn with(key: Key, args: Vec<(&'static str, String)>) -> Self {
        Self {
            key,
            args,
            failure: None,
        }
    }

    fn failed(key: Key, failure: Failure) -> Self {
        Self {
            key,
            args: Vec::new(),
            failure: Some(failure),
        }
    }

    pub fn text(&self, texts: &Texts) -> String {
        let mut out = texts.fill(self.key, &self.args);
        if let Some(failure) = &self.failure {
            out.push_str(&failure.text(texts));
        }
        out
    }
}

#[derive(Debug, Default)]
pub struct RulesState {
    pub table: Table,
    pub mode: Mode,
    pub busy: Option<Busy>,
    pub load_error: Option<Failure>,
    pub note: Option<Note>,
    /// The rules applied are the administrator's baseline (`sudo`), not the
    /// caller's own.
    pub baseline: bool,
    /// The quit question chose "apply, then quit".
    quit_after_apply: bool,
}

pub struct RulesScreen;

impl Screen for RulesScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        render::view(app, texts)
    }

    fn help(&self) -> &'static [Key] {
        &[
            text::HELP_FOCUS,
            text::HELP_MOVE,
            text::HELP_EDIT,
            text::HELP_DELETE,
            text::HELP_FILTER,
            text::HELP_APPLY,
            text::HELP_FILES,
            text::HELP_RELOAD,
            text::HELP_FORM,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            text::PLAIN_ADD,
            text::PLAIN_EDIT,
            text::PLAIN_DELETE,
            text::PLAIN_TOGGLE,
            text::PLAIN_FILTER,
            text::PLAIN_SEARCH,
            text::PLAIN_PAGES,
            text::PLAIN_APPLY,
            text::PLAIN_FILES,
            text::PLAIN_RELOAD,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        let rules = &app.rules;
        if app.link.is_connected()
            && rules.busy.is_none()
            && !rules.table.is_loaded()
            && rules.table.rows.is_empty()
        {
            load(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        !matches!(app.rules.mode, Mode::List)
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        match std::mem::take(&mut app.rules.mode) {
            Mode::List => list_key(app, key),
            Mode::Input(input) => input_key(app, input, key),
            Mode::Form(form) => form_key(app, form, key),
            Mode::Choice(choice) => choice_key(app, choice, key),
            Mode::Review(review) => review_key(app, review, key),
        }
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        match std::mem::take(&mut app.rules.mode) {
            Mode::List => list_line(app, line),
            Mode::Input(input) => {
                if line == "!" {
                    return true;
                }
                let mut input = input;
                if !line.is_empty() {
                    input.text = line.to_owned();
                }
                commit_input(app, input);
                true
            }
            Mode::Form(mut form) => {
                if line == "!" {
                    return true;
                }
                if form.answer(line) {
                    save_form(app, form);
                } else {
                    app.rules.mode = Mode::Form(form);
                }
                true
            }
            Mode::Choice(mut choice) => {
                if line == "!" {
                    cancel_choice(app, choice);
                    return true;
                }
                let count = render::choice_len(&choice.purpose);
                match line.parse::<usize>() {
                    Ok(n) if (1..=count).contains(&n) => {
                        choice.cursor = n - 1;
                        pick(app, choice);
                    }
                    _ => app.rules.mode = Mode::Choice(choice),
                }
                true
            }
            Mode::Review(mut review) => {
                match line {
                    "y" | "Y" => confirm(app, review),
                    "n" | "N" => {}
                    "c" | "C" if review.is_critical() => {
                        review.understood = !review.understood;
                        app.rules.mode = Mode::Review(review);
                    }
                    ">" => {
                        review.scroll = review.scroll.saturating_add(render::REVIEW_PAGE);
                        app.rules.mode = Mode::Review(review);
                    }
                    "<" => {
                        review.scroll = review.scroll.saturating_sub(render::REVIEW_PAGE);
                        app.rules.mode = Mode::Review(review);
                    }
                    _ => app.rules.mode = Mode::Review(review),
                }
                true
            }
        }
    }

    fn plain_prompt(&self, app: &AppState) -> Option<Key> {
        match &app.rules.mode {
            Mode::List => None,
            Mode::Input(_) | Mode::Form(_) => Some(text::PLAIN_PROMPT),
            Mode::Choice(_) => Some(text::PLAIN_CHOICE_PROMPT),
            Mode::Review(review) if review.is_critical() => {
                Some(text::PLAIN_REVIEW_CRITICAL_PROMPT)
            }
            Mode::Review(_) => Some(text::PLAIN_REVIEW_PROMPT),
        }
    }
}

// ── What the rest of the interface asks ─────────────────────────────────────

/// Whether quitting now would lose rules the service does not have.
pub fn holds_unapplied(app: &AppState) -> bool {
    app.rules.table.is_dirty()
}

/// Open the question "apply / discard / stay" on this screen.
pub fn ask_before_quit(app: &mut AppState) {
    app.open(ScreenId::Rules);
    app.rules.mode = Mode::Choice(Choice {
        purpose: ChoicePurpose::Quit,
        cursor: 0,
    });
}

/// A `mutation-progress` push: the apply in flight moved on.
pub fn on_progress(
    app: &mut AppState,
    correlation_id: &str,
    phase: &str,
    error_code: Option<&str>,
    error_args: &std::collections::BTreeMap<String, String>,
) {
    let Some(Busy::Applying {
        correlation_id: ours,
        phase: current,
    }) = app.rules.busy.as_mut()
    else {
        return;
    };
    if ours != correlation_id {
        return;
    }
    *current = match phase {
        "started" => Some(Phase::Started),
        "completed" => Some(Phase::Completed),
        "failed" => Some(Phase::Failed(Failure::Code {
            code: error_code.unwrap_or_default().to_owned(),
            args: error_args.clone(),
        })),
        _ => return,
    };
}

/// Somebody's rules revision changed (another window, the tray, the
/// service's own additions): reread, unless that would drop edits.
pub fn on_revision_changed(app: &mut AppState) {
    let rules = &app.rules;
    if rules.table.is_loaded()
        && !rules.table.is_dirty()
        && rules.busy.is_none()
        && matches!(rules.mode, Mode::List)
        && app.link.is_connected()
    {
        load(app);
    }
}

// ── Answers from the service ────────────────────────────────────────────────

fn load(app: &mut AppState) {
    app.rules.busy = Some(Busy::Loading);
    app.outbox.push(apply::load_job());
}

fn loaded(app: &mut AppState, result: Result<RulesListResponse, Failure>) {
    let rules = &mut app.rules;
    rules.busy = None;
    match result {
        Ok(list) => {
            rules.load_error = None;
            rules.table.load(&list.rows);
        }
        Err(failure) => rules.load_error = Some(failure),
    }
}

fn previewed(app: &mut AppState, previewed: Previewed) {
    let rules = &mut app.rules;
    rules.busy = None;
    match previewed {
        Previewed::Review(review) => rules.mode = Mode::Review(review),
        Previewed::NothingToApply => {
            // The service already applies exactly this set.
            rules.table.mark_applied();
            rules.note = Some(Note::new(text::NOTHING_TO_APPLY));
            if std::mem::take(&mut rules.quit_after_apply) {
                app.quit = true;
            }
        }
        Previewed::Refused(failure) => {
            rules.quit_after_apply = false;
            rules.note = Some(Note::failed(text::ACTIVATE_FAILED, failure));
        }
    }
}

fn finished(app: &mut AppState, finished: Finished) {
    let rules = &mut app.rules;
    rules.busy = None;
    let quit = std::mem::take(&mut rules.quit_after_apply);
    rules.note = Some(match finished {
        Finished::Applied => {
            rules.table.mark_applied();
            if quit {
                app.quit = true;
            }
            Note::new(text::ACTIVATED)
        }
        // The edits stay on screen: nothing was applied.
        Finished::Expired => Note::new(text::EXPIRED),
        Finished::UacDeclined => Note::new(text::UAC_DECLINED),
        Finished::Failed(failure) => Note::failed(text::ACTIVATE_FAILED, failure),
    });
}

// ── Actions ─────────────────────────────────────────────────────────────────

/// Edits wait while the service is busy with this list.
fn locked(app: &mut AppState) -> bool {
    if app.rules.busy.is_some() {
        app.rules.note = Some(Note::new(text::BUSY));
        return true;
    }
    false
}

fn start_apply(app: &mut AppState) {
    if locked(app) {
        return;
    }
    if !app.link.is_connected() {
        app.rules.quit_after_apply = false;
        app.rules.note = Some(Note::new(text::APPLY_OFFLINE));
        return;
    }
    let Some(pending) = apply::pending_from(&app.rules.table, app.rules.baseline) else {
        app.rules.note = Some(Note::failed(
            text::ACTIVATE_FAILED,
            Failure::code("gui-internal"),
        ));
        return;
    };
    app.rules.note = None;
    app.rules.busy = Some(Busy::Previewing);
    app.outbox.push(apply::preview_job(pending));
}

fn confirm(app: &mut AppState, review: Box<Review>) {
    if !review.may_apply() {
        app.rules.mode = Mode::Review(review);
        return;
    }
    let Review { pending, token, .. } = *review;
    app.rules.busy = Some(Busy::Applying {
        correlation_id: pending.correlation_id.clone(),
        phase: None,
    });
    app.outbox.push(apply::confirm_job(pending, token));
}

fn open_form(app: &mut AppState, form: Form) {
    if !locked(app) {
        app.rules.mode = Mode::Form(Box::new(form));
    }
}

fn edit_selected(app: &mut AppState, master: Option<usize>) {
    if let Some(form) = master.and_then(|i| Form::edit(&app.rules.table, i)) {
        open_form(app, form);
    }
}

fn toggle(app: &mut AppState, master: Option<usize>) {
    if locked(app) {
        return;
    }
    if let Some(row) = master.and_then(|i| app.rules.table.rows.get_mut(i)) {
        row.rule.enabled = !row.rule.enabled;
    }
}

fn ask(app: &mut AppState, purpose: ChoicePurpose) {
    let cursor = match &purpose {
        ChoicePurpose::Filter => RouteFilter::ALL
            .iter()
            .position(|f| *f == app.rules.table.filter)
            .unwrap_or(0),
        _ => 0,
    };
    app.rules.mode = Mode::Choice(Choice { purpose, cursor });
}

fn ask_delete(app: &mut AppState, master: Option<usize>) {
    if locked(app) {
        return;
    }
    if let Some(i) = master.filter(|i| *i < app.rules.table.rows.len()) {
        ask(app, ChoicePurpose::Delete(i));
    }
}

fn reload(app: &mut AppState) {
    if locked(app) {
        return;
    }
    if !app.link.is_connected() {
        app.rules.note = Some(Note::new(text::NOT_LOADED));
    } else if app.rules.table.is_dirty() {
        ask(app, ChoicePurpose::Reload);
    } else {
        load(app);
    }
}

fn start_input(app: &mut AppState, purpose: InputPurpose) {
    let text = match purpose {
        InputPurpose::Search => app.rules.table.search.clone(),
        InputPurpose::Import | InputPurpose::Export => std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default(),
    };
    if purpose == InputPurpose::Search || !locked(app) {
        app.rules.mode = Mode::Input(Input { purpose, text });
    }
}

fn presets(app: &mut AppState) {
    if locked(app) {
        return;
    }
    let found = files::presets();
    if found.is_empty() {
        app.rules.note = Some(Note::new(text::NO_PRESETS));
    } else {
        ask(app, ChoicePurpose::Preset(found));
    }
}

fn save_form(app: &mut AppState, mut form: Box<Form>) {
    let saved = form.save(&mut app.rules.table);
    let note = match saved {
        Saved::Added { enabled: true } => text::RULE_ADDED,
        Saved::Added { enabled: false } => text::RULE_ADDED_DISABLED,
        Saved::Updated => text::RULE_UPDATED,
        Saved::Refused | Saved::Duplicate(_) => {
            app.rules.mode = Mode::Form(form);
            return;
        }
        Saved::Limit => {
            app.rules.note = Some(Note::with(
                text::LIMIT_REACHED,
                vec![("max", FREE_MAX_RULES.to_string())],
            ));
            app.rules.mode = Mode::Form(form);
            return;
        }
    };
    app.rules.note = Some(Note::new(note));
}

fn commit_input(app: &mut AppState, input: Input) {
    match input.purpose {
        InputPurpose::Search => {
            let table = &mut app.rules.table;
            table.search = search_box_text(&input.text);
            table.cursor = 0;
        }
        InputPurpose::Import => {
            let path = path_of(&input.text);
            let shown = path.display().to_string();
            match files::read_set(&path) {
                Err((file, error)) => app.rules.note = Some(read_failed(&file, error)),
                Ok(set) if set.files == 0 => {
                    app.rules.note = Some(Note::with(text::IMPORT_NOTHING, vec![("path", shown)]));
                }
                Ok(set) => offer_import(app, set, shown),
            }
        }
        InputPurpose::Export => {
            let path = path_of(&input.text);
            if files::set_exists(&path) {
                ask(app, ChoicePurpose::Overwrite(path));
            } else {
                export(app, &path);
            }
        }
    }
}

fn path_of(typed: &str) -> PathBuf {
    let typed = typed.trim();
    PathBuf::from(if typed.is_empty() { "." } else { typed })
}

fn read_failed(file: &std::path::Path, error: files::ReadError) -> Note {
    match error {
        files::ReadError::Io(error) => Note::with(
            text::READ_FAILED,
            vec![("path", file.display().to_string()), ("error", error)],
        ),
        files::ReadError::NotUtf8 => Note::new(text::FILE_ENCODING),
        files::ReadError::TooLarge => Note::new(text::PAYLOAD_TOO_LARGE),
    }
}

/// An empty list takes the files whole; otherwise the user picks.
fn offer_import(app: &mut AppState, set: RuleSet, path: String) {
    if app.rules.table.rows.is_empty() {
        import(app, set, path, true);
    } else {
        ask(
            app,
            ChoicePurpose::ImportMode {
                set: Box::new(set),
                path,
            },
        );
    }
}

fn import(app: &mut AppState, set: RuleSet, path: String, replace: bool) {
    let table = &mut app.rules.table;
    let added = table.import(set.rows, replace);
    table.passthrough = set.passthrough;
    table.filter = RouteFilter::All;
    table.search.clear();
    table.cursor = 0;
    app.rules.note = Some(Note::with(
        text::IMPORTED,
        vec![("count", added.to_string()), ("path", path)],
    ));
}

fn export(app: &mut AppState, path: &std::path::Path) {
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    app.rules.note = Some(
        match files::write_set(path, &app.rules.table, &exported_at) {
            Ok(()) => Note::with(text::EXPORTED, vec![("path", path.display().to_string())]),
            Err((file, error)) => Note::with(
                text::WRITE_FAILED,
                vec![("path", file.display().to_string()), ("error", error)],
            ),
        },
    );
}

fn cancel_choice(app: &mut AppState, choice: Choice) {
    if matches!(choice.purpose, ChoicePurpose::Quit) {
        app.rules.quit_after_apply = false;
    }
}

/// The option under the cursor was chosen.
fn pick(app: &mut AppState, choice: Choice) {
    let at = choice.cursor;
    match choice.purpose {
        ChoicePurpose::Filter => {
            let table = &mut app.rules.table;
            table.filter = RouteFilter::ALL.get(at).copied().unwrap_or_default();
            table.cursor = 0;
        }
        ChoicePurpose::Delete(i) if at == 0 => {
            let table = &mut app.rules.table;
            if i < table.rows.len() {
                table.rows.remove(i);
                table.clamp_cursor();
                app.rules.note = Some(Note::new(text::RULE_REMOVED));
            }
        }
        ChoicePurpose::Reload if at == 0 => load(app),
        ChoicePurpose::Quit => match at {
            0 => {
                app.rules.quit_after_apply = true;
                start_apply(app);
            }
            1 => app.quit = true,
            _ => {}
        },
        ChoicePurpose::ImportMode { set, path } if at < 2 => import(app, *set, path, at == 0),
        ChoicePurpose::Preset(presets) => {
            if let Some(preset) = presets.get(at) {
                match files::read_set(&preset.dir) {
                    Err((file, error)) => app.rules.note = Some(read_failed(&file, error)),
                    Ok(set) => offer_import(app, set, preset.label.clone()),
                }
            }
        }
        ChoicePurpose::Overwrite(path) if at == 0 => export(app, &path),
        _ => {}
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

fn list_key(app: &mut AppState, key: KeyEvent) -> bool {
    let selected = app.rules.table.selected();
    let table = &mut app.rules.table;
    let page = PAGE as isize;
    match key.code {
        KeyCode::Up => table.move_cursor(-1),
        KeyCode::Down => table.move_cursor(1),
        KeyCode::PageUp => table.move_cursor(-page),
        KeyCode::PageDown => table.move_cursor(page),
        KeyCode::Home => table.cursor = 0,
        KeyCode::End => table.move_cursor(isize::MAX),
        KeyCode::Enter => edit_selected(app, selected),
        KeyCode::Delete => ask_delete(app, selected),
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => start_apply(app),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => match c {
            'a' => open_form(app, Form::add()),
            'e' => edit_selected(app, selected),
            'd' => ask_delete(app, selected),
            ' ' | 't' => toggle(app, selected),
            'f' => ask(app, ChoicePurpose::Filter),
            '/' => start_input(app, InputPurpose::Search),
            's' => start_apply(app),
            'r' => reload(app),
            'i' => start_input(app, InputPurpose::Import),
            'x' => start_input(app, InputPurpose::Export),
            'p' => presets(app),
            _ => return false,
        },
        _ => return false,
    }
    true
}

/// Text keys; `false` for F1 so the help still opens.
fn edit_text(text: &mut String, key: KeyEvent) -> Option<bool> {
    match key.code {
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            text.push(c);
            Some(true)
        }
        KeyCode::Backspace => {
            text.pop();
            Some(true)
        }
        KeyCode::F(1) => Some(false),
        _ => None,
    }
}

fn input_key(app: &mut AppState, mut input: Input, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => {}
        KeyCode::Enter => commit_input(app, input),
        _ => {
            let used = edit_text(&mut input.text, key);
            app.rules.mode = Mode::Input(input);
            return used.unwrap_or(true);
        }
    }
    true
}

fn form_key(app: &mut AppState, mut form: Box<Form>, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => return true,
        KeyCode::Enter => {
            if let Some(existing) = form.duplicate {
                app.rules.table.select(existing);
                edit_selected(app, Some(existing));
            } else {
                save_form(app, form);
            }
            return true;
        }
        KeyCode::Up | KeyCode::BackTab => form.move_field(-1),
        KeyCode::Down | KeyCode::Tab => form.move_field(1),
        KeyCode::Left => form.cycle(-1),
        KeyCode::Right => form.cycle(1),
        KeyCode::Char(' ') if matches!(form.field, Field::Type | Field::Route) => form.cycle(1),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => form.type_char(c),
        KeyCode::Backspace => form.backspace(),
        KeyCode::F(1) => {
            app.rules.mode = Mode::Form(form);
            return false;
        }
        _ => {}
    }
    app.rules.mode = Mode::Form(form);
    true
}

fn choice_key(app: &mut AppState, mut choice: Choice, key: KeyEvent) -> bool {
    let count = render::choice_len(&choice.purpose);
    match key.code {
        KeyCode::Esc => {
            cancel_choice(app, choice);
            return true;
        }
        KeyCode::Enter if count > 0 => {
            pick(app, choice);
            return true;
        }
        KeyCode::Up => choice.cursor = choice.cursor.saturating_sub(1),
        KeyCode::Down => choice.cursor = (choice.cursor + 1).min(count.saturating_sub(1)),
        KeyCode::Char(c) => {
            if let Some(n) = c.to_digit(10).map(|n| n as usize) {
                if (1..=count).contains(&n) {
                    choice.cursor = n - 1;
                    pick(app, choice);
                    return true;
                }
            }
        }
        KeyCode::F(1) => {
            app.rules.mode = Mode::Choice(choice);
            return false;
        }
        _ => {}
    }
    app.rules.mode = Mode::Choice(choice);
    true
}

fn review_key(app: &mut AppState, mut review: Box<Review>, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc => return true,
        KeyCode::Enter => {
            confirm(app, review);
            return true;
        }
        KeyCode::Char(' ' | 'c') if review.is_critical() => {
            review.understood = !review.understood;
        }
        KeyCode::Up => review.scroll = review.scroll.saturating_sub(1),
        KeyCode::Down => review.scroll = review.scroll.saturating_add(1),
        KeyCode::PageUp => review.scroll = review.scroll.saturating_sub(render::REVIEW_PAGE),
        KeyCode::PageDown => review.scroll = review.scroll.saturating_add(render::REVIEW_PAGE),
        KeyCode::F(1) => {
            app.rules.mode = Mode::Review(review);
            return false;
        }
        _ => {}
    }
    app.rules.mode = Mode::Review(review);
    true
}

// ── Line mode ────────────────────────────────────────────────────────────────

/// A number in the list as shown: `e 3` names the third visible rule.
fn numbered(app: &AppState, arg: &str) -> Option<usize> {
    let n: usize = arg.trim().parse().ok()?;
    app.rules.table.visible().get(n.checked_sub(1)?).copied()
}

fn list_line(app: &mut AppState, line: &str) -> bool {
    let (command, arg) = line.split_once(' ').unwrap_or((line, ""));
    let page = PAGE as isize;
    match command {
        "a" => {
            let mut form = Form::add();
            form.field = Field::Type;
            open_form(app, form);
        }
        "e" => {
            let master = numbered(app, arg);
            if let Some(i) = master {
                app.rules.table.select(i);
            }
            edit_selected(app, master);
            if let Mode::Form(form) = &mut app.rules.mode {
                form.field = Field::Type;
            }
        }
        "d" => {
            let master = numbered(app, arg);
            ask_delete(app, master);
        }
        "t" => {
            let master = numbered(app, arg);
            toggle(app, master);
        }
        "f" => ask(app, ChoicePurpose::Filter),
        "/" => {
            commit_input(
                app,
                Input {
                    purpose: InputPurpose::Search,
                    text: arg.to_owned(),
                },
            );
        }
        ">" => app.rules.table.move_cursor(page),
        "<" => app.rules.table.move_cursor(-page),
        "s" => start_apply(app),
        "r" => reload(app),
        "i" => start_input(app, InputPurpose::Import),
        "x" => start_input(app, InputPurpose::Export),
        "p" => presets(app),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests;

//! The Rules screen (the GUI's `RulesSection`, `RuleEditDialog` and review
//! flow): the list with its route filter and search; add, edit, delete,
//! switch on and off; the two rules files and the shipped rule sets; and the
//! apply through one "changes" view.

mod ace;
mod apply;
mod files;
mod folder;
mod form;
mod main_route;
mod own_settings;
mod render;
mod table;
mod text;
pub mod verdicts;

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::rules_table::search_box_text;
use nrr_shared::ipc_payloads::RulesListResponse;
use nrr_shared::rules_json::FREE_MAX_RULES;
use nrr_shared::rules_overlap::{find_route_overlaps, RouteOverlap};
use nrr_shared::user_settings::UserSettingsError;

use self::apply::{Failure, Finished, Previewed, Review};
use self::files::{Preset, RuleSet};
use self::form::{Field, Form, Saved};
use self::table::{RouteFilter, Table, PAGE};
use super::{overlaps, Screen, ScreenId};
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
    RulesFolder,
    /// The rule-set folder asked for before `?` rules move.
    VerdictFolder,
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
    Preset(SetList),
    Overwrite(PathBuf),
}

/// The rule sets offered, and where they came from.
#[derive(Debug, Default)]
pub struct SetList {
    pub sets: Vec<Preset>,
    /// The folder the sets were found in.
    pub folder: Option<PathBuf>,
    /// The user's own folder, when it holds no set and the shipped ones are
    /// offered instead.
    pub empty_own_folder: Option<PathBuf>,
    /// Why the settings file could not be read.
    pub settings_error: Option<String>,
    /// The remembered choice, `<source>:<label>`.
    pub selected: String,
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
    /// A sentence said after this one.
    pub then: Option<Box<Note>>,
}

impl Note {
    fn new(key: Key) -> Self {
        Self {
            key,
            args: Vec::new(),
            failure: None,
            then: None,
        }
    }

    fn with(key: Key, args: Vec<(&'static str, String)>) -> Self {
        Self {
            key,
            args,
            failure: None,
            then: None,
        }
    }

    fn failed(key: Key, failure: Failure) -> Self {
        Self {
            key,
            args: Vec::new(),
            failure: Some(failure),
            then: None,
        }
    }

    fn then(mut self, next: Note) -> Self {
        self.then = Some(Box::new(next));
        self
    }

    /// The failure fills an `{error}` the sentence has, else follows it.
    pub fn text(&self, texts: &Texts) -> String {
        let mut out = match &self.failure {
            Some(failure) if texts.get(self.key).contains("{error}") => {
                let mut args = self.args.clone();
                args.push(("error", failure.text(texts)));
                texts.fill(self.key, &args)
            }
            Some(failure) => texts.fill(self.key, &self.args) + &failure.text(texts),
            None => texts.fill(self.key, &self.args),
        };
        if let Some(next) = &self.then {
            out.push(' ');
            out.push_str(&next.text(texts));
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
    /// The settings file shared with the GUI; `None` when this session has no
    /// file of the user's own (under `sudo` the rules are the baseline's).
    pub settings_file: Option<PathBuf>,
    /// The files the rules on screen were last read from or written to, per
    /// route, as the settings file spells them; `""` is none.
    pub loaded_files: [String; 2],
    /// "My rules" in the reader's language: the name of a set with no other.
    pub my_rules: String,
    /// `?` rules that work only on the other route, waiting for an answer.
    pub verdicts: verdicts::Verdicts,
    /// Rules the service keeps but this build cannot read, so never applies.
    pub unrecognized: u32,
    /// The main-route check and whether its column is shown.
    pub main_route: main_route::MainRoute,
}

impl RulesState {
    fn my_rules_name(&self) -> &str {
        if self.my_rules.is_empty() {
            text::MY_RULES.en
        } else {
            &self.my_rules
        }
    }
}

/// The texts were loaded or changed language.
pub fn on_texts(app: &mut AppState, texts: &Texts) {
    app.rules.my_rules = texts.get(text::MY_RULES);
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
            text::HELP_FOLDER,
            text::HELP_RELOAD,
            text::HELP_VERDICTS,
            text::HELP_MAIN_ROUTE,
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
            text::PLAIN_FOLDER,
            text::PLAIN_RELOAD,
            text::PLAIN_VERDICTS,
            text::PLAIN_MAIN_ROUTE,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        load_if_needed(app);
        verdicts::load(app);
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
                    if input.purpose == InputPurpose::VerdictFolder {
                        verdicts::not_now(app);
                    }
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
                    refresh_form(app, &mut form);
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

/// Read the rules once, when nothing is on screen yet.
pub fn load_if_needed(app: &mut AppState) {
    let rules = &app.rules;
    if app.link.is_connected()
        && rules.busy.is_none()
        && !rules.table.is_loaded()
        && rules.table.rows.is_empty()
    {
        load(app);
    }
}

pub fn is_loading(app: &AppState) -> bool {
    matches!(app.rules.busy, Some(Busy::Loading))
}

/// Why the last read of the rules failed, in words.
pub fn load_failure(app: &AppState, texts: &Texts) -> Option<String> {
    app.rules.load_error.as_ref().map(|f| f.text(texts))
}

/// The list cannot change while it is applied or its changes are reviewed:
/// the apply marks what is on screen as applied.
pub fn edits_locked(app: &AppState) -> bool {
    app.rules.busy.is_some() || matches!(app.rules.mode, Mode::Review(_))
}

/// Rules of the two routes that cover the same sites, over the rules on
/// screen rather than the applied ones.
pub fn route_overlaps(app: &AppState) -> Vec<RouteOverlap> {
    find_route_overlaps(
        &apply::book_of(app.rules.table.rules()),
        include_subdomains(app),
    )
}

/// The reader's subdomain setting; absent means on, the product default.
fn include_subdomains(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .is_none_or(|p| p.include_subdomains)
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
            rules.unrecognized = list.unrecognized;
            rules.table.load(&list.rows);
            overlaps::refresh(app);
            verdicts::write_bound_files(app);
        }
        Err(failure) => {
            rules.load_error = Some(failure);
            rules.verdicts.rewrite_files = false;
        }
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

fn open_form(app: &mut AppState, mut form: Form) {
    if !locked(app) {
        refresh_form(app, &mut form);
        app.rules.mode = Mode::Form(Box::new(form));
    }
}

/// The form's overlap line follows the rule in it.
fn refresh_form(app: &AppState, form: &mut Form) {
    form.refresh_overlaps(&app.rules.table, include_subdomains(app));
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
        ChoicePurpose::Preset(list) => list
            .sets
            .iter()
            .position(|set| set.selection_key() == list.selected)
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
        InputPurpose::Import | InputPurpose::Export => files_input_start(app),
        InputPurpose::RulesFolder => folder::prompt_text(app),
        InputPurpose::VerdictFolder => String::new(),
    };
    if purpose == InputPurpose::Search || !locked(app) {
        app.rules.mode = Mode::Input(Input { purpose, text });
    }
}

/// The user's rule-set folder, ready for a set name; else where the terminal
/// is.
fn files_input_start(app: &AppState) -> String {
    let own = app
        .rules
        .settings_file
        .as_deref()
        .and_then(own_settings::rules_folder);
    match own {
        Some(folder) => folder.join("").display().to_string(),
        None => std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default(),
    }
}

fn presets(app: &mut AppState) {
    if locked(app) {
        return;
    }
    let list = set_list(app.rules.settings_file.as_deref());
    if list.sets.is_empty() {
        app.rules.note = Some(Note::new(text::NO_PRESETS));
    } else {
        ask(app, ChoicePurpose::Preset(list));
    }
}

/// The GUI's choice of list: the sets in the user's folder, or — when there is
/// no folder or nothing in it — the shipped ones.
fn set_list(settings_file: Option<&Path>) -> SetList {
    let (settings, settings_error) = match settings_file.map(own_settings::read) {
        None => (Default::default(), None),
        Some(Ok(settings)) => (settings, None),
        Some(Err(error)) => (Default::default(), Some(error.to_string())),
    };
    let own = own_settings::own_folder(&settings);
    if let Some(folder) = own.as_ref() {
        let sets = files::user_sets(folder);
        if !sets.is_empty() {
            return SetList {
                sets,
                folder: own,
                empty_own_folder: None,
                settings_error,
                selected: settings.selected_set,
            };
        }
    }
    let shipped = files::presets_root();
    SetList {
        sets: shipped
            .as_deref()
            .map(files::presets_in)
            .unwrap_or_default(),
        folder: shipped,
        empty_own_folder: own,
        settings_error,
        selected: settings.selected_set,
    }
}

/// Remembers a picked set in the shared settings; only a failure is said.
fn remember_set(app: &mut AppState, set: &Preset) {
    let Some(file) = app.rules.settings_file.as_deref() else {
        return;
    };
    if let Err(error) = own_settings::remember_set(file, &set.selection_key()) {
        app.rules.note = Some(Note::with(
            text::SETTINGS_NOT_WRITTEN,
            vec![("error", error.to_string())],
        ));
    }
}

fn save_form(app: &mut AppState, mut form: Box<Form>) {
    let saved = form.save(&mut app.rules.table);
    let note = match saved {
        Saved::Added { enabled: true } => text::RULE_ADDED,
        Saved::Added { enabled: false } => text::RULE_ADDED_DISABLED,
        Saved::Updated => text::RULE_UPDATED,
        Saved::Refused | Saved::Duplicate(_) => {
            refresh_form(app, &mut form);
            app.rules.mode = Mode::Form(form);
            return;
        }
        Saved::Limit => {
            app.rules.note = Some(Note::with(
                text::LIMIT_REACHED,
                vec![("max", FREE_MAX_RULES.to_string())],
            ));
            refresh_form(app, &mut form);
            app.rules.mode = Mode::Form(form);
            return;
        }
    };
    app.rules.note = Some(Note::new(note));
    let table = &app.rules.table;
    let row = match saved {
        Saved::Added { .. } => table.rows.last(),
        _ => form.editing.and_then(|i| table.rows.get(i)),
    };
    if let Some(id) = row.map(|r| r.rule.id.clone()) {
        overlaps::confirm_own_edit(app, &id);
    }
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
        InputPurpose::RulesFolder => folder::choose(app, &input.text),
        InputPurpose::VerdictFolder => verdicts::folder_answered(app, &input.text),
    }
}

/// The folder prompt; a session with no settings of its own says why not.
fn start_folder_input(app: &mut AppState) {
    if app.rules.settings_file.is_none() {
        app.rules.note = Some(Note::new(text::FOLDER_UNAVAILABLE));
    } else {
        start_input(app, InputPurpose::RulesFolder);
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
    let mut note = Note::with(
        text::IMPORTED,
        vec![("count", added.to_string()), ("path", path)],
    );
    if let Err(error) = bind_imported(app, &set.paths) {
        note = note.then(Note::with(
            text::SETTINGS_NOT_WRITTEN,
            vec![("error", error.to_string())],
        ));
    }
    app.rules.note = Some(note);
}

/// The files read become where the rules come from and, outside the shipped
/// tree, the user's rules files, as a load does in the GUI.
fn bind_imported(
    app: &mut AppState,
    paths: &[Option<PathBuf>; 2],
) -> Result<(), UserSettingsError> {
    let read = own_settings::imported_texts(paths);
    for (slot, path) in app.rules.loaded_files.iter_mut().zip(read) {
        if let Some(path) = path {
            *slot = path;
        }
    }
    let Some(file) = app.rules.settings_file.as_deref() else {
        return Ok(());
    };
    own_settings::bind_imported(file, paths, files::presets_root().as_deref())
}

/// Writes both files, then binds them as the user's rules files, as the GUI
/// does after every write.
fn export(app: &mut AppState, path: &Path) {
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if let Err((file, error)) = files::write_set(path, &app.rules.table, &exported_at) {
        let file = file.display().to_string();
        let note = Note::with(text::WRITE_FAILED, vec![("path", file), ("error", error)]);
        app.rules.note = Some(note);
        return;
    }
    app.rules.loaded_files = folder::written_texts(path);
    let shown = path.display().to_string();
    app.rules.note = Some(match bind_written_set(app, path) {
        Ok(()) => Note::with(text::EXPORTED, vec![("path", shown)]),
        Err(error) => Note::with(
            text::EXPORTED_UNBOUND,
            vec![("path", shown), ("error", error.to_string())],
        ),
    });
}

fn bind_written_set(app: &AppState, dir: &Path) -> Result<(), UserSettingsError> {
    let Some(file) = app.rules.settings_file.as_deref() else {
        return Ok(());
    };
    own_settings::bind_written_set(file, dir, files::presets_root().as_deref())
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
        ChoicePurpose::Preset(list) => {
            if let Some(preset) = list.sets.get(at) {
                match files::read_set(&preset.dir) {
                    Err((file, error)) => app.rules.note = Some(read_failed(&file, error)),
                    Ok(set) => {
                        offer_import(app, set, preset.label.clone());
                        remember_set(app, preset);
                    }
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
            'o' => start_folder_input(app),
            'm' => return verdicts::move_all(app),
            'n' => return verdicts::not_now(app),
            'c' => return main_route::start(app),
            'O' => change_order(app),
            _ => return false,
        },
        _ => return false,
    }
    true
}

/// The other order; the cursor goes back to the top, as a new filter does.
fn change_order(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.sort = table.sort.next();
    table.cursor = 0;
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
        KeyCode::Esc => {
            if input.purpose == InputPurpose::VerdictFolder {
                verdicts::not_now(app);
            }
        }
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
    refresh_form(app, &mut form);
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
        "o" => start_folder_input(app),
        "m" => return verdicts::move_all(app),
        "n" => return verdicts::not_now(app),
        "c" => return main_route::start(app),
        "O" => change_order(app),
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests;

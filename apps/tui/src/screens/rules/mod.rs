//! The Rules screen (the GUI's `RulesSection`, `RuleEditDialog` and review
//! flow): the list with its route filter and search; add, edit, delete,
//! switch on and off; the two rules files and the shipped rule sets; and the
//! apply through one "changes" view.

mod ace;
pub mod app_routes;
mod apply;
mod bulk;
mod coverage;
mod file_merge;
mod files;
mod folder;
mod form;
mod gateway;
mod main_route;
mod merge;
pub mod overrides;
pub(crate) mod own_settings;
mod recent;
mod render;
mod spare;
mod table;
mod text;
pub mod verdicts;

pub use bulk::start_moving;
pub use files::presets_root;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::rule_value_class::misplaced_target_type;
use nrr_client_logic::rules_table::{search_box_text, RuleRow, RuleType, TargetRoute};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{RulesListResponse, RULES_CHANGED_ELSEWHERE};
use nrr_shared::merge_dto::MergePolicyDto;
use nrr_shared::rules_json::FREE_MAX_RULES;
use nrr_shared::rules_overlap::{find_route_overlaps, RouteOverlap};
use nrr_shared::user_settings::{UserSettings, UserSettingsError, UserSettingsStore};

use self::apply::{Failure, Finished, Previewed, Review};
use self::files::{Preset, RuleSet};
use self::form::{offered_types, Field, Form, Saved};
use self::table::{RouteFilter, StatusFilter, Table, PAGE, TYPE_FILTERS};
use super::{overlaps, Screen, ScreenId};
use crate::i18n::{Key, Plural, Texts};
use crate::paste::TextTarget;
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
    /// `v`: a rule for a VPN's gateway.
    Gateway(Box<gateway::Stage>),
    /// `A`: several rules at once, as lines of a rules file.
    Bulk(Box<bulk::BulkForm>),
    /// `P`: a protected rule confirmed to apply despite the protection.
    Override(Box<overrides::Confirm>),
    /// Edits over the rules changed elsewhere, to be picked through.
    Merge(Box<merge::Merge>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPurpose {
    Search,
    Import,
    Export,
    RulesFolder,
    /// The rule-set folder asked for before `?` rules move.
    VerdictFolder,
    /// The file one route's rules are written to.
    ExportRoute(nrr_client_logic::Route),
}

/// Where a write goes: a set's folder, or one route's file.
#[derive(Debug)]
pub enum SaveTarget {
    Set(PathBuf),
    Route(nrr_client_logic::Route, PathBuf),
}

impl SaveTarget {
    fn folder(&self) -> &Path {
        match self {
            Self::Set(dir) => dir,
            Self::Route(_, file) => file.parent().unwrap_or(file),
        }
    }

    fn exists(&self) -> bool {
        match self {
            Self::Set(dir) => files::set_exists(dir),
            Self::Route(_, file) => file.exists(),
        }
    }

    pub fn shown(&self) -> String {
        match self {
            Self::Set(path) | Self::Route(_, path) => path.display().to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Input {
    pub purpose: InputPurpose,
    pub text: String,
}

#[derive(Debug)]
pub enum ChoicePurpose {
    Filter,
    StatusFilter,
    TypeFilter,
    Delete(usize),
    Reload,
    Quit,
    ImportMode {
        set: Box<RuleSet>,
        path: String,
    },
    Preset(SetList),
    Overwrite(SaveTarget),
    /// The write would go into the tree shipped with the program.
    Shipped(SaveTarget),
    /// `X`: which route's rules to save.
    ExportRoute,
    /// `W`: every rule goes.
    ClearAll,
    /// The import's questions about its sections, one at a time.
    ImportReview(Box<ReviewFlow>),
    /// `B`: what to do with the selected rules.
    Marked,
    /// The selected rules go, asked first.
    DeleteMarked,
    Recent,
    Restore(usize),
    /// Bound files edited by hand since this program wrote them, which a
    /// write of the rules in force would have replaced: take them or replace
    /// them.
    HandEdited(Vec<(nrr_client_logic::Route, PathBuf)>),
    /// The apply was refused as built on rules no longer in force: put the
    /// edits on top of the rules now in force, or keep the list as it is.
    ChangedElsewhere,
    /// `C`: remove the rules a wildcard of the same route already covers.
    RemoveSpare(Vec<spare::Spare>),
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

/// An import waiting for the answers about its sections.
#[derive(Debug)]
pub struct ReviewFlow {
    pub set: RuleSet,
    pub path: String,
    /// The question asked now.
    pub at: usize,
    pub duplicates: BTreeMap<String, files::DuplicateChoice>,
    pub unknown: BTreeMap<String, files::UnknownChoice>,
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
    /// Said in the plural form `count` takes, instead of `key`.
    pub counted: Option<(Plural, usize)>,
}

impl Note {
    fn new(key: Key) -> Self {
        Self {
            key,
            args: Vec::new(),
            failure: None,
            then: None,
            counted: None,
        }
    }

    fn with(key: Key, args: Vec<(&'static str, String)>) -> Self {
        Self {
            args,
            ..Self::new(key)
        }
    }

    fn failed(key: Key, failure: Failure) -> Self {
        Self {
            failure: Some(failure),
            ..Self::new(key)
        }
    }

    fn counted(plural: Plural, count: usize) -> Self {
        Self {
            counted: Some((plural, count)),
            ..Self::new(Key {
                id: plural.stem,
                en: plural.other,
            })
        }
    }

    fn then(mut self, next: Note) -> Self {
        self.then = Some(Box::new(next));
        self
    }

    /// The failure fills an `{error}` the sentence has, else follows it.
    pub fn text(&self, texts: &Texts) -> String {
        let mut out = match (&self.failure, self.counted) {
            (_, Some((plural, count))) => texts.counted(plural, count),
            (Some(failure), None) if texts.get(self.key).contains("{error}") => {
                let mut args = self.args.clone();
                args.push(("error", failure.text(texts)));
                texts.fill(self.key, &args)
            }
            (Some(failure), None) => texts.fill(self.key, &self.args) + &failure.text(texts),
            (None, None) => texts.fill(self.key, &self.args),
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
    /// The terminal runs with administrator rights, which pass the lock below.
    pub elevated: bool,
    /// An administrator turned rule editing off for this machine: the list
    /// is read-only here, as the service would refuse any change.
    pub admin_locked: bool,
    /// The quit question chose "apply, then quit".
    quit_after_apply: bool,
    /// The settings file shared with the GUI; `None` when this session has no
    /// file of the user's own (under `sudo` the rules are the baseline's).
    pub settings_file: Option<PathBuf>,
    /// The files the rules on screen were last read from or written to, per
    /// route, as the settings file spells them; `""` is none.
    pub loaded_files: [String; 2],
    /// The rules files the settings file binds, main route first, for the
    /// line that says where the rules are saved; read when the list is read
    /// or the binding written, never per frame.
    pub bound_paths: Vec<String>,
    /// The settings file's stamp when this terminal last read it on the tick.
    pub settings_stamp: String,
    /// The rule-set folder was offered this run.
    pub folder_offered: bool,
    /// The demo rules are read in Russian.
    pub demo_russian: bool,
    /// The two routes' names in the reader's language, main first.
    pub route_names: [String; 2],
    /// "+{n} more" after the names a sentence lists, in the reader's language.
    pub list_more: String,
    /// The preview or confirm in flight is the reset to the baseline.
    resetting: bool,
    /// The folder offer's title, question and how-to, in the reader's language.
    pub folder_offer_words: [String; 3],
    /// "My rules" in the reader's language: the name of a set with no other.
    pub my_rules: String,
    /// `?` rules that work only on the other route, waiting for an answer.
    pub verdicts: verdicts::Verdicts,
    /// Rules the service keeps but this build cannot read, so never applies.
    pub unrecognized: u32,
    /// The main-route check and whether its column is shown.
    pub main_route: main_route::MainRoute,
    /// The comment a VPN-gateway rule gets, in the reader's language.
    pub gateway_comment: String,
    /// The syntax hint a written rules file opens with, in the reader's
    /// language.
    pub file_hint: Vec<String>,
    /// The `base-revision` of the rules on screen: what the next apply is
    /// built on. `None` until a read names it.
    pub base_revision: Option<String>,
    /// The caller's rules applied despite the protection of system programs,
    /// by [`overrides::key_of`], as the last snapshot listed them.
    pub overrides: std::collections::HashMap<String, nrr_shared::ipc_payloads::RuleOverrideDto>,
    /// An add form another screen asked for while the list was being read;
    /// it opens once the list is in, so the read cannot replace the rule.
    prefilled: Option<Box<Form>>,
    /// The rules changed elsewhere while the list was not free to be re-read;
    /// it is re-read once it is ([`settle`]).
    reread_due: bool,
    /// Line mode: the visible rules as last printed (`merge_key`), so `t 3`
    /// switches the rule the user read as the third.
    printed: Vec<String>,
    /// Edits waiting for the re-read they are laid over, then reviewed.
    rebase: Option<table::Edits>,
    /// The payload under review is not the rows on screen (the bound files
    /// merged with the service's rules): once it is in force the rows are
    /// read back instead of being marked applied.
    reload_after_apply: bool,
    /// The bound files and the texts that merge was built from: once it is in
    /// force, those versions are the program's to follow.
    merged_from: Vec<(PathBuf, String)>,
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
    super::app_groups::on_texts(app, texts);
    app.rules.my_rules = texts.get(text::MY_RULES);
    app.rules.gateway_comment = texts.get(text::GATEWAY_COMMENT);
    app.rules.demo_russian = texts.language().starts_with("ru");
    app.rules.route_names = [
        texts.get(text::ROUTE_PRIMARY),
        texts.get(text::ROUTE_SECONDARY),
    ];
    app.rules.list_more = texts.get(text::LIST_MORE);
    app.rules.folder_offer_words = [
        texts.get(text::FOLDER_OFFER_TITLE),
        texts.get(text::FOLDER_OFFER),
        texts.get(text::FOLDER_OFFER_HOW),
    ];
    app.rules.file_hint = text::file_hint_keys()
        .into_iter()
        .map(|k| texts.get(k))
        .collect();
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
            text::HELP_FILTERS,
            text::HELP_APPLY,
            text::HELP_FILES,
            text::HELP_MORE_FILES,
            text::HELP_RESET,
            text::HELP_MARK,
            text::HELP_FOLDER,
            text::HELP_RELOAD,
            text::HELP_BOOK,
            text::HELP_VERDICTS,
            text::HELP_MOVE_TO_TYPE,
            text::HELP_MAIN_ROUTE,
            text::HELP_GATEWAY,
            text::HELP_APP_GROUPS,
            text::HELP_FILES_MERGE,
            text::HELP_SPARE,
            text::HELP_FORM,
            text::HELP_BULK,
            text::HELP_RECENT,
            text::HELP_OVERRIDE,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            text::PLAIN_ADD,
            text::PLAIN_EDIT,
            text::PLAIN_DELETE,
            text::PLAIN_TOGGLE,
            text::PLAIN_FILTER,
            text::PLAIN_FILTERS,
            text::PLAIN_SEARCH,
            text::PLAIN_PAGES,
            text::PLAIN_APPLY,
            text::PLAIN_FILES,
            text::HELP_MORE_FILES,
            text::HELP_RESET,
            text::HELP_MARK,
            text::PLAIN_FOLDER,
            text::PLAIN_RELOAD,
            text::PLAIN_BOOK,
            text::PLAIN_VERDICTS,
            text::PLAIN_MAIN_ROUTE,
            text::PLAIN_GATEWAY,
            text::PLAIN_APP_GROUPS,
            text::PLAIN_FILES_MERGE,
            text::PLAIN_SPARE,
            text::PLAIN_BULK,
            text::PLAIN_MOVE_TO_TYPE,
            text::PLAIN_RECENT,
            text::PLAIN_OVERRIDE,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        refresh_bound_paths(app);
        load_if_needed(app);
        verdicts::load(app);
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        !matches!(app.rules.mode, Mode::List)
    }

    fn text_target(&self, app: &AppState) -> TextTarget {
        match &app.rules.mode {
            Mode::Input(_) => TextTarget::Line,
            Mode::Form(form) if matches!(form.field, Field::Value | Field::Comment) => {
                TextTarget::Line
            }
            Mode::Bulk(form) if form.field == bulk::BulkField::Text => TextTarget::Lines,
            _ => TextTarget::None,
        }
    }

    fn on_paste(&self, app: &mut AppState, pasted: &str) -> bool {
        let Mode::Bulk(form) = &mut app.rules.mode else {
            return false;
        };
        if form.field != bulk::BulkField::Text {
            return false;
        }
        let left = form.paste(pasted);
        if left > 0 {
            app.rules.note = Some(Note::with(
                text::BULK_PASTE_CUT,
                vec![("count", left.to_string())],
            ));
        }
        true
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        let handled = match std::mem::take(&mut app.rules.mode) {
            Mode::List => list_key(app, key),
            Mode::Input(input) => input_key(app, input, key),
            Mode::Form(form) => form_key(app, form, key),
            Mode::Choice(choice) => choice_key(app, choice, key),
            Mode::Review(review) => review_key(app, review, key),
            Mode::Gateway(stage) => gateway::on_key(app, *stage, key),
            Mode::Bulk(form) => bulk::on_key(app, form, key),
            Mode::Override(confirm) => overrides::on_key(app, confirm, key),
            Mode::Merge(merge) => merge::on_key(app, merge, key),
        };
        settle(app);
        handled
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let handled = line_in_mode(app, line);
        settle(app);
        handled
    }

    fn on_printed(&self, app: &mut AppState) {
        let table = &app.rules.table;
        app.rules.printed = table
            .visible()
            .iter()
            .map(|&i| table.rows[i].rule.merge_key())
            .collect();
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
            Mode::Gateway(stage) => gateway::plain_prompt(stage),
            Mode::Bulk(form) => Some(bulk::plain_prompt(form)),
            Mode::Override(confirm) => Some(overrides::plain_prompt(confirm)),
            Mode::Merge(_) => Some(text::MERGE_PLAIN_PROMPT),
        }
    }
}

/// A line typed in `--plain`, by what the screen is doing.
fn line_in_mode(app: &mut AppState, line: &str) -> bool {
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
            if line == "!t" {
                form.switch_type();
                refresh_form(app, &mut form);
                app.rules.mode = Mode::Form(form);
                return true;
            }
            if line == "!f" {
                form.toggle_scope();
                refresh_form(app, &mut form);
                app.rules.mode = Mode::Form(form);
                return true;
            }
            // The number past the last type: several rules instead.
            let several = (offered_types().len() + 1).to_string();
            if form.editing.is_none() && form.field == Field::Type && line == several {
                return bulk::start(app, form.route.clone(), form.value.clone(), true);
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
                "n" | "N" => app.rules.quit_after_apply = false,
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
        Mode::Gateway(stage) => {
            gateway::on_line(app, *stage, line);
            true
        }
        Mode::Bulk(form) => {
            if line != "!" {
                bulk::on_line(app, form, line);
            }
            true
        }
        Mode::Override(confirm) => {
            if line != "!" {
                overrides::on_line(app, confirm, line);
            }
            true
        }
        Mode::Merge(merge) => {
            if line == "!" {
                merge::on_line(app, merge, "n");
            } else {
                merge::on_line(app, merge, line);
            }
            true
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
    app.rules.busy.is_some() || matches!(app.rules.mode, Mode::Review(_) | Mode::Merge(_))
}

/// Rules of the two routes that cover the same sites, over the rules on
/// screen rather than the applied ones. `None`: the rule set is one the wire
/// refuses, so there is nothing to compare.
pub fn route_overlaps(app: &AppState) -> Option<Vec<RouteOverlap>> {
    apply::book_of(app.rules.table.rules())
        .map(|book| find_route_overlaps(&book, include_subdomains(app)))
        .ok()
}

/// The reader's subdomain setting; absent means on, the product default.
fn include_subdomains(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .is_none_or(|p| p.include_subdomains)
}

/// Open the question "apply / discard / stay" on this screen.
/// Whether the "apply / discard / stay" question is already on screen.
pub fn quit_question_open(app: &AppState) -> bool {
    matches!(
        &app.rules.mode,
        Mode::Choice(Choice {
            purpose: ChoicePurpose::Quit,
            ..
        })
    )
}

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
/// service's own additions, a reset): reread once the list is free.
pub fn on_revision_changed(app: &mut AppState) {
    reread_when_free(app);
}

/// The service wrote rules for an answer given here (an accepted suggestion,
/// a blocked site routed): the bound files follow once they are read back.
pub fn rules_written_for_an_answer(app: &mut AppState) {
    app.rules.verdicts.rewrite_files = true;
    load_if_needed(app);
    on_revision_changed(app);
}

/// Nothing on screen holds a row number into the list or edits it: no
/// edits, no service call, no form or question open.
fn list_is_free(app: &AppState) -> bool {
    let rules = &app.rules;
    rules.table.is_loaded()
        && !rules.table.is_dirty()
        && rules.busy.is_none()
        && matches!(rules.mode, Mode::List)
        && app.link.is_connected()
}

/// Re-read now, or as soon as the list is free: a form open over a row, or
/// a delete question, would otherwise land on whatever rule the re-read put
/// at that row.
fn reread_when_free(app: &mut AppState) {
    if list_is_free(app) {
        load(app);
    } else {
        app.rules.reread_due = true;
    }
}

/// The re-read that waited for the list, once nothing holds it.
fn settle(app: &mut AppState) {
    if app.rules.reread_due && list_is_free(app) {
        load(app);
    }
}

// ── Answers from the service ────────────────────────────────────────────────

fn load(app: &mut AppState) {
    app.rules.busy = Some(Busy::Loading);
    // Ahead of the list, so a form waiting for it opens knowing the lock.
    if nrr_shared::platform_profile::PlatformProfile::current()
        .supports
        .service_stability_config
    {
        app.outbox.push(apply::edit_permission_job());
    }
    app.outbox.push(apply::load_job(app.rules.baseline));
}

/// Take the administrator's lock out of a service-stability row, whichever
/// screen read it.
pub fn adopt_edit_permission(
    app: &mut AppState,
    config: &serde_json::Map<String, serde_json::Value>,
) {
    app.rules.admin_locked =
        nrr_client_logic::stability::rule_edits_locked(config, app.rules.elevated);
}

/// Refuse a change to the rules while the administrator's lock is on, and
/// say why. Viewing, searching, filtering and exporting stay open.
fn refuse_when_admin_locked(app: &mut AppState) -> bool {
    if app.rules.admin_locked {
        app.rules.note = Some(Note::new(text::LOCKED));
        return true;
    }
    false
}

/// The list's keys and line commands that change rules.
fn changes_rules(command: &str) -> bool {
    const CHANGING: &[&str] = &[
        "a", "e", "d", "s", "i", "p", "m", "v", "F", "C", "T", "M", "A", "U", "P", "L", "W", "Z",
        "B",
    ];
    CHANGING.contains(&command)
}

/// The window writes the settings file too. Called on the idle tick: when the
/// file's stamp moved, what this terminal shows from it is read again, and
/// `true` asks for a redraw.
pub fn follow_settings_file(app: &mut AppState) -> bool {
    let Some(file) = app.rules.settings_file.clone() else {
        return false;
    };
    let stamp = UserSettingsStore::at(file.clone()).stamp();
    if stamp == app.rules.settings_stamp {
        return false;
    }
    app.rules.settings_stamp = stamp;
    let settings = own_settings::read(&file);
    app.rules.bound_paths = bound_paths_of(Some(&settings));
    if let Ok(settings) = &settings {
        app.settings.merge_policy = MergePolicyDto::from_slug(&settings.merge_policy);
    }
    crate::window_parked::refresh(app);
    true
}

/// The window may bind other files at any time: the settings file is shared.
fn refresh_bound_paths(app: &mut AppState) {
    let settings = app.rules.settings_file.as_deref().map(own_settings::read);
    app.rules.bound_paths = bound_paths_of(settings.as_ref());
}

/// Each route's sections this build does not apply, as its bound file holds
/// them now: what a rewrite of the file would carry.
pub(crate) fn bound_passthrough(app: &mut AppState) -> [BTreeMap<String, String>; 2] {
    let rules = &mut app.rules;
    files::take_bound_passthrough(&mut rules.table, rules.settings_file.as_deref());
    rules.table.passthrough.clone()
}

fn bound_paths_of(settings: Option<&Result<UserSettings, UserSettingsError>>) -> Vec<String> {
    match settings {
        Some(Ok(settings)) => [
            &settings.rules_files.primary,
            &settings.rules_files.secondary,
        ]
        .into_iter()
        .filter(|path| !path.is_empty())
        .cloned()
        .collect(),
        _ => Vec::new(),
    }
}

fn loaded(app: &mut AppState, result: Result<RulesListResponse, Failure>) {
    refresh_bound_paths(app);
    let rules = &mut app.rules;
    rules.busy = None;
    rules.reread_due = false;
    let mut rebased = false;
    match result {
        Ok(list) => {
            rules.load_error = None;
            let view = rules.rebase.as_ref().map(|edits| edits.preview(&list.rows));
            match (rules.rebase.take(), view) {
                // The edits stay on screen, standing on the revision they were
                // made against, until the user has picked.
                (Some(edits), Some(view)) if !view.is_noop() => {
                    rules.mode = Mode::Merge(Box::new(merge::Merge::new(
                        edits,
                        list.rows.clone(),
                        list.base_revision.clone(),
                        list.unrecognized,
                        view,
                    )));
                    return;
                }
                (edits, _) => {
                    rules.unrecognized = list.unrecognized;
                    rules.base_revision = list.base_revision.clone();
                    rules.table.load(&list.rows);
                    files::take_bound_passthrough(&mut rules.table, rules.settings_file.as_deref());
                    if let Some(edits) = edits {
                        rules.table.apply_edits(edits, &[]);
                        rules.note = Some(Note::new(text::REBASED));
                        rebased = true;
                    }
                }
            }
            overlaps::refresh(app);
            verdicts::write_bound_files(app);
            file_merge::check_drift(app);
            // The set the service holds was read again: an apply may be in it.
            recent::refresh(app);
        }
        Err(failure) => {
            rules.load_error = Some(failure);
            rules.verdicts.rewrite_files = false;
            // The edits are still on screen, the table was not replaced.
            rules.rebase = None;
        }
    }
    if let Some(form) = app.rules.prefilled.take() {
        if app.rules.load_error.is_none() && matches!(app.rules.mode, Mode::List) {
            open_form(app, *form);
        }
    }
    // The edits now stand on the rules in force; the review shows the result.
    if rebased {
        start_apply(app);
    }
}

/// The rules changed elsewhere since the list was read: the refusal is a
/// question, not only a sentence.
fn changed_elsewhere(failure: &Failure) -> bool {
    matches!(failure, Failure::Code { code, .. } if code == RULES_CHANGED_ELSEWHERE)
}

/// "Put my edits on top": the edits are kept aside, the rules in force read,
/// and the edits laid over them in [`loaded`].
fn rebase_edits(app: &mut AppState) {
    if !app.link.is_connected() {
        app.rules.note = Some(Note::new(text::APPLY_OFFLINE));
        return;
    }
    app.rules.rebase = Some(app.rules.table.edits());
    load(app);
}

fn previewed(app: &mut AppState, previewed: Previewed) {
    let rules = &mut app.rules;
    rules.busy = None;
    if rules.resetting {
        match previewed {
            Previewed::Review(review) => rules.mode = Mode::Review(review),
            Previewed::NothingToApply => {
                rules.resetting = false;
                rules.note = Some(Note::new(text::RESET_NOOP));
            }
            Previewed::Refused(failure) => {
                rules.resetting = false;
                rules.note = Some(Note::failed(text::RESET_FAILED, failure));
            }
        }
        return;
    }
    if !matches!(previewed, Previewed::Review(_)) {
        rules.reload_after_apply = false;
        rules.merged_from.clear();
    }
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
            if changed_elsewhere(&failure) {
                ask(app, ChoicePurpose::ChangedElsewhere);
                return;
            }
            rules.note = Some(Note::failed(text::ACTIVATE_FAILED, failure));
        }
    }
}

fn finished(app: &mut AppState, finished: Finished) {
    if std::mem::take(&mut app.rules.resetting) {
        reset_finished(app, finished);
        return;
    }
    let rules = &mut app.rules;
    rules.busy = None;
    let quit = std::mem::take(&mut rules.quit_after_apply);
    let applied = matches!(finished, Finished::Applied { .. });
    let reload = std::mem::take(&mut rules.reload_after_apply);
    let merged_from = std::mem::take(&mut rules.merged_from);
    if applied && reload {
        // The user merged these files into the rules now in force.
        if let Some(file) = rules.settings_file.as_deref() {
            let _ = own_settings::note_taken(file, &merged_from);
        }
    }
    rules.note = Some(match finished {
        Finished::Applied { base } => {
            // The next apply is built on what this one left in force.
            rules.base_revision = base;
            if reload {
                // The files are written from the rules read back.
                rules.verdicts.rewrite_files = true;
                rules.reread_due = true;
            } else {
                rules.table.mark_applied();
            }
            app.snapshot_refresh_due = true;
            if quit {
                app.quit = true;
            }
            Note::new(text::ACTIVATED)
        }
        // The edits stay on screen: nothing was applied.
        Finished::Expired => Note::new(text::EXPIRED),
        Finished::UacDeclined => Note::new(text::UAC_DECLINED),
        Finished::Failed(failure) => {
            if changed_elsewhere(&failure) {
                rules.mode = Mode::Choice(Choice {
                    purpose: ChoicePurpose::ChangedElsewhere,
                    cursor: 0,
                });
            }
            Note::failed(text::ACTIVATE_FAILED, failure)
        }
    });
    if applied && !reload {
        // The bound files follow the rules in force, or the tray reverts them.
        let note = app.rules.note.take();
        verdicts::write_bound_files_now(app);
        app.rules.note = app.rules.note.take().or(note);
        // What was applied is read back in the service's own spelling: a set
        // remembered as typed cannot name the rule the next edit deletes.
        app.rules.reread_due = true;
    }
    settle(app);
}

/// The baseline applies now: the list is read back. The user's rules files
/// are not rewritten — they are the user's copy of what was dropped.
fn reset_finished(app: &mut AppState, finished: Finished) {
    let rules = &mut app.rules;
    rules.busy = None;
    rules.quit_after_apply = false;
    let applied = matches!(finished, Finished::Applied { .. });
    rules.note = Some(match finished {
        Finished::Applied { base } => {
            rules.base_revision = base;
            app.snapshot_refresh_due = true;
            Note::new(text::RESET_DONE)
        }
        Finished::Expired => Note::new(text::EXPIRED),
        Finished::UacDeclined => Note::new(text::UAC_DECLINED),
        Finished::Failed(failure) => Note::failed(text::RESET_FAILED, failure),
    });
    if applied {
        load(app);
    }
}

// ── Actions ─────────────────────────────────────────────────────────────────

/// `Z`: back to the administrator's baseline. The service shows what goes
/// before anything does; the review's confirm is the user's answer.
fn start_reset(app: &mut AppState) {
    if locked(app) || !own_rules_on_screen(app) {
        return;
    }
    if !app.link.is_connected() {
        app.rules.note = Some(Note::new(text::APPLY_OFFLINE));
        return;
    }
    app.rules.resetting = true;
    app.rules.busy = Some(Busy::Previewing);
    app.rules.note = None;
    app.outbox.push(apply::preview_job(apply::reset_pending()));
}

/// Edits wait while the service is busy with this list.
fn locked(app: &mut AppState) -> bool {
    if app.rules.busy.is_some() {
        app.rules.note = Some(Note::new(text::BUSY));
        return true;
    }
    false
}

fn start_apply(app: &mut AppState) {
    if locked(app) || refuse_when_admin_locked(app) {
        return;
    }
    if !app.link.is_connected() {
        app.rules.quit_after_apply = false;
        app.rules.note = Some(Note::new(text::APPLY_OFFLINE));
        return;
    }
    let pending = match apply::pending_from(
        &app.rules.table,
        app.rules.baseline,
        app.rules.base_revision.as_deref(),
    ) {
        Ok(pending) => pending,
        Err(failure) => {
            app.rules.note = Some(Note::failed(text::ACTIVATE_FAILED, failure));
            return;
        }
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
    if !locked(app) && !refuse_when_admin_locked(app) {
        refresh_form(app, &mut form);
        app.rules.mode = Mode::Form(Box::new(form));
    }
}

/// The form's overlap line follows the rule in it, and its count of what a
/// rule by path covers is asked again once the value rests.
fn refresh_form(app: &mut AppState, form: &mut Form) {
    form.refresh_overlaps(&app.rules.table, include_subdomains(app));
    coverage::schedule(app, form);
}

fn edit_selected(app: &mut AppState, master: Option<usize>) {
    if let Some(form) = master.and_then(|i| Form::edit(&app.rules.table, i)) {
        open_form(app, form);
    }
}

fn toggle(app: &mut AppState, master: Option<usize>) {
    if locked(app) || refuse_when_admin_locked(app) {
        return;
    }
    if let Some(row) = master.and_then(|i| app.rules.table.rows.get_mut(i)) {
        row.rule.enabled = !row.rule.enabled;
    }
}

/// Gives the chosen rule the type its value is, when its verdict says the
/// value belongs to another; only on this key, never on its own. `false` when
/// the row has no such offer, so the key does nothing else.
fn move_to_type(app: &mut AppState, master: Option<usize>) -> bool {
    let offered = master
        .and_then(|i| app.rules.table.rows.get(i))
        .is_some_and(|row| misplaced_target_type(&row.verdict.message_key).is_some());
    if !offered {
        return false;
    }
    if !locked(app) && master.is_some_and(|i| refile_row(&mut app.rules.table.rows[i])) {
        if let Some(i) = master {
            app.rules.table.keep_chosen(i);
        }
        app.rules.note = Some(Note::new(text::RULE_UPDATED));
    }
    true
}

/// Every rule with that offer, moved at once; `false` when there is none.
fn move_all_to_type(app: &mut AppState) -> bool {
    let offered = app
        .rules
        .table
        .rows
        .iter()
        .any(|row| misplaced_target_type(&row.verdict.message_key).is_some());
    if !offered {
        return false;
    }
    if !locked(app) {
        let mut moved = false;
        for row in &mut app.rules.table.rows {
            moved |= refile_row(row);
        }
        if moved {
            app.rules.note = Some(Note::new(text::RULE_UPDATED));
        }
    }
    true
}

/// The row under the type its verdict names, judged again there.
fn refile_row(row: &mut table::Row) -> bool {
    let Some(target) = misplaced_target_type(&row.verdict.message_key) else {
        return false;
    };
    let refiled = table::Row::new(RuleRow {
        rule_type: RuleType::from_slug(target),
        ..row.rule.clone()
    });
    row.rule = refiled.rule;
    row.ace_lower = refiled.ace_lower;
    row.verdict = refiled.verdict;
    true
}

fn ask(app: &mut AppState, purpose: ChoicePurpose) {
    let cursor = match &purpose {
        ChoicePurpose::Filter => RouteFilter::ALL
            .iter()
            .position(|f| *f == app.rules.table.filter)
            .unwrap_or(0),
        ChoicePurpose::StatusFilter => StatusFilter::ALL
            .iter()
            .position(|f| *f == app.rules.table.status)
            .unwrap_or(0),
        ChoicePurpose::TypeFilter => TYPE_FILTERS
            .iter()
            .position(|f| *f == app.rules.table.type_filter)
            .unwrap_or(0),
        ChoicePurpose::Preset(list) => list
            .sets
            .iter()
            .position(|set| set.selection_key() == list.selected)
            .unwrap_or(0),
        // The destructive answer is listed first but never preselected.
        ChoicePurpose::Delete(_)
        | ChoicePurpose::Reload
        | ChoicePurpose::Overwrite(_)
        | ChoicePurpose::Shipped(_)
        | ChoicePurpose::ClearAll
        | ChoicePurpose::DeleteMarked
        | ChoicePurpose::RemoveSpare(_) => 1,
        _ => 0,
    };
    app.rules.mode = Mode::Choice(Choice { purpose, cursor });
}

/// The question a bound file edited by hand raises instead of being replaced.
fn ask_about_hand_edited(app: &mut AppState, held: Vec<(nrr_client_logic::Route, PathBuf)>) {
    ask(app, ChoicePurpose::HandEdited(held));
}

/// "Take the file": its folder is read like any rule set, and the import
/// question decides how it meets the list; the apply then reviews it.
fn take_hand_edited(app: &mut AppState, held: &[(nrr_client_logic::Route, PathBuf)]) {
    let Some(dir) = held.first().and_then(|(_, path)| path.parent()) else {
        return;
    };
    match files::read_set(dir) {
        Err((file, error)) => app.rules.note = Some(read_failed(&file, error)),
        Ok(set) => offer_import(app, set, dir.display().to_string()),
    }
}

/// "Replace the file": the rows on screen, the rules in force, are written.
fn replace_hand_edited(app: &mut AppState, held: &[(nrr_client_logic::Route, PathBuf)]) {
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut written = Vec::new();
    for (route, path) in held {
        files::take_passthrough_from(&mut app.rules.table, *route, path);
        let (table, hint) = (&app.rules.table, &app.rules.file_hint);
        if let Err((path, error)) = files::write_route(path, *route, table, hint, &exported_at) {
            let path = path.display().to_string();
            let note = Note::with(text::WRITE_FAILED, vec![("path", path), ("error", error)]);
            app.rules.note = Some(note);
            break;
        }
        written.push(path.clone());
    }
    if let Some(file) = app.rules.settings_file.as_deref() {
        let _ = own_settings::note_written(file, &written);
    }
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
        InputPurpose::ExportRoute(route) => files_input_start(app) + files::file_name(route),
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
            table.set_cursor(0);
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
        InputPurpose::Export => save_to(app, SaveTarget::Set(path_of(&input.text)), false),
        InputPurpose::ExportRoute(route) => {
            save_to(app, SaveTarget::Route(route, path_of(&input.text)), false);
        }
        InputPurpose::RulesFolder => {
            folder::choose(app, &input.text);
            refresh_bound_paths(app);
        }
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
/// A set whose sections need a decision is asked about first, one question
/// at a time, as the window's import review; Esc drops the import.
fn offer_import(app: &mut AppState, set: RuleSet, path: String) {
    if set.questions.is_empty() {
        offer_reviewed_import(app, set, path);
        return;
    }
    let flow = ReviewFlow {
        set,
        path,
        at: 0,
        duplicates: BTreeMap::new(),
        unknown: BTreeMap::new(),
    };
    ask(app, ChoicePurpose::ImportReview(Box::new(flow)));
}

/// One answer of the import review; the last one lets the set land.
fn review_answered(app: &mut AppState, mut flow: Box<ReviewFlow>, answer: usize) {
    use files::{DuplicateChoice, ReviewQuestion, UnknownChoice, REFILE_HEADERS};
    match flow.set.questions.get(flow.at) {
        Some(ReviewQuestion::Duplicate { name, .. }) => {
            let choice = match answer {
                0 => DuplicateChoice::KeepAll,
                1 => DuplicateChoice::LastOnly,
                _ => DuplicateChoice::Ignore,
            };
            flow.duplicates.insert(name.clone(), choice);
        }
        Some(ReviewQuestion::Unknown { name, .. }) => {
            let choice = match answer {
                0 => UnknownChoice::Keep,
                n if n <= REFILE_HEADERS.len() => UnknownChoice::Refile(REFILE_HEADERS[n - 1]),
                _ => UnknownChoice::Skip,
            };
            flow.unknown.insert(name.clone(), choice);
        }
        None => {}
    }
    flow.at += 1;
    if flow.at < flow.set.questions.len() {
        app.rules.mode = Mode::Choice(Choice {
            purpose: ChoicePurpose::ImportReview(flow),
            cursor: 0,
        });
        return;
    }
    let ReviewFlow {
        mut set,
        path,
        duplicates,
        unknown,
        ..
    } = *flow;
    set.apply_review(&duplicates, &unknown);
    offer_reviewed_import(app, set, path);
}

fn offer_reviewed_import(app: &mut AppState, set: RuleSet, path: String) {
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
    let dir = PathBuf::from(&path);
    let table = &mut app.rules.table;
    let added = table.import(set.rows, replace);
    table.passthrough = set.passthrough;
    table.clear_filters();
    table.set_cursor(0);
    let mut note = Note::with(
        text::IMPORTED,
        vec![("count", added.to_string()), ("path", path)],
    );
    // A rule section written twice: all of its rules are taken, said once.
    for (name, times) in &set.known_duplicates {
        note = note.then(Note::with(
            text::PRESET_DUPLICATE_KNOWN,
            vec![
                ("name", display_text(name).into_owned()),
                ("n", times.to_string()),
            ],
        ));
    }
    if let Err(error) = bind_imported(app, &set.paths) {
        note = note.then(Note::with(
            text::SETTINGS_NOT_WRITTEN,
            vec![("error", error.to_string())],
        ));
    }
    app.rules.note = Some(note);
    refresh_bound_paths(app);
    folder::offer(app, &dir);
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
    let written = files::write_set(path, &app.rules.table, &app.rules.file_hint, &exported_at);
    if let Err((file, error)) = written {
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
    refresh_bound_paths(app);
}

fn bind_written_set(app: &AppState, dir: &Path) -> Result<(), UserSettingsError> {
    let Some(file) = app.rules.settings_file.as_deref() else {
        return Ok(());
    };
    own_settings::bind_written_set(file, dir, files::presets_root().as_deref())
}

/// A write asks first when it would go into the shipped tree, which an update
/// replaces, and when it would replace files already there.
fn save_to(app: &mut AppState, target: SaveTarget, shipped_ok: bool) {
    let shipped = files::presets_root();
    if !shipped_ok && own_settings::inside_shipped(target.folder(), shipped.as_deref()) {
        ask(app, ChoicePurpose::Shipped(target));
    } else if target.exists() {
        ask(app, ChoicePurpose::Overwrite(target));
    } else {
        write_target(app, &target);
    }
}

fn write_target(app: &mut AppState, target: &SaveTarget) {
    match target {
        SaveTarget::Set(dir) => export(app, dir),
        SaveTarget::Route(route, file) => export_route(app, *route, file),
    }
}

/// One route's rules into `file`, which becomes that route's rules file.
fn export_route(app: &mut AppState, route: nrr_client_logic::Route, file: &Path) {
    let failed = |path: &Path, error: String| {
        Note::with(
            text::WRITE_FAILED,
            vec![("path", path.display().to_string()), ("error", error)],
        )
    };
    if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
        if let Err(error) = std::fs::create_dir_all(dir) {
            app.rules.note = Some(failed(dir, error.to_string()));
            return;
        }
    }
    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let written = files::write_route(
        file,
        route,
        &app.rules.table,
        &app.rules.file_hint,
        &exported_at,
    );
    if let Err((path, error)) = written {
        app.rules.note = Some(failed(&path, error));
        return;
    }
    let shown = file.display().to_string();
    let shipped = files::presets_root();
    let bound = app.rules.settings_file.as_deref().map(|settings| {
        own_settings::bind_written_route(settings, route, file, shipped.as_deref())
    });
    app.rules.note = Some(match bound {
        Some(Err(error)) => Note::with(
            text::EXPORTED_UNBOUND,
            vec![("path", shown), ("error", error.to_string())],
        ),
        _ => Note::with(text::EXPORTED, vec![("path", shown)]),
    });
    let slot = match route {
        nrr_client_logic::Route::Primary => 0,
        nrr_client_logic::Route::Secondary => 1,
    };
    app.rules.loaded_files[slot] = own_settings::path_text(&own_settings::absolute(file));
    refresh_bound_paths(app);
}

/// `L`: the demo rules join the list, as the window's "Load demo rules"
/// does; a rule already listed is not added twice.
fn load_demo(app: &mut AppState) {
    if locked(app) {
        return;
    }
    let Some(dir) = files::demo_dir(app.rules.demo_russian) else {
        app.rules.note = Some(Note::new(text::DEMO_MISSING));
        return;
    };
    match files::read_set(&dir) {
        Err((file, error)) => app.rules.note = Some(read_failed(&file, error)),
        Ok(set) => {
            let added = app.rules.table.import(set.rows, false);
            app.rules.note = Some(Note::with(
                text::DEMO_ADDED,
                vec![("count", added.to_string())],
            ));
            if added > 0 && app.link.is_connected() {
                start_apply(app);
            }
        }
    }
}

fn toggle_mark(app: &mut AppState, i: usize) {
    if let Some(row) = app.rules.table.rows.get_mut(i) {
        row.marked = !row.marked;
    }
}

fn ask_marked(app: &mut AppState) {
    if locked(app) {
        return;
    }
    if app.rules.table.marked().is_empty() {
        app.rules.note = Some(Note::new(text::NONE_MARKED));
    } else {
        ask(app, ChoicePurpose::Marked);
    }
}

/// The options of [`ChoicePurpose::Marked`], in order.
pub(crate) const MARKED_ACTIONS: usize = 7;

/// An action on every selected rule, as the window's selection bar: on, off,
/// to a route, deny, delete (asked first), or unselect.
fn act_on_marked(app: &mut AppState, at: usize) {
    let marked = app.rules.table.marked();
    let n = marked.len().to_string();
    let rows = &mut app.rules.table.rows;
    let note = match at {
        0 | 1 => {
            for &i in &marked {
                rows[i].rule.enabled = at == 0;
            }
            Note::with(
                if at == 0 {
                    text::BULK_ENABLED
                } else {
                    text::BULK_DISABLED
                },
                vec![("n", n)],
            )
        }
        2 | 3 => {
            let to = if at == 2 {
                TargetRoute::Primary
            } else {
                TargetRoute::Secondary
            };
            for &i in &marked {
                rows[i].move_to(to.clone());
            }
            let route = if at == 2 {
                app.rules.route_names[0].clone()
            } else {
                app.rules.route_names[1].clone()
            };
            Note::with(text::BULK_MOVED, vec![("n", n), ("route", route)])
        }
        4 => {
            for &i in &marked {
                rows[i].move_to(TargetRoute::Block);
            }
            Note::with(text::BULK_DENIED, vec![("n", n)])
        }
        5 => {
            ask(app, ChoicePurpose::DeleteMarked);
            return;
        }
        6 => {
            app.rules.table.clear_marks();
            return;
        }
        _ => return,
    };
    app.rules.note = Some(note);
}

fn delete_marked(app: &mut AppState) {
    let table = &mut app.rules.table;
    let before = table.rows.len();
    table.rows.retain(|row| !row.marked);
    table.clamp_cursor();
    let n = (before - table.rows.len()).to_string();
    app.rules.note = Some(Note::with(text::BULK_DELETED, vec![("n", n)]));
}

fn ask_clear_all(app: &mut AppState) {
    if !locked(app) && !app.rules.table.rows.is_empty() {
        ask(app, ChoicePurpose::ClearAll);
    }
}

/// Every rule leaves the list and the rules files stop being written, as the
/// window's "Clear all rules"; with the service there, the review that
/// empties it follows. The files themselves stay on disk.
fn clear_all(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.import(Vec::new(), true);
    table.passthrough = Default::default();
    table.clear_filters();
    table.set_cursor(0);
    app.rules.loaded_files = Default::default();
    let mut note = Note::new(text::CLEARED);
    if let Some(file) = app.rules.settings_file.as_deref() {
        note = match own_settings::unbind_files(file) {
            Ok(()) => note.then(Note::new(text::CLEARED_FILES_KEPT)),
            Err(error) => note.then(Note::with(
                text::SETTINGS_NOT_WRITTEN,
                vec![("error", error.to_string())],
            )),
        };
    }
    app.rules.note = Some(note);
    refresh_bound_paths(app);
    if app.link.is_connected() {
        start_apply(app);
    }
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
            table.set_cursor(0);
        }
        ChoicePurpose::StatusFilter => {
            let table = &mut app.rules.table;
            table.status = StatusFilter::ALL.get(at).copied().unwrap_or_default();
            table.set_cursor(0);
        }
        ChoicePurpose::TypeFilter => {
            let table = &mut app.rules.table;
            table.type_filter = TYPE_FILTERS.get(at).copied().unwrap_or(TYPE_FILTERS[0]);
            table.set_cursor(0);
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
        ChoicePurpose::RemoveSpare(spare) if at == 0 => spare::remove(app, &spare),
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
        ChoicePurpose::Overwrite(target) if at == 0 => write_target(app, &target),
        ChoicePurpose::Shipped(target) if at == 0 => save_to(app, target, true),
        ChoicePurpose::ExportRoute => {
            if let Some(route) = nrr_client_logic::Route::ALL.get(at) {
                start_input(app, InputPurpose::ExportRoute(*route));
            }
        }
        ChoicePurpose::ClearAll if at == 0 => clear_all(app),
        ChoicePurpose::Marked => act_on_marked(app, at),
        ChoicePurpose::DeleteMarked if at == 0 => delete_marked(app),
        ChoicePurpose::ImportReview(flow) => review_answered(app, flow, at),
        ChoicePurpose::ChangedElsewhere if at == 0 => rebase_edits(app),
        ChoicePurpose::HandEdited(held) => match at {
            0 => take_hand_edited(app, &held),
            1 => replace_hand_edited(app, &held),
            _ => {}
        },
        ChoicePurpose::Recent => recent::picked(app, at),
        ChoicePurpose::Restore(_) => recent::restore(app, at),
        _ => {}
    }
}

// ── Keys ─────────────────────────────────────────────────────────────────────

fn list_key(app: &mut AppState, key: KeyEvent) -> bool {
    let changing = match key.code {
        KeyCode::Enter | KeyCode::Delete => true,
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            changes_rules(c.encode_utf8(&mut [0; 4]))
        }
        _ => false,
    };
    if changing && refuse_when_admin_locked(app) {
        return true;
    }
    let selected = app.rules.table.selected();
    let table = &mut app.rules.table;
    let page = PAGE as isize;
    match key.code {
        KeyCode::Up => table.move_cursor(-1),
        KeyCode::Down => table.move_cursor(1),
        KeyCode::PageUp => table.move_cursor(-page),
        KeyCode::PageDown => table.move_cursor(page),
        KeyCode::Home => table.set_cursor(0),
        KeyCode::End => table.move_cursor(isize::MAX),
        KeyCode::Enter => edit_selected(app, selected),
        KeyCode::Delete => ask_delete(app, selected),
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => start_apply(app),
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => match c {
            'a' => open_form(app, Form::add()),
            'e' => edit_selected(app, selected),
            'd' => ask_delete(app, selected),
            // From the menu the row marker is not drawn: the first press
            // only shows which rule the next one switches.
            ' ' | 't' if app.focus != crate::state::Focus::Feed => {
                app.focus = crate::state::Focus::Feed;
            }
            ' ' | 't' => toggle(app, selected),
            'f' => ask(app, ChoicePurpose::Filter),
            'S' => ask(app, ChoicePurpose::StatusFilter),
            'y' => ask(app, ChoicePurpose::TypeFilter),
            'u' => toggle_auto_only(app),
            'E' => show_invalid(app),
            'H' => toggle_not_working(app),
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
            'v' => return gateway::start(app),
            'g' => app.open(ScreenId::AppGroups),
            'F' => return file_merge::start(app),
            'C' => return spare::start(app),
            'O' => change_order(app),
            'T' => return move_to_type(app, selected),
            'M' => return move_all_to_type(app),
            'A' => return bulk::start(app, TargetRoute::Primary, String::new(), false),
            'R' => return recent::ask(app),
            'U' => return recent::ask_restore(app),
            'P' => return overrides::start(app, selected),
            'b' => switch_book(app),
            'X' => ask(app, ChoicePurpose::ExportRoute),
            'L' => load_demo(app),
            'W' => ask_clear_all(app),
            'Z' => start_reset(app),
            '*' => {
                if let Some(i) = selected {
                    toggle_mark(app, i);
                }
            }
            'B' => ask_marked(app),
            _ => return false,
        },
        _ => return false,
    }
    true
}

/// `b`: the other set, the caller's own rules or the baseline every user
/// without rules of their own follows. Every writer of this terminal writes the
/// set on screen, so edits made in one are applied or dropped before the other
/// is shown.
fn switch_book(app: &mut AppState) {
    let rules = &mut app.rules;
    if rules.busy.is_some() {
        return;
    }
    if rules.table.is_dirty() {
        rules.note = Some(Note::new(text::BOOK_DIRTY));
        return;
    }
    rules.baseline = !rules.baseline;
    rules.note = Some(Note::new(if rules.baseline {
        text::BOOK_BASELINE
    } else {
        text::BOOK_OWN
    }));
    load(app);
}

/// What a writer outside this screen says when [`own_rules_on_screen`] refuses.
pub const OWN_RULES_ONLY: Key = text::OWN_RULES_ONLY;

/// A writer that only reaches the caller's own rules, refused while the
/// baseline is on screen: the set shown and the set written stay one.
pub fn own_rules_on_screen(app: &mut AppState) -> bool {
    if app.rules.baseline {
        app.rules.note = Some(Note::new(text::OWN_RULES_ONLY));
        return false;
    }
    true
}

/// The Rules screen with the add form already holding a rule, as the GUI's
/// rule window opens from another screen; the user still checks and saves
/// it. A dialog already open there is left as it was. `false` when this
/// system offers no such rule type.
pub fn add_prefilled(app: &mut AppState, rule_type: RuleType, value: String) -> bool {
    if !offered_types().contains(&rule_type) {
        return false;
    }
    app.open(ScreenId::Rules);
    if !matches!(app.rules.mode, Mode::List) {
        return true;
    }
    let mut form = Form::add();
    form.set_type(rule_type);
    form.value = value;
    if matches!(app.rules.busy, Some(Busy::Loading)) {
        app.rules.prefilled = Some(Box::new(form));
    } else {
        open_form(app, form);
    }
    true
}

/// `u`: only the rules the app added, or every rule again.
fn toggle_auto_only(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.auto_only = !table.auto_only;
    table.set_cursor(0);
}

/// `H`: leave out the rules that do not work, or show them again (the
/// window's «Show rules that do not work»).
fn toggle_not_working(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.hide_not_working = !table.hide_not_working;
    table.set_cursor(0);
}

/// `E`: the rules that will not be applied (the window's «Show them»).
fn show_invalid(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.status = StatusFilter::WithErrors;
    table.set_cursor(0);
}

/// The next order; the cursor goes back to the top, as a new filter does.
fn change_order(app: &mut AppState) {
    let table = &mut app.rules.table;
    table.sort = table.sort.next();
    table.set_cursor(0);
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
        KeyCode::Char('t') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            form.switch_type();
        }
        KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            form.toggle_scope();
        }
        KeyCode::F(2) if form.editing.is_none() => {
            return bulk::start(app, form.route.clone(), form.value.clone(), true);
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
        KeyCode::Esc => {
            app.rules.quit_after_apply = false;
            return true;
        }
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

/// A number in the list as last printed: `e 3` names the rule printed third,
/// wherever a re-read or a re-sort has put it since.
fn numbered(app: &mut AppState, arg: &str) -> Option<usize> {
    let n: usize = arg.trim().parse().ok()?;
    let table = &app.rules.table;
    let shown = table.visible();
    let now: Vec<String> = shown
        .iter()
        .map(|&i| table.rows[i].rule.merge_key())
        .collect();
    match crate::screens::numbered_now(&app.rules.printed, &now, n) {
        crate::screens::Numbered::At(at) => shown.get(at).copied(),
        crate::screens::Numbered::Gone => {
            app.rules.note = Some(Note::with(text::NUMBER_GONE, vec![("n", n.to_string())]));
            None
        }
        crate::screens::Numbered::NoSuch => None,
    }
}

fn list_line(app: &mut AppState, line: &str) -> bool {
    let (command, arg) = line.split_once(' ').unwrap_or((line, ""));
    if changes_rules(command) && refuse_when_admin_locked(app) {
        return true;
    }
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
        "S" => ask(app, ChoicePurpose::StatusFilter),
        "y" => ask(app, ChoicePurpose::TypeFilter),
        "u" => toggle_auto_only(app),
        "E" => show_invalid(app),
        "H" => toggle_not_working(app),
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
        "b" => switch_book(app),
        "X" => ask(app, ChoicePurpose::ExportRoute),
        "L" => load_demo(app),
        "W" => ask_clear_all(app),
        "Z" => start_reset(app),
        "B" => ask_marked(app),
        // `* 2 5` selects the rules read as the second and the fifth.
        "*" => {
            for n in arg.split_whitespace() {
                if let Some(i) = numbered(app, n) {
                    toggle_mark(app, i);
                }
            }
        }
        "i" => start_input(app, InputPurpose::Import),
        "x" => start_input(app, InputPurpose::Export),
        "p" => presets(app),
        "o" => start_folder_input(app),
        "m" => return verdicts::move_all(app),
        "n" => return verdicts::not_now(app),
        "c" => return main_route::start(app),
        "v" => return gateway::start(app),
        "g" => app.open(ScreenId::AppGroups),
        "F" => return file_merge::start(app),
        "C" => return spare::start(app),
        "O" => change_order(app),
        "A" => return bulk::start(app, TargetRoute::Primary, String::new(), false),
        "T" => {
            let master = numbered(app, arg);
            if let Some(i) = master {
                app.rules.table.select(i);
            }
            return move_to_type(app, master);
        }
        "M" => return move_all_to_type(app),
        "R" => return recent::ask(app),
        "P" => {
            let master = numbered(app, arg);
            if let Some(i) = master {
                app.rules.table.select(i);
            }
            return overrides::start(app, master);
        }
        "U" => {
            // `U 2` puts back the second deleted rule listed.
            match arg.trim().parse::<usize>() {
                Ok(n) if (1..=recent::restore_len(app)).contains(&n) => {
                    if !locked(app) {
                        recent::restore(app, n - 1);
                    }
                }
                _ => return recent::ask_restore(app),
            }
        }
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests;

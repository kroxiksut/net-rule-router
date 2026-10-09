//! The Settings screen: the GUI's settings that are not about the GUI itself,
//! by section — notifications, routing behaviour, the apply failure policy,
//! the service, the full settings export, logs and storage, traffic
//! statistics, updates — and the terminal's own drawing options.
//!
//! Every change goes through the same operation the GUI uses; the full
//! replacement writes start from a fresh read (`nrr-client-logic`).

mod clock;
mod items;
mod jobs;
pub mod prefs;
#[cfg(test)]
mod tests;
mod text;

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::notice_mutes::{notice_mute_request, NOTICE_MUTE_CHOICES_MS};
use nrr_client_logic::route_policy;
use nrr_ipc_client::IpcClientError;
use nrr_platform_api::service_control::ServiceStatusReport;
use nrr_shared::ipc_payloads::{
    BlockNoticeMuteDto, BlockNoticeMuteScopeDto, LogRetentionConfigDto,
    LogRetentionConfigSetRequest, RetentionSettingsDto, RetentionSettingsSetRequest,
    StorageUsageDto, TrafficStatsGetResponse, TrafficStatsSettingsDto,
};
use nrr_shared::ipc_transport::IpcErrorCode;
use nrr_shared::platform_profile::{PlatformProfile, PlatformSupports};
use serde_json::{json, Map, Value};

pub use clock::Clock;
use items::{Item, ItemId, Kind, LogField, PrefField, RevisionField, TrafficField, Words};
pub use prefs::TuiPrefs;

use super::Screen;
use crate::backend::RegistrationProbe;
use crate::i18n::{Key, Texts};
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};

/// The sections, in the GUI's order, then the terminal's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Notifications,
    Routing,
    FailurePolicy,
    Service,
    Presets,
    Logs,
    Traffic,
    Updates,
    Terminal,
}

impl Category {
    pub const ALL: [Self; 9] = [
        Self::Notifications,
        Self::Routing,
        Self::FailurePolicy,
        Self::Service,
        Self::Presets,
        Self::Logs,
        Self::Traffic,
        Self::Updates,
        Self::Terminal,
    ];

    pub fn title(self) -> Key {
        match self {
            Self::Notifications => text::NOTIFICATIONS,
            Self::Routing => text::ROUTING,
            Self::FailurePolicy => text::FAILURE_POLICY,
            Self::Service => text::SERVICE,
            Self::Presets => text::PRESETS,
            Self::Logs => text::LOGS,
            Self::Traffic => text::TRAFFIC,
            Self::Updates => text::UPDATES,
            Self::Terminal => text::TERMINAL,
        }
    }
}

/// Why a read or a change did not go through, in the terms its words need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The GUI's `errors.<slug>`; empty when only `detail` says what happened.
    pub slug: String,
    /// The terminal was not started with the rights this needs.
    pub elevation: bool,
    pub detail: String,
}

impl Failure {
    pub fn from_ipc(error: &IpcClientError) -> Self {
        let (slug, detail) = nrr_ipc_client::ipc_error_to_wire(error);
        // The terminal never elevates, so a refusal for want of rights is
        // always answered with how to start it with them.
        let elevation = matches!(
            error,
            IpcClientError::ServerError {
                code: IpcErrorCode::Forbidden,
                ..
            }
        );
        Self {
            slug: slug.to_owned(),
            elevation,
            detail,
        }
    }

    pub fn detail(detail: impl Into<String>) -> Self {
        Self {
            slug: String::new(),
            elevation: false,
            detail: detail.into(),
        }
    }

    pub fn elevation() -> Self {
        Self {
            slug: "forbidden".to_owned(),
            elevation: true,
            detail: String::new(),
        }
    }
}

/// The words for a failure: the remedy for missing rights, the GUI's wording
/// for a known service code, else what the source said.
pub fn failure_text(failure: &Failure, texts: &Texts) -> String {
    if failure.elevation {
        return texts.get(if cfg!(windows) {
            text::NEEDS_ELEVATION_WINDOWS
        } else {
            text::NEEDS_ELEVATION_UNIX
        });
    }
    if failure.slug.is_empty() {
        return failure.detail.clone();
    }
    text::ERRORS
        .iter()
        .find(|(slug, _)| *slug == failure.slug)
        .map_or_else(|| texts.get(text::ERROR_UNKNOWN), |(_, k)| texts.get(*k))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Loadable<T> {
    #[default]
    NotLoaded,
    Loading,
    Ready(T),
    Failed(Failure),
}

impl<T> Loadable<T> {
    fn ready(&self) -> Option<&T> {
        match self {
            Self::Ready(value) => Some(value),
            _ => None,
        }
    }

    /// Marks a read in flight, keeping a value already shown.
    fn start(&mut self) {
        if !matches!(self, Self::Ready(_)) {
            *self = Self::Loading;
        }
    }
}

/// What the system's service manager says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceInfo {
    NoManager,
    NotInstalled,
    Registered(ServiceStatusReport),
}

/// What the service answered, per section.
#[derive(Clone, Debug, Default)]
pub struct Data {
    /// The raw `route-policy` of the last snapshot, the base of every write.
    pub policy: Loadable<Map<String, Value>>,
    pub stability: Loadable<Map<String, Value>>,
    pub mutes: Loadable<Vec<BlockNoticeMuteDto>>,
    pub failure_policy: Loadable<String>,
    pub retention: Loadable<RetentionSettingsDto>,
    pub log_retention: Loadable<LogRetentionConfigDto>,
    pub storage: Loadable<StorageUsageDto>,
    pub traffic: Loadable<TrafficStatsGetResponse>,
    pub service: Loadable<ServiceInfo>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MuteScope {
    #[default]
    All,
    Host,
    App,
}

impl MuteScope {
    pub fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Host => "host",
            Self::App => "app",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MuteUnit {
    Minutes,
    #[default]
    Hours,
    Days,
}

impl MuteUnit {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Minutes => "minutes",
            Self::Hours => "hours",
            Self::Days => "days",
        }
    }

    fn millis(self) -> i64 {
        match self {
            Self::Minutes => 60_000,
            Self::Hours => 3_600_000,
            Self::Days => 86_400_000,
        }
    }
}

/// The "add a mute" form, as the GUI starts it: every notice, 24 hours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuteForm {
    pub scope: MuteScope,
    pub target: String,
    pub amount: i64,
    pub unit: MuteUnit,
    pub forever: bool,
}

impl Default for MuteForm {
    fn default() -> Self {
        Self {
            scope: MuteScope::All,
            target: String::new(),
            amount: 24,
            unit: MuteUnit::Hours,
            forever: false,
        }
    }
}

/// What the cursor row is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Browse,
    /// Choosing among a choice's options; `option` has the marker.
    Picking { option: usize },
    /// Typing a value.
    Editing { buffer: String },
    /// An action that cannot be undone waits for a second yes.
    Confirming,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub words: Words,
    pub tone: Option<StateTone>,
}

#[derive(Debug)]
pub struct SettingsState {
    /// The open section; `None` lists the sections.
    pub open: Option<Category>,
    /// The row with the cursor among the rows it can stop on.
    pub cursor: usize,
    pub mode: Mode,
    /// The outcome of the last change, until the next one.
    pub message: Option<Message>,
    pub data: Data,
    pub mute_form: MuteForm,
    pub export_path: String,
    pub prefs: TuiPrefs,
    /// Where the terminal's settings are saved; `None` cannot save.
    pub prefs_path: Option<PathBuf>,
    pub clock: Clock,
    pub service_probe: RegistrationProbe,
    pub supports: PlatformSupports,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            open: None,
            cursor: 0,
            mode: Mode::Browse,
            message: None,
            data: Data::default(),
            mute_form: MuteForm::default(),
            export_path: String::new(),
            prefs: TuiPrefs::default(),
            prefs_path: None,
            clock: Clock::default(),
            service_probe: crate::platform::service_control,
            supports: PlatformProfile::current().supports,
        }
    }
}

impl SettingsState {
    fn say(&mut self, words: Words, tone: Option<StateTone>) {
        self.message = Some(Message { words, tone });
    }

    fn done(&mut self, words: Words) {
        self.say(words, Some(StateTone::Good));
    }

    fn failed(&mut self, key: Key, failure: Failure) {
        self.say(Words::Failed(key, failure), Some(StateTone::Bad));
    }

    fn refuse(&mut self, words: Words) {
        self.say(words, Some(StateTone::Caution));
    }

    fn supports_map(&self) -> Map<String, Value> {
        match serde_json::to_value(self.supports) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        }
    }
}

pub struct SettingsScreen;

impl Screen for SettingsScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let s = &app.settings;
        let mut panels = Vec::new();
        if let Some(message) = &s.message {
            let words = message.words.resolve(texts);
            let line = match message.tone {
                Some(tone) => ViewLine::new(vec![Segment::state(words, tone)]),
                None => ViewLine::text(words),
            };
            panels.push(Panel {
                title: texts.get(text::RESULT),
                lines: vec![line],
                feed: false,
            });
        }
        let (title, lines) = match s.open {
            None => (texts.get(text::SECTIONS), section_lines(app, texts)),
            Some(category) => (
                texts.get(category.title()),
                item_lines(app, category, texts),
            ),
        };
        panels.push(Panel {
            title,
            lines,
            feed: true,
        });
        ScreenView {
            title: texts.get(crate::keys::SCREEN_SETTINGS),
            panels,
        }
    }

    fn help(&self) -> &'static [Key] {
        &[text::HELP_FOCUS, text::HELP_ENTER, text::HELP_ESC]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[text::PLAIN_SECTIONS, text::PLAIN_ITEMS, text::PLAIN_BACK]
    }

    fn on_show(&self, app: &mut AppState) {
        load(app);
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        app.settings.mode != Mode::Browse
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        on_key(app, key)
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        on_line(app, line.trim())
    }

    fn plain_prompt(&self, app: &AppState) -> Option<Key> {
        match app.settings.mode {
            Mode::Browse => None,
            Mode::Picking { .. } => Some(text::PLAIN_PICK),
            Mode::Editing { .. } => Some(text::PLAIN_EDIT),
            Mode::Confirming => Some(text::PLAIN_CONFIRM),
        }
    }
}

// ── Drawing ──────────────────────────────────────────────────────────────────

/// The row with the cursor: `>` and bold, so it never rests on colour.
fn marked(cursor: bool, text: String) -> Segment {
    if cursor {
        Segment::strong(format!("> {text}"))
    } else {
        Segment::plain(format!("  {text}"))
    }
}

fn section_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let cursor = app.settings.cursor.min(Category::ALL.len() - 1);
    Category::ALL
        .iter()
        .enumerate()
        .map(|(i, c)| {
            ViewLine::new(vec![marked(
                i == cursor,
                format!("c{}. {}", i + 1, texts.get(c.title())),
            )])
        })
        .collect()
}

/// The section's rows. While the full screen has the focus the list starts a
/// few rows above the cursor, so the cursor is always in sight; line mode
/// prints every row.
fn item_lines(app: &AppState, category: Category, texts: &Texts) -> Vec<ViewLine> {
    let s = &app.settings;
    let list = items::items(app, category);
    let selectable = list.iter().filter(|i| i.selectable()).count();
    let cursor = s.cursor.min(selectable.saturating_sub(1));
    let focused = app.focus == Focus::Feed;
    let mut lines = Vec::new();
    let mut number = 0;
    let mut cursor_line = None;
    for item in &list {
        let label = item.label.resolve(texts);
        match &item.kind {
            Kind::Heading => lines.push(ViewLine::new(vec![Segment::strong(label)])),
            Kind::Info => lines.push(ViewLine::text(format!("  {label}"))),
            Kind::State(tone, template) => {
                let template = texts.get(*template);
                let (before, after) = template
                    .split_once("{state}")
                    .unwrap_or((template.as_str(), ""));
                lines.push(ViewLine::new(vec![
                    Segment::plain(format!("  {before}")),
                    Segment::state(label, *tone),
                    Segment::plain(after),
                ]));
            }
            _ => {
                number += 1;
                let here = number - 1 == cursor;
                let mut segments = vec![marked(here, format!("i{number}. {label}"))];
                if let Some(value) = item.value() {
                    segments.push(Segment::plain(format!(": {}", value.resolve(texts))));
                }
                if here {
                    cursor_line = Some(lines.len());
                }
                lines.push(ViewLine::new(segments));
                if here {
                    lines.extend(detail_lines(app, item, focused, texts));
                }
            }
        }
    }
    match cursor_line {
        Some(at) if focused && at > 3 => {
            let skipped = at - 3;
            let mut shown = vec![ViewLine::text(
                texts.fill(text::MORE_ABOVE, &[("count", skipped.to_string())]),
            )];
            shown.extend(lines.into_iter().skip(skipped));
            shown
        }
        _ => lines,
    }
}

/// Under the cursor row: the options being chosen from, the value being
/// typed, the question being asked, or the row's explanation.
fn detail_lines(app: &AppState, item: &Item, focused: bool, texts: &Texts) -> Vec<ViewLine> {
    let indent = |text: String| ViewLine::text(format!("      {text}"));
    match (&app.settings.mode, &item.kind) {
        (Mode::Picking { option }, Kind::Choice { options, .. }) => {
            let mut lines: Vec<ViewLine> = options
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    let mark = if i == *option { '>' } else { ' ' };
                    let line = format!("    {mark} {}. {}", i + 1, o.label.resolve(texts));
                    if i == *option {
                        ViewLine::new(vec![Segment::strong(line)])
                    } else {
                        ViewLine::text(line)
                    }
                })
                .collect();
            if focused {
                lines.push(indent(texts.get(text::PICK_HINT)));
            }
            lines
        }
        (Mode::Editing { buffer }, _) => {
            let mut lines = vec![indent(texts.fill(text::NEW_VALUE, &[("value", buffer)]))];
            if focused {
                lines.push(indent(texts.get(text::EDIT_HINT)));
            }
            lines
        }
        (Mode::Confirming, _) if focused => vec![indent(texts.get(text::CONFIRM))],
        (Mode::Browse, _) => item
            .note
            .iter()
            .map(|note| indent(note.resolve(texts)))
            .collect(),
        _ => Vec::new(),
    }
}

// ── Keys and lines ───────────────────────────────────────────────────────────

fn row_count(app: &AppState) -> usize {
    match app.settings.open {
        None => Category::ALL.len(),
        Some(category) => items::items(app, category)
            .iter()
            .filter(|i| i.selectable())
            .count(),
    }
}

fn move_cursor(app: &mut AppState, by: isize) {
    let rows = row_count(app);
    let s = &mut app.settings;
    if rows == 0 {
        s.cursor = 0;
        return;
    }
    let current = s.cursor.min(rows - 1);
    s.cursor = current.saturating_add_signed(by).min(rows - 1);
    app.scroll = 0;
}

fn focused_item(app: &AppState) -> Option<Item> {
    let category = app.settings.open?;
    items::items(app, category)
        .into_iter()
        .filter(Item::selectable)
        .nth(app.settings.cursor)
}

fn open_section(app: &mut AppState, index: usize) -> bool {
    let Some(category) = Category::ALL.get(index).copied() else {
        return false;
    };
    let s = &mut app.settings;
    s.open = Some(category);
    s.cursor = 0;
    s.mode = Mode::Browse;
    s.message = None;
    app.scroll = 0;
    load(app);
    true
}

fn back(app: &mut AppState) -> bool {
    let s = &mut app.settings;
    let Some(category) = s.open.take() else {
        return false;
    };
    s.cursor = Category::ALL
        .iter()
        .position(|c| *c == category)
        .unwrap_or(0);
    s.mode = Mode::Browse;
    app.scroll = 0;
    true
}

/// Enter on the cursor row: open the section, or start changing the row.
fn enter(app: &mut AppState) {
    if app.settings.open.is_none() {
        let index = app.settings.cursor.min(Category::ALL.len() - 1);
        open_section(app, index);
        return;
    }
    if let Some(item) = focused_item(app) {
        begin(app, &item);
    }
}

fn begin(app: &mut AppState, item: &Item) {
    let mode = match &item.kind {
        Kind::Toggle(_) => {
            activate(app, item, Input::Toggle);
            return;
        }
        Kind::Choice { current, .. } => Mode::Picking {
            option: current.unwrap_or(0),
        },
        Kind::Number { value, .. } => Mode::Editing {
            buffer: value.map(|v| v.to_string()).unwrap_or_default(),
        },
        Kind::Text(text) => Mode::Editing {
            buffer: text.clone(),
        },
        Kind::Action { confirm: true } => Mode::Confirming,
        Kind::Action { confirm: false } => {
            activate(app, item, Input::Run);
            return;
        }
        Kind::Heading | Kind::Info | Kind::State(..) => return,
    };
    app.settings.mode = mode;
}

/// A typed value for the cursor row.
fn commit(app: &mut AppState, typed: &str) {
    let Some(item) = focused_item(app) else {
        return;
    };
    match &item.kind {
        Kind::Number { min, max, .. } => match typed.trim().parse::<i64>() {
            Ok(n) if (*min..=*max).contains(&n) => activate(app, &item, Input::Number(n)),
            _ => app.settings.refuse(Words::Fill(
                text::NUMBER_RANGE,
                vec![("min", min.to_string()), ("max", max.to_string())],
            )),
        },
        Kind::Text(_) => activate(app, &item, Input::Text(typed.trim().to_owned())),
        _ => {}
    }
}

fn pick(app: &mut AppState, option: usize) {
    let Some(item) = focused_item(app) else {
        return;
    };
    if let Kind::Choice { options, .. } = &item.kind {
        if let Some(slug) = options.get(option).map(|o| o.slug) {
            activate(app, &item, Input::Pick(slug));
        }
    }
}

fn run_confirmed(app: &mut AppState) {
    if let Some(item) = focused_item(app) {
        activate(app, &item, Input::Run);
    }
}

fn on_key(app: &mut AppState, key: KeyEvent) -> bool {
    let mode = std::mem::take(&mut app.settings.mode);
    match mode {
        Mode::Editing { mut buffer } => {
            match key.code {
                KeyCode::Enter => commit(app, &buffer),
                KeyCode::Esc => {}
                KeyCode::Backspace => {
                    buffer.pop();
                    app.settings.mode = Mode::Editing { buffer };
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    buffer.push(c);
                    app.settings.mode = Mode::Editing { buffer };
                }
                _ => app.settings.mode = Mode::Editing { buffer },
            }
            true
        }
        Mode::Picking { option } => {
            let count = match focused_item(app).map(|i| i.kind) {
                Some(Kind::Choice { options, .. }) => options.len(),
                _ => 0,
            };
            match key.code {
                KeyCode::Enter => pick(app, option),
                KeyCode::Esc => {}
                KeyCode::Up => {
                    app.settings.mode = Mode::Picking {
                        option: option.saturating_sub(1),
                    };
                }
                KeyCode::Down => {
                    app.settings.mode = Mode::Picking {
                        option: (option + 1).min(count.saturating_sub(1)),
                    };
                }
                _ => app.settings.mode = Mode::Picking { option },
            }
            true
        }
        Mode::Confirming => {
            if key.code == KeyCode::Enter {
                run_confirmed(app);
            }
            true
        }
        Mode::Browse => {
            if app.focus != Focus::Feed {
                return false;
            }
            match key.code {
                KeyCode::Up => move_cursor(app, -1),
                KeyCode::Down => move_cursor(app, 1),
                KeyCode::PageUp => move_cursor(app, -5),
                KeyCode::PageDown => move_cursor(app, 5),
                KeyCode::Home => move_cursor(app, isize::MIN / 2),
                KeyCode::End => move_cursor(app, isize::MAX / 2),
                KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => enter(app),
                KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => return back(app),
                _ => return false,
            }
            true
        }
    }
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.to_lowercase().as_str(), "y" | "yes")
}

/// `c2`, `i3`, `i3 30`: the code's letter, number and the rest.
fn parse_code(line: &str, letter: char) -> Option<(usize, &str)> {
    let rest = line.strip_prefix(letter)?;
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let number = rest[..digits].parse::<usize>().ok()?.checked_sub(1)?;
    Some((number, rest[digits..].trim()))
}

fn on_line(app: &mut AppState, line: &str) -> bool {
    match std::mem::take(&mut app.settings.mode) {
        Mode::Editing { .. } => {
            if !line.is_empty() {
                commit(app, line);
            }
            return true;
        }
        Mode::Picking { .. } => {
            if let Some(n) = line.parse::<usize>().ok().and_then(|n| n.checked_sub(1)) {
                pick(app, n);
            }
            return true;
        }
        Mode::Confirming => {
            if is_yes(line) {
                run_confirmed(app);
            }
            return true;
        }
        Mode::Browse => {}
    }
    if line == "b" {
        back(app);
        return true;
    }
    if let Some((index, _)) = parse_code(line, 'c') {
        if !open_section(app, index) {
            app.settings.refuse(Words::Fill(
                text::PLAIN_NO_ITEM,
                vec![("code", line.to_owned())],
            ));
        }
        return true;
    }
    let Some((index, rest)) = parse_code(line, 'i') else {
        return false;
    };
    let rows = if app.settings.open.is_some() {
        row_count(app)
    } else {
        0
    };
    if index >= rows {
        app.settings.refuse(Words::Fill(
            text::PLAIN_NO_ITEM,
            vec![("code", line.to_owned())],
        ));
        return true;
    }
    app.settings.cursor = index;
    let Some(item) = focused_item(app) else {
        return true;
    };
    if rest.is_empty() {
        begin(app, &item);
        return true;
    }
    match &item.kind {
        Kind::Choice { .. } => {
            if let Some(n) = rest.parse::<usize>().ok().and_then(|n| n.checked_sub(1)) {
                pick(app, n);
            }
        }
        Kind::Number { .. } | Kind::Text(_) => commit(app, rest),
        Kind::Action { confirm: true } if is_yes(rest) => run_confirmed(app),
        _ => begin(app, &item),
    }
    true
}

// ── Reading ──────────────────────────────────────────────────────────────────

/// Queues the reads the open section needs. The service manager is asked
/// even without the service: that is when its answer matters most.
fn load(app: &mut AppState) {
    let Some(category) = app.settings.open else {
        return;
    };
    if category == Category::Service {
        app.settings.data.service.start();
        app.outbox
            .push(jobs::load_service(app.settings.service_probe));
        return;
    }
    if !app.link.is_connected() {
        return;
    }
    let s = &mut app.settings;
    let stability_wanted = nrr_client_logic::stability::any_key_applies(Some(&s.supports_map()));
    let day = s.clock.local_day();
    let mut queue = Vec::new();
    match category {
        Category::Notifications => {
            s.data.mutes.start();
            queue.push(jobs::load_mutes());
        }
        Category::Routing => {
            s.data.policy.start();
            queue.push(jobs::load_policy());
            if stability_wanted {
                s.data.stability.start();
                queue.push(jobs::load_stability());
            }
        }
        Category::FailurePolicy => {
            s.data.failure_policy.start();
            queue.push(jobs::load_failure_policy());
        }
        Category::Logs => {
            s.data.log_retention.start();
            s.data.storage.start();
            s.data.retention.start();
            queue.push(jobs::load_log_retention());
            if stability_wanted {
                s.data.stability.start();
                queue.push(jobs::load_stability());
            }
            queue.push(jobs::load_storage());
            queue.push(jobs::load_retention());
        }
        Category::Traffic => {
            s.data.traffic.start();
            queue.push(jobs::load_traffic(day));
        }
        Category::Service | Category::Presets | Category::Updates | Category::Terminal => {}
    }
    for job in queue {
        app.outbox.push(job);
    }
}

// ── Changing ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum Input {
    Toggle,
    Pick(&'static str),
    Number(i64),
    Text(String),
    Run,
}

/// Rows that only edit the form on screen, or the terminal's own file.
fn needs_service(id: ItemId) -> bool {
    !matches!(
        id,
        ItemId::MuteScope
            | ItemId::MuteTarget
            | ItemId::MuteForever
            | ItemId::MuteAmount
            | ItemId::MuteUnit
            | ItemId::ExportPath
            | ItemId::Pref(_)
            | ItemId::ServiceStart
            | ItemId::ServiceStop
            | ItemId::ServiceRestart
            | ItemId::None
    )
}

fn activate(app: &mut AppState, item: &Item, input: Input) {
    if needs_service(item.id) && !app.link.is_connected() {
        app.settings.refuse(Words::Key(text::OFFLINE));
        return;
    }
    let toggled = match item.kind {
        Kind::Toggle(on) => !on,
        _ => false,
    };
    let job = match (item.id, input) {
        (ItemId::HideKind(kind), Input::Pick(choice)) => hide_kind(app, kind, choice),
        (ItemId::RemoveMute(index), Input::Run) => {
            let scope = app
                .settings
                .data
                .mutes
                .ready()
                .and_then(|m| items::fine_mutes(m).get(index).map(|m| m.scope.clone()));
            scope.map(|scope| jobs::remove_mutes(vec![scope]))
        }
        (ItemId::ClearMutes, Input::Run) => app.settings.data.mutes.ready().map(|m| {
            jobs::remove_mutes(
                items::fine_mutes(m)
                    .into_iter()
                    .map(|m| m.scope.clone())
                    .collect(),
            )
        }),
        (ItemId::MuteAdd, Input::Run) => add_mute(app),
        (ItemId::Policy(key), input) => {
            let value = match input {
                Input::Toggle => Value::Bool(toggled),
                Input::Pick("fail-closed") if key == "kill-switch-fail-closed" => Value::Bool(true),
                Input::Pick("fail-open") if key == "kill-switch-fail-closed" => Value::Bool(false),
                Input::Pick(slug) => Value::from(slug),
                Input::Number(n) => Value::from(n),
                Input::Text(text) => Value::from(text),
                Input::Run => return,
            };
            Some(policy_change(app, vec![(key, value)]))
        }
        (ItemId::Protocol(bit), Input::Toggle) => protocol(app, bit),
        (ItemId::ShortToggle, Input::Toggle) => {
            let suffix = policy_field(app, items::policy_text, "short-name-suffix");
            Some(policy_change(
                app,
                vec![
                    ("short-name-completion", Value::Bool(toggled)),
                    ("short-name-suffix", Value::from(suffix)),
                ],
            ))
        }
        (ItemId::ShortSuffix, Input::Text(suffix)) => {
            let on = policy_field(app, items::policy_bool, "short-name-completion");
            Some(policy_change(
                app,
                vec![
                    ("short-name-completion", Value::Bool(on)),
                    ("short-name-suffix", Value::from(suffix)),
                ],
            ))
        }
        (ItemId::ProbeReset, Input::Run) => {
            let defaults = items::PROBE_LIMITS
                .iter()
                .filter_map(|(key, ..)| {
                    route_policy::field_default(key).map(|d| (*key, d.to_value()))
                })
                .collect();
            Some(policy_change(app, defaults))
        }
        (ItemId::Stability(key), Input::Toggle) => stability_change(app, key, Value::Bool(toggled)),
        (ItemId::Stability(key), Input::Number(n)) => {
            if key == "secondary-liveness-window-secs" && (1..5).contains(&n) {
                app.settings.refuse(Words::Key(text::LIVENESS_RANGE));
                return;
            }
            stability_change(app, key, Value::from(n))
        }
        (ItemId::RuleLock, Input::Toggle) => {
            stability_change(app, "allow-user-rule-edits", Value::Bool(toggled))
        }
        (ItemId::StopPersist, Input::Toggle) => stability_change(
            app,
            "routing-stop-policy",
            Value::from(if toggled { "persist" } else { "teardown" }),
        ),
        (ItemId::LogWindow(key), Input::Pick(change)) => {
            stability_change(app, key, Value::from(change))
        }
        (ItemId::FailurePolicy, Input::Pick(slug)) => Some(jobs::set_failure_policy(slug)),
        (ItemId::ServiceStart, Input::Run) => Some(jobs::control_service(
            jobs::ServiceOp::Start,
            app.settings.service_probe,
        )),
        (ItemId::ServiceStop, Input::Run) => Some(jobs::control_service(
            jobs::ServiceOp::Stop,
            app.settings.service_probe,
        )),
        (ItemId::ServiceRestart, Input::Run) => Some(jobs::control_service(
            jobs::ServiceOp::Restart,
            app.settings.service_probe,
        )),
        (ItemId::ExportRun, Input::Run) => {
            let path = app.settings.export_path.trim().to_owned();
            if path.is_empty() {
                app.settings.refuse(Words::Key(text::EXPORT_NEED_PATH));
                return;
            }
            Some(jobs::export_settings(PathBuf::from(path)))
        }
        (ItemId::LogRetention(field), Input::Number(n)) => log_retention(app, field, n),
        (ItemId::ClearLogs, Input::Run) => Some(jobs::clear_logs()),
        (ItemId::Revisions(field), Input::Number(n)) => revisions(app, Some((field, n)), None),
        (ItemId::PinLkg, Input::Toggle) => revisions(app, None, Some(toggled)),
        (ItemId::Traffic(field), Input::Toggle) => traffic(app, |s| match field {
            TrafficField::Enabled => s.enabled = toggled,
            TrafficField::Loopback => s.count_loopback = toggled,
            TrafficField::Virtual => s.count_virtual = toggled,
        }),
        (ItemId::TrafficRetention, Input::Number(n)) => traffic(app, |s| {
            s.retention_days = u32::try_from(n).unwrap_or(s.retention_days);
        }),
        (ItemId::TrafficReset, Input::Run) => {
            Some(jobs::clear_traffic(app.settings.clock.local_day()))
        }
        // The form and the terminal's own settings change here and now.
        (ItemId::MuteScope, Input::Pick(slug)) => {
            let form = &mut app.settings.mute_form;
            form.scope = match slug {
                "host" => MuteScope::Host,
                "app" => MuteScope::App,
                _ => MuteScope::All,
            };
            None
        }
        (ItemId::MuteTarget, Input::Text(target)) => {
            app.settings.mute_form.target = target;
            None
        }
        (ItemId::MuteForever, Input::Toggle) => {
            app.settings.mute_form.forever = toggled;
            None
        }
        (ItemId::MuteAmount, Input::Number(n)) => {
            app.settings.mute_form.amount = n;
            None
        }
        (ItemId::MuteUnit, Input::Pick(slug)) => {
            app.settings.mute_form.unit = match slug {
                "minutes" => MuteUnit::Minutes,
                "days" => MuteUnit::Days,
                _ => MuteUnit::Hours,
            };
            None
        }
        (ItemId::ExportPath, Input::Text(path)) => {
            app.settings.export_path = path;
            None
        }
        (ItemId::Pref(field), Input::Toggle) => {
            save_pref(app, field, toggled);
            None
        }
        _ => None,
    };
    if let Some(job) = job {
        app.settings.say(Words::Key(text::SAVING), None);
        app.outbox.push(job);
    }
}

fn policy_field<T>(app: &AppState, read: fn(&Map<String, Value>, &str) -> T, key: &str) -> T
where
    T: Default,
{
    app.settings
        .data
        .policy
        .ready()
        .map(|p| read(p, key))
        .unwrap_or_default()
}

fn policy_change(_app: &AppState, changes: Vec<(&'static str, Value)>) -> crate::backend::Job {
    let changes: Map<String, Value> = changes
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    jobs::write_policy(changes)
}

fn protocol(app: &mut AppState, bit: i32) -> Option<crate::backend::Job> {
    let key = route_policy::KILL_SWITCH_PROTOCOLS_KEY;
    let mask = app
        .settings
        .data
        .policy
        .ready()
        .and_then(|p| route_policy::effective(p, key))
        .unwrap_or(Value::Null);
    if route_policy::kill_switch_protocol_locked(&mask, bit) {
        app.settings.refuse(Words::Key(text::PROTOCOL_LAST));
        return None;
    }
    let current = mask
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(route_policy::KILL_SWITCH_PROTOCOLS_ALL);
    Some(policy_change(app, vec![(key, Value::from(current ^ bit))]))
}

/// A stability change, cut to what this system's service applies.
fn stability_change(
    app: &mut AppState,
    key: &'static str,
    value: Value,
) -> Option<crate::backend::Job> {
    let mut partial = Map::new();
    partial.insert(key.to_owned(), value);
    let partial = nrr_client_logic::stability::patch_for_platform(
        &partial,
        Some(&app.settings.supports_map()),
    );
    if partial.is_empty() {
        app.settings.refuse(Words::Key(text::UNSUPPORTED));
        return None;
    }
    Some(jobs::write_stability(partial))
}

fn hide_kind(app: &mut AppState, kind: &'static str, choice: &str) -> Option<crate::backend::Job> {
    let scope = items::kind_scope(kind);
    if choice == "show" {
        let muted = app
            .settings
            .data
            .mutes
            .ready()
            .is_some_and(|m| items::kind_mute(m, kind).is_some());
        return muted.then(|| jobs::remove_mutes(vec![scope]));
    }
    let now = app.settings.clock.now();
    let request = if kind == items::BLOCK_NOTICES {
        let span = NOTICE_MUTE_CHOICES_MS
            .iter()
            .find(|(slug, _)| *slug == choice)
            .map(|(_, span)| *span)?;
        let mut request = json!({ "scope": { "kind": "all" } });
        if span > 0 {
            request["until-unix-ms"] = Value::from(now.saturating_add(span));
        }
        request
    } else {
        notice_mute_request(kind, choice, now)?
    };
    Some(jobs::set_mute(request, false))
}

fn add_mute(app: &mut AppState) -> Option<crate::backend::Job> {
    let form = app.settings.mute_form.clone();
    let target = form.target.trim().to_owned();
    let scope = match form.scope {
        MuteScope::All => BlockNoticeMuteScopeDto::All,
        _ if target.is_empty() => {
            app.settings.refuse(Words::Key(text::NEED_TARGET));
            return None;
        }
        MuteScope::Host => BlockNoticeMuteScopeDto::Host { host: target },
        MuteScope::App => BlockNoticeMuteScopeDto::App { app: target },
    };
    let mut request = json!({ "scope": scope });
    if !form.forever {
        let until = app
            .settings
            .clock
            .now()
            .saturating_add(form.amount.saturating_mul(form.unit.millis()));
        request["until-unix-ms"] = Value::from(until);
    }
    Some(jobs::set_mute(request, true))
}

const MIB: u64 = 1024 * 1024;

fn log_retention(app: &mut AppState, field: LogField, n: i64) -> Option<crate::backend::Job> {
    let current = app.settings.data.log_retention.ready()?.clone();
    let mut request = LogRetentionConfigSetRequest {
        log_max_age_days: current.log_max_age_days,
        log_max_size_bytes: current.log_max_size_bytes,
        audit_max_age_days: current.audit_max_age_days,
        audit_max_size_bytes: current.audit_max_size_bytes,
    };
    let days = u32::try_from(n).ok()?;
    let bytes = u64::try_from(n).ok()?.saturating_mul(MIB);
    match field {
        LogField::LogsAge => request.log_max_age_days = days,
        LogField::LogsSize => request.log_max_size_bytes = bytes,
        LogField::AuditAge => request.audit_max_age_days = days,
        LogField::AuditSize => request.audit_max_size_bytes = bytes,
    }
    Some(jobs::set_log_retention(request))
}

fn revisions(
    app: &mut AppState,
    number: Option<(RevisionField, i64)>,
    pin: Option<bool>,
) -> Option<crate::backend::Job> {
    let current = app.settings.data.retention.ready()?.clone();
    let mut request = RetentionSettingsSetRequest {
        superseded_days: current.superseded_days,
        superseded_count_cap: current.superseded_count_cap,
        rejected_days: current.rejected_days,
        rolledback_days: current.rolledback_days,
        rolledback_count_cap: current.rolledback_count_cap,
        pin_lkg: pin.unwrap_or(current.pin_lkg),
    };
    if let Some((field, n)) = number {
        let n = u32::try_from(n).ok()?;
        match field {
            RevisionField::SupersededDays => request.superseded_days = n,
            RevisionField::SupersededCount => request.superseded_count_cap = n,
            RevisionField::RejectedDays => request.rejected_days = n,
            RevisionField::RolledbackDays => request.rolledback_days = n,
            RevisionField::RolledbackCount => request.rolledback_count_cap = n,
        }
    }
    Some(jobs::set_retention(request))
}

fn traffic(
    app: &mut AppState,
    change: impl FnOnce(&mut TrafficStatsSettingsDto),
) -> Option<crate::backend::Job> {
    let mut settings = app.settings.data.traffic.ready()?.settings.clone();
    change(&mut settings);
    Some(jobs::set_traffic(settings, app.settings.clock.local_day()))
}

fn save_pref(app: &mut AppState, field: PrefField, on: bool) {
    let s = &mut app.settings;
    let Some(path) = s.prefs_path.clone() else {
        s.refuse(Words::Key(text::PREF_NO_FILE));
        return;
    };
    let mut prefs = s.prefs;
    match field {
        PrefField::Plain => prefs.plain = on,
        PrefField::NoColor => prefs.no_color = on,
        PrefField::Ascii => prefs.ascii = on,
    }
    match prefs::save(&path, prefs) {
        Ok(()) => {
            s.prefs = prefs;
            s.done(Words::Key(text::PREF_SAVED));
        }
        Err(error) => s.failed(text::PREF_SAVE_FAILED, Failure::detail(error.to_string())),
    }
}

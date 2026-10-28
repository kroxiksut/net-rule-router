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
mod providers;
mod reset;
#[cfg(test)]
mod tests;
mod text;

use std::io;
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::notice_mutes::{notice_mute_request, NOTICE_MUTE_CHOICES_MS};
use nrr_client_logic::route_policy;
use nrr_ipc_client::IpcClientError;
use nrr_platform_api::console_path::ConsolePathState;
use nrr_platform_api::path_registration::PathRegistrationPort;
use nrr_platform_api::service_control::ServiceStatusReport;
use nrr_platform_api::service_placement::RegistrationCheck;
use nrr_shared::ipc_payloads::{
    BlockNoticeMuteDto, BlockNoticeMuteScopeDto, ConnHistoryListResponse, DohResolverEntryDto,
    DohResolversGetResponse, LocalDnsSuffixesGetResponse, LocalNetworksGetResponse,
    LogRetentionConfigDto, LogRetentionConfigSetRequest, RetentionSettingsDto,
    RetentionSettingsSetRequest, RollbackTargetDto, SettingsExportFullRequest, StorageUsageDto,
    ThirdPartyComponentsListResponse, TrafficStatsGetResponse, TrafficStatsSettingsDto,
};
use nrr_shared::ipc_transport::IpcErrorCode;
use nrr_shared::merge_dto::MergePolicyDto;
use nrr_shared::platform_profile::{PlatformProfile, PlatformSupports};
use serde_json::{json, Map, Value};

pub use clock::Clock;
use items::{
    IpcField, Item, ItemId, Kind, LogField, PrefField, RevisionField, TrafficField, Words,
};
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
            Self::Updates => text::ABOUT,
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
        // A plain refusal for want of rights is answered with how to start the
        // terminal with them; the authority's own outcome (declined, nobody to
        // prompt, no authority) keeps its words.
        let elevation = slug == IpcErrorCode::Forbidden.client_slug()
            && matches!(
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

/// How to start the terminal with the rights a machine-wide action needs.
pub fn elevation_text(texts: &Texts) -> String {
    texts.get(if cfg!(windows) {
        text::NEEDS_ELEVATION_WINDOWS
    } else {
        text::NEEDS_ELEVATION_UNIX
    })
}

/// The words for a failure: the remedy for missing rights, the GUI's wording
/// for a known service code, else what the source said.
pub fn failure_text(failure: &Failure, texts: &Texts) -> String {
    if failure.elevation {
        return elevation_text(texts);
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

/// How the registered service stands against this terminal's own build.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceCheck {
    pub registration: RegistrationCheck,
    /// The running service is provably an older build than this terminal.
    pub older: bool,
}

/// The host's `PATH` mechanism and the folder holding the console beside
/// this terminal; an error says why there is none.
pub type ConsolePort = fn() -> Result<(Box<dyn PathRegistrationPort>, PathBuf), String>;

/// What the service answered, per section.
#[derive(Clone, Debug, Default)]
pub struct Data {
    /// The raw `route-policy` of the last snapshot, the base of every write.
    pub policy: Loadable<Map<String, Value>>,
    pub stability: Loadable<Map<String, Value>>,
    /// The machine-wide home-network suffix list, with the network's offers.
    pub local_suffixes: Loadable<LocalDnsSuffixesGetResponse>,
    /// The local networks leak protection may leave reachable.
    pub local_networks: Loadable<LocalNetworksGetResponse>,
    /// The machine-wide DoH/DoT resolver list, read when it is opened.
    pub doh_resolvers: Loadable<DohResolversGetResponse>,
    pub mutes: Loadable<Vec<BlockNoticeMuteDto>>,
    pub failure_policy: Loadable<String>,
    pub retention: Loadable<RetentionSettingsDto>,
    pub log_retention: Loadable<LogRetentionConfigDto>,
    pub storage: Loadable<StorageUsageDto>,
    pub traffic: Loadable<TrafficStatsGetResponse>,
    /// The shipped third-party binaries and how they check out.
    pub third_party: Loadable<ThirdPartyComponentsListResponse>,
    /// The caller's own connection-history choices.
    pub conn_history: Loadable<ConnHistoryListResponse>,
    pub service: Loadable<ServiceInfo>,
    /// Read with `service`, for a registered one.
    pub service_check: Option<ServiceCheck>,
    /// Where the service writes its logs, read with `service`.
    pub logs_folder: Loadable<Option<PathBuf>>,
    pub console: Loadable<ConsolePathState>,
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
    /// An action that cannot be undone waits for a second yes. The row is
    /// kept as asked: a list read meanwhile may move it.
    Confirming { item: Box<Item> },
    /// A pick that would hold traffic (a leak-protection level, or a default
    /// route that raises it) waits for a yes, for the row `id`.
    ConfirmingPick {
        id: ItemId,
        slug: &'static str,
        why: route_policy::LeakProtectionConfirm,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub words: Words,
    pub tone: Option<StateTone>,
}

/// What the safe-rollback lookup found; the token is spent by one rollback.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RollbackOffer {
    #[default]
    Unasked,
    Nothing,
    Ready {
        token: String,
        target: RollbackTargetDto,
    },
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
    /// The suffix typed and not yet added.
    pub local_suffix_new: String,
    pub local_network_new: String,
    /// The list of shared addresses left open is shown.
    pub shared_exemptions_open: bool,
    /// The resolver list is open, and the entry being typed for it.
    pub doh_open: bool,
    pub doh_new_target: String,
    pub doh_new_comment: String,
    pub export_path: String,
    /// Where the traffic CSV goes, and the unit of its byte columns.
    pub traffic_export_path: String,
    pub traffic_export_unit: &'static str,
    /// Why protection is being switched off, kept in the audit trail.
    pub safe_disable_reason: String,
    /// The term picked for the next safe disable.
    pub safe_disable_term: &'static str,
    /// How long the next pause from the rules toggle lasts.
    pub pause_term: &'static str,
    pub rollback: RollbackOffer,
    /// Files and bytes clearing the logs would delete, read when it is asked.
    pub log_clear_preview: Loadable<(u64, u64)>,
    pub prefs: TuiPrefs,
    /// Where the terminal's settings are saved; `None` cannot save.
    pub prefs_path: Option<PathBuf>,
    /// Why that file did not read, at start or at the last save: saves are
    /// refused until it reads again, and the Status screen says so.
    pub prefs_damaged: Option<prefs::Damaged>,
    pub clock: Clock,
    pub service_probe: RegistrationProbe,
    /// The service binary shipped beside this terminal, when it is there.
    pub expected_service: Option<PathBuf>,
    pub console_port: ConsolePort,
    /// After a registration: open terminals still need the line shown.
    pub console_hint: bool,
    pub supports: PlatformSupports,
    /// Where this OS keeps its hosts file, shown beside the bypass toggle.
    pub hosts_file_path: String,
    /// The hosts file holds a real mapping; a stock file hides the group, as
    /// in the window. Read each time Routing opens.
    pub hosts_file_has_entries: bool,
    /// Who wins a rule the bound files and the service hold differently;
    /// read from the shared settings file when Rule sets opens.
    pub merge_policy: MergePolicyDto,
    pub reset: reset::ResetState,
    pub providers: providers::ProvidersState,
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
            local_suffix_new: String::new(),
            local_network_new: String::new(),
            shared_exemptions_open: false,
            doh_open: false,
            doh_new_target: String::new(),
            doh_new_comment: String::new(),
            export_path: String::new(),
            traffic_export_path: String::new(),
            traffic_export_unit: "mb",
            safe_disable_reason: String::new(),
            safe_disable_term: "until-restart",
            pause_term: "until-resumed",
            rollback: RollbackOffer::default(),
            log_clear_preview: Loadable::NotLoaded,
            prefs: TuiPrefs::default(),
            prefs_path: None,
            prefs_damaged: None,
            clock: Clock::default(),
            service_probe: crate::platform::service_control,
            expected_service: sibling_service_binary(),
            console_port: crate::platform::console_path_port,
            console_hint: false,
            supports: PlatformProfile::current().supports,
            hosts_file_path: PlatformProfile::current().hosts_file_path,
            hosts_file_has_entries: true,
            merge_policy: MergePolicyDto::Union,
            reset: reset::ResetState::default(),
            providers: providers::ProvidersState::default(),
        }
    }
}

/// The service binary beside this executable: only the sibling counts, as
/// for the window.
fn sibling_service_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe
        .parent()?
        .join(nrr_shared::product_identity::BinaryRole::Service.host_file_name());
    path.is_file().then_some(path)
}

impl SettingsState {
    /// Saves the terminal's options to its file; `None` without one.
    pub(crate) fn save_prefs(&mut self) -> Option<io::Result<()>> {
        let path = self.prefs_path.as_deref()?;
        let result = prefs::save(path, self.prefs);
        Some(self.note_prefs_write(result))
    }

    /// Puts another part's section into the terminal's file; `None` without one.
    pub(crate) fn write_prefs(&mut self, entries: Map<String, Value>) -> Option<io::Result<()>> {
        let path = self.prefs_path.as_deref()?;
        let result = prefs::write_merged(path, entries);
        Some(self.note_prefs_write(result))
    }

    /// Every write reads the file first, so its outcome is the file's state.
    fn note_prefs_write(&mut self, result: io::Result<()>) -> io::Result<()> {
        self.prefs_damaged = result.as_ref().err().and_then(prefs::damage_of);
        result
    }

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

    fn text_target(&self, app: &AppState) -> crate::paste::TextTarget {
        match app.settings.mode {
            Mode::Editing { .. } => crate::paste::TextTarget::Line,
            _ => crate::paste::TextTarget::None,
        }
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
            Mode::Confirming { .. } | Mode::ConfirmingPick { .. } => Some(text::PLAIN_CONFIRM),
        }
    }
}

// ── Drawing ──────────────────────────────────────────────────────────────────

/// The row with the cursor: `>` and bold, so it never rests on colour.
fn marked(cursor: bool, text: String) -> Segment {
    if cursor {
        Segment::selected(format!("> {text}"))
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
                        ViewLine::new(vec![Segment::selected(line)])
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
        (Mode::Confirming { item: asked }, _) if asked.id == ItemId::ClearLogs => {
            let mut lines = vec![
                indent(texts.get(text::CLEAR_LOGS_BODY)),
                indent(clear_preview_text(&app.settings.log_clear_preview, texts)),
            ];
            if focused {
                lines.push(indent(texts.get(text::CONFIRM)));
            }
            lines
        }
        (Mode::Confirming { .. }, _) if focused => vec![indent(texts.get(text::CONFIRM))],
        (Mode::ConfirmingPick { why, .. }, _) if focused => {
            let mut lines = leak_confirm_lines(app, *why, texts);
            lines.push(indent(texts.get(text::CONFIRM)));
            lines
        }
        (Mode::Browse, _) => item
            .note
            .iter()
            .map(|note| indent(note.resolve(texts)))
            .collect(),
        _ => Vec::new(),
    }
}

/// What the service said a clear would delete, before anything is.
fn clear_preview_text(preview: &Loadable<(u64, u64)>, texts: &Texts) -> String {
    match preview {
        Loadable::Ready((files, bytes)) => texts.fill(
            text::CLEAR_LOGS_PREVIEW,
            &[
                ("count", files.to_string()),
                (
                    "size",
                    nrr_client_logic::units::format_storage_bytes(*bytes),
                ),
            ],
        ),
        Loadable::Failed(failure) => texts.fill(
            text::LOAD_FAILED,
            &[("error", failure_text(failure, texts))],
        ),
        Loadable::NotLoaded => texts.get(text::NO_DATA),
        Loadable::Loading => texts.get(text::LOADING),
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
    if category == Category::Routing {
        s.hosts_file_has_entries = nrr_platform_api::hosts_file::hosts_file_has_entries(
            std::path::Path::new(&s.hosts_file_path),
        );
    }
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

/// The list of sections, as going back from a section shows it.
pub fn show_sections(app: &mut AppState) {
    back(app);
}

/// Opens `category`, as choosing it in the list of sections does.
pub fn open_category(app: &mut AppState, category: Category) {
    if let Some(index) = Category::ALL.iter().position(|c| *c == category) {
        open_section(app, index);
    }
}

/// Another surface changed what `category` shows: re-read it while it is on
/// screen, unless the user is in the middle of a change of their own.
pub fn reload_if_open(app: &mut AppState, category: Category) {
    if app.screen == crate::screens::ScreenId::Settings
        && app.settings.open == Some(category)
        && app.settings.mode == Mode::Browse
    {
        load(app);
    }
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
        Kind::Action { confirm: true } => {
            if item.id == ItemId::ClearLogs && app.link.is_connected() {
                app.settings.log_clear_preview = Loadable::Loading;
                app.outbox.push(jobs::preview_clear_logs());
            }
            Mode::Confirming {
                item: Box::new(item.clone()),
            }
        }
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
            let asks_about_protection = matches!(
                item.id,
                ItemId::Policy(route_policy::LEAK_PROTECTION_KEY) | ItemId::Policy("mode")
            );
            if asks_about_protection && app.link.is_connected() {
                let id = item.id;
                app.outbox.push(jobs::reread_policy_then(move |app| {
                    decide_pick(app, id, slug)
                }));
                return;
            }
            if let Some(why) = leak_confirm(app, &item, slug) {
                app.settings.mode = Mode::ConfirmingPick {
                    id: item.id,
                    slug,
                    why,
                };
                return;
            }
            activate(app, &item, Input::Pick(slug));
        }
    }
}

/// The confirmation decision over the policy just read again.
fn decide_pick(app: &mut AppState, id: ItemId, slug: &'static str) {
    let found = app
        .settings
        .open
        .and_then(|category| items::items(app, category).into_iter().find(|i| i.id == id));
    let Some(item) = found else {
        app.settings.refuse(Words::Key(text::CONFIRM_GONE));
        return;
    };
    if let Some(why) = leak_confirm(app, &item, slug) {
        app.settings.mode = Mode::ConfirmingPick { id, slug, why };
        return;
    }
    activate(app, &item, Input::Pick(slug));
}

/// What a pick must be confirmed for, as the window and the tray decide it:
/// a leak-protection level, or a default route whose write raises the level.
fn leak_confirm(
    app: &AppState,
    item: &Item,
    next: &str,
) -> Option<route_policy::LeakProtectionConfirm> {
    let Loadable::Ready(policy) = &app.settings.data.policy else {
        return None;
    };
    let level = items::leak_protection(policy);
    let secondary = bound_secondary_row(app);
    match item.id {
        ItemId::Policy(route_policy::LEAK_PROTECTION_KEY) => {
            route_policy::leak_protection_confirm(level, next, secondary)
        }
        ItemId::Policy("mode") => {
            route_policy::default_route_change_confirm(level, next, secondary)
        }
        _ => None,
    }
}

fn bound_secondary_row(app: &AppState) -> Option<&nrr_shared::ipc_payloads::InterfaceRowDto> {
    let snapshot = app.snapshot.as_ref()?;
    let binding = snapshot.route_policy.as_ref()?.secondary.as_ref()?;
    crate::screens::status::bound_row(&snapshot.adapters.rows, binding)
}

fn leak_confirm_lines(
    app: &AppState,
    why: route_policy::LeakProtectionConfirm,
    texts: &Texts,
) -> Vec<ViewLine> {
    use crate::screens::interfaces::keys as ik;
    let words = match why {
        route_policy::LeakProtectionConfirm::HoldsNow => vec![
            texts.get(text::LEAK_HOLDS_TITLE),
            texts.get(text::LEAK_HOLDS_BODY),
            texts.get(text::LEAK_HOLDS_EFFECT),
        ],
        route_policy::LeakProtectionConfirm::Unroutable => {
            let name = bound_secondary_row(app)
                .map(nrr_client_logic::adapters::display_name)
                .unwrap_or_default();
            vec![
                texts.get(ik::UNROUTABLE_TITLE),
                texts.fill(ik::UNROUTABLE_ADAPTER, &[("name", &name)]),
                texts.get(text::LEAK_UNROUTABLE_BODY),
                texts.get(text::LEAK_UNROUTABLE_EFFECT),
            ]
        }
    };
    words
        .into_iter()
        .map(|text| ViewLine::text(format!("      {text}")))
        .collect()
}

/// The row a question was about, found again by what it says rather than by
/// the cursor: a list read while the question was up may have moved it, and
/// a row by number would then be another one. Gone or changed, nothing runs.
fn run_confirmed(app: &mut AppState, asked: &Item) {
    let found = app.settings.open.and_then(|category| {
        items::items(app, category).into_iter().find(|i| {
            std::mem::discriminant(&i.id) == std::mem::discriminant(&asked.id)
                && i.label == asked.label
                && i.kind == asked.kind
        })
    });
    match found {
        Some(item) => activate(app, &item, Input::Run),
        None => app.settings.refuse(Words::Key(text::CONFIRM_GONE)),
    }
}

fn run_confirmed_pick(app: &mut AppState, id: ItemId, slug: &'static str) {
    let found = app
        .settings
        .open
        .and_then(|category| items::items(app, category).into_iter().find(|i| i.id == id));
    match found {
        Some(item) => activate(app, &item, Input::Pick(slug)),
        None => app.settings.refuse(Words::Key(text::CONFIRM_GONE)),
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
        Mode::Confirming { item } => {
            if key.code == KeyCode::Enter {
                run_confirmed(app, &item);
            }
            true
        }
        Mode::ConfirmingPick { id, slug, .. } => {
            if key.code == KeyCode::Enter {
                run_confirmed_pick(app, id, slug);
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
        Mode::Confirming { item } => {
            if is_yes(line) {
                run_confirmed(app, &item);
            }
            return true;
        }
        Mode::ConfirmingPick { id, slug, .. } => {
            if is_yes(line) {
                run_confirmed_pick(app, id, slug);
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
        Kind::Action { confirm: true } if is_yes(rest) => run_confirmed(app, &item),
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
    if category == Category::Presets {
        app.settings.merge_policy = app
            .rules
            .settings_file
            .as_deref()
            .and_then(|file| crate::screens::rules::own_settings::merge_policy(file).ok())
            .unwrap_or_default();
    }
    if category == Category::Service {
        let s = &mut app.settings;
        s.data.service.start();
        s.data.console.start();
        let service = jobs::load_service(s.service_probe, s.expected_service.clone());
        let console = jobs::load_console(s.console_port);
        app.outbox.push(service);
        app.outbox.push(console);
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
            s.data.local_suffixes.start();
            queue.push(jobs::load_local_suffixes());
            if s.supports.local_network_exceptions {
                s.data.local_networks.start();
                queue.push(jobs::load_local_networks());
            }
            if stability_wanted {
                s.data.stability.start();
                queue.push(jobs::load_stability());
            }
            // The fake-IP row names its driver's verdict.
            s.data.third_party.start();
            queue.push(jobs::load_third_party());
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
            s.data.conn_history.start();
            queue.push(jobs::load_conn_history());
        }
        Category::Traffic => {
            s.data.traffic.start();
            queue.push(jobs::load_traffic(day));
        }
        Category::Presets => {
            s.reset.others.start();
            queue.push(reset::load_others());
        }
        Category::Updates => {
            s.data.third_party.start();
            queue.push(jobs::load_third_party());
        }
        Category::Service | Category::Terminal => {}
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
            | ItemId::LocalSuffixNew
            | ItemId::LocalNetworkNew
            | ItemId::DohNewTarget
            | ItemId::SharedExemptionsDetails
            | ItemId::DohNewComment
            | ItemId::Provider(providers::ProviderRow::New)
            | ItemId::Provider(providers::ProviderRow::Scan)
            | ItemId::Reset(reset::ResetRow::Scope)
            | ItemId::ExportPath
            | ItemId::MergePolicy
            | ItemId::TrafficExportPath
            | ItemId::TrafficExportUnit
            | ItemId::SafeDisableReason
            | ItemId::SafeDisableTerm
            | ItemId::RulesPauseTerm
            | ItemId::Pref(_)
            | ItemId::ServiceStart
            | ItemId::ServiceStop
            | ItemId::ServiceRestart
            | ItemId::ConsolePath
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
        (ItemId::Reset(row), input) => reset::activate(app, row, input),
        (ItemId::Provider(row), input) => providers::activate(app, row, input),
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
        (ItemId::LocalSuffixNew, Input::Text(suffix)) => {
            app.settings.local_suffix_new = suffix;
            None
        }
        (ItemId::LocalSuffixAdd, Input::Run) => {
            let typed = app.settings.local_suffix_new.trim().to_owned();
            if typed.is_empty() {
                app.settings.refuse(Words::Key(text::NEED_SUFFIX));
                return;
            }
            local_suffix_change(app, |list| list.push(typed))
        }
        (ItemId::LocalSuffixAccept(index), Input::Run) => {
            let offered = app
                .settings
                .data
                .local_suffixes
                .ready()
                .and_then(|l| l.offered.get(index).map(|o| o.suffix.clone()));
            offered.and_then(|suffix| local_suffix_change(app, |list| list.push(suffix)))
        }
        (ItemId::LocalNetwork(index), Input::Toggle) => local_network_cidr(app, index)
            .map(|cidr| jobs::write_local_networks(vec![(cidr, toggled)], Vec::new())),
        (ItemId::LocalNetworkForget(index), Input::Run) => local_network_cidr(app, index)
            .map(|cidr| jobs::write_local_networks(Vec::new(), vec![cidr])),
        (ItemId::IpcPolicy, Input::Pick(kind)) => ipc_policy_change(app, |policy| {
            if kind == "critical" {
                *policy = json!({ "kind": "critical" });
            } else if policy.get("kind").and_then(Value::as_str) != Some("recoverable") {
                *policy = json!({ "kind": "recoverable", "max-restarts": 20,
                                  "backoff-base-ms": 100, "backoff-cap-ms": 5000 });
            }
            Ok(())
        }),
        (ItemId::IpcNumber(field), Input::Number(n)) => ipc_policy_change(app, |policy| {
            let (key, value) = match field {
                IpcField::MaxRestarts => ("max-restarts", n),
                IpcField::BackoffBaseMs => ("backoff-base-ms", n),
                IpcField::BackoffCapSecs => ("backoff-cap-ms", n.saturating_mul(1000)),
            };
            policy[key] = json!(value);
            let base = policy
                .get("backoff-base-ms")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let cap = policy
                .get("backoff-cap-ms")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if cap < base {
                return Err(text::IPC_CAP_BELOW_BASE);
            }
            Ok(())
        }),
        (ItemId::CacheRefresh, Input::Number(minutes)) => stability_change(
            app,
            "cache-refresh-interval-secs",
            json!(minutes.saturating_mul(60)),
        ),
        (ItemId::SharedExemptionsDetails, Input::Run) => {
            app.settings.shared_exemptions_open = !app.settings.shared_exemptions_open;
            None
        }
        (ItemId::DohManage, Input::Run) => {
            app.settings.doh_open = !app.settings.doh_open;
            app.settings.doh_open.then(|| {
                app.settings.data.doh_resolvers.start();
                jobs::load_doh_resolvers()
            })
        }
        (ItemId::DohResolver(index), Input::Toggle) => doh_change(app, |list| {
            if let Some(entry) = list.get_mut(index) {
                entry.enabled = toggled;
            }
        }),
        (ItemId::DohResolverRemove(index), Input::Run) => doh_change(app, |list| {
            if index < list.len() {
                list.remove(index);
            }
        }),
        (ItemId::DohNewTarget, Input::Text(target)) => {
            app.settings.doh_new_target = target;
            None
        }
        (ItemId::DohNewComment, Input::Text(comment)) => {
            app.settings.doh_new_comment = comment;
            None
        }
        (ItemId::DohAdd, Input::Run) => {
            let target = app.settings.doh_new_target.trim().to_owned();
            if target.is_empty() {
                app.settings.refuse(Words::Key(text::NEED_RESOLVER));
                return;
            }
            let comment = app.settings.doh_new_comment.trim().to_owned();
            doh_change(app, |list| list.push(doh_entry(target, comment)))
        }
        (ItemId::LocalNetworkNew, Input::Text(cidr)) => {
            app.settings.local_network_new = cidr;
            None
        }
        (ItemId::LocalNetworkAdd, Input::Run) => {
            let typed = app.settings.local_network_new.trim().to_owned();
            if typed.is_empty() {
                app.settings.refuse(Words::Key(text::NEED_NETWORK));
                return;
            }
            Some(jobs::write_local_networks(vec![(typed, true)], Vec::new()))
        }
        (ItemId::LocalSuffixRemove(index), Input::Run) => local_suffix_change(app, |list| {
            if index < list.len() {
                list.remove(index);
            }
        }),
        (ItemId::Policy("browser-history-auto-seed"), Input::Toggle) if toggled => {
            Some(jobs::write_auto_seed_on())
        }
        (ItemId::Policy(key), input) => {
            let value = match input {
                Input::Toggle => Value::Bool(toggled),
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
        (ItemId::Stability(key), Input::Pick(slug)) => {
            stability_change(app, key, Value::from(slug))
        }
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
        (ItemId::ServiceStart, Input::Run) => {
            // Starting would run the copy registered elsewhere, the one the
            // user is replacing: the window offers re-registering instead.
            let elsewhere = app
                .settings
                .data
                .service_check
                .as_ref()
                .is_some_and(|check| check.registration.registered_elsewhere);
            if elsewhere {
                app.settings.refuse(Words::Fill(
                    text::SERVICE_START_ELSEWHERE,
                    vec![("command", crate::link::admin_command("reinstall"))],
                ));
                return;
            }
            Some(jobs::control_service(
                jobs::ServiceOp::Start,
                app.settings.service_probe,
            ))
        }
        (ItemId::ConsolePath, Input::Run) => {
            let owned = app
                .settings
                .data
                .console
                .ready()
                .map(|state| state.owned_entry_present);
            owned.map(|owned| jobs::console_path_change(app.settings.console_port, !owned, owned))
        }
        (ItemId::ServiceStop, Input::Run) => Some(jobs::control_service(
            jobs::ServiceOp::Stop,
            app.settings.service_probe,
        )),
        (ItemId::ServiceRestart, Input::Run) => Some(jobs::control_service(
            jobs::ServiceOp::Restart,
            app.settings.service_probe,
        )),
        (ItemId::RulesPause, Input::Toggle) => {
            Some(jobs::set_rules_paused(!toggled, app.settings.pause_term))
        }
        (ItemId::RulesPauseTerm, Input::Pick(slug)) => {
            app.settings.pause_term = slug;
            None
        }
        (ItemId::SafeDisableReason, Input::Text(reason)) => {
            app.settings.safe_disable_reason = reason;
            None
        }
        (ItemId::SafeDisableTerm, Input::Pick(slug)) => {
            app.settings.safe_disable_term = slug;
            None
        }
        (ItemId::SafeDisableRun, Input::Run) => {
            let reason = app.settings.safe_disable_reason.trim().to_owned();
            if reason.is_empty() {
                app.settings
                    .refuse(Words::Key(text::SAFE_DISABLE_NEED_REASON));
                return;
            }
            Some(jobs::safe_disable(reason, app.settings.safe_disable_term))
        }
        (ItemId::RollbackLookup, Input::Run) => {
            app.settings.rollback = RollbackOffer::Unasked;
            Some(jobs::rollback_lookup())
        }
        (ItemId::RollbackRun, Input::Run) => {
            // The token is single-use: a second Enter finds nothing to spend.
            match std::mem::take(&mut app.settings.rollback) {
                RollbackOffer::Ready { token, target } => Some(jobs::rollback_run(token, target)),
                _ => None,
            }
        }
        (ItemId::ExportRun, Input::Run) => {
            let path = app.settings.export_path.trim().to_owned();
            if path.is_empty() {
                app.settings.refuse(Words::Key(text::EXPORT_NEED_PATH));
                return;
            }
            // The service keeps neither the bound files nor their sections
            // this build does not apply: both reach the export from here, as
            // from the window and as "Save to file" carries them.
            let [passthrough_primary, passthrough_secondary] =
                crate::screens::rules::bound_passthrough(app);
            let bound = app
                .rules
                .settings_file
                .as_deref()
                .and_then(|file| crate::screens::rules::own_settings::read(file).ok())
                .map(|settings| settings.rules_files)
                .unwrap_or_default();
            let named = |path: String| (!path.is_empty()).then_some(path);
            let request = SettingsExportFullRequest {
                rules_file_path_primary: named(bound.primary),
                rules_file_path_secondary: named(bound.secondary),
                passthrough_sections_primary: passthrough_primary,
                passthrough_sections_secondary: passthrough_secondary,
            };
            Some(jobs::export_settings(PathBuf::from(path), request))
        }
        (ItemId::LogRetention(field), Input::Number(n)) => log_retention(app, field, n),
        (ItemId::ClearLogs, Input::Run) => Some(jobs::clear_logs()),
        (ItemId::Revisions(field), Input::Number(n)) => revisions(app, Some((field, n)), None),
        (ItemId::PinLkg, Input::Toggle) => revisions(app, None, Some(toggled)),
        (ItemId::RevisionsReset, Input::Run) => {
            Some(jobs::set_retention(RetentionSettingsSetRequest::DEFAULT))
        }
        (ItemId::Traffic(field), Input::Toggle) => traffic(app, move |s| match field {
            TrafficField::Enabled => s.enabled = toggled,
            TrafficField::Loopback => s.count_loopback = toggled,
            TrafficField::Virtual => s.count_virtual = toggled,
        }),
        (ItemId::TrafficRetention, Input::Number(n)) => traffic(app, move |s| {
            s.retention_days = u32::try_from(n).unwrap_or(s.retention_days);
        }),
        (ItemId::TrafficMerge(merged), Input::Run) => {
            let day = app.settings.clock.local_day();
            app.settings
                .data
                .traffic
                .ready()
                .and_then(|stats| stats.history_merge.clone())
                .map(|q| jobs::answer_traffic_merge(q.old_key, q.new_key, merged, day))
        }
        (ItemId::TrafficExportPath, Input::Text(path)) => {
            app.settings.traffic_export_path = path;
            None
        }
        (ItemId::TrafficExportUnit, Input::Pick(unit)) => {
            app.settings.traffic_export_unit = unit;
            None
        }
        (ItemId::TrafficExport, Input::Run) => {
            let path = app.settings.traffic_export_path.trim().to_owned();
            if path.is_empty() {
                app.settings.refuse(Words::Key(text::EXPORT_NEED_PATH));
                return;
            }
            let day = app.settings.clock.local_day();
            let retention = app
                .settings
                .data
                .traffic
                .ready()
                .map_or(365, |stats| i64::from(stats.settings.retention_days));
            Some(jobs::export_traffic_csv(
                PathBuf::from(path),
                day - retention,
                day,
                app.settings.traffic_export_unit,
            ))
        }
        (ItemId::TrafficReset, Input::Run) => {
            Some(jobs::clear_traffic(app.settings.clock.local_day()))
        }
        (ItemId::HistoryEnabled, Input::Toggle) => {
            Some(jobs::set_conn_history(Some(toggled), None))
        }
        (ItemId::HistoryRetention, Input::Number(n)) => {
            Some(jobs::set_conn_history(None, u32::try_from(n).ok()))
        }
        (ItemId::HistoryClear, Input::Run) => Some(jobs::clear_conn_history()),
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
        (ItemId::MergePolicy, Input::Pick(slug)) => {
            save_merge_policy(app, MergePolicyDto::from_slug(slug));
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
/// The whole control-channel policy, as stored now with `edit` applied: the
/// service validates the object as one.
fn ipc_policy_change(
    app: &mut AppState,
    edit: impl FnOnce(&mut Value) -> Result<(), Key>,
) -> Option<crate::backend::Job> {
    let mut policy = app
        .settings
        .data
        .stability
        .ready()?
        .get("ipc-accept-policy")
        .cloned()
        .unwrap_or_else(|| json!({ "kind": "recoverable" }));
    if let Err(refusal) = edit(&mut policy) {
        app.settings.refuse(Words::Key(refusal));
        return None;
    }
    stability_change(app, "ipc-accept-policy", policy)
}

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

/// The network a listed row names, as the service spelled it.
fn local_network_cidr(app: &AppState, index: usize) -> Option<String> {
    app.settings
        .data
        .local_networks
        .ready()?
        .networks
        .get(index)
        .map(|network| network.cidr.clone())
}

/// A typed resolver, its kind told by whether it reads as an address, as the
/// window tells it.
fn doh_entry(target: String, comment: String) -> DohResolverEntryDto {
    let target_kind = if target.parse::<std::net::IpAddr>().is_ok() {
        "ip"
    } else {
        "host"
    };
    DohResolverEntryDto {
        target_kind: target_kind.to_owned(),
        target,
        comment,
        enabled: true,
    }
}

/// The whole resolver list, as stored now plus `edit`: the service replaces it.
fn doh_change(
    app: &mut AppState,
    edit: impl FnOnce(&mut Vec<DohResolverEntryDto>),
) -> Option<crate::backend::Job> {
    let base = app.settings.data.doh_resolvers.ready()?.resolvers.clone();
    let mut list = base.clone();
    edit(&mut list);
    Some(jobs::write_doh_resolvers(base, list))
}

/// The whole list is sent, as stored now plus `edit`: the service replaces it.
fn local_suffix_change(
    app: &mut AppState,
    edit: impl FnOnce(&mut Vec<String>),
) -> Option<crate::backend::Job> {
    let base: Vec<String> = app
        .settings
        .data
        .local_suffixes
        .ready()?
        .suffixes
        .iter()
        .map(|entry| entry.suffix.clone())
        .collect();
    let mut list = base.clone();
    edit(&mut list);
    Some(jobs::write_local_suffixes(base, list))
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

/// Only after a successful load, and only the one field the user changed.
fn log_retention(app: &mut AppState, field: LogField, n: i64) -> Option<crate::backend::Job> {
    app.settings.data.log_retention.ready()?;
    let days = u32::try_from(n).ok()?;
    let bytes = u64::try_from(n).ok()?.saturating_mul(MIB);
    Some(jobs::change_log_retention(
        move |request: &mut LogRetentionConfigSetRequest| match field {
            LogField::LogsAge => request.log_max_age_days = days,
            LogField::LogsSize => request.log_max_size_bytes = bytes,
            LogField::AuditAge => request.audit_max_age_days = days,
            LogField::AuditSize => request.audit_max_size_bytes = bytes,
        },
    ))
}

fn revisions(
    app: &mut AppState,
    number: Option<(RevisionField, i64)>,
    pin: Option<bool>,
) -> Option<crate::backend::Job> {
    app.settings.data.retention.ready()?;
    let number = match number {
        Some((field, n)) => Some((field, u32::try_from(n).ok()?)),
        None => None,
    };
    Some(jobs::change_retention(
        move |request: &mut RetentionSettingsSetRequest| {
            if let Some(pin) = pin {
                request.pin_lkg = pin;
            }
            if let Some((field, n)) = number {
                match field {
                    RevisionField::SupersededDays => request.superseded_days = n,
                    RevisionField::SupersededCount => request.superseded_count_cap = n,
                    RevisionField::RejectedDays => request.rejected_days = n,
                    RevisionField::RolledbackDays => request.rolledback_days = n,
                    RevisionField::RolledbackCount => request.rolledback_count_cap = n,
                }
            }
        },
    ))
}

fn traffic(
    app: &mut AppState,
    change: impl FnOnce(&mut TrafficStatsSettingsDto) + Send + 'static,
) -> Option<crate::backend::Job> {
    app.settings.data.traffic.ready()?;
    Some(jobs::change_traffic(change, app.settings.clock.local_day()))
}

fn save_merge_policy(app: &mut AppState, policy: MergePolicyDto) {
    let Some(file) = app.rules.settings_file.clone() else {
        app.settings.refuse(Words::Key(text::MERGE_POLICY_NO_FILE));
        return;
    };
    let s = &mut app.settings;
    match crate::screens::rules::own_settings::set_merge_policy(&file, policy) {
        Ok(()) => {
            s.merge_policy = policy;
            s.done(Words::Key(text::SAVED));
        }
        Err(error) => s.failed(
            text::MERGE_POLICY_SAVE_FAILED,
            Failure::detail(error.to_string()),
        ),
    }
}

fn save_pref(app: &mut AppState, field: PrefField, on: bool) {
    let s = &mut app.settings;
    let Some(path) = s.prefs_path.clone() else {
        s.refuse(Words::Key(text::PREF_NO_FILE));
        return;
    };
    let before = s.prefs;
    let prefs = &mut s.prefs;
    match field {
        PrefField::Plain => prefs.plain = on,
        PrefField::NoColor => prefs.no_color = on,
        PrefField::Ascii => prefs.ascii = on,
        PrefField::HideBlockAddresses => prefs.hide_block_addresses = on,
    }
    match s.save_prefs() {
        Some(Ok(())) => s.done(Words::Key(text::PREF_SAVED)),
        // The choice holds for this run; the damaged file stays as it is.
        Some(Err(_)) if s.prefs_damaged.is_some() => {
            let words = prefs_damaged_words(&path, s.prefs_damaged);
            s.refuse(words)
        }
        Some(Err(error)) => {
            s.prefs = before;
            s.failed(text::PREF_SAVE_FAILED, Failure::detail(error.to_string()));
        }
        None => s.prefs = before,
    }
}

/// The title and body that say why the terminal's file does not read: a held
/// file is not called damaged, since its content may be fine.
pub(crate) fn prefs_damaged_keys(damage: Option<prefs::Damaged>) -> (Key, Key) {
    match damage {
        Some(prefs::Damaged::Unreadable) => (
            crate::keys::TUI_SETTINGS_UNREADABLE_TITLE,
            crate::keys::TUI_SETTINGS_UNREADABLE_BODY,
        ),
        _ => (
            crate::keys::TUI_SETTINGS_DAMAGED_TITLE,
            crate::keys::TUI_SETTINGS_DAMAGED_BODY,
        ),
    }
}

/// The terminal's file does not read: which file, why, and that nothing is
/// saved over it.
pub(crate) fn prefs_damaged_words(path: &std::path::Path, damage: Option<prefs::Damaged>) -> Words {
    let path = nrr_shared::display_text::display_text(&path.display().to_string()).into_owned();
    let (title, body) = prefs_damaged_keys(damage);
    Words::Join(vec![
        Words::Key(title),
        Words::Raw(" ".to_owned()),
        Words::Fill(body, vec![("path", path)]),
    ])
}

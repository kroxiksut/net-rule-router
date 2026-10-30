//! The first-run setup: the GUI's first-run window minus its look-and-feel
//! questions. Language (for this session), then the window's five steps: the
//! main and the additional connection, the starting rule set — a country's
//! bundled set, the user's own files, or none — leak protection, and a
//! summary. Every step is one numbered list of answers, the same in both modes.

pub(crate) mod import;
pub mod keys;
mod licence;
mod presets;
mod stability;

use std::cell::OnceCell;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_client_logic::adapters::{
    adapter_passes_filter, display_name, first_run_suggestion, held_other_role, looks_like_tunnel,
    offered_for_role, unroutable_reason,
};
use nrr_client_logic::first_run::first_run_country;
use nrr_client_logic::route_policy::{
    first_run_held_protection, first_run_writes, leak_protection_choices_at_least,
    leak_protection_holds_now, raise_leak_protection,
};
use nrr_client_logic::Route;
use nrr_shared::display_text::display_text;
use nrr_shared::first_run_sheet::ProvisioningAnswers;
use nrr_shared::ipc_payloads::{BehaviorModeDto, InterfaceRowDto, SnapshotInitialResponse};
use nrr_shared::AppSection;
use serde_json::Value;

use self::import::Preview;
use self::keys as k;
use self::presets::{Pack, ReadError, RulesFile};
use super::binding::{
    adapters, adapters_read, binding, error_text, find, holds, kill_switch_on, picker_label,
    policy_write, role_write, rows_are_live, unroutable_lines, RoleChange, WriteFailure,
};
use super::interfaces::keys as ik;
use super::{choice, Screen, ScreenId};
use crate::i18n::{available_languages, Key, Language, Texts};
use crate::keys as common;
use crate::rule_set_load::Refusal;
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, ViewLine};

pub struct WizardScreen;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Step {
    /// The agreement, before the first question; not one of the numbered steps.
    Licence,
    #[default]
    Language,
    Primary,
    Secondary,
    Protection,
    Rules,
    OtherCountries,
    Files,
    Review,
    Summary,
}

const STEP_COUNT: usize = 5;

impl Step {
    /// The window's step number; the agreement and the session language come
    /// before the window's steps and are not counted.
    fn number(self) -> Option<usize> {
        match self {
            Self::Licence | Self::Language => None,
            Self::Primary => Some(1),
            Self::Secondary => Some(2),
            Self::Rules | Self::OtherCountries | Self::Files | Self::Review => Some(3),
            Self::Protection => Some(4),
            Self::Summary => Some(5),
        }
    }

    fn name(self) -> Key {
        match self {
            Self::Licence => k::LICENCE_TITLE,
            Self::Language => k::LANGUAGE_TITLE,
            Self::Primary => common::ROLE_PRIMARY,
            Self::Secondary => common::ROLE_SECONDARY,
            Self::Protection => k::OPTIONS_STEP,
            Self::Rules | Self::OtherCountries | Self::Files | Self::Review => k::RULES_STEP,
            Self::Summary => k::SUMMARY_STEP,
        }
    }

    /// The starting rules follow the connections they route between, as in
    /// the window; the protection answers come next, the summary last.
    fn next(self) -> Self {
        match self {
            Self::Licence => Self::Language,
            Self::Language => Self::Primary,
            Self::Primary => Self::Secondary,
            Self::Secondary => Self::Rules,
            Self::Protection | Self::Summary => Self::Summary,
            Self::Rules | Self::OtherCountries | Self::Files | Self::Review => Self::Protection,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Licence | Self::Language | Self::Primary => Self::Language,
            Self::Secondary => Self::Primary,
            Self::Rules => Self::Secondary,
            Self::OtherCountries | Self::Files | Self::Review | Self::Protection => Self::Rules,
            Self::Summary => Self::Protection,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Busy {
    Saving,
    Previewing,
}

/// The starting rules the setup applies as it closes.
#[derive(Clone, Debug)]
enum Chosen {
    Set(Box<Pending>),
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Role(RoleChange),
    RoleFailed(WriteFailure),
    ProtectionSaved,
    ProtectionFailed(WriteFailure),
    NeedsService,
    Exclusive,
    Placeholder,
    FileError { path: String, error: ReadError },
    ImportFailed(String),
    NotUnderstood(String),
    LicenceNotSaved,
}

/// The files of the starting set, as read, and the payload sent for them.
#[derive(Clone, Debug)]
struct Pending {
    files: [Option<RulesFile>; 2],
    payload: Value,
    /// How the set is named when its outcome is told.
    name: crate::rule_set_load::SetName,
}

#[derive(Debug)]
pub struct WizardState {
    /// The system's locale candidates, for the country whose set is offered.
    pub locale: Vec<String>,
    /// The country the system is set to; outranks `locale`.
    pub region: Option<String>,
    /// The start-up check (open when the user has no connections) has run.
    decided: bool,
    /// The setup was asked for (`--wizard`), so accepting the agreement goes on
    /// to its questions rather than back to where the program started.
    requested: bool,
    /// The agreement has not been accepted by this user yet: nothing else opens.
    licence_needed: bool,
    licence_page: usize,
    /// The session language the agreement is shown in.
    licence_language: String,
    /// What the installer answered ahead of the first launch.
    pub sheet: Option<ProvisioningAnswers>,
    step: Step,
    cursor: usize,
    /// The leak-protection level, as its wire slug.
    leak_protection: &'static str,
    doh_lockdown: bool,
    /// Route sites by name (fake-IP); the GUI offers it on.
    fake_ip: bool,
    /// The window detailed diagnostic logs are written for; `None`: none.
    diagnostic_logs: Option<&'static str>,
    /// The machine-wide answers went to the service this run.
    stability_sent: bool,
    /// The log window was changed on the protection step.
    stability_touched: bool,
    /// Fake-IP was switched on the protection step; untouched, a user already
    /// set up keeps the service's value.
    fake_ip_touched: bool,
    /// What their write left to tell; outlives the run it came from.
    stability_notice: Option<stability::StabilityNotice>,
    /// What the service held when the setup opened, when the user was already
    /// set up; the protection is then sent only if the user changed it.
    protection_at_start: Option<(&'static str, bool)>,
    /// What this run's own protection write left the service holding.
    protection_written: Option<(&'static str, bool)>,
    /// The first look at the snapshot has been taken.
    seeded: bool,
    secondary_deferred: bool,
    /// The adapter lists include adapters that are not connected.
    show_all_adapters: bool,
    question: Option<RoleChange>,
    busy: Option<Busy>,
    outcome: Option<Outcome>,
    paths: [String; 2],
    /// The file being typed (0 main, 1 additional) and the text so far.
    editing: Option<(usize, String)>,
    pending: Option<Pending>,
    preview: Option<Preview>,
    /// Applied as the setup closes, once the protection is in force.
    chosen: Option<Chosen>,
    languages: OnceCell<Vec<Language>>,
    packs: OnceCell<Vec<Pack>>,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            locale: Vec::new(),
            region: None,
            decided: false,
            requested: false,
            licence_needed: false,
            licence_page: 0,
            licence_language: String::new(),
            sheet: None,
            step: Step::default(),
            cursor: 0,
            // The GUI offers both on: protection helps only if it is on before
            // the first rule applies.
            leak_protection: LEAK_OFFERED,
            doh_lockdown: true,
            fake_ip: true,
            diagnostic_logs: None,
            stability_sent: false,
            stability_touched: false,
            fake_ip_touched: false,
            stability_notice: None,
            protection_at_start: None,
            protection_written: None,
            seeded: false,
            secondary_deferred: false,
            show_all_adapters: false,
            question: None,
            busy: None,
            outcome: None,
            paths: Default::default(),
            editing: None,
            pending: None,
            preview: None,
            chosen: None,
            languages: OnceCell::new(),
            packs: OnceCell::new(),
        }
    }
}

impl WizardState {
    /// `--wizard`: the user asked for the setup, so start-up does not decide.
    pub fn opened_by_request(&mut self) {
        self.decided = true;
        self.requested = true;
    }

    /// The agreement is still to be accepted; every other screen waits.
    pub fn licence_pending(&self) -> bool {
        self.licence_needed
    }

    /// Start-up: what the user's settings say about the agreement, and the
    /// installer's answers when there are any.
    pub fn at_startup(
        &mut self,
        accepted_eula: u32,
        language: &str,
        sheet: Option<ProvisioningAnswers>,
    ) {
        self.sheet = sheet;
        self.licence_language = language.to_string();
        self.licence_needed = !nrr_shared::eula::is_accepted(accepted_eula);
        if self.licence_needed {
            self.step = Step::Licence;
        }
    }

    fn languages(&self) -> &[Language] {
        self.languages.get_or_init(available_languages)
    }

    fn packs(&self) -> &[Pack] {
        self.packs.get_or_init(|| {
            presets::bundled_root()
                .map(|root| presets::packs(&root))
                .unwrap_or_default()
        })
    }

    fn go(&mut self, step: Step) {
        self.step = step;
        self.cursor = 0;
        self.outcome = None;
    }

    /// Back to the first question for the next run, keeping what start-up
    /// learned.
    fn reset(&mut self) {
        let fresh = Self {
            locale: std::mem::take(&mut self.locale),
            region: self.region.take(),
            decided: true,
            sheet: self.sheet.take(),
            stability_notice: self.stability_notice.take(),
            languages: std::mem::take(&mut self.languages),
            packs: std::mem::take(&mut self.packs),
            ..Self::default()
        };
        *self = fresh;
    }
}

/// The user has nothing the service could route by: no policy at all, or no
/// connection named in it. The data the GUI's banner reads.
pub fn needs_setup(snapshot: &SnapshotInitialResponse) -> bool {
    snapshot
        .route_policy
        .as_ref()
        .is_none_or(|p| p.primary.is_none() && p.secondary.is_none())
}

pub use stability::announce;

/// The first snapshot decides, once, whether the setup opens by itself — and
/// only while the user is still on the screen the program started on.
pub fn snapshot_arrived(app: &mut AppState) {
    seed_protection(app);
    if app.wizard.decided || !app.link.is_connected() {
        return;
    }
    app.wizard.decided = true;
    // The baseline's editor has no routing of its own to set up: `sudo` has
    // no policy, and opening the setup for it is what wrote root's rules over
    // the baseline. `--wizard` still opens it, and its import lands there.
    let wanted = app.snapshot.as_ref().is_some_and(needs_setup) && !app.rules.baseline;
    if wanted && app.screen == ScreenId::Status {
        app.open(ScreenId::Wizard);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Language(String),
    Next,
    Back,
    Close,
    Assign(Route, String),
    Later,
    ChooseNow,
    Refresh,
    ShowAll,
    LeakProtection(&'static str),
    ToggleDohLockdown,
    ToggleFakeIp,
    DiagnosticLogs,
    Pack(usize),
    OtherCountries,
    OwnFiles,
    StartEmpty,
    EditPath(usize),
    ImportFiles,
    Confirm,
    Cancel,
    PreviousPage,
    NextPage,
    Accept,
    Decline,
}

fn region(app: &AppState) -> Option<String> {
    let state = &app.wizard;
    let country = first_run_country(state.region.as_deref().unwrap_or_default(), &state.locale);
    (!country.is_empty()).then_some(country)
}

fn regional_indexes(app: &AppState) -> Vec<usize> {
    let packs = app.wizard.packs();
    let country = region(app);
    presets::regional(packs, country.as_deref())
        .into_iter()
        .filter_map(|pack| packs.iter().position(|p| p == pack))
        .collect()
}

fn assigned(app: &AppState, route: Route) -> Option<String> {
    let rows = adapters(app, true);
    rows.iter()
        .find(|row| holds(row, route))
        .map(display_name)
        .or_else(|| binding(app, route).map(|b| b.display_name.clone()))
        .map(|name| display_text(&name).into_owned())
}

/// The additional connection the user has bound, as the adapters read shows it.
/// The adapter bound to `route` is down while another copy of its driver is
/// on the computer: a VPN program often brings up a different copy.
fn sibling_warning(app: &AppState, route: Route, texts: &Texts) -> Option<String> {
    let all = adapters(app, true);
    let row = all.iter().find(|row| holds(row, route))?;
    super::binding::driver_sibling_warning(&all, row, route, texts)
}

fn secondary_row(app: &AppState) -> Option<InterfaceRowDto> {
    adapters(app, true)
        .into_iter()
        .find(|row| holds(row, Route::Secondary))
}

/// The adapters the setup offers for `route`: connected ones unless all were
/// asked for, never the one holding the other route, the one that fits the
/// role best first.
fn offered_adapters(app: &AppState, route: Route) -> Vec<InterfaceRowDto> {
    let mut rows: Vec<InterfaceRowDto> = adapters(app, false)
        .into_iter()
        .filter(|row| {
            offered_for_role(row, route)
                && adapter_passes_filter(row, app.wizard.show_all_adapters, "")
        })
        .collect();
    if let Some(best) = first_run_suggestion(&rows, route, None) {
        let row = rows.remove(best);
        rows.insert(0, row);
    }
    rows
}

fn pickable(app: &AppState) -> bool {
    app.link.is_connected() && rows_are_live(app)
}

/// The answers of the current step, in order.
fn actions(app: &AppState) -> Vec<Action> {
    let state = &app.wizard;
    if state.question.is_some() {
        return vec![Action::Confirm, Action::Cancel];
    }
    let mut actions = Vec::new();
    match state.step {
        Step::Licence => {
            if state.licence_page > 0 {
                actions.push(Action::PreviousPage);
            }
            if state.licence_page + 1 < licence_pages(app).len() {
                actions.push(Action::NextPage);
            }
            actions.extend([Action::Accept, Action::Decline]);
            return actions;
        }
        Step::Language => {
            actions.extend(
                state
                    .languages()
                    .iter()
                    .map(|l| Action::Language(l.id.clone())),
            );
            actions.push(Action::Next);
        }
        Step::Primary | Step::Secondary => {
            let route = if state.step == Step::Primary {
                Route::Primary
            } else {
                Route::Secondary
            };
            let held = assigned(app, route).is_some();
            let deferred = !held && route == Route::Secondary && state.secondary_deferred;
            if !held && !deferred {
                if pickable(app) {
                    actions.extend(
                        offered_adapters(app, route)
                            .iter()
                            .map(|row| Action::Assign(route, super::binding::row_key(row))),
                    );
                    actions.push(Action::ShowAll);
                }
                if route == Route::Secondary {
                    actions.push(Action::Later);
                    actions.push(Action::Refresh);
                }
            }
            if deferred {
                actions.push(Action::ChooseNow);
            }
            actions.push(Action::Next);
            actions.push(Action::Back);
        }
        Step::Protection => {
            actions.extend(
                leak_protection_choices_at_least(default_route(app), leak_floor(app))
                    .into_iter()
                    .map(Action::LeakProtection),
            );
            actions.push(Action::ToggleDohLockdown);
            if stability::offers_fake_ip() {
                actions.push(Action::ToggleFakeIp);
            }
            if stability::offers_logs() {
                actions.push(Action::DiagnosticLogs);
            }
            actions.extend([Action::Next, Action::Back]);
        }
        Step::Rules => {
            let regional = regional_indexes(app);
            let others = state.packs().len() > regional.len();
            actions.extend(regional.into_iter().map(Action::Pack));
            if others {
                actions.push(Action::OtherCountries);
            }
            actions.extend([Action::OwnFiles, Action::StartEmpty, Action::Back]);
        }
        Step::OtherCountries => {
            actions.extend((0..state.packs().len()).map(Action::Pack));
            actions.push(Action::Back);
        }
        Step::Files => {
            actions.extend([
                Action::EditPath(0),
                Action::EditPath(1),
                Action::ImportFiles,
                Action::Back,
            ]);
        }
        Step::Review => {
            // An unchanged set goes on too: its rules are already in force.
            if state.preview.as_ref().is_some_and(|p| p.refused.is_none()) {
                actions.push(Action::Next);
            }
            actions.push(Action::Back);
        }
        Step::Summary => actions.extend([Action::Next, Action::Back]),
    }
    actions.push(Action::Close);
    actions
}

fn country_name(country: &str, texts: &Texts) -> String {
    texts.dynamic(
        &format!("dialog.first-run-wizard.country.{country}.name"),
        &country.to_uppercase(),
    )
}

/// In the list of every set (`listed`), each goes by its own name, as the
/// window shows it: "for your region" belongs to the region's set alone.
fn pack_label(packs: &[Pack], index: usize, listed: bool, texts: &Texts) -> String {
    let Some(pack) = packs.get(index) else {
        return String::new();
    };
    let folder = pack.dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if listed {
        let home = if pack.abroad {
            "abroad"
        } else {
            pack.country.as_str()
        };
        return texts.dynamic(
            &format!("rules.bundled-preset.name.{home}-{folder}"),
            &format!("{} — {folder}", country_name(&pack.country, texts)),
        );
    }
    let key = if pack.abroad {
        k::COUNTRY_PRESET_ABROAD
    } else {
        k::COUNTRY_PRESET
    };
    let mut label = texts.fill(key, &[("country", country_name(&pack.country, texts))]);
    // Two sets for one country are told apart by their folder names.
    let twins = packs
        .iter()
        .filter(|p| p.country == pack.country && p.abroad == pack.abroad)
        .count();
    if twins > 1 && !folder.is_empty() {
        label.push_str(&format!(" — {folder}"));
    }
    label
}

fn file_key(index: usize) -> Key {
    if index == 0 {
        k::PRIMARY_FILE
    } else {
        k::SECONDARY_FILE
    }
}

fn label(action: &Action, app: &AppState, texts: &Texts) -> String {
    let state = &app.wizard;
    let yes_no = |on: bool| texts.get(if on { k::YES } else { k::NO });
    match action {
        Action::Language(id) => {
            let name = state
                .languages()
                .iter()
                .find(|l| &l.id == id)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| id.clone());
            if id == texts.language() {
                texts.fill(k::CURRENT, &[("name", name)])
            } else {
                name
            }
        }
        Action::Next if state.step == Step::Summary => texts.get(k::FINISH),
        Action::Next => texts.get(k::NEXT),
        Action::Back => texts.get(k::BACK),
        Action::Close => texts.get(k::CLOSE),
        Action::Assign(route, key) => find(&adapters(app, false), key)
            .map(|row| picker_label(row, *route, texts))
            .unwrap_or_default(),
        Action::Later => texts.get(k::SECONDARY_LATER),
        Action::ChooseNow => texts.get(k::CHOOSE_NOW),
        Action::Refresh => texts.get(k::REFRESH),
        Action::ShowAll => texts.fill(
            k::SETTING,
            &[
                ("name", texts.get(k::SHOW_ALL_ADAPTERS)),
                ("value", yes_no(state.show_all_adapters)),
            ],
        ),
        Action::LeakProtection(level) => {
            let value = texts.get(level_label(level));
            let value = if *level == shown_level(app) {
                texts.fill(k::CURRENT, &[("name", value)])
            } else {
                value
            };
            texts.fill(
                k::SETTING,
                &[("name", texts.get(k::LEAK_PROTECTION)), ("value", value)],
            )
        }
        Action::ToggleDohLockdown => texts.fill(
            k::SETTING,
            &[
                ("name", texts.get(k::DOH_LOCKDOWN)),
                ("value", yes_no(state.doh_lockdown)),
            ],
        ),
        Action::ToggleFakeIp => texts.fill(
            k::SETTING,
            &[
                ("name", texts.get(k::FAKE_IP)),
                ("value", yes_no(state.fake_ip)),
            ],
        ),
        Action::DiagnosticLogs => texts.fill(
            k::SETTING,
            &[
                ("name", texts.get(k::DIAGNOSTIC_LOGS)),
                (
                    "value",
                    texts.get(stability::log_window_label(state.diagnostic_logs)),
                ),
            ],
        ),
        Action::Pack(index) => pack_label(
            state.packs(),
            *index,
            state.step == Step::OtherCountries,
            texts,
        ),
        Action::OtherCountries => texts.get(k::OTHER_COUNTRY),
        Action::OwnFiles => texts.get(k::OPEN_FILES),
        Action::StartEmpty => texts.get(k::START_EMPTY),
        Action::EditPath(index) => {
            let path = match &state.editing {
                Some((editing, typed)) if editing == index => format!("{typed}_"),
                _ if state.paths[*index].is_empty() => texts.get(k::NO_FILE),
                _ => state.paths[*index].clone(),
            };
            format!("{} {path}", texts.get(file_key(*index)))
        }
        Action::ImportFiles => texts.get(k::IMPORT_FILES),
        Action::Confirm => texts.get(ik::UNROUTABLE_CONFIRM),
        Action::Cancel => texts.get(ik::CANCEL),
        Action::PreviousPage => texts.get(k::LICENCE_PREVIOUS),
        Action::NextPage => texts.get(k::LICENCE_NEXT),
        Action::Accept => texts.get(k::LICENCE_ACCEPT),
        Action::Decline => texts.get(k::LICENCE_DECLINE),
    }
}

fn perform(app: &mut AppState, action: Action) {
    if app.wizard.busy.is_some() {
        return;
    }
    match action {
        Action::Language(id) => app.language_change = Some(id),
        Action::Next => match app.wizard.step {
            Step::Summary => finish(app),
            // The protection is in force before the summary tells of it.
            Step::Protection => {
                app.wizard.go(Step::Summary);
                send_protection(app, None);
            }
            step => {
                app.wizard.go(step.next());
                preselect(app);
            }
        },
        Action::Back => {
            let previous = app.wizard.step.previous();
            app.wizard.go(previous);
            preselect(app);
        }
        Action::PreviousPage => {
            app.wizard.licence_page = app.wizard.licence_page.saturating_sub(1);
            app.wizard.cursor = 0;
        }
        Action::NextPage => {
            app.wizard.licence_page += 1;
            app.wizard.cursor = 0;
        }
        Action::Accept => accept_licence(app),
        Action::Decline => app.quit = true,
        Action::Close => finish(app),
        Action::StartEmpty => {
            app.wizard.chosen = Some(Chosen::Empty);
            app.wizard.go(Step::Protection);
        }
        Action::Assign(route, key) => assign(app, route, &key),
        Action::Later => {
            app.wizard.secondary_deferred = true;
            app.wizard.cursor = 0;
        }
        Action::ChooseNow => {
            app.wizard.secondary_deferred = false;
            app.wizard.cursor = 0;
        }
        Action::Refresh => app.outbox.push(adapters_read(false, |_, _| {})),
        Action::ShowAll => app.wizard.show_all_adapters = !app.wizard.show_all_adapters,
        Action::LeakProtection(level) => {
            seed_protection(app);
            app.wizard.leak_protection = level;
        }
        Action::ToggleDohLockdown => {
            seed_protection(app);
            app.wizard.doh_lockdown = !app.wizard.doh_lockdown;
        }
        Action::ToggleFakeIp => {
            seed_protection(app);
            app.wizard.fake_ip = !app.wizard.fake_ip;
            app.wizard.stability_sent = false;
            app.wizard.fake_ip_touched = true;
        }
        Action::DiagnosticLogs => {
            seed_protection(app);
            app.wizard.diagnostic_logs = stability::next_log_window(app.wizard.diagnostic_logs);
            app.wizard.stability_sent = false;
            app.wizard.stability_touched = true;
        }
        Action::Pack(index) => {
            let Some(pack) = app.wizard.packs().get(index).cloned() else {
                return;
            };
            let [primary, secondary] = pack.files();
            preview_files(app, [primary, secondary], pack_name(&pack));
        }
        Action::OtherCountries => app.wizard.go(Step::OtherCountries),
        Action::OwnFiles => app.wizard.go(Step::Files),
        Action::EditPath(index) => {
            app.wizard.editing = Some((index, app.wizard.paths[index].clone()));
        }
        Action::ImportFiles => {
            let paths = app.wizard.paths.clone().map(|p| {
                let p = presets::typed_path(&p);
                (!p.is_empty()).then(|| std::path::PathBuf::from(p))
            });
            let name = paths
                .iter()
                .flatten()
                .next()
                .map(|p| crate::rule_set_load::SetName::of_path(p));
            if let Some(name) = name {
                preview_files(app, paths, name);
            }
        }
        Action::Confirm => {
            if let Some(change) = app.wizard.question.take() {
                start_role(app, change);
            }
        }
        Action::Cancel => app.wizard.question = None,
    }
}

/// The agreement version this account has accepted, counting the current one
/// when it accepted that on the installer's licence page; that acceptance is
/// then written where an acceptance here would be.
pub fn accepted_with_installer(
    settings_file: Option<&std::path::Path>,
    recorded: u32,
    installer: &dyn nrr_platform_api::installer_agreement::InstallerAgreementPort,
) -> u32 {
    let current = nrr_shared::eula::CURRENT_EULA_VERSION;
    if nrr_shared::eula::is_accepted(recorded)
        || !nrr_platform_api::installer_agreement::accepted_in_installer(installer)
    {
        return recorded;
    }
    if let Some(file) = settings_file {
        // Not kept, it is found in the installer's record again next start.
        let _ = nrr_shared::user_settings::UserSettingsStore::at(file.to_path_buf())
            .update(|settings| settings.accepted_eula = settings.accepted_eula.max(current));
    }
    current
}

/// Records the acceptance where the window reads it, then goes on: to the
/// questions when the setup was asked for or is due, else back to the screen the
/// program started on.
fn accept_licence(app: &mut AppState) {
    let saved = match app.rules.settings_file.clone() {
        Some(file) => nrr_shared::user_settings::UserSettingsStore::at(file)
            .update(|settings| {
                settings.accepted_eula = settings
                    .accepted_eula
                    .max(nrr_shared::eula::CURRENT_EULA_VERSION);
            })
            .is_ok(),
        // Under `sudo` there is no file of the user's own to write.
        None => false,
    };
    app.wizard.licence_needed = false;
    app.wizard.licence_page = 0;
    if app.wizard.requested {
        app.wizard.go(Step::Language);
        preselect(app);
    } else {
        app.wizard.reset();
        app.wizard.decided = false;
        app.open(ScreenId::Status);
        snapshot_arrived(app);
    }
    if !saved && app.rules.settings_file.is_some() {
        app.wizard.outcome = Some(Outcome::LicenceNotSaved);
    }
}

fn licence_pages(app: &AppState) -> Vec<Vec<String>> {
    licence::pages(licence::text(&app.wizard.licence_language))
}

/// Puts the cursor on the answer the installer's sheet gave for the step just
/// entered; the user still confirms it.
fn preselect(app: &mut AppState) {
    let Some(sheet) = app.wizard.sheet.clone() else {
        return;
    };
    let wanted: Option<Action> = match app.wizard.step {
        Step::Language => sheet.language.as_deref().and_then(|tag| {
            let base = tag
                .split(['-', '_'])
                .next()
                .unwrap_or(tag)
                .to_ascii_lowercase();
            app.wizard
                .languages()
                .iter()
                .find(|l| l.id.eq_ignore_ascii_case(&base) || l.id.eq_ignore_ascii_case(tag))
                .map(|l| Action::Language(l.id.clone()))
        }),
        Step::Primary | Step::Secondary => {
            let (route, name) = if app.wizard.step == Step::Primary {
                (Route::Primary, sheet.primary_connection.as_deref())
            } else {
                (Route::Secondary, sheet.secondary_connection.as_deref())
            };
            name.and_then(|name| {
                adapters(app, false)
                    .iter()
                    .find(|row| {
                        row.name == name
                            || row.adapter_name == name
                            || row.interface_description == name
                    })
                    .map(|row| Action::Assign(route, super::binding::row_key(row)))
            })
        }
        Step::Rules => sheet.rule_set.as_deref().and_then(|set| {
            if set == "none" {
                return Some(Action::StartEmpty);
            }
            let root = presets::bundled_root()?;
            app.wizard
                .packs()
                .iter()
                .position(|pack| pack_is_named(pack, &root, set))
                .map(Action::Pack)
        }),
        _ => None,
    };
    if let Some(at) = wanted.and_then(|w| actions(app).iter().position(|a| *a == w)) {
        app.wizard.cursor = at;
    }
}

/// Whether the sheet's `<country>/<pack>` names this bundled set.
fn pack_is_named(pack: &Pack, root: &std::path::Path, named: &str) -> bool {
    pack.dir.strip_prefix(root).is_ok_and(|relative| {
        let portable = relative.to_string_lossy().replace('\\', "/");
        portable == named.trim_matches('/')
    })
}

fn assign(app: &mut AppState, route: Route, key: &str) {
    let rows = adapters(app, false);
    let Some(row) = find(&rows, key) else {
        return;
    };
    let state = &mut app.wizard;
    if held_other_role(row, route).is_some() {
        state.outcome = Some(Outcome::Exclusive);
    } else if unroutable_reason(row).is_some() {
        state.question = Some(RoleChange::assign(row, route));
    } else {
        let change = RoleChange::assign(row, route);
        start_role(app, change);
    }
}

fn start_role(app: &mut AppState, change: RoleChange) {
    if !app.link.is_connected() {
        app.wizard.outcome = Some(Outcome::NeedsService);
        return;
    }
    if !rows_are_live(app) {
        app.wizard.outcome = Some(Outcome::Placeholder);
        return;
    }
    app.wizard.busy = Some(Busy::Saving);
    app.wizard.outcome = None;
    app.outbox.push(role_write(change, |app, change, result| {
        let state = &mut app.wizard;
        state.busy = None;
        state.cursor = 0;
        state.outcome = Some(match result {
            Ok(()) => Outcome::Role(change.clone()),
            Err(failure) => Outcome::RoleFailed(failure),
        });
    }));
}

/// What a new user is offered: protection helps only if it is on before the
/// first rule applies.
const LEAK_OFFERED: &str = "sites";

/// The default route the service holds, as its wire slug; while there is no
/// policy yet, the one the first save starts from.
fn default_route(app: &AppState) -> &'static str {
    let Some(snapshot) = app.snapshot.as_ref() else {
        return "prefer-primary";
    };
    match (&snapshot.route_policy, &snapshot.first_policy) {
        (Some(policy), _) => route_slug(policy.mode),
        (None, Some(first)) => route_slug(first.mode),
        (None, None) => "prefer-primary",
    }
}

/// The weakest level the first save may hold; none once a policy exists.
fn leak_floor(app: &AppState) -> &'static str {
    app.snapshot
        .as_ref()
        .filter(|s| s.route_policy.is_none())
        .and_then(|s| s.first_policy.as_ref())
        .map_or("off", |first| first.leak_protection_at_least.as_slug())
}

fn route_slug(mode: BehaviorModeDto) -> &'static str {
    match mode {
        BehaviorModeDto::PreferPrimary => "prefer-primary",
        BehaviorModeDto::PreferSecondaryWhenAvailable => "prefer-secondary-when-available",
    }
}

/// The chosen level as the current default route offers it, never below the
/// first save's floor.
fn shown_level(app: &AppState) -> &'static str {
    raise_leak_protection(
        default_route(app),
        app.wizard.leak_protection,
        leak_floor(app),
    )
}

fn level_label(level: &str) -> Key {
    match level {
        "sites" => k::LEAK_SITES,
        "everything" => k::LEAK_EVERYTHING,
        _ => k::LEAK_OFF,
    }
}

fn level_note(level: &str) -> Key {
    match level {
        "sites" => k::LEAK_SITES_NOTE,
        "everything" => k::LEAK_EVERYTHING_NOTE,
        _ => k::LEAK_OFF_NOTE,
    }
}

/// Leak protection and DNS lockdown as ONE write, so neither is sent over a
/// snapshot the other has not reached yet.
/// A user already set up starts from what the service holds; a new one from
/// the offer (both on). Taken once, before anything is changed.
fn seed_protection(app: &mut AppState) {
    let state = &app.wizard;
    if state.seeded {
        return;
    }
    let Some(snapshot) = app.snapshot.as_ref() else {
        return;
    };
    // Any saved policy is a choice, bound connections or not.
    let held = snapshot.route_policy.as_ref().and_then(|p| {
        first_run_held_protection(
            true,
            route_slug(p.mode),
            p.leak_protection.as_slug(),
            p.doh_lockdown_auto,
            p.doh_lockdown_enabled,
        )
    });
    let state = &mut app.wizard;
    state.seeded = true;
    state.protection_at_start = held;
    if let Some((level, doh_lockdown)) = held {
        state.leak_protection = level;
        state.doh_lockdown = doh_lockdown;
    } else if let Some(sheet) = &state.sheet {
        // A new user starts from the installer's answers, else from the offer.
        if let Some(level) = sheet.leak_protection {
            state.leak_protection = level.as_slug();
        }
        state.doh_lockdown = sheet.doh_lockdown.unwrap_or(state.doh_lockdown);
        state.fake_ip = sheet.fake_ip.unwrap_or(state.fake_ip);
    }
    // Read only for a setup on show: the snapshot seeds it in the background.
    if held.is_some() && app.screen == ScreenId::Wizard {
        stability::read_held(app);
    }
}

/// The chosen protection, as its write sends it.
fn chosen_protection(app: &AppState) -> (&'static str, bool) {
    (shown_level(app), app.wizard.doh_lockdown)
}

/// Writes the chosen protection unless the service holds it already, then
/// hands `rules` on: they are applied only once the protection is in force,
/// and never over a write that failed.
fn send_protection(app: &mut AppState, rules: Option<Pending>) {
    seed_protection(app);
    let chosen = chosen_protection(app);
    let held = app
        .wizard
        .protection_written
        .or(app.wizard.protection_at_start);
    // Nothing changed for a user already set up: nothing to write.
    if !first_run_writes(held, chosen, false, false).protection {
        if let Some(rules) = rules {
            apply_rules(app, rules);
        }
        return;
    }
    if !app.link.is_connected() {
        app.wizard.outcome = Some(Outcome::NeedsService);
        if let Some(rules) = rules {
            crate::rule_set_load::refused(app, rules.name, Refusal::NoService);
        }
        return;
    }
    app.wizard.busy = Some(Busy::Saving);
    let (level, doh_lockdown) = chosen;
    app.outbox.push(policy_write(
        move |request| {
            // Settled against the default route the service holds at the write.
            request.insert("leak-protection".into(), Value::from(level));
            request.insert("doh-lockdown-enabled".into(), Value::Bool(doh_lockdown));
            // "Yes" is the automatic posture; "no" is a choice that holds.
            request.insert("doh-lockdown-auto".into(), Value::Bool(doh_lockdown));
        },
        move |app, result| {
            // Sent from the protection step, the summary tells the outcome;
            // sent as the setup closes, a failure is told where the user
            // landed, and the closed setup keeps nothing for its next run.
            let on_setup = app.screen == ScreenId::Wizard;
            if on_setup {
                app.wizard.busy = None;
            }
            match result {
                Ok(()) => {
                    if on_setup {
                        app.wizard.protection_written = Some(chosen);
                        app.wizard.outcome = Some(Outcome::ProtectionSaved);
                    }
                    if let Some(rules) = rules {
                        apply_rules(app, rules);
                    }
                }
                Err(failure) => {
                    if let Some(rules) = rules {
                        crate::rule_set_load::refused(app, rules.name, Refusal::ProtectionNotSaved);
                    }
                    if on_setup {
                        app.wizard.outcome = Some(Outcome::ProtectionFailed(failure));
                    } else {
                        super::interfaces::protection_failed(app, failure);
                    }
                }
            }
        },
    ));
}

/// Whether the service holds the protection chosen here.
fn protection_in_force(app: &AppState) -> bool {
    if app.wizard.busy == Some(Busy::Saving) {
        return false;
    }
    let held = app
        .snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .and_then(|p| {
            first_run_held_protection(
                true,
                route_slug(p.mode),
                p.leak_protection.as_slug(),
                p.doh_lockdown_auto,
                p.doh_lockdown_enabled,
            )
        });
    held == Some(chosen_protection(app))
}

/// A shipped set by the name the window gives it in the list of every set.
fn pack_name(pack: &Pack) -> crate::rule_set_load::SetName {
    let folder = pack.dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let home = if pack.abroad {
        "abroad"
    } else {
        pack.country.as_str()
    };
    crate::rule_set_load::SetName::keyed(
        format!("rules.bundled-preset.name.{home}-{folder}"),
        folder.to_owned(),
    )
}

fn preview_files(
    app: &mut AppState,
    paths: [Option<std::path::PathBuf>; 2],
    name: crate::rule_set_load::SetName,
) {
    let mut files: [Option<RulesFile>; 2] = Default::default();
    for (slot, path) in files.iter_mut().zip(paths) {
        let Some(path) = path else { continue };
        match presets::read(&path) {
            Ok(file) => *slot = Some(file),
            Err(error) => {
                app.wizard.outcome = Some(Outcome::FileError {
                    path: path.display().to_string(),
                    error,
                });
                return;
            }
        }
    }
    let payload = import::payload(files[0].as_ref(), files[1].as_ref(), app.rules.baseline);
    app.wizard.go(Step::Review);
    app.wizard.preview = None;
    app.wizard.busy = Some(Busy::Previewing);
    app.wizard.outcome = None;
    app.wizard.pending = Some(Pending {
        files,
        payload: payload.clone(),
        name: name.clone(),
    });
    if app.link.is_connected() {
        send_preview(app, payload);
        return;
    }
    // The set is applied in the same action: a stopped service is started
    // first, and the preview goes once it answers.
    app.outbox.push(crate::rule_set_load::start_then(
        app.settings.service_probe,
        move |app, result| match result {
            Ok(()) => send_preview(app, payload),
            Err(why) => {
                app.wizard.busy = None;
                app.wizard.pending = None;
                app.wizard.go(Step::Rules);
                app.wizard.outcome = Some(Outcome::NeedsService);
                crate::rule_set_load::not_applied(app, name, why);
            }
        },
    ));
}

/// The dry run shows what the set would change; a set that would change
/// something becomes the choice the setup applies as it closes.
fn send_preview(app: &mut AppState, payload: Value) {
    app.outbox.push(import::preview_job(payload, |app, result| {
        let state = &mut app.wizard;
        state.busy = None;
        match result {
            Ok(preview) => {
                if !preview.empty && preview.refused.is_none() {
                    state.chosen = state.pending.clone().map(|p| Chosen::Set(Box::new(p)));
                }
                state.preview = Some(preview);
            }
            Err(code) => state.outcome = Some(Outcome::ImportFailed(code)),
        }
    }));
}

/// The starting set reaches the service: a fresh dry run (the rules step's
/// token may have lapsed while the protection was answered), then the
/// confirmation with its token. The setup is closed by then; the outcome is
/// told in the feed.
fn apply_rules(app: &mut AppState, pending: Pending) {
    let rules: usize = pending.files.iter().flatten().map(|f| f.rules).sum();
    let payload = import::renewed(&pending.payload);
    let name = pending.name;
    app.outbox
        .push(import::preview_job(payload.clone(), move |app, result| {
            let preview = match result {
                Ok(preview) => preview,
                Err(code) => return crate::rule_set_load::refused(app, name, Refusal::Code(code)),
            };
            if let Some(code) = preview.refused {
                return crate::rule_set_load::refused(app, name, Refusal::Code(code));
            }
            if preview.empty {
                return crate::rule_set_load::applied(app, name, rules);
            }
            app.outbox.push(import::apply_job(
                payload,
                preview.token,
                move |app, result| match result {
                    Ok(()) => crate::rule_set_load::applied(app, name, rules),
                    Err(code) => crate::rule_set_load::refused(app, name, Refusal::Code(code)),
                },
            ));
        }));
}

/// The screen the GUI's first-run contract opens when the setup is done.
fn after_setup() -> ScreenId {
    match nrr_shared::gui_shell_v1()
        .first_run
        .quick_start_path_sections
        .first()
    {
        Some(AppSection::Rules) => ScreenId::Rules,
        Some(AppSection::Diagnostics) => ScreenId::Diagnostics,
        _ => ScreenId::Interfaces,
    }
}

/// Every way out of the setup applies its answers, as closing the GUI's
/// window does: the protection first, the starting rules once it is in force.
fn finish(app: &mut AppState) {
    let rules = match app.wizard.chosen.take() {
        Some(Chosen::Set(pending)) => Some(*pending),
        Some(Chosen::Empty) | None => None,
    };
    send_protection(app, rules);
    stability::send(app);
    app.wizard.reset();
    let target = after_setup();
    app.open(target);
    if target == ScreenId::Interfaces {
        super::interfaces::setup_finished(app, None);
    }
}

impl Screen for WizardScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.wizard;
        let step = state.step;
        let heading = match step.number() {
            Some(number) => texts.fill(
                k::STEP,
                &[
                    ("number", number.to_string()),
                    ("total", STEP_COUNT.to_string()),
                    ("name", texts.get(step.name())),
                ],
            ),
            None => texts.get(step.name()),
        };
        let mut panels = vec![Panel {
            title: heading,
            lines: step_lines(app, texts),
            feed: false,
        }];
        if let Some(change) = &state.question {
            let lines = match change {
                RoleChange::Assign { stable_id, .. } => find(&adapters(app, false), stable_id)
                    .map(|row| unroutable_lines(row, change.route(), kill_switch_on(app), texts))
                    .unwrap_or_default(),
                RoleChange::Unassign { .. } => Vec::new(),
            };
            panels.push(Panel {
                title: texts.get(ik::UNROUTABLE_TITLE),
                lines,
                feed: false,
            });
        }
        let actions = actions(app);
        let labels: Vec<String> = actions.iter().map(|a| label(a, app, texts)).collect();
        let cursor = state.cursor.min(labels.len().saturating_sub(1));
        let mut lines = choice::lines(&labels, Some(cursor));
        if state.editing.is_some() {
            lines.push(ViewLine::text(texts.get(k::TYPING)));
        }
        panels.push(Panel {
            title: texts.get(k::ANSWERS_TITLE),
            lines,
            feed: false,
        });
        ScreenView {
            title: texts.get(k::TITLE),
            panels,
        }
    }

    fn help(&self) -> &'static [Key] {
        &[k::HELP_CHOOSE, k::HELP_TYPE]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[k::PLAIN_NUMBER]
    }

    fn on_show(&self, app: &mut AppState) {
        // A run not begun yet starts from what the service holds now.
        if app.wizard.step == Step::Language {
            app.wizard.seeded = false;
            preselect(app);
        }
        seed_protection(app);
        if app.link.is_connected() {
            app.outbox.push(adapters_read(false, |_, _| {}));
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    /// Every step waits for an answer: in line mode a number picks one of
    /// them rather than opening a screen.
    fn captures_keys(&self, _app: &AppState) -> bool {
        true
    }

    fn text_target(&self, app: &AppState) -> crate::paste::TextTarget {
        if app.wizard.editing.is_some() {
            crate::paste::TextTarget::Line
        } else {
            crate::paste::TextTarget::None
        }
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if let Some((index, typed)) = app.wizard.editing.as_mut() {
            match key.code {
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    typed.push(c);
                }
                KeyCode::Backspace => {
                    typed.pop();
                }
                KeyCode::Enter => {
                    let path = presets::typed_path(typed);
                    let index = *index;
                    app.wizard.paths[index] = path;
                    app.wizard.editing = None;
                }
                KeyCode::Esc => app.wizard.editing = None,
                _ => return false,
            }
            return true;
        }
        if app.focus != Focus::Feed && app.wizard.question.is_none() {
            return false;
        }
        let actions = actions(app);
        let cursor = app.wizard.cursor.min(actions.len().saturating_sub(1));
        if let Some(next) = choice::moved(cursor, actions.len(), key.code) {
            app.wizard.cursor = next;
            return true;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(action) = actions.get(cursor).cloned() {
                    perform(app, action);
                }
                true
            }
            KeyCode::Esc if app.wizard.question.is_some() => {
                app.wizard.question = None;
                true
            }
            _ => false,
        }
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if let Some((index, _)) = app.wizard.editing.take() {
            app.wizard.paths[index] = presets::typed_path(line);
            return true;
        }
        if line.is_empty() || !line.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let actions = actions(app);
        match choice::pick(line, actions.len()) {
            Some(index) => {
                app.wizard.cursor = index;
                if let Some(action) = actions.get(index).cloned() {
                    perform(app, action);
                }
            }
            None => app.wizard.outcome = Some(Outcome::NotUnderstood(line.to_string())),
        }
        true
    }

    fn plain_prompt(&self, app: &AppState) -> Option<Key> {
        Some(if app.wizard.editing.is_some() {
            k::PATH_PROMPT
        } else {
            k::PLAIN_PROMPT
        })
    }
}

/// The candidate the hint names: the first connection that looks like a
/// tunnel, by the kind the OS decided, else by the classification.
/// The connected adapter that reads as the VPN; an idle one a VPN client left
/// behind is not it.
fn tunnel_candidate(rows: &[InterfaceRowDto]) -> Option<String> {
    rows.iter()
        .filter(|row| !holds(row, Route::Primary) && row.availability == "available")
        .find(|row| looks_like_tunnel(row))
        .map(|row| row.name.clone())
}

fn step_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.wizard;
    let mut lines: Vec<String> = Vec::new();
    match state.step {
        Step::Licence => {
            let pages = licence_pages(app);
            lines.extend(pages.get(state.licence_page).cloned().unwrap_or_default());
            lines.push(texts.fill(
                k::LICENCE_PAGE,
                &[
                    ("number", (state.licence_page + 1).to_string()),
                    ("total", pages.len().max(1).to_string()),
                ],
            ));
        }
        Step::Language => {
            lines.push(texts.get(k::LANGUAGE_NOTE));
            if state.sheet.is_some() {
                lines.push(texts.get(k::SHEET_NOTE));
            }
        }
        Step::Primary => match assigned(app, Route::Primary) {
            Some(name) => {
                lines.push(texts.fill(k::PRIMARY_ASSIGNED, &[("name", name)]));
                lines.extend(sibling_warning(app, Route::Primary, texts));
            }
            None => {
                lines.push(texts.get(k::PRIMARY_DESCRIPTION));
                if !pickable(app) || adapters(app, false).is_empty() {
                    lines.push(texts.get(k::NO_ADAPTERS));
                }
            }
        },
        Step::Secondary => match assigned(app, Route::Secondary) {
            Some(name) => {
                // A VPN adapter is down until its client connects: still chosen.
                let up = secondary_row(app).is_some_and(|row| row.availability == "available");
                let key = if up {
                    k::SECONDARY_ASSIGNED
                } else {
                    k::SECONDARY_ASSIGNED_DOWN
                };
                lines.push(texts.fill(key, &[("name", name)]));
                lines.extend(sibling_warning(app, Route::Secondary, texts));
            }
            None if state.secondary_deferred => lines.push(texts.get(k::SECONDARY_DEFERRED)),
            None => {
                lines.push(texts.get(k::SECONDARY_DESCRIPTION));
                let rows = adapters(app, false);
                lines.push(match tunnel_candidate(&rows) {
                    Some(name) => texts.fill(k::VPN_HINT, &[("name", name)]),
                    None => texts.get(k::VPN_NONE),
                });
                if !pickable(app) || rows.is_empty() {
                    lines.push(texts.get(k::NO_ADAPTERS));
                }
            }
        },
        Step::Protection => {
            lines.push(texts.get(k::PROTECTION_DESCRIPTION));
            lines.push(texts.get(level_note(shown_level(app))));
            if leak_protection_holds_now(shown_level(app), secondary_row(app).as_ref()) {
                lines.push(texts.get(k::LEAK_HOLDS_NOW));
            }
            if app.settings.supports.site_notice_without_tray {
                lines.push(texts.get(k::SITE_NOTICE_NOTE));
            }
        }
        Step::Rules | Step::OtherCountries => {
            lines.push(texts.get(k::RULES_DESCRIPTION));
            if state.step == Step::Rules && regional_indexes(app).is_empty() {
                lines.push(texts.get(k::NO_COUNTRY_PRESET));
            }
        }
        Step::Files => lines.push(texts.get(k::OPEN_FILES_DESCRIPTION)),
        Step::Review => lines.extend(review_lines(app, texts)),
        Step::Summary => lines.extend(summary_lines(app, texts)),
    }
    if let Some(line) = status_line(app, texts) {
        lines.push(line);
    }
    lines.into_iter().map(ViewLine::text).collect()
}

fn review_lines(app: &AppState, texts: &Texts) -> Vec<String> {
    let state = &app.wizard;
    let mut lines = Vec::new();
    if let Some(pending) = &state.pending {
        for (index, file) in pending.files.iter().enumerate() {
            let Some(file) = file else { continue };
            let name = file
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            lines.push(texts.fill(
                k::FILE_RULES,
                &[
                    ("route", texts.get(file_key(index))),
                    ("file", name),
                    ("count", file.rules.to_string()),
                ],
            ));
        }
    }
    if let Some(preview) = &state.preview {
        lines.push(match &preview.refused {
            Some(code) => format!("{}{}", texts.get(k::IMPORT_FAILED), error_text(code, texts)),
            None if preview.empty => texts.get(k::NOTHING_TO_APPLY),
            None => texts.fill(
                k::REVIEW_COUNTS,
                &[
                    ("added", preview.added.to_string()),
                    ("removed", preview.removed.to_string()),
                    ("changed", preview.changed.to_string()),
                ],
            ),
        });
    }
    lines
}

/// What closing the setup applies, as the window's last step lists it: the
/// protection as the service now holds it.
fn summary_lines(app: &AppState, texts: &Texts) -> Vec<String> {
    let state = &app.wizard;
    let named = |key: Key, name: String| texts.fill(key, &[("name", name)]);
    let mut lines = vec![texts.get(k::REVIEW_DESCRIPTION)];
    let primary = assigned(app, Route::Primary);
    let no_primary = primary.is_none();
    lines.push(named(
        k::REVIEW_PRIMARY,
        primary.unwrap_or_else(|| texts.get(k::REVIEW_NOT_CHOSEN)),
    ));
    if no_primary {
        lines.push(texts.get(k::REVIEW_NO_PRIMARY));
    }
    let secondary = assigned(app, Route::Secondary).unwrap_or_else(|| {
        texts.get(if state.secondary_deferred {
            k::REVIEW_LATER
        } else {
            k::REVIEW_NOT_CHOSEN
        })
    });
    lines.push(named(k::REVIEW_SECONDARY, secondary));
    let rules = match &state.chosen {
        Some(Chosen::Set(pending)) => pending.name.resolve(texts),
        Some(Chosen::Empty) => texts.get(k::RULE_SET_EMPTY_NAME),
        None => texts.get(k::REVIEW_RULES_CURRENT),
    };
    lines.push(named(k::REVIEW_RULES, rules));
    let leak = if protection_in_force(app) {
        k::REVIEW_LEAK_IN_FORCE
    } else {
        k::REVIEW_LEAK_NOT_YET
    };
    lines.push(named(leak, texts.get(level_label(shown_level(app)))));
    lines
}

fn status_line(app: &AppState, texts: &Texts) -> Option<String> {
    let state = &app.wizard;
    if let Some(busy) = state.busy {
        return Some(texts.get(match busy {
            Busy::Saving => k::SAVING,
            Busy::Previewing => k::PREVIEWING,
        }));
    }
    Some(match state.outcome.as_ref()? {
        Outcome::Role(change) => change.done_text(texts),
        Outcome::RoleFailed(failure) => failure.text(ik::BINDING_FAILED, texts),
        Outcome::ProtectionSaved => texts.get(k::PROTECTION_SAVED),
        Outcome::ProtectionFailed(failure) => failure.text(k::PROTECTION_FAILED, texts),
        Outcome::NeedsService => texts.get(k::NEEDS_SERVICE),
        Outcome::Exclusive => texts.get(ik::EXCLUSIVE_NOTE),
        Outcome::Placeholder => texts.get(ik::PLACEHOLDER_BODY),
        Outcome::FileError { path, error } => match error {
            ReadError::Unreadable(reason) => texts.fill(
                k::FILE_UNREADABLE,
                &[("path", path.as_str()), ("error", reason.as_str())],
            ),
            ReadError::TooLarge => texts.fill(k::FILE_TOO_LARGE, &[("path", path)]),
            ReadError::NotText => texts.fill(k::FILE_NOT_TEXT, &[("path", path)]),
        },
        Outcome::ImportFailed(code) => {
            format!("{}{}", texts.get(k::IMPORT_FAILED), error_text(code, texts))
        }
        Outcome::LicenceNotSaved => texts.get(k::LICENCE_NOT_SAVED),
        Outcome::NotUnderstood(input) => texts.fill(common::PLAIN_UNKNOWN, &[("input", input)]),
    })
}

#[cfg(test)]
mod tests;

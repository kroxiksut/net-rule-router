//! The rule set offered to a user who has no rules, as the window's banner and
//! its empty Rules section offer it: the set the window's quick-load points
//! at, loaded only when asked. Either answer, here or in the window, closes
//! the offer until a full reset; the shared settings file carries it.

use nrr_client_logic::first_run::first_run_country;
use nrr_client_logic::rule_sets::{rule_set_offer_due, RuleSetOffer, ServiceState};
use nrr_shared::user_settings::{UserSettings, UserSettingsError, UserSettingsStore};

use super::files::{self, Preset, SetSource};
use super::{set_list_of, text, Note};
use crate::i18n::Texts;
use crate::link::Link;
use crate::rule_set_load::SetName;
use crate::screens::ScreenId;
use crate::state::AppState;
use crate::view::{Segment, ViewLine};

#[derive(Debug, Default)]
pub struct Offer {
    /// The set the window's quick-load points at; `None` when there is none
    /// or the settings file cannot record an answer.
    set: Option<Preset>,
    /// A rules file the user bound backs their rules.
    user_bound: bool,
    answered: bool,
    /// The setup was on screen this run: what it chose is not questioned now.
    setup_seen: bool,
}

/// Read again whenever the settings file is.
pub(super) fn refresh(
    app: &mut AppState,
    settings: Option<&Result<UserSettings, UserSettingsError>>,
) {
    let country = first_run_country(
        app.wizard.region.as_deref().unwrap_or_default(),
        &app.wizard.locale,
    );
    let offer = &mut app.rules.offer;
    match settings {
        Some(Ok(settings)) => {
            offer.answered = settings.rule_set_offer_answered;
            offer.user_bound = !settings.rules_files.primary.is_empty()
                || !settings.rules_files.secondary.is_empty();
            offer.set = default_set(settings, &country);
        }
        // No file of the user's own, or one that cannot be read: an answer
        // could not be kept.
        _ => offer.set = None,
    }
}

/// The setup screen opened: nothing is offered for the rest of this run.
pub fn setup_shown(app: &mut AppState) {
    app.rules.offer.setup_seen = true;
}

/// The window's default pick: the remembered set, else the one for the
/// system's country, else the first; none from a folder of the user's own
/// that holds no set.
fn default_set(settings: &UserSettings, country: &str) -> Option<Preset> {
    let list = set_list_of(settings);
    if list.empty_own_folder.is_some() {
        return None;
    }
    let remembered = list
        .sets
        .iter()
        .find(|set| set.selection_key() == settings.selected_set);
    let regional = || {
        let prefix = format!("{country}_");
        list.sets.iter().find(|set| {
            set.source == SetSource::Bundled
                && !country.is_empty()
                && set.label.starts_with(&prefix)
        })
    };
    remembered
        .or_else(regional)
        .or_else(|| list.sets.first())
        .cloned()
}

fn name_of(set: &Preset) -> SetName {
    match set.source {
        SetSource::User => SetName::plain(&set.label),
        SetSource::Bundled => SetName::keyed(
            format!(
                "rules.bundled-preset.name.{}",
                set.label.replacen('_', "-", 1)
            ),
            set.label.clone(),
        ),
    }
}

/// The empty list may load the set with one key, answered or not.
fn loadable(app: &AppState) -> Option<&Preset> {
    let rules = &app.rules;
    let set = rules.offer.set.as_ref()?;
    let usable = rules.settings_file.is_some()
        && !rules.baseline
        && !rules.offer.user_bound
        && rules.table.rows.is_empty();
    usable.then_some(set)
}

pub fn due(app: &AppState) -> bool {
    let rules = &app.rules;
    let Some(set) = loadable(app) else {
        return false;
    };
    let service = match app.link {
        Link::Connected => ServiceState::Running,
        Link::Stopped | Link::NotInstalled => ServiceState::Stopped,
        _ => ServiceState::NotKnown,
    };
    let table = &rules.table;
    let service_rules = if !app.link.is_connected() {
        None
    } else if table.is_loaded() && !table.is_dirty() {
        Some(table.rows.len())
    } else {
        app.snapshot
            .as_ref()
            .and_then(|s| s.active_rule_count)
            .and_then(|count| usize::try_from(count).ok())
    };
    let setup_done = !rules.offer.setup_seen
        && app.screen != ScreenId::Wizard
        && !app.wizard.licence_pending()
        && app
            .snapshot
            .as_ref()
            .is_none_or(|s| !crate::screens::wizard::needs_setup(s));
    rule_set_offer_due(&RuleSetOffer {
        first_run_done: setup_done,
        service,
        service_rules,
        local_rules: table.rows.len(),
        user_bound: rules.offer.user_bound,
        set_name: &set.label,
        answered: rules.offer.answered,
        edits_locked: rules.admin_locked,
    })
}

/// `l`: the set, loaded as picking it from the list loads it. `false` when
/// there is nothing to load here.
pub(super) fn load(app: &mut AppState) -> bool {
    let Some(set) = loadable(app).cloned() else {
        return false;
    };
    if super::locked(app) {
        return true;
    }
    answer(app);
    match files::read_set(&set.dir) {
        Err((file, error)) => app.rules.note = Some(super::read_failed(&file, error)),
        Ok(read) => {
            super::offer_import(app, read, set.label.clone());
            super::remember_set(app, &set);
        }
    }
    true
}

/// `n` while the offer is up: the window's "Not now".
pub(super) fn not_now(app: &mut AppState) -> bool {
    if !due(app) {
        return false;
    }
    answer(app);
    true
}

fn answer(app: &mut AppState) {
    let Some(file) = app.rules.settings_file.clone() else {
        return;
    };
    match UserSettingsStore::at(file).update(|s| s.rule_set_offer_answered = true) {
        Ok(_) => app.rules.offer.answered = true,
        Err(error) => {
            app.rules.note = Some(Note::with(
                text::SETTINGS_NOT_WRITTEN,
                vec![("error", error.to_string())],
            ));
        }
    }
}

fn offer_text(set: &Preset, texts: &Texts) -> String {
    texts.fill(
        text::RULE_SET_OFFER,
        &[("name", name_of(set).resolve(texts))],
    )
}

/// The offer with its keys, at the top of the Rules screen.
pub(super) fn state_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let set = loadable(app).filter(|_| due(app))?;
    Some(ViewLine::new(vec![
        Segment::strong(offer_text(set, texts)),
        Segment::plain(format!(" {}", texts.get(text::RULE_SET_OFFER_KEYS))),
    ]))
}

/// The empty list's one-key load.
pub(super) fn empty_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let set = loadable(app)?;
    let label = texts.fill(
        text::RULE_SET_LOAD,
        &[("name", name_of(set).resolve(texts))],
    );
    Some(ViewLine::text(format!("l: {label}")))
}

/// The offer on the Status screen, pointing at the keys on the Rules screen.
pub fn status_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let set = loadable(app).filter(|_| due(app))?;
    Some(ViewLine::new(vec![
        Segment::strong(offer_text(set, texts)),
        Segment::plain(format!(" {}", texts.get(text::RULE_SET_OFFER_HOW))),
    ]))
}

#[cfg(test)]
mod tests;

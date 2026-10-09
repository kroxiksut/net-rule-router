//! Choosing the folder with the user's rule sets, and the set on screen moving
//! into it (the GUI's `adoptRulesFolder`).

use std::path::Path;

use nrr_client_logic::rule_sets::{
    adopted_set_name, numbered_set_name, rules_file_folder, rules_live_in_folder, RouteFiles,
};
use nrr_client_logic::Route;
use nrr_shared::user_settings::UserSettingsError;

use super::{files, own_settings, text, Note};
use crate::state::AppState;

/// The answer to the folder prompt that goes back to the shipped sets.
pub const CLEAR: &str = "-";

/// The prompt's first text: the folder the user has, else nothing.
pub fn prompt_text(app: &AppState) -> String {
    app.rules
        .settings_file
        .as_deref()
        .and_then(own_settings::rules_folder)
        .map(|folder| folder.display().to_string())
        .unwrap_or_default()
}

/// The answer to the folder prompt: `-` clears the folder, a folder that
/// exists becomes the user's and the set on screen moves into it.
pub fn choose(app: &mut AppState, typed: &str) {
    let Some(file) = app.rules.settings_file.clone() else {
        app.rules.note = Some(Note::new(text::FOLDER_UNAVAILABLE));
        return;
    };
    let typed = typed.trim();
    if typed.is_empty() {
        return;
    }
    if typed == CLEAR {
        app.rules.note = Some(match own_settings::set_rules_folder(&file, None) {
            Ok(()) => Note::new(text::FOLDER_CLEARED),
            Err(error) => not_written(&error),
        });
        return;
    }
    let folder = own_settings::absolute(Path::new(typed));
    if !folder.is_dir() {
        let path = folder.display().to_string();
        app.rules.note = Some(Note::with(text::FOLDER_MISSING, vec![("path", path)]));
        return;
    }
    if let Err(error) = own_settings::set_rules_folder(&file, Some(&folder)) {
        app.rules.note = Some(not_written(&error));
        return;
    }
    app.rules.note = Some(adopt(app, &file, &folder));
}

/// The files of a set written to `dir`, as the settings file spells them.
pub fn written_texts(dir: &Path) -> [String; 2] {
    let dir = own_settings::absolute(dir);
    Route::ALL.map(|route| own_settings::path_text(&dir.join(files::file_name(route))))
}

fn not_written(error: &UserSettingsError) -> Note {
    Note::with(
        text::SETTINGS_NOT_WRITTEN,
        vec![("error", error.to_string())],
    )
}

/// The set on screen moves into `folder` unless it already lives there. A
/// taken name gets a number, never an overwrite and never a question, and the
/// files the rules were bound to stay where they are.
fn adopt(app: &mut AppState, file: &Path, folder: &Path) -> Note {
    let shown = folder.display().to_string();
    let folder_set = Note::with(text::FOLDER_SET, vec![("path", shown.clone())]);
    if app.rules.table.rows.is_empty() {
        return folder_set;
    }
    let settings = match own_settings::read(file) {
        Ok(settings) => settings,
        Err(error) => return not_written(&error),
    };
    let bound = [
        settings.rules_files.primary.as_str(),
        settings.rules_files.secondary.as_str(),
    ];
    let loaded = &app.rules.loaded_files;
    let routes = [
        RouteFiles {
            saved: bound[0],
            loaded: &loaded[0],
            auto_open: "",
        },
        RouteFiles {
            saved: bound[1],
            loaded: &loaded[1],
            auto_open: "",
        },
    ];
    if rules_live_in_folder(&routes, &own_settings::path_text(folder)) {
        return folder_set;
    }
    let base = adopted_set_name(&routes, &settings.selected_set, app.rules.my_rules_name());
    let name = numbered_set_name(&base, |name| files::set_exists(&folder.join(name)));
    let dir = folder.join(&name);
    if files::set_exists(&dir) {
        return Note::with(text::SET_NAMES_TAKEN, vec![("name", base), ("path", shown)]);
    }
    let mut previous: Vec<String> = Vec::new();
    for path in bound {
        let old = rules_file_folder(path);
        if !old.is_empty() && !previous.contains(&old) {
            previous.push(old);
        }
    }

    let exported_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if let Err((path, error)) = files::write_set(&dir, &app.rules.table, &exported_at) {
        let path = path.display().to_string();
        return Note::with(text::WRITE_FAILED, vec![("path", path), ("error", error)]);
    }
    let written = dir.display().to_string();
    let shipped = files::presets_root();
    if let Err(error) = own_settings::bind_written_set(file, &dir, shipped.as_deref()) {
        return Note::with(
            text::EXPORTED_UNBOUND,
            vec![("path", written), ("error", error.to_string())],
        );
    }
    app.rules.loaded_files = written_texts(&dir);
    let saved = Note::with(text::FOLDER_SET_SAVED, vec![("dir", written)]);
    if previous.is_empty() {
        saved
    } else {
        saved.then(Note::with(
            text::OLD_FILES_KEPT,
            vec![("dir", previous.join(", "))],
        ))
    }
}

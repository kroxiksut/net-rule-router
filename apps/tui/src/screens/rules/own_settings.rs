//! The user's settings file the GUI shares: the rule-set folder, the bound
//! rules files and the chosen set. Read on each use, so a choice made in the
//! window meanwhile is the one this screen sees; written per key, so the
//! window's other keys survive.

use std::path::{Component, Path, PathBuf};

use nrr_client_logic::rule_sets::is_path_under_dir;
use nrr_client_logic::Route;
use nrr_shared::user_settings::{
    portable_path, UserSettings, UserSettingsError, UserSettingsStore,
};

use super::files;

/// The settings as they stand; no file yet reads as empty settings.
pub fn read(file: &Path) -> Result<UserSettings, UserSettingsError> {
    UserSettingsStore::at(file.to_path_buf())
        .load()
        .map(Option::unwrap_or_default)
}

/// The user's rule-set folder, if they have one and it can be read.
pub fn rules_folder(file: &Path) -> Option<PathBuf> {
    read(file).ok().as_ref().and_then(own_folder)
}

pub fn own_folder(settings: &UserSettings) -> Option<PathBuf> {
    let folder = &settings.rules_folder;
    (!folder.is_empty()).then(|| PathBuf::from(folder))
}

/// Remembers the set picked, as the GUI's rule-set dropdown does.
pub fn remember_set(file: &Path, selection_key: &str) -> Result<(), UserSettingsError> {
    UserSettingsStore::at(file.to_path_buf())
        .update(|settings| settings.selected_set = selection_key.to_string())
        .map(drop)
}

/// Makes `folder` the user's rule-set folder; `None` goes back to the sets
/// shipped with the program.
pub fn set_rules_folder(file: &Path, folder: Option<&Path>) -> Result<(), UserSettingsError> {
    let text = folder.map(path_text).unwrap_or_default();
    UserSettingsStore::at(file.to_path_buf())
        .update(|settings| settings.set_rules_folder(&text))
        .map(drop)
}

/// `path` made absolute, `.` and `..` resolved by name rather than on disk:
/// both clients compare these paths as text.
pub fn absolute(path: &Path) -> PathBuf {
    let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// A path as the settings file spells it.
pub fn path_text(path: &Path) -> String {
    portable_path(&path.to_string_lossy())
}

/// Inside the shipped tree and not inside the user's own folder: the next
/// update overwrites it, so it is never a save target (the GUI's
/// `isFactoryPresetPath`).
fn is_factory(path: &str, own_folder: &str, shipped_root: Option<&Path>) -> bool {
    let shipped = shipped_root.map(|root| path_text(&absolute(root)));
    !is_path_under_dir(path, own_folder)
        && shipped.is_some_and(|root| is_path_under_dir(path, &root))
}

/// Too wide to be a rule-set folder: the filesystem root or the home
/// directory, where every other folder would list as a set.
fn is_too_wide(dir: &Path) -> bool {
    if dir.parent().is_none() {
        return true;
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" });
    let dir = path_text(dir);
    home.is_some_and(|home| {
        let home = path_text(Path::new(&home));
        is_path_under_dir(&home, &dir) && is_path_under_dir(&dir, &home)
    })
}

/// After both files were written to `dir`: they become the user's rules files,
/// and the folder above `dir` becomes their rule-set folder if they had none —
/// the GUI's "the first folder a set is saved to" rule, never for the root or
/// the home directory. Neither happens in the shipped tree.
pub fn bind_written_set(
    file: &Path,
    dir: &Path,
    shipped_root: Option<&Path>,
) -> Result<(), UserSettingsError> {
    let dir = absolute(dir);
    let dir_text = path_text(&dir);
    UserSettingsStore::at(file.to_path_buf())
        .update(|settings| {
            if is_factory(&dir_text, &settings.rules_folder, shipped_root) {
                return;
            }
            settings.set_primary_file(&path_text(&dir.join(files::file_name(Route::Primary))));
            settings.set_secondary_file(&path_text(&dir.join(files::file_name(Route::Secondary))));
            if settings.rules_folder.is_empty() {
                if let Some(parent) = dir.parent().filter(|parent| !is_too_wide(parent)) {
                    settings.set_rules_folder(&path_text(parent));
                }
            }
        })
        .map(drop)
}

/// After a set was read into the table: each route read from a file is bound
/// to that file, as the GUI binds what it loads. A file in the shipped tree
/// leaves its route with no file: it is not a save target.
pub fn bind_imported(
    file: &Path,
    paths: &[Option<PathBuf>; 2],
    shipped_root: Option<&Path>,
) -> Result<(), UserSettingsError> {
    let [primary, secondary] = imported_texts(paths);
    UserSettingsStore::at(file.to_path_buf())
        .update(|settings| {
            if let Some(path) = &primary {
                let factory = is_factory(path, &settings.rules_folder, shipped_root);
                settings.set_primary_file(if factory { "" } else { path.as_str() });
            }
            if let Some(path) = &secondary {
                let factory = is_factory(path, &settings.rules_folder, shipped_root);
                settings.set_secondary_file(if factory { "" } else { path.as_str() });
            }
        })
        .map(drop)
}

/// The files a set was read from, as the settings file spells them.
pub fn imported_texts(paths: &[Option<PathBuf>; 2]) -> [Option<String>; 2] {
    paths
        .each_ref()
        .map(|path| path.as_deref().map(|path| path_text(&absolute(path))))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use nrr_shared::user_settings::USER_SETTINGS_FILE_NAME;

    /// The scratch directory with this module's file name in it.
    struct Scratch(crate::testing::Scratch);

    impl Scratch {
        fn new(name: &str) -> Self {
            Self(crate::testing::Scratch::new(&format!(
                "own-settings-{name}"
            )))
        }

        fn path(&self) -> &Path {
            self.0.path()
        }

        fn settings_file(&self) -> PathBuf {
            self.path().join(USER_SETTINGS_FILE_NAME)
        }
    }

    #[test]
    fn no_file_reads_as_no_folder() {
        let dir = Scratch::new("none");
        assert_eq!(rules_folder(&dir.settings_file()), None);
        assert_eq!(
            read(&dir.settings_file()).expect("read"),
            UserSettings::default()
        );
    }

    #[test]
    fn the_first_set_written_binds_its_files_and_names_the_folder() {
        let dir = Scratch::new("first");
        let file = dir.settings_file();
        let set = dir.path().join("sets").join("home");
        bind_written_set(&file, &set, None).expect("bind");

        let settings = read(&file).expect("read");
        assert_eq!(
            PathBuf::from(&settings.rules_files.primary),
            set.join("rules_primary.txt")
        );
        assert_eq!(
            PathBuf::from(&settings.rules_files.secondary),
            set.join("rules_secondary.txt")
        );
        assert_eq!(
            PathBuf::from(&settings.rules_folder),
            dir.path().join("sets")
        );
    }

    #[test]
    fn a_folder_the_user_has_is_kept() {
        let dir = Scratch::new("kept");
        let file = dir.settings_file();
        let own = dir.path().join("mine");
        UserSettingsStore::at(file.clone())
            .update(|s| s.rules_folder = own.to_string_lossy().into_owned())
            .expect("seed");
        bind_written_set(&file, &dir.path().join("elsewhere").join("x"), None).expect("bind");
        assert_eq!(rules_folder(&file), Some(own));
    }

    #[test]
    fn the_shipped_tree_is_not_bound() {
        let dir = Scratch::new("shipped");
        let file = dir.settings_file();
        let shipped = dir.path().join("presets");
        bind_written_set(&file, &shipped.join("ru").join("basic"), Some(&shipped)).expect("bind");
        assert_eq!(read(&file).expect("read"), UserSettings::default());
    }

    #[test]
    fn a_pick_is_remembered_without_touching_the_rest() {
        let dir = Scratch::new("pick");
        let file = dir.settings_file();
        UserSettingsStore::at(file.clone())
            .update(|s| s.rules_files.primary = "/p".to_string())
            .expect("seed");
        remember_set(&file, "user:home").expect("remember");
        let settings = read(&file).expect("read");
        assert_eq!(settings.selected_set, "user:home");
        assert_eq!(settings.rules_files.primary, "/p");
    }

    #[test]
    fn the_user_folder_lists_its_sets_like_the_gui() {
        let dir = Scratch::new("list");
        let write = |set: &Path| {
            std::fs::create_dir_all(set).expect("set dir");
            std::fs::write(set.join("rules_primary.txt"), "").expect("rules file");
        };
        write(&dir.path().join("home"));
        write(&dir.path().join("ru").join("basic"));
        std::fs::create_dir_all(dir.path().join("empty")).expect("empty dir");

        let sets = files::user_sets(dir.path());
        let keys: Vec<String> = sets.iter().map(files::Preset::selection_key).collect();
        assert_eq!(keys, ["user:home", "user:ru_basic"]);
    }

    #[test]
    fn the_set_list_names_the_users_folder_or_says_it_is_empty() {
        let dir = Scratch::new("set-list");
        let file = dir.settings_file();
        let sets = dir.path().join("sets");
        std::fs::create_dir_all(sets.join("home")).expect("set dir");
        std::fs::write(sets.join("home").join("rules_primary.txt"), "").expect("rules file");
        let store = UserSettingsStore::at(file.clone());
        store
            .update(|s| {
                s.rules_folder = sets.to_string_lossy().into_owned();
                s.selected_set = "user:home".to_string();
            })
            .expect("seed");

        let list = super::super::set_list(Some(&file));
        assert_eq!(list.folder.as_deref(), Some(sets.as_path()));
        assert_eq!(list.sets.len(), 1);
        assert_eq!(list.selected, "user:home");
        assert_eq!(list.empty_own_folder, None);

        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).expect("empty dir");
        store
            .update(|s| s.rules_folder = empty.to_string_lossy().into_owned())
            .expect("point at the empty folder");
        let list = super::super::set_list(Some(&file));
        assert_eq!(list.empty_own_folder, Some(empty));
        for set in &list.sets {
            assert_eq!(set.source, files::SetSource::Bundled);
        }
    }

    #[test]
    fn a_damaged_settings_file_is_said_in_the_set_list() {
        let dir = Scratch::new("damaged");
        let file = dir.settings_file();
        std::fs::write(&file, "{broken").expect("seed");
        let list = super::super::set_list(Some(&file));
        assert!(list.settings_error.is_some());
        assert_eq!(std::fs::read_to_string(&file).expect("read"), "{broken");
    }
}

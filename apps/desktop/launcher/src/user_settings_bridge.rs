//! The GUI's side of the shared `user-settings.json`.
//!
//! The window keeps reading and writing its own preferences; the launcher
//! makes the shared file authoritative for the fields both clients use. The
//! file overrides the preferences when a session opens, and afterwards only a
//! field the window itself changed is written back — a field it merely carried
//! must not undo what the terminal client set meanwhile.

use std::sync::atomic::{AtomicBool, Ordering};

use nrr_shared::client_error_codes::{
    MALFORMED_INPUT, USER_SETTINGS_READ_ONLY, USER_SETTINGS_UNAVAILABLE,
};
use nrr_shared::user_settings::{
    portable_path, read_rules_file_bytes, UserSettings, UserSettingsError, UserSettingsStore,
    INTENT_NOTICE_MUTES, INTENT_ROUTE_POLICY,
};
use nrr_ui_support::ui_preferences::{is_storable_json_blob, UiPreferences};
use serde_json::{Map, Value};

/// The shared fields as the preferences hold them, paths in the file's
/// spelling.
pub(crate) fn settings_from_preferences(preferences: &UiPreferences) -> UserSettings {
    let mut settings = UserSettings {
        selected_set: preferences.selected_preset_set.clone(),
        service_intent: intent_object(&preferences.service_intent_json),
        accepted_eula: preferences.accepted_eula_version,
        ..UserSettings::default()
    };
    let bound = |path: &Option<String>| path.as_deref().unwrap_or_default().to_owned();
    settings.set_rules_folder(&preferences.user_presets_dir);
    settings.set_primary_file(&bound(&preferences.last_saved_path_primary));
    settings.set_secondary_file(&bound(&preferences.last_saved_path_secondary));
    settings
}

/// One path in two spellings (`\` or `/`, a trailing separator) is one path.
fn same_path(a: &str, b: &str) -> bool {
    portable_path(a) == portable_path(b)
}

/// The preferences keep the intent as JSON text; anything but an object is
/// "none" there too.
fn intent_object(json: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(object)) => object,
        _ => Map::new(),
    }
}

/// Puts the shared fields over `preferences`. A value the preferences file
/// cannot hold (a line break, an oversized intent) leaves the field as it was.
pub(crate) fn overlay(preferences: &mut UiPreferences, settings: &UserSettings) {
    let folder = &settings.rules_folder;
    if one_line(folder) && !same_path(folder, &preferences.user_presets_dir) {
        preferences.user_presets_dir = folder.clone();
    }
    if one_line(&settings.selected_set) {
        preferences.selected_preset_set = settings.selected_set.clone();
    }
    let bound = [
        (
            &settings.rules_files.primary,
            &mut preferences.last_saved_path_primary,
            &mut preferences.last_loaded_path_primary,
        ),
        (
            &settings.rules_files.secondary,
            &mut preferences.last_saved_path_secondary,
            &mut preferences.last_loaded_path_secondary,
        ),
    ];
    for (path, saved, loaded) in bound {
        if !one_line(path) {
            continue;
        }
        if same_path(path, saved.as_deref().unwrap_or_default()) {
            continue;
        }
        let path = (!path.is_empty()).then(|| path.clone());
        // Files bound elsewhere are also where the rules now come from, as
        // after a write in the window itself.
        if path.is_some() {
            loaded.clone_from(&path);
        }
        *saved = path;
    }
    let intent = if settings.service_intent.is_empty() {
        String::new()
    } else {
        Value::Object(settings.service_intent.clone()).to_string()
    };
    preferences.accepted_eula_version = preferences
        .accepted_eula_version
        .max(settings.accepted_eula);
    if is_storable_json_blob(&intent) {
        preferences.service_intent_json = intent;
    }
}

/// The preferences file keeps each value on one line.
fn one_line(value: &str) -> bool {
    !value.contains(['\n', '\r'])
}

/// Writes the shared fields this session changes.
pub(crate) struct UserSettingsMirror {
    store: UserSettingsStore,
    /// The shared fields as this session last read or wrote them.
    known: UserSettings,
}

impl UserSettingsMirror {
    pub(crate) fn new(store: UserSettingsStore, preferences: &UiPreferences) -> Self {
        Self {
            store,
            known: settings_from_preferences(preferences),
        }
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        self.store.path()
    }

    /// Merges into the file each shared field `preferences` holds differently
    /// from what this session last knew. `Ok(false)`: nothing to write.
    pub(crate) fn publish(
        &mut self,
        preferences: &UiPreferences,
    ) -> Result<bool, UserSettingsError> {
        let mine = settings_from_preferences(preferences);
        if !self.known.clone().adopt_changes(&self.known, &mine) {
            return Ok(false);
        }
        let known = &self.known;
        self.store.update(|current| {
            current.adopt_changes(known, &mine);
        })?;
        self.known = mine;
        Ok(true)
    }
}

/// Opens the shared file for a session and lays it over `preferences`.
///
/// The first run after an upgrade finds no file and writes one from the
/// preferences. `writable: false` — the preferences could not be read — still
/// reads the file but never writes it. `None`: nothing is to be written this
/// session, the reason already reported on stderr.
pub(crate) fn open_session(
    preferences: &mut UiPreferences,
    writable: bool,
) -> Option<UserSettingsMirror> {
    let store = match UserSettingsStore::open() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("nrr-launcher: user settings unavailable: {error}");
            return None;
        }
    };
    let mirror = open_session_in(store, preferences, writable);
    SESSION_MAY_WRITE.store(mirror.is_some(), Ordering::Relaxed);
    mirror
}

/// Whether this session may write the shared file at all: the same answer the
/// preferences mirror got, so a read-only session records no intent either.
static SESSION_MAY_WRITE: AtomicBool = AtomicBool::new(false);

/// Why an intent read or record did not happen.
#[derive(Debug)]
pub(crate) enum IntentError {
    /// This session does not write the shared file.
    ReadOnly,
    /// The request named no namespace this operation records, or no value.
    BadRequest(&'static str),
    Settings(UserSettingsError),
}

impl IntentError {
    pub(crate) fn wire_code(&self) -> &'static str {
        match self {
            Self::ReadOnly => USER_SETTINGS_READ_ONLY,
            Self::BadRequest(_) => MALFORMED_INPUT,
            Self::Settings(_) => USER_SETTINGS_UNAVAILABLE,
        }
    }
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => f.write_str("this session does not write the user settings"),
            Self::BadRequest(what) => f.write_str(what),
            Self::Settings(error) => write!(f, "{error}"),
        }
    }
}

impl From<UserSettingsError> for IntentError {
    fn from(error: UserSettingsError) -> Self {
        Self::Settings(error)
    }
}

/// `local.user-settings.intent-get`: the recorded intent, read afresh — the
/// terminal client may have written it since this session started.
pub(crate) fn intent_get() -> Result<Value, IntentError> {
    intent_get_in(&UserSettingsStore::open()?)
}

pub(crate) fn intent_get_in(store: &UserSettingsStore) -> Result<Value, IntentError> {
    let settings = store.load()?.unwrap_or_default();
    Ok(serde_json::json!({ "service-intent": Value::Object(settings.service_intent) }))
}

/// `local.user-settings.intent-record`: what a confirmed user write decided.
/// `{"namespace": "route-policy", "merge": {key: value}}` merges keys (`null`
/// drops one); `{"namespace": "notice-mutes", "value": [...]}` replaces the
/// list. The stability namespace rides the preferences instead.
pub(crate) fn intent_record(payload: &Value) -> Result<Value, IntentError> {
    let may_write = SESSION_MAY_WRITE.load(Ordering::Relaxed);
    intent_record_in(&UserSettingsStore::open()?, payload, may_write)
}

pub(crate) fn intent_record_in(
    store: &UserSettingsStore,
    payload: &Value,
    may_write: bool,
) -> Result<Value, IntentError> {
    if !may_write {
        return Err(IntentError::ReadOnly);
    }
    let namespace = payload.get("namespace").and_then(Value::as_str);
    match namespace {
        Some(INTENT_ROUTE_POLICY) => {
            let values = payload
                .get("merge")
                .and_then(Value::as_object)
                .ok_or(IntentError::BadRequest("`merge` is not an object"))?;
            store.update(|settings| settings.merge_intent(INTENT_ROUTE_POLICY, values))?;
        }
        Some(INTENT_NOTICE_MUTES) => {
            let value = payload
                .get("value")
                .filter(|value| value.is_array())
                .ok_or(IntentError::BadRequest("`value` is not a list"))?;
            store.update(|settings| settings.set_intent(INTENT_NOTICE_MUTES, value.clone()))?;
        }
        _ => return Err(IntentError::BadRequest("unknown intent namespace")),
    }
    Ok(serde_json::json!({ "recorded": true }))
}

/// A request names at most the two route files and a few more.
const MAX_CHECKED_PATHS: usize = 8;

/// SHA-256 of a rules file's bytes; `Ok(None)` when it is absent.
fn rules_file_sha256(path: &str) -> std::io::Result<Option<String>> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let Some(bytes) = read_rules_file_bytes(std::path::Path::new(path))? else {
        return Ok(None);
    };
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(Some(hex))
}

fn path_field(value: Option<&Value>) -> Result<&str, IntentError> {
    value
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty() && one_line(path))
        .ok_or(IntentError::BadRequest("`path` is not a file path"))
}

/// `local.user-settings.rules-file-written`: the program has just written the
/// rules file at `path`; what is there now is its version of it.
pub(crate) fn rules_file_written(payload: &Value) -> Result<Value, IntentError> {
    let may_write = SESSION_MAY_WRITE.load(Ordering::Relaxed);
    rules_file_written_in(&UserSettingsStore::open()?, payload, may_write)
}

pub(crate) fn rules_file_written_in(
    store: &UserSettingsStore,
    payload: &Value,
    may_write: bool,
) -> Result<Value, IntentError> {
    if !may_write {
        return Err(IntentError::ReadOnly);
    }
    let path = path_field(payload.get("path"))?;
    // Unreadable or gone right after the write: nothing to remember.
    let Ok(Some(sha256)) = rules_file_sha256(path) else {
        return Ok(serde_json::json!({ "recorded": false }));
    };
    store.update(|settings| settings.record_rules_file_written(path, &sha256))?;
    Ok(serde_json::json!({ "recorded": true }))
}

/// `local.user-settings.rules-files-hand-edited`: which of `paths` changed
/// since the program last wrote them. A file that cannot be read counts as
/// changed when there is a record: overwriting it unasked is the loss to avoid.
pub(crate) fn rules_files_hand_edited(payload: &Value) -> Result<Value, IntentError> {
    rules_files_hand_edited_in(&UserSettingsStore::open()?, payload)
}

pub(crate) fn rules_files_hand_edited_in(
    store: &UserSettingsStore,
    payload: &Value,
) -> Result<Value, IntentError> {
    let paths = payload
        .get("paths")
        .and_then(Value::as_array)
        .filter(|paths| paths.len() <= MAX_CHECKED_PATHS)
        .ok_or(IntentError::BadRequest("`paths` is not a short list"))?;
    let settings = store.load()?.unwrap_or_default();
    let mut edited = Vec::new();
    for path in paths {
        let path = path_field(Some(path))?;
        let on_disk = rules_file_sha256(path).unwrap_or_else(|_| Some(String::new()));
        if settings.rules_file_hand_edited(path, on_disk.as_deref()) {
            edited.push(Value::String(path.to_owned()));
        }
    }
    Ok(serde_json::json!({ "hand-edited": edited }))
}

pub(crate) fn open_session_in(
    store: UserSettingsStore,
    preferences: &mut UiPreferences,
    writable: bool,
) -> Option<UserSettingsMirror> {
    if !writable {
        match store.load() {
            Ok(Some(settings)) => overlay(preferences, &settings),
            Ok(None) => {}
            Err(error) => eprintln!("nrr-launcher: user settings not read: {error}"),
        }
        return None;
    }
    match store.load_or_seed(|| settings_from_preferences(preferences)) {
        Ok(outcome) => {
            if outcome.seeded {
                // File name only: the directory names the account.
                eprintln!(
                    "nrr-launcher: user settings ({}) created from the preferences",
                    store
                        .path()
                        .file_name()
                        .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                );
            } else {
                overlay(preferences, &outcome.settings);
                // An agreement accepted before the file carried it: the
                // terminal client reads it only from here.
                let accepted = preferences.accepted_eula_version;
                if accepted > outcome.settings.accepted_eula {
                    let _ = store.update(|settings| {
                        settings.accepted_eula = settings.accepted_eula.max(accepted);
                    });
                }
            }
            Some(UserSettingsMirror::new(store, preferences))
        }
        Err(error) => {
            // A file we cannot read is the user's copy; it is not rewritten.
            eprintln!("nrr-launcher: user settings not read, not written this session: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::user_settings::USER_SETTINGS_FILE_NAME;

    fn store_in(dir: &tempfile::TempDir) -> UserSettingsStore {
        UserSettingsStore::at(dir.path().join(USER_SETTINGS_FILE_NAME))
    }

    fn preferences() -> UiPreferences {
        UiPreferences {
            user_presets_dir: "/home/user/sets".to_string(),
            last_saved_path_primary: Some("/home/user/sets/a/rules_primary.txt".to_string()),
            last_saved_path_secondary: None,
            selected_preset_set: "user:a".to_string(),
            service_intent_json: r#"{"stability":{"verbose-logging":true}}"#.to_string(),
            ..UiPreferences::default()
        }
    }

    #[test]
    fn the_first_session_creates_the_file_from_the_preferences() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut prefs = preferences();
        let mirror = open_session_in(store_in(&dir), &mut prefs, true);
        assert!(mirror.is_some());
        assert_eq!(prefs, preferences(), "the preferences are unchanged");

        let written = store_in(&dir).load().expect("load").expect("created");
        assert_eq!(written.rules_folder, "/home/user/sets");
        assert_eq!(
            written.rules_files.primary,
            "/home/user/sets/a/rules_primary.txt"
        );
        assert_eq!(written.rules_files.secondary, "");
        assert_eq!(written.selected_set, "user:a");
        assert_eq!(
            written.service_intent["stability"]["verbose-logging"],
            Value::Bool(true)
        );
    }

    #[test]
    fn the_file_overrides_the_preferences() {
        let dir = tempfile::tempdir().expect("temp dir");
        store_in(&dir)
            .update(|s| {
                s.rules_folder = "/terminal/sets".to_string();
                s.rules_files.secondary = "/terminal/sets/b/rules_secondary.txt".to_string();
                s.selected_set = "bundled:ru_basic".to_string();
            })
            .expect("seed");
        let mut prefs = preferences();
        open_session_in(store_in(&dir), &mut prefs, true).expect("mirror");

        assert_eq!(prefs.user_presets_dir, "/terminal/sets");
        assert_eq!(prefs.last_saved_path_primary, None);
        let secondary = Some("/terminal/sets/b/rules_secondary.txt".to_string());
        assert_eq!(prefs.last_saved_path_secondary, secondary);
        assert_eq!(prefs.last_loaded_path_secondary, secondary);
        assert_eq!(prefs.selected_preset_set, "bundled:ru_basic");
        assert_eq!(prefs.service_intent_json, "", "an empty intent is none");
    }

    #[test]
    fn a_value_the_preferences_cannot_hold_is_not_overlaid() {
        let mut prefs = preferences();
        let settings = UserSettings {
            rules_folder: "/two\nlines".to_string(),
            ..settings_from_preferences(&prefs)
        };
        overlay(&mut prefs, &settings);
        assert_eq!(prefs.user_presets_dir, "/home/user/sets");
    }

    #[test]
    fn an_agreement_accepted_in_the_terminal_is_not_asked_again() {
        let mut prefs = preferences();
        prefs.accepted_eula_version = 0;
        let settings = UserSettings {
            accepted_eula: 1,
            ..settings_from_preferences(&prefs)
        };
        overlay(&mut prefs, &settings);
        assert_eq!(prefs.accepted_eula_version, 1);
        let older = UserSettings {
            accepted_eula: 0,
            ..settings_from_preferences(&prefs)
        };
        overlay(&mut prefs, &older);
        assert_eq!(prefs.accepted_eula_version, 1);
    }

    // A backslash separates only on Windows; elsewhere it is part of a name.
    #[cfg(windows)]
    #[test]
    fn a_path_spelled_with_backslashes_is_the_same_file() {
        let mut prefs = UiPreferences {
            user_presets_dir: "C:\\Sets\\".to_string(),
            last_saved_path_primary: Some("C:\\Sets\\a\\rules_primary.txt".to_string()),
            ..UiPreferences::default()
        };
        let settings = settings_from_preferences(&prefs);
        assert_eq!(settings.rules_folder, "C:/Sets");
        assert_eq!(settings.rules_files.primary, "C:/Sets/a/rules_primary.txt");

        let before = prefs.clone();
        overlay(&mut prefs, &settings);
        assert_eq!(prefs, before, "the window keeps its own spelling");
    }

    #[test]
    fn an_intent_record_merges_into_its_namespace_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        store
            .update(|s| {
                s.merge_intent(
                    "stability",
                    serde_json::json!({ "x": 1 }).as_object().expect("o"),
                );
            })
            .expect("seed");
        let record = serde_json::json!({
            "namespace": "route-policy",
            "merge": { "leak-protection": "everything" }
        });
        intent_record_in(&store, &record, true).expect("recorded");
        let mutes = serde_json::json!({ "namespace": "notice-mutes", "value": [] });
        intent_record_in(&store, &mutes, true).expect("recorded");

        let got = intent_get_in(&store).expect("read");
        assert_eq!(
            got["service-intent"],
            serde_json::json!({
                "stability": { "x": 1 },
                "route-policy": { "leak-protection": "everything" },
                "notice-mutes": []
            })
        );
    }

    #[test]
    fn a_read_only_session_records_no_intent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let record = serde_json::json!({ "namespace": "route-policy", "merge": { "mode": "x" } });
        assert!(matches!(
            intent_record_in(&store, &record, false),
            Err(IntentError::ReadOnly)
        ));
        assert!(!store.path().exists());
        let stability = serde_json::json!({ "namespace": "stability", "merge": {} });
        assert!(matches!(
            intent_record_in(&store, &stability, true),
            Err(IntentError::BadRequest(_))
        ));
    }

    #[test]
    fn a_rules_file_changed_after_the_program_wrote_it_is_named() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let file = dir.path().join("rules_primary.txt");
        let path = file.to_string_lossy().into_owned();
        std::fs::write(&file, "example.com\n").expect("write");
        let written = serde_json::json!({ "path": path });
        rules_file_written_in(&store, &written, true).expect("recorded");

        let ask = serde_json::json!({ "paths": [path] });
        let answer = rules_files_hand_edited_in(&store, &ask).expect("checked");
        assert_eq!(answer["hand-edited"], serde_json::json!([]));

        std::fs::write(&file, "example.com\nexample.org\n").expect("hand edit");
        let answer = rules_files_hand_edited_in(&store, &ask).expect("checked");
        assert_eq!(answer["hand-edited"], serde_json::json!([path]));

        assert!(matches!(
            rules_file_written_in(&store, &written, false),
            Err(IntentError::ReadOnly)
        ));
        let bad = serde_json::json!({ "paths": "x" });
        assert!(rules_files_hand_edited_in(&store, &bad).is_err());
    }

    #[test]
    fn a_read_only_session_reads_but_never_writes() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut prefs = preferences();
        assert!(open_session_in(store_in(&dir), &mut prefs, false).is_none());
        assert!(!store_in(&dir).path().exists(), "no migration either");

        store_in(&dir)
            .update(|s| s.selected_set = "user:b".to_string())
            .expect("seed");
        assert!(open_session_in(store_in(&dir), &mut prefs, false).is_none());
        assert_eq!(prefs.selected_preset_set, "user:b");
    }

    #[test]
    fn a_damaged_file_is_neither_overlaid_nor_rewritten() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = store_in(&dir).path().to_path_buf();
        std::fs::write(&path, "{broken").expect("seed");
        let mut prefs = preferences();
        assert!(open_session_in(store_in(&dir), &mut prefs, true).is_none());
        assert_eq!(prefs, preferences());
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "{broken");
    }

    #[test]
    fn publishing_does_not_clobber_a_change_made_elsewhere() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut prefs = preferences();
        let mut mirror = open_session_in(store_in(&dir), &mut prefs, true).expect("mirror");

        // The terminal binds other files while the window runs.
        store_in(&dir)
            .update(|s| {
                s.rules_files.primary = "/terminal/rules_primary.txt".to_string();
            })
            .expect("terminal write");

        // The window saves its preferences with only the set changed; its
        // primary path is still the one it loaded.
        prefs.selected_preset_set = "user:c".to_string();
        assert!(mirror.publish(&prefs).expect("publish"));

        let on_disk = store_in(&dir).load().expect("load").expect("present");
        assert_eq!(on_disk.selected_set, "user:c");
        assert_eq!(
            on_disk.rules_files.primary, "/terminal/rules_primary.txt",
            "a field the window did not change keeps the terminal's value"
        );
    }

    #[test]
    fn an_unchanged_snapshot_writes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut prefs = preferences();
        let mut mirror = open_session_in(store_in(&dir), &mut prefs, true).expect("mirror");
        let before = std::fs::read_to_string(mirror.path()).expect("read");
        // Same intent, keys in another order: the same object.
        prefs.service_intent_json = r#"{ "stability": { "verbose-logging": true } }"#.to_string();
        assert!(!mirror.publish(&prefs).expect("publish"));
        let after = std::fs::read_to_string(mirror.path()).expect("read");
        assert_eq!(after, before);
    }

    #[test]
    fn a_field_the_window_changes_twice_is_written_both_times() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut prefs = preferences();
        let mut mirror = open_session_in(store_in(&dir), &mut prefs, true).expect("mirror");
        prefs.user_presets_dir = "/one".to_string();
        assert!(mirror.publish(&prefs).expect("first"));
        prefs.user_presets_dir = "/two".to_string();
        assert!(mirror.publish(&prefs).expect("second"));
        let on_disk = store_in(&dir).load().expect("load").expect("present");
        assert_eq!(on_disk.rules_folder, "/two");
    }

    /// The hash of a rules file is stored beside it; a crypto-crate upgrade
    /// must not change it, or every hand-edit check misfires.
    #[test]
    fn the_rules_file_hash_is_pinned() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("rules_primary.txt");
        std::fs::write(&file, b"abc").expect("write");
        let hash = rules_file_sha256(file.to_str().expect("utf-8 path"))
            .expect("read")
            .expect("present");
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

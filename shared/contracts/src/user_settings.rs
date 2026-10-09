//! The user's own settings that every client reads without the service: the
//! rule-set folder, the bound rules files, the chosen set and the recorded
//! service intents.
//!
//! One JSON file per OS user, so the terminal client sees what the window
//! chose, and the user keeps a copy of their choices when the service's
//! database cannot be read. Writes are per-key merges under a lock file: two
//! clients changing different keys never erase each other, and a key this
//! build does not know survives the rewrite.
//!
//! A file that is there but cannot be read is never overwritten: the caller
//! gets [`UserSettingsError::Damaged`] and decides what to tell the user.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Map, Value};

pub const USER_SETTINGS_FILE_NAME: &str = "user-settings.json";

/// Intent namespaces: the machine-wide stability settings, the user's route
/// policy (wire keys of `route.policy.update`, adapter bindings included) and
/// the user's notice mutes (the `block-notices.mutes.list` array).
pub const INTENT_STABILITY: &str = "stability";
pub const INTENT_ROUTE_POLICY: &str = "route-policy";
pub const INTENT_NOTICE_MUTES: &str = "notice-mutes";

/// The format this build writes. A newer number in the file is kept on
/// rewrite, together with the keys that came with it.
pub const USER_SETTINGS_FORMAT: u64 = 1;

/// Far above any real file; a bigger one is not ours and is not read whole.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// A write holds the lock for milliseconds; waiting longer means a writer is
/// stuck, and the caller reports that rather than hanging a UI.
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_RETRY: Duration = Duration::from_millis(15);
/// A lock this old was left by a process that died mid-write.
const LOCK_STALE: Duration = Duration::from_secs(10);

const KEY_FORMAT: &str = "format";
const KEY_RULES_FOLDER: &str = "rules-folder";
const KEY_RULES_FILES: &str = "rules-files";
const KEY_SELECTED_SET: &str = "selected-set";
const KEY_SERVICE_INTENT: &str = "service-intent";
const KEY_PRIMARY: &str = "primary";
const KEY_SECONDARY: &str = "secondary";

static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The user's bound rules files: where their rules are written. `""` is none.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RulesFiles {
    pub primary: String,
    pub secondary: String,
    /// Keys a newer build added here, written back unchanged.
    pub other: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserSettings {
    /// The format the file declared.
    pub format: u64,
    /// The folder the user keeps their rule sets in; `""` is none.
    pub rules_folder: String,
    pub rules_files: RulesFiles,
    /// `<source>:<label>` of the chosen rule set (`user:` or `bundled:`).
    pub selected_set: String,
    /// What the user decided the service-owned settings should be.
    pub service_intent: Map<String, Value>,
    /// Top-level keys this build does not know, written back unchanged.
    pub other: Map<String, Value>,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            format: USER_SETTINGS_FORMAT,
            rules_folder: String::new(),
            rules_files: RulesFiles::default(),
            selected_set: String::new(),
            service_intent: Map::new(),
            other: Map::new(),
        }
    }
}

/// A path as the file stores it: `/` separators on every OS, so two clients
/// spell one folder alike (Windows accepts `/`), and no trailing separator
/// except on a root (`/`, `C:/`).
pub fn portable_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return if path.is_empty() {
            path
        } else {
            "/".to_string()
        };
    }
    if trimmed.len() == 2 && trimmed.ends_with(':') && path.len() > 2 {
        return format!("{trimmed}/");
    }
    trimmed.to_string()
}

impl UserSettings {
    /// Written by a build newer than this one: known keys are read, the rest
    /// is carried.
    pub fn is_newer_format(&self) -> bool {
        self.format > USER_SETTINGS_FORMAT
    }

    pub fn set_rules_folder(&mut self, folder: &str) {
        self.rules_folder = portable_path(folder);
    }

    pub fn set_primary_file(&mut self, path: &str) {
        self.rules_files.primary = portable_path(path);
    }

    pub fn set_secondary_file(&mut self, path: &str) {
        self.rules_files.secondary = portable_path(path);
    }

    /// Takes into `self` — the file as it is now — every known key `mine`
    /// changed relative to `base`, the version `mine` started from. A key
    /// `mine` left alone keeps whatever another client wrote meanwhile.
    /// Returns whether anything changed.
    pub fn adopt_changes(&mut self, base: &UserSettings, mine: &UserSettings) -> bool {
        fn adopt<T: PartialEq + Clone>(slot: &mut T, base: &T, mine: &T, changed: &mut bool) {
            if mine != base && *slot != *mine {
                *slot = mine.clone();
                *changed = true;
            }
        }
        let mut changed = false;
        adopt(
            &mut self.rules_folder,
            &base.rules_folder,
            &mine.rules_folder,
            &mut changed,
        );
        adopt(
            &mut self.rules_files.primary,
            &base.rules_files.primary,
            &mine.rules_files.primary,
            &mut changed,
        );
        adopt(
            &mut self.rules_files.secondary,
            &base.rules_files.secondary,
            &mine.rules_files.secondary,
            &mut changed,
        );
        adopt(
            &mut self.selected_set,
            &base.selected_set,
            &mine.selected_set,
            &mut changed,
        );
        changed |= adopt_map(
            &mut self.service_intent,
            &base.service_intent,
            &mine.service_intent,
            2,
        );
        changed
    }

    /// The recorded intent of one namespace (`stability`, `route-policy`,
    /// `notice-mutes`).
    pub fn intent(&self, namespace: &str) -> Option<&Value> {
        self.service_intent.get(namespace)
    }

    /// Merges `values` into object namespace `namespace`; a `null` value drops
    /// its key, and a namespace left empty is dropped. Other namespaces and the
    /// other keys of this one are left as they are.
    pub fn merge_intent(&mut self, namespace: &str, values: &Map<String, Value>) {
        let mut object = match self.service_intent.remove(namespace) {
            Some(Value::Object(object)) => object,
            _ => Map::new(),
        };
        for (key, value) in values {
            if value.is_null() {
                object.remove(key);
            } else {
                object.insert(key.clone(), value.clone());
            }
        }
        if !object.is_empty() {
            self.service_intent
                .insert(namespace.to_owned(), Value::Object(object));
        }
    }

    /// Replaces namespace `namespace` whole; `null` drops it.
    pub fn set_intent(&mut self, namespace: &str, value: Value) {
        if value.is_null() {
            self.service_intent.remove(namespace);
        } else {
            self.service_intent.insert(namespace.to_owned(), value);
        }
    }
}

/// A three-way merge of maps: every key `mine` changed against `base` is taken
/// into `slot`, a key `mine` dropped is dropped, and the rest of `slot` — what
/// another client wrote — stays. Values that are objects on all sides are
/// merged the same way down to `depth` levels, so two clients recording
/// different keys of one intent namespace do not erase each other.
fn adopt_map(
    slot: &mut Map<String, Value>,
    base: &Map<String, Value>,
    mine: &Map<String, Value>,
    depth: u32,
) -> bool {
    let mut changed = false;
    let keys: BTreeSet<String> = base.keys().chain(mine.keys()).cloned().collect();
    for key in keys {
        let (before, after) = (base.get(&key), mine.get(&key));
        if before == after {
            continue;
        }
        if let (Some(Value::Object(before)), Some(Value::Object(after))) = (before, after) {
            if depth > 1 {
                if let Some(Value::Object(current)) = slot.get_mut(&key) {
                    changed |= adopt_map(current, before, after, depth - 1);
                    continue;
                }
            }
        }
        match after {
            None => changed |= slot.remove(&key).is_some(),
            Some(after) => {
                if slot.get(&key) != Some(after) {
                    slot.insert(key, after.clone());
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Reads the file's text. A known key of the wrong type makes the whole file
/// unreadable rather than silently dropping the value: what the caller cannot
/// read it must not overwrite.
pub fn parse_user_settings(text: &str) -> Result<UserSettings, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut object = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return Err("the top level is not a JSON object".to_string()),
        Err(error) => return Err(error.to_string()),
    };
    let format = match object.remove(KEY_FORMAT) {
        None | Some(Value::Null) => USER_SETTINGS_FORMAT,
        Some(value) => value
            .as_u64()
            .filter(|format| *format >= 1)
            .ok_or_else(|| wrong_type(KEY_FORMAT, "a positive whole number"))?,
    };
    let rules_folder = take_string(&mut object, KEY_RULES_FOLDER)?;
    let selected_set = take_string(&mut object, KEY_SELECTED_SET)?;
    let rules_files = match object.remove(KEY_RULES_FILES) {
        None | Some(Value::Null) => RulesFiles::default(),
        Some(Value::Object(mut files)) => {
            let nested = |error: String| format!("{KEY_RULES_FILES}: {error}");
            RulesFiles {
                primary: take_string(&mut files, KEY_PRIMARY).map_err(nested)?,
                secondary: take_string(&mut files, KEY_SECONDARY).map_err(nested)?,
                other: files,
            }
        }
        Some(_) => return Err(wrong_type(KEY_RULES_FILES, "an object")),
    };
    let service_intent = match object.remove(KEY_SERVICE_INTENT) {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(intent)) => intent,
        Some(_) => return Err(wrong_type(KEY_SERVICE_INTENT, "an object")),
    };
    Ok(UserSettings {
        format,
        rules_folder,
        rules_files,
        selected_set,
        service_intent,
        other: object,
    })
}

/// The file's text: pretty-printed for a human editor, known keys first.
pub fn format_user_settings(settings: &UserSettings) -> serde_json::Result<String> {
    let mut object = Map::new();
    object.insert(
        KEY_FORMAT.to_string(),
        Value::from(settings.format.max(USER_SETTINGS_FORMAT)),
    );
    object.insert(
        KEY_RULES_FOLDER.to_string(),
        Value::String(settings.rules_folder.clone()),
    );
    let mut files = Map::new();
    files.insert(
        KEY_PRIMARY.to_string(),
        Value::String(settings.rules_files.primary.clone()),
    );
    files.insert(
        KEY_SECONDARY.to_string(),
        Value::String(settings.rules_files.secondary.clone()),
    );
    for (key, value) in &settings.rules_files.other {
        files.entry(key.clone()).or_insert_with(|| value.clone());
    }
    object.insert(KEY_RULES_FILES.to_string(), Value::Object(files));
    object.insert(
        KEY_SELECTED_SET.to_string(),
        Value::String(settings.selected_set.clone()),
    );
    object.insert(
        KEY_SERVICE_INTENT.to_string(),
        Value::Object(settings.service_intent.clone()),
    );
    // A known key wins over a same-named entry a caller put among the others.
    for (key, value) in &settings.other {
        object.entry(key.clone()).or_insert_with(|| value.clone());
    }
    let mut text = serde_json::to_string_pretty(&Value::Object(object))?;
    text.push('\n');
    Ok(text)
}

fn take_string(object: &mut Map<String, Value>, key: &str) -> Result<String, String> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(wrong_type(key, "a string")),
    }
}

fn wrong_type(key: &str, expected: &str) -> String {
    format!("`{key}` is not {expected}")
}

/// What a power cut between rename and data flush leaves: empty or zeroes.
fn is_husk(text: &str) -> bool {
    text.trim_matches(|c: char| c.is_whitespace() || c == '\0')
        .is_empty()
}

#[derive(Debug)]
pub enum UserSettingsError {
    /// No per-user directory exists or could be created.
    NoRoot,
    Io {
        path: PathBuf,
        source: io::Error,
    },
    /// The file is there but is not settings this build can read. It is left
    /// as it is.
    Damaged {
        path: PathBuf,
        reason: String,
    },
    /// Another client held the lock for longer than a write takes.
    Busy {
        path: PathBuf,
    },
}

impl UserSettingsError {
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::NoRoot => None,
            Self::Io { path, .. } | Self::Damaged { path, .. } | Self::Busy { path } => Some(path),
        }
    }
}

impl fmt::Display for UserSettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoot => f.write_str("no per-user settings directory is available"),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Damaged { path, reason } => {
                write!(f, "{} cannot be read: {reason}", path.display())
            }
            Self::Busy { path } => write!(f, "{} is held by another writer", path.display()),
        }
    }
}

impl std::error::Error for UserSettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// What [`UserSettingsStore::load_or_seed`] found.
#[derive(Clone, Debug, PartialEq)]
pub struct SeedOutcome {
    pub settings: UserSettings,
    /// The file was absent and was written from the seed.
    pub seeded: bool,
}

enum FileState {
    Absent,
    Husk,
    Settings(UserSettings),
}

pub struct UserSettingsStore {
    path: PathBuf,
}

impl UserSettingsStore {
    /// The file in the per-user root: the first root that already holds one,
    /// else the first that can be created — so two clients whose first choice
    /// differed for a moment still meet at the same file.
    pub fn open() -> Result<Self, UserSettingsError> {
        let roots = crate::user_paths::user_app_roots();
        if let Some(root) = roots
            .iter()
            .find(|root| root.join(USER_SETTINGS_FILE_NAME).is_file())
        {
            return Ok(Self::at(root.join(USER_SETTINGS_FILE_NAME)));
        }
        let mut last_error = UserSettingsError::NoRoot;
        for root in roots {
            if let Err(error) = fs::create_dir_all(&root) {
                last_error = UserSettingsError::Io {
                    path: root,
                    source: error,
                };
                continue;
            }
            return Ok(Self::at(root.join(USER_SETTINGS_FILE_NAME)));
        }
        Err(last_error)
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `None` when there is no file yet.
    pub fn load(&self) -> Result<Option<UserSettings>, UserSettingsError> {
        match self.read_file(&self.path)? {
            FileState::Settings(settings) => Ok(Some(settings)),
            FileState::Absent => Ok(None),
            // A deliberately deleted file is not brought back from the backup;
            // only a gutted one is.
            FileState::Husk => match self.read_file(&self.backup_path()) {
                Ok(FileState::Settings(settings)) => Ok(Some(settings)),
                _ => Ok(None),
            },
        }
    }

    /// The file, or — when there is none yet — `seed()` written as the first
    /// one. Checked again under the lock, so a client that wrote the file a
    /// moment earlier is never overwritten by a seed.
    pub fn load_or_seed<F>(&self, seed: F) -> Result<SeedOutcome, UserSettingsError>
    where
        F: FnOnce() -> UserSettings,
    {
        if let Some(settings) = self.load()? {
            return Ok(SeedOutcome {
                settings,
                seeded: false,
            });
        }
        let _lock = self.lock()?;
        if let Some(settings) = self.load()? {
            return Ok(SeedOutcome {
                settings,
                seeded: false,
            });
        }
        let settings = seed();
        self.write(&settings)?;
        Ok(SeedOutcome {
            settings,
            seeded: true,
        })
    }

    /// Re-reads the file under the lock, applies `change`, and writes the
    /// result only if it differs. `change` should touch only the keys its
    /// caller means to set; the rest is what other clients wrote. Returns the
    /// settings as they now stand.
    pub fn update<F>(&self, change: F) -> Result<UserSettings, UserSettingsError>
    where
        F: FnOnce(&mut UserSettings),
    {
        let _lock = self.lock()?;
        let current = self.load()?.unwrap_or_default();
        let mut next = current.clone();
        change(&mut next);
        if next != current {
            self.write(&next)?;
        }
        Ok(next)
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(OsString::from)
            .unwrap_or_default();
        name.push(suffix);
        self.path.with_file_name(name)
    }

    fn backup_path(&self) -> PathBuf {
        self.sibling(".bak")
    }

    fn read_file(&self, path: &Path) -> Result<FileState, UserSettingsError> {
        let io_error = |source: io::Error| UserSettingsError::Io {
            path: path.to_path_buf(),
            source,
        };
        let size = match fs::metadata(path) {
            Ok(meta) => meta.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileState::Absent),
            Err(error) => return Err(io_error(error)),
        };
        if size > MAX_FILE_BYTES {
            return Err(UserSettingsError::Damaged {
                path: path.to_path_buf(),
                reason: format!("larger than {MAX_FILE_BYTES} bytes"),
            });
        }
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileState::Absent),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                return Err(UserSettingsError::Damaged {
                    path: path.to_path_buf(),
                    reason: "not UTF-8 text".to_string(),
                });
            }
            Err(error) => return Err(io_error(error)),
        };
        if is_husk(&text) {
            return Ok(FileState::Husk);
        }
        parse_user_settings(&text)
            .map(FileState::Settings)
            .map_err(|reason| UserSettingsError::Damaged {
                path: path.to_path_buf(),
                reason,
            })
    }

    /// Exclusive creation of `<file>.lock` is the lock; dropping the guard
    /// removes it.
    fn lock(&self) -> Result<LockGuard, UserSettingsError> {
        let path = self.sibling(".lock");
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| UserSettingsError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let started = Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    // The holder's pid, for whoever finds a lock left behind.
                    let _ = write!(file, "{}", std::process::id());
                    return Ok(LockGuard { path });
                }
                Err(error) => {
                    let held = error.kind() == io::ErrorKind::AlreadyExists;
                    if held && lock_is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    // Windows answers "access denied" while a just-released
                    // lock is still being deleted, so that is waited out too.
                    let contended = held || error.kind() == io::ErrorKind::PermissionDenied;
                    if !contended || started.elapsed() >= LOCK_WAIT {
                        return Err(if held {
                            UserSettingsError::Busy { path }
                        } else {
                            UserSettingsError::Io {
                                path,
                                source: error,
                            }
                        });
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
            }
        }
    }

    /// Stages the new text beside the file, refreshes the backup from the
    /// outgoing file, and renames the staged file into place. The file itself
    /// is never absent in between, so a reader without the lock sees the old
    /// or the new settings, never "no settings".
    fn write(&self, settings: &UserSettings) -> Result<(), UserSettingsError> {
        let text = format_user_settings(settings).map_err(|error| UserSettingsError::Io {
            path: self.path.clone(),
            source: io::Error::other(error),
        })?;
        let staged = self.sibling(&format!(
            ".{}-{}.tmp",
            std::process::id(),
            WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        write_synced(&staged, text.as_bytes()).map_err(|source| UserSettingsError::Io {
            path: staged.clone(),
            source,
        })?;
        self.refresh_backup();
        fs::rename(&staged, &self.path).map_err(|source| {
            let _ = fs::remove_file(&staged);
            UserSettingsError::Io {
                path: self.path.clone(),
                source,
            }
        })
    }

    /// Best effort, and only from a file that reads as settings: a gutted
    /// file must never replace a good backup.
    fn refresh_backup(&self) {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return;
        };
        if is_husk(&text) || parse_user_settings(&text).is_err() {
            return;
        }
        let staged = self.sibling(".bak.tmp");
        if write_synced(&staged, text.as_bytes()).is_err()
            || fs::rename(&staged, self.backup_path()).is_err()
        {
            let _ = fs::remove_file(&staged);
        }
    }
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age >= LOCK_STALE)
}

/// Creates `path` fresh (owner-only on Unix: it names the user's folders and
/// files) and flushes it, removing it again on any failure.
fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = options.open(path).and_then(|mut file| {
        file.write_all(bytes)?;
        // A rename survives a process kill but not a power cut: the journal
        // can commit it before the data blocks.
        file.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> UserSettings {
        UserSettings {
            rules_folder: "/home/user/rule-sets".to_string(),
            rules_files: RulesFiles {
                primary: "/home/user/rule-sets/home/rules_primary.txt".to_string(),
                secondary: "/home/user/rule-sets/home/rules_secondary.txt".to_string(),
                other: Map::new(),
            },
            selected_set: "user:home".to_string(),
            service_intent: json!({"stability": {"verbose-logging": true}})
                .as_object()
                .cloned()
                .unwrap_or_default(),
            ..UserSettings::default()
        }
    }

    fn store_in(dir: &tempfile::TempDir) -> UserSettingsStore {
        UserSettingsStore::at(dir.path().join(USER_SETTINGS_FILE_NAME))
    }

    fn rewritten(settings: &UserSettings) -> Value {
        let text = format_user_settings(settings).expect("format");
        serde_json::from_str(&text).expect("json")
    }

    #[test]
    fn a_round_trip_keeps_every_field() {
        let settings = sample();
        let text = format_user_settings(&settings).expect("format");
        assert_eq!(parse_user_settings(&text), Ok(settings));
    }

    #[test]
    fn the_file_is_the_documented_shape() {
        let text = format_user_settings(&sample()).expect("format");
        let value: Value = serde_json::from_str(&text).expect("json");
        assert_eq!(value["format"], json!(1));
        assert_eq!(value["rules-folder"], json!("/home/user/rule-sets"));
        assert_eq!(
            value["rules-files"]["primary"],
            json!("/home/user/rule-sets/home/rules_primary.txt")
        );
        assert_eq!(value["selected-set"], json!("user:home"));
        assert_eq!(
            value["service-intent"]["stability"]["verbose-logging"],
            json!(true)
        );
    }

    #[test]
    fn paths_are_stored_with_forward_slashes() {
        for (given, stored) in [
            ("C:\\Users\\u\\Sets\\", "C:/Users/u/Sets"),
            ("/home/u/sets/", "/home/u/sets"),
            ("/", "/"),
            ("C:\\", "C:/"),
            ("C:", "C:"),
            ("", ""),
            (
                "D:/Sets/home/rules_primary.txt",
                "D:/Sets/home/rules_primary.txt",
            ),
            ("\\\\server\\share\\sets", "//server/share/sets"),
        ] {
            assert_eq!(portable_path(given), stored, "{given}");
        }
        let mut settings = UserSettings::default();
        settings.set_rules_folder("C:\\Sets\\");
        settings.set_secondary_file("C:\\Sets\\a\\rules_secondary.txt");
        assert_eq!(settings.rules_folder, "C:/Sets");
        assert_eq!(
            settings.rules_files.secondary,
            "C:/Sets/a/rules_secondary.txt"
        );
    }

    #[test]
    fn missing_keys_read_as_empty() {
        assert_eq!(parse_user_settings("{}"), Ok(UserSettings::default()));
        let parsed = parse_user_settings(r#"{"format": 1, "rules-folder": null}"#);
        assert_eq!(parsed, Ok(UserSettings::default()));
    }

    #[test]
    fn unknown_keys_survive_a_rewrite() {
        let text = r#"{
            "format": 1,
            "rules-folder": "/r",
            "theme-of-tomorrow": {"a": [1, 2]},
            "rules-files": {"primary": "/r/p.txt", "tertiary": "/r/t.txt"}
        }"#;
        let mut settings = parse_user_settings(text).expect("parse");
        settings.rules_folder = "/elsewhere".to_string();
        let written = rewritten(&settings);
        assert_eq!(written["theme-of-tomorrow"], json!({"a": [1, 2]}));
        assert_eq!(written["rules-files"]["tertiary"], json!("/r/t.txt"));
        assert_eq!(written["rules-folder"], json!("/elsewhere"));
    }

    #[test]
    fn a_newer_format_reads_what_is_known_and_keeps_its_number() {
        let text = r#"{"format": 3, "selected-set": "bundled:ru_basic", "new-key": 7}"#;
        let settings = parse_user_settings(text).expect("parse");
        assert!(settings.is_newer_format());
        assert_eq!(settings.selected_set, "bundled:ru_basic");
        let written = rewritten(&settings);
        assert_eq!(written["format"], json!(3));
        assert_eq!(written["new-key"], json!(7));
    }

    #[test]
    fn damaged_text_is_an_error_not_defaults() {
        for text in [
            "{not json",
            "[]",
            r#"{"rules-folder": 5}"#,
            r#"{"rules-files": "x"}"#,
            r#"{"rules-files": {"primary": 1}}"#,
            r#"{"service-intent": "{}"}"#,
            r#"{"format": "one"}"#,
            r#"{"format": 0}"#,
        ] {
            assert!(parse_user_settings(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_byte_order_mark_is_tolerated() {
        let text = "\u{feff}{\"selected-set\": \"user:a\"}";
        let parsed = parse_user_settings(text).expect("parse");
        assert_eq!(parsed.selected_set, "user:a");
    }

    #[test]
    fn adopting_changes_keeps_the_keys_another_writer_set() {
        let base = UserSettings::default();
        // The terminal set the folder; the window, starting from `base`,
        // changed only the selected set.
        let mut on_disk = UserSettings {
            rules_folder: "/terminal".to_string(),
            ..base.clone()
        };
        let mine = UserSettings {
            selected_set: "user:window".to_string(),
            ..base.clone()
        };
        assert!(on_disk.adopt_changes(&base, &mine));
        assert_eq!(on_disk.rules_folder, "/terminal");
        assert_eq!(on_disk.selected_set, "user:window");
        assert!(!on_disk.adopt_changes(&base, &mine), "already adopted");
        assert!(!on_disk.clone().adopt_changes(&base, &base));
    }

    #[test]
    fn intent_namespaces_merge_key_by_key() {
        let base = UserSettings {
            service_intent: json!({
                "stability": { "verbose-logging": true, "fake-ip-enabled": true },
                "route-policy": { "mode": "prefer-primary" }
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
            ..UserSettings::default()
        };
        // The terminal recorded another route-policy key and a mute list.
        let mut on_disk = base.clone();
        on_disk.merge_intent(
            INTENT_ROUTE_POLICY,
            json!({ "kill-switch-enabled": true })
                .as_object()
                .expect("object"),
        );
        on_disk.set_intent(INTENT_NOTICE_MUTES, json!([{ "scope": { "kind": "all" } }]));
        // The window changed one stability key and dropped another.
        let mut mine = base.clone();
        mine.merge_intent(
            INTENT_STABILITY,
            json!({ "verbose-logging": false, "fake-ip-enabled": null })
                .as_object()
                .expect("object"),
        );

        assert!(on_disk.adopt_changes(&base, &mine));
        assert_eq!(
            Value::Object(on_disk.service_intent.clone()),
            json!({
                "stability": { "verbose-logging": false },
                "route-policy": { "mode": "prefer-primary", "kill-switch-enabled": true },
                "notice-mutes": [{ "scope": { "kind": "all" } }]
            })
        );
        assert!(!on_disk.adopt_changes(&base, &mine), "already adopted");
    }

    #[test]
    fn a_namespace_emptied_by_a_merge_is_dropped() {
        let mut settings = UserSettings::default();
        settings.merge_intent(
            INTENT_ROUTE_POLICY,
            json!({ "mode": "x" }).as_object().expect("o"),
        );
        settings.merge_intent(
            INTENT_ROUTE_POLICY,
            json!({ "mode": null }).as_object().expect("o"),
        );
        assert!(settings.intent(INTENT_ROUTE_POLICY).is_none());
        settings.set_intent(INTENT_NOTICE_MUTES, json!([]));
        settings.set_intent(INTENT_NOTICE_MUTES, Value::Null);
        assert!(settings.service_intent.is_empty());
    }

    #[test]
    fn an_absent_file_loads_as_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert_eq!(store_in(&dir).load().expect("load"), None);
    }

    #[test]
    fn update_writes_and_load_reads_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let written = store
            .update(|s| s.rules_folder = "/r".to_string())
            .expect("update");
        assert_eq!(written.rules_folder, "/r");
        assert_eq!(store.load().expect("load"), Some(written));
        assert!(!store.sibling(".lock").exists(), "the lock is released");
    }

    #[test]
    fn two_writers_on_different_keys_both_land() {
        let dir = tempfile::tempdir().expect("temp dir");
        let window = store_in(&dir);
        let terminal = store_in(&dir);
        window
            .update(|s| s.selected_set = "user:a".to_string())
            .expect("window");
        terminal
            .update(|s| s.rules_folder = "/r".to_string())
            .expect("terminal");
        let settings = window.load().expect("load").expect("present");
        assert_eq!(settings.selected_set, "user:a");
        assert_eq!(settings.rules_folder, "/r");
    }

    #[test]
    fn an_update_that_changes_nothing_writes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        store.update(|_| {}).expect("update");
        assert!(!store.path().exists());
    }

    #[test]
    fn a_damaged_file_is_reported_and_left_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        fs::write(store.path(), "{\"rules-folder\": ").expect("seed");
        assert!(matches!(
            store.load(),
            Err(UserSettingsError::Damaged { .. })
        ));
        assert!(matches!(
            store.update(|s| s.rules_folder = "/r".to_string()),
            Err(UserSettingsError::Damaged { .. })
        ));
        assert!(matches!(
            store.load_or_seed(UserSettings::default),
            Err(UserSettingsError::Damaged { .. })
        ));
        assert_eq!(
            fs::read_to_string(store.path()).expect("read"),
            "{\"rules-folder\": "
        );
    }

    #[test]
    fn a_gutted_file_falls_back_to_the_backup() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        store
            .update(|s| s.rules_folder = "/first".to_string())
            .expect("first");
        store
            .update(|s| s.rules_folder = "/second".to_string())
            .expect("second");
        fs::write(store.path(), "\0\0\0").expect("gut");
        let recovered = store.load().expect("load").expect("from backup");
        assert_eq!(recovered.rules_folder, "/first");
    }

    #[test]
    fn a_seed_is_written_only_when_there_is_no_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let first = store.load_or_seed(sample).expect("seed");
        assert!(first.seeded);
        assert_eq!(first.settings, sample());
        let second = store.load_or_seed(UserSettings::default).expect("existing");
        assert!(!second.seeded);
        assert_eq!(second.settings, sample());
    }

    #[test]
    fn a_stale_lock_does_not_block_forever() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let lock = store.sibling(".lock");
        fs::write(&lock, "999999").expect("plant lock");
        let old = SystemTime::now() - LOCK_STALE - Duration::from_secs(1);
        fs::File::options()
            .write(true)
            .open(&lock)
            .and_then(|file| file.set_modified(old))
            .expect("age lock");
        store
            .update(|s| s.selected_set = "user:a".to_string())
            .expect("update through a stale lock");
    }

    #[test]
    fn a_live_lock_reports_busy() {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = store_in(&dir);
        let _held = store.lock().expect("first holder");
        assert!(matches!(
            store.update(|s| s.selected_set = "user:a".to_string()),
            Err(UserSettingsError::Busy { .. })
        ));
    }
}

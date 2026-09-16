//! Where preferences live on disk, and the session that owns the handle.
//!
//! A read that fails opens the session READ-ONLY rather than handing back
//! defaults: overwriting a file we could not parse is how a user loses
//! settings they never changed.

use super::*;

/// What a session got when it opened the preferences store.
///
/// The distinction that matters is whether the store may be WRITTEN. `load`
/// already falls back to the `.bak` copy, so a read that still fails means
/// neither file could be read — a lock held by a scanner or a profile sync,
/// not an empty file. Writing through such a store replaces settings that were
/// merely unavailable with defaults, and the user meets the first-run wizard
/// and the EULA again.
pub enum SessionPreferences {
    /// The file was read; write-through is safe.
    Writable {
        store: UiPreferencesStore,
        preferences: UiPreferences,
    },
    /// The file could not be read. Defaults are used for THIS session and
    /// nothing is written back, so the file survives to be read next time.
    ReadOnly {
        preferences: UiPreferences,
        error: io::Error,
    },
}

/// Open `store` for a session: read it, and keep the write handle only if the
/// read worked. Both shells (GUI and launcher) go through this so the rule
/// cannot be half-applied in one of them.
pub fn open_for_session(store: UiPreferencesStore) -> SessionPreferences {
    match store.load() {
        Ok(preferences) => SessionPreferences::Writable { store, preferences },
        Err(error) => SessionPreferences::ReadOnly {
            preferences: UiPreferences::default(),
            error,
        },
    }
}

pub struct UiPreferencesStore {
    pub(super) path: PathBuf,
    pub(super) legacy_paths: Vec<PathBuf>,
    pub(super) is_profile_persistent: bool,
}

impl UiPreferencesStore {
    pub fn managed_local() -> io::Result<Self> {
        let storage = resolve_storage_location()?;
        let legacy_paths = legacy_preference_paths(storage.root.clone());
        Ok(Self {
            path: storage.root.join(STABLE_PREFERENCES_FILE_NAME),
            legacy_paths,
            is_profile_persistent: storage.is_profile_persistent,
        })
    }

    pub fn for_path(path: PathBuf) -> Self {
        Self {
            path,
            legacy_paths: Vec::new(),
            is_profile_persistent: true,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_profile_persistent(&self) -> bool {
        self.is_profile_persistent
    }

    pub fn load(&self) -> io::Result<UiPreferences> {
        self.try_migrate_legacy_file()?;
        match fs::read_to_string(&self.path) {
            Ok(content) if has_preference_lines(&content) => {
                let parsed = parse_preferences(&content);
                warn_if_written_by_a_newer_build(&parsed);
                Ok(without_expired_parked_intents(parsed, unix_now_ms()))
            }
            // The file exists but holds no `key=value` line: a dirty-shutdown
            // artifact (power cut after the rename committed but before the
            // data flushed leaves an empty or NUL-filled file). Silently
            // starting with defaults here is what cost a user their EULA
            // acceptance and every local setting — recover from the backup.
            Ok(_) => Ok(self.load_backup().unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(self.load_backup().unwrap_or_default())
            }
            Err(error) => match self.load_backup() {
                Some(preferences) => Ok(preferences),
                None => Err(error),
            },
        }
    }

    /// The previous good file, kept by [`Self::save`]. `None` when it is
    /// absent or just as gutted as the primary.
    fn load_backup(&self) -> Option<UiPreferences> {
        let content = fs::read_to_string(self.backup_path()).ok()?;
        if !has_preference_lines(&content) {
            return None;
        }
        let parsed = parse_preferences(&content);
        warn_if_written_by_a_newer_build(&parsed);
        Some(without_expired_parked_intents(parsed, unix_now_ms()))
    }

    fn backup_path(&self) -> PathBuf {
        self.path.with_extension("bak")
    }

    pub fn save(&self, preferences: &UiPreferences) -> io::Result<()> {
        self.try_migrate_legacy_file()?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write-then-rename: `fs::rename` replaces the destination in one step
        // on every supported OS, so a process killed at any point leaves either
        // the old file or the new one — never a truncated one. Deleting the
        // destination first would open exactly that window, and it buys
        // nothing.
        // The scratch name is unique per writer. Both the GUI and the tray save
        // preferences, and a single `<path>.tmp` shared between them lets the
        // second writer truncate the first one's file mid-write — the first
        // then renames the other's half-written payload into place, defeating
        // the very swap this dance exists for.
        let temporary_path = self.path.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            SAVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let payload = format_preferences(preferences);
        {
            use std::io::Write;
            let mut file = fs::File::create(&temporary_path)?;
            file.write_all(payload.as_bytes())?;
            // The rename survives a process kill, but not a power cut: the
            // journal can commit the rename while the data blocks are still
            // in the write-behind cache, and recovery then produces an empty
            // file under the final name. Flush the data before the swap.
            file.sync_all()?;
        }
        // Keep the outgoing file as the fallback `load` recovers from — but
        // never let a gutted primary overwrite a good backup.
        if let Ok(current) = fs::read_to_string(&self.path) {
            if has_preference_lines(&current) {
                let _ = fs::write(self.backup_path(), current);
            }
        }
        let renamed = fs::rename(&temporary_path, &self.path);
        if renamed.is_err() {
            // Nothing else will ever look at this name again, so a failed swap
            // must not leave it behind.
            let _ = fs::remove_file(&temporary_path);
        }
        renamed
    }

    fn try_migrate_legacy_file(&self) -> io::Result<()> {
        if self.path.exists() {
            return Ok(());
        }

        for legacy_path in &self.legacy_paths {
            if !legacy_path.exists() {
                continue;
            }

            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }

            match fs::rename(legacy_path, &self.path) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    // Cross-volume move fallback.
                    fs::copy(legacy_path, &self.path)?;
                    fs::remove_file(legacy_path)?;
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

struct StorageLocation {
    root: PathBuf,
    is_profile_persistent: bool,
}

fn resolve_storage_location() -> io::Result<StorageLocation> {
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    if let Some(app_data) = env::var_os("APPDATA") {
        candidates.push((PathBuf::from(app_data), true));
    }
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        candidates.push((PathBuf::from(local_app_data), true));
    }
    candidates.push((env::temp_dir(), false));

    let mut last_error = None;
    for (base, is_profile_persistent) in candidates {
        let managed_path = base.join(MANAGED_ROOT_FOLDER).join(MANAGED_SUBFOLDER);
        match fs::create_dir_all(&managed_path) {
            Ok(_) => {
                return Ok(StorageLocation {
                    root: managed_path,
                    is_profile_persistent,
                });
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        Err(error)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No candidate path is available for managed UI storage.",
        ))
    }
}

fn legacy_preference_paths(root: PathBuf) -> Vec<PathBuf> {
    let mut paths = LEGACY_PREFERENCES_FILE_NAMES
        .iter()
        .map(|name| root.join(name))
        .collect::<Vec<_>>();
    let temp_root = env::temp_dir()
        .join(MANAGED_ROOT_FOLDER)
        .join(MANAGED_SUBFOLDER);
    paths.extend(
        LEGACY_PREFERENCES_FILE_NAMES
            .iter()
            .map(|name| temp_root.join(name)),
    );
    paths.push(temp_root.join(STABLE_PREFERENCES_FILE_NAME));
    paths
}

/// Whether `content` carries at least one `key=value` line — what separates a
/// real preferences file (ours always leads with `schema_version=`, a legacy
/// one has its settings) from the empty or NUL-filled husk a dirty shutdown
/// leaves behind.
fn has_preference_lines(content: &str) -> bool {
    content.lines().any(|raw| {
        let line = raw.trim();
        !line.is_empty() && !line.starts_with('#') && line.contains('=')
    })
}

/// Says on stderr that the file came from a newer build, once per load.
///
/// Nothing else can be done about it and nothing needs to be: the unknown keys
/// ride along in [`ForwardCompat`] and are written back, so the file is not
/// downgraded. The line is here for a support archive, not for a decision.
fn warn_if_written_by_a_newer_build(preferences: &UiPreferences) {
    if let Some(v) = preferences.forward_compat.newer_schema_version {
        let carried = preferences.forward_compat.unknown_lines.len();
        eprintln!(
            "nrr: ui-preferences file declares schema_version={v}; this build supports up to \
             {CURRENT_UI_PREFS_SCHEMA_VERSION}. Known fields are loaded, {carried} unknown \
             setting(s) are carried through unchanged."
        );
    }
}

/// The `schema_version` the file declares, if any.
///
/// Absent means a legacy v0 file — every known field loads as-is. Read in its
/// own pass because the unknown-key capture in [`parse_preferences`] has to
/// know the verdict before it reaches the first unknown key, and a hand-edited
/// file may not lead with the version the way ours do.
pub(super) fn declared_schema_version(content: &str) -> Option<u32> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("schema_version=") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

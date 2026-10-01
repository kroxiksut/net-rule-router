//! Where preferences live on disk, and the session that owns the handle.
//!
//! A read that fails opens the session READ-ONLY rather than handing back
//! defaults: overwriting a file we could not parse is how a user loses
//! settings they never changed.

use super::*;
use std::time::{Duration, SystemTime};

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
}

impl UiPreferencesStore {
    pub fn managed_local() -> io::Result<Self> {
        Ok(Self {
            path: resolve_storage_root()?.join(STABLE_PREFERENCES_FILE_NAME),
        })
    }

    pub fn for_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> io::Result<UiPreferences> {
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
        self.sweep_orphaned_tmp_files();
        let staged = self.stage(preferences)?;
        self.retire_primary_to_backup();
        self.commit(&staged)
    }

    /// Writes the new payload under a scratch name and flushes it. The name is
    /// unique per writer: the GUI and the tray both save, and a shared
    /// `<path>.tmp` lets one truncate the other's file mid-write.
    pub(super) fn stage(&self, preferences: &UiPreferences) -> io::Result<PathBuf> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary_path = self.path.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            SAVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        // Written as one closure so any failure past file creation removes the
        // scratch file instead of orphaning it: `?` alone would return before
        // cleanup ran.
        let write = (|| -> io::Result<()> {
            let mut file = fs::File::create(&temporary_path)?;
            #[cfg(test)]
            if FORCE_NEXT_STAGE_WRITE_FAILURE.with(|flag| flag.replace(false)) {
                return Err(io::Error::other("forced for a test"));
            }
            file.write_all(format_preferences(preferences).as_bytes())?;
            // A rename survives a process kill but not a power cut: the journal
            // can commit it before the data blocks, leaving an empty file.
            file.sync_all()
        })();
        match write {
            Ok(()) => Ok(temporary_path),
            Err(error) => {
                let _ = fs::remove_file(&temporary_path);
                Err(error)
            }
        }
    }

    /// Deletes this store's own `.tmp` scratch files once they are old enough
    /// that no writer still owns them: a write error in [`Self::stage`] before
    /// this cleanup existed, or a crash between staging and [`Self::commit`],
    /// left them here forever. The one-minute floor is well past any save's
    /// write-and-rename, so a concurrent writer's own in-flight file is never
    /// touched. Best effort: a failed listing or delete does not fail the save.
    fn sweep_orphaned_tmp_files(&self) {
        let (Some(parent), Some(stem)) = (self.path.parent(), self.path.file_stem()) else {
            return;
        };
        let Some(stem) = stem.to_str() else {
            return;
        };
        let prefix = format!("{stem}.");
        let Ok(entries) = fs::read_dir(parent) else {
            return;
        };
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
                continue;
            }
            let is_old = entry
                .metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|modified| modified < cutoff);
            if is_old {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    /// Moves the outgoing primary over the backup in one rename, so the backup
    /// is always a whole file. A husk primary is left alone: it must never
    /// replace a good backup.
    pub(super) fn retire_primary_to_backup(&self) {
        let whole = fs::read_to_string(&self.path).is_ok_and(|c| has_preference_lines(&c));
        if whole {
            // Best effort: without a backup the save still lands.
            let _ = fs::rename(&self.path, self.backup_path());
        }
    }

    /// Renames the staged file into place; `fs::rename` replaces the
    /// destination in one step on every supported OS.
    pub(super) fn commit(&self, staged: &Path) -> io::Result<()> {
        let renamed = fs::rename(staged, &self.path);
        if renamed.is_err() {
            let _ = fs::remove_file(staged);
        }
        renamed
    }
}

// Test-only fault injection: proves `stage`'s cleanup removes a scratch file
// that really exists on disk, not just one that failed to be created. Compiled
// out of every non-test build; thread-local so parallel tests cannot trip it
// for each other.
#[cfg(test)]
thread_local! {
    pub(crate) static FORCE_NEXT_STAGE_WRITE_FAILURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Where the OS wants a per-user file kept is not this crate's business — it
/// asks [`nrr_shared::user_paths`], which is also what the localization layer
/// reads, so the override directory and the settings file cannot drift apart.
fn resolve_storage_root() -> io::Result<PathBuf> {
    let mut last_error = None;
    for root in nrr_shared::user_paths::user_app_roots() {
        let managed_path = root.join(MANAGED_SUBFOLDER);
        match fs::create_dir_all(&managed_path) {
            Ok(_) => return Ok(managed_path),
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

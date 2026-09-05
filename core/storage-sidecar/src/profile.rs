//! Path resolution for the sidecar database.
//!
//! Default location is the per-user roaming AppData directory so each
//! Windows account on a shared machine sees its own comments and
//! pending state, consistent with the per-SID storage convention the
//! service-side runtime uses for rules themselves (block 16.8).
//!
//! Tests, headless drivers, and the CI runner override via
//! `NRR_SIDECAR_PATH`. The value is used verbatim, but it must be an absolute
//! path to a file: a relative one resolves against the process's working
//! directory, so the same override would name a different database depending on
//! how the app was started.
//!
//! The env-aware [`resolve_path`] is split into an env-free
//! [`resolve_path_with`] helper so tests don't have to mutate process
//! environment (which is unsafe in modern Rust and globally racy).

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{SidecarError, SidecarResult};

/// Environment variable that overrides the default sidecar path.
///
/// Tests and headless drivers set this to point at a `tempfile::NamedTempFile`
/// path; absent the override we use [`resolve_default_path`].
pub const NRR_SIDECAR_PATH_ENV: &str = "NRR_SIDECAR_PATH";

/// File name used inside the resolved directory. Kept private so callers
/// who care about location go through [`resolve_default_path`] rather
/// than reconstructing the filename themselves.
const FILE_NAME: &str = "gui_metadata.db";

/// Resolve the sidecar path, honouring the `NRR_SIDECAR_PATH` override.
///
/// Returns the override verbatim when set; otherwise delegates to
/// [`resolve_default_path`] which uses the platform's user-AppData
/// directory. The parent directory is ensured to exist as a side effect
/// so callers can pass the returned path straight to `rusqlite::Connection::open`.
pub fn resolve_path() -> SidecarResult<PathBuf> {
    resolve_path_with(env::var_os(NRR_SIDECAR_PATH_ENV), default_base())
}

/// Env-free resolver used by [`resolve_path`] and by tests that want
/// to exercise override / default behaviour without mutating process
/// environment.
///
/// `override_value` is the verbatim override from `NRR_SIDECAR_PATH`
/// (or any test substitute); `default_base_dir` is the platform's
/// user-data base directory (`%LOCALAPPDATA%` on Windows).
pub fn resolve_path_with(
    override_value: Option<OsString>,
    default_base_dir: Option<OsString>,
) -> SidecarResult<PathBuf> {
    if let Some(value) = override_value {
        let path = PathBuf::from(value);
        // Absolute only. A relative override resolves against the process's
        // working directory, so two shortcuts with different "start in" values
        // opened two different comment databases and each looked like the
        // user's — and `ensure_parent_dir` would happily create the tree for
        // both. Nothing legitimate sets this to a relative path: tests and CI
        // pass a temp-directory path.
        if !path.is_absolute() {
            return Err(SidecarError::PathResolution {
                reason: format!(
                    "{NRR_SIDECAR_PATH_ENV} must be an absolute path (got {})",
                    path.display()
                ),
            });
        }
        if path.is_dir() {
            return Err(SidecarError::PathResolution {
                reason: format!(
                    "{NRR_SIDECAR_PATH_ENV} names a directory, not a database file ({})",
                    path.display()
                ),
            });
        }
        ensure_parent_dir(&path)?;
        return Ok(path);
    }
    let base = default_base_dir.ok_or_else(|| SidecarError::PathResolution {
        reason: "no user-data directory available on this platform".into(),
    })?;
    let mut path = PathBuf::from(base);
    path.push("NetRuleRouter");
    path.push(FILE_NAME);
    ensure_parent_dir(&path)?;
    Ok(path)
}

/// Resolve the default platform path, ignoring `NRR_SIDECAR_PATH`.
///
/// Windows: `%LOCALAPPDATA%\NetRuleRouter\gui_metadata.db`.
/// Non-Windows: `$XDG_DATA_HOME/NetRuleRouter/gui_metadata.db` falling
/// back to `$HOME/.local/share/NetRuleRouter/gui_metadata.db`. The GUI
/// is Windows-first today (block 16.16) but the implementation stays
/// portable so tests on developer macOS/Linux laptops don't have to
/// override the path.
pub fn resolve_default_path() -> SidecarResult<PathBuf> {
    let path = resolve_path_with(None, default_base())?;
    Ok(adopt_legacy_roaming_sidecar(path))
}

/// Move a sidecar left behind in the ROAMING profile to the local one, once.
///
/// The database moved to `%LOCALAPPDATA%` because a WAL database must not roam.
/// What it holds, though, is the user's own typing — rule comments, parked
/// edits — and pointing at a fresh empty file would quietly lose it. So the
/// first run on the new path adopts the old file instead of ignoring it.
///
/// Every failure returns the LEGACY path rather than the new one: if the file
/// cannot be moved (the tray still has it open — Windows refuses to rename an
/// open file), keeping both processes on the old location loses nothing and the
/// next start tries again. Only the sidecars are moved with it; a missing
/// `-wal` is normal after a clean close.
fn adopt_legacy_roaming_sidecar(new_path: PathBuf) -> PathBuf {
    #[cfg(not(target_os = "windows"))]
    {
        new_path
    }
    #[cfg(target_os = "windows")]
    {
        if new_path.exists() {
            return new_path;
        }
        let Some(roaming) = env::var_os("APPDATA") else {
            return new_path;
        };
        let mut legacy = PathBuf::from(roaming);
        legacy.push("NetRuleRouter");
        legacy.push(FILE_NAME);
        if !legacy.exists() || legacy == new_path {
            return new_path;
        }
        if std::fs::rename(&legacy, &new_path).is_err() {
            return legacy;
        }
        for suffix in ["-wal", "-shm"] {
            let mut from = legacy.clone().into_os_string();
            from.push(suffix);
            let mut to = new_path.clone().into_os_string();
            to.push(suffix);
            let _ = std::fs::rename(PathBuf::from(from), PathBuf::from(to));
        }
        new_path
    }
}

/// Look up the platform default base directory (i.e. the parent of
/// `NetRuleRouter/gui_metadata.db`). Internal helper exposed for the
/// env-free resolver above.
fn default_base() -> Option<OsString> {
    #[cfg(target_os = "windows")]
    {
        // LOCAL app data, not roaming. This is a SQLite database in WAL mode,
        // and a roaming profile copies the `.db` while leaving `-wal` / `-shm`
        // behind — the file that arrives on the next machine is missing
        // committed data and looks intact. A redirected `%APPDATA%` on SMB is
        // worse still: WAL will not engage there at all, and the open is fatal,
        // so the user simply loses their comments and parked edits.
        //
        // Nothing in here wants to travel anyway: rule comments, parked edits
        // and the per-adapter external-address cache all describe THIS machine.
        env::var_os("LOCALAPPDATA").or_else(|| env::var_os("APPDATA"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
            return Some(xdg);
        }
        env::var_os("HOME").map(|home| {
            let mut p = PathBuf::from(home);
            p.push(".local");
            p.push("share");
            p.into_os_string()
        })
    }
}

/// Create the parent directory of `path` if it does not exist.
///
/// `rusqlite::Connection::open` fails on a missing parent directory;
/// callers expect the resolver to take care of that so they can treat
/// the returned path as immediately openable.
fn ensure_parent_dir(path: &Path) -> SidecarResult<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
            restrict_to_owner(parent);
        }
    }
    Ok(())
}

/// Keep a freshly created sidecar directory to its owner on Unix.
///
/// The sidecar holds the user's own rule comments and parked edits. Created
/// with the default mask it lands at `0777 & ~umask` — commonly `0755` — so on
/// a shared Linux box every local account could read another user's notes. On
/// Windows the path inherits the profile's ACL and there is nothing to do.
///
/// Best-effort by design: a filesystem that cannot express the mode (a mounted
/// share) must not stop the sidecar from opening — losing comments is the worse
/// outcome, and the directory is inside the user's own profile either way.
fn restrict_to_owner(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_value_wins_over_default() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let override_path = tmp.path().join("custom.db");
        let resolved = resolve_path_with(
            Some(override_path.clone().into_os_string()),
            Some(OsString::from("/should/not/be/used")),
        )?;
        assert_eq!(resolved, override_path);
        Ok(())
    }

    /// The database moved off the roaming profile because a WAL database must
    /// not roam. What it holds is the user's own typing, so the first run on
    /// the new path has to ADOPT the old file, not start empty beside it.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_sidecar_left_in_roaming_is_adopted_not_abandoned() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let legacy = tmp.path().join("roaming").join("NetRuleRouter");
        std::fs::create_dir_all(&legacy)?;
        let legacy_db = legacy.join(FILE_NAME);
        std::fs::write(&legacy_db, b"user comments live here")?;
        std::fs::write(legacy.join(format!("{FILE_NAME}-wal")), b"journal")?;

        let new_path = tmp
            .path()
            .join("local")
            .join("NetRuleRouter")
            .join(FILE_NAME);
        ensure_parent_dir(&new_path)?;

        // `adopt_legacy_roaming_sidecar` reads %APPDATA% itself, so point it at
        // the fixture for the length of this test.
        let previous = env::var_os("APPDATA");
        env::set_var("APPDATA", tmp.path().join("roaming"));
        let resolved = adopt_legacy_roaming_sidecar(new_path.clone());
        match previous {
            Some(v) => env::set_var("APPDATA", v),
            None => env::remove_var("APPDATA"),
        }

        assert_eq!(resolved, new_path, "the new path is what gets opened");
        assert_eq!(std::fs::read(&new_path)?, b"user comments live here");
        assert!(
            !legacy_db.exists(),
            "moved, not copied — no stale second copy"
        );
        assert!(
            new_path.with_file_name(format!("{FILE_NAME}-wal")).exists(),
            "the journal travels with the database"
        );
        Ok(())
    }

    /// A relative override resolves against the process's working directory, so
    /// the SAME setting names a different comment database depending on how the
    /// app was started — and the resolver would create the tree for each.
    #[test]
    fn a_relative_override_is_refused_rather_than_resolved_against_the_cwd() {
        match resolve_path_with(Some(OsString::from("sidecar.db")), None) {
            Err(SidecarError::PathResolution { reason }) => {
                assert!(reason.contains("absolute"), "unhelpful reason: {reason}");
            }
            Err(other) => panic!("wrong error variant: {other:?}"),
            Ok(p) => panic!("expected a refusal, got {p:?}"),
        }
    }

    /// A directory is not a database file; opening it fails deep in SQLite with
    /// a message about the file, not about the setting that named it.
    #[test]
    fn an_override_naming_a_directory_is_refused() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        match resolve_path_with(Some(tmp.path().as_os_str().to_os_string()), None) {
            Err(SidecarError::PathResolution { reason }) => {
                assert!(reason.contains("directory"), "unhelpful reason: {reason}");
            }
            Err(other) => panic!("wrong error variant: {other:?}"),
            Ok(p) => panic!("expected a refusal, got {p:?}"),
        }
        Ok(())
    }

    #[test]
    fn override_with_nested_path_creates_parent_dirs() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let nested = tmp.path().join("nested").join("dir").join("sidecar.db");
        let resolved = resolve_path_with(Some(nested.clone().into_os_string()), None)?;
        assert_eq!(resolved, nested);
        let parent = nested.parent().ok_or(SidecarError::PathResolution {
            reason: "test asserted a path with no parent".into(),
        })?;
        assert!(
            parent.exists(),
            "resolver should create the parent directory"
        );
        Ok(())
    }

    #[test]
    fn default_base_appends_netruleouter_dir() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let resolved = resolve_path_with(None, Some(tmp.path().as_os_str().to_os_string()))?;
        let mut expected = tmp.path().to_path_buf();
        expected.push("NetRuleRouter");
        expected.push("gui_metadata.db");
        assert_eq!(resolved, expected);
        assert!(expected.parent().map(|p| p.exists()).unwrap_or(false));
        Ok(())
    }

    #[test]
    fn no_override_and_no_base_is_path_resolution_error() {
        match resolve_path_with(None, None) {
            Err(SidecarError::PathResolution { .. }) => {}
            Err(other) => panic!("wrong error variant: {other:?}"),
            Ok(p) => panic!("expected error, got {p:?}"),
        }
    }
}

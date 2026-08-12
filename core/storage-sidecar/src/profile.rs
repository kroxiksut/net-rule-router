//! Path resolution for the sidecar database.
//!
//! Default location is the per-user roaming AppData directory so each
//! Windows account on a shared machine sees its own comments and
//! pending state, consistent with the per-SID storage convention the
//! service-side runtime uses for rules themselves (block 16.8).
//!
//! Tests, headless drivers, and the CI runner override via
//! `NRR_SIDECAR_PATH`. When set, the value is used verbatim — including
//! relative paths, which resolve against the current working directory.
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
/// user-AppData base directory (e.g. `%APPDATA%` on Windows).
pub fn resolve_path_with(
    override_value: Option<OsString>,
    default_base_dir: Option<OsString>,
) -> SidecarResult<PathBuf> {
    if let Some(value) = override_value {
        let path = PathBuf::from(value);
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
/// Windows: `%APPDATA%\NetRuleRouter\gui_metadata.db`.
/// Non-Windows: `$XDG_DATA_HOME/NetRuleRouter/gui_metadata.db` falling
/// back to `$HOME/.local/share/NetRuleRouter/gui_metadata.db`. The GUI
/// is Windows-first today (block 16.16) but the implementation stays
/// portable so tests on developer macOS/Linux laptops don't have to
/// override the path.
pub fn resolve_default_path() -> SidecarResult<PathBuf> {
    resolve_path_with(None, default_base())
}

/// Look up the platform default base directory (i.e. the parent of
/// `NetRuleRouter/gui_metadata.db`). Internal helper exposed for the
/// env-free resolver above.
fn default_base() -> Option<OsString> {
    #[cfg(target_os = "windows")]
    {
        env::var_os("APPDATA")
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
        }
    }
    Ok(())
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

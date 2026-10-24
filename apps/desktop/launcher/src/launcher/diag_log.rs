// Per-surface diagnostic log: the user diagnostics directory, the
// `launcher-{surface}.log` path, session rotation, and the `diag_log` writer.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use super::LauncherSurface;

/// Per-user directory for the launcher's own diagnostic artefacts — its
/// `launcher-{surface}.log` files and the user-local copy of an exported
/// diagnostic archive. Shared by [`diag_log_path`] and
/// [`crate::archive_localize`]'s `user_archive_dir` so both always agree on
/// where the launcher logs live.
///
/// - **Windows**: `%TEMP%\NetRuleRouter` — transient per-user scratch. The
///   launcher is a GUI-subsystem binary with no console, so these files are the
///   only way to diagnose detached-spawn failures.
/// - **Linux / other unix**: `$XDG_STATE_HOME/netrulerouter`, falling back to
///   `~/.local/state/netrulerouter` per the XDG Base Directory spec. State data
///   (logs, history) belongs in `XDG_STATE_HOME` — deliberately NOT `/tmp`
///   (cleared on reboot, unfindable for a bug report) and NOT `~/.netrulerouter`
///   (a home dotfile, which XDG deprecates). A final fall back to the temp dir
///   keeps this total when neither `XDG_STATE_HOME` nor `HOME` is set.
pub(crate) fn user_diagnostics_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let mut dir = env::temp_dir();
        dir.push(nrr_shared::product_identity::PRODUCT_NAME);
        dir
    }
    #[cfg(not(windows))]
    {
        use nrr_shared::product_identity::PRODUCT_NAME_UNIX;
        if let Some(base) = env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(base).join(PRODUCT_NAME_UNIX);
        }
        if let Some(home) = env::var_os("HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join(PRODUCT_NAME_UNIX);
        }
        let mut dir = env::temp_dir();
        dir.push(PRODUCT_NAME_UNIX);
        dir
    }
}

/// Path of the per-surface diagnostic log file,
/// `<user_diagnostics_dir>/launcher-{surface}.log`. Shared by [`diag_log`] and
/// [`rotate_session_log`] so both agree on the exact location.
pub(super) fn diag_log_path(surface_tag: &str) -> PathBuf {
    // Tests write beside themselves, never into the user's real log directory.
    #[cfg(test)]
    let mut path = env::temp_dir().join(format!("nrr-launcher-tests-{}", std::process::id()));
    #[cfg(not(test))]
    let mut path = user_diagnostics_dir();
    path.push(format!("launcher-{surface_tag}.log"));
    path
}

/// Append a single diagnostic line to a per-surface log file under
/// [`user_diagnostics_dir`] (`launcher-{surface}.log`). The launcher is a
/// GUI-subsystem binary, so `eprintln!` is swallowed by the OS when there is
/// no parent console — file logging is the only way to diagnose problems in
/// detached-tray spawns (`QProcess::startDetached` from the C++ host) and
/// double-click launches.
pub(crate) fn diag_log(surface_tag: &str, message: &str) {
    // Tests keep their lines in the harness's captured stderr, never on disk.
    #[cfg(not(test))]
    append_line(&diag_log_path(surface_tag), message);
    #[cfg(test)]
    let _ = surface_tag;
    // Mirror to the error stream — visible when launched from a console. Once
    // that stream has been pointed at this very file, echoing would only write
    // the same line twice, so it stops.
    if !crate::diag_stream::error_stream_is_captured() {
        eprintln!("{message}");
    }
}

#[cfg(not(test))]
fn append_line(path: &Path, message: &str) {
    use std::io::Write;
    // The directory is created once per process, not once per line. This is
    // called for every line the child writes that is not a protocol marker, and
    // a chatty child turned one log line into a directory syscall as well.
    static DIR_READY: std::sync::Once = std::sync::Once::new();
    DIR_READY.call_once(|| {
        if let Some(parent) = path.parent() {
            prepare_log_dir(parent);
        }
        narrow_to_owner(path);
    });
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    // The host's lines and arguments land here; on Unix nobody else reads them.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    if let Ok(mut file) = options.open(path) {
        // Best-effort timestamp using std::time. chrono is not a dep.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "{ts} pid={} {message}", std::process::id());
    }
}

#[cfg(not(test))]
fn prepare_log_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        if let Some(parent) = dir.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::DirBuilder::new().mode(0o700).create(dir);
        narrow_to_owner(dir);
    }
    #[cfg(not(unix))]
    {
        let _ = fs::create_dir_all(dir);
    }
}

/// Owner-only on Unix for a directory or file an older version left readable
/// by others. A link is left alone: what it points at is not ours to change.
#[cfg(not(test))]
fn narrow_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = fs::symlink_metadata(path) else {
            return;
        };
        let owner_only = if meta.is_dir() { 0o700 } else { 0o600 };
        if !meta.file_type().is_symlink() && meta.permissions().mode() & 0o077 != 0 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(owner_only));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Rotates a per-session log file so a fresh process only accumulates lines
/// from the current session: any existing file is renamed to a `.prev.log`
/// sibling (replacing an older `.prev.log`), and the next [`diag_log`] call
/// re-creates the original path empty via its own `create(true)` open.
///
/// Best-effort by design: a locked file (or any other I/O error) is silently
/// left in place and the caller keeps appending to it, same as before this
/// existed. Callers must only invoke this once the single-instance lock for
/// this surface is confirmed held by the CURRENT process — a duplicate
/// launch that hands activation off to the real primary must never rotate
/// (and thus never split) the primary's live log out from under it.
pub(super) fn rotate_session_log(path: &Path) {
    if !path.is_file() {
        return;
    }
    let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
        return;
    };
    let prev_path = path.with_extension(format!("prev.{extension}"));
    let _ = fs::remove_file(&prev_path);
    let _ = fs::rename(path, &prev_path);
}

pub(super) fn surface_tag(surface: LauncherSurface) -> &'static str {
    match surface {
        LauncherSurface::MainGui => "main",
        LauncherSurface::Tray => "tray",
    }
}

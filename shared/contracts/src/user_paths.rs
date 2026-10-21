//! Where a per-user file of ours belongs on this OS.
//!
//! The OS shape lives here, at the bottom of the graph, because two layers
//! above need the same answer: the UI preference store and the localization
//! bundles. Each had its own copy of the ladder, and both spelled it in
//! Windows environment variables alone — off Windows they fell through to the
//! temp directory, which is shared between users and cleared on a schedule
//! nobody controls.
//!
//! `nrr_platform_api::paths::user_config_root` is the shim for callers that
//! already speak to that module.

use std::path::PathBuf;

/// The spelling this OS uses for a directory named after the product:
/// canonical (`NetRuleRouter`) on Windows, unix (`netrulerouter`) elsewhere.
pub fn product_dir_leaf() -> &'static str {
    if cfg!(windows) {
        crate::product_identity::PRODUCT_NAME
    } else {
        crate::product_identity::PRODUCT_NAME_UNIX
    }
}

/// Roots for per-user application files, best first, each already ending in
/// [`product_dir_leaf`]. Callers walk the list and take the first they can
/// create.
///
/// Windows keeps the roaming profile, then the local one. Elsewhere it is
/// `$XDG_CONFIG_HOME`, falling back to the `~/.config` the spec defines when
/// the variable is unset. The temp directory closes the list on every OS as
/// the answer of last resort.
pub fn user_app_roots() -> Vec<PathBuf> {
    let leaf = product_dir_leaf();
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |base: PathBuf| roots.push(base.join(leaf));

    #[cfg(windows)]
    {
        if let Some(app_data) = std::env::var_os("APPDATA") {
            push(PathBuf::from(app_data));
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            push(PathBuf::from(local_app_data));
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
        {
            push(base);
        } else if let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) {
            push(PathBuf::from(home).join(".config"));
        }
    }

    push(std::env::temp_dir());
    roots
}

/// The best root without asking whether it can be created — for documentation,
/// diagnostics and tests. A caller that is about to WRITE wants
/// [`user_app_roots`], which lets it fall to the next candidate.
pub fn user_config_root() -> Option<PathBuf> {
    user_app_roots().into_iter().next()
}

/// A stop of the service the asking user requested on purpose. Written before
/// the stop by whoever asked (window, tray, console); read by the clients so a
/// requested stop raises no "unexpected stop" notice.
pub const EXPECTED_STOP_MARKER: &str = "service-stop-expected.flag";

/// How long a marker vouches for a stop.
pub const EXPECTED_STOP_WINDOW: std::time::Duration = std::time::Duration::from_secs(180);

/// The per-user directory the desktop surfaces coordinate through (locks,
/// activation hand-off, shutdown flags, the stop marker). Windows: the per-user
/// temp folder. Elsewhere a shared `/tmp` would let another user plant a link,
/// so it is `$XDG_RUNTIME_DIR` or the user config root, never the temp root. The
/// Qt host spells the same two places (`host_support.h`).
pub fn runtime_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        Some(std::env::temp_dir().join(crate::product_identity::PRODUCT_NAME))
    }
    #[cfg(not(windows))]
    {
        let temp = std::env::temp_dir();
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|p| p.join(product_dir_leaf()))
            .or_else(|| user_app_roots().into_iter().find(|r| !r.starts_with(&temp)))
    }
}

/// The directory holding the marker: the runtime directory.
pub fn expected_stop_marker_dir() -> Option<PathBuf> {
    runtime_dir()
}

/// The marker inside `dir`.
pub fn expected_stop_marker_in(dir: &std::path::Path) -> PathBuf {
    dir.join(EXPECTED_STOP_MARKER)
}

/// Whether a marker of this age still vouches for a stop.
pub fn expected_stop_is_fresh(age: std::time::Duration) -> bool {
    age <= EXPECTED_STOP_WINDOW
}

/// Whether the asking user left a fresh marker. A link is never followed.
pub fn expected_stop_was_requested() -> bool {
    expected_stop_marker_dir().is_some_and(|dir| expected_stop_marker_fresh_in(&dir))
}

/// [`expected_stop_was_requested`] for a given directory.
pub fn expected_stop_marker_fresh_in(dir: &std::path::Path) -> bool {
    std::fs::symlink_metadata(expected_stop_marker_in(dir))
        .ok()
        .filter(|m| m.file_type().is_file())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .is_some_and(expected_stop_is_fresh)
}

/// Leave the marker for this user. Best effort: a failure only means the stop
/// reads as unexpected, which errs toward telling the user.
pub fn note_expected_stop() {
    if let Some(dir) = expected_stop_marker_dir() {
        note_expected_stop_in(&dir);
    }
}

/// [`note_expected_stop`] into a given directory. The directory must be a real
/// one of ours; the file is written beside the marker and renamed over it, so a
/// planted link at the marker is replaced, never written through.
pub fn note_expected_stop_in(dir: &std::path::Path) {
    let _ = write_marker(dir);
}

fn write_marker(dir: &std::path::Path) -> std::io::Result<()> {
    ensure_own_dir(dir)?;
    let marker = expected_stop_marker_in(dir);
    let staging = dir.join(format!("{EXPECTED_STOP_MARKER}.{}", std::process::id()));
    let _ = std::fs::remove_file(&staging);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(&staging)?;
    std::fs::rename(&staging, &marker).inspect_err(|_| {
        let _ = std::fs::remove_file(&staging);
    })
}

/// A real directory, not a link, that only its owner can change; created
/// private when missing.
pub fn ensure_own_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    if std::fs::symlink_metadata(dir).is_err() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(Error::new(ErrorKind::InvalidInput, "not a plain directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // The parent is the per-user root we trust; a directory of another
        // owner, or one others can write, is not ours.
        let parent_uid = dir
            .parent()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.uid());
        if parent_uid != Some(meta.uid()) || meta.mode() & 0o022 != 0 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "directory is not ours",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_marker_vouches_only_while_fresh() {
        assert!(expected_stop_is_fresh(std::time::Duration::from_secs(179)));
        assert!(!expected_stop_is_fresh(std::time::Duration::from_secs(181)));
    }

    #[test]
    fn noting_a_stop_creates_a_fresh_marker_and_its_folder() {
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("stop");
        assert!(!expected_stop_marker_fresh_in(&dir));
        note_expected_stop_in(&dir);
        assert!(expected_stop_marker_fresh_in(&dir));
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_link_at_the_marker_is_replaced_not_followed() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("stop");
        note_expected_stop_in(&dir);
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").expect("victim");
        let marker = expected_stop_marker_in(&dir);
        std::fs::remove_file(&marker).expect("rm");
        symlink(&victim, &marker).expect("plant");
        assert!(
            !expected_stop_marker_fresh_in(&dir),
            "a link is not a marker"
        );
        note_expected_stop_in(&dir);
        assert_eq!(std::fs::read(&victim).expect("read"), b"keep");
        assert!(expected_stop_marker_fresh_in(&dir));
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_link_as_the_folder_is_not_written_through() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().expect("tempdir");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("dir");
        let dir = root.path().join("stop");
        symlink(&elsewhere, &dir).expect("plant");
        note_expected_stop_in(&dir);
        assert_eq!(std::fs::read_dir(&elsewhere).expect("ls").count(), 0);
    }

    #[test]
    fn the_runtime_dir_is_never_the_bare_temp_root() {
        if let Some(dir) = runtime_dir() {
            assert_ne!(dir, std::env::temp_dir());
            if cfg!(not(windows)) {
                assert!(!dir.starts_with(std::env::temp_dir()));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_runtime_folder_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("run");
        std::fs::create_dir(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert!(ensure_own_dir(&dir).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(ensure_own_dir(&dir).is_ok());
    }

    #[test]
    fn every_root_ends_in_the_product_leaf() {
        for root in user_app_roots() {
            assert_eq!(
                root.file_name().and_then(|name| name.to_str()),
                Some(product_dir_leaf()),
                "candidate does not end in the product directory: {}",
                root.display()
            );
        }
    }

    #[test]
    fn the_last_resort_is_temp_and_the_only_one() {
        let roots = user_app_roots();
        let temp = std::env::temp_dir();
        let last = roots.last().expect("at least the temp candidate");
        assert!(last.starts_with(&temp));
        assert!(
            roots[..roots.len() - 1]
                .iter()
                .all(|root| !root.starts_with(&temp)),
            "only the last candidate may be the temp directory"
        );
    }

    #[test]
    fn a_profile_root_is_offered_before_the_temp_directory() {
        // Windows always has APPDATA, unix always has HOME under test; the
        // point of the assert is that we never hand a caller temp as the FIRST
        // answer on a normally configured account.
        let roots = user_app_roots();
        assert!(
            roots.len() > 1,
            "no profile root was offered: {:?}",
            roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
        );
        assert!(!roots[0].starts_with(std::env::temp_dir()));
    }

    #[cfg(not(windows))]
    #[test]
    fn xdg_config_home_wins_over_the_home_default() {
        // The env is process-wide, so this asserts the ORDER the builder
        // declares rather than mutating it: the XDG branch is taken first and
        // the `.config` default is its `else`.
        let from_env = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute());
        let Some(expected_base) = from_env else {
            return;
        };
        let expected = expected_base.join(product_dir_leaf());
        assert!(
            user_app_roots().contains(&expected),
            "XDG_CONFIG_HOME is set but no candidate uses it"
        );
    }
}

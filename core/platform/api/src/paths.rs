//! Production directory roots — the single declaration of where the service
//! keeps state and operational logs on each OS.
//!
//! The leaf is never retyped: it comes from
//! [`nrr_shared::product_identity`], canonical spelling on Windows and unix
//! spelling on Linux/macOS. The OS *shape* lives here because that is what
//! this crate is for — a root derived a second time somewhere else is a
//! standard by coincidence, and it survives a rename in only one of the two
//! places.

use std::path::PathBuf;

/// The spelling this OS uses for a directory named after the product:
/// canonical (`NetRuleRouter`) on Windows, unix (`netrulerouter`) elsewhere —
/// macOS included, since it follows the FHS layout until its own port lands.
/// Every product-named directory — production root, per-user dev and cache
/// dirs — takes its leaf from here.
///
/// Declared one layer down, in `nrr-shared`, because the localization bundles
/// live below this crate and name the same directory.
pub fn product_dir_leaf() -> &'static str {
    nrr_shared::user_paths::product_dir_leaf()
}

/// Root of the per-user configuration directory: `%APPDATA%\<product>` on
/// Windows, `$XDG_CONFIG_HOME/<product>` (or `~/.config/<product>`) elsewhere.
///
/// This is the READ answer. A caller about to write walks
/// [`nrr_shared::user_paths::user_app_roots`] instead, which offers the next
/// candidate when one cannot be created.
///
/// Holds `user-settings.json` ([`nrr_shared::user_settings`]), the settings
/// every client reads without the service, and `managed/` with the GUI's own
/// preferences.
pub fn user_config_root() -> Option<PathBuf> {
    nrr_shared::user_paths::user_config_root()
}

/// Root of the production service's state directory: `%ProgramData%\<product>`
/// on Windows, `/var/lib/<product>` on Linux (the systemd `StateDirectory`).
/// macOS follows the Linux FHS layout until its own port lands.
///
/// `None` only on Windows with no `PROGRAMDATA` in the environment — the
/// caller decides whether that is fatal (the service) or just one candidate
/// that did not pan out (the GUI's "open logs folder").
///
/// TRUST NOTE: this reads the process environment, and on Windows a user can
/// rewrite their own environment through `HKCU\Environment` without any
/// administrative right. The service under SCM and a console the user elevated
/// themselves are both fine — the environment is the system's or their own. A
/// process elevated ON A USER'S BEHALF is not: it inherits the environment of
/// whoever triggered the prompt. That path (the broker spawning the service's
/// `install`/`cleanup` verbs) hands the child the MACHINE environment instead;
/// see `nrr_broker::trusted_env`.
pub fn production_data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("PROGRAMDATA").map(|base| PathBuf::from(base).join(product_dir_leaf()))
    }
    #[cfg(all(unix, not(windows)))]
    {
        Some(PathBuf::from("/var/lib").join(product_dir_leaf()))
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

/// Operational-log directory of the production service. Linux splits logs to
/// `/var/log/<product>` (systemd `LogsDirectory`) so they live under `/var/log`
/// per FHS while state stays in `/var/lib`; Windows nests them under the state
/// root. The audit trail deliberately does NOT live here — it stays under the
/// state root on every OS, out of reach of a logrotate config scoped to
/// `/var/log`.
pub fn production_logs_dir() -> Option<PathBuf> {
    #[cfg(all(unix, not(windows)))]
    {
        Some(PathBuf::from("/var/log").join(product_dir_leaf()))
    }
    #[cfg(not(all(unix, not(windows))))]
    {
        production_data_root().map(|root| root.join("logs"))
    }
}

/// The elevation broker's lifecycle log, in the production logs directory. The
/// service ships it in the diagnostic archive.
pub const BROKER_LOG_FILE: &str = "nrr-broker.log";
/// The previous broker session's log, kept beside [`BROKER_LOG_FILE`].
pub const BROKER_PREVIOUS_LOG_FILE: &str = "nrr-broker.prev.log";

/// Directory the desktop surfaces coordinate through at run time: the
/// single-instance locks, the activation hand-off, the shutdown flag.
///
/// Windows: `%TEMP%\<product>` — the temp directory is already per-user there.
/// Unix: `$XDG_RUNTIME_DIR/<product>`, which is per-user, mode 0700, and wiped
/// at logout — the right lifetime for coordination state. Deliberately NOT
/// `/tmp`, which is one shared world-writable directory: two users' sessions
/// would collide on the same lock (the second could not start its GUI at all)
/// and anyone on the box could plant the shutdown flag. The fallbacks keep the
/// function total on a session without a runtime dir, still without putting two
/// users on one path.
pub fn user_runtime_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::temp_dir().join(product_dir_leaf())
    }
    #[cfg(not(windows))]
    {
        let leaf = product_dir_leaf();
        if let Some(base) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            return PathBuf::from(base).join(leaf);
        }
        match std::env::var_os("USER").filter(|v| !v.is_empty()) {
            Some(user) => std::env::temp_dir().join(format!("{leaf}-{}", user.to_string_lossy())),
            None => std::env::temp_dir().join(leaf),
        }
    }
}

/// Creates [`user_runtime_dir`] if needed and refuses to use one that is not
/// private to this user.
///
/// Without `XDG_RUNTIME_DIR` the path falls back into `/tmp`, which every local
/// user can write. A directory or symlink another user planted there with our
/// name would have us drop the activation hand-off into their hands, and the
/// launcher and the C++ host DISPATCH what that file says. Windows keeps
/// `%TEMP%`, which is already per-user.
pub fn ensure_user_runtime_dir() -> std::io::Result<PathBuf> {
    let dir = user_runtime_dir();
    #[cfg(windows)]
    std::fs::create_dir_all(&dir)?;
    #[cfg(not(windows))]
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Creates `dir` owner-only, or accepts it only as this user's private
/// directory. The check follows the creation: a name planted between a
/// look and a create is caught either way, and a sticky `/tmp` keeps anyone
/// else from swapping it afterwards.
#[cfg(not(windows))]
pub fn ensure_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    let create = || std::fs::DirBuilder::new().mode(0o700).create(dir);
    match create() {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        // The parent is the runtime base or the temp root, not ours to secure.
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent)?;
            }
            match create() {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }

    let refuse = |why: String| Err(Error::new(ErrorKind::PermissionDenied, why));
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return refuse(format!(
            "{} is a symlink; refusing to use it",
            dir.display()
        ));
    }
    if !meta.is_dir() {
        return refuse(format!("{} is not a directory", dir.display()));
    }
    if meta.uid() != effective_uid() {
        return refuse(format!(
            "{} belongs to uid {}; refusing to use it",
            dir.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return refuse(format!(
            "{} is readable or writable by other users (mode {:o})",
            dir.display(),
            meta.mode() & 0o777
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::geteuid() }
}

/// Creates `path` for writing, failing if anything is already there.
///
/// `fs::write` follows a symlink and reuses whatever file it finds, and on Unix
/// leaves the result world-readable. These files carry a user's settings into
/// the Qt host, so: exclusive creation (a planted name is an error, not a
/// redirect) and owner-only mode.
pub fn create_private_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::product_identity::{PRODUCT_NAME, PRODUCT_NAME_UNIX};

    /// The rule this module exists to hold: the actual root ends in the leaf
    /// declared by `product_identity`, not in a literal that happens to match.
    #[test]
    fn production_root_leaf_comes_from_product_identity() {
        let root = production_data_root().expect("production root resolves on a normal host");
        let leaf = if cfg!(windows) {
            PRODUCT_NAME
        } else {
            PRODUCT_NAME_UNIX
        };
        assert_eq!(
            root.file_name().and_then(|n| n.to_str()),
            Some(leaf),
            "root {root:?} must end in the product-identity leaf",
        );
    }

    #[test]
    fn the_runtime_dir_is_never_a_bare_shared_temp() {
        // The whole point of this helper: on Unix, `/tmp` itself is shared
        // between users, so the path must always carry a product-specific
        // component and, without a runtime dir, a user-specific one too.
        let dir = user_runtime_dir();
        assert_ne!(
            dir,
            std::env::temp_dir(),
            "must not be the temp root itself"
        );
        let leaf = dir
            .file_name()
            .and_then(|n| n.to_str())
            .expect("runtime dir has a final component");
        assert!(
            leaf.starts_with(product_dir_leaf()),
            "runtime dir {dir:?} must be named after the product",
        );
    }

    #[test]
    fn logs_dir_splits_from_state_only_on_unix() {
        let root = production_data_root().expect("production root");
        let logs = production_logs_dir().expect("production logs dir");
        if cfg!(all(unix, not(windows))) {
            assert_eq!(logs, PathBuf::from("/var/log").join(PRODUCT_NAME_UNIX));
            assert!(!logs.starts_with(&root));
        } else {
            assert_eq!(logs, root.join("logs"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn a_fresh_runtime_dir_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let base = tempfile::tempdir().expect("temp");
        let dir = base.path().join("runtime");
        ensure_private_dir(&dir).expect("created");
        let mode = std::fs::metadata(&dir).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        ensure_private_dir(&dir).expect("our own directory is accepted again");
    }

    /// The race this guards: the name appears between "not there" and
    /// "create". A recursive create reports success on the planted symlink.
    #[cfg(not(windows))]
    #[test]
    fn a_planted_symlink_is_refused_even_at_the_creation_step() {
        let base = tempfile::tempdir().expect("temp");
        let elsewhere = base.path().join("elsewhere");
        std::fs::DirBuilder::new()
            .create(&elsewhere)
            .expect("target");
        std::fs::set_permissions(
            &elsewhere,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("chmod");
        let dir = base.path().join("runtime");
        std::os::unix::fs::symlink(&elsewhere, &dir).expect("plant");

        let result = ensure_private_dir(&dir);
        assert_eq!(
            result.map_err(|e| e.kind()),
            Err(std::io::ErrorKind::PermissionDenied)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn an_existing_dir_open_to_others_is_refused() {
        let base = tempfile::tempdir().expect("temp");
        let dir = base.path().join("runtime");
        std::fs::DirBuilder::new().create(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("chmod");
        assert!(ensure_private_dir(&dir).is_err());
    }

    /// Only root can hand a directory to another uid, so this runs only there.
    #[cfg(not(windows))]
    #[test]
    fn a_dir_owned_by_another_user_is_refused() {
        if effective_uid() != 0 {
            return;
        }
        let base = tempfile::tempdir().expect("temp");
        let dir = base.path().join("runtime");
        std::fs::DirBuilder::new().create(&dir).expect("dir");
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .expect("chmod");
        std::os::unix::fs::chown(&dir, Some(65_534), None).expect("chown");
        assert!(ensure_private_dir(&dir).is_err());
    }

    #[test]
    fn a_second_writer_is_refused_rather_than_handed_the_same_file() {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("context.json");

        let first = create_private_file(&path);
        assert!(first.is_ok(), "the first creation must succeed");
        let second = create_private_file(&path);
        assert!(
            second.is_err(),
            "a name that already exists is a planted file, not a target"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_context_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("context.json");
        create_private_file(&path).expect("create");

        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode {:o} leaks the user's settings", mode);
    }
}

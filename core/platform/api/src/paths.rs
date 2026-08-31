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
pub fn product_dir_leaf() -> &'static str {
    if cfg!(windows) {
        nrr_shared::product_identity::PRODUCT_NAME
    } else {
        nrr_shared::product_identity::PRODUCT_NAME_UNIX
    }
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
/// user can write. A directory another user created there first — with our
/// exact name — would have us drop the activation hand-off into their hands,
/// and the launcher and the C++ host DISPATCH what that file says. So: never
/// follow a symlink, and never accept a directory that grants group or other
/// any access at all. Windows keeps `%TEMP%`, which is already per-user.
pub fn ensure_user_runtime_dir() -> std::io::Result<PathBuf> {
    let dir = user_runtime_dir();

    #[cfg(windows)]
    {
        std::fs::create_dir_all(&dir)?;
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};

        match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is a symlink; refusing to use it", dir.display()),
                ));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{} is not a directory", dir.display()),
                ));
            }
            Ok(meta) if meta.mode() & 0o077 != 0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is readable or writable by other users (mode {:o})",
                        dir.display(),
                        meta.mode() & 0o777
                    ),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Parents may already exist with looser modes (`/tmp` does);
                // the mode applies to the ones this call creates, which is the
                // leaf we are about to own.
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)?;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(dir)
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

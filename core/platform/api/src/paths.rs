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
}

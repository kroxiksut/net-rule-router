//! Whether a file an unprivileged process acts on was placed by an
//! administrator.
//!
//! The machine state root can exist before the service ever locked it down,
//! and any local account may create it first and stay its owner. A file there
//! that seeds a user's setup is believed only when no ordinary account could
//! have written or swapped it. How ownership and rights are read is per-OS.

use std::path::Path;

pub use nrr_shared::first_run_sheet::AdminAuthored;

/// The OS check behind "only an administrator (root) could have put this here".
pub trait AdminAuthoredFiles: Send + Sync {
    /// `path` opened for reading when only SYSTEM/Administrators (root) could
    /// have written it and neither it nor a folder on the way is a link;
    /// otherwise why not. The check runs on the opened file itself, so what
    /// was judged is what the caller reads. Rights that cannot be read refuse.
    fn open_admin_authored(&self, path: &Path) -> AdminAuthored;
}

/// For a platform with no mechanism yet: nothing is believed.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrustNothing;

impl AdminAuthoredFiles for TrustNothing {
    fn open_admin_authored(&self, path: &Path) -> AdminAuthored {
        if std::fs::symlink_metadata(path).is_err() {
            return AdminAuthored::Missing;
        }
        AdminAuthored::Refused("this platform cannot tell who wrote the file".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_platform_without_a_mechanism_believes_no_file() {
        let dir = std::env::temp_dir();
        assert!(matches!(
            TrustNothing.open_admin_authored(&dir),
            AdminAuthored::Refused(_)
        ));
    }
}

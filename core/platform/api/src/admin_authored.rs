//! Whether a file an unprivileged process acts on was placed by an
//! administrator.
//!
//! The machine state root can exist before the service ever locked it down,
//! and any local account may create it first and stay its owner. A file there
//! that seeds a user's setup is believed only when no ordinary account could
//! have written or swapped it. How ownership and rights are read is per-OS.

use std::path::Path;

/// The OS check behind "only an administrator (root) could have put this here".
pub trait AdminAuthoredFiles: Send + Sync {
    /// `None` when only SYSTEM/Administrators (root) could have written `path`
    /// and neither it nor its folder is a link; otherwise why not. A path whose
    /// owner or rights cannot be read is untrusted, never trusted by default.
    fn untrusted_because(&self, path: &Path) -> Option<String>;
}

/// For a platform with no mechanism yet: nothing is believed.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrustNothing;

impl AdminAuthoredFiles for TrustNothing {
    fn untrusted_because(&self, _path: &Path) -> Option<String> {
        Some("this platform cannot tell who wrote the file".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_platform_without_a_mechanism_believes_no_file() {
        assert!(TrustNothing
            .untrusted_because(Path::new("first-run.json"))
            .is_some());
    }
}

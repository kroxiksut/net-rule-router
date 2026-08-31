//! System appearance (light / dark), behind a port.
//!
//! The probe is OS mechanism, so it belongs here as a trait with per-OS
//! implementations rather than inside a neutral UI crate. The only real
//! implementation used to sit under `#[cfg(windows)]` in `nrr-ui-support`, so
//! every other OS silently received "light" — a guess presented as a fact.

/// What the system says it wants to look like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemAppearance {
    Light,
    Dark,
}

/// Reads the host's appearance preference.
pub trait SystemThemePort: Send + Sync {
    /// `None` means the question could not be answered on this host — NOT
    /// "light". The caller decides what to show and, crucially, gets to say
    /// that it is a fallback rather than an observation.
    fn detect(&self) -> Option<SystemAppearance>;
}

/// A port that never knows. The default wherever no OS implementation is
/// wired, so a missing implementation reads as "undetected" instead of
/// silently answering "light".
pub struct UnknownSystemTheme;

impl SystemThemePort for UnknownSystemTheme {
    fn detect(&self) -> Option<SystemAppearance> {
        None
    }
}

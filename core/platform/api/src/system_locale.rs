//! The language the user runs their system in, behind a port.
//!
//! Reading it is OS mechanism (a Win32 call, the POSIX locale environment), so
//! a neutral UI crate asks this trait and only decides which bundled
//! translation the answer maps to.

/// Reads the host's display-language preference.
pub trait SystemLocalePort: Send + Sync {
    /// Ordered display-language candidates, most preferred first, each a
    /// language tag as the host spells it (`ru-RU`, `en_US.UTF-8`, `de`). An
    /// empty list means the host did not say. The port only orders raw
    /// candidates by the host's own precedence rules; it never judges which
    /// one this build has a translation for — that decision stays with the
    /// caller, which is the one place that knows the bundled catalogue.
    fn ui_language_candidates(&self) -> Vec<String>;
}

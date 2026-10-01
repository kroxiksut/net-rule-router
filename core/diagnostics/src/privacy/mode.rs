//! Privacy/redaction mode.

use crate::logs::filter::LoggingMode;
use nrr_storage::DiagnosticRedactionLevel;

// ── RedactionMode ─────────────────────────────────────────────────────────────

/// Unified surface-level privacy mode applied across logs, explain, and archive.
///
/// This is the user-facing concept.  Internal subsystems convert it to their
/// own level types via the `From` impls below.
///
/// # Mode comparison
///
/// The table below describes the explicit field redactors
/// ([`crate::privacy::redact_hostname`], [`crate::privacy::redact_ipv4`],
/// [`crate::privacy::redact_process_path`]) that DTO builders call by hand.
/// The structured operational log stream is redacted separately, by
/// [`crate::logs::privacy::redact_above`] against a `PrivacyClass` ceiling
/// derived from the mode: it is coarser and replaces an over-ranked field
/// wholesale with `<redacted>`, not with an eTLD+1 or filename-only form.
///
/// | Mode           | Hostnames        | IPs               | Process path     |
/// |----------------|------------------|-------------------|------------------|
/// | `Default`      | eTLD+1 only      | masked / category | filename only    |
/// | `Diagnostics`  | full hostname    | full IPv4         | masked-username  |
/// | `DeveloperLocal`| full hostname   | full IPv4         | full path        |
///
/// `DeveloperLocal` is only available in dev/test profiles; it must not be
/// surfaced to end users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedactionMode {
    Default,
    Diagnostics,
    DeveloperLocal,
}

impl RedactionMode {
    /// Returns `true` if this mode reveals more than default.
    #[must_use]
    pub fn is_elevated(self) -> bool {
        self > Self::Default
    }

    /// Returns `true` if IP addresses may be shown.
    #[must_use]
    pub fn shows_ip(self) -> bool {
        self >= Self::Diagnostics
    }

    /// Returns `true` if full process paths may be shown.
    #[must_use]
    pub fn shows_full_path(self) -> bool {
        self >= Self::DeveloperLocal
    }

    /// Returns `true` if full hostnames may be shown.
    #[must_use]
    pub fn shows_full_hostname(self) -> bool {
        self >= Self::Diagnostics
    }
}

// ── Conversions ───────────────────────────────────────────────────────────────

impl From<RedactionMode> for DiagnosticRedactionLevel {
    fn from(m: RedactionMode) -> Self {
        match m {
            RedactionMode::Default => Self::Compact,
            RedactionMode::Diagnostics => Self::Diagnostics,
            RedactionMode::DeveloperLocal => Self::Diagnostics,
        }
    }
}

impl From<RedactionMode> for LoggingMode {
    fn from(m: RedactionMode) -> Self {
        match m {
            RedactionMode::Default => Self::Default,
            RedactionMode::Diagnostics => Self::Diagnostic,
            RedactionMode::DeveloperLocal => Self::DeveloperTrace,
        }
    }
}

impl From<LoggingMode> for RedactionMode {
    fn from(m: LoggingMode) -> Self {
        match m {
            LoggingMode::Default => Self::Default,
            LoggingMode::Diagnostic => Self::Diagnostics,
            LoggingMode::DeveloperTrace => Self::DeveloperLocal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_mode_ordering() {
        assert!(RedactionMode::Default < RedactionMode::Diagnostics);
        assert!(RedactionMode::Diagnostics < RedactionMode::DeveloperLocal);
    }

    #[test]
    fn redaction_mode_predicates() {
        assert!(!RedactionMode::Default.shows_ip());
        assert!(RedactionMode::Diagnostics.shows_ip());
        assert!(RedactionMode::DeveloperLocal.shows_ip());

        assert!(!RedactionMode::Default.shows_full_path());
        assert!(!RedactionMode::Diagnostics.shows_full_path());
        assert!(RedactionMode::DeveloperLocal.shows_full_path());

        assert!(!RedactionMode::Default.shows_full_hostname());
        assert!(RedactionMode::Diagnostics.shows_full_hostname());
    }

    #[test]
    fn redaction_mode_to_diagnostic_redaction_level() {
        assert_eq!(
            DiagnosticRedactionLevel::from(RedactionMode::Default),
            DiagnosticRedactionLevel::Compact
        );
        assert_eq!(
            DiagnosticRedactionLevel::from(RedactionMode::Diagnostics),
            DiagnosticRedactionLevel::Diagnostics
        );
    }

    #[test]
    fn redaction_mode_to_logging_mode() {
        assert_eq!(
            LoggingMode::from(RedactionMode::Default),
            LoggingMode::Default
        );
        assert_eq!(
            LoggingMode::from(RedactionMode::Diagnostics),
            LoggingMode::Diagnostic
        );
        assert_eq!(
            LoggingMode::from(RedactionMode::DeveloperLocal),
            LoggingMode::DeveloperTrace
        );
    }

    #[test]
    fn logging_mode_to_redaction_mode() {
        assert_eq!(
            RedactionMode::from(LoggingMode::Default),
            RedactionMode::Default
        );
        assert_eq!(
            RedactionMode::from(LoggingMode::Diagnostic),
            RedactionMode::Diagnostics
        );
        assert_eq!(
            RedactionMode::from(LoggingMode::DeveloperTrace),
            RedactionMode::DeveloperLocal
        );
    }
}

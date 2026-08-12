//! Privacy/redaction mode and diagnostic session.

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

// ── DiagnosticSessionScope ────────────────────────────────────────────────────

/// What categories of data the diagnostic session makes available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticSessionScope {
    /// All diagnostic categories enabled.
    All,
    /// Only decision and cache explain detail.
    DecisionAndCache,
    /// Only privacy-redacted process/adapter identifiers.
    ProcessAndAdapter,
}

// ── DiagnosticSession ─────────────────────────────────────────────────────────

/// State of an explicit user-enabled diagnostic session.
///
/// Enables `RedactionMode::Diagnostics` for a bounded time window.
/// Created when the user enables diagnostic mode from GUI/tray.
/// Auto-expires at `expires_at`.
#[derive(Clone, Debug)]
pub struct DiagnosticSession {
    /// UTC Unix milliseconds when the session was enabled.
    pub enabled_at: i64,
    /// UTC Unix milliseconds when the session will auto-expire.
    pub expires_at: i64,
    /// Actor description (user-facing label, not a raw username).
    pub enabled_by: String,
    /// What categories this session unlocks.
    pub scope: DiagnosticSessionScope,
    /// Free-text reason provided by the user (optional, for audit trail).
    pub reason: Option<String>,
}

impl DiagnosticSession {
    /// Default session duration in milliseconds (1 hour).
    pub const DEFAULT_DURATION_MS: i64 = 3_600_000;
    /// Maximum session duration in milliseconds (4 hours).
    pub const MAX_DURATION_MS: i64 = 4 * 3_600_000;

    /// Creates a new session expiring after `duration_ms` milliseconds.
    ///
    /// Duration is clamped to [`MAX_DURATION_MS`].
    pub fn new(
        now_ms: i64,
        duration_ms: i64,
        enabled_by: impl Into<String>,
        scope: DiagnosticSessionScope,
        reason: Option<String>,
    ) -> Self {
        let clamped = duration_ms.clamp(1, Self::MAX_DURATION_MS);
        Self {
            enabled_at: now_ms,
            expires_at: now_ms + clamped,
            enabled_by: enabled_by.into(),
            scope,
            reason,
        }
    }

    /// A session with NO expiry: active until the
    /// service process restarts (the in-memory session is lost on restart).
    /// Backs the GUI's "until restart" TTL radio. `expires_at = i64::MAX` is
    /// the no-expiry sentinel; [`is_active`](Self::is_active) stays true and
    /// [`is_until_restart`](Self::is_until_restart) recognises it.
    pub fn until_restart(
        now_ms: i64,
        enabled_by: impl Into<String>,
        scope: DiagnosticSessionScope,
        reason: Option<String>,
    ) -> Self {
        Self {
            enabled_at: now_ms,
            expires_at: i64::MAX,
            enabled_by: enabled_by.into(),
            scope,
            reason,
        }
    }

    /// `true` when this is a no-expiry ("until restart") session.
    #[must_use]
    pub fn is_until_restart(&self) -> bool {
        self.expires_at == i64::MAX
    }

    /// Returns `true` if the session is still active at `now_ms`.
    #[must_use]
    pub fn is_active(&self, now_ms: i64) -> bool {
        now_ms < self.expires_at
    }

    /// Returns the effective `RedactionMode` for this session.
    #[must_use]
    pub fn redaction_mode(&self) -> RedactionMode {
        RedactionMode::Diagnostics
    }

    /// Remaining milliseconds until expiry, or 0 if already expired.
    #[must_use]
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        (self.expires_at - now_ms).max(0)
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

    #[test]
    fn diagnostic_session_active_and_expiry() {
        let now = 1_745_000_000_000_i64;
        let session =
            DiagnosticSession::new(now, 3_600_000, "user", DiagnosticSessionScope::All, None);
        assert!(session.is_active(now));
        assert!(session.is_active(now + 3_599_999));
        assert!(!session.is_active(now + 3_600_000));
    }

    #[test]
    fn diagnostic_session_max_duration_clamped() {
        let now = 0_i64;
        let session = DiagnosticSession::new(now, i64::MAX, "u", DiagnosticSessionScope::All, None);
        assert_eq!(
            session.expires_at - session.enabled_at,
            DiagnosticSession::MAX_DURATION_MS
        );
    }

    #[test]
    fn diagnostic_session_remaining_ms() {
        let now = 1_000_000_i64;
        let session = DiagnosticSession::new(now, 5_000, "u", DiagnosticSessionScope::All, None);
        assert_eq!(session.remaining_ms(now + 2_000), 3_000);
        assert_eq!(session.remaining_ms(now + 10_000), 0);
    }

    #[test]
    fn diagnostic_session_redaction_mode() {
        let s = DiagnosticSession::new(0, 1000, "u", DiagnosticSessionScope::All, None);
        assert_eq!(s.redaction_mode(), RedactionMode::Diagnostics);
    }
}

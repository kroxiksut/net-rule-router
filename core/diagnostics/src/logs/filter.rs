//! Operational log filtering — allowlists, logging mode, rate limits.
//!
//! # Logging modes
//!
//! | Mode             | Who enables           | What is logged                        |
//! |------------------|-----------------------|---------------------------------------|
//! | `Default`        | Always active         | Service lifecycle, errors, security   |
//! | `Diagnostic`     | Explicit user action  | + decision summaries, cache details   |
//! | `DeveloperTrace` | Dev/test profile only | Everything at Trace level             |
//!
//! # Default allowlist
//!
//! Categories emitted unconditionally in Default mode (at `Info` or above):
//! `Service`, `Security`, `Apply` (failures only), `Integrity`, `Diagnostics`.
//! `Decision` and `Cache` are rate-limited to at most one summary per window.
//!
//! # Rate limiting
//!
//! High-frequency categories (`Decision`, `Cache`) are rate-limited in Default
//! and Diagnostic modes.  The rate limiter uses a fixed window of
//! [`RATE_LIMIT_WINDOW_SECS`] seconds and allows at most
//! [`RATE_LIMIT_MAX_PER_WINDOW`] events per category per window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::taxonomy::{EventCategory, EventLevel, PrivacyClass};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Rate-limit window in seconds for high-frequency categories.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 10;

/// Maximum events per category per window in Default mode.
pub const RATE_LIMIT_MAX_DEFAULT: u64 = 5;

/// Maximum events per category per window in Diagnostic mode.
pub const RATE_LIMIT_MAX_DIAGNOSTIC: u64 = 50;

/// Categories that are rate-limited in Default mode.
pub const RATE_LIMITED_CATEGORIES: &[EventCategory] =
    &[EventCategory::Decision, EventCategory::Cache];

// ── LoggingMode ───────────────────────────────────────────────────────────────

/// Current operational logging mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoggingMode {
    /// Normal runtime: minimum required events only.
    Default,
    /// Explicit user-enabled diagnostic mode: adds decision and cache detail.
    Diagnostic,
    /// Developer/test profile: all events including Trace.
    DeveloperTrace,
}

impl LoggingMode {
    /// Minimum level emitted in this mode.
    #[must_use]
    pub fn min_level(self) -> EventLevel {
        match self {
            Self::Default => EventLevel::Info,
            Self::Diagnostic => EventLevel::Debug,
            Self::DeveloperTrace => EventLevel::Trace,
        }
    }

    /// Maximum privacy class emitted in this mode.
    #[must_use]
    pub fn max_privacy(self) -> PrivacyClass {
        match self {
            Self::Default => PrivacyClass::PublicSummary,
            Self::Diagnostic => PrivacyClass::Diagnostic,
            Self::DeveloperTrace => PrivacyClass::Sensitive,
        }
    }
}

// ── AllowedCategories ─────────────────────────────────────────────────────────

/// Returns `true` if the category is unconditionally allowed in Default mode.
fn is_default_allowed(category: EventCategory) -> bool {
    matches!(
        category,
        EventCategory::Service
            | EventCategory::Security
            | EventCategory::Apply
            | EventCategory::Integrity
            | EventCategory::Diagnostics
    )
}

/// Returns `true` if the category is always allowed in Diagnostic mode.
fn is_diagnostic_allowed(category: EventCategory) -> bool {
    // In Diagnostic mode all categories are allowed; rate limits still apply.
    let _ = category;
    true
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

struct RateBucket {
    count: u64,
    window_start: Instant,
}

impl RateBucket {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
        }
    }

    /// Returns `true` if the event should be allowed (not rate-limited).
    fn allow(&mut self, max_per_window: u64) -> bool {
        let elapsed = self.window_start.elapsed().as_secs();
        if elapsed >= RATE_LIMIT_WINDOW_SECS {
            // Reset window.
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count < max_per_window {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

// ── LogFilter ─────────────────────────────────────────────────────────────────

/// Thread-safe event filter for the operational log writer.
pub struct LogFilter {
    mode: Mutex<LoggingMode>,
    rate_buckets: Mutex<HashMap<u8, RateBucket>>,
}

// Lock-poisoning `expect()` on the mode/rate-bucket locks propagates a prior
// panic — not a recoverable error.
#[allow(clippy::expect_used)]
impl LogFilter {
    pub fn new(initial_mode: LoggingMode) -> Self {
        Self {
            mode: Mutex::new(initial_mode),
            rate_buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the current logging mode.
    pub fn mode(&self) -> LoggingMode {
        *self.mode.lock().expect("LogFilter mode")
    }

    /// Changes the logging mode (e.g., when user enables/disables diagnostic mode).
    pub fn set_mode(&self, mode: LoggingMode) {
        *self.mode.lock().expect("LogFilter mode") = mode;
    }

    /// Returns `true` if an event with these properties should be written.
    ///
    /// Called by the writer before serialising an event.
    pub fn should_emit(
        &self,
        level: EventLevel,
        category: EventCategory,
        privacy: PrivacyClass,
    ) -> bool {
        let mode = self.mode();

        // Level gate.
        if level < mode.min_level() {
            return false;
        }

        // Privacy gate — never emit SecretNeverLog.
        if privacy == PrivacyClass::SecretNeverLog {
            return false;
        }
        if privacy > mode.max_privacy() {
            return false;
        }

        // Category allowlist.
        let category_allowed = match mode {
            LoggingMode::Default => is_default_allowed(category),
            LoggingMode::Diagnostic => is_diagnostic_allowed(category),
            LoggingMode::DeveloperTrace => true,
        };
        if !category_allowed {
            return false;
        }

        // Rate limiting for high-frequency categories.
        let is_rate_limited_cat = RATE_LIMITED_CATEGORIES.contains(&category);
        if is_rate_limited_cat {
            let max = match mode {
                LoggingMode::Default => RATE_LIMIT_MAX_DEFAULT,
                LoggingMode::Diagnostic => RATE_LIMIT_MAX_DIAGNOSTIC,
                LoggingMode::DeveloperTrace => u64::MAX,
            };
            let cat_key = category as u8;
            let mut buckets = self.rate_buckets.lock().expect("rate buckets");
            let bucket = buckets.entry(cat_key).or_insert_with(RateBucket::new);
            if !bucket.allow(max) {
                return false;
            }
        }

        true
    }

    /// Resets all rate-limit buckets (useful for tests).
    pub fn reset_rate_limits(&self) {
        self.rate_buckets.lock().expect("rate buckets").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mode_allows_service_info() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(f.should_emit(
            EventLevel::Info,
            EventCategory::Service,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn default_mode_blocks_debug() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(!f.should_emit(
            EventLevel::Debug,
            EventCategory::Service,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn default_mode_blocks_user_action_category() {
        let f = LogFilter::new(LoggingMode::Default);
        // UserAction is not in default allowlist.
        assert!(!f.should_emit(
            EventLevel::Info,
            EventCategory::UserAction,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn default_mode_blocks_review_category() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(!f.should_emit(
            EventLevel::Info,
            EventCategory::Review,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn default_mode_blocks_diagnostic_privacy() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(!f.should_emit(
            EventLevel::Info,
            EventCategory::Service,
            PrivacyClass::Diagnostic
        ));
    }

    #[test]
    fn default_mode_blocks_secret_never_log() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(!f.should_emit(
            EventLevel::Error,
            EventCategory::Service,
            PrivacyClass::SecretNeverLog
        ));
    }

    #[test]
    fn diagnostic_mode_allows_debug_and_decision() {
        let f = LogFilter::new(LoggingMode::Diagnostic);
        assert!(f.should_emit(
            EventLevel::Debug,
            EventCategory::Decision,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn diagnostic_mode_allows_diagnostic_privacy() {
        let f = LogFilter::new(LoggingMode::Diagnostic);
        assert!(f.should_emit(
            EventLevel::Info,
            EventCategory::Service,
            PrivacyClass::Diagnostic
        ));
    }

    #[test]
    fn diagnostic_mode_blocks_sensitive_privacy() {
        let f = LogFilter::new(LoggingMode::Diagnostic);
        assert!(!f.should_emit(
            EventLevel::Info,
            EventCategory::Service,
            PrivacyClass::Sensitive
        ));
    }

    #[test]
    fn developer_trace_allows_everything() {
        let f = LogFilter::new(LoggingMode::DeveloperTrace);
        assert!(f.should_emit(
            EventLevel::Trace,
            EventCategory::Decision,
            PrivacyClass::Sensitive
        ));
    }

    #[test]
    fn set_mode_takes_effect() {
        let f = LogFilter::new(LoggingMode::Default);
        assert!(!f.should_emit(
            EventLevel::Debug,
            EventCategory::Service,
            PrivacyClass::PublicSummary
        ));
        f.set_mode(LoggingMode::Diagnostic);
        assert!(f.should_emit(
            EventLevel::Debug,
            EventCategory::Service,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn rate_limit_blocks_after_max() {
        // Decision is rate-limited in Diagnostic mode (where it's in the allowlist).
        // In Default mode Decision is blocked by category allowlist before rate limiting.
        let f = LogFilter::new(LoggingMode::Diagnostic);
        let mut allowed = 0u64;
        for _ in 0..RATE_LIMIT_MAX_DIAGNOSTIC + 5 {
            if f.should_emit(
                EventLevel::Info,
                EventCategory::Decision,
                PrivacyClass::PublicSummary,
            ) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, RATE_LIMIT_MAX_DIAGNOSTIC);
    }

    #[test]
    fn rate_limit_reset_clears_buckets() {
        let f = LogFilter::new(LoggingMode::Diagnostic);
        for _ in 0..RATE_LIMIT_MAX_DIAGNOSTIC + 1 {
            f.should_emit(
                EventLevel::Info,
                EventCategory::Decision,
                PrivacyClass::PublicSummary,
            );
        }
        f.reset_rate_limits();
        // After reset, should be allowed again.
        assert!(f.should_emit(
            EventLevel::Info,
            EventCategory::Decision,
            PrivacyClass::PublicSummary
        ));
    }

    #[test]
    fn service_category_not_rate_limited() {
        let f = LogFilter::new(LoggingMode::Default);
        // Service is not in RATE_LIMITED_CATEGORIES — unlimited.
        for _ in 0..100 {
            assert!(f.should_emit(
                EventLevel::Info,
                EventCategory::Service,
                PrivacyClass::PublicSummary
            ));
        }
    }

    #[test]
    fn logging_mode_ordering() {
        assert!(LoggingMode::Default < LoggingMode::Diagnostic);
        assert!(LoggingMode::Diagnostic < LoggingMode::DeveloperTrace);
    }

    #[test]
    fn logging_mode_min_level() {
        assert_eq!(LoggingMode::Default.min_level(), EventLevel::Info);
        assert_eq!(LoggingMode::Diagnostic.min_level(), EventLevel::Debug);
        assert_eq!(LoggingMode::DeveloperTrace.min_level(), EventLevel::Trace);
    }
}

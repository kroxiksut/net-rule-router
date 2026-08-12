//! Retention policies for operational logs and audit trail.
//!
//! # Separation of concerns
//!
//! | Store                | Policy               | User clear? |
//! |----------------------|----------------------|-------------|
//! | Operational logs     | `LogRetentionPolicy` | Yes (via GUI) |
//! | Audit NDJSON         | `AuditRetentionPolicy` | **No**    |
//! | `security_alerts` table | (part of `nrr_service_state.db`) | **No** |
//!
//! `ManualCleanupScope` controls what a user-triggered cleanup is allowed to touch.
//! Audit NDJSON and `security_alerts` are always excluded.

// ── Defaults ──────────────────────────────────────────────────────────────────

/// Default max age for operational logs (90 days).
pub const DEFAULT_LOG_MAX_AGE_DAYS: u32 = 90;
/// Default max total size for operational logs (50 MiB).
pub const DEFAULT_LOG_MAX_SIZE_BYTES: u64 = 50 * 1024 * 1024;
/// Default max number of log files (0 = unlimited by count).
pub const DEFAULT_LOG_MAX_FILES: u32 = 0;
/// Default max duration for explicit diagnostic mode (hours).
pub const DEFAULT_DIAGNOSTIC_MODE_MAX_HOURS: u32 = 4;

/// Default max age for audit NDJSON trail (365 days).
pub const DEFAULT_AUDIT_MAX_AGE_DAYS: u32 = 365;
/// Default max total size for audit NDJSON (50 MiB).
pub const DEFAULT_AUDIT_MAX_SIZE_BYTES: u64 = 50 * 1024 * 1024;

// ── LogRetentionPolicy ────────────────────────────────────────────────────────

/// Retention policy for operational NDJSON logs.
///
/// Configurable by the user via Settings → «Диагностика и логи».
/// Defaults are defined by the product baseline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRetentionPolicy {
    /// Delete files older than this many days. `0` = delete all.
    pub max_age_days: u32,
    /// Delete oldest files when total size exceeds this limit (bytes).
    pub max_total_size_bytes: u64,
    /// Keep at most this many log files total. `0` = no limit.
    pub max_files: u32,
    /// Maximum duration (hours) for explicit diagnostic mode before auto-expiry.
    pub diagnostic_mode_max_hours: u32,
}

impl Default for LogRetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: DEFAULT_LOG_MAX_AGE_DAYS,
            max_total_size_bytes: DEFAULT_LOG_MAX_SIZE_BYTES,
            max_files: DEFAULT_LOG_MAX_FILES,
            diagnostic_mode_max_hours: DEFAULT_DIAGNOSTIC_MODE_MAX_HOURS,
        }
    }
}

impl LogRetentionPolicy {
    /// Returns `true` if the policy is valid (non-zero size limit, reasonable age).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.max_total_size_bytes > 0
    }
}

// ── AuditRetentionPolicy ──────────────────────────────────────────────────────

/// Retention policy for security audit NDJSON files.
///
/// Configurable by the user via Settings, but **manual user-triggered cleanup
/// is not allowed** — only the scheduled service-side retention job may delete
/// audit files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRetentionPolicy {
    /// Delete audit files older than this many days.
    pub max_age_days: u32,
    /// Delete oldest audit files when total size exceeds this limit (bytes).
    pub max_total_size_bytes: u64,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: DEFAULT_AUDIT_MAX_AGE_DAYS,
            max_total_size_bytes: DEFAULT_AUDIT_MAX_SIZE_BYTES,
        }
    }
}

// ── ManualCleanupScope ────────────────────────────────────────────────────────

/// What a user-triggered manual cleanup is allowed to delete.
///
/// Audit NDJSON files and `security_alerts` table rows are **always excluded**
/// regardless of the configured scope.
#[derive(Clone, Debug)]
pub struct ManualCleanupScope {
    /// Delete operational NDJSON log files per `LogRetentionPolicy`.
    pub operational_logs: bool,
    /// Delete temporary diagnostic data (e.g., in-progress archive staging dirs).
    pub diagnostic_temp_data: bool,
    /// Delete previously exported diagnostic archives.
    pub exported_archives: bool,
}

impl Default for ManualCleanupScope {
    fn default() -> Self {
        Self {
            operational_logs: true,
            diagnostic_temp_data: true,
            exported_archives: false, // user must opt in to delete archives
        }
    }
}

impl ManualCleanupScope {
    /// Returns `true` if the scope includes at least one deletable category.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.operational_logs && !self.diagnostic_temp_data && !self.exported_archives
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_retention_policy_defaults() {
        let p = LogRetentionPolicy::default();
        assert_eq!(p.max_age_days, DEFAULT_LOG_MAX_AGE_DAYS);
        assert_eq!(p.max_total_size_bytes, DEFAULT_LOG_MAX_SIZE_BYTES);
        assert_eq!(p.max_files, DEFAULT_LOG_MAX_FILES);
        assert_eq!(
            p.diagnostic_mode_max_hours,
            DEFAULT_DIAGNOSTIC_MODE_MAX_HOURS
        );
        assert!(p.is_valid());
    }

    #[test]
    fn audit_retention_policy_defaults() {
        let p = AuditRetentionPolicy::default();
        assert_eq!(p.max_age_days, DEFAULT_AUDIT_MAX_AGE_DAYS);
        assert_eq!(p.max_total_size_bytes, DEFAULT_AUDIT_MAX_SIZE_BYTES);
    }

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn log_retention_longer_than_audit_would_be_invalid() {
        // Audit should always be preserved longer than operational logs.
        assert!(DEFAULT_AUDIT_MAX_AGE_DAYS > DEFAULT_LOG_MAX_AGE_DAYS);
    }

    #[test]
    fn manual_cleanup_scope_default_excludes_archives() {
        let s = ManualCleanupScope::default();
        assert!(s.operational_logs);
        assert!(
            !s.exported_archives,
            "archives must require explicit opt-in"
        );
    }

    #[test]
    fn manual_cleanup_scope_is_empty() {
        let s = ManualCleanupScope {
            operational_logs: false,
            diagnostic_temp_data: false,
            exported_archives: false,
        };
        assert!(s.is_empty());
    }

    #[test]
    fn log_retention_invalid_if_zero_size() {
        let p = LogRetentionPolicy {
            max_total_size_bytes: 0,
            ..LogRetentionPolicy::default()
        };
        assert!(!p.is_valid());
    }
}

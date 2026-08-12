//! Typed errors for the diagnostics/logging subsystem.
//!
//! # Failure policy summary
//!
//! | Error                     | Service action                                      |
//! |---------------------------|-----------------------------------------------------|
//! | `LogStorageUnavailable`   | Continue degraded; raise health warning             |
//! | `AuditWriteFailed`        | **Block** security-critical action or enter recovery|
//! | `RedactionFailed`         | Block output; never leak raw sensitive data         |
//! | `ExportFailed`            | Surface to GUI; operation may be retried            |
//! | `RetentionCleanupFailed`  | Log warning; next scheduled run will retry          |

use std::fmt;

/// Result alias for diagnostics operations.
pub type DiagnosticsResult<T> = Result<T, DiagnosticsError>;

/// Typed error variants for the diagnostics/logging subsystem.
#[derive(Debug)]
pub enum DiagnosticsError {
    /// The operational log storage directory or file is inaccessible.
    ///
    /// The service may continue running in degraded mode, but operational
    /// events will be dropped.  The dropped-event counter must be incremented.
    LogStorageUnavailable { reason: String },

    /// Writing an audit event to the NDJSON audit trail failed.
    ///
    /// For security-critical state transitions the caller **must** either
    /// block the action or enter an explicit recovery flow.
    AuditWriteFailed { reason: String },

    /// Applying the privacy redaction policy to an event or explain response
    /// failed.  The subsystem must never output raw sensitive data on failure;
    /// the caller must treat this as a hard block.
    RedactionFailed { reason: String },

    /// Building or writing the diagnostic archive failed.
    ExportFailed { reason: String },

    /// The scheduled retention cleanup job failed to remove expired files.
    /// The next scheduled run will retry; this is non-blocking.
    RetentionCleanupFailed { reason: String },
}

impl fmt::Display for DiagnosticsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogStorageUnavailable { reason } => {
                write!(f, "log storage unavailable: {reason}")
            }
            Self::AuditWriteFailed { reason } => {
                write!(f, "audit write failed: {reason}")
            }
            Self::RedactionFailed { reason } => {
                write!(f, "redaction failed: {reason}")
            }
            Self::ExportFailed { reason } => {
                write!(f, "diagnostic export failed: {reason}")
            }
            Self::RetentionCleanupFailed { reason } => {
                write!(f, "retention cleanup failed: {reason}")
            }
        }
    }
}

impl std::error::Error for DiagnosticsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_contains_reason() {
        let e = DiagnosticsError::LogStorageUnavailable {
            reason: "permission denied".into(),
        };
        assert!(e.to_string().contains("permission denied"));
    }

    #[test]
    fn audit_write_failed_display() {
        let e = DiagnosticsError::AuditWriteFailed {
            reason: "disk full".into(),
        };
        assert!(e.to_string().contains("audit write failed"));
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn redaction_failed_display() {
        let e = DiagnosticsError::RedactionFailed {
            reason: "serializer error".into(),
        };
        assert!(e.to_string().contains("redaction failed"));
    }

    #[test]
    fn export_failed_display() {
        let e = DiagnosticsError::ExportFailed {
            reason: "temp dir creation failed".into(),
        };
        assert!(e.to_string().contains("diagnostic export failed"));
    }

    #[test]
    fn retention_cleanup_failed_display() {
        let e = DiagnosticsError::RetentionCleanupFailed {
            reason: "I/O error".into(),
        };
        assert!(e.to_string().contains("retention cleanup failed"));
    }

    #[test]
    fn error_implements_std_error() {
        fn takes_std_error(_: &dyn std::error::Error) {}
        let e = DiagnosticsError::AuditWriteFailed { reason: "x".into() };
        takes_std_error(&e);
    }
}

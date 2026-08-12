//! Diagnostics subsystem startup policy.
//!
//! This module defines how the service behaves when the diagnostics
//! subsystem is partially or fully unavailable at startup.
//!
//! # Failure tiers
//!
//! ```text
//! Operational          All sinks available and healthy.
//! Degraded             Operational logs unavailable; audit is OK.
//!                      Service continues; health warning is raised.
//! AuditUnavailable     Audit NDJSON writer cannot initialise.
//!                      Security-critical actions are blocked until resolved.
//! FullyUnavailable     Both operational logs and audit unavailable.
//!                      Service enters recovery mode; no policy is applied.
//! ```

/// Availability state of the diagnostics subsystem after startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiagnosticsAvailability {
    /// All sinks initialised successfully.
    Operational,
    /// Operational log writer failed to initialise; audit is healthy.
    /// Service continues with a degraded health status.
    Degraded,
    /// Audit NDJSON writer failed to initialise.
    /// Security-critical actions must be blocked until the audit trail
    /// is restored or the operator explicitly acknowledges the gap.
    AuditUnavailable,
    /// Both operational logs and audit writer failed.
    /// The service cannot safely apply or audit policy changes.
    FullyUnavailable,
}

impl DiagnosticsAvailability {
    /// Returns `true` if the service may proceed with normal operation.
    ///
    /// `Degraded` is allowed because operational log loss is non-critical.
    /// `AuditUnavailable` and `FullyUnavailable` block security-critical
    /// actions.
    #[must_use]
    pub fn allows_normal_operation(self) -> bool {
        matches!(self, Self::Operational | Self::Degraded)
    }

    /// Returns `true` if security-critical state transitions are safe.
    ///
    /// Only `Operational` allows security-critical writes; all other
    /// states require the caller to block or enter recovery.
    #[must_use]
    pub fn allows_security_critical_write(self) -> bool {
        matches!(self, Self::Operational)
    }

    /// A short, developer-facing label for logging and health status.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Degraded => "degraded",
            Self::AuditUnavailable => "audit_unavailable",
            Self::FullyUnavailable => "fully_unavailable",
        }
    }
}

/// Runtime health snapshot of the diagnostics subsystem.
///
/// Returned by [`DiagnosticsQueryService::startup_health`] and included
/// in the service health DTO exposed to GUI/tray.
#[derive(Clone, Debug)]
pub struct DiagnosticsStartupHealth {
    pub availability: DiagnosticsAvailability,
    /// Human-readable reason for non-`Operational` states, for developer
    /// logs only — never surfaced verbatim to the GUI.
    pub degraded_reason: Option<String>,
    /// Number of operational log events dropped since startup.
    pub dropped_log_count: u64,
}

impl DiagnosticsStartupHealth {
    /// Constructs a fully-operational health snapshot.
    #[must_use]
    pub fn operational() -> Self {
        Self {
            availability: DiagnosticsAvailability::Operational,
            degraded_reason: None,
            dropped_log_count: 0,
        }
    }

    /// Constructs a degraded snapshot (operational logs unavailable).
    #[must_use]
    pub fn degraded(reason: impl Into<String>) -> Self {
        Self {
            availability: DiagnosticsAvailability::Degraded,
            degraded_reason: Some(reason.into()),
            dropped_log_count: 0,
        }
    }

    /// Constructs an audit-unavailable snapshot.
    #[must_use]
    pub fn audit_unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: DiagnosticsAvailability::AuditUnavailable,
            degraded_reason: Some(reason.into()),
            dropped_log_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operational_allows_normal_and_security_writes() {
        let a = DiagnosticsAvailability::Operational;
        assert!(a.allows_normal_operation());
        assert!(a.allows_security_critical_write());
    }

    #[test]
    fn degraded_allows_normal_but_not_security_writes() {
        let a = DiagnosticsAvailability::Degraded;
        assert!(a.allows_normal_operation());
        assert!(!a.allows_security_critical_write());
    }

    #[test]
    fn audit_unavailable_blocks_everything() {
        let a = DiagnosticsAvailability::AuditUnavailable;
        assert!(!a.allows_normal_operation());
        assert!(!a.allows_security_critical_write());
    }

    #[test]
    fn fully_unavailable_blocks_everything() {
        let a = DiagnosticsAvailability::FullyUnavailable;
        assert!(!a.allows_normal_operation());
        assert!(!a.allows_security_critical_write());
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(DiagnosticsAvailability::Operational.label(), "operational");
        assert_eq!(DiagnosticsAvailability::Degraded.label(), "degraded");
        assert_eq!(
            DiagnosticsAvailability::AuditUnavailable.label(),
            "audit_unavailable"
        );
        assert_eq!(
            DiagnosticsAvailability::FullyUnavailable.label(),
            "fully_unavailable"
        );
    }

    #[test]
    fn startup_health_operational_has_no_reason() {
        let h = DiagnosticsStartupHealth::operational();
        assert_eq!(h.availability, DiagnosticsAvailability::Operational);
        assert!(h.degraded_reason.is_none());
        assert_eq!(h.dropped_log_count, 0);
    }

    #[test]
    fn startup_health_degraded_has_reason() {
        let h = DiagnosticsStartupHealth::degraded("logs dir not writable");
        assert_eq!(h.availability, DiagnosticsAvailability::Degraded);
        assert!(h
            .degraded_reason
            .as_deref()
            .unwrap()
            .contains("not writable"));
    }
}

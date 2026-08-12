//! Read-only diagnostics query facade.
//!
//! [`DiagnosticsQueryService`] is the narrow interface through which GUI and
//! tray read diagnostic data.  The concrete query/response types (log entries,
//! audit entries, explain responses, pagination cursors) live in the facade
//! module's full DTO surface.
//!
//! # What lives here
//!
//! Only the trait definition and a minimal `NoopQueryService` stub that
//! returns `is_available() = false`.  This lets the GUI/tray scaffold compile
//! against a stable interface while the implementation is built out.
//!
//! # Ownership rule
//!
//! GUI and tray receive a `Arc<dyn DiagnosticsQueryService>` through the IPC
//! facade.  They must never read service-owned storage files or
//! SQLite databases directly.

use crate::startup::DiagnosticsStartupHealth;

/// Minimal read-only facade for GUI/tray diagnostics access.
///
/// The full query surface (log pagination, audit trail, explain responses,
/// alert acknowledgement) lives in the facade module. This trait is
/// intentionally minimal so the compile boundary is established without
/// blocking the event taxonomy work.
pub trait DiagnosticsQueryService: Send + Sync {
    /// Returns `true` if the diagnostics subsystem is reachable and healthy
    /// enough to serve queries.
    fn is_available(&self) -> bool;

    /// Returns the startup health snapshot for this diagnostics instance.
    fn startup_health(&self) -> DiagnosticsStartupHealth;
}

// ── NoopQueryService ──────────────────────────────────────────────────────────

/// A [`DiagnosticsQueryService`] that reports the subsystem as unavailable.
///
/// Used in scaffold code before the real implementation is wired.
pub struct NoopQueryService;

impl DiagnosticsQueryService for NoopQueryService {
    fn is_available(&self) -> bool {
        false
    }

    fn startup_health(&self) -> DiagnosticsStartupHealth {
        DiagnosticsStartupHealth::audit_unavailable(
            "NoopQueryService: no real diagnostics backend connected",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::DiagnosticsAvailability;

    #[test]
    fn noop_is_not_available() {
        let q = NoopQueryService;
        assert!(!q.is_available());
    }

    #[test]
    fn noop_startup_health_is_audit_unavailable() {
        let q = NoopQueryService;
        let h = q.startup_health();
        assert_eq!(h.availability, DiagnosticsAvailability::AuditUnavailable);
        assert!(h.degraded_reason.is_some());
    }

    #[test]
    fn noop_query_service_is_object_safe() {
        fn takes_dyn(_: &dyn DiagnosticsQueryService) {}
        takes_dyn(&NoopQueryService);
    }
}

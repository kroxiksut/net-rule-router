//! Diagnostics mock backend.
//!
//! Re-exports the mock facade from `nrr-diagnostics` and exposes
//! synchronous preview wrappers so the GUI/tray shell can fetch a snapshot
//! without holding a long-lived `MockDiagnosticsFacade` handle.
//!
//! These scaffold exports will be replaced with the real service-backed
//! implementation via IPC.

pub use nrr_diagnostics::facade::{
    DiagnosticModeStateDto, DiagnosticsFacade, DiagnosticsStatusDto, MockDiagnosticsFacade,
    MockScenario, SecurityAlertDto,
};

/// Returns the default mock facade (healthy scenario) for preview mode.
pub fn preview_diagnostics_facade() -> MockDiagnosticsFacade {
    MockDiagnosticsFacade::healthy()
}

/// Returns a one-shot preview of the diagnostics status snapshot.
///
/// Uses the `Healthy` scenario. Callers that need other scenarios should
/// construct a [`MockDiagnosticsFacade`] directly.
pub fn preview_diagnostics_status() -> DiagnosticsStatusDto {
    MockDiagnosticsFacade::healthy().get_status()
}

/// Returns a one-shot preview of the active security alerts list.
///
/// Uses the `Healthy` scenario (empty list). For alert-rich scenarios, build
/// a [`MockDiagnosticsFacade`] with [`MockScenario::ActiveTamperAlert`].
pub fn preview_active_security_alerts() -> Vec<SecurityAlertDto> {
    MockDiagnosticsFacade::healthy()
        .list_active_alerts()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_diagnostics_status_is_healthy() {
        let status = preview_diagnostics_status();
        assert!(status.overall_healthy);
        assert!(!status.stale);
        assert_eq!(status.service_health.state, "running");
        assert!(status.security_status.audit_chain_ok);
        assert_eq!(status.security_status.active_alert_count, 0);
        assert!(status.cache_health.healthy);
        assert!(status.log_health.dir_writable);
        assert!(!status.diagnostic_mode.active);
    }

    #[test]
    fn preview_active_security_alerts_healthy_is_empty() {
        let alerts = preview_active_security_alerts();
        assert!(alerts.is_empty());
    }

    #[test]
    fn preview_diagnostics_facade_is_healthy_scenario() {
        let facade = preview_diagnostics_facade();
        assert_eq!(facade.scenario, MockScenario::Healthy);
    }
}

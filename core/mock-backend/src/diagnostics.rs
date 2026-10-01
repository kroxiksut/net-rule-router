//! Diagnostics preview: the healthy snapshot a mock or preview backend shows.
//! The live GUI reads diagnostics from the service over IPC instead.

use nrr_diagnostics::facade::dto::DiagnosticsAudience;
use nrr_diagnostics::facade::MockDiagnosticsFacade;
pub use nrr_diagnostics::facade::{
    AlertListFilter, DiagnosticsDataOrigin, DiagnosticsFacade, DiagnosticsStatusDto,
    SecurityAlertDto, SecurityAlertsView,
};

/// A one-shot healthy diagnostics status.
pub fn preview_diagnostics_status() -> DiagnosticsStatusDto {
    MockDiagnosticsFacade::healthy().get_status(&DiagnosticsAudience::Machine)
}

/// A one-shot healthy (empty) list of active security alerts.
pub fn preview_active_security_alerts() -> SecurityAlertsView {
    SecurityAlertsView::fresh(
        MockDiagnosticsFacade::healthy()
            .list_alerts(AlertListFilter::Open, &DiagnosticsAudience::Machine)
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_diagnostics_status_is_healthy() {
        let status = preview_diagnostics_status();
        assert!(status.overall_healthy);
        assert!(!status.stale);
        assert_eq!(status.origin, DiagnosticsDataOrigin::Preview);
        assert_eq!(status.service_health.state, "running");
        assert!(status.security_status.audit_chain_ok);
        assert_eq!(status.security_status.active_alert_count, 0);
        assert!(status.cache_health.healthy);
        assert!(status.log_health.dir_writable);
    }

    #[test]
    fn preview_active_security_alerts_healthy_is_empty() {
        let alerts = preview_active_security_alerts();
        assert!(alerts.alerts.is_empty());
        assert!(!alerts.stale);
    }
}

//! Mock diagnostics facade for GUI scaffold.
//!
//! Provides canned responses for each scenario so the GUI can be developed
//! and tested before the real service integration.
//!
//! # Scenarios
//!
//! | Scenario            | Description                                      |
//! |---------------------|--------------------------------------------------|
//! | `Healthy`           | Everything operational, no alerts                |
//! | `ActiveTamperAlert` | Audit chain mismatch detected, alert active      |
//! | `StaleCache`        | Cache entries are stale, no rebuild in progress  |
//! | `FailClosedBlock`   | Secondary unavailable, traffic blocked           |
//! | `ServiceDegraded`   | Service running in degraded mode                 |
//! | `EmptyLogs`         | No log files exist yet                           |

use crate::error::{DiagnosticsError, DiagnosticsResult};
use crate::explain::{ExplainDataAvailability, ExplainQuery, ExplainResponse};
use crate::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, CacheHealthCard, ClearLogsRequest,
    ClearLogsResult, DiagnosticModeStateDto, DiagnosticsStatusDto, LogEntryDto, LogEntryFilter,
    LogHealthCard, SecurityAlertDto, SecurityStatusCard, ServiceHealthCard,
    SetDiagnosticModeRequest,
};
use crate::facade::pagination::{PageResult, PaginationParams};
use crate::facade::service::DiagnosticsFacade;
use crate::redaction::ExplainDetailLevel;

// ── MockScenario ──────────────────────────────────────────────────────────────

/// Canned scenario for the mock facade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MockScenario {
    Healthy,
    ActiveTamperAlert,
    StaleCache,
    FailClosedBlock,
    ServiceDegraded,
    EmptyLogs,
}

// ── MockDiagnosticsFacade ─────────────────────────────────────────────────────

/// Scaffold diagnostics facade returning canned data for GUI development.
pub struct MockDiagnosticsFacade {
    pub scenario: MockScenario,
}

impl MockDiagnosticsFacade {
    pub fn new(scenario: MockScenario) -> Self {
        Self { scenario }
    }

    pub fn healthy() -> Self {
        Self::new(MockScenario::Healthy)
    }
}

impl DiagnosticsFacade for MockDiagnosticsFacade {
    fn get_status(&self) -> DiagnosticsStatusDto {
        match self.scenario {
            MockScenario::Healthy => healthy_status(),
            MockScenario::ActiveTamperAlert => tamper_alert_status(),
            MockScenario::StaleCache => stale_cache_status(),
            MockScenario::FailClosedBlock => fail_closed_status(),
            MockScenario::ServiceDegraded => degraded_status(),
            MockScenario::EmptyLogs => empty_logs_status(),
        }
    }

    fn list_log_entries(
        &self,
        _filter: &LogEntryFilter,
        _pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        if self.scenario == MockScenario::EmptyLogs {
            return Ok(PageResult::empty());
        }
        Ok(PageResult::single_page(mock_log_entries(self.scenario)))
    }

    fn list_audit_entries(
        &self,
        _filter: &AuditEntryFilter,
        _pagination: &PaginationParams,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        Ok(PageResult::single_page(mock_audit_entries(self.scenario)))
    }

    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        if self.scenario == MockScenario::ActiveTamperAlert {
            Ok(vec![mock_tamper_alert()])
        } else {
            Ok(Vec::new())
        }
    }

    fn acknowledge_alert(&self, req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
        if req.alert_id.is_empty() {
            return Err(DiagnosticsError::AuditWriteFailed {
                reason: "alert_id must not be empty".into(),
            });
        }
        Ok(()) // mock: always succeeds
    }

    fn set_diagnostic_mode(&self, _req: &SetDiagnosticModeRequest) -> DiagnosticsResult<()> {
        Ok(()) // mock: always succeeds
    }

    fn clear_logs(&self, req: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult> {
        if req.dry_run {
            Ok(ClearLogsResult {
                files_deleted: 3,
                bytes_freed: 1024 * 1024,
                dry_run: true,
            })
        } else {
            Ok(ClearLogsResult {
                files_deleted: 3,
                bytes_freed: 1024 * 1024,
                dry_run: false,
            })
        }
    }

    fn get_explain(
        &self,
        query: &ExplainQuery,
        level: ExplainDetailLevel,
        _caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        Ok(ExplainResponse::unavailable(
            query.kind(),
            level,
            ExplainDataAvailability::ServiceUnavailable,
        ))
    }
}

// ── Canned scenario builders ──────────────────────────────────────────────────

/// Public helper for integration tests — returns the healthy status DTO.
pub fn healthy_status_for_test() -> DiagnosticsStatusDto {
    healthy_status()
}

fn healthy_status() -> DiagnosticsStatusDto {
    DiagnosticsStatusDto {
        overall_healthy: true,
        service_health: ServiceHealthCard {
            state: "running".into(),
            active_revision_id: Some("rev-preview-001".into()),
            pending_changes: 0,
        },
        security_status: SecurityStatusCard {
            audit_chain_ok: true,
            active_alert_count: 0,
            audit_write_healthy: true,
        },
        active_alerts: Vec::new(),
        cache_health: CacheHealthCard {
            entry_count: 24,
            healthy: true,
            rebuilding: false,
        },
        log_health: LogHealthCard {
            dir_writable: true,
            total_size_bytes: 256 * 1024,
            file_count: 2,
            dropped_count: 0,
            last_cleanup_at: None,
        },
        diagnostic_mode: DiagnosticModeStateDto::inactive(),
        stale: false,
    }
}

fn tamper_alert_status() -> DiagnosticsStatusDto {
    let mut s = healthy_status();
    s.overall_healthy = false;
    s.security_status.audit_chain_ok = false;
    s.security_status.active_alert_count = 1;
    s.active_alerts = vec![mock_tamper_alert()];
    s
}

fn stale_cache_status() -> DiagnosticsStatusDto {
    let mut s = healthy_status();
    s.cache_health.healthy = false;
    s.overall_healthy = false;
    s
}

fn fail_closed_status() -> DiagnosticsStatusDto {
    let mut s = healthy_status();
    s.service_health.state = "degraded".into();
    s.overall_healthy = false;
    s
}

fn degraded_status() -> DiagnosticsStatusDto {
    let mut s = healthy_status();
    s.overall_healthy = false;
    s.service_health.state = "degraded".into();
    s.stale = true;
    s
}

fn empty_logs_status() -> DiagnosticsStatusDto {
    let mut s = healthy_status();
    s.log_health.file_count = 0;
    s.log_health.total_size_bytes = 0;
    s
}

fn mock_tamper_alert() -> SecurityAlertDto {
    SecurityAlertDto {
        alert_id: "alt-preview-001".into(),
        kind: "tamper_alert_raised".into(),
        state: "active".into(),
        created_at: 1_745_000_000_000,
        updated_at: 1_745_000_000_000,
        reason_code: "integrity.audit_chain_mismatch".into(),
        raised_file: "nrr_audit_20260423-1.ndjson".into(),
        requires_action: true,
    }
}

fn mock_log_entries(scenario: MockScenario) -> Vec<LogEntryDto> {
    let mut entries = vec![
        LogEntryDto {
            event_id: "evt-preview-001".into(),
            created_at: 1_745_000_000_000,
            level: "info".into(),
            category: "service".into(),
            kind: "service.started".into(),
            message_key: "diag.service.started.summary".into(),
            has_payload: false,
            correlation_summary: Vec::new(),
        },
        LogEntryDto {
            event_id: "evt-preview-002".into(),
            created_at: 1_745_000_001_000,
            level: "info".into(),
            category: "apply".into(),
            kind: "apply.completed".into(),
            message_key: "diag.apply.completed.summary".into(),
            has_payload: false,
            correlation_summary: vec!["rev-preview-001".into()],
        },
    ];
    if scenario == MockScenario::FailClosedBlock {
        entries.push(LogEntryDto {
            event_id: "evt-preview-003".into(),
            created_at: 1_745_000_002_000,
            level: "warn".into(),
            category: "decision".into(),
            kind: "decision.fail_closed".into(),
            message_key: "diag.decision.fail_closed.summary".into(),
            has_payload: false,
            correlation_summary: Vec::new(),
        });
    }
    entries
}

fn mock_audit_entries(scenario: MockScenario) -> Vec<AuditEntryDto> {
    let mut entries = vec![AuditEntryDto {
        event_id: "adt-preview-001".into(),
        seq: 1,
        kind: "revision_activated".into(),
        created_at: 1_745_000_000_000,
        result: "success".into(),
        reason_code: "review.approved".into(),
        revision_id: Some("rev-preview-001".into()),
        has_payload_summary: false,
    }];
    if scenario == MockScenario::ActiveTamperAlert {
        entries.push(AuditEntryDto {
            event_id: "adt-preview-002".into(),
            seq: 2,
            kind: "tamper_alert_raised".into(),
            created_at: 1_745_000_001_000,
            result: "failure".into(),
            reason_code: "integrity.audit_chain_mismatch".into(),
            revision_id: None,
            has_payload_summary: false,
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_healthy_is_healthy() {
        let facade = MockDiagnosticsFacade::healthy();
        let status = facade.get_status();
        assert!(status.overall_healthy);
        assert!(status.active_alerts.is_empty());
        assert!(!status.stale);
    }

    #[test]
    fn mock_tamper_alert_has_active_alert() {
        let facade = MockDiagnosticsFacade::new(MockScenario::ActiveTamperAlert);
        let status = facade.get_status();
        assert!(!status.overall_healthy);
        assert_eq!(status.active_alerts.len(), 1);
        assert!(status.active_alerts[0].requires_action);
    }

    #[test]
    fn mock_empty_logs_returns_no_entries() {
        let facade = MockDiagnosticsFacade::new(MockScenario::EmptyLogs);
        let r = facade
            .list_log_entries(&LogEntryFilter::default(), &PaginationParams::default())
            .expect("ok");
        assert!(r.is_empty());
    }

    #[test]
    fn mock_fail_closed_has_warn_entry() {
        let facade = MockDiagnosticsFacade::new(MockScenario::FailClosedBlock);
        let r = facade
            .list_log_entries(&LogEntryFilter::default(), &PaginationParams::default())
            .expect("ok");
        assert!(r.items.iter().any(|e| e.level == "warn"));
    }

    #[test]
    fn mock_acknowledge_alert_empty_id_fails() {
        let facade = MockDiagnosticsFacade::healthy();
        let req = AcknowledgeAlertRequest {
            alert_id: String::new(),
            reason: None,
        };
        assert!(facade.acknowledge_alert(&req).is_err());
    }

    #[test]
    fn mock_clear_logs_dry_run() {
        let facade = MockDiagnosticsFacade::healthy();
        let req = ClearLogsRequest {
            include_archives: false,
            dry_run: true,
        };
        let r = facade.clear_logs(&req).expect("ok");
        assert!(r.dry_run);
        assert!(r.files_deleted > 0);
    }

    #[test]
    fn mock_set_diagnostic_mode_succeeds() {
        let facade = MockDiagnosticsFacade::healthy();
        let req = SetDiagnosticModeRequest {
            enabled: true,
            duration_ms: Some(3_600_000),
            scope: None,
            until_restart: false,
        };
        assert!(facade.set_diagnostic_mode(&req).is_ok());
    }

    #[test]
    fn mock_list_active_alerts_healthy_is_empty() {
        let facade = MockDiagnosticsFacade::healthy();
        let alerts = facade.list_active_alerts().expect("ok");
        assert!(alerts.is_empty());
    }

    #[test]
    fn mock_get_explain_returns_unavailable() {
        use crate::explain::ExplainQuery;
        use nrr_domain::decision_explain::DecisionId;

        let facade = MockDiagnosticsFacade::healthy();
        let q = ExplainQuery::HistoricalDecision {
            decision_id: DecisionId("d-001".into()),
        };
        let r = facade
            .get_explain(&q, ExplainDetailLevel::CompactUi, "")
            .expect("ok");
        assert!(!r.is_available());
    }

    #[test]
    fn all_scenarios_return_status_without_panic() {
        for scenario in [
            MockScenario::Healthy,
            MockScenario::ActiveTamperAlert,
            MockScenario::StaleCache,
            MockScenario::FailClosedBlock,
            MockScenario::ServiceDegraded,
            MockScenario::EmptyLogs,
        ] {
            let facade = MockDiagnosticsFacade::new(scenario);
            let _ = facade.get_status();
        }
    }
}

//! The integrity stack at boot, and what a start does when it cannot run.
//!
//! Fail-open by decision: when the key store, the state database or the sweep
//! fails, the service keeps routing without row signatures. Failing silently is
//! what is refused. An outage goes to the audit trail, is raised as a security
//! alert, and is named in the health breakdown; when the alert cannot be
//! recorded, the health report turns degraded, the one channel that does not
//! share the failing store.
//!
//! Called only where a key store exists. A platform without one has no check
//! that could fail, and must not raise this alert on every start.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::reason::integrity;
use nrr_diagnostics::{ActorKind, AuditEventInput, AuditEventKind, AuditEventResult, AuditSink};
use nrr_platform_api::key_store::KeyStore;
use rusqlite::Connection;

use crate::activation_coordinator::{ActivationCoordinator, ActiveIntegrityOutcome};
use crate::health::{HealthAggregator, HealthComponent};
use crate::state::ServiceHealthSeverity;
use crate::tamper_bootstrap::{
    emit_alert, run_tamper_bootstrap, TamperBootstrapError, TamperBootstrapOutcome,
};

/// The audit trail as the boot sees it.
pub type AuditTrail = dyn AuditSink<Event = AuditEventInput>;

/// Which part of the integrity stack failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutageSource {
    KeyStore,
    Storage,
    Alerts,
    /// The active-revision sweep, for one principal or for all of them.
    Sweep,
}

impl OutageSource {
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::KeyStore => "key-store",
            Self::Storage => "storage",
            Self::Alerts => "alerts",
            Self::Sweep => "sweep",
        }
    }
}

impl From<&TamperBootstrapError> for OutageSource {
    fn from(error: &TamperBootstrapError) -> Self {
        match error {
            TamperBootstrapError::KeyStore(_) => Self::KeyStore,
            TamperBootstrapError::Storage(_) => Self::Storage,
            TamperBootstrapError::Alerts(_) => Self::Alerts,
        }
    }
}

/// How far the report of an outage got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutageReport {
    /// An alert of this kind is active, raised now or by an earlier report.
    pub alert_active: bool,
    pub audited: bool,
}

/// Keeps the audit payload inside the trail's compact-summary budget.
const DETAIL_CHARS: usize = 160;

/// Where the boot reports what the integrity stack found.
pub struct BootIntegrity<'a> {
    pub alerts: &'a Arc<dyn SecurityAlertsRepository>,
    pub audit: Option<&'a AuditTrail>,
    pub health: &'a HealthAggregator,
    pub now_ms: i64,
}

impl BootIntegrity<'_> {
    /// Runs the tamper bootstrap. `None` means no signing key this start: the
    /// coordinator runs unsigned, and the outage has been reported.
    pub fn bootstrap(
        &self,
        conn: &Arc<Mutex<Connection>>,
        key_store: &dyn KeyStore,
    ) -> Option<TamperBootstrapOutcome> {
        match run_tamper_bootstrap(conn, key_store, self.alerts, self.now_ms) {
            Ok(outcome) => {
                if outcome.raised_blocking_alert {
                    tracing::warn!(
                        target: "nrr::tamper",
                        msg_key = "svc-boot-tamper-blocking-alert",
                        tampered = outcome.tampered_revision_ids.len(),
                        key_reset = outcome.key_was_reset,
                        backfilled = outcome.backfilled_rows,
                        "DB-MAC tamper bootstrap raised blocking alert(s); \
                         mutations gated until acknowledged",
                    );
                } else {
                    tracing::info!(
                        target: "nrr::tamper",
                        msg_key = "svc-boot-tamper-clean",
                        backfilled = outcome.backfilled_rows,
                        "DB-MAC tamper bootstrap clean",
                    );
                }
                Some(outcome)
            }
            Err(e) => {
                tracing::error!(
                    target: "nrr::tamper",
                    msg_key = "svc-boot-tamper-bootstrap-failed",
                    error = %e,
                    "DB-MAC tamper bootstrap failed; coordinator will run unsigned",
                );
                self.report_outage(OutageSource::from(&e), &e.to_string());
                None
            }
        }
    }

    /// Runs the active-revision sweep and raises an alert for every principal
    /// it rolled back or cleared. A principal the sweep could not check is
    /// logged on its own and reported as an outage.
    pub fn enforce_active(
        &self,
        coordinator: &ActivationCoordinator,
        bootstrap: &TamperBootstrapOutcome,
    ) {
        let outcomes = match coordinator
            .enforce_active_integrity_at_boot(bootstrap, "svc-boot-integrity-scan")
        {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(
                    target: "nrr::tamper",
                    msg_key = "svc-boot-integrity-sweep-failed",
                    error = %e,
                    "active-revision integrity sweep failed",
                );
                self.report_outage(OutageSource::Sweep, &e.to_string());
                return;
            }
        };
        let mut unchecked = 0usize;
        for (principal, outcome) in &outcomes {
            match outcome {
                ActiveIntegrityOutcome::RolledBack {
                    rejected_revision_id,
                    ..
                }
                | ActiveIntegrityOutcome::ClearedNoTrustedFallback {
                    rejected_revision_id,
                    ..
                } => self.raise_untrusted_revision(principal, rejected_revision_id, outcome),
                ActiveIntegrityOutcome::CheckFailed { error } => {
                    unchecked += 1;
                    tracing::error!(
                        target: "nrr::tamper",
                        msg_key = "integrity-sweep-principal-failed",
                        principal = %principal,
                        error = %error,
                        "could not check this principal's active revision; it stays as it was",
                    );
                }
                _ => {}
            }
        }
        if unchecked > 0 {
            self.report_outage(
                OutageSource::Sweep,
                &format!("{unchecked} principal(s) could not be checked"),
            );
        }
    }

    /// Audit, alert and health, each attempted whatever became of the others.
    pub fn report_outage(&self, source: OutageSource, detail: &str) -> OutageReport {
        tracing::error!(
            target: "nrr::tamper",
            msg_key = "integrity-check-unavailable",
            source = source.slug(),
            error = %detail,
            "integrity check unavailable; the service keeps routing without it",
        );
        let audited = self.audit_outage(source, detail);
        let alert = self.raise_outage_alert();
        let summary = format!("integrity check unavailable ({}): {detail}", source.slug());
        let (severity, message) = match &alert {
            Ok(()) => (ServiceHealthSeverity::Warning, summary),
            Err(e) => {
                tracing::error!(
                    target: "nrr::tamper",
                    error = %e,
                    "could not record the integrity-outage alert; reporting it through service health",
                );
                (
                    ServiceHealthSeverity::Degraded,
                    format!("{summary}; the security alert could not be recorded: {e}"),
                )
            }
        };
        self.health
            .record(HealthComponent::Integrity, severity, message);
        OutageReport {
            alert_active: alert.is_ok(),
            audited,
        }
    }

    /// One active alert per outage, not one per start: a key store that stays
    /// broken would otherwise pile up an alert on every boot.
    fn raise_outage_alert(&self) -> Result<(), String> {
        let kind = AuditEventKind::IntegrityCheckUnavailable.as_str();
        let active = self
            .alerts
            .list_by_state(SecurityAlertState::Active)
            .map_err(|e| e.to_string())?;
        if active.iter().any(|a| a.kind == kind) {
            return Ok(());
        }
        emit_alert(
            self.alerts,
            format!("alt-integrity-unavailable-{}", self.now_ms),
            kind,
            integrity::INTEGRITY_CHECK_UNAVAILABLE.as_str(),
            self.now_ms,
        )
        .map_err(|e| e.to_string())
    }

    fn audit_outage(&self, source: OutageSource, detail: &str) -> bool {
        let Some(audit) = self.audit else {
            tracing::warn!(
                target: "nrr::tamper",
                "no audit trail at this start; the integrity outage is not audited",
            );
            return false;
        };
        let details: String = detail.chars().take(DETAIL_CHARS).collect();
        let input = AuditEventInput {
            event_id: crate::recovery_audit::next_event_id(),
            kind: AuditEventKind::IntegrityCheckUnavailable,
            created_at: self.now_ms,
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: None,
            risk_level: Some("high".to_string()),
            result: AuditEventResult::Failure,
            reason_code: integrity::INTEGRITY_CHECK_UNAVAILABLE,
            payload_summary_json: Some(
                serde_json::json!({
                    "event": "integrity_check_unavailable",
                    "source": source.slug(),
                    "details": details,
                })
                .to_string(),
            ),
        };
        match audit.append(input) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(
                    target: "nrr::tamper",
                    error = %e,
                    "could not audit the integrity outage",
                );
                false
            }
        }
    }

    fn raise_untrusted_revision(
        &self,
        principal: &str,
        rejected_revision_id: &str,
        outcome: &ActiveIntegrityOutcome,
    ) {
        tracing::warn!(
            target: "nrr::tamper",
            msg_key = "svc-boot-revision-integrity-rejected",
            principal = %principal,
            rejected_revision_id = %rejected_revision_id,
            outcome = ?outcome,
            "active revision failed the integrity gate; rolled back to last trusted revision",
        );
        if let Err(e) = emit_alert(
            self.alerts,
            crate::integrity_review::untrusted_revision_alert_id(rejected_revision_id),
            AuditEventKind::UntrustedRevisionRejected.as_str(),
            integrity::UNTRUSTED_REVISION_REJECTED.as_str(),
            self.now_ms,
        ) {
            tracing::error!(
                target: "nrr::tamper",
                msg_key = "svc-boot-revision-alert-failed",
                error = %e,
                rejected_revision_id = %rejected_revision_id,
                "failed to raise untrusted-revision-rejected alert",
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

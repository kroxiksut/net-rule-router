//! Acknowledging and resolving security alerts.
//!
//! The one mutation kind that changes nothing about routing: it moves an
//! alert's state and writes the audit trail for who moved it. Grouped
//! together because the review summary an alert change produces is a
//! different shape from the rules one, and reading them side by side is
//! what made the executor look like one thing doing four.
//!
//! Same inherent impl, split across files.

use std::collections::BTreeSet;

use nrr_diagnostics::audit::alert::SecurityAlert;
use nrr_diagnostics::audit::kind::{ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::audit::writer::{AuditEventInput, AuditEventLocation};
use nrr_diagnostics::reason::integrity;
use nrr_shared::ipc_payloads::{IntegrityRowRef, UnverifiedRowDto};
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::{AdoptionOutcome, ScannedRow};

use super::*;
use crate::integrity_review;

/// What an acknowledgement adopted, and what it was shown but left alone.
#[derive(Clone, Copy, Debug, Default)]
struct AdoptionSummary {
    adopted: usize,
    changed: usize,
}

// Carried over from the impl this was split out of — the same code under the
// same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ProductionMutationExecutor {
    fn parse_alert_payload(
        payload: &serde_json::Value,
    ) -> Result<SecurityAlertMutationPayload, OperationError> {
        serde_json::from_value::<SecurityAlertMutationPayload>(payload.clone()).map_err(|e| {
            OperationError {
                args: Default::default(),
                code: "malformed-payload".into(),
                message: format!("SecurityAlert payload invalid: {e}"),
            }
        })
    }

    /// Executes an ack/resolve transition by `principal`. `target` must be
    /// `SecurityAlertState::Acknowledged` or `SecurityAlertState::Resolved`.
    /// Validates the source state and rejects illegal transitions.
    pub(super) fn execute_alert_state_change(
        &self,
        payload: &serde_json::Value,
        target: SecurityAlertState,
        principal: &str,
    ) -> MutationOutcome {
        let parsed = match Self::parse_alert_payload(payload) {
            Ok(p) => p,
            Err(e) => return MutationOutcome::Failed(e),
        };
        let Some(repo) = self.alerts_repo.as_ref() else {
            return MutationOutcome::Failed(OperationError {
                args: Default::default(),
                code: "alerts-store-unavailable".into(),
                message: "security alerts repository not wired".into(),
            });
        };
        let alert = match repo.find_by_id(&parsed.alert_id) {
            Ok(Some(a)) => a,
            Ok(None) => {
                return MutationOutcome::Failed(OperationError {
                    args: Default::default(),
                    code: "alert-not-found".into(),
                    message: format!("alert {} not found", parsed.alert_id),
                });
            }
            Err(e) => {
                return MutationOutcome::Failed(OperationError {
                    args: Default::default(),
                    code: "alerts-storage-failure".into(),
                    message: format!("alerts repo find_by_id failed: {e}"),
                });
            }
        };
        // Validate transitions:
        //   Active        → Acknowledged | Resolved
        //   Acknowledged  → Resolved
        //   Resolved      → (none)
        //   Superseded    → (none)
        let allowed = matches!(
            (alert.state, target),
            (SecurityAlertState::Active, SecurityAlertState::Acknowledged)
                | (SecurityAlertState::Active, SecurityAlertState::Resolved)
                | (
                    SecurityAlertState::Acknowledged,
                    SecurityAlertState::Resolved
                )
        );
        if !allowed {
            return MutationOutcome::Failed(OperationError {
                args: Default::default(),
                code: "illegal-state-transition".into(),
                message: format!(
                    "cannot transition alert {} from {} to {}",
                    parsed.alert_id, alert.state, target,
                ),
            });
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(alert.updated_at);
        // Recorded before the state moves: an acknowledgement the trail cannot
        // show did not happen.
        let recorded = match self.record_alert_state_change(&alert, target, principal, now_ms) {
            Ok(location) => location,
            Err(e) => return MutationOutcome::Failed(e),
        };
        if let Err(e) = repo.update_state(
            &parsed.alert_id,
            target,
            recorded.seq,
            &recorded.file_name,
            now_ms,
        ) {
            return MutationOutcome::Failed(OperationError {
                args: Default::default(),
                code: "alerts-storage-failure".into(),
                message: format!("alerts update_state failed: {e}"),
            });
        }
        // Acknowledging a DB tamper / key-reset alert adopts exactly the rows
        // the dialog listed, and only those still holding the content shown.
        let adoption = if crate::tamper_bootstrap::is_blocking_alert_kind(&alert.kind) {
            self.adopt_acknowledged_rows(&alert, parsed.adopt_rows.as_deref(), repo, now_ms)
        } else {
            AdoptionSummary::default()
        };
        // Every session re-reads the list: the gate is machine-wide, and the
        // adoption may have raised alerts for rows changed since shown.
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(StatusUpdateEvent::SecurityAlertsChanged);
        }
        let action_slug = match target {
            SecurityAlertState::Acknowledged => "acknowledged",
            SecurityAlertState::Resolved => "resolved",
            _ => "unchanged",
        };
        MutationOutcome::Completed(serde_json::json!({
            "outcome": format!("alert-{action_slug}"),
            "alert-id": parsed.alert_id,
            "previous-state": alert.state.as_str(),
            "new-state": target.as_str(),
            "updated-at-ms": now_ms,
            "reason": parsed.reason.unwrap_or_default(),
            "rows-adopted": adoption.adopted,
            "rows-changed": adoption.changed,
        }))
    }

    /// Writes the audit event for an alert moving to `target` and says where it
    /// landed. Without a wired audit trail there is no line to point at, and
    /// the alert keeps an empty reference rather than an invented one.
    fn record_alert_state_change(
        &self,
        alert: &SecurityAlert,
        target: SecurityAlertState,
        principal: &str,
        now_ms: i64,
    ) -> Result<AuditEventLocation, OperationError> {
        let (kind, reason) = match target {
            SecurityAlertState::Resolved => (
                AuditEventKind::TamperAlertResolved,
                integrity::ALERT_RESOLVED,
            ),
            _ => (
                AuditEventKind::TamperAlertAcknowledged,
                integrity::ALERT_ACKNOWLEDGED,
            ),
        };
        let Some(writer) = self.audit_writer.as_ref() else {
            return Ok(AuditEventLocation {
                file_name: String::new(),
                seq: 0,
            });
        };
        writer
            .append_located(AuditEventInput {
                event_id: crate::production_ipc_audit::next_audit_event_id(),
                kind,
                created_at: now_ms,
                actor_kind: ActorKind::User,
                actor_id_hash: nrr_diagnostics::audit::actor_id_hash(principal),
                revision_id: None,
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: reason,
                payload_summary_json: Some(
                    serde_json::json!({
                        "alert_id": alert.alert_id,
                        "alert_kind": alert.kind,
                        "previous_state": alert.state.as_str(),
                    })
                    .to_string(),
                ),
            })
            .map_err(|e| OperationError {
                args: Default::default(),
                code: "audit-write-failed".into(),
                message: format!("could not record the alert change: {e}"),
            })
    }

    /// The rows the dry-run of an acknowledgement lists, from a live scan.
    pub(super) fn alert_unverified_rows(
        &self,
        payload: &serde_json::Value,
    ) -> Vec<UnverifiedRowDto> {
        let Ok(parsed) = Self::parse_alert_payload(payload) else {
            return Vec::new();
        };
        let Some(repo) = self.alerts_repo.as_ref() else {
            return Vec::new();
        };
        let Ok(Some(alert)) = repo.find_by_id(&parsed.alert_id) else {
            return Vec::new();
        };
        if !crate::tamper_bootstrap::is_blocking_alert_kind(&alert.kind) {
            return Vec::new();
        }
        match self.scope_of(&alert, repo.as_ref()) {
            Ok(scope) => scope.iter().map(integrity_review::row_dto).collect(),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::tamper",
                    alert_id = %alert.alert_id,
                    error = %e,
                    "could not list the rows an acknowledgement would adopt",
                );
                Vec::new()
            }
        }
    }

    /// The rows acknowledging `alert` adopts, from a live scan.
    fn scope_of(
        &self,
        alert: &SecurityAlert,
        repo: &dyn SecurityAlertsRepository,
    ) -> Result<Vec<ScannedRow>, String> {
        let scan = self
            .coordinator
            .integrity_scan()
            .map_err(|e| e.to_string())?;
        // Unreadable alerts would drop the exclusion of rows under an active
        // tamper alert, so that is a refusal, not an empty list.
        let active = repo
            .list_by_state(SecurityAlertState::Active)
            .map_err(|e| e.to_string())?;
        Ok(integrity_review::alert_scope(
            alert,
            &scan,
            self.coordinator.key_reset_pending(),
            &active,
        )
        .into_iter()
        .cloned()
        .collect())
    }

    fn adopt_acknowledged_rows(
        &self,
        alert: &SecurityAlert,
        shown: Option<&[IntegrityRowRef]>,
        repo: &Arc<dyn SecurityAlertsRepository>,
        now_ms: i64,
    ) -> AdoptionSummary {
        let summary = match shown {
            // An acknowledgement that listed nothing adopts nothing, and a key
            // reset it names stays pending, so its alert comes back next start.
            None => {
                tracing::info!(
                    target: "nrr::tamper",
                    alert_id = %alert.alert_id,
                    "alert acknowledged without a row list; nothing adopted",
                );
                AdoptionSummary::default()
            }
            Some(shown) => match self.adopt_shown(alert, shown, repo.as_ref()) {
                Ok(summary) => {
                    // By kind, not id: every key loss raises its own alert id.
                    if alert.kind == AuditEventKind::KeyResetWithExistingData.as_str() {
                        if let Err(e) = self.coordinator.clear_key_reset_marker() {
                            tracing::warn!(
                                target: "nrr::tamper",
                                alert_id = %alert.alert_id,
                                error = %e,
                                "rows re-signed but the key-reset marker could not be cleared; \
                                 the next boot will skip the integrity sweep again",
                            );
                        }
                    }
                    summary
                }
                // A failed adoption keeps the marker, so the next boot still
                // spares the rows.
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::tamper",
                        msg_key = "prod-alert-resign-failed",
                        alert_id = %alert.alert_id,
                        error = %e,
                        "re-sign after tamper-alert acknowledgement failed",
                    );
                    AdoptionSummary::default()
                }
            },
        };
        self.raise_alerts_for_remaining_rows(repo, now_ms);
        summary
    }

    fn adopt_shown(
        &self,
        alert: &SecurityAlert,
        shown: &[IntegrityRowRef],
        repo: &dyn SecurityAlertsRepository,
    ) -> Result<AdoptionSummary, String> {
        let scope = self.scope_of(alert, repo)?;
        let shown_set: BTreeSet<&IntegrityRowRef> = shown.iter().collect();
        let to_adopt: Vec<&ScannedRow> = scope
            .iter()
            .filter(|row| shown_set.contains(&integrity_review::row_ref(row)))
            .collect();
        let requests: Vec<_> = to_adopt
            .iter()
            .map(|row| integrity_review::adoption_request(row))
            .collect();
        let outcomes = self
            .coordinator
            .adopt_rows(&requests)
            .map_err(|e| e.to_string())?;
        let adopted: Vec<String> = to_adopt
            .iter()
            .zip(&outcomes)
            .filter(|(_, o)| matches!(o, AdoptionOutcome::Adopted))
            .map(|(row, _)| integrity_review::row_label(row))
            .collect();
        // Shown, still failing, but no longer holding the content that was shown.
        let changed = match self.coordinator.integrity_scan() {
            Ok(now) => shown
                .iter()
                .filter(|s| {
                    now.iter().any(|r| {
                        r.verification == HmacVerification::Tampered
                            && integrity_review::same_row(&integrity_review::row_ref(r), s)
                            && r.fingerprint != s.content_hash
                    })
                })
                .count(),
            Err(_) => 0,
        };
        let ignored = shown.len().saturating_sub(adopted.len() + changed);
        if adopted.is_empty() {
            tracing::info!(
                target: "nrr::tamper",
                msg_key = "prod-alert-resign-ok",
                alert_id = %alert.alert_id,
                re_signed = 0,
                "re-signed revision rows on tamper-alert acknowledgement",
            );
        } else {
            // Named at warn level: the acknowledgement makes their current
            // contents trusted, and that must stay visible afterwards.
            tracing::warn!(
                target: "nrr::tamper",
                msg_key = "prod-alert-resign-adopted-tampered",
                alert_id = %alert.alert_id,
                re_signed = adopted.len(),
                adopted = adopted.len(),
                revisions = %adopted.join(", "),
                "tamper-alert acknowledgement re-signed revision rows that did NOT match \
                 their stored signature; their current contents are now trusted",
            );
        }
        if changed > 0 || ignored > 0 {
            tracing::warn!(
                target: "nrr::tamper",
                msg_key = "prod-alert-adopt-skipped",
                alert_id = %alert.alert_id,
                changed,
                ignored,
                "acknowledgement named rows it did not adopt: changed since shown, \
                 or not under this alert",
            );
        }
        Ok(AdoptionSummary {
            adopted: adopted.len(),
            changed,
        })
    }

    /// Whatever still fails verification gets the alert for its current
    /// content, a row edited after the dialog showed it included. Skipped
    /// while a key reset is pending: every old-key row fails then, and the
    /// reset alert already covers them.
    fn raise_alerts_for_remaining_rows(
        &self,
        repo: &Arc<dyn SecurityAlertsRepository>,
        now_ms: i64,
    ) {
        if self.coordinator.key_reset_pending() {
            return;
        }
        let scan = match self.coordinator.integrity_scan() {
            Ok(scan) => scan,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::tamper",
                    error = %e,
                    "could not rescan after acknowledgement; remaining rows are alerted at next start",
                );
                return;
            }
        };
        for row in scan
            .iter()
            .filter(|r| r.verification == HmacVerification::Tampered)
        {
            if let Err(e) = crate::tamper_bootstrap::raise_tamper_alert(repo, row, now_ms) {
                tracing::warn!(
                    target: "nrr::tamper",
                    revision_id = %integrity_review::row_label(row),
                    error = %e,
                    "could not raise the tamper alert for a row left unadopted",
                );
            }
        }
    }

    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn alert_review_summary(
        &self,
        payload: &serde_json::Value,
        target: SecurityAlertState,
    ) -> ReviewSummaryResponse {
        let parsed = match Self::parse_alert_payload(payload) {
            Ok(p) => p,
            Err(e) => return malformed_summary(&e.message),
        };
        let action = match target {
            SecurityAlertState::Acknowledged => "acknowledge",
            SecurityAlertState::Resolved => "resolve",
            _ => "no-op",
        };
        ReviewSummaryResponse {
            diff_summary: format!("{action} security alert {}", parsed.alert_id),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::Low,
            requires_review: true,
            changed_fields: vec![format!("alert-id:{}", parsed.alert_id)],
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }

    // ── PresetImport pipeline ───────────────────────────────────────────────
}

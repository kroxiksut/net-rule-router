//! Acknowledging and resolving security alerts.
//!
//! The one mutation kind that changes nothing about routing: it moves an
//! alert's state and writes the audit trail for who moved it. Grouped
//! together because the review summary an alert change produces is a
//! different shape from the rules one, and reading them side by side is
//! what made the executor look like one thing doing four.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

// Carried over from the impl this was split out of — the same code under the
// same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ProductionMutationExecutor {
    fn parse_alert_payload(
        payload: &serde_json::Value,
    ) -> Result<SecurityAlertMutationPayload, OperationError> {
        serde_json::from_value::<SecurityAlertMutationPayload>(payload.clone()).map_err(|e| {
            OperationError {
                code: "malformed-payload".into(),
                message: format!("SecurityAlert payload invalid: {e}"),
            }
        })
    }

    /// Executes an ack/resolve transition. `target` must
    /// be `SecurityAlertState::Acknowledged` or `SecurityAlertState::Resolved`.
    /// Validates the source state and rejects illegal transitions.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn execute_alert_state_change(
        &self,
        payload: &serde_json::Value,
        target: SecurityAlertState,
    ) -> MutationOutcome {
        let parsed = match Self::parse_alert_payload(payload) {
            Ok(p) => p,
            Err(e) => return MutationOutcome::Failed(e),
        };
        let Some(repo) = self.alerts_repo.as_ref() else {
            return MutationOutcome::Failed(OperationError {
                code: "alerts-store-unavailable".into(),
                message: "security alerts repository not wired".into(),
            });
        };
        let alert = match repo.find_by_id(&parsed.alert_id) {
            Ok(Some(a)) => a,
            Ok(None) => {
                return MutationOutcome::Failed(OperationError {
                    code: "alert-not-found".into(),
                    message: format!("alert {} not found", parsed.alert_id),
                });
            }
            Err(e) => {
                return MutationOutcome::Failed(OperationError {
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
        // TODO:: the schema's ack_event_seq /
        // ack_file (and resolved_event_seq / resolved_file) are meant
        // to point at the audit NDJSON line that recorded this state
        // change. The current `AuditWriter::append` API does not return
        // the assigned seq/filename, and `AuditEventKind` does not yet
        // have a `TamperAlertResolved` variant. Until the audit
        // surface is extended, we record synthetic placeholders that
        // are unique per call but do not point at a real NDJSON line.
        // Acknowledgement is the only state change that today has a
        // matching `TamperAlertAcknowledged` event kind, so a future
        // closure can wire the ack path without touching the schema.
        let synthetic_seq = now_ms.unsigned_abs();
        let synthetic_file = "nrr_ipc_pending_audit.ndjson";
        if let Err(e) = repo.update_state(
            &parsed.alert_id,
            target,
            synthetic_seq,
            synthetic_file,
            now_ms,
        ) {
            return MutationOutcome::Failed(OperationError {
                code: "alerts-storage-failure".into(),
                message: format!("alerts update_state failed: {e}"),
            });
        }
        // Acknowledging (or resolving) a DB
        // tamper / key-reset alert means the user has reviewed the
        // current rules and accepts the DB state as authoritative. Stamp
        // it: re-sign every revision row so the next service load
        // verifies clean and the mutation gate lifts. The ack itself
        // already succeeded; a re-sign failure is logged but does not
        // fail the mutation (the gate is lifted by the state change, and
        // a still-tampered row would simply be re-flagged next boot,
        // deduped against the now-acknowledged alert).
        if crate::tamper_bootstrap::is_blocking_alert_kind(&alert.kind) {
            match self.coordinator.re_sign_all_revisions() {
                // Rows that did NOT match their signature before this call are
                // named, at warn level: acknowledging the alert adopts their
                // current contents as legitimate, and that decision must be
                // visible afterwards rather than buried in a row count.
                Ok(report) if !report.adopted_tampered.is_empty() => tracing::warn!(
                    target: "nrr::tamper",
                    alert_id = %parsed.alert_id,
                    re_signed = report.re_signed,
                    adopted = report.adopted_tampered.len(),
                    revisions = %report.adopted_tampered.join(", "),
                    "tamper-alert acknowledgement re-signed revision rows that did NOT match                      their stored signature — their current contents are now trusted",
                ),
                Ok(report) => tracing::info!(
                    target: "nrr::tamper",
                    alert_id = %parsed.alert_id,
                    re_signed = report.re_signed,
                    "re-signed revision rows on tamper-alert acknowledgement",
                ),
                Err(e) => tracing::warn!(
                    target: "nrr::tamper",
                    alert_id = %parsed.alert_id,
                    error = ?e,
                    "re-sign after tamper-alert acknowledgement failed",
                ),
            }
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
        }))
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

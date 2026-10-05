//! Restarting the audit chain over breaks an administrator was shown.
//!
//! The dry-run lists the breaks from the service's own verification; the
//! confirm echoes their digest, and the writer restarts only while the chain
//! still yields it. The restart is sealed with a key derived from the
//! service's integrity key, so nobody who merely writes the audit directory
//! can produce one the verifier honours.

use nrr_diagnostics::audit::{AuditChainRestartError, AuditChainRestartRequest};
use nrr_shared::ipc_payloads::{
    AuditChainBreakDto, AuditChainRestartPayload, AuditChainRestartPreviewDto,
};

use super::*;

impl ProductionMutationExecutor {
    /// What a restart would paper over; `None` when the audit trail is not
    /// wired.
    pub(super) fn audit_chain_restart_preview(&self) -> Option<AuditChainRestartPreviewDto> {
        let writer = self.audit_writer.as_ref()?;
        let verdict = writer.verify_chain(self.coordinator.audit_restart_key().as_ref());
        Some(AuditChainRestartPreviewDto {
            break_count: verdict.break_count as u64,
            breaks: verdict
                .breaks
                .iter()
                .map(|b| AuditChainBreakDto {
                    kind: b.kind.slug().to_string(),
                    file: b.file_name.clone(),
                    line: b.line as u64,
                    seq: b.seq,
                })
                .collect(),
            breaks_digest: verdict.breaks_digest.unwrap_or_default(),
        })
    }

    pub(super) fn audit_chain_restart_summary(&self) -> ReviewSummaryResponse {
        let breaks = self
            .audit_chain_restart_preview()
            .map_or(0, |p| p.break_count);
        ReviewSummaryResponse {
            diff_summary: format!("restart the audit chain over {breaks} break(s)"),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::High,
            requires_review: true,
            changed_fields: Vec::new(),
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            extended_sections: Vec::new(),
            cross_set_duplicates: Vec::new(),
        }
    }

    /// `principal` is the confirming administrator, whom the restart names.
    pub(super) fn execute_audit_chain_restart(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> MutationOutcome {
        let failed = |code: &str, message: String| {
            MutationOutcome::Failed(OperationError {
                args: Default::default(),
                code: code.into(),
                message,
            })
        };
        let parsed = match serde_json::from_value::<AuditChainRestartPayload>(payload.clone()) {
            Ok(p) => p,
            Err(e) => {
                return failed(
                    "malformed-payload",
                    format!("AuditChainRestart payload invalid: {e}"),
                )
            }
        };
        let Some(writer) = self.audit_writer.as_ref() else {
            return failed("audit-unavailable", "audit trail not wired".into());
        };
        // Without the key a restart could not be told from a forged one.
        let Some(key) = self.coordinator.audit_restart_key() else {
            return failed(
                "restart-key-unavailable",
                "no integrity key to seal a chain restart with".into(),
            );
        };
        let request = AuditChainRestartRequest {
            event_id: crate::production_ipc_audit::next_audit_event_id(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            actor_id_hash: nrr_diagnostics::audit::actor_id_hash(principal),
        };
        match writer.restart_chain(&key, &parsed.breaks_digest, request) {
            Ok(covered) => {
                let first = covered.breaks.first();
                tracing::warn!(
                    target: "nrr::audit",
                    msg_key = "audit-chain-restarted",
                    breaks = covered.break_count,
                    first_file = first.map(|b| b.file_name.as_str()).unwrap_or_default(),
                    first_line = first.map_or(0, |b| b.line),
                    "audit chain restarted by an administrator over the breaks shown",
                );
                MutationOutcome::Completed(serde_json::json!({
                    "outcome": "audit-chain-restarted",
                    "breaks": covered.break_count,
                }))
            }
            Err(AuditChainRestartError::Intact) => {
                failed("audit-chain-intact", "the audit chain is intact".into())
            }
            Err(AuditChainRestartError::ChangedSinceShown) => failed(
                "audit-chain-changed",
                "the audit chain changed since the breaks were shown".into(),
            ),
            Err(AuditChainRestartError::Write(e)) => failed("audit-write-failed", e.to_string()),
        }
    }
}

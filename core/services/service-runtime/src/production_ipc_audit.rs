//! The audit trail for privileged IPC requests.
//!
//! The router records every state-changing request BEFORE the handler runs, and
//! treats a failed write as a refusal: an operation that cannot be accounted for
//! does not happen. That safeguard was inert — the only implementation of the
//! emitter trait in the tree was the no-op one, wired into both production
//! builds, so the trail existed on paper and nowhere else.
//!
//! What is written is deliberately thin: which operation, which class, whether
//! the caller was elevated, and a hash of who they are. The payload itself is
//! not — a rules payload carries the user's hostnames, and the audit file is a
//! security record, not a copy of their policy.

use std::sync::Arc;

use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::audit::writer::AuditEventInput;
use nrr_diagnostics::reason;
use nrr_diagnostics::sink::AuditSink;
use nrr_diagnostics::{ActorKind, AuditEventResult};

use crate::ipc::{IpcAuditEmitter, IpcRequestContext, IpcRequestEnvelope};
use nrr_shared::ipc::IpcOperationName;

/// Writes privileged-request records into the audit NDJSON.
pub struct ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput>,
{
    sink: Arc<S>,
}

impl<S> ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput>,
{
    pub fn new(sink: Arc<S>) -> Self {
        Self { sink }
    }
}

impl<S> IpcAuditEmitter for ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput> + Send + Sync,
{
    fn record_request(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<(), String> {
        let summary = serde_json::json!({
            "operation": request.operation.slug(),
            "class": request.operation_class.slug(),
            "elevated": ctx.caller_is_elevated,
            "profile": format!("{:?}", ctx.client_profile),
        })
        .to_string();
        self.sink
            .append(AuditEventInput {
                event_id: next_audit_event_id(),
                kind: AuditEventKind::PrivilegedRequestAdmitted,
                created_at: now_ms(),
                actor_kind: ActorKind::User,
                // Hashed, never the SID itself: the trail must survive being
                // read by someone who should not learn who is on this machine.
                actor_id_hash: hash_actor(ctx.caller_stored()),
                revision_id: None,
                risk_level: risk_of(request),
                result: AuditEventResult::Success,
                reason_code: reason::service::IPC_PRIVILEGED_REQUEST,
                payload_summary_json: Some(summary),
            })
            .map_err(|e| e.to_string())
    }
}

/// Risk level for a request the pre-execution audit can judge from its payload.
///
/// A rule revision gets a full `RiskAssessment` through review; a route-policy
/// update never goes through review, so the same catalogue's two relevant
/// signals were computed for nobody. Arming fail-closed or the blanket block is
/// exactly what `FailClosedActivation` describes (High), and any other change
/// of behaviour mode is `DefaultBehaviorChanged` (Medium).
///
/// This reads the REQUESTED value, not a diff — a pre-execution entry records
/// what was asked for, which is what an operator reconstructing the day needs.
fn risk_of(request: &IpcRequestEnvelope) -> Option<String> {
    use nrr_domain::revision::RiskLevel;

    if request.operation != IpcOperationName::RoutePolicyUpdate {
        return None;
    }
    let payload = &request.payload;
    let mode = payload.get("mode").and_then(|v| v.as_str());
    let flag = |name: &str| {
        payload
            .get(name)
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };

    let level = if mode == Some("strict-secondary-fail-closed")
        || flag("kill-switch-block-all")
        || flag("block-secondary-when-unavailable")
    {
        RiskLevel::High
    } else if mode.is_some() {
        RiskLevel::Medium
    } else {
        return None;
    };
    Some(level.to_string())
}

/// `adt-<nanos>-<counter>`, matching what the other audit paths emit.
fn next_audit_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("adt-{nanos:x}-{n:x}")
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hash_actor(stored: &str) -> Option<String> {
    if stored.is_empty() {
        return None;
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(stored.as_bytes());
    Some(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<AuditEventInput>>,
        fail: bool,
    }

    impl AuditSink for RecordingSink {
        type Event = AuditEventInput;
        fn append(
            &self,
            input: AuditEventInput,
        ) -> Result<(), nrr_diagnostics::error::DiagnosticsError> {
            if self.fail {
                return Err(nrr_diagnostics::error::DiagnosticsError::AuditWriteFailed {
                    reason: "disk full".into(),
                });
            }
            self.events
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(input);
            Ok(())
        }
    }

    fn envelope() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: crate::IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: nrr_shared::ipc::IpcOperationName::MutationSubmit,
            operation_class: crate::ipc::IpcOperationClass::MutationRequest,
            confirmation_token: Some("tok".into()),
            payload: serde_json::json!({"secret-host": "example.internal"}),
        }
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: nrr_shared::ipc::IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: nrr_domain::user_principal::UserPrincipal::from_windows_sid(
                "S-1-5-21-A",
            )
            .ok(),
            caller_pid: None,
        }
    }

    #[test]
    fn the_record_names_the_operation_and_never_the_payload() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = ProductionIpcAuditEmitter::new(Arc::clone(&sink));
        emitter.record_request(&envelope(), &ctx()).expect("write");

        let events = sink.events.lock().unwrap_or_else(|p| p.into_inner());
        let summary = events[0].payload_summary_json.clone().expect("a summary");
        assert!(summary.contains("mutation.submit"));
        assert!(
            !summary.contains("example.internal"),
            "the audit file is a security record, not a copy of the user's policy: {summary}",
        );
        assert_ne!(
            events[0].actor_id_hash.as_deref(),
            Some("S-1-5-21-A"),
            "the actor is hashed, never stored raw",
        );
    }

    #[test]
    fn a_failed_write_is_reported_so_the_router_can_refuse() {
        // The router turns this into a refusal: an operation that cannot be
        // accounted for does not happen.
        let sink = Arc::new(RecordingSink {
            fail: true,
            ..Default::default()
        });
        let emitter = ProductionIpcAuditEmitter::new(sink);
        assert!(emitter.record_request(&envelope(), &ctx()).is_err());
    }

    fn policy_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            operation: IpcOperationName::RoutePolicyUpdate,
            operation_class: crate::ipc::IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
            ..envelope()
        }
    }

    #[test]
    fn arming_a_blocking_posture_is_recorded_as_high_risk() {
        // A route-policy update never goes through review, so the risk
        // catalogue's two relevant signals were computed for nobody.
        for payload in [
            serde_json::json!({ "mode": "strict-secondary-fail-closed" }),
            serde_json::json!({ "mode": "prefer-primary", "kill-switch-block-all": true }),
            serde_json::json!({
                "mode": "prefer-primary",
                "block-secondary-when-unavailable": true
            }),
        ] {
            assert_eq!(
                risk_of(&policy_envelope(payload.clone())).as_deref(),
                Some("high"),
                "{payload} arms a posture that can cut the user's traffic"
            );
        }
    }

    #[test]
    fn an_ordinary_mode_change_is_medium_and_other_operations_carry_no_risk() {
        assert_eq!(
            risk_of(&policy_envelope(
                serde_json::json!({ "mode": "prefer-primary" })
            ))
            .as_deref(),
            Some("medium")
        );
        // The emitter judges only what it can read from a payload it
        // understands; everything else stays unscored rather than guessed.
        assert_eq!(risk_of(&envelope()), None);
    }
}

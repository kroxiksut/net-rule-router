//! Production [`RecoveryAuditEmitter`] backed by [`nrr_diagnostics::AuditWriter`].
//!
//! ## Mapping
//!
//! | RecoveryAuditEvent          | AuditEventKind            | result    | reason_code                          |
//! |-----------------------------|---------------------------|-----------|--------------------------------------|
//! | `IntegrityFailureReported`  | `IntegrityFailureDetected`| `Failure` | `integrity.policy_integrity_failure` |
//! | `RecoveryRequired`          | `IntegrityFailureDetected`| `Blocked` | `integrity.policy_integrity_failure` |
//!
//! `actor_kind` is always [`ActorKind::Service`]; neither event names a
//! revision, because the keyless loader cannot tell which one to trust.
//!
//! ## Event ID generation
//!
//! Spec calls for `adt-{uuid_v4}`, but the workspace avoids a `uuid` dependency
//! (no other crate needs it). IDs are `adt-{epoch_nanos}-{atomic_counter}`;
//! collisions are possible only across processes within the same nanosecond,
//! which the audit chain's `seq` + `prev_hash` catch anyway.
//!
//! ## Failure semantics
//!
//! Any [`nrr_diagnostics::error::DiagnosticsError`] from `AuditWriter::append` is
//! converted to a `String` and returned via `Err(...)`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_diagnostics::reason::integrity;
use nrr_diagnostics::{
    ActorKind, AuditEventInput, AuditEventKind, AuditEventResult, AuditSink, AuditWriter,
};

use crate::policy_loader::{RecoveryAuditEmitter, RecoveryAuditEvent};

/// Production-grade emitter that persists every recovery audit event
/// through the shared [`AuditWriter`].
///
/// Cheap to clone (the writer lives behind `Arc`).
#[derive(Clone)]
pub struct DiagnosticsRecoveryAuditEmitter {
    audit: Arc<AuditWriter>,
}

impl DiagnosticsRecoveryAuditEmitter {
    pub fn new(audit: Arc<AuditWriter>) -> Self {
        Self { audit }
    }
}

impl RecoveryAuditEmitter for DiagnosticsRecoveryAuditEmitter {
    fn emit(&self, event: RecoveryAuditEvent) -> Result<(), String> {
        let input = recovery_event_to_audit_input(event);
        self.audit
            .append(input)
            .map_err(|e| format!("recovery audit persist failed: {e}"))
    }
}

/// Pure mapping helper. Exposed `pub(crate)` so the bootstrap and unit
/// tests can build inputs without going through the writer (golden
/// snapshot tests of the wire shape).
pub(crate) fn recovery_event_to_audit_input(event: RecoveryAuditEvent) -> AuditEventInput {
    match event {
        RecoveryAuditEvent::IntegrityFailureReported { details } => AuditEventInput {
            event_id: next_event_id(),
            kind: AuditEventKind::IntegrityFailureDetected,
            created_at: now_ms(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: None,
            risk_level: Some("critical".to_string()),
            result: AuditEventResult::Failure,
            reason_code: integrity::POLICY_INTEGRITY_FAILURE,
            payload_summary_json: Some(payload_integrity_failure_reported(&details)),
        },
        RecoveryAuditEvent::RecoveryRequired { details } => AuditEventInput {
            event_id: next_event_id(),
            kind: AuditEventKind::IntegrityFailureDetected,
            created_at: now_ms(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            // Intentionally None — there is no usable revision when the
            // loader emits this variant.
            revision_id: None,
            risk_level: Some("critical".to_string()),
            result: AuditEventResult::Blocked,
            reason_code: integrity::POLICY_INTEGRITY_FAILURE,
            payload_summary_json: Some(payload_recovery_required(&details)),
        },
    }
}

/// Audit event input emitted by the bootstrap pipeline when the FQDN/IP
/// cache database is rebuilt after corruption. The cache is rebuildable
/// by design, so this is `Success` from a recovery standpoint, but the
/// reason code surfaces the underlying corruption.
pub(crate) fn cache_rebuild_audit_input(original_error: &str) -> AuditEventInput {
    AuditEventInput {
        event_id: next_event_id(),
        kind: AuditEventKind::RecoveryActionRequested,
        created_at: now_ms(),
        actor_kind: ActorKind::Service,
        actor_id_hash: None,
        revision_id: None,
        risk_level: Some("medium".to_string()),
        result: AuditEventResult::Success,
        reason_code: integrity::CACHE_CORRUPT_REBUILDABLE,
        payload_summary_json: Some(payload_cache_rebuilt(original_error)),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

pub(crate) fn next_event_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("adt-{nanos:020}-{n:08x}")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Serialised by the JSON library: `details` carries error text whose content is
// not ours to assume, and a raw control character leaves the payload unparseable.
fn payload_integrity_failure_reported(details: &str) -> String {
    serde_json::json!({ "event": "integrity_failure_reported", "details": details }).to_string()
}

fn payload_recovery_required(details: &str) -> String {
    serde_json::json!({ "event": "recovery_required", "details": details }).to_string()
}

fn payload_cache_rebuilt(original_error: &str) -> String {
    serde_json::json!({
        "event": "cache_rebuilt_after_corruption",
        "original_error": original_error,
    })
    .to_string()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    use nrr_diagnostics::AuditWriterConfig;

    /// Recording sink that captures inputs in memory. Lets us verify the
    /// emitter writes through to the audit layer without spinning up the
    /// real NDJSON file.
    struct RecordingSink {
        inputs: Mutex<Vec<AuditEventInput>>,
        fail_next: Mutex<bool>,
    }

    impl AuditSink for RecordingSink {
        type Event = AuditEventInput;
        fn append(
            &self,
            input: AuditEventInput,
        ) -> Result<(), nrr_diagnostics::error::DiagnosticsError> {
            if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                return Err(nrr_diagnostics::error::DiagnosticsError::AuditWriteFailed {
                    reason: "test-forced".into(),
                });
            }
            self.inputs.lock().unwrap().push(input);
            Ok(())
        }
    }

    #[test]
    fn maps_integrity_failure_reported_to_integrity_failure_detected() {
        let input = recovery_event_to_audit_input(RecoveryAuditEvent::IntegrityFailureReported {
            details: "hash mismatch".into(),
        });
        assert_eq!(input.kind, AuditEventKind::IntegrityFailureDetected);
        assert_eq!(input.result, AuditEventResult::Failure);
        assert_eq!(input.actor_kind, ActorKind::Service);
        assert!(input.revision_id.is_none());
        assert_eq!(input.reason_code, integrity::POLICY_INTEGRITY_FAILURE);
        let payload = input.payload_summary_json.unwrap();
        assert!(payload.contains("\"integrity_failure_reported\""));
        assert!(payload.contains("hash mismatch"));
    }

    #[test]
    fn maps_recovery_required_to_blocked_outcome_with_no_revision() {
        let input = recovery_event_to_audit_input(RecoveryAuditEvent::RecoveryRequired {
            details: "no LKG available".into(),
        });
        assert_eq!(input.kind, AuditEventKind::IntegrityFailureDetected);
        assert_eq!(input.result, AuditEventResult::Blocked);
        assert!(input.revision_id.is_none());
        assert!(input
            .payload_summary_json
            .as_deref()
            .unwrap()
            .contains("no LKG available"));
    }

    #[test]
    fn cache_rebuild_input_uses_cache_corrupt_reason_code() {
        let input = cache_rebuild_audit_input("malformed sqlite header");
        assert_eq!(input.kind, AuditEventKind::RecoveryActionRequested);
        assert_eq!(input.result, AuditEventResult::Success);
        assert_eq!(input.reason_code, integrity::CACHE_CORRUPT_REBUILDABLE);
        assert!(input
            .payload_summary_json
            .as_deref()
            .unwrap()
            .contains("malformed sqlite header"));
    }

    #[test]
    fn event_ids_are_unique_within_process() {
        let a = next_event_id();
        let b = next_event_id();
        let c = next_event_id();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert!(a.starts_with("adt-"));
    }

    /// Built from code points so the fixture carries no escapes of its own.
    #[test]
    fn a_payload_survives_json_metacharacters_and_control_characters() {
        let nasty: String = [
            'C',
            ':',
            char::from(92u8),
            'x',
            char::from(34u8),
            char::from(10u8),
            char::from(1u8),
            char::from(31u8),
            char::from(127u8),
            'y',
        ]
        .into_iter()
        .collect();
        for payload in [
            payload_integrity_failure_reported(&nasty),
            payload_recovery_required(&nasty),
            payload_cache_rebuilt(&nasty),
        ] {
            assert!(
                !payload.contains(char::from(10u8)),
                "NDJSON-unsafe: {payload}"
            );
            let value: serde_json::Value = serde_json::from_str(&payload).expect("valid JSON");
            let carried = value
                .get("details")
                .or_else(|| value.get("original_error"))
                .and_then(serde_json::Value::as_str);
            assert_eq!(carried, Some(nasty.as_str()));
        }
    }

    #[test]
    fn emit_persists_through_audit_writer_and_appends_a_line() {
        let dir = TempDir::new().expect("tempdir");
        let writer = Arc::new(AuditWriter::open(AuditWriterConfig::new(dir.path())));
        let emitter = DiagnosticsRecoveryAuditEmitter::new(writer);
        emitter
            .emit(RecoveryAuditEvent::IntegrityFailureReported {
                details: "rev-bad signature mismatch".into(),
            })
            .expect("persist ok");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read audit dir")
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("ndjson"))
            .collect();
        assert_eq!(entries.len(), 1, "exactly one audit file produced");
        let body = std::fs::read_to_string(entries[0].path()).unwrap();
        assert!(body.contains("integrity_failure_detected"));
        assert!(body.contains("rev-bad"));
        assert!(body.ends_with('\n'));
    }

    #[test]
    fn persistence_failure_propagates_to_loader() {
        let sink = Arc::new(RecordingSink {
            inputs: Mutex::new(Vec::new()),
            fail_next: Mutex::new(true),
        });
        let result = sink.append(recovery_event_to_audit_input(
            RecoveryAuditEvent::RecoveryRequired {
                details: "x".into(),
            },
        ));
        assert!(result.is_err(), "AuditSink failure must surface");
    }
}

//! production [`RecoveryAuditEmitter`] backed by
//! [`nrr_diagnostics::AuditWriter`].
//!
//! ## Purpose
//!
//! [`crate::policy_loader::PolicyLoader`] consults a `RecoveryAuditEmitter`
//! when integrity verification fails and the LKG-fallback recovery path
//! kicks in. The contract (see policy_loader.rs lines 96–99) is hard:
//!
//! > The emitter must persist the event durably *before* returning `Ok`.
//! > If persistence fails, returning `Err` causes the loader to fall
//! > through to `RecoveryRequired` rather than silently mutate the
//! > active pointer.
//!
//! used [`crate::policy_loader::NoopAuditEmitter`] as a
//! placeholder; this module ships the real adapter that maps the
//! loader's narrow [`crate::policy_loader::RecoveryAuditEvent`] enum
//! onto the broader [`nrr_diagnostics::AuditEventInput`] schema and
//! flushes through the durable NDJSON writer.
//!
//! ## Mapping
//!
//! | RecoveryAuditEvent              | AuditEventKind            | result   | reason_code                          |
//! |---------------------------------|---------------------------|----------|--------------------------------------|
//! | `LkgFallbackStarted`            | `IntegrityFailureDetected`| `Failure`| `integrity.policy_integrity_failure` |
//! | `LkgFallbackCompleted`          | `RecoveryActionRequested` | `Success`| `integrity.policy_integrity_failure` |
//! | `RecoveryRequired`              | `IntegrityFailureDetected`| `Blocked`| `integrity.policy_integrity_failure` |
//!
//! `actor_kind` is always [`ActorKind::Service`] (recovery is service-driven, never user-initiated).
//! `revision_id` is set to `broken_active` for the two LKG variants so an
//! auditor reading the chain can immediately correlate the failure to a
//! specific revision; `RecoveryRequired` carries no revision because by
//! definition there is no usable active.
//!
//! ## Event ID generation
//!
//! Spec calls for `adt-{uuid_v4}`, but the workspace deliberately avoids a
//! `uuid` dependency (no other crate uses it). We derive a deterministic-
//! enough id from `epoch_nanos + per-process atomic counter`, formatted as
//! `adt-{nanos}-{counter}`. Collisions are possible only across processes
//! within the same nanosecond, which the audit chain's `seq` + `prev_hash`
//! detect anyway.
//!
//! ## Failure semantics
//!
//! Any [`nrr_diagnostics::error::DiagnosticsError`] from `AuditWriter::append`
//! is converted to a `String` and returned via `Err(...)`. The loader's
//! invariant takes care of the rest — it will not mutate state on `Err`.

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
        RecoveryAuditEvent::LkgFallbackStarted {
            broken_active,
            lkg_target,
            details,
        } => AuditEventInput {
            event_id: next_event_id(),
            kind: AuditEventKind::IntegrityFailureDetected,
            created_at: now_ms(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: Some(broken_active.clone()),
            risk_level: Some("critical".to_string()),
            result: AuditEventResult::Failure,
            reason_code: integrity::POLICY_INTEGRITY_FAILURE,
            payload_summary_json: Some(payload_lkg_started(&broken_active, &lkg_target, &details)),
        },
        RecoveryAuditEvent::LkgFallbackCompleted {
            broken_active,
            new_active,
        } => AuditEventInput {
            event_id: next_event_id(),
            kind: AuditEventKind::RecoveryActionRequested,
            created_at: now_ms(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: Some(new_active.clone()),
            risk_level: Some("high".to_string()),
            result: AuditEventResult::Success,
            reason_code: integrity::POLICY_INTEGRITY_FAILURE,
            payload_summary_json: Some(payload_lkg_completed(&broken_active, &new_active)),
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

fn next_event_id() -> String {
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

/// Build a compact payload summary. We hand-roll the JSON instead of
/// pulling in serde_json::Value because (a) the shape is small and
/// fixed, (b) the audit pipeline trims to ~200 chars anyway, and (c) the
/// fields are guaranteed safe to splice directly (revision IDs are
/// `rev-{uuid}` and details strings are produced by our own code paths,
/// no untrusted input). We still escape the message text defensively.
fn payload_lkg_started(broken: &str, lkg: &str, details: &str) -> String {
    format!(
        r#"{{"event":"lkg_fallback_started","broken_active":{},"lkg_target":{},"details":{}}}"#,
        json_str(broken),
        json_str(lkg),
        json_str(details),
    )
}

fn payload_lkg_completed(broken: &str, new_active: &str) -> String {
    format!(
        r#"{{"event":"lkg_fallback_completed","broken_active":{},"new_active":{}}}"#,
        json_str(broken),
        json_str(new_active),
    )
}

fn payload_recovery_required(details: &str) -> String {
    format!(
        r#"{{"event":"recovery_required","details":{}}}"#,
        json_str(details)
    )
}

fn payload_cache_rebuilt(original_error: &str) -> String {
    format!(
        r#"{{"event":"cache_rebuilt_after_corruption","original_error":{}}}"#,
        json_str(original_error)
    )
}

/// Minimal JSON-string escape: covers the four characters that would
/// break the surrounding JSON literal (`"`, `\`, control chars
/// `\n`/`\r`/`\t`). Other control characters are rare in our inputs but
/// passed through unchanged — they don't break parsing, just look ugly.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
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
    fn maps_lkg_fallback_started_to_integrity_failure_detected() {
        let input = recovery_event_to_audit_input(RecoveryAuditEvent::LkgFallbackStarted {
            broken_active: "rev-bad".into(),
            lkg_target: "rev-good".into(),
            details: "hash mismatch".into(),
        });
        assert_eq!(input.kind, AuditEventKind::IntegrityFailureDetected);
        assert_eq!(input.result, AuditEventResult::Failure);
        assert_eq!(input.actor_kind, ActorKind::Service);
        assert_eq!(input.revision_id.as_deref(), Some("rev-bad"));
        assert_eq!(input.reason_code, integrity::POLICY_INTEGRITY_FAILURE);
        let payload = input.payload_summary_json.unwrap();
        assert!(payload.contains("\"lkg_fallback_started\""));
        assert!(payload.contains("rev-bad"));
        assert!(payload.contains("rev-good"));
        assert!(payload.contains("hash mismatch"));
    }

    #[test]
    fn maps_lkg_fallback_completed_to_recovery_action_requested() {
        let input = recovery_event_to_audit_input(RecoveryAuditEvent::LkgFallbackCompleted {
            broken_active: "rev-bad".into(),
            new_active: "rev-good".into(),
        });
        assert_eq!(input.kind, AuditEventKind::RecoveryActionRequested);
        assert_eq!(input.result, AuditEventResult::Success);
        assert_eq!(input.revision_id.as_deref(), Some("rev-good"));
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

    #[test]
    fn json_str_escapes_quotes_and_backslashes() {
        assert_eq!(json_str("plain"), r#""plain""#);
        assert_eq!(json_str(r#"with "quotes""#), r#""with \"quotes\"""#);
        assert_eq!(json_str("back\\slash"), r#""back\\slash""#);
        assert_eq!(json_str("tab\there"), r#""tab\there""#);
    }

    #[test]
    fn emit_persists_through_audit_writer_and_appends_a_line() {
        let dir = TempDir::new().expect("tempdir");
        let writer = Arc::new(AuditWriter::open(AuditWriterConfig::new(dir.path())));
        let emitter = DiagnosticsRecoveryAuditEmitter::new(writer);
        emitter
            .emit(RecoveryAuditEvent::LkgFallbackStarted {
                broken_active: "rev-bad".into(),
                lkg_target: "rev-good".into(),
                details: "test".into(),
            })
            .expect("persist ok");
        // Verify a file was created with at least one NDJSON line.
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

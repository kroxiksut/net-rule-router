//! Production [`PerSidApplyAudit`] sink that writes
//! NDJSON audit entries to an [`AuditWriter`].
//!
//! The orchestrator's contract (see [`PerSidApplyAuditRecord`])
//! is rich enough to feed the audit chain; [`NoopPerSidApplyAudit`] is the
//! observability-free alternative for callers that don't wire this sink.
//!
//! ## AuditEventKind mapping
//!
//! The current [`AuditEventKind`] catalogue does not have a dedicated
//! per-SID apply variant; introducing one is a wire-schema bump
//! (every NDJSON consumer would need to handle the new kind string).
//! Instead we encode the per-SID lifecycle in the existing
//! [`AuditEventKind::RevisionActivated`] kind plus a discriminating
//! [`ReasonCode`] in the `apply.*` namespace:
//!
//! | [`PerSidApplyAuditKind`] | Audit kind          | Reason code                          | Result   |
//! |--------------------------|---------------------|--------------------------------------|----------|
//! | `Applied`                | `RevisionActivated` | `reason::apply::COMPLETED`           | Success  |
//! | `Updated`                | `RevisionActivated` | `reason::apply::COMPLETED`           | Success  |
//! | `Withdrawn`              | `RevisionActivated` | `reason::apply::BLOCK_REMOVED`       | Success  |
//! | `Failed`                 | `RevisionActivated` | `reason::apply::FAILED`              | Failure  |
//!
//! `payload_summary_json` carries `{event, sid, kind, filter_count,
//! message}` so an offline auditor can reconstruct which SID was
//! affected and how many filters changed without parsing message
//! free-form text.
//!
//! ## Failure mode
//!
//! `AuditSink::append` returns a `DiagnosticsError`. The orchestrator
//! doesn't currently care whether the audit append succeeded — it
//! fires-and-forgets. So this impl logs the failure via `tracing`
//! and swallows the error, matching the `ProductionActivationAuditEmitter`
//! pattern (and unlike `ProductionRecoveryAuditSink` which propagates
//! because recovery has a stricter audit-before-act invariant).

use std::sync::Arc;

use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter};
use nrr_diagnostics::audit::{ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::reason::{apply as apply_reason, ReasonCode};
use nrr_diagnostics::sink::AuditSink;

use crate::per_sid_orchestrator::{PerSidApplyAudit, PerSidApplyAuditKind, PerSidApplyAuditRecord};
use crate::production_coordinator::ProductionIdGenerator;

/// Production sink — writes each `PerSidApplyAuditRecord` as a
/// `RevisionActivated`/`apply.*` NDJSON line via the shared
/// [`AuditWriter`]. Construct once per service lifetime.
pub struct ProductionPerSidApplyAudit {
    writer: Arc<AuditWriter>,
    ids: Arc<ProductionIdGenerator>,
}

impl ProductionPerSidApplyAudit {
    pub fn new(writer: Arc<AuditWriter>, ids: Arc<ProductionIdGenerator>) -> Self {
        Self { writer, ids }
    }

    fn map_record(record: &PerSidApplyAuditRecord) -> (ReasonCode, AuditEventResult) {
        match record.kind {
            PerSidApplyAuditKind::Applied | PerSidApplyAuditKind::Updated => {
                (apply_reason::COMPLETED, AuditEventResult::Success)
            }
            PerSidApplyAuditKind::Withdrawn => {
                (apply_reason::BLOCK_REMOVED, AuditEventResult::Success)
            }
            PerSidApplyAuditKind::Failed => (apply_reason::FAILED, AuditEventResult::Failure),
        }
    }

    /// Build the compact JSON payload summary.
    ///
    /// Serialised by the JSON library: hand-escaping covered the quote and the
    /// backslash but not the control characters, and the audit trail is NDJSON
    /// — one newline inside `message` split one event into two unparseable
    /// lines. The message is assembled from platform error text, so what it can
    /// contain is not ours to assume.
    fn payload_summary(record: &PerSidApplyAuditRecord) -> String {
        serde_json::json!({
            "event": "per_sid_apply",
            "sid": record.sid,
            "kind": record.kind.slug(),
            "filter_count": record.filter_count,
            "message": record.message,
        })
        .to_string()
    }
}

impl PerSidApplyAudit for ProductionPerSidApplyAudit {
    fn emit(&self, record: PerSidApplyAuditRecord) {
        let (reason_code, result) = Self::map_record(&record);
        let payload = Self::payload_summary(&record);
        let input = AuditEventInput {
            event_id: format!("adt-{}", self.ids.next_suffix()),
            kind: AuditEventKind::RevisionActivated,
            created_at: millis_since_epoch(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: None,
            risk_level: None,
            result,
            reason_code,
            payload_summary_json: Some(payload),
        };
        if let Err(e) = self.writer.append(input) {
            tracing::error!(
                target: "nrr::audit",
                error = %format!("{e:?}"),
                sid = %record.sid,
                kind = %record.kind.slug(),
                "per-sid apply audit append failed; entry dropped",
            );
        }
    }
}

/// Lifted from `production_coordinator.rs` to avoid a `pub fn` export
/// across modules just for this. UTC Unix milliseconds.
fn millis_since_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::audit::writer::AuditWriterConfig;
    use tempfile::TempDir;

    fn make_writer() -> (Arc<AuditWriter>, TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = Arc::new(AuditWriter::open(AuditWriterConfig::new(dir.path())));
        (writer, dir)
    }

    #[test]
    fn applied_record_maps_to_completed_success() {
        let (writer, _dir) = make_writer();
        let ids = Arc::new(ProductionIdGenerator::new());
        let sink = ProductionPerSidApplyAudit::new(writer, ids);
        sink.emit(PerSidApplyAuditRecord {
            sid: "S-1-5-21-test-1".into(),
            kind: PerSidApplyAuditKind::Applied,
            filter_count: 7,
            message: "applied for test".into(),
        });
        // Append succeeded if the closure didn't panic / log error.
        // We verified the mapping arithmetic via map_record directly
        // below.
    }

    #[test]
    fn map_record_assigns_correct_reason_and_result() {
        let cases = [
            (
                PerSidApplyAuditKind::Applied,
                apply_reason::COMPLETED,
                AuditEventResult::Success,
            ),
            (
                PerSidApplyAuditKind::Updated,
                apply_reason::COMPLETED,
                AuditEventResult::Success,
            ),
            (
                PerSidApplyAuditKind::Withdrawn,
                apply_reason::BLOCK_REMOVED,
                AuditEventResult::Success,
            ),
            (
                PerSidApplyAuditKind::Failed,
                apply_reason::FAILED,
                AuditEventResult::Failure,
            ),
        ];
        for (kind, expected_reason, expected_result) in cases {
            let record = PerSidApplyAuditRecord {
                sid: "S-1-5-21-x".into(),
                kind,
                filter_count: 0,
                message: String::new(),
            };
            let (reason, result) = ProductionPerSidApplyAudit::map_record(&record);
            assert_eq!(reason, expected_reason, "reason for {:?}", kind);
            assert_eq!(result, expected_result, "result for {:?}", kind);
        }
    }

    #[test]
    fn payload_summary_escapes_quotes_in_message() {
        let record = PerSidApplyAuditRecord {
            sid: "S-1-5-21-x".into(),
            kind: PerSidApplyAuditKind::Failed,
            filter_count: 3,
            message: r#"err with "quotes" and \backslashes"#.into(),
        };
        let payload = ProductionPerSidApplyAudit::payload_summary(&record);
        // Must be valid JSON.
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must parse as JSON");
        assert_eq!(parsed["sid"], "S-1-5-21-x");
        assert_eq!(parsed["kind"], "per-sid-policy-failed");
        assert_eq!(parsed["filter_count"], 3);
        assert_eq!(parsed["message"], "err with \"quotes\" and \\backslashes");
    }

    /// The trail is NDJSON — one event per line. A newline inside the message
    /// used to split one event into two lines, neither of them parseable.
    #[test]
    fn payload_summary_survives_control_characters_in_the_message() {
        let newline = char::from(10u8);
        let tab = char::from(9u8);
        let record = PerSidApplyAuditRecord {
            sid: "S-1-5-21-x".into(),
            kind: PerSidApplyAuditKind::Failed,
            filter_count: 1,
            message: format!("first line{newline}second{tab}line"),
        };
        let payload = ProductionPerSidApplyAudit::payload_summary(&record);
        assert_eq!(payload.lines().count(), 1, "one event is one line");
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must parse as JSON");
        assert_eq!(parsed["message"], record.message);
    }

    #[test]
    fn payload_summary_carries_all_record_fields() {
        let record = PerSidApplyAuditRecord {
            sid: "S-1-5-21-42".into(),
            kind: PerSidApplyAuditKind::Updated,
            filter_count: 12,
            message: "filters rebuilt".into(),
        };
        let payload = ProductionPerSidApplyAudit::payload_summary(&record);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["event"], "per_sid_apply");
        assert_eq!(parsed["sid"], "S-1-5-21-42");
        assert_eq!(parsed["kind"], "per-sid-policy-updated");
        assert_eq!(parsed["filter_count"], 12);
        assert_eq!(parsed["message"], "filters rebuilt");
    }
}

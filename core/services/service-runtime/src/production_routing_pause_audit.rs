//! Production [`RoutingPauseAudit`]: a user's pause and resume land in the
//! audit trail, filed under that user's actor hash so only they (and an
//! administrator) read them back.
//!
//! No audit kind names a pause, and a new one is a schema change for every
//! reader of the trail; like the per-SID apply sink, the event rides
//! `RevisionActivated` with its own `apply.*` reason code.

use std::sync::Arc;

use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter};
use nrr_diagnostics::audit::{actor_id_hash, ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::reason::{apply, ReasonCode};
use nrr_diagnostics::sink::AuditSink;

use crate::production_coordinator::ProductionIdGenerator;
use crate::routing_pause::{RoutingPauseAudit, RoutingPauseAuditEvent};

const PAUSED: ReasonCode = apply::ROUTING_PAUSED;
const RESUMED: ReasonCode = apply::ROUTING_RESUMED;
const KEPT_PAUSED: ReasonCode = apply::ROUTING_KEPT_PAUSED;

pub struct ProductionRoutingPauseAudit {
    writer: Arc<AuditWriter>,
    ids: Arc<ProductionIdGenerator>,
}

impl ProductionRoutingPauseAudit {
    pub fn new(writer: Arc<AuditWriter>, ids: Arc<ProductionIdGenerator>) -> Self {
        Self { writer, ids }
    }

    /// Who acted, under whose hash, why, and the payload line.
    fn map(event: &RoutingPauseAuditEvent) -> (ActorKind, &str, ReasonCode, serde_json::Value) {
        match event {
            RoutingPauseAuditEvent::Paused {
                sid,
                reason,
                at_secs,
            } => (
                ActorKind::User,
                sid.as_str(),
                PAUSED,
                serde_json::json!({
                    "event": "routing_pause",
                    "action": "paused",
                    "reason": reason,
                    "at_secs": at_secs,
                }),
            ),
            RoutingPauseAuditEvent::Resumed { sid, at_secs } => (
                ActorKind::User,
                sid.as_str(),
                RESUMED,
                serde_json::json!({
                    "event": "routing_pause",
                    "action": "resumed",
                    "at_secs": at_secs,
                }),
            ),
            RoutingPauseAuditEvent::PausedOnTrayConnect {
                sid,
                paused_at_secs,
                observed_at_secs,
            } => (
                ActorKind::Service,
                sid.as_str(),
                KEPT_PAUSED,
                serde_json::json!({
                    "event": "routing_pause",
                    "action": "kept-paused",
                    "paused_at_secs": paused_at_secs,
                    "at_secs": observed_at_secs,
                }),
            ),
        }
    }
}

impl RoutingPauseAudit for ProductionRoutingPauseAudit {
    fn emit(&self, event: RoutingPauseAuditEvent) {
        let (actor_kind, sid, reason_code, payload) = Self::map(&event);
        let input = AuditEventInput {
            event_id: format!("adt-{}", self.ids.next_suffix()),
            kind: AuditEventKind::RevisionActivated,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0),
            actor_kind,
            actor_id_hash: actor_id_hash(sid),
            revision_id: None,
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code,
            payload_summary_json: Some(payload.to_string()),
        };
        // The pause already happened; a lost line must not undo it.
        if let Err(e) = self.writer.append(input) {
            tracing::error!(
                target: "nrr::audit",
                error = %format!("{e:?}"),
                "routing pause audit append failed; entry dropped",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::audit::writer::AuditWriterConfig;
    use nrr_diagnostics::audit::{AuditQueryFilter, AuditReader};
    use nrr_diagnostics::facade::dto::DiagnosticsAudience;

    #[test]
    fn a_pause_and_its_reason_reach_the_trail_for_that_user_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = Arc::new(AuditWriter::open(AuditWriterConfig::new(dir.path())));
        let sink = ProductionRoutingPauseAudit::new(writer, Arc::new(ProductionIdGenerator::new()));
        sink.emit(RoutingPauseAuditEvent::Paused {
            sid: "S-1-5-21-1-2-3-1001".into(),
            reason: Some("watching a film".into()),
            at_secs: 10,
        });
        sink.emit(RoutingPauseAuditEvent::Resumed {
            sid: "S-1-5-21-1-2-3-1001".into(),
            at_secs: 20,
        });
        drop(sink);

        let reader = AuditReader::new(dir.path());
        let read = |principal: &str| {
            reader
                .scan(
                    &AuditQueryFilter::new(),
                    &DiagnosticsAudience::Principal(principal.into()),
                )
                .into_iter()
                .filter_map(|e| e.payload_summary_json)
                .collect::<Vec<_>>()
        };
        let mine = read("S-1-5-21-1-2-3-1001");
        assert_eq!(mine.len(), 2, "{mine:?}");
        assert!(mine.iter().any(|p| p.contains("watching a film")));
        assert!(
            read("S-1-5-21-1-2-3-1002").is_empty(),
            "another user does not read it"
        );
    }
}

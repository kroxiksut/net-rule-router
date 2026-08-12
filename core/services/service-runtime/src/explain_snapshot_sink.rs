//! Write-path port for per-`DecisionId` explain
//! snapshots. The decision-emission site (per-SID orchestrator, or the
//! production wrapper around `DecisionEngine::decide_route`) calls
//! `sink.record(...)` after producing a `DecisionOutcome`. The default
//! `NoopExplainSnapshotSink` exists so degraded boot paths (no state
//! DB connection) continue running without explain persistence.
//!
//! ## Design — fire-and-forget, sink-side errors
//!
//! The trait method returns `()` rather than `Result` on purpose:
//!
//! 1. The caller — `DecisionEngine` consumers — must not couple
//!    decision correctness to diagnostic-snapshot success. An apply
//!    decision MUST proceed even if the SQLite write fails.
//! 2. Errors are logged via `tracing::warn!` inside the sink so
//!    operators still see them in NDJSON.
//! 3. Tests use the `Noop` variant when explain isn't under test.
//!
//! ## Serialisation
//!
//! `ExplainResponse` is `Serialize`+`Deserialize`. The sink renders
//! to a compact JSON string for SQLite TEXT storage; rehydration in
//! `ProductionDiagnosticsFacade::get_explain` uses
//! `serde_json::from_str` on the way out.
//!
//! ## TTL
//!
//! Default TTL is 7 days — long enough for an operator to dig into
//! a complaint about a routing decision they made earlier in the
//! week, short enough to keep the table from unbounded growth on a
//! busy service. Configurable per-instance via
//! `ProductionExplainSnapshotSink::new`. The eventual retention task
//! (`explain-snapshot-gc`) calls `repo.prune_expired(now_ms)`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use nrr_diagnostics::ExplainResponse;
use nrr_domain::decision_explain::ExplainDetailLevel;
use nrr_storage::explain_snapshots::{
    ExplainRedactionLevel, ExplainSnapshotRecord, ExplainSnapshotRepository,
};

/// Write-path port. Implementations persist (or discard) the explain
/// snapshot. See module docs for the fire-and-forget contract.
pub trait ExplainSnapshotSink: Send + Sync {
    fn record(
        &self,
        decision_id: &str,
        explain: &ExplainResponse,
        detail_level: ExplainDetailLevel,
    );
}

/// Default sink for degraded boot / tests that don't care about
/// explain persistence. Silently drops every record call.
pub struct NoopExplainSnapshotSink;

impl ExplainSnapshotSink for NoopExplainSnapshotSink {
    fn record(
        &self,
        _decision_id: &str,
        _explain: &ExplainResponse,
        _detail_level: ExplainDetailLevel,
    ) {
        // Intentional no-op.
    }
}

/// Production sink backed by `nrr_storage::ExplainSnapshotRepository`.
/// Serialises the `ExplainResponse` to compact JSON, computes
/// `expires_at = now + ttl`, inserts. All errors are logged via
/// `tracing::warn!` and swallowed.
pub struct ProductionExplainSnapshotSink {
    state_conn: Arc<Mutex<Connection>>,
    ttl: Duration,
}

impl ProductionExplainSnapshotSink {
    /// Default TTL — 7 days. Long enough for retroactive
    /// investigation of "why did the service route this site that
    /// way last Tuesday"; short enough to keep table size bounded.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(7 * 24 * 3_600);

    pub fn new(state_conn: Arc<Mutex<Connection>>, ttl: Duration) -> Self {
        Self { state_conn, ttl }
    }

    pub fn with_default_ttl(state_conn: Arc<Mutex<Connection>>) -> Self {
        Self::new(state_conn, Self::DEFAULT_TTL)
    }

    fn detail_level_to_redaction(level: ExplainDetailLevel) -> ExplainRedactionLevel {
        match level {
            ExplainDetailLevel::CompactUi => ExplainRedactionLevel::CompactUi,
            ExplainDetailLevel::Diagnostics => ExplainRedactionLevel::Diagnostics,
            ExplainDetailLevel::DeveloperTrace => ExplainRedactionLevel::DeveloperTrace,
        }
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

impl ExplainSnapshotSink for ProductionExplainSnapshotSink {
    fn record(
        &self,
        decision_id: &str,
        explain: &ExplainResponse,
        detail_level: ExplainDetailLevel,
    ) {
        if decision_id.is_empty() {
            tracing::warn!(
                target: "nrr::diagnostics",
                "explain snapshot sink received empty decision_id; dropping"
            );
            return;
        }
        let payload_json = match serde_json::to_string(explain) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    error = %e,
                    decision_id,
                    "explain snapshot serialise failed; dropping record"
                );
                return;
            }
        };
        let now = Self::now_ms();
        let expires_at = now.saturating_add(self.ttl.as_millis() as i64);
        let record = ExplainSnapshotRecord {
            decision_id: decision_id.to_string(),
            created_at: now,
            redaction_level: Self::detail_level_to_redaction(detail_level),
            payload_json,
            expires_at,
        };
        let guard = match self.state_conn.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    decision_id,
                    "explain snapshot sink: state DB mutex poisoned; dropping record"
                );
                return;
            }
        };
        let repo = ExplainSnapshotRepository::new(&guard);
        if let Err(e) = repo.insert(&record) {
            tracing::warn!(
                target: "nrr::diagnostics",
                error = %e,
                decision_id,
                "explain snapshot insert failed; dropping record (decision still proceeds)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::{ExplainDataAvailability, ExplainQueryKind, ExplainResponse};
    use nrr_domain::decision_explain::ExplainDetailLevel;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;

    fn open_state_db() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        (dir, Arc::new(Mutex::new(conn)))
    }

    fn make_explain() -> ExplainResponse {
        // Use the public Unavailable constructor — sink doesn't care
        // about the variant, only that the JSON roundtrip succeeds.
        ExplainResponse::unavailable(
            ExplainQueryKind::Historical,
            ExplainDetailLevel::CompactUi,
            ExplainDataAvailability::ServiceUnavailable,
        )
    }

    #[test]
    fn noop_sink_silently_drops_record() {
        let sink = NoopExplainSnapshotSink;
        let explain = make_explain();
        // Just must not panic.
        sink.record("dec-x", &explain, ExplainDetailLevel::CompactUi);
        sink.record("", &explain, ExplainDetailLevel::Diagnostics);
    }

    #[test]
    fn production_sink_persists_record_readable_by_repo() {
        let (_d, conn) = open_state_db();
        let sink = ProductionExplainSnapshotSink::with_default_ttl(Arc::clone(&conn));
        let explain = make_explain();
        sink.record("dec-001", &explain, ExplainDetailLevel::CompactUi);

        let guard = conn.lock().unwrap();
        let repo = ExplainSnapshotRepository::new(&guard);
        let back = repo.get("dec-001").expect("get").expect("Some");
        assert_eq!(back.decision_id, "dec-001");
        assert_eq!(back.redaction_level, ExplainRedactionLevel::CompactUi);
        assert!(
            !back.payload_json.is_empty(),
            "payload must be non-empty JSON"
        );
        // expires_at must be in the future by ~7 days (DEFAULT_TTL).
        let delta = back.expires_at - back.created_at;
        assert_eq!(
            delta as u128,
            ProductionExplainSnapshotSink::DEFAULT_TTL.as_millis(),
            "expires_at must be created_at + DEFAULT_TTL exactly"
        );
    }

    #[test]
    fn production_sink_respects_custom_ttl() {
        let (_d, conn) = open_state_db();
        let sink = ProductionExplainSnapshotSink::new(Arc::clone(&conn), Duration::from_secs(60));
        let explain = make_explain();
        sink.record("dec-ttl", &explain, ExplainDetailLevel::DeveloperTrace);

        let guard = conn.lock().unwrap();
        let repo = ExplainSnapshotRepository::new(&guard);
        let back = repo.get("dec-ttl").expect("get").expect("Some");
        assert_eq!(back.redaction_level, ExplainRedactionLevel::DeveloperTrace);
        assert_eq!(back.expires_at - back.created_at, 60_000);
    }

    #[test]
    fn production_sink_drops_empty_decision_id_without_writing() {
        let (_d, conn) = open_state_db();
        let sink = ProductionExplainSnapshotSink::with_default_ttl(Arc::clone(&conn));
        let explain = make_explain();
        sink.record("", &explain, ExplainDetailLevel::CompactUi);

        let guard = conn.lock().unwrap();
        let repo = ExplainSnapshotRepository::new(&guard);
        assert_eq!(repo.count().expect("count"), 0);
    }

    #[test]
    fn production_sink_silently_swallows_duplicate_decision_id() {
        // Per-decision uniqueness is enforced by PRIMARY KEY. A
        // duplicate insert errors at the repo layer; the sink must
        // log + swallow rather than propagate (decision must
        // proceed). The repo state stays at 1 row.
        let (_d, conn) = open_state_db();
        let sink = ProductionExplainSnapshotSink::with_default_ttl(Arc::clone(&conn));
        let explain = make_explain();
        sink.record("dup", &explain, ExplainDetailLevel::CompactUi);
        sink.record("dup", &explain, ExplainDetailLevel::CompactUi); // logs warn, no panic

        let guard = conn.lock().unwrap();
        let repo = ExplainSnapshotRepository::new(&guard);
        assert_eq!(repo.count().expect("count"), 1);
    }

    #[test]
    fn detail_level_maps_one_to_one_to_redaction_level() {
        assert_eq!(
            ProductionExplainSnapshotSink::detail_level_to_redaction(ExplainDetailLevel::CompactUi),
            ExplainRedactionLevel::CompactUi
        );
        assert_eq!(
            ProductionExplainSnapshotSink::detail_level_to_redaction(
                ExplainDetailLevel::Diagnostics
            ),
            ExplainRedactionLevel::Diagnostics
        );
        assert_eq!(
            ProductionExplainSnapshotSink::detail_level_to_redaction(
                ExplainDetailLevel::DeveloperTrace
            ),
            ExplainRedactionLevel::DeveloperTrace
        );
    }
}

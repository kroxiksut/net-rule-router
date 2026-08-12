//! Persistent store for per-`DecisionId` explain snapshots. Without it,
//! `DiagnosticsFacade::get_explain` has nothing to return: the engine
//! produces an `ExplainResponse` but nothing persists it. With this repo
//! and the `ProductionExplainSnapshotSink` port wired at the per-SID
//! orchestrator, the GUI probe widget shows real explain output for any
//! decision made within the TTL window.
//!
//! The repo is intentionally minimal: insert, get, prune_expired,
//! count. No update — every write is a fresh `decision_id` (UUID v4
//! from the engine's caller), and PRIMARY KEY collisions surface as
//! `Internal` errors the orchestrator can log + drop.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

/// Wire-stable redaction-mode slug used in the `redaction_level`
/// column. Matches the slugs documented by
/// `nrr_diagnostics::ExplainQueryKind` for round-trip consistency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainRedactionLevel {
    CompactUi,
    Diagnostics,
    DeveloperTrace,
}

impl ExplainRedactionLevel {
    pub fn slug(self) -> &'static str {
        match self {
            Self::CompactUi => "compact-ui",
            Self::Diagnostics => "diagnostics",
            Self::DeveloperTrace => "developer-trace",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "compact-ui" => Some(Self::CompactUi),
            "diagnostics" => Some(Self::Diagnostics),
            "developer-trace" => Some(Self::DeveloperTrace),
            _ => None,
        }
    }
}

/// One persisted explain snapshot row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainSnapshotRecord {
    pub decision_id: String,
    pub created_at: i64,
    pub redaction_level: ExplainRedactionLevel,
    /// Opaque JSON payload — the producer (`ProductionDiagnosticsFacade`)
    /// rehydrates this into an `ExplainResponse` via `serde_json`.
    pub payload_json: String,
    pub expires_at: i64,
}

pub struct ExplainSnapshotRepository<'c> {
    conn: &'c Connection,
}

impl<'c> ExplainSnapshotRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Insert a new snapshot. PRIMARY KEY collision returns
    /// `StorageError::Internal` — `DecisionId` is meant to be unique
    /// per `DecisionEngine::decide_route` call, so a collision
    /// indicates upstream bug, not a normal flow.
    pub fn insert(&self, record: &ExplainSnapshotRecord) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO explain_snapshots
                    (decision_id, created_at, redaction_level, payload_json, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.decision_id,
                    record.created_at,
                    record.redaction_level.slug(),
                    record.payload_json,
                    record.expires_at,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("explain_snapshots insert: {e}")))?;
        Ok(())
    }

    /// Fetch the snapshot for `decision_id`. Returns `None` when no
    /// row exists (decision predates the store, was pruned by
    /// retention, or never went through the snapshot sink).
    pub fn get(&self, decision_id: &str) -> StorageResult<Option<ExplainSnapshotRecord>> {
        self.conn
            .query_row(
                "SELECT decision_id, created_at, redaction_level, payload_json, expires_at
                 FROM explain_snapshots
                 WHERE decision_id = ?1",
                params![decision_id],
                |row| {
                    let id: String = row.get(0)?;
                    let created_at: i64 = row.get(1)?;
                    let level_slug: String = row.get(2)?;
                    let payload: String = row.get(3)?;
                    let expires_at: i64 = row.get(4)?;
                    Ok((id, created_at, level_slug, payload, expires_at))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("explain_snapshots get: {e}")))?
            .map(|(id, created_at, level_slug, payload, expires_at)| {
                let level = ExplainRedactionLevel::from_slug(&level_slug).ok_or_else(|| {
                    StorageError::Internal(format!(
                        "explain_snapshots: unknown redaction_level slug {level_slug:?}"
                    ))
                })?;
                Ok(ExplainSnapshotRecord {
                    decision_id: id,
                    created_at,
                    redaction_level: level,
                    payload_json: payload,
                    expires_at,
                })
            })
            .transpose()
    }

    /// Delete every row whose `expires_at <= now_ms`. Returns the
    /// number of rows removed. Called by the optional
    /// `explain-snapshot-gc` supervisor task (1h tick).
    pub fn prune_expired(&self, now_ms: i64) -> StorageResult<usize> {
        let n = self
            .conn
            .execute(
                "DELETE FROM explain_snapshots WHERE expires_at <= ?1",
                params![now_ms],
            )
            .map_err(|e| StorageError::Internal(format!("explain_snapshots prune: {e}")))?;
        Ok(n)
    }

    /// Row count — diagnostics-only; not part of the wire surface.
    pub fn count(&self) -> StorageResult<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM explain_snapshots", [], |row| {
                row.get(0)
            })
            .map_err(|e| StorageError::Internal(format!("explain_snapshots count: {e}")))?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;
    use tempfile::TempDir;

    fn open_state_db() -> (TempDir, Connection) {
        let dir = tempfile::tempdir().expect("temp");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, runner.into_connection())
    }

    fn rec(id: &str, created_at: i64, expires_at: i64) -> ExplainSnapshotRecord {
        ExplainSnapshotRecord {
            decision_id: id.into(),
            created_at,
            redaction_level: ExplainRedactionLevel::CompactUi,
            payload_json: r#"{"input":null,"summary":{"summary_key":"ok"}}"#.into(),
            expires_at,
        }
    }

    #[test]
    fn redaction_level_slug_roundtrips() {
        for v in [
            ExplainRedactionLevel::CompactUi,
            ExplainRedactionLevel::Diagnostics,
            ExplainRedactionLevel::DeveloperTrace,
        ] {
            assert_eq!(ExplainRedactionLevel::from_slug(v.slug()), Some(v));
        }
        assert_eq!(ExplainRedactionLevel::from_slug("bogus"), None);
    }

    #[test]
    fn insert_then_get_roundtrips() {
        let (_d, conn) = open_state_db();
        let repo = ExplainSnapshotRepository::new(&conn);
        let r = rec("dec-001", 1_000, 2_000);
        repo.insert(&r).expect("insert");
        let back = repo.get("dec-001").expect("get").expect("Some");
        assert_eq!(back, r);
    }

    #[test]
    fn get_missing_decision_returns_none() {
        let (_d, conn) = open_state_db();
        let repo = ExplainSnapshotRepository::new(&conn);
        assert!(repo.get("missing").expect("get").is_none());
    }

    #[test]
    fn duplicate_decision_id_is_rejected() {
        let (_d, conn) = open_state_db();
        let repo = ExplainSnapshotRepository::new(&conn);
        repo.insert(&rec("dec-A", 1, 100)).expect("first insert");
        let res = repo.insert(&rec("dec-A", 2, 200));
        assert!(res.is_err(), "duplicate decision_id must surface as error");
    }

    #[test]
    fn prune_expired_drops_only_rows_at_or_before_now() {
        let (_d, conn) = open_state_db();
        let repo = ExplainSnapshotRepository::new(&conn);
        repo.insert(&rec("old-1", 0, 100)).expect("insert");
        repo.insert(&rec("old-2", 0, 150)).expect("insert");
        repo.insert(&rec("fresh", 0, 500)).expect("insert");
        let dropped = repo.prune_expired(200).expect("prune");
        assert_eq!(dropped, 2);
        assert_eq!(repo.count().expect("count"), 1);
        assert!(repo.get("fresh").expect("get").is_some());
        assert!(repo.get("old-1").expect("get").is_none());
        assert!(repo.get("old-2").expect("get").is_none());
    }

    #[test]
    fn schema_rejects_invalid_redaction_level_slug() {
        let (_d, conn) = open_state_db();
        let res = conn.execute(
            "INSERT INTO explain_snapshots
                (decision_id, created_at, redaction_level, payload_json, expires_at)
             VALUES ('x', 1, 'invalid-slug', '{}', 100)",
            [],
        );
        assert!(res.is_err(), "CHECK constraint must reject unknown slug");
    }

    #[test]
    fn count_is_zero_initially() {
        let (_d, conn) = open_state_db();
        let repo = ExplainSnapshotRepository::new(&conn);
        assert_eq!(repo.count().expect("count"), 0);
    }
}

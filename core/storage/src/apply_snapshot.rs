//! `apply_snapshots` table repository.
//!
//! Persists `PlatformStateSnapshot` (serialised as JSON) in
//! `nrr_service_state.db` keyed by `ApplyAttemptMarker.attempt_id`.
//!
//! ## Lifecycle
//!
//! 1. Before apply (Preparing phase): `save(attempt_id, stored_snapshot)`.
//! 2. After successful apply + verify: `rotate_keeping_latest_n(2)`.
//! 3. On rollback (startup recovery): `load(attempt_id)` → deserialise.
//! 4. On clean shutdown: no action needed (DB stays intact for next start).
//!
//! ## Schema version guard
//!
//! If a loaded snapshot has a `schema_version` unknown to the current binary,
//! `load` returns `Err(StorageError::Internal)` so the caller can escalate to
//! `RecoveryRequired` rather than silently deserialising an incompatible blob.
//!
//! ## Rotation
//!
//! At most `N` snapshots are kept (cap enforced by `rotate_keeping_latest_n`).
//! The cap prevents unbounded growth when many apply attempts are made.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

/// Maximum schema version this binary can read.
const MAX_KNOWN_SCHEMA_VERSION: u32 = 1;

/// One row from the `apply_snapshots` table.
#[derive(Clone, Debug)]
pub struct StoredSnapshot {
    /// Matches `ApplyAttemptMarker.attempt_id`.
    pub attempt_id: String,
    /// SHA-256 hex of the canonical snapshot content. Recomputed on load
    /// to detect DB tampering.
    pub snapshot_hash: String,
    /// Serialised `PlatformStateSnapshot` JSON blob.
    pub snapshot_json: String,
    /// Schema version from the time the snapshot was serialised.
    pub schema_version: u32,
    /// Wall-clock seconds when this snapshot was created.
    pub created_at: u64,
}

// ── Repository ────────────────────────────────────────────────────────────────

/// Synchronous repository for the `apply_snapshots` table.
///
/// Borrows an open `Connection`. The connection must already have the
/// `apply_snapshots` table (created by migration v4). All operations are
/// single-statement; WAL journal mode and the 5-second busy timeout are
/// configured at connection open time.
pub struct ApplySnapshotRepository<'c> {
    conn: &'c Connection,
}

impl<'c> ApplySnapshotRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Persist `snapshot`. Replaces any existing row with the same
    /// `attempt_id` (INSERT OR REPLACE semantics).
    pub fn save(&self, snapshot: &StoredSnapshot) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO apply_snapshots
                 (attempt_id, snapshot_hash, snapshot_json, schema_version, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    snapshot.attempt_id,
                    snapshot.snapshot_hash,
                    snapshot.snapshot_json,
                    snapshot.schema_version,
                    snapshot.created_at,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("apply_snapshots save: {e}")))?;
        Ok(())
    }

    /// Load the snapshot for `attempt_id`. Returns `None` if not found.
    ///
    /// Returns `Err` if the stored `schema_version` exceeds
    /// `MAX_KNOWN_SCHEMA_VERSION` (forward-compatibility guard).
    pub fn load(&self, attempt_id: &str) -> StorageResult<Option<StoredSnapshot>> {
        let row = self
            .conn
            .query_row(
                "SELECT attempt_id, snapshot_hash, snapshot_json, schema_version, created_at
                 FROM apply_snapshots WHERE attempt_id = ?1",
                rusqlite::params![attempt_id],
                |row| {
                    Ok(StoredSnapshot {
                        attempt_id: row.get(0)?,
                        snapshot_hash: row.get(1)?,
                        snapshot_json: row.get(2)?,
                        schema_version: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("apply_snapshots load: {e}")))?;

        if let Some(ref s) = row {
            if s.schema_version > MAX_KNOWN_SCHEMA_VERSION {
                return Err(StorageError::Internal(format!(
                    "apply_snapshot schema_version {} is newer than supported {}; \
                     cannot deserialise — escalate to RecoveryRequired",
                    s.schema_version, MAX_KNOWN_SCHEMA_VERSION
                )));
            }
        }
        Ok(row)
    }

    /// Delete the snapshot for `attempt_id`. No-op if not present.
    pub fn delete(&self, attempt_id: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM apply_snapshots WHERE attempt_id = ?1",
                rusqlite::params![attempt_id],
            )
            .map_err(|e| StorageError::Internal(format!("apply_snapshots delete: {e}")))?;
        Ok(())
    }

    /// Delete all but the `n` most recently created snapshots.
    /// Returns the number of rows deleted.
    pub fn rotate_keeping_latest_n(&self, n: usize) -> StorageResult<usize> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM apply_snapshots
                 WHERE attempt_id NOT IN (
                     SELECT attempt_id FROM apply_snapshots
                     ORDER BY created_at DESC LIMIT ?1
                 )",
                rusqlite::params![n as i64],
            )
            .map_err(|e| StorageError::Internal(format!("apply_snapshots rotate: {e}")))?;
        Ok(deleted)
    }

    /// Count total rows.
    pub fn count(&self) -> StorageResult<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM apply_snapshots", [], |r| r.get(0))
            .map_err(|e| StorageError::Internal(format!("apply_snapshots count: {e}")))?;
        Ok(n as usize)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
    use tempfile::TempDir;

    fn fresh_state_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nrr_service_state.db");
        let conn = open_connection(&path).unwrap();
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().unwrap();
        runner.verify_schema().unwrap();
        (dir, runner.into_connection())
    }

    fn sample(attempt_id: &str, created_at: u64) -> StoredSnapshot {
        StoredSnapshot {
            attempt_id: attempt_id.to_string(),
            snapshot_hash: "abc123".to_string(),
            snapshot_json: r#"{"routing":{},"wfp":{}}"#.to_string(),
            schema_version: 1,
            created_at,
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        let s = sample("att-001", 1000);
        repo.save(&s).unwrap();
        let loaded = repo
            .load("att-001")
            .unwrap()
            .expect("must find saved snapshot");
        assert_eq!(loaded.attempt_id, s.attempt_id);
        assert_eq!(loaded.snapshot_hash, s.snapshot_hash);
        assert_eq!(loaded.snapshot_json, s.snapshot_json);
    }

    #[test]
    fn load_returns_none_for_missing() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        assert!(repo.load("nonexistent").unwrap().is_none());
    }

    #[test]
    fn save_replaces_existing_row() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        repo.save(&sample("att-001", 1000)).unwrap();
        let updated = StoredSnapshot {
            snapshot_hash: "updated_hash".to_string(),
            ..sample("att-001", 1001)
        };
        repo.save(&updated).unwrap();
        let loaded = repo.load("att-001").unwrap().unwrap();
        assert_eq!(loaded.snapshot_hash, "updated_hash");
        assert_eq!(repo.count().unwrap(), 1);
    }

    #[test]
    fn delete_removes_row() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        repo.save(&sample("att-001", 1000)).unwrap();
        repo.delete("att-001").unwrap();
        assert!(repo.load("att-001").unwrap().is_none());
    }

    #[test]
    fn rotate_keeps_latest_n() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        for i in 0..5u64 {
            repo.save(&sample(&format!("att-{i:03}"), i * 100)).unwrap();
        }
        assert_eq!(repo.count().unwrap(), 5);
        let deleted = repo.rotate_keeping_latest_n(2).unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(repo.count().unwrap(), 2);
        // The 2 most recent (att-003 and att-004) must survive.
        assert!(repo.load("att-004").unwrap().is_some());
        assert!(repo.load("att-003").unwrap().is_some());
        assert!(repo.load("att-000").unwrap().is_none());
    }

    #[test]
    fn load_rejects_future_schema_version() {
        let (_dir, conn) = fresh_state_db();
        let repo = ApplySnapshotRepository::new(&conn);
        let future = StoredSnapshot {
            schema_version: MAX_KNOWN_SCHEMA_VERSION + 1,
            ..sample("att-future", 1000)
        };
        repo.save(&future).unwrap();
        let result = repo.load("att-future");
        assert!(
            result.is_err(),
            "future schema_version must produce an error, not silently deserialise"
        );
    }

    #[test]
    fn schema_v4_table_exists_after_migration() {
        let (_dir, conn) = fresh_state_db();
        // If the table didn't exist, save would fail.
        let repo = ApplySnapshotRepository::new(&conn);
        repo.save(&sample("probe", 0)).unwrap();
        assert_eq!(repo.count().unwrap(), 1);
    }
}

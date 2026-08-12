//! `auto_rule_evidence` persistence.
//!
//! What the companion-domain learner has observed, kept across restarts — see
//! [`crate::schema::STATE_DB_V52_DDL`]. A proposal needs the same host beside
//! the same site in two distinct windows, and a restart used to reset that
//! count: on a laptop that sleeps and restarts several times a day the second
//! window never arrived, so nothing was ever offered.
//!
//! `snapshot_json` is opaque here, exactly like `auto_rule_pending.dto_json`:
//! the caller owns the shape, and a new field in it never becomes a migration
//! in this crate.
//!
//! Per-SID, like every other rules-adjacent table: one user's browsing must
//! never inform another user's suggestions.

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Repository over the `auto_rule_evidence` table (state DB).
pub struct AutoRuleEvidenceRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AutoRuleEvidenceRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// The snapshot stored for `sid`, or `None` when nothing was ever saved.
    pub fn load(&self, sid: &str) -> StorageResult<Option<String>> {
        if sid.is_empty() {
            return Ok(None);
        }
        self.conn
            .query_row(
                "SELECT snapshot_json FROM auto_rule_evidence WHERE sid = ?1",
                params![sid],
                |row| row.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StorageError::Internal(format!(
                    "auto_rule_evidence load: {other}"
                ))),
            })
    }

    /// Replaces `sid`'s snapshot. The caller always holds the definitive
    /// in-memory ledger, so one row per SID overwritten wholesale is both
    /// simpler and no less correct than an incremental record.
    pub fn save(&self, sid: &str, snapshot_json: &str, now_ms: i64) -> StorageResult<()> {
        if sid.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO auto_rule_evidence (sid, snapshot_json, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(sid) DO UPDATE SET
                     snapshot_json = excluded.snapshot_json,
                     updated_at = excluded.updated_at",
                params![sid, snapshot_json, now_ms],
            )
            .map_err(|e| StorageError::Internal(format!("auto_rule_evidence save: {e}")))?;
        Ok(())
    }

    /// Forgets everything learned for `sid` — the "start over" path.
    pub fn clear(&self, sid: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM auto_rule_evidence WHERE sid = ?1",
                params![sid],
            )
            .map_err(|e| StorageError::Internal(format!("auto_rule_evidence clear: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;

    fn migrated_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn a_saved_snapshot_reads_back_after_a_restart() {
        let conn = migrated_conn();
        let repo = AutoRuleEvidenceRepository::new(&conn);
        assert_eq!(repo.load("S-A").expect("empty"), None);
        repo.save("S-A", "{\"anchors\":[]}", 100).expect("save");
        // A fresh repository over the same database is what a restart sees.
        assert_eq!(
            AutoRuleEvidenceRepository::new(&conn)
                .load("S-A")
                .expect("load"),
            Some("{\"anchors\":[]}".to_string())
        );
    }

    #[test]
    fn saving_again_replaces_rather_than_duplicates() {
        let conn = migrated_conn();
        let repo = AutoRuleEvidenceRepository::new(&conn);
        repo.save("S-A", "first", 100).expect("first");
        repo.save("S-A", "second", 200).expect("second");
        assert_eq!(repo.load("S-A").expect("load"), Some("second".to_string()));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM auto_rule_evidence", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 1);
    }

    #[test]
    fn one_principal_never_reads_another_ones_evidence() {
        let conn = migrated_conn();
        let repo = AutoRuleEvidenceRepository::new(&conn);
        repo.save("S-A", "a", 100).expect("a");
        assert_eq!(repo.load("S-B").expect("b"), None);
        repo.clear("S-B").expect("clear b");
        assert_eq!(repo.load("S-A").expect("a still there"), Some("a".into()));
    }

    #[test]
    fn clear_forgets_the_named_principal() {
        let conn = migrated_conn();
        let repo = AutoRuleEvidenceRepository::new(&conn);
        repo.save("S-A", "a", 100).expect("a");
        repo.clear("S-A").expect("clear");
        assert_eq!(repo.load("S-A").expect("load"), None);
    }
}

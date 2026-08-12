//! `auto_rule_pending_candidates` persistence.
//!
//! Companion-domain suggestions still waiting for an answer. Durable so the set
//! a user is expected to work through accumulates across service restarts
//! instead of vanishing on the next one — see [`crate::schema::STATE_DB_V47_DDL`].
//!
//! `dto_json` is an opaque blob from this crate's point of view: it is the
//! caller's serialized wire DTO, stored verbatim so a new DTO field never needs
//! a migration here. `route` and `match_kind` are pulled out into their own
//! columns purely so a row is legible in a `.dump` — this crate does not
//! interpret either value.
//!
//! Per-SID, like `auto_rule_dismissals`: one user's suggestions must not leak
//! into another user's list.

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// One pending suggestion as persisted. Reconstructing the caller's typed
/// candidate from this is the caller's job — this crate never depends on the
/// DTO type the JSON encodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoRulePendingRecord {
    /// Stable candidate id — also the `accept` / `dismiss` unit.
    pub candidate_id: String,
    /// Route slug the rule would join, stored for legibility only.
    pub route: String,
    /// Match-kind slug, stored for legibility only.
    pub match_kind: String,
    /// The caller's wire DTO, serialized as-is.
    pub dto_json: String,
    /// UTC Unix millis this row was last written.
    pub parked_at: i64,
}

/// Repository over the `auto_rule_pending_candidates` table (state DB).
pub struct AutoRulePendingRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AutoRulePendingRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Replaces `sid`'s entire persisted set with `candidates`, in one
    /// transaction. The caller always holds the definitive in-memory set for a
    /// SID, so mirroring it wholesale on every change is simpler and no less
    /// correct than diffing row by row — an empty slice clears the SID.
    pub fn replace(&self, sid: &str, candidates: &[AutoRulePendingRecord]) -> StorageResult<()> {
        if sid.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("auto_rule_pending_candidates tx: {e}")))?;
        tx.execute(
            "DELETE FROM auto_rule_pending_candidates WHERE sid = ?1",
            params![sid],
        )
        .map_err(|e| StorageError::Internal(format!("auto_rule_pending_candidates clear: {e}")))?;
        for c in candidates {
            if c.candidate_id.is_empty() {
                continue;
            }
            tx.execute(
                "INSERT INTO auto_rule_pending_candidates
                     (sid, candidate_id, route, match_kind, dto_json, parked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    sid,
                    c.candidate_id,
                    c.route,
                    c.match_kind,
                    c.dto_json,
                    c.parked_at
                ],
            )
            .map_err(|e| {
                StorageError::Internal(format!("auto_rule_pending_candidates insert: {e}"))
            })?;
        }
        tx.commit().map_err(|e| {
            StorageError::Internal(format!("auto_rule_pending_candidates commit: {e}"))
        })
    }

    /// Drops every persisted suggestion for `sid` — companion discovery turned
    /// off, or the principal was evicted for the tracked-principal cap.
    pub fn clear(&self, sid: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM auto_rule_pending_candidates WHERE sid = ?1",
                params![sid],
            )
            .map_err(|e| {
                StorageError::Internal(format!("auto_rule_pending_candidates clear: {e}"))
            })?;
        Ok(())
    }

    /// Every persisted suggestion for every SID, read once at startup to
    /// hydrate the in-memory pending set. Grouping by SID is the caller's job.
    pub fn load_all(&self) -> StorageResult<Vec<(String, AutoRulePendingRecord)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sid, candidate_id, route, match_kind, dto_json, parked_at
                 FROM auto_rule_pending_candidates ORDER BY sid, parked_at DESC",
            )
            .map_err(|e| {
                StorageError::Internal(format!("auto_rule_pending_candidates prepare: {e}"))
            })?;
        let rows = stmt
            .query_map(params![], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    AutoRulePendingRecord {
                        candidate_id: row.get(1)?,
                        route: row.get(2)?,
                        match_kind: row.get(3)?,
                        dto_json: row.get(4)?,
                        parked_at: row.get(5)?,
                    },
                ))
            })
            .map_err(|e| {
                StorageError::Internal(format!("auto_rule_pending_candidates query: {e}"))
            })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::Internal(format!("auto_rule_pending_candidates row: {e}"))
            })?);
        }
        Ok(out)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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

    fn record(id: &str, parked_at: i64) -> AutoRulePendingRecord {
        AutoRulePendingRecord {
            candidate_id: id.to_string(),
            route: "secondary".to_string(),
            match_kind: "exact".to_string(),
            dto_json: format!("{{\"id\":\"{id}\"}}"),
            parked_at,
        }
    }

    #[test]
    fn replace_then_load_round_trips() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("S-A", &[record("arc-1", 100), record("arc-2", 200)])
            .expect("replace");
        let rows = repo.load_all().expect("load");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|(sid, _)| sid == "S-A"));
    }

    #[test]
    fn replace_is_a_full_mirror_not_a_merge() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("S-A", &[record("arc-1", 100), record("arc-2", 200)])
            .expect("first");
        // A second replace naming only one id must drop the other — the
        // caller's in-memory set is always the full truth.
        repo.replace("S-A", &[record("arc-1", 300)])
            .expect("second");
        let rows = repo.load_all().expect("load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.candidate_id, "arc-1");
        assert_eq!(rows[0].1.parked_at, 300);
    }

    #[test]
    fn replace_with_empty_slice_clears_the_sid() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("S-A", &[record("arc-1", 100)]).expect("seed");
        repo.replace("S-A", &[]).expect("clear via empty replace");
        assert!(repo.load_all().expect("load").is_empty());
    }

    #[test]
    fn rows_are_scoped_to_their_sid() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("S-A", &[record("arc-1", 100)]).expect("a");
        repo.replace("S-B", &[record("arc-2", 100)]).expect("b");
        let rows = repo.load_all().expect("load");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn clear_drops_only_the_named_sid() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("S-A", &[record("arc-1", 100)]).expect("a");
        repo.replace("S-B", &[record("arc-2", 100)]).expect("b");
        repo.clear("S-A").expect("clear");
        let rows = repo.load_all().expect("load");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "S-B");
    }

    #[test]
    fn empty_sid_is_a_no_op() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        repo.replace("", &[record("arc-1", 100)]).expect("no-op");
        assert!(repo.load_all().expect("load").is_empty());
    }

    #[test]
    fn dto_json_round_trips_verbatim() {
        let conn = migrated_conn();
        let repo = AutoRulePendingRepository::new(&conn);
        let mut r = record("arc-1", 100);
        r.dto_json = "{\"id\":\"arc-1\",\"affinity\":0.87,\"consumers\":[]}".to_string();
        repo.replace("S-A", &[r.clone()]).expect("replace");
        let rows = repo.load_all().expect("load");
        assert_eq!(rows[0].1.dto_json, r.dto_json);
    }
}

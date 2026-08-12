//! `auto_rule_dismissals` persistence.
//!
//! Companion-domain suggestions the user explicitly refused. See
//! [`crate::schema::STATE_DB_V43_DDL`] for why a refusal is durable — it is a
//! decision made once, and the evidence behind it keeps accumulating, so a
//! restart must not offer the same rejected host again. Pending (unanswered)
//! suggestions have their own durable table; see
//! [`crate::auto_rule_pending`].
//!
//! Per-SID: one user's refusal must not silence another user's suggestion, the
//! same partitioning every other rules-adjacent table uses.

use rusqlite::{params, Connection};
use std::collections::HashSet;

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained refusals per SID. Each row only suppresses one
/// suggestion, so the set is harmless but must not grow without bound on a
/// machine that browses widely for years. On overflow the OLDEST refusals are
/// evicted: by then the evidence that produced them has long since aged out of
/// the in-memory ledger, so re-offering such a host is a fresh finding rather
/// than a repeat of the question the user already answered.
const MAX_DISMISSALS_PER_SID: usize = 4096;

/// One refused suggestion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoRuleDismissal {
    /// Stable candidate id (SID + anchor + proposed match derived).
    pub candidate_id: String,
    /// The routed host the suggestion was made alongside.
    pub anchor: String,
    /// The hostname or domain that was suggested.
    pub proposed_match: String,
    /// The caller's serialized wire DTO, kept verbatim so undoing the refusal
    /// can hand the offer back with its evidence. Never parsed here; empty for
    /// rows written before the column existed.
    pub dto_json: String,
}

/// A refused suggestion as read back for review — [`AutoRuleDismissal`] plus
/// when it happened, which a "your declined suggestions" surface needs and the
/// write path does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoRuleDismissalRecord {
    pub candidate_id: String,
    pub anchor: String,
    pub proposed_match: String,
    /// See [`AutoRuleDismissal::dto_json`].
    pub dto_json: String,
    /// UTC Unix millis the refusal was recorded, or last re-affirmed.
    pub dismissed_at: i64,
}

/// Repository over the `auto_rule_dismissals` table (state DB).
pub struct AutoRuleDismissalsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AutoRuleDismissalsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Record `dismissals` for `sid`, stamping `now` (UTC Unix millis).
    /// Idempotent per `(sid, candidate_id)` — re-refusing refreshes the
    /// timestamp, which also keeps a recently re-offered-and-refused entry
    /// away from the eviction edge. An empty SID or an empty list is a no-op.
    pub fn record(
        &self,
        sid: &str,
        dismissals: &[AutoRuleDismissal],
        now: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() || dismissals.is_empty() {
            return Ok(());
        }
        for d in dismissals {
            if d.candidate_id.is_empty() {
                continue;
            }
            self.conn
                .execute(
                    "INSERT INTO auto_rule_dismissals
                         (sid, candidate_id, anchor, proposed_match, dto_json, dismissed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(sid, candidate_id) DO UPDATE SET
                         anchor = excluded.anchor,
                         proposed_match = excluded.proposed_match,
                         dto_json = excluded.dto_json,
                         dismissed_at = excluded.dismissed_at",
                    params![
                        sid,
                        d.candidate_id,
                        d.anchor,
                        d.proposed_match,
                        d.dto_json,
                        now
                    ],
                )
                .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals insert: {e}")))?;
        }
        self.conn
            .execute(
                "DELETE FROM auto_rule_dismissals WHERE sid = ?1 AND candidate_id IN (
                     SELECT candidate_id FROM auto_rule_dismissals
                     WHERE sid = ?1
                     ORDER BY dismissed_at DESC, candidate_id ASC
                     LIMIT -1 OFFSET ?2
                 )",
                params![sid, MAX_DISMISSALS_PER_SID as i64],
            )
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals evict: {e}")))?;
        Ok(())
    }

    /// Every candidate id `sid` has refused. The caller keeps this in memory
    /// for the lifetime of the process and consults it on every proposal tick,
    /// so the read happens once per SID per service session.
    pub fn load_ids(&self, sid: &str) -> StorageResult<HashSet<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT candidate_id FROM auto_rule_dismissals WHERE sid = ?1")
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals query: {e}")))?;
        let mut out = HashSet::new();
        for row in rows {
            out.insert(
                row.map_err(|e| StorageError::Internal(format!("auto_rule_dismissals row: {e}")))?,
            );
        }
        Ok(out)
    }

    /// Every refusal `sid` has recorded, most recent first — the shape a
    /// "review your declined suggestions" surface needs, as opposed to
    /// [`Self::load_ids`] which only tracks which ids are suppressed.
    pub fn load_all(&self, sid: &str) -> StorageResult<Vec<AutoRuleDismissalRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT candidate_id, anchor, proposed_match, dto_json, dismissed_at
                 FROM auto_rule_dismissals WHERE sid = ?1 ORDER BY dismissed_at DESC",
            )
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| {
                Ok(AutoRuleDismissalRecord {
                    candidate_id: row.get(0)?,
                    anchor: row.get(1)?,
                    proposed_match: row.get(2)?,
                    dto_json: row.get(3)?,
                    dismissed_at: row.get(4)?,
                })
            })
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row.map_err(|e| StorageError::Internal(format!("auto_rule_dismissals row: {e}")))?,
            );
        }
        Ok(out)
    }

    /// Undoes one refusal so the host may be offered again. Returns whether a
    /// row actually existed.
    pub fn forget(&self, sid: &str, candidate_id: &str) -> StorageResult<bool> {
        let changed = self
            .conn
            .execute(
                "DELETE FROM auto_rule_dismissals WHERE sid = ?1 AND candidate_id = ?2",
                params![sid, candidate_id],
            )
            .map_err(|e| StorageError::Internal(format!("auto_rule_dismissals forget: {e}")))?;
        Ok(changed > 0)
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

    fn dismissal(id: &str) -> AutoRuleDismissal {
        AutoRuleDismissal {
            candidate_id: id.to_string(),
            anchor: "site.example".to_string(),
            proposed_match: "cdn.example".to_string(),
            dto_json: format!("{{\"id\":\"{id}\"}}"),
        }
    }

    #[test]
    fn recorded_dismissals_survive_a_reopen_of_the_repository() {
        let conn = migrated_conn();
        AutoRuleDismissalsRepository::new(&conn)
            .record("S-A", &[dismissal("arc-1"), dismissal("arc-2")], 100)
            .expect("record");
        // A fresh repository over the same database is exactly what a service
        // restart sees.
        let ids = AutoRuleDismissalsRepository::new(&conn)
            .load_ids("S-A")
            .expect("load");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("arc-1"));
        assert!(ids.contains("arc-2"));
    }

    #[test]
    fn dismissals_are_scoped_to_their_sid() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("S-A", &[dismissal("arc-1")], 100).expect("a");
        assert!(repo.load_ids("S-B").expect("load").is_empty());
    }

    #[test]
    fn re_recording_is_idempotent_and_refreshes_the_timestamp() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("S-A", &[dismissal("arc-1")], 100).expect("a");
        repo.record("S-A", &[dismissal("arc-1")], 500).expect("b");
        assert_eq!(repo.load_ids("S-A").expect("load").len(), 1);
        let at: i64 = conn
            .query_row("SELECT dismissed_at FROM auto_rule_dismissals", [], |r| {
                r.get(0)
            })
            .expect("query");
        assert_eq!(at, 500);
    }

    #[test]
    fn empty_inputs_are_no_ops() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("", &[dismissal("arc-1")], 100).expect("no sid");
        repo.record("S-A", &[], 100).expect("no rows");
        assert!(repo.load_ids("S-A").expect("load").is_empty());
    }

    #[test]
    fn overflow_evicts_the_oldest_refusals() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        for i in 0..(MAX_DISMISSALS_PER_SID + 8) {
            repo.record("S-A", &[dismissal(&format!("arc-{i}"))], i as i64)
                .expect("record");
        }
        let ids = repo.load_ids("S-A").expect("load");
        assert_eq!(ids.len(), MAX_DISMISSALS_PER_SID);
        assert!(!ids.contains("arc-0"), "oldest refusal evicted");
        assert!(
            ids.contains(&format!("arc-{}", MAX_DISMISSALS_PER_SID + 7)),
            "newest refusal survives"
        );
    }

    #[test]
    fn load_all_returns_full_rows_newest_first() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("S-A", &[dismissal("arc-1")], 100).expect("a");
        repo.record("S-A", &[dismissal("arc-2")], 200).expect("b");
        let rows = repo.load_all("S-A").expect("load_all");
        assert_eq!(
            rows,
            vec![
                AutoRuleDismissalRecord {
                    candidate_id: "arc-2".to_string(),
                    anchor: "site.example".to_string(),
                    proposed_match: "cdn.example".to_string(),
                    dto_json: "{\"id\":\"arc-2\"}".to_string(),
                    dismissed_at: 200,
                },
                AutoRuleDismissalRecord {
                    candidate_id: "arc-1".to_string(),
                    anchor: "site.example".to_string(),
                    proposed_match: "cdn.example".to_string(),
                    dto_json: "{\"id\":\"arc-1\"}".to_string(),
                    dismissed_at: 100,
                },
            ]
        );
    }

    #[test]
    fn forget_removes_the_row_and_reports_whether_one_existed() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("S-A", &[dismissal("arc-1")], 100).expect("a");
        assert!(repo.forget("S-A", "arc-1").expect("forget"));
        assert!(repo.load_ids("S-A").expect("load").is_empty());
        assert!(!repo.forget("S-A", "arc-1").expect("forget again"));
    }

    #[test]
    fn forget_is_scoped_to_its_sid() {
        let conn = migrated_conn();
        let repo = AutoRuleDismissalsRepository::new(&conn);
        repo.record("S-A", &[dismissal("arc-1")], 100).expect("a");
        assert!(!repo.forget("S-B", "arc-1").expect("forget wrong sid"));
        assert!(repo.load_ids("S-A").expect("load").contains("arc-1"));
    }
}

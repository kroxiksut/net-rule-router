//! `block_notice_journal` persistence.
//!
//! A queue of block notices raised while nothing was listening. The push
//! channel is live-only: with no tray and no window up, a
//! [`nrr_domain::block_notice::BlockNotice`] used to reach the operational log
//! and nowhere else, so a user running the service alone was told nothing.
//! Rows land here at the moment the notice is raised and leave when a surface
//! acknowledges having shown them.
//!
//! Per-SID for the same reason mutes are: one user's blocks are not another
//! user's news.
//!
//! Bounded twice over — by count and by age. This is a backlog of things worth
//! telling someone, not a history: what happened last month answers no question
//! the user still has, and the audit trail keeps the record either way.

use nrr_domain::block_notice::{BlockNotice, BlockReason};
use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Retained unacknowledged notices per SID. A drop storm folds into episodes
/// long before it gets here, so reaching this cap means the user was away for
/// a very long time — and the oldest entries are the least worth keeping.
const MAX_ENTRIES_PER_SID: usize = 200;

/// Age at which an unshown notice stops being news, in milliseconds.
const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Separator of the stored ancestry. Image names never contain it; one that
/// did is dropped rather than split into two false names.
const LAUNCHED_BY_SEPARATOR: char = '\n';

/// One journalled notice: the notice itself plus the identity a surface
/// acknowledges it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalledNotice {
    /// Monotonic per-database id; `ack_through` takes the largest one shown.
    pub id: i64,
    pub raised_at_ms: i64,
    pub notice: BlockNotice,
}

/// Repository over the `block_notice_journal` table (state DB).
pub struct BlockNoticeJournalRepository<'c> {
    conn: &'c Connection,
}

impl<'c> BlockNoticeJournalRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Record one raised notice. A no-op for an empty `sid`: an unattributed
    /// block has no user to tell about it later.
    pub fn append(&self, sid: &str, notice: &BlockNotice, now_ms: i64) -> StorageResult<()> {
        if sid.is_empty() {
            return Ok(());
        }
        // The eviction keeps the cap only if it commits with the insert.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("block_notice_journal tx: {e}")))?;
        tx.execute(
            "INSERT INTO block_notice_journal
                     (sid, raised_at, destination, app, reason, attempts, launched_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                sid,
                now_ms,
                notice.destination,
                notice.app,
                notice.reason.slug(),
                i64::from(notice.attempts),
                encode_launched_by(&notice.launched_by),
            ],
        )
        .map_err(|e| StorageError::Internal(format!("block_notice_journal append: {e}")))?;
        self.purge_stale(sid, now_ms)?;
        self.evict_overflow(sid)?;
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("block_notice_journal commit: {e}")))
    }

    /// Everything `sid` has not been shown yet, oldest first — the order a
    /// surface would have received them in.
    pub fn list_pending(&self, sid: &str, now_ms: i64) -> StorageResult<Vec<JournalledNotice>> {
        self.purge_stale(sid, now_ms)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, raised_at, destination, app, reason, attempts, launched_by
                 FROM block_notice_journal WHERE sid = ?1 ORDER BY id ASC",
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_journal prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("block_notice_journal query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, raised_at, destination, app, reason, attempts, launched_by) =
                row.map_err(|e| StorageError::Internal(format!("block_notice_journal row: {e}")))?;
            // An unreadable reason slug drops the row rather than the whole
            // read: the backlog is best-effort news, and refusing to show the
            // other nine entries helps nobody.
            let Some(reason) = BlockReason::from_slug(&reason) else {
                continue;
            };
            out.push(JournalledNotice {
                id,
                raised_at_ms: raised_at,
                notice: BlockNotice {
                    destination,
                    app,
                    reason,
                    first_attempt_ms: raised_at.max(0) as u64,
                    attempts: attempts.clamp(0, i64::from(u32::MAX)) as u32,
                    launched_by: decode_launched_by(&launched_by),
                },
            });
        }
        Ok(out)
    }

    /// Drop everything up to and including `through_id` — a surface has shown
    /// those. Bounded by id rather than "delete all" so notices raised while
    /// the list was in flight survive to be shown next time.
    pub fn ack_through(&self, sid: &str, through_id: i64) -> StorageResult<usize> {
        let removed = self
            .conn
            .execute(
                "DELETE FROM block_notice_journal WHERE sid = ?1 AND id <= ?2",
                params![sid, through_id],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_journal ack: {e}")))?;
        Ok(removed)
    }

    fn purge_stale(&self, sid: &str, now_ms: i64) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM block_notice_journal WHERE sid = ?1 AND raised_at < ?2",
                params![sid, now_ms.saturating_sub(MAX_AGE_MS)],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_journal purge: {e}")))?;
        Ok(())
    }

    fn evict_overflow(&self, sid: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM block_notice_journal WHERE sid = ?1 AND id IN (
                     SELECT id FROM block_notice_journal
                     WHERE sid = ?1
                     ORDER BY id DESC
                     LIMIT -1 OFFSET ?2
                 )",
                params![sid, MAX_ENTRIES_PER_SID as i64],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_journal evict: {e}")))?;
        Ok(())
    }
}

/// Names joined for the TEXT column, within its length bound: the tail of a
/// longer chain is the least useful part and goes first.
fn encode_launched_by(names: &[String]) -> String {
    const MAX_BYTES: usize = 2048;
    let mut out = String::new();
    for name in names
        .iter()
        .filter(|n| !n.is_empty() && !n.contains(LAUNCHED_BY_SEPARATOR))
    {
        let extra = name.len() + usize::from(!out.is_empty());
        if out.len() + extra > MAX_BYTES {
            break;
        }
        if !out.is_empty() {
            out.push(LAUNCHED_BY_SEPARATOR);
        }
        out.push_str(name);
    }
    out
}

fn decode_launched_by(stored: &str) -> Vec<String> {
    stored
        .split(LAUNCHED_BY_SEPARATOR)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .collect()
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

    fn notice(destination: &str) -> BlockNotice {
        BlockNotice {
            destination: destination.to_string(),
            app: "app.exe".to_string(),
            reason: BlockReason::BlockedByRule,
            first_attempt_ms: 0,
            attempts: 3,
            launched_by: Vec::new(),
        }
    }

    #[test]
    fn the_ancestry_survives_the_backlog() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        let mut raised = notice("a.example");
        raised.launched_by = vec!["pwsh.exe".into(), "explorer.exe".into()];
        repo.append("S-1", &raised, 1_000).expect("append");
        repo.append("S-1", &notice("b.example"), 1_001)
            .expect("append");

        let pending = repo.list_pending("S-1", 2_000).expect("list");
        assert_eq!(pending[0].notice.launched_by, raised.launched_by);
        assert!(pending[1].notice.launched_by.is_empty());
    }

    #[test]
    fn a_name_that_would_split_is_dropped_not_stored() {
        let names = vec!["a.exe".to_string(), "b\nc".to_string(), "d.exe".to_string()];
        assert_eq!(
            decode_launched_by(&encode_launched_by(&names)),
            vec!["a.exe", "d.exe"]
        );
        let long = vec!["x".repeat(1500), "y".repeat(1500)];
        assert_eq!(decode_launched_by(&encode_launched_by(&long)).len(), 1);
    }

    #[test]
    fn appended_notices_come_back_oldest_first() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        repo.append("S-1-5-21-1", &notice("a.example"), 1_000)
            .expect("append");
        repo.append("S-1-5-21-1", &notice("b.example"), 2_000)
            .expect("append");

        let pending = repo.list_pending("S-1-5-21-1", 3_000).expect("list");
        let names: Vec<_> = pending
            .iter()
            .map(|e| e.notice.destination.as_str())
            .collect();
        assert_eq!(names, vec!["a.example", "b.example"]);
        assert_eq!(pending[0].raised_at_ms, 1_000);
        assert_eq!(pending[0].notice.attempts, 3);
    }

    #[test]
    fn one_principals_backlog_is_invisible_to_another() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        repo.append("S-1-5-21-1", &notice("a.example"), 1_000)
            .expect("append");

        assert!(repo
            .list_pending("S-1-5-21-2", 2_000)
            .expect("list")
            .is_empty());
    }

    #[test]
    fn ack_removes_only_what_was_shown() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        repo.append("S-1", &notice("a.example"), 1_000)
            .expect("append");
        repo.append("S-1", &notice("b.example"), 2_000)
            .expect("append");
        let shown = repo.list_pending("S-1", 2_500).expect("list");
        let first = shown[0].id;
        // Raised after the surface read the list — must survive the ack.
        repo.append("S-1", &notice("c.example"), 2_600)
            .expect("append");

        assert_eq!(repo.ack_through("S-1", first).expect("ack"), 1);
        let left: Vec<_> = repo
            .list_pending("S-1", 3_000)
            .expect("list")
            .into_iter()
            .map(|e| e.notice.destination)
            .collect();
        assert_eq!(left, vec!["b.example", "c.example"]);
    }

    #[test]
    fn entries_older_than_the_age_bound_are_dropped() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        repo.append("S-1", &notice("stale.example"), 1_000)
            .expect("append");

        let pending = repo
            .list_pending("S-1", 1_000 + MAX_AGE_MS + 1)
            .expect("list");
        assert!(pending.is_empty(), "a week-old notice is no longer news");
    }

    #[test]
    fn the_backlog_keeps_the_newest_entries_when_it_overflows() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        for i in 0..(MAX_ENTRIES_PER_SID + 5) {
            repo.append("S-1", &notice(&format!("h{i}.example")), 1_000 + i as i64)
                .expect("append");
        }

        let pending = repo.list_pending("S-1", 2_000).expect("list");
        assert_eq!(pending.len(), MAX_ENTRIES_PER_SID);
        assert_eq!(
            pending
                .last()
                .map(|e| e.notice.destination.as_str())
                .unwrap_or_default(),
            format!("h{}.example", MAX_ENTRIES_PER_SID + 4)
        );
    }

    #[test]
    fn an_unattributed_principal_is_not_journalled() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        repo.append("", &notice("a.example"), 1_000)
            .expect("append");

        assert!(repo.list_pending("", 2_000).expect("list").is_empty());
    }

    #[test]
    fn a_failed_eviction_rolls_the_append_back_so_the_cap_holds() {
        let conn = migrated_conn();
        let repo = BlockNoticeJournalRepository::new(&conn);
        for i in 0..MAX_ENTRIES_PER_SID {
            repo.append("S-A", &notice(&format!("host-{i}.example")), 1_000)
                .expect("fill to cap");
        }
        conn.execute_batch(
            "CREATE TEMP TRIGGER fail_evict BEFORE DELETE ON block_notice_journal
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .expect("trigger");

        assert!(repo.append("S-A", &notice("late.example"), 1_000).is_err());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM block_notice_journal", [], |r| {
                r.get(0)
            })
            .expect("count");
        assert_eq!(count, MAX_ENTRIES_PER_SID as i64);
        let stored: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM block_notice_journal WHERE destination = 'late.example'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(stored, 0, "the failed append left no row");
    }
}

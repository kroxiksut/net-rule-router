//! Connection-history store (`nrr_conn_history.db`) and each user's choices
//! about it (`conn_history_prefs` in the state DB).
//!
//! The history is rebuildable: a damaged file is deleted and created again
//! (see [`crate::migration::open_conn_history_connection_or_rebuild`]), losing
//! only history. The choices live in the state DB so that a rebuild never
//! switches back on a history a user switched off.
//!
//! Rows arrive already folded per hour by the service; this layer adds them
//! up, ages them out per user, keeps the file under a byte cap by removing the
//! oldest hour of whoever holds the most rows, and counts what the cap removed.

use std::cell::RefCell;

use rusqlite::{params, Connection, ErrorCode, OptionalExtension};

use crate::error::{StorageError, StorageResult};

/// One hour of a user's connections to one destination, as the service folded
/// them. Empty strings stand for "not known".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnHistoryRow {
    pub principal: String,
    /// Unix milliseconds divided by an hour.
    pub hour: i64,
    pub program: String,
    pub host: String,
    pub remote_ip: String,
    pub route: String,
    pub verdict: String,
    pub blocked_by: String,
    pub first_ms: i64,
    pub last_ms: i64,
    pub attempts: u32,
    pub block_reason: String,
}

/// One destination of one program over the asked period, its hours added up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnHistoryEntry {
    pub program: String,
    pub host: String,
    pub remote_ip: String,
    pub route: String,
    pub verdict: String,
    pub blocked_by: String,
    pub first_ms: i64,
    pub last_ms: i64,
    pub attempts: u64,
    pub block_reason: String,
}

/// Where the previous page ended: the sort key of its last entry (its clipped
/// last time stands for its hour), so the next page starts after it whatever
/// was written in between.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnHistoryCursor {
    pub last_ms: i64,
    pub program: String,
    pub host: String,
    pub remote_ip: String,
    pub route: String,
    pub verdict: String,
    pub blocked_by: String,
}

impl ConnHistoryCursor {
    /// The cursor that continues after `entry`.
    pub fn after(entry: &ConnHistoryEntry) -> Self {
        Self {
            last_ms: entry.last_ms,
            program: entry.program.clone(),
            host: entry.host.clone(),
            remote_ip: entry.remote_ip.clone(),
            route: entry.route.clone(),
            verdict: entry.verdict.clone(),
            blocked_by: entry.blocked_by.clone(),
        }
    }
}

/// What [`SqliteConnHistoryStore::list`] reads.
#[derive(Clone, Debug, Default)]
pub struct ConnHistoryQuery<'a> {
    /// `None` reads every user's rows; no client read asks for it.
    pub principal: Option<&'a str>,
    pub from_ms: i64,
    pub to_ms: i64,
    /// Case-insensitive part of the program path.
    pub program: Option<&'a str>,
    /// An exact verdict slug.
    pub verdict: Option<&'a str>,
    /// Continue after this entry; `None` starts from the newest.
    pub after: Option<&'a ConnHistoryCursor>,
    pub limit: u32,
}

const HOUR_MS: i64 = 3_600_000;

/// Owns the one connection to `nrr_conn_history.db`.
pub struct SqliteConnHistoryStore {
    conn: RefCell<Connection>,
}

/// A damaged file reads as [`StorageError::CorruptCache`], the signal to
/// rebuild; anything else is [`StorageError::Internal`].
fn db_err(context: &str, e: rusqlite::Error) -> StorageError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            StorageError::CorruptCache(format!("conn history {context}: {e}"))
        }
        _ => StorageError::Internal(format!("conn history {context}: {e}")),
    }
}

/// `LIKE` with `\` as the escape, so a `%` or `_` in a path matches itself.
fn like_pattern(part: &str) -> String {
    let mut out = String::with_capacity(part.len() + 2);
    out.push('%');
    for c in part.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

impl SqliteConnHistoryStore {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: RefCell::new(conn),
        }
    }

    pub fn into_connection(self) -> Connection {
        self.conn.into_inner()
    }

    /// Adds one flush worth of hour rows, in one transaction.
    pub fn upsert(&self, rows: &[ConnHistoryRow]) -> StorageResult<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(|e| db_err("begin", e))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO conn_history (principal, hour, program, host, remote_ip, route,
                         verdict, blocked_by, first_ms, last_ms, attempts, block_reason)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(principal, hour, program, remote_ip, host, route, verdict,
                                 blocked_by) DO UPDATE SET
                         first_ms = MIN(first_ms, excluded.first_ms),
                         last_ms = MAX(last_ms, excluded.last_ms),
                         attempts = attempts + excluded.attempts,
                         block_reason = CASE WHEN excluded.block_reason != ''
                                             THEN excluded.block_reason ELSE block_reason END",
                )
                .map_err(|e| db_err("prepare upsert", e))?;
            for r in rows {
                stmt.execute(params![
                    r.principal,
                    r.hour,
                    r.program,
                    r.host,
                    r.remote_ip,
                    r.route,
                    r.verdict,
                    r.blocked_by,
                    r.first_ms,
                    r.last_ms,
                    i64::from(r.attempts),
                    r.block_reason,
                ])
                .map_err(|e| db_err("upsert", e))?;
            }
        }
        tx.commit().map_err(|e| db_err("commit", e))
    }

    /// The period's destinations, latest hour first, each one's hours added
    /// up; first and last times are clipped to the period. Reads `limit` rows
    /// after the cursor. The order is by hour, not by last time: a write
    /// under a pinned period end moves a last time but never an hour, so a
    /// walk over pages neither repeats nor skips a destination.
    pub fn list(&self, q: &ConnHistoryQuery<'_>) -> StorageResult<Vec<ConnHistoryEntry>> {
        let conn = self.conn.borrow();
        let from_hour = q.from_ms.div_euclid(HOUR_MS);
        let to_hour = q.to_ms.div_euclid(HOUR_MS);
        let program = q.program.filter(|p| !p.is_empty()).map(like_pattern);
        // Two statements rather than `?1 IS NULL OR …`, which would cost a
        // user's read the `(principal, hour)` key and scan the whole file.
        let sql = format!(
            "SELECT program, host, remote_ip, route, verdict, blocked_by,
                    MAX(MIN(first_ms), ?4), MAX(MIN(last_ms, ?5)), SUM(attempts),
                    MAX(block_reason)
             FROM conn_history
             WHERE {}
               AND hour BETWEEN ?2 AND ?3
               AND last_ms >= ?4 AND first_ms <= ?5
               AND (?6 IS NULL OR program LIKE ?6 ESCAPE '\\')
               AND (?7 IS NULL OR verdict = ?7)
             GROUP BY program, host, remote_ip, route, verdict, blocked_by
             HAVING ?9 IS NULL
                 OR MAX(hour) < ?9
                 OR (MAX(hour) = ?9
                     AND (program, host, remote_ip, route, verdict, blocked_by)
                         > (?10, ?11, ?12, ?13, ?14, ?15))
             ORDER BY MAX(hour) DESC,
                      program, host, remote_ip, route, verdict, blocked_by
             LIMIT ?8",
            if q.principal.is_some() {
                "principal = ?1"
            } else {
                "?1 IS NULL"
            }
        );
        let mut stmt = conn
            .prepare_cached(&sql)
            .map_err(|e| db_err("prepare list", e))?;
        let after = q.after;
        let rows = stmt
            .query_map(
                params![
                    q.principal,
                    from_hour,
                    to_hour,
                    q.from_ms,
                    q.to_ms,
                    program,
                    q.verdict,
                    i64::from(q.limit),
                    after.map(|c| c.last_ms.div_euclid(HOUR_MS)),
                    after.map(|c| c.program.as_str()),
                    after.map(|c| c.host.as_str()),
                    after.map(|c| c.remote_ip.as_str()),
                    after.map(|c| c.route.as_str()),
                    after.map(|c| c.verdict.as_str()),
                    after.map(|c| c.blocked_by.as_str()),
                ],
                |r| {
                    Ok(ConnHistoryEntry {
                        program: r.get(0)?,
                        host: r.get(1)?,
                        remote_ip: r.get(2)?,
                        route: r.get(3)?,
                        verdict: r.get(4)?,
                        blocked_by: r.get(5)?,
                        first_ms: r.get(6)?,
                        last_ms: r.get(7)?,
                        attempts: r.get::<_, i64>(8)?.max(0) as u64,
                        block_reason: r.get(9)?,
                    })
                },
            )
            .map_err(|e| db_err("list", e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| db_err("list row", e))
    }

    /// Rows the size cap removed from `principal` (`None`: every user's).
    pub fn removed_for(&self, principal: Option<&str>) -> StorageResult<u64> {
        let conn = self.conn.borrow();
        let n: Option<i64> = conn
            .query_row(
                "SELECT SUM(rows) FROM conn_history_removed WHERE ?1 IS NULL OR principal = ?1",
                params![principal],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| db_err("removed", e))?
            .flatten();
        Ok(n.unwrap_or(0).max(0) as u64)
    }

    /// Erases one user's history and their removal count. Returns the rows
    /// erased. Freed pages are zeroed (`secure_delete`), so nothing of it
    /// stays readable in the file.
    pub fn clear_principal(&self, principal: &str) -> StorageResult<u64> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(|e| db_err("begin", e))?;
        let erased = tx
            .execute(
                "DELETE FROM conn_history WHERE principal = ?1",
                params![principal],
            )
            .map_err(|e| db_err("clear", e))?;
        tx.execute(
            "DELETE FROM conn_history_removed WHERE principal = ?1",
            params![principal],
        )
        .map_err(|e| db_err("clear removed", e))?;
        tx.commit().map_err(|e| db_err("commit", e))?;
        Ok(erased as u64)
    }

    /// Erases every user's history and every removal count, for a reset of
    /// the whole machine. Returns the rows erased.
    pub fn clear_all(&self) -> StorageResult<u64> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(|e| db_err("begin", e))?;
        let erased = tx
            .execute("DELETE FROM conn_history", [])
            .map_err(|e| db_err("clear all", e))?;
        tx.execute("DELETE FROM conn_history_removed", [])
            .map_err(|e| db_err("clear all removed", e))?;
        tx.commit().map_err(|e| db_err("commit", e))?;
        Ok(erased as u64)
    }

    /// Drops every row older than its user's cutoff hour (`cutoff_hour` is
    /// asked once per user present in the file). Returns the rows dropped.
    pub fn expire(&self, cutoff_hour: impl Fn(&str) -> i64) -> StorageResult<u64> {
        let principals: Vec<String> = {
            let conn = self.conn.borrow();
            let mut stmt = conn
                .prepare("SELECT DISTINCT principal FROM conn_history")
                .map_err(|e| db_err("prepare principals", e))?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| db_err("principals", e))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| db_err("principals row", e))?
        };
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(|e| db_err("begin", e))?;
        let mut dropped = 0u64;
        for principal in &principals {
            let n = tx
                .execute(
                    "DELETE FROM conn_history WHERE principal = ?1 AND hour < ?2",
                    params![principal, cutoff_hour(principal)],
                )
                .map_err(|e| db_err("expire", e))?;
            dropped = dropped.saturating_add(n as u64);
        }
        tx.commit().map_err(|e| db_err("commit", e))?;
        Ok(dropped)
    }

    /// Bytes the rows occupy: the file's pages less the free ones, which the
    /// next writes reuse.
    pub fn used_bytes(&self) -> StorageResult<u64> {
        let conn = self.conn.borrow();
        let pragma = |name: &str| -> StorageResult<i64> {
            conn.query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))
                .map_err(|e| db_err("pragma", e))
        };
        let pages = pragma("page_count")?.saturating_sub(pragma("freelist_count")?);
        Ok((pages.max(0) as u64).saturating_mul(pragma("page_size")?.max(0) as u64))
    }

    /// Removes whole hours until the rows fit in `max_bytes`: each pass takes
    /// the oldest hour of the user holding the most rows, so one user's
    /// burst never costs another their week. What went is added to that
    /// user's removal count. Returns the rows removed.
    pub fn enforce_cap(&self, max_bytes: u64) -> StorageResult<u64> {
        let mut removed = 0u64;
        while self.used_bytes()? > max_bytes {
            let mut conn = self.conn.borrow_mut();
            let tx = conn.transaction().map_err(|e| db_err("begin", e))?;
            let oldest: Option<(String, i64)> = tx
                .query_row(
                    "SELECT principal, MIN(hour) FROM conn_history
                     GROUP BY principal ORDER BY COUNT(*) DESC, principal LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| db_err("oldest hour", e))?;
            let Some((principal, hour)) = oldest else {
                break;
            };
            tx.execute(
                "INSERT INTO conn_history_removed (principal, rows)
                 SELECT principal, COUNT(*) FROM conn_history
                 WHERE principal = ?1 AND hour = ?2 GROUP BY principal
                 ON CONFLICT(principal) DO UPDATE SET rows = rows + excluded.rows",
                params![principal, hour],
            )
            .map_err(|e| db_err("count removed", e))?;
            let n = tx
                .execute(
                    "DELETE FROM conn_history WHERE principal = ?1 AND hour = ?2",
                    params![principal, hour],
                )
                .map_err(|e| db_err("remove hour", e))?;
            tx.commit().map_err(|e| db_err("commit", e))?;
            removed = removed.saturating_add(n as u64);
        }
        Ok(removed)
    }

    /// Folds the journal into the file and truncates it; refused while another
    /// connection is open, in which case the next pass retries.
    pub fn checkpoint_wal(&self) -> StorageResult<()> {
        crate::migration::checkpoint_wal_truncate(&self.conn.borrow())
    }
}

// ── Each user's choices (state DB) ───────────────────────────────────────────

/// Keep the history unless the user says otherwise.
pub const DEFAULT_ENABLED: bool = true;
/// Days kept unless the user chose otherwise.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// The longest period a user may choose.
pub const MAX_RETENTION_DAYS: u32 = 30;

/// One user's connection-history choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnHistoryPrefs {
    pub enabled: bool,
    /// `1..=MAX_RETENTION_DAYS`.
    pub retention_days: u32,
}

impl Default for ConnHistoryPrefs {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_ENABLED,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// `conn_history_prefs` over the state DB connection.
pub struct ConnHistoryPrefsRepository<'a> {
    conn: &'a Connection,
}

impl<'a> ConnHistoryPrefsRepository<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Every user who chose something; the rest keep the defaults.
    pub fn list(&self) -> StorageResult<Vec<(String, ConnHistoryPrefs)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT sid, enabled, retention_days FROM conn_history_prefs ORDER BY sid")
            .map_err(|e| StorageError::Internal(format!("conn history prefs prepare: {e}")))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    ConnHistoryPrefs {
                        enabled: r.get::<_, i64>(1)? != 0,
                        retention_days: r.get::<_, i64>(2)?.clamp(1, i64::from(MAX_RETENTION_DAYS))
                            as u32,
                    },
                ))
            })
            .map_err(|e| StorageError::Internal(format!("conn history prefs query: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("conn history prefs row: {e}")))
    }

    /// Store `sid`'s choices; out-of-range days are refused, not clamped.
    pub fn set(&self, sid: &str, prefs: ConnHistoryPrefs, now_ms: i64) -> StorageResult<()> {
        if sid.is_empty() || !(1..=MAX_RETENTION_DAYS).contains(&prefs.retention_days) {
            return Err(StorageError::Internal(
                "conn history prefs: no user or days out of range".into(),
            ));
        }
        self.conn
            .execute(
                "INSERT INTO conn_history_prefs (sid, enabled, retention_days, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(sid) DO UPDATE SET enabled = excluded.enabled,
                     retention_days = excluded.retention_days,
                     updated_at = excluded.updated_at",
                params![
                    sid,
                    i64::from(prefs.enabled),
                    i64::from(prefs.retention_days),
                    now_ms
                ],
            )
            .map(|_| ())
            .map_err(|e| StorageError::Internal(format!("conn history prefs upsert: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_conn_history_connection_or_rebuild, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn store() -> (tempfile::TempDir, SqliteConnHistoryStore) {
        let dir = tempfile::tempdir().expect("temp dir");
        let opened = open_conn_history_connection_or_rebuild(&dir.path().join("h.db"))
            .expect("open history");
        (dir, SqliteConnHistoryStore::new(opened.connection))
    }

    fn row(principal: &str, hour: i64, program: &str, ip: &str, attempts: u32) -> ConnHistoryRow {
        let base = hour * HOUR_MS;
        ConnHistoryRow {
            principal: principal.into(),
            hour,
            program: program.into(),
            host: "site.example".into(),
            remote_ip: ip.into(),
            route: "primary".into(),
            verdict: "permit".into(),
            blocked_by: String::new(),
            first_ms: base + 10,
            last_ms: base + 20,
            attempts,
            block_reason: String::new(),
        }
    }

    fn all(principal: Option<&str>) -> ConnHistoryQuery<'_> {
        ConnHistoryQuery {
            principal,
            from_ms: 0,
            to_ms: i64::MAX / 2,
            limit: 100,
            ..ConnHistoryQuery::default()
        }
    }

    #[test]
    fn flushes_add_up_and_a_read_folds_the_hours_of_one_destination() {
        let (_dir, s) = store();
        s.upsert(&[row("S-1", 10, r"C:\a\browser.exe", "192.0.2.1", 3)])
            .expect("first");
        s.upsert(&[
            row("S-1", 10, r"C:\a\browser.exe", "192.0.2.1", 2),
            row("S-1", 11, r"C:\a\browser.exe", "192.0.2.1", 5),
            row("S-1", 11, r"C:\a\mail.exe", "192.0.2.2", 1),
        ])
        .expect("second");
        let got = s.list(&all(Some("S-1"))).expect("list");
        assert_eq!(got.len(), 2);
        let browser = got
            .iter()
            .find(|e| e.program.ends_with("browser.exe"))
            .expect("browser");
        assert_eq!(browser.attempts, 10, "two flushes of hour 10 plus hour 11");
        assert_eq!(browser.first_ms, 10 * HOUR_MS + 10);
        assert_eq!(browser.last_ms, 11 * HOUR_MS + 20);
    }

    #[test]
    fn a_read_keeps_to_its_user_its_period_and_its_filters() {
        let (_dir, s) = store();
        s.upsert(&[
            row("S-1", 10, r"C:\a\browser.exe", "192.0.2.1", 1),
            row("S-1", 20, r"C:\a\100%_app.exe", "192.0.2.3", 1),
            row("S-2", 10, r"C:\a\secret.exe", "192.0.2.9", 1),
        ])
        .expect("upsert");
        let mine = s.list(&all(Some("S-1"))).expect("mine");
        assert!(mine.iter().all(|e| !e.program.contains("secret")));
        assert_eq!(s.list(&all(None)).expect("machine").len(), 3);

        let period = ConnHistoryQuery {
            from_ms: 20 * HOUR_MS,
            ..all(Some("S-1"))
        };
        let late = s.list(&period).expect("period");
        assert_eq!(late.len(), 1);
        assert!(late[0].program.contains("100%_app"));

        let literal = ConnHistoryQuery {
            program: Some("0%_A"),
            ..all(Some("S-1"))
        };
        assert_eq!(
            s.list(&literal).expect("filter").len(),
            1,
            "% and _ match themselves, case-insensitively"
        );
        let blocked = ConnHistoryQuery {
            verdict: Some("block"),
            ..all(Some("S-1"))
        };
        assert!(s.list(&blocked).expect("verdict").is_empty());
    }

    #[test]
    fn paging_walks_the_destinations_newest_first() {
        let (_dir, s) = store();
        let rows: Vec<_> = (0..5)
            .map(|n| row("S-1", 10 + n, "app.exe", &format!("192.0.2.{n}"), 1))
            .collect();
        s.upsert(&rows).expect("upsert");
        let first = s
            .list(&ConnHistoryQuery {
                limit: 2,
                ..all(Some("S-1"))
            })
            .expect("page 1");
        assert_eq!(first[0].remote_ip, "192.0.2.4");
        let cursor = ConnHistoryCursor::after(&first[1]);
        let second = s
            .list(&ConnHistoryQuery {
                limit: 2,
                after: Some(&cursor),
                ..all(Some("S-1"))
            })
            .expect("page 2");
        assert_eq!(second[0].remote_ip, "192.0.2.2");
    }

    #[test]
    fn a_page_continues_after_its_cursor_whatever_was_written_meanwhile() {
        let (_dir, s) = store();
        // Four destinations last used in the same hour; the order within it
        // is the full group key, so two with one address still sort alike
        // from page to page.
        let mut rows: Vec<_> = (0..4)
            .map(|n| row("S-1", 10, "app.exe", &format!("192.0.2.{n}"), 1))
            .collect();
        rows[2].host = "other.example".into();
        rows[2].remote_ip = "192.0.2.1".into();
        s.upsert(&rows).expect("upsert");
        let to_ms = 10 * HOUR_MS + 30;
        let page = |after: Option<&ConnHistoryCursor>| {
            s.list(&ConnHistoryQuery {
                limit: 2,
                after,
                to_ms,
                ..all(Some("S-1"))
            })
            .expect("page")
        };
        let first = page(None);
        let cursor = ConnHistoryCursor::after(&first[1]);
        // A destination not shown yet is used again before page 2 is read,
        // in the same hour past the pinned end and in a newer hour: it keeps
        // its place either way.
        let mut same_hour = row("S-1", 10, "app.exe", "192.0.2.3", 1);
        same_hour.first_ms = 10 * HOUR_MS + 40;
        same_hour.last_ms = 10 * HOUR_MS + 40;
        s.upsert(&[same_hour, row("S-1", 12, "app.exe", "192.0.2.3", 1)])
            .expect("newer");
        let second = page(Some(&cursor));
        let mut seen: Vec<(String, String)> = first
            .iter()
            .chain(&second)
            .map(|e| (e.remote_ip.clone(), e.host.clone()))
            .collect();
        assert_eq!(seen.len(), 4, "every destination once");
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 4, "none twice");
        assert!(page(Some(&ConnHistoryCursor::after(&second[1]))).is_empty());
    }

    #[test]
    fn first_and_last_times_are_clipped_to_the_period() {
        let (_dir, s) = store();
        s.upsert(&[row("S-1", 10, "app.exe", "192.0.2.1", 3)])
            .expect("upsert");
        let got = s
            .list(&ConnHistoryQuery {
                from_ms: 10 * HOUR_MS + 15,
                to_ms: 10 * HOUR_MS + 18,
                ..all(Some("S-1"))
            })
            .expect("list");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].first_ms, 10 * HOUR_MS + 15);
        assert_eq!(got[0].last_ms, 10 * HOUR_MS + 18);
        assert_eq!(got[0].attempts, 3, "hours are folded; attempts stay whole");
    }

    #[test]
    fn the_cap_takes_from_the_heaviest_user_not_from_the_oldest_rows() {
        let (_dir, s) = store();
        let mut rows = vec![row("S-2", 0, "light.exe", "192.0.2.9", 1)];
        for hour in 1..40 {
            for n in 0..50 {
                rows.push(row(
                    "S-1",
                    hour,
                    &format!("program-{n}.exe"),
                    "192.0.2.1",
                    1,
                ));
            }
        }
        s.upsert(&rows).expect("upsert");
        let before = s.used_bytes().expect("used");
        assert!(s.enforce_cap(before / 2).expect("cap") > 0);
        assert_eq!(
            s.list(&all(Some("S-2"))).expect("S-2").len(),
            1,
            "the light user's oldest row stays"
        );
        assert_eq!(s.removed_for(Some("S-2")).expect("S-2"), 0);
        assert!(s.removed_for(Some("S-1")).expect("S-1") > 0);
    }

    #[test]
    fn expiry_follows_each_users_own_cutoff() {
        let (_dir, s) = store();
        s.upsert(&[
            row("S-1", 10, "a.exe", "192.0.2.1", 1),
            row("S-1", 30, "a.exe", "192.0.2.1", 1),
            row("S-2", 10, "b.exe", "192.0.2.2", 1),
        ])
        .expect("upsert");
        let dropped = s
            .expire(|p| if p == "S-1" { 20 } else { 0 })
            .expect("expire");
        assert_eq!(dropped, 1);
        assert_eq!(s.list(&all(Some("S-2"))).expect("S-2").len(), 1);
        assert_eq!(
            s.removed_for(Some("S-1")).expect("removed"),
            0,
            "age is not counted"
        );
    }

    #[test]
    fn the_cap_removes_the_oldest_hours_first_and_counts_them_per_user() {
        let (_dir, s) = store();
        let mut rows = Vec::new();
        for hour in 0..40 {
            for n in 0..50 {
                let who = if n % 2 == 0 { "S-1" } else { "S-2" };
                rows.push(row(who, hour, &format!("program-{n}.exe"), "192.0.2.1", 1));
            }
        }
        s.upsert(&rows).expect("upsert");
        let before = s.used_bytes().expect("used");
        let removed = s.enforce_cap(before / 2).expect("cap");
        assert!(removed > 0);
        assert!(s.used_bytes().expect("used") <= before / 2);
        let left = s.list(&all(None)).expect("left");
        let oldest_left = left.iter().map(|e| e.first_ms).min().expect("rows left");
        assert!(oldest_left >= HOUR_MS, "hour 0 went first");
        let counted =
            s.removed_for(Some("S-1")).expect("S-1") + s.removed_for(Some("S-2")).expect("S-2");
        assert_eq!(counted, removed);
        assert_eq!(s.removed_for(None).expect("all"), removed);
        assert_eq!(s.enforce_cap(u64::MAX).expect("no-op"), 0);
    }

    #[test]
    fn clearing_erases_one_user_and_their_count_only() {
        let (_dir, s) = store();
        s.upsert(&[
            row("S-1", 1, "a.exe", "192.0.2.1", 1),
            row("S-2", 1, "b.exe", "192.0.2.2", 1),
        ])
        .expect("upsert");
        s.enforce_cap(0).expect("remove all, counted");
        s.upsert(&[row("S-1", 2, "a.exe", "192.0.2.1", 1)])
            .expect("again");
        assert_eq!(s.clear_principal("S-1").expect("clear"), 1);
        assert!(s.list(&all(Some("S-1"))).expect("S-1").is_empty());
        assert_eq!(s.removed_for(Some("S-1")).expect("S-1"), 0);
        assert_eq!(s.removed_for(Some("S-2")).expect("S-2"), 1);

        assert_eq!(
            s.clear_all().expect("clear all"),
            0,
            "S-1 was already erased"
        );
        s.upsert(&[row("S-2", 3, "b.exe", "192.0.2.2", 1)])
            .expect("S-2 again");
        assert_eq!(s.clear_all().expect("clear all"), 1);
        assert!(s.list(&all(None)).expect("all").is_empty());
        assert_eq!(s.removed_for(None).expect("all"), 0);
    }

    #[test]
    fn prefs_round_trip_and_refuse_out_of_range_days() {
        let conn = Connection::open_in_memory().expect("db");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let repo = ConnHistoryPrefsRepository::new(&conn);
        assert!(repo.list().expect("empty").is_empty());
        let off = ConnHistoryPrefs {
            enabled: false,
            retention_days: 3,
        };
        repo.set("S-1", off, 1).expect("set");
        assert_eq!(repo.list().expect("list"), vec![("S-1".to_string(), off)]);
        for days in [0, MAX_RETENTION_DAYS + 1] {
            let bad = ConnHistoryPrefs {
                enabled: true,
                retention_days: days,
            };
            assert!(repo.set("S-1", bad, 2).is_err());
        }
        assert!(repo.set("", ConnHistoryPrefs::default(), 2).is_err());
    }
}

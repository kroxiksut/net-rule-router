//! `block_notice_mutes` persistence.
//!
//! Durable "Do not show" choices for blocked-connection notices
//! (`nrr_domain::block_notice::Mute`). `BlockNoticeLedger::set_mutes` is pure
//! and I/O-free by design — the caller supplies the mute list on every
//! restart. Without a durable table that list is empty on every restart, and
//! the user is back to the full drop-storm noise the episode folding exists
//! to tame — the same lesson auto-rule suggestions already learned.
//!
//! Per-SID: one user's mute must not silence another user's notices, the same
//! partitioning every other rules-adjacent table uses.
//!
//! Expired mutes are purged opportunistically on read rather than tracked by
//! a background sweep: nothing else touches this table on a timer, and the
//! caller only ever asks "what's active right now", so folding the cleanup
//! into that same query is the whole cost.

use nrr_domain::block_notice::{Mute, MuteScope};
use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained mutes per SID. A user mutes hosts/apps by hand, so in
/// practice this never gets close, but every other per-SID table in this
/// crate bounds itself the same way. On overflow the oldest mutes (by
/// `updated_at`) are evicted first.
const MAX_MUTES_PER_SID: usize = 512;

const SCOPE_HOST: &str = "host";
const SCOPE_APP: &str = "app";
const SCOPE_REASON: &str = "reason";
const SCOPE_ALL: &str = "all";

fn encode_scope(scope: &MuteScope) -> (&'static str, &str) {
    match scope {
        MuteScope::Host(host) => (SCOPE_HOST, host.as_str()),
        MuteScope::App(app) => (SCOPE_APP, app.as_str()),
        // The reason's own slug is the value — the scope column is text, so a
        // new scope kind costs no migration.
        MuteScope::Reason(reason) => (SCOPE_REASON, reason.slug()),
        MuteScope::All => (SCOPE_ALL, ""),
    }
}

fn decode_scope(kind: &str, value: String) -> StorageResult<MuteScope> {
    match kind {
        SCOPE_HOST => Ok(MuteScope::Host(value)),
        SCOPE_APP => Ok(MuteScope::App(value)),
        SCOPE_REASON => nrr_domain::block_notice::BlockReason::from_slug(&value)
            .map(MuteScope::Reason)
            .ok_or_else(|| {
                StorageError::Internal(format!("block_notice_mutes: unknown reason {value:?}"))
            }),
        SCOPE_ALL => Ok(MuteScope::All),
        other => Err(StorageError::Internal(format!(
            "block_notice_mutes: unknown scope_kind {other:?}"
        ))),
    }
}

/// Repository over the `block_notice_mutes` table (state DB).
pub struct BlockNoticeMutesRepository<'c> {
    conn: &'c Connection,
}

impl<'c> BlockNoticeMutesRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Add or replace one mute for `sid`, stamping `now_ms`. Re-muting the
    /// same scope refreshes `until_ms` in place — the primary key is
    /// `(sid, scope_kind, scope_value)`, so this never creates a duplicate
    /// row for a host/app that was already muted. A no-op for an empty `sid`
    /// or an empty host/app name (the `all` scope has no name to check).
    pub fn upsert(&self, sid: &str, mute: &Mute, now_ms: i64) -> StorageResult<()> {
        if sid.is_empty() {
            return Ok(());
        }
        let (kind, value) = encode_scope(&mute.scope);
        if kind != SCOPE_ALL && value.is_empty() {
            return Ok(());
        }
        let until_ms = mute.until_ms.map(|u| u as i64);
        self.conn
            .execute(
                "INSERT INTO block_notice_mutes (sid, scope_kind, scope_value, until_ms, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid, scope_kind, scope_value) DO UPDATE SET
                     until_ms = excluded.until_ms,
                     updated_at = excluded.updated_at",
                params![sid, kind, value, until_ms, now_ms],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes upsert: {e}")))?;
        self.evict_overflow(sid)
    }

    /// Every mute for `sid` still in force at `now_ms`. Lapsed rows (a
    /// non-NULL `until_ms` at or before `now_ms`) are deleted as a side
    /// effect, so the table never accumulates mutes nobody can see anymore.
    pub fn list_active(&self, sid: &str, now_ms: i64) -> StorageResult<Vec<Mute>> {
        self.purge_expired(sid, now_ms)?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT scope_kind, scope_value, until_ms
                 FROM block_notice_mutes WHERE sid = ?1 ORDER BY updated_at DESC",
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, value, until_ms) =
                row.map_err(|e| StorageError::Internal(format!("block_notice_mutes row: {e}")))?;
            out.push(Mute {
                scope: decode_scope(&kind, value)?,
                until_ms: until_ms.map(|u| u as u64),
            });
        }
        Ok(out)
    }

    /// Undoes one mute so its notices show again. Returns whether a row
    /// actually existed.
    pub fn remove(&self, sid: &str, scope: &MuteScope) -> StorageResult<bool> {
        let (kind, value) = encode_scope(scope);
        let changed = self
            .conn
            .execute(
                "DELETE FROM block_notice_mutes
                 WHERE sid = ?1 AND scope_kind = ?2 AND scope_value = ?3",
                params![sid, kind, value],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes remove: {e}")))?;
        Ok(changed > 0)
    }

    /// Drops every mute for `sid` — "unmute everything".
    pub fn clear(&self, sid: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM block_notice_mutes WHERE sid = ?1",
                params![sid],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes clear: {e}")))?;
        Ok(())
    }

    fn purge_expired(&self, sid: &str, now_ms: i64) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM block_notice_mutes
                 WHERE sid = ?1 AND until_ms IS NOT NULL AND until_ms <= ?2",
                params![sid, now_ms],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes purge: {e}")))?;
        Ok(())
    }

    fn evict_overflow(&self, sid: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM block_notice_mutes WHERE sid = ?1 AND rowid IN (
                     SELECT rowid FROM block_notice_mutes
                     WHERE sid = ?1
                     ORDER BY updated_at DESC, rowid DESC
                     LIMIT -1 OFFSET ?2
                 )",
                params![sid, MAX_MUTES_PER_SID as i64],
            )
            .map_err(|e| StorageError::Internal(format!("block_notice_mutes evict: {e}")))?;
        Ok(())
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

    #[test]
    fn upserted_mute_survives_a_reopen_of_the_repository() {
        let conn = migrated_conn();
        let mute = Mute::until(MuteScope::Host("example.com".to_string()), 5_000);
        BlockNoticeMutesRepository::new(&conn)
            .upsert("S-A", &mute, 100)
            .expect("upsert");
        // A fresh repository over the same database is exactly what a
        // service restart sees.
        let mutes = BlockNoticeMutesRepository::new(&conn)
            .list_active("S-A", 1_000)
            .expect("list");
        assert_eq!(mutes, vec![mute]);
    }

    #[test]
    fn re_muting_the_same_scope_replaces_rather_than_duplicates() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        let scope = MuteScope::Host("example.com".to_string());
        repo.upsert("S-A", &Mute::until(scope.clone(), 5_000), 100)
            .expect("first");
        repo.upsert("S-A", &Mute::forever(scope.clone()), 200)
            .expect("second");
        let mutes = repo.list_active("S-A", 1_000).expect("list");
        assert_eq!(mutes.len(), 1, "same scope must replace, not duplicate");
        assert_eq!(mutes[0].until_ms, None, "second write's value must win");
    }

    #[test]
    fn app_and_all_scopes_round_trip_alongside_host() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert(
            "S-A",
            &Mute::forever(MuteScope::Host("a.example".to_string())),
            1,
        )
        .expect("host");
        repo.upsert(
            "S-A",
            &Mute::forever(MuteScope::App("chrome.exe".to_string())),
            2,
        )
        .expect("app");
        repo.upsert(
            "S-A",
            &Mute::forever(MuteScope::Reason(
                nrr_domain::block_notice::BlockReason::RouteUnavailable,
            )),
            3,
        )
        .expect("reason");
        repo.upsert("S-A", &Mute::forever(MuteScope::All), 4)
            .expect("all");
        let mutes = repo.list_active("S-A", 100).expect("list");
        assert_eq!(mutes.len(), 4);
        assert!(mutes.contains(&Mute::forever(MuteScope::Reason(
            nrr_domain::block_notice::BlockReason::RouteUnavailable
        ))));
    }

    #[test]
    fn mutes_are_isolated_between_two_different_sids() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert(
            "S-A",
            &Mute::forever(MuteScope::Host("example.com".to_string())),
            1,
        )
        .expect("a");
        // What does the second user see? Nothing muted for them.
        let second_user_view = repo.list_active("S-B", 100).expect("list");
        assert!(
            second_user_view.is_empty(),
            "one user's mute must not silence another user's notices"
        );
    }

    #[test]
    fn an_expired_mute_does_not_come_back_as_active() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert(
            "S-A",
            &Mute::until(MuteScope::Host("example.com".to_string()), 1_000),
            1,
        )
        .expect("upsert");
        // Still active before the deadline.
        assert_eq!(repo.list_active("S-A", 999).expect("before").len(), 1);
        // Lapsed at/after the deadline.
        assert!(repo.list_active("S-A", 1_000).expect("at").is_empty());
        assert!(repo.list_active("S-A", 5_000).expect("after").is_empty());
    }

    #[test]
    fn expired_mute_is_purged_from_storage_not_just_filtered() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert(
            "S-A",
            &Mute::until(MuteScope::Host("example.com".to_string()), 1_000),
            1,
        )
        .expect("upsert");
        repo.list_active("S-A", 5_000).expect("triggers purge");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM block_notice_mutes", [], |r| r.get(0))
            .expect("count");
        assert_eq!(count, 0, "the lapsed row must actually be deleted");
    }

    #[test]
    fn a_forever_mute_never_expires() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert("S-A", &Mute::forever(MuteScope::All), 1)
            .expect("upsert");
        assert_eq!(repo.list_active("S-A", i64::MAX).expect("list").len(), 1);
    }

    #[test]
    fn remove_undoes_one_mute_and_reports_whether_one_existed() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        let scope = MuteScope::Host("example.com".to_string());
        repo.upsert("S-A", &Mute::forever(scope.clone()), 1)
            .expect("upsert");
        assert!(repo.remove("S-A", &scope).expect("remove"));
        assert!(repo.list_active("S-A", 100).expect("list").is_empty());
        assert!(!repo.remove("S-A", &scope).expect("remove again"));
    }

    #[test]
    fn remove_is_scoped_to_its_sid() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        let scope = MuteScope::Host("example.com".to_string());
        repo.upsert("S-A", &Mute::forever(scope.clone()), 1)
            .expect("a");
        assert!(!repo.remove("S-B", &scope).expect("wrong sid"));
        assert_eq!(repo.list_active("S-A", 100).expect("list").len(), 1);
    }

    #[test]
    fn clear_drops_only_the_named_sid() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert("S-A", &Mute::forever(MuteScope::All), 1)
            .expect("a");
        repo.upsert("S-B", &Mute::forever(MuteScope::All), 1)
            .expect("b");
        repo.clear("S-A").expect("clear");
        assert!(repo.list_active("S-A", 100).expect("list").is_empty());
        assert_eq!(repo.list_active("S-B", 100).expect("list").len(), 1);
    }

    #[test]
    fn empty_inputs_are_no_ops() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        repo.upsert(
            "",
            &Mute::forever(MuteScope::Host("x.example".to_string())),
            1,
        )
        .expect("no sid");
        repo.upsert("S-A", &Mute::forever(MuteScope::Host(String::new())), 1)
            .expect("no host name");
        assert!(repo.list_active("S-A", 100).expect("list").is_empty());
    }

    #[test]
    fn overflow_evicts_the_oldest_mutes() {
        let conn = migrated_conn();
        let repo = BlockNoticeMutesRepository::new(&conn);
        for i in 0..(MAX_MUTES_PER_SID + 8) {
            repo.upsert(
                "S-A",
                &Mute::forever(MuteScope::Host(format!("host-{i}.example"))),
                i as i64,
            )
            .expect("upsert");
        }
        let mutes = repo
            .list_active("S-A", (MAX_MUTES_PER_SID + 100) as i64)
            .expect("list");
        assert_eq!(mutes.len(), MAX_MUTES_PER_SID);
        assert!(
            !mutes.contains(&Mute::forever(MuteScope::Host(
                "host-0.example".to_string()
            ))),
            "oldest mute evicted"
        );
        assert!(mutes.contains(&Mute::forever(MuteScope::Host(format!(
            "host-{}.example",
            MAX_MUTES_PER_SID + 7
        )))));
    }
}

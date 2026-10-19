//! `override_grants`: the overrides of the protection of system programs and
//! folders a user confirmed, and the revocations an emergency network reset
//! left for the service to record.
//!
//! The rows only persist what the service decided; it signs each one and
//! honours nothing that does not verify. The reset runs while the service is
//! stopped and holds no key, so it cannot sign anything: it only takes rows
//! away, which needs no trust, and leaves a note per row for the audit.

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// One confirmed override as stored. Lists are sorted and joined by `\n`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideGrantRow {
    pub sid: String,
    /// The rule's application pattern, canonical spelling.
    pub rule_value: String,
    /// `deny` or `secondary`.
    pub effect: String,
    /// The protection reason slug the override lifts.
    pub reason: String,
    /// Critical processes the rule covered when confirmed.
    pub critical: String,
    /// Service accounts seen running what the rule covers when confirmed.
    pub accounts: String,
    /// Programs the rule covered when confirmed.
    pub programs: i64,
    /// Who confirmed it (stored principal form).
    pub granted_by: String,
    pub granted_at: i64,
    /// `None`: until revoked.
    pub expires_at: Option<i64>,
    pub row_hmac: Vec<u8>,
}

impl OverrideGrantRow {
    /// The fields the tag covers.
    #[must_use]
    pub fn signed_fields(&self) -> crate::revision_hmac::GrantFields<'_> {
        crate::revision_hmac::GrantFields {
            sid: &self.sid,
            rule_value: &self.rule_value,
            effect: &self.effect,
            reason: &self.reason,
            critical: &self.critical,
            accounts: &self.accounts,
            programs: self.programs,
            granted_by: &self.granted_by,
            granted_at: self.granted_at,
            expires_at: self.expires_at,
        }
    }
}

/// A grant an emergency reset took away while the service was stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRevocation {
    pub sid: String,
    pub rule_value: String,
    pub effect: String,
    pub revoked_at: i64,
    /// Why, as a slug (`emergency-reset`).
    pub cause: String,
}

/// Rows read at most: the service caps grants far below this, so a file
/// holding more was not written by it, and the rest is not read.
pub const MAX_ROWS_READ: usize = 4096;

pub struct OverrideGrantsRepository<'c> {
    conn: &'c Connection,
}

fn internal(what: &str, e: rusqlite::Error) -> StorageError {
    StorageError::Internal(format!("override_grants {what}: {e}"))
}

impl<'c> OverrideGrantsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Every stored grant, at most [`MAX_ROWS_READ`].
    pub fn list(&self) -> StorageResult<Vec<OverrideGrantRow>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sid, rule_value, effect, reason, critical, accounts, programs,
                        granted_by, granted_at, expires_at, row_hmac
                 FROM override_grants ORDER BY sid, rule_value, effect LIMIT ?1",
            )
            .map_err(|e| internal("list prepare", e))?;
        let limit = i64::try_from(MAX_ROWS_READ).unwrap_or(i64::MAX);
        let rows = stmt
            .query_map(params![limit], |r| {
                Ok(OverrideGrantRow {
                    sid: r.get(0)?,
                    rule_value: r.get(1)?,
                    effect: r.get(2)?,
                    reason: r.get(3)?,
                    critical: r.get(4)?,
                    accounts: r.get(5)?,
                    programs: r.get(6)?,
                    granted_by: r.get(7)?,
                    granted_at: r.get(8)?,
                    expires_at: r.get(9)?,
                    row_hmac: r.get(10)?,
                })
            })
            .map_err(|e| internal("list query", e))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| internal("list row", e))?;
        Ok(rows)
    }

    /// Store `row`, replacing the grant for the same user, value and effect.
    pub fn upsert(&self, row: &OverrideGrantRow) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO override_grants (sid, rule_value, effect, reason, critical,
                     accounts, programs, granted_by, granted_at, expires_at, row_hmac)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(sid, rule_value, effect) DO UPDATE SET
                     reason = excluded.reason,
                     critical = excluded.critical,
                     accounts = excluded.accounts,
                     programs = excluded.programs,
                     granted_by = excluded.granted_by,
                     granted_at = excluded.granted_at,
                     expires_at = excluded.expires_at,
                     row_hmac = excluded.row_hmac",
                params![
                    row.sid,
                    row.rule_value,
                    row.effect,
                    row.reason,
                    row.critical,
                    row.accounts,
                    row.programs,
                    row.granted_by,
                    row.granted_at,
                    row.expires_at,
                    row.row_hmac,
                ],
            )
            .map_err(|e| internal("upsert", e))?;
        Ok(())
    }

    /// Remove one grant; `true` when there was one.
    pub fn delete(&self, sid: &str, rule_value: &str, effect: &str) -> StorageResult<bool> {
        let n = self
            .conn
            .execute(
                "DELETE FROM override_grants WHERE sid = ?1 AND rule_value = ?2 AND effect = ?3",
                params![sid, rule_value, effect],
            )
            .map_err(|e| internal("delete", e))?;
        Ok(n > 0)
    }

    /// The emergency reset: every grant goes, and each leaves a note for the
    /// service to audit at its next start. One transaction, so a grant is
    /// never gone without its note.
    pub fn revoke_all_pending_audit(&self, now_ms: i64, cause: &str) -> StorageResult<usize> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| internal("revoke begin", e))?;
        tx.execute(
            "INSERT INTO override_revocations_pending (sid, rule_value, effect, revoked_at, cause)
             SELECT sid, rule_value, effect, ?1, ?2 FROM override_grants",
            params![now_ms, cause],
        )
        .map_err(|e| internal("revoke note", e))?;
        let n = tx
            .execute("DELETE FROM override_grants WHERE 1 = 1", [])
            .map_err(|e| internal("revoke delete", e))?;
        tx.commit().map_err(|e| internal("revoke commit", e))?;
        Ok(n)
    }

    /// The notes the reset left, removed as they are read (at most
    /// [`MAX_ROWS_READ`]; the rest wait for the next read).
    pub fn take_pending_revocations(&self) -> StorageResult<Vec<PendingRevocation>> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| internal("pending begin", e))?;
        let limit = i64::try_from(MAX_ROWS_READ).unwrap_or(i64::MAX);
        let mut stmt = tx
            .prepare(
                "SELECT rowid, sid, rule_value, effect, revoked_at, cause
                 FROM override_revocations_pending ORDER BY rowid LIMIT ?1",
            )
            .map_err(|e| internal("pending prepare", e))?;
        let rows: Vec<(i64, PendingRevocation)> = stmt
            .query_map(params![limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    PendingRevocation {
                        sid: r.get(1)?,
                        rule_value: r.get(2)?,
                        effect: r.get(3)?,
                        revoked_at: r.get(4)?,
                        cause: r.get(5)?,
                    },
                ))
            })
            .map_err(|e| internal("pending query", e))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| internal("pending row", e))?;
        drop(stmt);
        if let Some((last, _)) = rows.last() {
            tx.execute(
                "DELETE FROM override_revocations_pending WHERE rowid <= ?1",
                params![last],
            )
            .map_err(|e| internal("pending delete", e))?;
        }
        tx.commit().map_err(|e| internal("pending commit", e))?;
        Ok(rows.into_iter().map(|(_, row)| row).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn migrated() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_connection(&dir.path().join("state.db")).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, runner.into_connection())
    }

    fn grant(sid: &str, value: &str, expires_at: Option<i64>) -> OverrideGrantRow {
        OverrideGrantRow {
            sid: sid.into(),
            rule_value: value.into(),
            effect: "deny".into(),
            reason: "shared-folder".into(),
            critical: String::new(),
            accounts: String::new(),
            programs: 2,
            granted_by: sid.into(),
            granted_at: 10,
            expires_at,
            row_hmac: vec![1; 32],
        }
    }

    #[test]
    fn a_grant_is_stored_replaced_and_removed() {
        let (_dir, conn) = migrated();
        let repo = OverrideGrantsRepository::new(&conn);
        repo.upsert(&grant("S-A", "/var/www/*", Some(100)))
            .expect("store");
        repo.upsert(&grant("S-A", "/var/www/*", None))
            .expect("replace");
        repo.upsert(&grant("S-B", "/srv/www/*", Some(5)))
            .expect("store");
        let rows = repo.list().expect("list");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].sid, "S-A");
        assert_eq!(rows[0].expires_at, None, "the newer confirmation wins");
        assert!(repo.delete("S-A", "/var/www/*", "deny").expect("delete"));
        assert!(!repo.delete("S-A", "/var/www/*", "deny").expect("again"));
        assert_eq!(repo.list().expect("list").len(), 1);
    }

    #[test]
    fn the_effect_is_one_of_two() {
        let (_dir, conn) = migrated();
        let mut row = grant("S-A", "/var/www/*", None);
        row.effect = "primary".into();
        assert!(OverrideGrantsRepository::new(&conn).upsert(&row).is_err());
    }

    /// The reset takes every grant and leaves one note per grant; the notes
    /// are read once.
    #[test]
    fn the_reset_revokes_everything_and_leaves_notes_read_once() {
        let (_dir, conn) = migrated();
        let repo = OverrideGrantsRepository::new(&conn);
        repo.upsert(&grant("S-A", "/var/www/*", None))
            .expect("store");
        repo.upsert(&grant("S-B", "/srv/www/*", Some(5)))
            .expect("store");
        assert_eq!(
            repo.revoke_all_pending_audit(77, "emergency-reset")
                .expect("revoke"),
            2
        );
        assert!(repo.list().expect("list").is_empty());
        let notes = repo.take_pending_revocations().expect("take");
        assert_eq!(notes.len(), 2);
        assert!(notes
            .iter()
            .all(|n| n.revoked_at == 77 && n.cause == "emergency-reset"));
        assert!(repo.take_pending_revocations().expect("again").is_empty());
        assert_eq!(
            repo.revoke_all_pending_audit(78, "emergency-reset")
                .expect("nothing left"),
            0
        );
    }
}

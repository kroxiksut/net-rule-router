//! `mutation_tokens` SQLite-backed store.
//!
//! Persists confirmation tokens issued by the service for two-phase
//! mutations (revision activation, rollback, retention/policy/pause
//! settings changes), so a user with an open review dialog does not lose
//! their token if the service restarts between issue and consume.
//!
//! ## Lifecycle
//!
//! 1. [`issue`] inserts a new row with `consumed = 0` and a future
//!    `expires_at`.
//! 2. [`consume`] atomically marks the row `consumed = 1` and returns
//!    the stored payload (or `None` if the token is unknown / already
//!    consumed / expired).
//! 3. [`gc_expired`] deletes rows whose `expires_at` is older than `now -
//!    grace_seconds`. Consumed rows linger until their original
//!    `expires_at` plus the grace window so audit replay can still find
//!    them.
//!
//! ## Concurrency
//!
//! Single-writer (`&Connection` borrowed). Concurrent `consume` calls
//! for the same token serialise via SQL transactions — only one `UPDATE
//! ... WHERE consumed = 0` succeeds.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};
use crate::schema::BASELINE_PRINCIPAL;

// ── DTO ───────────────────────────────────────────────────────────────────────

/// One row from the `mutation_tokens` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMutationToken {
    pub token: String,
    /// The principal (Windows SID or baseline sentinel) the token was
    /// issued for. A token is only consumable by the principal it was
    /// issued to (see [`MutationTokenStoreSqlite::consume_for`]).
    pub principal: String,
    pub mutation_payload_json: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub consumed: bool,
}

/// Outcome of a [`MutationTokenStoreSqlite::consume`] call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumeOutcome {
    /// Token consumed; payload returned.
    Consumed { payload_json: String },
    /// Token does not exist.
    Unknown,
    /// Token exists but was already consumed.
    AlreadyConsumed,
    /// Token exists and is unconsumed but `now` is past its `expires_at`.
    Expired,
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// SQLite-backed mutation token store. Borrows a connection.
pub struct MutationTokenStoreSqlite<'c> {
    conn: &'c Connection,
}

impl<'c> MutationTokenStoreSqlite<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Inserts a new token. Returns an error if the token already
    /// exists (PRIMARY KEY violation).
    pub fn issue(
        &self,
        token: &str,
        mutation_payload_json: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> StorageResult<()> {
        self.issue_for(
            BASELINE_PRINCIPAL,
            token,
            mutation_payload_json,
            issued_at,
            expires_at,
        )
    }

    /// Issue a token scoped to `principal`. The principal is persisted so
    /// [`Self::consume_for`] can reject a cross-principal consume attempt.
    pub fn issue_for(
        &self,
        principal: &str,
        token: &str,
        mutation_payload_json: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> StorageResult<()> {
        if principal.is_empty() {
            return Err(StorageError::Internal("issue: empty principal".into()));
        }
        if token.is_empty() {
            return Err(StorageError::Internal("issue: empty token".into()));
        }
        if expires_at <= issued_at {
            return Err(StorageError::Internal(
                "issue: expires_at must be strictly greater than issued_at".into(),
            ));
        }
        self.conn
            .execute(
                "INSERT INTO mutation_tokens
                 (token, principal, mutation_payload_json, issued_at, expires_at, consumed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    token,
                    principal,
                    mutation_payload_json,
                    issued_at,
                    expires_at
                ],
            )
            .map_err(|e| StorageError::Internal(format!("mutation_tokens issue: {e}")))?;
        Ok(())
    }

    /// Atomic consume. Marks `consumed = 1` and returns the payload only
    /// when the token is unconsumed and not yet expired.
    ///
    /// `now` is the caller-supplied wall-clock seconds value used for
    /// the expiration check.
    pub fn consume(&self, token: &str, now: i64) -> StorageResult<ConsumeOutcome> {
        self.consume_inner(token, now, None)
    }

    /// Consume `token` only if it was issued for
    /// `principal`. A token belonging to a different principal is reported
    /// as [`ConsumeOutcome::Unknown`] — from the caller's perspective the
    /// token simply does not exist, which is the correct authorization
    /// posture (no information leak about other users' tokens).
    pub fn consume_for(
        &self,
        principal: &str,
        token: &str,
        now: i64,
    ) -> StorageResult<ConsumeOutcome> {
        self.consume_inner(token, now, Some(principal))
    }

    fn consume_inner(
        &self,
        token: &str,
        now: i64,
        expected_principal: Option<&str>,
    ) -> StorageResult<ConsumeOutcome> {
        let existing: Option<StoredMutationToken> = self.get(token)?;
        match existing {
            None => Ok(ConsumeOutcome::Unknown),
            Some(record) if expected_principal.is_some_and(|p| p != record.principal) => {
                // Cross-principal consume attempt — indistinguishable from
                // a non-existent token to this caller.
                Ok(ConsumeOutcome::Unknown)
            }
            Some(record) if record.consumed => Ok(ConsumeOutcome::AlreadyConsumed),
            Some(record) if record.expires_at < now => Ok(ConsumeOutcome::Expired),
            Some(record) => {
                let updated = self
                    .conn
                    .execute(
                        "UPDATE mutation_tokens
                         SET consumed = 1
                         WHERE token = ?1 AND consumed = 0",
                        params![token],
                    )
                    .map_err(|e| StorageError::Internal(format!("mutation_tokens consume: {e}")))?;
                if updated != 1 {
                    // Another consumer raced and won.
                    return Ok(ConsumeOutcome::AlreadyConsumed);
                }
                Ok(ConsumeOutcome::Consumed {
                    payload_json: record.mutation_payload_json,
                })
            }
        }
    }

    /// Reads a token row without consuming it.
    pub fn get(&self, token: &str) -> StorageResult<Option<StoredMutationToken>> {
        self.conn
            .query_row(
                "SELECT token, principal, mutation_payload_json, issued_at, expires_at, consumed
                 FROM mutation_tokens WHERE token = ?1",
                params![token],
                |row| {
                    let consumed_int: i64 = row.get(5)?;
                    Ok(StoredMutationToken {
                        token: row.get(0)?,
                        principal: row.get(1)?,
                        mutation_payload_json: row.get(2)?,
                        issued_at: row.get(3)?,
                        expires_at: row.get(4)?,
                        consumed: consumed_int != 0,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("mutation_tokens get: {e}")))
    }

    /// Removes rows whose `expires_at` is older than `now - grace_seconds`.
    /// Returns the number of rows deleted.
    ///
    /// Audit replay needs the consumed-token rows for a while after
    /// expiration; the default grace window in service-runtime is 1 day.
    pub fn gc_expired(&self, now: i64, grace_seconds: i64) -> StorageResult<usize> {
        let threshold = now.saturating_sub(grace_seconds);
        let deleted = self
            .conn
            .execute(
                "DELETE FROM mutation_tokens WHERE expires_at < ?1",
                params![threshold],
            )
            .map_err(|e| StorageError::Internal(format!("mutation_tokens gc: {e}")))?;
        Ok(deleted)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn open_state_db(dir: &tempfile::TempDir) -> Connection {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn issue_inserts_unconsumed_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);

        store
            .issue("tok-1", r#"{"op":"activate"}"#, 100, 500)
            .expect("issue");

        let row = store.get("tok-1").expect("get").expect("present");
        assert_eq!(row.token, "tok-1");
        assert_eq!(row.mutation_payload_json, r#"{"op":"activate"}"#);
        assert_eq!(row.issued_at, 100);
        assert_eq!(row.expires_at, 500);
        assert!(!row.consumed);
    }

    #[test]
    fn issue_rejects_empty_token() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        assert!(store.issue("", "{}", 0, 1).is_err());
    }

    #[test]
    fn issue_rejects_non_positive_ttl() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        assert!(store.issue("t", "{}", 100, 100).is_err());
        assert!(store.issue("t", "{}", 100, 50).is_err());
    }

    #[test]
    fn issue_rejects_duplicate_token() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        store.issue("dup", "{}", 0, 100).expect("first");
        assert!(store.issue("dup", "{}", 0, 100).is_err());
    }

    #[test]
    fn consume_returns_payload_and_marks_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);

        store.issue("tok", r#"{"k":"v"}"#, 100, 500).expect("issue");
        let outcome = store.consume("tok", 200).expect("consume");
        match outcome {
            ConsumeOutcome::Consumed { payload_json } => {
                assert_eq!(payload_json, r#"{"k":"v"}"#);
            }
            other => panic!("expected Consumed, got {other:?}"),
        }
        // Row is now marked consumed.
        let row = store.get("tok").expect("get").expect("present");
        assert!(row.consumed);
    }

    #[test]
    fn consume_unknown_token_returns_unknown() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        let outcome = store.consume("ghost", 0).expect("consume");
        assert_eq!(outcome, ConsumeOutcome::Unknown);
    }

    #[test]
    fn consume_already_consumed_token_returns_already_consumed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        store.issue("once", "{}", 0, 1000).expect("issue");
        let _ = store.consume("once", 100).expect("first consume");
        let outcome = store.consume("once", 100).expect("second consume");
        assert_eq!(outcome, ConsumeOutcome::AlreadyConsumed);
    }

    #[test]
    fn consume_expired_token_returns_expired_and_does_not_mark() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        store.issue("exp", "{}", 0, 100).expect("issue");
        let outcome = store.consume("exp", 200).expect("consume");
        assert_eq!(outcome, ConsumeOutcome::Expired);
        // Row stays unconsumed for audit visibility.
        let row = store.get("exp").expect("get").expect("present");
        assert!(!row.consumed);
    }

    #[test]
    fn gc_expired_deletes_old_rows_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);

        store.issue("old", "{}", 0, 100).expect("issue old");
        store
            .issue("recent", "{}", 0, 1_000_000)
            .expect("issue recent");

        // now=10_000, grace=1_000 → threshold = 9_000. "old" expired at
        // 100, so 100 < 9_000 → deleted. "recent" expires at 1_000_000 →
        // 1_000_000 >= 9_000 → kept.
        let deleted = store.gc_expired(10_000, 1_000).expect("gc");
        assert_eq!(deleted, 1);

        assert!(store.get("old").expect("get").is_none());
        assert!(store.get("recent").expect("get").is_some());
    }

    #[test]
    fn token_persists_across_connection_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Issue via one connection.
        {
            let conn = open_state_db(&dir);
            MutationTokenStoreSqlite::new(&conn)
                .issue("persistent", r#"{"x":1}"#, 0, 1_000)
                .expect("issue");
        }
        // Reopen and verify the row survived.
        let path = dir.path().join("state.db");
        let conn = crate::migration::open_connection(&path).expect("reopen");
        let store = MutationTokenStoreSqlite::new(&conn);
        let row = store.get("persistent").expect("get").expect("present");
        assert_eq!(row.mutation_payload_json, r#"{"x":1}"#);
        assert!(!row.consumed);
    }

    // ── per-principal token scoping ─────────────────────────────────────────

    #[test]
    fn shim_issue_records_baseline_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        store.issue("tok", "{}", 0, 100).expect("issue");
        let row = store.get("tok").expect("get").expect("present");
        assert_eq!(row.principal, crate::schema::BASELINE_PRINCIPAL);
    }

    #[test]
    fn consume_for_rejects_wrong_principal_as_unknown() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);

        store
            .issue_for("S-1-5-21-A", "tok-a", r#"{"op":"x"}"#, 0, 1000)
            .expect("issue A");

        // B cannot consume A's token — it looks non-existent to B.
        assert_eq!(
            store.consume_for("S-1-5-21-B", "tok-a", 100).expect("b"),
            ConsumeOutcome::Unknown
        );
        // The token is still unconsumed and available to A.
        assert!(!store.get("tok-a").expect("get").expect("present").consumed);
        match store.consume_for("S-1-5-21-A", "tok-a", 100).expect("a") {
            ConsumeOutcome::Consumed { payload_json } => {
                assert_eq!(payload_json, r#"{"op":"x"}"#);
            }
            other => panic!("expected Consumed for owning principal, got {other:?}"),
        }
    }

    #[test]
    fn global_consume_ignores_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let store = MutationTokenStoreSqlite::new(&conn);
        store
            .issue_for("S-1-5-21-A", "tok", "{}", 0, 1000)
            .expect("issue");
        // The back-compat global consume does not enforce the principal.
        assert!(matches!(
            store.consume("tok", 100).expect("consume"),
            ConsumeOutcome::Consumed { .. }
        ));
    }
}

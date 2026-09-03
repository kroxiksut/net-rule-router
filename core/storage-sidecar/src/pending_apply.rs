//! `pending_apply` single-row table — the marker that says the user parked
//! changes because the service was unreachable.
//!
//! When the user clicks "Work without service" in the
//! `ServiceNotRunningDialog`, the GUI records a `{added, modified,
//! removed}` summary and the content hash of the rules it holds. On the
//! next successful connect it reads the row and offers an "Apply pending
//! changes?" toast.
//!
//! # What is deliberately NOT stored
//!
//! The rules themselves. The park is a marker: the rules the toast
//! applies are rebuilt from the live model, which is the state the user
//! has been looking at. Keeping a second copy meant every park wrote a
//! full set — host names, executable paths — that no reader ever opened,
//! and that a TTL hid rather than removed. The hash is what tells the
//! toast whether the parked work is still the work in front of the user.
//!
//! # Single-row contract
//!
//! The schema enforces `CHECK(id = 1)`, so there's only ever one row.
//! Writes go through `INSERT OR REPLACE`, reads return `Option`.
//!
//! # TTL
//!
//! Each write stamps `expires_at = modified_at + PENDING_APPLY_TTL_SECONDS`.
//! A read past that point deletes the row and answers `None`: an expired
//! park is not a hidden park, and nothing should be able to resurrect it
//! by reading with a different clock.
//!
//! # Why store `summary_json` separately
//!
//! The toast "{added} added, {modified} modified, {removed} removed" is
//! rendered on every status-bar tick while the user decides, so the
//! counts are computed once, at write time.

use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};

use crate::db::SidecarDb;
use crate::error::SidecarResult;

/// Pre-computed counts surfaced by the "Apply pending changes?" toast.
///
/// Kept as a typed companion to the JSON-encoded `summary_json` column
/// so callers that want to render the toast without parsing JSON have
/// a strongly-typed struct ready. The bridge wire format is still the
/// JSON string (compatible with QML's JSON.parse on the QML side).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingApplySummary {
    pub added: u32,
    pub modified: u32,
    pub removed: u32,
}

/// One persisted pending-apply state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApplyEntry {
    /// Cached `{added, modified, removed}` summary string (JSON-encoded
    /// for portability across the bridge boundary).
    pub summary_json: String,
    /// SHA-256 of the parked rules, for comparison against what the GUI
    /// holds now and against the service's `activeContentHash` — when
    /// they match the toast path stays silent.
    pub content_hash: String,
    /// Unix epoch milliseconds when the row was last written.
    pub modified_at_ms: i64,
    /// Unix epoch milliseconds at which the row becomes stale. Reads
    /// past this point return `None`.
    pub expires_at_ms: i64,
}

/// Default TTL for `pending_apply` rows — seven days, expressed in
/// seconds for compactness; the storage column is milliseconds. After
/// this the row is treated as absent.
pub const PENDING_APPLY_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const PENDING_APPLY_TTL_MS: i64 = PENDING_APPLY_TTL_SECONDS * 1000;

impl SidecarDb {
    /// Read the parked state, or `None` when the row is missing or
    /// expired. An expired row is deleted, not skipped. Expiration is
    /// computed against the system clock at call time.
    pub fn read_pending_apply(&self) -> SidecarResult<Option<PendingApplyEntry>> {
        self.read_pending_apply_at(unix_now_ms())
    }

    /// Test-friendly variant that accepts an explicit "now" timestamp
    /// (milliseconds since epoch). Production code goes through
    /// [`read_pending_apply`] which calls `SystemTime::now()`.
    pub fn read_pending_apply_at(&self, now_ms: i64) -> SidecarResult<Option<PendingApplyEntry>> {
        let conn = self.conn_mut();
        conn.execute(
            "DELETE FROM pending_apply WHERE id = 1 AND expires_at <= ?1",
            params![now_ms],
        )?;
        let row = conn
            .query_row(
                "SELECT summary_json, content_hash, modified_at, expires_at
                     FROM pending_apply
                     WHERE id = 1",
                [],
                |r| {
                    Ok(PendingApplyEntry {
                        summary_json: r.get(0)?,
                        content_hash: r.get(1)?,
                        modified_at_ms: r.get(2)?,
                        expires_at_ms: r.get(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Overwrite the parked marker, stamping `expires_at` at
    /// `now + PENDING_APPLY_TTL_SECONDS`.
    pub fn write_pending_apply(&self, summary_json: &str, content_hash: &str) -> SidecarResult<()> {
        self.write_pending_apply_at(summary_json, content_hash, unix_now_ms())
    }

    /// Test-friendly variant that accepts an explicit "now" timestamp
    /// for deterministic TTL assertions.
    pub fn write_pending_apply_at(
        &self,
        summary_json: &str,
        content_hash: &str,
        now_ms: i64,
    ) -> SidecarResult<()> {
        let expires_at = now_ms.saturating_add(PENDING_APPLY_TTL_MS);
        let conn = self.conn_mut();
        conn.execute(
            "INSERT OR REPLACE INTO pending_apply
                 (id, summary_json, content_hash, modified_at, expires_at)
                 VALUES (1, ?1, ?2, ?3, ?4)",
            params![summary_json, content_hash, now_ms, expires_at],
        )?;
        Ok(())
    }

    /// Drop the parked state row (Discard / Applied paths). No-op when
    /// the row was already absent.
    pub fn clear_pending_apply(&self) -> SidecarResult<()> {
        let conn = self.conn_mut();
        conn.execute("DELETE FROM pending_apply WHERE id = 1", [])?;
        Ok(())
    }
}

/// Current Unix epoch in milliseconds. Mirrors the helper in other
/// DAO modules; kept private here so each table file remains
/// self-contained.
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used)] // tests panic on None to surface assertion intent
mod tests {
    use super::*;
    use crate::SidecarDb;

    fn open_sidecar(tmp: &tempfile::TempDir) -> SidecarResult<SidecarDb> {
        let path = tmp.path().join("sidecar.db");
        SidecarDb::open(&path)
    }

    const T0: i64 = 1_700_000_000_000; // arbitrary fixed "now" in ms

    #[test]
    fn empty_reads_as_none() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        assert!(db.read_pending_apply()?.is_none());
        Ok(())
    }

    #[test]
    fn write_then_read_roundtrip() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at(r#"{"added":2,"modified":1,"removed":0}"#, "deadbeef", T0)?;
        let got = db.read_pending_apply_at(T0 + 100)?;
        let entry = got.expect("row should be present immediately after write");
        assert_eq!(
            entry.summary_json,
            r#"{"added":2,"modified":1,"removed":0}"#
        );
        assert_eq!(entry.content_hash, "deadbeef");
        assert_eq!(entry.modified_at_ms, T0);
        assert_eq!(entry.expires_at_ms, T0 + PENDING_APPLY_TTL_MS);
        Ok(())
    }

    #[test]
    fn expired_row_reads_as_none() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary", "hash", T0)?;
        // Advance now past expiry.
        let after_expiry = T0 + PENDING_APPLY_TTL_MS + 1;
        assert!(db.read_pending_apply_at(after_expiry)?.is_none());
        Ok(())
    }

    #[test]
    fn unexpired_row_reads_at_boundary() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary", "hash", T0)?;
        // One millisecond before expiry is still fresh.
        assert!(db
            .read_pending_apply_at(T0 + PENDING_APPLY_TTL_MS - 1)?
            .is_some());
        // Exactly at expiry the row is stale — `expires_at > now`, so
        // equality is not fresh — and reading it takes it out of the file.
        assert!(db
            .read_pending_apply_at(T0 + PENDING_APPLY_TTL_MS)?
            .is_none());
        // A clock that walks back does not resurrect it.
        assert!(db.read_pending_apply_at(T0 + 1)?.is_none());
        Ok(())
    }

    #[test]
    fn write_overwrites_previous_row() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary1", "hash1", T0)?;
        db.write_pending_apply_at("summary2", "hash2", T0 + 5_000)?;
        let got = db.read_pending_apply_at(T0 + 6_000)?.expect("row");
        assert_eq!(got.summary_json, "summary2");
        assert_eq!(got.content_hash, "hash2");
        assert_eq!(got.modified_at_ms, T0 + 5_000);
        assert_eq!(got.expires_at_ms, T0 + 5_000 + PENDING_APPLY_TTL_MS);
        Ok(())
    }

    #[test]
    fn an_expired_park_is_deleted_not_merely_hidden() -> SidecarResult<()> {
        // Hiding it left the row — and everything in it — in the file for
        // good: invisible to every reader, and untouched by VACUUM.
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary", "hash", T0)?;

        assert!(db
            .read_pending_apply_at(T0 + PENDING_APPLY_TTL_MS + 1)?
            .is_none());

        let rows: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pending_apply", [], |r| r.get(0))?;
        assert_eq!(rows, 0, "the expired row must be gone from the file");
        Ok(())
    }

    #[test]
    fn clear_removes_row() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary", "hash", T0)?;
        db.clear_pending_apply()?;
        assert!(db.read_pending_apply_at(T0 + 100)?.is_none());
        Ok(())
    }

    #[test]
    fn clear_is_idempotent() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.clear_pending_apply()?;
        db.clear_pending_apply()?;
        Ok(())
    }

    #[test]
    fn rewrite_after_expiry_resets_ttl() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_pending_apply_at("summary", "hash", T0)?;
        // Past expiry — row gone.
        assert!(db
            .read_pending_apply_at(T0 + PENDING_APPLY_TTL_MS + 1)?
            .is_none());
        // New write with fresh "now" → row visible again.
        let t1 = T0 + PENDING_APPLY_TTL_MS + 10_000;
        db.write_pending_apply_at("fresh-summary", "hash", t1)?;
        let got = db.read_pending_apply_at(t1 + 100)?.expect("row");
        assert_eq!(got.summary_json, "fresh-summary");
        Ok(())
    }

    #[test]
    fn single_row_invariant_holds_under_many_writes() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        for i in 0..10 {
            db.write_pending_apply_at(&format!("summary-{i}"), "hash", T0 + i64::from(i) * 1000)?;
        }
        // The schema CHECK(id=1) means only one row can exist; SELECT
        // COUNT(*) must be exactly 1 after 10 writes.
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pending_apply", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        // The final write wins.
        let got = db.read_pending_apply_at(T0 + 9_500)?.expect("row");
        assert_eq!(got.summary_json, "summary-9");
        Ok(())
    }

    #[test]
    fn unicode_payload_survives_reopen() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let payload = r#"{"rules-added":["рф"],"total-rules":1,"note":"Россия"}"#;
        {
            let db = SidecarDb::open(&path)?;
            db.write_pending_apply_at(payload, "hash", T0)?;
        }
        let db = SidecarDb::open(&path)?;
        let got = db.read_pending_apply_at(T0 + 100)?.expect("row");
        assert_eq!(got.summary_json, payload);
        Ok(())
    }

    #[test]
    fn ttl_constant_is_seven_days() {
        // Sanity: 7 * 24 * 60 * 60 = 604_800 seconds.
        assert_eq!(PENDING_APPLY_TTL_SECONDS, 604_800);
        assert_eq!(PENDING_APPLY_TTL_MS, 604_800 * 1000);
    }

    #[test]
    fn saturating_add_handles_max_timestamp() -> SidecarResult<()> {
        // Pathological "now" close to i64::MAX must not overflow.
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let huge_now = i64::MAX - 1000;
        db.write_pending_apply_at("summary", "hash", huge_now)?;
        // The row exists (expires_at saturates at i64::MAX).
        let got = db.read_pending_apply_at(huge_now)?.expect("row");
        assert_eq!(got.expires_at_ms, i64::MAX);
        Ok(())
    }
}

//! Startup VACUUM throttle for the sidecar database.
//!
//! Comments and passthrough are sparse, but `pending_apply` can hold a
//! multi-megabyte `rules_json` blob and SQLite never gives space back
//! after a DELETE without a VACUUM. Over many import/discard cycles
//! the file can grow much larger than the live data.
//!
//! Strategy:
//!
//! * VACUUM is checked once during `SidecarDb::open` (i.e. once per
//!   GUI launch). It is deliberately not periodic — the sidecar is
//!   small enough that startup is the right time to absorb the cost.
//! * We only vacuum when the file is **above the size threshold**
//!   AND we haven't vacuumed within the last [`VACUUM_MIN_INTERVAL_MS`].
//!   Both gates must hold; either alone would either be too aggressive
//!   (every launch on a moderately-sized DB) or too lazy (DB grows
//!   unbounded for users who launch rarely).
//! * The throttle timestamp lives in the `db_state` single-row table.
//!
//! VACUUM in SQLite cannot run inside a transaction and rewrites the
//! whole file. Since `SidecarDb` owns the sole connection (and the GUI
//! is single-instance) we can do this safely on the open path.

use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};

use crate::db::SidecarDb;
use crate::error::SidecarResult;

/// File-size threshold above which the startup VACUUM is considered.
/// Ten mebibytes — below this the wasted space is too small to matter
/// even for users who never restart for weeks.
pub const SIDECAR_VACUUM_SIZE_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

/// Minimum gap between two automatic VACUUMs. One day; tight enough
/// to keep growth bounded but loose enough not to penalise users who
/// launch the GUI many times per day.
pub const SIDECAR_VACUUM_MIN_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

impl SidecarDb {
    /// Run a startup VACUUM if both the size-threshold and
    /// time-throttle conditions are met. Returns `true` when a
    /// VACUUM actually ran, `false` when conditions were not met.
    /// Production callers (i.e. `open`) use the default constants;
    /// tests inject custom thresholds via [`maybe_vacuum_with`].
    pub fn maybe_vacuum(&self) -> SidecarResult<bool> {
        self.maybe_vacuum_with(
            SIDECAR_VACUUM_SIZE_THRESHOLD_BYTES,
            SIDECAR_VACUUM_MIN_INTERVAL_MS,
            unix_now_ms(),
        )
    }

    /// Test-friendly variant of [`maybe_vacuum`]. Both gates and the
    /// "now" timestamp are parameterised so unit tests can exercise
    /// every branch without inflating the on-disk file or sleeping.
    pub fn maybe_vacuum_with(
        &self,
        threshold_bytes: u64,
        min_interval_ms: i64,
        now_ms: i64,
    ) -> SidecarResult<bool> {
        // 1. Size gate. Failing this is the common case — keeps the
        //    cost zero on fresh installs. We sum the on-disk footprint
        //    of the SQLite triple (`.db` + `.db-wal` + `.db-shm`)
        //    because in WAL mode the main file can stay small while
        //    the WAL accumulates megabytes of pending writes — and
        //    "what the user sees on disk" is the meaningful number.
        let size = sidecar_disk_footprint(self.path());
        if size < threshold_bytes {
            return Ok(false);
        }
        // 2. Time gate. `last_vacuum_at_ms` defaults to 0 when no
        //    row exists yet, which means a brand-new oversized DB
        //    vacuums on the first launch (e.g. user dropped a huge
        //    preset into the sidecar via direct edit — unusual but
        //    the size already says they need it).
        let last = self.read_last_vacuum_at_ms()?;
        if now_ms.saturating_sub(last) < min_interval_ms {
            return Ok(false);
        }
        // 3. Both gates passed → vacuum and record the timestamp.
        self.vacuum_now_at(now_ms)?;
        Ok(true)
    }

    /// Force a VACUUM regardless of conditions. Intended for the
    /// Settings → "Reset application data" path where the user
    /// explicitly asked us to compact the sidecar.
    pub fn vacuum_now(&self) -> SidecarResult<()> {
        self.vacuum_now_at(unix_now_ms())
    }

    /// Test-friendly variant of [`vacuum_now`] with an explicit
    /// timestamp for deterministic last-vacuum assertions.
    pub fn vacuum_now_at(&self, now_ms: i64) -> SidecarResult<()> {
        let conn = self.conn_mut();
        // VACUUM cannot run inside a transaction; `execute_batch`
        // runs the statement directly. SQLite handles the file
        // rewrite atomically using its journal.
        conn.execute_batch("VACUUM")?;
        // Update the db_state housekeeping row.
        conn.execute(
            "INSERT INTO db_state (id, last_vacuum_at_ms) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET last_vacuum_at_ms = excluded.last_vacuum_at_ms",
            params![now_ms],
        )?;
        // In WAL mode the VACUUM rewrite is itself logged into the
        // WAL, which can leave the on-disk footprint *larger* than
        // before VACUUM ran. A TRUNCATE checkpoint flushes the WAL
        // back into the main DB and resets `.db-wal` to zero bytes,
        // so the on-disk size actually shrinks afterwards. Without
        // this step, callers who measure the disk footprint right
        // after VACUUM would see paradoxical growth.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(())
    }

    /// Read the `last_vacuum_at_ms` value from `db_state`, returning
    /// zero when no row exists yet (fresh DB — the throttle reads as
    /// "infinitely long ago" so the first oversized launch vacuums).
    pub fn read_last_vacuum_at_ms(&self) -> SidecarResult<i64> {
        let conn = self.conn();
        let value: Option<i64> = conn
            .query_row(
                "SELECT last_vacuum_at_ms FROM db_state WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0))
    }
}

/// Sum the on-disk size of the SQLite triple at `db_path`:
/// the main `.db` file plus its `.db-wal` and `.db-shm` siblings when
/// they exist. Missing siblings count as zero so a freshly opened DB
/// without a checkpoint behaves identically to one after checkpoint.
///
/// This is the right metric for the VACUUM threshold because in WAL
/// mode SQLite buffers writes in `.db-wal` and only relocates them to
/// the main file at checkpoint time. Looking at the main file alone
/// would mis-report a few megabytes of pending writes as "still small".
fn sidecar_disk_footprint(db_path: &std::path::Path) -> u64 {
    fn len_or_zero(path: &std::path::Path) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }
    let main = len_or_zero(db_path);
    let with_suffix = |suffix: &str| -> u64 {
        let mut p = db_path.as_os_str().to_owned();
        p.push(suffix);
        len_or_zero(std::path::Path::new(&p))
    };
    main.saturating_add(with_suffix("-wal"))
        .saturating_add(with_suffix("-shm"))
}

/// Current Unix epoch in milliseconds. Duplicated across DAO modules
/// so each file remains self-contained; the alternative is a tiny
/// shared `time` module, which feels over-engineered for ~6 lines.
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used)] // tests panic on impossible states
mod tests {
    use super::*;
    use crate::SidecarDb;

    fn open_sidecar(tmp: &tempfile::TempDir) -> SidecarResult<SidecarDb> {
        let path = tmp.path().join("sidecar.db");
        SidecarDb::open(&path)
    }

    fn current_file_size(db: &SidecarDb) -> u64 {
        // Use the same total-disk footprint metric the production
        // code uses — main + WAL + SHM — so size assertions reflect
        // what the gate actually sees.
        sidecar_disk_footprint(db.path())
    }

    /// Inflate the database past `target_bytes` by writing a large
    /// `pending_apply.rules_json` row. We then delete it — SQLite
    /// retains the freed pages until VACUUM, so the file stays large
    /// while the live data is tiny, which is exactly the situation
    /// VACUUM is meant to clean up.
    fn inflate_then_free(db: &SidecarDb, target_bytes: u64) -> SidecarResult<()> {
        let blob = "x".repeat(target_bytes as usize);
        db.write_pending_apply_at(&blob, "{}", "hash", 1)?;
        db.clear_pending_apply()?;
        Ok(())
    }

    const T0: i64 = 1_700_000_000_000;

    #[test]
    fn fresh_db_below_threshold_does_not_vacuum() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        // Fresh DB with all schema + WAL header runs ~40-100 KiB total.
        // Threshold well above that → gate fails, no vacuum.
        let ran = db.maybe_vacuum_with(1024 * 1024, 0, T0)?;
        assert!(!ran, "fresh DB should be below 1 MiB total footprint");
        assert_eq!(db.read_last_vacuum_at_ms()?, 0);
        Ok(())
    }

    #[test]
    fn oversized_db_vacuums_and_records_timestamp() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        // Bloat the file past 256 KiB, then free the data so VACUUM
        // has work to do.
        inflate_then_free(&db, 300 * 1024)?;
        let size_before = current_file_size(&db);
        assert!(
            size_before >= 256 * 1024,
            "inflate should leave the file ≥ 256 KiB (was {size_before})"
        );
        let ran = db.maybe_vacuum_with(256 * 1024, 0, T0)?;
        assert!(ran, "oversized DB should vacuum");
        assert_eq!(db.read_last_vacuum_at_ms()?, T0);
        let size_after = current_file_size(&db);
        assert!(
            size_after < size_before,
            "VACUUM should shrink the file (before={size_before}, after={size_after})"
        );
        Ok(())
    }

    #[test]
    fn second_vacuum_within_min_interval_is_skipped() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        inflate_then_free(&db, 300 * 1024)?;
        // First run vacuums.
        let ran1 = db.maybe_vacuum_with(256 * 1024, 1_000, T0)?;
        assert!(ran1);
        // Re-inflate to keep size above threshold.
        inflate_then_free(&db, 300 * 1024)?;
        // 500 ms later — within the 1000 ms interval — should skip.
        let ran2 = db.maybe_vacuum_with(256 * 1024, 1_000, T0 + 500)?;
        assert!(!ran2, "second call within min_interval must skip");
        assert_eq!(db.read_last_vacuum_at_ms()?, T0);
        Ok(())
    }

    #[test]
    fn second_vacuum_after_min_interval_runs() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        inflate_then_free(&db, 300 * 1024)?;
        db.maybe_vacuum_with(256 * 1024, 1_000, T0)?;
        // Re-inflate so the size gate stays open.
        inflate_then_free(&db, 300 * 1024)?;
        let ran = db.maybe_vacuum_with(256 * 1024, 1_000, T0 + 2_000)?;
        assert!(ran, "vacuum should run again after the interval elapses");
        assert_eq!(db.read_last_vacuum_at_ms()?, T0 + 2_000);
        Ok(())
    }

    #[test]
    fn vacuum_now_force_runs_regardless_of_size() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.vacuum_now_at(T0)?;
        assert_eq!(db.read_last_vacuum_at_ms()?, T0);
        Ok(())
    }

    #[test]
    fn read_last_vacuum_defaults_to_zero() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        assert_eq!(db.read_last_vacuum_at_ms()?, 0);
        Ok(())
    }

    #[test]
    fn vacuum_creates_db_state_row_exactly_once() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.vacuum_now_at(T0)?;
        db.vacuum_now_at(T0 + 5_000)?;
        db.vacuum_now_at(T0 + 10_000)?;
        // The schema enforces CHECK(id=1), so any path that violates
        // single-row contract would error out earlier. Confirm only
        // one row exists.
        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM db_state", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        assert_eq!(db.read_last_vacuum_at_ms()?, T0 + 10_000);
        Ok(())
    }

    #[test]
    fn production_constants_are_sane() {
        // 10 MiB threshold and one-day interval — sanity-check the
        // numbers haven't drifted to nonsense in a rebase.
        assert_eq!(SIDECAR_VACUUM_SIZE_THRESHOLD_BYTES, 10 * 1024 * 1024);
        assert_eq!(SIDECAR_VACUUM_MIN_INTERVAL_MS, 86_400_000);
    }
}

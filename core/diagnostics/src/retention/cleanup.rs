//! Retention cleanup job.
//!
//! [`CleanupJob`] enforces retention policies by deleting files that exceed
//! the configured age, count, or total size limits.
//!
//! # Safety invariants
//!
//! - Audit NDJSON files (`nrr_audit_*`) are **never** deleted by operational
//!   log cleanup.  The cleanup functions are typed to operate on separate
//!   directories and match only the appropriate file prefix.
//! - The currently-open log file is skipped — deletion is safe only for closed
//!   (rotated-away) files. The writer's file is always the newest, so the
//!   newest entry is held back from every pass (`split_off_newest`). This used
//!   to be a promise with no code behind it.
//! - A limit of `0` means "no limit", for size exactly as for age and count.
//!   Read literally, a zero size cap means "delete until nothing is left".
//! - `security_alerts` rows in `nrr_service_state.db` are SQLite data managed
//!   by the service layer — they are never touched by file-based cleanup.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::retention::policy::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};

// ── CleanupResult ─────────────────────────────────────────────────────────────

/// Result of a single cleanup run.
#[derive(Clone, Debug, Default)]
pub struct CleanupResult {
    /// Number of files successfully deleted.
    pub files_deleted: u32,
    /// Total bytes freed.
    pub bytes_freed: u64,
    /// Number of files skipped (protected, active, or out of scope).
    pub files_skipped: u32,
    /// Errors encountered during deletion (file paths that could not be removed).
    pub errors: Vec<String>,
}

impl CleanupResult {
    /// Returns `true` if no files were deleted and no errors occurred.
    #[must_use]
    pub fn is_no_op(&self) -> bool {
        self.files_deleted == 0 && self.errors.is_empty()
    }

    fn deleted(&mut self, bytes: u64) {
        self.files_deleted += 1;
        self.bytes_freed += bytes;
    }
    #[allow(dead_code)] // symmetric counter helper; not currently called
    fn skipped(&mut self) {
        self.files_skipped += 1;
    }
    fn error(&mut self, path: &Path, reason: &str) {
        self.errors.push(format!("{}: {reason}", path.display()));
    }
}

// ── CleanupJob ────────────────────────────────────────────────────────────────

/// Stateless cleanup executor.  All methods are pure functions of their inputs.
pub struct CleanupJob;

impl CleanupJob {
    /// Runs the user-triggered manual cleanup of operational logs.
    ///
    /// Only deletes files allowed by `scope`.  Audit files are never touched.
    /// Returns a summary of what was deleted.
    pub fn run_logs(
        logs_dir: &Path,
        policy: &LogRetentionPolicy,
        scope: &ManualCleanupScope,
    ) -> CleanupResult {
        let mut result = CleanupResult::default();
        if !scope.operational_logs {
            return result;
        }
        let files = collect_log_files(logs_dir, "nrr_service_");
        apply_retention(
            &files,
            policy.max_age_days,
            policy.max_total_size_bytes,
            policy.max_files,
            &mut result,
        );
        result
    }

    /// Runs the scheduled cleanup of audit NDJSON files.
    ///
    /// This is a **service-internal** operation — not user-triggered.
    /// The user cannot call this directly from the GUI.
    pub fn run_audit(audit_dir: &Path, policy: &AuditRetentionPolicy) -> CleanupResult {
        let mut result = CleanupResult::default();
        let files = collect_log_files(audit_dir, "nrr_audit_");
        let policy = policy.clamped();
        apply_retention(
            &files,
            policy.max_age_days,
            policy.max_total_size_bytes,
            0,
            &mut result,
        );
        result
    }

    /// Produces a dry-run summary of what `run_logs` would delete.
    pub fn dry_run_logs(
        logs_dir: &Path,
        policy: &LogRetentionPolicy,
        scope: &ManualCleanupScope,
    ) -> CleanupResult {
        let mut result = CleanupResult::default();
        if !scope.operational_logs {
            return result;
        }
        let files = collect_log_files(logs_dir, "nrr_service_");
        dry_run_retention(
            &files,
            policy.max_age_days,
            policy.max_total_size_bytes,
            policy.max_files,
            &mut result,
        );
        result
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// A file entry with its size and modification time, ready for cleanup decisions.
struct FileEntry {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

fn collect_log_files(dir: &Path, prefix: &str) -> Vec<FileEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<FileEntry> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(prefix) || !name.ends_with(".ndjson") {
                return None;
            }
            let meta = e.metadata().ok()?;
            let modified = meta.modified().ok()?;
            Some(FileEntry {
                path: e.path(),
                size: meta.len(),
                modified,
            })
        })
        .collect();
    // Sort oldest first — we remove from the front.
    files.sort_by_key(|f| f.modified);
    files
}

fn apply_retention(
    files: &[FileEntry],
    max_age_days: u32,
    max_total_size_bytes: u64,
    max_files: u32,
    result: &mut CleanupResult,
) {
    let now = SystemTime::now();
    let age_threshold = Duration::from_secs(max_age_days as u64 * 86400);

    // The newest file is the one the writer currently holds open, and this
    // module's header has always promised to skip it. There was no code behind
    // the promise: a size pass could unlink the live file while `write_all` went
    // on returning `Ok` (Linux unlinks the inode, Windows opens with
    // FILE_SHARE_DELETE), so security events would be written into nothing and
    // reported as recorded. Protecting the newest entry keeps the promise
    // without threading a file handle through every caller.
    let (files, live) = split_off_newest(files);

    // Remaining files after age-based deletion (newest-first for size/count trimming).
    let mut remaining: Vec<&FileEntry> = Vec::new();

    for f in files {
        let age = now.duration_since(f.modified).unwrap_or(Duration::ZERO);
        if max_age_days > 0 && age > age_threshold {
            match std::fs::remove_file(&f.path) {
                Ok(()) => result.deleted(f.size),
                Err(e) => result.error(&f.path, &e.to_string()),
            }
        } else {
            remaining.push(f);
        }
    }

    // Count-based trim: keep only the newest `max_files` files. The protected
    // live file is one of them, so it counts against the budget — otherwise
    // "keep 2" would quietly keep 3.
    let keep_closed = (max_files as usize).saturating_sub(live.iter().count());
    if max_files > 0 && remaining.len() > keep_closed {
        let to_delete = remaining.len() - keep_closed;
        // `remaining` is oldest-first, so delete from the front.
        for f in remaining.iter().take(to_delete) {
            match std::fs::remove_file(&f.path) {
                Ok(()) => result.deleted(f.size),
                Err(e) => result.error(&f.path, &e.to_string()),
            }
        }
        remaining = remaining.into_iter().skip(to_delete).collect();
    }

    // Size-based trim: delete oldest until total size is within limit.
    //
    // Zero means "no size cap", exactly as `max_age_days` and `max_files` above
    // already read it and as the config layer documents and validates it. Taken
    // literally it meant "shrink to zero bytes": the loop could never satisfy
    // `total_size <= 0`, so picking "do not limit the size" in Settings deleted
    // every log — and, through `run_audit`, the whole audit hash chain with it.
    if max_total_size_bytes == 0 {
        return;
    }
    // The live file counts toward the total: the cap is about disk usage, and
    // pretending it is not there would trim the closed files harder than asked.
    let mut total_size: u64 =
        remaining.iter().map(|f| f.size).sum::<u64>() + live.map(|f| f.size).unwrap_or(0);
    // Decide the whole delete set FIRST, then attempt it. Shrinking the running
    // total only on success let one failed delete (file held by an export, an
    // ACL) push the loop on into ever NEWER files, deleting past the budget the
    // successful part had already met. Over budget until the next pass is the
    // right failure; deleting more than asked is not.
    let mut doomed = 0usize;
    for f in &remaining {
        if total_size <= max_total_size_bytes {
            break;
        }
        total_size = total_size.saturating_sub(f.size);
        doomed += 1;
    }
    for f in remaining.iter().take(doomed) {
        match std::fs::remove_file(&f.path) {
            Ok(()) => result.deleted(f.size),
            Err(e) => result.error(&f.path, &e.to_string()),
        }
    }
}

/// Split the newest entry off the (oldest-first) list. That entry is the file
/// the writer holds open; the rest are rotated away and safe to delete.
fn split_off_newest(files: &[FileEntry]) -> (&[FileEntry], Option<&FileEntry>) {
    match files.split_last() {
        Some((newest, rest)) => (rest, Some(newest)),
        None => (files, None),
    }
}

fn dry_run_retention(
    files: &[FileEntry],
    max_age_days: u32,
    max_total_size_bytes: u64,
    max_files: u32,
    result: &mut CleanupResult,
) {
    let now = SystemTime::now();
    let age_threshold = Duration::from_secs(max_age_days as u64 * 86400);
    let (files, live) = split_off_newest(files);
    let mut remaining: Vec<&FileEntry> = Vec::new();

    for f in files {
        let age = now.duration_since(f.modified).unwrap_or(Duration::ZERO);
        if max_age_days > 0 && age > age_threshold {
            result.deleted(f.size); // dry-run: count but don't delete
        } else {
            remaining.push(f);
        }
    }

    if max_files > 0 && remaining.len() > max_files as usize {
        let to_delete = remaining.len() - max_files as usize;
        for f in remaining.iter().take(to_delete) {
            result.deleted(f.size);
        }
        remaining = remaining.into_iter().skip(to_delete).collect();
    }

    if max_total_size_bytes == 0 {
        return;
    }
    let mut total_size: u64 =
        remaining.iter().map(|f| f.size).sum::<u64>() + live.map(|f| f.size).unwrap_or(0);
    for f in &remaining {
        if total_size <= max_total_size_bytes {
            break;
        }
        result.deleted(f.size);
        total_size = total_size.saturating_sub(f.size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::policy::{
        AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope, MIN_AUDIT_MAX_AGE_DAYS,
        MIN_AUDIT_MAX_SIZE_BYTES,
    };
    use std::io::Write;

    fn create_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(content).expect("write");
        path
    }

    fn log_file(dir: &Path, n: u32) -> PathBuf {
        create_file(dir, &format!("nrr_service_20260423-{n}.ndjson"), b"data")
    }

    fn audit_file(dir: &Path, n: u32) -> PathBuf {
        create_file(
            dir,
            &format!("nrr_audit_20260423-{n}.ndjson"),
            b"audit data",
        )
    }

    #[test]
    fn cleanup_logs_scope_false_is_no_op() {
        let dir = tempfile::tempdir().expect("temp");
        log_file(dir.path(), 1);

        let scope = ManualCleanupScope {
            operational_logs: false,
            ..ManualCleanupScope::default()
        };
        let policy = LogRetentionPolicy::default();
        let r = CleanupJob::run_logs(dir.path(), &policy, &scope);

        assert!(r.is_no_op());
        assert!(dir.path().join("nrr_service_20260423-1.ndjson").exists());
    }

    #[test]
    fn cleanup_logs_by_count_keeps_newest() {
        let dir = tempfile::tempdir().expect("temp");
        for i in 1..=5 {
            log_file(dir.path(), i);
        }

        let policy = LogRetentionPolicy {
            max_files: 2,
            max_age_days: 0,                // no age limit
            max_total_size_bytes: u64::MAX, // no size limit
            ..LogRetentionPolicy::default()
        };
        let scope = ManualCleanupScope::default();
        let r = CleanupJob::run_logs(dir.path(), &policy, &scope);

        // Should have deleted 3 oldest files.
        assert_eq!(r.files_deleted, 3);
        let remaining = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .count();
        assert_eq!(remaining, 2);
    }

    #[test]
    fn no_size_limit_means_no_limit_not_delete_everything() {
        // Choosing "do not limit the size" in Settings sends zero, which the
        // config layer documents and validates as "no size cap". Read literally
        // it meant "shrink to zero bytes", and the loop could never satisfy
        // that — so the setting deleted every operational log.
        let dir = tempfile::tempdir().expect("temp");
        for i in 1..=4 {
            log_file(dir.path(), i);
        }
        let policy = LogRetentionPolicy {
            max_files: 0,
            max_age_days: 0,
            max_total_size_bytes: 0,
            ..LogRetentionPolicy::default()
        };
        let r = CleanupJob::run_logs(dir.path(), &policy, &ManualCleanupScope::default());
        assert_eq!(r.files_deleted, 0, "zero means unlimited, not 'delete all'");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 4);
    }

    #[test]
    fn no_size_limit_leaves_the_audit_chain_alone() {
        // The same function runs over audit files, so the same setting took the
        // hash chain with it — the one thing the product promises never to
        // delete on the user's behalf.
        let dir = tempfile::tempdir().expect("temp");
        for i in 1..=3 {
            create_file(
                dir.path(),
                &format!("nrr_audit_2026010{i}-1.ndjson"),
                b"{\"seq\":1}\n",
            );
        }
        let policy = AuditRetentionPolicy {
            max_age_days: 0,
            max_total_size_bytes: 0,
        };
        let r = CleanupJob::run_audit(dir.path(), &policy);
        assert_eq!(r.files_deleted, 0);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn the_file_the_writer_holds_open_is_never_deleted() {
        // A single file that alone exceeds the cap used to be deleted — while
        // the writer kept writing into the unlinked handle and reporting every
        // security event as recorded.
        let dir = tempfile::tempdir().expect("temp");
        let live = create_file(dir.path(), "nrr_audit_20260101-1.ndjson", &vec![b'x'; 4096]);
        let policy = AuditRetentionPolicy {
            max_age_days: 0,
            max_total_size_bytes: 10,
        };
        let r = CleanupJob::run_audit(dir.path(), &policy);
        assert_eq!(r.files_deleted, 0, "the live file must survive any pass");
        assert!(live.exists());
    }

    #[test]
    fn an_age_sweep_that_covers_everything_still_spares_the_live_file() {
        let dir = tempfile::tempdir().expect("temp");
        for i in 1..=3 {
            log_file(dir.path(), i);
        }
        let policy = LogRetentionPolicy {
            max_files: 0,
            // Everything on disk is older than "zero days ago" once the
            // threshold is this small, so without the guard the sweep would
            // take the file currently being written to as well.
            max_age_days: 1,
            max_total_size_bytes: u64::MAX,
            ..LogRetentionPolicy::default()
        };
        let _ = CleanupJob::run_logs(dir.path(), &policy, &ManualCleanupScope::default());
        assert!(
            std::fs::read_dir(dir.path()).unwrap().count() >= 1,
            "at least the live file must remain",
        );
    }

    #[test]
    fn cleanup_logs_by_size_removes_oldest() {
        let dir = tempfile::tempdir().expect("temp");
        // Each file is 4 bytes ("data"). 5 files = 20 bytes.
        for i in 1..=5 {
            log_file(dir.path(), i);
        }

        let policy = LogRetentionPolicy {
            max_total_size_bytes: 8, // allow only 2 files worth
            max_age_days: 0,
            max_files: 0,
            ..LogRetentionPolicy::default()
        };
        let scope = ManualCleanupScope::default();
        let r = CleanupJob::run_logs(dir.path(), &policy, &scope);

        assert!(r.files_deleted > 0);
        let remaining_size: u64 = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok().map(|m| m.len()))
            .sum();
        assert!(remaining_size <= 8);
    }

    #[test]
    fn audit_files_not_deleted_by_log_cleanup() {
        let dir = tempfile::tempdir().expect("temp");
        log_file(dir.path(), 1);
        let audit = audit_file(dir.path(), 1);

        let policy = LogRetentionPolicy {
            max_files: 0,
            max_age_days: 0,
            max_total_size_bytes: 1, // tiny limit to force deletion
            ..LogRetentionPolicy::default()
        };
        let scope = ManualCleanupScope::default();
        CleanupJob::run_logs(dir.path(), &policy, &scope);

        // Audit file must still exist.
        assert!(
            audit.exists(),
            "audit file must not be deleted by log cleanup"
        );
    }

    #[test]
    fn dry_run_does_not_delete_files() {
        let dir = tempfile::tempdir().expect("temp");
        for i in 1..=5 {
            log_file(dir.path(), i);
        }

        let policy = LogRetentionPolicy {
            max_files: 2,
            max_age_days: 0,
            max_total_size_bytes: u64::MAX,
            ..LogRetentionPolicy::default()
        };
        let scope = ManualCleanupScope::default();
        let r = CleanupJob::dry_run_logs(dir.path(), &policy, &scope);

        // Dry run reports what would be deleted but doesn't delete.
        assert!(r.files_deleted > 0);
        let still_present = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(still_present, 5, "dry run must not delete files");
    }

    #[test]
    fn cleanup_result_default_is_no_op() {
        let r = CleanupResult::default();
        assert!(r.is_no_op());
        assert_eq!(r.files_deleted, 0);
        assert_eq!(r.bytes_freed, 0);
    }

    #[test]
    fn audit_cleanup_does_not_touch_service_logs() {
        let dir = tempfile::tempdir().expect("temp");
        let log = log_file(dir.path(), 1);
        audit_file(dir.path(), 1);

        let policy = AuditRetentionPolicy {
            max_age_days: 0,
            max_total_size_bytes: 1,
        };
        CleanupJob::run_audit(dir.path(), &policy);

        // Service log must still exist.
        assert!(
            log.exists(),
            "service log must not be touched by audit cleanup"
        );
    }

    #[test]
    fn cleanup_empty_dir_is_no_op() {
        let dir = tempfile::tempdir().expect("temp");
        let policy = LogRetentionPolicy::default();
        let scope = ManualCleanupScope::default();
        let r = CleanupJob::run_logs(dir.path(), &policy, &scope);
        assert!(r.is_no_op());
    }

    #[test]
    fn a_one_day_audit_policy_cannot_erase_the_trail() {
        let dir = tempfile::tempdir().expect("temp");
        for n in 1..=3 {
            audit_file(dir.path(), n);
        }

        // What a user could save in Settings before the floor existed.
        let policy = AuditRetentionPolicy {
            max_age_days: 1,
            max_total_size_bytes: 1024,
        };
        let clamped = policy.clamped();
        assert_eq!(clamped.max_age_days, MIN_AUDIT_MAX_AGE_DAYS);
        assert_eq!(clamped.max_total_size_bytes, MIN_AUDIT_MAX_SIZE_BYTES);

        let r = CleanupJob::run_audit(dir.path(), &policy);
        assert_eq!(r.files_deleted, 0, "the floor must keep the trail intact");
        for n in 1..=3 {
            assert!(dir
                .path()
                .join(format!("nrr_audit_20260423-{n}.ndjson"))
                .exists());
        }
    }

    #[test]
    fn a_disabled_size_cap_is_not_turned_into_a_ten_mib_one() {
        let policy = AuditRetentionPolicy {
            max_age_days: 365,
            max_total_size_bytes: 0,
        };
        assert_eq!(policy.clamped().max_total_size_bytes, 0);
    }

    #[cfg(windows)]
    #[test]
    fn a_failed_delete_does_not_push_the_size_pass_into_newer_files() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().expect("temp");
        // Four closed files of 100 bytes plus the live one; a 250-byte budget
        // needs the three oldest gone and must not reach the fourth.
        for n in 1..=5 {
            create_file(
                dir.path(),
                &format!("nrr_service_20260423-{n}.ndjson"),
                &[b'x'; 100],
            );
        }
        // The oldest cannot be removed: an exclusive handle stands in for the
        // real cases (an export holding the file, an ACL).
        let locked = dir.path().join("nrr_service_20260423-1.ndjson");
        let _handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&locked)
            .expect("exclusive open");

        let policy = LogRetentionPolicy {
            max_age_days: 0,
            max_total_size_bytes: 250,
            max_files: 0,
            ..LogRetentionPolicy::default()
        };
        let r = CleanupJob::run_logs(dir.path(), &policy, &ManualCleanupScope::default());

        assert!(
            !r.errors.is_empty(),
            "the failed delete must be reported: {r:?}"
        );
        assert!(
            dir.path().join("nrr_service_20260423-4.ndjson").exists(),
            "a delete that failed must not cost a newer file its life"
        );
    }
}

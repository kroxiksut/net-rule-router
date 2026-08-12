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
//! - The currently-open log file (if any) is skipped — deletion is safe only
//!   for closed (rotated-away) files.  In practice the writer's file is always
//!   the newest; the age/size limits remove older files first.
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

    // Count-based trim: keep only the newest `max_files` files.
    if max_files > 0 && remaining.len() > max_files as usize {
        let to_delete = remaining.len() - max_files as usize;
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
    let mut total_size: u64 = remaining.iter().map(|f| f.size).sum();
    for f in &remaining {
        if total_size <= max_total_size_bytes {
            break;
        }
        match std::fs::remove_file(&f.path) {
            Ok(()) => {
                result.deleted(f.size);
                total_size = total_size.saturating_sub(f.size);
            }
            Err(e) => result.error(&f.path, &e.to_string()),
        }
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

    let mut total_size: u64 = remaining.iter().map(|f| f.size).sum();
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
    use crate::retention::policy::{AuditRetentionPolicy, LogRetentionPolicy, ManualCleanupScope};
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
}

//! Storage health snapshot.
//!
//! [`StorageHealthSnapshot`] aggregates the health of all diagnostic storage
//! components and is exposed to GUI/tray via the service facade.

// ── AuditWriteStatus ──────────────────────────────────────────────────────────

/// Health of the audit NDJSON trail writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditWriteStatus {
    /// Audit trail is healthy; all writes succeed.
    Healthy,
    /// The audit writer is in a degraded state (e.g., disk error).
    /// Security-critical actions must be blocked.
    Degraded { last_error_ms: i64 },
    /// The audit directory is not writable at all.
    Unavailable,
}

impl AuditWriteStatus {
    #[must_use]
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    #[must_use]
    pub fn allows_security_critical_action(self) -> bool {
        self.is_healthy()
    }
}

// ── StorageHealthSnapshot ─────────────────────────────────────────────────────

/// Aggregated health of all diagnostic storage components.
///
/// Populated by the service and exposed to GUI/tray via the diagnostics
/// query facade.
#[derive(Clone, Debug)]
pub struct StorageHealthSnapshot {
    /// Whether the operational logs directory is writable.
    pub logs_dir_writable: bool,

    /// Whether the audit NDJSON directory is writable.
    pub audit_dir_writable: bool,

    /// UTC Unix milliseconds of the last log file rotation, if any.
    pub last_rotation_at: Option<i64>,

    /// UTC Unix milliseconds of the last retention cleanup run, if any.
    pub last_cleanup_at: Option<i64>,

    /// Number of operational log events dropped since the writer started.
    pub dropped_log_count: u64,

    /// Health of the audit trail writer.
    pub audit_write_status: AuditWriteStatus,

    /// Approximate total size of operational log files (bytes).
    pub log_total_size_bytes: u64,

    /// Approximate total size of audit NDJSON files (bytes).
    pub audit_total_size_bytes: u64,

    /// Number of operational log files currently on disk.
    pub log_file_count: u32,

    /// Number of audit NDJSON files currently on disk.
    pub audit_file_count: u32,
}

impl StorageHealthSnapshot {
    /// Constructs a healthy snapshot with zeroed counters.
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            logs_dir_writable: true,
            audit_dir_writable: true,
            last_rotation_at: None,
            last_cleanup_at: None,
            dropped_log_count: 0,
            audit_write_status: AuditWriteStatus::Healthy,
            log_total_size_bytes: 0,
            audit_total_size_bytes: 0,
            log_file_count: 0,
            audit_file_count: 0,
        }
    }

    /// Returns `true` if both logs and audit are accessible and healthy.
    #[must_use]
    pub fn is_fully_healthy(&self) -> bool {
        self.logs_dir_writable && self.audit_dir_writable && self.audit_write_status.is_healthy()
    }

    /// Returns `true` if security-critical audit operations are safe.
    #[must_use]
    pub fn allows_security_critical_action(&self) -> bool {
        self.audit_dir_writable && self.audit_write_status.allows_security_critical_action()
    }
}

// ── StorageHealthCollector ────────────────────────────────────────────────────

/// Collects a live health snapshot by inspecting the file system.
pub struct StorageHealthCollector {
    pub logs_dir: std::path::PathBuf,
    pub audit_dir: std::path::PathBuf,
}

impl StorageHealthCollector {
    pub fn new(
        logs_dir: impl Into<std::path::PathBuf>,
        audit_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            logs_dir: logs_dir.into(),
            audit_dir: audit_dir.into(),
        }
    }

    /// Collects the health snapshot by scanning directories.
    ///
    /// Never fails — returns a degraded snapshot on I/O errors.
    pub fn collect(
        &self,
        dropped_log_count: u64,
        audit_status: AuditWriteStatus,
    ) -> StorageHealthSnapshot {
        let (log_size, log_count) = dir_stats(&self.logs_dir, "nrr_service_", ".ndjson");
        let (audit_size, audit_count) = dir_stats(&self.audit_dir, "nrr_audit_", ".ndjson");

        let logs_dir_writable = is_dir_writable(&self.logs_dir);
        let audit_dir_writable = is_dir_writable(&self.audit_dir);

        StorageHealthSnapshot {
            logs_dir_writable,
            audit_dir_writable,
            last_rotation_at: None,
            last_cleanup_at: None,
            dropped_log_count,
            audit_write_status: audit_status,
            log_total_size_bytes: log_size,
            audit_total_size_bytes: audit_size,
            log_file_count: log_count,
            audit_file_count: audit_count,
        }
    }
}

fn dir_stats(dir: &std::path::Path, prefix: &str, suffix: &str) -> (u64, u32) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut total_size = 0u64;
    let mut count = 0u32;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && name.ends_with(suffix) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            total_size += size;
            count += 1;
        }
    }
    (total_size, count)
}

fn is_dir_writable(dir: &std::path::Path) -> bool {
    if !dir.exists() {
        return std::fs::create_dir_all(dir).is_ok();
    }
    // Try to create and immediately delete a probe file.
    let probe = dir.join(".nrr_write_probe");
    let ok = std::fs::write(&probe, b"").is_ok();
    if ok {
        let _ = std::fs::remove_file(&probe);
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_snapshot_is_fully_healthy() {
        let s = StorageHealthSnapshot::healthy();
        assert!(s.is_fully_healthy());
        assert!(s.allows_security_critical_action());
    }

    #[test]
    fn unavailable_audit_blocks_security_action() {
        let mut s = StorageHealthSnapshot::healthy();
        s.audit_write_status = AuditWriteStatus::Unavailable;
        assert!(!s.allows_security_critical_action());
        assert!(!s.is_fully_healthy());
    }

    #[test]
    fn unwritable_logs_dir_not_fully_healthy() {
        let mut s = StorageHealthSnapshot::healthy();
        s.logs_dir_writable = false;
        assert!(!s.is_fully_healthy());
        // Security action still allowed if audit is healthy.
        assert!(s.allows_security_critical_action());
    }

    #[test]
    fn audit_write_status_healthy() {
        assert!(AuditWriteStatus::Healthy.is_healthy());
        assert!(AuditWriteStatus::Healthy.allows_security_critical_action());
    }

    #[test]
    fn audit_write_status_degraded() {
        let s = AuditWriteStatus::Degraded { last_error_ms: 0 };
        assert!(!s.is_healthy());
        assert!(!s.allows_security_critical_action());
    }

    #[test]
    fn health_collector_on_temp_dir() {
        let dir = tempfile::tempdir().expect("temp");
        let collector = StorageHealthCollector::new(dir.path(), dir.path());
        let snap = collector.collect(0, AuditWriteStatus::Healthy);
        assert!(snap.logs_dir_writable);
        assert_eq!(snap.log_file_count, 0);
        assert_eq!(snap.dropped_log_count, 0);
    }

    #[test]
    fn health_collector_counts_files() {
        let dir = tempfile::tempdir().expect("temp");
        std::fs::write(dir.path().join("nrr_service_20260423-1.ndjson"), b"test").unwrap();
        std::fs::write(dir.path().join("nrr_service_20260423-2.ndjson"), b"test").unwrap();
        std::fs::write(dir.path().join("nrr_audit_20260423-1.ndjson"), b"test").unwrap();

        let collector = StorageHealthCollector::new(dir.path(), dir.path());
        let snap = collector.collect(0, AuditWriteStatus::Healthy);
        assert_eq!(snap.log_file_count, 2);
        assert_eq!(snap.audit_file_count, 1);
        assert!(snap.log_total_size_bytes > 0);
    }
}

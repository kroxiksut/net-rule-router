use std::path::Path;
use std::time::SystemTime;

use crate::profile::StorageTopology;

/// Write-access status of a storage location.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageAccessStatus {
    /// Parent directory exists and a probe file was successfully written.
    Writable,
    /// Parent directory exists but writing was denied by OS permissions.
    ReadOnly,
    /// Parent directory does not exist — storage not bootstrapped yet.
    Missing,
    /// Write attempt failed for a reason other than permissions (disk full,
    /// I/O error, etc.).
    ProbeWriteFailed { reason: String },
}

impl StorageAccessStatus {
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::Writable)
    }
}

/// Access report for a single database file.
#[derive(Debug)]
pub struct DatabaseAccessReport {
    /// Short identifier used in diagnostics.
    pub db_name: &'static str,
    /// Whether the parent data directory exists.
    pub data_dir_exists: bool,
    /// Whether the database file itself exists (it may not on a fresh install).
    pub db_file_exists: bool,
    /// Result of a non-destructive probe write into the data directory.
    pub access: StorageAccessStatus,
}

impl DatabaseAccessReport {
    pub fn is_service_ready(&self) -> bool {
        self.data_dir_exists && self.access.is_writable()
    }
}

/// Aggregated access report for both storage databases.
///
/// Produced by [`verify_storage_access`] and exposed to the GUI via the
/// service facade.  The GUI must not read the SQLite files
/// directly even if they are physically accessible.
#[derive(Debug)]
pub struct StorageAccessReport {
    pub cache_db: DatabaseAccessReport,
    pub state_db: DatabaseAccessReport,
    pub checked_at: SystemTime,
}

impl StorageAccessReport {
    /// Returns `true` only when both databases are in a service-ready state
    /// (parent directory exists and probe write succeeded).
    pub fn both_writable(&self) -> bool {
        self.cache_db.is_service_ready() && self.state_db.is_service_ready()
    }
}

/// Verifies that the service can write to both database locations.
///
/// Uses a temporary probe file inside `topology.data_dir` — it never opens or
/// modifies the actual SQLite files.  Safe to call before the databases exist.
pub fn verify_storage_access(topology: &StorageTopology) -> StorageAccessReport {
    let data_dir_exists = topology.data_dir.exists();

    let access = if data_dir_exists {
        probe_write_access(&topology.data_dir)
    } else {
        StorageAccessStatus::Missing
    };

    // Both databases live in the same data directory, so one probe covers both.
    // We record individual db_file_exists flags for the health surface.
    StorageAccessReport {
        cache_db: DatabaseAccessReport {
            db_name: "nrr_fqdn_ip_cache.db",
            data_dir_exists,
            db_file_exists: topology.cache_db_path.exists(),
            access: clone_access_status(&access),
        },
        state_db: DatabaseAccessReport {
            db_name: "nrr_service_state.db",
            data_dir_exists,
            db_file_exists: topology.state_db_path.exists(),
            access,
        },
        checked_at: SystemTime::now(),
    }
}

/// Attempts to create and immediately remove a probe file in `dir`.
///
/// Uses a dedicated probe filename (`.nrr_write_probe`) to avoid touching any
/// SQLite file.  The probe file is removed regardless of success or failure.
fn probe_write_access(dir: &Path) -> StorageAccessStatus {
    let probe_path = dir.join(".nrr_write_probe");

    let open_result = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe_path);

    match open_result {
        Ok(_) => {
            // Always clean up; ignore removal errors — they don't affect the
            // writability conclusion.
            let _ = std::fs::remove_file(&probe_path);
            StorageAccessStatus::Writable
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => StorageAccessStatus::ReadOnly,
        Err(e) => StorageAccessStatus::ProbeWriteFailed {
            reason: e.to_string(),
        },
    }
}

/// Clones an `StorageAccessStatus` value for reuse across two report entries.
fn clone_access_status(status: &StorageAccessStatus) -> StorageAccessStatus {
    match status {
        StorageAccessStatus::Writable => StorageAccessStatus::Writable,
        StorageAccessStatus::ReadOnly => StorageAccessStatus::ReadOnly,
        StorageAccessStatus::Missing => StorageAccessStatus::Missing,
        StorageAccessStatus::ProbeWriteFailed { reason } => StorageAccessStatus::ProbeWriteFailed {
            reason: reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::bootstrap_storage_directories;
    use crate::profile::{resolve_storage_topology, StorageProfile};

    fn bootstrapped_topology() -> (tempfile::TempDir, StorageTopology) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let topology =
            resolve_storage_topology(&StorageProfile::TestTemp(dir.path().to_path_buf()))
                .expect("topology");
        bootstrap_storage_directories(
            &topology,
            &StorageProfile::TestTemp(topology.data_dir.clone()),
        )
        .expect("bootstrap");
        (dir, topology)
    }

    #[test]
    fn writable_after_bootstrap() {
        let (_dir, topology) = bootstrapped_topology();
        let report = verify_storage_access(&topology);

        assert!(report.both_writable());
        assert_eq!(report.cache_db.access, StorageAccessStatus::Writable);
        assert_eq!(report.state_db.access, StorageAccessStatus::Writable);
        assert!(report.cache_db.data_dir_exists);
        assert!(report.state_db.data_dir_exists);
    }

    #[test]
    fn db_files_not_present_before_schema_creation() {
        let (_dir, topology) = bootstrapped_topology();
        let report = verify_storage_access(&topology);

        // Directories exist after bootstrap, but DB files don't exist yet.
        assert!(!report.cache_db.db_file_exists);
        assert!(!report.state_db.db_file_exists);
    }

    #[test]
    fn missing_when_dir_not_bootstrapped() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        // Note: subdirectory that does NOT exist
        let missing_dir = dir.path().join("nonexistent");
        let topology =
            resolve_storage_topology(&StorageProfile::TestTemp(missing_dir)).expect("topology");

        let report = verify_storage_access(&topology);

        assert!(!report.cache_db.data_dir_exists);
        assert!(!report.state_db.data_dir_exists);
        assert_eq!(report.cache_db.access, StorageAccessStatus::Missing);
        assert_eq!(report.state_db.access, StorageAccessStatus::Missing);
        assert!(!report.both_writable());
    }

    #[test]
    fn probe_does_not_leave_leftover_file() {
        let (_dir, topology) = bootstrapped_topology();
        verify_storage_access(&topology);

        let probe_path = topology.data_dir.join(".nrr_write_probe");
        assert!(
            !probe_path.exists(),
            "probe file must be cleaned up after access check"
        );
    }

    #[test]
    fn db_name_labels_are_correct() {
        let (_dir, topology) = bootstrapped_topology();
        let report = verify_storage_access(&topology);

        assert_eq!(report.cache_db.db_name, "nrr_fqdn_ip_cache.db");
        assert_eq!(report.state_db.db_name, "nrr_service_state.db");
    }
}

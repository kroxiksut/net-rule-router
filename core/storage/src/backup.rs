use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{StorageError, StorageResult};

/// Whether a database backup is mandatory or optional before a migration.
///
/// | Database | Policy |
/// |----------|--------|
/// | `nrr_service_state.db` | `Required` — contains non-rebuildable revision pointers |
/// | `nrr_fqdn_ip_cache.db` | `Optional` — fully rebuildable from the source of truth |
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupPolicy {
    /// Backup is mandatory.  Migration runner must abort if the backup fails.
    Required,
    /// Backup is optional.  If it fails, migration may proceed; a warning is
    /// emitted but the operation is not aborted.
    Optional,
}

/// Why a backup was requested.  Encoded into the backup filename for traceability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackupReason {
    /// Created by the migration runner before applying a structural schema change.
    PreMigration { from_version: u32, to_version: u32 },
    /// Created before a user-requested manual cache reset.
    PreCacheReset,
    /// Created by the manual export flow.
    ManualExport,
}

/// Copies a SQLite database file into `backup_dir`.
///
/// The backup filename is:
/// `<db_stem>_<utc_ms>_<reason_tag>.db`
///
/// For example:
/// `nrr_service_state_1714000000000_premig_v1_v2.db`
///
/// Returns the path of the newly created backup file.
///
/// # Errors
///
/// Returns [`StorageError::Internal`] if `source` does not exist, the copy
/// fails (I/O error, disk full), or the source path has no usable file stem.
pub fn backup_database(
    source: &Path,
    backup_dir: &Path,
    reason: &BackupReason,
) -> StorageResult<PathBuf> {
    if !source.exists() {
        return Err(StorageError::Internal(format!(
            "backup source does not exist: {}",
            source.display()
        )));
    }

    let stem = source.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
        StorageError::Internal(format!(
            "database path has no usable file stem: {}",
            source.display()
        ))
    })?;

    let timestamp_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default();

    let backup_name = format!("{stem}_{timestamp_ms}_{}.db", reason_tag(reason));
    let dest = backup_dir.join(backup_name);

    std::fs::copy(source, &dest).map_err(|e| {
        StorageError::Internal(format!(
            "failed to copy {} → {}: {e}",
            source.display(),
            dest.display()
        ))
    })?;

    Ok(dest)
}

fn reason_tag(reason: &BackupReason) -> String {
    match reason {
        BackupReason::PreMigration {
            from_version,
            to_version,
        } => {
            format!("premig_v{from_version}_v{to_version}")
        }
        BackupReason::PreCacheReset => "pre_reset".into(),
        BackupReason::ManualExport => "manual".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::bootstrap_storage_directories;
    use crate::profile::{resolve_storage_topology, StorageProfile};

    fn setup() -> (tempfile::TempDir, crate::profile::StorageTopology) {
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

    fn create_dummy_db(path: &Path) {
        std::fs::write(path, b"SQLite format 3\x00dummy").expect("create dummy db");
    }

    #[test]
    fn backup_creates_file_in_backup_dir() {
        let (_dir, topology) = setup();
        create_dummy_db(&topology.state_db_path);

        let dest = backup_database(
            &topology.state_db_path,
            &topology.migration_backup_dir,
            &BackupReason::PreMigration {
                from_version: 1,
                to_version: 2,
            },
        )
        .expect("backup must succeed");

        assert!(dest.exists());
        assert_eq!(dest.parent(), Some(topology.migration_backup_dir.as_path()));
    }

    #[test]
    fn backup_filename_contains_reason_tag() {
        let (_dir, topology) = setup();
        create_dummy_db(&topology.state_db_path);

        let dest = backup_database(
            &topology.state_db_path,
            &topology.migration_backup_dir,
            &BackupReason::PreMigration {
                from_version: 3,
                to_version: 4,
            },
        )
        .expect("backup");

        let name = dest.file_name().and_then(|n| n.to_str()).expect("filename");
        assert!(
            name.contains("premig_v3_v4"),
            "filename {name:?} must contain reason tag"
        );
        assert!(name.starts_with("nrr_service_state_"));
        assert!(name.ends_with(".db"));
    }

    #[test]
    fn backup_pre_cache_reset_tag() {
        let (_dir, topology) = setup();
        create_dummy_db(&topology.cache_db_path);

        let dest = backup_database(
            &topology.cache_db_path,
            &topology.backup_dir,
            &BackupReason::PreCacheReset,
        )
        .expect("backup");

        let name = dest.file_name().and_then(|n| n.to_str()).expect("filename");
        assert!(name.contains("pre_reset"));
    }

    #[test]
    fn backup_missing_source_returns_error() {
        let (_dir, topology) = setup();
        // state_db_path does not exist yet
        let result = backup_database(
            &topology.state_db_path,
            &topology.migration_backup_dir,
            &BackupReason::PreMigration {
                from_version: 1,
                to_version: 2,
            },
        );

        assert!(
            result.is_err(),
            "backing up a non-existent source must return Err"
        );
        assert!(matches!(result, Err(StorageError::Internal(_))));
    }

    #[test]
    fn backup_preserves_content() {
        let (_dir, topology) = setup();
        let content = b"SQLite format 3\x00test_content_xyz";
        std::fs::write(&topology.cache_db_path, content).expect("write source");

        let dest = backup_database(
            &topology.cache_db_path,
            &topology.backup_dir,
            &BackupReason::ManualExport,
        )
        .expect("backup");

        let read_back = std::fs::read(&dest).expect("read backup");
        assert_eq!(read_back, content);
    }

    #[test]
    fn backup_policy_values_are_distinct() {
        assert_ne!(BackupPolicy::Required, BackupPolicy::Optional);
    }
}

use std::path::PathBuf;
use std::time::SystemTime;

use crate::error::{StorageError, StorageResult};
use crate::profile::{StorageProfile, StorageTopology};

/// Summary of what `bootstrap_storage_directories` created.
#[derive(Debug)]
pub struct StorageBootstrapResult {
    /// Directories that were newly created during this call.
    pub created_dirs: Vec<PathBuf>,
    /// Directories that already existed and were left untouched.
    pub already_existed: Vec<PathBuf>,
    pub bootstrapped_at: SystemTime,
}

/// Creates all directories required by the storage layer.
///
/// Safe to call repeatedly — directories that already exist are silently
/// accepted.  Returns a summary of what was created vs what was pre-existing.
///
/// # ACL expectations
///
/// For `ProductionService`, the **service installer** is responsible
/// for restricting `%ProgramData%\NetRuleRouter\` to SYSTEM and the service
/// account using `icacls`.  This function only creates the directory structure;
/// it does not set ACLs.
///
/// `DevelopmentLocal` and `TestTemp` profiles inherit the current-user ACLs
/// from the parent directory — no special configuration is needed.
///
/// # Security invariant
///
/// Regular users must not be able to modify service-owned databases directly.
/// The expected production ACL state (set by the installer, not this function):
/// - `%ProgramData%\NetRuleRouter\`: SYSTEM (Full), service account (Full),
///   Administrators (Read+Execute), Users (none).
///
/// The service installer (`nrr-windows-service::scm::install_service_with_config`)
/// invokes `icacls` after first creation to enforce the ACL above
/// (`apply_data_dir_acl`). The installer's `InstallOutcome.acl_applied`
/// reports whether the lockdown succeeded; operators can re-run install
/// to retry on a Permissive ACL.
pub fn bootstrap_storage_directories(
    topology: &StorageTopology,
    _profile: &StorageProfile,
) -> StorageResult<StorageBootstrapResult> {
    let required_dirs: &[&PathBuf] = &[
        &topology.data_dir,
        &topology.backup_dir,
        &topology.migration_backup_dir,
        &topology.temp_dir,
    ];

    let mut created_dirs = Vec::new();
    let mut already_existed = Vec::new();

    for &dir in required_dirs {
        if dir.exists() {
            already_existed.push(dir.clone());
        } else {
            std::fs::create_dir_all(dir).map_err(|e| {
                StorageError::StorageUnavailable(format!(
                    "cannot create storage directory {}: {e}",
                    dir.display()
                ))
            })?;
            created_dirs.push(dir.clone());
        }
    }

    Ok(StorageBootstrapResult {
        created_dirs,
        already_existed,
        bootstrapped_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{resolve_storage_topology, StorageProfile};

    fn test_topology() -> (tempfile::TempDir, StorageTopology) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let topology =
            resolve_storage_topology(&StorageProfile::TestTemp(dir.path().to_path_buf()))
                .expect("topology");
        (dir, topology)
    }

    #[test]
    fn bootstrap_creates_all_required_dirs() {
        let (_dir, topology) = test_topology();
        let result = bootstrap_storage_directories(
            &topology,
            &StorageProfile::TestTemp(topology.data_dir.clone()),
        )
        .expect("bootstrap must succeed");

        // All four directories should have been created.
        assert!(topology.data_dir.exists());
        assert!(topology.backup_dir.exists());
        assert!(topology.migration_backup_dir.exists());
        assert!(topology.temp_dir.exists());

        assert!(
            !result.created_dirs.is_empty(),
            "at least one dir should be newly created"
        );
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let (_dir, topology) = test_topology();
        let profile = StorageProfile::TestTemp(topology.data_dir.clone());

        bootstrap_storage_directories(&topology, &profile).expect("first bootstrap");
        let result = bootstrap_storage_directories(&topology, &profile)
            .expect("second bootstrap must also succeed");

        // Everything already existed on the second call.
        assert!(result.created_dirs.is_empty());
        assert_eq!(result.already_existed.len(), 4);
    }

    #[test]
    fn bootstrap_reports_created_vs_existing() {
        let (_dir, topology) = test_topology();
        let profile = StorageProfile::TestTemp(topology.data_dir.clone());

        // Pre-create data_dir only.
        std::fs::create_dir_all(&topology.data_dir).expect("pre-create");

        let result = bootstrap_storage_directories(&topology, &profile).expect("bootstrap");

        assert!(result.already_existed.contains(&topology.data_dir));
        assert!(result.created_dirs.contains(&topology.backup_dir));
        assert!(result.created_dirs.contains(&topology.migration_backup_dir));
        assert!(result.created_dirs.contains(&topology.temp_dir));
    }
}

use std::path::PathBuf;

use crate::error::{StorageError, StorageResult};

/// Selects which file-system layout the storage layer uses.
///
/// The production layout requires `%ProgramData%` (elevated service territory).
/// Tests use `TestTemp` to stay in a caller-supplied temp directory without
/// needing elevated privileges.
#[derive(Debug, Clone)]
pub enum StorageProfile {
    /// Production system-service layout. On Windows this is
    /// `%ProgramData%\NetRuleRouter\`; on Linux it is `/var/lib/netrulerouter`
    /// (the systemd `StateDirectory`) for state/cache/traffic/audit, with
    /// operational logs split out to `/var/log/netrulerouter` per FHS.
    /// Used only by the real system service.
    ProductionService,
    /// `%LOCALAPPDATA%\NetRuleRouter\dev\` — developer workstation layout,
    /// no elevated privileges needed.
    DevelopmentLocal,
    /// Caller-supplied directory.  All database files are placed directly
    /// inside it.  Created by test helpers via `tempfile::TempDir`.
    TestTemp(PathBuf),
}

/// Resolved absolute paths for all storage artefacts.
///
/// Constructed via [`resolve_storage_topology`]; never built by hand.
/// All paths are absolute and ready for use — directory creation is a
/// separate step performed by the startup sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageTopology {
    /// Root data directory that contains all other artefacts.
    pub data_dir: PathBuf,
    /// Operational NDJSON log directory. On Windows and in dev/test profiles
    /// this is `data_dir/logs`; on the Linux production service it diverges to
    /// `/var/log/netrulerouter` (FHS: `/var/log` for logs, `/var/lib` for
    /// state). Audit NDJSON always stays under `data_dir/audit`, never here.
    /// Read this field instead of recomputing `data_dir.join("logs")` so the
    /// per-OS split stays a single source of truth.
    pub logs_dir: PathBuf,
    /// Rebuildable FQDN/IP cache database.
    pub cache_db_path: PathBuf,
    /// Service-critical state database (revision pointers, integrity metadata).
    pub state_db_path: PathBuf,
    /// Rebuildable per-adapter traffic-statistics database.
    pub traffic_db_path: PathBuf,
    /// General backup directory.
    pub backup_dir: PathBuf,
    /// Pre-migration backups go here so a failed migration can be rolled back.
    pub migration_backup_dir: PathBuf,
    /// Scratch space for atomic writes and temporary exports.
    pub temp_dir: PathBuf,
    /// Service singleton lock file (prevents two service instances from
    /// opening the same databases concurrently).
    pub lock_file_path: PathBuf,
}

/// Derives a [`StorageTopology`] from a [`StorageProfile`].
///
/// Returns `Err(StorageError::StorageUnavailable)` only when a required Windows
/// environment variable (`PROGRAMDATA` or `LOCALAPPDATA`) is absent —
/// a condition that cannot occur on a normally configured Windows system.
pub fn resolve_storage_topology(profile: &StorageProfile) -> StorageResult<StorageTopology> {
    let data_dir = match profile {
        StorageProfile::ProductionService => production_service_data_dir()?,
        StorageProfile::DevelopmentLocal => {
            let base = std::env::var("LOCALAPPDATA").map_err(|_| {
                StorageError::StorageUnavailable(
                    "LOCALAPPDATA environment variable is not set".into(),
                )
            })?;
            PathBuf::from(base)
                .join(nrr_platform_api::paths::product_dir_leaf())
                .join("dev")
        }
        StorageProfile::TestTemp(dir) => dir.clone(),
    };

    let backup_dir = data_dir.join("backups");

    Ok(StorageTopology {
        cache_db_path: data_dir.join("nrr_fqdn_ip_cache.db"),
        state_db_path: data_dir.join("nrr_service_state.db"),
        traffic_db_path: data_dir.join("nrr_traffic_stats.db"),
        migration_backup_dir: backup_dir.join("migrations"),
        temp_dir: data_dir.join("tmp"),
        lock_file_path: data_dir.join("nrr_service.lock"),
        logs_dir: production_logs_dir(profile, &data_dir),
        backup_dir,
        data_dir,
    })
}

/// Resolves the production-service root data directory. The OS shape and the
/// product leaf are declared once in `nrr_platform_api::paths`; this crate is a
/// consumer, not a second author.
fn production_service_data_dir() -> StorageResult<PathBuf> {
    nrr_platform_api::paths::production_data_root().ok_or_else(|| {
        StorageError::StorageUnavailable(
            "no production storage root for this platform (on Windows: PROGRAMDATA is not set)"
                .into(),
        )
    })
}

/// Resolves the operational log directory. Only the production service can
/// split logs away from the state directory (Linux does, per FHS); every other
/// profile keeps them under its own `data_dir`.
fn production_logs_dir(profile: &StorageProfile, data_dir: &std::path::Path) -> PathBuf {
    match profile {
        StorageProfile::ProductionService => {
            nrr_platform_api::paths::production_logs_dir().unwrap_or_else(|| data_dir.join("logs"))
        }
        _ => data_dir.join("logs"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_topology_uses_supplied_dir() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let topology =
            resolve_storage_topology(&StorageProfile::TestTemp(dir.path().to_path_buf()))
                .expect("resolve must succeed for TestTemp");

        assert_eq!(topology.data_dir, dir.path());
        assert_eq!(
            topology.cache_db_path,
            dir.path().join("nrr_fqdn_ip_cache.db")
        );
        assert_eq!(
            topology.state_db_path,
            dir.path().join("nrr_service_state.db")
        );
        assert_eq!(
            topology.traffic_db_path,
            dir.path().join("nrr_traffic_stats.db")
        );
        assert_eq!(topology.backup_dir, dir.path().join("backups"));
        assert_eq!(
            topology.migration_backup_dir,
            dir.path().join("backups").join("migrations")
        );
        assert_eq!(topology.temp_dir, dir.path().join("tmp"));
        assert_eq!(topology.lock_file_path, dir.path().join("nrr_service.lock"));
        // Non-production profiles keep logs under the data dir on every OS.
        assert_eq!(topology.logs_dir, dir.path().join("logs"));
    }

    #[test]
    fn production_service_topology_is_os_shaped() {
        // `resolve_storage_topology` is pure path computation (no I/O, no dir
        // creation), so it is safe to resolve the production profile in a unit
        // test. On Windows it needs PROGRAMDATA; on unix it is a fixed FHS
        // layout. Either way the operational logs split away from the state
        // dir exactly on the Linux production service.
        #[cfg(unix)]
        {
            let topology = resolve_storage_topology(&StorageProfile::ProductionService)
                .expect("unix production topology resolves without env vars");
            assert_eq!(topology.data_dir, PathBuf::from("/var/lib/netrulerouter"));
            assert_eq!(topology.logs_dir, PathBuf::from("/var/log/netrulerouter"));
            // Same roots the platform layer declares — the literals above are
            // the expectation, not a second derivation.
            assert_eq!(
                Some(topology.data_dir.clone()),
                nrr_platform_api::paths::production_data_root()
            );
            assert_eq!(
                Some(topology.logs_dir.clone()),
                nrr_platform_api::paths::production_logs_dir()
            );
            // Audit stays under the state dir (never in /var/log), so a
            // logrotate config scoped to /var/log can never touch it.
            assert!(topology.state_db_path.starts_with("/var/lib/netrulerouter"));
        }
        #[cfg(windows)]
        {
            // PROGRAMDATA is always set on a normally configured Windows host
            // (the CI/dev machines this test runs on). Logs stay nested under
            // the ProgramData data dir — no /var split on Windows.
            let topology = resolve_storage_topology(&StorageProfile::ProductionService)
                .expect("windows production topology resolves via PROGRAMDATA");
            assert_eq!(topology.logs_dir, topology.data_dir.join("logs"));
            // The root is the platform layer's, not a literal retyped here —
            // a product rename must reach this path through one edit.
            assert_eq!(
                Some(topology.data_dir.clone()),
                nrr_platform_api::paths::production_data_root()
            );
        }
    }

    #[test]
    fn test_temp_topology_is_deterministic() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().to_path_buf();
        let t1 = resolve_storage_topology(&StorageProfile::TestTemp(path.clone())).expect("first");
        let t2 = resolve_storage_topology(&StorageProfile::TestTemp(path)).expect("second");
        assert_eq!(t1, t2);
    }
}

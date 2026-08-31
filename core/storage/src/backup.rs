use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rusqlite::Connection;

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

/// How many backups of one database are kept. The newest survive; older ones
/// are deleted as each new backup lands, so an upgrade chain cannot fill the
/// disk with snapshots nobody will ever read.
pub const BACKUP_RETENTION_PER_DATABASE: usize = 5;

/// Snapshots a SQLite database into `backup_dir`.
///
/// The backup filename is:
/// `<db_stem>_<utc_ms>_<reason_tag>.db`
///
/// For example:
/// `nrr_service_state_1714000000000_premig_v1_v2.db`
///
/// Taken with `VACUUM INTO`, not by copying the file: the snapshot is made by
/// SQLite itself, so it carries everything committed to the write-ahead log and
/// can never catch a half-written page. Copying the `.db` alone silently
/// dropped every commit still living in the WAL — which is most of them, since
/// WAL is mandatory for these databases. The result is one self-contained file
/// (no `-wal`/`-shm` to carry along) and it is compacted on the way out.
///
/// Returns the path of the newly created backup file.
///
/// # Errors
///
/// Returns [`StorageError::Internal`] if `source` does not exist, is not a
/// readable SQLite database, the snapshot fails (I/O error, disk full), or the
/// source path has no usable file stem.
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
    let dest_sql = dest.to_str().ok_or_else(|| {
        StorageError::Internal(format!(
            "backup destination path is not valid UTF-8: {}",
            dest.display()
        ))
    })?;

    // A separate connection on purpose: the caller may already hold one on this
    // database, and WAL lets both coexist. Opened read-write because a database
    // whose WAL needs recovery cannot be read through a read-only handle.
    let conn = Connection::open(source).map_err(|e| {
        StorageError::Internal(format!("backup: cannot open {}: {e}", source.display()))
    })?;
    conn.execute("VACUUM INTO ?1", [dest_sql]).map_err(|e| {
        StorageError::Internal(format!(
            "failed to snapshot {} → {}: {e}",
            source.display(),
            dest.display()
        ))
    })?;

    prune_old_backups(backup_dir, stem);
    Ok(dest)
}

/// Keeps the newest [`BACKUP_RETENTION_PER_DATABASE`] snapshots of `stem` and
/// deletes the rest. Best-effort: a snapshot that cannot be removed is left
/// alone, because failing here would fail a backup that already succeeded.
fn prune_old_backups(backup_dir: &Path, stem: &str) {
    let Ok(entries) = std::fs::read_dir(backup_dir) else {
        return;
    };
    let prefix = format!("{stem}_");
    let mut ours: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("db")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
        })
        .collect();
    if ours.len() <= BACKUP_RETENTION_PER_DATABASE {
        return;
    }
    // The timestamp is in the name, so sorting by name sorts by age without
    // asking the filesystem for times it may not keep accurately.
    ours.sort();
    let doomed = ours.len() - BACKUP_RETENTION_PER_DATABASE;
    for path in ours.into_iter().take(doomed) {
        let _ = std::fs::remove_file(path);
    }
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

    /// A real database, because the snapshot goes through SQLite now: a file of
    /// plausible-looking bytes is not something `VACUUM INTO` can read, and a
    /// test that passed on one would be testing nothing.
    fn create_dummy_db(path: &Path) {
        let conn = Connection::open(path).expect("create db");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE probe (id INTEGER PRIMARY KEY, note TEXT NOT NULL);
             INSERT INTO probe (note) VALUES ('kept');",
        )
        .expect("seed db");
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
        // The snapshot is compacted, so it is NOT byte-identical to the source.
        // What must survive is the data, which is the only thing a restore
        // needs — asserting bytes here would only re-state that we copy files.
        let (_dir, topology) = setup();
        create_dummy_db(&topology.cache_db_path);

        let dest = backup_database(
            &topology.cache_db_path,
            &topology.backup_dir,
            &BackupReason::ManualExport,
        )
        .expect("backup");

        let restored = Connection::open(&dest).expect("open backup");
        let note: String = restored
            .query_row("SELECT note FROM probe", [], |r| r.get(0))
            .expect("read row from the backup");
        assert_eq!(note, "kept");
    }

    #[test]
    fn a_commit_living_only_in_the_wal_is_in_the_backup() {
        // The reason this stopped being a file copy: WAL is mandatory for these
        // databases, so a copy of the `.db` alone is a copy of the state BEFORE
        // most of the commits.
        let (_dir, topology) = setup();
        create_dummy_db(&topology.cache_db_path);
        let live = Connection::open(&topology.cache_db_path).expect("open source");
        live.execute("INSERT INTO probe (note) VALUES ('written-into-wal')", [])
            .expect("insert");

        let dest = backup_database(
            &topology.cache_db_path,
            &topology.backup_dir,
            &BackupReason::ManualExport,
        )
        .expect("backup");

        let restored = Connection::open(&dest).expect("open backup");
        let count: i64 = restored
            .query_row(
                "SELECT COUNT(*) FROM probe WHERE note = 'written-into-wal'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(count, 1, "a committed row must survive into the snapshot");
    }

    #[test]
    fn only_the_newest_backups_are_kept() {
        let (_dir, topology) = setup();
        create_dummy_db(&topology.cache_db_path);
        let mut made = Vec::new();
        for _ in 0..BACKUP_RETENTION_PER_DATABASE + 3 {
            // The name carries a millisecond stamp; sleep so two snapshots in
            // the same millisecond cannot collide into one file.
            std::thread::sleep(std::time::Duration::from_millis(2));
            made.push(
                backup_database(
                    &topology.cache_db_path,
                    &topology.backup_dir,
                    &BackupReason::ManualExport,
                )
                .expect("backup"),
            );
        }
        let left = std::fs::read_dir(&topology.backup_dir)
            .expect("read dir")
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("db"))
            .count();
        assert_eq!(left, BACKUP_RETENTION_PER_DATABASE);
        assert!(
            made.last().expect("last backup").exists(),
            "the newest snapshot must be one of the survivors",
        );
    }

    #[test]
    fn backup_policy_values_are_distinct() {
        assert_ne!(BackupPolicy::Required, BackupPolicy::Optional);
    }
}

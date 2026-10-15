//! The machine-wide list of home and local network suffixes.
//!
//! One list for every user of the machine, pre-filled by the schema and edited
//! by an administrator. The service leaves names under these suffixes to the
//! network's own resolver; the policy that decides what that means lives in
//! `nrr-shared`, this module only stores the words.

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Repository over `local_dns_suffixes`. Full-replacement semantics, like the
/// DoH resolver list.
pub struct LocalDnsSuffixesRepository<'a> {
    conn: &'a Connection,
}

impl<'a> LocalDnsSuffixesRepository<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Every stored suffix, sorted, for a stable list.
    pub fn load_all(&self) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT suffix FROM local_dns_suffixes ORDER BY suffix ASC")
            .map_err(|e| StorageError::Internal(format!("prepare local suffixes: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("query local suffixes: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("row local suffixes: {e}")))
    }

    /// Replace the whole list in one transaction. The caller has already
    /// normalised and validated every entry; duplicates collapse.
    pub fn replace_all(&self, suffixes: &[String], now_epoch_secs: i64) -> StorageResult<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("begin local suffixes tx: {e}")))?;
        tx.execute("DELETE FROM local_dns_suffixes", [])
            .map_err(|e| StorageError::Internal(format!("clear local suffixes: {e}")))?;
        for suffix in suffixes {
            tx.execute(
                "INSERT OR REPLACE INTO local_dns_suffixes (suffix, updated_at) VALUES (?1, ?2)",
                params![suffix, now_epoch_secs],
            )
            .map_err(|e| StorageError::Internal(format!("insert local suffix: {e}")))?;
        }
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("commit local suffixes tx: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;

    fn conn() -> Connection {
        let runner =
            SqliteMigrationRunner::for_state_db(Connection::open_in_memory().expect("in-memory"));
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    /// A fresh machine already knows the common home-network suffixes.
    #[test]
    fn the_list_is_pre_filled() {
        let conn = conn();
        let stored = LocalDnsSuffixesRepository::new(&conn)
            .load_all()
            .expect("load");
        assert_eq!(stored, ["fritz.box", "home.arpa", "lan", "local"]);
    }

    /// An administrator's list replaces the seed entirely: a removed default
    /// stays removed.
    #[test]
    fn replace_all_is_the_whole_list() {
        let conn = conn();
        let repo = LocalDnsSuffixesRepository::new(&conn);
        repo.replace_all(&["corp.example".into(), "lan".into(), "lan".into()], 7)
            .expect("replace");
        assert_eq!(repo.load_all().expect("load"), ["corp.example", "lan"]);
        repo.replace_all(&[], 8).expect("clear");
        assert!(repo.load_all().expect("load").is_empty());
    }
}

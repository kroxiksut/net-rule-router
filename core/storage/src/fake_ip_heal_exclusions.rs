//! `fake_ip_heal_exclusions` persistence.
//!
//! Hostnames the VPN self-heal excluded from fake-IP: a relayed flow was owned
//! by a VPN client, so the server hostname must resolve to its REAL address.
//! The live exclusion set is in-memory and empty on every service start, which
//! made a VPN's FIRST connect attempt of each session pay one failed round
//! through the relay before the exclusion was re-learned. Persisting the
//! learned hostnames lets boot pre-seed the set so the first attempt goes
//! direct.
//!
//! Additive like `vpn_bootstrap_endpoints`: rows are never deleted when a
//! server goes briefly unseen (re-learning refreshes `learned_at`); a bounded
//! cap evicts the oldest rows so a churny VPN cannot grow the set without
//! limit.

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained exclusions. Each row spares one hostname from
/// fake-IP, so the set must never grow unbounded — on overflow the OLDEST
/// rows (by `learned_at`) are evicted, keeping the live VPN's current server.
const MAX_EXCLUSIONS: usize = 64;

/// Repository over the `fake_ip_heal_exclusions` table (state DB).
pub struct FakeIpHealExclusionsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> FakeIpHealExclusionsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Upsert one learned `hostname`, stamping `now` (UTC Unix millis) as the
    /// learn time. Idempotent; re-learning refreshes `learned_at`. Evicts the
    /// oldest rows past [`MAX_EXCLUSIONS`].
    pub fn upsert(&self, hostname: &str, now: i64) -> StorageResult<()> {
        if hostname.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO fake_ip_heal_exclusions (hostname, learned_at)
                 VALUES (?1, ?2)
                 ON CONFLICT(hostname) DO UPDATE SET learned_at = excluded.learned_at",
                params![hostname, now],
            )
            .map_err(|e| StorageError::Internal(format!("fake_ip_heal_exclusions upsert: {e}")))?;
        self.conn
            .execute(
                "DELETE FROM fake_ip_heal_exclusions WHERE hostname IN (
                     SELECT hostname FROM fake_ip_heal_exclusions
                     ORDER BY learned_at DESC, hostname ASC
                     LIMIT -1 OFFSET ?1
                 )",
                params![MAX_EXCLUSIONS as i64],
            )
            .map_err(|e| StorageError::Internal(format!("fake_ip_heal_exclusions evict: {e}")))?;
        Ok(())
    }

    /// Load every persisted hostname, newest first.
    pub fn load(&self) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT hostname FROM fake_ip_heal_exclusions ORDER BY learned_at DESC, hostname ASC")
            .map_err(|e| StorageError::Internal(format!("fake_ip_heal_exclusions prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("fake_ip_heal_exclusions query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::Internal(format!("fake_ip_heal_exclusions row: {e}"))
            })?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;

    fn migrated_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn upsert_then_load_round_trips_newest_first() {
        let conn = migrated_conn();
        let repo = FakeIpHealExclusionsRepository::new(&conn);
        repo.upsert("vpn.example", 100).expect("insert");
        repo.upsert("gw.other.example", 200).expect("insert");
        assert_eq!(
            repo.load().expect("load"),
            vec!["gw.other.example".to_string(), "vpn.example".to_string()]
        );
        // Re-learning refreshes the timestamp instead of duplicating the row.
        repo.upsert("vpn.example", 300).expect("refresh");
        assert_eq!(
            repo.load().expect("load"),
            vec!["vpn.example".to_string(), "gw.other.example".to_string()]
        );
    }

    #[test]
    fn empty_hostname_is_a_no_op() {
        let conn = migrated_conn();
        let repo = FakeIpHealExclusionsRepository::new(&conn);
        repo.upsert("", 100).expect("no-op");
        assert!(repo.load().expect("load").is_empty());
    }

    #[test]
    fn overflow_evicts_the_oldest_rows() {
        let conn = migrated_conn();
        let repo = FakeIpHealExclusionsRepository::new(&conn);
        for i in 0..(MAX_EXCLUSIONS + 5) {
            repo.upsert(&format!("host{i}.example"), i as i64)
                .expect("insert");
        }
        let loaded = repo.load().expect("load");
        assert_eq!(loaded.len(), MAX_EXCLUSIONS, "cap holds");
        assert!(
            !loaded.contains(&"host0.example".to_string()),
            "oldest row evicted"
        );
        assert_eq!(
            loaded.first().map(String::as_str),
            Some(format!("host{}.example", MAX_EXCLUSIONS + 4).as_str()),
            "newest row survives"
        );
    }
}

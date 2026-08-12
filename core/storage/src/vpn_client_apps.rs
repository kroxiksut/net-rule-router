//! `vpn_client_apps` persistence.
//!
//! Executable paths of VPN client processes whose role was VERIFIED by a
//! kill-switch drop: the connection observer saw OUR kill-switch/fail-closed
//! Block drop a flow from a VPN-named process and role-verified the dropping
//! filter's spec id against the live Block-id registry. A verified client's
//! own traffic IS the tunnel's transport (server handshake, connectivity
//! checks against rotating provider IPs), so it earns a proactive app-scoped
//! exemption whenever a block-all posture arms — before the first drop of a
//! session — instead of one reactive per-IP exemption per rotated endpoint.
//!
//! Machine-wide (an exe path is not per-SID) and additive like
//! `vpn_bootstrap_endpoints`: re-learning refreshes `learned_at`; a bounded
//! cap evicts the oldest rows so a churny environment cannot grow the
//! exemption surface without limit. Paths are stored/compared
//! case-insensitively (`COLLATE NOCASE` primary key — Windows paths).

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained client apps. Each row punches a per-process hole in
/// the block-all posture, so the set must never grow unbounded — on overflow
/// the OLDEST rows (by `learned_at`) are evicted, keeping the live client. A
/// real machine runs one or two VPN clients; 16 is generous headroom.
const MAX_CLIENT_APPS: usize = 16;

/// Repository over the `vpn_client_apps` table (state DB).
pub struct VpnClientAppsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> VpnClientAppsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Upsert one learned client `exe_path`, stamping `now` (UTC Unix millis)
    /// as the learn time. Idempotent per path (case-insensitive); re-learning
    /// refreshes `learned_at`. Evicts the oldest rows past [`MAX_CLIENT_APPS`].
    /// An empty path is a no-op.
    pub fn upsert(&self, exe_path: &str, now: i64) -> StorageResult<()> {
        if exe_path.trim().is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO vpn_client_apps (exe_path, learned_at)
                 VALUES (?1, ?2)
                 ON CONFLICT(exe_path) DO UPDATE SET learned_at = excluded.learned_at",
                params![exe_path, now],
            )
            .map_err(|e| StorageError::Internal(format!("vpn_client_apps upsert: {e}")))?;
        self.conn
            .execute(
                "DELETE FROM vpn_client_apps WHERE exe_path IN (
                     SELECT exe_path FROM vpn_client_apps
                     ORDER BY learned_at DESC, exe_path ASC
                     LIMIT -1 OFFSET ?1
                 )",
                params![MAX_CLIENT_APPS as i64],
            )
            .map_err(|e| StorageError::Internal(format!("vpn_client_apps evict: {e}")))?;
        Ok(())
    }

    /// Load every persisted client exe path, newest first.
    pub fn load(&self) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT exe_path FROM vpn_client_apps ORDER BY learned_at DESC, exe_path ASC")
            .map_err(|e| StorageError::Internal(format!("vpn_client_apps prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("vpn_client_apps query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StorageError::Internal(format!("vpn_client_apps row: {e}")))?);
        }
        Ok(out)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
        let repo = VpnClientAppsRepository::new(&conn);
        repo.upsert(r"C:\Apps\openvpn.exe", 100).expect("insert");
        repo.upsert(r"C:\Apps\hidemy.name vpn 3.0.exe", 200)
            .expect("insert");
        assert_eq!(
            repo.load().expect("load"),
            vec![
                r"C:\Apps\hidemy.name vpn 3.0.exe".to_string(),
                r"C:\Apps\openvpn.exe".to_string()
            ]
        );
    }

    #[test]
    fn re_learning_refreshes_instead_of_duplicating_case_insensitively() {
        let conn = migrated_conn();
        let repo = VpnClientAppsRepository::new(&conn);
        repo.upsert(r"C:\Apps\OpenVPN.exe", 100).expect("insert");
        // Same path, different case — must collapse into the existing row.
        repo.upsert(r"c:\apps\openvpn.exe", 200).expect("refresh");
        let loaded = repo.load().expect("load");
        assert_eq!(loaded.len(), 1, "case-insensitive dedup");
        let learned_at: i64 = conn
            .query_row("SELECT learned_at FROM vpn_client_apps", [], |r| r.get(0))
            .expect("query");
        assert_eq!(learned_at, 200, "re-learning refreshes the learn time");
    }

    #[test]
    fn empty_path_is_a_no_op() {
        let conn = migrated_conn();
        let repo = VpnClientAppsRepository::new(&conn);
        repo.upsert("", 100).expect("no-op");
        repo.upsert("   ", 100).expect("no-op");
        assert!(repo.load().expect("load").is_empty());
    }

    #[test]
    fn overflow_evicts_the_oldest_rows() {
        let conn = migrated_conn();
        let repo = VpnClientAppsRepository::new(&conn);
        for i in 0..(MAX_CLIENT_APPS + 4) {
            repo.upsert(&format!(r"C:\Apps\client-{i}.exe"), i as i64)
                .expect("insert");
        }
        let loaded = repo.load().expect("load");
        assert_eq!(loaded.len(), MAX_CLIENT_APPS, "cap holds");
        assert!(
            !loaded.contains(&r"C:\Apps\client-0.exe".to_string()),
            "oldest row evicted"
        );
        assert_eq!(
            loaded.first().map(String::as_str),
            Some(format!(r"C:\Apps\client-{}.exe", MAX_CLIENT_APPS + 3).as_str()),
            "newest row survives"
        );
    }
}

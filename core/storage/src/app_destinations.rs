//! `app_observed_destinations` persistence.
//!
//! Destinations an application the rule book routes over the additional link has
//! actually been seen using. The routing layer can only put an application's
//! flow on that link through a host route, and a host route can only be derived
//! from an address something has already observed — so an in-memory-only
//! observation set means every session starts empty and the app's first contact
//! with each address is refused until the observation catches up. Keeping the
//! set across restarts lets the next session install those routes BEFORE the
//! first connection.
//!
//! Machine-wide, like the sibling `vpn_client_apps`: the route table it feeds is
//! machine-wide too, so a per-user split would promise an isolation the mechanism
//! cannot keep. Rows are written only for applications a rule names, so the table
//! can never describe an app the user never routed.
//!
//! Rows are additive and idempotent per `(app_key, ip)`; re-confirming an address
//! refreshes `learned_at`, which is what the reader's freshness window keys on.

use std::net::Ipv4Addr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Hard cap on retained destinations per application. Each row becomes a host
/// route (and, under the leak guard, a per-destination pin), so the set must
/// stay bounded — a busy application touches far more addresses than any of them
/// can enforce. On overflow the OLDEST rows (by `learned_at`) are evicted, so an
/// address still in use always survives.
///
/// 64 is deliberately the enforcement fan-out cap: persisting more than the
/// enforcement layer will ever act on buys nothing and would only crowd the
/// in-memory set that the live observer needs room in.
pub const MAX_DESTINATIONS_PER_APP: usize = 64;

/// Repository over the `app_observed_destinations` table (state DB).
pub struct AppDestinationsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AppDestinationsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Record `ips` as `app_key`'s currently-known destinations, stamping `now`
    /// (UTC Unix millis) as the confirmation time. Additive: an address missing
    /// from `ips` is NOT deleted — it simply keeps its older `learned_at` and
    /// ages out of the reader's freshness window on its own. Idempotent per
    /// `(app_key, ip)`. Evicts the oldest rows past
    /// [`MAX_DESTINATIONS_PER_APP`]. An empty key or empty address list is a
    /// no-op.
    pub fn upsert(&self, app_key: &str, ips: &[Ipv4Addr], now: i64) -> StorageResult<()> {
        if app_key.trim().is_empty() || ips.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations tx: {e}")))?;
        for ip in ips {
            tx.execute(
                "INSERT INTO app_observed_destinations (app_key, ip, learned_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(app_key, ip) DO UPDATE SET learned_at = excluded.learned_at",
                params![app_key, ip.to_string(), now],
            )
            .map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations insert: {e}"))
            })?;
        }
        tx.execute(
            "DELETE FROM app_observed_destinations
             WHERE app_key = ?1 AND ip NOT IN (
                 SELECT ip FROM app_observed_destinations
                 WHERE app_key = ?1
                 ORDER BY learned_at DESC, ip ASC
                 LIMIT ?2
             )",
            params![app_key, MAX_DESTINATIONS_PER_APP as i64],
        )
        .map_err(|e| StorageError::Internal(format!("app_observed_destinations evict: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations commit: {e}")))
    }

    /// Every `(app_key, ip)` pair confirmed at or after `confirmed_since` (UTC
    /// Unix millis), newest first. Rows older than the cutoff are left in place
    /// but withheld: the caller's freshness policy decides what may be enforced,
    /// while a later re-confirmation can still revive the row in one write.
    ///
    /// A row whose `ip` fails to parse is skipped rather than failing the whole
    /// load — a can't-happen guard against a hand-edited database (this module
    /// only ever writes `Ipv4Addr::to_string`).
    pub fn load_confirmed_since(
        &self,
        confirmed_since: i64,
    ) -> StorageResult<Vec<(String, Ipv4Addr)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT app_key, ip FROM app_observed_destinations
                 WHERE learned_at >= ?1
                 ORDER BY learned_at DESC, app_key ASC, ip ASC",
            )
            .map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations prepare: {e}"))
            })?;
        let rows = stmt
            .query_map(params![confirmed_since], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (key, raw) = row.map_err(|e| {
                StorageError::Internal(format!("app_observed_destinations row: {e}"))
            })?;
            if let Ok(ip) = raw.parse::<Ipv4Addr>() {
                out.push((key, ip));
            }
        }
        Ok(out)
    }

    /// Delete every row last confirmed before `cutoff` (UTC Unix millis).
    /// Called once on the read path's schedule so the table cannot accumulate
    /// destinations of applications whose rules were removed long ago.
    pub fn prune_before(&self, cutoff: i64) -> StorageResult<usize> {
        self.conn
            .execute(
                "DELETE FROM app_observed_destinations WHERE learned_at < ?1",
                params![cutoff],
            )
            .map_err(|e| StorageError::Internal(format!("app_observed_destinations prune: {e}")))
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

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, d)
    }

    #[test]
    fn upsert_then_load_round_trips() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("telegram.exe", &[ip(1), ip(2)], 1_000)
            .expect("upsert");
        let mut loaded = repo.load_confirmed_since(0).expect("load");
        loaded.sort();
        assert_eq!(
            loaded,
            vec![
                ("telegram.exe".to_string(), ip(1)),
                ("telegram.exe".to_string(), ip(2))
            ]
        );
    }

    #[test]
    fn re_confirming_refreshes_instead_of_duplicating() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("telegram.exe", &[ip(1)], 1_000).expect("first");
        repo.upsert("telegram.exe", &[ip(1)], 5_000)
            .expect("second");
        assert_eq!(repo.load_confirmed_since(0).expect("load").len(), 1);
        // The refreshed timestamp is what keeps a still-used address inside the
        // caller's freshness window across sessions.
        assert_eq!(repo.load_confirmed_since(4_999).expect("load").len(), 1);
    }

    #[test]
    fn app_key_matching_is_case_insensitive() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("Telegram.exe", &[ip(1)], 1_000).expect("first");
        repo.upsert("telegram.exe", &[ip(1)], 2_000)
            .expect("second");
        assert_eq!(
            repo.load_confirmed_since(0).expect("load").len(),
            1,
            "one row — Windows executable names are not case-sensitive"
        );
    }

    #[test]
    fn load_withholds_rows_outside_the_window() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("telegram.exe", &[ip(1)], 1_000).expect("stale");
        repo.upsert("telegram.exe", &[ip(2)], 9_000).expect("fresh");
        assert_eq!(
            repo.load_confirmed_since(5_000).expect("load"),
            vec![("telegram.exe".to_string(), ip(2))]
        );
        // Withheld, not deleted: a re-confirmation revives it in one write.
        repo.upsert("telegram.exe", &[ip(1)], 9_500).expect("again");
        assert_eq!(repo.load_confirmed_since(5_000).expect("load").len(), 2);
    }

    #[test]
    fn upsert_evicts_the_oldest_beyond_the_per_app_cap() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        let total = MAX_DESTINATIONS_PER_APP + 4;
        for i in 0..total {
            repo.upsert(
                "busy.exe",
                &[Ipv4Addr::new(198, 51, 100, i as u8)],
                1_000 + i as i64,
            )
            .expect("upsert");
        }
        let kept = repo.load_confirmed_since(0).expect("load");
        assert_eq!(kept.len(), MAX_DESTINATIONS_PER_APP);
        assert!(!kept.contains(&("busy.exe".to_string(), Ipv4Addr::new(198, 51, 100, 0))));
        assert!(kept.contains(&(
            "busy.exe".to_string(),
            Ipv4Addr::new(198, 51, 100, (total - 1) as u8)
        )));
    }

    #[test]
    fn caps_are_per_app_not_global() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("a.exe", &[ip(1)], 1_000).expect("a");
        repo.upsert("b.exe", &[ip(2)], 1_000).expect("b");
        assert_eq!(repo.load_confirmed_since(0).expect("load").len(), 2);
    }

    #[test]
    fn prune_drops_only_rows_older_than_the_cutoff() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("telegram.exe", &[ip(1)], 1_000).expect("old");
        repo.upsert("telegram.exe", &[ip(2)], 9_000).expect("new");
        assert_eq!(repo.prune_before(5_000).expect("prune"), 1);
        assert_eq!(
            repo.load_confirmed_since(0).expect("load"),
            vec![("telegram.exe".to_string(), ip(2))]
        );
    }

    #[test]
    fn empty_inputs_are_no_ops() {
        let conn = migrated_conn();
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("", &[ip(1)], 1_000).expect("empty key");
        repo.upsert("telegram.exe", &[], 1_000).expect("empty ips");
        assert!(repo.load_confirmed_since(0).expect("load").is_empty());
    }

    #[test]
    fn load_skips_unparseable_ip_rows() {
        let conn = migrated_conn();
        conn.execute(
            "INSERT INTO app_observed_destinations (app_key, ip, learned_at)
             VALUES ('telegram.exe', 'not-an-ip', 1000)",
            [],
        )
        .expect("inject bad row");
        let repo = AppDestinationsRepository::new(&conn);
        repo.upsert("telegram.exe", &[ip(1)], 2_000).expect("good");
        assert_eq!(
            repo.load_confirmed_since(0).expect("load"),
            vec![("telegram.exe".to_string(), ip(1))]
        );
    }
}

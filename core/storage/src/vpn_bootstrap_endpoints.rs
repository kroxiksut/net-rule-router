//! `vpn_bootstrap_endpoints` persistence.
//!
//! Observed (and, in Phase 2, manually-entered) VPN bootstrap server endpoints.
//! The catch-all kill-switch refuses to arm without at least one server exemption
//! — arming a block-everything filter with no hole for the tunnel's own server
//! would trap its reconnection. Today that server set is derived ONLY from live
//! route observation (`route_reconciler::bootstrap_server_ips`) and is lost on a
//! service restart, so a restart with the VPN still down leaves the exemption
//! empty and the kill-switch cannot re-arm.
//!
//! Persisting the observed IPs lets the exemption set survive a restart even
//! before the VPN reconnects.
//!
//! # Phase 1 vs Phase 2
//!
//! Phase 1 (this change) writes only `source = 'observed'` rows carrying `ip`;
//! `port`, `protocol` and `source = 'manual'` are schema headroom for Phase 2
//! (letting a user pin a corporate-VPN endpoint by hand). [`upsert_observed`] and
//! [`load_ips`] are the only Phase-1 surface.
//!
//! [`upsert_observed`]: VpnBootstrapEndpointsRepository::upsert_observed
//! [`load_ips`]: VpnBootstrapEndpointsRepository::load_ips

use std::net::Ipv4Addr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// The `source` column value for a route-observed endpoint (Phase 1).
const SOURCE_OBSERVED: &str = "observed";

/// Hard cap on retained endpoints, per source. The exemption set punches
/// holes in the fail-closed kill-switch, so
/// it must never grow without bound (a churny VPN, or — if reactive learning is
/// ever re-enabled — a hostile learner, could otherwise accumulate arbitrarily
/// many). On overflow the OLDEST endpoints (by `learned_at`) are evicted, so a
/// live VPN's current server always survives while stale ones age out. 32 is
/// ample for any real multi-server VPN while keeping the WFP exemption set tiny.
const MAX_ENDPOINTS_PER_SOURCE: usize = 32;

/// Repository over the `vpn_bootstrap_endpoints` table (state DB).
pub struct VpnBootstrapEndpointsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> VpnBootstrapEndpointsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Upsert each observed server `ip` (source `'observed'`, no port/protocol),
    /// stamping `now` (UTC Unix millis) as the learn time. Additive: an IP that is
    /// no longer observed is intentionally NOT deleted — a briefly-unobserved
    /// server (VPN blip) should keep its exemption so the tunnel can reconnect.
    /// Idempotent per `(ip, 'observed')`; re-observing refreshes `learned_at`.
    pub fn upsert_observed(&self, ips: &[Ipv4Addr], now: i64) -> StorageResult<()> {
        if ips.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints tx: {e}")))?;
        for ip in ips {
            tx.execute(
                "INSERT INTO vpn_bootstrap_endpoints
                 (ip, port, protocol, source, learned_at)
                 VALUES (?1, NULL, NULL, ?2, ?3)
                 ON CONFLICT(ip, source) DO UPDATE SET learned_at = excluded.learned_at",
                params![ip.to_string(), SOURCE_OBSERVED, now],
            )
            .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints insert: {e}")))?;
        }
        // Evict the oldest rows beyond the per-source cap so the exemption
        // set can never grow unbounded. Keeps the newest
        // `MAX_ENDPOINTS_PER_SOURCE` by `learned_at` (ties broken by `ip` for a
        // deterministic result); a re-observed live server refreshes its
        // `learned_at` above, so it is always among the kept newest.
        tx.execute(
            "DELETE FROM vpn_bootstrap_endpoints
             WHERE source = ?1 AND ip NOT IN (
                 SELECT ip FROM vpn_bootstrap_endpoints
                 WHERE source = ?1
                 ORDER BY learned_at DESC, ip ASC
                 LIMIT ?2
             )",
            params![SOURCE_OBSERVED, MAX_ENDPOINTS_PER_SOURCE as i64],
        )
        .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints prune: {e}")))?;
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints commit: {e}")))?;
        Ok(())
    }

    /// Load every persisted endpoint IP (all sources), newest first. A row whose
    /// `ip` fails to parse as an IPv4 address is skipped rather than failing the
    /// whole load — defence-in-depth against a hand-corrupted row (Phase 1 only
    /// ever writes `ip.to_string()`, so this is a can't-happen guard). `nrr-storage`
    /// carries no logging framework by design, so the skip is silent; the caller
    /// (the route coordinator) is the layer that logs observability for the set.
    pub fn load_ips(&self) -> StorageResult<Vec<Ipv4Addr>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ip FROM vpn_bootstrap_endpoints ORDER BY learned_at DESC, ip ASC")
            .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let raw = row
                .map_err(|e| StorageError::Internal(format!("vpn_bootstrap_endpoints row: {e}")))?;
            // Skip an unparseable IP (can't-happen defence) — see doc comment.
            if let Ok(ip) = raw.parse::<Ipv4Addr>() {
                out.push(ip);
            }
        }
        Ok(out)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn open_state_db(dir: &tempfile::TempDir) -> Connection {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn upsert_then_load_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        repo.upsert_observed(
            &[
                Ipv4Addr::new(203, 0, 113, 5),
                Ipv4Addr::new(198, 51, 100, 9),
            ],
            100,
        )
        .expect("upsert");
        let mut ips = repo.load_ips().expect("load");
        ips.sort();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(198, 51, 100, 9),
                Ipv4Addr::new(203, 0, 113, 5)
            ]
        );
    }

    #[test]
    fn load_empty_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        assert!(repo.load_ips().expect("load").is_empty());
    }

    #[test]
    fn upsert_empty_is_noop() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        repo.upsert_observed(&[], 100).expect("noop upsert");
        assert!(repo.load_ips().expect("load").is_empty());
    }

    #[test]
    fn re_observing_is_idempotent_and_refreshes_learned_at() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        repo.upsert_observed(&[ip], 100).expect("first");
        repo.upsert_observed(&[ip], 200).expect("second");
        // Still a single row (PRIMARY KEY(ip, source) dedup).
        assert_eq!(repo.load_ips().expect("load"), vec![ip]);
        let learned_at: i64 = conn
            .query_row(
                "SELECT learned_at FROM vpn_bootstrap_endpoints WHERE ip = ?1",
                params![ip.to_string()],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(learned_at, 200, "re-observe refreshes the learn time");
    }

    #[test]
    fn load_skips_unparseable_ip_rows() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        // Inject a malformed row directly (a corrupt/hand-edited DB).
        conn.execute(
            "INSERT INTO vpn_bootstrap_endpoints (ip, port, protocol, source, learned_at)
             VALUES ('not-an-ip', NULL, NULL, 'observed', 50)",
            [],
        )
        .expect("inject bad row");
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        repo.upsert_observed(&[Ipv4Addr::new(203, 0, 113, 5)], 100)
            .expect("upsert good");
        // The bad row is skipped, the good one survives.
        assert_eq!(
            repo.load_ips().expect("load"),
            vec![Ipv4Addr::new(203, 0, 113, 5)]
        );
    }

    #[test]
    fn upsert_evicts_oldest_beyond_the_cap() {
        // The retained set is bounded; the oldest endpoints age out, the
        // freshest (incl. a re-observed live server) survive.
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        // Insert MAX+8 distinct IPs, each with a strictly increasing learn time
        // so eviction order is unambiguous.
        let total = MAX_ENDPOINTS_PER_SOURCE + 8;
        for i in 0..total {
            let ip = Ipv4Addr::new(203, 0, 113, i as u8);
            repo.upsert_observed(&[ip], 1_000 + i as i64)
                .expect("upsert");
        }
        let kept = repo.load_ips().expect("load");
        assert_eq!(
            kept.len(),
            MAX_ENDPOINTS_PER_SOURCE,
            "retained set is capped"
        );
        // The 8 oldest (i = 0..8) must be gone; the newest must remain.
        assert!(!kept.contains(&Ipv4Addr::new(203, 0, 113, 0)));
        assert!(!kept.contains(&Ipv4Addr::new(203, 0, 113, 7)));
        assert!(kept.contains(&Ipv4Addr::new(203, 0, 113, (total - 1) as u8)));
    }

    #[test]
    fn manual_and_observed_coexist_for_same_ip() {
        // Phase-2 headroom check: the (ip, source) PK allows an 'observed' and a
        // 'manual' row for the same IP. Insert the manual row directly (Phase 1 has
        // no manual writer) and confirm both load.
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let repo = VpnBootstrapEndpointsRepository::new(&conn);
        repo.upsert_observed(&[ip], 100).expect("observed");
        conn.execute(
            "INSERT INTO vpn_bootstrap_endpoints (ip, port, protocol, source, learned_at)
             VALUES (?1, 1194, 'udp', 'manual', 200)",
            params![ip.to_string()],
        )
        .expect("manual insert");
        assert_eq!(repo.load_ips().expect("load"), vec![ip, ip]);
    }
}

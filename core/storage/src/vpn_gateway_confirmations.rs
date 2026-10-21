//! `vpn_gateway_confirmations` persistence.
//!
//! The gateways of another VPN a user let through leak protection, one row
//! per (user, address). Replaced whole per user, so a revoked gateway leaves
//! with the write that dropped it. Bounded: every row is a hole in the block.

use std::net::IpAddr;

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Rows one user may hold; the IPC layer refuses a longer list first.
pub const MAX_GATEWAYS_PER_SID: usize = 8;

/// One stored gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnGatewayConfirmation {
    pub address: IpAddr,
    /// The program seen connecting; empty for the system itself.
    pub program: String,
}

/// Repository over the `vpn_gateway_confirmations` table (state DB).
pub struct VpnGatewayConfirmationsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> VpnGatewayConfirmationsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Replace `sid`'s gateways with `gateways` (first [`MAX_GATEWAYS_PER_SID`],
    /// one row per address), stamping `now`.
    pub fn replace_for_sid(
        &self,
        sid: &str,
        gateways: &[VpnGatewayConfirmation],
        now: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal(
                "vpn_gateway_confirmations: empty sid".into(),
            ));
        }
        let failed = |what: &str, e: rusqlite::Error| {
            StorageError::Internal(format!("vpn_gateway_confirmations {what}: {e}"))
        };
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| failed("tx", e))?;
        tx.execute(
            "DELETE FROM vpn_gateway_confirmations WHERE sid = ?1",
            params![sid],
        )
        .map_err(|e| failed("clear", e))?;
        for gateway in gateways.iter().take(MAX_GATEWAYS_PER_SID) {
            tx.execute(
                "INSERT INTO vpn_gateway_confirmations (sid, address, program, confirmed_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(sid, address) DO UPDATE SET program = excluded.program",
                params![sid, gateway.address.to_string(), gateway.program, now],
            )
            .map_err(|e| failed("insert", e))?;
        }
        tx.commit().map_err(|e| failed("commit", e))
    }

    /// `sid`'s gateways, oldest first. A row whose address does not parse is
    /// skipped: this writer only stores parsed addresses.
    pub fn load_for_sid(&self, sid: &str) -> StorageResult<Vec<VpnGatewayConfirmation>> {
        let failed =
            |e: rusqlite::Error| StorageError::Internal(format!("vpn_gateway_confirmations: {e}"));
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, program FROM vpn_gateway_confirmations WHERE sid = ?1
                 ORDER BY confirmed_at ASC, address ASC LIMIT ?2",
            )
            .map_err(failed)?;
        let rows = stmt
            .query_map(params![sid, MAX_GATEWAYS_PER_SID as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(failed)?;
        let mut out = Vec::new();
        for row in rows {
            let (address, program) = row.map_err(failed)?;
            if let Ok(address) = address.parse::<IpAddr>() {
                out.push(VpnGatewayConfirmation { address, program });
            }
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

    fn gateway(text: &str, program: &str) -> VpnGatewayConfirmation {
        VpnGatewayConfirmation {
            address: text.parse().expect("address"),
            program: program.to_string(),
        }
    }

    #[test]
    fn a_replace_is_whole_and_per_user() {
        let conn = migrated_conn();
        let repo = VpnGatewayConfirmationsRepository::new(&conn);
        repo.replace_for_sid(
            "S-A",
            &[
                gateway("203.0.113.20", ""),
                gateway("2001:db8::7", "corp.exe"),
            ],
            1,
        )
        .expect("write a");
        repo.replace_for_sid("S-B", &[gateway("198.51.100.4", "")], 1)
            .expect("write b");
        assert_eq!(repo.load_for_sid("S-A").expect("load").len(), 2);

        repo.replace_for_sid("S-A", &[gateway("2001:db8::7", "corp.exe")], 2)
            .expect("revoke one");
        assert_eq!(
            repo.load_for_sid("S-A").expect("load"),
            vec![gateway("2001:db8::7", "corp.exe")]
        );
        assert_eq!(
            repo.load_for_sid("S-B").expect("load"),
            vec![gateway("198.51.100.4", "")],
            "another user's answer is untouched"
        );

        repo.replace_for_sid("S-A", &[], 3).expect("clear");
        assert!(repo.load_for_sid("S-A").expect("load").is_empty());
    }

    #[test]
    fn the_set_is_bounded_and_needs_an_owner() {
        let conn = migrated_conn();
        let repo = VpnGatewayConfirmationsRepository::new(&conn);
        let many: Vec<VpnGatewayConfirmation> = (0..MAX_GATEWAYS_PER_SID + 4)
            .map(|i| gateway(&format!("203.0.113.{}", i + 1), ""))
            .collect();
        repo.replace_for_sid("S-A", &many, 1).expect("write");
        assert_eq!(
            repo.load_for_sid("S-A").expect("load").len(),
            MAX_GATEWAYS_PER_SID
        );
        assert!(repo.replace_for_sid("", &many, 1).is_err());
    }
}

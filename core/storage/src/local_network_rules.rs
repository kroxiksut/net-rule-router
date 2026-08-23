//! Per-principal exceptions for LOCAL networks under the kill-switch.
//!
//! The service already exempts what it can recognise on its own: the main
//! link's own subnets and the host-side segments of hypervisor adapters. This
//! table holds only the DIFFERENCES from that answer, and there are exactly
//! two:
//!
//! - a discovered segment the user does not want exempted (`allow = false`);
//! - a network the service cannot discover at all, named by the user
//!   (`allow = true`, `origin = Manual`) — a hypervisor in NAT mode creates no
//!   host interface, so nothing in the route table names its network.
//!
//! Storing only the differences is what keeps a laptop whose virtual networks
//! come and go from accumulating rows for segments it already handles right.

use rusqlite::{params, Connection};

use crate::{StorageError, StorageResult};

/// Where a rule came from. A `Discovered` row only ever exists to record a
/// refusal; the accepted case is the default and stores nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalNetworkOrigin {
    Discovered,
    Manual,
}

impl LocalNetworkOrigin {
    fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Manual => "manual",
        }
    }

    fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "discovered" => Some(Self::Discovered),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// One stored decision about a local network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNetworkRule {
    /// Network in `a.b.c.d/len` form, exactly as it will be matched.
    pub cidr: String,
    pub allow: bool,
    pub origin: LocalNetworkOrigin,
}

pub struct LocalNetworkRulesRepository<'a> {
    conn: &'a Connection,
}

impl<'a> LocalNetworkRulesRepository<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Every stored decision for `sid`, ordered by network so a listing is
    /// stable between calls.
    pub fn list_for_sid(&self, sid: &str) -> StorageResult<Vec<LocalNetworkRule>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT cidr, allow, origin FROM local_network_rules
                 WHERE sid = ?1 ORDER BY cidr",
            )
            .map_err(|e| StorageError::Internal(format!("local networks prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("local networks query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (cidr, allow, origin) =
                row.map_err(|e| StorageError::Internal(format!("local networks row: {e}")))?;
            // An origin this build does not know is a row from a newer schema:
            // drop it rather than guess what it meant.
            if let Some(origin) = LocalNetworkOrigin::from_str(&origin) {
                out.push(LocalNetworkRule {
                    cidr,
                    allow,
                    origin,
                });
            }
        }
        Ok(out)
    }

    /// Record one decision, replacing whatever this principal said about the
    /// same network before.
    pub fn upsert(
        &self,
        sid: &str,
        rule: &LocalNetworkRule,
        now_epoch_secs: i64,
    ) -> StorageResult<()> {
        self.conn
            .execute(
                "INSERT INTO local_network_rules (sid, cidr, allow, origin, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid, cidr) DO UPDATE SET
                     allow = excluded.allow,
                     origin = excluded.origin,
                     updated_at = excluded.updated_at",
                params![
                    sid,
                    rule.cidr,
                    rule.allow as i64,
                    rule.origin.as_str(),
                    now_epoch_secs
                ],
            )
            .map(|_| ())
            .map_err(|e| StorageError::Internal(format!("local networks upsert: {e}")))
    }

    /// Forget one decision — the network goes back to whatever the automatic
    /// answer says about it.
    pub fn remove(&self, sid: &str, cidr: &str) -> StorageResult<bool> {
        self.conn
            .execute(
                "DELETE FROM local_network_rules WHERE sid = ?1 AND cidr = ?2",
                params![sid, cidr],
            )
            .map(|n| n > 0)
            .map_err(|e| StorageError::Internal(format!("local networks delete: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;

    fn conn() -> Connection {
        let runner = SqliteMigrationRunner::for_state_db(
            Connection::open_in_memory().expect("in-memory db"),
        );
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    fn manual(cidr: &str) -> LocalNetworkRule {
        LocalNetworkRule {
            cidr: cidr.into(),
            allow: true,
            origin: LocalNetworkOrigin::Manual,
        }
    }

    #[test]
    fn a_decision_round_trips_and_is_scoped_to_its_principal() {
        let c = conn();
        let repo = LocalNetworkRulesRepository::new(&c);
        repo.upsert("S-A", &manual("10.0.2.0/24"), 1).expect("save");
        assert_eq!(
            repo.list_for_sid("S-A").expect("read"),
            vec![manual("10.0.2.0/24")]
        );
        assert!(repo.list_for_sid("S-B").expect("read").is_empty());
    }

    #[test]
    fn saying_it_again_replaces_rather_than_duplicates() {
        let c = conn();
        let repo = LocalNetworkRulesRepository::new(&c);
        repo.upsert("S", &manual("192.168.56.0/24"), 1)
            .expect("save");
        repo.upsert(
            "S",
            &LocalNetworkRule {
                cidr: "192.168.56.0/24".into(),
                allow: false,
                origin: LocalNetworkOrigin::Discovered,
            },
            2,
        )
        .expect("save again");
        let stored = repo.list_for_sid("S").expect("read");
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].allow, "the later answer wins");
        assert_eq!(stored[0].origin, LocalNetworkOrigin::Discovered);
    }

    #[test]
    fn removing_a_decision_returns_to_the_automatic_answer() {
        let c = conn();
        let repo = LocalNetworkRulesRepository::new(&c);
        repo.upsert("S", &manual("172.20.0.0/16"), 1).expect("save");
        assert!(repo.remove("S", "172.20.0.0/16").expect("remove"));
        assert!(!repo.remove("S", "172.20.0.0/16").expect("remove again"));
        assert!(repo.list_for_sid("S").expect("read").is_empty());
    }
}

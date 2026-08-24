//! Per-principal answers about LOCAL networks under the kill-switch.
//!
//! The service already exempts what it can recognise on its own: the main
//! link's own subnets and the host-side segments of hypervisor adapters. A row
//! here is the user's ANSWER about one of those, or about a network no
//! interface names at all (a hypervisor in NAT mode creates none) — which is
//! why a plain confirmation is stored too: without it the offer would come back
//! every time.
//!
//! Each row carries the ADAPTER it was decided about. A hypervisor switch
//! renumbers its segment on every host reboot, and an answer keyed by the
//! network alone dies with the number — the same question every day, one dead
//! row per day. Keyed by adapter it survives the renumbering.

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
    /// Adapter the network belonged to when the answer was given. Empty for a
    /// network the user typed in, since nothing on the machine names one.
    pub adapter: String,
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
                "SELECT cidr, allow, origin, adapter FROM local_network_rules
                 WHERE sid = ?1 ORDER BY cidr",
            )
            .map_err(|e| StorageError::Internal(format!("local networks prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("local networks query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            let (cidr, allow, origin, adapter) =
                row.map_err(|e| StorageError::Internal(format!("local networks row: {e}")))?;
            // An origin this build does not know is a row from a newer schema:
            // drop it rather than guess what it meant.
            if let Some(origin) = LocalNetworkOrigin::from_str(&origin) {
                out.push(LocalNetworkRule {
                    cidr,
                    allow,
                    origin,
                    adapter,
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
                "INSERT INTO local_network_rules
                     (sid, cidr, allow, origin, updated_at, adapter)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sid, cidr) DO UPDATE SET
                     allow = excluded.allow,
                     origin = excluded.origin,
                     updated_at = excluded.updated_at,
                     adapter = excluded.adapter",
                params![
                    sid,
                    rule.cidr,
                    rule.allow as i64,
                    rule.origin.as_str(),
                    now_epoch_secs,
                    rule.adapter
                ],
            )
            .map(|_| ())
            .map_err(|e| StorageError::Internal(format!("local networks upsert: {e}")))
    }

    /// Drop the confirmations this adapter has outgrown: same adapter, same
    /// "yes", a network number it no longer carries. `keep_cidr` is the answer
    /// just given, the one that inherits from here on. Refusals are never
    /// touched — forgetting one reopens a segment the user closed.
    pub fn forget_superseded_confirmations(
        &self,
        sid: &str,
        adapter: &str,
        keep_cidr: &str,
    ) -> StorageResult<usize> {
        if adapter.is_empty() {
            return Ok(0);
        }
        self.conn
            .execute(
                "DELETE FROM local_network_rules
                 WHERE sid = ?1 AND adapter = ?2 AND cidr <> ?3
                   AND origin = 'discovered' AND allow = 1",
                params![sid, adapter, keep_cidr],
            )
            .map_err(|e| StorageError::Internal(format!("local networks prune: {e}")))
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
            adapter: String::new(),
        }
    }

    fn discovered(cidr: &str, adapter: &str, allow: bool) -> LocalNetworkRule {
        LocalNetworkRule {
            cidr: cidr.into(),
            allow,
            origin: LocalNetworkOrigin::Discovered,
            adapter: adapter.into(),
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
        repo.upsert("S", &discovered("192.168.56.0/24", "vEthernet", false), 2)
            .expect("save again");
        let stored = repo.list_for_sid("S").expect("read");
        assert_eq!(stored.len(), 1);
        assert!(!stored[0].allow, "the later answer wins");
        assert_eq!(stored[0].origin, LocalNetworkOrigin::Discovered);
    }

    #[test]
    fn a_renumbered_switch_leaves_one_row_not_one_per_reboot() {
        let c = conn();
        let repo = LocalNetworkRulesRepository::new(&c);
        let switch = "Ethernet (Default Switch)";
        repo.upsert("S", &discovered("172.23.208.0/20", switch, true), 1)
            .expect("yesterday");
        repo.upsert("S", &discovered("172.28.176.0/20", switch, true), 2)
            .expect("today");
        // A refusal on another adapter must survive the prune.
        repo.upsert("S", &discovered("192.168.56.0/24", "VirtualBox", false), 2)
            .expect("refusal");
        let pruned = repo
            .forget_superseded_confirmations("S", switch, "172.28.176.0/20")
            .expect("prune");
        assert_eq!(pruned, 1);
        let stored = repo.list_for_sid("S").expect("read");
        assert_eq!(stored.len(), 2);
        assert!(stored.iter().any(|r| r.cidr == "172.28.176.0/20"));
        assert!(stored
            .iter()
            .any(|r| r.cidr == "192.168.56.0/24" && !r.allow));
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

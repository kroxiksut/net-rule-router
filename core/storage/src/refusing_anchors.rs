//! Sites the user says answer the MAIN link with a refusal.
//!
//! The one fact about a routed site that no measurement in this product can
//! establish. A connection that completes proves the packet arrives; whether
//! the service on the far end then serves us or answers "this address is not
//! served" is inside the response body, and reading response bodies is not
//! something a router does. So the user tells us, once per site, and the
//! consequence is deliberately narrow — see the gate in
//! `nrr_service_runtime::auto_rules`.

use rusqlite::{params, Connection};

use crate::{StorageError, StorageResult};

pub struct RefusingAnchorsRepository<'a> {
    conn: &'a Connection,
}

impl<'a> RefusingAnchorsRepository<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Every site `sid` has marked, ordered by hostname so a listing is stable.
    pub fn list_for_sid(&self, sid: &str) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT hostname FROM refusing_anchors WHERE sid = ?1 ORDER BY hostname")
            .map_err(|e| StorageError::Internal(format!("refusing anchors prepare: {e}")))?;
        let rows = stmt
            .query_map(params![sid], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("refusing anchors query: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("refusing anchors row: {e}")))
    }

    /// Mark or unmark one site. Hostnames are stored canonically (lower-case, no
    /// trailing dot) so the mark matches however the user typed it.
    pub fn set(
        &self,
        sid: &str,
        hostname: &str,
        refusing: bool,
        now_epoch_secs: i64,
    ) -> StorageResult<bool> {
        let host = canonical_host(hostname);
        if host.is_empty() {
            return Ok(false);
        }
        if refusing {
            self.conn
                .execute(
                    "INSERT INTO refusing_anchors (sid, hostname, marked_at)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(sid, hostname) DO UPDATE SET marked_at = excluded.marked_at",
                    params![sid, host, now_epoch_secs],
                )
                .map(|_| true)
                .map_err(|e| StorageError::Internal(format!("refusing anchors upsert: {e}")))
        } else {
            self.conn
                .execute(
                    "DELETE FROM refusing_anchors WHERE sid = ?1 AND hostname = ?2",
                    params![sid, host],
                )
                .map(|n| n > 0)
                .map_err(|e| StorageError::Internal(format!("refusing anchors delete: {e}")))
        }
    }
}

/// Lower-case, no trailing dot — the spelling every hostname comparison in the
/// product uses.
fn canonical_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
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

    #[test]
    fn a_mark_round_trips_per_principal_and_however_it_was_typed() {
        let c = conn();
        let repo = RefusingAnchorsRepository::new(&c);
        assert!(repo.set("S-A", "ChatGPT.com.", true, 1).expect("mark"));
        assert_eq!(
            repo.list_for_sid("S-A").expect("read"),
            vec!["chatgpt.com".to_string()]
        );
        assert!(repo.list_for_sid("S-B").expect("read").is_empty());
        // Marking again is a harmless rewrite, not a duplicate.
        assert!(repo.set("S-A", "chatgpt.com", true, 2).expect("mark"));
        assert_eq!(repo.list_for_sid("S-A").expect("read").len(), 1);
    }

    #[test]
    fn unmarking_removes_it_and_says_whether_there_was_anything_to_remove() {
        let c = conn();
        let repo = RefusingAnchorsRepository::new(&c);
        repo.set("S", "reddit.com", true, 1).expect("mark");
        assert!(repo.set("S", "REDDIT.com", false, 2).expect("unmark"));
        assert!(!repo.set("S", "reddit.com", false, 3).expect("unmark again"));
        assert!(repo.list_for_sid("S").expect("read").is_empty());
    }

    #[test]
    fn an_empty_hostname_is_refused_rather_than_stored() {
        let c = conn();
        let repo = RefusingAnchorsRepository::new(&c);
        assert!(!repo.set("S", "   ", true, 1).expect("blank"));
        assert!(repo.list_for_sid("S").expect("read").is_empty());
    }
}

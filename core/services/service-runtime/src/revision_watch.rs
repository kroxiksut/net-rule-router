//! Catches a rules revision edited in the state database while the service
//! runs. The boot sweep only sees what was there at start; without this a row
//! changed afterwards is served until the next restart.
//!
//! Off the traffic path: a periodic task polls `PRAGMA data_version`, which
//! moves only when another connection commits, and only then rechecks the
//! active rows.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::SecurityAlertsRepository;
use nrr_platform_api::key_store::KeyStore;
use rusqlite::Connection;

use crate::activation_coordinator::ActivationCoordinator;
use crate::boot_integrity::{AuditTrail, BootIntegrity};
use crate::health::HealthAggregator;

/// Whether the database was committed to by another connection since the
/// last look. The first look only records where it stands: the boot sweep
/// has just checked that state.
pub struct OutsideWrites {
    conn: Arc<Mutex<Connection>>,
    seen: Option<i64>,
}

impl OutsideWrites {
    #[must_use]
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn, seen: None }
    }

    /// `Err` when the version cannot be read; the last one seen is kept.
    pub fn changed(&mut self) -> Result<bool, rusqlite::Error> {
        let version: i64 = {
            let conn = self
                .conn
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            conn.query_row("PRAGMA data_version", [], |row| row.get(0))?
        };
        Ok(self
            .seen
            .replace(version)
            .is_some_and(|seen| seen != version))
    }
}

/// Everything a recheck reports through, owned so the task can hold it.
pub struct RevisionWatch {
    pub writes: OutsideWrites,
    pub coordinator: Arc<ActivationCoordinator>,
    pub key_store: Arc<dyn KeyStore>,
    pub signing_key: Vec<u8>,
    pub alerts: Arc<dyn SecurityAlertsRepository>,
    pub audit: Option<Arc<AuditTrail>>,
    pub health: Arc<HealthAggregator>,
}

impl RevisionWatch {
    /// One poll. Rechecks only after an outside write, and not while a key
    /// reset is unacknowledged: every row then fails against the new key.
    pub fn tick(&mut self, now_ms: i64) {
        match self.writes.changed() {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::tamper",
                    error = %e,
                    "could not read the state database version; revisions not rechecked",
                );
                return;
            }
        }
        if crate::tamper_bootstrap::resign_pending(self.key_store.as_ref(), &self.signing_key) {
            return;
        }
        let report = BootIntegrity {
            alerts: &self.alerts,
            audit: self.audit.as_deref(),
            health: self.health.as_ref(),
            now_ms,
        };
        // Alerts after the sweep, as at boot: a rollback rewrites the row.
        match self
            .coordinator
            .recheck_active_integrity("svc-live-integrity-scan")
        {
            Ok(outcomes) => {
                report.report_sweep(&outcomes);
                report.raise_after_recheck(&self.coordinator, Some(&outcomes));
            }
            Err(e) => {
                report.report_sweep_failure(&e.to_string());
                report.raise_after_recheck(&self.coordinator, None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::open_connection;

    #[test]
    fn only_a_commit_from_another_connection_counts_as_an_outside_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nrr_service_state.db");
        let own = Arc::new(Mutex::new(open_connection(&path).expect("own")));
        own.lock()
            .expect("own")
            .execute_batch("CREATE TABLE t (v INTEGER);")
            .expect("table");
        let mut writes = OutsideWrites::new(Arc::clone(&own));

        assert!(
            !writes.changed().expect("first look"),
            "first look only records"
        );
        own.lock()
            .expect("own")
            .execute("INSERT INTO t VALUES (1)", [])
            .expect("own write");
        assert!(!writes.changed().expect("after own write"));

        let other = open_connection(&path).expect("other");
        other
            .execute("INSERT INTO t VALUES (2)", [])
            .expect("outside write");
        assert!(writes.changed().expect("after outside write"));
        assert!(!writes.changed().expect("nothing since"));
    }
}

//! production [`SecurityAlertsRepository`] backed by the
//! `security_alerts` table in `nrr_service_state.db` (schema v3, defined
//! in block 13.3).
//!
//! Replaces `core/application/src/alert_store.rs` (the file-backed JSON
//! store) for the service-owned write path. The legacy module is
//! deleted in this sub-block — there are no remaining production
//! callers, only the local `mod tests` exercises and a doc reference
//! in `core/domain/src/block8_outputs.rs`.
//!
//! ## Lifecycle invariants
//!
//! - `insert` writes a fresh row with `state = 'active'` and the
//!   genesis raise-event coordinates (`raised_event_seq` /
//!   `raised_file`). `created_at` and `updated_at` are seeded
//!   identically.
//! - `update_state` writes the new state plus the ack/resolve
//!   coordinates. The schema does not enforce monotonic state
//!   transitions (Active → Acknowledged → Resolved); the executor
//!   layer is responsible for refusing illegal transitions before
//!   reaching the repo.
//! - `list_by_state` returns ascending `created_at` (oldest first) so
//!   the GUI can paint a timeline; `list_open` returns descending
//!   `created_at` (newest first) for the badge / banner pane.

use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::error::{DiagnosticsError, DiagnosticsResult};

pub struct ProductionSecurityAlertsRepository {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionSecurityAlertsRepository {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    fn lock(&self) -> DiagnosticsResult<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("security_alerts connection mutex poisoned: {e}"),
            })
    }

    fn row_to_alert(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityAlert> {
        let state_raw: String = row.get(2)?;
        let state = SecurityAlertState::from_str(&state_raw).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown security_alerts.state '{state_raw}'"),
                )),
            )
        })?;
        Ok(SecurityAlert {
            alert_id: row.get(0)?,
            kind: row.get(1)?,
            state,
            raised_event_seq: row.get::<_, i64>(3)? as u64,
            raised_file: row.get(4)?,
            ack_event_seq: row.get::<_, Option<i64>>(5)?.map(|v| v as u64),
            ack_file: row.get(6)?,
            resolved_event_seq: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
            resolved_file: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
            reason_code: row.get(11)?,
        })
    }
}

const SELECT_COLUMNS: &str = "alert_id, kind, state, raised_event_seq, raised_file, \
     ack_event_seq, ack_file, resolved_event_seq, resolved_file, \
     created_at, updated_at, reason_code";

impl SecurityAlertsRepository for ProductionSecurityAlertsRepository {
    fn insert(&self, alert: &SecurityAlert) -> DiagnosticsResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO security_alerts \
             (alert_id, kind, state, raised_event_seq, raised_file, \
              ack_event_seq, ack_file, resolved_event_seq, resolved_file, \
              created_at, updated_at, reason_code) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                alert.alert_id,
                alert.kind,
                alert.state.as_str(),
                alert.raised_event_seq as i64,
                alert.raised_file,
                alert.ack_event_seq.map(|v| v as i64),
                alert.ack_file,
                alert.resolved_event_seq.map(|v| v as i64),
                alert.resolved_file,
                alert.created_at,
                alert.updated_at,
                alert.reason_code,
            ],
        )
        .map_err(|e| DiagnosticsError::AuditWriteFailed {
            reason: format!("security_alerts INSERT failed: {e}"),
        })?;
        Ok(())
    }

    fn update_state(
        &self,
        alert_id: &str,
        new_state: SecurityAlertState,
        event_seq: u64,
        event_file: &str,
        updated_at: i64,
    ) -> DiagnosticsResult<()> {
        let conn = self.lock()?;
        let event_seq_i = event_seq as i64;
        let rows = match new_state {
            SecurityAlertState::Acknowledged => conn.execute(
                "UPDATE security_alerts SET state = ?1, \
                 ack_event_seq = ?2, ack_file = ?3, updated_at = ?4 \
                 WHERE alert_id = ?5",
                params![
                    new_state.as_str(),
                    event_seq_i,
                    event_file,
                    updated_at,
                    alert_id,
                ],
            ),
            SecurityAlertState::Resolved => conn.execute(
                "UPDATE security_alerts SET state = ?1, \
                 resolved_event_seq = ?2, resolved_file = ?3, updated_at = ?4 \
                 WHERE alert_id = ?5",
                params![
                    new_state.as_str(),
                    event_seq_i,
                    event_file,
                    updated_at,
                    alert_id,
                ],
            ),
            SecurityAlertState::Active | SecurityAlertState::Superseded => conn.execute(
                "UPDATE security_alerts SET state = ?1, updated_at = ?2 \
                 WHERE alert_id = ?3",
                params![new_state.as_str(), updated_at, alert_id],
            ),
        }
        .map_err(|e| DiagnosticsError::AuditWriteFailed {
            reason: format!("security_alerts UPDATE failed: {e}"),
        })?;
        if rows == 0 {
            return Err(DiagnosticsError::AuditWriteFailed {
                reason: format!("alert '{alert_id}' not found"),
            });
        }
        Ok(())
    }

    fn list_by_state(&self, state: SecurityAlertState) -> DiagnosticsResult<Vec<SecurityAlert>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM security_alerts \
                 WHERE state = ?1 ORDER BY created_at ASC"
            ))
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("prepare failed: {e}"),
            })?;
        let rows = stmt
            .query_map(params![state.as_str()], Self::row_to_alert)
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("query failed: {e}"),
            })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("row decode failed: {e}"),
            })
    }

    fn list_open(&self) -> DiagnosticsResult<Vec<SecurityAlert>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM security_alerts \
                 WHERE state IN ('active', 'acknowledged') \
                 ORDER BY created_at DESC"
            ))
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("prepare failed: {e}"),
            })?;
        let rows = stmt.query_map([], Self::row_to_alert).map_err(|e| {
            DiagnosticsError::AuditWriteFailed {
                reason: format!("query failed: {e}"),
            }
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("row decode failed: {e}"),
            })
    }

    fn find_by_id(&self, alert_id: &str) -> DiagnosticsResult<Option<SecurityAlert>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM security_alerts \
                 WHERE alert_id = ?1"
            ))
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("prepare failed: {e}"),
            })?;
        let alert = stmt
            .query_row(params![alert_id], Self::row_to_alert)
            .map(Some)
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(DiagnosticsError::AuditWriteFailed {
                        reason: format!("find_by_id failed: {e}"),
                    })
                }
            })?;
        Ok(alert)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
    use nrr_storage::repository::MigrationRunner;

    struct Fixture {
        repo: ProductionSecurityAlertsRepository,
        _dir: tempfile::TempDir,
    }

    fn build_fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let conn = Arc::new(Mutex::new(conn));
        Fixture {
            repo: ProductionSecurityAlertsRepository::new(conn),
            _dir: dir,
        }
    }

    fn sample_alert(id: &str) -> SecurityAlert {
        SecurityAlert {
            alert_id: id.into(),
            kind: "tamper_alert_raised".into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 1,
            raised_file: "nrr_audit_20260509-1.ndjson".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1_745_000_000_000,
            updated_at: 1_745_000_000_000,
            reason_code: "integrity.audit_chain_mismatch".into(),
        }
    }

    #[test]
    fn insert_and_find_by_id_round_trip() {
        let fx = build_fixture();
        let a = sample_alert("alt-001");
        fx.repo.insert(&a).expect("insert");
        let found = fx
            .repo
            .find_by_id("alt-001")
            .expect("find")
            .expect("present");
        assert_eq!(found.alert_id, "alt-001");
        assert_eq!(found.state, SecurityAlertState::Active);
        assert_eq!(found.kind, "tamper_alert_raised");
    }

    #[test]
    fn update_state_to_acknowledged_persists_ack_columns() {
        let fx = build_fixture();
        fx.repo.insert(&sample_alert("alt-002")).expect("insert");
        fx.repo
            .update_state(
                "alt-002",
                SecurityAlertState::Acknowledged,
                42,
                "nrr_audit_20260509-2.ndjson",
                1_745_000_001_000,
            )
            .expect("ack");
        let after = fx
            .repo
            .find_by_id("alt-002")
            .expect("find")
            .expect("present");
        assert_eq!(after.state, SecurityAlertState::Acknowledged);
        assert_eq!(after.ack_event_seq, Some(42));
        assert_eq!(
            after.ack_file.as_deref(),
            Some("nrr_audit_20260509-2.ndjson")
        );
        assert_eq!(after.updated_at, 1_745_000_001_000);
        assert!(after.resolved_event_seq.is_none());
    }

    #[test]
    fn update_state_to_resolved_persists_resolve_columns() {
        let fx = build_fixture();
        fx.repo.insert(&sample_alert("alt-003")).expect("insert");
        fx.repo
            .update_state(
                "alt-003",
                SecurityAlertState::Resolved,
                100,
                "nrr_audit_20260509-3.ndjson",
                1_745_000_002_000,
            )
            .expect("resolve");
        let after = fx
            .repo
            .find_by_id("alt-003")
            .expect("find")
            .expect("present");
        assert_eq!(after.state, SecurityAlertState::Resolved);
        assert_eq!(after.resolved_event_seq, Some(100));
    }

    #[test]
    fn update_state_unknown_id_returns_err() {
        let fx = build_fixture();
        let result =
            fx.repo
                .update_state("no-such-alt", SecurityAlertState::Acknowledged, 1, "f", 0);
        assert!(result.is_err());
    }

    #[test]
    fn list_by_state_filters_and_orders_by_created_at_asc() {
        let fx = build_fixture();
        let mut a = sample_alert("alt-old");
        a.created_at = 1000;
        fx.repo.insert(&a).expect("insert old");
        let mut b = sample_alert("alt-new");
        b.created_at = 2000;
        fx.repo.insert(&b).expect("insert new");
        let mut c = sample_alert("alt-resolved");
        c.created_at = 1500;
        fx.repo.insert(&c).expect("insert third");
        fx.repo
            .update_state("alt-resolved", SecurityAlertState::Resolved, 1, "f", 1500)
            .expect("resolve");

        let active = fx
            .repo
            .list_by_state(SecurityAlertState::Active)
            .expect("list");
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].alert_id, "alt-old");
        assert_eq!(active[1].alert_id, "alt-new");

        let resolved = fx
            .repo
            .list_by_state(SecurityAlertState::Resolved)
            .expect("list");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].alert_id, "alt-resolved");
    }

    #[test]
    fn list_open_returns_active_and_acknowledged_newest_first() {
        let fx = build_fixture();
        let mut a = sample_alert("alt-1");
        a.created_at = 1000;
        fx.repo.insert(&a).expect("insert");
        let mut b = sample_alert("alt-2");
        b.created_at = 2000;
        fx.repo.insert(&b).expect("insert");
        fx.repo
            .update_state("alt-2", SecurityAlertState::Acknowledged, 5, "f", 2000)
            .expect("ack");
        let mut c = sample_alert("alt-3");
        c.created_at = 3000;
        fx.repo.insert(&c).expect("insert");
        fx.repo
            .update_state("alt-3", SecurityAlertState::Resolved, 6, "f", 3000)
            .expect("resolve");

        let open = fx.repo.list_open().expect("list_open");
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].alert_id, "alt-2"); // newest first
        assert_eq!(open[1].alert_id, "alt-1");
    }

    #[test]
    fn state_persists_across_connection_reopen() {
        // Spec test: persistent state across service restarts.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("state.db");

        // First "service run": insert + ack.
        {
            let conn = open_connection(&path).expect("open");
            let runner = SqliteMigrationRunner::for_state_db(conn);
            runner.run_pending_migrations().expect("migrate");
            let conn = Arc::new(Mutex::new(runner.into_connection()));
            let repo = ProductionSecurityAlertsRepository::new(conn);
            repo.insert(&sample_alert("alt-persist")).expect("insert");
            repo.update_state("alt-persist", SecurityAlertState::Acknowledged, 7, "f", 123)
                .expect("ack");
        }
        // Second "service run": same DB file, fresh connection.
        let conn = open_connection(&path).expect("re-open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("re-migrate noop");
        let conn = Arc::new(Mutex::new(runner.into_connection()));
        let repo = ProductionSecurityAlertsRepository::new(conn);
        let after = repo
            .find_by_id("alt-persist")
            .expect("find")
            .expect("present");
        assert_eq!(after.state, SecurityAlertState::Acknowledged);
        assert_eq!(after.ack_event_seq, Some(7));
    }
}

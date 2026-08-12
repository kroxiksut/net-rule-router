//! Security alert types and repository.
//!
//! `SecurityAlert` represents the *mutable state* of a tamper-visible alert.
//! The immutable history lives in NDJSON audit files; this struct (and its
//! SQLite-backed repository) record the current lifecycle state so GUI/tray
//! can show active alerts without scanning files on every query.
//!
//! # Persistence
//!
//! Alert state is stored in the `security_alerts` table in `nrr_service_state.db`.
//! The repository trait is implemented
//! by `SqliteSecurityAlertsRepository` which wraps the state store connection.
//!
//! # Alert lifecycle
//!
//! ```text
//! TamperAlertRaised → Active
//!     │
//!     ├─[user acknowledge]──→ Acknowledged
//!     │                           │
//!     │                           └─[operator resolves]──→ Resolved
//!     │
//!     └─[superseded by newer alert]──→ Superseded
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{DiagnosticsError, DiagnosticsResult};

// ── SecurityAlertState ────────────────────────────────────────────────────────

/// Lifecycle state of a security alert.
///
/// Ordered from most-active to most-resolved; `Active` requires immediate
/// attention, `Superseded` is informational only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAlertState {
    /// Raised and not yet acknowledged by the user.
    Active,
    /// User has acknowledged the alert but it is not yet resolved.
    Acknowledged,
    /// The underlying issue was resolved; alert is closed.
    Resolved,
    /// A newer alert of the same kind superseded this one.
    Superseded,
}

impl SecurityAlertState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::Superseded => "superseded",
        }
    }

    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "acknowledged" => Some(Self::Acknowledged),
            "resolved" => Some(Self::Resolved),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_open(self) -> bool {
        matches!(self, Self::Active | Self::Acknowledged)
    }
}

impl std::fmt::Display for SecurityAlertState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── SecurityAlert ─────────────────────────────────────────────────────────────

/// A persistent tamper-visible alert with its current lifecycle state.
///
/// Stored in `security_alerts` table in `nrr_service_state.db`.
/// The originating audit event is in the NDJSON file referenced by
/// `raised_file` at sequence `raised_event_seq`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityAlert {
    /// Unique identifier (`alt-{uuid_v4}`).
    pub alert_id: String,
    /// The audit event kind that raised this alert.
    pub kind: String,
    /// Current lifecycle state.
    pub state: SecurityAlertState,
    /// Sequence number of the NDJSON audit event that raised this alert.
    pub raised_event_seq: u64,
    /// Filename (not full path) of the NDJSON audit file containing the raise event.
    pub raised_file: String,
    /// Sequence number of the acknowledgement event, if any.
    pub ack_event_seq: Option<u64>,
    /// NDJSON file for the acknowledgement event.
    pub ack_file: Option<String>,
    /// Sequence number of the resolution event, if any.
    pub resolved_event_seq: Option<u64>,
    /// NDJSON file for the resolution event.
    pub resolved_file: Option<String>,
    /// UTC Unix milliseconds when the alert was first raised.
    pub created_at: i64,
    /// UTC Unix milliseconds of the last state change.
    pub updated_at: i64,
    /// Namespaced reason code from the originating audit event.
    pub reason_code: String,
}

impl SecurityAlert {
    /// Returns `true` if this alert requires user attention.
    #[must_use]
    pub fn requires_action(&self) -> bool {
        self.state.is_open()
    }
}

// ── SecurityAlertsRepository ──────────────────────────────────────────────────

/// Repository interface for security alert state persistence.
///
/// Implemented by `SqliteSecurityAlertsRepository` (wired to
/// `nrr_service_state.db`).  For tests, use [`InMemorySecurityAlertsRepository`].
pub trait SecurityAlertsRepository: Send + Sync {
    /// Inserts a new alert (state = `Active`).
    fn insert(&self, alert: &SecurityAlert) -> DiagnosticsResult<()>;

    /// Updates the state and related fields of an existing alert.
    fn update_state(
        &self,
        alert_id: &str,
        new_state: SecurityAlertState,
        event_seq: u64,
        event_file: &str,
        updated_at: i64,
    ) -> DiagnosticsResult<()>;

    /// Returns all alerts that match `state`, in ascending `created_at` order.
    fn list_by_state(&self, state: SecurityAlertState) -> DiagnosticsResult<Vec<SecurityAlert>>;

    /// Returns all open alerts (Active or Acknowledged), newest first.
    fn list_open(&self) -> DiagnosticsResult<Vec<SecurityAlert>>;

    /// Looks up a single alert by id.
    fn find_by_id(&self, alert_id: &str) -> DiagnosticsResult<Option<SecurityAlert>>;
}

// ── InMemorySecurityAlertsRepository ─────────────────────────────────────────

/// Thread-safe in-memory implementation for tests and scaffold.
///
/// Not persistent — all state is lost on drop.
#[derive(Default)]
pub struct InMemorySecurityAlertsRepository {
    alerts: std::sync::Mutex<Vec<SecurityAlert>>,
}

// In-memory test-support repo: lock-poisoning `expect()` is acceptable.
#[allow(clippy::expect_used)]
impl InMemorySecurityAlertsRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn all_alerts(&self) -> Vec<SecurityAlert> {
        self.alerts
            .lock()
            .expect("InMemorySecurityAlertsRepository mutex")
            .clone()
    }
}

// In-memory test-support repo: lock-poisoning `expect()` is acceptable.
#[allow(clippy::expect_used)]
impl SecurityAlertsRepository for InMemorySecurityAlertsRepository {
    fn insert(&self, alert: &SecurityAlert) -> DiagnosticsResult<()> {
        self.alerts.lock().expect("mutex").push(alert.clone());
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
        let mut alerts = self.alerts.lock().expect("mutex");
        let alert = alerts
            .iter_mut()
            .find(|a| a.alert_id == alert_id)
            .ok_or_else(|| DiagnosticsError::AuditWriteFailed {
                reason: format!("alert '{alert_id}' not found"),
            })?;
        match new_state {
            SecurityAlertState::Acknowledged => {
                alert.ack_event_seq = Some(event_seq);
                alert.ack_file = Some(event_file.to_string());
            }
            SecurityAlertState::Resolved => {
                alert.resolved_event_seq = Some(event_seq);
                alert.resolved_file = Some(event_file.to_string());
            }
            _ => {}
        }
        alert.state = new_state;
        alert.updated_at = updated_at;
        Ok(())
    }

    fn list_by_state(&self, state: SecurityAlertState) -> DiagnosticsResult<Vec<SecurityAlert>> {
        let mut results: Vec<SecurityAlert> = self
            .alerts
            .lock()
            .expect("mutex")
            .iter()
            .filter(|a| a.state == state)
            .cloned()
            .collect();
        results.sort_by_key(|a| a.created_at);
        Ok(results)
    }

    fn list_open(&self) -> DiagnosticsResult<Vec<SecurityAlert>> {
        let mut results: Vec<SecurityAlert> = self
            .alerts
            .lock()
            .expect("mutex")
            .iter()
            .filter(|a| a.state.is_open())
            .cloned()
            .collect();
        results.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        Ok(results)
    }

    fn find_by_id(&self, alert_id: &str) -> DiagnosticsResult<Option<SecurityAlert>> {
        Ok(self
            .alerts
            .lock()
            .expect("mutex")
            .iter()
            .find(|a| a.alert_id == alert_id)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_alert(id: &str, state: SecurityAlertState) -> SecurityAlert {
        SecurityAlert {
            alert_id: id.into(),
            kind: "tamper_alert_raised".into(),
            state,
            raised_event_seq: 1,
            raised_file: "nrr_audit_20260423-1.ndjson".into(),
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
    fn security_alert_state_ordering() {
        assert!(SecurityAlertState::Active < SecurityAlertState::Acknowledged);
        assert!(SecurityAlertState::Acknowledged < SecurityAlertState::Resolved);
        assert!(SecurityAlertState::Resolved < SecurityAlertState::Superseded);
    }

    #[test]
    fn security_alert_state_stable_strings() {
        assert_eq!(SecurityAlertState::Active.as_str(), "active");
        assert_eq!(SecurityAlertState::Acknowledged.as_str(), "acknowledged");
        assert_eq!(SecurityAlertState::Resolved.as_str(), "resolved");
        assert_eq!(SecurityAlertState::Superseded.as_str(), "superseded");
    }

    #[test]
    fn security_alert_state_round_trip() {
        for state in [
            SecurityAlertState::Active,
            SecurityAlertState::Acknowledged,
            SecurityAlertState::Resolved,
            SecurityAlertState::Superseded,
        ] {
            let back = SecurityAlertState::from_str(state.as_str()).expect("round trip");
            assert_eq!(back, state);
        }
    }

    #[test]
    fn is_open_only_for_active_and_acknowledged() {
        assert!(SecurityAlertState::Active.is_open());
        assert!(SecurityAlertState::Acknowledged.is_open());
        assert!(!SecurityAlertState::Resolved.is_open());
        assert!(!SecurityAlertState::Superseded.is_open());
    }

    #[test]
    fn in_memory_repo_insert_and_find() {
        let repo = InMemorySecurityAlertsRepository::new();
        let alert = sample_alert("alt-001", SecurityAlertState::Active);
        repo.insert(&alert).expect("insert");

        let found = repo.find_by_id("alt-001").expect("find").expect("exists");
        assert_eq!(found.alert_id, "alt-001");
        assert_eq!(found.state, SecurityAlertState::Active);
    }

    #[test]
    fn in_memory_repo_update_state_to_acknowledged() {
        let repo = InMemorySecurityAlertsRepository::new();
        repo.insert(&sample_alert("alt-002", SecurityAlertState::Active))
            .expect("insert");

        repo.update_state(
            "alt-002",
            SecurityAlertState::Acknowledged,
            2,
            "nrr_audit_20260423-1.ndjson",
            1_745_000_001_000,
        )
        .expect("update");

        let found = repo.find_by_id("alt-002").expect("find").expect("exists");
        assert_eq!(found.state, SecurityAlertState::Acknowledged);
        assert_eq!(found.ack_event_seq, Some(2));
        assert!(found.ack_file.is_some());
    }

    #[test]
    fn in_memory_repo_list_by_state() {
        let repo = InMemorySecurityAlertsRepository::new();
        repo.insert(&sample_alert("a1", SecurityAlertState::Active))
            .expect("ok");
        repo.insert(&sample_alert("a2", SecurityAlertState::Active))
            .expect("ok");
        repo.insert(&sample_alert("a3", SecurityAlertState::Resolved))
            .expect("ok");

        let active = repo
            .list_by_state(SecurityAlertState::Active)
            .expect("list");
        assert_eq!(active.len(), 2);
        let resolved = repo
            .list_by_state(SecurityAlertState::Resolved)
            .expect("list");
        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn in_memory_repo_list_open_excludes_resolved() {
        let repo = InMemorySecurityAlertsRepository::new();
        repo.insert(&sample_alert("a1", SecurityAlertState::Active))
            .expect("ok");
        repo.insert(&sample_alert("a2", SecurityAlertState::Acknowledged))
            .expect("ok");
        repo.insert(&sample_alert("a3", SecurityAlertState::Resolved))
            .expect("ok");
        repo.insert(&sample_alert("a4", SecurityAlertState::Superseded))
            .expect("ok");

        let open = repo.list_open().expect("list_open");
        assert_eq!(open.len(), 2);
        assert!(open.iter().all(|a| a.state.is_open()));
    }

    #[test]
    fn in_memory_repo_update_unknown_id_returns_err() {
        let repo = InMemorySecurityAlertsRepository::new();
        let result = repo.update_state("no-such-id", SecurityAlertState::Resolved, 1, "f", 0);
        assert!(result.is_err());
    }

    #[test]
    fn alert_requires_action_for_open_states() {
        let active = sample_alert("x", SecurityAlertState::Active);
        let resolved = sample_alert("y", SecurityAlertState::Resolved);
        assert!(active.requires_action());
        assert!(!resolved.requires_action());
    }
}

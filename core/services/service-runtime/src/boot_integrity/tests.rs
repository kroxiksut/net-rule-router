use super::*;
use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlert};
use nrr_diagnostics::error::DiagnosticsError;
use nrr_diagnostics::{CapturingSink, DiagnosticsResult};
use nrr_domain::revision::RiskLevel;
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
use nrr_platform_api::error::PlatformError;
use nrr_platform_api::key_store::InMemKeyStore;
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};

use crate::managers::HealthReporter;
use crate::state::ServiceRuntimeState;

const NOW: i64 = 1_745_000_000_000;
const OUTAGE_KIND: &str = "integrity_check_unavailable";

fn open_state() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let runner = SqliteMigrationRunner::for_state_db(
        open_connection(&dir.path().join("state.db")).expect("open"),
    );
    runner.run_pending_migrations().expect("migrate");
    (dir, Arc::new(Mutex::new(runner.into_connection())))
}

fn seed_signed_row(conn: &Arc<Mutex<Connection>>) {
    let guard = conn.lock().unwrap();
    RevisionsRepository::with_signing_key(&guard, vec![0x11; 32])
        .insert_candidate(&RevisionRecord {
            revision_id: "rev-1".into(),
            content_hash: "h-1".into(),
            rules_json: "{}".into(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr".into(),
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: Some(RiskLevel::Low),
        })
        .expect("insert");
}

fn failure(operation: &'static str) -> PlatformError {
    PlatformError::Transient {
        operation,
        detail: "injected".into(),
    }
}

/// A key store that fails at one chosen step.
#[derive(Default)]
struct FaultyKeyStore {
    inner: InMemKeyStore,
    fail_load: bool,
    fail_save: bool,
    fail_marker: bool,
}

impl KeyStore for FaultyKeyStore {
    fn load(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        if self.fail_load {
            return Err(failure("load"));
        }
        self.inner.load()
    }
    fn save(&self, key: &[u8]) -> Result<(), PlatformError> {
        if self.fail_save {
            return Err(failure("save"));
        }
        self.inner.save(key)
    }
    fn delete(&self) -> Result<(), PlatformError> {
        self.inner.delete()
    }
    fn save_resign_marker(&self, marker: &[u8]) -> Result<(), PlatformError> {
        if self.fail_marker {
            return Err(failure("save_resign_marker"));
        }
        self.inner.save_resign_marker(marker)
    }
    fn load_resign_marker(&self) -> Result<Option<Vec<u8>>, PlatformError> {
        self.inner.load_resign_marker()
    }
    fn delete_resign_marker(&self) -> Result<(), PlatformError> {
        self.inner.delete_resign_marker()
    }
}

/// The alert store is itself what failed.
struct BrokenAlerts;

impl SecurityAlertsRepository for BrokenAlerts {
    fn insert(&self, _: &SecurityAlert) -> DiagnosticsResult<()> {
        Err(broken())
    }
    fn update_state(
        &self,
        _: &str,
        _: SecurityAlertState,
        _: u64,
        _: &str,
        _: i64,
    ) -> DiagnosticsResult<()> {
        Err(broken())
    }
    fn list_by_state(&self, _: SecurityAlertState) -> DiagnosticsResult<Vec<SecurityAlert>> {
        Err(broken())
    }
    fn list_open(&self) -> DiagnosticsResult<Vec<SecurityAlert>> {
        Err(broken())
    }
    fn find_by_id(&self, _: &str) -> DiagnosticsResult<Option<SecurityAlert>> {
        Err(broken())
    }
}

fn broken() -> DiagnosticsError {
    DiagnosticsError::AuditWriteFailed {
        reason: "alert store unavailable".into(),
    }
}

struct Harness {
    alerts: Arc<dyn SecurityAlertsRepository>,
    audit: CapturingSink<AuditEventInput>,
    health: HealthAggregator,
}

impl Harness {
    fn new(alerts: Arc<dyn SecurityAlertsRepository>) -> Self {
        let health = HealthAggregator::new();
        health.clear_lifecycle_override();
        Self {
            alerts,
            audit: CapturingSink::new(),
            health,
        }
    }

    fn boot(&self, now_ms: i64) -> BootIntegrity<'_> {
        BootIntegrity {
            alerts: &self.alerts,
            audit: Some(&self.audit as &AuditTrail),
            health: &self.health,
            now_ms,
        }
    }

    fn active_outage_alerts(&self) -> usize {
        self.alerts
            .list_by_state(SecurityAlertState::Active)
            .unwrap()
            .iter()
            .filter(|a| a.kind == OUTAGE_KIND)
            .count()
    }

    fn integrity_health(&self) -> Option<(ServiceHealthSeverity, String)> {
        self.health
            .components()
            .into_iter()
            .find(|(slug, _, _)| *slug == "integrity")
            .map(|(_, severity, message)| (severity, message))
    }
}

fn assert_reported(h: &Harness, source: &str) {
    assert_eq!(h.active_outage_alerts(), 1, "one visible alert");
    let audited = h.audit.drain();
    assert_eq!(audited.len(), 1, "one audit event");
    assert_eq!(audited[0].kind, AuditEventKind::IntegrityCheckUnavailable);
    assert_eq!(audited[0].result, AuditEventResult::Failure);
    let payload: serde_json::Value =
        serde_json::from_str(audited[0].payload_summary_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["source"], source);
    let (severity, message) = h.integrity_health().expect("health names the outage");
    assert_eq!(severity, ServiceHealthSeverity::Warning);
    assert!(message.contains(source), "{message}");
}

/// Every way the bootstrap can fail ends the same: no key (the coordinator
/// runs unsigned), and the outage is on record where the user can see it.
#[test]
fn every_bootstrap_failure_is_raised_audited_and_left_unsigned() {
    let cases: [(&str, FaultyKeyStore, bool, &str); 4] = [
        (
            "unreadable key file",
            FaultyKeyStore {
                fail_load: true,
                ..Default::default()
            },
            false,
            "key-store",
        ),
        (
            "key cannot be saved",
            FaultyKeyStore {
                fail_save: true,
                ..Default::default()
            },
            false,
            "key-store",
        ),
        (
            "re-sign marker cannot be saved",
            FaultyKeyStore {
                fail_marker: true,
                ..Default::default()
            },
            true,
            "key-store",
        ),
        (
            "state database unreadable",
            FaultyKeyStore {
                inner: InMemKeyStore::with_key(vec![0x11; 32]),
                ..Default::default()
            },
            false,
            "storage",
        ),
    ];
    for (name, key_store, seed_rows, source) in cases {
        let (_dir, conn) = open_state();
        if seed_rows {
            seed_signed_row(&conn);
        }
        if source == "storage" {
            conn.lock()
                .unwrap()
                .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE revisions;")
                .expect("break the table");
        }
        let h = Harness::new(Arc::new(InMemorySecurityAlertsRepository::new()));
        let outcome = h.boot(NOW).bootstrap(&conn, &key_store);
        assert!(outcome.is_none(), "{name}: no signing key this start");
        assert_reported(&h, source);
        assert_eq!(
            h.health.current_state(),
            ServiceRuntimeState::Running,
            "{name}: the service keeps running"
        );
    }
}

#[test]
fn a_broken_alert_store_turns_the_health_report_degraded() {
    let (_dir, conn) = open_state();
    let key_store = FaultyKeyStore {
        fail_load: true,
        ..Default::default()
    };
    let h = Harness::new(Arc::new(BrokenAlerts));

    assert!(h.boot(NOW).bootstrap(&conn, &key_store).is_none());

    let (severity, message) = h.integrity_health().expect("health names the outage");
    assert_eq!(severity, ServiceHealthSeverity::Degraded);
    assert!(message.contains("alert could not be recorded"), "{message}");
    assert_eq!(h.health.current_state(), ServiceRuntimeState::Degraded);
    assert_eq!(
        h.audit.len(),
        1,
        "the audit trail does not depend on the alert store"
    );
}

#[test]
fn an_outage_that_persists_across_starts_keeps_one_alert_until_acknowledged() {
    let h = Harness::new(Arc::new(InMemorySecurityAlertsRepository::new()));
    h.boot(NOW)
        .report_outage(OutageSource::KeyStore, "first start");
    h.boot(NOW + 1_000)
        .report_outage(OutageSource::KeyStore, "second start");
    assert_eq!(h.active_outage_alerts(), 1);

    let raised = h.alerts.list_by_state(SecurityAlertState::Active).unwrap();
    h.alerts
        .update_state(
            &raised[0].alert_id,
            SecurityAlertState::Acknowledged,
            1,
            "ack",
            NOW + 2_000,
        )
        .unwrap();
    let report = h
        .boot(NOW + 3_000)
        .report_outage(OutageSource::KeyStore, "third start");
    assert!(report.alert_active && report.audited);
    assert_eq!(
        h.active_outage_alerts(),
        1,
        "a new incident after acknowledgement"
    );
}

#[test]
fn an_outage_without_an_audit_trail_is_still_raised() {
    let h = Harness::new(Arc::new(InMemorySecurityAlertsRepository::new()));
    let boot = BootIntegrity {
        audit: None,
        ..h.boot(NOW)
    };
    let report = boot.report_outage(OutageSource::Sweep, "sweep failed");
    assert!(report.alert_active);
    assert!(!report.audited);
}

#[test]
fn a_healthy_bootstrap_reports_no_outage() {
    let (_dir, conn) = open_state();
    let h = Harness::new(Arc::new(InMemorySecurityAlertsRepository::new()));
    assert!(h
        .boot(NOW)
        .bootstrap(&conn, &InMemKeyStore::new())
        .is_some());
    assert_eq!(h.active_outage_alerts(), 0);
    assert!(h.audit.is_empty());
    assert!(h.integrity_health().is_none());
}

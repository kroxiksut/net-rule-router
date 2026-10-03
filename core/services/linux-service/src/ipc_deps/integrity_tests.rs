//! Revision integrity on the daemon's real IPC surface: the on-disk key store,
//! the boot check, the acknowledgement and the live recheck, exercised the way
//! the Windows `integrity_ack` / `key_reset` tests exercise the shared code.
//! No root: the state tree is a temp directory.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState};
use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_platform_api::active_principals::{ActivePrincipalError, ActivePrincipalSource};
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EnforcementFailure, EnforcementPlan, PolicyEnforcer,
    UserPrincipal,
};
use nrr_platform_linux::key_store::FileKeyStore;
use nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation;
use nrr_service_runtime::ipc_handlers::payloads::MutationKind;
use nrr_service_runtime::ipc_handlers::providers::MutationOutcome;
use nrr_service_runtime::principal_enforcement::{PlannedPolicy, PrincipalPlanSource};
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::RevisionsRepository;

use super::*;

const USER: &str = "1000";
const KEY_FILE: &str = "db-mac-key.bin";
const MARKER_FILE: &str = "db-mac-resign-pending.bin";

/// Nobody is signed in: no pass ever runs, so these are never asked.
struct Nobody;

impl ActivePrincipalSource for Nobody {
    fn active_principals(&self) -> Result<Vec<UserPrincipal>, ActivePrincipalError> {
        Ok(Vec::new())
    }
    fn authority(&self) -> &'static str {
        "test"
    }
}

impl PrincipalPlanSource for Nobody {
    fn plan_for(&self, _: &UserPrincipal, _: ChannelAvailability) -> Option<PlannedPolicy> {
        None
    }
}

impl PolicyEnforcer for Nobody {
    fn enforce(&self, _: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        unreachable!("no enforcement pass runs in these tests")
    }
    fn channel_availability(&self, _: &UserPrincipal) -> ChannelAvailability {
        unreachable!("no enforcement pass runs in these tests")
    }
    fn teardown(&self) -> Result<(), EnforcementFailure> {
        Ok(())
    }
}

/// A state tree the daemon is restarted over.
struct Machine {
    dir: tempfile::TempDir,
}

impl Machine {
    fn new() -> Self {
        let machine = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        std::fs::create_dir_all(machine.state_dir()).expect("state dir");
        machine
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    fn state_db(&self) -> PathBuf {
        self.state_dir().join("nrr_service_state.db")
    }

    fn key_file(&self) -> PathBuf {
        self.state_dir().join(KEY_FILE)
    }

    fn marker_file(&self) -> PathBuf {
        self.state_dir().join(MARKER_FILE)
    }

    fn open_state(&self) -> Arc<Mutex<rusqlite::Connection>> {
        let runner =
            SqliteMigrationRunner::for_state_db(open_connection(&self.state_db()).expect("open"));
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    /// One daemon start, through the same builder `run` uses.
    fn boot(&self) -> IpcSurface {
        let cache_db = self.state_dir().join("nrr_fqdn_ip_cache.db");
        let audit_dir = self.state_dir().join("audit");
        let cycle = Arc::new(PrincipalEnforcementCycle::new(
            Arc::new(Nobody),
            Arc::new(Nobody),
            Arc::new(Nobody),
        ));
        build_ipc_surface(
            self.open_state(),
            None,
            self.state_dir(),
            self.dir.path().join("logs"),
            audit_dir.clone(),
            self.state_db(),
            cache_db.clone(),
            Some(Arc::new(nrr_diagnostics::AuditWriter::open(
                nrr_diagnostics::AuditWriterConfig::new(audit_dir),
            ))),
            None,
            Arc::new(nrr_platform_linux::LinuxApi),
            cycle,
            Arc::new(nrr_service_runtime::HealthAggregator::new()),
            Arc::new(EventBus::new()),
            PathBuf::from("gui"),
            None,
            None,
            nrr_service_runtime::production_principal_plan::open_cache_store(&cache_db)
                .expect("cache"),
            Arc::new(nrr_service_runtime::conn_observation_consumer::ConnectionTraceRing::new(16)),
            nrr_service_runtime::app_enforcement_status::AppEnforcementStatus::new(),
            Arc::new(|_| {}),
            None,
            Arc::new(FileKeyStore::in_state_dir(&self.state_dir())),
        )
    }

    fn active(&self) -> Option<nrr_storage::RevisionRecord> {
        let conn = open_connection(&self.state_db()).expect("reader");
        RevisionsRepository::new(&conn)
            .get_active_for(USER)
            .expect("active")
    }

    fn edit_from_outside(&self, revision_id: &str) {
        open_connection(&self.state_db())
            .expect("outside connection")
            .execute(
                "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
                rusqlite::params![r#"{"tampered":true}"#, revision_id],
            )
            .expect("outside edit");
    }

    fn alerts(&self, state: SecurityAlertState, kind: AuditEventKind) -> Vec<SecurityAlert> {
        ProductionSecurityAlertsRepository::new(Arc::new(Mutex::new(
            open_connection(&self.state_db()).expect("alerts"),
        )))
        .list_by_state(state)
        .expect("list")
        .into_iter()
        .filter(|a| a.kind == kind.as_str())
        .collect()
    }

    fn verdict(&self, revision_id: &str) -> Option<HmacVerification> {
        let key = std::fs::read(self.key_file()).expect("key file");
        let conn = open_connection(&self.state_db()).expect("reader");
        RevisionsRepository::with_signing_key(&conn, key)
            .verify_row_hmac(revision_id)
            .expect("verify")
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

fn stored(kind: MutationKind, payload: serde_json::Value) -> StoredMutation {
    StoredMutation {
        kind,
        payload,
        correlation_id: None,
        issuer_sid: USER.to_string(),
        caller_is_elevated: false,
    }
}

/// A rule change from the GUI, through the surface's own executor.
fn apply(surface: &IpcSurface, hash: &str) -> MutationOutcome {
    surface.deps.mutation_executor.execute(
        stored(
            MutationKind::RulesUpdate,
            serde_json::json!({ "rules-json": r#"{"rules":[]}"#, "content-hash": hash }),
        ),
        USER,
    )
}

fn applied(surface: &IpcSurface, hash: &str) -> String {
    let outcome = apply(surface, hash);
    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "{outcome:?}"
    );
    surface
        .coordinator
        .current_active_for(USER)
        .expect("active")
        .expect("something active")
        .revision_id
}

/// Acknowledges as the dialog does: echoing the rows the dry-run listed.
fn acknowledge(surface: &IpcSurface, alert_id: &str) -> serde_json::Value {
    let executor = &surface.deps.mutation_executor;
    let shown: Vec<_> = executor
        .unverified_rows(
            MutationKind::SecurityAlertAck,
            &serde_json::json!({ "alert-id": alert_id }),
        )
        .into_iter()
        .map(|r| r.row)
        .collect();
    match executor.execute(
        stored(
            MutationKind::SecurityAlertAck,
            serde_json::json!({ "alert-id": alert_id, "adopt-rows": shown }),
        ),
        USER,
    ) {
        MutationOutcome::Completed(result) => result,
        other => panic!("{other:?}"),
    }
}

/// The one tamper alert, acknowledged once, adopts the edited row and lifts
/// the gate: nothing is raised again for the same edit.
fn one_acknowledgement_settles(machine: &Machine, surface: &IpcSurface, edited: &str) {
    let tamper = machine.alerts(SecurityAlertState::Active, AuditEventKind::DbTamperDetected);
    assert_eq!(tamper.len(), 1, "{tamper:?}");
    assert!(
        tamper[0].alert_id.contains(edited),
        "names the edited revision"
    );
    assert!(
        matches!(apply(surface, "h-3"), MutationOutcome::Failed(_)),
        "rule changes wait for the acknowledgement"
    );

    let result = acknowledge(surface, &tamper[0].alert_id);

    assert_eq!(result["rows-adopted"], 1, "{result}");
    assert_eq!(machine.verdict(edited), Some(HmacVerification::Verified));
    assert!(machine
        .alerts(SecurityAlertState::Active, AuditEventKind::DbTamperDetected)
        .is_empty());
    applied(surface, "h-3");
}

#[test]
fn the_key_lives_beside_the_state_database_owner_only_and_signs_every_revision() {
    let machine = Machine::new();
    std::fs::set_permissions(machine.state_dir(), std::fs::Permissions::from_mode(0o755))
        .expect("loosen");
    let surface = machine.boot();

    assert_eq!(mode(&machine.key_file()), 0o600);
    assert_eq!(mode(&machine.state_dir()), 0o700);
    let id = applied(&surface, "h-1");
    assert_eq!(machine.verdict(&id), Some(HmacVerification::Verified));
    assert!(
        surface.revision_watch.is_some(),
        "the live recheck is wired"
    );
    assert!(
        surface.coordinator.audit_restart_key().is_some(),
        "a chain restart can be sealed"
    );
    assert!(
        surface.deps.alerts_repo.is_some(),
        "tamper gate at the socket"
    );
    assert!(surface.deps.other_principals_hold_revisions.is_some());
}

#[test]
fn an_active_revision_edited_while_stopped_is_rolled_back_and_needs_one_acknowledgement() {
    let machine = Machine::new();
    let edited = {
        let surface = machine.boot();
        applied(&surface, "h-1");
        applied(&surface, "h-2")
    };
    machine.edit_from_outside(&edited);

    let surface = machine.boot();

    let restored = machine.active().expect("a trusted revision is active");
    assert_ne!(restored.revision_id, edited);
    assert_eq!(restored.rules_json, r#"{"rules":[]}"#);
    one_acknowledgement_settles(&machine, &surface, &edited);
}

#[test]
fn acknowledging_a_tampered_row_adopts_exactly_it_and_lifts_the_gate() {
    let machine = Machine::new();
    let (edited, active) = {
        let surface = machine.boot();
        (applied(&surface, "h-1"), applied(&surface, "h-2"))
    };
    machine.edit_from_outside(&edited);

    let surface = machine.boot();
    assert_eq!(machine.active().map(|r| r.revision_id), Some(active));
    let tamper = machine.alerts(SecurityAlertState::Active, AuditEventKind::DbTamperDetected);
    assert_eq!(tamper.len(), 1, "{tamper:?}");
    assert!(matches!(apply(&surface, "h-3"), MutationOutcome::Failed(_)));

    assert_eq!(
        acknowledge(&surface, &tamper[0].alert_id)["rows-adopted"],
        1
    );

    assert_eq!(machine.verdict(&edited), Some(HmacVerification::Verified));
    assert!(machine
        .alerts(SecurityAlertState::Active, AuditEventKind::DbTamperDetected)
        .is_empty());
    applied(&surface, "h-3");
}

#[test]
fn a_lost_key_holds_every_rollback_until_its_acknowledgement_clears_the_marker() {
    let machine = Machine::new();
    let active = {
        let surface = machine.boot();
        applied(&surface, "h-1");
        applied(&surface, "h-2")
    };
    std::fs::remove_file(machine.key_file()).expect("lose the key");

    let surface = machine.boot();
    assert_eq!(mode(&machine.marker_file()), 0o600, "marker beside the key");
    assert_eq!(
        machine.active().map(|r| r.revision_id),
        Some(active.clone()),
        "nothing is rolled back on a key that never signed the rows"
    );
    let reset = machine.alerts(
        SecurityAlertState::Active,
        AuditEventKind::KeyResetWithExistingData,
    );
    assert_eq!(reset.len(), 1, "{reset:?}");

    let _ = acknowledge(&surface, &reset[0].alert_id);
    drop(surface);

    assert!(
        !machine.marker_file().exists(),
        "the acknowledgement clears it"
    );
    assert_eq!(machine.verdict(&active), Some(HmacVerification::Verified));
    let _restart = machine.boot();
    assert_eq!(machine.active().map(|r| r.revision_id), Some(active));
    assert!(machine
        .alerts(
            SecurityAlertState::Active,
            AuditEventKind::KeyResetWithExistingData
        )
        .is_empty());
    assert!(machine
        .alerts(SecurityAlertState::Active, AuditEventKind::DbTamperDetected)
        .is_empty());
}

#[test]
fn the_running_daemon_rolls_back_a_revision_edited_from_outside_and_needs_one_acknowledgement() {
    let machine = Machine::new();
    let mut surface = machine.boot();
    applied(&surface, "h-1");
    let edited = applied(&surface, "h-2");
    let mut watch = surface.revision_watch.take().expect("watch");
    watch.tick(1);

    machine.edit_from_outside(&edited);
    watch.tick(2);

    let restored = machine.active().expect("a trusted revision is active");
    assert_ne!(restored.revision_id, edited);
    assert_eq!(
        machine
            .alerts(
                SecurityAlertState::Active,
                AuditEventKind::UntrustedRevisionRejected
            )
            .len(),
        1
    );
    one_acknowledgement_settles(&machine, &surface, &edited);
}

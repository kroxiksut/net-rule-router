#![allow(clippy::unwrap_used, clippy::expect_used)]
//! End-to-end integration tests for the
//! DB-MAC tamper-detection bootstrap, exercised through the public
//! `nrr_service_runtime::tamper_bootstrap` API plus the storage and
//! alert repositories.
//!
//! These map 1:1 to four scenarios:
//!
//! 1. External tamper → load continues, alert raised, ack re-signs and
//!    the table "heals" (next boot is clean).
//! 2. Key deleted + revisions non-empty → silent key regen, blocking
//!    alert, mutations gated.
//! 3. Key deleted + revisions empty → silent regen, no alert (fresh
//!    install path).
//! 4. Acknowledge → re-sign + restart → gate clear, no duplicate alert.

use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{
    InMemorySecurityAlertsRepository, SecurityAlertState, SecurityAlertsRepository,
};
use nrr_domain::revision::RiskLevel;
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
// KeyStore + the InMemKeyStore mock are neutral (live in
// nrr-platform-api), so this tamper-bootstrap test is cross-platform — import
// from the api SSOT, not the Windows backend (absent off Windows).
use nrr_platform_api::key_store::{InMemKeyStore, KeyStore};
use nrr_service_runtime::bootstrap::sweep_signed_orphaned_candidates;
use nrr_service_runtime::tamper_bootstrap::{mutations_blocked_by_alert, run_tamper_bootstrap};
use nrr_service_runtime::ProductionSecurityAlertsRepository;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};
use rusqlite::Connection;

const NOW: i64 = 1_745_000_000_000;

fn key() -> Vec<u8> {
    vec![0x33u8; 32]
}

fn state_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory state db");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("run migrations");
    Arc::new(Mutex::new(runner.into_connection()))
}

fn record(id: &str, hash: &str) -> RevisionRecord {
    RevisionRecord {
        revision_id: id.into(),
        content_hash: hash.into(),
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
    }
}

fn alerts() -> Arc<dyn SecurityAlertsRepository> {
    Arc::new(InMemorySecurityAlertsRepository::new())
}

/// Scenario 1: an externally tampered row is detected at load. Routing
/// is unaffected (the bootstrap still returns the key), an alert is
/// raised, and the mutation gate engages.
#[test]
fn scenario_1_external_tamper_detected_and_gated() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        let repo = RevisionsRepository::with_signing_key(&g, key());
        repo.insert_candidate(&record("rev-1", "h-1")).unwrap();
        // Tamper outside the service write path.
        g.execute(
            "UPDATE revisions SET rules_json = '{\"evil\":true}' WHERE revision_id = 'rev-1'",
            [],
        )
        .unwrap();
    }
    let ks = InMemKeyStore::with_key(key());
    let repo = alerts();

    let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

    assert!(!out.key_was_reset);
    assert_eq!(out.tampered_revision_ids, vec!["rev-1".to_string()]);
    assert_eq!(out.signing_key, key(), "key is intact; routing continues");
    let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].kind, "db_tamper_detected");
    assert!(mutations_blocked_by_alert(repo.as_ref()));
}

/// Scenario 2: the key file is gone but revisions exist. The service
/// regenerates a key, raises a single key-reset alert, and gates
/// mutations until acknowledged.
#[test]
fn scenario_2_key_reset_with_existing_data_blocks() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        // Sign with the old key, which is then "lost".
        RevisionsRepository::with_signing_key(&g, key())
            .insert_candidate(&record("rev-1", "h-1"))
            .unwrap();
    }
    let ks = InMemKeyStore::new(); // key absent
    let repo = alerts();

    let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

    assert!(out.key_was_reset);
    assert_eq!(out.signing_key.len(), 32);
    assert!(ks.load().unwrap().is_some(), "fresh key persisted");
    let active = repo.list_by_state(SecurityAlertState::Active).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].kind, "key_reset_with_existing_data");
    assert!(mutations_blocked_by_alert(repo.as_ref()));
}

/// Scenario 3: fresh install — no key, no revisions. Silent key
/// generation, no alert, gate open.
#[test]
fn scenario_3_fresh_install_silent() {
    let conn = state_db();
    let ks = InMemKeyStore::new();
    let repo = alerts();

    let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("bootstrap");

    assert!(!out.key_was_reset);
    assert!(!out.raised_blocking_alert);
    assert!(repo
        .list_by_state(SecurityAlertState::Active)
        .unwrap()
        .is_empty());
    assert!(!mutations_blocked_by_alert(repo.as_ref()));
    assert!(ks.load().unwrap().is_some());
}

/// Scenario 4: full acknowledge cycle. After a tamper alert, the user
/// acknowledges (which re-signs the table — modelled here via the same
/// `re_sign_all` the executor's ack path calls); a subsequent restart
/// finds the table clean, raises no new alert, and the gate is clear.
#[test]
fn scenario_4_ack_re_signs_and_restart_is_clean() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        let repo = RevisionsRepository::with_signing_key(&g, key());
        repo.insert_candidate(&record("rev-1", "h-1")).unwrap();
        g.execute(
            "UPDATE revisions SET rules_json = '{\"evil\":true}' WHERE revision_id = 'rev-1'",
            [],
        )
        .unwrap();
    }
    let ks = InMemKeyStore::with_key(key());
    let repo = alerts();

    // First boot raises the alert and gates.
    run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("boot1");
    assert!(mutations_blocked_by_alert(repo.as_ref()));
    let alert_id = repo.list_by_state(SecurityAlertState::Active).unwrap()[0]
        .alert_id
        .clone();

    // User acknowledges: the alert transitions to Acknowledged and the
    // service re-signs the table (this is exactly what the
    // `ProductionMutationExecutor` ack path does via
    // `coordinator.re_sign_all_revisions`).
    repo.update_state(
        &alert_id,
        SecurityAlertState::Acknowledged,
        1,
        "ack",
        NOW + 10,
    )
    .unwrap();
    {
        let g = conn.lock().unwrap();
        let signed = RevisionsRepository::with_signing_key(&g, key());
        let n = signed.re_sign_all().unwrap();
        assert_eq!(n, 1);
    }
    // Gate lifts immediately after ack.
    assert!(!mutations_blocked_by_alert(repo.as_ref()));

    // Second boot over the healed table: clean, no new alert, no
    // duplicate of the acknowledged one.
    let out2 = run_tamper_bootstrap(&conn, &ks, &repo, NOW + 100).expect("boot2");
    assert!(out2.tampered_revision_ids.is_empty(), "table healed");
    assert!(!out2.raised_blocking_alert);
    assert!(repo
        .list_by_state(SecurityAlertState::Active)
        .unwrap()
        .is_empty());
    assert!(!mutations_blocked_by_alert(repo.as_ref()));
    // The previously-acknowledged alert is still recorded, just not active.
    let healed = {
        let g = conn.lock().unwrap();
        RevisionsRepository::with_signing_key(&g, key())
            .verify_row_hmac("rev-1")
            .unwrap()
    };
    assert_eq!(healed, Some(HmacVerification::Verified));
}

/// Regression for a startup hang: in production the alerts
/// repository shares the state-DB connection mutex with the bootstrap
/// itself (`ProductionSecurityAlertsRepository` over the same
/// `Arc<Mutex<Connection>>`). Holding the connection guard across
/// `emit_alert` self-deadlocks the startup thread the moment a tampered
/// row is found; the in-memory alerts repo used by the other tests can
/// never catch that. The bootstrap runs on a worker thread here so a
/// reintroduced deadlock fails the test instead of hanging the suite.
#[test]
fn tamper_alert_on_shared_connection_does_not_deadlock() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        let repo = RevisionsRepository::with_signing_key(&g, key());
        repo.insert_candidate(&record("rev-bad", "h-bad")).unwrap();
        g.execute(
            "UPDATE revisions SET rules_json = '{\"evil\":true}' WHERE revision_id = 'rev-bad'",
            [],
        )
        .unwrap();
    }
    let alerts_repo: Arc<dyn SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(&conn)));

    let (tx, rx) = std::sync::mpsc::channel();
    let worker_conn = Arc::clone(&conn);
    let worker_alerts = Arc::clone(&alerts_repo);
    std::thread::spawn(move || {
        let ks = InMemKeyStore::with_key(key());
        let out = run_tamper_bootstrap(&worker_conn, &ks, &worker_alerts, NOW);
        let _ = tx.send(out.map(|o| o.tampered_revision_ids));
    });
    let tampered = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("tamper bootstrap deadlocked on the shared state connection")
        .expect("bootstrap");

    assert_eq!(tampered, vec!["rev-bad".to_string()]);
    let active = alerts_repo
        .list_by_state(SecurityAlertState::Active)
        .unwrap();
    assert_eq!(active.len(), 1);
    assert!(mutations_blocked_by_alert(alerts_repo.as_ref()));
}

/// Same shared-connection wiring, key-reset branch: a lost key with
/// existing rows must raise its alert without deadlocking either.
#[test]
fn key_reset_alert_on_shared_connection_does_not_deadlock() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        RevisionsRepository::with_signing_key(&g, key())
            .insert_candidate(&record("rev-1", "h-1"))
            .unwrap();
    }
    let alerts_repo: Arc<dyn SecurityAlertsRepository> =
        Arc::new(ProductionSecurityAlertsRepository::new(Arc::clone(&conn)));

    let (tx, rx) = std::sync::mpsc::channel();
    let worker_conn = Arc::clone(&conn);
    let worker_alerts = Arc::clone(&alerts_repo);
    std::thread::spawn(move || {
        let ks = InMemKeyStore::new(); // key file absent
        let out = run_tamper_bootstrap(&worker_conn, &ks, &worker_alerts, NOW);
        let _ = tx.send(out.map(|o| o.key_was_reset));
    });
    let key_was_reset = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("tamper bootstrap deadlocked on the shared state connection")
        .expect("bootstrap");

    assert!(key_was_reset);
    assert!(mutations_blocked_by_alert(alerts_repo.as_ref()));
}

/// Regression for the companion self-tamper of the same incident: a
/// candidate row orphaned by a hard kill is collected by the keyed sweep
/// AFTER the integrity scan, re-signed in the same pass, and the next
/// boot verifies clean — no self-inflicted tamper alert.
#[test]
fn keyed_sweep_after_bootstrap_leaves_next_boot_clean() {
    let conn = state_db();
    {
        let g = conn.lock().unwrap();
        RevisionsRepository::with_signing_key(&g, key())
            .insert_candidate(&record("rev-orphan", "h-orphan"))
            .unwrap();
        // No activation follow-up: simulates the hard kill that leaves
        // the row stuck in `candidate`.
    }
    let ks = InMemKeyStore::with_key(key());
    let repo = alerts();

    let out = run_tamper_bootstrap(&conn, &ks, &repo, NOW).expect("boot1");
    assert!(out.tampered_revision_ids.is_empty());
    sweep_signed_orphaned_candidates(&conn, &out.signing_key);

    {
        let g = conn.lock().unwrap();
        let r = RevisionsRepository::with_signing_key(&g, key());
        let row = r.get_by_id("rev-orphan").unwrap().expect("present");
        assert_eq!(row.status, RevisionStatus::Rejected);
        assert_eq!(
            r.verify_row_hmac("rev-orphan").unwrap(),
            Some(HmacVerification::Verified),
            "sweep must re-sign the flipped row"
        );
    }

    let out2 = run_tamper_bootstrap(&conn, &ks, &repo, NOW + 100).expect("boot2");
    assert!(
        out2.tampered_revision_ids.is_empty(),
        "swept row must not read as tampered on the next boot"
    );
    assert!(!out2.raised_blocking_alert);
    assert!(!mutations_blocked_by_alert(repo.as_ref()));
}

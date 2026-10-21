#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Saving the revision-retention settings prunes with the new limits at once,
//! instead of leaving the old history in place until the next hourly pass.

use std::sync::{Arc, Mutex};

use nrr_domain::revision::RiskLevel;
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
use nrr_service_runtime::ipc_handlers::providers::RetentionSettingsWriter;
use nrr_service_runtime::ProductionRetentionSettings;
use nrr_shared::ipc_payloads::RetentionSettingsSetRequest;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};
use rusqlite::Connection;

fn state_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory state db");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("run migrations");
    Arc::new(Mutex::new(runner.into_connection()))
}

fn record(id: &str) -> RevisionRecord {
    RevisionRecord {
        revision_id: id.into(),
        content_hash: format!("hash-{id}"),
        rules_json: "{}".into(),
        status: RevisionStatus::Candidate,
        source: RulesRevisionSource::GuiRulesEdit,
        correlation_id: "corr".into(),
        created_at: 100,
        activated_at: None,
        superseded_at: None,
        superseded_by: None,
        rejected_reason: None,
        review_summary_json: None,
        risk_level: Some(RiskLevel::Low),
    }
}

/// "Reset to defaults" in the clients sends the wire copy of the defaults; it
/// must be the service's own.
#[test]
fn the_clients_defaults_are_the_services() {
    let stored = nrr_storage::RetentionSettings::DEFAULT;
    let wire = RetentionSettingsSetRequest::DEFAULT;
    assert_eq!(
        (
            wire.superseded_days,
            wire.superseded_count_cap,
            wire.rejected_days,
            wire.rolledback_days,
            wire.rolledback_count_cap,
            wire.pin_lkg,
        ),
        (
            stored.superseded_days,
            stored.superseded_count_cap,
            stored.rejected_days,
            stored.rolledback_days,
            stored.rolledback_count_cap,
            stored.pin_lkg,
        )
    );
}

#[test]
fn saving_retention_prunes_with_the_new_limits_at_once() {
    let conn = state_db();
    {
        let guard = conn.lock().unwrap();
        let repo = RevisionsRepository::new(&guard);
        let mut previous: Option<String> = None;
        // Superseded long ago: far past any age limit the settings allow.
        for (i, id) in ["rev-a", "rev-b", "rev-c"].iter().enumerate() {
            repo.insert_candidate(&record(id)).expect("insert");
            repo.mark_apply_succeeded(id, previous.as_deref(), 100 * (i as i64 + 1))
                .expect("activate");
            previous = Some((*id).to_string());
        }
    }

    let saved = ProductionRetentionSettings::new(Arc::clone(&conn))
        .set(&RetentionSettingsSetRequest {
            superseded_days: 7,
            superseded_count_cap: 20,
            rejected_days: 1,
            rolledback_days: 1,
            rolledback_count_cap: 5,
            pin_lkg: true,
        })
        .expect("save");

    let guard = conn.lock().unwrap();
    let repo = RevisionsRepository::new(&guard);
    assert!(
        repo.get_by_id("rev-a").expect("read").is_none(),
        "an old superseded revision outlived the save"
    );
    assert!(
        repo.get_by_id("rev-b").expect("read").is_some(),
        "the pinned last known-good revision was pruned"
    );
    assert!(
        repo.get_by_id("rev-c").expect("read").is_some(),
        "the active revision was pruned"
    );
    assert!(
        saved.last_cleanup_at.is_some(),
        "the save ran a cleanup but does not say so"
    );
}

#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The book enforcement reads is checked against the start's signing key: a
//! row edited outside the service is not put on the wire in the seconds before
//! the integrity watch rolls it back. Its own binary, since the check is
//! installed once per process.

use std::sync::{Arc, Mutex};

use nrr_platform_api::key_store::{InMemKeyStore, KeyStore};
use nrr_service_runtime::per_sid_orchestrator::{RulesProvider, RulesRead};
use nrr_service_runtime::production_rules_provider::{
    install_signature_check, ProductionRulesProvider,
};
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revisions::RevisionsRepository;
use rusqlite::Connection;

const KEY: [u8; 32] = [0x42; 32];
const USER: &str = "S-1-5-21-1-2-3-1001";

fn book(host: &str) -> String {
    serde_json::json!({
        "schema-version": 1,
        "primary": [{
            "id": "r-1",
            "enabled": true,
            "address-match": { "kind": "exact-fqdn", "value": host },
            "comment": "",
            "action": "route",
        }],
        "secondary": [],
    })
    .to_string()
}

fn state_with_signed_book(id: &str, host: &str) -> Arc<Mutex<Connection>> {
    let runner = SqliteMigrationRunner::for_state_db(Connection::open_in_memory().unwrap());
    runner.run_pending_migrations().unwrap();
    let conn = runner.into_connection();
    conn.execute(
        "INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status, source,
             correlation_id, created_at, activated_at)
         VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', 'c', 1, 1)",
        rusqlite::params![USER, id, format!("h-{id}"), book(host)],
    )
    .unwrap();
    RevisionsRepository::with_signing_key(&conn, KEY.to_vec())
        .re_sign_row(id)
        .unwrap();
    Arc::new(Mutex::new(conn))
}

fn enforced_host(provider: &ProductionRulesProvider) -> Option<String> {
    match provider.rules_read_for(USER) {
        RulesRead::Rules(snapshot) => Some(format!("{:?}", snapshot.rule_book)),
        _ => None,
    }
}

#[test]
fn a_book_edited_outside_the_service_is_not_enforced_and_a_signed_one_is() {
    let key_store: Arc<dyn KeyStore> = Arc::new(InMemKeyStore::with_key(KEY.to_vec()));
    install_signature_check(KEY.to_vec(), Arc::clone(&key_store));

    let signed = state_with_signed_book("rev-a", "own.example");
    let shown = enforced_host(&ProductionRulesProvider::new(signed)).expect("a signed book");
    assert!(shown.contains("own.example"), "{shown}");

    let edited = state_with_signed_book("rev-b", "own.example");
    edited
        .lock()
        .unwrap()
        .execute(
            "UPDATE revisions SET rules_json = ?1, content_hash = 'h-forged'",
            [book("planted.example")],
        )
        .unwrap();
    let provider = ProductionRulesProvider::new(edited);
    assert!(
        matches!(provider.rules_read_for(USER), RulesRead::Unreadable(_)),
        "an edited row is held as unreadable: what is installed stays, nothing new is applied"
    );
}

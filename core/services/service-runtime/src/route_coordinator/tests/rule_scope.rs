//! The routing scope on the hot path: a DNS answer or a relayed flow asks who
//! is served, and must never wait on the settings store to learn it.

use super::*;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::service_stability_config::{
    IpcAcceptPolicyWrite, ServiceStabilityConfigRepository,
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const VASYA: &str = "S-1-5-21-1-2-3-1001";

fn state_conn() -> Arc<Mutex<rusqlite::Connection>> {
    let conn = rusqlite::Connection::open_in_memory().expect("open in-memory");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    Arc::new(Mutex::new(runner.into_connection()))
}

fn save_scope(conn: &Arc<Mutex<rusqlite::Connection>>, service_driven: bool) {
    let guard = conn.lock().expect("lock");
    let repo = ServiceStabilityConfigRepository::new(&guard);
    let r = repo.get_or_default().expect("read stability");
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        r.verbose_until_ms,
        r.conn_trace_ndjson_until_ms,
        r.conn_trace_gui,
        service_driven,
        r.routing_stop_policy,
        r.cache_refresh_interval_secs,
        r.enforcement_mode,
        r.secondary_liveness_window_secs,
        r.fake_ip_enabled,
        r.dns_via_secondary,
        r.dns_fast_answers,
        r.fake_ip_udp_relay,
        r.fake_ip_instant_rst,
        r.allow_user_rule_edits,
        None,
        0,
    )
    .expect("save stability");
}

/// A writer holding the settings store (an activation, an import) must not
/// stall name resolution: the scope read answers at once with what it last
/// saw, and a saved change is seen by the next read once the store is free.
#[test]
fn the_scope_answers_at_once_while_a_writer_holds_the_store() {
    let conn = state_conn();
    save_scope(&conn, false);
    let scope = rule_scope_from_store(&conn);
    assert!(!scope(), "the saved scope, not the factory one");

    let writer = conn.lock().expect("store");
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let scope = Arc::clone(&scope);
        std::thread::spawn(move || {
            let _ = tx.send(scope());
        });
    }
    let answer = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the scope read waited on the store's lock");
    assert!(!answer, "the scope last seen answers");
    drop(writer);

    save_scope(&conn, true);
    assert!(scope(), "a saved change is read once the store is free");
}

/// Every DNS answer asks who is served; the scope behind that answer is a
/// stored setting. Hot readers ask the store at most once a second, and a
/// pass reads it at once, so a change reaches the routes on the next pass and
/// the answers within a second.
#[test]
fn hot_readers_ask_the_store_for_the_scope_once_a_second() {
    let api = Arc::new(MockWindowsApi::new());
    api.set_interactive_user_sids(&[VASYA]);
    let service_driven = Arc::new(AtomicBool::new(true));
    let asked = Arc::new(AtomicUsize::new(0));
    let scope: RuleScopeProvider = {
        let (service_driven, asked) = (Arc::clone(&service_driven), Arc::clone(&asked));
        Arc::new(move || {
            asked.fetch_add(1, Ordering::SeqCst);
            service_driven.load(Ordering::SeqCst)
        })
    };
    let coord = SecondaryRouteCoordinator::new(
        Arc::clone(&api) as Arc<dyn RouteTablePort>,
        Arc::new(FakeRules::new()) as Arc<dyn RulesProvider>,
        Arc::new(FakePolicy::new()) as Arc<dyn RoutePolicySource>,
        Arc::new(MockFqdnCacheLookup::new()) as Arc<dyn FqdnCacheLookup>,
        scope,
    );

    for _ in 0..100 {
        assert_eq!(coord.served_sids(&[]), vec![VASYA.to_owned()]);
    }
    assert!(
        asked.load(Ordering::SeqCst) <= 1,
        "{} store reads for 100 answers",
        asked.load(Ordering::SeqCst)
    );

    // App-driven with no tray serves nobody.
    service_driven.store(false, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !coord.served_sids(&[]).is_empty() {
        assert!(Instant::now() < deadline, "the answers never followed");
        std::thread::sleep(Duration::from_millis(20));
    }

    service_driven.store(true, Ordering::SeqCst);
    assert_eq!(
        coord.served_sids_fresh(&[]),
        vec![VASYA.to_owned()],
        "a pass reads the scope at once"
    );
    assert_eq!(
        coord.served_sids(&[]),
        vec![VASYA.to_owned()],
        "and the answers follow the pass"
    );
}

//! The DNS refresh tick and the policy read run side by side without a
//! deadlock. They share two locks: the state DB (held by the policy read while
//! it resolves the DoH resolver list through the FQDN cache) and the FQDN cache
//! (held by the refresh while it lists expired names). The refresh's use gate
//! reads the state DB, as the production rule-scope provider does; asked under
//! the cache lock, the two waited on each other and the whole service stalled.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use nrr_domain::decision_lookup::FreshnessThresholds;
use nrr_platform_api::dns::{DnsResolverPort, MockDnsResolver};
use nrr_service_runtime::dns_refresh::DnsRefreshOrchestrator;
use nrr_service_runtime::fqdn_cache_lookup::SqliteFqdnCacheLookup;
use nrr_service_runtime::per_sid_orchestrator::RoutePolicySource;
use nrr_service_runtime::production_handlers_misc::ProductionRoutePolicySource;
use nrr_storage::doh_lockdown::{DohResolverEntriesRepository, DohResolverEntry, DohTarget};
use nrr_storage::dto::ResolutionEntry;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::{CacheRepository, MigrationRunner};
use nrr_storage::resolution_source::StorageResolutionSource;
use nrr_storage::route_bindings::{
    BindingSource, RouteBindingRecord, RouteBindingsRepository, RoutePolicyRecord,
};
use nrr_storage::store::SqliteCacheStore;
use rusqlite::Connection;

const SID: &str = "S-1-5-21-1";
const RESOLVER_HOST: &str = "resolver.example";

fn state_db() -> Arc<Mutex<Connection>> {
    let runner = SqliteMigrationRunner::for_state_db(Connection::open_in_memory().expect("db"));
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    let mut record = RoutePolicyRecord::empty(BindingSource::UserAssigned);
    record.primary = Some(RouteBindingRecord {
        stable_id: "main".into(),
        display_name: "main".into(),
        user_confirmed: true,
        known_stable_ids: Vec::new(),
    });
    record.doh_lockdown_enabled = true;
    RouteBindingsRepository::new(&conn)
        .update_for_sid(SID, &record, 1)
        .expect("bind");
    DohResolverEntriesRepository::new(&conn)
        .replace_all(
            &[DohResolverEntry {
                target: DohTarget::Host(RESOLVER_HOST.into()),
                comment: String::new(),
                enabled: true,
            }],
            1,
        )
        .expect("resolver list");
    Arc::new(Mutex::new(conn))
}

fn cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
    let runner = SqliteMigrationRunner::for_cache_db(Connection::open_in_memory().expect("db"));
    runner.run_pending_migrations().expect("migrate");
    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds {
            fallback_ttl_secs: 10,
            ..FreshnessThresholds::default_production()
        },
    );
    let cache: Arc<Mutex<dyn CacheRepository + Send>> = Arc::new(Mutex::new(store));
    let long_ago = SystemTime::now() - Duration::from_secs(3_600);
    for (i, host) in [RESOLVER_HOST, "a.example", "b.example"].iter().enumerate() {
        cache
            .lock()
            .unwrap()
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: (*host).into(),
                raw_hostname_sample: None,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, i as u8 + 1))],
                ttl_seconds: Some(60),
                source: StorageResolutionSource::Dns,
                resolved_at: long_ago,
                active_revision_id: None,
            })
            .expect("seed");
    }
    cache
}

#[test]
fn the_refresh_tick_and_the_policy_read_do_not_wait_on_each_other() {
    let state = state_db();
    let cache = cache();
    let policy = Arc::new(
        ProductionRoutePolicySource::new(Arc::clone(&state)).with_fqdn_cache(Arc::new(
            SqliteFqdnCacheLookup::new(
                Arc::clone(&cache),
                FreshnessThresholds::default_production(),
            ),
        )),
    );
    // The production gate reaches the state DB through the rule-scope provider.
    let gate_state = Arc::clone(&state);
    let refresh = Arc::new(
        DnsRefreshOrchestrator::new(
            Arc::new(MockDnsResolver::new()) as Arc<dyn DnsResolverPort>,
            Arc::clone(&cache),
        )
        .with_use_gate(
            Arc::new(move || {
                let _held = gate_state.lock().unwrap();
                std::thread::sleep(Duration::from_millis(1));
                Vec::new()
            }),
            Duration::from_secs(7 * 24 * 3_600),
        ),
    );

    let (done, finished) = mpsc::channel();
    let rounds = 300;
    {
        let done = done.clone();
        let policy = Arc::clone(&policy);
        std::thread::spawn(move || {
            for _ in 0..rounds {
                assert!(policy.load_for_sid(SID).is_some());
            }
            let _ = done.send("policy");
        });
    }
    std::thread::spawn(move || {
        for _ in 0..rounds {
            refresh.run_once(SystemTime::now(), 16);
        }
        let _ = done.send("refresh");
    });

    for _ in 0..2 {
        finished
            .recv_timeout(Duration::from_secs(30))
            .expect("the two ticks deadlocked on the state DB and the FQDN cache");
    }
}

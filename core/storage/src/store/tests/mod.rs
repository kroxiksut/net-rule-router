use super::*;
use crate::migration::{open_connection, SqliteMigrationRunner};
use crate::repository::MigrationRunner;
use std::net::Ipv6Addr;

fn migrated_cache_store(dir: &tempfile::TempDir) -> SqliteCacheStore {
    let path = dir.path().join("cache.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().expect("migrate");
    SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds::default_production(),
    )
}

/// Short-TTL thresholds for exercising the expiry MECHANISM. Production
/// defaults hold entries for a week (leak-guard stickiness), so
/// mechanism tests that assert "expired after an hour" build the store with
/// a small `fallback_ttl_secs` floor instead.
fn short_ttl_thresholds() -> FreshnessThresholds {
    FreshnessThresholds {
        fresh_max_age_secs: 300,
        stale_usable_max_age_secs: 3_600,
        fallback_ttl_secs: 10,
        negative_ttl_secs: 30,
    }
}

fn migrated_cache_store_short_ttl(dir: &tempfile::TempDir) -> SqliteCacheStore {
    let path = dir.path().join("cache.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().expect("migrate");
    SqliteCacheStore::new(runner.into_connection(), short_ttl_thresholds())
}

fn migrated_state_store(dir: &tempfile::TempDir) -> SqliteStateStore {
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    SqliteStateStore::new(runner.into_connection())
}

fn sample_resolution(hostname: &str, ip: Ipv4Addr) -> ResolutionEntry {
    ResolutionEntry {
        canonical_hostname: hostname.to_string(),
        raw_hostname_sample: None,
        resolved_ips: vec![IpAddr::V4(ip)],
        ttl_seconds: Some(300),
        source: StorageResolutionSource::Dns,
        resolved_at: SystemTime::now(),
        active_revision_id: Some("rev-test-001".to_string()),
    }
}

/// The cache table was always family-agnostic; what pinned it to v4 was the
/// Rust type and a hardcoded literal. This is the proof that a v6 answer now
/// survives the write: the row lands under its own family, and the v4-only
/// index column is left NULL rather than filled with something invented.
#[test]
fn a_v6_resolution_is_stored_under_its_own_family() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let v6: Ipv6Addr = "2001:db8::1".parse().expect("v6");

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "six.example".to_string(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V6(v6)],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: SystemTime::now(),
            active_revision_id: None,
        })
        .expect("v6 resolution must be storable");

    let row: (String, String, Option<i64>) = store
        .conn
        .borrow()
        .query_row(
            "SELECT address_family, canonical_ip, ipv4_packed FROM ip_addresses",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("one row");
    assert_eq!(row.0, "ipv6");
    assert_eq!(row.1, "2001:db8::1", "canonical, compressed, lower-case");
    assert_eq!(row.2, None, "the packed column is a v4 index");
}

/// Both families under one hostname must be two rows, not one overwriting
/// the other: the UNIQUE key is (family, address), and a product that lost
/// the v4 row when a v6 arrived would drop the route it is actually using.
#[test]
fn both_families_of_one_host_coexist() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let v6: Ipv6Addr = "2001:db8::2".parse().expect("v6");

    store
        .upsert_resolution(sample_resolution(
            "dual.example",
            Ipv4Addr::new(203, 0, 113, 7),
        ))
        .expect("v4");
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "dual.example".to_string(),
            resolved_ips: vec![IpAddr::V6(v6)],
            ..sample_resolution("dual.example", Ipv4Addr::UNSPECIFIED)
        })
        .expect("v6");

    let families: Vec<String> = store
        .conn
        .borrow()
        .prepare("SELECT address_family FROM ip_addresses ORDER BY address_family")
        .and_then(|mut st| {
            st.query_map([], |r| r.get(0))
                .and_then(|rows| rows.collect::<Result<Vec<String>, _>>())
        })
        .expect("rows");
    assert_eq!(families, vec!["ipv4".to_string(), "ipv6".to_string()]);

    // The per-host read returns BOTH families: a reader that acts on one
    // narrows for itself. Filtering here would make «not cached» and
    // «cached in the other family» indistinguishable to every caller.
    let lookup = store
        .get_by_hostname(
            "dual.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("lookup");
    let families: Vec<bool> = lookup
        .resolved_ips
        .iter()
        .map(|e| e.addr.is_ipv4())
        .collect();
    assert_eq!(lookup.resolved_ips.len(), 2, "both rows come back");
    assert!(
        families.contains(&true) && families.contains(&false),
        "one of each family"
    );
}

// ── Fixtures shared by more than one theme ───────────────────────────────

/// A revision row for the baseline principal. Needed because the active
/// pointer now carries a foreign key into `revisions`: a revision that does
/// not exist can no longer be made active, which is the point.
fn seed_revision(store: &SqliteStateStore, revision_id: &str, status: &str) {
    let conn = store.conn.borrow();
    conn.execute(
        "INSERT INTO revisions (principal, revision_id, content_hash, rules_json,
                                    status, source, correlation_id, created_at)
             VALUES (?1, ?2, 'h', '{}', ?3, 'gui-rules-edit', 'c', 0)",
        params![crate::BASELINE_PRINCIPAL, revision_id, status],
    )
    .expect("seed revision");
}

mod cache;
mod integrity_and_stats;
mod listing_and_wal;
mod state_store;

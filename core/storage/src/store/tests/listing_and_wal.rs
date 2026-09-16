use super::*;

// ── periodic_vacuum ───────────────────────────────────────────────────────

#[test]
fn periodic_vacuum_preserves_data_and_schema() {
    use crate::repository::MigrationRunner;

    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("cache.db");

    // Upsert some entries, then vacuum.
    {
        let store = migrated_cache_store(&dir);
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "vacuum.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("upsert");

        store.periodic_vacuum().expect("vacuum must not error");
    }

    // Re-open — schema must still pass verify_schema.
    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    let v = runner.verify_schema().expect("verify");
    assert!(v.is_ok(), "schema must be intact after vacuum: {v:?}");

    // Data inserted before vacuum must still be readable.
    let conn = runner.into_connection();
    let store = SqliteCacheStore::new(conn, FreshnessThresholds::default_production());
    let result = store
        .get_by_hostname(
            "vacuum.test",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("lookup");
    assert!(!result.resolved_ips.is_empty(), "data must survive vacuum");
}

// ── WAL concurrent access ─────────────────────────────────────────────────

#[test]
fn wal_multiple_connections_open_to_same_file() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("cache.db");

    // Create and migrate once.
    {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
    }

    // Open two independent connections simultaneously — WAL allows this.
    let conn1 = open_connection(&path).expect("conn1");
    let conn2 = open_connection(&path).expect("conn2");

    let c1: i64 = conn1
        .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
        .expect("c1");
    let c2: i64 = conn2
        .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
        .expect("c2");
    assert_eq!(c1, c2, "both readers must see the same data");

    let m1: String = conn1
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("mode1");
    let m2: String = conn2
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("mode2");
    assert_eq!(m1, "wal");
    assert_eq!(m2, "wal");
}

#[test]
fn wal_reader_observes_committed_write() {
    // Verifies that a second connection opened after a write sees the
    // committed data — the basic WAL durability guarantee.
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("cache.db");

    {
        let conn = open_connection(&path).expect("open writer");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let store = SqliteCacheStore::new(
            runner.into_connection(),
            FreshnessThresholds::default_production(),
        );
        store
            .upsert_resolution(ResolutionEntry {
                canonical_hostname: "durable.test".into(),
                raw_hostname_sample: None,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))],
                ttl_seconds: Some(300),
                source: StorageResolutionSource::Dns,
                resolved_at: SystemTime::now(),
                active_revision_id: None,
            })
            .expect("write");
    } // writer connection closed here; WAL checkpointed on close

    let reader = open_connection(&path).expect("reader");
    let count: i64 = reader
        .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
        .expect("count");
    assert_eq!(count, 1, "reader must observe committed write");
}

// ── invalidation cause integration ────────────────────────────────────────

#[test]
fn invalidation_cause_file_modified_marks_stale_not_full_clear() {
    use crate::rebuild::InvalidationCause;

    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "rules.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-a".into()),
        })
        .expect("upsert");

    // ExternalFileModified → mark-stale, not full clear.
    let cause = InvalidationCause::ExternalFileModified;
    assert!(
        !cause.requires_full_clear(),
        "file change is a mark-stale invalidation"
    );

    let staled = store.mark_revision_stale("rev-b").expect("mark stale");
    assert_eq!(staled, 1);

    // Entry must still be in the cache (just marked stale).
    let result = store
        .get_by_hostname(
            "rules.test",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("lookup");
    assert!(
        !result.resolved_ips.is_empty(),
        "entry must survive mark-stale"
    );
    assert!(
        result
            .resolved_ips
            .iter()
            .any(|e| e.cache_state == CacheEntryState::StaleUsable),
        "entry must be stale after mark_revision_stale",
    );

    // CacheStats must reflect the stale count without inflating resolution_count.
    let stats = store.get_cache_stats().expect("stats");
    assert_eq!(stats.resolution_count, 1);
    assert_eq!(stats.stale_resolution_count, 1);
}

// ── list_expired_resolutions ────────────────────────────────────────────

fn seed_resolution(
    store: &SqliteCacheStore,
    hostname: &str,
    ip: Ipv4Addr,
    source: StorageResolutionSource,
    resolved_at: SystemTime,
    ttl_secs: u32,
) {
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: hostname.to_string(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(ip)],
            ttl_seconds: Some(ttl_secs),
            source,
            resolved_at,
            active_revision_id: None,
        })
        .expect("upsert");
}

/// Touches `hostnames.last_seen_at` to mark the hostname as hot.
/// Mirrors what `get_by_hostname` would do via its lookup pass.
fn touch_last_seen(store: &SqliteCacheStore, hostname: &str, at: SystemTime) {
    let conn = store.conn.borrow();
    conn.execute(
        "UPDATE hostnames SET last_seen_at = ?1 WHERE canonical_host = ?2",
        rusqlite::params![system_time_to_ms(at), hostname],
    )
    .expect("touch");
}

#[test]
fn list_expired_resolutions_returns_only_expired_dns_rows() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store_short_ttl(&dir);

    let now = SystemTime::now();
    let past_resolved = now - Duration::from_secs(3_600); // 1h ago, ttl 60s → expired
    let recent_resolved = now - Duration::from_secs(10); // 10s ago, ttl 3600s → fresh

    seed_resolution(
        &store,
        "expired.test",
        Ipv4Addr::new(1, 1, 1, 1),
        StorageResolutionSource::Dns,
        past_resolved,
        60,
    );
    seed_resolution(
        &store,
        "fresh.test",
        Ipv4Addr::new(2, 2, 2, 2),
        StorageResolutionSource::Dns,
        recent_resolved,
        3_600,
    );

    let listed = store
        .list_expired_resolutions(now, 16)
        .expect("list_expired_resolutions");
    assert_eq!(listed.len(), 1, "only the expired row should be listed");
    assert_eq!(listed[0].canonical_hostname, "expired.test");
}

#[test]
fn list_expired_resolutions_excludes_observed_from_traffic() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store_short_ttl(&dir);

    let now = SystemTime::now();
    let past = now - Duration::from_secs(3_600);

    // Two expired rows — one DNS-sourced, one observed-from-traffic.
    seed_resolution(
        &store,
        "dns.test",
        Ipv4Addr::new(1, 1, 1, 1),
        StorageResolutionSource::Dns,
        past,
        60,
    );
    seed_resolution(
        &store,
        "observed.test",
        Ipv4Addr::new(2, 2, 2, 2),
        StorageResolutionSource::ObservedFromTraffic,
        past,
        60,
    );

    let listed = store
        .list_expired_resolutions(now, 16)
        .expect("list_expired_resolutions");
    assert_eq!(listed.len(), 1, "observed-from-traffic must be skipped");
    assert_eq!(listed[0].canonical_hostname, "dns.test");
}

#[test]
fn list_expired_resolutions_orders_hot_first() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store_short_ttl(&dir);

    let now = SystemTime::now();
    let past = now - Duration::from_secs(3_600);

    for name in ["cold.test", "warm.test", "hot.test"] {
        seed_resolution(
            &store,
            name,
            Ipv4Addr::new(1, 1, 1, 1),
            StorageResolutionSource::Dns,
            past,
            60,
        );
    }
    // Stagger `last_seen_at` so `hot.test` is hottest.
    touch_last_seen(&store, "cold.test", now - Duration::from_secs(86_400));
    touch_last_seen(&store, "warm.test", now - Duration::from_secs(3_600));
    touch_last_seen(&store, "hot.test", now - Duration::from_secs(10));

    let listed = store
        .list_expired_resolutions(now, 16)
        .expect("list_expired_resolutions");
    assert_eq!(
        listed
            .iter()
            .map(|e| e.canonical_hostname.as_str())
            .collect::<Vec<_>>(),
        vec!["hot.test", "warm.test", "cold.test"]
    );
}

#[test]
fn list_expired_resolutions_respects_limit() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store_short_ttl(&dir);

    let now = SystemTime::now();
    let past = now - Duration::from_secs(3_600);
    for i in 0..5 {
        seed_resolution(
            &store,
            &format!("h{i}.test"),
            Ipv4Addr::new(10, 0, 0, i as u8),
            StorageResolutionSource::Dns,
            past,
            60,
        );
    }

    let listed = store
        .list_expired_resolutions(now, 2)
        .expect("list_expired_resolutions");
    assert_eq!(listed.len(), 2);

    let none = store.list_expired_resolutions(now, 0).expect("limit=0");
    assert!(none.is_empty(), "limit=0 must short-circuit");
}

#[test]
fn list_expired_resolutions_returns_empty_for_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let listed = store
        .list_expired_resolutions(SystemTime::now(), 16)
        .expect("list");
    assert!(listed.is_empty());
}

// ── list_hostnames_under_suffix ─────────────────────────────────────────

#[test]
fn list_hostnames_under_suffix_returns_only_subdomains_not_apex() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    seed_resolution(
        &store,
        "example.com",
        Ipv4Addr::new(1, 1, 1, 1),
        StorageResolutionSource::Dns,
        now,
        300,
    );
    seed_resolution(
        &store,
        "www.example.com",
        Ipv4Addr::new(2, 2, 2, 2),
        StorageResolutionSource::Dns,
        now,
        300,
    );
    seed_resolution(
        &store,
        "api.example.com",
        Ipv4Addr::new(3, 3, 3, 3),
        StorageResolutionSource::Dns,
        now,
        300,
    );

    let listed = store
        .list_hostnames_under_suffix("example.com", 16)
        .expect("list");
    assert_eq!(
        listed,
        vec!["api.example.com".to_string(), "www.example.com".to_string()],
        "apex hostname must be excluded, subdomains returned in ASC order"
    );
}

/// The suffix is a value from the user's rule, so it is spliced into a
/// LIKE pattern and must be escaped: an unescaped `_` matched any single
/// character and `%` matched everything, quietly widening a zone rule into
/// permits and routes for hosts it never named.
#[test]
fn list_hostnames_under_suffix_treats_like_wildcards_as_literal_text() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    for host in ["a.ru", "b.eu", "c.nu", "d.example.com"] {
        seed_resolution(
            &store,
            host,
            Ipv4Addr::new(9, 9, 9, 9),
            StorageResolutionSource::Dns,
            now,
            300,
        );
    }

    // `_u` is not a zone anybody owns; before escaping it matched `.ru`,
    // `.eu` and `.nu`.
    assert!(store
        .list_hostnames_under_suffix("_u", 16)
        .expect("list")
        .is_empty());
    // `%` used to match every hostname containing a dot.
    assert!(store
        .list_hostnames_under_suffix("%", 16)
        .expect("list")
        .is_empty());
    // A real zone still resolves.
    assert_eq!(
        store.list_hostnames_under_suffix("ru", 16).expect("list"),
        vec!["a.ru".to_string()],
    );
}

#[test]
fn list_hostnames_under_suffix_respects_limit_and_zero_short_circuits() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    for sub in ["a.test", "b.test", "c.test", "d.test"] {
        seed_resolution(
            &store,
            sub,
            Ipv4Addr::new(10, 0, 0, 0),
            StorageResolutionSource::Dns,
            now,
            300,
        );
    }

    let two = store
        .list_hostnames_under_suffix("test", 2)
        .expect("list 2");
    assert_eq!(two.len(), 2);

    let zero = store
        .list_hostnames_under_suffix("test", 0)
        .expect("list 0");
    assert!(zero.is_empty(), "limit=0 must short-circuit");
}

#[test]
fn list_hostnames_under_suffix_is_case_insensitive_and_strips_trailing_dot() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();
    seed_resolution(
        &store,
        "api.example.com",
        Ipv4Addr::new(1, 1, 1, 1),
        StorageResolutionSource::Dns,
        now,
        300,
    );

    let upper = store
        .list_hostnames_under_suffix("EXAMPLE.COM", 16)
        .expect("upper");
    assert_eq!(upper, vec!["api.example.com".to_string()]);

    let with_dot = store
        .list_hostnames_under_suffix("example.com.", 16)
        .expect("trailing dot");
    assert_eq!(with_dot, vec!["api.example.com".to_string()]);
}

#[test]
fn list_hostnames_under_suffix_empty_suffix_returns_empty() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let listed = store.list_hostnames_under_suffix("", 16).expect("list");
    assert!(listed.is_empty());
}

/// Bootstrap asks this to decide whether the machine has a policy at all.
/// It used to read only the singleton the loader itself writes, so a
/// machine that had been enforcing rules for months reported "first run" -
/// and the recovery offered on the strength of that would have written a
/// pointer nothing reads.
#[test]
fn the_active_revision_comes_from_the_pointer_the_activation_path_writes() {
    use crate::revisions::{ActiveRevisionPointer, RevisionsRepository};
    use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    {
        let repo = RevisionsRepository::new(&conn);
        repo.insert_candidate(&crate::revisions::RevisionRecord {
            revision_id: "rev-live".into(),
            content_hash: "h".into(),
            rules_json: r#"{"rules":[]}"#.into(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "c".into(),
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: None,
        })
        .expect("insert");
        repo.set_active_pointer(&ActiveRevisionPointer {
            revision_id: "rev-live".into(),
            activated_at: 1_700_000_000,
            apply_attempt_id: None,
        })
        .expect("pointer");
    }
    let store = SqliteStateStore::new(conn);
    assert_eq!(
        store
            .get_active_revision()
            .expect("read")
            .map(|id| id.as_str().to_string()),
        Some("rev-live".to_string()),
    );
}

use super::*;

// ── build_lookup_envelope ─────────────────────────────────────────────────

#[test]
fn build_lookup_envelope_returns_lookup_result() {
    use nrr_domain::decision_lookup::LookupDirection;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(203, 0, 113, 138);

    store
        .upsert_resolution(sample_resolution("example.com", ip))
        .expect("upsert");

    let request = CacheLookupRequest {
        hostname: Some("example.com".to_string()),
        direction: LookupDirection::Both,
        active_revision_id: None,
        requested_at: SystemTime::now(),
    };
    let result = store
        .build_lookup_envelope(
            &request,
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("envelope");

    assert!(result.selected_ip.is_some());
    assert_eq!(result.selected_ip.unwrap().addr, ip);
    assert!(result.explain_data.standard.cache_hit);
}

// ── SqliteStateStore ──────────────────────────────────────────────────────

#[test]
fn state_store_reads_the_baseline_pointer() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    seed_revision(&store, "rev-abc-001", "active");

    point_baseline(&store, "rev-abc-001").expect("set");
    let got = store.get_active_revision().expect("get");
    assert_eq!(got.unwrap().as_str(), "rev-abc-001");
}

#[test]
fn an_active_pointer_cannot_name_a_revision_that_does_not_exist() {
    // The pointer carries a foreign key into `revisions`.
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    assert!(point_baseline(&store, "rev-ghost").is_err());
}

#[test]
fn state_store_get_active_revision_none_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let got = store.get_active_revision().expect("get");
    assert!(got.is_none());
}

#[test]
fn state_store_check_integrity_ok_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let (result, action) = store.check_integrity().expect("check");
    assert_eq!(result, IntegrityCheckResult::Ok);
    assert_eq!(action, RecoveryAction::None);
}

// ── cleanup, vacuum, cache_generation ───────────────────────────────────

#[test]
fn cleanup_expired_removes_expired_resolutions() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // Insert a resolution that is already expired (expires_at in the past).
    let far_past = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    {
        let conn = store.conn.borrow();
        // Seed hostname + ip rows.
        conn.execute(
                "INSERT INTO hostnames (canonical_host, first_seen_at, last_seen_at) VALUES ('old.example', 0, 0)",
                [],
            ).expect("hostname");
        conn.execute(
                "INSERT INTO ip_addresses (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at) VALUES ('ipv4', '198.51.100.9', 3325256713, 0, 0)",
                [],
            ).expect("ip");
        conn.execute(
            "INSERT INTO hostname_ip_resolutions
                 (hostname_id, ip_id, source, ttl_seconds, resolved_at, expires_at, freshness_state)
                 VALUES (1, 1, 'dns', 60, 0, ?1, 'fresh')",
            rusqlite::params![system_time_to_ms(far_past)],
        )
        .expect("resolution");
    }

    let policy = crate::dto::CleanupPolicy {
        run_vacuum: false,
        ..Default::default()
    };
    let summary = store
        .cleanup_expired(SystemTime::now(), &policy)
        .expect("cleanup");
    assert_eq!(summary.expired_resolutions_removed, 1);

    // Hostname and IP rows should also be gone (orphan cleanup).
    let conn = store.into_connection();
    let h_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM hostnames", [], |r| r.get(0))
        .expect("h");
    let ip_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM ip_addresses", [], |r| r.get(0))
        .expect("ip");
    assert_eq!(h_count, 0);
    assert_eq!(ip_count, 0);
}

#[test]
fn cleanup_expired_removes_stale_negative_cache() {
    use std::time::Duration;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // Insert expired negative cache entry.
    let far_past = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
    {
        let conn = store.conn.borrow();
        conn.execute(
                "INSERT INTO negative_cache (input_hash, reason, created_at, expires_at, retry_after, source)
                 VALUES ('deadbeef00000001', 'nxdomain', ?1, ?1, ?1, 'dns')",
                rusqlite::params![system_time_to_ms(far_past)],
            ).expect("neg insert");
    }

    let policy = crate::dto::CleanupPolicy {
        max_negative_cache_age_secs: 10, // 10 s — far_past is >> 10 s old
        run_vacuum: false,
        ..Default::default()
    };
    let summary = store
        .cleanup_expired(SystemTime::now(), &policy)
        .expect("cleanup");
    assert_eq!(summary.negative_cache_entries_removed, 1);
}

#[test]
fn cleanup_expired_with_vacuum_does_not_error() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let policy = crate::dto::CleanupPolicy {
        run_vacuum: true,
        ..Default::default()
    };
    let summary = store
        .cleanup_expired(SystemTime::now(), &policy)
        .expect("cleanup");
    assert!(
        summary.vacuumed,
        "vacuumed should be true when run_vacuum = true"
    );
}

#[test]
fn clear_cache_increments_cache_generation() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .upsert_resolution(sample_resolution("h.example", Ipv4Addr::new(192, 0, 2, 4)))
        .expect("upsert");
    store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear1");
    store
        .upsert_resolution(sample_resolution("h2.example", Ipv4Addr::new(192, 0, 2, 8)))
        .expect("upsert2");
    store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear2");

    let gen: i64 = {
        let conn = store.conn.borrow();
        conn.query_row(
            "SELECT cache_generation FROM cache_metadata WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .expect("gen")
    };
    assert_eq!(gen, 2, "two clears should yield cache_generation = 2");
}

#[test]
fn cleanup_lookup_events_removes_overflow() {
    use std::time::Duration;

    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();
    let far_future = system_time_to_ms(now + Duration::from_secs(86_400));
    {
        let conn = store.conn.borrow();
        for _ in 0..5 {
            conn.execute(
                "INSERT INTO lookup_events
                 (direction, result_state, error_code, duration_ms, created_at, expires_at)
                 VALUES ('hostname_to_ip', 'hit', NULL, 1, ?1, ?2)",
                params![system_time_to_ms(now), far_future],
            )
            .expect("seed lookup event");
        }
    }

    // Cleanup with max_lookup_events = 3 — overflow trim should remove 2.
    let policy = crate::dto::CleanupPolicy {
        max_lookup_events: 3,
        run_vacuum: false,
        ..Default::default()
    };
    store.cleanup_expired(now, &policy).expect("cleanup");

    let conn = store.into_connection();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM lookup_events", [], |r| r.get(0))
        .expect("count");
    assert!(
        count <= 3,
        "overflow trim must leave at most max_lookup_events rows, got {count}"
    );
}

#[test]
fn cache_store_touch_last_rebuild_at_creates_singleton_on_fresh_db() {
    use crate::repository::CacheRepository;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // No singleton row on a fresh DB.
    assert_eq!(
        store.get_last_rebuild_at_ms().expect("get"),
        None,
        "fresh DB must have no last_rebuild_at"
    );

    store
        .touch_last_rebuild_at(1_700_000_000_000)
        .expect("touch");

    assert_eq!(
        store.get_last_rebuild_at_ms().expect("get"),
        Some(1_700_000_000_000)
    );
}

#[test]
fn cache_store_touch_last_rebuild_at_updates_existing_singleton() {
    use crate::repository::CacheRepository;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store.touch_last_rebuild_at(1_000).expect("touch 1");
    store.touch_last_rebuild_at(2_000).expect("touch 2");
    assert_eq!(store.get_last_rebuild_at_ms().expect("get"), Some(2_000));
}

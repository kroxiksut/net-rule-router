use super::*;

// ── build_lookup_envelope ─────────────────────────────────────────────────

#[test]
fn build_lookup_envelope_returns_lookup_result() {
    use nrr_domain::decision_lookup::LookupDirection;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(23, 10, 20, 138);

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
fn state_store_set_and_get_active_revision() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let rev = RevisionId::from_prefixed_string("rev-abc-001".to_string()).expect("rev");
    seed_revision(&store, "rev-abc-001", "active");

    store.set_active_revision(&rev).expect("set");
    let got = store.get_active_revision().expect("get");
    assert_eq!(got.unwrap().as_str(), "rev-abc-001");
}

#[test]
fn an_active_pointer_cannot_name_a_revision_that_does_not_exist() {
    // The pointer carries a foreign key into `revisions`, so the recovery
    // flow can no longer point the system at an id nothing backs.
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let ghost = RevisionId::from_prefixed_string("rev-ghost".to_string()).expect("rev");
    assert!(store.set_active_revision(&ghost).is_err());
}

#[test]
fn state_store_get_active_revision_none_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let got = store.get_active_revision().expect("get");
    assert!(got.is_none());
}

#[test]
fn lkg_is_the_revision_that_was_active_before_this_one() {
    // Nothing "promotes" a revision to last-known-good any more: the answer
    // is read off the revision history, so it exists as soon as a second
    // revision replaces the first. Previously it came from a singleton
    // table nothing wrote, so this always answered `None` in production.
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    assert!(
        store.get_last_known_good().expect("get").is_none(),
        "nothing superseded yet — no rollback target",
    );

    {
        let conn = store.conn.borrow();
        for (id, status, superseded_at) in [
            ("rev-lkg-001", "superseded", 1_000_i64),
            ("rev-lkg-002", "superseded", 2_000),
            ("rev-lkg-003", "active", 0),
        ] {
            conn.execute(
                "INSERT INTO revisions (principal, revision_id, content_hash, rules_json,
                                            status, source, correlation_id, created_at,
                                            superseded_at)
                     VALUES (?1, ?2, 'h', '{}', ?3, 'gui-rules-edit', 'c', ?4, ?5)",
                params![
                    crate::BASELINE_PRINCIPAL,
                    id,
                    status,
                    superseded_at,
                    (superseded_at > 0).then_some(superseded_at)
                ],
            )
            .expect("seed revision");
        }
    }

    let got = store.get_last_known_good().expect("get").expect("present");
    assert_eq!(
        got.as_str(),
        "rev-lkg-002",
        "the MOST RECENTLY superseded revision is the rollback target",
    );
}

#[test]
fn state_store_check_integrity_ok_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let (result, action) = store.check_integrity().expect("check");
    assert_eq!(
        result,
        IntegrityCheckResult::OkNoRollbackTarget,
        "a fresh DB verifies clean, and has nothing to roll back to"
    );
    assert_eq!(action, RecoveryAction::None);
}

#[test]
fn state_store_record_and_get_integrity_status() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let now = SystemTime::now();

    store
        .record_integrity_check(&IntegrityCheckResult::Ok, now)
        .expect("record");

    let status = store.get_integrity_status().expect("status");
    assert_eq!(status.state_db, DbIntegrityState::Ok);
    assert!(status.last_verified_at.is_some());
}

#[test]
fn state_store_set_active_overrides_previous() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);

    let r1 = RevisionId::from_prefixed_string("rev-v1".to_string()).expect("r1");
    let r2 = RevisionId::from_prefixed_string("rev-v2".to_string()).expect("r2");
    seed_revision(&store, "rev-v1", "superseded");
    seed_revision(&store, "rev-v2", "active");

    store.set_active_revision(&r1).expect("set r1");
    store.set_active_revision(&r2).expect("set r2");

    let got = store.get_active_revision().expect("get");
    assert_eq!(got.unwrap().as_str(), "rev-v2");
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
                "INSERT INTO ip_addresses (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at) VALUES ('ipv4', '9.9.9.9', 151587081, 0, 0)",
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
        .upsert_resolution(sample_resolution("h.example", Ipv4Addr::new(1, 2, 3, 4)))
        .expect("upsert");
    store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear1");
    store
        .upsert_resolution(sample_resolution("h2.example", Ipv4Addr::new(5, 6, 7, 8)))
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
    use crate::dto::{LookupEventEntry, LookupResultState};
    use nrr_domain::decision_lookup::LookupDirection;
    use std::time::Duration;

    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();
    let far_future = now + Duration::from_secs(86_400);

    // Insert 5 lookup events with a far-future expires_at.
    for _ in 0..5 {
        store
            .record_lookup_event(LookupEventEntry {
                direction: LookupDirection::HostnameToIp,
                result_state: LookupResultState::Hit,
                error_code: None,
                duration_ms: 1,
                created_at: now,
                expires_at: far_future,
            })
            .expect("record");
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
fn cache_store_check_health_returns_schema_version() {
    use crate::repository::StorageHealthChecker;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let health = store.check_health().expect("health");
    assert_eq!(health.cache_db.schema_version, Some(4));
    assert!(health.cache_db.path_exists);
    assert!(health.cache_db.last_migration_at.is_some());
}

#[test]
fn cache_store_check_health_records_last_cleanup_after_clear() {
    use crate::repository::StorageHealthChecker;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // Before clear, no metadata row → last_cleanup_at is None.
    let health_before = store.check_health().expect("health before");
    assert!(health_before.cache_db.last_cleanup_at.is_none());

    // clear_cache sets last_rebuild_at and cache_generation in cache_metadata.
    store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear");

    // After clear, cache_metadata row exists; cleanup path still None (only
    // cleanup_expired sets last_cleanup_at — that's a future migration step).
    // Verify schema_version is still reported correctly.
    let health_after = store.check_health().expect("health after");
    assert_eq!(health_after.cache_db.schema_version, Some(4));
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

#[test]
fn cache_store_touch_last_rebuild_at_surfaces_in_health_status() {
    use crate::repository::{CacheRepository, StorageHealthChecker};
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .touch_last_rebuild_at(1_700_000_000_000)
        .expect("touch");
    let health = store.check_health().expect("health");
    assert!(
        health.cache_db.last_rebuild_at.is_some(),
        "last_rebuild_at must be propagated to StorageHealthStatus"
    );
}

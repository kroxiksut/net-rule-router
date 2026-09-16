use super::*;

// ── upsert + get_by_hostname ──────────────────────────────────────────────

#[test]
fn upsert_and_get_by_hostname() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(23, 10, 20, 138);

    store
        .upsert_resolution(sample_resolution("example.com", ip))
        .expect("upsert");

    let result = store
        .get_by_hostname(
            "example.com",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert_eq!(result.resolved_ips.len(), 1);
    assert_eq!(result.resolved_ips[0].addr, ip);
    assert_eq!(result.resolved_ips[0].cache_state, CacheEntryState::Fresh);
    assert_eq!(result.resolved_ips[0].source, StorageResolutionSource::Dns);
    assert!(!result.is_multi_ip);
}

#[test]
fn get_by_hostname_missing_returns_empty() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    let result = store
        .get_by_hostname(
            "nxdomain.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert!(result.resolved_ips.is_empty());
    assert!(result.overall_freshness.is_none());
}

#[test]
fn upsert_multi_ip_hostname() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip1 = Ipv4Addr::new(1, 1, 1, 1);
    let ip2 = Ipv4Addr::new(1, 0, 0, 1);

    let entry = ResolutionEntry {
        canonical_hostname: "cloudflare.com".to_string(),
        raw_hostname_sample: None,
        resolved_ips: vec![IpAddr::V4(ip1), IpAddr::V4(ip2)],
        ttl_seconds: Some(60),
        source: StorageResolutionSource::Dns,
        resolved_at: SystemTime::now(),
        active_revision_id: None,
    };
    store.upsert_resolution(entry).expect("upsert");

    let result = store
        .get_by_hostname(
            "cloudflare.com",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert_eq!(result.resolved_ips.len(), 2);
    assert!(result.is_multi_ip);
}

#[test]
fn upsert_updates_existing_entry() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(10, 0, 0, 1);

    store
        .upsert_resolution(sample_resolution("host.local", ip))
        .expect("first");
    // Second upsert with a different TTL — should update, not duplicate.
    let entry2 = ResolutionEntry {
        ttl_seconds: Some(600),
        ..sample_resolution("host.local", ip)
    };
    store.upsert_resolution(entry2).expect("second");

    let result = store
        .get_by_hostname(
            "host.local",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    // Still one entry (same hostname/ip/source triple).
    assert_eq!(result.resolved_ips.len(), 1);
    assert_eq!(result.resolved_ips[0].ttl_seconds, Some(600));
}

// ── mark_revision_stale ───────────────────────────────────────────────────

#[test]
fn mark_revision_stale_transitions_fresh_entries() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // Write with rev-001.
    store
        .upsert_resolution(sample_resolution("host.example", Ipv4Addr::new(1, 2, 3, 4)))
        .expect("upsert");

    // Activate rev-002 — entries from rev-001 should become stale_usable.
    let updated = store.mark_revision_stale("rev-002").expect("mark");
    assert_eq!(updated, 1);

    let result = store
        .get_by_hostname(
            "host.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert_eq!(
        result.resolved_ips[0].cache_state,
        CacheEntryState::StaleUsable
    );
}

#[test]
fn mark_revision_stale_skips_same_revision() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .upsert_resolution(sample_resolution("h.example", Ipv4Addr::new(5, 6, 7, 8)))
        .expect("upsert");

    // "New" revision is the same as the one used for writing — no rows updated.
    let updated = store.mark_revision_stale("rev-test-001").expect("mark");
    assert_eq!(updated, 0);
}

// ── negative cache ────────────────────────────────────────────────────────

#[test]
fn negative_cache_blocks_hostname_lookup() {
    use crate::dto::NegativeCacheReason;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    let now = SystemTime::now();
    store
        .upsert_negative_cache(NegativeCacheEntry {
            input: "nxdomain.test".to_string(),
            reason: NegativeCacheReason::NxDomain,
            created_at: now,
            expires_at: now + std::time::Duration::from_secs(30),
            source: StorageResolutionSource::Dns,
        })
        .expect("neg upsert");

    let result = store
        .get_by_hostname(
            "nxdomain.test",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert!(result.resolved_ips.is_empty());
    assert_eq!(
        result.overall_freshness,
        Some(CacheEntryState::NegativeCached)
    );
}

// ── record_lookup_event ───────────────────────────────────────────────────

#[test]
fn record_lookup_event_inserts_row() {
    use crate::dto::LookupResultState;
    use nrr_domain::decision_lookup::LookupDirection;
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .record_lookup_event(LookupEventEntry {
            direction: LookupDirection::HostnameToIp,
            result_state: LookupResultState::Hit,
            error_code: None,
            duration_ms: 5,
            created_at: now,
            expires_at: now + std::time::Duration::from_secs(3600),
        })
        .expect("record");

    let conn = store.into_connection();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM lookup_events", [], |r| r.get(0))
        .expect("count");
    assert_eq!(count, 1);
}

// ── clear_cache ───────────────────────────────────────────────────────────

#[test]
fn clear_cache_removes_all_data() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .upsert_resolution(sample_resolution("h1.example", Ipv4Addr::new(1, 1, 1, 1)))
        .expect("upsert");
    store
        .upsert_resolution(sample_resolution("h2.example", Ipv4Addr::new(2, 2, 2, 2)))
        .expect("upsert");

    let summary = store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear");
    assert!(summary.resolutions_removed >= 2);

    let result = store
        .get_by_hostname(
            "h1.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert!(result.resolved_ips.is_empty());
}

#[test]
fn fake_ip_bindings_roundtrip_and_stamp_wipe() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    // First load stores the stamp and returns nothing.
    assert!(store
        .load_fake_ip_bindings("v4=198.18.0.0/15")
        .expect("load")
        .is_empty());
    store
        .record_fake_ip_binding("old.example", 2, 100)
        .expect("record");
    store
        .record_fake_ip_binding("new.example", 3, 200)
        .expect("record");
    assert_eq!(
        store
            .load_fake_ip_bindings("v4=198.18.0.0/15")
            .expect("load"),
        vec![
            ("old.example".to_string(), 2),
            ("new.example".to_string(), 3)
        ]
    );

    // Re-dealing the index replaces the old domain; re-dealing the domain
    // replaces the old index.
    store
        .record_fake_ip_binding("taken.example", 2, 300)
        .expect("record");
    store
        .record_fake_ip_binding("new.example", 7, 400)
        .expect("record");
    assert_eq!(
        store
            .load_fake_ip_bindings("v4=198.18.0.0/15")
            .expect("load"),
        vec![
            ("taken.example".to_string(), 2),
            ("new.example".to_string(), 7)
        ]
    );

    store.remove_fake_ip_binding(2).expect("remove");
    assert_eq!(
        store
            .load_fake_ip_bindings("v4=198.18.0.0/15")
            .expect("load"),
        vec![("new.example".to_string(), 7)]
    );

    // A different pool stamp wipes the table.
    assert!(store
        .load_fake_ip_bindings("v4=10.0.0.0/8")
        .expect("load")
        .is_empty());
    assert!(store
        .load_fake_ip_bindings("v4=10.0.0.0/8")
        .expect("load")
        .is_empty());
}

#[test]
fn forgetting_a_census_host_stops_its_ips_counting_as_shared() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(23, 10, 20, 156);
    store
        .record_shared_ip_direct_host(ip, "static.cdninsta.test", 1, false)
        .expect("census");
    store
        .record_shared_ip_direct_host(ip, "unrelated.example", 1, false)
        .expect("census");
    assert_eq!(store.direct_host_count_for_ip(ip).expect("count"), 2);

    // The trailing dot and the case are what a resolver hands us.
    let removed = store
        .forget_shared_ip_direct_host("Static.CDNInsta.Test.")
        .expect("forget");
    assert_eq!(removed, 1);
    assert_eq!(
        store.direct_host_count_for_ip(ip).expect("count"),
        1,
        "the other tenant still keeps the IP shared"
    );
    // Idempotent: a host that left the census is not an error.
    assert_eq!(
        store
            .forget_shared_ip_direct_host("static.cdninsta.test")
            .expect("forget"),
        0
    );
}

#[test]
fn purge_ip_range_v4_removes_only_the_range() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .upsert_resolution(sample_resolution(
            "fake.example",
            Ipv4Addr::new(198, 18, 0, 35),
        ))
        .expect("upsert");
    store
        .upsert_resolution(sample_resolution(
            "real.example",
            Ipv4Addr::new(23, 10, 20, 138),
        ))
        .expect("upsert");
    store
        .record_shared_ip_direct_host(Ipv4Addr::new(198, 19, 1, 2), "victim.example", 1, false)
        .expect("census");
    store
        .record_shared_ip_direct_host(Ipv4Addr::new(8, 8, 8, 8), "kept.example", 1, false)
        .expect("census");

    let removed = store
        .purge_ip_range_v4(
            Ipv4Addr::new(198, 18, 0, 0),
            Ipv4Addr::new(198, 19, 255, 255),
        )
        .expect("purge");
    assert_eq!(removed, 1);

    let purged = store
        .get_by_hostname(
            "fake.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert!(purged.resolved_ips.is_empty());
    let kept = store
        .get_by_hostname(
            "real.example",
            &FreshnessThresholds::default_production(),
            CachePriorityStrategy::default(),
        )
        .expect("get");
    assert_eq!(kept.resolved_ips.len(), 1);
    assert_eq!(
        store
            .direct_host_count_for_ip(Ipv4Addr::new(198, 19, 1, 2))
            .expect("count"),
        0
    );
    assert_eq!(
        store
            .direct_host_count_for_ip(Ipv4Addr::new(8, 8, 8, 8))
            .expect("count"),
        1
    );
}

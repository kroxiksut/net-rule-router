use super::*;

// ── upsert + get_by_hostname ──────────────────────────────────────────────

#[test]
fn upsert_and_get_by_hostname() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(203, 0, 113, 138);

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
    let ip1 = Ipv4Addr::new(198, 51, 100, 1);
    let ip2 = Ipv4Addr::new(1, 0, 0, 1);

    let entry = ResolutionEntry {
        canonical_hostname: "cdn.example.com".to_string(),
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
            "cdn.example.com",
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

// ── clear_cache ───────────────────────────────────────────────────────────

#[test]
fn clear_cache_removes_all_data() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);

    store
        .upsert_resolution(sample_resolution(
            "h1.example",
            Ipv4Addr::new(198, 51, 100, 1),
        ))
        .expect("upsert");
    store
        .upsert_resolution(sample_resolution(
            "h2.example",
            Ipv4Addr::new(198, 51, 100, 2),
        ))
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
    let ip = Ipv4Addr::new(203, 0, 113, 156);
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
            Ipv4Addr::new(203, 0, 113, 138),
        ))
        .expect("upsert");
    store
        .record_shared_ip_direct_host(Ipv4Addr::new(198, 19, 1, 2), "victim.example", 1, false)
        .expect("census");
    store
        .record_shared_ip_direct_host(Ipv4Addr::new(198, 51, 100, 8), "kept.example", 1, false)
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
            .direct_host_count_for_ip(Ipv4Addr::new(198, 51, 100, 8))
            .expect("count"),
        1
    );
}

#[test]
fn an_unreadable_census_row_fails_the_read_instead_of_shrinking_it() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    store
        .record_shared_ip_direct_host(Ipv4Addr::new(192, 0, 2, 7), "ok.example", 1, true)
        .expect("census");
    store
        .conn
        .borrow()
        .execute(
            "INSERT INTO shared_ip_direct_hosts (ipv4_packed, hostname, last_seen, primary_ruled)
             VALUES ('not-an-address', 'broken.example', 1, 1)",
            [],
        )
        .expect("broken row");

    assert!(store.shared_ip_census_primary_ruled_ips().is_err());
    assert!(store.shared_ip_census_ips().is_err());
}

#[test]
fn cleanup_ages_out_census_tenants_not_seen_within_the_policy() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();
    let now_ms = system_time_to_ms(now);
    let max_age_secs = crate::dto::CleanupPolicy::default().max_shared_ip_direct_host_age_secs;
    let (stale, live) = (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2));
    let stale_ms = now_ms - max_age_secs as i64 * 1_000 - 1;
    store
        .record_shared_ip_direct_host(stale, "stale.example", stale_ms, false)
        .expect("census");
    store
        .record_shared_ip_direct_host(live, "live.example", now_ms - 1_000, false)
        .expect("census");

    let summary = store
        .cleanup_expired(now, &crate::dto::CleanupPolicy::default())
        .expect("cleanup");

    assert_eq!(summary.shared_ip_direct_hosts_removed, 1);
    assert_eq!(store.direct_host_count_for_ip(stale).expect("count"), 0);
    assert_eq!(store.direct_host_count_for_ip(live).expect("count"), 1);
}

#[test]
fn clear_cache_empties_the_census() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(192, 0, 2, 3);
    store
        .record_shared_ip_direct_host(ip, "tenant.example", 1, true)
        .expect("census");

    let summary = store
        .clear_cache(CacheResetReason::ManualUserReset)
        .expect("clear");

    assert_eq!(summary.shared_ip_direct_hosts_removed, 1);
    assert!(store.shared_ip_census_ips().expect("census").is_empty());
    assert!(store
        .shared_ip_census_primary_ruled_ips()
        .expect("census")
        .is_empty());
}

// ── names_for_address ─────────────────────────────────────────────────────

fn resolution_at(hostname: &str, ip: IpAddr, at: SystemTime) -> ResolutionEntry {
    ResolutionEntry {
        canonical_hostname: hostname.to_string(),
        raw_hostname_sample: None,
        resolved_ips: vec![ip],
        ttl_seconds: Some(300),
        source: StorageResolutionSource::Dns,
        resolved_at: at,
        active_revision_id: None,
    }
}

#[test]
fn an_address_is_named_newest_first_with_census_tenants_and_a_total() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(192, 0, 2, 40);
    let now = SystemTime::now();
    let ago = |secs: u64| now - std::time::Duration::from_secs(secs);
    for (host, at) in [
        ("old.example", ago(300)),
        ("new.example", ago(10)),
        ("mid.example", ago(60)),
    ] {
        store
            .upsert_resolution(resolution_at(host, IpAddr::V4(ip), at))
            .expect("upsert");
    }
    let tenant_ms = system_time_to_ms(ago(30));
    store
        .record_shared_ip_direct_host(ip, "tenant.example", tenant_ms, false)
        .expect("census");
    // A neighbour address is somebody else's business.
    store
        .upsert_resolution(sample_resolution(
            "neighbour.example",
            Ipv4Addr::new(192, 0, 2, 41),
        ))
        .expect("upsert");

    let named = store
        .names_for_address(IpAddr::V4(ip), ago(3_600), 3)
        .expect("names");
    assert_eq!(
        named.names,
        vec!["new.example", "tenant.example", "mid.example"],
        "most recently seen first, census tenants interleaved by recency"
    );
    assert_eq!(named.total, 4, "the limit trims the list, never the count");
}

#[test]
fn a_name_not_seen_since_the_cutoff_does_not_name_the_address() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
    let now = SystemTime::now();
    store
        .upsert_resolution(resolution_at(
            "gone.example",
            ip,
            now - std::time::Duration::from_secs(7_200),
        ))
        .expect("upsert");
    store
        .upsert_resolution(resolution_at("here.example", ip, now))
        .expect("upsert");

    let named = store
        .names_for_address(ip, now - std::time::Duration::from_secs(3_600), 8)
        .expect("names");
    assert_eq!(named.names, vec!["here.example"]);
    assert_eq!(named.total, 1);
}

#[test]
fn an_unknown_address_has_no_names_and_v6_is_looked_up_in_its_own_family() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let v6: IpAddr = "2001:db8::7".parse().expect("v6");
    let now = SystemTime::now();
    store
        .upsert_resolution(resolution_at("dual.example", v6, now))
        .expect("upsert");
    let since = now - std::time::Duration::from_secs(60);

    let named = store.names_for_address(v6, since, 8).expect("names");
    assert_eq!(named.names, vec!["dual.example"]);
    assert_eq!(named.total, 1);

    let none = store
        .names_for_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), since, 8)
        .expect("names");
    assert!(none.names.is_empty());
    assert_eq!(none.total, 0);

    // A zero limit still reports how many there are.
    let counted = store.names_for_address(v6, since, 0).expect("names");
    assert!(counted.names.is_empty());
    assert_eq!(counted.total, 1);
}

/// Asked once per newly seen connection address, so a full scan here would
/// grow with the cache. The plan must reach every table through an index.
#[test]
fn naming_an_address_never_scans_a_table() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let conn = store.conn.borrow();
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {NAMES_FOR_ADDRESS_SQL}"))
        .expect("plan");
    let steps: Vec<String> = stmt
        .query_map(
            params!["v4", "192.0.2.1", 0_i64, 3_221_225_985_i64, 8_i64],
            |r| r.get::<_, String>(3),
        )
        .expect("query")
        .map(|r| r.expect("row"))
        .collect();
    // Base tables appear under their alias; CTE and window co-routines are
    // scans of a handful of in-memory rows and do not count.
    for name in ["a", "r", "h", "shared_ip_direct_hosts"] {
        assert!(
            steps
                .iter()
                .any(|s| s.starts_with(&format!("SEARCH {name} "))),
            "{name} is not searched by index: {steps:?}"
        );
        assert!(
            !steps.iter().any(|s| s.starts_with(&format!("SCAN {name}"))),
            "{name} is scanned: {steps:?}"
        );
    }
}

/// Every DNS answer restamps the pairs it repeats; only a pair that was not
/// held moves the generation, or an idle pass would re-plan on each answer.
#[test]
fn only_news_moves_the_change_generation() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let ip = Ipv4Addr::new(203, 0, 113, 7);

    let start = store.change_generation().expect("generation");
    store
        .upsert_resolution(sample_resolution("news.example", ip))
        .expect("first");
    let after_new = store.change_generation().expect("generation");
    assert_ne!(after_new, start, "a new pair did not move it");

    store
        .upsert_resolution(sample_resolution("news.example", ip))
        .expect("restamp");
    assert_eq!(
        store.change_generation(),
        Some(after_new),
        "a restamp of a held pair moved it"
    );

    store
        .upsert_resolution(sample_resolution(
            "news.example",
            Ipv4Addr::new(203, 0, 113, 8),
        ))
        .expect("second address");
    let after_second = store.change_generation().expect("generation");
    assert_ne!(after_second, after_new, "a new address did not move it");

    store
        .record_shared_ip_direct_host(ip, "tenant.example", 1, false)
        .expect("census");
    let after_census = store.change_generation().expect("generation");
    assert_ne!(
        after_census, after_second,
        "a new census tenant did not move it"
    );
    store
        .record_shared_ip_direct_host(ip, "tenant.example", 2, false)
        .expect("census restamp");
    assert_eq!(store.change_generation(), Some(after_census));
}

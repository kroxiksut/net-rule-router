use super::*;

// ── integrity checks ─────────────────────────────────────────────────────

/// A signed revision row, written the way production writes one.
fn seed_signed_revision(conn: &Connection, key: &[u8], revision_id: &str, status: &str) {
    let repo = crate::revisions::RevisionsRepository::with_signing_key(conn, key.to_vec());
    repo.insert_candidate_for(
        crate::BASELINE_PRINCIPAL,
        &crate::revisions::RevisionRecord {
            revision_id: revision_id.to_string(),
            content_hash: format!("{revision_id}-hash"),
            rules_json: "{}".to_string(),
            status: nrr_domain::rules_revision::RevisionStatus::Candidate,
            source: nrr_domain::rules_revision::RulesRevisionSource::GuiRulesEdit,
            correlation_id: "c".to_string(),
            created_at: 0,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: None,
        },
    )
    .expect("seed signed revision");
    conn.execute(
        "UPDATE revisions SET status = ?2, superseded_at = 1 WHERE revision_id = ?1",
        params![revision_id, status],
    )
    .expect("set status");
    // The status is part of the signed payload, so a direct UPDATE
    // invalidates the row's signature exactly as tampering would. Production
    // re-signs on every status change; the fixture does the same, otherwise
    // every test row would read as tampered.
    repo.re_sign_row(revision_id).expect("re-sign");
}

const TEST_SIGNING_KEY: &[u8] = b"integrity-test-key-0123456789abcdef";

#[test]
fn state_store_check_integrity_ok_with_signed_rows() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir).with_signing_key(TEST_SIGNING_KEY.to_vec());
    {
        let conn = store.conn.borrow();
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-valid-001", "active");
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-valid-000", "superseded");
    }
    point_baseline(&store, "rev-valid-001").expect("set active");

    let (result, action) = store.check_integrity().expect("check");
    assert_eq!(result, IntegrityCheckResult::Ok);
    assert_eq!(action, RecoveryAction::None);
}

/// The check now protects the row the ENFORCEMENT path reads, so editing
/// that row behind the service's back is what it must catch.
#[test]
fn state_store_check_integrity_detects_a_tampered_active_row() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir).with_signing_key(TEST_SIGNING_KEY.to_vec());
    {
        let conn = store.conn.borrow();
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-tamper-001", "active");
        conn.execute(
            "UPDATE revisions SET rules_json = '{\"tampered\":true}' WHERE revision_id = ?1",
            params!["rev-tamper-001"],
        )
        .expect("tamper");
    }
    point_baseline(&store, "rev-tamper-001").expect("set active");

    let (result, action) = store.check_integrity().expect("check");
    assert!(
        matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
        "an edited active row must yield PolicyIntegrityFailed, got {result:?}"
    );
    assert_eq!(action, RecoveryAction::FallbackToLastKnownGood);
}

#[test]
fn state_store_check_integrity_detects_a_tampered_rollback_target() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir).with_signing_key(TEST_SIGNING_KEY.to_vec());
    {
        let conn = store.conn.borrow();
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-lkg-tamper", "superseded");
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-active-002", "active");
        conn.execute(
            "UPDATE revisions SET rules_json = '{\"tampered\":true}' WHERE revision_id = ?1",
            params!["rev-lkg-tamper"],
        )
        .expect("tamper lkg");
    }
    point_baseline(&store, "rev-active-002").expect("set active");

    let (result, action) = store.check_integrity().expect("check");
    assert!(
        matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
        "an edited rollback target must yield PolicyIntegrityFailed, got {result:?}"
    );
    // The target itself is suspect — falling back to it would install
    // edited policy.
    assert!(
        matches!(action, RecoveryAction::RequireUserAction(_)),
        "corrupt LKG must require user action, got {action:?}"
    );
}

/// Deleting the active row leaves no signature to fail; the pointer that
/// still names it is the only trace, and it needs no key to see.
#[test]
fn state_store_check_integrity_fails_on_a_pointer_to_a_deleted_revision() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    seed_revision(&store, "rev-deleted", "active");
    point_baseline(&store, "rev-deleted").expect("set active");
    {
        let conn = store.conn.borrow();
        conn.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DELETE FROM revisions WHERE revision_id = 'rev-deleted';
             PRAGMA foreign_keys = ON;",
        )
        .expect("external delete");
    }

    let (result, action) = store.check_integrity().expect("check");
    assert!(
        matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
        "a pointer to a missing revision must fail, got {result:?}"
    );
    assert_eq!(action, RecoveryAction::FallbackToLastKnownGood);
}

/// Moving the pointer onto an older, validly signed row passes every row
/// check; only the pointer's own signature catches it.
#[test]
fn state_store_check_integrity_detects_a_redirected_pointer() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir).with_signing_key(TEST_SIGNING_KEY.to_vec());
    {
        let conn = store.conn.borrow();
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-old-001", "superseded");
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-new-002", "active");
    }
    point_baseline(&store, "rev-new-002").expect("set active");
    {
        let conn = store.conn.borrow();
        conn.execute(
            "UPDATE active_revision_pointer SET revision_id = 'rev-old-001'",
            [],
        )
        .expect("redirect pointer");
    }

    let (result, _) = store.check_integrity().expect("check");
    assert!(
        matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
        "a redirected pointer must fail, got {result:?}"
    );
}

#[test]
fn state_store_check_integrity_is_ok_with_nothing_to_roll_back_to() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    seed_revision(&store, "rev-no-lkg", "active");
    // The very first revision: nothing superseded behind it.
    point_baseline(&store, "rev-no-lkg").expect("set active");

    let (result, action) = store.check_integrity().expect("check");
    assert_eq!(result, IntegrityCheckResult::Ok);
    assert_eq!(action, RecoveryAction::None);
}

/// Every principal's rollback target is checked, not only the baseline's.
#[test]
fn state_store_check_integrity_checks_the_rollback_target_of_every_principal() {
    const OTHER: &str = "S-1-5-21-1000-1000-1000-1001";
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir).with_signing_key(TEST_SIGNING_KEY.to_vec());
    {
        let conn = store.conn.borrow();
        seed_signed_revision(&conn, TEST_SIGNING_KEY, "rev-base-001", "active");
        let repo = crate::revisions::RevisionsRepository::with_signing_key(
            &conn,
            TEST_SIGNING_KEY.to_vec(),
        );
        for (id, status) in [("rev-other-old", "superseded"), ("rev-other-new", "active")] {
            conn.execute(
                "INSERT INTO revisions (principal, revision_id, content_hash, rules_json,
                                        status, source, correlation_id, created_at, superseded_at)
                 VALUES (?1, ?2, ?2, '{}', ?3, 'gui-rules-edit', 'c', 0, 1)",
                params![OTHER, id, status],
            )
            .expect("seed other principal");
            repo.re_sign_row(id).expect("sign");
        }
        repo.set_active_pointer_for(
            OTHER,
            &crate::revisions::ActiveRevisionPointer {
                revision_id: "rev-other-new".to_string(),
                activated_at: 1,
                apply_attempt_id: None,
            },
        )
        .expect("point other");
    }
    point_baseline(&store, "rev-base-001").expect("set active");
    assert_eq!(
        store.check_integrity().expect("check").0,
        IntegrityCheckResult::Ok,
        "positive control: both principals clean"
    );

    store
        .conn
        .borrow()
        .execute(
            "UPDATE revisions SET rules_json = '{\"tampered\":true}' WHERE revision_id = 'rev-other-old'",
            [],
        )
        .expect("tamper");
    let (result, action) = store.check_integrity().expect("check");
    assert!(
        matches!(result, IntegrityCheckResult::PolicyIntegrityFailed { .. }),
        "got {result:?}"
    );
    assert!(matches!(action, RecoveryAction::RequireUserAction(_)));
}

#[test]
fn state_store_check_integrity_detects_bad_revision_format() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);

    // A revision row whose id is not a valid `RevisionId`, plus the pointer
    // that names it. Written directly: every production path validates the
    // format, and this test is about what happens when something bypassed
    // them (a hand-edited database, a partially-applied migration).
    {
        let conn = store.conn.borrow();
        conn.execute(
                "INSERT INTO revisions (principal, revision_id, content_hash, rules_json,
                                        status, source, correlation_id, created_at)
                 VALUES (?1, 'NOT_A_VALID_REVISION', 'h', '{}', 'active', 'gui-rules-edit', 'c', 0)",
                params![crate::BASELINE_PRINCIPAL],
            )
            .expect("inject bad revision");
        conn.execute(
            "INSERT INTO active_revision_pointer (principal, revision_id, activated_at)
                 VALUES (?1, 'NOT_A_VALID_REVISION', 0)",
            params![crate::BASELINE_PRINCIPAL],
        )
        .expect("inject bad pointer");
    }

    let (result, action) = store.check_integrity().expect("check");
    assert!(matches!(
        result,
        IntegrityCheckResult::PolicyIntegrityFailed { .. }
    ));
    assert_eq!(action, RecoveryAction::FallbackToLastKnownGood);
}

#[test]
fn cache_store_check_cache_integrity_ok_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let (result, action) = store.check_cache_integrity().expect("check");
    assert_eq!(result, IntegrityCheckResult::Ok);
    assert_eq!(action, RecoveryAction::None);
}

// ── get_cache_stats ───────────────────────────────────────────────────────

#[test]
fn get_cache_stats_zero_on_fresh_db() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let stats = store.get_cache_stats().expect("stats");

    assert_eq!(stats.hostname_count, 0);
    assert_eq!(stats.ip_count, 0);
    assert_eq!(stats.resolution_count, 0);
    assert_eq!(stats.stale_resolution_count, 0);
    assert_eq!(stats.negative_cache_count, 0);
    assert_eq!(stats.lookup_events_count, 0);
    assert_eq!(stats.cache_generation, 0);
}

#[test]
fn get_cache_stats_counts_all_entities() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "alpha.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert alpha");

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "beta.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
            ttl_seconds: Some(60),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert beta");

    let stats = store.get_cache_stats().expect("stats");
    assert_eq!(stats.hostname_count, 2, "two distinct hostnames");
    assert_eq!(
        stats.ip_count, 3,
        "three distinct IPs across both hostnames"
    );
    assert_eq!(
        stats.resolution_count, 3,
        "three hostname→IP resolution rows"
    );
    assert_eq!(stats.stale_resolution_count, 0, "none stale yet");
    assert_eq!(stats.cache_generation, 0, "no clear yet");
}

#[test]
fn get_cache_stats_counts_stale_entries() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "example.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert");

    // Entries written under an older revision, as the cache marks them.
    store
        .conn
        .borrow()
        .execute(
            "UPDATE hostname_ip_resolutions SET freshness_state = 'stale_usable'",
            [],
        )
        .expect("mark stale");

    let stats = store.get_cache_stats().expect("stats");
    assert_eq!(stats.resolution_count, 1, "entry still exists");
    assert_eq!(stats.stale_resolution_count, 1, "entry is stale");
}

// ── list_resolutions ──────────────────────────────────────────────────────

#[test]
fn list_resolutions_orders_and_respects_offset_limit_and_has_more() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "alpha.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            ],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert alpha");
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "beta.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
            ttl_seconds: Some(60),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert beta");

    // Full window: fetches limit+1 but only 3 rows exist. Ordered by
    // (canonical_host, canonical_ip): 192.0.2.1 sorts before 198.51.100.1.
    let all = store.list_resolutions(0, 10, "").expect("list all");
    assert_eq!(all.len(), 3, "three resolution rows exist");
    assert_eq!(all[0].canonical_hostname, "alpha.test");
    assert_eq!(all[0].canonical_ip, "192.0.2.1");
    assert_eq!(all[0].freshness_state, "fresh");
    assert_eq!(all[0].source, "dns");
    assert_eq!(all[1].canonical_hostname, "alpha.test");
    assert_eq!(all[1].canonical_ip, "198.51.100.1");
    assert_eq!(all[2].canonical_hostname, "beta.test");
    assert_eq!(all[2].canonical_ip, "198.51.100.2");

    // First page of size 2: fetches 3 (limit+1) so the caller sees a
    // "has more" probe row beyond the requested two.
    let page1 = store.list_resolutions(0, 2, "").expect("page 1");
    assert_eq!(page1.len(), 3, "limit+1 fetched → caller detects more");
    assert!(page1.len() as u32 > 2, "more pages available");
    assert_eq!(page1[0].canonical_ip, "192.0.2.1");
    assert_eq!(page1[1].canonical_ip, "198.51.100.1");

    // Second page (offset 2): only the last row remains, no probe row.
    let page2 = store.list_resolutions(2, 2, "").expect("page 2");
    assert_eq!(page2.len(), 1, "last row only, no further pages");
    assert_eq!(page2[0].canonical_hostname, "beta.test");

    // Zero limit short-circuits.
    assert!(store
        .list_resolutions(0, 0, "")
        .expect("zero limit")
        .is_empty());
}

// Server-side query filters on host OR IP, case-insensitive,
// with LIKE metacharacters escaped so a literal search stays literal.
#[test]
fn list_resolutions_filters_by_query_on_host_or_ip() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "alpha.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert alpha");
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "beta.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2))],
            ttl_seconds: Some(60),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert beta");

    // EXACT host match by default (query contains a
    // dot), case-insensitive.
    let by_host = store
        .list_resolutions(0, 10, "ALPHA.test")
        .expect("by host");
    assert_eq!(by_host.len(), 1);
    assert_eq!(by_host[0].canonical_hostname, "alpha.test");
    // A bare token (no dot, no `*`) is an implicit
    // substring so single-word searches find their hosts.
    let bare = store
        .list_resolutions(0, 10, "ALPHA")
        .expect("bare fragment");
    assert_eq!(bare.len(), 1, "bare token substring-matches its host");
    assert_eq!(bare[0].canonical_hostname, "alpha.test");

    // `*` is the user-facing wildcard: `*alpha*` restores substring; a
    // suffix pattern lists everything under the zone.
    let by_wild = store.list_resolutions(0, 10, "*ALPHA*").expect("wild");
    assert_eq!(by_wild.len(), 1);
    assert_eq!(by_wild[0].canonical_hostname, "alpha.test");
    let by_suffix = store.list_resolutions(0, 10, "*.test").expect("suffix");
    assert_eq!(by_suffix.len(), 2, "alpha.test + beta.test");

    // Exact IP match; a bare IP fragment does not match.
    let by_ip = store.list_resolutions(0, 10, "203.0.113.2").expect("by ip");
    assert_eq!(by_ip.len(), 1);
    assert_eq!(by_ip[0].canonical_hostname, "beta.test");
    assert!(store
        .list_resolutions(0, 10, "203.0.113")
        .expect("ip fragment")
        .is_empty());

    // No match.
    assert!(store
        .list_resolutions(0, 10, "nonexistent")
        .expect("no match")
        .is_empty());

    // LIKE metacharacters are escaped → treated literally (no row contains '%').
    assert!(store
        .list_resolutions(0, 10, "%")
        .expect("literal percent")
        .is_empty());
}

use super::*;

// ── integrity checks ─────────────────────────────────────────────────────

/// Seed the legacy singleton rows `check_integrity` still verifies.
///
/// They are seeded by SQL because nothing in the product writes them any
/// more: `set_active_revision` now writes `active_revision_pointer`, where
/// the readers look, and the LKG is derived from `revisions`. The checks
/// below therefore cover code that is still present, over data that is no
/// longer produced — see the open half of §36.12.2 (moving tamper detection
/// onto `revisions.row_hmac`).
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
    let rev = RevisionId::from_prefixed_string("rev-valid-001".to_string()).expect("rev");
    store.set_active_revision(&rev).expect("set active");

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
    let rev = RevisionId::from_prefixed_string("rev-tamper-001".to_string()).expect("rev");
    store.set_active_revision(&rev).expect("set active");

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
    let rev = RevisionId::from_prefixed_string("rev-active-002".to_string()).expect("rev");
    store.set_active_revision(&rev).expect("set active");

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

#[test]
fn state_store_check_integrity_missing_lkg_returns_ok_on_first_start() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_state_store(&dir);
    let rev = RevisionId::from_prefixed_string("rev-no-lkg".to_string()).expect("rev");
    seed_revision(&store, "rev-no-lkg", "active");

    // The very first revision: active, and nothing superseded behind it,
    // so there is no rollback target yet.
    store.set_active_revision(&rev).expect("set active");
    assert!(store.get_last_known_good().expect("lkg").is_none());

    let (result, action) = store.check_integrity().expect("check");
    // Not a failure — just means rollback is unsafe until LKG is promoted.
    assert_eq!(
        result,
        IntegrityCheckResult::OkNoRollbackTarget,
        "reported as its own state, not as an indistinguishable Ok"
    );
    assert_eq!(action, RecoveryAction::None);
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
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
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
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
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
fn get_cache_stats_stale_count_after_revision_change() {
    let dir = tempfile::tempdir().expect("tmp");
    let store = migrated_cache_store(&dir);
    let now = SystemTime::now();

    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "example.test".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert");

    let staled = store.mark_revision_stale("rev-002").expect("mark stale");
    assert_eq!(staled, 1);

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
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
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
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
            ttl_seconds: Some(60),
            source: StorageResolutionSource::Dns,
            resolved_at: now,
            active_revision_id: Some("rev-001".into()),
        })
        .expect("upsert beta");

    // Full window: fetches limit+1 but only 3 rows exist. Ordered by
    // (canonical_host, canonical_ip): 1.0.0.1 sorts before 1.1.1.1.
    let all = store.list_resolutions(0, 10, "").expect("list all");
    assert_eq!(all.len(), 3, "three resolution rows exist");
    assert_eq!(all[0].canonical_hostname, "alpha.test");
    assert_eq!(all[0].canonical_ip, "1.0.0.1");
    assert_eq!(all[0].freshness_state, "fresh");
    assert_eq!(all[0].source, "dns");
    assert_eq!(all[1].canonical_hostname, "alpha.test");
    assert_eq!(all[1].canonical_ip, "1.1.1.1");
    assert_eq!(all[2].canonical_hostname, "beta.test");
    assert_eq!(all[2].canonical_ip, "2.2.2.2");

    // First page of size 2: fetches 3 (limit+1) so the caller sees a
    // "has more" probe row beyond the requested two.
    let page1 = store.list_resolutions(0, 2, "").expect("page 1");
    assert_eq!(page1.len(), 3, "limit+1 fetched → caller detects more");
    assert!(page1.len() as u32 > 2, "more pages available");
    assert_eq!(page1[0].canonical_ip, "1.0.0.1");
    assert_eq!(page1[1].canonical_ip, "1.1.1.1");

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
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(20, 0, 0, 2))],
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
    let by_ip = store.list_resolutions(0, 10, "20.0.0.2").expect("by ip");
    assert_eq!(by_ip.len(), 1);
    assert_eq!(by_ip[0].canonical_hostname, "beta.test");
    assert!(store
        .list_resolutions(0, 10, "20.0.0")
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

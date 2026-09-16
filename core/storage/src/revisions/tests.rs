use super::*;
use crate::migration::{open_connection, SqliteMigrationRunner};
use crate::repository::MigrationRunner;
use crate::retention_settings::RetentionSettings;

fn open_state_db(dir: &tempfile::TempDir) -> Connection {
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    runner.into_connection()
}

fn sample_record(id: &str, hash: &str) -> RevisionRecord {
    RevisionRecord {
        revision_id: id.to_string(),
        content_hash: hash.to_string(),
        rules_json: "{}".to_string(),
        status: RevisionStatus::Candidate,
        source: RulesRevisionSource::GuiRulesEdit,
        correlation_id: "corr-123".to_string(),
        created_at: 1_700_000_000,
        activated_at: None,
        superseded_at: None,
        superseded_by: None,
        rejected_reason: None,
        review_summary_json: None,
        risk_level: Some(RiskLevel::Low),
    }
}

#[test]
fn insert_candidate_creates_row_with_candidate_status() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    let rec = sample_record("rev-001", "hash-001");
    repo.insert_candidate(&rec).expect("insert");

    let loaded = repo.get_by_id("rev-001").expect("get").expect("present");
    assert_eq!(loaded.revision_id, "rev-001");
    assert_eq!(loaded.status, RevisionStatus::Candidate);
    assert_eq!(loaded.source, RulesRevisionSource::GuiRulesEdit);
    assert_eq!(loaded.risk_level, Some(RiskLevel::Low));
    assert!(loaded.activated_at.is_none());
}

#[test]
fn insert_rejects_empty_revision_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    let mut rec = sample_record("", "hash");
    rec.revision_id.clear();
    assert!(repo.insert_candidate(&rec).is_err());
}

#[test]
fn find_by_content_hash_returns_inserted_revision() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    let rec = sample_record("rev-002", "hash-xyz");
    repo.insert_candidate(&rec).expect("insert");

    let found = repo
        .find_by_content_hash("hash-xyz")
        .expect("query")
        .expect("present");
    assert_eq!(found.revision_id, "rev-002");
}

#[test]
fn find_by_content_hash_unknown_returns_none() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    assert!(repo
        .find_by_content_hash("never-seen")
        .expect("query")
        .is_none());
}

#[test]
fn mark_apply_succeeded_promotes_candidate_to_active_no_previous() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate(&sample_record("rev-100", "h-100"))
        .expect("insert");
    repo.mark_apply_succeeded("rev-100", None, 1_700_001_000)
        .expect("activate");

    let active = repo.get_active().expect("query").expect("present");
    assert_eq!(active.revision_id, "rev-100");
    assert_eq!(active.status, RevisionStatus::Active);
    assert_eq!(active.activated_at, Some(1_700_001_000));
}

#[test]
fn mark_apply_succeeded_supersedes_previous_active() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // First activation.
    repo.insert_candidate(&sample_record("rev-A", "h-A"))
        .expect("insert A");
    repo.mark_apply_succeeded("rev-A", None, 1_700_000_100)
        .expect("activate A");

    // Second activation supersedes A.
    repo.insert_candidate(&sample_record("rev-B", "h-B"))
        .expect("insert B");
    repo.mark_apply_succeeded("rev-B", Some("rev-A"), 1_700_000_200)
        .expect("activate B");

    let active = repo.get_active().expect("query").expect("present");
    assert_eq!(active.revision_id, "rev-B");

    let previous = repo.get_by_id("rev-A").expect("query").expect("present");
    assert_eq!(previous.status, RevisionStatus::Superseded);
    assert_eq!(previous.superseded_at, Some(1_700_000_200));
    assert_eq!(previous.superseded_by, Some("rev-B".to_string()));
}

#[test]
fn partial_unique_index_blocks_double_active_same_principal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);

    // Bypass the repository and try to insert a second active row for
    // the SAME principal directly.
    conn.execute(
        "INSERT INTO revisions
             (principal, revision_id, content_hash, rules_json, status, source,
              correlation_id, created_at)
             VALUES ('S-1-5-21-A', 'rev-1', 'h-1', '{}', 'active', 'gui-rules-edit', 'c-1', 0)",
        [],
    )
    .expect("first active");

    let result = conn.execute(
        "INSERT INTO revisions
             (principal, revision_id, content_hash, rules_json, status, source,
              correlation_id, created_at)
             VALUES ('S-1-5-21-A', 'rev-2', 'h-2', '{}', 'active', 'gui-rules-edit', 'c-2', 0)",
        [],
    );
    assert!(
        result.is_err(),
        "per-principal partial unique index must reject a second active \
             revision for the same principal"
    );
}

#[test]
fn two_principals_can_each_have_an_active_revision() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a", "h-a"))
        .expect("insert A");
    repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a", None, 100)
        .expect("activate A");

    repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
        .expect("insert B");
    repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 100)
        .expect("activate B");

    // Each principal sees its own active revision; neither leaks into
    // the other.
    assert_eq!(
        repo.get_active_for("S-1-5-21-A")
            .expect("a")
            .expect("present")
            .revision_id,
        "rev-a"
    );
    assert_eq!(
        repo.get_active_for("S-1-5-21-B")
            .expect("b")
            .expect("present")
            .revision_id,
        "rev-b"
    );
    // The baseline principal has nothing.
    assert!(repo
        .get_active_for(BASELINE_PRINCIPAL)
        .expect("baseline")
        .is_none());
}

#[test]
fn reject_orphaned_candidates_rejects_across_principals_leaves_active_untouched() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // An active revision for the baseline principal — must survive the
    // sweep untouched.
    repo.insert_candidate(&sample_record("rev-active", "h-active"))
        .expect("insert active");
    repo.mark_apply_succeeded("rev-active", None, 100)
        .expect("activate");

    // Two orphaned candidates left behind by a simulated hard kill, one
    // per principal.
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-orphan-a", "h-orphan-a"))
        .expect("insert orphan A");
    repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-orphan-b", "h-orphan-b"))
        .expect("insert orphan B");

    let rejected = repo
        .reject_orphaned_candidates("interrupted-before-activation (service restart)", 12345)
        .expect("sweep");
    assert_eq!(rejected, 2);

    let orphan_a = repo
        .get_by_id("rev-orphan-a")
        .expect("query")
        .expect("present");
    assert_eq!(orphan_a.status, RevisionStatus::Rejected);
    assert_eq!(
        orphan_a.rejected_reason.as_deref(),
        Some("interrupted-before-activation (service restart)")
    );

    let orphan_b = repo
        .get_by_id("rev-orphan-b")
        .expect("query")
        .expect("present");
    assert_eq!(orphan_b.status, RevisionStatus::Rejected);
    assert_eq!(
        orphan_b.rejected_reason.as_deref(),
        Some("interrupted-before-activation (service restart)")
    );

    // The active revision was never touched.
    let active = repo.get_active().expect("query").expect("present");
    assert_eq!(active.revision_id, "rev-active");

    // Re-running the sweep finds nothing left to reject.
    let rejected_again = repo
        .reject_orphaned_candidates("interrupted-before-activation (service restart)", 99999)
        .expect("sweep again");
    assert_eq!(rejected_again, 0);
}

#[test]
fn reject_orphaned_candidates_without_key_skips_signed_rows() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);

    let signed = RevisionsRepository::with_signing_key(&conn, hmac_key());
    signed
        .insert_candidate(&sample_record("rev-signed", "h-signed"))
        .expect("insert signed");
    let unsigned = RevisionsRepository::new(&conn);
    unsigned
        .insert_candidate(&sample_record("rev-unsigned", "h-unsigned"))
        .expect("insert unsigned");

    // Keyless sweep: only the unsigned candidate may be touched.
    let rejected = unsigned
        .reject_orphaned_candidates("interrupted-before-activation (service restart)", 1)
        .expect("keyless sweep");
    assert_eq!(rejected, 1);
    let signed_row = signed
        .get_by_id("rev-signed")
        .expect("query")
        .expect("present");
    assert_eq!(signed_row.status, RevisionStatus::Candidate);
    let unsigned_row = signed
        .get_by_id("rev-unsigned")
        .expect("query")
        .expect("present");
    assert_eq!(unsigned_row.status, RevisionStatus::Rejected);

    // The signed row still verifies clean — the keyless sweep must
    // not have staled its HMAC.
    assert_eq!(
        signed.verify_row_hmac("rev-signed").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
    );
}

#[test]
fn reject_orphaned_candidates_with_key_rejects_and_re_signs() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
    repo.insert_candidate(&sample_record("rev-signed", "h-signed"))
        .expect("insert signed");

    let rejected = repo
        .reject_orphaned_candidates("interrupted-before-activation (service restart)", 1)
        .expect("keyed sweep");
    assert_eq!(rejected, 1);

    let row = repo
        .get_by_id("rev-signed")
        .expect("query")
        .expect("present");
    assert_eq!(row.status, RevisionStatus::Rejected);
    // The status flip was re-signed: the row must NOT read as
    // tampered on the next integrity scan.
    assert_eq!(
        repo.verify_row_hmac("rev-signed").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
    );
}

#[test]
fn delete_all_revisions_for_clears_principal_and_resumes_read_through() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // Baseline has an active revision; A diverged with its own.
    repo.insert_candidate_for(BASELINE_PRINCIPAL, &sample_record("base", "h-base"))
        .expect("insert baseline");
    repo.mark_apply_succeeded_for(BASELINE_PRINCIPAL, "base", None, 100)
        .expect("activate baseline");
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a1", "h-a1"))
        .expect("insert A1");
    repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a1", None, 100)
        .expect("activate A1");
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a2", "h-a2"))
        .expect("insert A2 (candidate)");
    repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
        .expect("insert B");
    repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 100)
        .expect("activate B");

    // Reset A: both its active and its candidate rows go.
    let deleted = repo
        .delete_all_revisions_for("S-1-5-21-A")
        .expect("delete A");
    assert_eq!(deleted, 2, "both of A's revisions must be deleted");

    // A has no own revision and no pointer → read-through resumes.
    assert!(repo.get_active_for("S-1-5-21-A").expect("a").is_none());
    assert!(repo
        .get_active_pointer_for("S-1-5-21-A")
        .expect("a ptr")
        .is_none());
    // B and baseline are untouched.
    assert_eq!(
        repo.get_active_for("S-1-5-21-B")
            .expect("b")
            .expect("present")
            .revision_id,
        "rev-b"
    );
    assert_eq!(
        repo.get_active_for(BASELINE_PRINCIPAL)
            .expect("base")
            .expect("present")
            .revision_id,
        "base"
    );
}

#[test]
fn delete_all_revisions_for_refuses_baseline() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    let err = repo
        .delete_all_revisions_for(BASELINE_PRINCIPAL)
        .expect_err("must refuse baseline");
    assert!(matches!(err, StorageError::Internal(_)));
}

#[test]
fn mark_apply_failed_marks_candidate_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate(&sample_record("rev-fail", "h-fail"))
        .expect("insert");
    repo.mark_apply_failed("rev-fail", "WFP failed on SID-A", 1_700_001_500)
        .expect("reject");

    let rec = repo.get_by_id("rev-fail").expect("query").expect("present");
    assert_eq!(rec.status, RevisionStatus::Rejected);
    assert_eq!(rec.rejected_reason, Some("WFP failed on SID-A".to_string()));
}

#[test]
fn mark_apply_failed_on_non_candidate_errors() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate(&sample_record("rev-x", "h-x"))
        .expect("insert");
    repo.mark_apply_succeeded("rev-x", None, 1)
        .expect("activate");
    // Now active — apply_failed should error rather than silently no-op.
    assert!(repo.mark_apply_failed("rev-x", "reason", 2).is_err());
}

#[test]
fn last_known_good_is_most_recent_superseded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // Activate three in sequence so that two are superseded.
    repo.insert_candidate(&sample_record("rev-a", "h-a"))
        .expect("insert a");
    repo.mark_apply_succeeded("rev-a", None, 100).expect("a");

    repo.insert_candidate(&sample_record("rev-b", "h-b"))
        .expect("insert b");
    repo.mark_apply_succeeded("rev-b", Some("rev-a"), 200)
        .expect("b");

    repo.insert_candidate(&sample_record("rev-c", "h-c"))
        .expect("insert c");
    repo.mark_apply_succeeded("rev-c", Some("rev-b"), 300)
        .expect("c");

    let lkg = repo.last_known_good().expect("query").expect("present");
    assert_eq!(lkg.revision_id, "rev-b"); // most recently superseded
}

#[test]
fn last_known_good_none_when_no_superseded() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    assert!(repo.last_known_good().expect("query").is_none());

    // Even one Active revision yields no LKG.
    repo.insert_candidate(&sample_record("rev-only", "h-only"))
        .expect("insert");
    repo.mark_apply_succeeded("rev-only", None, 1).expect("act");
    assert!(repo.last_known_good().expect("query").is_none());
}

#[test]
fn mark_rolled_back_transitions_active_to_rolled_back() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate(&sample_record("rev-r", "h-r"))
        .expect("insert");
    repo.mark_apply_succeeded("rev-r", None, 1)
        .expect("activate");
    repo.mark_rolled_back("rev-r", 99).expect("rollback");

    let rec = repo.get_by_id("rev-r").expect("query").expect("present");
    assert_eq!(rec.status, RevisionStatus::RolledBack);
    assert_eq!(rec.superseded_at, Some(99));
}

/// Retention walks principals in a fixed order. A row the pointer still
/// references cannot be deleted (composite FK, no `ON DELETE`), and that
/// one failure used to abort the whole pass — so every principal sorted
/// after the stale one stopped being pruned, permanently and silently.
#[test]
fn a_stale_pointer_of_one_principal_does_not_stop_retention_for_the_others() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    let old = 1_000_000i64;
    let now = old + 100 * 86_400;

    // "A" sorts first and keeps a pointer at an old superseded row.
    for (principal, id) in [("S-A", "rev-a"), ("S-B", "rev-b")] {
        repo.insert_candidate_for(principal, &sample_record(id, "h"))
            .expect("insert");
        conn.execute(
            "UPDATE revisions SET status = 'superseded', superseded_at = ?1
                 WHERE principal = ?2 AND revision_id = ?3",
            params![old, principal, id],
        )
        .expect("age the row");
    }
    repo.set_active_pointer_for(
        "S-A",
        &ActiveRevisionPointer {
            revision_id: "rev-a".to_string(),
            activated_at: old,
            apply_attempt_id: None,
        },
    )
    .expect("stale pointer");

    let settings = RetentionSettings {
        superseded_days: 1,
        pin_lkg: false,
        ..RetentionSettings::DEFAULT
    };
    let summary = repo
        .prune_by_retention(&settings, now)
        .expect("retention must not abort on one principal");

    // B's history is pruned even though A's row is pinned by its pointer.
    assert_eq!(summary.superseded_dropped, 1);
    assert!(repo.get_by_id("rev-b").expect("get").is_none());
    assert!(
        repo.get_by_id("rev-a").expect("get").is_some(),
        "the pointed-at row must survive rather than break the FK",
    );
    // And A's own pass is not an error either: the pinned row is excluded
    // from the DELETE instead of colliding with the foreign key.
    assert!(repo.prune_by_retention_for("S-A", &settings, now).is_ok());
}

#[test]
fn active_pointer_set_get_clear_roundtrip() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    assert!(repo.get_active_pointer().expect("query").is_none());

    // Pointer references revisions(revision_id), so the rows must exist
    // first — `PRAGMA foreign_keys = ON` rejects dangling references.
    repo.insert_candidate(&sample_record("rev-A", "h-A"))
        .expect("insert A");
    repo.insert_candidate(&sample_record("rev-B", "h-B"))
        .expect("insert B");

    let p = ActiveRevisionPointer {
        revision_id: "rev-A".to_string(),
        activated_at: 1_700_000_777,
        apply_attempt_id: Some("att-9".to_string()),
    };
    repo.set_active_pointer(&p).expect("set");
    let loaded = repo.get_active_pointer().expect("query").expect("present");
    assert_eq!(loaded, p);

    // Update — should replace, not duplicate.
    let p2 = ActiveRevisionPointer {
        revision_id: "rev-B".to_string(),
        activated_at: 1_700_000_999,
        apply_attempt_id: None,
    };
    repo.set_active_pointer(&p2).expect("set 2");
    let loaded2 = repo.get_active_pointer().expect("query").expect("present");
    assert_eq!(loaded2, p2);

    repo.clear_active_pointer().expect("clear");
    assert!(repo.get_active_pointer().expect("query").is_none());
}

// ── Retention pruning ────────────────────────────────────────────────────

fn drive_to_status(repo: &RevisionsRepository<'_>, id: &str, hash: &str) {
    repo.insert_candidate(&sample_record(id, hash))
        .expect("insert");
}

#[test]
fn prune_drops_old_superseded_when_pin_lkg_protects_most_recent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    // Active for the chain.
    drive_to_status(&repo, "rev-A", "h-A");
    repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
    drive_to_status(&repo, "rev-B", "h-B");
    repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
        .expect("b");
    drive_to_status(&repo, "rev-C", "h-C");
    repo.mark_apply_succeeded("rev-C", Some("rev-B"), 300)
        .expect("c");
    // Now rev-A and rev-B are Superseded, rev-C is Active. LKG = rev-B.

    // Settings whose threshold falls between A's and B's
    // superseded_at: A was superseded at 200, B at 300.
    // superseded_days=7 → cutoff = now - 7*86400.
    // Pick now=200 + 7*86400 + 1 → cutoff = 201. A (200) < 201 → drop.
    // B (300) > 201 → keep.
    let settings = RetentionSettings {
        superseded_days: 7,
        ..RetentionSettings::DEFAULT
    };
    let now = 200 + 7 * 86_400 + 1;
    let summary = repo.prune_by_retention(&settings, now).expect("prune");
    assert_eq!(summary.superseded_dropped, 1);
    assert!(repo.get_by_id("rev-A").expect("query").is_none());
    assert!(repo.get_by_id("rev-B").expect("query").is_some());
    assert!(repo.get_by_id("rev-C").expect("query").is_some());
}

#[test]
fn prune_protects_lkg_even_when_age_exceeds_threshold() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    drive_to_status(&repo, "rev-A", "h-A");
    repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
    drive_to_status(&repo, "rev-B", "h-B");
    repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
        .expect("b");
    // rev-A is now Superseded (the LKG).

    // Threshold far in the future — without pin_lkg, A would be dropped.
    let settings = RetentionSettings {
        superseded_days: 7,
        pin_lkg: true,
        ..RetentionSettings::DEFAULT
    };
    let now = 100 + 1_000_000_000;
    let summary = repo.prune_by_retention(&settings, now).expect("prune");
    assert_eq!(summary.superseded_dropped, 0);
    assert!(repo.get_by_id("rev-A").expect("query").is_some());
}

#[test]
fn prune_drops_lkg_when_pin_lkg_disabled_and_threshold_passed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    drive_to_status(&repo, "rev-A", "h-A");
    repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
    drive_to_status(&repo, "rev-B", "h-B");
    repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
        .expect("b");
    let settings = RetentionSettings {
        superseded_days: 7,
        pin_lkg: false,
        ..RetentionSettings::DEFAULT
    };
    let now = 100 + 8 * 86_400;
    let summary = repo.prune_by_retention(&settings, now).expect("prune");
    assert_eq!(summary.superseded_dropped, 1);
    assert!(repo.get_by_id("rev-A").expect("query").is_none());
}

#[test]
fn prune_count_cap_drops_oldest_above_cap() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    // Build a chain of 25 revisions; 24 of them end up Superseded.
    // The first activate has no previous, so each subsequent one
    // supersedes the prior. We use cap=20 (legal min) with pin_lkg
    // so the LKG (most recent superseded) is protected.
    let mut prev: Option<String> = None;
    for i in 0..25 {
        let id = format!("rev-{i:02}");
        drive_to_status(&repo, &id, &format!("h-{i:02}"));
        repo.mark_apply_succeeded(&id, prev.as_deref(), (i * 10) as i64)
            .expect("succ");
        prev = Some(id);
    }
    // Now 24 superseded + 1 active.
    let settings = RetentionSettings {
        // Force the age sweep to be a no-op so we observe the cap pass alone.
        superseded_days: 365,
        superseded_count_cap: 20,
        pin_lkg: true,
        ..RetentionSettings::DEFAULT
    };
    let summary = repo.prune_by_retention(&settings, 1_000).expect("prune");
    // 24 superseded → cap 20 → 4 dropped.
    assert_eq!(summary.superseded_dropped, 4);
    // Oldest 4 (rev-00..rev-03) gone.
    assert!(repo.get_by_id("rev-00").expect("query").is_none());
    assert!(repo.get_by_id("rev-03").expect("query").is_none());
    assert!(repo.get_by_id("rev-04").expect("query").is_some());
    // LKG (rev-23) still present.
    assert!(repo.get_by_id("rev-23").expect("query").is_some());
}

#[test]
fn prune_drops_old_rejected_revisions() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    // Insert two candidates with different created_at.
    let mut old = sample_record("rev-rej-old", "h-old");
    old.created_at = 100;
    let mut new = sample_record("rev-rej-new", "h-new");
    new.created_at = 1_000_000;
    repo.insert_candidate(&old).expect("old");
    repo.insert_candidate(&new).expect("new");
    // Drive both to Rejected (mark_apply_failed updates status only,
    // not created_at).
    repo.mark_apply_failed("rev-rej-old", "fail", 0).expect("o");
    repo.mark_apply_failed("rev-rej-new", "fail", 0).expect("n");

    let settings = RetentionSettings {
        rejected_days: 7,
        ..RetentionSettings::DEFAULT
    };
    let now = 100 + 8 * 86_400;
    let summary = repo.prune_by_retention(&settings, now).expect("prune");
    assert_eq!(summary.rejected_dropped, 1);
    assert!(repo.get_by_id("rev-rej-old").expect("query").is_none());
    assert!(repo.get_by_id("rev-rej-new").expect("query").is_some());
}

#[test]
fn prune_active_revision_is_never_touched() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    drive_to_status(&repo, "rev-act", "h-act");
    repo.mark_apply_succeeded("rev-act", None, 0).expect("act");

    // Even with aggressive retention, Active stays.
    let settings = RetentionSettings {
        superseded_days: 7,
        superseded_count_cap: 20,
        rejected_days: 1,
        rolledback_days: 1,
        rolledback_count_cap: 5,
        pin_lkg: false,
        ..RetentionSettings::DEFAULT
    };
    let _ = repo
        .prune_by_retention(&settings, 1_000_000_000)
        .expect("prune");
    assert!(repo.get_by_id("rev-act").expect("query").is_some());
}

#[test]
fn prune_returns_summary_totals() {
    let summary = RetentionPruneSummary {
        superseded_dropped: 3,
        rejected_dropped: 2,
        rolledback_dropped: 1,
    };
    assert_eq!(summary.total(), 6);
}

#[test]
fn active_pointer_rejects_dangling_revision_id() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    // No revisions inserted; FK must reject.
    let p = ActiveRevisionPointer {
        revision_id: "ghost".to_string(),
        activated_at: 1,
        apply_attempt_id: None,
    };
    assert!(repo.set_active_pointer(&p).is_err());
}

// ── row_hmac tamper detection ───────────────────────────────────────────

fn hmac_key() -> Vec<u8> {
    vec![0x42u8; crate::revision_hmac::RECOMMENDED_KEY_BYTE_LEN]
}

/// Which revision is ACTIVE is part of the enforced policy. Repointing it
/// leaves both revisions verifying perfectly, so without a tag on the
/// pointer itself the swap is invisible.
#[test]
fn moving_the_active_pointer_out_of_band_is_caught() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
    for (id, hash) in [("rev-one", "h-1"), ("rev-two", "h-2")] {
        repo.insert_candidate(&sample_record(id, hash))
            .expect("insert");
    }
    repo.set_active_pointer(&ActiveRevisionPointer {
        revision_id: "rev-one".into(),
        activated_at: 10,
        apply_attempt_id: None,
    })
    .expect("point");
    assert_eq!(
        repo.verify_all_pointers().expect("verify"),
        vec![(
            crate::BASELINE_PRINCIPAL.to_string(),
            crate::revision_hmac::HmacVerification::Verified
        )],
    );

    conn.execute(
        "UPDATE active_revision_pointer SET revision_id = 'rev-two'",
        [],
    )
    .expect("hand edit");
    assert_eq!(
        repo.verify_all_pointers().expect("verify"),
        vec![(
            crate::BASELINE_PRINCIPAL.to_string(),
            crate::revision_hmac::HmacVerification::Tampered
        )],
    );

    // Acknowledging adopts the state — and says which row it adopted.
    let report = repo.re_sign_all().expect("re-sign");
    assert!(report
        .adopted_tampered
        .iter()
        .any(|id| id.starts_with("pointer:")));
    assert!(repo
        .verify_all_pointers()
        .expect("verify")
        .iter()
        .all(|(_, v)| *v == crate::revision_hmac::HmacVerification::Verified));
}

/// Retiring the previous revision is half of Phase 3a. Naming one that is
/// not active did nothing and still reported success — history then kept
/// two stories about which revision had been replaced.
#[test]
fn superseding_a_revision_that_is_not_active_is_an_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    for (id, hash) in [("rev-a", "h-a"), ("rev-b", "h-b")] {
        repo.insert_candidate(&sample_record(id, hash))
            .expect("insert");
    }

    // `rev-a` is still a candidate, so it cannot be the one being replaced.
    let err = repo
        .mark_apply_succeeded("rev-b", Some("rev-a"), 10)
        .expect_err("naming a non-active predecessor must not pass silently");
    assert!(format!("{err}").contains("was not the active revision"));

    // The honest sequence works, and repeating it is idempotent — a retry
    // after a crash between the two statements must not fail.
    repo.mark_apply_succeeded("rev-a", None, 10).expect("first");
    repo.mark_apply_succeeded("rev-b", Some("rev-a"), 20)
        .expect("second");
    repo.mark_apply_succeeded("rev-b", Some("rev-a"), 20)
        .expect_err("rev-b is already active, not a candidate");
}

/// A pointer written before the column existed is unsigned, not forged.
#[test]
fn a_pointer_from_before_signing_reads_unsigned() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    RevisionsRepository::new(&conn)
        .insert_candidate(&sample_record("rev-old", "h-old"))
        .expect("insert");
    conn.execute(
        "INSERT INTO active_revision_pointer (principal, revision_id, activated_at)
             VALUES (?1, 'rev-old', 1)",
        params![crate::BASELINE_PRINCIPAL],
    )
    .expect("legacy pointer");

    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
    assert_eq!(
        repo.verify_all_pointers().expect("verify")[0].1,
        crate::revision_hmac::HmacVerification::Unsigned,
    );
    repo.re_sign_pointer_for(crate::BASELINE_PRINCIPAL)
        .expect("backfill");
    assert_eq!(
        repo.verify_all_pointers().expect("verify")[0].1,
        crate::revision_hmac::HmacVerification::Verified,
    );
}

/// One principal's tag must not verify over another's row: a pointer
/// copied between users would otherwise carry its signature with it.
#[test]
fn a_pointer_tag_does_not_travel_between_principals() {
    let key = hmac_key();
    let pointer = ActiveRevisionPointer {
        revision_id: "rev-one".into(),
        activated_at: 10,
        apply_attempt_id: None,
    };
    let mine = crate::revision_hmac::compute_pointer_hmac(&pointer_fields("S-A", &pointer), &key);
    assert_eq!(
        crate::revision_hmac::verify_pointer(&pointer_fields("S-B", &pointer), &mine, &key),
        crate::revision_hmac::HmacVerification::Tampered,
    );
}

#[test]
fn insert_without_key_leaves_row_unsigned() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    repo.insert_candidate(&sample_record("rev-x", "h-x"))
        .expect("insert");
    let (_rec, hmac) = repo.get_with_hmac("rev-x").expect("get").expect("present");
    assert!(hmac.is_empty(), "no key → empty default blob");

    // Verifying via the no-key repo collapses to Unsigned even
    // when stored blob would be non-empty.
    assert_eq!(
        repo.verify_row_hmac("rev-x").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Unsigned),
    );
}

#[test]
fn insert_with_key_persists_hmac_and_verifies() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate(&sample_record("rev-y", "h-y"))
        .expect("insert");
    let (_rec, hmac) = repo.get_with_hmac("rev-y").expect("get").expect("present");
    assert_eq!(
        hmac.len(),
        crate::revision_hmac::HMAC_BYTE_LEN,
        "HMAC must be 32 bytes when key set"
    );
    assert_eq!(
        repo.verify_row_hmac("rev-y").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
    );
}

/// The table's key is `(principal, revision_id)` and the HMAC exists
/// precisely because an outsider can write the file. A shadow row sharing
/// an id used to be indistinguishable to the id-keyed signing paths: the
/// read picked whichever SQLite returned, and the re-sign UPDATE stamped
/// one row's signature onto both.
#[test]
fn a_shadow_row_sharing_a_revision_id_is_refused_not_picked_at_random() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate_for("S-1-5-21-owner", &sample_record("rev-dup", "h-own"))
        .expect("insert owner row");
    // An outside writer adds a row with the same id under another
    // principal — legal for the schema, impossible through this API.
    conn.execute(
        "INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status,
                                    source, correlation_id, created_at, row_hmac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, x'')",
        params![
            "S-1-5-21-intruder",
            "rev-dup",
            "h-shadow",
            r#"{"shadow":true}"#,
            "candidate",
            "gui-rules-edit",
            "corr-shadow",
            1_700_000_001i64,
        ],
    )
    .expect("shadow INSERT");

    assert!(
        matches!(
            repo.verify_row_hmac("rev-dup"),
            Err(StorageError::IntegrityFailed(
                crate::error::IntegrityFailureKind::PolicyRevisionCorrupt
            ))
        ),
        "an ambiguous id must not resolve to an arbitrary row",
    );
    assert!(matches!(
        repo.re_sign_row("rev-dup"),
        Err(StorageError::IntegrityFailed(_))
    ));
    // The owner's signature is untouched by the intruder's presence.
    conn.execute(
        "DELETE FROM revisions WHERE principal = ?1",
        params!["S-1-5-21-intruder"],
    )
    .expect("remove shadow");
    assert_eq!(
        repo.verify_row_hmac("rev-dup").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
    );
}

#[test]
fn external_tamper_of_rules_json_is_detected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate(&sample_record("rev-t", "h-t"))
        .expect("insert");

    // Simulate an external admin / rogue process opening the DB
    // directly and rewriting `rules_json` outside the service's
    // write path. The repository never knows about this UPDATE,
    // so the stored `row_hmac` becomes invalid.
    conn.execute(
        "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
        params![r#"{"tampered":true}"#, "rev-t"],
    )
    .expect("tamper UPDATE");

    assert_eq!(
        repo.verify_row_hmac("rev-t").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Tampered),
    );
}

#[test]
fn verify_with_different_key_is_tampered() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);

    // Sign with key_a …
    let repo_a = RevisionsRepository::with_signing_key(&conn, vec![0x42u8; 32]);
    repo_a
        .insert_candidate(&sample_record("rev-k", "h-k"))
        .expect("insert");

    // … verify with key_b. Same row, but the HMAC computed by
    // key_b will not match what key_a produced.
    let repo_b = RevisionsRepository::with_signing_key(&conn, vec![0x43u8; 32]);
    assert_eq!(
        repo_b.verify_row_hmac("rev-k").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Tampered),
    );
}

#[test]
fn re_sign_row_repairs_after_status_change() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate(&sample_record("rev-s", "h-s"))
        .expect("insert");
    // Activate via the standard path. The UPDATE invalidates the
    // HMAC because activation changes both `status` and
    // `activated_at`. Until the coordinator wires re-sign in
    // automatically, we call it manually.
    repo.mark_apply_succeeded("rev-s", None, 1_700_001_000)
        .expect("activate");
    assert_eq!(
        repo.verify_row_hmac("rev-s").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Tampered),
        "post-activate row diverges from insert-time HMAC"
    );

    repo.re_sign_row("rev-s").expect("re-sign");
    assert_eq!(
        repo.verify_row_hmac("rev-s").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
        "re-sign repairs the HMAC against the current row"
    );
}

#[test]
fn re_sign_all_walks_every_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // Insert three rows WITHOUT a key (simulating legacy / lazy-
    // backfill state after a v10→v11 migration).
    let unsigned = RevisionsRepository::new(&conn);
    for i in 0..3 {
        unsigned
            .insert_candidate(&sample_record(&format!("rev-{i}"), &format!("h-{i}")))
            .expect("insert");
    }
    // All three should be Unsigned.
    let with_key = RevisionsRepository::with_signing_key(&conn, hmac_key());
    for i in 0..3 {
        assert_eq!(
            with_key
                .verify_row_hmac(&format!("rev-{i}"))
                .expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Unsigned),
        );
    }
    // Re-sign all in one pass …
    assert_eq!(with_key.re_sign_all().expect("re-sign-all").re_signed, 3);
    // … and every row is now Verified.
    for i in 0..3 {
        assert_eq!(
            with_key
                .verify_row_hmac(&format!("rev-{i}"))
                .expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
        );
    }
}

#[test]
fn re_sign_all_without_key_is_noop() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    repo.insert_candidate(&sample_record("rev-noop", "h-noop"))
        .expect("insert");
    assert_eq!(repo.re_sign_all().expect("re-sign-all").re_signed, 0);
}

#[test]
fn count_reflects_inserts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);
    assert_eq!(repo.count().expect("count"), 0);
    repo.insert_candidate(&sample_record("rev-a", "h-a"))
        .expect("insert");
    repo.insert_candidate(&sample_record("rev-b", "h-b"))
        .expect("insert");
    assert_eq!(repo.count().expect("count"), 2);
}

#[test]
fn verify_all_classifies_each_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    // rev-ok: signed and intact → Verified.
    repo.insert_candidate(&sample_record("rev-ok", "h-ok"))
        .expect("insert");
    // rev-leg: legacy row inserted without a key → Unsigned.
    RevisionsRepository::new(&conn)
        .insert_candidate(&sample_record("rev-leg", "h-leg"))
        .expect("insert");
    // rev-bad: signed, then externally mutated → Tampered.
    repo.insert_candidate(&sample_record("rev-bad", "h-bad"))
        .expect("insert");
    conn.execute(
        "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
        params![r#"{"tampered":true}"#, "rev-bad"],
    )
    .expect("tamper");

    let results = repo.verify_all().expect("verify_all");
    let by_id: std::collections::HashMap<_, _> = results.into_iter().collect();
    use crate::revision_hmac::HmacVerification::*;
    assert_eq!(by_id.get("rev-ok"), Some(&Verified));
    assert_eq!(by_id.get("rev-leg"), Some(&Unsigned));
    assert_eq!(by_id.get("rev-bad"), Some(&Tampered));
}

// ── activation_history_for ───────────────────────────────────────────────

#[test]
fn activation_history_orders_active_first_then_by_recency() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
    let principal = "S-1-5-21-hist";

    repo.insert_candidate_for(principal, &sample_record("rev-1", "h-1"))
        .expect("insert 1");
    repo.mark_apply_succeeded_for(principal, "rev-1", None, 1_700_000_100)
        .expect("activate 1");
    repo.re_sign_row("rev-1").expect("re-sign 1");

    repo.insert_candidate_for(principal, &sample_record("rev-2", "h-2"))
        .expect("insert 2");
    repo.mark_apply_succeeded_for(principal, "rev-2", Some("rev-1"), 1_700_000_200)
        .expect("activate 2");
    repo.re_sign_row("rev-1").expect("re-sign 1 (superseded)");
    repo.re_sign_row("rev-2").expect("re-sign 2");

    repo.insert_candidate_for(principal, &sample_record("rev-3", "h-3"))
        .expect("insert 3");
    repo.mark_apply_succeeded_for(principal, "rev-3", Some("rev-2"), 1_700_000_300)
        .expect("activate 3");
    repo.re_sign_row("rev-2").expect("re-sign 2 (superseded)");
    repo.re_sign_row("rev-3").expect("re-sign 3");

    let history = repo
        .activation_history_for(principal)
        .expect("activation_history_for");
    let ids: Vec<&str> = history
        .iter()
        .map(|e| e.record.revision_id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec!["rev-3", "rev-2", "rev-1"],
        "active first, then supersede-recency descending"
    );
    assert!(
        history
            .iter()
            .all(|e| e.verification == crate::revision_hmac::HmacVerification::Verified),
        "every row was (re)signed after its status change"
    );
}

#[test]
fn activation_history_flags_tampered_active_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
    let principal = "S-1-5-21-tamper";

    repo.insert_candidate_for(principal, &sample_record("rev-good", "h-good"))
        .expect("insert");
    repo.mark_apply_succeeded_for(principal, "rev-good", None, 1_700_000_000)
        .expect("activate");
    repo.re_sign_row("rev-good").expect("re-sign");

    // External mutation of the now-active row, bypassing the service.
    conn.execute(
        "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
        params![r#"{"tampered":true}"#, "rev-good"],
    )
    .expect("tamper");

    let history = repo
        .activation_history_for(principal)
        .expect("activation_history_for");
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].verification,
        crate::revision_hmac::HmacVerification::Tampered
    );
}

#[test]
fn activation_history_scoped_by_principal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a", "h-a"))
        .expect("insert a");
    repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a", None, 1_700_000_000)
        .expect("activate a");

    repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
        .expect("insert b");
    repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 1_700_000_000)
        .expect("activate b");

    let history_a = repo
        .activation_history_for("S-1-5-21-A")
        .expect("history a");
    assert_eq!(history_a.len(), 1);
    assert_eq!(history_a[0].record.revision_id, "rev-a");
}

#[test]
fn activation_history_without_key_reports_unsigned() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let signed = RevisionsRepository::with_signing_key(&conn, hmac_key());
    let principal = "S-1-5-21-nokey";
    signed
        .insert_candidate_for(principal, &sample_record("rev-x", "h-x"))
        .expect("insert");
    signed
        .mark_apply_succeeded_for(principal, "rev-x", None, 1_700_000_000)
        .expect("activate");

    let unsigned = RevisionsRepository::new(&conn);
    let history = unsigned.activation_history_for(principal).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].verification,
        crate::revision_hmac::HmacVerification::Unsigned
    );
}

// ── per-principal isolation ─────────────────────────────────────────────

#[test]
fn baseline_shims_route_to_baseline_principal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // The no-principal shim writes under the baseline sentinel.
    repo.insert_candidate(&sample_record("rev-base", "h-base"))
        .expect("insert");
    assert!(repo
        .get_by_id_for(BASELINE_PRINCIPAL, "rev-base")
        .expect("scoped get")
        .is_some());
    // A different principal cannot see the baseline row by id.
    assert!(repo
        .get_by_id_for("S-1-5-21-X", "rev-base")
        .expect("scoped get other")
        .is_none());
}

#[test]
fn activation_does_not_supersede_another_principals_active() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // A activates rev-a1, then rev-a2 (supersedes a1) — all within A.
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("a1", "ha1"))
        .expect("a1");
    repo.mark_apply_succeeded_for("S-1-5-21-A", "a1", None, 100)
        .expect("act a1");

    // B activates b1 in parallel.
    repo.insert_candidate_for("S-1-5-21-B", &sample_record("b1", "hb1"))
        .expect("b1");
    repo.mark_apply_succeeded_for("S-1-5-21-B", "b1", None, 110)
        .expect("act b1");

    // A's second activation supersedes ONLY a1, leaving b1 active.
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("a2", "ha2"))
        .expect("a2");
    repo.mark_apply_succeeded_for("S-1-5-21-A", "a2", Some("a1"), 200)
        .expect("act a2");

    assert_eq!(
        repo.get_by_id("a1").expect("a1").expect("present").status,
        RevisionStatus::Superseded
    );
    assert_eq!(
        repo.get_active_for("S-1-5-21-B")
            .expect("b active")
            .expect("present")
            .revision_id,
        "b1",
        "B's active revision must be untouched by A's activation"
    );
}

#[test]
fn content_hash_dedup_is_per_principal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // Same content hash under two principals → two independent rows.
    repo.insert_candidate_for("S-1-5-21-A", &sample_record("a", "shared-hash"))
        .expect("a");
    repo.insert_candidate_for("S-1-5-21-B", &sample_record("b", "shared-hash"))
        .expect("b");

    assert_eq!(
        repo.find_by_content_hash_for("S-1-5-21-A", "shared-hash")
            .expect("a")
            .expect("present")
            .revision_id,
        "a"
    );
    assert_eq!(
        repo.find_by_content_hash_for("S-1-5-21-B", "shared-hash")
            .expect("b")
            .expect("present")
            .revision_id,
        "b"
    );
}

#[test]
fn hmac_binds_the_principal_column() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

    repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-p", "h-p"))
        .expect("insert");
    assert_eq!(
        repo.verify_row_hmac("rev-p").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Verified),
    );

    // Re-home the row to a different principal outside the write path.
    // The HMAC was computed over the original principal, so the move
    // is detected as tampering.
    conn.execute(
        "UPDATE revisions SET principal = ?1 WHERE revision_id = ?2",
        params!["S-1-5-21-B", "rev-p"],
    )
    .expect("re-home");
    assert_eq!(
        repo.verify_row_hmac("rev-p").expect("verify"),
        Some(crate::revision_hmac::HmacVerification::Tampered),
        "moving a row to a different principal must invalidate its HMAC"
    );
}

#[test]
fn prune_caps_are_per_principal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = RevisionsRepository::new(&conn);

    // Build a 25-revision superseded chain for EACH of two principals.
    for principal in ["S-1-5-21-A", "S-1-5-21-B"] {
        let mut prev: Option<String> = None;
        for i in 0..25 {
            let id = format!("{principal}-rev-{i:02}");
            repo.insert_candidate_for(principal, &sample_record(&id, &format!("h-{id}")))
                .expect("insert");
            repo.mark_apply_succeeded_for(principal, &id, prev.as_deref(), (i * 10) as i64)
                .expect("activate");
            prev = Some(id);
        }
    }
    // 24 superseded per principal. Cap 20, pin LKG → 4 dropped per
    // principal = 8 total.
    let settings = RetentionSettings {
        superseded_days: 365,
        superseded_count_cap: 20,
        pin_lkg: true,
        ..RetentionSettings::DEFAULT
    };
    let summary = repo.prune_by_retention(&settings, 1_000).expect("prune");
    assert_eq!(
        summary.superseded_dropped, 8,
        "each principal's cap is enforced independently"
    );
    // Each principal still has its active revision.
    assert!(repo.get_active_for("S-1-5-21-A").expect("a").is_some());
    assert!(repo.get_active_for("S-1-5-21-B").expect("b").is_some());
}

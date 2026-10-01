//! The keyed boot sweep is the only recovery: it works per principal, and it
//! leaves every pointer naming what that principal's `active` status names.

use super::*;
use nrr_storage::revision_hmac::HmacVerification;

const KEY: [u8; 32] = [0x41; 32];
const USER: &str = "S-1-5-21-0-0-0-2001";
const BASELINE: &str = nrr_storage::BASELINE_PRINCIPAL;

fn activate_for(fx: &Fixture, principal: &str, hash: &str) -> RevisionId {
    let id = submit_for(fx, principal, hash);
    let token = issue_token(fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");
    id
}

fn pointer_of(fx: &Fixture, principal: &str) -> Option<String> {
    let conn = fx.conn.lock().expect("conn");
    RevisionsRepository::new(&conn)
        .get_active_pointer_for(principal)
        .expect("pointer")
        .map(|p| p.revision_id)
}

fn status_active_of(fx: &Fixture, principal: &str) -> Option<String> {
    fx.coordinator
        .current_active_for(principal)
        .expect("current active")
        .map(|r| r.revision_id)
}

fn record(fx: &Fixture, id: &str) -> RevisionRecord {
    let conn = fx.conn.lock().expect("conn");
    RevisionsRepository::new(&conn)
        .get_by_id(id)
        .expect("get")
        .expect("present")
}

fn pointer_verdicts(fx: &Fixture) -> Vec<(String, HmacVerification)> {
    let conn = fx.conn.lock().expect("conn");
    RevisionsRepository::with_signing_key(&conn, KEY.to_vec())
        .verify_all_pointers()
        .expect("verify pointers")
}

fn outcome_of(
    outcomes: &[(String, ActiveIntegrityOutcome)],
    principal: &str,
) -> ActiveIntegrityOutcome {
    outcomes
        .iter()
        .find(|(p, _)| p == principal)
        .map(|(_, o)| o.clone())
        .unwrap_or_else(|| panic!("no outcome for {principal}"))
}

fn assert_pointers_follow_status(fx: &Fixture) {
    for principal in [BASELINE, USER] {
        assert_eq!(
            pointer_of(fx, principal),
            status_active_of(fx, principal),
            "pointer and `active` status of {principal} disagree"
        );
    }
    assert!(
        pointer_verdicts(fx)
            .iter()
            .all(|(_, v)| *v == HmacVerification::Verified),
        "every pointer must verify after the sweep"
    );
}

#[test]
fn a_clean_database_is_left_exactly_as_it_was() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let b1 = activate_for(&fx, BASELINE, "h-b1");
    let x1 = activate_for(&fx, USER, "h-x1");

    let outcomes = fx
        .coordinator
        .enforce_active_integrity_all("corr")
        .expect("sweep");

    assert_eq!(
        outcome_of(&outcomes, BASELINE),
        ActiveIntegrityOutcome::Trusted {
            revision_id: b1.as_str().to_string()
        }
    );
    assert_eq!(
        outcome_of(&outcomes, USER),
        ActiveIntegrityOutcome::Trusted {
            revision_id: x1.as_str().to_string()
        }
    );
    assert!(!fx
        .audit
        .snapshot()
        .iter()
        .any(|e| matches!(e, ActivationAuditEvent::ActiveIntegrityRejected { .. })));
    assert_pointers_follow_status(&fx);
}

/// Corruption at one user with a baseline history present: the user is
/// recovered from the user's own history, the baseline is not touched, and
/// the next activation supersedes the recovered revision instead of undoing
/// the recovery.
#[test]
fn corruption_at_one_principal_is_recovered_there_and_nowhere_else() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let _b1 = activate_for(&fx, BASELINE, "h-b1");
    let b2 = activate_for(&fx, BASELINE, "h-b2");
    let x1 = activate_for(&fx, USER, "h-x1");
    let x2 = activate_for(&fx, USER, "h-x2");
    tamper_rules_json(&fx, x2.as_str());

    let outcomes = fx
        .coordinator
        .enforce_active_integrity_all("corr")
        .expect("sweep");

    assert_eq!(
        outcome_of(&outcomes, BASELINE),
        ActiveIntegrityOutcome::Trusted {
            revision_id: b2.as_str().to_string()
        }
    );
    let recovered = match outcome_of(&outcomes, USER) {
        ActiveIntegrityOutcome::RolledBack {
            rejected_revision_id,
            trusted_source_revision_id,
            new_active_revision_id,
            ..
        } => {
            assert_eq!(rejected_revision_id, x2.as_str());
            assert_eq!(trusted_source_revision_id, x1.as_str());
            new_active_revision_id
        }
        other => panic!("expected RolledBack, got {other:?}"),
    };
    assert_eq!(pointer_of(&fx, BASELINE).as_deref(), Some(b2.as_str()));
    assert_eq!(status_active_of(&fx, USER), Some(recovered.clone()));
    assert_pointers_follow_status(&fx);

    let x3 = activate_for(&fx, USER, "h-x3");
    assert_eq!(
        record(&fx, &recovered).superseded_by.as_deref(),
        Some(x3.as_str()),
        "the next activation supersedes the recovered revision"
    );
    assert_ne!(record(&fx, x2.as_str()).status, RevisionStatus::Active);
    assert_eq!(status_active_of(&fx, USER).as_deref(), Some(x3.as_str()));
    assert_eq!(
        status_active_of(&fx, BASELINE).as_deref(),
        Some(b2.as_str())
    );
    assert_pointers_follow_status(&fx);
}

/// What the old keyless fallback left behind: the baseline pointer moved onto
/// a superseded row while the `active` status stayed put.
#[test]
fn a_pointer_left_on_a_superseded_row_follows_the_status_again() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let b1 = activate_for(&fx, BASELINE, "h-b1");
    let b2 = activate_for(&fx, BASELINE, "h-b2");
    {
        let conn = fx.conn.lock().expect("conn");
        RevisionsRepository::with_signing_key(&conn, KEY.to_vec())
            .set_active_pointer_for(
                BASELINE,
                &ActiveRevisionPointer {
                    revision_id: b1.as_str().to_string(),
                    activated_at: 1,
                    apply_attempt_id: None,
                },
            )
            .expect("misplace pointer");
    }

    let outcome = fx
        .coordinator
        .enforce_active_integrity_for(BASELINE, "corr")
        .expect("sweep");

    assert_eq!(
        outcome,
        ActiveIntegrityOutcome::PointerRealigned {
            pointer_was: Some(b1.as_str().to_string()),
            revision_id: Some(b2.as_str().to_string()),
        }
    );
    assert_eq!(pointer_of(&fx, BASELINE).as_deref(), Some(b2.as_str()));
    assert_eq!(record(&fx, b1.as_str()).status, RevisionStatus::Superseded);
}

/// An edited pointer that still names the right row is re-signed, not left
/// failing for the next boot.
#[test]
fn a_pointer_with_a_broken_signature_is_rewritten() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let b1 = activate_for(&fx, BASELINE, "h-b1");
    fx.conn
        .lock()
        .expect("conn")
        .execute("UPDATE active_revision_pointer SET activated_at = 7", [])
        .expect("edit pointer");
    assert!(pointer_verdicts(&fx)
        .iter()
        .any(|(_, v)| *v == HmacVerification::Tampered));

    let outcome = fx
        .coordinator
        .enforce_active_integrity_for(BASELINE, "corr")
        .expect("sweep");

    assert_eq!(
        outcome,
        ActiveIntegrityOutcome::PointerRealigned {
            pointer_was: Some(b1.as_str().to_string()),
            revision_id: Some(b1.as_str().to_string()),
        }
    );
    assert_pointers_follow_status(&fx);
}

/// A principal whose every row was deleted still has its pointer found and
/// cleared: the sweep walks pointers as well as revisions.
#[test]
fn a_pointer_whose_rows_were_deleted_is_cleared() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let b1 = activate_for(&fx, BASELINE, "h-b1");
    let x1 = activate_for(&fx, USER, "h-x1");
    fx.conn
        .lock()
        .expect("conn")
        .execute_batch(&format!(
            "PRAGMA foreign_keys = OFF;
             DELETE FROM revisions WHERE revision_id = '{}';
             PRAGMA foreign_keys = ON;",
            x1.as_str()
        ))
        .expect("external delete");

    let outcomes = fx
        .coordinator
        .enforce_active_integrity_all("corr")
        .expect("sweep");

    assert_eq!(
        outcome_of(&outcomes, USER),
        ActiveIntegrityOutcome::PointerRealigned {
            pointer_was: Some(x1.as_str().to_string()),
            revision_id: None,
        }
    );
    assert_eq!(pointer_of(&fx, USER), None);
    assert_eq!(pointer_of(&fx, BASELINE).as_deref(), Some(b1.as_str()));
}

/// A principal whose history cannot be read is reported as unchecked, and the
/// principals after it are still checked and recovered.
#[test]
fn one_unreadable_principal_does_not_stop_the_sweep() {
    // Sorts ahead of `USER` and the baseline, so the sweep meets it first.
    const BROKEN: &str = "S-1-5-21-0-0-0-1000";
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, KEY.to_vec());
    let b1 = activate_for(&fx, BASELINE, "h-b1");
    let broken = activate_for(&fx, BROKEN, "h-y1");
    let _x1 = activate_for(&fx, USER, "h-x1");
    let x2 = activate_for(&fx, USER, "h-x2");
    tamper_rules_json(&fx, x2.as_str());
    fx.conn
        .lock()
        .expect("conn")
        .execute_batch(&format!(
            "PRAGMA ignore_check_constraints = ON;
             UPDATE revisions SET source = 'written-elsewhere' WHERE revision_id = '{}';
             PRAGMA ignore_check_constraints = OFF;",
            broken.as_str()
        ))
        .expect("unreadable row");

    let outcomes = fx
        .coordinator
        .enforce_active_integrity_all("corr")
        .expect("sweep");

    assert!(matches!(
        outcome_of(&outcomes, BROKEN),
        ActiveIntegrityOutcome::CheckFailed { .. }
    ));
    match outcome_of(&outcomes, USER) {
        ActiveIntegrityOutcome::RolledBack {
            rejected_revision_id,
            ..
        } => assert_eq!(rejected_revision_id, x2.as_str()),
        other => panic!("expected RolledBack, got {other:?}"),
    }
    assert_eq!(
        outcome_of(&outcomes, BASELINE),
        ActiveIntegrityOutcome::Trusted {
            revision_id: b1.as_str().to_string()
        }
    );
}

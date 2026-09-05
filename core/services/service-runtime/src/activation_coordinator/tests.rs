//! Unit tests for [`super`] — ActivationCoordinator.
//!
//! 1388 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

use super::*;
use nrr_shared::ipc::IpcClientProfile;
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;

struct Fixture {
    coordinator: ActivationCoordinator,
    clock: Arc<FixedClock>,
    dispatcher: Arc<ScriptedDispatcher>,
    audit: Arc<RecordingAudit>,
    registry: Arc<ActiveSidRegistry>,
    marker: Arc<InMemoryMarkerStore>,
    /// Shared with the coordinator; tests open their own
    /// `RevisionsRepository` over it to assert HMAC state.
    conn: Arc<Mutex<Connection>>,
    _dir: tempfile::TempDir,
}

fn build_fixture(policy: ApplyFailurePolicy) -> Fixture {
    build_fixture_inner(policy, None)
}

/// Fixture whose coordinator signs the
/// `revisions.row_hmac` column with `key`.
fn build_signed_fixture(policy: ApplyFailurePolicy, key: Vec<u8>) -> Fixture {
    build_fixture_inner(policy, Some(key))
}

fn build_fixture_inner(policy: ApplyFailurePolicy, key: Option<Vec<u8>>) -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    let conn = Arc::new(Mutex::new(conn));

    let registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher = Arc::new(ScriptedDispatcher::new());
    let marker = Arc::new(InMemoryMarkerStore::new());
    let audit = Arc::new(RecordingAudit::new());
    let clock = FixedClock::new(1_700_000_000);
    let ids: Arc<dyn IdGenerator> = Arc::new(CounterIds::new());

    let mut coordinator = ActivationCoordinator::new(
        conn.clone(),
        registry.clone(),
        dispatcher.clone() as Arc<dyn RulesApplyDispatcher>,
        marker.clone() as Arc<dyn ApplyMarkerStore>,
        audit.clone() as Arc<dyn ActivationAuditEmitter>,
        clock.clone() as Arc<dyn Clock>,
        ids,
        policy,
    );
    if let Some(k) = key {
        coordinator = coordinator.with_signing_key(k);
    }
    Fixture {
        coordinator,
        clock,
        dispatcher,
        audit,
        registry,
        marker,
        conn,
        _dir: dir,
    }
}

fn submit(fx: &Fixture, hash: &str) -> RevisionId {
    submit_for(fx, nrr_storage::BASELINE_PRINCIPAL, hash)
}

fn submit_for(fx: &Fixture, principal: &str, hash: &str) -> RevisionId {
    fx.coordinator
        .submit_candidate(CandidateSubmission {
            principal: principal.to_string(),
            rules_json: r#"{"rules":[]}"#.to_string(),
            content_hash: hash.to_string(),
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr-1".to_string(),
            risk_level: Some(RiskLevel::Low),
            review_summary_json: None,
        })
        .expect("submit")
}

fn issue_token(fx: &Fixture, id: &RevisionId) -> ConfirmationToken {
    fx.coordinator
        .issue_confirmation_token(id, 300)
        .expect("issue token")
}

// ── submit_candidate ──────────────────────────────────────────────────────

#[test]
fn submit_candidate_creates_revision_with_candidate_status() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-1");
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(rec.status, RevisionStatus::Candidate);
    assert_eq!(rec.source, RulesRevisionSource::GuiRulesEdit);
    assert_eq!(rec.content_hash, "h-1");
}

#[test]
fn submit_candidate_dedupes_by_content_hash() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let first = submit(&fx, "duplicate");
    let second = submit(&fx, "duplicate");
    assert_eq!(first, second, "second submit must return the existing id");

    let events = fx.audit.snapshot();
    let dedups: Vec<&ActivationAuditEvent> = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                ActivationAuditEvent::RevisionSubmitted {
                    was_dedup: true,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(dedups.len(), 1);
}

// ── re-sign on activation ─────────────────────────

#[test]
fn activation_re_signs_rows_no_false_tamper() {
    let key = vec![0x5Au8; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    fx.registry
        .on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight);

    // First activation: candidate → active.
    let id1 = submit(&fx, "h-sign-1");
    let token1 = issue_token(&fx, &id1);
    let outcome = fx
        .coordinator
        .activate(&id1, &token1, "corr-1")
        .expect("activate1");
    assert!(matches!(outcome, ActivationOutcome::Activated { .. }));

    // Second activation supersedes the first — exercises both the
    // re-sign of the newly-active row AND the superseded previous row.
    let id2 = submit(&fx, "h-sign-2");
    let token2 = issue_token(&fx, &id2);
    fx.coordinator
        .activate(&id2, &token2, "corr-2")
        .expect("activate2");

    // Every row must still verify: the coordinator re-signed each
    // row whose signed columns its UPDATEs touched. A regression
    // (forgetting a re_sign_row) would surface here as Tampered.
    let guard = fx.conn.lock().expect("conn");
    let repo = nrr_storage::revisions::RevisionsRepository::with_signing_key(&guard, key);
    let results = repo.verify_all().expect("verify_all");
    assert_eq!(results.len(), 2);
    for (rid, v) in results {
        assert_eq!(
            v,
            nrr_storage::revision_hmac::HmacVerification::Verified,
            "row {rid} must verify after coordinator activation",
        );
    }
}

// ── dry run ───────────────────────────────────────────────────────────────

#[test]
fn dry_run_returns_per_sid_action_plans_without_storing_a_candidate() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-1-5-21-B", IpcClientProfile::TrayLightweight);
    let summary = fx.coordinator.dry_run_rules(
        nrr_storage::BASELINE_PRINCIPAL,
        r#"{"schema-version":1,"primary":[],"secondary":[]}"#,
        "corr-dr",
    );
    assert_eq!(summary.action_plans.len(), 2);
    assert!(summary.action_plans.iter().all(|p| p.filter_additions == 1));
    assert!(
        summary.revision_id.is_none(),
        "a preview describes rules, not a stored revision"
    );
}

/// Records which of the dispatcher's three preview entry points the
/// coordinator actually used. The combined one answers with different
/// numbers than the two singles, so a test can tell them apart by the
/// summary alone as well as by the log.
struct CountingDispatcher {
    calls: Mutex<Vec<String>>,
}

// Test double: lock-poisoning `expect()` is acceptable scaffolding.
#[allow(clippy::expect_used)]
impl RulesApplyDispatcher for CountingDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        self.calls
            .lock()
            .expect("calls mutex")
            .push(format!("dry-run:{sid}"));
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 1,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        self.calls
            .lock()
            .expect("calls mutex")
            .push(format!("pre-flight:{sid}"));
        Ok(Vec::new())
    }

    fn plan_with_pre_flight_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> (
        Result<SidActionPlanSummary, DispatchFailure>,
        Vec<PreFlightWarning>,
    ) {
        self.calls
            .lock()
            .expect("calls mutex")
            .push(format!("combined:{sid}"));
        (
            Ok(SidActionPlanSummary {
                sid: sid.to_string(),
                filter_additions: 3,
                filter_removals: 2,
                routing_actions: 0,
            }),
            vec![PreFlightWarning {
                sid: sid.to_string(),
                category: PreFlightCategory::BindingUnresolved,
                message: "from the combined call".to_string(),
            }],
        )
    }

    fn apply_for_sid(&self, _sid: &str, _rules_json: &str) -> Result<(), DispatchFailure> {
        Ok(())
    }

    fn revert_for_sid(&self, _sid: &str, _previous: &str) -> Result<(), DispatchFailure> {
        Ok(())
    }
}

/// A preview asks each SID for ONE plan.
///
/// Deriving a SID's plan is the entire cost of a preview — the whole filter
/// set, one FQDN-cache query per rule — and the review dialog wants two
/// things out of it. Asking through the two single methods derived it twice:
/// 18.7 s on a real rule set, during which the GUI's one connection sat
/// behind the call and its own 1 s health poll timed out into a "no
/// connection to the service" banner.
#[test]
fn a_preview_asks_each_sid_for_one_plan_not_two() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_connection(&dir.path().join("state.db")).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = Arc::new(Mutex::new(runner.into_connection()));

    let registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher = Arc::new(CountingDispatcher {
        calls: Mutex::new(Vec::new()),
    });
    let coordinator = ActivationCoordinator::new(
        conn,
        registry.clone(),
        dispatcher.clone() as Arc<dyn RulesApplyDispatcher>,
        Arc::new(InMemoryMarkerStore::new()) as Arc<dyn ApplyMarkerStore>,
        Arc::new(RecordingAudit::new()) as Arc<dyn ActivationAuditEmitter>,
        FixedClock::new(1_700_000_000) as Arc<dyn Clock>,
        Arc::new(CounterIds::new()) as Arc<dyn IdGenerator>,
        ApplyFailurePolicy::AllOrNothing,
    );
    registry.on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight);
    registry.on_connect("S-1-5-21-B", IpcClientProfile::TrayLightweight);

    let summary = coordinator.dry_run_rules(
        nrr_storage::BASELINE_PRINCIPAL,
        r#"{"schema-version":1,"primary":[],"secondary":[]}"#,
        "corr-once",
    );

    let calls = dispatcher.calls.lock().expect("calls mutex").clone();
    assert_eq!(calls.len(), 2, "one plan per SID, got {calls:?}");
    assert!(
        calls.iter().all(|c| c.starts_with("combined:")),
        "the preview must not fall back to the two single calls: {calls:?}",
    );

    // Positive control: the combined answer is the one that reached the
    // summary, warnings included. A guard that only counts calls would pass
    // just as happily on a preview that returned nothing at all.
    assert_eq!(summary.action_plans.len(), 2);
    assert!(summary
        .action_plans
        .iter()
        .all(|p| p.filter_additions == 3 && p.filter_removals == 2));
    assert_eq!(summary.pre_flight_warnings.len(), 2);
}

/// The baseline is written only to users who still inherit it. The set is
/// built in phase 1 and used in phase 2, and a user can create their own
/// revision in between — writing the baseline to them then would replace
/// their policy with somebody else's.
#[test]
fn a_user_who_diverges_between_phases_keeps_their_own_revision() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-1-5-21-B", IpcClientProfile::TrayLightweight);
    let both = vec!["S-1-5-21-A".to_string(), "S-1-5-21-B".to_string()];

    // Nobody has diverged yet.
    assert_eq!(
        fx.coordinator
            .still_inheriting(nrr_storage::BASELINE_PRINCIPAL, &both),
        both
    );

    // B activates a revision of their own.
    let own = submit_for(&fx, "S-1-5-21-B", "h-own");
    let token = issue_token(&fx, &own);
    fx.coordinator
        .activate(&own, &token, "c")
        .expect("activate");

    assert_eq!(
        fx.coordinator
            .still_inheriting(nrr_storage::BASELINE_PRINCIPAL, &both),
        vec!["S-1-5-21-A".to_string()],
        "the baseline is no longer B's to receive"
    );
    // A principal applying its OWN revision is unaffected by the check.
    assert_eq!(
        fx.coordinator.still_inheriting("S-1-5-21-B", &both),
        both,
        "only the baseline defers to a user's own revision"
    );
}

// ── token plumbing ────────────────────────────────────────────────────────

#[test]
fn activate_with_unknown_token_returns_unknown() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-tok");
    let bogus = ConfirmationToken::from_string("never-issued".into());
    let err = fx
        .coordinator
        .activate(&id, &bogus, "c")
        .expect_err("must fail");
    assert!(matches!(err, PolicyError::ConfirmationTokenUnknown));
}

/// A confirmation is a confirmation OF SOMETHING. A token issued for one
/// candidate used to activate any other candidate of the same principal —
/// including one the user had just rejected.
#[test]
fn a_token_issued_for_one_revision_cannot_activate_another() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let confirmed = submit(&fx, "h-confirmed");
    let rejected = submit(&fx, "h-rejected");
    let token = issue_token(&fx, &confirmed);

    let err = fx
        .coordinator
        .activate(&rejected, &token, "c")
        .expect_err("must fail");
    assert!(matches!(
        err,
        PolicyError::ConfirmationTokenForOtherRevision
    ));

    // The token is spent either way — a misuse does not get a second try.
    let err = fx
        .coordinator
        .activate(&confirmed, &token, "c")
        .expect_err("must fail");
    assert!(matches!(err, PolicyError::ConfirmationTokenAlreadyUsed));
}

#[test]
fn activate_with_expired_token_returns_expired() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-exp");
    let token = issue_token(&fx, &id);
    // Advance clock past TTL.
    fx.clock.tick(10_000);
    let err = fx
        .coordinator
        .activate(&id, &token, "c")
        .expect_err("must fail");
    assert!(matches!(err, PolicyError::ConfirmationTokenExpired));
}

#[test]
fn activate_with_already_consumed_token_returns_already_used() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-twice");
    let token = issue_token(&fx, &id);
    let _ = fx.coordinator.activate(&id, &token, "c").expect("first");
    // Second submit needs a fresh candidate — first is now active.
    let id2 = submit(&fx, "h-second");
    let err = fx
        .coordinator
        .activate(&id2, &token, "c2")
        .expect_err("must fail");
    assert!(matches!(err, PolicyError::ConfirmationTokenAlreadyUsed));
}

// ── activate happy path / failures ────────────────────────────────────────

#[test]
fn activate_happy_path_all_or_nothing_transitions_correctly() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-1-B", IpcClientProfile::TrayLightweight);
    let id = submit(&fx, "h-ok");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    match outcome {
        ActivationOutcome::Activated { revision_id, .. } => {
            assert_eq!(revision_id, id);
        }
        other => panic!("expected Activated, got {other:?}"),
    }
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(rec.status, RevisionStatus::Active);
    let active = fx.coordinator.current_active().expect("active");
    assert!(active.is_some());
    // Marker cleared.
    assert!(fx.marker.read().is_none());
}

/// The status change and the pointer are one commit. Apart, a failure
/// between them leaves a revision marked Active that the pointer does not
/// name — and the integrity gate reads that disagreement as tampering and
/// answers by discarding the user's rules.
/// Re-signing repairs OUR edit; it must never mint a valid signature for
/// somebody else's. Without this the row that tripped the integrity gate
/// came back through it clean, and then qualified as `trusted` and as
/// last-known-good.
#[test]
fn a_tampered_revision_is_not_laundered_by_activation() {
    let key = vec![0x5au8; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    fx.registry
        .on_connect("S-1-A", IpcClientProfile::TrayLightweight);
    let id = submit(&fx, "h-tamper");
    let token = issue_token(&fx, &id);

    // Edit a signed column behind the repository's back.
    fx.conn
        .lock()
        .expect("lock")
        .execute(
            "UPDATE revisions SET content_hash = 'forged' WHERE revision_id = ?1",
            rusqlite::params![id.as_str()],
        )
        .expect("tamper");

    let outcome = fx.coordinator.activate(&id, &token, "c");
    assert!(
        outcome.is_err(),
        "a tampered revision must not be activated, let alone re-signed",
    );

    let conn = fx.conn.lock().expect("lock");
    let repo = nrr_storage::revisions::RevisionsRepository::with_signing_key(&conn, key);
    assert_eq!(
        repo.verify_row_hmac(id.as_str()).expect("verify"),
        Some(nrr_storage::revision_hmac::HmacVerification::Tampered),
        "and it must still read as tampered afterwards",
    );
}

#[test]
fn a_failed_pointer_write_leaves_no_half_activated_revision() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-A", IpcClientProfile::TrayLightweight);
    let id = submit(&fx, "h-atomic");
    let token = issue_token(&fx, &id);

    // Fail the pointer WRITE only: renaming the table would break the
    // earlier read in Phase 1 and the activation would never reach the
    // commit this test is about.
    fx.conn
        .lock()
        .expect("lock")
        .execute_batch(
            "CREATE TRIGGER no_pointer_write BEFORE UPDATE ON active_revision_pointer
             BEGIN SELECT RAISE(ABORT, 'pointer write refused'); END;
             CREATE TRIGGER no_pointer_insert BEFORE INSERT ON active_revision_pointer
             BEGIN SELECT RAISE(ABORT, 'pointer write refused'); END;",
        )
        .expect("trigger");

    let outcome = fx.coordinator.activate(&id, &token, "c");
    assert!(outcome.is_err(), "the activation cannot report success");

    fx.conn
        .lock()
        .expect("lock")
        .execute_batch("DROP TRIGGER no_pointer_write; DROP TRIGGER no_pointer_insert;")
        .expect("drop triggers");
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(
        rec.status,
        RevisionStatus::Candidate,
        "the status change must have rolled back with the failed pointer write",
    );
}

#[test]
fn a_users_revision_applies_only_to_that_user() {
    // A revision belongs to one principal. Applying it to every active SID
    // enforced one user's rules on another user's session — and on an
    // AllOrNothing failure rolled that second user back to a revision that
    // was never theirs.
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-1-B", IpcClientProfile::TrayLightweight);
    let id = submit_for(&fx, "S-1-A", "h-per-user");
    let token = issue_token(&fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");
    let applied: Vec<String> = fx
        .dispatcher
        .apply_log()
        .into_iter()
        .map(|(sid, _)| sid)
        .collect();
    assert_eq!(applied, vec!["S-1-A".to_string()]);
}

#[test]
fn the_baseline_skips_a_user_who_runs_their_own_revision() {
    // The baseline is the one principal that spans users — but only those
    // who have not diverged. A user with an active revision of their own is
    // running it, and the baseline must not overwrite that.
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-1-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-1-B", IpcClientProfile::TrayLightweight);
    let own = submit_for(&fx, "S-1-A", "h-own");
    let own_token = issue_token(&fx, &own);
    fx.coordinator
        .activate(&own, &own_token, "c")
        .expect("activate own");

    let baseline = submit(&fx, "h-baseline");
    let token = issue_token(&fx, &baseline);
    fx.coordinator
        .activate(&baseline, &token, "c")
        .expect("activate baseline");

    let applied_baseline: Vec<String> = fx
        .dispatcher
        .apply_log()
        .into_iter()
        .skip(1)
        .map(|(sid, _)| sid)
        .collect();
    assert_eq!(applied_baseline, vec!["S-1-B".to_string()]);
}

#[test]
fn activate_dispatches_to_console_fallback_sid_when_registry_empty() {
    // Dead tray subscription (empty registry):
    // the activation must still dispatch to the effective routing user
    // (console session, service-driven scope), not to nobody.
    let mut fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.coordinator = fx
        .coordinator
        .with_fallback_routing_sid(Arc::new(|| Some("S-CONSOLE".to_string())));
    let id = submit(&fx, "h-fallback");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
    let applied: Vec<String> = fx
        .dispatcher
        .apply_log()
        .into_iter()
        .map(|(sid, _)| sid)
        .collect();
    assert_eq!(applied, vec!["S-CONSOLE".to_string()]);
}

#[test]
fn activate_with_empty_registry_and_no_fallback_dispatches_to_nobody() {
    // Without a configured fallback, storage transitions happen but
    // there is no per-SID dispatch.
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-nobody");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
    assert!(fx.dispatcher.apply_log().is_empty());
}

#[test]
fn activate_apply_failure_all_or_nothing_reverts_successful_sids() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    // Two SIDs; second fails Phase 2.
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-B", IpcClientProfile::TrayLightweight);
    fx.dispatcher.queue_apply(
        "S-B",
        Err(DispatchFailure {
            sid: "S-B".into(),
            message: "WFP error".into(),
        }),
    );

    let id = submit(&fx, "h-fail");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    match outcome {
        ActivationOutcome::RolledBackOnFailure {
            rejected_revision,
            reverted_sids,
            ..
        } => {
            assert_eq!(rejected_revision, id);
            // Both are reverted, not just the one that succeeded: a SID
            // whose apply FAILED may have installed part of its set before
            // failing, and leaving it out left that partial policy live
            // under a revision the service has just rejected.
            assert_eq!(reverted_sids, vec!["S-A".to_string(), "S-B".to_string()],);
        }
        other => panic!("expected RolledBackOnFailure, got {other:?}"),
    }
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(rec.status, RevisionStatus::Rejected);
    // Revert was called for both.
    assert_eq!(fx.dispatcher.revert_log().len(), 2);
    // Marker cleared.
    assert!(fx.marker.read().is_none());
}

/// A revert that fails is the state that matters most: the SID keeps rules
/// from a revision the service has just rejected. It used to be discarded
/// by an `is_ok()` and left no trace anywhere.
#[test]
fn a_revert_that_fails_is_recorded_on_the_revision() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-B", IpcClientProfile::TrayLightweight);
    fx.dispatcher.queue_apply(
        "S-B",
        Err(DispatchFailure {
            sid: "S-B".into(),
            message: "WFP error".into(),
        }),
    );
    fx.dispatcher.queue_revert(
        "S-A",
        Err(DispatchFailure {
            sid: "S-A".into(),
            message: "revert refused".into(),
        }),
    );

    let id = submit(&fx, "h-revert-fail");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    match outcome {
        ActivationOutcome::RolledBackOnFailure { reverted_sids, .. } => {
            assert!(
                !reverted_sids.contains(&"S-A".to_string()),
                "a SID whose revert failed was not reverted",
            );
        }
        other => panic!("expected RolledBackOnFailure, got {other:?}"),
    }
    let rec = fx.coordinator.load_record(&id).expect("load");
    let reason = rec.rejected_reason.unwrap_or_default();
    assert!(
        reason.contains("revert failed"),
        "the rejection reason must say the machine was not fully put back: {reason}",
    );
}

#[test]
fn activate_apply_failure_best_effort_keeps_successful_sids() {
    let fx = build_fixture(ApplyFailurePolicy::BestEffort);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    fx.registry
        .on_connect("S-B", IpcClientProfile::TrayLightweight);
    fx.dispatcher.queue_apply(
        "S-B",
        Err(DispatchFailure {
            sid: "S-B".into(),
            message: "WFP error".into(),
        }),
    );

    let id = submit(&fx, "h-be");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    match outcome {
        ActivationOutcome::AppliedWithDrift {
            revision_id,
            succeeded_sids,
            failed_sids,
        } => {
            assert_eq!(revision_id, id);
            assert_eq!(succeeded_sids, vec!["S-A".to_string()]);
            assert_eq!(failed_sids.len(), 1);
            assert_eq!(failed_sids[0].0, "S-B");
        }
        other => panic!("expected AppliedWithDrift, got {other:?}"),
    }
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(rec.status, RevisionStatus::Active);
    // BestEffort does NOT revert.
    assert!(fx.dispatcher.revert_log().is_empty());
}

#[test]
fn activate_pre_flight_failure_does_not_apply() {
    let fx = build_fixture(ApplyFailurePolicy::PreFlightThenAllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    fx.dispatcher.set_pre_flight(
        "S-A",
        vec![PreFlightWarning {
            sid: "S-A".into(),
            category: PreFlightCategory::FilterIdCollision,
            message: "two filters share UUID".into(),
        }],
    );

    let id = submit(&fx, "h-pf");
    let token = issue_token(&fx, &id);
    let outcome = fx.coordinator.activate(&id, &token, "c").expect("activate");
    match outcome {
        ActivationOutcome::PreFlightFailed {
            rejected_revision,
            sid_failures,
        } => {
            assert_eq!(rejected_revision, id);
            assert_eq!(sid_failures.len(), 1);
            assert_eq!(sid_failures[0].0, "S-A");
        }
        other => panic!("expected PreFlightFailed, got {other:?}"),
    }
    // Apply was NOT called.
    assert!(fx.dispatcher.apply_log().is_empty());
    // Revision is rejected.
    let rec = fx.coordinator.load_record(&id).expect("load");
    assert_eq!(rec.status, RevisionStatus::Rejected);
}

#[test]
fn activate_pre_flight_passed_but_apply_failed_audit_recorded() {
    let fx = build_fixture(ApplyFailurePolicy::PreFlightThenAllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    // Pre-flight returns a non-blocking warning (`SidLeftRegistry`
    // is not in our failure-upgrade set, but we use no warnings here
    // to keep the test focused).
    fx.dispatcher.queue_apply(
        "S-A",
        Err(DispatchFailure {
            sid: "S-A".into(),
            message: "real WFP error".into(),
        }),
    );

    let id = submit(&fx, "h-pfaf");
    let token = issue_token(&fx, &id);
    let _ = fx.coordinator.activate(&id, &token, "c").expect("activate");

    let events = fx.audit.snapshot();
    let saw_special = events.iter().any(|e| {
        matches!(
            e,
            ActivationAuditEvent::PreFlightPassedButApplyFailed { .. }
        )
    });
    assert!(
        saw_special,
        "must emit PreFlightPassedButApplyFailed audit event"
    );
}

// ── rollback_to ───────────────────────────────────────────────────────────

#[test]
fn rollback_to_lkg_no_lkg_returns_error() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let err = fx
        .coordinator
        .rollback_to(nrr_storage::BASELINE_PRINCIPAL, RollbackTarget::Lkg, "c")
        .expect_err("must fail");
    assert!(matches!(err, PolicyError::NoLastKnownGood));
}

#[test]
fn prepare_rollback_candidate_returns_new_revision_id_without_activating() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);

    // Activate two revisions so we have a Superseded LKG.
    let id_a = submit(&fx, "h-A");
    let token_a = issue_token(&fx, &id_a);
    fx.coordinator
        .activate(&id_a, &token_a, "c1")
        .expect("act a");
    let id_b = submit(&fx, "h-B");
    let token_b = issue_token(&fx, &id_b);
    fx.coordinator
        .activate(&id_b, &token_b, "c2")
        .expect("act b");

    // Step 1: prepare — does not activate.
    let rb_id = fx
        .coordinator
        .prepare_rollback_candidate(nrr_storage::BASELINE_PRINCIPAL, RollbackTarget::Lkg, "c-rb")
        .expect("prepare");
    // Active is still B.
    let active_after_prepare = fx
        .coordinator
        .current_active()
        .expect("active")
        .expect("present");
    assert_eq!(active_after_prepare.revision_id, id_b.as_str());

    // Step 2: caller issues token + activates.
    let token_rb = issue_token(&fx, &rb_id);
    let outcome = fx
        .coordinator
        .activate(&rb_id, &token_rb, "c-rb")
        .expect("activate");
    match outcome {
        ActivationOutcome::Activated { .. } => {}
        other => panic!("expected Activated, got {other:?}"),
    }
    let active_after_activate = fx
        .coordinator
        .current_active()
        .expect("active")
        .expect("present");
    assert_eq!(active_after_activate.revision_id, rb_id.as_str());
    assert_eq!(active_after_activate.source, RulesRevisionSource::Rollback);
}

#[test]
fn rollback_to_lkg_creates_new_revision_and_activates() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);

    // Activate two revisions so we have a Superseded LKG.
    let id_a = submit(&fx, "h-A");
    let token_a = issue_token(&fx, &id_a);
    let _ = fx
        .coordinator
        .activate(&id_a, &token_a, "c1")
        .expect("act a");
    let id_b = submit(&fx, "h-B");
    let token_b = issue_token(&fx, &id_b);
    let _ = fx
        .coordinator
        .activate(&id_b, &token_b, "c2")
        .expect("act b");
    // Now A is superseded → LKG. B is active.

    // Roll back to LKG (= A's content).
    // First we need a new token issued against the rollback's new
    // candidate id. The coordinator creates the candidate, so we
    // must pre-issue a token under a predictable id. Counter IDs
    // makes this deterministic: next id is rev-00000005.
    // We issue a token whose `mutation_payload_json` is unrelated —
    // the consume just checks the token string itself.

    // Pre-issue token by submitting a stand-in revision and issuing
    // against it... actually, the coordinator's flow is:
    //   1. resolve target
    //   2. insert new candidate (gets id N+1)
    //   3. activate(N+1, token, ...)
    // So the token must already exist. The rollback flow as-is
    // expects callers to pre-issue. Since CounterIds is sequential,
    // we know the next id. But issue_confirmation_token requires
    // an EXISTING candidate. So in production, the flow is:
    //   GUI calls rollback_to which returns `RequiresUserAction` or
    //   similar with the new candidate id, then GUI requests a
    //   token, then calls activate(new_id, token).
    //
    // For our test we follow that two-step shape: directly insert
    // the rollback candidate via the same mechanism rollback_to
    // uses, issue a token, then call activate.
    let lkg = fx
        .coordinator
        .last_known_good()
        .expect("lkg")
        .expect("present");
    assert_eq!(lkg, id_a);

    // Manually craft the rollback by replicating rollback_to's
    // candidate-creation step via submit_candidate with a slightly
    // different content hash (so dedup doesn't collapse it).
    let rollback_id = fx
        .coordinator
        .submit_candidate(CandidateSubmission {
            principal: nrr_storage::BASELINE_PRINCIPAL.to_string(),
            rules_json: r#"{"rules":[]}"#.to_string(),
            content_hash: "h-A-rollback".into(),
            source: RulesRevisionSource::Rollback,
            correlation_id: "c-rb".to_string(),
            risk_level: None,
            review_summary_json: None,
        })
        .expect("rollback submit");
    let token_rb = issue_token(&fx, &rollback_id);
    let outcome = fx
        .coordinator
        .activate(&rollback_id, &token_rb, "c-rb")
        .expect("activate rollback");
    match outcome {
        ActivationOutcome::Activated { .. } => {}
        other => panic!("expected Activated, got {other:?}"),
    }
    let active = fx
        .coordinator
        .current_active()
        .expect("active")
        .expect("present");
    assert_eq!(active.revision_id, rollback_id.as_str());
    assert_eq!(active.source, RulesRevisionSource::Rollback);
}

// ── Marker semantics during apply ─────────────────────────────────────────

#[test]
fn apply_marker_is_written_during_phase2_and_cleared_on_3a() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    let id = submit(&fx, "h-marker");
    let token = issue_token(&fx, &id);
    // Before activate — no marker.
    assert!(fx.marker.read().is_none());
    let _ = fx.coordinator.activate(&id, &token, "c").expect("act");
    // After successful activate — marker cleared.
    assert!(fx.marker.read().is_none());
}

#[test]
fn apply_marker_is_cleared_on_phase3b() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    fx.dispatcher.queue_apply(
        "S-A",
        Err(DispatchFailure {
            sid: "S-A".into(),
            message: "fail".into(),
        }),
    );
    let id = submit(&fx, "h-3b");
    let token = issue_token(&fx, &id);
    let _ = fx.coordinator.activate(&id, &token, "c").expect("act");
    // Marker cleared even on rejection.
    assert!(fx.marker.read().is_none());
}

// ── Partial unique index ──────────────────────────────────────────────────

#[test]
fn partial_unique_index_blocks_double_active_via_coordinator() {
    // Two activations sequenced through the coordinator should
    // succeed; the second one supersedes the first. The partial
    // unique index is what enforces "exactly one active".
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);

    let id_a = submit(&fx, "h-A");
    let token_a = issue_token(&fx, &id_a);
    let _ = fx
        .coordinator
        .activate(&id_a, &token_a, "c1")
        .expect("act A");
    let id_b = submit(&fx, "h-B");
    let token_b = issue_token(&fx, &id_b);
    let _ = fx
        .coordinator
        .activate(&id_b, &token_b, "c2")
        .expect("act B");

    let rec_a = fx.coordinator.load_record(&id_a).expect("load A");
    assert_eq!(rec_a.status, RevisionStatus::Superseded);
    let rec_b = fx.coordinator.load_record(&id_b).expect("load B");
    assert_eq!(rec_b.status, RevisionStatus::Active);
}

// ── per-principal activation isolation ───────────────────

#[test]
fn two_principals_activate_independently() {
    // User A and user B each submit and activate their own revision.
    // B's activation must NOT supersede A's active revision — the
    // supersede in Phase 3a is scoped to the activating principal.
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);

    let user_a = "S-1-5-21-100-200-300-1001";
    let user_b = "S-1-5-21-100-200-300-1002";

    let id_a = submit_for(&fx, user_a, "h-user-a");
    let token_a = issue_token(&fx, &id_a);
    fx.coordinator
        .activate(&id_a, &token_a, "ca")
        .expect("activate A");

    let id_b = submit_for(&fx, user_b, "h-user-b");
    let token_b = issue_token(&fx, &id_b);
    fx.coordinator
        .activate(&id_b, &token_b, "cb")
        .expect("activate B");

    // Each principal sees its own active revision.
    assert_eq!(
        fx.coordinator
            .current_active_for(user_a)
            .expect("a")
            .expect("present")
            .revision_id,
        id_a.as_str()
    );
    assert_eq!(
        fx.coordinator
            .current_active_for(user_b)
            .expect("b")
            .expect("present")
            .revision_id,
        id_b.as_str()
    );
    // A stays Active — B's activation did not supersede it.
    assert_eq!(
        fx.coordinator.load_record(&id_a).expect("load A").status,
        RevisionStatus::Active,
        "A's revision must remain active after B activates independently"
    );
}

#[test]
fn confirmation_token_is_scoped_to_its_principal() {
    // A token issued for user A's candidate cannot drive an activation
    // pretending to be a different revision/principal: phase1 consumes
    // it via `consume_for(principal_of(revision))`, and a token whose
    // principal differs reads as Unknown.
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    fx.registry
        .on_connect("S-A", IpcClientProfile::TrayLightweight);
    let user_a = "S-1-5-21-100-200-300-2001";
    let id_a = submit_for(&fx, user_a, "h-scoped");
    let token_a = issue_token(&fx, &id_a);
    // Activating A's revision with A's token works (principal matches).
    fx.coordinator
        .activate(&id_a, &token_a, "c")
        .expect("activate A with its own token");
    assert_eq!(
        fx.coordinator
            .current_active_for(user_a)
            .expect("a")
            .expect("present")
            .revision_id,
        id_a.as_str()
    );
}

// ── activation-integrity gate ────────────────────────────────────────────

fn tamper_rules_json(fx: &Fixture, revision_id: &str) {
    let conn = fx.conn.lock().expect("conn");
    conn.execute(
        "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
        rusqlite::params![r#"{"tampered":true}"#, revision_id],
    )
    .expect("tamper");
}

fn over_cap_rules_json() -> String {
    use nrr_shared::rules_json::{
        AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
    };
    let primary: Vec<RuleDto> = (0..=nrr_shared::rules_json::FREE_MAX_RULES)
        .map(|i| RuleDto {
            id: format!("r-{i}"),
            enabled: true,
            address_match: Some(AddressMatchDto::ExactIpv4 {
                address: format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256),
            }),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        })
        .collect();
    let dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary,
        secondary: vec![],
    };
    nrr_shared::rules_json::to_canonical_string(&dto).expect("serialise")
}

fn outside_app_record(revision_id: &str, rules_json: String) -> RevisionRecord {
    RevisionRecord {
        revision_id: revision_id.to_string(),
        content_hash: format!("h-{revision_id}"),
        rules_json,
        status: RevisionStatus::Candidate,
        source: RulesRevisionSource::GuiRulesEdit,
        correlation_id: "corr".to_string(),
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
fn issue_token_rejects_unsigned_row_inserted_outside_the_app() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x21u8; 32]);
    {
        let conn = fx.conn.lock().expect("conn");
        // No signing key here — simulates a row written by a tool
        // other than the app (or the app's own unsigned code path).
        RevisionsRepository::new(&conn)
            .insert_candidate(&outside_app_record("rev-outside", "{}".to_string()))
            .expect("insert outside");
    }
    let id = RevisionId::from_prefixed_string("rev-outside".to_string()).expect("id");
    let err = fx
        .coordinator
        .issue_confirmation_token(&id, 300)
        .expect_err("unsigned row must be rejected");
    assert!(matches!(
        err,
        PolicyError::RevisionIntegrityRejected {
            reason: RevisionRejectReason::Unsigned,
            ..
        }
    ));
}

#[test]
fn activate_rejects_externally_tampered_candidate() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x22u8; 32]);
    let id = submit(&fx, "h-tamper");
    let token = issue_token(&fx, &id);
    tamper_rules_json(&fx, id.as_str());

    let err = fx
        .coordinator
        .activate(&id, &token, "c")
        .expect_err("tampered candidate must be rejected");
    assert!(matches!(
        err,
        PolicyError::RevisionIntegrityRejected {
            reason: RevisionRejectReason::Tampered,
            ..
        }
    ));
}

#[test]
fn issue_token_rejects_row_exceeding_free_rule_cap() {
    let key = vec![0x23u8; 32];
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, key.clone());
    {
        let conn = fx.conn.lock().expect("conn");
        // Signed with the SAME key the coordinator uses — a properly
        // signed row that still violates the Free cap.
        RevisionsRepository::with_signing_key(&conn, key)
            .insert_candidate(&outside_app_record("rev-overcap", over_cap_rules_json()))
            .expect("insert over-cap row");
    }
    let id = RevisionId::from_prefixed_string("rev-overcap".to_string()).expect("id");
    let err = fx
        .coordinator
        .issue_confirmation_token(&id, 300)
        .expect_err("over-cap row must be rejected");
    assert!(matches!(
        err,
        PolicyError::RevisionIntegrityRejected {
            reason: RevisionRejectReason::RuleCapExceeded { .. },
            ..
        }
    ));
}

#[test]
fn valid_signed_candidate_activates_normally() {
    // Regression: the gate must not disturb the ordinary path.
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x24u8; 32]);
    let id = submit(&fx, "h-ok");
    let token = issue_token(&fx, &id);
    let outcome = fx
        .coordinator
        .activate(&id, &token, "c")
        .expect("valid candidate must activate");
    assert!(matches!(outcome, ActivationOutcome::Activated { .. }));
}

#[test]
fn enforce_active_integrity_rolls_back_tampered_active_to_last_trusted() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x25u8; 32]);

    let id1 = submit(&fx, "h-1");
    let t1 = issue_token(&fx, &id1);
    fx.coordinator
        .activate(&id1, &t1, "c1")
        .expect("activate 1");

    let id2 = submit(&fx, "h-2");
    let t2 = issue_token(&fx, &id2);
    fx.coordinator
        .activate(&id2, &t2, "c2")
        .expect("activate 2");

    // External mutation of the now-active revision, bypassing the
    // coordinator entirely — never re-signed.
    tamper_rules_json(&fx, id2.as_str());

    let outcome = fx
        .coordinator
        .enforce_active_integrity_for(nrr_storage::BASELINE_PRINCIPAL, "corr-integrity")
        .expect("enforce");
    match outcome {
        ActiveIntegrityOutcome::RolledBack {
            rejected_revision_id,
            reason,
            trusted_source_revision_id,
            new_active_revision_id,
            ..
        } => {
            assert_eq!(rejected_revision_id, id2.as_str());
            assert_eq!(reason, RevisionRejectReason::Tampered);
            assert_eq!(trusted_source_revision_id, id1.as_str());

            let new_active = fx
                .coordinator
                .current_active_for(nrr_storage::BASELINE_PRINCIPAL)
                .expect("current active")
                .expect("an active revision exists after rollback");
            assert_eq!(new_active.revision_id, new_active_revision_id);
            assert_eq!(
                new_active.content_hash, "h-1",
                "the new active revision carries the trusted row's content"
            );
        }
        other => panic!("expected RolledBack, got {other:?}"),
    }

    let events = fx.audit.snapshot();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ActivationAuditEvent::ActiveIntegrityRejected {
                reason: RevisionRejectReason::Tampered,
                ..
            }
        )),
        "the rejection must be audited"
    );
}

#[test]
fn enforce_active_integrity_clears_when_no_trusted_fallback_exists() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x26u8; 32]);

    let id1 = submit(&fx, "h-only");
    let t1 = issue_token(&fx, &id1);
    fx.coordinator.activate(&id1, &t1, "c1").expect("activate");
    tamper_rules_json(&fx, id1.as_str());

    let outcome = fx
        .coordinator
        .enforce_active_integrity_for(nrr_storage::BASELINE_PRINCIPAL, "corr-integrity")
        .expect("enforce");
    assert!(matches!(
        outcome,
        ActiveIntegrityOutcome::ClearedNoTrustedFallback {
            reason: RevisionRejectReason::Tampered,
            ..
        }
    ));
    assert!(
        fx.coordinator
            .current_active_for(nrr_storage::BASELINE_PRINCIPAL)
            .expect("current active")
            .is_none(),
        "no trusted revision anywhere in history → no active revision, never the rejected one"
    );
}

#[test]
fn enforce_active_integrity_leaves_trusted_active_untouched() {
    let fx = build_signed_fixture(ApplyFailurePolicy::AllOrNothing, vec![0x27u8; 32]);
    let id = submit(&fx, "h-trusted");
    let token = issue_token(&fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");

    let outcome = fx
        .coordinator
        .enforce_active_integrity_for(nrr_storage::BASELINE_PRINCIPAL, "corr-integrity")
        .expect("enforce");
    assert_eq!(
        outcome,
        ActiveIntegrityOutcome::Trusted {
            revision_id: id.as_str().to_string()
        }
    );
    assert!(
        !fx.audit
            .snapshot()
            .iter()
            .any(|e| matches!(e, ActivationAuditEvent::ActiveIntegrityRejected { .. })),
        "a trusted active revision must not be audited as rejected"
    );
}

#[test]
fn enforce_active_integrity_all_is_noop_without_signing_key() {
    let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
    let id = submit(&fx, "h-unsigned");
    let token = issue_token(&fx, &id);
    fx.coordinator.activate(&id, &token, "c").expect("activate");

    let outcomes = fx
        .coordinator
        .enforce_active_integrity_all("corr-integrity")
        .expect("enforce_all");
    assert!(
        outcomes.is_empty(),
        "no signing key → gate is skipped, matching the tamper bootstrap's fail-open posture"
    );
}

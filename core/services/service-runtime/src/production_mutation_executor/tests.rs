//! Unit tests for [`super`] — ProductionMutationExecutor.
//!
//! 1049 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

use super::*;

#[test]
fn parse_rules_payload_round_trip() {
    let raw = serde_json::json!({
        "rules-json": "{\"rules\":[]}",
        "content-hash": "abc",
        "correlation-id": "corr-1",
    });
    let parsed = ProductionMutationExecutor::parse_rules_payload(&raw).unwrap();
    assert_eq!(parsed.rules_json, "{\"rules\":[]}");
    assert_eq!(parsed.content_hash, "abc");
    assert_eq!(parsed.correlation_id.as_deref(), Some("corr-1"));
}

#[test]
fn parse_rules_payload_rejects_missing_fields() {
    let raw = serde_json::json!({"rules-json": "{}"});
    let err = ProductionMutationExecutor::parse_rules_payload(&raw).unwrap_err();
    assert_eq!(err.code, "malformed-payload");
}

#[test]
fn a_rule_written_into_both_route_sets_is_reported_with_the_preview() {
    // Neither copy is wrong on its own; together they claim the same
    // traffic for two different routes, and the service cannot pick.
    let both = serde_json::json!({
        "schema-version": 1,
        "primary": [{
            "id": "r-1",
            "enabled": true,
            "address-match": { "kind": "exact-fqdn", "value": "example.com" },
            "comment": "",
            "action": "route",
        }],
        "secondary": [{
            "id": "r-2",
            "enabled": true,
            "address-match": { "kind": "exact-fqdn", "value": "example.com" },
            "comment": "",
            "action": "route",
        }],
    })
    .to_string();
    let found = cross_set_duplicates_of(&both, HostPlatform::Windows);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].primary_rule_id, "r-1");
    assert_eq!(found[0].secondary_rule_id, "r-2");
    assert_eq!(found[0].match_summary, "example.com");

    // Undecodable input says nothing here — the malformed path speaks for
    // it, and inventing a duplicate report would be worse than silence.
    assert!(cross_set_duplicates_of("{", HostPlatform::Windows).is_empty());
}

/// One rule book, two spellings of the same application name: after
/// canonicalization both payloads are byte-identical and carry the same
/// content hash, which is what stops the revision churn that made the same
/// rule look added and removed on every pass.
#[test]
fn two_spellings_of_one_app_rule_become_one_payload() {
    fn payload(app: &str) -> RulesUpdatePayload {
        let rules_json = serde_json::json!({
            "schema-version": 1,
            "primary": [{
                "id": "r-1",
                "enabled": true,
                "app-match": { "pattern": { "kind": "exact", "value": app },
                               "include-child-processes": false },
                "comment": "",
                "action": "route",
            }],
            "secondary": [],
        })
        .to_string();
        let mut p = RulesUpdatePayload {
            rules_json,
            content_hash: "client-supplied".into(),
            correlation_id: None,
        };
        ProductionMutationExecutor::canonicalize_rules_payload(&mut p, HostPlatform::Windows);
        p
    }

    let typed = payload("ExampleVPN 3.0.exe");
    let stored = payload("examplevpn 3.0.exe");
    assert_eq!(typed.rules_json, stored.rules_json);
    assert_eq!(typed.content_hash, stored.content_hash);
    assert_ne!(
        typed.content_hash, "client-supplied",
        "the hash must be recomputed from the canonical form, not trusted"
    );
    assert!(typed.rules_json.contains("examplevpn 3.0.exe"));
}

/// The GUI table re-sorted is the same rule book: rules sharing one address
/// must not keep their arrival order, or the dedup that says "no change"
/// never fires. What does distinguish them still moves the hash.
#[test]
fn one_rule_book_in_two_orders_hashes_once() {
    fn rule(id: &str, app: Option<&str>, enabled: bool, action: &str) -> serde_json::Value {
        let mut r = serde_json::json!({
            "id": id,
            "enabled": enabled,
            "address-match": { "kind": "exact-fqdn", "value": "example.com" },
            "action": action,
        });
        if let Some(app) = app {
            r["app-match"] = serde_json::json!({
                "pattern": { "kind": "exact", "value": app },
                "include-child-processes": false,
            });
        }
        r
    }
    fn hash(primary: Vec<serde_json::Value>) -> String {
        let mut p = RulesUpdatePayload {
            rules_json: serde_json::json!({
                "schema-version": 1, "primary": primary, "secondary": [],
            })
            .to_string(),
            content_hash: "client-supplied".into(),
            correlation_id: None,
        };
        ProductionMutationExecutor::canonicalize_rules_payload(&mut p, HostPlatform::Windows);
        p.content_hash
    }
    let book = vec![
        rule("r-1", None, true, "route"),
        rule("r-2", Some("chrome.exe"), true, "route"),
        rule("r-3", None, true, "block"),
        rule("r-4", None, false, "route"),
    ];
    let mut reversed = book.clone();
    reversed.reverse();
    assert_eq!(hash(book.clone()), hash(reversed));

    let mut other_action = book.clone();
    other_action[0]["action"] = "block".into();
    let mut other_enabled = book.clone();
    other_enabled[0]["enabled"] = false.into();
    let mut other_app = book.clone();
    other_app[1]["app-match"]["pattern"]["value"] = "firefox.exe".into();
    for changed in [other_action, other_enabled, other_app] {
        assert_ne!(hash(book.clone()), hash(changed));
    }
}

/// A Linux service stores the name the process has; appending the Windows
/// suffix there wrote a spelling no file on the machine carries.
#[test]
fn a_linux_service_re_spells_an_app_rule_without_the_windows_suffix() {
    let mut p = RulesUpdatePayload {
        rules_json: serde_json::json!({
            "schema-version": 1,
            "primary": [{
                "id": "r-1",
                "enabled": true,
                "app-match": { "pattern": { "kind": "exact", "value": "Messenger-Desktop" },
                               "include-child-processes": false },
                "comment": "",
                "action": "route",
            }],
            "secondary": [],
        })
        .to_string(),
        content_hash: "client-supplied".into(),
        correlation_id: None,
    };
    ProductionMutationExecutor::canonicalize_rules_payload(&mut p, HostPlatform::Linux);
    assert!(
        p.rules_json.contains("\"messenger-desktop\""),
        "{}",
        p.rules_json
    );
    assert!(!p.rules_json.contains(".exe"), "{}", p.rules_json);
}

#[test]
fn an_undecodable_payload_is_left_alone_for_the_validator_to_reject() {
    let mut p = RulesUpdatePayload {
        rules_json: "not json at all".into(),
        content_hash: "h".into(),
        correlation_id: None,
    };
    ProductionMutationExecutor::canonicalize_rules_payload(&mut p, HostPlatform::Windows);
    assert_eq!(p.rules_json, "not json at all");
    assert_eq!(p.content_hash, "h");
}

#[test]
fn classify_risk_low_for_few_changes() {
    assert!(matches!(
        classify_risk_heuristic(2, 1, &[]),
        ReviewRiskLevel::Low
    ));
}

#[test]
fn classify_risk_medium_for_dozen_changes() {
    assert!(matches!(
        classify_risk_heuristic(15, 0, &[]),
        ReviewRiskLevel::Medium
    ));
}

#[test]
fn classify_risk_high_when_warnings_present() {
    let warnings = vec![PreFlightWarning {
        sid: "S".into(),
        category: crate::activation_coordinator::PreFlightCategory::FilterIdCollision,
        subjects: Vec::new(),
        message: "test".into(),
    }];
    assert!(matches!(
        classify_risk_heuristic(0, 0, &warnings),
        ReviewRiskLevel::High
    ));
}

#[test]
fn pre_flight_findings_reach_the_review_as_one_signal_per_kind() {
    let warning = |category, subjects: &[&str]| PreFlightWarning {
        sid: "S".into(),
        category,
        subjects: subjects.iter().map(|s| s.to_string()).collect(),
        message: String::new(),
    };
    let signals = pre_flight_signals(
        &[
            warning(PreFlightCategory::AppRuleUnenforceable, &["b.exe", "a.exe"]),
            warning(PreFlightCategory::AppRuleUnenforceable, &["a.exe"]),
            warning(PreFlightCategory::BindingUnresolved, &[]),
            warning(PreFlightCategory::BatchOverflow, &[]),
            warning(PreFlightCategory::FilterIdCollision, &[]),
        ],
        ApplyFailurePolicy::PreFlightThenAllOrNothing,
    );
    assert_eq!(
        signals,
        vec![
            RiskSignalDto::ApplyWillBeRefused,
            RiskSignalDto::AdditionalAdapterUnresolved,
            RiskSignalDto::AppRuleUnenforceable {
                executables: vec!["a.exe".into(), "b.exe".into()],
            },
        ]
    );
    assert!(pre_flight_signals(&[], ApplyFailurePolicy::AllOrNothing).is_empty());
}

const POLICIES: [ApplyFailurePolicy; 3] = [
    ApplyFailurePolicy::AllOrNothing,
    ApplyFailurePolicy::BestEffort,
    ApplyFailurePolicy::PreFlightThenAllOrNothing,
];

/// The review promises a refusal for exactly the findings the coordinator
/// refuses on under the policy in force.
#[test]
fn the_review_says_refused_for_exactly_what_the_policy_refuses() {
    for policy in POLICIES {
        for category in [
            PreFlightCategory::FilterIdCollision,
            PreFlightCategory::BatchOverflow,
            PreFlightCategory::InvalidRulesContent,
            PreFlightCategory::AppRuleUnenforceable,
            PreFlightCategory::BindingUnresolved,
        ] {
            let signals = pre_flight_signals(
                &[PreFlightWarning {
                    sid: "S".into(),
                    category,
                    subjects: Vec::new(),
                    message: String::new(),
                }],
                policy,
            );
            assert_eq!(
                signals.contains(&RiskSignalDto::ApplyWillBeRefused),
                category.refuses_activation(policy),
                "{category:?} under {policy:?}"
            );
        }
    }
}

/// A rule pack past one transaction is refused only by the strict policy;
/// under the others it applies, in several steps.
#[test]
fn a_batch_overflow_is_a_refusal_only_under_the_strict_policy() {
    for policy in POLICIES {
        let signals = pre_flight_signals(
            &[PreFlightWarning {
                sid: "S".into(),
                category: PreFlightCategory::BatchOverflow,
                subjects: Vec::new(),
                message: String::new(),
            }],
            policy,
        );
        let expected = if policy == ApplyFailurePolicy::PreFlightThenAllOrNothing {
            RiskSignalDto::ApplyWillBeRefused
        } else {
            RiskSignalDto::ApplyInSeveralBatches
        };
        assert_eq!(signals, vec![expected], "{policy:?}");
    }
}

// ── Real risk-scoring path ────────────────────────────────────────────

/// `score_candidate_for_payload` returns `None` when no state DB
/// connection is wired (older test fixtures). The dry-run falls
/// back to the count-based heuristic via `classify_risk_heuristic`.
#[test]
fn score_candidate_returns_none_without_state_conn() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use std::sync::Arc;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));

    // No `with_state_conn` — score_candidate_for_payload short-circuits
    // to None.
    let executor = ProductionMutationExecutor::new(Arc::clone(&coord));
    let scored = executor
        .score_candidate_for_payload(&minimal_rules_json(), nrr_storage::BASELINE_PRINCIPAL);
    assert!(scored.is_none(), "no state_conn → None");
}

/// With `with_state_conn` and a candidate that adds a high-risk
/// SuffixDomain rule (TLD), real scoring should fire
/// `BroadSuffixScope` and return `High`.
#[test]
fn score_candidate_emits_broad_suffix_scope_for_tld_addition() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use std::sync::Arc;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let executor = ProductionMutationExecutor::new(Arc::clone(&coord))
        .with_state_conn(Arc::clone(&state_conn));

    let rules_json = build_rules_json_with_suffix("com");
    let scored = executor.score_candidate_for_payload(&rules_json, nrr_storage::BASELINE_PRINCIPAL);
    let scored = scored.expect("real scoring must produce Some");
    assert_eq!(scored.level, ReviewRiskLevel::High);
    assert!(scored.signals.iter().any(|s| matches!(
        s,
        RiskSignalDto::BroadSuffixScope { label } if label == "com"
    )));
}

/// `RuleSetEmptied` fires when prev had rules and next has zero.
/// Requires an active revision in storage; we seed one then call
/// `score_candidate_for_payload` with empty rules.
#[test]
fn score_candidate_emits_rule_set_emptied_when_clearing_rules() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use std::sync::Arc;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    // Seed an active revision with 2 ExactFqdn rules.
    seed_active_revision_with_two_fqdn_rules(&state_conn);
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let executor = ProductionMutationExecutor::new(Arc::clone(&coord))
        .with_state_conn(Arc::clone(&state_conn));

    let scored = executor
        .score_candidate_for_payload(&minimal_rules_json(), nrr_storage::BASELINE_PRINCIPAL)
        .expect("scoring produced Some");
    assert_eq!(scored.level, ReviewRiskLevel::High);
    assert!(scored
        .signals
        .iter()
        .any(|s| matches!(s, RiskSignalDto::RuleSetEmptied { prev_total: 2 })));
}

/// A process-unique apply-marker subdir, so parallel
/// test coordinators never share a marker file. Lives UNDER the cargo
/// target dir (the test binary's own directory), not the system temp
/// dir, so `cargo clean` reclaims it and test runs never litter
/// `%TEMP%` with `nrr-test-markers-*` folders.
fn unique_test_marker_dir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let root = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        .unwrap_or_else(std::env::temp_dir);
    let dir = root.join(format!(
        "nrr-test-markers-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn build_test_coordinator(
    state_conn: Arc<std::sync::Mutex<rusqlite::Connection>>,
) -> Arc<ActivationCoordinator> {
    build_test_coordinator_opt(state_conn, None)
}

/// Signed coordinator for the ack-heal test.
fn build_test_coordinator_signed(
    state_conn: Arc<std::sync::Mutex<rusqlite::Connection>>,
    key: Vec<u8>,
) -> Arc<ActivationCoordinator> {
    build_test_coordinator_opt(state_conn, Some(key))
}

fn build_test_coordinator_opt(
    state_conn: Arc<std::sync::Mutex<rusqlite::Connection>>,
    key: Option<Vec<u8>>,
) -> Arc<ActivationCoordinator> {
    use crate::activation_coordinator::{ApplyFailurePolicy, IdGenerator};
    use crate::active_sid_registry::ActiveSidRegistry;
    use crate::production_coordinator::{
        NoopRulesApplyDispatcher, ProductionApplyMarkerStore, ProductionIdGenerator,
    };

    let id_gen = Arc::new(ProductionIdGenerator::new());
    // Unique per-coordinator marker dir — a single shared apply-marker
    // file in the system temp dir would let two tests running
    // `activate` in parallel race on it.
    let marker_store = Arc::new(ProductionApplyMarkerStore::new(&unique_test_marker_dir()));
    let audit_emitter = Arc::new(TestActivationAuditEmitter)
        as Arc<dyn crate::activation_coordinator::ActivationAuditEmitter>;
    let sid_registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher = Arc::new(NoopRulesApplyDispatcher)
        as Arc<dyn crate::activation_coordinator::RulesApplyDispatcher>;
    let mut coordinator = ActivationCoordinator::new(
        state_conn,
        sid_registry,
        dispatcher,
        marker_store,
        audit_emitter,
        Arc::new(crate::production_settings::SystemClock),
        Arc::clone(&id_gen) as Arc<dyn IdGenerator>,
        ApplyFailurePolicy::AllOrNothing,
    );
    if let Some(k) = key {
        coordinator = coordinator.with_signing_key(k);
    }
    Arc::new(coordinator)
}

#[test]
fn ack_of_tamper_alert_re_signs_the_shown_row_and_lifts_gate() {
    use crate::tamper_bootstrap::mutations_blocked_by_alert;
    use nrr_diagnostics::audit::alert::{
        InMemorySecurityAlertsRepository, SecurityAlert, SecurityAlertState,
        SecurityAlertsRepository,
    };
    use nrr_domain::revision::RiskLevel;
    use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::revision_hmac::HmacVerification;
    use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};

    let key = vec![0x9Au8; 32];
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));

    // Seed a signed revision, then tamper it externally so it fails
    // verification — exactly what the bootstrap would have flagged.
    {
        let g = state_conn.lock().unwrap();
        let repo = RevisionsRepository::with_signing_key(&g, key.clone());
        repo.insert_candidate(&RevisionRecord {
            revision_id: "rev-1".into(),
            content_hash: "h-1".into(),
            rules_json: "{}".into(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr".into(),
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: Some(RiskLevel::Low),
        })
        .unwrap();
        g.execute(
            "UPDATE revisions SET rules_json = '{\"x\":1}' WHERE revision_id = 'rev-1'",
            [],
        )
        .unwrap();
        assert_eq!(
            repo.verify_row_hmac("rev-1").unwrap(),
            Some(HmacVerification::Tampered),
        );
    }

    let alert_id = {
        let g = state_conn.lock().unwrap();
        let scan = RevisionsRepository::with_signing_key(&g, key.clone())
            .integrity_scan()
            .unwrap();
        crate::integrity_review::tamper_alert_id(
            scan.iter().find(|r| r.revision_id() == "rev-1").unwrap(),
        )
    };

    let coord = build_test_coordinator_signed(Arc::clone(&state_conn), key.clone());
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    alerts
        .insert(&SecurityAlert {
            alert_id: alert_id.clone(),
            kind: "db_tamper_detected".into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: "scan".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1,
            updated_at: 1,
            reason_code: "integrity.db_row_hmac_mismatch".into(),
        })
        .unwrap();
    assert!(
        mutations_blocked_by_alert(alerts.as_ref()),
        "gate blocks pre-ack"
    );

    let exec =
        ProductionMutationExecutor::new(Arc::clone(&coord)).with_alerts_repo(Arc::clone(&alerts));

    // Acknowledge through the real dry-run + execute() path.
    let payload = serde_json::json!({ "alert-id": alert_id });
    let shown: Vec<_> = exec
        .unverified_rows(MutationKind::SecurityAlertAck, &payload)
        .into_iter()
        .map(|r| r.row)
        .collect();
    assert_eq!(shown.len(), 1, "the dialog lists the tampered row");
    let stored = StoredMutation {
        kind: MutationKind::SecurityAlertAck,
        payload: serde_json::json!({ "alert-id": alert_id, "adopt-rows": shown }),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: false,
    };
    assert!(matches!(
        exec.execute(stored, nrr_storage::BASELINE_PRINCIPAL),
        MutationOutcome::Completed(_)
    ));

    // The ack re-signed the table: the previously-tampered row now
    // verifies clean.
    {
        let g = state_conn.lock().unwrap();
        let repo = RevisionsRepository::with_signing_key(&g, key);
        assert_eq!(
            repo.verify_row_hmac("rev-1").unwrap(),
            Some(HmacVerification::Verified),
            "ack must re-sign the row",
        );
    }
    // Alert moved to Acknowledged → the live gate lifts.
    let alert = alerts.find_by_id(&alert_id).unwrap().unwrap();
    assert_eq!(alert.state, SecurityAlertState::Acknowledged);
    assert!(
        !mutations_blocked_by_alert(alerts.as_ref()),
        "gate lifts post-ack"
    );
}

#[test]
fn reimport_of_superseded_content_reactivates_instead_of_failing() {
    // Re-applying rules whose content hash matches a `Superseded`
    // revision dedups to that revision; the executor re-activates it
    // via `rollback_to(Specific)` rather than failing the
    // `Candidate`-only `activate` gate with
    // `RevisionNotInExpectedStatus { actual: Superseded, expected:
    // "candidate" }`.
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let exec = ProductionMutationExecutor::new(Arc::clone(&coord));

    let rules_update = |content_hash: &str, body: &str| StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": body,
            "content-hash": content_hash,
        }),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: false,
    };
    let active_hash = || coord.current_active().unwrap().map(|r| r.content_hash);

    // 1. Apply A → A active.
    assert!(matches!(
        exec.execute(
            rules_update("hash-A", r#"{"v":"a"}"#),
            nrr_storage::BASELINE_PRINCIPAL
        ),
        MutationOutcome::Completed(_)
    ));
    assert_eq!(active_hash().as_deref(), Some("hash-A"));

    // 2. Apply B → B active, A superseded.
    assert!(matches!(
        exec.execute(
            rules_update("hash-B", r#"{"v":"b"}"#),
            nrr_storage::BASELINE_PRINCIPAL
        ),
        MutationOutcome::Completed(_)
    ));
    assert_eq!(active_hash().as_deref(), Some("hash-B"));

    // 3. Re-apply A (dedups to the now-Superseded revision). Must
    //    succeed and make A active again — NOT fail.
    let outcome = exec.execute(
        rules_update("hash-A", r#"{"v":"a"}"#),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "re-import of superseded content must reactivate, got {outcome:?}"
    );
    assert_eq!(
        active_hash().as_deref(),
        Some("hash-A"),
        "the previously-superseded revision A must be live again"
    );
}

#[test]
fn reset_to_baseline_clears_principal_divergence() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    const SID_A: &str = "S-1-5-21-9000-1";

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let exec = ProductionMutationExecutor::new(Arc::clone(&coord));

    let reset = || StoredMutation {
        kind: MutationKind::RulesResetToBaseline,
        payload: serde_json::json!({}),
        correlation_id: None,
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: false,
    };

    // No divergence yet → preview reports the benign no-op, execute is
    // a clean Completed with zero deleted.
    let pre = exec.preview(
        MutationKind::RulesResetToBaseline,
        &serde_json::json!({}),
        SID_A,
    );
    assert!(!pre.requires_review, "no divergence → no review needed");
    assert!(pre.diff_summary.contains("already on baseline"));
    match exec.execute(reset(), SID_A) {
        MutationOutcome::Completed(p) => {
            assert_eq!(p.get("deleted-revisions").and_then(|v| v.as_u64()), Some(0));
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    // A diverges with its own active revision.
    let rules_update = StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": r#"{"v":"a"}"#,
            "content-hash": "hash-A",
        }),
        correlation_id: None,
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: false,
    };
    assert!(matches!(
        exec.execute(rules_update, SID_A),
        MutationOutcome::Completed(_)
    ));
    assert!(
        coord.current_active_for(SID_A).unwrap().is_some(),
        "A must now have its own active revision"
    );

    // Preview now reports divergence (review required).
    let div = exec.preview(
        MutationKind::RulesResetToBaseline,
        &serde_json::json!({}),
        SID_A,
    );
    assert!(div.requires_review);
    assert!(div.diff_summary.contains("discard"));

    // Reset → A's revisions gone, read-through resumes (no own active).
    match exec.execute(reset(), SID_A) {
        MutationOutcome::Completed(p) => {
            assert_eq!(
                p.get("outcome").and_then(|v| v.as_str()),
                Some("reset-to-baseline")
            );
            assert!(p.get("deleted-revisions").and_then(|v| v.as_u64()).unwrap() >= 1);
        }
        other => panic!("expected Completed, got {other:?}"),
    }
    assert!(
        coord.current_active_for(SID_A).unwrap().is_none(),
        "after reset A has no own revision → provider read-through to baseline"
    );
}

/// A user's rules change is that user's news; the baseline's reaches every
/// session, since every un-diverged user runs it.
#[test]
fn mutation_progress_reaches_only_the_owner_of_the_changed_rules() {
    const SID_A: &str = "S-1-5-21-9000-1";
    const SID_B: &str = "S-1-5-21-9000-2";
    let (exec, _conn) = build_test_executor();
    let bus = Arc::new(EventBus::new());
    let exec = exec.with_event_bus(Arc::clone(&bus));
    let a = bus.subscribe_as("gui-a".into(), Some(SID_A.into()), None);
    let b = bus.subscribe_as("gui-b".into(), Some(SID_B.into()), None);
    let update = |correlation: &str| StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": r#"{"schema-version":1,"primary":[],"secondary":[]}"#,
            "content-hash": "h",
        }),
        correlation_id: Some(correlation.into()),
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: true,
    };
    let progress = |sub: &str| -> Vec<String> {
        bus.peek_pending_for(sub, 64)
            .into_iter()
            .filter_map(|e| match e.event {
                StatusUpdateEvent::MutationProgress {
                    correlation_id,
                    phase,
                    ..
                } => Some(format!("{correlation_id}:{phase}")),
                _ => None,
            })
            .collect()
    };

    exec.execute(update("corr-own"), SID_A);
    assert_eq!(progress(&a.subscription_id).len(), 2, "started + terminal");
    assert!(
        progress(&b.subscription_id).is_empty(),
        "another user must not see this user's rules change"
    );

    exec.execute(update("corr-baseline"), nrr_storage::BASELINE_PRINCIPAL);
    for sub in [&a.subscription_id, &b.subscription_id] {
        assert_eq!(
            progress(sub)
                .iter()
                .filter(|p| p.starts_with("corr-baseline:"))
                .count(),
            2,
            "the baseline change reaches every session"
        );
    }
}

/// Alerts and the audit chain are the machine's, whoever confirmed them.
#[test]
fn machine_wide_mutations_are_not_addressed_to_their_confirmer() {
    const SID_A: &str = "S-1-5-21-9000-1";
    assert_eq!(
        progress_addressee(MutationKind::RulesUpdate, SID_A).as_deref(),
        Some(SID_A)
    );
    for kind in [
        MutationKind::AuditChainRestart,
        MutationKind::SecurityAlertAck,
    ] {
        assert_eq!(progress_addressee(kind, SID_A), None, "{kind:?}");
    }
}

/// An acknowledgement changes the alert list every session shows, and only a
/// change does: a refused transition announces nothing.
#[test]
fn an_alert_state_change_tells_every_session_to_reread_the_list() {
    use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlert};

    const SID_A: &str = "S-1-5-21-9000-1";
    const SID_B: &str = "S-1-5-21-9000-2";
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    alerts
        .insert(&SecurityAlert {
            alert_id: "alt-audit-1".into(),
            kind: "tamper_alert_raised".into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: "scan".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1,
            updated_at: 1,
            reason_code: "r".into(),
        })
        .unwrap();
    let (exec, _conn) = build_test_executor();
    let bus = Arc::new(EventBus::new());
    let exec = exec
        .with_alerts_repo(Arc::clone(&alerts))
        .with_event_bus(Arc::clone(&bus));
    let a = bus.subscribe_as("gui-a".into(), Some(SID_A.into()), None);
    let b = bus.subscribe_as("gui-b".into(), Some(SID_B.into()), None);
    let announced = |sub: &str| {
        bus.peek_pending_for(sub, 64)
            .into_iter()
            .filter(|e| matches!(e.event, StatusUpdateEvent::SecurityAlertsChanged))
            .count()
    };
    let ack = || StoredMutation {
        kind: MutationKind::SecurityAlertAck,
        payload: serde_json::json!({ "alert-id": "alt-audit-1" }),
        correlation_id: None,
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: false,
    };

    assert!(matches!(
        exec.execute(ack(), SID_A),
        MutationOutcome::Completed(_)
    ));
    for sub in [&a.subscription_id, &b.subscription_id] {
        assert_eq!(announced(sub), 1, "{sub}");
    }

    assert!(matches!(
        exec.execute(ack(), SID_A),
        MutationOutcome::Failed(_)
    ));
    assert_eq!(
        announced(&a.subscription_id),
        1,
        "a refused ack changed nothing"
    );
}

/// Acknowledging and resolving an alert each leave their own event in the
/// audit trail, and the alert points at that exact line.
#[test]
fn an_alert_state_change_is_audited_and_the_alert_points_at_the_line() {
    use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlert};
    use nrr_diagnostics::audit::AuditReader;
    use nrr_diagnostics::facade::dto::DiagnosticsAudience;
    use nrr_diagnostics::{AuditWriter, AuditWriterConfig};

    const SID_A: &str = "S-1-5-21-9000-1";
    let dir = tempfile::tempdir().expect("tempdir");
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    alerts
        .insert(&SecurityAlert {
            alert_id: "alt-audit-2".into(),
            kind: "tamper_alert_raised".into(),
            state: SecurityAlertState::Active,
            raised_event_seq: 0,
            raised_file: "scan".into(),
            ack_event_seq: None,
            ack_file: None,
            resolved_event_seq: None,
            resolved_file: None,
            created_at: 1,
            updated_at: 1,
            reason_code: "r".into(),
        })
        .unwrap();
    let (exec, _conn) = build_test_executor();
    let exec = exec
        .with_alerts_repo(Arc::clone(&alerts))
        .with_audit_writer(Arc::new(AuditWriter::open(AuditWriterConfig::new(
            dir.path(),
        ))));
    let change = |kind| StoredMutation {
        kind,
        payload: serde_json::json!({ "alert-id": "alt-audit-2" }),
        correlation_id: None,
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: false,
    };

    for kind in [
        MutationKind::SecurityAlertAck,
        MutationKind::SecurityAlertResolve,
    ] {
        assert!(matches!(
            exec.execute(change(kind), SID_A),
            MutationOutcome::Completed(_)
        ));
    }

    let events = AuditReader::new(dir.path()).scan(
        &nrr_diagnostics::audit::AuditQueryFilter::new(),
        &DiagnosticsAudience::Machine,
    );
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["tamper_alert_acknowledged", "tamper_alert_resolved"]
    );
    assert!(events.iter().all(|e| e.actor_kind == "user"));
    let alert = alerts
        .find_by_id("alt-audit-2")
        .unwrap()
        .expect("alert kept");
    let kind_at = |seq: Option<u64>| {
        events
            .iter()
            .find(|e| Some(e.seq) == seq)
            .map(|e| e.kind.as_str())
    };
    assert_eq!(
        kind_at(alert.ack_event_seq),
        Some("tamper_alert_acknowledged")
    );
    assert_eq!(
        kind_at(alert.resolved_event_seq),
        Some("tamper_alert_resolved")
    );
    let files = AuditReader::new(dir.path()).list_files();
    let file_name = files[0]
        .file_name()
        .and_then(|n| n.to_str())
        .expect("file name")
        .to_string();
    assert_eq!(alert.ack_file.as_deref(), Some(file_name.as_str()));
    assert_eq!(alert.resolved_file.as_deref(), Some(file_name.as_str()));
}

struct TestActivationAuditEmitter;
impl crate::activation_coordinator::ActivationAuditEmitter for TestActivationAuditEmitter {
    fn emit(&self, _event: crate::activation_coordinator::ActivationAuditEvent) {}
}

fn minimal_rules_json() -> String {
    use nrr_shared::rules_json::{
        to_canonical_string, CanonicalRulesJsonV1, RULES_JSON_SCHEMA_VERSION,
    };
    to_canonical_string(&CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![],
        secondary: vec![],
    })
    .unwrap()
}

fn build_rules_json_with_suffix(suffix: &str) -> String {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, CanonicalRulesJsonV1, RuleDto,
        RULES_JSON_SCHEMA_VERSION,
    };
    to_canonical_string(&CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![RuleDto {
            id: "r-suf".into(),
            enabled: true,
            address_match: Some(AddressMatchDto::SuffixDomain {
                suffix: suffix.into(),
            }),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        }],
        secondary: vec![],
    })
    .unwrap()
}

fn seed_active_revision_with_two_fqdn_rules(conn: &std::sync::Mutex<rusqlite::Connection>) {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, CanonicalRulesJsonV1, RuleDto,
        RULES_JSON_SCHEMA_VERSION,
    };
    let dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![
            RuleDto {
                id: "r-1".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: "api.example.com".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            },
            RuleDto {
                id: "r-2".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: "www.example.com".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            },
        ],
        secondary: vec![],
    };
    let rules_json = to_canonical_string(&dto).unwrap();
    let g = conn.lock().unwrap();
    // `revisions` is per-principal; seed under the
    // baseline sentinel the production read path uses via the shim.
    g.execute(
        "INSERT INTO revisions (
            principal, revision_id, content_hash, rules_json, status, source,
            correlation_id, created_at, activated_at
         ) VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', ?5, ?6, ?6)",
        rusqlite::params![
            nrr_storage::BASELINE_PRINCIPAL,
            "rev-prev-001",
            "abc",
            rules_json,
            "corr-1",
            1_700_000_000_i64
        ],
    )
    .expect("insert");
}

#[test]
fn dry_run_to_review_summary_aggregates_per_sid() {
    let summary = DryRunSummary {
        revision_id: Some(RevisionId::from_prefixed_string("rev-test".into()).unwrap()),
        action_plans: vec![
            crate::activation_coordinator::SidActionPlanSummary {
                sid: "S-1".into(),
                filter_additions: 3,
                filter_removals: 1,
                routing_actions: 0,
            },
            crate::activation_coordinator::SidActionPlanSummary {
                sid: "S-2".into(),
                filter_additions: 2,
                filter_removals: 0,
                routing_actions: 1,
            },
        ],
        pre_flight_warnings: Vec::new(),
        estimated_duration_ms: 50,
    };
    let review = dry_run_to_review_summary(&summary, None, ApplyFailurePolicy::AllOrNothing);
    assert!(review.diff_summary.contains("+5"));
    assert!(review.diff_summary.contains("-1"));
    assert_eq!(review.changed_fields.len(), 2);
    assert!(review.requires_review);
}

// ── PresetImport pipeline ───────────────────────────────────────────────

fn build_test_executor() -> (
    ProductionMutationExecutor,
    Arc<std::sync::Mutex<rusqlite::Connection>>,
) {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let exec = ProductionMutationExecutor::new(Arc::clone(&coord))
        .with_state_conn(Arc::clone(&state_conn));
    (exec, state_conn)
}

fn b64(text: &str) -> String {
    BASE64_STANDARD.encode(text.as_bytes())
}

/// Minimal valid single-route preset: one Domains entry.
const SAMPLE_PRESET: &str = "--- Domains\nexample.com\n";

#[test]
fn preset_import_payload_with_no_bytes_is_rejected_as_malformed() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "include-child-processes": false,
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    assert!(matches!(
        outcome,
        MutationOutcome::Failed(OperationError { ref code, .. }) if code == "malformed-payload"
    ));
}

#[test]
fn preset_import_rejects_route_mismatch() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "route": "secondary",
        "primary-bytes-b64": b64(SAMPLE_PRESET),
        "include-child-processes": false,
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    let MutationOutcome::Failed(err) = outcome else {
        panic!("expected Failed, got {outcome:?}");
    };
    assert_eq!(err.code, "malformed-payload");
    assert!(err.message.contains("mismatches"));
}

#[test]
fn preset_import_rejects_invalid_base64() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": "!!!not-base64!!!",
        "include-child-processes": false,
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    let MutationOutcome::Failed(err) = outcome else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "malformed-payload");
}

#[test]
fn preset_import_rejects_invalid_utf8_bytes() {
    let (exec, _conn) = build_test_executor();
    // UTF-16 LE BOM is FF FE — not valid UTF-8.
    let invalid = BASE64_STANDARD.encode(b"\xFF\xFE--- Domains\n");
    let payload = serde_json::json!({
        "primary-bytes-b64": invalid,
        "include-child-processes": false,
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    let MutationOutcome::Failed(err) = outcome else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "file-encoding");
}

/// A preset the service cannot read previews as a refusal under the code its
/// execute fails with, not as a change set the window could offer to apply.
#[test]
fn an_unreadable_preset_previews_as_a_refusal() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": BASE64_STANDARD.encode(b"\xFF\xFE--- Domains\n"),
        "include-child-processes": false,
    });
    let review = exec.preview_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    assert_eq!(
        review.risk_signals,
        vec![RiskSignalDto::ChangeRefused {
            code: "file-encoding".into(),
            args: Default::default(),
        }]
    );
    assert!(
        review.changed_fields.is_empty(),
        "a refusal carries nothing to review: {:?}",
        review.changed_fields
    );
}

#[test]
fn preset_import_rejects_inline_comment_over_limit() {
    let (exec, _conn) = build_test_executor();
    let long = "a".repeat(201);
    let preset = format!("--- Domains\nexample.com  # {long}\n");
    let payload = serde_json::json!({
        "primary-bytes-b64": b64(&preset),
        "include-child-processes": false,
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    let MutationOutcome::Failed(err) = outcome else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "inline-comment-too-long");
}

/// A preset and a rules payload are refused under one code, so the window
/// shows one message for the same defect.
#[test]
fn preset_and_rules_payload_refuse_a_control_character_alike() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": b64("--- Domains\nexample.com  # note\r--- IP\n"),
        "include-child-processes": false,
    });
    let MutationOutcome::Failed(err) =
        exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL)
    else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "control-character");
    let review = exec.preview_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    assert_eq!(
        review.risk_signals,
        vec![RiskSignalDto::ChangeRefused {
            code: "control-character".into(),
            args: Default::default(),
        }]
    );

    let rules_json = serde_json::json!({
        "schema-version": 1,
        "primary": [{
            "id": "r-1",
            "enabled": true,
            "address-match": { "kind": "exact-fqdn", "value": "example.com" },
            "comment": "note\n--- IP\n192.0.2.9",
        }],
        "secondary": [],
    })
    .to_string();
    let payload = serde_json::json!({ "rules-json": rules_json, "content-hash": "h" });
    let MutationOutcome::Failed(err) =
        exec.execute_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL)
    else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "control-character");
    assert!(err.message.contains("r-1"), "{}", err.message);
    let review = exec.preview_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL);
    assert_eq!(
        review.risk_signals,
        vec![RiskSignalDto::ChangeRefused {
            code: "control-character".into(),
            args: Default::default(),
        }]
    );
}

/// A value the rules table marks as an error is refused under its own code;
/// the preview names the values (in canonical rule order), so the user learns
/// which rows to fix.
#[test]
fn a_refused_rule_value_has_its_own_code_and_the_preview_names_the_values() {
    let (exec, _conn) = build_test_executor();
    let rules_json = serde_json::json!({
        "schema-version": 1,
        "primary": [
            { "id": "r-1", "enabled": true,
              "address-match": { "kind": "zone", "name": "123" } },
            { "id": "r-2", "enabled": true,
              "address-match": { "kind": "exact-fqdn", "value": "example.com" } },
            { "id": "r-3", "enabled": true,
              "address-match": { "kind": "exact-fqdn", "value": "192.0.2.1" } },
        ],
        "secondary": [],
    })
    .to_string();
    let payload = serde_json::json!({ "rules-json": rules_json, "content-hash": "h" });

    let review = exec.preview_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL);
    assert_eq!(
        review.risk_signals,
        vec![RiskSignalDto::InvalidRuleValue {
            rules: vec!["192.0.2.1".into(), "123".into()],
        }]
    );

    let MutationOutcome::Failed(err) =
        exec.execute_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL)
    else {
        panic!("expected Failed");
    };
    assert_eq!(err.code, "invalid-rule-value");
    assert!(err.message.contains("r-3, r-1"), "{}", err.message);
}

/// A long list stops at the cap and says there is more.
#[test]
fn the_preview_names_a_bounded_number_of_refused_values() {
    let refused: Vec<RefusedRuleValue> = (0..REFUSED_VALUES_SHOWN + 3)
        .map(|i| RefusedRuleValue {
            rule_id: format!("r-{i}"),
            value: format!("{i}"),
        })
        .collect();
    let summary = invalid_rule_value_summary(&refused);
    let [RiskSignalDto::InvalidRuleValue { rules }] = summary.risk_signals.as_slice() else {
        panic!("one signal expected: {:?}", summary.risk_signals);
    };
    assert_eq!(rules.len(), REFUSED_VALUES_SHOWN + 1);
    assert_eq!(rules.last().map(String::as_str), Some("…"));
}

#[test]
fn preview_preset_import_single_route_succeeds_with_empty_db() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": b64(SAMPLE_PRESET),
        "include-child-processes": false,
    });
    let review = exec.preview_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    // The coordinator's preview may succeed or fail depending on
    // empty-DB state — either way the wire shape must be a valid
    // review summary, not a malformed/precondition stub.
    assert!(!review.diff_summary.is_empty());
    assert!(!review.diff_summary.starts_with("malformed payload"));
}

/// A first revision activated while the user sits in the strict fail-closed
/// mode is exactly what `FailClosedActivation` exists to flag, and it could
/// never fire: the scorer compared two synthetic profiles that both said
/// `PreferPrimary`.
#[test]
fn the_strict_mode_of_the_caller_reaches_the_risk_scorer() {
    let (exec, conn) = build_test_executor();
    let sid = nrr_storage::BASELINE_PRINCIPAL;
    {
        let guard = conn.lock().expect("lock");
        let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
        let mut policy = repo.load_for_sid(sid).expect("load");
        // Strict mode is only storable with a bound secondary — the same
        // precondition the GUI enforces.
        policy.secondary = Some(nrr_storage::RouteBindingRecord {
            stable_id: "win-adapter:vpn".into(),
            display_name: "vpn".into(),
            user_confirmed: true,
            known_stable_ids: Vec::new(),
        });
        policy.mode = nrr_storage::route_bindings::BehaviorMode::StrictSecondaryFailClosed;
        repo.update_for_sid(sid, &policy, 0).expect("store");
    }

    let scored = exec
        .score_candidate_for_payload(r#"{"schema-version":1,"primary":[],"secondary":[]}"#, sid)
        .expect("scored");
    assert!(
        scored
            .signals
            .iter()
            .any(|s| matches!(s, RiskSignalDto::FailClosedActivation)),
        "expected the fail-closed signal, got {:?}",
        scored.signals
    );
}

/// A preview is a READ. Submitting a candidate to get a plan would write a
/// revision row on every press — rows the user would then find in their
/// pending list as edits they never made.
#[test]
fn a_preview_writes_no_revision_row() {
    let (exec, conn) = build_test_executor();
    let count = |conn: &Arc<Mutex<rusqlite::Connection>>| -> i64 {
        let guard = conn.lock().expect("lock");
        guard
            .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))
            .expect("count")
    };
    assert_eq!(count(&conn), 0, "empty to start with");

    let payload = serde_json::json!({
        "primary-bytes-b64": b64(SAMPLE_PRESET),
        "include-child-processes": false,
    });
    for _ in 0..3 {
        let _ = exec.preview_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    }
    assert_eq!(count(&conn), 0, "a preview stores nothing");
}

#[test]
fn execute_preset_import_round_trips_to_completed_outcome() {
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": b64(SAMPLE_PRESET),
        "secondary-bytes-b64": b64("--- Domains\nsecondary.example\n"),
        "include-child-processes": true,
        "correlation-id": "test-corr-1",
    });
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    // With the test coordinator's NoopRulesApplyDispatcher, activation
    // succeeds and we get Completed. The point of the test is that
    // the full assemble → submit → token → activate chain runs end
    // to end without any "not-implemented" / "malformed" surfaces.
    match outcome {
        MutationOutcome::Completed(payload) => {
            let s = payload.to_string();
            assert!(
                s.contains("revision") || s.contains("outcome"),
                "completed payload should mention revision/outcome; got {s}"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }
}

#[test]
fn execute_preset_import_identical_to_active_is_noop_success() {
    // Regression (field bug): re-importing content identical to the
    // active revision — or clearing rules that are already empty (the
    // full-reset path) — dedups in `submit_candidate` to the already-
    // ACTIVE revision. Activating it then failed with
    // `RevisionNotInExpectedStatus { actual: Active, expected: candidate }`.
    // The executor must now short-circuit to a Completed no-op instead.
    let (exec, _conn) = build_test_executor();
    let payload = serde_json::json!({
        "primary-bytes-b64": b64(SAMPLE_PRESET),
        "secondary-bytes-b64": b64("--- Domains\nsecondary.example\n"),
        "include-child-processes": false,
        "correlation-id": "noop-corr-1",
    });
    // First import activates the revision.
    assert!(matches!(
        exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL),
        MutationOutcome::Completed(_)
    ));
    // Second, identical import dedups to the now-active revision.
    let outcome = exec.execute_preset_import(&payload, nrr_storage::BASELINE_PRINCIPAL);
    match outcome {
        MutationOutcome::Completed(p) => {
            assert_eq!(
                p.get("outcome").and_then(|v| v.as_str()),
                Some("already-active"),
                "second identical import should report the already-active no-op; got {p}"
            );
        }
        other => panic!("expected Completed already-active no-op, got {other:?}"),
    }
}

#[test]
fn preset_import_single_route_preserves_active_other_route() {
    let (exec, conn) = build_test_executor();
    // Seed an active revision whose SECONDARY has a distinctive rule.
    let active_secondary = "--- Domains\nkeep-secondary-on-import.example\n";
    // To seed, we exercise the executor's primary+secondary import
    // path first — that lands a revision with both routes populated.
    let seed = serde_json::json!({
        "primary-bytes-b64": b64("--- Domains\nseed-primary.example\n"),
        "secondary-bytes-b64": b64(active_secondary),
        "include-child-processes": false,
        "correlation-id": "seed",
    });
    let seed_outcome = exec.execute_preset_import(&seed, nrr_storage::BASELINE_PRINCIPAL);
    assert!(matches!(seed_outcome, MutationOutcome::Completed(_)));

    // Now do a single-route Primary import: secondary should be
    // preserved from the seed revision.
    let new_primary = "--- Domains\nnew-primary.example\n";
    let single = serde_json::json!({
        "primary-bytes-b64": b64(new_primary),
        "include-child-processes": false,
        "correlation-id": "single",
    });
    let single_outcome = exec.execute_preset_import(&single, nrr_storage::BASELINE_PRINCIPAL);
    assert!(matches!(single_outcome, MutationOutcome::Completed(_)));

    // Read back the active revision; secondary rules must still
    // reference the seeded host.
    let guard = conn.lock().unwrap();
    let repo = nrr_storage::revisions::RevisionsRepository::new(&guard);
    let active = repo
        .get_active()
        .expect("query")
        .expect("active revision present");
    assert!(
        active
            .rules_json
            .contains("keep-secondary-on-import.example"),
        "secondary route was lost on single-route import; rules_json={}",
        active.rules_json
    );
    assert!(
        active.rules_json.contains("new-primary.example"),
        "primary route was not applied; rules_json={}",
        active.rules_json
    );
    // Old primary must be replaced.
    assert!(
        !active.rules_json.contains("seed-primary.example"),
        "old primary leaked into post-import revision; rules_json={}",
        active.rules_json
    );
}

/// Both write paths of a Linux service — a preset import and a rules edit the
/// GUI sends unvalidated — store application names as the process carries
/// them: no `.exe`, and the inactive `--- Windows` section left out.
#[test]
fn a_linux_service_stores_app_names_without_the_windows_suffix() {
    let (exec, conn) = build_test_executor();
    let exec = exec.with_host_platform(HostPlatform::Linux);
    let active_rules_json = || {
        let guard = conn.lock().unwrap();
        nrr_storage::revisions::RevisionsRepository::new(&guard)
            .get_active()
            .expect("query")
            .expect("active revision present")
            .rules_json
    };

    let preset = "--- Linux\nmessenger-desktop\nCodex*\n--- Windows\nbrowser\n";
    let import = serde_json::json!({
        "secondary-bytes-b64": b64(preset),
        "include-child-processes": false,
        "correlation-id": "linux-import",
    });
    assert!(matches!(
        exec.execute_preset_import(&import, nrr_storage::BASELINE_PRINCIPAL),
        MutationOutcome::Completed(_)
    ));
    let stored = active_rules_json();
    assert!(stored.contains("\"messenger-desktop\""), "{stored}");
    assert!(stored.contains("\"codex*\""), "{stored}");
    assert!(
        !stored.contains(".exe") && !stored.contains("browser"),
        "{stored}"
    );

    let mut dto = nrr_shared::rules_json::from_canonical_string(&stored).expect("stored parses");
    dto.secondary.push(nrr_shared::rules_json::RuleDto {
        id: "R-0009".into(),
        enabled: true,
        address_match: None,
        app_match: Some(nrr_shared::rules_json::AppMatchDto {
            pattern: nrr_shared::rules_json::AppPatternDto::Exact {
                value: "Signal-Desktop".into(),
            },
            include_child_processes: false,
        }),
        comment: String::new(),
        action: nrr_shared::rules_json::RuleAction::Route,
        origin: None,
    });
    let edit = serde_json::json!({
        "rules-json": nrr_shared::rules_json::to_canonical_string(&dto).expect("serialize"),
        "content-hash": "client-supplied",
        "correlation-id": "linux-edit",
    });
    assert!(matches!(
        exec.execute_rules_update(&edit, nrr_storage::BASELINE_PRINCIPAL),
        MutationOutcome::Completed(_)
    ));
    let stored = active_rules_json();
    assert!(stored.contains("\"signal-desktop\""), "{stored}");
    assert!(stored.contains("\"messenger-desktop\""), "{stored}");
    assert!(!stored.contains(".exe"), "{stored}");
}

// ── Administrative rules lock (defence in depth) ─────────────────────

/// The IPC handler refuses a locked user's submission first, so this test
/// exists for everything that does not pass a handler: the
/// companion-domain rule author, and any future in-process caller. If
/// only the handler enforced the lock, that path would quietly keep
/// writing rules an administrator had frozen.
#[test]
fn locked_machine_refuses_a_non_elevated_execute_at_the_executor() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    const SID_A: &str = "S-1-5-21-9000-7";

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));

    let submission = |elevated: bool| StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": r#"{"v":"locked"}"#,
            "content-hash": "hash-locked",
        }),
        correlation_id: None,
        issuer_sid: SID_A.to_string(),
        caller_is_elevated: elevated,
    };

    let locked = ProductionMutationExecutor::new(Arc::clone(&coord))
        .with_stability_provider(crate::ipc_handlers::test_fakes::FakeRulesLock::locked());
    match locked.execute(submission(false), SID_A) {
        MutationOutcome::Failed(e) => assert_eq!(e.code, "rules-locked"),
        other => panic!("expected a rules-locked refusal, got {other:?}"),
    }
    assert!(
        coord.current_active_for(SID_A).unwrap().is_none(),
        "nothing may have been persisted for the restricted principal"
    );

    // The same submission from an elevated caller goes through.
    assert!(matches!(
        locked.execute(submission(true), SID_A),
        MutationOutcome::Completed(_)
    ));
    assert!(coord.current_active_for(SID_A).unwrap().is_some());
}

/// An unwired provider must not become an accidental lockout — the
/// degraded-boot path keeps behaving exactly as it did before the lock
/// existed.
#[test]
fn executor_without_a_stability_provider_leaves_the_gate_open() {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    const SID_A: &str = "S-1-5-21-9000-8";

    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coord = build_test_coordinator(Arc::clone(&state_conn));
    let exec = ProductionMutationExecutor::new(Arc::clone(&coord));

    assert!(matches!(
        exec.execute(
            StoredMutation {
                kind: MutationKind::RulesUpdate,
                payload: serde_json::json!({
                    "rules-json": r#"{"v":"open"}"#,
                    "content-hash": "hash-open",
                }),
                correlation_id: None,
                issuer_sid: SID_A.to_string(),
                caller_is_elevated: false,
            },
            SID_A
        ),
        MutationOutcome::Completed(_)
    ));
}

// ── Tamper gate at the executor ──────────────────────────────────────

/// Any principal's rule book is empty: enough for the author to append to.
struct EmptyBook;

impl crate::per_sid_orchestrator::RulesProvider for EmptyBook {
    fn active_rules(&self) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
        Some(crate::per_sid_orchestrator::ActiveRulesSnapshot {
            rule_book: CanonicalRuleBook::default(),
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        })
    }
}

/// The tray's "route this blocked host" and companion-domain acceptance reach
/// the executor through the rule author, never through the IPC handler, so an
/// unacknowledged tamper or key-reset alert must stop them here.
#[test]
fn an_active_blocking_alert_refuses_auto_authored_rules_until_acknowledged() {
    use crate::auto_rules::{AuthoredMatchKind, AuthoredRule, AutoRuleAuthor};
    use crate::tamper_bootstrap::SECURITY_ALERT_GATE_CODE;
    use nrr_diagnostics::audit::alert::{InMemorySecurityAlertsRepository, SecurityAlert};
    use nrr_diagnostics::audit::kind::AuditEventKind;
    use nrr_shared::AutoRuleReason;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    const SID_A: &str = "S-1-5-21-9000-9";

    let rule = |host: &str| AuthoredRule {
        route: RouteRole::Secondary,
        match_kind: AuthoredMatchKind::SuffixDomain,
        value: host.to_string(),
        anchor: host.to_string(),
    };
    for kind in [
        AuditEventKind::DbTamperDetected,
        AuditEventKind::KeyResetWithExistingData,
    ] {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().unwrap();
        let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
        let coord = build_test_coordinator(Arc::clone(&state_conn));
        let alerts: Arc<dyn SecurityAlertsRepository> =
            Arc::new(InMemorySecurityAlertsRepository::new());
        alerts
            .insert(&SecurityAlert {
                alert_id: "alt-1".into(),
                kind: kind.as_str().into(),
                state: SecurityAlertState::Active,
                raised_event_seq: 0,
                raised_file: "scan".into(),
                ack_event_seq: None,
                ack_file: None,
                resolved_event_seq: None,
                resolved_file: None,
                created_at: 1,
                updated_at: 1,
                reason_code: "r".into(),
            })
            .unwrap();
        let exec = ProductionMutationExecutor::new(Arc::clone(&coord))
            .with_alerts_repo(Arc::clone(&alerts));
        let author = crate::auto_rules::ProductionAutoRuleAuthor::new(
            Arc::new(EmptyBook),
            Arc::new(exec) as Arc<dyn MutationExecutor>,
        );
        let now = SystemTime::now();

        let routed = author
            .author(
                SID_A,
                &AutoRuleReason::BlockNoticeRouted,
                &[rule("blocked.example")],
                now,
                "c-route",
            )
            .expect_err("route-blocked-host must be refused");
        assert_eq!(routed.code, SECURITY_ALERT_GATE_CODE, "{kind:?}");
        let accepted = author
            .author_with_outcome(
                SID_A,
                &AutoRuleReason::UserConfirmed,
                &[rule("cdn.example")],
                now,
                "c-accept",
            )
            .expect_err("companion acceptance must be refused");
        assert_eq!(accepted.code, SECURITY_ALERT_GATE_CODE, "{kind:?}");
        assert!(
            coord.current_active_for(SID_A).unwrap().is_none(),
            "no revision may be created while the alert is active ({kind:?})"
        );

        alerts
            .update_state("alt-1", SecurityAlertState::Acknowledged, 1, "ack", 2)
            .unwrap();
        assert_eq!(
            author
                .author(
                    SID_A,
                    &AutoRuleReason::BlockNoticeRouted,
                    &[rule("blocked.example")],
                    now,
                    "c-route-2",
                )
                .expect("route-blocked-host after acknowledgement"),
            1
        );
        let accepted = author
            .author_with_outcome(
                SID_A,
                &AutoRuleReason::UserConfirmed,
                &[rule("cdn.example")],
                now,
                "c-accept-2",
            )
            .expect("companion acceptance after acknowledgement");
        assert_eq!(accepted.authored, 1);
        assert!(coord.current_active_for(SID_A).unwrap().is_some());
    }
}

/// One rule with the given conditions, as a submitted `rules-update` payload.
fn shaped_rules_update(
    address: bool,
    app: bool,
    action: nrr_shared::rules_json::RuleAction,
    correlation: &str,
) -> serde_json::Value {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, AppMatchDto, AppPatternDto, CanonicalRulesJsonV1,
        RuleDto, RULES_JSON_SCHEMA_VERSION,
    };
    let rules_json = to_canonical_string(&CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![],
        secondary: vec![RuleDto {
            id: "R-0001".into(),
            enabled: true,
            address_match: address.then(|| AddressMatchDto::ExactFqdn {
                value: "host.example".into(),
            }),
            app_match: app.then(|| AppMatchDto {
                pattern: AppPatternDto::Exact {
                    value: "app.exe".into(),
                },
                include_child_processes: false,
            }),
            comment: String::new(),
            action,
            origin: None,
        }],
    })
    .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(rules_json.as_bytes());
    serde_json::json!({
        "rules-json": rules_json,
        "content-hash": format!("{:x}", hasher.finalize()),
        "correlation-id": correlation,
    })
}

/// Enforcement cannot limit an address to one application, so a revision
/// asking for it is refused at submission — for either action, before any row
/// is written, and the preview says the same.
#[test]
fn a_rule_naming_both_an_app_and_an_address_is_refused_at_submission() {
    use nrr_shared::rules_json::RuleAction as WireAction;
    let (exec, conn) = build_test_executor();
    for (action, slug) in [
        (WireAction::Route, "app-scoped-destination-route"),
        (WireAction::Block, "app-scoped-destination-block"),
    ] {
        let payload = shaped_rules_update(true, true, action, "corr-shape");
        match exec.execute_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL) {
            MutationOutcome::Failed(e) => {
                assert_eq!(e.code, "unsupported-rule-shape");
                assert!(e.message.contains("R-0001"), "{}", e.message);
                assert!(e.message.contains(slug), "{}", e.message);
            }
            other => panic!("{action:?}: expected a refusal, got {other:?}"),
        }
        let review = exec.preview_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL);
        assert!(
            review.diff_summary.contains(slug),
            "{}",
            review.diff_summary
        );
        assert_eq!(
            review.risk_signals,
            vec![RiskSignalDto::ChangeRefused {
                code: "unsupported-rule-shape".into(),
                args: Default::default(),
            }],
            "the refused preview must not read as an unchanged rule set"
        );
    }
    let rows: i64 = conn
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0, "a refused submission stores nothing");
}

/// Positive control: the shapes enforcement carries out still go through.
#[test]
fn address_only_and_app_only_rules_are_accepted() {
    use nrr_shared::rules_json::RuleAction as WireAction;
    for (address, app) in [(true, false), (false, true)] {
        for action in [WireAction::Route, WireAction::Block] {
            let (exec, _conn) = build_test_executor();
            let payload = shaped_rules_update(address, app, action, "corr-ok");
            assert!(
                matches!(
                    exec.execute_rules_update(&payload, nrr_storage::BASELINE_PRINCIPAL),
                    MutationOutcome::Completed(_)
                ),
                "address {address}, app {app}, {action:?} must be accepted"
            );
        }
    }
}

/// An old audit break is reported until an administrator restarts the chain;
/// the restart covers exactly the breaks it was shown, clears the status, and
/// names the administrator. A reader without the service's key still sees the
/// break: nothing but the key makes a restart count.
#[test]
fn an_administrator_restarts_a_broken_audit_chain_and_the_status_clears() {
    use crate::production_diagnostics::ProductionDiagnosticsFacade;
    use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
    use nrr_diagnostics::audit::{
        ActorKind, AuditEventKind, AuditEventResult, AuditQueryFilter, AuditReader,
    };
    use nrr_diagnostics::facade::dto::DiagnosticsAudience;
    use nrr_diagnostics::facade::service::DiagnosticsFacade;
    use nrr_diagnostics::sink::AuditSink;
    use nrr_diagnostics::{AuditEventInput, AuditWriter, AuditWriterConfig};
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    const ADMIN: &str = "S-1-5-21-10-20-30-500";
    let dir = tempfile::tempdir().expect("temp");
    let audit_dir = dir.path().join("audit");
    let logs_dir = dir.path().join("logs");
    std::fs::create_dir_all(&logs_dir).expect("logs dir");
    for n in 0..3 {
        AuditWriter::open(AuditWriterConfig::new(&audit_dir))
            .append(AuditEventInput {
                event_id: format!("adt-{n}"),
                kind: AuditEventKind::RevisionActivated,
                created_at: 1_700_000_000_000,
                actor_kind: ActorKind::Service,
                actor_id_hash: None,
                revision_id: Some("rev-1".into()),
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: nrr_diagnostics::reason::review::APPROVED,
                payload_summary_json: None,
            })
            .expect("append");
    }
    let oldest = AuditReader::new(&audit_dir).list_files()[0].clone();
    let content = std::fs::read_to_string(&oldest).expect("read");
    std::fs::write(&oldest, content.replace("rev-1", "rev-9")).expect("tamper");

    let runner =
        SqliteMigrationRunner::for_state_db(rusqlite::Connection::open_in_memory().unwrap());
    runner.run_pending_migrations().unwrap();
    let state_conn = Arc::new(std::sync::Mutex::new(runner.into_connection()));
    let coordinator = build_test_coordinator_signed(state_conn, vec![0x5Cu8; 32]);
    let exec = ProductionMutationExecutor::new(Arc::clone(&coordinator)).with_audit_writer(
        Arc::new(AuditWriter::open(AuditWriterConfig::new(&audit_dir))),
    );
    let facade = |key| {
        ProductionDiagnosticsFacade::new(
            &logs_dir,
            &audit_dir,
            None,
            Arc::new(InMemorySecurityAlertsRepository::new()),
            None,
        )
        .with_chain_restart_key(key)
    };
    let chain_ok = |key| {
        facade(key)
            .get_status(&DiagnosticsAudience::Machine)
            .security_status
            .audit_chain_ok
    };
    assert!(
        !chain_ok(coordinator.audit_restart_key()),
        "positive control"
    );

    let preview = exec
        .audit_chain_preview(MutationKind::AuditChainRestart)
        .expect("preview");
    assert_eq!(preview.break_count, 1);
    assert_eq!(preview.breaks[0].kind, "hash-mismatch");
    let restart = |digest: &str| StoredMutation {
        kind: MutationKind::AuditChainRestart,
        payload: serde_json::json!({ "breaks-digest": digest }),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: true,
    };
    match exec.execute(restart("not what was shown"), ADMIN) {
        MutationOutcome::Failed(e) => assert_eq!(e.code, "audit-chain-changed"),
        other => panic!("a stale digest restarts nothing: {other:?}"),
    }
    assert!(matches!(
        exec.execute(restart(&preview.breaks_digest), ADMIN),
        MutationOutcome::Completed(_)
    ));

    assert!(chain_ok(coordinator.audit_restart_key()));
    assert!(!chain_ok(None), "without the key the break still shows");
    let restarts = AuditReader::new(&audit_dir).scan(
        &AuditQueryFilter::new().kind("audit_chain_restarted"),
        &DiagnosticsAudience::Principal(ADMIN.into()),
    );
    assert_eq!(restarts.len(), 1, "the administrator's own record");
}

// ── Rule caps on the write path ─────────────────────────────────────────

fn book_json(user: usize, auto: usize) -> String {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RuleOriginDto,
        RULES_JSON_SCHEMA_VERSION,
    };
    let rule = |id: String, value: String, origin: Option<RuleOriginDto>| RuleDto {
        id,
        enabled: true,
        address_match: Some(AddressMatchDto::ExactFqdn { value }),
        app_match: None,
        comment: String::new(),
        action: nrr_shared::rules_json::RuleAction::Route,
        origin,
    };
    let primary = (0..user)
        .map(|i| rule(format!("R-{i}"), format!("host{i}.example.com"), None))
        .collect();
    let secondary = (0..auto)
        .map(|i| {
            rule(
                format!("auto-{i}"),
                format!("cdn{i}.example.net"),
                Some(RuleOriginDto::auto(
                    nrr_shared::AutoRuleReason::SiteCompanion,
                    "example.com",
                    "2026-07-31",
                )),
            )
        })
        .collect();
    to_canonical_string(&CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary,
        secondary,
    })
    .unwrap()
}

/// Marking rules `auto` must not take a crafted payload past both caps: the
/// app's rules have a budget of their own on every write.
#[test]
fn a_rules_update_past_the_app_rule_budget_is_refused() {
    let (exec, _conn) = build_test_executor();
    let auto_cap = nrr_domain::auto_rule_budget::MAX_AUTO_RULES;
    let payload = |body: String| {
        serde_json::json!({
            "rules-json": body,
            "content-hash": "h-cap",
        })
    };
    let update = |body: String| StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: payload(body),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: false,
    };

    let over = book_json(10, auto_cap + 1);
    let preview = exec.preview(
        MutationKind::RulesUpdate,
        &payload(over.clone()),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert!(
        preview
            .risk_signals
            .contains(&RiskSignalDto::ChangeRefused {
                code: "auto-rule-cap-exceeded".into(),
                args: Default::default(),
            }),
        "{:?}",
        preview.risk_signals
    );
    match exec.execute(update(over), nrr_storage::BASELINE_PRINCIPAL) {
        MutationOutcome::Failed(e) => {
            assert_eq!(e.code, "auto-rule-cap-exceeded");
            assert!(
                e.message.contains(&(auto_cap + 1).to_string()),
                "{}",
                e.message
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }

    let at_budget = exec.execute(
        update(book_json(10, auto_cap)),
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert!(
        matches!(at_budget, MutationOutcome::Completed(_)),
        "{at_budget:?}"
    );
}

/// Stores `rules_json` as `principal`'s active book past the executor's write
/// cap, the way a book saved before the app's budget existed got there.
fn seed_active_book(exec: &ProductionMutationExecutor, principal: &str, rules_json: String) {
    let mut hasher = Sha256::new();
    hasher.update(rules_json.as_bytes());
    let id = exec
        .coordinator
        .submit_candidate(CandidateSubmission {
            principal: principal.to_string(),
            rules_json,
            content_hash: format!("{:x}", hasher.finalize()),
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "seed".into(),
            risk_level: None,
            review_summary_json: None,
        })
        .expect("seed submit");
    let token = exec
        .coordinator
        .issue_confirmation_token(&id, COORDINATOR_TOKEN_TTL_SECS)
        .expect("seed token");
    exec.coordinator
        .activate(&id, &token, "seed")
        .expect("seed activate");
}

fn rules_update(body: String) -> StoredMutation {
    StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({ "rules-json": body, "content-hash": "h-cap" }),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: false,
    }
}

fn refusal_code(outcome: MutationOutcome) -> String {
    match outcome {
        MutationOutcome::Failed(e) => e.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A book saved before the app's budget stays editable: the user's own edit
/// goes through, and so does dropping app rules, but the app's share cannot
/// grow past what the book already held.
#[test]
fn a_book_past_the_app_budget_stays_editable_but_cannot_grow() {
    const SID: &str = "S-1-5-21-1000-1000-1000-1001";
    let (exec, _conn) = build_test_executor();
    seed_active_book(&exec, SID, book_json(10, 2_500));

    let own_edit = exec.execute(rules_update(book_json(11, 2_500)), SID);
    assert!(
        matches!(own_edit, MutationOutcome::Completed(_)),
        "{own_edit:?}"
    );
    assert_eq!(
        refusal_code(exec.execute(rules_update(book_json(11, 2_501)), SID)),
        "auto-rule-cap-exceeded"
    );
    let preview = exec.preview(
        MutationKind::RulesUpdate,
        &rules_update(book_json(11, 2_501)).payload,
        SID,
    );
    assert!(
        preview
            .risk_signals
            .contains(&RiskSignalDto::ChangeRefused {
                code: "auto-rule-cap-exceeded".into(),
                args: Default::default(),
            }),
        "{:?}",
        preview.risk_signals
    );

    let shrunk = exec.execute(rules_update(book_json(11, 2_400)), SID);
    assert!(
        matches!(shrunk, MutationOutcome::Completed(_)),
        "{shrunk:?}"
    );
    assert_eq!(
        refusal_code(exec.execute(rules_update(book_json(11, 2_450)), SID)),
        "auto-rule-cap-exceeded",
        "the allowance follows the book down, never back up"
    );
}

/// Under the budget, the budget is the ceiling — however close the book was.
#[test]
fn a_book_under_the_app_budget_cannot_cross_it() {
    const SID: &str = "S-1-5-21-1000-1000-1000-1002";
    let (exec, _conn) = build_test_executor();
    seed_active_book(&exec, SID, book_json(10, 1_999));
    assert_eq!(
        refusal_code(exec.execute(rules_update(book_json(10, 2_001)), SID)),
        "auto-rule-cap-exceeded"
    );
}

/// The allowance is the caller's own book's: another user's pre-budget book
/// lends nothing.
#[test]
fn another_users_large_book_lends_no_allowance() {
    const OWNER: &str = "S-1-5-21-1000-1000-1000-1003";
    const OTHER: &str = "S-1-5-21-1000-1000-1000-1004";
    let (exec, _conn) = build_test_executor();
    seed_active_book(&exec, OWNER, book_json(10, 2_500));
    seed_active_book(&exec, OTHER, book_json(10, 5));
    assert_eq!(
        refusal_code(exec.execute(rules_update(book_json(10, 2_500)), OTHER)),
        "auto-rule-cap-exceeded"
    );
}

/// An export of a pre-budget book imports back into that book; the user's
/// own cap still holds on the same path.
#[test]
fn an_exported_pre_budget_book_imports_back() {
    const SID: &str = "S-1-5-21-1000-1000-1000-1005";
    let (exec, _conn) = build_test_executor();
    seed_active_book(&exec, SID, book_json(10, 2_500));
    let file = |user: usize, auto: usize| {
        let mut text = String::from("--- Domains\n");
        for i in 0..user {
            text.push_str(&format!("host{i}.example.com\n"));
        }
        text.push_str("--- Auto\n");
        for i in 0..auto {
            text.push_str(&format!(
                "cdn{i}.example.net  # auto:site-companion anchor:example.com added:2026-07-31\n"
            ));
        }
        text
    };
    let import = |text: String| {
        serde_json::json!({
            "secondary-bytes-b64": b64(&text),
            "include-child-processes": false,
        })
    };
    let back = exec.execute_preset_import(&import(file(0, 2_500)), SID);
    assert!(matches!(back, MutationOutcome::Completed(_)), "{back:?}");
    assert_eq!(
        refusal_code(exec.execute_preset_import(&import(file(0, 2_501)), SID)),
        "auto-rule-cap-exceeded"
    );
}

/// The review names the channel a rules change came through, in the words its
/// revision will record; a kind with no channel keeps the service's own label.
#[test]
fn the_review_names_where_a_rules_change_came_from() {
    let (exec, _conn) = build_test_executor();
    let sid = nrr_storage::BASELINE_PRINCIPAL;
    let edit = exec.preview(
        MutationKind::RulesUpdate,
        &serde_json::json!({ "rules-json": "{}", "content-hash": "h" }),
        sid,
    );
    assert_eq!(edit.provenance, RulesRevisionSource::GuiRulesEdit.as_slug());
    let import = exec.preview(
        MutationKind::PresetImport,
        &serde_json::json!({
            "primary-bytes-b64": b64(SAMPLE_PRESET),
            "include-child-processes": false,
        }),
        sid,
    );
    assert_eq!(
        import.provenance,
        RulesRevisionSource::PresetImport.as_slug()
    );
    let reset = exec.preview(
        MutationKind::RulesResetToBaseline,
        &serde_json::json!({}),
        sid,
    );
    assert_eq!(reset.provenance, "service");
}

// ── Rules of an unknown kind, network screening ─────────────────────────

/// A book a newer build wrote: one rule this build reads, one it cannot.
fn book_with_unknown_kind(known_value: &str) -> String {
    serde_json::json!({
        "schema-version": 3,
        "primary": [
            {
                "id": "r-known",
                "enabled": true,
                "address-match": { "kind": "exact-fqdn", "value": known_value },
                "comment": "",
                "action": "route",
            },
            {
                "id": "r-future",
                "enabled": true,
                "address-match": { "kind": "port-span", "from": 8000, "to": 8100 },
                "comment": "",
                "action": "route",
            },
        ],
        "secondary": [],
    })
    .to_string()
}

fn rules_update_of(rules_json: &str) -> StoredMutation {
    StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": rules_json,
            "content-hash": "client-supplied",
        }),
        correlation_id: None,
        issuer_sid: String::new(),
        caller_is_elevated: false,
    }
}

fn active_rules_json(conn: &Arc<std::sync::Mutex<rusqlite::Connection>>) -> String {
    let g = conn.lock().unwrap();
    nrr_storage::revisions::RevisionsRepository::new(&g)
        .get_active()
        .unwrap()
        .expect("an active revision")
        .rules_json
}

/// What the GUI submits after an edit: the rules it was shown, which never
/// include a kind this build cannot read.
fn gui_book(value: &str) -> String {
    serde_json::json!({
        "schema-version": 1,
        "primary": [{
            "id": "r-known",
            "enabled": true,
            "address-match": { "kind": "exact-fqdn", "value": value },
            "comment": "",
            "action": "route",
        }],
        "secondary": [],
    })
    .to_string()
}

#[test]
fn an_edit_keeps_the_rules_of_a_kind_this_build_cannot_read() {
    let (exec, conn) = build_test_executor();
    let baseline = nrr_storage::BASELINE_PRINCIPAL;
    let seeded = exec.execute(
        rules_update_of(&book_with_unknown_kind("a.example")),
        baseline,
    );
    assert!(
        matches!(seeded, MutationOutcome::Completed(_)),
        "{seeded:?}"
    );

    let outcome = exec.execute(rules_update_of(&gui_book("b.example")), baseline);

    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "{outcome:?}"
    );
    let active = active_rules_json(&conn);
    assert!(active.contains("b.example"), "the edit landed: {active}");
    assert!(!active.contains("a.example"));
    assert!(
        active.contains("r-future"),
        "the unknown rule was kept: {active}"
    );
    assert!(active.contains("port-span"));
}

#[test]
fn resubmitting_the_shown_book_is_a_no_op_not_a_deletion() {
    let (exec, conn) = build_test_executor();
    let baseline = nrr_storage::BASELINE_PRINCIPAL;
    let seeded = exec.execute(
        rules_update_of(&book_with_unknown_kind("a.example")),
        baseline,
    );
    assert!(
        matches!(seeded, MutationOutcome::Completed(_)),
        "{seeded:?}"
    );
    let before = active_rules_json(&conn);

    let outcome = exec.execute(rules_update_of(&gui_book("a.example")), baseline);

    assert!(
        matches!(&outcome, MutationOutcome::Completed(v) if v["outcome"] == "already-active"),
        "{outcome:?}"
    );
    assert_eq!(active_rules_json(&conn), before);
}

#[test]
fn a_preset_import_keeps_the_rules_of_a_kind_this_build_cannot_read() {
    let (exec, conn) = build_test_executor();
    let baseline = nrr_storage::BASELINE_PRINCIPAL;
    let seeded = exec.execute(
        rules_update_of(&book_with_unknown_kind("a.example")),
        baseline,
    );
    assert!(
        matches!(seeded, MutationOutcome::Completed(_)),
        "{seeded:?}"
    );
    let payload = serde_json::json!({
        "primary-bytes-b64": b64("--- Domains\nimported.example\n"),
        "secondary-bytes-b64": b64("--- Domains\nother.example\n"),
        "include-child-processes": false,
    });

    let outcome = exec.execute_preset_import(&payload, baseline);

    assert!(
        matches!(outcome, MutationOutcome::Completed(_)),
        "{outcome:?}"
    );
    let active = active_rules_json(&conn);
    assert!(active.contains("imported.example"), "{active}");
    assert!(active.contains("r-future"), "{active}");
}

#[test]
fn carrying_forward_never_duplicates_an_id_the_submission_holds() {
    let decode = |json: &str| {
        rules_json_codec::decode(
            nrr_shared::rules_json::from_canonical_string(json).unwrap(),
            HostPlatform::Windows,
        )
        .unwrap()
    };
    let carried = decode(&book_with_unknown_kind("a.example")).unrecognized;
    let mut fresh = decode(&gui_book("b.example"));
    assert_eq!(carry_forward(&mut fresh, &carried), 1);
    assert_eq!(fresh.unrecognized.primary.len(), 1);
    // A second pass adds nothing.
    assert_eq!(carry_forward(&mut fresh, &carried), 0);
    // An id the submission reuses is the submission's.
    let mut reuses_id = decode(&gui_book("c.example").replace("r-known", "r-future"));
    assert_eq!(carry_forward(&mut reuses_id, &carried), 0);
    assert!(reuses_id.unrecognized.is_empty());
}

/// The production screen over a machine attached to `192.168.1.0/24` with
/// the tunnel server at `203.0.113.7`, and the default fake-IP pool.
fn machine_screen() -> Arc<dyn NetworkRuleScreen> {
    use crate::network_rule_screen::ProductionNetworkScreen;
    use crate::route_codegen::network_routes::NetworkRouteFacts;
    Arc::new(ProductionNetworkScreen::new(
        Arc::new(|_| NetworkRouteFacts {
            local_networks: vec![nrr_shared::ip_block::IpBlock::parse("192.168.1.0/24").unwrap()],
            tunnel_servers: vec!["203.0.113.7".parse().unwrap()],
            ..NetworkRouteFacts::default()
        }),
        Some(nrr_platform_api::fake_ip::FakeIpPoolConfig::default()),
    ))
}

fn network_book(networks: &[&str]) -> String {
    let rules: Vec<serde_json::Value> = networks
        .iter()
        .enumerate()
        .map(|(i, network)| {
            let address = match network.split_once('-') {
                Some((first, last)) => {
                    serde_json::json!({ "kind": "ip-range", "first": first, "last": last })
                }
                None => serde_json::json!({ "kind": "subnet", "network": network }),
            };
            serde_json::json!({
                "id": format!("n-{i}"),
                "enabled": true,
                "address-match": address,
                "comment": "",
                "action": "route",
            })
        })
        .collect();
    serde_json::json!({ "schema-version": 2, "primary": [], "secondary": rules }).to_string()
}

fn refused_with(summary: &ReviewSummaryResponse, code: &str) -> bool {
    summary
        .risk_signals
        .iter()
        .any(|s| matches!(s, RiskSignalDto::ChangeRefused { code: c, .. } if c == code))
}

#[test]
fn a_network_over_the_pool_or_a_link_is_refused_with_its_own_code() {
    let (exec, _conn) = build_test_executor();
    let exec = exec.with_network_screen(machine_screen());
    let principal = "S-1-5-21-net";

    let over_pool = network_book(&["198.18.0.0/16"]);
    let error = exec
        .network_refusal(&over_pool, principal)
        .expect("refused");
    assert_eq!(error.code, NETWORK_COVERS_FAKE_IP_POOL_CODE);
    assert!(error.message.contains("198.18.0.0/16"), "{}", error.message);
    assert_eq!(error.args["rule"], "n-0");
    assert_eq!(error.args["network"], "198.18.0.0/16");
    assert_eq!(error.args["covers-kind"], "fake-ip-pool");
    assert!(!error.args.contains_key("covers"));

    // A range is screened block by block.
    let over_link = network_book(&["192.168.1.200-192.168.1.210"]);
    let error = exec
        .network_refusal(&over_link, principal)
        .expect("refused");
    assert_eq!(error.code, NETWORK_COVERS_LINK_CODE);
    assert!(
        error.message.contains("192.168.1.200-192.168.1.210"),
        "{}",
        error.message
    );

    let preview = exec.preview(
        MutationKind::RulesUpdate,
        &rules_update_of(&over_link).payload,
        principal,
    );
    assert!(
        refused_with(&preview, NETWORK_COVERS_LINK_CODE),
        "{preview:?}"
    );
    assert!(
        preview.risk_signals.iter().any(|s| matches!(
            s,
            RiskSignalDto::ChangeRefused { args, .. }
                if args.get("covers-kind").map(String::as_str) == Some("local-network")
                    && args.get("network").map(String::as_str)
                        == Some("192.168.1.200-192.168.1.210")
        )),
        "the preview names the network and what it covers: {preview:?}"
    );

    let over_lan = network_book(&["192.168.0.0/16"]);
    let error = exec.network_refusal(&over_lan, principal).expect("refused");
    assert_eq!(error.code, NETWORK_COVERS_LINK_CODE);
    assert!(
        error.message.contains("192.168.1.0/24"),
        "{}",
        error.message
    );
    assert_eq!(error.args["covers-kind"], "local-network");
    assert_eq!(error.args["covers"], "192.168.1.0/24");

    let over_server = network_book(&["203.0.113.0/24"]);
    let error = exec
        .network_refusal(&over_server, principal)
        .expect("refused");
    assert_eq!(error.code, NETWORK_COVERS_LINK_CODE);
    assert!(error.message.contains("203.0.113.7"), "{}", error.message);
    assert_eq!(error.args["covers-kind"], "tunnel-server");
    assert_eq!(error.args["covers"], "203.0.113.7");
    assert_eq!(error.args["network"], "203.0.113.0/24");

    // Positive control: a network clear of both is accepted.
    assert!(exec
        .network_refusal(&network_book(&["198.51.100.0/24"]), principal)
        .is_none());
}

/// The toast reads the refusal from the progress push, not from the operation
/// status, so the push must name the network too.
#[test]
fn a_refused_network_reaches_the_progress_event_with_its_args() {
    const SID: &str = "S-1-5-21-9000-1";
    let (exec, _conn) = build_test_executor();
    let bus = Arc::new(EventBus::new());
    let exec = exec
        .with_network_screen(machine_screen())
        .with_event_bus(Arc::clone(&bus));
    let sub = bus.subscribe_as("gui".into(), Some(SID.into()), None);
    let mut stored = rules_update_of(&network_book(&["203.0.113.0/24"]));
    stored.correlation_id = Some("corr-net".into());
    stored.issuer_sid = SID.to_string();
    stored.caller_is_elevated = true;

    let outcome = exec.execute(stored, SID);
    assert!(
        matches!(&outcome, MutationOutcome::Failed(e) if e.code == NETWORK_COVERS_LINK_CODE),
        "{outcome:?}"
    );
    let failed = bus
        .peek_pending_for(&sub.subscription_id, 64)
        .into_iter()
        .find_map(|e| match e.event {
            StatusUpdateEvent::MutationProgress {
                phase,
                error_code,
                error_args,
                ..
            } if phase == "failed" => Some((error_code, error_args)),
            _ => None,
        })
        .expect("a failed progress event");
    assert_eq!(failed.0.as_deref(), Some(NETWORK_COVERS_LINK_CODE));
    assert_eq!(failed.1["network"], "203.0.113.0/24");
    assert_eq!(failed.1["covers-kind"], "tunnel-server");
    assert_eq!(failed.1["covers"], "203.0.113.7");
}

#[test]
fn without_a_screen_networks_pass_on_their_values_alone() {
    let (exec, _conn) = build_test_executor();
    assert!(exec
        .network_refusal(&network_book(&["198.18.0.0/16"]), "S-1-5-21-net")
        .is_none());
}

#[test]
fn a_network_the_book_in_force_holds_is_not_judged_again() {
    // Built directly: what counts as new is `new_networks`' decision alone.
    let book = |nets: &[&str]| {
        decode_rule_book(&network_book(nets), HostPlatform::Windows).expect("network book")
    };
    // Saved before the machine moved onto this LAN: it stays editable.
    let in_force = book(&["192.168.0.0/16"]);

    assert!(
        super::unrecognized::new_networks(&book(&["192.168.0.0/16"]), Some(&in_force)).is_empty()
    );
    // A different network over the same LAN is new and is judged.
    assert_eq!(
        super::unrecognized::new_networks(&book(&["192.168.1.0/25"]), Some(&in_force)).len(),
        1
    );
    // With nothing in force every network is new.
    assert_eq!(
        super::unrecognized::new_networks(&book(&["192.168.0.0/16"]), None).len(),
        1
    );
}

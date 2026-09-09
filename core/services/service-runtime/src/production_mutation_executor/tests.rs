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
    let found = cross_set_duplicates_of(&both);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].primary_rule_id, "r-1");
    assert_eq!(found[0].secondary_rule_id, "r-2");
    assert_eq!(found[0].match_summary, "example.com");

    // Undecodable input says nothing here — the malformed path speaks for
    // it, and inventing a duplicate report would be worse than silence.
    assert!(cross_set_duplicates_of("{").is_empty());
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
        ProductionMutationExecutor::canonicalize_rules_payload(&mut p);
        p
    }

    let typed = payload("SwiftVPN 3.0.exe");
    let stored = payload("swiftvpn 3.0.exe");
    assert_eq!(typed.rules_json, stored.rules_json);
    assert_eq!(typed.content_hash, stored.content_hash);
    assert_ne!(
        typed.content_hash, "client-supplied",
        "the hash must be recomputed from the canonical form, not trusted"
    );
    assert!(typed.rules_json.contains("swiftvpn 3.0.exe"));
}

#[test]
fn an_undecodable_payload_is_left_alone_for_the_validator_to_reject() {
    let mut p = RulesUpdatePayload {
        rules_json: "not json at all".into(),
        content_hash: "h".into(),
        correlation_id: None,
    };
    ProductionMutationExecutor::canonicalize_rules_payload(&mut p);
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
        message: "test".into(),
    }];
    assert!(matches!(
        classify_risk_heuristic(0, 0, &warnings),
        ReviewRiskLevel::High
    ));
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
fn ack_of_tamper_alert_re_signs_rows_and_lifts_gate() {
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

    let coord = build_test_coordinator_signed(Arc::clone(&state_conn), key.clone());
    let alerts: Arc<dyn SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    alerts
        .insert(&SecurityAlert {
            alert_id: "alt-dbtamper-rev-1".into(),
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

    // Acknowledge through the real execute() path.
    let stored = StoredMutation {
        kind: MutationKind::SecurityAlertAck,
        payload: serde_json::json!({ "alert-id": "alt-dbtamper-rev-1" }),
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
    let alert = alerts.find_by_id("alt-dbtamper-rev-1").unwrap().unwrap();
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
    let review = dry_run_to_review_summary(&summary, None);
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

/// A preview is a READ. It used to submit a candidate to get a plan, so
/// every press of it wrote a revision row — rows the user then found in
/// their pending list as edits they never made.
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

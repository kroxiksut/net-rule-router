#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Acceptance E2E for the per-SID rule model.
//!
//! Ties the whole story together through the production executor +
//! coordinator + rules provider on an in-memory state DB:
//! - a non-elevated daily edit lands under the caller's own principal;
//! - two principals are isolated (one's edit never touches the other);
//! - a principal with no revision of its own reads THROUGH to the admin
//!   baseline (lazy divergence / seed-on-first-use);
//! - "reset to baseline" discards a principal's divergence so read-through
//!   resumes;
//! - an admin baseline edit is seen by every non-diverged user, but a
//!   diverged user keeps its own rules.
//!
//! The principal strings are exercised through the cross-OS
//! [`nrr_domain::user_principal::UserPrincipal`] view so the acceptance
//! also pins the on-disk format.

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nrr_domain::user_principal::UserPrincipal;
use nrr_service_runtime::activation_coordinator::{
    ActivationAuditEmitter, ActivationCoordinator, ApplyFailurePolicy, Clock, IdGenerator,
    RulesApplyDispatcher,
};
use nrr_service_runtime::active_sid_registry::ActiveSidRegistry;
use nrr_service_runtime::crash_recovery::ApplyMarkerStore;
use nrr_service_runtime::ipc_handlers::mutation_token_store::StoredMutation;
use nrr_service_runtime::ipc_handlers::providers::{MutationExecutor, MutationOutcome};
use nrr_service_runtime::per_sid_orchestrator::RulesProvider;
use nrr_service_runtime::production_coordinator::{
    NoopRulesApplyDispatcher, ProductionApplyMarkerStore, ProductionIdGenerator,
};
use nrr_service_runtime::production_mutation_executor::ProductionMutationExecutor;
use nrr_service_runtime::production_rules_provider::ProductionRulesProvider;
use nrr_service_runtime::production_settings::SystemClock;
use nrr_shared::ipc_payloads::MutationKind;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::BASELINE_PRINCIPAL;
use rusqlite::Connection;

const SID_A: &str = "S-1-5-21-1111-2222-3333-1001";
const SID_B: &str = "S-1-5-21-1111-2222-3333-1002";
const SID_FRESH: &str = "S-1-5-21-1111-2222-3333-1009";

struct NoopActivationAudit;
impl ActivationAuditEmitter for NoopActivationAudit {
    fn emit(&self, _: nrr_service_runtime::activation_coordinator::ActivationAuditEvent) {}
}

/// Process-unique marker dir so this binary never shares the apply-marker
/// file with another test process running `activate` in parallel. Rooted at
/// `CARGO_TARGET_TMPDIR` (under the cargo target dir, reclaimed by `cargo
/// clean`) rather than the system temp dir, so test runs never litter
/// `%TEMP%` with `nrr-acceptance-markers-*` folders.
fn unique_marker_dir() -> std::path::PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "nrr-acceptance-markers-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn build() -> (
    ProductionMutationExecutor,
    Arc<ActivationCoordinator>,
    ProductionRulesProvider,
) {
    let conn = Connection::open_in_memory().expect("open in-memory state DB");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("state migrations");
    let state_conn = Arc::new(Mutex::new(runner.into_connection()));

    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&state_conn),
        Arc::new(ActiveSidRegistry::new()),
        Arc::new(NoopRulesApplyDispatcher) as Arc<dyn RulesApplyDispatcher>,
        Arc::new(ProductionApplyMarkerStore::new(&unique_marker_dir()))
            as Arc<dyn ApplyMarkerStore>,
        Arc::new(NoopActivationAudit) as Arc<dyn ActivationAuditEmitter>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        Arc::new(ProductionIdGenerator::new()) as Arc<dyn IdGenerator>,
        ApplyFailurePolicy::AllOrNothing,
    ));
    let executor = ProductionMutationExecutor::new(Arc::clone(&coordinator))
        .with_state_conn(Arc::clone(&state_conn));
    let provider = ProductionRulesProvider::new(Arc::clone(&state_conn));
    (executor, coordinator, provider)
}

/// A valid canonical rules-json with one distinctive suffix-domain rule.
fn canonical_rules(tag: &str) -> String {
    use nrr_shared::rules_json::{
        to_canonical_string, AddressMatchDto, CanonicalRulesJsonV1, RuleDto,
        RULES_JSON_SCHEMA_VERSION,
    };
    to_canonical_string(&CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![RuleDto {
            id: format!("r-{tag}"),
            enabled: true,
            address_match: Some(AddressMatchDto::SuffixDomain {
                suffix: format!("{tag}.example"),
            }),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        }],
        secondary: vec![],
    })
    .expect("serialise canonical rules")
}

fn commit_rules(exec: &ProductionMutationExecutor, principal: &str, tag: &str) {
    let stored = StoredMutation {
        kind: MutationKind::RulesUpdate,
        payload: serde_json::json!({
            "rules-json": canonical_rules(tag),
            "content-hash": format!("hash-{tag}"),
        }),
        correlation_id: None,
        issuer_sid: principal.to_string(),
        caller_is_elevated: false,
    };
    match exec.execute(stored, principal) {
        MutationOutcome::Completed(_) => {}
        MutationOutcome::Failed(e) => panic!("commit for {principal} failed: {e:?}"),
    }
}

fn reset_to_baseline(exec: &ProductionMutationExecutor, principal: &str) {
    let stored = StoredMutation {
        kind: MutationKind::RulesResetToBaseline,
        payload: serde_json::json!({}),
        correlation_id: None,
        issuer_sid: principal.to_string(),
        caller_is_elevated: false,
    };
    match exec.execute(stored, principal) {
        MutationOutcome::Completed(_) => {}
        MutationOutcome::Failed(e) => panic!("reset for {principal} failed: {e:?}"),
    }
}

fn active_hash(coord: &ActivationCoordinator, principal: &str) -> Option<String> {
    coord
        .current_active_for(principal)
        .expect("current_active_for")
        .map(|r| r.content_hash)
}

/// The id of the single rule the provider resolves for `principal`
/// (`r-<tag>`), or `None` when the principal resolves to no rules at all.
/// The id is preserved verbatim through canonicalization, so it is a
/// stable, normalization-proof witness of WHICH content was resolved.
fn resolved_rule_id(provider: &ProductionRulesProvider, principal: &str) -> Option<String> {
    let snap = provider.active_rules_for(principal)?;
    let rule = snap.rule_book.primary.rules().first()?;
    Some(rule.id.as_str().to_string())
}

#[test]
fn two_principals_commit_independently_and_stay_isolated() {
    let (exec, coord, _provider) = build();
    commit_rules(&exec, SID_A, "alpha");
    commit_rules(&exec, SID_B, "beta");

    // Each principal owns exactly its own active revision.
    assert_eq!(active_hash(&coord, SID_A).as_deref(), Some("hash-alpha"));
    assert_eq!(active_hash(&coord, SID_B).as_deref(), Some("hash-beta"));
    // The baseline was never written by a user-scoped commit.
    assert_eq!(active_hash(&coord, BASELINE_PRINCIPAL), None);

    // B re-edits — A is untouched (isolation).
    commit_rules(&exec, SID_B, "beta2");
    assert_eq!(active_hash(&coord, SID_B).as_deref(), Some("hash-beta2"));
    assert_eq!(active_hash(&coord, SID_A).as_deref(), Some("hash-alpha"));
}

#[test]
fn fresh_principal_reads_through_to_baseline_then_diverges_on_edit() {
    let (exec, coord, provider) = build();

    // No baseline yet → a fresh principal resolves to NOTHING.
    assert_eq!(resolved_rule_id(&provider, SID_FRESH), None);

    // Admin sets the baseline (principal = baseline sentinel).
    commit_rules(&exec, BASELINE_PRINCIPAL, "base");

    // The fresh principal now READS THROUGH to baseline (no copied row).
    assert_eq!(active_hash(&coord, SID_FRESH), None, "no own revision");
    assert_eq!(
        resolved_rule_id(&provider, SID_FRESH).as_deref(),
        Some("r-base"),
        "fresh principal inherits baseline via read-through"
    );

    // The principal edits → it diverges (own revision overrides baseline).
    commit_rules(&exec, SID_FRESH, "mine");
    assert_eq!(active_hash(&coord, SID_FRESH).as_deref(), Some("hash-mine"));
    assert_eq!(
        resolved_rule_id(&provider, SID_FRESH).as_deref(),
        Some("r-mine")
    );
}

#[test]
fn reset_discards_divergence_and_resumes_baseline_read_through() {
    let (exec, coord, provider) = build();
    commit_rules(&exec, BASELINE_PRINCIPAL, "base");
    commit_rules(&exec, SID_A, "alpha");
    assert_eq!(
        resolved_rule_id(&provider, SID_A).as_deref(),
        Some("r-alpha")
    );

    reset_to_baseline(&exec, SID_A);

    // A's own revision is gone → read-through to baseline resumes.
    assert_eq!(active_hash(&coord, SID_A), None);
    assert_eq!(
        resolved_rule_id(&provider, SID_A).as_deref(),
        Some("r-base"),
        "after reset, A follows baseline again"
    );
}

#[test]
fn admin_baseline_edit_reaches_non_diverged_users_only() {
    let (exec, coord, provider) = build();
    commit_rules(&exec, BASELINE_PRINCIPAL, "base");
    // B diverges; the fresh principal stays on baseline.
    commit_rules(&exec, SID_B, "beta");

    // Admin updates the baseline.
    commit_rules(&exec, BASELINE_PRINCIPAL, "base2");
    assert_eq!(
        active_hash(&coord, BASELINE_PRINCIPAL).as_deref(),
        Some("hash-base2")
    );

    // Non-diverged fresh principal sees the new baseline...
    assert_eq!(
        resolved_rule_id(&provider, SID_FRESH).as_deref(),
        Some("r-base2")
    );
    // ...but the diverged user B keeps its OWN rules.
    assert_eq!(
        resolved_rule_id(&provider, SID_B).as_deref(),
        Some("r-beta")
    );
}

#[test]
fn user_principal_view_round_trips_the_stored_sids() {
    // The acceptance also pins the cross-OS on-disk format: every SID we
    // partition by round-trips through the typed view, and the baseline
    // sentinel is the `Baseline` variant — never an `OsUser`.
    for sid in [SID_A, SID_B, SID_FRESH] {
        let p = UserPrincipal::from_windows_sid(sid).expect("valid SID");
        assert!(!p.is_baseline());
        assert_eq!(p.as_stored(), sid);
    }
    assert!(UserPrincipal::from_stored(BASELINE_PRINCIPAL)
        .unwrap()
        .is_baseline());
}

#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Cross-cutting integration tests for the apply pipeline.
//!
//! These exercise the full chain from `bootstrap`-style state +
//! cache DB creation, through `PerSidApplyOrchestrator` construction
//! with real producers, to the WFP plan executed against a
//! `MockWindowsApi` backing. Each test covers one end-to-end
//! scenario the per-module unit tests can't observe in isolation:
//!
//! - install_for_sid lands rule-driven filters in the WFP layer with
//!   correct per-user tagging,
//! - recompile_for_sid swaps live filter sets when the active
//!   revision changes,
//! - the fail-closed default Block filter is emitted alongside rule
//!   filters when the per-SID mode is `StrictSecondaryFailClosed`,
//! - ExactFqdn rules silently emit zero filters when the FQDN cache
//!   is cold (DNS warm-up pending),
//! - per-SID filter sets are isolated by `user_sid` tag and filter
//!   id derivation,
//! - the dry-run path produces real `RiskAssessment`-derived signals
//!   in `ReviewSummaryResponse`,
//! - re-installing the same active revision produces an idempotent
//!   `Updated` audit record without filter churn.
//!
//! All tests run on a tempdir-backed SQLite + an in-memory mock WFP
//! engine, so they pass on any host without administrator rights.

#![cfg(target_os = "windows")]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::RuleId;
use nrr_platform_windows::types::WfpAction;
use nrr_platform_windows::wfp::WfpSession;
use nrr_platform_windows::windows_api::{MockWindowsApi, WindowsApiPort};
use nrr_service_runtime::fqdn_cache_lookup::{FqdnCacheLookup, MockFqdnCacheLookup};
use nrr_service_runtime::per_sid_orchestrator::{
    ActiveRulesSnapshot, PerSidApplyAudit, PerSidApplyAuditKind, PerSidApplyOrchestrator,
    RoutePolicySource, RulesProvider,
};
use nrr_service_runtime::production_handlers_misc::ProductionRoutePolicySource;
use nrr_service_runtime::production_rules_provider::ProductionRulesProvider;
use nrr_shared::rules_json::{
    to_canonical_string, AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
};
use nrr_shared::RouteBehaviorMode;
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::route_bindings::{
    BehaviorMode, BindingSource, RouteBindingRecord, RouteBindingsRepository, RoutePolicyRecord,
};
use rusqlite::Connection;

// ── Fixture ──────────────────────────────────────────────────────────────────

/// Holds every dep the apply pipeline needs. `_dir` is dropped at the
/// end of the test → tempdir cleanup. The MockWindowsApi's filter
/// store is the assertion target for "what reached the kernel".
struct PipelineFixture {
    api: Arc<MockWindowsApi>,
    state_conn: Arc<Mutex<Connection>>,
    rules_provider: Arc<ScriptedRulesProvider>,
    /// Held alive so the orchestrator's `Arc<dyn FqdnCacheLookup>`
    /// shares state with the test (per-test rule-book seeding adds
    /// IPs here when ExactFqdn rules need cached lookups).
    #[allow(dead_code)]
    fqdn_cache: Arc<MockFqdnCacheLookup>,
    audit: Arc<RecordingAudit>,
    orchestrator: Arc<PerSidApplyOrchestrator>,
    _dir: tempfile::TempDir,
}

/// In-memory rules provider so tests can swap the active rules
/// without going through `RevisionsRepository`. The
/// `ProductionRulesProvider` path is exercised separately in test
/// `production_rules_provider_decodes_active_revision_e2e`.
#[derive(Default)]
struct ScriptedRulesProvider {
    snapshot: Mutex<Option<ActiveRulesSnapshot>>,
}

impl ScriptedRulesProvider {
    fn set(&self, snap: ActiveRulesSnapshot) {
        *self.snapshot.lock().unwrap() = Some(snap);
    }
}

impl RulesProvider for ScriptedRulesProvider {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        self.snapshot.lock().unwrap().clone()
    }
}

/// Audit sink that captures every `PerSidApplyAuditRecord` so tests
/// can assert on the lifecycle ordering (Applied / Updated /
/// Withdrawn / Failed) and filter counts.
#[derive(Default)]
struct RecordingAudit {
    records: Mutex<Vec<nrr_service_runtime::PerSidApplyAuditRecord>>,
}

impl RecordingAudit {
    fn snapshot(&self) -> Vec<nrr_service_runtime::PerSidApplyAuditRecord> {
        self.records.lock().unwrap().clone()
    }
}

impl PerSidApplyAudit for RecordingAudit {
    fn emit(&self, record: nrr_service_runtime::PerSidApplyAuditRecord) {
        self.records.lock().unwrap().push(record);
    }
}

fn build_fixture() -> PipelineFixture {
    // tempdir + state DB.
    let dir = tempfile::tempdir().expect("temp dir");
    let state_path = dir.path().join("state.db");
    let conn = open_connection(&state_path).expect("open state");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate state");
    let state_conn = Arc::new(Mutex::new(runner.into_connection()));

    // MockWindowsApi + WfpSession.
    let api = Arc::new(MockWindowsApi::new());
    let session = Arc::new(
        WfpSession::open(Arc::clone(&api) as Arc<dyn WindowsApiPort>)
            .expect("WfpSession::open over mock"),
    );

    // Producers.
    let route_source: Arc<dyn RoutePolicySource> =
        Arc::new(ProductionRoutePolicySource::new(Arc::clone(&state_conn)));
    let rules_provider = Arc::new(ScriptedRulesProvider::default());
    let fqdn_cache = Arc::new(MockFqdnCacheLookup::new());
    let audit = Arc::new(RecordingAudit::default());

    let orchestrator = Arc::new(PerSidApplyOrchestrator::new(
        session,
        route_source,
        Arc::clone(&rules_provider) as Arc<dyn RulesProvider>,
        Arc::clone(&fqdn_cache) as Arc<dyn FqdnCacheLookup>,
        Arc::clone(&audit) as Arc<dyn PerSidApplyAudit>,
    ));

    PipelineFixture {
        api,
        state_conn,
        rules_provider,
        fqdn_cache,
        audit,
        orchestrator,
        _dir: dir,
    }
}

// ── Seed helpers ─────────────────────────────────────────────────────────────

fn exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(addr)),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn exact_fqdn_rule(id: &str, fqdn: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(fqdn.into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn rule_book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

/// Seed a row in `route_bindings` so `ProductionRoutePolicySource`
/// returns a non-None snapshot for `sid`. `mode` controls the
/// per-SID behavior mode that the orchestrator threads through
/// `behavior_mode_for_codegen`.
fn seed_route_binding(fx: &PipelineFixture, sid: &str, mode: BehaviorMode) {
    let g = fx.state_conn.lock().unwrap();
    let repo = RouteBindingsRepository::new(&g);
    let record = RoutePolicyRecord {
        primary: Some(RouteBindingRecord {
            stable_id: format!("adapter-primary-{sid}"),
            display_name: "Primary Adapter".into(),
            user_confirmed: true,
            known_stable_ids: vec![],
        }),
        secondary: Some(RouteBindingRecord {
            stable_id: format!("adapter-secondary-{sid}"),
            display_name: "Secondary Adapter".into(),
            user_confirmed: true,
            known_stable_ids: vec![],
        }),
        mode,
        block_secondary_when_unavailable: matches!(mode, BehaviorMode::StrictSecondaryFailClosed),
        // Fail-OPEN here: these e2e tests isolate the rule/route codegen and
        // wire NO kill-switch resolver, so the fail-closed posture (which would
        // add a block-all when the secondary is unresolvable) must not perturb
        // the filter counts. Fail-closed behaviour is covered by the
        // per_sid_orchestrator unit tests.
        kill_switch_fail_closed: false,
        kill_switch_protocols: 0x7F,
        kill_switch_block_all: false,
        // Kill-switch OFF so the leak-guard stays disarmed and does not
        // perturb the isolated rule/route filter counts (matches the fail-open intent above).
        kill_switch_enabled: false,
        allow_dns_over_primary: false,
        include_subdomains: false,
        shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
        mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
        resolve_hosts_bypass: true,
        doh_lockdown_enabled: false,
        doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
        browser_history_auto_seed: false,
        kill_switch_strict_shared_ips: false,
        auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
        auto_rules_eager_delivery_names: false,
        binding_source: BindingSource::UserAssigned,
    };
    repo.update_for_sid(sid, &record, 1_700_000_000)
        .expect("seed binding");
}

fn applied_rules_snapshot(book: CanonicalRuleBook) -> ActiveRulesSnapshot {
    ActiveRulesSnapshot {
        rule_book: book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// install_for_sid with two ExactIp rules
/// produces two filters tagged with the caller SID. Verifies the
/// chain orchestrator → wfp_codegen → WfpSession → MockWindowsApi.
#[test]
fn install_for_sid_with_active_rules_produces_tagged_filters() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S-1-5-21-A", BehaviorMode::PreferPrimary);
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![
            exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 1)),
            exact_ip_rule("r-2", Ipv4Addr::new(203, 0, 113, 2)),
        ],
        vec![],
    )));

    let count = fx
        .orchestrator
        .install_for_sid("S-1-5-21-A")
        .expect("install");
    assert_eq!(count, 2);

    let filters = fx.api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2);
    assert!(filters
        .iter()
        .all(|f| f.user_sid.as_deref() == Some("S-1-5-21-A")));
    let ips: Vec<_> = filters.iter().filter_map(|f| f.remote_ip).collect();
    assert!(ips.contains(&Ipv4Addr::new(203, 0, 113, 1)));
    assert!(ips.contains(&Ipv4Addr::new(203, 0, 113, 2)));

    // Audit: one Applied with the right count + slug.
    let records = fx.audit.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[0].filter_count, 2);
    assert_eq!(records[0].sid, "S-1-5-21-A");
}

/// Mid-session rule edits flow through `recompile_for_sid` as a
/// window-free MAKE-then-BREAK diff: new filters are installed before
/// the old ones are removed, so there is never a gap with no filter
/// installed.
/// The first install yields filters from book A; after swapping the
/// active rules snapshot to book B and calling recompile, the WFP store
/// reflects book B's filters and the audit trail records
/// Applied → Updated (a single diff pass, no Withdrawn).
#[test]
fn recompile_for_sid_reflects_rule_changes() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S", BehaviorMode::PreferPrimary);

    // Book A → 3 filters.
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![
            exact_ip_rule("r-1", Ipv4Addr::new(10, 0, 0, 1)),
            exact_ip_rule("r-2", Ipv4Addr::new(10, 0, 0, 2)),
            exact_ip_rule("r-3", Ipv4Addr::new(10, 0, 0, 3)),
        ],
        vec![],
    )));
    let c1 = fx.orchestrator.install_for_sid("S").expect("install A");
    assert_eq!(c1, 3);
    assert_eq!(fx.api.wfp_filters.lock().unwrap().len(), 3);

    // Book B → 1 filter.
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![exact_ip_rule("r-x", Ipv4Addr::new(192, 0, 2, 9))],
        vec![],
    )));
    let c2 = fx.orchestrator.recompile_for_sid("S").expect("recompile B");
    assert_eq!(c2, 1, "after recompile, B's single rule wins");
    let filters = fx.api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].remote_ip, Some(Ipv4Addr::new(192, 0, 2, 9)));
    drop(filters);

    let kinds: Vec<_> = fx.audit.snapshot().into_iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![PerSidApplyAuditKind::Applied, PerSidApplyAuditKind::Updated],
        "window-free recompile audits one Updated diff pass, never a Withdrawn/Applied teardown pair"
    );
}

/// Per-SID policy with `StrictSecondaryFailClosed` triggers the
/// codegen's catch-all `Block` filter. Verified via filter action +
/// the absence of `remote_ip`.
#[test]
fn strict_secondary_fail_closed_emits_default_block_filter() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S", BehaviorMode::StrictSecondaryFailClosed);
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 9))],
        vec![],
    )));

    fx.orchestrator.install_for_sid("S").expect("install");
    let filters = fx.api.wfp_filters.lock().unwrap();
    // 1 rule-driven Permit + 1 catch-all Block.
    assert_eq!(filters.len(), 2);
    assert!(
        filters
            .iter()
            .any(|f| f.action == WfpAction::Block && f.remote_ip.is_none()),
        "fail-closed catch-all Block must be present"
    );
    assert!(
        filters
            .iter()
            .any(|f| f.action == WfpAction::Permit && f.remote_ip.is_some()),
        "rule-driven Permit must also be present"
    );
}

/// `ExactFqdn` rule with an empty FQDN cache → 0 filters land. The
/// orchestrator still records the SID as known and emits an
/// `Applied` audit with `filter_count = 0`. Codegen diagnostics aren't
/// surfaced through the orchestrator today; we assert on the filter
/// count + audit only.
#[test]
fn exact_fqdn_with_cold_cache_emits_no_filter() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S", BehaviorMode::PreferPrimary);
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![exact_fqdn_rule("r-fqdn", "api.example.com")],
        vec![],
    )));
    // fqdn_cache is empty by default — no IPs known for the hostname.

    let count = fx.orchestrator.install_for_sid("S").expect("install");
    assert_eq!(count, 0, "cold cache → no filters");
    assert!(fx.api.wfp_filters.lock().unwrap().is_empty());

    let records = fx.audit.snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, PerSidApplyAuditKind::Applied);
    assert_eq!(records[0].filter_count, 0);
}

/// Same rule book, two different SIDs → distinct filter sets tagged
/// by `user_sid`. Filter ids must differ across SIDs even when the
/// underlying rules are identical (sid is part of the FNV-1a 5-tuple).
#[test]
fn per_sid_isolation_distinct_filter_ids() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S-A", BehaviorMode::PreferPrimary);
    seed_route_binding(&fx, "S-B", BehaviorMode::PreferPrimary);
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
        vec![],
    )));

    fx.orchestrator.install_for_sid("S-A").expect("install A");
    fx.orchestrator.install_for_sid("S-B").expect("install B");

    let filters = fx.api.wfp_filters.lock().unwrap();
    assert_eq!(filters.len(), 2, "one filter per SID");
    let a: Vec<_> = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("S-A"))
        .collect();
    let b: Vec<_> = filters
        .iter()
        .filter(|f| f.user_sid.as_deref() == Some("S-B"))
        .collect();
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_ne!(
        a[0].id.raw, b[0].id.raw,
        "filter ids must differ across SIDs even for the same rule"
    );
}

/// Re-installing the same active revision for a SID that's already
/// known produces an `Updated` audit (not `Applied`) and keeps the
/// filter count stable. The WFP `AddFilter` calls are idempotent —
/// they don't fail when the filter id is already present (per the
/// `ErrorClass::Idempotent` handling in WfpSession::execute_batch).
#[test]
fn second_install_for_same_sid_is_idempotent_and_audited_as_updated() {
    let fx = build_fixture();
    seed_route_binding(&fx, "S", BehaviorMode::PreferPrimary);
    fx.rules_provider.set(applied_rules_snapshot(rule_book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(8, 8, 8, 8))],
        vec![],
    )));

    let c1 = fx.orchestrator.install_for_sid("S").expect("install #1");
    assert_eq!(c1, 1);
    let c2 = fx.orchestrator.install_for_sid("S").expect("install #2");
    assert_eq!(c2, 1, "filter count must stay at 1");

    let kinds: Vec<_> = fx.audit.snapshot().into_iter().map(|r| r.kind).collect();
    assert_eq!(
        kinds,
        vec![PerSidApplyAuditKind::Applied, PerSidApplyAuditKind::Updated]
    );
}

/// Dry-run risk scoring E2E: seed an active revision with 4 ExactFqdn
/// rules; preview a candidate that has zero rules; the wire
/// `ReviewSummaryResponse` must surface `risk_level: High` and
/// `risk_signals` containing `RuleSetEmptied { prev_total: 4 }`. This
/// is the full chain `ProductionMutationExecutor::preview` →
/// `score_candidate_for_payload` →
/// `RevisionsRepository::get_active` → `rules_json_codec::decode` →
/// `compute_diff` → `score_candidate` → wire DTO.
#[test]
fn dry_run_preview_emits_real_risk_signals_when_rules_emptied() {
    use nrr_service_runtime::activation_coordinator::{
        ActivationAuditEmitter, ActivationCoordinator, ApplyFailurePolicy, CounterIds, FixedClock,
        IdGenerator, InMemoryMarkerStore, NoopActivationAudit, RulesApplyDispatcher,
        ScriptedDispatcher,
    };
    use nrr_service_runtime::active_sid_registry::ActiveSidRegistry;
    use nrr_service_runtime::ipc_handlers::payloads::{MutationKind, ReviewRiskLevel};
    use nrr_service_runtime::ipc_handlers::providers::MutationExecutor;
    use nrr_service_runtime::{ApplyMarkerStore, Clock, ProductionMutationExecutor};
    use nrr_shared::ipc_payloads::RiskSignalDto;

    // Fresh tempdir + state DB. Independent of `build_fixture()` so
    // this test owns its full lifecycle.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let state_conn = Arc::new(Mutex::new(runner.into_connection()));

    // Seed an active revision with 4 ExactFqdn rules.
    let prev_dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: (0..4)
            .map(|i| RuleDto {
                id: format!("r-{i}"),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: format!("host{i}.example.com"),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            })
            .collect(),
        secondary: vec![],
    };
    let prev_json = to_canonical_string(&prev_dto).unwrap();
    {
        let g = state_conn.lock().unwrap();
        g.execute(
            "INSERT INTO revisions (
                principal, revision_id, content_hash, rules_json, status, source,
                correlation_id, created_at, activated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', ?5, ?6, ?6)",
            rusqlite::params![
                nrr_storage::BASELINE_PRINCIPAL,
                "rev-prev-001",
                "prev-hash",
                prev_json,
                "corr-prev",
                1_700_000_000_i64
            ],
        )
        .expect("seed active");
    }

    // Construct coordinator with scripted dispatcher (no real WFP
    // for the dry-run path — coordinator's dry_run_apply produces
    // SidActionPlanSummary entries directly from the dispatcher).
    let registry = Arc::new(ActiveSidRegistry::new());
    let dispatcher: Arc<dyn RulesApplyDispatcher> = Arc::new(ScriptedDispatcher::new());
    let marker: Arc<dyn ApplyMarkerStore> = Arc::new(InMemoryMarkerStore::new());
    let clock: Arc<dyn Clock> = FixedClock::new(1_700_000_100);
    let ids: Arc<dyn IdGenerator> = Arc::new(CounterIds::new());
    let coordinator = Arc::new(ActivationCoordinator::new(
        Arc::clone(&state_conn),
        registry,
        dispatcher,
        marker,
        Arc::new(NoopActivationAudit) as Arc<dyn ActivationAuditEmitter>,
        clock,
        ids,
        ApplyFailurePolicy::AllOrNothing,
    ));

    // Executor with state_conn wired → real `score_candidate` path.
    let executor = ProductionMutationExecutor::new(Arc::clone(&coordinator))
        .with_state_conn(Arc::clone(&state_conn));

    // Candidate: zero rules.
    let empty_dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![],
        secondary: vec![],
    };
    let payload = serde_json::json!({
        "rules-json": to_canonical_string(&empty_dto).unwrap(),
        "content-hash": "candidate-hash-2026",
        "correlation-id": "preview-corr-001",
    });

    let response = executor.preview(
        MutationKind::RulesUpdate,
        &payload,
        nrr_storage::BASELINE_PRINCIPAL,
    );
    assert_eq!(
        response.risk_level,
        ReviewRiskLevel::High,
        "wire risk_level must reflect RuleSetEmptied severity"
    );
    assert!(
        response
            .risk_signals
            .iter()
            .any(|s| matches!(s, RiskSignalDto::RuleSetEmptied { prev_total: 4 })),
        "expected RuleSetEmptied {{ prev_total: 4 }}, got {:?}",
        response.risk_signals
    );
    assert!(response.requires_review);
}

/// Production rules provider end-to-end: seed `revisions` with a real
/// canonical rules-json blob; `ProductionRulesProvider::active_rules`
/// decodes it back into a `CanonicalRuleBook`. This is the production
/// path that the orchestrator uses in production wiring;
/// `ScriptedRulesProvider` is convenient for other tests, but this
/// one proves the decode chain works end-to-end.
#[test]
fn production_rules_provider_decodes_active_revision_e2e() {
    let fx = build_fixture();

    // Seed a real `status='active'` row.
    let dto = CanonicalRulesJsonV1 {
        schema_version: RULES_JSON_SCHEMA_VERSION,
        primary: vec![RuleDto {
            id: "r-1".into(),
            enabled: true,
            address_match: Some(AddressMatchDto::ExactIpv4 {
                address: "203.0.113.42".into(),
            }),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        }],
        secondary: vec![],
    };
    let rules_json = to_canonical_string(&dto).unwrap();
    {
        let g = fx.state_conn.lock().unwrap();
        g.execute(
            "INSERT INTO revisions (
                principal, revision_id, content_hash, rules_json, status, source,
                correlation_id, created_at, activated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', ?5, ?6, ?6)",
            rusqlite::params![
                nrr_storage::BASELINE_PRINCIPAL,
                "rev-test-001",
                "abc",
                rules_json,
                "corr-1",
                1_700_000_000_i64
            ],
        )
        .expect("seed revision");
    }

    let provider = ProductionRulesProvider::new(Arc::clone(&fx.state_conn));
    let snap = provider.active_rules().expect("active rules present");
    assert_eq!(snap.rule_book.primary.rules().len(), 1);
    let rule = &snap.rule_book.primary.rules()[0];
    assert!(matches!(
        rule.address_match.as_ref(),
        Some(CanonicalAddressMatch::ExactIp(addr)) if *addr == Ipv4Addr::new(203, 0, 113, 42)
    ));
}

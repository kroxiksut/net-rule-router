//! Integration contracts: port traits and `ServiceDecisionFlow`.
//!
//! ## Overview
//!
//! This module is the seam between the service orchestration layer
//! and its four subsystem dependencies:
//!
//! | Port | Dependency | What it abstracts |
//! |------|------------|-------------------|
//! | `RuleEnginePort` | `nrr-domain` | pure `decide_route` call |
//! | `CacheLookupPort` | `nrr-storage` | FQDN/IP cache lookup |
//! | `DiagnosticsPort` | `nrr-diagnostics` | audit/log sinks |
//! | `ApplyLayerPort` | `nrr-platform-windows` | route/WFP apply |
//! | `PolicyStorePort` | `nrr-storage` | active revision + profile |
//!
//! None of the production implementations live here. Each port is a
//! `Send + Sync` trait; the runtime wires in the real implementations. Unit
//! tests inject fakes from the `test_support` sub-module.
//!
//! ## `ServiceDecisionFlow`
//!
//! The main orchestrator. Calling `run(context)` executes the canonical
//! per-observation pipeline:
//!
//! 1. Load the active policy from `PolicyStorePort`.
//! 2. Look up the FQDN in the cache via `CacheLookupPort`.
//! 3. Normalise `RuntimeInput` via `nrr_domain::decision_engine_input::normalize_runtime_input`.
//! 4. Assemble `DecisionRequest` and call `RuleEnginePort::decide`.
//! 5. Emit the outcome to `DiagnosticsPort`.
//! 6. If `apply_request` is present in the context, call `ApplyLayerPort::apply`.
//!    On failure, emit a recovery event to `DiagnosticsPort`.
//! 7. Return `ServiceDecisionResult`.
//!
//! ## Correlation IDs
//!
//! A `CorrelationId` (caller-provided) flows through every step so that the
//! IPC request, the decision outcome, the apply attempt, and the diagnostics
//! event are all linkable in the audit trail.
//!
//! ## Production wiring
//!
//! All production implementations of the port traits live in
//! `nrr-service-runtime::production_*` modules; the mock variants in
//! `core/application/src/backend_facade.rs` carry `// preview-only`
//! comments. Nothing in this module changes between mock and production
//! — only the `Arc<dyn ...>` values passed to `ServiceDecisionFlow::new`.

use std::sync::Arc;

use nrr_domain::{
    canonical::CanonicalProfile,
    decision_availability::RouteAvailabilitySnapshot,
    decision_engine::{decide_route, DecisionOutcome, DecisionRequest},
    decision_engine_input::normalize_runtime_input,
    decision_explain::DecisionId,
    decision_lookup::{
        LookupExplainData, LookupExtendedMetadata, LookupResult, LookupStandardSignals,
    },
    decision_matching::ZonePriorityPolicy,
    decision_pipeline::RuntimeInput,
    revision::RevisionId,
};

// ── CorrelationId ─────────────────────────────────────────────────────────────

/// Caller-generated identifier that links one IPC request to the decision,
/// apply attempt, and diagnostics events it produces.
///
/// Format is caller-defined (typically a UUID-v4 string). The service
/// generates one per IPC request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrelationId(pub String);

// ── Cache lookup ──────────────────────────────────────────────────────────────

/// Result of a cache lookup for a single FQDN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheLookupOutcome {
    /// Cache has a fresh entry. No refresh needed.
    Hit(LookupResult),
    /// Cache has no entry for this FQDN. Caller should enqueue a DNS refresh.
    Miss,
    /// Cache has an entry but it is stale. Usable for matching; refresh needed.
    Stale(LookupResult),
}

impl CacheLookupOutcome {
    /// Extract the `LookupResult` (for `Hit` and `Stale`), or return a
    /// no-IP result for `Miss`. In all cases, `was_miss()` indicates whether
    /// a refresh hint should be emitted.
    pub fn into_parts(self) -> (LookupResult, bool) {
        match self {
            CacheLookupOutcome::Hit(lr) => (lr, false),
            CacheLookupOutcome::Stale(lr) => (lr, true),
            CacheLookupOutcome::Miss => (empty_lookup_result(), true),
        }
    }

    pub fn was_miss(&self) -> bool {
        !matches!(self, CacheLookupOutcome::Hit(_))
    }
}

// ── Apply layer ───────────────────────────────────────────────────────────────

/// Routing safety mode forwarded to the apply layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafetyMode {
    /// Block traffic rather than route via an unavailable adapter.
    FailClosed,
    /// Fall back to primary if secondary is unavailable.
    FailOpen,
}

/// Request to push a policy revision to the platform routing/WFP layer.
/// `nrr-platform-windows` implements `ApplyLayerPort` and
/// consumes this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyRequest {
    /// Links this apply to the originating IPC request and decision.
    pub correlation_id: CorrelationId,
    /// The policy revision being applied.
    pub revision_id: RevisionId,
    /// Full canonical profile (rule book + route bindings) to apply.
    pub profile: CanonicalProfile,
    /// Safety mode for in-flight connections during the apply window.
    pub safety_mode: SafetyMode,
    /// When `true`, compute and return what *would* be applied without
    /// making any platform changes (dry-run / confirmation flow).
    pub dry_run: bool,
}

/// Outcome of an `ApplyLayerPort::apply` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyResult {
    /// Platform routing/WFP state now matches the requested revision.
    Success { applied_at_epoch_secs: u64 },
    /// Apply attempt failed. `retryable = true` if a retry is safe.
    Failed { reason: String, retryable: bool },
    /// Apply succeeded but post-apply state verification failed.
    VerificationFailed { expected: String, actual: String },
    /// Automatic rollback initiated; routing is returning to the previous state.
    RollbackStarted { reason: String },
    /// Rollback completed. `fallback_revision_id` is the revision now active.
    RollbackCompleted {
        fallback_revision_id: Option<String>,
    },
    /// Cannot proceed automatically; user must intervene.
    RequiresUserAction { reason: String },
}

// ── Active policy ─────────────────────────────────────────────────────────────

/// Active policy state loaded by `PolicyStorePort`.
#[derive(Clone, Debug)]
pub struct ActivePolicy {
    pub revision_id: RevisionId,
    pub profile: CanonicalProfile,
    /// Whether `ExactIp` (true, default) or `Zone` (false) wins when both
    /// match. Comes from user settings (UiPreferences) until block 16 migrates
    /// these fields to a service-owned store.
    pub zone_policy: ZonePriorityPolicy,
}

// ── Port traits ───────────────────────────────────────────────────────────────

/// Wraps `nrr_domain::decide_route`. All routing decisions go through this
/// port so the service layer never imports the pure function directly, keeping
/// the seam testable.
pub trait RuleEnginePort: Send + Sync {
    fn decide(&self, request: DecisionRequest) -> DecisionOutcome;
}

/// Abstracts over the FQDN/IP cache from `nrr-storage`. The service layer
/// calls this before constructing a `DecisionRequest`; the engine never reads
/// SQLite directly.
pub trait CacheLookupPort: Send + Sync {
    /// Look up the best `LookupResult` for `fqdn`. Returns `Miss` if the
    /// cache has no entry; `Stale` if it has an expired entry.
    fn lookup(&self, fqdn: &str) -> CacheLookupOutcome;
}

/// Write-only sink for service-layer diagnostics, decisions, apply attempts,
/// and recovery events. Fire-and-forget — callers do not wait for the write.
pub trait DiagnosticsPort: Send + Sync {
    fn emit_decision(&self, outcome: &DecisionOutcome, correlation: &CorrelationId);
    fn emit_apply_attempt(
        &self,
        request: &ApplyRequest,
        result: &ApplyResult,
        correlation: &CorrelationId,
    );
    fn emit_recovery_event(&self, detail: &str, correlation: &CorrelationId);
}

/// Interface that block 15 (`nrr-platform-windows`) implements to push
/// routing/WFP policy changes. The service orchestrates *when* to call this;
/// the platform adapter owns *how* the Windows APIs are invoked.
pub trait ApplyLayerPort: Send + Sync {
    fn apply(&self, request: ApplyRequest) -> ApplyResult;
}

/// Reads the currently active policy revision and its canonical profile from
/// the service-owned state store (`nrr-storage`).
pub trait PolicyStorePort: Send + Sync {
    fn load_active(&self) -> Option<ActivePolicy>;
}

// ── Decision flow context and result ──────────────────────────────────────────

/// Everything the `ServiceDecisionFlow` needs for one pipeline execution.
pub struct ServiceDecisionContext {
    /// Raw WFP/test observation, including process context and observation
    /// source. Normalized inside `run()`.
    pub runtime_input: RuntimeInput,
    /// Current adapter availability snapshot from the service's adapter
    /// monitor. Injected here so the engine never polls adapters directly.
    pub availability: RouteAvailabilitySnapshot,
    /// IPC-request correlation identifier.
    pub correlation_id: CorrelationId,
    /// If the caller wants a policy apply to accompany this decision, provide
    /// one. `None` for read-only / observe-only decisions.
    pub apply_request: Option<ApplyRequest>,
}

/// Result of one `ServiceDecisionFlow::run` execution.
// Variants differ in size (the decided path carries a full outcome); this
// result is constructed, matched, and dropped immediately, so the size
// difference doesn't justify boxing on the hot decision path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ServiceDecisionResult {
    /// The decision pipeline ran to completion.
    Decided {
        outcome: DecisionOutcome,
        /// Present when `context.apply_request` was `Some`.
        apply_result: Option<ApplyResult>,
        /// Set to the FQDN that needs a DNS refresh when the cache returned
        /// `Miss` or `Stale`. The runtime loop enqueues this for the cache
        /// refresh task (block 14.7).
        cache_refresh_hint: Option<String>,
        correlation_id: CorrelationId,
    },
    /// No active policy revision is loaded. The service is still bootstrapping
    /// or recovery is required. The caller should surface this state via the
    /// `HealthReporter` rather than silently dropping the request.
    NoActivePolicy { correlation_id: CorrelationId },
}

// ── ServiceDecisionFlow ───────────────────────────────────────────────────────

/// Orchestrates the per-observation pipeline by connecting the five ports.
/// Stateless — multiple threads may call `run()` concurrently (each call is
/// independent; port implementations must be `Sync`).
pub struct ServiceDecisionFlow {
    engine: Arc<dyn RuleEnginePort>,
    cache: Arc<dyn CacheLookupPort>,
    diag: Arc<dyn DiagnosticsPort>,
    apply: Arc<dyn ApplyLayerPort>,
    policy: Arc<dyn PolicyStorePort>,
}

impl ServiceDecisionFlow {
    pub fn new(
        engine: Arc<dyn RuleEnginePort>,
        cache: Arc<dyn CacheLookupPort>,
        diag: Arc<dyn DiagnosticsPort>,
        apply: Arc<dyn ApplyLayerPort>,
        policy: Arc<dyn PolicyStorePort>,
    ) -> Self {
        Self {
            engine,
            cache,
            diag,
            apply,
            policy,
        }
    }

    /// Execute the full per-observation pipeline. See module doc for the
    /// numbered steps.
    pub fn run(&self, ctx: ServiceDecisionContext) -> ServiceDecisionResult {
        let ServiceDecisionContext {
            runtime_input,
            availability,
            correlation_id,
            apply_request,
        } = ctx;

        // ── Step 1: load active policy ────────────────────────────────────
        let active = match self.policy.load_active() {
            Some(p) => p,
            None => return ServiceDecisionResult::NoActivePolicy { correlation_id },
        };

        // ── Step 2: cache lookup ──────────────────────────────────────────
        let fqdn_hint = runtime_input.destination_hostname.clone();
        let (lookup, cache_miss) = match fqdn_hint.as_deref() {
            Some(fqdn) => {
                let outcome = self.cache.lookup(fqdn);
                let miss = outcome.was_miss();
                let (lr, _) = outcome.into_parts();
                (lr, if miss { fqdn_hint.clone() } else { None })
            }
            None => (empty_lookup_result(), None),
        };

        // ── Step 3+4: normalize + build request ───────────────────────────
        let input = normalize_runtime_input(&runtime_input);
        let request = DecisionRequest {
            // Derive the decision ID from the correlation ID so the two are
            // always linkable in diagnostics without an extra index.
            decision_id: DecisionId(format!("d-{}", correlation_id.0)),
            revision_id: active.revision_id,
            profile: active.profile,
            input,
            lookup,
            availability,
            zone_policy: active.zone_policy,
            feature_flags: runtime_input.feature_flags,
            process_context: runtime_input.process_context,
            observation_source: runtime_input.observation_source,
        };

        // ── Step 5: decide ────────────────────────────────────────────────
        let outcome = self.engine.decide(request);

        // ── Step 6: emit decision to diagnostics ──────────────────────────
        self.diag.emit_decision(&outcome, &correlation_id);

        // ── Step 7: optional apply ────────────────────────────────────────
        let apply_result = apply_request.map(|req| {
            let result = self.apply.apply(req.clone());
            self.diag.emit_apply_attempt(&req, &result, &correlation_id);
            if matches!(
                &result,
                ApplyResult::Failed { .. }
                    | ApplyResult::VerificationFailed { .. }
                    | ApplyResult::RollbackStarted { .. }
            ) {
                let detail = format!(
                    "apply attempt failed for revision {}; correlation={}",
                    req.revision_id.as_str(),
                    correlation_id.0
                );
                self.diag.emit_recovery_event(&detail, &correlation_id);
            }
            result
        });

        ServiceDecisionResult::Decided {
            outcome,
            apply_result,
            cache_refresh_hint: cache_miss,
            correlation_id,
        }
    }
}

// ── Production implementations ────────────────────────────────────────────────

/// Production `RuleEnginePort` — delegates directly to `decide_route`.
pub struct DirectRuleEnginePort;

impl RuleEnginePort for DirectRuleEnginePort {
    fn decide(&self, request: DecisionRequest) -> DecisionOutcome {
        decide_route(request)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns a `LookupResult` with no cached IP data. Used when the cache
/// returns `Miss` — the engine will skip `ExactIp` matching but still
/// matches on FQDN/zone rules.
fn empty_lookup_result() -> LookupResult {
    LookupResult {
        selected_ip: None,
        is_multi_ip: false,
        has_conflict: false,
        explain_data: LookupExplainData {
            standard: LookupStandardSignals {
                cache_hit: false,
                freshness: None,
                source: None,
                errors: Vec::new(),
            },
            extended: LookupExtendedMetadata {
                all_resolved_ips: Vec::new(),
                reverse_hostnames: Vec::new(),
                selected_entry_ttl_secs: None,
                selected_entry_resolved_at: None,
            },
        },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub mod test_support {
    use super::*;
    use std::sync::Mutex;

    use nrr_domain::{
        decision_availability::{
            AvailabilityCheckSource, InterfaceLifecycleState, RouteAdapterAvailability,
            RouteAvailabilitySnapshot, RouteAvailabilityState, SnapshotStaleness,
        },
        decision_pipeline::{
            AdapterAvailability, DecisionFeatureFlags, InterfaceAvailabilitySnapshot,
            ObservationSource, ProcessContext, ProtocolHints, RuntimeInput,
        },
        revision::RevisionId,
    };

    // ── Fakes ──────────────────────────────────────────────────────────

    /// Delegates directly to the real `decide_route`. Tests care about
    /// correlation flow, not the specific decision outcome, so no override
    /// mechanism is needed here.
    pub struct FakeRuleEngine;

    impl FakeRuleEngine {
        pub fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    impl RuleEnginePort for FakeRuleEngine {
        fn decide(&self, request: DecisionRequest) -> DecisionOutcome {
            decide_route(request)
        }
    }

    pub struct FakeCachePort {
        pub result: Mutex<CacheLookupOutcome>,
    }

    impl FakeCachePort {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(CacheLookupOutcome::Miss),
            })
        }

        pub fn set(&self, outcome: CacheLookupOutcome) {
            *self.result.lock().unwrap() = outcome;
        }
    }

    impl CacheLookupPort for FakeCachePort {
        fn lookup(&self, _fqdn: &str) -> CacheLookupOutcome {
            self.result.lock().unwrap().clone()
        }
    }

    pub struct FakeDiagnosticsPort {
        pub decisions: Mutex<Vec<(String /* decision_id */, String /* correlation */)>>,
        pub apply_attempts: Mutex<Vec<String /* correlation */>>,
        pub recovery_events: Mutex<Vec<String /* detail */>>,
    }

    impl FakeDiagnosticsPort {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                decisions: Mutex::new(Vec::new()),
                apply_attempts: Mutex::new(Vec::new()),
                recovery_events: Mutex::new(Vec::new()),
            })
        }

        pub fn decision_count(&self) -> usize {
            self.decisions.lock().unwrap().len()
        }

        pub fn apply_count(&self) -> usize {
            self.apply_attempts.lock().unwrap().len()
        }

        pub fn recovery_count(&self) -> usize {
            self.recovery_events.lock().unwrap().len()
        }

        pub fn last_decision_correlation(&self) -> Option<String> {
            self.decisions
                .lock()
                .unwrap()
                .last()
                .map(|(_, cid)| cid.clone())
        }

        pub fn last_apply_correlation(&self) -> Option<String> {
            self.apply_attempts.lock().unwrap().last().cloned()
        }
    }

    impl DiagnosticsPort for FakeDiagnosticsPort {
        fn emit_decision(&self, outcome: &DecisionOutcome, correlation: &CorrelationId) {
            self.decisions
                .lock()
                .unwrap()
                .push((outcome.decision_id.0.clone(), correlation.0.clone()));
        }

        fn emit_apply_attempt(
            &self,
            _request: &ApplyRequest,
            _result: &ApplyResult,
            correlation: &CorrelationId,
        ) {
            self.apply_attempts
                .lock()
                .unwrap()
                .push(correlation.0.clone());
        }

        fn emit_recovery_event(&self, detail: &str, _correlation: &CorrelationId) {
            self.recovery_events
                .lock()
                .unwrap()
                .push(detail.to_string());
        }
    }

    pub struct FakeApplyPort {
        pub result: Mutex<ApplyResult>,
        pub calls: Mutex<Vec<CorrelationId>>,
    }

    impl FakeApplyPort {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                result: Mutex::new(ApplyResult::Success {
                    applied_at_epoch_secs: 1_000_000,
                }),
                calls: Mutex::new(Vec::new()),
            })
        }

        pub fn set(&self, result: ApplyResult) {
            *self.result.lock().unwrap() = result;
        }

        pub fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        pub fn last_correlation(&self) -> Option<String> {
            self.calls.lock().unwrap().last().map(|c| c.0.clone())
        }
    }

    impl ApplyLayerPort for FakeApplyPort {
        fn apply(&self, request: ApplyRequest) -> ApplyResult {
            self.calls
                .lock()
                .unwrap()
                .push(request.correlation_id.clone());
            self.result.lock().unwrap().clone()
        }
    }

    pub struct FakePolicyStore {
        pub active: Mutex<Option<ActivePolicy>>,
    }

    impl FakePolicyStore {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                active: Mutex::new(None),
            })
        }

        pub fn set(&self, policy: ActivePolicy) {
            *self.active.lock().unwrap() = Some(policy);
        }

        pub fn clear(&self) {
            *self.active.lock().unwrap() = None;
        }
    }

    impl PolicyStorePort for FakePolicyStore {
        fn load_active(&self) -> Option<ActivePolicy> {
            self.active.lock().unwrap().clone()
        }
    }

    // ── Fixture helpers ────────────────────────────────────────────────

    pub fn make_flow(
        engine: Arc<dyn RuleEnginePort>,
        cache: Arc<dyn CacheLookupPort>,
        diag: Arc<dyn DiagnosticsPort>,
        apply: Arc<dyn ApplyLayerPort>,
        policy: Arc<dyn PolicyStorePort>,
    ) -> ServiceDecisionFlow {
        ServiceDecisionFlow::new(engine, cache, diag, apply, policy)
    }

    pub fn make_active_policy() -> ActivePolicy {
        use nrr_domain::canonical::CanonicalProfile;
        use nrr_domain::{
            AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole,
        };
        ActivePolicy {
            revision_id: RevisionId::from_prefixed_string(
                "rev-11111111-2222-3333-4444-555555555555".to_string(),
            )
            .unwrap(),
            profile: CanonicalProfile {
                primary: RouteBinding {
                    role: RouteRole::Primary,
                    adapter: AdapterIdentity {
                        stable_id: "eth0".to_string(),
                        display_name: "Ethernet".to_string(),
                    },
                    source: BindingSource::UserAssigned,
                },
                secondary: None,
                behavior_mode: RouteBehaviorMode::PreferPrimary,
                rule_book: Default::default(),
            },
            zone_policy: ZonePriorityPolicy { prefer_ip: true },
        }
    }

    pub fn make_runtime_input(hostname: Option<&str>) -> RuntimeInput {
        use nrr_domain::RouteBehaviorMode;
        use std::time::SystemTime;
        RuntimeInput {
            process_context: ProcessContext {
                pid: 1234,
                process_name: Some("test.exe".to_string()),
                process_path: None,
                parent_pid: None,
                browser_hint: false,
            },
            destination_hostname: hostname.map(str::to_string),
            destination_ip: None,
            protocol_hints: ProtocolHints {
                ip_protocol: None,
                destination_port: None,
            },
            active_revision_id: RevisionId::from_prefixed_string(
                "rev-11111111-2222-3333-4444-555555555555".to_string(),
            )
            .unwrap(),
            route_behavior_mode: RouteBehaviorMode::PreferPrimary,
            interface_availability: InterfaceAvailabilitySnapshot {
                primary: AdapterAvailability::Available,
                secondary: None,
            },
            observed_at: SystemTime::UNIX_EPOCH,
            observation_source: ObservationSource::TestHarness,
            feature_flags: DecisionFeatureFlags {
                browser_stub_experimental: false,
            },
        }
    }

    pub fn primary_available_snapshot() -> RouteAvailabilitySnapshot {
        use nrr_domain::decision_availability::SecondaryAvailabilityStatus;
        use std::time::SystemTime;
        RouteAvailabilitySnapshot {
            primary: RouteAdapterAvailability {
                state: RouteAvailabilityState::Available,
                lifecycle: InterfaceLifecycleState::PresentActive,
                reason: None,
            },
            secondary: SecondaryAvailabilityStatus::NotConfigured,
            taken_at: SystemTime::UNIX_EPOCH,
            age_ms: 0,
            staleness: SnapshotStaleness::Fresh,
            check_source: AvailabilityCheckSource::TestHarness,
        }
    }

    pub fn make_apply_request(correlation_id: &str) -> ApplyRequest {
        let policy = make_active_policy();
        ApplyRequest {
            correlation_id: CorrelationId(correlation_id.to_string()),
            revision_id: policy.revision_id,
            profile: policy.profile,
            safety_mode: SafetyMode::FailClosed,
            dry_run: false,
        }
    }

    pub fn cid(s: &str) -> CorrelationId {
        CorrelationId(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn default_flow() -> (
        Arc<FakeCachePort>,
        Arc<FakeDiagnosticsPort>,
        Arc<FakeApplyPort>,
        Arc<FakePolicyStore>,
        ServiceDecisionFlow,
    ) {
        let engine = FakeRuleEngine::new();
        let cache = FakeCachePort::new();
        let diag = FakeDiagnosticsPort::new();
        let apply = FakeApplyPort::new();
        let policy = FakePolicyStore::new();

        let flow = make_flow(
            engine as Arc<dyn RuleEnginePort>,
            Arc::clone(&cache) as Arc<dyn CacheLookupPort>,
            Arc::clone(&diag) as Arc<dyn DiagnosticsPort>,
            Arc::clone(&apply) as Arc<dyn ApplyLayerPort>,
            Arc::clone(&policy) as Arc<dyn PolicyStorePort>,
        );
        (cache, diag, apply, policy, flow)
    }

    fn ctx(
        hostname: Option<&str>,
        correlation: &str,
        apply: Option<ApplyRequest>,
    ) -> ServiceDecisionContext {
        ServiceDecisionContext {
            runtime_input: make_runtime_input(hostname),
            availability: primary_available_snapshot(),
            correlation_id: cid(correlation),
            apply_request: apply,
        }
    }

    // ── Cases ──────────────────────────────────────────────────────────

    #[test]
    fn decision_run_emits_decision_to_diagnostics() {
        let (cache, diag, _apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        cache.set(CacheLookupOutcome::Hit(super::empty_lookup_result()));

        let result = flow.run(ctx(Some("example.com"), "req-1", None));

        assert!(
            matches!(result, ServiceDecisionResult::Decided { .. }),
            "got: {result:?}"
        );
        assert_eq!(diag.decision_count(), 1, "one decision emitted");
        assert_eq!(
            diag.last_decision_correlation().as_deref(),
            Some("req-1"),
            "correlation ID forwarded to diagnostics"
        );
    }

    #[test]
    fn cache_miss_produces_refresh_hint() {
        let (cache, _diag, _apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        cache.set(CacheLookupOutcome::Miss);

        let result = flow.run(ctx(Some("cache-miss.example"), "req-2", None));

        match result {
            ServiceDecisionResult::Decided {
                cache_refresh_hint: Some(fqdn),
                ..
            } => assert_eq!(fqdn, "cache-miss.example"),
            other => panic!("expected Decided with hint, got: {other:?}"),
        }
    }

    #[test]
    fn cache_stale_produces_refresh_hint_with_lookup_result() {
        let (cache, _diag, _apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        cache.set(CacheLookupOutcome::Stale(super::empty_lookup_result()));

        let result = flow.run(ctx(Some("stale.example"), "req-3", None));

        match result {
            ServiceDecisionResult::Decided {
                cache_refresh_hint: Some(fqdn),
                ..
            } => assert_eq!(fqdn, "stale.example"),
            other => panic!("expected Decided with hint, got: {other:?}"),
        }
    }

    #[test]
    fn no_apply_request_leaves_apply_result_none() {
        let (_cache, _diag, apply, policy, flow) = default_flow();
        policy.set(make_active_policy());

        let result = flow.run(ctx(None, "req-4", None));

        assert_eq!(apply.call_count(), 0, "apply port not called");
        match result {
            ServiceDecisionResult::Decided {
                apply_result: None, ..
            } => {}
            other => panic!("expected no apply_result, got: {other:?}"),
        }
    }

    #[test]
    fn apply_success_recorded_in_result() {
        let (_cache, diag, _apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        // apply port returns Success by default.
        let req = make_apply_request("req-5");

        let result = flow.run(ctx(None, "req-5", Some(req)));

        match result {
            ServiceDecisionResult::Decided {
                apply_result: Some(ApplyResult::Success { .. }),
                ..
            } => {}
            other => panic!("expected Success apply result, got: {other:?}"),
        }
        assert_eq!(diag.recovery_count(), 0, "no recovery event on success");
    }

    #[test]
    fn apply_failure_triggers_recovery_event() {
        let (_cache, diag, apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        apply.set(ApplyResult::Failed {
            reason: "route add failed".to_string(),
            retryable: true,
        });
        let req = make_apply_request("req-6");

        let result = flow.run(ctx(None, "req-6", Some(req)));

        match result {
            ServiceDecisionResult::Decided {
                apply_result: Some(ApplyResult::Failed { .. }),
                ..
            } => {}
            other => panic!("expected Failed apply result, got: {other:?}"),
        }
        assert_eq!(
            diag.recovery_count(),
            1,
            "recovery event emitted on failure"
        );
    }

    #[test]
    fn correlation_id_flows_through_decision_apply_and_diagnostics() {
        let (_cache, diag, apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        let req = make_apply_request("req-xyz");

        let result = flow.run(ctx(None, "req-xyz", Some(req)));

        match &result {
            ServiceDecisionResult::Decided { correlation_id, .. } => {
                assert_eq!(correlation_id.0, "req-xyz");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(
            diag.last_decision_correlation().as_deref(),
            Some("req-xyz"),
            "diagnostics received correlation ID"
        );
        assert_eq!(
            apply.last_correlation().as_deref(),
            Some("req-xyz"),
            "apply port received correlation ID"
        );
        assert_eq!(
            diag.last_apply_correlation().as_deref(),
            Some("req-xyz"),
            "apply attempt logged with correlation ID"
        );
    }

    #[test]
    fn no_active_policy_returns_no_active_policy_variant() {
        let (_cache, _diag, _apply, _policy, flow) = default_flow();
        // policy store returns None (not set).

        let result = flow.run(ctx(Some("example.com"), "req-8", None));

        match &result {
            ServiceDecisionResult::NoActivePolicy { correlation_id } => {
                assert_eq!(correlation_id.0, "req-8");
            }
            other => panic!("expected NoActivePolicy, got: {other:?}"),
        }
    }

    #[test]
    fn no_hostname_skips_cache_lookup_and_emits_no_hint() {
        let (cache, _diag, _apply, policy, flow) = default_flow();
        policy.set(make_active_policy());
        cache.set(CacheLookupOutcome::Miss); // should not be called

        let result = flow.run(ctx(None, "req-9", None));

        match result {
            ServiceDecisionResult::Decided {
                cache_refresh_hint: None,
                ..
            } => {}
            other => panic!("expected no hint for no-hostname request, got: {other:?}"),
        }
    }
}

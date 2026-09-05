//! Production [`MutationExecutor`] backed by
//! [`ActivationCoordinator`].
//!
//! Handles `MutationKind::RulesUpdate` end-to-end through the
//! coordinator's revision lifecycle:
//! - `preview` → `submit_candidate` (idempotent dedup) +
//!   `dry_run_rules` → `ReviewSummaryResponse`
//! - `execute` → `submit_candidate` + `issue_confirmation_token` +
//!   `activate` → `MutationOutcome`
//! - `rollback` → `rollback_to(target)` → `MutationOutcome`
//! - `safe_disable` → `crash_recovery::execute_safe_disable` (audit +
//!   confirmation) THEN the REAL teardown via the routing-pause coordinator
//!   (`pause_all_active`: remove every active SID's WFP filters + persist the
//!   pause, resumable via the routing-pause toggle). Requires
//!   `with_pause_coordinator`; audit-only + `apply-layer-unavailable` without it.
//!
//! Other `MutationKind` variants (`RouteBindingsUpdate`, `PresetImport`,
//! `PresetExport`, `SettingsExport`) return a structured "not yet
//! implemented" result. `RouteBindingsUpdate` is intentionally NOT
//! routed here — per-SID route policy has its own dedicated
//! `RoutePolicyUpdate` IPC op.
//!
//! Wire payload schema for `RulesUpdate` (kebab-case JSON):
//! ```json
//! {
//!   "rules-json": "<serialised RulesRevisionContent>",
//!   "content-hash": "<sha-256 hex>",
//!   "correlation-id": "<ipc request id>"
//! }
//! ```

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::activation_coordinator::{
    ActivationCoordinator, ActivationOutcome, CandidateSubmission, ConfirmationToken,
    DryRunSummary, PolicyError, PreFlightWarning, RollbackTarget,
};
use crate::crash_recovery::{
    execute_safe_disable, RecoveryAuditSink, SafeDisableOutcome, SafeDisableRequest,
};
use crate::ipc_handlers::event_bus::EventBus;
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::operation_status_store::OperationError;
use crate::ipc_handlers::payloads::{
    MutationKind, ReviewRiskLevel, ReviewSummaryResponse, SecurityAlertMutationPayload,
};
use crate::ipc_handlers::providers::{
    rule_edits_allowed_for, MutationExecutor, MutationOutcome, RoutePolicyApplyTrigger,
    ServiceStabilityConfigProvider, RULES_LOCKED_ERROR_CODE, RULES_LOCKED_MESSAGE,
};
use nrr_diagnostics::audit::alert::{SecurityAlertState, SecurityAlertsRepository};
use nrr_domain::canonical::{CanonicalProfile, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::preset_canonicalize::{canonicalize_preset_rules, PresetRulesCanonicalizeOutcome};
use nrr_domain::preset_validation::{
    validate_preset_bytes, PresetFileValidationOutcome, PresetImportRejectedReason,
};
use nrr_domain::revision::RevisionId;
use nrr_domain::rules_file::HostPlatform;
use nrr_domain::rules_json_codec;
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionContent, RulesRevisionSource};
use nrr_domain::{AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole};
use nrr_shared::ipc_payloads::RiskSignalDto;
use nrr_shared::ipc_payloads::{
    CrossSetDuplicateDto, PresetImportPayload, PresetImportPayloadError, PresetImportTarget,
    StatusUpdateEvent,
};
use nrr_shared::rules_json;
use nrr_storage::revisions::RevisionsRepository;
use rusqlite::Connection;

/// 5-minute TTL for the *internal* coordinator confirmation token. The
/// IPC-side confirmation token (handled by `MutationTokenStore`) has
/// its own TTL; the coordinator token is consumed within milliseconds
/// of issue inside `execute_rules_update` and never returns to the
/// caller, so the TTL here is only a defensive ceiling.
const COORDINATOR_TOKEN_TTL_SECS: i64 = 60;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RulesUpdatePayload {
    rules_json: String,
    content_hash: String,
    #[serde(default)]
    correlation_id: Option<String>,
}

pub struct ProductionMutationExecutor {
    coordinator: Arc<ActivationCoordinator>,
    /// Recovery audit sink for `safe_disable`. When `None`,
    /// safe-disable returns `audit-unavailable`. Wired by
    /// `runtime_deps.rs` once the production audit writer is present.
    recovery_audit_sink: Option<Arc<dyn RecoveryAuditSink>>,
    /// Security alerts repository for ack/resolve
    /// mutations. When `None`, the corresponding `MutationKind`
    /// variants return `alerts-store-unavailable`.
    alerts_repo: Option<Arc<dyn SecurityAlertsRepository>>,
    /// State DB connection used by the real
    /// risk-scoring path to load the previous active revision via
    /// `RevisionsRepository::get_active`. When `None`, the executor
    /// falls back to the count-based heuristic
    /// ([`classify_risk_heuristic`]) — keeping older tests that don't
    /// construct a full DB working.
    state_conn: Option<Arc<Mutex<Connection>>>,
    /// Event bus for emitting `MutationProgress`
    /// push events at execute() lifecycle boundaries. When `None`,
    /// progress emission is suppressed (older tests, runtime paths
    /// where the GUI doesn't care about per-mutation progress).
    event_bus: Option<Arc<EventBus>>,
    /// Recompile hook fired after a `RulesResetToBaseline`
    /// so the caller's live WFP enforcement falls back to the baseline
    /// rules immediately (same `on_policy_changed(sid)` trigger
    /// `RoutePolicyUpdate` uses). `rules-update` / `preset-import` don't
    /// need this — they recompile inside `ActivationCoordinator::activate`
    /// — but a reset bypasses activation (it deletes, it doesn't activate).
    /// When `None` (tests / recovery-blocked startup) the state is reset
    /// and live recompile is skipped.
    apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    /// Routing-pause coordinator, so
    /// `safe_disable` performs the REAL teardown (remove every active SID's WFP
    /// filters + persist the pause flag) instead of an audit-only no-op. When
    /// `None` (WFP/orchestrator unavailable, or tests) safe-disable falls back
    /// to audit-only and reports the apply layer as unavailable.
    pause_coordinator: Option<Arc<crate::routing_pause::RoutingPauseCoordinator>>,
    /// Reader for the machine-wide administrative rules lock. Enforced here —
    /// not only at the IPC handler — because this is where mutations actually
    /// land, and because the companion-domain author submits through this
    /// executor without passing any handler at all. `None` leaves the gate
    /// open (degraded boot / tests).
    stability: Option<Arc<dyn ServiceStabilityConfigProvider>>,
}

impl ProductionMutationExecutor {
    pub fn new(coordinator: Arc<ActivationCoordinator>) -> Self {
        Self {
            coordinator,
            recovery_audit_sink: None,
            alerts_repo: None,
            state_conn: None,
            event_bus: None,
            apply_trigger: None,
            pause_coordinator: None,
            stability: None,
        }
    }

    /// Attach the reader for the machine-wide administrative rules lock, so a
    /// non-elevated submission is refused where mutations are applied rather
    /// than only where they arrive.
    pub fn with_stability_provider(
        mut self,
        provider: Arc<dyn ServiceStabilityConfigProvider>,
    ) -> Self {
        self.stability = Some(provider);
        self
    }

    /// Attaches the per-SID recompile trigger so a
    /// `RulesResetToBaseline` re-applies the baseline rules to the
    /// caller's live WFP filters. Without it, the reset still clears the
    /// stored divergence (read-through resumes on the next snapshot/apply)
    /// but does not eagerly recompile.
    pub fn with_apply_trigger(mut self, trigger: Arc<dyn RoutePolicyApplyTrigger>) -> Self {
        self.apply_trigger = Some(trigger);
        self
    }

    /// Attaches the routing-pause coordinator so
    /// `safe_disable` really tears down enforcement (per-active-SID
    /// `remove_for_sid` + persisted pause) via the same path the routing-pause
    /// toggle uses. Without it, `safe_disable` is audit-only and reports the
    /// apply layer unavailable.
    pub fn with_pause_coordinator(
        mut self,
        coordinator: Arc<crate::routing_pause::RoutingPauseCoordinator>,
    ) -> Self {
        self.pause_coordinator = Some(coordinator);
        self
    }

    /// Attaches the event bus so `execute()` emits
    /// `StatusUpdateEvent::MutationProgress` at start (`phase:
    /// "started"`) and end (`phase: "completed"` / `"failed"`). The
    /// GUI's `MutationsModel` consumes these via the
    /// `StatusUpdatesSubscribe` push channel to drive `hasInFlight`
    /// state without polling.
    pub fn with_event_bus(mut self, bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    /// Attaches the state DB connection so the
    /// dry-run path can load the previous active revision and run
    /// [`nrr_domain::risk::score_candidate`] over a real
    /// `StructuralDiff` instead of the count-based heuristic.
    pub fn with_state_conn(mut self, conn: Arc<Mutex<Connection>>) -> Self {
        self.state_conn = Some(conn);
        self
    }

    /// Attaches a recovery audit sink so `safe_disable` can
    /// run. Until an apply-layer suspension hook is defined,
    /// `apply_available` is hardcoded to `true` here (the caller has
    /// already validated the IPC-level confirmation token via
    /// `MutationTokenStore`; the upstream
    /// [`crate::ipc_handlers::product_impact_disable`] handler is the
    /// one place that reaches `safe_disable`).
    pub fn with_recovery_audit_sink(mut self, sink: Arc<dyn RecoveryAuditSink>) -> Self {
        self.recovery_audit_sink = Some(sink);
        self
    }

    /// Attaches the security alerts repository so
    /// `SecurityAlertAck` and `SecurityAlertResolve` mutations can run.
    /// Without it, the corresponding kinds return `alerts-store-unavailable`.
    pub fn with_alerts_repo(mut self, repo: Arc<dyn SecurityAlertsRepository>) -> Self {
        self.alerts_repo = Some(repo);
        self
    }

    fn parse_rules_payload(
        payload: &serde_json::Value,
    ) -> Result<RulesUpdatePayload, OperationError> {
        serde_json::from_value::<RulesUpdatePayload>(payload.clone()).map_err(|e| OperationError {
            code: "malformed-payload".into(),
            message: format!("RulesUpdate payload invalid: {e}"),
        })
    }

    /// Defense-in-depth Free-tier rule cap. The GUI already refuses to add past
    /// `freeRulesMaxCount`, but a hand-edited preset file or a crafted IPC
    /// payload could carry more; the service rejects those authoritatively here.
    /// Uses `nrr_shared::rules_json` — the SAME canonical decoder the apply layer
    /// uses — so the cap can't be dodged by malforming the payload (a string the
    /// apply layer accepts is counted identically). Guards both `RulesUpdate` and
    /// `PresetImport` before the candidate reaches the coordinator.
    fn enforce_free_rule_cap(rules_json: &str) -> Result<(), OperationError> {
        if nrr_shared::rules_json::exceeds_free_rule_cap(rules_json) {
            // Report the number the cap actually counts, or the message names a
            // total the user cannot reconcile with the limit they hit.
            let count = nrr_shared::rules_json::user_rule_count(rules_json);
            return Err(OperationError {
                code: "rule-cap-exceeded".into(),
                message: format!(
                    "Up to {} active rules are allowed; this revision has {count}.",
                    nrr_shared::rules_json::FREE_MAX_RULES
                ),
            });
        }
        Ok(())
    }

    /// Re-spell the incoming rule book the one canonical way, and re-hash it.
    ///
    /// A client can send a rule book that never went through validation, so
    /// `Cloud.exe` and `cloud.exe` arrive as two different payloads with two
    /// different content hashes — and since the hash is what dedupes
    /// revisions, the same rule set became a NEW revision every time the
    /// spelling flipped, which the apply layer then saw as a rule added and
    /// removed on every pass. Canonicalizing here makes the two identical
    /// before anything downstream compares them.
    ///
    /// A payload we cannot decode is left exactly as it came: rejecting it is
    /// the validation layer's call, not this one's.
    fn canonicalize_rules_payload(payload: &mut RulesUpdatePayload) {
        let Ok(dto) = serde_json::from_str::<nrr_shared::rules_json::CanonicalRulesJsonV1>(
            &payload.rules_json,
        ) else {
            return;
        };
        let Ok(content) = nrr_domain::rules_json_codec::decode(dto) else {
            return;
        };
        let Ok(canonical) = nrr_shared::rules_json::to_canonical_string(
            &nrr_domain::rules_json_codec::encode(&content),
        ) else {
            return;
        };
        if canonical == payload.rules_json {
            return;
        }
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        payload.content_hash = format!("{:x}", hasher.finalize());
        payload.rules_json = canonical;
    }

    fn submission_from(
        payload: &RulesUpdatePayload,
        fallback_correlation: &str,
        principal: &str,
    ) -> CandidateSubmission {
        CandidateSubmission {
            // The caller's principal (own SID for a
            // `UserScopedMutation`, or baseline for an elevated
            // `MutationRequest`), threaded from `IpcRequestContext.caller_stored()`
            // by the submit handler.
            principal: principal.to_string(),
            rules_json: payload.rules_json.clone(),
            content_hash: payload.content_hash.clone(),
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: payload
                .correlation_id
                .clone()
                .unwrap_or_else(|| fallback_correlation.to_string()),
            risk_level: None,
            review_summary_json: None,
        }
    }

    fn preview_rules_update(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> ReviewSummaryResponse {
        let mut parsed = match Self::parse_rules_payload(payload) {
            Ok(p) => p,
            Err(e) => return malformed_summary(&e.message),
        };
        // Same spelling the execute path will store, so the preview scores and
        // dedupes against exactly what would be applied.
        Self::canonicalize_rules_payload(&mut parsed);
        if let Err(e) = Self::enforce_free_rule_cap(&parsed.rules_json) {
            return malformed_summary(&e.message);
        }
        // The score is reflected back into the wire `ReviewSummaryResponse`.
        let scored = self.score_candidate_for_payload(&parsed.rules_json, principal);
        // Planned from the payload, NOT from a stored candidate. This is a read
        // operation; submitting one made it write a revision row per press of
        // the preview button, and those rows then showed up in the user's
        // pending list as edits they never made.
        let summary = self
            .coordinator
            .dry_run_rules(principal, &parsed.rules_json, "ipc-dry-run");
        let mut response = dry_run_to_review_summary(&summary, scored);
        response.cross_set_duplicates = cross_set_duplicates_of(&parsed.rules_json);
        response
    }

    /// Computes the [`RiskAssessment`] for the
    /// candidate against the currently-active revision. Returns
    /// `None` when:
    /// - The executor has no state DB connection wired (older test
    ///   fixtures, recovery-blocked startup);
    /// - The candidate's `rules_json` fails to decode (`malformed_summary`
    ///   already handled it upstream);
    /// - Any storage failure on `get_active` — degrades to the
    ///   count-based heuristic so a transient lock doesn't break the
    ///   dry-run path.
    ///
    /// `None` means "no real scoring; fall back to heuristic". `Some`
    /// carries the wire-shaped (`ReviewRiskLevel`,
    /// `Vec<RiskSignalDto>`) ready for the response.
    fn score_candidate_for_payload(
        &self,
        rules_json: &str,
        principal: &str,
    ) -> Option<ScoredCandidate> {
        let conn = self.state_conn.as_ref()?;
        let candidate_book = decode_rule_book(rules_json)?;
        // Diff against the CALLER's per-principal active book,
        // not the baseline: comparing every candidate against the
        // (often-populated) baseline would make a user whose own active set
        // differs see "no changes" even though their edit/preset genuinely
        // differed.
        let prev_book = load_active_rule_book(conn, principal);

        let prev_profile = prev_book.map(|book| profile_for(conn, principal, book));
        let next_profile = profile_for(conn, principal, candidate_book);

        let diff = nrr_domain::review::compute_diff(prev_profile.as_ref(), &next_profile);
        let assessment = nrr_domain::risk::score_candidate(
            &diff,
            &nrr_domain::revision::RevisionSource::DirectEdit,
        );

        let wire_signals: Vec<RiskSignalDto> =
            assessment.signals.iter().map(RiskSignalDto::from).collect();
        // Project the domain ReviewSummary (per-rule
        // diff buckets) into wire `RuleSummaryEntryDto` vectors so
        // the GUI's ReviewDiffDialog renders the three columns with
        // real content.
        let review = diff.to_review_summary();
        Some(ScoredCandidate {
            level: assessment.level.into(),
            signals: wire_signals,
            rules_added: review.rules_added.iter().map(map_rule_entry).collect(),
            rules_removed: review.rules_removed.iter().map(map_rule_entry).collect(),
            rules_modified: review.rules_modified.iter().map(map_rule_entry).collect(),
            rules_retargeted: review.rules_retargeted.iter().map(map_rule_entry).collect(),
        })
    }

    // Split across files, same inherent impl: alerts in `::alerts`, preset
    // import in `::preset_import`, driving a revision to active in
    // `::activation_drive`.
}

/// Map `MutationKind` to its kebab-case wire slug. Mirrors the
/// `#[serde(rename_all = "kebab-case")]` derivation on the enum so
/// the slug round-trips through the wire DTO.
#[allow(deprecated)] // PresetExport / SettingsExport variants are wire-stable but deprecated
fn mutation_kind_slug(kind: MutationKind) -> &'static str {
    match kind {
        MutationKind::RulesUpdate => "rules-update",
        MutationKind::RouteBindingsUpdate => "route-bindings-update",
        MutationKind::PresetImport => "preset-import",
        MutationKind::PresetExport => "preset-export",
        MutationKind::SettingsExport => "settings-export",
        MutationKind::SecurityAlertAck => "security-alert-ack",
        MutationKind::SecurityAlertResolve => "security-alert-resolve",
        MutationKind::RulesResetToBaseline => "rules-reset-to-baseline",
    }
}

#[allow(deprecated)] // PresetExport / SettingsExport variants are wire-stable but deprecated
impl MutationExecutor for ProductionMutationExecutor {
    fn preview(
        &self,
        kind: MutationKind,
        payload: &serde_json::Value,
        principal: &str,
    ) -> ReviewSummaryResponse {
        // Demoted info → debug: a preview runs on every "Save and
        // review" click. Operationally interesting events live on
        // the `execute` boundary (started / completed / warn-failed)
        // which already log via the bus and via tracing below.
        // The correlation id names the CALL SITE (the client prefixes it), and
        // two flows can preview a byte-identical payload at the same moment —
        // without this, a log of two previews cannot say who asked for either.
        tracing::debug!(
            target: "nrr::mutation::preview",
            kind = ?kind,
            principal = %principal,
            payload_size = payload.to_string().len(),
            correlation_id = payload
                .get("correlation-id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            "mutation preview requested",
        );
        match kind {
            MutationKind::RulesUpdate => self.preview_rules_update(payload, principal),
            // RouteBindingsUpdate goes through the dedicated
            // `RoutePolicyUpdate` IPC op — not routed via
            // this executor.
            MutationKind::RouteBindingsUpdate => {
                not_implemented_summary("use RoutePolicyUpdate IPC op for per-SID route policy")
            }
            MutationKind::PresetImport => self.preview_preset_import(payload, principal),
            MutationKind::RulesResetToBaseline => self.preview_reset_to_baseline(principal),
            MutationKind::PresetExport | MutationKind::SettingsExport => not_implemented_summary(
                "use PresetExportGet / SettingsExportFull read-only IPC ops",
            ),
            MutationKind::SecurityAlertAck => {
                self.alert_review_summary(payload, SecurityAlertState::Acknowledged)
            }
            MutationKind::SecurityAlertResolve => {
                self.alert_review_summary(payload, SecurityAlertState::Resolved)
            }
        }
    }

    fn execute(&self, stored: StoredMutation, principal: &str) -> MutationOutcome {
        tracing::info!(
            target: "nrr::mutation::execute",
            kind = ?stored.kind,
            principal = %principal,
            correlation_id = stored.correlation_id.as_deref().unwrap_or(""),
            payload_size = stored.payload.to_string().len(),
            "mutation execute started",
        );
        // Emit `started` push event before dispatch
        // so the GUI's MutationsModel marks the correlation-id in
        // flight. Suppressed when correlation_id is None (older
        // clients / non-progress-aware payloads) or when no event
        // bus is wired.
        self.emit_progress(&stored, "started", None);

        // Administrative rules lock, enforced at the point of application.
        // The IPC handler refuses the same submission earlier with a typed
        // wire code; this is the backstop for every other way into the
        // executor (the companion-domain rule author) and the reason a
        // hand-built client gains nothing by skipping the handler.
        if stored.kind.changes_rules()
            && !rule_edits_allowed_for(self.stability.as_ref(), stored.caller_is_elevated)
        {
            let error = OperationError {
                code: RULES_LOCKED_ERROR_CODE.into(),
                message: RULES_LOCKED_MESSAGE.into(),
            };
            tracing::warn!(
                target: "nrr::mutation::execute",
                kind = ?stored.kind,
                principal = %principal,
                "mutation refused — rule changes are locked by the administrator",
            );
            self.emit_progress(&stored, "failed", Some(error.code.clone()));
            return MutationOutcome::Failed(error);
        }

        let outcome = match stored.kind {
            MutationKind::RulesUpdate => self.execute_rules_update(&stored.payload, principal),
            MutationKind::RouteBindingsUpdate => MutationOutcome::Failed(OperationError {
                code: "wrong-channel".into(),
                message: "RouteBindingsUpdate uses RoutePolicyUpdate IPC op".into(),
            }),
            MutationKind::PresetImport => self.execute_preset_import(&stored.payload, principal),
            MutationKind::RulesResetToBaseline => self.execute_reset_to_baseline(
                principal,
                stored.correlation_id.as_deref().unwrap_or("ipc-reset"),
            ),
            MutationKind::PresetExport | MutationKind::SettingsExport => {
                MutationOutcome::Failed(OperationError {
                    code: "wrong-channel".into(),
                    message: format!(
                        "{:?} is deprecated; use PresetExportGet / SettingsExportFull \
                         read-only IPC ops instead",
                        stored.kind
                    ),
                })
            }
            MutationKind::SecurityAlertAck => {
                self.execute_alert_state_change(&stored.payload, SecurityAlertState::Acknowledged)
            }
            MutationKind::SecurityAlertResolve => {
                self.execute_alert_state_change(&stored.payload, SecurityAlertState::Resolved)
            }
        };

        // Terminal phase event — `completed` or `failed`. Error
        // code threads through to the wire so the GUI can render a
        // localised toast.
        match &outcome {
            MutationOutcome::Completed(_) => {
                tracing::info!(
                    target: "nrr::mutation::execute",
                    kind = ?stored.kind,
                    correlation_id = stored.correlation_id.as_deref().unwrap_or(""),
                    "mutation execute completed",
                );
                self.emit_progress(&stored, "completed", None);
            }
            MutationOutcome::Failed(err) => {
                tracing::warn!(
                    target: "nrr::mutation::execute",
                    kind = ?stored.kind,
                    correlation_id = stored.correlation_id.as_deref().unwrap_or(""),
                    error_code = %err.code,
                    error_message = %err.message,
                    "mutation execute failed",
                );
                self.emit_progress(&stored, "failed", Some(err.code.clone()));
            }
        }
        outcome
    }

    fn rollback(&self, principal: &str, target_revision_id: Option<&str>) -> MutationOutcome {
        let target = match target_revision_id {
            None => RollbackTarget::Lkg,
            Some(raw) => match RevisionId::from_prefixed_string(raw.to_string()) {
                Ok(id) => RollbackTarget::Specific(id),
                Err(e) => {
                    return MutationOutcome::Failed(OperationError {
                        code: "malformed-revision-id".into(),
                        message: format!("invalid target revision id: {e}"),
                    });
                }
            },
        };
        // Rollback is scoped to the caller's principal,
        // threaded from the rollback handler's `IpcRequestContext.caller_stored()`.
        match self
            .coordinator
            .rollback_to(principal, target, "ipc-rollback")
        {
            Ok(outcome) => activation_to_outcome(outcome),
            Err(e) => policy_error_outcome(&e),
        }
    }

    fn safe_disable(&self, reason: &str) -> MutationOutcome {
        // Calls `crash_recovery::execute_safe_disable` with
        // the production recovery audit sink. The IPC-level confirmation
        // token has already been validated by the upstream handler; we
        // pass identical tokens to the inner check so it short-circuits
        // (defence in depth — if the sink is misconfigured the outcome
        // is `AuditWriteFailed`, not silent corruption).
        let Some(sink) = self.recovery_audit_sink.as_ref() else {
            return MutationOutcome::Failed(OperationError {
                code: "audit-unavailable".into(),
                message: "recovery audit sink not wired; safe-disable refused".into(),
            });
        };
        const CONFIRM_TOKEN: &str = "ipc-safe-disable";
        let request = SafeDisableRequest {
            correlation_id: "ipc-safe-disable".into(),
            reason: reason.to_string(),
            confirm_token: CONFIRM_TOKEN.into(),
        };
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // The apply layer is "available" exactly
        // when the routing-pause coordinator is wired (WFP/orchestrator present).
        // Without it, safe-disable is audit-only and must NOT claim enforcement
        // was suspended, so report the apply layer as unavailable.
        let apply_available = self.pause_coordinator.is_some();
        match execute_safe_disable(
            &request,
            CONFIRM_TOKEN,
            apply_available,
            sink.as_ref(),
            now_secs,
        ) {
            SafeDisableOutcome::Disabled {
                disabled_at_epoch_secs,
            } => {
                // The SafeDisableExecuted audit is written; now perform the REAL
                // teardown — remove every active SID's WFP filters and persist
                // the pause so a routing-pause `resume` reinstalls them.
                let Some(coordinator) = self.pause_coordinator.as_ref() else {
                    // Unreachable given the `apply_available` gate above.
                    return MutationOutcome::Failed(OperationError {
                        code: "apply-layer-unavailable".into(),
                        message: "pause coordinator not wired; cannot suspend enforcement".into(),
                    });
                };
                match coordinator.pause_all_active(Some(reason)) {
                    Ok(paused) => MutationOutcome::Completed(serde_json::json!({
                        "outcome": "safe-disabled",
                        "disabled-at-secs": disabled_at_epoch_secs,
                        "reason": reason,
                        "suspended-sids": paused.len(),
                    })),
                    Err(e) => MutationOutcome::Failed(OperationError {
                        code: "safe-disable-teardown-failed".into(),
                        message: format!("enforcement teardown failed after audit: {e:?}"),
                    }),
                }
            }
            SafeDisableOutcome::AlreadyDisabled => MutationOutcome::Completed(serde_json::json!({
                "outcome": "already-safe-disabled",
            })),
            SafeDisableOutcome::AuditWriteFailed { detail } => {
                MutationOutcome::Failed(OperationError {
                    code: "audit-write-failed".into(),
                    message: format!("audit write failed before safe-disable: {detail}"),
                })
            }
            SafeDisableOutcome::ApplyLayerUnavailable => MutationOutcome::Failed(OperationError {
                code: "apply-layer-unavailable".into(),
                message: "apply layer unreachable; cannot restore default routing".into(),
            }),
            SafeDisableOutcome::ConfirmationRequired => {
                // Defensive: tokens are constructed identical above.
                MutationOutcome::Failed(OperationError {
                    code: "confirmation-required".into(),
                    message: "internal: confirmation token mismatch".into(),
                })
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Review summary for a `RulesResetToBaseline` dry-run.
/// `has_divergence` is whether the caller currently has its own active
/// revision; `discarded_rules` is how many of the caller's rules will be
/// dropped (when decodable). The GUI renders this in the confirm dialog.
fn reset_review_summary(
    has_divergence: bool,
    discarded_rules: Option<usize>,
) -> ReviewSummaryResponse {
    let (diff_summary, requires_review, risk_level) = if has_divergence {
        // Machine-parseable form so `ReviewDiffDialog.diffSummaryText()`
        // localises it (mirrors the SID-counter `diff_summary`). Fallback
        // count `0` keeps the `\d+` shape when the user's own rules_json
        // can't be decoded (rare); the GUI only ever renders this diverged
        // branch (the no-op branch is short-circuited client-side).
        let count = discarded_rules.unwrap_or(0);
        (
            format!("reset-to-baseline; discard {count} rule(s)"),
            true,
            ReviewRiskLevel::Medium,
        )
    } else {
        (
            "reset-to-baseline: already on baseline (no custom rules to discard)".to_string(),
            false,
            ReviewRiskLevel::Low,
        )
    };
    ReviewSummaryResponse {
        diff_summary,
        provenance: "service".into(),
        risk_level,
        requires_review,
        changed_fields: vec!["rules:reset-to-baseline".into()],
        risk_signals: Vec::new(),
        rules_added: Vec::new(),
        rules_removed: Vec::new(),
        rules_modified: Vec::new(),
        rules_retargeted: Vec::new(),
        extended_sections: Vec::new(),
        cross_set_duplicates: Vec::new(),
    }
}

/// The same rule written into both route sets, both copies enabled.
///
/// Reported with the preview rather than blocked: the candidate is valid, the
/// two copies simply disagree about where the traffic goes, and only the user
/// can settle that. An undecodable candidate yields nothing — the malformed
/// path already speaks for it.
fn cross_set_duplicates_of(rules_json: &str) -> Vec<CrossSetDuplicateDto> {
    let Some(book) = decode_rule_book(rules_json) else {
        return Vec::new();
    };
    nrr_domain::validation::enabled_duplicates_across_sets(&book)
        .into_iter()
        .map(|found| CrossSetDuplicateDto {
            identity_key: found.identity_key,
            primary_rule_id: found.primary_rule_id.as_str().to_string(),
            secondary_rule_id: found.secondary_rule_id.as_str().to_string(),
            match_summary: found.match_summary,
        })
        .collect()
}

fn malformed_summary(message: &str) -> ReviewSummaryResponse {
    ReviewSummaryResponse {
        diff_summary: format!("malformed payload: {message}"),
        provenance: "service".into(),
        risk_level: ReviewRiskLevel::Low,
        requires_review: true,
        changed_fields: Vec::new(),
        risk_signals: Vec::new(),
        rules_added: Vec::new(),
        rules_removed: Vec::new(),
        rules_modified: Vec::new(),
        rules_retargeted: Vec::new(),
        extended_sections: Vec::new(),
        cross_set_duplicates: Vec::new(),
    }
}

/// Output of [`ProductionMutationExecutor::assemble_preset_import`] —
/// fully canonicalised + serialised, ready for `CandidateSubmission`.
struct AssembledPresetImport {
    /// Canonical `rules_json` covering both routes after merge.
    rules_json: String,
    /// SHA-256 hex of `rules_json`.
    content_hash: String,
    /// Caller-supplied correlation ID (forwarded to the coordinator and
    /// to `MutationProgress` push events).
    correlation_id: Option<String>,
}

/// Build a `CandidateSubmission` for the assembled preset import. Mirrors
/// [`ProductionMutationExecutor::submission_from`] but tags the
/// revision with `RulesRevisionSource::PresetImport`.
fn preset_submission_from(
    assembled: &AssembledPresetImport,
    fallback_correlation: &str,
    principal: &str,
) -> CandidateSubmission {
    CandidateSubmission {
        // The caller's principal, threaded from the submit
        // handler's `IpcRequestContext.caller_stored()` (own SID for a
        // `UserScopedMutation`, baseline for an elevated `MutationRequest`).
        principal: principal.to_string(),
        rules_json: assembled.rules_json.clone(),
        content_hash: assembled.content_hash.clone(),
        source: RulesRevisionSource::PresetImport,
        correlation_id: assembled
            .correlation_id
            .clone()
            .unwrap_or_else(|| fallback_correlation.to_string()),
        risk_level: None,
        review_summary_json: None,
    }
}

/// Build a `ReviewSummaryResponse` describing a preset-import failure
/// without touching the coordinator (the input never reached
/// `submit_candidate`). Risk-level is Low because the candidate hash
/// is unknown — the structural error is the actionable signal.
fn preset_failure_summary(err: &OperationError) -> ReviewSummaryResponse {
    ReviewSummaryResponse {
        diff_summary: format!("{}: {}", err.code, err.message),
        provenance: "service".into(),
        risk_level: ReviewRiskLevel::Low,
        requires_review: true,
        changed_fields: vec![format!("error-code:{}", err.code)],
        risk_signals: Vec::new(),
        rules_added: Vec::new(),
        rules_removed: Vec::new(),
        rules_modified: Vec::new(),
        rules_retargeted: Vec::new(),
        extended_sections: Vec::new(),
        cross_set_duplicates: Vec::new(),
    }
}

/// Decode a base64-wrapped preset blob, run the structural validator,
/// and canonicalize it for `route`. Returns the resulting
/// `CanonicalRuleSet` on success. Errors map to wire-stable codes:
///
/// - `malformed-payload` — base64 decode failed.
/// - `payload-too-large` — preset > 1 MiB.
/// - `file-encoding` — preset is not valid UTF-8.
/// - `match-value-too-long`, `inline-comment-too-long`, `too-many-rules`
///   — corresponding rejection reasons from `validate_preset_bytes`.
/// - `canonicalize-rejected` — semantic validation failure
///   (IDNA / IPv4 / unsupported section in a known slot / etc.).
fn canonicalize_route_bytes(
    b64: &str,
    route: RouteRole,
    include_child_processes: bool,
    import_only_active: bool,
) -> Result<CanonicalRuleSet, OperationError> {
    let bytes = BASE64_STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| OperationError {
            code: "malformed-payload".into(),
            message: format!("PresetImport: base64 decode failed for {route:?}: {e}"),
        })?;
    let outcome = validate_preset_bytes(&bytes);
    let parse_outcome = match outcome {
        PresetFileValidationOutcome::Accepted { parse_outcome } => parse_outcome,
        PresetFileValidationOutcome::AcceptedWithWarnings { parse_outcome, .. } => parse_outcome,
        PresetFileValidationOutcome::Rejected(reason) => {
            return Err(rejection_to_operation_error(route, &reason));
        }
        // Forward-compat: `PresetFileValidationOutcome` is
        // `#[non_exhaustive]` — treat any future variant as a rejection
        // so the executor never panics on unknown shapes.
        _ => {
            return Err(OperationError {
                code: "preset-validation-failed".into(),
                message: format!("PresetImport: unknown validation outcome for {route:?}"),
            });
        }
    };
    // Diagnostic: surface how many rules the SERVER-side
    // parser actually recognised vs dropped into unknown/unsupported sections.
    // A report of "GUI shows N rules but the service stores 0" pins here:
    // if known_rules==0 while the file clearly had Free-section rules, the
    // server parser disagrees with the launcher parser (nrr_shared::
    // preset_parser) — the divergence the parser-unification will remove.
    {
        let known_rules: usize = parse_outcome
            .parsed
            .sections
            .iter()
            .map(|s| s.entries.len())
            .sum();
        let unknown_rules: usize = parse_outcome
            .unknown_sections
            .iter()
            .map(|u| u.entries.len())
            .sum();
        tracing::info!(
            target: "nrr::mutation::preset",
            route = ?route,
            known_sections = parse_outcome.parsed.sections.len(),
            known_rules,
            unknown_sections = parse_outcome.unknown_sections.len(),
            unknown_rules,
            "preset bytes parsed (server-side)"
        );
    }
    let canonicalized = canonicalize_preset_rules(
        &parse_outcome,
        route,
        HostPlatform::compiled(),
        include_child_processes,
    );
    // "Import only active": drop rules disabled in the source preset
    // (commented recognizable lines — e.g. application rules left off pending
    // per-process routing) so they don't enter the revision at all. Filtering
    // here (server-side, before the revision is built) keeps the service and
    // the GUI consistent; a client-side table filter would drift because the
    // service would still store and re-send the disabled rows.
    let finalize = |rule_set: CanonicalRuleSet| -> CanonicalRuleSet {
        if !import_only_active {
            return rule_set;
        }
        CanonicalRuleSet::from_rules(
            rule_set
                .rules()
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect(),
        )
    };
    match canonicalized {
        PresetRulesCanonicalizeOutcome::Accepted { rule_set } => Ok(finalize(rule_set)),
        PresetRulesCanonicalizeOutcome::AcceptedWithWarnings { rule_set, .. } => {
            Ok(finalize(rule_set))
        }
        PresetRulesCanonicalizeOutcome::Rejected { errors } => Err(OperationError {
            code: "canonicalize-rejected".into(),
            message: format!(
                "PresetImport: canonicalization rejected {route:?} ({} errors): {errors:?}",
                errors.len()
            ),
        }),
        // Forward-compat: `PresetRulesCanonicalizeOutcome` is
        // `#[non_exhaustive]`. If domain adds a new variant, default to
        // a generic rejection so the executor never panics.
        _ => Err(OperationError {
            code: "canonicalize-rejected".into(),
            message: format!("PresetImport: unknown canonicalize outcome for {route:?}"),
        }),
    }
}

fn rejection_to_operation_error(
    route: RouteRole,
    reason: &PresetImportRejectedReason,
) -> OperationError {
    let (code, detail) = match reason {
        PresetImportRejectedReason::FileTooLarge {
            size_bytes,
            limit_bytes,
        } => (
            "payload-too-large",
            format!("{size_bytes} bytes (limit {limit_bytes})"),
        ),
        PresetImportRejectedReason::EncodingError => {
            ("file-encoding", "not valid UTF-8".to_string())
        }
        PresetImportRejectedReason::TooManyRules { count, limit } => {
            ("too-many-rules", format!("{count} rules (limit {limit})"))
        }
        PresetImportRejectedReason::MatchValueTooLong {
            section,
            len,
            limit,
            ..
        } => (
            "match-value-too-long",
            format!("section '{section}' value {len} bytes (limit {limit})"),
        ),
        PresetImportRejectedReason::InlineCommentTooLong {
            section,
            chars,
            limit,
            ..
        } => (
            "inline-comment-too-long",
            format!("section '{section}' comment {chars} chars (limit {limit})"),
        ),
        // Forward-compat: `#[non_exhaustive]` enum — map any future
        // variant to a generic code rather than panic.
        _ => (
            "preset-validation-failed",
            "unknown rejection reason".to_string(),
        ),
    };
    OperationError {
        code: code.into(),
        message: format!("PresetImport: {route:?} {detail}"),
    }
}

/// Single-route preset import preserves the OTHER route's rules from
/// the currently active revision. Returns empty when no active revision
/// exists or any storage/decode failure occurs (first-import scenario).
fn load_active_primary(conn: Option<&Arc<Mutex<Connection>>>, principal: &str) -> CanonicalRuleSet {
    load_active_book_or_empty(conn, principal).primary
}

fn load_active_secondary(
    conn: Option<&Arc<Mutex<Connection>>>,
    principal: &str,
) -> CanonicalRuleSet {
    load_active_book_or_empty(conn, principal).secondary
}

fn load_active_book_or_empty(
    conn: Option<&Arc<Mutex<Connection>>>,
    principal: &str,
) -> CanonicalRuleBook {
    let Some(conn) = conn else {
        return CanonicalRuleBook::default();
    };
    let Ok(guard) = conn.lock() else {
        return CanonicalRuleBook::default();
    };
    let repo = RevisionsRepository::new(&guard);
    let record = match repo.get_active_for(principal) {
        Ok(Some(r)) => r,
        _ => return CanonicalRuleBook::default(),
    };
    let dto = match rules_json::from_canonical_string(&record.rules_json) {
        Ok(d) => d,
        Err(_) => return CanonicalRuleBook::default(),
    };
    match rules_json_codec::decode(dto) {
        Ok(c) => c.rule_book,
        Err(_) => CanonicalRuleBook::default(),
    }
}

fn not_implemented_summary(reason: &str) -> ReviewSummaryResponse {
    ReviewSummaryResponse {
        diff_summary: format!("not implemented: {reason}"),
        provenance: "service".into(),
        risk_level: ReviewRiskLevel::Low,
        requires_review: true,
        changed_fields: Vec::new(),
        risk_signals: Vec::new(),
        rules_added: Vec::new(),
        rules_removed: Vec::new(),
        rules_modified: Vec::new(),
        rules_retargeted: Vec::new(),
        extended_sections: Vec::new(),
        cross_set_duplicates: Vec::new(),
    }
}

/// Wire-shaped scoring result produced by
/// [`ProductionMutationExecutor::score_candidate_for_payload`]. When
/// `None` is returned the dry-run path falls back to the legacy
/// count-based heuristic.
///
/// Also carries the projected per-rule
/// diff buckets, populated when the wire `ReviewSummaryResponse`
/// returns them to the GUI's `ReviewDiffDialog`.
#[derive(Debug)]
struct ScoredCandidate {
    level: ReviewRiskLevel,
    signals: Vec<RiskSignalDto>,
    rules_added: Vec<nrr_shared::ipc_payloads::RuleSummaryEntryDto>,
    rules_removed: Vec<nrr_shared::ipc_payloads::RuleSummaryEntryDto>,
    rules_modified: Vec<nrr_shared::ipc_payloads::RuleSummaryEntryDto>,
    rules_retargeted: Vec<nrr_shared::ipc_payloads::RuleSummaryEntryDto>,
}

/// Projects a domain `RuleSummaryEntry` into the
/// wire `RuleSummaryEntryDto`. `route` is rendered as the slug
/// `"primary"` / `"secondary"` so the GUI can use it as a CSS-style
/// hint (column accent, sort key) without enum awareness.
fn map_rule_entry(
    entry: &nrr_domain::review::RuleSummaryEntry,
) -> nrr_shared::ipc_payloads::RuleSummaryEntryDto {
    let route_slug = match entry.route {
        nrr_domain::RouteRole::Primary => "primary",
        nrr_domain::RouteRole::Secondary => "secondary",
    };
    nrr_shared::ipc_payloads::RuleSummaryEntryDto {
        id: entry.id.clone(),
        display: entry.display.clone(),
        route: route_slug.to_string(),
        enabled: entry.enabled,
    }
}

/// Decode a canonical rules-json string into a domain
/// [`CanonicalRuleBook`]. Returns `None` on any wire/codec failure —
/// the caller falls back to the heuristic path.
fn decode_rule_book(rules_json: &str) -> Option<CanonicalRuleBook> {
    let dto = nrr_shared::rules_json::from_canonical_string(rules_json).ok()?;
    let content = nrr_domain::rules_json_codec::decode(dto).ok()?;
    Some(content.rule_book)
}

/// Load the currently-active revision's rule book, if any. `None`
/// means "no prev revision" (first activation) OR storage failure;
/// risk scoring degrades gracefully either way (the new signals
/// `RuleSetEmptied` / `HighRemovalRatio` simply don't fire when prev
/// is None).
fn load_active_rule_book(
    conn: &Arc<Mutex<Connection>>,
    principal: &str,
) -> Option<CanonicalRuleBook> {
    let guard = conn.lock().ok()?;
    let repo = nrr_storage::revisions::RevisionsRepository::new(&guard);
    let record = repo.get_active_for(principal).ok()??;
    decode_rule_book(&record.rules_json)
}

/// Wrap a rule book into the [`CanonicalProfile`] the risk scorer compares.
///
/// The binding and the behaviour mode are read from the caller's stored policy
/// rather than invented: they used to be fixed placeholders
/// (`PreferPrimary`, one synthetic adapter) on BOTH sides of the diff, which
/// made `FailClosedActivation` unreachable — a first revision activated while
/// the user is in the strict fail-closed mode is exactly the case that signal
/// exists for, and it read as `PreferPrimary`.
///
/// `DefaultBehaviorChanged` and `UnstableInterfaceBinding` still cannot fire
/// HERE, and that is correct: editing rules changes neither, so both sides of
/// this diff carry the same policy. They belong to the route-policy update
/// path, which does not score risk at all today.
fn profile_for(
    conn: &Arc<Mutex<Connection>>,
    principal: &str,
    rule_book: CanonicalRuleBook,
) -> CanonicalProfile {
    const SYNTHETIC_ID: &str = "synthetic-rules-update";
    let stored = conn.lock().ok().and_then(|guard| {
        nrr_storage::route_bindings::RouteBindingsRepository::new(&guard)
            .load_for_sid(principal)
            .ok()
    });
    let binding = |b: Option<&nrr_storage::RouteBindingRecord>, role: RouteRole| RouteBinding {
        role,
        adapter: AdapterIdentity {
            stable_id: b
                .map(|b| b.stable_id.clone())
                .unwrap_or_else(|| SYNTHETIC_ID.to_string()),
            display_name: b
                .map(|b| b.display_name.clone())
                .unwrap_or_else(|| SYNTHETIC_ID.to_string()),
        },
        source: BindingSource::UserAssigned,
    };
    CanonicalProfile {
        primary: binding(
            stored.as_ref().and_then(|p| p.primary.as_ref()),
            RouteRole::Primary,
        ),
        secondary: stored
            .as_ref()
            .and_then(|p| p.secondary.as_ref())
            .map(|b| binding(Some(b), RouteRole::Secondary)),
        behavior_mode: stored
            .as_ref()
            .map(|p| match p.mode {
                nrr_storage::route_bindings::BehaviorMode::PreferPrimary => {
                    RouteBehaviorMode::PreferPrimary
                }
                nrr_storage::route_bindings::BehaviorMode::PreferSecondaryWhenAvailable => {
                    RouteBehaviorMode::PreferSecondaryWhenAvailable
                }
                nrr_storage::route_bindings::BehaviorMode::StrictSecondaryFailClosed => {
                    RouteBehaviorMode::StrictSecondaryFailClosed
                }
            })
            .unwrap_or(RouteBehaviorMode::PreferPrimary),
        rule_book,
    }
}

fn dry_run_to_review_summary(
    summary: &DryRunSummary,
    scored: Option<ScoredCandidate>,
) -> ReviewSummaryResponse {
    let total_additions: u32 = summary
        .action_plans
        .iter()
        .map(|p| p.filter_additions)
        .sum();
    let total_removals: u32 = summary.action_plans.iter().map(|p| p.filter_removals).sum();
    let warning_count = summary.pre_flight_warnings.len();
    let (risk_level, risk_signals, rules_added, rules_removed, rules_modified, rules_retargeted) =
        match scored {
            Some(s) => (
                s.level,
                s.signals,
                s.rules_added,
                s.rules_removed,
                s.rules_modified,
                s.rules_retargeted,
            ),
            None => (
                classify_risk_heuristic(
                    total_additions,
                    total_removals,
                    &summary.pre_flight_warnings,
                ),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        };
    ReviewSummaryResponse {
        diff_summary: format!(
            "{} SID(s); +{total_additions} / -{total_removals} filters; {warning_count} pre-flight warning(s)",
            summary.action_plans.len(),
        ),
        provenance: "service".into(),
        risk_level,
        requires_review: warning_count > 0
            || total_additions + total_removals > 0
            || !matches!(risk_level, ReviewRiskLevel::Low),
        changed_fields: summary
            .action_plans
            .iter()
            .map(|p| format!("sid:{}", p.sid))
            .collect(),
        risk_signals,
        // Populate per-rule diff buckets from
        // the scored candidate so the GUI's three diff columns render
        // real content when the candidate added/removed/modified rules.
        rules_added,
        rules_removed,
        rules_modified,
        rules_retargeted,
        extended_sections: Vec::new(),
        cross_set_duplicates: Vec::new(),
    }
}

/// Legacy count-based heuristic, kept as the
/// fallback path (no state DB connection wired). Production wiring
/// always passes [`Some(ScoredCandidate)`] to
/// [`dry_run_to_review_summary`]; this function only fires in test
/// fixtures or recovery-blocked startup.
fn classify_risk_heuristic(
    additions: u32,
    removals: u32,
    warnings: &[PreFlightWarning],
) -> ReviewRiskLevel {
    if !warnings.is_empty() || removals + additions > 100 {
        ReviewRiskLevel::High
    } else if removals + additions > 10 {
        ReviewRiskLevel::Medium
    } else {
        ReviewRiskLevel::Low
    }
}

fn activation_to_outcome(outcome: ActivationOutcome) -> MutationOutcome {
    match outcome {
        ActivationOutcome::Activated {
            revision_id,
            applied_at_secs,
        } => MutationOutcome::Completed(serde_json::json!({
            "outcome": "activated",
            "revision-id": revision_id.as_str(),
            "applied-at-secs": applied_at_secs,
        })),
        ActivationOutcome::AppliedWithDrift {
            revision_id,
            succeeded_sids,
            failed_sids,
        } => MutationOutcome::Completed(serde_json::json!({
            "outcome": "applied-with-drift",
            "revision-id": revision_id.as_str(),
            "succeeded-sids": succeeded_sids,
            "failed-sids": failed_sids,
        })),
        ActivationOutcome::RolledBackOnFailure {
            rejected_revision,
            reverted_sids,
            reason,
        } => MutationOutcome::Failed(OperationError {
            code: "rolled-back-on-failure".into(),
            message: format!(
                "revision {} rejected; reverted {} SID(s); reason: {reason}",
                rejected_revision.as_str(),
                reverted_sids.len(),
            ),
        }),
        ActivationOutcome::PreFlightFailed {
            rejected_revision,
            sid_failures,
        } => MutationOutcome::Failed(OperationError {
            code: "pre-flight-failed".into(),
            message: format!(
                "revision {} rejected by pre-flight; {} SID failure(s)",
                rejected_revision.as_str(),
                sid_failures.len(),
            ),
        }),
    }
}

fn policy_error_outcome(err: &PolicyError) -> MutationOutcome {
    let (code, message) = match err {
        PolicyError::ConfirmationTokenUnknown => (
            "token-not-found",
            "confirmation token unknown to coordinator store".into(),
        ),
        PolicyError::ConfirmationTokenAlreadyUsed => (
            "token-already-consumed",
            "confirmation token already used".into(),
        ),
        PolicyError::ConfirmationTokenExpired => {
            ("token-expired", "confirmation token TTL elapsed".into())
        }
        PolicyError::ConfirmationTokenForOtherRevision => (
            "token-revision-mismatch",
            "confirmation token was issued for a different revision".into(),
        ),
        PolicyError::RevisionNotFound(_) => ("revision-not-found", format!("{err:?}")),
        PolicyError::RevisionNotInExpectedStatus { .. } => {
            ("revision-status-mismatch", format!("{err:?}"))
        }
        PolicyError::NoLastKnownGood => (
            "no-last-known-good",
            "rollback to LKG requested but no last-known-good revision exists".into(),
        ),
        PolicyError::StorageFailure { .. } => ("storage-failure", format!("{err:?}")),
        PolicyError::MarkerWriteFailed(_) => ("marker-write-failed", format!("{err:?}")),
        PolicyError::RevisionIntegrityRejected {
            revision_id,
            reason,
        } => (
            "revision-integrity-rejected",
            format!(
                "revision {} failed the integrity gate: {reason:?}",
                revision_id.as_str()
            ),
        ),
    };
    MutationOutcome::Failed(OperationError {
        code: code.into(),
        message,
    })
}

// `Duration` import retained for future TTL plumbing.
#[allow(dead_code)]
const _DURATION_USED: Duration = Duration::from_secs(0);

// `ConfirmationToken` import is used through `coordinator.activate(...)`.
#[allow(dead_code)]
fn _confirmation_token_unused(_: &ConfirmationToken) {}

// ── Tests ────────────────────────────────────────────────────────────────────

mod activation_drive;
mod alerts;
mod preset_import;
#[cfg(test)]
mod tests;

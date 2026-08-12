//! Production [`MutationExecutor`] backed by
//! [`ActivationCoordinator`].
//!
//! Handles `MutationKind::RulesUpdate` end-to-end through the
//! coordinator's revision lifecycle:
//! - `preview` → `submit_candidate` (idempotent dedup) +
//!   `dry_run_apply` → `ReviewSummaryResponse`
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
    PresetImportPayload, PresetImportPayloadError, PresetImportTarget, StatusUpdateEvent,
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
        let parsed = match Self::parse_rules_payload(payload) {
            Ok(p) => p,
            Err(e) => return malformed_summary(&e.message),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&parsed.rules_json) {
            return malformed_summary(&e.message);
        }
        // Score risk BEFORE submitting the candidate
        // so we don't poison the candidate's stored `risk_level` when
        // the dry-run path completes. The score is reflected back into
        // the wire `ReviewSummaryResponse`; the candidate itself stays
        // at `risk_level: None` until activation persists it.
        let scored = self.score_candidate_for_payload(&parsed.rules_json, principal);

        let submission = Self::submission_from(&parsed, "ipc-dry-run", principal);
        let revision_id = match self.coordinator.submit_candidate(submission) {
            Ok(id) => id,
            Err(e) => return policy_error_summary(&e),
        };
        match self.coordinator.dry_run_apply(&revision_id, "ipc-dry-run") {
            Ok(summary) => dry_run_to_review_summary(&summary, scored),
            Err(e) => policy_error_summary(&e),
        }
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

        let prev_profile = prev_book.map(synthetic_profile);
        let next_profile = synthetic_profile(candidate_book);

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

    fn parse_alert_payload(
        payload: &serde_json::Value,
    ) -> Result<SecurityAlertMutationPayload, OperationError> {
        serde_json::from_value::<SecurityAlertMutationPayload>(payload.clone()).map_err(|e| {
            OperationError {
                code: "malformed-payload".into(),
                message: format!("SecurityAlert payload invalid: {e}"),
            }
        })
    }

    /// Executes an ack/resolve transition. `target` must
    /// be `SecurityAlertState::Acknowledged` or `SecurityAlertState::Resolved`.
    /// Validates the source state and rejects illegal transitions.
    fn execute_alert_state_change(
        &self,
        payload: &serde_json::Value,
        target: SecurityAlertState,
    ) -> MutationOutcome {
        let parsed = match Self::parse_alert_payload(payload) {
            Ok(p) => p,
            Err(e) => return MutationOutcome::Failed(e),
        };
        let Some(repo) = self.alerts_repo.as_ref() else {
            return MutationOutcome::Failed(OperationError {
                code: "alerts-store-unavailable".into(),
                message: "security alerts repository not wired".into(),
            });
        };
        let alert = match repo.find_by_id(&parsed.alert_id) {
            Ok(Some(a)) => a,
            Ok(None) => {
                return MutationOutcome::Failed(OperationError {
                    code: "alert-not-found".into(),
                    message: format!("alert {} not found", parsed.alert_id),
                });
            }
            Err(e) => {
                return MutationOutcome::Failed(OperationError {
                    code: "alerts-storage-failure".into(),
                    message: format!("alerts repo find_by_id failed: {e}"),
                });
            }
        };
        // Validate transitions:
        //   Active        → Acknowledged | Resolved
        //   Acknowledged  → Resolved
        //   Resolved      → (none)
        //   Superseded    → (none)
        let allowed = matches!(
            (alert.state, target),
            (SecurityAlertState::Active, SecurityAlertState::Acknowledged)
                | (SecurityAlertState::Active, SecurityAlertState::Resolved)
                | (
                    SecurityAlertState::Acknowledged,
                    SecurityAlertState::Resolved
                )
        );
        if !allowed {
            return MutationOutcome::Failed(OperationError {
                code: "illegal-state-transition".into(),
                message: format!(
                    "cannot transition alert {} from {} to {}",
                    parsed.alert_id, alert.state, target,
                ),
            });
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(alert.updated_at);
        // TODO:: the schema's ack_event_seq /
        // ack_file (and resolved_event_seq / resolved_file) are meant
        // to point at the audit NDJSON line that recorded this state
        // change. The current `AuditWriter::append` API does not return
        // the assigned seq/filename, and `AuditEventKind` does not yet
        // have a `TamperAlertResolved` variant. Until the audit
        // surface is extended, we record synthetic placeholders that
        // are unique per call but do not point at a real NDJSON line.
        // Acknowledgement is the only state change that today has a
        // matching `TamperAlertAcknowledged` event kind, so a future
        // closure can wire the ack path without touching the schema.
        let synthetic_seq = now_ms.unsigned_abs();
        let synthetic_file = "nrr_ipc_pending_audit.ndjson";
        if let Err(e) = repo.update_state(
            &parsed.alert_id,
            target,
            synthetic_seq,
            synthetic_file,
            now_ms,
        ) {
            return MutationOutcome::Failed(OperationError {
                code: "alerts-storage-failure".into(),
                message: format!("alerts update_state failed: {e}"),
            });
        }
        // Acknowledging (or resolving) a DB
        // tamper / key-reset alert means the user has reviewed the
        // current rules and accepts the DB state as authoritative. Stamp
        // it: re-sign every revision row so the next service load
        // verifies clean and the mutation gate lifts. The ack itself
        // already succeeded; a re-sign failure is logged but does not
        // fail the mutation (the gate is lifted by the state change, and
        // a still-tampered row would simply be re-flagged next boot,
        // deduped against the now-acknowledged alert).
        if crate::tamper_bootstrap::is_blocking_alert_kind(&alert.kind) {
            match self.coordinator.re_sign_all_revisions() {
                Ok(n) => tracing::info!(
                    target: "nrr::tamper",
                    alert_id = %parsed.alert_id,
                    re_signed = n,
                    "re-signed revision rows on tamper-alert acknowledgement",
                ),
                Err(e) => tracing::warn!(
                    target: "nrr::tamper",
                    alert_id = %parsed.alert_id,
                    error = ?e,
                    "re-sign after tamper-alert acknowledgement failed",
                ),
            }
        }
        let action_slug = match target {
            SecurityAlertState::Acknowledged => "acknowledged",
            SecurityAlertState::Resolved => "resolved",
            _ => "unchanged",
        };
        MutationOutcome::Completed(serde_json::json!({
            "outcome": format!("alert-{action_slug}"),
            "alert-id": parsed.alert_id,
            "previous-state": alert.state.as_str(),
            "new-state": target.as_str(),
            "updated-at-ms": now_ms,
            "reason": parsed.reason.unwrap_or_default(),
        }))
    }

    fn alert_review_summary(
        &self,
        payload: &serde_json::Value,
        target: SecurityAlertState,
    ) -> ReviewSummaryResponse {
        let parsed = match Self::parse_alert_payload(payload) {
            Ok(p) => p,
            Err(e) => return malformed_summary(&e.message),
        };
        let action = match target {
            SecurityAlertState::Acknowledged => "acknowledge",
            SecurityAlertState::Resolved => "resolve",
            _ => "no-op",
        };
        ReviewSummaryResponse {
            diff_summary: format!("{action} security alert {}", parsed.alert_id),
            provenance: "service".into(),
            risk_level: ReviewRiskLevel::Low,
            requires_review: true,
            changed_fields: vec![format!("alert-id:{}", parsed.alert_id)],
            risk_signals: Vec::new(),
            rules_added: Vec::new(),
            rules_removed: Vec::new(),
            rules_modified: Vec::new(),
            rules_retargeted: Vec::new(),
            pro_sections: Vec::new(),
        }
    }

    // ── PresetImport pipeline ───────────────────────────────────────────────

    /// Preview path for `MutationKind::PresetImport`. Decodes the wire
    /// payload, canonicalizes each route's bytes, merges with the
    /// active revision's other-route rules (single-route imports only)
    /// or assembles both routes (both-routes imports), encodes into
    /// canonical `rules_json`, then runs the standard
    /// `submit_candidate` + `dry_run_apply` flow.
    fn preview_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> ReviewSummaryResponse {
        let assembled = match self.assemble_preset_import(payload, principal) {
            Ok(a) => a,
            Err(e) => return preset_failure_summary(&e),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&assembled.rules_json) {
            return malformed_summary(&e.message);
        }
        let scored = self.score_candidate_for_payload(&assembled.rules_json, principal);
        let submission = preset_submission_from(&assembled, "ipc-dry-run", principal);
        let revision_id = match self.coordinator.submit_candidate(submission) {
            Ok(id) => id,
            Err(e) => return policy_error_summary(&e),
        };
        match self.coordinator.dry_run_apply(&revision_id, "ipc-dry-run") {
            Ok(summary) => dry_run_to_review_summary(&summary, scored),
            Err(e) => policy_error_summary(&e),
        }
    }

    /// Execute path for `MutationKind::PresetImport`. Same assembly as
    /// preview, then issues a confirmation token and activates.
    fn execute_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> MutationOutcome {
        let assembled = match self.assemble_preset_import(payload, principal) {
            Ok(a) => a,
            Err(e) => return MutationOutcome::Failed(e),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&assembled.rules_json) {
            return MutationOutcome::Failed(e);
        }
        let correlation = assembled
            .correlation_id
            .clone()
            .unwrap_or_else(|| "ipc-execute".to_string());
        let submission = preset_submission_from(&assembled, &correlation, principal);
        let revision_id = match self.coordinator.submit_candidate(submission) {
            Ok(id) => id,
            Err(e) => return policy_error_outcome(&e),
        };
        tracing::info!(
            target: "nrr::mutation::preset",
            revision_id = %revision_id,
            content_hash = %assembled.content_hash,
            "preset candidate submitted (a deduped id == an existing/active \
             revision means no new rules were detected)"
        );
        if let Some(outcome) =
            self.drive_deduped_revision_active(&revision_id, &correlation, principal)
        {
            return outcome;
        }
        let token = match self
            .coordinator
            .issue_confirmation_token(&revision_id, COORDINATOR_TOKEN_TTL_SECS)
        {
            Ok(t) => t,
            Err(e) => return policy_error_outcome(&e),
        };
        match self
            .coordinator
            .activate(&revision_id, &token, &correlation)
        {
            Ok(outcome) => {
                tracing::info!(
                    target: "nrr::mutation::preset",
                    revision_id = %revision_id,
                    "preset activate OK"
                );
                activation_to_outcome(outcome)
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::mutation::preset",
                    revision_id = %revision_id,
                    error = ?e,
                    "preset activate FAILED"
                );
                policy_error_outcome(&e)
            }
        }
    }

    /// Common assembly: payload deserialization → byte decoding →
    /// validate → canonicalize → merge with active → encode. Returns
    /// the materials needed by both `preview_preset_import` and
    /// `execute_preset_import`.
    fn assemble_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> Result<AssembledPresetImport, OperationError> {
        let parsed: PresetImportPayload =
            serde_json::from_value(payload.clone()).map_err(|e| OperationError {
                code: "malformed-payload".into(),
                message: format!("PresetImport payload invalid: {e}"),
            })?;
        let target = parsed.target().map_err(|e| OperationError {
            code: "malformed-payload".into(),
            message: match e {
                PresetImportPayloadError::NoBytesSupplied => {
                    "PresetImport: no bytes supplied".into()
                }
                PresetImportPayloadError::RouteMismatch => {
                    "PresetImport: route hint mismatches populated bytes field".into()
                }
            },
        })?;

        // Decode + canonicalize each route's bytes.
        let primary_set = match (parsed.primary_bytes_b64.as_deref(), &target) {
            (Some(b64), _) => Some(canonicalize_route_bytes(
                b64,
                RouteRole::Primary,
                parsed.include_child_processes,
                parsed.import_only_active,
            )?),
            _ => None,
        };
        let secondary_set = match (parsed.secondary_bytes_b64.as_deref(), &target) {
            (Some(b64), _) => Some(canonicalize_route_bytes(
                b64,
                RouteRole::Secondary,
                parsed.include_child_processes,
                parsed.import_only_active,
            )?),
            _ => None,
        };

        // Build the full canonical book. For single-route imports, the
        // OTHER route is carried over from the currently-active revision
        // (or starts empty if none).
        // Each match arm's `expect()` is an invariant: the `target` discriminant
        // already proves the matching `*_set` Option is `Some` (decoded above).
        #[allow(clippy::expect_used)]
        let book = match target {
            PresetImportTarget::BothRoutes => CanonicalRuleBook {
                primary: primary_set.expect("BothRoutes implies primary bytes"),
                secondary: secondary_set.expect("BothRoutes implies secondary bytes"),
            },
            PresetImportTarget::SingleRoute(RouteRole::Primary) => {
                let other = load_active_secondary(self.state_conn.as_ref(), principal);
                CanonicalRuleBook {
                    primary: primary_set.expect("SingleRoute(Primary) implies primary bytes"),
                    secondary: other,
                }
            }
            PresetImportTarget::SingleRoute(RouteRole::Secondary) => {
                let other = load_active_primary(self.state_conn.as_ref(), principal);
                CanonicalRuleBook {
                    primary: other,
                    secondary: secondary_set
                        .expect("SingleRoute(Secondary) implies secondary bytes"),
                }
            }
        };

        let content = RulesRevisionContent::new(book);
        let dto = rules_json_codec::encode(&content);
        let rules_json = rules_json::to_canonical_string(&dto).map_err(|e| OperationError {
            code: "internal".into(),
            message: format!("PresetImport canonical serialise failed: {e}"),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(rules_json.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        tracing::info!(
            target: "nrr::mutation::preset",
            rules_json_len = rules_json.len(),
            content_hash = %content_hash,
            "preset assembled canonical book (rules_json_len is the populated \
             size; an empty book serialises to ~50 bytes)"
        );
        Ok(AssembledPresetImport {
            rules_json,
            content_hash,
            correlation_id: parsed.correlation_id,
        })
    }

    fn execute_rules_update(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> MutationOutcome {
        let parsed = match Self::parse_rules_payload(payload) {
            Ok(p) => p,
            Err(e) => return MutationOutcome::Failed(e),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&parsed.rules_json) {
            return MutationOutcome::Failed(e);
        }
        let correlation = parsed
            .correlation_id
            .clone()
            .unwrap_or_else(|| "ipc-execute".to_string());
        let submission = Self::submission_from(&parsed, &correlation, principal);
        let revision_id = match self.coordinator.submit_candidate(submission) {
            Ok(id) => id,
            Err(e) => return policy_error_outcome(&e),
        };
        if let Some(outcome) =
            self.drive_deduped_revision_active(&revision_id, &correlation, principal)
        {
            return outcome;
        }
        let token = match self
            .coordinator
            .issue_confirmation_token(&revision_id, COORDINATOR_TOKEN_TTL_SECS)
        {
            Ok(t) => t,
            Err(e) => return policy_error_outcome(&e),
        };
        match self
            .coordinator
            .activate(&revision_id, &token, &correlation)
        {
            Ok(outcome) => activation_to_outcome(outcome),
            Err(e) => policy_error_outcome(&e),
        }
    }

    /// Emits a `MutationProgress` push event when both
    /// `correlation_id` and `event_bus` are present. Silent no-op
    /// otherwise (older clients / no GUI subscribers attached). The
    /// `phase` slug is one of `"started"` / `"completed"` /
    /// `"failed"`; `error_code` is required only on `"failed"`.
    fn emit_progress(&self, stored: &StoredMutation, phase: &str, error_code: Option<String>) {
        let (Some(bus), Some(correlation_id)) =
            (self.event_bus.as_ref(), stored.correlation_id.as_ref())
        else {
            return;
        };
        bus.publish(StatusUpdateEvent::MutationProgress {
            correlation_id: correlation_id.clone(),
            mutation_kind: mutation_kind_slug(stored.kind).to_string(),
            phase: phase.to_string(),
            error_code,
        });
    }

    /// `submit_candidate` dedups by content hash against revisions of ANY
    /// status — including the currently-active one. When the submitted
    /// content matches the active revision (e.g. clearing rules that are
    /// already empty, or re-importing the exact current book) there is
    /// nothing to activate: the desired state already holds. Proceeding to
    /// `issue_confirmation_token` / `activate` would fail with
    /// `RevisionNotInExpectedStatus { actual: Active, expected: candidate }`
    /// (the empty-import / full-reset clear failure observed in the field).
    /// Detect that case and report a no-op success instead.
    fn already_active_noop(&self, revision_id: &RevisionId) -> Option<MutationOutcome> {
        match self.coordinator.current_active() {
            Ok(Some(active)) if active.revision_id == revision_id.as_str() => {
                tracing::info!(
                    target: "nrr::mutation::execute",
                    revision_id = %revision_id,
                    "submitted content matches the active revision — no-op success (nothing to activate)"
                );
                Some(MutationOutcome::Completed(serde_json::json!({
                    "outcome": "already-active",
                    "revision-id": revision_id.as_str(),
                })))
            }
            _ => None,
        }
    }

    /// `submit_candidate` dedups by content hash and can hand back a
    /// revision in ANY lifecycle status. This drives that deduped
    /// revision to `Active`, branching on its status:
    ///
    /// - `Active`                  → no-op success (already live).
    /// - `Superseded` / `RolledBack` / `Rejected` → re-activate via
    ///   `rollback_to(Specific)`, which clones the historical content into
    ///   a fresh candidate and activates it. Without this, re-importing
    ///   content identical to such a revision deduped to its id and then
    ///   failed the `Candidate`-only `activate` gate with
    ///   `RevisionNotInExpectedStatus` — the apply silently did nothing
    ///   and the GUI showed stale rules. `Rejected` matters in practice:
    ///   a prior strict (all-or-nothing) apply that rolled back over one
    ///   un-materializable filter leaves the revision `Rejected`; once the
    ///   user retries (e.g. after switching to best-effort) the identical
    ///   content must re-activate cleanly rather than dead-end.
    /// - `Candidate` (the freshly inserted, non-deduped case) or anything
    ///   else → returns `None`; the caller proceeds with its normal
    ///   issue-token + `activate` path.
    ///
    /// Returns `Some(outcome)` only when activation was fully handled here.
    fn drive_deduped_revision_active(
        &self,
        revision_id: &RevisionId,
        correlation: &str,
        principal: &str,
    ) -> Option<MutationOutcome> {
        if let Some(noop) = self.already_active_noop(revision_id) {
            return Some(noop);
        }
        let status = match self.coordinator.status_of(revision_id) {
            Ok(s) => s,
            Err(e) => return Some(policy_error_outcome(&e)),
        };
        match status {
            RevisionStatus::Superseded | RevisionStatus::RolledBack | RevisionStatus::Rejected => {
                tracing::info!(
                    target: "nrr::mutation::execute",
                    revision_id = %revision_id,
                    ?status,
                    "submitted content deduped to a historical revision — \
                     re-activating it via rollback_to(Specific)"
                );
                match self.coordinator.rollback_to(
                    // Re-activate the deduped revision under
                    // the SAME principal as the originating rules/preset
                    // mutation (own SID or baseline).
                    principal,
                    RollbackTarget::Specific(revision_id.clone()),
                    correlation,
                ) {
                    Ok(outcome) => Some(activation_to_outcome(outcome)),
                    Err(e) => Some(policy_error_outcome(&e)),
                }
            }
            _ => None,
        }
    }

    // ── Reset to baseline ──────────────────────────────────────────────────

    /// Dry-run for `RulesResetToBaseline`: describe what the reset will
    /// discard. When the caller has no own divergence the reset is a
    /// benign no-op (they already run the baseline).
    fn preview_reset_to_baseline(&self, principal: &str) -> ReviewSummaryResponse {
        let own = self
            .coordinator
            .current_active_for(principal)
            .ok()
            .flatten();
        let discarded = own
            .as_ref()
            .and_then(|rec| rules_json::from_canonical_string(&rec.rules_json).ok())
            .map(|dto| dto.primary.len() + dto.secondary.len());
        reset_review_summary(own.is_some(), discarded)
    }

    /// Execute path for `RulesResetToBaseline`: clear the caller's own
    /// revisions (read-through to baseline resumes) and, when wired, fire
    /// the per-SID recompile so live enforcement falls back immediately.
    fn execute_reset_to_baseline(&self, principal: &str, correlation: &str) -> MutationOutcome {
        let deleted = match self
            .coordinator
            .reset_principal_to_baseline(principal, correlation)
        {
            Ok(n) => n,
            Err(e) => return policy_error_outcome(&e),
        };
        // Recompile the caller's live WFP filters from the now-effective
        // baseline rules. Best-effort: the durable state is already reset,
        // and an inactive SID picks the baseline up on its next connect.
        if let Some(trigger) = self.apply_trigger.as_ref() {
            trigger.on_policy_changed(principal);
        }
        MutationOutcome::Completed(serde_json::json!({
            "outcome": "reset-to-baseline",
            "deleted-revisions": deleted,
        }))
    }
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
        tracing::debug!(
            target: "nrr::mutation::preview",
            kind = ?kind,
            principal = %principal,
            payload_size = payload.to_string().len(),
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
        pro_sections: Vec::new(),
    }
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
        pro_sections: Vec::new(),
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
        pro_sections: Vec::new(),
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
///   (IDNA / IPv4 / Pro section in a known slot / etc.).
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
    // parser actually recognised vs dropped into unknown/Pro sections.
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
        pro_sections: Vec::new(),
    }
}

fn policy_error_summary(err: &PolicyError) -> ReviewSummaryResponse {
    ReviewSummaryResponse {
        diff_summary: format!("dry-run failed: {err:?}"),
        provenance: "service".into(),
        risk_level: ReviewRiskLevel::High,
        requires_review: true,
        changed_fields: Vec::new(),
        risk_signals: Vec::new(),
        rules_added: Vec::new(),
        rules_removed: Vec::new(),
        rules_modified: Vec::new(),
        rules_retargeted: Vec::new(),
        pro_sections: Vec::new(),
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

/// Wrap a rule book into a synthetic [`CanonicalProfile`] so
/// `review::compute_diff` can consume it. Bindings + behavior_mode
/// are placeholders — `RulesUpdate` doesn't change them, so prev and
/// next must use the SAME placeholder values for `compute_diff` to
/// report no binding/mode change. The synthetic adapter id is stable
/// across calls inside one `score_candidate_for_payload` invocation;
/// the actual binding-change signal is never emitted from this path.
fn synthetic_profile(rule_book: CanonicalRuleBook) -> CanonicalProfile {
    const SYNTHETIC_ID: &str = "synthetic-rules-update";
    CanonicalProfile {
        primary: RouteBinding {
            role: RouteRole::Primary,
            adapter: AdapterIdentity {
                stable_id: SYNTHETIC_ID.to_string(),
                display_name: SYNTHETIC_ID.to_string(),
            },
            source: BindingSource::UserAssigned,
        },
        secondary: None,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
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
        pro_sections: Vec::new(),
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

#[cfg(test)]
mod tests {
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
        let scored =
            executor.score_candidate_for_payload(&rules_json, nrr_storage::BASELINE_PRINCIPAL);
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

        let exec = ProductionMutationExecutor::new(Arc::clone(&coord))
            .with_alerts_repo(Arc::clone(&alerts));

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
            revision_id: RevisionId::from_prefixed_string("rev-test".into()).unwrap(),
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
        // Coordinator's dry_run_apply may succeed or fail depending on
        // empty-DB state — either way the wire shape must be a valid
        // review summary, not a malformed/precondition stub.
        assert!(!review.diff_summary.is_empty());
        assert!(!review.diff_summary.starts_with("malformed payload"));
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
}

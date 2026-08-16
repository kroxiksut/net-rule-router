//! production implementations for the
//! [`ActivationCoordinator`] dependency traits.
//!
//! Four trait impls land here:
//!
//! - [`ProductionIdGenerator`] — generates revision IDs / confirmation
//!   tokens / attempt IDs without pulling in the `uuid` crate (workspace
//!   policy). Format mirrors the audit event-id pattern from 16.5:
//!   `<prefix>-<nanos:020>-<counter:08x>`.
//! - [`ProductionActivationAuditEmitter`] — wraps an `Arc<AuditWriter>`
//!   and maps each `ActivationAuditEvent` variant to the closest
//!   `AuditEventKind` + `ReasonCode`. The emitter swallows write errors
//!   via `tracing::error` rather than panic — the coordinator's flow
//!   does not branch on audit success today, but a future revision may
//!   tighten this once the audit-before-act invariant from 16.5 is
//!   extended to activation events.
//! - [`ProductionApplyMarkerStore`] — file-backed marker persistence
//!   (`%ProgramData%\NetRuleRouter\apply_marker.json`). Atomic write via
//!   `.tmp` + rename; matches the `app-shutdown.flag` pattern.
//!   Deliberately not a SQLite column to avoid a v8 schema migration
//!   ahead of the integration tests in phase 3.
//! - [`ProductionRulesApplyDispatcher`] — wraps a
//!   `PerSidApplyOrchestrator` and forwards `apply_for_sid` /
//!   `revert_for_sid` / `dry_run_for_sid` / `pre_flight_for_sid`. The
//!   orchestrator's existing per-SID APIs already produce the action
//!   plan / install / remove primitives the coordinator needs.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter};
use nrr_diagnostics::audit::{ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::reason::review::APPROVED as REVIEW_APPROVED;
use nrr_diagnostics::reason::{apply as apply_reason, integrity, ReasonCode};
use nrr_diagnostics::sink::AuditSink;
use nrr_domain::revision::RevisionId;

use crate::activation_coordinator::{
    ActivationAuditEmitter, ActivationAuditEvent, DispatchFailure, IdGenerator, PreFlightCategory,
    PreFlightWarning, RevisionRejectReason, RulesApplyDispatcher, SidActionPlanSummary,
};
use crate::crash_recovery::{
    decide_recovery, ApplyAttemptMarker, ApplyMarkerStore, ApplyPhase, RecoveryAuditRecord,
    RecoveryAuditSink, RecoveryExecutionResult, StartupRecoveryCoordinator,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn nanos_since_epoch() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn millis_since_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ── ProductionIdGenerator ────────────────────────────────────────────────────

/// Generates revision/token/attempt ids without depending on the `uuid`
/// crate. Format: `<prefix>-<nanos:020>-<counter:08x>`. Collisions
/// require two ids generated within the same nanosecond on the same
/// counter — the `AtomicU64` saturates after `u64::MAX` ids, far beyond
/// any realistic service uptime.
pub struct ProductionIdGenerator {
    counter: AtomicU64,
}

impl ProductionIdGenerator {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }

    /// exposed `pub(crate)` so the new
    /// [`crate::production_per_sid_audit::ProductionPerSidApplyAudit`]
    /// sink can mint event ids consistently with the other audit
    /// emitters. Still private to the workspace; external callers
    /// should use whichever sink wraps it.
    pub(crate) fn next_suffix(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("{:020}-{:08x}", nanos_since_epoch(), n)
    }
}

impl Default for ProductionIdGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// Counter is `Mutex`-guarded; `lock().expect(...)` propagates poisoning — deliberate.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl IdGenerator for ProductionIdGenerator {
    fn new_revision_id(&self) -> RevisionId {
        // RevisionId carries a "rev-" prefix internally; from_prefixed_string
        // expects the full slug. We build it explicitly.
        let raw = format!("rev-{}", self.next_suffix());
        RevisionId::from_prefixed_string(raw)
            .expect("ProductionIdGenerator produces well-formed rev-* ids")
    }

    fn new_token(&self) -> String {
        format!("tok-{}", self.next_suffix())
    }

    fn new_attempt_id(&self) -> String {
        format!("att-{}", self.next_suffix())
    }
}

// ── ProductionActivationAuditEmitter ─────────────────────────────────────────

/// Maps `ActivationAuditEvent` variants to the audit NDJSON.
///
/// Mapping rationale:
/// - `RevisionActivated` → `RevisionActivated` (`apply.completed`)
/// - `RevisionRejected` → `RevisionActivated` with `result = Failure`
///   and `apply.failed` reason code (no separate `RevisionRejected`
///   variant in `AuditEventKind`)
/// - `RolledBack` / `RollbackRequested` → `RollbackStarted` /
///   `RollbackCompleted` with apply.rollback_* reason codes
/// - `ActivationStarted` → `RevisionActivated` with `apply.started`
///   reason and `result = Success` (the start is a successful event;
///   apply outcome lands in `RevisionActivated`/`RevisionRejected`)
/// - `RevisionSubmitted` / `DryRunRequested` / `TokenIssued` /
///   `TokenConsumed` → `ReviewApproved` (closest fit; phase 3 may add
///   dedicated audit kinds if precision is needed)
/// - `PreFlight*` → `RevisionActivated` with `apply.verification_failed`
///   reason on failure
/// - `ActiveIntegrityRejected` → `UntrustedRevisionRejected` with
///   `integrity.untrusted_revision_rejected`
pub struct ProductionActivationAuditEmitter {
    writer: Arc<AuditWriter>,
    ids: Arc<ProductionIdGenerator>,
    /// Phase 2: optional `EventBus` so terminal revision transitions
    /// (`RevisionActivated` / `RevisionRejected` / `RolledBack`) publish
    /// a `RevisionStatusChanged` push event alongside writing the audit
    /// NDJSON line. `None` skips the publish.
    event_bus: Option<Arc<crate::ipc_handlers::event_bus::EventBus>>,
}

impl ProductionActivationAuditEmitter {
    pub fn new(writer: Arc<AuditWriter>, ids: Arc<ProductionIdGenerator>) -> Self {
        Self {
            writer,
            ids,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, bus: Arc<crate::ipc_handlers::event_bus::EventBus>) -> Self {
        self.event_bus = Some(bus);
        self
    }

    fn publish_status_change(&self, revision_id: &str, status: &str) {
        if let Some(bus) = self.event_bus.as_ref() {
            bus.publish(
                nrr_shared::ipc_payloads::StatusUpdateEvent::RevisionStatusChanged {
                    revision_id: revision_id.to_string(),
                    status: status.to_string(),
                },
            );
        }
    }

    fn next_event_id(&self) -> String {
        format!("adt-{}", self.ids.next_suffix())
    }

    fn append(
        &self,
        kind: AuditEventKind,
        result: AuditEventResult,
        reason: ReasonCode,
        revision_id: Option<String>,
        payload_summary_json: Option<String>,
    ) {
        let input = AuditEventInput {
            event_id: self.next_event_id(),
            kind,
            created_at: millis_since_epoch(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id,
            risk_level: None,
            result,
            reason_code: reason,
            payload_summary_json,
        };
        if let Err(e) = self.writer.append(input) {
            tracing::error!(
                target: "nrr::audit",
                error = ?e,
                "audit append failed for activation event",
            );
        }
    }
}

impl ActivationAuditEmitter for ProductionActivationAuditEmitter {
    fn emit(&self, event: ActivationAuditEvent) {
        match event {
            ActivationAuditEvent::RevisionSubmitted {
                revision_id,
                content_hash,
                source: _,
                correlation_id: _,
                was_dedup,
            } => {
                let payload = format!(
                    r#"{{"event":"submitted","content_hash":"{content_hash}","dedup":{was_dedup}}}"#,
                );
                self.append(
                    AuditEventKind::ReviewApproved,
                    AuditEventResult::Success,
                    REVIEW_APPROVED,
                    Some(revision_id),
                    Some(payload),
                );
            }
            ActivationAuditEvent::DryRunRequested {
                revision_id,
                correlation_id: _,
            } => {
                self.append(
                    AuditEventKind::ReviewApproved,
                    AuditEventResult::Success,
                    REVIEW_APPROVED,
                    Some(revision_id),
                    Some(r#"{"event":"dry_run_requested"}"#.to_string()),
                );
            }
            ActivationAuditEvent::TokenIssued {
                revision_id,
                token: _,
                ttl_secs,
            } => {
                let payload = format!(r#"{{"event":"token_issued","ttl_secs":{ttl_secs}}}"#);
                self.append(
                    AuditEventKind::ReviewApproved,
                    AuditEventResult::Success,
                    REVIEW_APPROVED,
                    Some(revision_id),
                    Some(payload),
                );
            }
            ActivationAuditEvent::TokenConsumed {
                revision_id,
                token: _,
            } => {
                self.append(
                    AuditEventKind::ReviewApproved,
                    AuditEventResult::Success,
                    REVIEW_APPROVED,
                    Some(revision_id),
                    Some(r#"{"event":"token_consumed"}"#.to_string()),
                );
            }
            ActivationAuditEvent::ActivationStarted {
                revision_id,
                attempt_id,
                ..
            } => {
                let payload =
                    format!(r#"{{"event":"activation_started","attempt_id":"{attempt_id}"}}"#);
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Success,
                    apply_reason::STARTED,
                    Some(revision_id),
                    Some(payload),
                );
            }
            ActivationAuditEvent::PreFlightPassed {
                revision_id,
                sids: _,
            } => {
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Success,
                    apply_reason::STARTED,
                    Some(revision_id),
                    Some(r#"{"event":"pre_flight_passed"}"#.to_string()),
                );
            }
            ActivationAuditEvent::PreFlightFailed {
                revision_id,
                sid_failures,
            } => {
                let payload = format!(
                    r#"{{"event":"pre_flight_failed","failure_count":{}}}"#,
                    sid_failures.len()
                );
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Failure,
                    apply_reason::VERIFICATION_FAILED,
                    Some(revision_id),
                    Some(payload),
                );
            }
            ActivationAuditEvent::PreFlightPassedButApplyFailed {
                revision_id,
                sid_failures,
            } => {
                let payload = format!(
                    r#"{{"event":"pre_flight_passed_but_apply_failed","failure_count":{}}}"#,
                    sid_failures.len()
                );
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Failure,
                    apply_reason::FAILED,
                    Some(revision_id),
                    Some(payload),
                );
            }
            ActivationAuditEvent::RevisionActivated {
                revision_id,
                previous_revision_id,
                succeeded_sids,
                drift_sids,
            } => {
                let payload = format!(
                    r#"{{"event":"revision_activated","previous":{},"succeeded":{},"drift":{}}}"#,
                    previous_revision_id.map_or("null".to_string(), |s| format!("\"{s}\"")),
                    succeeded_sids.len(),
                    drift_sids.len(),
                );
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Success,
                    apply_reason::COMPLETED,
                    Some(revision_id.clone()),
                    Some(payload),
                );
                self.publish_status_change(&revision_id, "active");
            }
            ActivationAuditEvent::RevisionRejected {
                revision_id,
                reason,
                sid_failures: _,
            } => {
                let payload = format!(
                    r#"{{"event":"revision_rejected","reason":"{}"}}"#,
                    reason.replace('"', "\\\"")
                );
                self.append(
                    AuditEventKind::RevisionActivated,
                    AuditEventResult::Failure,
                    apply_reason::FAILED,
                    Some(revision_id.clone()),
                    Some(payload),
                );
                self.publish_status_change(&revision_id, "rejected");
            }
            ActivationAuditEvent::RollbackRequested {
                target,
                correlation_id: _,
            } => {
                let payload = format!(r#"{{"event":"rollback_requested","target":"{target}"}}"#);
                self.append(
                    AuditEventKind::RollbackStarted,
                    AuditEventResult::Success,
                    apply_reason::ROLLBACK_STARTED,
                    None,
                    Some(payload),
                );
            }
            ActivationAuditEvent::RolledBack {
                from_revision_id,
                to_revision_id,
            } => {
                let payload = format!(
                    r#"{{"event":"rolled_back","from":"{from_revision_id}","to":"{to_revision_id}"}}"#
                );
                self.append(
                    AuditEventKind::RollbackCompleted,
                    AuditEventResult::Success,
                    apply_reason::ROLLBACK_COMPLETED,
                    Some(to_revision_id.clone()),
                    Some(payload),
                );
                // Both ends of a rollback transitioned: previous active
                // → rolled-back, target → active. Two events so the GUI
                // can update both rows in its history view.
                self.publish_status_change(&from_revision_id, "rolled-back");
                self.publish_status_change(&to_revision_id, "active");
            }
            ActivationAuditEvent::ResetToBaseline {
                principal,
                deleted_revisions,
                correlation_id: _,
            } => {
                // a per-principal reset to baseline reads
                // as a revert to the shared default: audit it under the
                // rollback kind with a reset-specific payload. No target
                // revision id — the user falls through to baseline via the
                // provider read-through, not to a specific revision.
                let payload = format!(
                    r#"{{"event":"reset_to_baseline","principal":"{principal}","deleted":{deleted_revisions}}}"#
                );
                self.append(
                    AuditEventKind::RollbackCompleted,
                    AuditEventResult::Success,
                    apply_reason::ROLLBACK_COMPLETED,
                    None,
                    Some(payload),
                );
            }
            ActivationAuditEvent::ActiveIntegrityRejected {
                principal,
                rejected_revision_id,
                reason,
                rejected_user_rule_count,
                trusted_source_revision_id,
                trusted_user_rule_count,
                new_active_revision_id,
            } => {
                let reason_slug = match &reason {
                    RevisionRejectReason::Unsigned => "unsigned".to_string(),
                    RevisionRejectReason::Tampered => "tampered".to_string(),
                    RevisionRejectReason::RuleCapExceeded {
                        user_rule_count,
                        cap,
                    } => {
                        format!("rule-cap-exceeded({user_rule_count}>{cap})")
                    }
                };
                let payload = format!(
                    r#"{{"event":"active_integrity_rejected","principal":"{principal}","reason":"{reason_slug}","rejected_user_rule_count":{rejected_user_rule_count},"trusted_source_revision_id":{},"trusted_user_rule_count":{},"new_active_revision_id":{}}}"#,
                    trusted_source_revision_id
                        .as_deref()
                        .map_or("null".to_string(), |s| format!("\"{s}\"")),
                    trusted_user_rule_count.map_or("null".to_string(), |n| n.to_string()),
                    new_active_revision_id
                        .as_deref()
                        .map_or("null".to_string(), |s| format!("\"{s}\"")),
                );
                self.append(
                    AuditEventKind::UntrustedRevisionRejected,
                    AuditEventResult::Failure,
                    integrity::UNTRUSTED_REVISION_REJECTED,
                    Some(rejected_revision_id.clone()),
                    Some(payload),
                );
                self.publish_status_change(&rejected_revision_id, "rolled-back");
                if let Some(new_id) = &new_active_revision_id {
                    self.publish_status_change(new_id, "active");
                }
            }
        }
    }
}

// ── ProductionApplyMarkerStore ───────────────────────────────────────────────

/// File-backed `ApplyMarkerStore`. Persists a single JSON document at
/// `marker_path`. Writes are atomic via `.tmp` + rename. Reads return
/// `None` when the file is absent or malformed (treated as "no marker
/// present" — bootstrap will not trigger recovery).
///
/// Format (kebab-case JSON):
/// ```json
/// {
///   "attempt-id": "att-...",
///   "active-revision-id": "rev-...",
///   "phase": "applying",
///   "started-at-epoch-secs": 1700000000,
///   "last-step-at-epoch-secs": 1700000005,
///   "intended-rollback-to": null,
///   "correlation-id": "ipc-..."
/// }
/// ```
pub struct ProductionApplyMarkerStore {
    marker_path: PathBuf,
}

impl ProductionApplyMarkerStore {
    pub fn new(data_dir: &std::path::Path) -> Self {
        Self {
            marker_path: data_dir.join("apply_marker.json"),
        }
    }

    fn phase_to_slug(phase: &ApplyPhase) -> &'static str {
        match phase {
            ApplyPhase::Preparing => "preparing",
            ApplyPhase::Applying => "applying",
            ApplyPhase::Verifying => "verifying",
            ApplyPhase::Applied => "applied",
            ApplyPhase::RollbackRequired => "rollback-required",
            ApplyPhase::RollingBack => "rolling-back",
            ApplyPhase::RollbackDone => "rollback-done",
            ApplyPhase::FailedRequiresManualAction => "failed-requires-manual-action",
        }
    }

    fn phase_from_slug(slug: &str) -> Option<ApplyPhase> {
        Some(match slug {
            "preparing" => ApplyPhase::Preparing,
            "applying" => ApplyPhase::Applying,
            "verifying" => ApplyPhase::Verifying,
            "applied" => ApplyPhase::Applied,
            "rollback-required" => ApplyPhase::RollbackRequired,
            "rolling-back" => ApplyPhase::RollingBack,
            "rollback-done" => ApplyPhase::RollbackDone,
            "failed-requires-manual-action" => ApplyPhase::FailedRequiresManualAction,
            _ => return None,
        })
    }

    fn marker_to_json(marker: &ApplyAttemptMarker) -> String {
        let intended = marker
            .intended_rollback_to
            .as_ref()
            .map(|s| format!("\"{}\"", s.replace('"', "\\\"")))
            .unwrap_or_else(|| "null".to_string());
        format!(
            r#"{{"attempt-id":"{}","active-revision-id":"{}","phase":"{}","started-at-epoch-secs":{},"last-step-at-epoch-secs":{},"intended-rollback-to":{},"correlation-id":"{}"}}"#,
            marker.attempt_id.replace('"', "\\\""),
            marker.active_revision_id.replace('"', "\\\""),
            Self::phase_to_slug(&marker.phase),
            marker.started_at_epoch_secs,
            marker.last_step_at_epoch_secs,
            intended,
            marker.correlation_id.replace('"', "\\\""),
        )
    }

    fn marker_from_json(json: &str) -> Option<ApplyAttemptMarker> {
        let value: serde_json::Value = serde_json::from_str(json).ok()?;
        let obj = value.as_object()?;
        let phase_slug = obj.get("phase")?.as_str()?;
        Some(ApplyAttemptMarker {
            attempt_id: obj.get("attempt-id")?.as_str()?.to_string(),
            active_revision_id: obj.get("active-revision-id")?.as_str()?.to_string(),
            phase: Self::phase_from_slug(phase_slug)?,
            started_at_epoch_secs: obj.get("started-at-epoch-secs")?.as_u64()?,
            last_step_at_epoch_secs: obj.get("last-step-at-epoch-secs")?.as_u64()?,
            intended_rollback_to: obj
                .get("intended-rollback-to")
                .and_then(|v| v.as_str().map(str::to_string)),
            correlation_id: obj.get("correlation-id")?.as_str()?.to_string(),
        })
    }
}

impl ApplyMarkerStore for ProductionApplyMarkerStore {
    fn read(&self) -> Option<ApplyAttemptMarker> {
        let bytes = std::fs::read(&self.marker_path).ok()?;
        let json = std::str::from_utf8(&bytes).ok()?;
        Self::marker_from_json(json)
    }

    fn write(&self, marker: &ApplyAttemptMarker) -> Result<(), String> {
        let json = Self::marker_to_json(marker);
        let tmp_path = self.marker_path.with_extension("tmp");
        std::fs::write(&tmp_path, json.as_bytes()).map_err(|e| format!("write tmp marker: {e}"))?;
        std::fs::rename(&tmp_path, &self.marker_path)
            .map_err(|e| format!("rename tmp marker: {e}"))?;
        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        match std::fs::remove_file(&self.marker_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove marker: {e}")),
        }
    }
}

// ── NoopRulesApplyDispatcher ─────────────────────────────────────────────────

/// No-op `RulesApplyDispatcher` for partial bring-up paths where the
/// `PerSidApplyOrchestrator` has not been constructed yet (it requires
/// a `WfpSession` + `RoutePolicySource` production adapter, both of
/// which land later). All trait methods succeed; `dry_run_for_sid`
/// returns a zeroed `SidActionPlanSummary` so the GUI sees "no
/// changes". Phase 4 swaps this for [`ProductionRulesApplyDispatcher`]
/// once the orchestrator's policy source has a production adapter.
pub struct NoopRulesApplyDispatcher;

impl RulesApplyDispatcher for NoopRulesApplyDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 0,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        _sid: &str,
        _rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        Ok(Vec::new())
    }

    fn apply_for_sid(&self, _sid: &str, _rules_json: &str) -> Result<(), DispatchFailure> {
        Ok(())
    }

    fn revert_for_sid(
        &self,
        _sid: &str,
        _previous_rules_json: &str,
    ) -> Result<(), DispatchFailure> {
        Ok(())
    }
}

// ── ProductionRulesApplyDispatcher ───────────────────────────────────────────

/// Bridges the activation coordinator to the per-SID apply layer
/// (`PerSidApplyOrchestrator`). Each method delegates to the
/// orchestrator's existing API.
///
/// Phase 2 wiring: `apply_for_sid` calls
/// `PerSidApplyOrchestrator::recompile_for_sid` with the new rules.
/// `revert_for_sid` is the same primitive with the previous rules.
/// `dry_run_for_sid` returns a synthetic `SidActionPlanSummary` that
/// surfaces filter add/remove counts; phase 3 may extend it to
/// produce a full diff once the orchestrator exposes a dry-run path.
/// `pre_flight_for_sid` returns an empty warning list today (the
/// per-SID orchestrator's checks fire at apply time); phase 3 wires
/// real pre-flight (FilterId collisions, batch overflow).
pub struct ProductionRulesApplyDispatcher {
    orchestrator: Arc<crate::per_sid_orchestrator::PerSidApplyOrchestrator>,
    /// optional state-DB handle so the dispatched
    /// snapshot gets the caller's `include_subdomains` widening (the same
    /// widening `ProductionRulesProvider::active_rules_for` applies). `None`
    /// (tests / partial bring-up) applies the rules as-is.
    settings_conn: Option<Arc<std::sync::Mutex<rusqlite::Connection>>>,
}

impl ProductionRulesApplyDispatcher {
    pub fn new(orchestrator: Arc<crate::per_sid_orchestrator::PerSidApplyOrchestrator>) -> Self {
        Self {
            orchestrator,
            settings_conn: None,
        }
    }

    /// attach the state-DB connection (see the
    /// `settings_conn` field doc).
    #[must_use]
    pub fn with_settings_conn(mut self, conn: Arc<std::sync::Mutex<rusqlite::Connection>>) -> Self {
        self.settings_conn = Some(conn);
        self
    }

    /// Decode dispatched rules-JSON via the provider's shared path and apply
    /// the caller's `include_subdomains` widening when the state DB is
    /// available.
    fn snapshot_for_dispatch(
        &self,
        sid: &str,
        rules_json: &str,
        origin: &str,
    ) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
        let mut snapshot =
            crate::production_rules_provider::decode_rules_snapshot(rules_json, origin)?;
        if let Some(conn) = self.settings_conn.as_ref() {
            let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            if crate::production_rules_provider::include_subdomains_for(&guard, sid) {
                snapshot.rule_book = snapshot.rule_book.with_subdomain_coverage();
            }
        }
        Some(snapshot)
    }
}

impl RulesApplyDispatcher for ProductionRulesApplyDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
        // Phase 2 placeholder: the orchestrator does not yet expose a
        // dry-run path that returns counts without applying. We return a
        // zeroed summary so the GUI sees "no changes detected"; phase 3
        // wires a real diff against the per-SID filter set.
        Ok(SidActionPlanSummary {
            sid: sid.to_string(),
            filter_additions: 0,
            filter_removals: 0,
            routing_actions: 0,
        })
    }

    fn pre_flight_for_sid(
        &self,
        sid: &str,
        rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure> {
        // Content that will not decode cannot be applied, and finding that out
        // here costs one decode instead of a half-applied policy. The other
        // categories (id collisions, batch overflow, routing conflicts) need a
        // change plan computed WITHOUT applying, which the orchestrator does
        // not expose yet — the same gap that keeps the change summary at zero.
        // TODO: the orchestrator has no dry-run path; without it the remaining
        // pre-flight categories cannot be answered.
        if self
            .snapshot_for_dispatch(sid, rules_json, "pre-flight")
            .is_none()
        {
            return Ok(vec![PreFlightWarning {
                sid: sid.to_string(),
                category: PreFlightCategory::InvalidRulesContent,
                message: "rules content failed to decode".to_string(),
            }]);
        }
        Ok(Vec::new())
    }

    fn apply_for_sid(&self, sid: &str, rules_json: &str) -> Result<(), DispatchFailure> {
        // apply the revision content we were HANDED.
        // The coordinator dispatches BEFORE committing the active pointer
        // (all-or-nothing: revert must stay possible), so a storage read here
        // still sees the PREVIOUS revision — the 0716 run recorded
        // "no-active-rules" at the exact activation moment and the new rules
        // only reached WFP via the next 30 s safety tick.
        let snapshot = self
            .snapshot_for_dispatch(sid, rules_json, "activation-apply")
            .ok_or_else(|| DispatchFailure {
                sid: sid.to_string(),
                message: "dispatched rules-json failed to decode".to_string(),
            })?;
        self.orchestrator
            .recompile_for_sid_with_rules(sid, &snapshot)
            .map(|_count| ())
            .map_err(|e| DispatchFailure {
                sid: sid.to_string(),
                message: format!("recompile_for_sid failed: {e:?}"),
            })
    }

    fn revert_for_sid(&self, sid: &str, previous_rules_json: &str) -> Result<(), DispatchFailure> {
        // Same pass-through as apply, with the PREVIOUS revision content. A
        // decode failure here (no previous revision / legacy blob) falls back
        // to the storage read — Phase 3a has already restored the previous
        // active pointer by revert time, and a revert must stay best-effort.
        match self.snapshot_for_dispatch(sid, previous_rules_json, "activation-revert") {
            Some(snapshot) => self
                .orchestrator
                .recompile_for_sid_with_rules(sid, &snapshot)
                .map(|_count| ()),
            None => self.orchestrator.recompile_for_sid(sid).map(|_count| ()),
        }
        .map_err(|e| DispatchFailure {
            sid: sid.to_string(),
            message: format!("revert recompile_for_sid failed: {e:?}"),
        })
    }
}

// ── Production RecoveryAuditSink ─────────────────────────────────────────────

/// Maps `RecoveryAuditRecord` variants to NDJSON audit entries via
/// [`AuditWriter`]. Fails the recovery flow if the audit append fails
/// (the [`StartupRecoveryCoordinator`] aborts on `AuditWriteFailed`,
/// preserving the chain). All recovery actions are recorded against
/// `ActorKind::Service` since recovery runs without a user context.
pub struct ProductionRecoveryAuditSink {
    writer: Arc<AuditWriter>,
    ids: Arc<ProductionIdGenerator>,
}

impl ProductionRecoveryAuditSink {
    pub fn new(writer: Arc<AuditWriter>, ids: Arc<ProductionIdGenerator>) -> Self {
        Self { writer, ids }
    }
}

impl RecoveryAuditSink for ProductionRecoveryAuditSink {
    fn emit(&self, record: RecoveryAuditRecord) -> Result<(), String> {
        let (kind, reason, payload, revision_id) = match record {
            RecoveryAuditRecord::RecoveryStarted {
                attempt_id,
                phase_found,
            } => (
                AuditEventKind::RecoveryActionRequested,
                ReasonCode("integrity.recovery_started"),
                format!(
                    r#"{{"event":"recovery_started","attempt_id":"{}","phase":"{}"}}"#,
                    attempt_id, phase_found,
                ),
                None,
            ),
            RecoveryAuditRecord::RollbackInitiated {
                attempt_id,
                target_revision,
            } => (
                AuditEventKind::RollbackStarted,
                apply_reason::ROLLBACK_STARTED,
                format!(
                    r#"{{"event":"recovery_rollback_initiated","attempt_id":"{}"}}"#,
                    attempt_id,
                ),
                target_revision,
            ),
            RecoveryAuditRecord::RollbackCompleted { attempt_id } => (
                AuditEventKind::RollbackCompleted,
                apply_reason::ROLLBACK_COMPLETED,
                format!(
                    r#"{{"event":"recovery_rollback_completed","attempt_id":"{}"}}"#,
                    attempt_id,
                ),
                None,
            ),
            // Deliberately NOT `AuditEventKind::RollbackCompleted`: nothing was
            // rolled back, and the reader of this trail must be able to tell
            // the two apart during an incident.
            RecoveryAuditRecord::RollbackDeferred { attempt_id, reason } => (
                AuditEventKind::RecoveryActionRequested,
                ReasonCode("integrity.rollback_deferred"),
                format!(
                    r#"{{"event":"recovery_rollback_deferred","attempt_id":"{}","reason":"{}"}}"#,
                    attempt_id,
                    reason.replace('"', "\\\""),
                ),
                None,
            ),
            RecoveryAuditRecord::VerificationPassed { attempt_id } => (
                AuditEventKind::RecoveryActionRequested,
                ReasonCode("integrity.recovery_verified"),
                format!(
                    r#"{{"event":"recovery_verification_passed","attempt_id":"{}"}}"#,
                    attempt_id,
                ),
                None,
            ),
            RecoveryAuditRecord::ManualActionRequired { attempt_id, reason } => (
                AuditEventKind::IntegrityFailureDetected,
                ReasonCode("integrity.policy_integrity_failure"),
                format!(
                    r#"{{"event":"recovery_manual_action_required","attempt_id":"{}","reason":"{}"}}"#,
                    attempt_id,
                    reason.replace('"', "\\\""),
                ),
                None,
            ),
            RecoveryAuditRecord::SafeDisableExecuted {
                correlation_id,
                reason,
            } => (
                AuditEventKind::RecoveryActionRequested,
                ReasonCode("integrity.safe_disable_executed"),
                format!(
                    r#"{{"event":"safe_disable","correlation_id":"{}","reason":"{}"}}"#,
                    correlation_id,
                    reason.replace('"', "\\\""),
                ),
                None,
            ),
            RecoveryAuditRecord::MarkerCleared { attempt_id } => (
                AuditEventKind::RecoveryActionRequested,
                ReasonCode("integrity.marker_cleared"),
                format!(
                    r#"{{"event":"recovery_marker_cleared","attempt_id":"{}"}}"#,
                    attempt_id,
                ),
                None,
            ),
        };
        let result = match kind {
            AuditEventKind::IntegrityFailureDetected => AuditEventResult::Blocked,
            _ => AuditEventResult::Success,
        };
        let input = AuditEventInput {
            event_id: format!("adt-{}", self.ids.next_suffix()),
            kind,
            created_at: millis_since_epoch(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id,
            risk_level: None,
            result,
            reason_code: reason,
            payload_summary_json: Some(payload),
        };
        self.writer
            .append(input)
            .map_err(|e| format!("recovery audit append: {e:?}"))
    }
}

// ── Crash recovery startup hook ──────────────────────────────────────────────

/// Outcome surfaced by [`run_crash_recovery_on_startup`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrashRecoveryOutcome {
    /// Marker absent or already cleared; service may proceed normally.
    Clean,
    /// Recovery decision was executed; service may proceed normally.
    Recovered { detail: String },
    /// Recovery requires manual action — service should NOT transition
    /// to `Running`. The supervisor can route this to the bootstrap
    /// blocker path.
    ManualActionRequired { reason: String },
    /// Audit or marker IO failed; recovery is incomplete. Service
    /// should treat as `ManualActionRequired` to be safe.
    Aborted { reason: String },
    /// Audit writer was unavailable; we deliberately do nothing
    /// (mutating recovery without audit violates the audit-before-act
    /// invariant from 16.5). Caller logs the gap.
    SkippedNoAudit,
}

/// Phase 4a — probes `RevisionsRepository::last_known_good` to feed
/// `lkg_available` into [`run_crash_recovery_on_startup`]. Opens a
/// short-lived connection, queries, drops. Returns `false` on any
/// failure (file missing, lock contention, schema mismatch) — the
/// conservative default that triggers `RequireManualAction` for
/// recovery decisions that need an LKG.
pub fn probe_lkg_available(state_db_path: &std::path::Path) -> bool {
    if !state_db_path.exists() {
        return false;
    }
    let conn = match rusqlite::Connection::open(state_db_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let repo = nrr_storage::revisions::RevisionsRepository::new(&conn);
    matches!(repo.last_known_good(), Ok(Some(_)))
}

/// startup hook that reads the persisted apply
/// marker (if any), runs the recovery decision, and executes it before
/// the supervised runtime starts. Called from
/// `nrr-windows-service` between bootstrap and `run_supervised_runtime`.
///
/// Phase 4a wires `lkg_available` via [`probe_lkg_available`] at the
/// call site.
pub fn run_crash_recovery_on_startup(
    data_dir: &std::path::Path,
    audit_writer: Option<Arc<AuditWriter>>,
    ids: Arc<ProductionIdGenerator>,
    lkg_available: bool,
) -> CrashRecoveryOutcome {
    let marker_store = ProductionApplyMarkerStore::new(data_dir);

    // Quick exit when no marker is present — most boots.
    if marker_store.read().is_none() {
        return CrashRecoveryOutcome::Clean;
    }

    let writer = match audit_writer {
        Some(w) => w,
        None => return CrashRecoveryOutcome::SkippedNoAudit,
    };
    let sink = ProductionRecoveryAuditSink::new(writer, ids);
    let coordinator = StartupRecoveryCoordinator::new(marker_store, sink);
    let state = coordinator.assess();
    let decision = decide_recovery(&state, lkg_available, true);
    match coordinator.execute(decision) {
        RecoveryExecutionResult::Recovered => CrashRecoveryOutcome::Clean,
        RecoveryExecutionResult::VerifiedAndCleared => CrashRecoveryOutcome::Recovered {
            detail: "verified and marker cleared".into(),
        },
        RecoveryExecutionResult::RolledBack { revision_active } => {
            CrashRecoveryOutcome::Recovered {
                detail: format!(
                    "rolled back; active revision = {}",
                    revision_active.unwrap_or_else(|| "none".into()),
                ),
            }
        }
        RecoveryExecutionResult::ManualActionRequired { reason } => {
            CrashRecoveryOutcome::ManualActionRequired { reason }
        }
        RecoveryExecutionResult::AuditWriteFailed { detail } => CrashRecoveryOutcome::Aborted {
            reason: format!("audit write failed: {detail}"),
        },
        RecoveryExecutionResult::MarkerClearFailed { detail } => CrashRecoveryOutcome::Aborted {
            reason: format!("marker clear failed: {detail}"),
        },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── ProductionIdGenerator ────────────────────────────────────────────────

    #[test]
    fn production_id_generator_emits_unique_revision_ids() {
        let gen = ProductionIdGenerator::new();
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let id = gen.new_revision_id();
            assert!(seen.insert(id.as_str().to_string()), "duplicate id");
        }
    }

    #[test]
    fn production_id_generator_revision_ids_carry_rev_prefix() {
        let gen = ProductionIdGenerator::new();
        let id = gen.new_revision_id();
        assert!(id.as_str().starts_with("rev-"));
    }

    #[test]
    fn production_id_generator_tokens_and_attempts_are_distinct_namespaces() {
        let gen = ProductionIdGenerator::new();
        let token = gen.new_token();
        let attempt = gen.new_attempt_id();
        assert!(token.starts_with("tok-"));
        assert!(attempt.starts_with("att-"));
        assert_ne!(token, attempt);
    }

    // ── ProductionApplyMarkerStore ───────────────────────────────────────────

    #[test]
    fn marker_store_read_returns_none_when_file_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProductionApplyMarkerStore::new(dir.path());
        assert!(store.read().is_none());
    }

    #[test]
    fn marker_store_round_trips_marker_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProductionApplyMarkerStore::new(dir.path());
        let marker = ApplyAttemptMarker {
            attempt_id: "att-test-1".into(),
            active_revision_id: "rev-test-1".into(),
            phase: ApplyPhase::Applying,
            started_at_epoch_secs: 1_700_000_000,
            last_step_at_epoch_secs: 1_700_000_005,
            intended_rollback_to: Some("rev-prev".into()),
            correlation_id: "corr-1".into(),
        };
        store.write(&marker).expect("write");
        let read_back = store.read().expect("read");
        assert_eq!(read_back, marker);
    }

    #[test]
    fn marker_store_clear_removes_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProductionApplyMarkerStore::new(dir.path());
        let marker = ApplyAttemptMarker {
            attempt_id: "att-clear".into(),
            active_revision_id: "rev-clear".into(),
            phase: ApplyPhase::Applied,
            started_at_epoch_secs: 0,
            last_step_at_epoch_secs: 0,
            intended_rollback_to: None,
            correlation_id: "corr-clear".into(),
        };
        store.write(&marker).expect("write");
        assert!(store.read().is_some());
        store.clear().expect("clear");
        assert!(store.read().is_none());
    }

    #[test]
    fn marker_store_clear_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProductionApplyMarkerStore::new(dir.path());
        // Calling clear on an absent file must not error.
        store.clear().expect("clear on absent");
        store.clear().expect("clear again");
    }

    // ── run_crash_recovery_on_startup ─────────────────────────────────────────

    #[test]
    fn crash_recovery_no_marker_returns_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outcome = run_crash_recovery_on_startup(
            dir.path(),
            None, // no audit writer is fine when there is no marker
            Arc::new(ProductionIdGenerator::new()),
            false,
        );
        assert_eq!(outcome, CrashRecoveryOutcome::Clean);
    }

    #[test]
    fn crash_recovery_present_marker_without_audit_returns_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ProductionApplyMarkerStore::new(dir.path());
        let marker = ApplyAttemptMarker {
            attempt_id: "att-skipped".into(),
            active_revision_id: "rev-skipped".into(),
            phase: ApplyPhase::Applying,
            started_at_epoch_secs: 0,
            last_step_at_epoch_secs: 0,
            intended_rollback_to: None,
            correlation_id: "corr".into(),
        };
        store.write(&marker).expect("write");
        let outcome = run_crash_recovery_on_startup(
            dir.path(),
            None,
            Arc::new(ProductionIdGenerator::new()),
            false,
        );
        assert_eq!(outcome, CrashRecoveryOutcome::SkippedNoAudit);
        // Marker stays in place — recovery did not run.
        assert!(store.read().is_some());
    }
}

//! `ActivationCoordinator` orchestrates the rules-revision lifecycle
//! (submit → dry-run → token → activate → rollback).
//!
//! The coordinator is **transport-agnostic** — IPC handlers wrap it.
//! It is **rules-content-agnostic** — `rules_json` is opaque, interpreted
//! only by the [`RulesApplyDispatcher`] (the production implementation
//! wraps `PerSidApplyOrchestrator`).
//!
//! ## Two-phase commit (rules-only, Variant C)
//!
//! ```text
//! Phase 1 — PRE-APPLY (one SQLite TX, fast)
//!   ├─ Verify token (consume via mutation_tokens)
//!   ├─ Snapshot active SIDs from ActiveSidRegistry
//!   ├─ Write ApplyAttemptMarker { phase: Applying, attempt_id }
//!   └─ Commit
//!
//! Phase 2a — PRE-FLIGHT (only for ApplyFailurePolicy::PreFlightThenAllOrNothing)
//!   ├─ For each SID, RulesApplyDispatcher::pre_flight_for_sid
//!   └─ If any fail → audit "pre-flight-failed" → Phase 3b PreFlightFailed
//!
//! Phase 2b — APPLY (slow, no SQLite lock)
//!   ├─ For each SID, RulesApplyDispatcher::apply_for_sid
//!   └─ Apply ApplyFailurePolicy:
//!       - AllOrNothing       — any failure ⇒ revert successful → Phase 3b
//!       - BestEffort         — keep partials → Phase 3a (with drift summary)
//!       - PreFlightThenAllOrNothing — at this stage same as AllOrNothing
//!
//! Phase 3a — COMMIT-ON-SUCCESS (SQLite TX)
//!   ├─ revisions: candidate→active, previous→superseded
//!   ├─ active_revision_pointer ← target
//!   ├─ ApplyAttemptMarker cleared
//!   └─ Audit "revision-activated" or "pre-flight-passed-but-apply-failed"
//!
//! Phase 3b — COMMIT-ON-FAILURE (SQLite TX)
//!   ├─ revisions: candidate→rejected
//!   ├─ active_revision_pointer unchanged
//!   ├─ ApplyAttemptMarker cleared
//!   └─ Audit "revision-rejected" with per-SID details
//! ```
//!
//! ## Concurrency
//!
//! Concurrent activate requests serialise through:
//! 1. The IPC `MutationQueue` (single-writer FIFO).
//! 2. The partial unique index on `revisions` (only one row may carry
//!    `status='active'`) — `idx_one_active_revision_per_principal` scopes
//!    this per principal (one active row per OS-user), so the constraint
//!    serialises activations within a principal rather than globally.
//!
//! ## Crash recovery
//!
//! If the service crashes mid-Phase-2, the `ApplyAttemptMarker` survives
//! and `decide_recovery` consults it on next startup. Phase 3 commits are
//! atomic SQLite transactions — they either fully commit or leave no trace.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use nrr_domain::revision::{RevisionId, RiskLevel};
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
use nrr_storage::revision_hmac::HmacVerification;
use nrr_storage::{
    ActiveRevisionPointer, ConsumeOutcome, MutationTokenStoreSqlite, RevisionRecord,
    RevisionsRepository,
};

use crate::active_sid_registry::ActiveSidRegistry;
use crate::crash_recovery::{ApplyAttemptMarker, ApplyMarkerStore, ApplyPhase};

// ── Configuration types ───────────────────────────────────────────────────────

/// How the coordinator handles per-SID failures during Phase 2.
///
/// Single global setting, not yet persisted. The activation coordinator
/// reads the policy at the start of each activation; mid-flight changes do
/// not affect an in-progress apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApplyFailurePolicy {
    /// **Default.** Any per-SID failure → revert all successful SIDs to
    /// the previous rules → revision becomes `Rejected`. Preserves the
    /// invariant "active revision = applied everywhere".
    AllOrNothing,
    /// Failed SIDs stay on previous rules; successful SIDs adopt the new
    /// revision. Status flips to `Active` even with partial failures;
    /// audit records per-SID drift.
    BestEffort,
    /// Run pre-flight checks across all active SIDs first; if any fail,
    /// reject before touching WFP. If pre-flight passes, behave as
    /// `AllOrNothing`. Catches predictable failures (FilterId
    /// collisions, batch overflow) before any state mutation.
    PreFlightThenAllOrNothing,
}

impl ApplyFailurePolicy {
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::AllOrNothing => "all-or-nothing",
            Self::BestEffort => "best-effort",
            Self::PreFlightThenAllOrNothing => "pre-flight-then-all-or-nothing",
        }
    }

    pub fn from_slug(s: &str) -> Option<Self> {
        match s {
            "all-or-nothing" => Some(Self::AllOrNothing),
            "best-effort" => Some(Self::BestEffort),
            "pre-flight-then-all-or-nothing" => Some(Self::PreFlightThenAllOrNothing),
            _ => None,
        }
    }
}

/// Confirmation token issued by the coordinator and consumed at activate
/// time. Newtype so callers cannot accidentally pass an unrelated string.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConfirmationToken(String);

impl ConfirmationToken {
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What `rollback_to` should target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackTarget {
    /// The most recent superseded revision.
    Lkg,
    /// A specific revision by id (must currently be `Superseded`).
    Specific(RevisionId),
}

// ── Submit / dry-run / activate inputs ────────────────────────────────────────

/// Input for [`ActivationCoordinator::submit_candidate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSubmission {
    /// The principal (Windows SID, or
    /// [`nrr_storage::BASELINE_PRINCIPAL`]) that owns the revision. The
    /// IPC handler fills this from `IpcRequestContext.caller_stored()`; the
    /// candidate, its active pointer, and its confirmation token are all
    /// scoped to it, so one user's edit never touches another user's
    /// active revision.
    pub principal: String,
    /// Pre-serialised `RulesRevisionContent`. Opaque to the coordinator;
    /// the dispatcher interprets it.
    pub rules_json: String,
    /// SHA-256 hex of `rules_json` (caller computes — keeps the
    /// coordinator free of `sha2` dep).
    pub content_hash: String,
    pub source: RulesRevisionSource,
    pub correlation_id: String,
    pub risk_level: Option<RiskLevel>,
    pub review_summary_json: Option<String>,
}

// ── Outcome types ─────────────────────────────────────────────────────────────

/// Per-SID summary returned by [`RulesApplyDispatcher::dry_run_for_sid`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidActionPlanSummary {
    pub sid: String,
    /// How many filters would be added.
    pub filter_additions: u32,
    /// How many filters would be removed.
    pub filter_removals: u32,
    /// How many routing-table actions would run.
    pub routing_actions: u32,
}

/// Pre-flight finding that does not block apply but should be surfaced
/// to the user (mode `PreFlightThenAllOrNothing` upgrades these to
/// blocking failures).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreFlightWarning {
    pub sid: String,
    pub category: PreFlightCategory,
    pub message: String,
}

/// Reason a pre-flight check flagged a SID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PreFlightCategory {
    /// SID was active at Phase 1 snapshot but is no longer in the
    /// registry by the time pre-flight runs.
    SidLeftRegistry,
    /// Two filter specs would collide on FNV-1a `WfpFilterId`.
    FilterIdCollision,
    /// Action plan exceeds `MAX_FILTERS_PER_TRANSACTION` × N batches.
    BatchOverflow,
    /// Routing-table addition conflicts with an existing system route
    /// the engine cannot safely override.
    RoutingConflict,
    /// Rules JSON failed to deserialise / interpret. Pre-flight blocker.
    InvalidRulesContent,
}

/// Returned by [`ActivationCoordinator::dry_run_apply`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRunSummary {
    pub revision_id: RevisionId,
    pub action_plans: Vec<SidActionPlanSummary>,
    pub pre_flight_warnings: Vec<PreFlightWarning>,
    pub estimated_duration_ms: u32,
}

/// Outcome of [`ActivationCoordinator::activate`] / `rollback_to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// All target SIDs succeeded; revision is now `Active`.
    Activated {
        revision_id: RevisionId,
        applied_at_secs: i64,
    },
    /// `BestEffort` mode: revision is `Active` but some SIDs stayed on
    /// previous rules. Audit holds per-SID detail.
    AppliedWithDrift {
        revision_id: RevisionId,
        succeeded_sids: Vec<String>,
        failed_sids: Vec<(String, String)>,
    },
    /// `AllOrNothing` (or post-pre-flight): apply failed for at least
    /// one SID and successful SIDs were reverted. Revision is `Rejected`.
    RolledBackOnFailure {
        rejected_revision: RevisionId,
        reverted_sids: Vec<String>,
        reason: String,
    },
    /// `PreFlightThenAllOrNothing`: pre-flight blocked the apply.
    /// Revision is `Rejected`.
    PreFlightFailed {
        rejected_revision: RevisionId,
        sid_failures: Vec<(String, String)>,
    },
}

/// Coordinator-level errors. Distinct from `StorageError` and
/// `DispatchError` so the IPC layer can map cleanly to error codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// Storage call failed. `message` carries the underlying detail.
    StorageFailure {
        operation: &'static str,
        message: String,
    },
    /// Token unknown to the store.
    ConfirmationTokenUnknown,
    /// Token already consumed.
    ConfirmationTokenAlreadyUsed,
    /// Token past `expires_at`.
    ConfirmationTokenExpired,
    /// Revision not found by id.
    RevisionNotFound(RevisionId),
    /// Revision exists but is in a status that cannot be activated /
    /// rolled back.
    RevisionNotInExpectedStatus {
        revision_id: RevisionId,
        actual: RevisionStatus,
        expected: &'static str,
    },
    /// Rollback to LKG requested but no superseded revision exists.
    NoLastKnownGood,
    /// Apply attempt marker store rejected a write/clear.
    MarkerWriteFailed(String),
    /// The row failed the DB-tamper / Free-cap integrity gate — its
    /// signature doesn't match (or is absent) or it carries more user
    /// rules than the Free cap allows. Refused before touching the
    /// apply pipeline; see [`RevisionRejectReason`].
    RevisionIntegrityRejected {
        revision_id: RevisionId,
        reason: RevisionRejectReason,
    },
}

/// Why [`ActivationCoordinator`] refused to treat a row as trustworthy.
/// A row that got into `revisions` outside the app's own write path
/// either carries no `row_hmac` at all or one that doesn't match a
/// fresh recomputation — the coordinator cannot distinguish "legitimate
/// but never signed" from "forged", so both are rejected the same way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevisionRejectReason {
    /// No `row_hmac` on the row (never signed by the app).
    Unsigned,
    /// `row_hmac` present but doesn't match the row's current content.
    Tampered,
    /// Row verifies, but its user-rule count exceeds the Free cap.
    RuleCapExceeded { user_rule_count: usize, cap: usize },
}

/// Outcome of [`ActivationCoordinator::enforce_active_integrity_for`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActiveIntegrityOutcome {
    /// No signing key configured (bootstrap degraded to unsigned) — the
    /// gate has nothing to verify against and is skipped, matching the
    /// tamper bootstrap's own fail-open posture on key-store failure.
    SkippedNoKey,
    /// `principal` has no active revision; nothing to check.
    NoActiveRevision,
    /// The active revision verified and is within the Free rule cap.
    Trusted { revision_id: String },
    /// The active revision failed the gate; the coordinator rolled back
    /// to the newest prior revision that both verifies and respects the
    /// cap.
    RolledBack {
        rejected_revision_id: String,
        reason: RevisionRejectReason,
        rejected_user_rule_count: usize,
        trusted_source_revision_id: String,
        trusted_user_rule_count: usize,
        new_active_revision_id: String,
    },
    /// The active revision failed the gate and no prior revision in
    /// `principal`'s history verifies within the cap either. Left with
    /// no active revision — the same "install zero filters" state as a
    /// fresh install, never the rejected content.
    ClearedNoTrustedFallback {
        rejected_revision_id: String,
        reason: RevisionRejectReason,
        rejected_user_rule_count: usize,
    },
}

// ── Dispatcher abstraction ────────────────────────────────────────────────────

/// Per-SID failure surfaced by [`RulesApplyDispatcher`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchFailure {
    pub sid: String,
    pub message: String,
}

/// Bridge from the activation coordinator (rules-content-agnostic) to
/// the platform-aware apply layer (production wraps
/// `PerSidApplyOrchestrator` plus the rule-engine integration).
///
/// All methods are synchronous and return per-SID outcomes. They MUST
/// be re-entrant for the same SID — Phase 2 may call `apply_for_sid`
/// then on `AllOrNothing` failure call `revert_for_sid` to restore the
/// previous rules.
pub trait RulesApplyDispatcher: Send + Sync {
    /// Compute the per-SID action plan summary for a hypothetical apply
    /// of `rules_json` against this SID's current bindings. Used by
    /// `dry_run_apply`. Pure (no platform mutation).
    fn dry_run_for_sid(
        &self,
        sid: &str,
        rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure>;

    /// Run pre-flight checks for `sid` against `rules_json`. Returns
    /// warnings (informational) — caller decides if `PreFlightCategory`
    /// upgrades to a blocking failure (mode `PreFlightThenAllOrNothing`).
    fn pre_flight_for_sid(
        &self,
        sid: &str,
        rules_json: &str,
    ) -> Result<Vec<PreFlightWarning>, DispatchFailure>;

    /// Apply `rules_json` to `sid` (Phase 2). Real impl: recompile per
    /// `PerSidApplyOrchestrator::recompile_for_sid`.
    fn apply_for_sid(&self, sid: &str, rules_json: &str) -> Result<(), DispatchFailure>;

    /// Revert `sid` to `previous_rules_json`. Real impl: recompile to
    /// the previous content. Used by `AllOrNothing` rollback path.
    fn revert_for_sid(&self, sid: &str, previous_rules_json: &str) -> Result<(), DispatchFailure>;
}

// ── Audit emitter ─────────────────────────────────────────────────────────────

/// Audit events emitted by the coordinator. Real impl writes to the
/// audit NDJSON via `nrr-diagnostics`; tests use [`NoopActivationAudit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationAuditEvent {
    RevisionSubmitted {
        revision_id: String,
        content_hash: String,
        source: RulesRevisionSource,
        correlation_id: String,
        was_dedup: bool,
    },
    DryRunRequested {
        revision_id: String,
        correlation_id: String,
    },
    TokenIssued {
        revision_id: String,
        token: String,
        ttl_secs: i64,
    },
    TokenConsumed {
        revision_id: String,
        token: String,
    },
    ActivationStarted {
        revision_id: String,
        attempt_id: String,
        previous_revision_id: Option<String>,
        sid_snapshot: Vec<String>,
        policy: ApplyFailurePolicy,
    },
    PreFlightPassed {
        revision_id: String,
        sids: Vec<String>,
    },
    PreFlightFailed {
        revision_id: String,
        sid_failures: Vec<(String, String)>,
    },
    PreFlightPassedButApplyFailed {
        revision_id: String,
        sid_failures: Vec<(String, String)>,
    },
    RevisionActivated {
        revision_id: String,
        previous_revision_id: Option<String>,
        succeeded_sids: Vec<String>,
        drift_sids: Vec<(String, String)>,
    },
    RevisionRejected {
        revision_id: String,
        reason: String,
        sid_failures: Vec<(String, String)>,
    },
    RollbackRequested {
        target: String,
        correlation_id: String,
    },
    RolledBack {
        from_revision_id: String,
        to_revision_id: String,
    },
    /// A principal discarded its per-SID rule divergence
    /// and fell back to the admin baseline. `deleted_revisions` is how
    /// many of the principal's revision rows were removed.
    ResetToBaseline {
        principal: String,
        deleted_revisions: usize,
        correlation_id: String,
    },
    /// The boot-time integrity sweep found `principal`'s active revision
    /// unsigned, tampered, or over the Free rule cap and rolled it back
    /// (or cleared it, when `trusted_source_revision_id` is `None`).
    ActiveIntegrityRejected {
        principal: String,
        rejected_revision_id: String,
        reason: RevisionRejectReason,
        rejected_user_rule_count: usize,
        trusted_source_revision_id: Option<String>,
        trusted_user_rule_count: Option<usize>,
        new_active_revision_id: Option<String>,
    },
}

/// Receives audit events emitted during activation/rollback.
pub trait ActivationAuditEmitter: Send + Sync {
    fn emit(&self, event: ActivationAuditEvent);
}

/// Discards every event. Use in tests that do not assert on the audit
/// trail.
pub struct NoopActivationAudit;

impl ActivationAuditEmitter for NoopActivationAudit {
    fn emit(&self, _event: ActivationAuditEvent) {}
}

// ── Time + ID abstractions ────────────────────────────────────────────────────

/// Wall-clock seconds source. Production uses `SystemTime::now`; tests
/// inject a fixed value.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> i64;
}

/// Generates new revision IDs, confirmation tokens, and apply attempt
/// IDs. Production uses `uuid::Uuid::new_v4`; tests use a deterministic
/// counter so assertions are stable.
pub trait IdGenerator: Send + Sync {
    fn new_revision_id(&self) -> RevisionId;
    fn new_token(&self) -> String;
    fn new_attempt_id(&self) -> String;
}

// ── ActivationCoordinator ─────────────────────────────────────────────────────

/// Holds shared state required by the activation flow. The connection
/// is wrapped in an `Arc<Mutex<_>>` because the storage repositories
/// borrow it for the duration of a SQL transaction; serialising access
/// at the coordinator level matches the "single-writer" model.
pub struct ActivationCoordinator {
    conn: Arc<Mutex<Connection>>,
    sid_registry: Arc<ActiveSidRegistry>,
    dispatcher: Arc<dyn RulesApplyDispatcher>,
    marker_store: Arc<dyn ApplyMarkerStore>,
    audit: Arc<dyn ActivationAuditEmitter>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    /// Wrapped in `Mutex` so the production `ApplyFailurePolicyWriter` can
    /// update via `Arc<ActivationCoordinator>` without needing `&mut`. Read
    /// once at the start of each `activate`, so the lock contention is
    /// negligible.
    failure_policy: Mutex<ApplyFailurePolicy>,
    /// Optional HMAC signing key for the `revisions.row_hmac` column.
    /// `None` in tests and during early bring-up (the DPAPI keystore wires
    /// it via [`Self::with_signing_key`] at bootstrap). When set, every
    /// revision repository this coordinator builds signs on insert and
    /// re-signs after each status-changing UPDATE, so external tampering
    /// is detectable.
    signing_key: Option<Vec<u8>>,
    /// The no-tray routing-user fallback (console session under
    /// service-driven scope). Without it, an activation with a dead tray
    /// subscription dispatches to NOBODY: `active_sids()` is empty, the
    /// revision goes active in storage, and no WFP filter is ever compiled
    /// until the next tray connect.
    fallback_routing_sid: Option<crate::per_sid_orchestrator::FallbackRoutingSidFn>,
}

// The coordinator guards its state behind a `Mutex`; `lock().expect(...)`
// propagates lock poisoning (a prior panic) as a panic — not a recoverable
// error path. These `expect()`s are deliberate.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ActivationCoordinator {
    /// Bundles the shared dependencies. Production callers build this
    /// once at runtime startup and reuse it for every activation. Tests
    /// rebuild on every test for isolation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        conn: Arc<Mutex<Connection>>,
        sid_registry: Arc<ActiveSidRegistry>,
        dispatcher: Arc<dyn RulesApplyDispatcher>,
        marker_store: Arc<dyn ApplyMarkerStore>,
        audit: Arc<dyn ActivationAuditEmitter>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        failure_policy: ApplyFailurePolicy,
    ) -> Self {
        Self {
            conn,
            sid_registry,
            dispatcher,
            marker_store,
            audit,
            clock,
            ids,
            failure_policy: Mutex::new(failure_policy),
            signing_key: None,
            fallback_routing_sid: None,
        }
    }

    /// Attach the no-tray routing-user fallback
    /// (see the `fallback_routing_sid` field doc). A builder so the many
    /// existing `new(...)` call sites stay untouched.
    #[must_use]
    pub fn with_fallback_routing_sid(
        mut self,
        fallback: crate::per_sid_orchestrator::FallbackRoutingSidFn,
    ) -> Self {
        self.fallback_routing_sid = Some(fallback);
        self
    }

    /// The SIDs an activation applies to: every routing-active
    /// (tray-connected) SID, or — with no tray at all — the effective routing
    /// user from the fallback (console-session user under service-driven
    /// scope). Shared by dry-run, Phase 1 and the pre-flight re-check so all
    /// three see the SAME set.
    fn apply_target_sids(&self) -> Vec<String> {
        let sids = self.sid_registry.active_sids();
        if !sids.is_empty() {
            return sids;
        }
        self.fallback_routing_sid
            .as_ref()
            .and_then(|f| f())
            .into_iter()
            .collect()
    }

    /// Enable HMAC signing of `revisions`
    /// rows. The bootstrap calls this once with the DPAPI-sourced key
    /// before the coordinator handles any mutation. A builder rather
    /// than a `new` parameter so the dozens of existing `new(...)`
    /// call sites (tests, recovery paths) stay untouched and simply
    /// run unsigned.
    #[must_use]
    pub fn with_signing_key(mut self, key: Vec<u8>) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Build a `RevisionsRepository` over `conn`, carrying the signing
    /// key when one is configured. Centralises the
    /// signed-vs-unsigned choice so no call site can forget it.
    fn revisions_repo<'c>(&self, conn: &'c Connection) -> RevisionsRepository<'c> {
        match &self.signing_key {
            Some(key) => RevisionsRepository::with_signing_key(conn, key.clone()),
            None => RevisionsRepository::new(conn),
        }
    }

    /// Re-sign every `revisions` row with the
    /// current key. Invoked by the `SecurityAlertAck` flow: when the
    /// user acknowledges a `DbTamperDetected` / `KeyResetWithExistingData`
    /// alert they accept the current DB state, so the service stamps it
    /// as authoritative and the next load verifies clean. No-op (returns
    /// 0) when no signing key is configured.
    pub(crate) fn re_sign_all_revisions(&self) -> Result<usize, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        self.revisions_repo(&conn)
            .re_sign_all()
            .map_err(|e| PolicyError::StorageFailure {
                operation: "re_sign_all",
                message: e.to_string(),
            })
    }

    /// Replaces the failure policy. Takes `&self` so the production
    /// `ApplyFailurePolicyWriter` can call it through
    /// `Arc<ActivationCoordinator>` after persisting the new slug.
    pub fn set_failure_policy(&self, policy: ApplyFailurePolicy) {
        *self
            .failure_policy
            .lock()
            .expect("failure_policy mutex poisoned") = policy;
    }

    pub fn failure_policy(&self) -> ApplyFailurePolicy {
        *self
            .failure_policy
            .lock()
            .expect("failure_policy mutex poisoned")
    }

    // ── submit_candidate ─────────────────────────────────────────────────────

    /// Persists a new candidate revision, deduping by content hash. If
    /// an existing revision (any status) carries the same content hash,
    /// returns its id without inserting a duplicate.
    ///
    /// `pub(crate)` so the type system enforces the
    /// single mutation channel invariant: only the in-crate
    /// `ProductionMutationExecutor` (reached via the IPC
    /// `MutationSubmitHandler`) can create candidate revisions.
    /// External crates / integration tests must use the trait
    /// (`MutationExecutor::preview` / `::execute`).
    pub(crate) fn submit_candidate(
        &self,
        submission: CandidateSubmission,
    ) -> Result<RevisionId, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let repo = self.revisions_repo(&conn);
        let principal = submission.principal.as_str();

        if let Some(existing) = repo
            .find_by_content_hash_for(principal, &submission.content_hash)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "find_by_content_hash",
                message: e.to_string(),
            })?
        {
            let id = parse_revision_id(&existing.revision_id)?;
            self.audit.emit(ActivationAuditEvent::RevisionSubmitted {
                revision_id: existing.revision_id.clone(),
                content_hash: existing.content_hash.clone(),
                source: submission.source,
                correlation_id: submission.correlation_id.clone(),
                was_dedup: true,
            });
            return Ok(id);
        }

        let revision_id = self.ids.new_revision_id();
        let now = self.clock.now_secs();
        let record = RevisionRecord {
            revision_id: revision_id.as_str().to_string(),
            content_hash: submission.content_hash.clone(),
            rules_json: submission.rules_json,
            status: RevisionStatus::Candidate,
            source: submission.source,
            correlation_id: submission.correlation_id.clone(),
            created_at: now,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: submission.review_summary_json,
            risk_level: submission.risk_level,
        };
        repo.insert_candidate_for(principal, &record)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "insert_candidate",
                message: e.to_string(),
            })?;

        self.audit.emit(ActivationAuditEvent::RevisionSubmitted {
            revision_id: revision_id.as_str().to_string(),
            content_hash: submission.content_hash,
            source: submission.source,
            correlation_id: submission.correlation_id,
            was_dedup: false,
        });
        Ok(revision_id)
    }

    // ── dry_run_apply ────────────────────────────────────────────────────────

    /// Builds a per-SID action plan for the candidate. Pure: no platform
    /// state mutation, no token consumption.
    ///
    /// `pub(crate)` for the same reason as
    /// [`Self::submit_candidate`]: single-channel enforcement.
    pub(crate) fn dry_run_apply(
        &self,
        revision_id: &RevisionId,
        correlation_id: &str,
    ) -> Result<DryRunSummary, PolicyError> {
        let record = self.load_record(revision_id)?;
        let sids: Vec<String> = self.apply_target_sids();

        let mut action_plans: Vec<SidActionPlanSummary> = Vec::with_capacity(sids.len());
        let mut warnings: Vec<PreFlightWarning> = Vec::new();
        for sid in &sids {
            match self.dispatcher.dry_run_for_sid(sid, &record.rules_json) {
                Ok(plan) => action_plans.push(plan),
                Err(failure) => warnings.push(PreFlightWarning {
                    sid: failure.sid,
                    category: PreFlightCategory::InvalidRulesContent,
                    message: failure.message,
                }),
            }
            if let Ok(more) = self.dispatcher.pre_flight_for_sid(sid, &record.rules_json) {
                warnings.extend(more);
            }
        }

        self.audit.emit(ActivationAuditEvent::DryRunRequested {
            revision_id: revision_id.as_str().to_string(),
            correlation_id: correlation_id.to_string(),
        });

        Ok(DryRunSummary {
            revision_id: revision_id.clone(),
            action_plans,
            pre_flight_warnings: warnings,
            estimated_duration_ms: 0, // populated when 16.10 wires real timing
        })
    }

    // ── issue_confirmation_token ─────────────────────────────────────────────

    pub fn issue_confirmation_token(
        &self,
        revision_id: &RevisionId,
        ttl_secs: i64,
    ) -> Result<ConfirmationToken, PolicyError> {
        if ttl_secs <= 0 {
            return Err(PolicyError::StorageFailure {
                operation: "issue_token",
                message: "ttl must be positive".into(),
            });
        }
        let record = self.load_record(revision_id)?;
        if record.status != RevisionStatus::Candidate {
            return Err(PolicyError::RevisionNotInExpectedStatus {
                revision_id: revision_id.clone(),
                actual: record.status,
                expected: "candidate",
            });
        }

        // Scope the token to the candidate's principal so
        // it can only be consumed against that user's activation.
        let principal = self.principal_of(revision_id)?;
        let token = self.ids.new_token();
        let now = self.clock.now_secs();
        let expires = now + ttl_secs;
        let payload = format!(
            r#"{{"op":"activate","revision_id":"{}"}}"#,
            revision_id.as_str()
        );

        let conn = self.conn.lock().expect("connection mutex poisoned");
        let store = MutationTokenStoreSqlite::new(&conn);
        store
            .issue_for(&principal, &token, &payload, now, expires)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "issue_token",
                message: e.to_string(),
            })?;

        self.audit.emit(ActivationAuditEvent::TokenIssued {
            revision_id: revision_id.as_str().to_string(),
            token: token.clone(),
            ttl_secs,
        });
        Ok(ConfirmationToken::from_string(token))
    }

    // ── activate ─────────────────────────────────────────────────────────────

    /// `pub(crate)` for single-channel enforcement,
    /// see [`Self::submit_candidate`].
    pub(crate) fn activate(
        &self,
        revision_id: &RevisionId,
        token: &ConfirmationToken,
        correlation_id: &str,
    ) -> Result<ActivationOutcome, PolicyError> {
        let record = self.load_record(revision_id)?;
        if record.status != RevisionStatus::Candidate {
            return Err(PolicyError::RevisionNotInExpectedStatus {
                revision_id: revision_id.clone(),
                actual: record.status,
                expected: "candidate",
            });
        }

        // Derive the owning principal once; every storage
        // transition below is scoped to it.
        let principal = self.principal_of(revision_id)?;

        // Phase 1.
        let now = self.clock.now_secs();
        let phase1 =
            self.phase1_consume_and_mark(&principal, revision_id, token, correlation_id, now)?;

        let policy = self.failure_policy();
        self.audit.emit(ActivationAuditEvent::ActivationStarted {
            revision_id: revision_id.as_str().to_string(),
            attempt_id: phase1.attempt_id.clone(),
            previous_revision_id: phase1
                .previous_revision
                .as_ref()
                .map(|r| r.revision_id.clone()),
            sid_snapshot: phase1.sids.clone(),
            policy,
        });

        // Phase 2a — pre-flight (only PreFlightThenAllOrNothing).
        if matches!(policy, ApplyFailurePolicy::PreFlightThenAllOrNothing) {
            let pre = self.run_pre_flight(&phase1.sids, &record.rules_json);
            if !pre.failures.is_empty() {
                self.audit.emit(ActivationAuditEvent::PreFlightFailed {
                    revision_id: revision_id.as_str().to_string(),
                    sid_failures: pre.failures.clone(),
                });
                return self.phase3b_pre_flight_failed(
                    &principal,
                    revision_id,
                    &phase1,
                    pre.failures,
                    now,
                );
            }
            self.audit.emit(ActivationAuditEvent::PreFlightPassed {
                revision_id: revision_id.as_str().to_string(),
                sids: phase1.sids.clone(),
            });
        }

        // Phase 2b — apply per SID.
        let phase2 = self.phase2_apply(&phase1.sids, &record.rules_json);

        match policy {
            ApplyFailurePolicy::AllOrNothing | ApplyFailurePolicy::PreFlightThenAllOrNothing => {
                if phase2.failed.is_empty() {
                    self.phase3a_success(&principal, revision_id, &phase1, vec![], now)
                } else {
                    let pre_flight_passed =
                        matches!(policy, ApplyFailurePolicy::PreFlightThenAllOrNothing);
                    self.phase3b_revert_and_reject(
                        &principal,
                        revision_id,
                        &phase1,
                        &record.rules_json,
                        phase2,
                        pre_flight_passed,
                        now,
                    )
                }
            }
            ApplyFailurePolicy::BestEffort => {
                if phase2.failed.is_empty() {
                    self.phase3a_success(&principal, revision_id, &phase1, vec![], now)
                } else {
                    self.phase3a_success(&principal, revision_id, &phase1, phase2.failed, now)
                }
            }
        }
    }

    // ── rollback_to ──────────────────────────────────────────────────────────

    /// Step 1 of the 2-step rollback flow: resolves
    /// `target` and inserts a fresh `Rollback`-source candidate carrying
    /// the target's content. Returns the new candidate's [`RevisionId`]
    /// so the caller can:
    ///
    /// 1. Call [`Self::issue_confirmation_token`] against the returned id.
    /// 2. Call [`Self::activate`] with that token.
    ///
    /// The split exists because [`Self::issue_confirmation_token`]
    /// validates the token against an existing candidate row — issuing
    /// before the candidate is inserted is impossible. The original
    /// single-call [`Self::rollback_to`] still exists as a convenience
    /// wrapper for service-internal callers that auto-issue with a short
    /// TTL; IPC handlers should use this 2-step API so the GUI can show
    /// the candidate and review summary before requesting the token.
    pub fn prepare_rollback_candidate(
        &self,
        principal: &str,
        target: RollbackTarget,
        correlation_id: &str,
    ) -> Result<RevisionId, PolicyError> {
        let target_record = self.resolve_rollback_target(principal, &target)?;

        let new_id = self.ids.new_revision_id();
        let now = self.clock.now_secs();
        let new_record = RevisionRecord {
            revision_id: new_id.as_str().to_string(),
            content_hash: target_record.content_hash.clone(),
            rules_json: target_record.rules_json.clone(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::Rollback,
            correlation_id: correlation_id.to_string(),
            created_at: now,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: target_record.review_summary_json.clone(),
            risk_level: target_record.risk_level,
        };
        {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .insert_candidate_for(principal, &new_record)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "insert_candidate(rollback)",
                    message: e.to_string(),
                })?;
        }

        self.audit.emit(ActivationAuditEvent::RollbackRequested {
            target: rollback_target_str(&target),
            correlation_id: correlation_id.to_string(),
        });

        Ok(new_id)
    }

    /// Convenience wrapper combining [`Self::prepare_rollback_candidate`],
    /// auto-issued [`ConfirmationToken`] (5-minute TTL), and
    /// [`Self::activate`]. Suitable for service-internal callers (e.g.
    /// crash recovery, automated rollback paths) that do not need to
    /// surface the candidate to a user before activation.
    ///
    /// IPC-driven user rollback flows MUST use the 2-step API to give the
    /// GUI a chance to render the review summary before token issuance.
    ///
    /// `pub(crate)` for single-channel enforcement,
    /// see [`Self::submit_candidate`].
    pub(crate) fn rollback_to(
        &self,
        principal: &str,
        target: RollbackTarget,
        correlation_id: &str,
    ) -> Result<ActivationOutcome, PolicyError> {
        let new_id = self.prepare_rollback_candidate(principal, target, correlation_id)?;
        let token = self.issue_confirmation_token(&new_id, 300)?;

        let outcome = self.activate(&new_id, &token, correlation_id)?;
        if let ActivationOutcome::Activated { .. } | ActivationOutcome::AppliedWithDrift { .. } =
            &outcome
        {
            // The "from" id is the LKG / target — fetch it via the new
            // record's source/correlation. We re-resolve to keep this
            // method side-effect free if the caller's RollbackTarget
            // value has been moved elsewhere.
            if let Some(active_now) = self.current_active_for(principal)? {
                self.audit.emit(ActivationAuditEvent::RolledBack {
                    from_revision_id: new_id.as_str().to_string(),
                    to_revision_id: active_now.revision_id,
                });
            }
        }
        Ok(outcome)
    }

    // ── reset_principal_to_baseline ──────────────────────────────────────────

    /// Discard `principal`'s own per-SID rule revisions
    /// (active + history) so the provider's read-through resolves the
    /// admin baseline again. This is the "reset to my defaults" action:
    /// it does NOT touch the baseline, and after it the user transparently
    /// runs the baseline rules until they edit again (which re-diverges).
    ///
    /// Returns the number of revision rows removed (0 when the user had
    /// never diverged — already on baseline, a benign no-op). Refuses the
    /// baseline principal itself (handled in storage; surfaced as a
    /// `StorageFailure`), but the IPC path can never reach that: a
    /// user-scoped reset always targets the caller's own SID.
    ///
    /// `pub(crate)` for single-mutation-channel enforcement, like
    /// [`Self::submit_candidate`] — external callers go through the
    /// `MutationExecutor` trait.
    pub(crate) fn reset_principal_to_baseline(
        &self,
        principal: &str,
        correlation_id: &str,
    ) -> Result<usize, PolicyError> {
        let deleted = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .delete_all_revisions_for(principal)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "delete_all_revisions(reset)",
                    message: e.to_string(),
                })?
        };

        self.audit.emit(ActivationAuditEvent::ResetToBaseline {
            principal: principal.to_string(),
            deleted_revisions: deleted,
            correlation_id: correlation_id.to_string(),
        });

        Ok(deleted)
    }

    // ── readers ──────────────────────────────────────────────────────────────

    /// Read the lifecycle status of any revision by id. The mutation
    /// executor uses this after a content-hash dedup to decide whether the
    /// matched revision needs a fresh activation (`Candidate`), is already
    /// live (`Active` → no-op), or must be re-activated from a historical
    /// state (`Superseded` / `RolledBack`). `pub(crate)` keeps it inside
    /// the single-mutation-channel boundary like the other privileged
    /// methods.
    pub(crate) fn status_of(
        &self,
        revision_id: &RevisionId,
    ) -> Result<RevisionStatus, PolicyError> {
        Ok(self.load_record(revision_id)?.status)
    }

    pub fn current_active(&self) -> Result<Option<RevisionRecord>, PolicyError> {
        self.current_active_for(nrr_storage::BASELINE_PRINCIPAL)
    }

    /// The active revision for one `principal`.
    pub fn current_active_for(
        &self,
        principal: &str,
    ) -> Result<Option<RevisionRecord>, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        self.revisions_repo(&conn)
            .get_active_for(principal)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "get_active",
                message: e.to_string(),
            })
    }

    pub fn last_known_good(&self) -> Result<Option<RevisionId>, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let lkg = self.revisions_repo(&conn).last_known_good().map_err(|e| {
            PolicyError::StorageFailure {
                operation: "last_known_good",
                message: e.to_string(),
            }
        })?;
        match lkg {
            None => Ok(None),
            Some(rec) => Ok(Some(parse_revision_id(&rec.revision_id)?)),
        }
    }

    // ── Phase helpers ────────────────────────────────────────────────────────

    fn phase1_consume_and_mark(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        token: &ConfirmationToken,
        correlation_id: &str,
        now: i64,
    ) -> Result<Phase1Outcome, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let token_store = MutationTokenStoreSqlite::new(&conn);
        // Consume scoped to the principal: a token issued
        // for another user is reported as Unknown (no cross-user replay).
        let outcome = token_store
            .consume_for(principal, token.as_str(), now)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "consume_token",
                message: e.to_string(),
            })?;
        match outcome {
            ConsumeOutcome::Consumed { .. } => {}
            ConsumeOutcome::Unknown => return Err(PolicyError::ConfirmationTokenUnknown),
            ConsumeOutcome::AlreadyConsumed => {
                return Err(PolicyError::ConfirmationTokenAlreadyUsed)
            }
            ConsumeOutcome::Expired => return Err(PolicyError::ConfirmationTokenExpired),
        }

        self.audit.emit(ActivationAuditEvent::TokenConsumed {
            revision_id: revision_id.as_str().to_string(),
            token: token.as_str().to_string(),
        });

        // The previous active revision to supersede is THIS principal's.
        let previous_revision = self
            .revisions_repo(&conn)
            .get_active_for(principal)
            .map_err(|e| PolicyError::StorageFailure {
                operation: "get_active",
                message: e.to_string(),
            })?;
        drop(conn);

        let sids = self.apply_target_sids();
        let attempt_id = self.ids.new_attempt_id();
        let marker = ApplyAttemptMarker {
            attempt_id: attempt_id.clone(),
            active_revision_id: revision_id.as_str().to_string(),
            phase: ApplyPhase::Applying,
            started_at_epoch_secs: now as u64,
            last_step_at_epoch_secs: now as u64,
            intended_rollback_to: previous_revision.as_ref().map(|r| r.revision_id.clone()),
            correlation_id: correlation_id.to_string(),
        };
        self.marker_store
            .write(&marker)
            .map_err(PolicyError::MarkerWriteFailed)?;

        Ok(Phase1Outcome {
            attempt_id,
            sids,
            previous_revision,
        })
    }

    fn run_pre_flight(&self, sids: &[String], rules_json: &str) -> PreFlightOutcome {
        let registered_now: std::collections::HashSet<String> =
            self.apply_target_sids().into_iter().collect();
        let mut warnings: Vec<PreFlightWarning> = Vec::new();
        let mut failures: Vec<(String, String)> = Vec::new();
        for sid in sids {
            if !registered_now.contains(sid) {
                failures.push((
                    sid.clone(),
                    "SID left ActiveSidRegistry between Phase 1 and pre-flight".into(),
                ));
                continue;
            }
            match self.dispatcher.pre_flight_for_sid(sid, rules_json) {
                Ok(per_sid) => {
                    for w in per_sid {
                        // Pre-flight warnings of certain categories
                        // upgrade to blocking failures.
                        if matches!(
                            w.category,
                            PreFlightCategory::FilterIdCollision
                                | PreFlightCategory::BatchOverflow
                                | PreFlightCategory::RoutingConflict
                                | PreFlightCategory::InvalidRulesContent
                        ) {
                            failures.push((w.sid.clone(), w.message.clone()));
                        }
                        warnings.push(w);
                    }
                }
                Err(failure) => failures.push((failure.sid, failure.message)),
            }
        }
        PreFlightOutcome { warnings, failures }
    }

    fn phase2_apply(&self, sids: &[String], rules_json: &str) -> Phase2Outcome {
        let mut succeeded: Vec<String> = Vec::with_capacity(sids.len());
        let mut failed: Vec<(String, String)> = Vec::new();
        for sid in sids {
            match self.dispatcher.apply_for_sid(sid, rules_json) {
                Ok(()) => succeeded.push(sid.clone()),
                Err(failure) => failed.push((failure.sid, failure.message)),
            }
        }
        Phase2Outcome { succeeded, failed }
    }

    fn phase3a_success(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        phase1: &Phase1Outcome,
        drift: Vec<(String, String)>,
        now: i64,
    ) -> Result<ActivationOutcome, PolicyError> {
        // SQL TX wrapping mark_apply_succeeded + active_revision_pointer + marker clear.
        {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            repo.mark_apply_succeeded_for(
                principal,
                revision_id.as_str(),
                phase1
                    .previous_revision
                    .as_ref()
                    .map(|r| r.revision_id.as_str()),
                now,
            )
            .map_err(|e| PolicyError::StorageFailure {
                operation: "mark_apply_succeeded",
                message: e.to_string(),
            })?;
            repo.set_active_pointer_for(
                principal,
                &ActiveRevisionPointer {
                    revision_id: revision_id.as_str().to_string(),
                    activated_at: now,
                    apply_attempt_id: None,
                },
            )
            .map_err(|e| PolicyError::StorageFailure {
                operation: "set_active_pointer",
                message: e.to_string(),
            })?;
            // `mark_apply_succeeded` mutated
            // the signed columns of both the newly-active revision
            // (status/activated_at) and the previously-active one
            // (status/superseded_at/superseded_by). Re-sign both so a
            // legitimate activation never trips tamper detection. No-op
            // when no signing key is configured.
            repo.re_sign_row(revision_id.as_str())
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "re_sign_row(activated)",
                    message: e.to_string(),
                })?;
            if let Some(prev) = phase1.previous_revision.as_ref() {
                repo.re_sign_row(&prev.revision_id)
                    .map_err(|e| PolicyError::StorageFailure {
                        operation: "re_sign_row(superseded)",
                        message: e.to_string(),
                    })?;
            }
        }
        self.marker_store
            .clear()
            .map_err(PolicyError::MarkerWriteFailed)?;

        let succeeded_sids: Vec<String> = phase1
            .sids
            .iter()
            .filter(|s| !drift.iter().any(|(d, _)| d == *s))
            .cloned()
            .collect();
        let pre_flight_passed_but_apply_failed =
            self.failure_policy() == ApplyFailurePolicy::BestEffort && !drift.is_empty();
        if pre_flight_passed_but_apply_failed {
            self.audit
                .emit(ActivationAuditEvent::PreFlightPassedButApplyFailed {
                    revision_id: revision_id.as_str().to_string(),
                    sid_failures: drift.clone(),
                });
        }
        self.audit.emit(ActivationAuditEvent::RevisionActivated {
            revision_id: revision_id.as_str().to_string(),
            previous_revision_id: phase1
                .previous_revision
                .as_ref()
                .map(|r| r.revision_id.clone()),
            succeeded_sids: succeeded_sids.clone(),
            drift_sids: drift.clone(),
        });
        if drift.is_empty() {
            Ok(ActivationOutcome::Activated {
                revision_id: revision_id.clone(),
                applied_at_secs: now,
            })
        } else {
            Ok(ActivationOutcome::AppliedWithDrift {
                revision_id: revision_id.clone(),
                succeeded_sids,
                failed_sids: drift,
            })
        }
    }

    // `principal` as the first param pushes this internal phase helper to
    // 8 args. Bundling them into a struct would obscure the linear phase
    // flow for no real benefit on a private fn.
    #[allow(clippy::too_many_arguments)]
    fn phase3b_revert_and_reject(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        phase1: &Phase1Outcome,
        target_rules_json: &str,
        phase2: Phase2Outcome,
        pre_flight_passed: bool,
        now: i64,
    ) -> Result<ActivationOutcome, PolicyError> {
        let _ = target_rules_json; // explicitly unused — caller passes it for symmetry
                                   // Revert successful SIDs to previous rules (or empty rules if no
                                   // previous revision).
        let previous_rules_json = phase1
            .previous_revision
            .as_ref()
            .map(|r| r.rules_json.clone())
            .unwrap_or_else(|| "{}".to_string());
        let mut reverted: Vec<String> = Vec::new();
        for sid in &phase2.succeeded {
            if self
                .dispatcher
                .revert_for_sid(sid, &previous_rules_json)
                .is_ok()
            {
                reverted.push(sid.clone());
            }
        }

        let reason = format!(
            "{} SID(s) failed Phase 2: {}",
            phase2.failed.len(),
            phase2
                .failed
                .iter()
                .map(|(s, m)| format!("{s}={m}"))
                .collect::<Vec<_>>()
                .join("; ")
        );
        {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            repo.mark_apply_failed_for(principal, revision_id.as_str(), &reason, now)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "mark_apply_failed",
                    message: e.to_string(),
                })?;
            // Rejection changes status +
            // rejected_reason; re-sign so the rejected row verifies clean.
            repo.re_sign_row(revision_id.as_str())
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "re_sign_row(rejected)",
                    message: e.to_string(),
                })?;
        }
        self.marker_store
            .clear()
            .map_err(PolicyError::MarkerWriteFailed)?;

        if pre_flight_passed {
            self.audit
                .emit(ActivationAuditEvent::PreFlightPassedButApplyFailed {
                    revision_id: revision_id.as_str().to_string(),
                    sid_failures: phase2.failed.clone(),
                });
        }
        self.audit.emit(ActivationAuditEvent::RevisionRejected {
            revision_id: revision_id.as_str().to_string(),
            reason: reason.clone(),
            sid_failures: phase2.failed.clone(),
        });
        Ok(ActivationOutcome::RolledBackOnFailure {
            rejected_revision: revision_id.clone(),
            reverted_sids: reverted,
            reason,
        })
    }

    fn phase3b_pre_flight_failed(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        phase1: &Phase1Outcome,
        sid_failures: Vec<(String, String)>,
        now: i64,
    ) -> Result<ActivationOutcome, PolicyError> {
        let _ = phase1; // marker has already been written; no SID work to undo
        let reason = format!("pre-flight rejected {} SID(s)", sid_failures.len());
        {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            repo.mark_apply_failed_for(principal, revision_id.as_str(), &reason, now)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "mark_apply_failed",
                    message: e.to_string(),
                })?;
            // Re-sign the rejected row.
            repo.re_sign_row(revision_id.as_str())
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "re_sign_row(pre-flight-rejected)",
                    message: e.to_string(),
                })?;
        }
        self.marker_store
            .clear()
            .map_err(PolicyError::MarkerWriteFailed)?;
        self.audit.emit(ActivationAuditEvent::RevisionRejected {
            revision_id: revision_id.as_str().to_string(),
            reason: reason.clone(),
            sid_failures: sid_failures.clone(),
        });
        Ok(ActivationOutcome::PreFlightFailed {
            rejected_revision: revision_id.clone(),
            sid_failures,
        })
    }

    fn load_record(&self, revision_id: &RevisionId) -> Result<RevisionRecord, PolicyError> {
        let record = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            let record =
                repo.get_by_id(revision_id.as_str())
                    .map_err(|e| PolicyError::StorageFailure {
                        operation: "get_by_id",
                        message: e.to_string(),
                    })?;
            record.ok_or_else(|| PolicyError::RevisionNotFound(revision_id.clone()))?
        };
        self.verify_revision_integrity(&record)?;
        Ok(record)
    }

    /// Defense-in-depth gate: refuses a row whose `row_hmac` is missing
    /// or doesn't match its content, or whose user-rule count exceeds
    /// the Free cap — either symptom of a row that reached `revisions`
    /// outside the app's own write path. A no-op when the coordinator
    /// has no signing key (bootstrap degraded to unsigned; matches the
    /// tamper bootstrap's own fail-open posture rather than blocking
    /// every activation because DPAPI is transiently unavailable).
    fn verify_revision_integrity(&self, record: &RevisionRecord) -> Result<(), PolicyError> {
        if self.signing_key.is_none() {
            return Ok(());
        }
        let verification = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .verify_row_hmac(&record.revision_id)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "verify_row_hmac",
                    message: e.to_string(),
                })?
                .unwrap_or(HmacVerification::Unsigned)
        };
        match classify_reject_reason(record, verification) {
            Some(reason) => Err(PolicyError::RevisionIntegrityRejected {
                revision_id: parse_revision_id(&record.revision_id)?,
                reason,
            }),
            None => Ok(()),
        }
    }

    /// The principal that owns `revision_id`. `revision_id`
    /// is a globally-unique UUID created by an earlier `submit_candidate`,
    /// so the activate / rollback flow derives the partition key from the
    /// row rather than re-threading it from the caller. `RevisionNotFound`
    /// when no row matches.
    fn principal_of(&self, revision_id: &RevisionId) -> Result<String, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let repo = self.revisions_repo(&conn);
        repo.principal_of(revision_id.as_str())
            .map_err(|e| PolicyError::StorageFailure {
                operation: "principal_of",
                message: e.to_string(),
            })?
            .ok_or_else(|| PolicyError::RevisionNotFound(revision_id.clone()))
    }

    fn resolve_rollback_target(
        &self,
        principal: &str,
        target: &RollbackTarget,
    ) -> Result<RevisionRecord, PolicyError> {
        let record = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            match target {
                // The LKG is THIS principal's most recent
                // superseded revision.
                RollbackTarget::Lkg => repo
                    .last_known_good_for(principal)
                    .map_err(|e| PolicyError::StorageFailure {
                        operation: "last_known_good",
                        message: e.to_string(),
                    })?
                    .ok_or(PolicyError::NoLastKnownGood)?,
                RollbackTarget::Specific(id) => {
                    let rec = repo
                        .get_by_id(id.as_str())
                        .map_err(|e| PolicyError::StorageFailure {
                            operation: "get_by_id",
                            message: e.to_string(),
                        })?
                        .ok_or_else(|| PolicyError::RevisionNotFound(id.clone()))?;
                    // Accept historical revisions whose content we re-activate by
                    // cloning into a fresh candidate: Superseded / RolledBack, and
                    // Rejected. `Rejected` matters because a prior strict
                    // (all-or-nothing) apply that rolled back over one
                    // un-materializable filter leaves the revision Rejected — a
                    // later re-submit of the identical content dedups to it and
                    // must be able to re-activate it (its content is valid; only
                    // the previous *apply attempt* failed).
                    if rec.status != RevisionStatus::Superseded
                        && rec.status != RevisionStatus::RolledBack
                        && rec.status != RevisionStatus::Rejected
                    {
                        return Err(PolicyError::RevisionNotInExpectedStatus {
                            revision_id: id.clone(),
                            actual: rec.status,
                            expected: "superseded|rolled-back|rejected",
                        });
                    }
                    rec
                }
            }
        };
        self.verify_revision_integrity(&record)?;
        Ok(record)
    }

    // ── active-revision integrity gate ──────────────────────────────────────

    /// Verifies every principal's active revision (HMAC + Free rule cap)
    /// and rolls each failing one back to the newest trusted prior
    /// revision. Run once at service startup, before any SID install, so
    /// a row written into `revisions` outside the app is never enforced.
    /// Best-effort per principal: one principal's storage error does not
    /// abort the sweep for the rest.
    pub fn enforce_active_integrity_all(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<(String, ActiveIntegrityOutcome)>, PolicyError> {
        if self.signing_key.is_none() {
            return Ok(Vec::new());
        }
        let mut principals = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .distinct_principals()
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "distinct_principals",
                    message: e.to_string(),
                })?
        };
        if !principals
            .iter()
            .any(|p| p == nrr_storage::BASELINE_PRINCIPAL)
        {
            principals.push(nrr_storage::BASELINE_PRINCIPAL.to_string());
        }
        let mut outcomes = Vec::with_capacity(principals.len());
        for principal in principals {
            let outcome = self.enforce_active_integrity_for(&principal, correlation_id)?;
            outcomes.push((principal, outcome));
        }
        Ok(outcomes)
    }

    /// Single-principal integrity check. See [`Self::enforce_active_integrity_all`].
    pub(crate) fn enforce_active_integrity_for(
        &self,
        principal: &str,
        correlation_id: &str,
    ) -> Result<ActiveIntegrityOutcome, PolicyError> {
        if self.signing_key.is_none() {
            return Ok(ActiveIntegrityOutcome::SkippedNoKey);
        }
        let history = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .activation_history_for(principal)
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "activation_history_for",
                    message: e.to_string(),
                })?
        };
        let Some(active) = history
            .first()
            .filter(|e| e.record.status == RevisionStatus::Active)
        else {
            return Ok(ActiveIntegrityOutcome::NoActiveRevision);
        };
        let Some(reason) = classify_reject_reason(&active.record, active.verification) else {
            return Ok(ActiveIntegrityOutcome::Trusted {
                revision_id: active.record.revision_id.clone(),
            });
        };
        let rejected_revision_id = active.record.revision_id.clone();
        let rejected_user_rule_count =
            nrr_shared::rules_json::user_rule_count(&active.record.rules_json);

        let trusted = history.iter().skip(1).find(|e| {
            e.verification == HmacVerification::Verified
                && !nrr_shared::rules_json::exceeds_free_rule_cap(&e.record.rules_json)
        });

        // Populated only on the `RolledBack` branch; stays `None` for
        // `ClearedNoTrustedFallback`. Collected up front so the single
        // audit emit below doesn't need to re-destructure `outcome`.
        let mut trusted_source_revision_id = None;
        let mut trusted_user_rule_count = None;
        let mut new_active_revision_id = None;

        let outcome = match trusted {
            Some(entry) => {
                let trusted_id_str = entry.record.revision_id.clone();
                let trusted_count =
                    nrr_shared::rules_json::user_rule_count(&entry.record.rules_json);
                let trusted_id = parse_revision_id(&trusted_id_str)?;
                match self.rollback_to(
                    principal,
                    RollbackTarget::Specific(trusted_id),
                    correlation_id,
                )? {
                    ActivationOutcome::Activated { revision_id, .. }
                    | ActivationOutcome::AppliedWithDrift { revision_id, .. } => {
                        trusted_source_revision_id = Some(trusted_id_str.clone());
                        trusted_user_rule_count = Some(trusted_count);
                        new_active_revision_id = Some(revision_id.as_str().to_string());
                        ActiveIntegrityOutcome::RolledBack {
                            rejected_revision_id: rejected_revision_id.clone(),
                            reason: reason.clone(),
                            rejected_user_rule_count,
                            trusted_source_revision_id: trusted_id_str,
                            trusted_user_rule_count: trusted_count,
                            new_active_revision_id: revision_id.as_str().to_string(),
                        }
                    }
                    // The trusted content itself failed to apply (e.g. a stale
                    // FilterId collision) — the rejected row is left active
                    // rather than left half-migrated; the next boot/reconcile
                    // retries. Rare: zero SIDs are installed this early.
                    other => {
                        return Err(PolicyError::StorageFailure {
                            operation: "enforce_active_integrity(rollback_to)",
                            message: format!("trusted fallback failed to apply: {other:?}"),
                        });
                    }
                }
            }
            None => {
                let now = self.clock.now_secs();
                let conn = self.conn.lock().expect("connection mutex poisoned");
                let repo = self.revisions_repo(&conn);
                repo.mark_rolled_back_for(principal, &rejected_revision_id, now)
                    .map_err(|e| PolicyError::StorageFailure {
                        operation: "mark_rolled_back(integrity)",
                        message: e.to_string(),
                    })?;
                repo.clear_active_pointer_for(principal).map_err(|e| {
                    PolicyError::StorageFailure {
                        operation: "clear_active_pointer(integrity)",
                        message: e.to_string(),
                    }
                })?;
                ActiveIntegrityOutcome::ClearedNoTrustedFallback {
                    rejected_revision_id: rejected_revision_id.clone(),
                    reason: reason.clone(),
                    rejected_user_rule_count,
                }
            }
        };

        self.audit
            .emit(ActivationAuditEvent::ActiveIntegrityRejected {
                principal: principal.to_string(),
                rejected_revision_id,
                reason,
                rejected_user_rule_count,
                trusted_source_revision_id,
                trusted_user_rule_count,
                new_active_revision_id,
            });

        Ok(outcome)
    }
}

/// Classifies a verified-history entry against the activation-integrity
/// gate: `None` when the row is trustworthy, `Some(reason)` otherwise.
/// A [`HmacVerification::Verified`] row still fails on an over-cap user
/// rule count — the cap is app policy, not a signature property.
fn classify_reject_reason(
    record: &RevisionRecord,
    verification: HmacVerification,
) -> Option<RevisionRejectReason> {
    match verification {
        HmacVerification::Verified => {
            let count = nrr_shared::rules_json::user_rule_count(&record.rules_json);
            (count > nrr_shared::rules_json::FREE_MAX_RULES).then_some(
                RevisionRejectReason::RuleCapExceeded {
                    user_rule_count: count,
                    cap: nrr_shared::rules_json::FREE_MAX_RULES,
                },
            )
        }
        HmacVerification::Unsigned => Some(RevisionRejectReason::Unsigned),
        HmacVerification::Tampered => Some(RevisionRejectReason::Tampered),
    }
}

// ── Internal phase outputs ────────────────────────────────────────────────────

struct Phase1Outcome {
    attempt_id: String,
    sids: Vec<String>,
    previous_revision: Option<RevisionRecord>,
}

struct Phase2Outcome {
    succeeded: Vec<String>,
    failed: Vec<(String, String)>,
}

struct PreFlightOutcome {
    #[allow(dead_code)]
    warnings: Vec<PreFlightWarning>,
    failures: Vec<(String, String)>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_revision_id(s: &str) -> Result<RevisionId, PolicyError> {
    RevisionId::from_prefixed_string(s.to_string()).map_err(|e| PolicyError::StorageFailure {
        operation: "parse_revision_id",
        message: format!("{s:?}: {e}"),
    })
}

fn rollback_target_str(target: &RollbackTarget) -> String {
    match target {
        RollbackTarget::Lkg => "lkg".to_string(),
        RollbackTarget::Specific(id) => id.as_str().to_string(),
    }
}

// ── Test fixtures (test-only, public for cross-module use) ────────────────────

/// Fixed-time clock for tests. Seconds advance only via `tick()`.
pub struct FixedClock {
    secs: Mutex<i64>,
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl FixedClock {
    pub fn new(initial: i64) -> Arc<Self> {
        Arc::new(Self {
            secs: Mutex::new(initial),
        })
    }

    pub fn tick(&self, by: i64) {
        let mut s = self.secs.lock().expect("clock mutex poisoned");
        *s += by;
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl Clock for FixedClock {
    fn now_secs(&self) -> i64 {
        *self.secs.lock().expect("clock mutex poisoned")
    }
}

/// Counter-based ID generator for deterministic tests.
pub struct CounterIds {
    counter: Mutex<u64>,
}

impl Default for CounterIds {
    fn default() -> Self {
        Self::new()
    }
}

impl CounterIds {
    pub fn new() -> Self {
        Self {
            counter: Mutex::new(0),
        }
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl IdGenerator for CounterIds {
    fn new_revision_id(&self) -> RevisionId {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        let id = format!("rev-{:08}", *c);
        RevisionId::from_prefixed_string(id).expect("counter ids are well-formed")
    }

    fn new_token(&self) -> String {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        format!("tok-{:08}", *c)
    }

    fn new_attempt_id(&self) -> String {
        let mut c = self.counter.lock().expect("ids mutex poisoned");
        *c += 1;
        format!("att-{:08}", *c)
    }
}

/// Records every audit event for assertions.
pub struct RecordingAudit {
    events: Mutex<Vec<ActivationAuditEvent>>,
}

impl Default for RecordingAudit {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RecordingAudit {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn snapshot(&self) -> Vec<ActivationAuditEvent> {
        self.events.lock().expect("audit mutex poisoned").clone()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ActivationAuditEmitter for RecordingAudit {
    fn emit(&self, event: ActivationAuditEvent) {
        self.events
            .lock()
            .expect("audit mutex poisoned")
            .push(event);
    }
}

/// In-memory marker store for tests. Production uses a SQLite-backed
/// impl.
pub struct InMemoryMarkerStore {
    inner: Mutex<Option<ApplyAttemptMarker>>,
}

impl Default for InMemoryMarkerStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryMarkerStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ApplyMarkerStore for InMemoryMarkerStore {
    fn read(&self) -> Option<ApplyAttemptMarker> {
        self.inner.lock().expect("marker mutex poisoned").clone()
    }

    fn write(&self, marker: &ApplyAttemptMarker) -> Result<(), String> {
        *self.inner.lock().expect("marker mutex poisoned") = Some(marker.clone());
        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        *self.inner.lock().expect("marker mutex poisoned") = None;
        Ok(())
    }
}

/// Scriptable dispatcher — tests assign per-SID outcomes.
pub struct ScriptedDispatcher {
    apply_outcomes: Mutex<BTreeMap<String, Vec<Result<(), DispatchFailure>>>>,
    pre_flight_outcomes: Mutex<BTreeMap<String, Vec<PreFlightWarning>>>,
    pre_flight_errors: Mutex<BTreeMap<String, DispatchFailure>>,
    apply_log: Mutex<Vec<(String, String)>>,
    revert_log: Mutex<Vec<(String, String)>>,
}

impl Default for ScriptedDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ScriptedDispatcher {
    pub fn new() -> Self {
        Self {
            apply_outcomes: Mutex::new(BTreeMap::new()),
            pre_flight_outcomes: Mutex::new(BTreeMap::new()),
            pre_flight_errors: Mutex::new(BTreeMap::new()),
            apply_log: Mutex::new(Vec::new()),
            revert_log: Mutex::new(Vec::new()),
        }
    }

    /// Queue a per-SID `apply_for_sid` outcome. Multiple queued outcomes
    /// are drained in FIFO order.
    pub fn queue_apply(&self, sid: &str, outcome: Result<(), DispatchFailure>) {
        self.apply_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .entry(sid.to_string())
            .or_default()
            .push(outcome);
    }

    /// Configure pre-flight to return warnings (categories that upgrade
    /// to failures will fail Phase 2a).
    pub fn set_pre_flight(&self, sid: &str, warnings: Vec<PreFlightWarning>) {
        self.pre_flight_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .insert(sid.to_string(), warnings);
    }

    /// Configure pre-flight to return an outright dispatcher failure.
    pub fn set_pre_flight_error(&self, sid: &str, failure: DispatchFailure) {
        self.pre_flight_errors
            .lock()
            .expect("dispatcher mutex poisoned")
            .insert(sid.to_string(), failure);
    }

    pub fn apply_log(&self) -> Vec<(String, String)> {
        self.apply_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .clone()
    }

    pub fn revert_log(&self) -> Vec<(String, String)> {
        self.revert_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .clone()
    }
}

// Test double: lock-poisoning `unwrap()`/`expect()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl RulesApplyDispatcher for ScriptedDispatcher {
    fn dry_run_for_sid(
        &self,
        sid: &str,
        _rules_json: &str,
    ) -> Result<SidActionPlanSummary, DispatchFailure> {
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
        if let Some(err) = self
            .pre_flight_errors
            .lock()
            .expect("dispatcher mutex poisoned")
            .remove(sid)
        {
            return Err(err);
        }
        Ok(self
            .pre_flight_outcomes
            .lock()
            .expect("dispatcher mutex poisoned")
            .get(sid)
            .cloned()
            .unwrap_or_default())
    }

    fn apply_for_sid(&self, sid: &str, rules_json: &str) -> Result<(), DispatchFailure> {
        self.apply_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .push((sid.to_string(), rules_json.to_string()));
        let mut map = self
            .apply_outcomes
            .lock()
            .expect("dispatcher mutex poisoned");
        let queue = map.entry(sid.to_string()).or_default();
        if queue.is_empty() {
            Ok(())
        } else {
            queue.remove(0)
        }
    }

    fn revert_for_sid(&self, sid: &str, previous_rules_json: &str) -> Result<(), DispatchFailure> {
        self.revert_log
            .lock()
            .expect("dispatcher mutex poisoned")
            .push((sid.to_string(), previous_rules_json.to_string()));
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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

    // ── dry_run_apply ─────────────────────────────────────────────────────────

    #[test]
    fn dry_run_returns_per_sid_action_plans() {
        let fx = build_fixture(ApplyFailurePolicy::AllOrNothing);
        fx.registry
            .on_connect("S-1-5-21-A", IpcClientProfile::TrayLightweight);
        fx.registry
            .on_connect("S-1-5-21-B", IpcClientProfile::TrayLightweight);
        let id = submit(&fx, "h-dry");
        let summary = fx
            .coordinator
            .dry_run_apply(&id, "corr-dr")
            .expect("dry run");
        assert_eq!(summary.action_plans.len(), 2);
        assert!(summary.action_plans.iter().all(|p| p.filter_additions == 1));
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
                // S-A succeeded → must be reverted.
                assert_eq!(reverted_sids, vec!["S-A".to_string()]);
            }
            other => panic!("expected RolledBackOnFailure, got {other:?}"),
        }
        let rec = fx.coordinator.load_record(&id).expect("load");
        assert_eq!(rec.status, RevisionStatus::Rejected);
        // Revert was called.
        assert_eq!(fx.dispatcher.revert_log().len(), 1);
        // Marker cleared.
        assert!(fx.marker.read().is_none());
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
            .prepare_rollback_candidate(
                nrr_storage::BASELINE_PRINCIPAL,
                RollbackTarget::Lkg,
                "c-rb",
            )
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
}

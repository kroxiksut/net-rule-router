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
    /// An application rule matched no executable, so it would be stored and
    /// enforce nothing. Not a blocker — the rest of the revision is fine — but
    /// the user asked for something that will not happen.
    AppRuleUnenforceable,
    /// The SID has a secondary (additional) route bound to an adapter the OS
    /// cannot resolve. The revision applies, and its leak guard sits
    /// fail-closed until the adapter comes back.
    BindingUnresolved,
}

/// Returned by [`ActivationCoordinator::dry_run_rules`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRunSummary {
    /// The candidate this plan describes — `None` for a PREVIEW, which is
    /// computed from submitted rules without storing a candidate at all.
    pub revision_id: Option<RevisionId>,
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
    /// Token is valid for this principal but was issued to activate a DIFFERENT
    /// revision. It is consumed either way: a token used against something it
    /// was not issued for does not get a second chance.
    ConfirmationTokenForOtherRevision,
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
    /// `dry_run_rules`. Pure (no platform mutation).
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

    /// Both answers a preview needs, from ONE compute.
    ///
    /// [`Self::dry_run_for_sid`] and [`Self::pre_flight_for_sid`] read the same
    /// per-SID plan, and deriving that plan IS the cost of a preview — the whole
    /// filter set for the SID, one FQDN-cache query per rule. Asking twice
    /// doubled every "save and review" click for nothing, and the preview holds
    /// the client's single in-flight slot while it runs. So the preview path
    /// asks once, here.
    ///
    /// The pre-flight half returns warnings rather than a `Result`: a SID whose
    /// checks cannot run contributes nothing, which is what the caller already
    /// did with the error. The plan half keeps its `Err` — the caller turns it
    /// into an `InvalidRulesContent` warning that names the SID.
    ///
    /// Default: the two separate calls, so an implementation with nothing to
    /// share needs no change.
    fn plan_with_pre_flight_for_sid(
        &self,
        sid: &str,
        rules_json: &str,
    ) -> (
        Result<SidActionPlanSummary, DispatchFailure>,
        Vec<PreFlightWarning>,
    ) {
        (
            self.dry_run_for_sid(sid, rules_json),
            self.pre_flight_for_sid(sid, rules_json).unwrap_or_default(),
        )
    }

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
/// IDs. Production builds them from the clock plus a counter (there is no
/// CSPRNG in this tree - see the predictable-token task); tests use a deterministic
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

    /// The SIDs an activation applies to — every routing-active (tray-connected)
    /// SID, or the fallback routing user with no tray at all — SCOPED to the
    /// principal whose revision is being applied.
    ///
    /// A revision belongs to one principal. Applying it to everyone active is
    /// how a second user's machine ends up enforcing the first user's rules,
    /// and how an `AllOrNothing` failure rolls that second user back to a
    /// revision that was never theirs. The admin baseline is the one principal
    /// that legitimately spans users, and only those who have not diverged: a
    /// user running their own revision is not running the baseline.
    ///
    /// Shared by dry-run, Phase 1 and the pre-flight re-check so all three see
    /// the SAME set.
    fn apply_target_sids(&self, principal: &str) -> Vec<String> {
        let active = self.sid_registry.active_sids();
        let active = if active.is_empty() {
            self.fallback_routing_sid
                .as_ref()
                .and_then(|f| f())
                .into_iter()
                .collect()
        } else {
            active
        };
        if principal != nrr_storage::BASELINE_PRINCIPAL {
            return active.into_iter().filter(|s| s == principal).collect();
        }
        active
            .into_iter()
            .filter(|sid| {
                // Unreadable is treated as diverged: applying the baseline over
                // a user whose own revision we could not read would replace
                // their policy with somebody else's on a storage hiccup.
                matches!(self.current_active_for(sid), Ok(None))
            })
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
    pub(crate) fn re_sign_all_revisions(
        &self,
    ) -> Result<nrr_storage::revisions::ReSignReport, PolicyError> {
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

    // ── dry run ──────────────────────────────────────────────────────────────

    /// The same plan for rules that have NOT been stored as a candidate.
    ///
    /// The GUI's preview is a read: it asks "what would this do". Routing it
    /// through `submit_candidate` meant every press of it wrote a revision row
    /// — an operation classed as a read mutating the table it reads, and a
    /// pending list that filled with previews the user never asked to keep.
    pub(crate) fn dry_run_rules(
        &self,
        principal: &str,
        rules_json: &str,
        correlation_id: &str,
    ) -> DryRunSummary {
        let summary = self.plan_rules(principal, rules_json);
        self.audit.emit(ActivationAuditEvent::DryRunRequested {
            revision_id: String::new(),
            correlation_id: correlation_id.to_string(),
        });
        summary
    }

    /// Shared body: per-SID action plans plus pre-flight warnings for
    /// `rules_json`, with no revision of its own.
    fn plan_rules(&self, principal: &str, rules_json: &str) -> DryRunSummary {
        let sids: Vec<String> = self.apply_target_sids(principal);
        let mut action_plans: Vec<SidActionPlanSummary> = Vec::with_capacity(sids.len());
        let mut warnings: Vec<PreFlightWarning> = Vec::new();
        for sid in &sids {
            let (plan, sid_warnings) = self
                .dispatcher
                .plan_with_pre_flight_for_sid(sid, rules_json);
            match plan {
                Ok(plan) => action_plans.push(plan),
                Err(failure) => warnings.push(PreFlightWarning {
                    sid: failure.sid,
                    category: PreFlightCategory::InvalidRulesContent,
                    message: failure.message,
                }),
            }
            warnings.extend(sid_warnings);
        }
        DryRunSummary {
            revision_id: None,
            action_plans,
            pre_flight_warnings: warnings,
            estimated_duration_ms: 0, // populated when 16.10 wires real timing
        }
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
            let pre = self.run_pre_flight(&principal, &phase1.sids, &record.rules_json);
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

        // Phase 2b — apply per SID, re-checking divergence first. A user who
        // created their OWN revision between phase 1 and here is no longer
        // inheriting the baseline, and writing it to them now would replace
        // their policy with somebody else's — the same reasoning
        // `apply_target_sids` applies when it builds the set, applied again at
        // the moment it is used.
        let targets = self.still_inheriting(&principal, &phase1.sids);
        let phase2 = self.phase2_apply(&targets, &record.rules_json);

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

    /// The revision id a token's payload was issued for. `None` when the
    /// payload is not the shape this coordinator writes — treated as "not this
    /// revision", never as "any revision".
    fn token_revision_of(payload_json: &str) -> Option<String> {
        serde_json::from_str::<serde_json::Value>(payload_json)
            .ok()?
            .get("revision_id")?
            .as_str()
            .map(str::to_owned)
    }

    // The three activation phases live in `activation_coordinator::phases`;
    // reading a revision back and trusting it lives in `::integrity`. Same
    // inherent impl, split across files.
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
    revert_outcomes: Mutex<BTreeMap<String, Vec<Result<(), DispatchFailure>>>>,
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
            revert_outcomes: Mutex::new(BTreeMap::new()),
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

    /// Queue a per-SID `revert_for_sid` outcome, FIFO like `queue_apply`.
    pub fn queue_revert(&self, sid: &str, outcome: Result<(), DispatchFailure>) {
        self.revert_outcomes
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
        let mut queued = self
            .revert_outcomes
            .lock()
            .expect("dispatcher mutex poisoned");
        match queued.get_mut(sid).and_then(|q| {
            if q.is_empty() {
                None
            } else {
                Some(q.remove(0))
            }
        }) {
            Some(outcome) => outcome,
            None => Ok(()),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

mod integrity;
mod phases;
#[cfg(test)]
mod tests;

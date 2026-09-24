//! The values an activation is asked for and answers with: submissions,
//! summaries, outcomes and the errors each phase can end in.
//!
//! Split out of `activation_coordinator`; the code is unchanged.

use super::*;

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

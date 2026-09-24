//! What the coordinator needs from the outside: a dispatcher that applies,
//! an audit emitter, a clock and an id generator.
//!
//! Split out of `activation_coordinator`; the code is unchanged.

use super::*;

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
/// IDs. Production builds them from the clock plus a counter — no CSPRNG in
/// this tree; tests use a deterministic counter so assertions are stable.
pub trait IdGenerator: Send + Sync {
    fn new_revision_id(&self) -> RevisionId;
    fn new_token(&self) -> String;
    fn new_attempt_id(&self) -> String;
}

//! Driving a revision to active, and the no-ops on the way.
//!
//! Execute a rules update, report progress, recognise a submission that is
//! already active, and reset a principal to the baseline. What these share
//! is that they all end at the coordinator: the executor's job here is to
//! decide WHETHER to activate and to say what happened.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

// Carried over from the impl this was split out of — the same code under the
// same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ProductionMutationExecutor {
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn execute_rules_update(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> MutationOutcome {
        let mut parsed = match Self::parse_rules_payload(payload) {
            Ok(p) => p,
            Err(e) => return MutationOutcome::Failed(e),
        };
        Self::canonicalize_rules_payload(&mut parsed);
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
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn emit_progress(
        &self,
        stored: &StoredMutation,
        phase: &str,
        error_code: Option<String>,
    ) {
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
    fn already_active_noop(
        &self,
        revision_id: &RevisionId,
        principal: &str,
    ) -> Option<MutationOutcome> {
        // The CALLER's active revision, not the baseline's. A revision belongs
        // to one principal, so comparing against the baseline never matches a
        // user's own id: the no-op was missed and the flow went on to fail the
        // `Candidate`-only activate gate with `RevisionNotInExpectedStatus`.
        match self.coordinator.current_active_for(principal) {
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
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn drive_deduped_revision_active(
        &self,
        revision_id: &RevisionId,
        correlation: &str,
        principal: &str,
    ) -> Option<MutationOutcome> {
        if let Some(noop) = self.already_active_noop(revision_id, principal) {
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
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn preview_reset_to_baseline(&self, principal: &str) -> ReviewSummaryResponse {
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
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn execute_reset_to_baseline(
        &self,
        principal: &str,
        correlation: &str,
    ) -> MutationOutcome {
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

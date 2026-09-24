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

mod fixtures;
mod ports;
mod types;

pub use fixtures::*;
pub use ports::*;
pub use types::*;

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
            estimated_duration_ms: 0, // TODO: no apply-timing instrumentation exists yet
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

// ── Tests ─────────────────────────────────────────────────────────────────────

mod integrity;
mod phases;
#[cfg(test)]
mod tests;

//! The three phases of one activation.
//!
//! Phase 1 consumes the confirmation token and marks the attempt; phase 2
//! applies to every target SID; phase 3 either commits (`3a`) or reverts and
//! rejects (`3b`, with a separate entry for a pre-flight that never got to
//! apply). Splitting them out of the coordinator's impl is what makes the
//! sequence readable as a sequence — inline they were four hundred lines
//! between the token helpers and the integrity scan.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

// Carried over from the impl this was split out of — the same code under
// the same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ActivationCoordinator {
    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn phase1_consume_and_mark(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        token: &ConfirmationToken,
        correlation_id: &str,
        now: i64,
    ) -> Result<Phase1Outcome, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let token_store = MutationTokenStoreSqlite::new(&conn);
        // Consume scoped to the principal AND to this revision: a token is
        // issued to activate ONE candidate and its payload says which, so both
        // conditions are stated to the store rather than checked afterwards. A
        // token of the right user for a different candidate now fails without
        // being burned — it still authorises what the user actually confirmed.
        let outcome = token_store
            .consume_for_matching(principal, token.as_str(), now, |payload| {
                Self::token_revision_of(payload).as_deref() == Some(revision_id.as_str())
            })
            .map_err(|e| PolicyError::StorageFailure {
                operation: "consume_token",
                message: e.to_string(),
            })?;
        match outcome {
            ConsumeOutcome::Consumed { .. } => {}
            ConsumeOutcome::PayloadRejected => {
                return Err(PolicyError::ConfirmationTokenForOtherRevision)
            }
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

        let sids = self.apply_target_sids(principal);
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

    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn run_pre_flight(
        &self,
        principal: &str,
        sids: &[String],
        rules_json: &str,
    ) -> PreFlightOutcome {
        let registered_now: std::collections::HashSet<String> =
            self.apply_target_sids(principal).into_iter().collect();
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

    /// The subset of `sids` the baseline may still be written to. Non-baseline
    /// principals own their own revision, so the set is returned unchanged.
    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn still_inheriting(&self, principal: &str, sids: &[String]) -> Vec<String> {
        if principal != nrr_storage::BASELINE_PRINCIPAL {
            return sids.to_vec();
        }
        let kept: Vec<String> = sids
            .iter()
            .filter(|sid| matches!(self.current_active_for(sid), Ok(None)))
            .cloned()
            .collect();
        if kept.len() != sids.len() {
            tracing::info!(
                target: "nrr::activation",
                dropped = (sids.len() - kept.len()) as u64,
                "a user stopped inheriting the baseline between phases — their own revision stands",
            );
        }
        kept
    }

    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn phase2_apply(&self, sids: &[String], rules_json: &str) -> Phase2Outcome {
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

    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn phase3a_success(
        &self,
        principal: &str,
        revision_id: &RevisionId,
        phase1: &Phase1Outcome,
        drift: Vec<(String, String)>,
        now: i64,
    ) -> Result<ActivationOutcome, PolicyError> {
        // Re-signing is a REPAIR of our own edit, never a laundering of somebody
        // else's. `mark_apply_succeeded` rewrites signed columns on both rows,
        // so their stored HMACs go stale by design and have to be recomputed -
        // but recomputing over a row that was ALREADY tampered with mints a
        // valid signature for the tampering, and the row then sails through the
        // integrity gate, the `trusted` selection and last-known-good.
        //
        // The two rows are treated differently on purpose. Activating a
        // TAMPERED revision is refused outright. The row being superseded may
        // well be tampered - that is exactly the case the integrity gate is
        // rolling us out of - so the activation proceeds and its signature is
        // simply left alone, still failing verification for whoever looks next.
        let previous_is_tampered = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            let verdict = repo.verify_row_hmac(revision_id.as_str()).map_err(|e| {
                PolicyError::StorageFailure {
                    operation: "verify_row_hmac",
                    message: e.to_string(),
                }
            })?;
            if matches!(
                verdict,
                Some(nrr_storage::revision_hmac::HmacVerification::Tampered)
            ) {
                return Err(PolicyError::StorageFailure {
                    operation: "verify_row_hmac",
                    message: format!(
                        "revision {} failed integrity check; refusing to activate it",
                        revision_id.as_str()
                    ),
                });
            }
            match phase1.previous_revision.as_ref() {
                Some(prev) => matches!(
                    repo.verify_row_hmac(&prev.revision_id).map_err(|e| {
                        PolicyError::StorageFailure {
                            operation: "verify_row_hmac",
                            message: e.to_string(),
                        }
                    })?,
                    Some(nrr_storage::revision_hmac::HmacVerification::Tampered)
                ),
                None => false,
            }
        };
        // The status change, the pointer and both re-signings are ONE commit.
        // Apart, a crash between them leaves a revision marked active that the
        // pointer does not name, or rows whose signatures no longer match their
        // contents - which the integrity gate reads as tampering and answers by
        // discarding the user's rules. The marker file is cleared after the
        // commit: a marker left behind describes an attempt that did finish,
        // which recovery can see and settle, whereas a half-written database
        // cannot be reasoned about at all.
        {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "begin_activation_tx",
                    message: e.to_string(),
                })?;
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
                if !previous_is_tampered {
                    repo.re_sign_row(&prev.revision_id).map_err(|e| {
                        PolicyError::StorageFailure {
                            operation: "re_sign_row(superseded)",
                            message: e.to_string(),
                        }
                    })?;
                }
            }
            tx.commit().map_err(|e| PolicyError::StorageFailure {
                operation: "commit_activation_tx",
                message: e.to_string(),
            })?;
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
    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn phase3b_revert_and_reject(
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
        let mut revert_failures: Vec<(String, String)> = Vec::new();
        // Every SID Phase 2 TOUCHED, not just the ones it finished. A SID whose
        // apply failed may have installed part of its set before failing (the
        // batch-overflow warning says so in as many words), so leaving it out
        // of the revert left that partial policy live under a revision the
        // service has just rejected.
        let touched = phase2
            .succeeded
            .iter()
            .cloned()
            .chain(phase2.failed.iter().map(|(sid, _)| sid.clone()));
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for sid in touched.filter(|sid| seen.insert(sid.clone())) {
            match self.dispatcher.revert_for_sid(&sid, &previous_rules_json) {
                Ok(()) => reverted.push(sid),
                // A failed revert is the state that matters most and used to be
                // discarded by an `is_ok()`: the SID keeps rules from a
                // rejected revision and nothing anywhere says so.
                Err(failure) => {
                    tracing::error!(
                        target: "nrr::activation",
                        sid = %failure.sid,
                        revision_id = %revision_id,
                        "revert after a failed activation did not succeed; this SID may still                          be enforcing rules from a rejected revision: {}",
                        failure.message,
                    );
                    revert_failures.push((failure.sid, failure.message));
                }
            }
        }

        let mut reason = format!(
            "{} SID(s) failed Phase 2: {}",
            phase2.failed.len(),
            phase2
                .failed
                .iter()
                .map(|(s, m)| format!("{s}={m}"))
                .collect::<Vec<_>>()
                .join("; ")
        );
        if !revert_failures.is_empty() {
            // Recorded on the revision itself: whoever reads why it was
            // rejected also needs to know the machine was not fully put back.
            reason.push_str(&format!(
                "; revert failed for {} SID(s): {}",
                revert_failures.len(),
                revert_failures
                    .iter()
                    .map(|(s, m)| format!("{s}={m}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
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

    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn phase3b_pre_flight_failed(
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
}

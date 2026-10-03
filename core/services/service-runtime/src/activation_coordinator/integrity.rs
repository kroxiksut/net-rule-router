//! Reading a revision back and deciding whether to trust it.
//!
//! Loading a record, verifying its row MAC, resolving a rollback target, and
//! the active-integrity sweep. Nothing here applies anything: it answers "is
//! this row still what we wrote", which is why it reads as its own subject
//! rather than as the tail of the activation path.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

// Carried over from the impl this was split out of — the same code under
// the same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ActivationCoordinator {
    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn load_record(
        &self,
        revision_id: &RevisionId,
    ) -> Result<RevisionRecord, PolicyError> {
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
    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn principal_of(&self, revision_id: &RevisionId) -> Result<String, PolicyError> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let repo = self.revisions_repo(&conn);
        repo.principal_of(revision_id.as_str())
            .map_err(|e| PolicyError::StorageFailure {
                operation: "principal_of",
                message: e.to_string(),
            })?
            .ok_or_else(|| PolicyError::RevisionNotFound(revision_id.clone()))
    }

    // `pub(super)` because the impl is split across files and the parent is
    // now the caller.
    pub(super) fn resolve_rollback_target(
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
                    // Another principal's revision is "not found": a rollback
                    // must not copy someone else's rules into this chain.
                    let rec = repo
                        .get_by_id_for(principal, id.as_str())
                        .map_err(|e| PolicyError::StorageFailure {
                            operation: "get_by_id_for",
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

    /// The startup sweep, gated on what the tamper bootstrap found. After a
    /// key reset no row can verify against a key that never signed it, so
    /// the sweep would clear every principal's rules; the key-reset alert
    /// already reports that state, and acknowledging it re-signs the rows.
    pub fn enforce_active_integrity_at_boot(
        &self,
        bootstrap: &crate::tamper_bootstrap::TamperBootstrapOutcome,
        correlation_id: &str,
    ) -> Result<Vec<(String, ActiveIntegrityOutcome)>, PolicyError> {
        if bootstrap.key_reset_unacknowledged {
            return Ok(Vec::new());
        }
        self.enforce_active_integrity_all(correlation_id)
    }

    /// Verifies every principal's active revision (HMAC + Free rule cap),
    /// rolls each failing one back to the newest trusted prior revision, and
    /// makes each pointer name what the `active` status names. Run once at
    /// service startup, before any SID install, so a row written into
    /// `revisions` outside the app is never enforced. This is the only
    /// recovery: the keyless boot check before it only reports.
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
        // A pointer can outlive every row of its principal when an editor ran
        // without foreign keys; it still has to be cleared.
        let with_pointer = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            self.revisions_repo(&conn)
                .verify_all_pointers()
                .map_err(|e| PolicyError::StorageFailure {
                    operation: "verify_all_pointers",
                    message: e.to_string(),
                })?
        };
        for principal in with_pointer
            .into_iter()
            .map(|(p, _)| p)
            .chain(std::iter::once(nrr_storage::BASELINE_PRINCIPAL.to_string()))
        {
            if !principals.contains(&principal) {
                principals.push(principal);
            }
        }
        // One principal's failure must not leave the rest unchecked.
        let outcomes = principals
            .into_iter()
            .map(|principal| {
                let outcome = self
                    .enforce_active_integrity_for(&principal, correlation_id)
                    .unwrap_or_else(|error| ActiveIntegrityOutcome::CheckFailed { error });
                (principal, outcome)
            })
            .collect();
        Ok(outcomes)
    }

    /// The running service's counterpart of [`Self::enforce_active_integrity_all`],
    /// for after the database was written from outside: one signature check
    /// per active row, and the full check with its rollback only for a
    /// principal whose active row no longer passes.
    pub fn recheck_active_integrity(
        &self,
        correlation_id: &str,
    ) -> Result<Vec<(String, ActiveIntegrityOutcome)>, PolicyError> {
        if self.signing_key.is_none() {
            return Ok(Vec::new());
        }
        let storage = |operation: &'static str| {
            move |e: nrr_storage::StorageError| PolicyError::StorageFailure {
                operation,
                message: e.to_string(),
            }
        };
        let suspect = {
            let conn = self.conn.lock().expect("connection mutex poisoned");
            let repo = self.revisions_repo(&conn);
            let passes = |principal: &str| -> Result<bool, nrr_storage::StorageError> {
                let Some(record) = repo.get_active_for(principal)? else {
                    return Ok(true);
                };
                let verification = repo
                    .verify_row_hmac(&record.revision_id)?
                    .unwrap_or(HmacVerification::Unsigned);
                Ok(classify_reject_reason(&record, verification).is_none())
            };
            // A row that cannot be read goes to the full check, which reports it.
            repo.distinct_principals()
                .map_err(storage("distinct_principals(recheck)"))?
                .into_iter()
                .filter(|principal| !matches!(passes(principal), Ok(true)))
                .collect::<Vec<_>>()
        };
        Ok(suspect
            .into_iter()
            .map(|principal| {
                let outcome = self
                    .enforce_active_integrity_for(&principal, correlation_id)
                    .unwrap_or_else(|error| ActiveIntegrityOutcome::CheckFailed { error });
                (principal, outcome)
            })
            .collect())
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
            return Ok(self
                .realign_pointer(principal, None)?
                .unwrap_or(ActiveIntegrityOutcome::NoActiveRevision));
        };
        let Some(reason) = classify_reject_reason(&active.record, active.verification) else {
            return Ok(self
                .realign_pointer(principal, Some(&active.record))?
                .unwrap_or_else(|| ActiveIntegrityOutcome::Trusted {
                    revision_id: active.record.revision_id.clone(),
                }));
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
                // Same pair, same reason as the activation commit: a rollback
                // that marks the revision and does not clear the pointer leaves
                // the pointer naming a revision that is no longer active.
                let tx = conn
                    .unchecked_transaction()
                    .map_err(|e| PolicyError::StorageFailure {
                        operation: "begin_integrity_tx",
                        message: e.to_string(),
                    })?;
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
                tx.commit().map_err(|e| PolicyError::StorageFailure {
                    operation: "commit_integrity_tx",
                    message: e.to_string(),
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

    /// Point `principal`'s pointer at its `active` row, or clear it when there
    /// is none. Every enforcement read goes by status, so the status is the
    /// truth and the pointer follows it; a pointer left elsewhere is what let
    /// the next activation's supersede undo a recovery. `None` when it already
    /// agreed and its signature holds.
    fn realign_pointer(
        &self,
        principal: &str,
        active: Option<&RevisionRecord>,
    ) -> Result<Option<ActiveIntegrityOutcome>, PolicyError> {
        let storage = |operation: &'static str| {
            move |e: nrr_storage::StorageError| PolicyError::StorageFailure {
                operation,
                message: e.to_string(),
            }
        };
        let conn = self.conn.lock().expect("connection mutex poisoned");
        let repo = self.revisions_repo(&conn);
        let pointer_was = repo
            .get_active_pointer_for(principal)
            .map_err(storage("get_active_pointer(integrity)"))?
            .map(|p| p.revision_id);
        let signature_holds = !repo
            .verify_all_pointers()
            .map_err(storage("verify_all_pointers(integrity)"))?
            .iter()
            .any(|(p, v)| p == principal && *v == HmacVerification::Tampered);
        let active_id = active.map(|r| r.revision_id.clone());
        if pointer_was == active_id && signature_holds {
            return Ok(None);
        }
        match active {
            Some(record) => repo
                .set_active_pointer_for(
                    principal,
                    &ActiveRevisionPointer {
                        revision_id: record.revision_id.clone(),
                        activated_at: record.activated_at.unwrap_or_else(|| self.clock.now_secs()),
                        apply_attempt_id: None,
                    },
                )
                .map_err(storage("set_active_pointer(integrity)"))?,
            None => repo
                .clear_active_pointer_for(principal)
                .map_err(storage("clear_active_pointer(integrity)"))?,
        }
        tracing::warn!(
            target: "nrr::tamper",
            principal = %principal,
            pointer_was = ?pointer_was,
            active = ?active_id,
            "active pointer disagreed with the active revision; realigned",
        );
        Ok(Some(ActiveIntegrityOutcome::PointerRealigned {
            pointer_was,
            revision_id: active_id,
        }))
    }
}

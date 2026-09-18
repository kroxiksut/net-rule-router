//! Candidate insertion and the `Candidate → Active/Rejected/RolledBack`
//! status transitions that drive the apply/rollback lifecycle.

use super::*;

impl<'c> RevisionsRepository<'c> {
    /// Inserts a new candidate revision. Status is forced to `Candidate`
    /// regardless of what the caller put in `record.status` — only the
    /// activation coordinator may move a revision out of `Candidate`.
    ///
    /// When the repository was constructed with
    /// [`Self::with_signing_key`], an HMAC-SHA256 over the canonical
    /// row payload is computed and stored in the `row_hmac` column.
    /// Without a signing key the column stays at its schema
    /// default (empty blob); a later `read_verified` flags such
    /// rows as `Unsigned` and the C2 ack flow can backfill via
    /// [`Self::re_sign_all`].
    pub fn insert_candidate(&self, record: &RevisionRecord) -> StorageResult<()> {
        self.insert_candidate_for(BASELINE_PRINCIPAL, record)
    }

    /// Principal-scoped variant of [`Self::insert_candidate`].
    /// The candidate revision is owned by `principal` (a Windows SID or the
    /// [`BASELINE_PRINCIPAL`] sentinel); `principal` is folded into both the
    /// stored row and its HMAC.
    pub fn insert_candidate_for(
        &self,
        principal: &str,
        record: &RevisionRecord,
    ) -> StorageResult<()> {
        if principal.is_empty() {
            return Err(StorageError::Internal(
                "insert_candidate: empty principal".into(),
            ));
        }
        if record.revision_id.is_empty() {
            return Err(StorageError::Internal(
                "insert_candidate: empty revision_id".into(),
            ));
        }
        if record.content_hash.is_empty() {
            return Err(StorageError::Internal(
                "insert_candidate: empty content_hash".into(),
            ));
        }
        // Effective field set: candidate status, no activation /
        // supersede / rejection timestamps yet. Mirrors the
        // INSERT below so the HMAC is computed over what the row
        // will actually look like in the DB.
        let row_hmac: Vec<u8> = match self.key() {
            Some(key) => {
                let fields = crate::revision_hmac::RowFields {
                    principal,
                    revision_id: &record.revision_id,
                    content_hash: &record.content_hash,
                    rules_json: &record.rules_json,
                    status: "candidate",
                    source: record.source.as_slug(),
                    correlation_id: &record.correlation_id,
                    created_at: record.created_at,
                    activated_at: None,
                    superseded_at: None,
                    superseded_by: None,
                    rejected_reason: None,
                    review_summary_json: record.review_summary_json.as_deref(),
                    risk_level: record.risk_level.map(risk_level_to_slug),
                };
                crate::revision_hmac::compute_hmac(&fields, key).to_vec()
            }
            None => Vec::new(),
        };
        self.conn
            .execute(
                "INSERT INTO revisions
                 (principal, revision_id, content_hash, rules_json, status, source,
                  correlation_id, created_at, activated_at, superseded_at,
                  superseded_by, rejected_reason, review_summary_json, risk_level,
                  row_hmac)
                 VALUES (?1, ?2, ?3, ?4, 'candidate', ?5, ?6, ?7,
                         NULL, NULL, NULL, NULL, ?8, ?9, ?10)",
                params![
                    principal,
                    record.revision_id,
                    record.content_hash,
                    record.rules_json,
                    record.source.as_slug(),
                    record.correlation_id,
                    record.created_at,
                    record.review_summary_json,
                    record.risk_level.map(risk_level_to_slug),
                    row_hmac,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("revisions insert: {e}")))?;
        Ok(())
    }

    /// Phase 3a — Candidate `target_id` becomes Active; the previously
    /// active revision (if any) becomes Superseded with `superseded_by`
    /// pointing at the new target.
    ///
    /// Caller wraps this in a `BEGIN IMMEDIATE` transaction together
    /// with the `set_active_pointer` call so the partial unique index
    /// fires atomically.
    pub fn mark_apply_succeeded(
        &self,
        target_id: &str,
        previous_id: Option<&str>,
        now: i64,
    ) -> StorageResult<()> {
        self.mark_apply_succeeded_for(BASELINE_PRINCIPAL, target_id, previous_id, now)
    }

    /// Principal-scoped Phase 3a. Both the supersede of the
    /// previous active and the activation of the target are constrained to
    /// `principal`, so one user's activation can never supersede another
    /// user's active revision.
    pub fn mark_apply_succeeded_for(
        &self,
        principal: &str,
        target_id: &str,
        previous_id: Option<&str>,
        now: i64,
    ) -> StorageResult<()> {
        if let Some(prev) = previous_id {
            let superseded = self
                .conn
                .execute(
                    "UPDATE revisions
                     SET status = 'superseded',
                         superseded_at = ?1,
                         superseded_by = ?2
                     WHERE revision_id = ?3 AND principal = ?4 AND status = 'active'",
                    params![now, target_id, prev, principal],
                )
                .map_err(|e| {
                    StorageError::Internal(format!("revisions supersede previous: {e}"))
                })?;
            // Zero rows means the caller named a previous revision that was not
            // active. Retiring the old one is half of this phase, and reporting
            // success without doing it left the caller believing history moved.
            // The one benign case is a retry after a crash between the two
            // statements: already superseded BY THIS TARGET, which is the state
            // this call wanted.
            if superseded != 1 && !self.already_superseded_by(principal, prev, target_id)? {
                return Err(StorageError::Internal(format!(
                    "revisions supersede previous: expected 1 row updated, got {superseded} \
                     (revision_id={prev} principal={principal} was not the active revision)"
                )));
            }
        }
        let updated = self
            .conn
            .execute(
                "UPDATE revisions
                 SET status = 'active', activated_at = ?1
                 WHERE revision_id = ?2 AND principal = ?3 AND status = 'candidate'",
                params![now, target_id, principal],
            )
            .map_err(|e| StorageError::Internal(format!("revisions activate target: {e}")))?;
        if updated != 1 {
            return Err(StorageError::Internal(format!(
                "revisions activate target: expected 1 row updated, got {updated} \
                 (revision_id={target_id} principal={principal} may not be in candidate status)"
            )));
        }
        Ok(())
    }

    /// Was `revision_id` already retired in favour of `target_id`? Lets a
    /// retried Phase 3a tell "nothing to do" from "the wrong revision".
    fn already_superseded_by(
        &self,
        principal: &str,
        revision_id: &str,
        target_id: &str,
    ) -> StorageResult<bool> {
        self.conn
            .query_row(
                "SELECT 1 FROM revisions
                 WHERE principal = ?1 AND revision_id = ?2
                   AND status = 'superseded' AND superseded_by = ?3",
                params![principal, revision_id, target_id],
                |_| Ok(true),
            )
            .optional()
            .map(|found| found.unwrap_or(false))
            .map_err(|e| StorageError::Internal(format!("revisions supersede check: {e}")))
    }

    /// Phase 3b — Candidate `target_id` becomes Rejected with the given
    /// reason. Active pointer is left unchanged (rollback already handled
    /// by the apply layer, if needed).
    pub fn mark_apply_failed(&self, target_id: &str, reason: &str, now: i64) -> StorageResult<()> {
        self.mark_apply_failed_for(BASELINE_PRINCIPAL, target_id, reason, now)
    }

    /// Principal-scoped Phase 3b.
    pub fn mark_apply_failed_for(
        &self,
        principal: &str,
        target_id: &str,
        reason: &str,
        _now: i64,
    ) -> StorageResult<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE revisions
                 SET status = 'rejected', rejected_reason = ?1
                 WHERE revision_id = ?2 AND principal = ?3 AND status = 'candidate'",
                params![reason, target_id, principal],
            )
            .map_err(|e| StorageError::Internal(format!("revisions reject target: {e}")))?;
        if updated != 1 {
            return Err(StorageError::Internal(format!(
                "revisions reject target: expected 1 row updated, got {updated} \
                 (revision_id={target_id} principal={principal} may not be in candidate status)"
            )));
        }
        Ok(())
    }

    /// Active → RolledBack. Used during rollback flow when the user
    /// explicitly decides to leave the current active behind. The
    /// rollback target itself is activated via a fresh
    /// `mark_apply_succeeded` call — this method only marks the
    /// outgoing revision.
    pub fn mark_rolled_back(&self, revision_id: &str, now: i64) -> StorageResult<()> {
        self.mark_rolled_back_for(BASELINE_PRINCIPAL, revision_id, now)
    }

    /// Principal-scoped Active → RolledBack transition.
    pub fn mark_rolled_back_for(
        &self,
        principal: &str,
        revision_id: &str,
        now: i64,
    ) -> StorageResult<()> {
        let updated = self
            .conn
            .execute(
                "UPDATE revisions
                 SET status = 'rolled-back', superseded_at = ?1
                 WHERE revision_id = ?2 AND principal = ?3 AND status = 'active'",
                params![now, revision_id, principal],
            )
            .map_err(|e| StorageError::Internal(format!("revisions rolled_back: {e}")))?;
        if updated != 1 {
            return Err(StorageError::Internal(format!(
                "revisions rolled_back: expected 1 row updated, got {updated} \
                 (revision_id={revision_id} principal={principal} may not be in active status)"
            )));
        }
        Ok(())
    }
}

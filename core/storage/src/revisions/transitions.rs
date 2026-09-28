//! Candidate insertion and the `Candidate → Active/Rejected/RolledBack`
//! status transitions that drive the apply/rollback lifecycle.
//!
//! Every transition rewrites signed columns, so every transition re-signs
//! what it wrote. Left to the callers, one forgotten re-sign turned an
//! untouched database into a tamper alert on the next start.

use crate::revision_hmac::HmacVerification;

use super::*;

impl<'c> RevisionsRepository<'c> {
    /// Inserts a new candidate revision. Status is forced to `Candidate`
    /// regardless of what the caller put in `record.status` — only the
    /// activation coordinator may move a revision out of `Candidate`.
    ///
    /// Signed with the repository's key; without one the row stays
    /// `Unsigned` until the boot backfill or [`Self::re_sign_all`].
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
        // Signed over exactly what the INSERT below writes.
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

    /// Candidate `target_id` becomes Active; the previously active revision
    /// (if any) becomes Superseded by it. The caller commits this together
    /// with the pointer update in one transaction.
    pub fn mark_apply_succeeded(
        &self,
        target_id: &str,
        previous_id: Option<&str>,
        now: i64,
    ) -> StorageResult<()> {
        self.mark_apply_succeeded_for(BASELINE_PRINCIPAL, target_id, previous_id, now)
    }

    /// Principal-scoped [`Self::mark_apply_succeeded`]: one user's activation
    /// can never supersede another user's active revision.
    pub fn mark_apply_succeeded_for(
        &self,
        principal: &str,
        target_id: &str,
        previous_id: Option<&str>,
        now: i64,
    ) -> StorageResult<()> {
        let target_before = self.verdict_before_transition(target_id)?;
        let previous_before = match previous_id {
            Some(prev) => self.verdict_before_transition(prev)?,
            None => None,
        };
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
        self.re_sign_after_transition(target_id, target_before)?;
        if let Some(prev) = previous_id {
            self.re_sign_after_transition(prev, previous_before)?;
        }
        Ok(())
    }

    /// Was `revision_id` already retired in favour of `target_id`? Lets a
    /// retried activation tell "nothing to do" from "the wrong revision".
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

    /// Candidate `target_id` becomes Rejected with `reason`. The pointer is
    /// left alone: undoing the apply is the apply layer's job.
    pub fn mark_apply_failed(&self, target_id: &str, reason: &str, now: i64) -> StorageResult<()> {
        self.mark_apply_failed_for(BASELINE_PRINCIPAL, target_id, reason, now)
    }

    /// Principal-scoped [`Self::mark_apply_failed`].
    pub fn mark_apply_failed_for(
        &self,
        principal: &str,
        target_id: &str,
        reason: &str,
        _now: i64,
    ) -> StorageResult<()> {
        let before = self.verdict_before_transition(target_id)?;
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
        self.re_sign_after_transition(target_id, before)
    }

    /// Active → RolledBack for the outgoing revision only; the rollback
    /// target is activated through [`Self::mark_apply_succeeded`].
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
        let before = self.verdict_before_transition(revision_id)?;
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
        self.re_sign_after_transition(revision_id, before)
    }

    /// What the row's signature says before a transition rewrites it; `None`
    /// without a key, where there is nothing to re-sign with.
    pub(super) fn verdict_before_transition(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<HmacVerification>> {
        if self.key().is_none() {
            return Ok(None);
        }
        self.verify_row_hmac(revision_id)
    }

    /// Re-signs a row a transition just rewrote — unless it already failed
    /// verification before, where a fresh signature would legitimise somebody
    /// else's edit and the row has to keep failing for whoever looks next.
    pub(super) fn re_sign_after_transition(
        &self,
        revision_id: &str,
        before: Option<HmacVerification>,
    ) -> StorageResult<()> {
        if matches!(
            before,
            Some(HmacVerification::Verified | HmacVerification::Unsigned)
        ) {
            self.re_sign_row(revision_id)?;
        }
        Ok(())
    }
}

//! Per-principal reset, the orphaned-candidate boot sweep, and
//! terminal-status retention pruning (age + count caps).

use super::*;

impl<'c> RevisionsRepository<'c> {
    /// Delete ALL revision rows owned by `principal`, regardless of
    /// status. Used by the "reset to baseline" flow: once a
    /// user's per-principal revisions are gone the provider's read-through
    /// (`active_rules_for`) resolves the baseline principal again, so the
    /// user transparently falls back to the admin baseline rules.
    ///
    /// The caller is responsible for also clearing the principal's active
    /// pointer ([`Self::clear_active_pointer_for`]) — the coordinator's
    /// `reset_principal_to_baseline` does both in one transaction-free
    /// sequence (the composite FK from the pointer to a `revisions` row
    /// means the pointer must go first or in the same step). Returns the
    /// number of revision rows deleted.
    ///
    /// Refuses to touch the baseline sentinel: `delete_all_revisions_for`
    /// is a per-user reset, never a way to wipe the shared baseline.
    pub fn delete_all_revisions_for(&self, principal: &str) -> StorageResult<usize> {
        if principal == BASELINE_PRINCIPAL {
            return Err(StorageError::Internal(
                "refusing to delete the baseline principal's revisions".into(),
            ));
        }
        // Clear the pointer first so its composite FK
        // `(principal, revision_id) → revisions` cannot dangle.
        self.clear_active_pointer_for(principal)?;
        let deleted = self
            .conn
            .execute(
                "DELETE FROM revisions WHERE principal = ?1",
                params![principal],
            )
            .map_err(|e| StorageError::Internal(format!("revisions delete-all: {e}")))?;
        Ok(deleted)
    }

    /// Flips every row still in `status = 'candidate'`, across all
    /// principals, to `status = 'rejected'` with `rejected_reason = reason`.
    ///
    /// A candidate row is only ever supposed to be transient: the
    /// activation coordinator moves it to `active` or `rejected` within the
    /// same call that created it. A hard process kill between
    /// `insert_candidate_for` and that follow-up commit leaves the row
    /// stuck in `candidate` forever — the in-memory confirmation token that
    /// would have driven its transition dies with the process, so nothing
    /// else will ever advance it. Callers run this once at boot, after
    /// state-DB migrations succeed and before anything else reads
    /// `revisions`, so a fresh process never inherits a prior run's
    /// half-finished mutation.
    ///
    /// `now_ms` is accepted for interface symmetry with the other status
    /// transitions in this repository; the `revisions` schema has no
    /// `rejected_at` column (mirroring [`Self::mark_apply_failed_for`], the
    /// interactive reject path, which also does not write one).
    ///
    /// Rows are re-signed via [`Self::re_sign_row`] when the repository
    /// carries a signing key, keeping `row_hmac` consistent with the new
    /// status. **Without a signing key only unsigned rows (empty
    /// `row_hmac`) are eligible**: flipping a signed row keyless would
    /// leave its HMAC stale over the old status and read as `Tampered`
    /// on the next integrity scan. Signed candidates are left in place
    /// for a later keyed sweep. Returns the number of rows rejected.
    pub fn reject_orphaned_candidates(&self, reason: &str, _now_ms: i64) -> StorageResult<usize> {
        // One transaction over the whole sweep. The SELECT collects ids and the
        // UPDATE then matches `status = 'candidate'` again — a WIDER set if a
        // row was inserted in between. That row got flipped to `rejected` while
        // only the collected ids were re-signed, so its signature still covered
        // `candidate`: the next verification called it TAMPERED and blocked
        // every mutation on a database nobody had touched.
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("reject_orphaned_candidates tx: {e}")))?;
        let signed_rows_eligible = if self.key().is_some() {
            ""
        } else {
            " AND (row_hmac IS NULL OR length(row_hmac) = 0)"
        };
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT revision_id FROM revisions WHERE status = 'candidate'{signed_rows_eligible}"
            ))
            .map_err(|e| {
                StorageError::Internal(format!("reject_orphaned_candidates prepare: {e}"))
            })?;
        let orphan_ids: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("reject_orphaned_candidates query: {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| {
                StorageError::Internal(format!("reject_orphaned_candidates collect: {e}"))
            })?;
        drop(stmt);

        if orphan_ids.is_empty() {
            return Ok(0);
        }

        let rejected = tx
            .execute(
                &format!(
                    "UPDATE revisions
                     SET status = 'rejected', rejected_reason = ?1
                     WHERE status = 'candidate'{signed_rows_eligible}"
                ),
                params![reason],
            )
            .map_err(|e| {
                StorageError::Internal(format!("reject_orphaned_candidates update: {e}"))
            })?;

        for id in &orphan_ids {
            self.re_sign_row(id)?;
        }
        tx.commit().map_err(|e| {
            StorageError::Internal(format!("reject_orphaned_candidates commit: {e}"))
        })?;

        Ok(rejected)
    }

    /// Prunes terminal-status revisions per `settings`. Active revisions
    /// are never deleted.
    ///
    /// Rules:
    /// - `Superseded` — drop rows whose `superseded_at < now -
    ///   superseded_days * 86400`. Then if more than `superseded_count_cap`
    ///   remain, drop the oldest to bring the count back to the cap.
    ///   When `pin_lkg` is set, the most recent superseded row is
    ///   excluded from BOTH passes (it is the LKG and must stay
    ///   reachable for rollback).
    /// - `Rejected` — drop rows whose `created_at < now - rejected_days
    ///   * 86400`. No count cap (rejected revisions tend to be sparse).
    /// - `RolledBack` — drop rows whose `superseded_at < now -
    ///   rolledback_days * 86400`. Then enforce `rolledback_count_cap`.
    ///
    /// Returns `(superseded_dropped, rejected_dropped, rolledback_dropped)`.
    pub fn prune_by_retention(
        &self,
        settings: &RetentionSettings,
        now_secs: i64,
    ) -> StorageResult<RetentionPruneSummary> {
        // Retention runs independently per principal so each user keeps
        // their own count caps and (when pinned) their own LKG.
        //
        // Independently also means one principal's failure must not end the
        // pass: principals are walked in a fixed order, so a single failing
        // user used to stop retention for everyone sorted after them — silently
        // and on every subsequent run. A failure is reported and the walk
        // continues; the first error is returned only if NOTHING succeeded.
        let mut total = RetentionPruneSummary::default();
        let mut first_error: Option<StorageError> = None;
        let mut pruned_any = false;
        for principal in self.distinct_principals()? {
            match self.prune_by_retention_for(&principal, settings, now_secs) {
                Ok(s) => {
                    pruned_any = true;
                    total.superseded_dropped += s.superseded_dropped;
                    total.rejected_dropped += s.rejected_dropped;
                    total.rolledback_dropped += s.rolledback_dropped;
                }
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
        match first_error {
            Some(e) if !pruned_any => Err(e),
            _ => Ok(total),
        }
    }

    /// Prune one principal's terminal-status revisions per
    /// `settings`. The active revision is never deleted. Count caps and the
    /// pinned LKG are scoped to this principal.
    pub fn prune_by_retention_for(
        &self,
        principal: &str,
        settings: &RetentionSettings,
        now_secs: i64,
    ) -> StorageResult<RetentionPruneSummary> {
        let lkg_id: Option<String> = if settings.pin_lkg {
            self.last_known_good_for(principal)?.map(|r| r.revision_id)
        } else {
            None
        };

        let secs_per_day: i64 = 86_400;
        let superseded_dropped = self.prune_status_by_age(
            principal,
            "superseded",
            "superseded_at",
            now_secs.saturating_sub(settings.superseded_days as i64 * secs_per_day),
            lkg_id.as_deref(),
        )?;
        let superseded_capped = self.cap_status_count(
            principal,
            "superseded",
            "superseded_at",
            settings.superseded_count_cap,
            lkg_id.as_deref(),
        )?;
        let rejected_dropped = self.prune_status_by_age(
            principal,
            "rejected",
            "created_at",
            now_secs.saturating_sub(settings.rejected_days as i64 * secs_per_day),
            None,
        )?;
        let rolledback_dropped = self.prune_status_by_age(
            principal,
            "rolled-back",
            "superseded_at",
            now_secs.saturating_sub(settings.rolledback_days as i64 * secs_per_day),
            None,
        )?;
        let rolledback_capped = self.cap_status_count(
            principal,
            "rolled-back",
            "superseded_at",
            settings.rolledback_count_cap,
            None,
        )?;

        Ok(RetentionPruneSummary {
            superseded_dropped: superseded_dropped + superseded_capped,
            rejected_dropped,
            rolledback_dropped: rolledback_dropped + rolledback_capped,
        })
    }

    fn prune_status_by_age(
        &self,
        principal: &str,
        status_slug: &str,
        time_col: &str,
        threshold_secs: i64,
        protect_id: Option<&str>,
    ) -> StorageResult<usize> {
        // Never delete the row `active_revision_pointer` points at. Its
        // composite FK has no `ON DELETE`, so such a DELETE fails — and since
        // retention walks principals in one loop, a single stale pointer used
        // to abort the pass and leave every principal after it unpruned for
        // good. Whether the pointer is current or stale, its target has to
        // survive; a stale one is repaired by the pointer's own writers.
        let sql = match protect_id {
            Some(_) => format!(
                "DELETE FROM revisions
                 WHERE principal = ?1 AND status = ?2 AND {time_col} IS NOT NULL
                       AND {time_col} < ?3
                       AND revision_id != ?4
                       AND revision_id NOT IN
                           (SELECT revision_id FROM active_revision_pointer WHERE principal = ?1)"
            ),
            None => format!(
                "DELETE FROM revisions
                 WHERE principal = ?1 AND status = ?2 AND {time_col} IS NOT NULL
                       AND {time_col} < ?3
                       AND revision_id NOT IN
                           (SELECT revision_id FROM active_revision_pointer WHERE principal = ?1)"
            ),
        };
        let dropped = match protect_id {
            Some(id) => self
                .conn
                .execute(&sql, params![principal, status_slug, threshold_secs, id])
                .map_err(|e| StorageError::Internal(format!("prune {status_slug} age: {e}")))?,
            None => self
                .conn
                .execute(&sql, params![principal, status_slug, threshold_secs])
                .map_err(|e| StorageError::Internal(format!("prune {status_slug} age: {e}")))?,
        };
        Ok(dropped)
    }

    fn cap_status_count(
        &self,
        principal: &str,
        status_slug: &str,
        time_col: &str,
        cap: u32,
        protect_id: Option<&str>,
    ) -> StorageResult<usize> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM revisions WHERE principal = ?1 AND status = ?2",
                params![principal, status_slug],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Internal(format!("cap count {status_slug}: {e}")))?;
        let cap_i64 = cap as i64;
        if count <= cap_i64 {
            return Ok(0);
        }
        let to_drop = (count - cap_i64) as usize;
        // Identify the rows to drop: oldest first by `time_col`,
        // skipping `protect_id` if present.
        let select_sql = match protect_id {
            Some(_) => format!(
                "SELECT revision_id FROM revisions
                 WHERE principal = ?1 AND status = ?2 AND revision_id != ?3
                 ORDER BY {time_col} ASC, revision_id ASC LIMIT ?4"
            ),
            None => format!(
                "SELECT revision_id FROM revisions
                 WHERE principal = ?1 AND status = ?2
                 ORDER BY {time_col} ASC, revision_id ASC LIMIT ?3"
            ),
        };
        let mut stmt = self
            .conn
            .prepare(&select_sql)
            .map_err(|e| StorageError::Internal(format!("cap select {status_slug}: {e}")))?;
        let to_drop_ids: Vec<String> = match protect_id {
            Some(id) => stmt
                .query_map(params![principal, status_slug, id, to_drop as i64], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| StorageError::Internal(format!("cap query {status_slug}: {e}")))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| StorageError::Internal(format!("cap rows {status_slug}: {e}")))?,
            None => stmt
                .query_map(params![principal, status_slug, to_drop as i64], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| StorageError::Internal(format!("cap query {status_slug}: {e}")))?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|e| StorageError::Internal(format!("cap rows {status_slug}: {e}")))?,
        };
        drop(stmt);
        let mut dropped = 0usize;
        for id in &to_drop_ids {
            let n = self
                .conn
                .execute(
                    "DELETE FROM revisions WHERE principal = ?1 AND revision_id = ?2",
                    params![principal, id],
                )
                .map_err(|e| StorageError::Internal(format!("cap delete: {e}")))?;
            dropped += n;
        }
        Ok(dropped)
    }
}

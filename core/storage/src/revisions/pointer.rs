//! The `active_revision_pointer` singleton: per-principal read, upsert, and
//! clear.

use super::*;

impl<'c> RevisionsRepository<'c> {
    /// Reads the active-revision pointer for the baseline principal, or
    /// `None` if no revision has ever been activated. The pointer table
    /// is keyed by `principal` (not a singleton).
    pub fn get_active_pointer(&self) -> StorageResult<Option<ActiveRevisionPointer>> {
        self.get_active_pointer_for(BASELINE_PRINCIPAL)
    }

    /// The active-revision pointer for one `principal`.
    pub fn get_active_pointer_for(
        &self,
        principal: &str,
    ) -> StorageResult<Option<ActiveRevisionPointer>> {
        self.conn
            .query_row(
                "SELECT revision_id, activated_at, apply_attempt_id
                 FROM active_revision_pointer WHERE principal = ?1",
                params![principal],
                |row| {
                    Ok(ActiveRevisionPointer {
                        revision_id: row.get(0)?,
                        activated_at: row.get(1)?,
                        apply_attempt_id: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("active_revision_pointer get: {e}")))
    }

    /// Inserts or replaces the baseline principal's pointer row.
    pub fn set_active_pointer(&self, pointer: &ActiveRevisionPointer) -> StorageResult<()> {
        self.set_active_pointer_for(BASELINE_PRINCIPAL, pointer)
    }

    /// Upsert the active-revision pointer for one `principal`. The
    /// composite foreign key
    /// `(principal, revision_id) → revisions(principal, revision_id)`
    /// rejects a pointer that references a revision the principal does not
    /// own.
    pub fn set_active_pointer_for(
        &self,
        principal: &str,
        pointer: &ActiveRevisionPointer,
    ) -> StorageResult<()> {
        let row_hmac = self.pointer_hmac(principal, pointer);
        self.conn
            .execute(
                "INSERT INTO active_revision_pointer
                 (principal, revision_id, activated_at, apply_attempt_id, row_hmac)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(principal) DO UPDATE SET
                     revision_id = excluded.revision_id,
                     activated_at = excluded.activated_at,
                     apply_attempt_id = excluded.apply_attempt_id,
                     row_hmac = excluded.row_hmac",
                params![
                    principal,
                    pointer.revision_id,
                    pointer.activated_at,
                    pointer.apply_attempt_id,
                    row_hmac,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("active_revision_pointer set: {e}")))?;
        Ok(())
    }

    /// Removes the baseline principal's pointer row. Used by safe-disable /
    /// first-time install flows where no revision is active.
    pub fn clear_active_pointer(&self) -> StorageResult<()> {
        self.clear_active_pointer_for(BASELINE_PRINCIPAL)
    }

    /// Removes one `principal`'s pointer row.
    pub fn clear_active_pointer_for(&self, principal: &str) -> StorageResult<()> {
        self.conn
            .execute(
                "DELETE FROM active_revision_pointer WHERE principal = ?1",
                params![principal],
            )
            .map_err(|e| StorageError::Internal(format!("active_revision_pointer clear: {e}")))?;
        Ok(())
    }
}

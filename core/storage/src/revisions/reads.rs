//! Non-mutating lookups over `revisions`: counts, id/hash/status queries,
//! and the verified activation history used by the integrity gate.

use super::*;

impl<'c> RevisionsRepository<'c> {
    /// Total number of rows in `revisions`. The tamper bootstrap uses
    /// this to distinguish "fresh install"
    /// (empty → silent key regen) from "key reset with existing data"
    /// (non-empty → alert + mutation block).
    pub fn count(&self) -> StorageResult<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM revisions", [], |row| row.get(0))
            .map_err(|e| StorageError::Internal(format!("revisions count: {e}")))?;
        Ok(n as usize)
    }

    /// Fetches a revision by its id, or `None` if not found. Global lookup:
    /// `revision_id` is a globally-unique UUID, so this resolves across all
    /// principals. Internal/diagnostic use; authorization-sensitive callers
    /// must use [`Self::get_by_id_for`] so a caller cannot read another
    /// principal's revision by guessing its id.
    pub fn get_by_id(&self, revision_id: &str) -> StorageResult<Option<RevisionRecord>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level
                 FROM revisions WHERE revision_id = ?1",
                params![revision_id],
                row_to_record,
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions get_by_id: {e}")))
    }

    /// The principal that owns `revision_id`, or `None` if
    /// no such revision. Lets the activation coordinator derive the
    /// partition key from a globally-unique revision id (created by an
    /// earlier `submit_candidate_for`) so the rest of the activate /
    /// rollback flow can use the principal-scoped storage methods without
    /// the caller re-supplying it.
    pub fn principal_of(&self, revision_id: &str) -> StorageResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT principal FROM revisions WHERE revision_id = ?1",
                params![revision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions principal_of: {e}")))
    }

    /// Principal-scoped id lookup. Returns `None` if the
    /// revision exists but belongs to a different principal, giving callers
    /// isolation without a separate ownership check.
    pub fn get_by_id_for(
        &self,
        principal: &str,
        revision_id: &str,
    ) -> StorageResult<Option<RevisionRecord>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level
                 FROM revisions WHERE principal = ?1 AND revision_id = ?2",
                params![principal, revision_id],
                row_to_record,
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions get_by_id_for: {e}")))
    }

    /// Returns the existing revision with this content hash if any. Used
    /// by the service to dedupe `submit_candidate` requests.
    pub fn find_by_content_hash(&self, hash: &str) -> StorageResult<Option<RevisionRecord>> {
        self.find_by_content_hash_for(BASELINE_PRINCIPAL, hash)
    }

    /// Principal-scoped dedup. User A's content hash never
    /// dedupes against user B's identical revision; each user owns an
    /// independent revision lineage.
    pub fn find_by_content_hash_for(
        &self,
        principal: &str,
        hash: &str,
    ) -> StorageResult<Option<RevisionRecord>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level
                 FROM revisions WHERE principal = ?1 AND content_hash = ?2
                 ORDER BY created_at DESC LIMIT 1",
                params![principal, hash],
                row_to_record,
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions find_by_content_hash: {e}")))
    }

    /// Returns the currently active revision, if any. Reads through the
    /// per-principal `status='active'` partial unique index.
    pub fn get_active(&self) -> StorageResult<Option<RevisionRecord>> {
        self.get_active_for(BASELINE_PRINCIPAL)
    }

    /// The active revision for one `principal`. At most one
    /// row matches (enforced by `idx_one_active_revision_per_principal`).
    pub fn get_active_for(&self, principal: &str) -> StorageResult<Option<RevisionRecord>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level
                 FROM revisions WHERE principal = ?1 AND status = 'active' LIMIT 1",
                params![principal],
                row_to_record,
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions get_active: {e}")))
    }

    /// `(revision_id, content_hash)` of `principal`'s active revision, without
    /// the rules blob: lets a reader tell whether its decoded copy is current.
    pub fn active_identity_for(&self, principal: &str) -> StorageResult<Option<(String, String)>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash FROM revisions
                 WHERE principal = ?1 AND status = 'active' LIMIT 1",
                params![principal],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions active_identity_for: {e}")))
    }

    /// Returns the most recent superseded revision — the canonical
    /// "last known good" rollback target.
    ///
    /// `None` when no revision has ever been superseded (first-ever
    /// activate or every prior activation went straight to `Rejected`).
    pub fn last_known_good(&self) -> StorageResult<Option<RevisionRecord>> {
        self.last_known_good_for(BASELINE_PRINCIPAL)
    }

    /// The most recent superseded revision for one
    /// `principal` — that user's canonical rollback target.
    pub fn last_known_good_for(&self, principal: &str) -> StorageResult<Option<RevisionRecord>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level
                 FROM revisions
                 WHERE principal = ?1 AND status = 'superseded'
                 ORDER BY superseded_at DESC LIMIT 1",
                params![principal],
                row_to_record,
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions last_known_good: {e}")))
    }

    /// `principal`'s revisions that have ever enforced policy, most-
    /// recently-active first: the current `active` row (if any), then
    /// `superseded`/`rolled-back` rows ordered by when they stopped being
    /// active. Each entry carries its HMAC verification outcome against
    /// the repository's signing key (a repository built via [`Self::new`]
    /// reports every row [`crate::revision_hmac::HmacVerification::Unsigned`]).
    ///
    /// Drives the activation-integrity gate: when the active row fails
    /// verification, the caller walks this list (skipping the active
    /// entry) for the newest one that still verifies.
    pub fn activation_history_for(
        &self,
        principal: &str,
    ) -> StorageResult<Vec<VerifiedHistoryEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac, principal
                 FROM revisions
                 WHERE principal = ?1 AND status IN ('active', 'superseded', 'rolled-back')
                 ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END ASC,
                          COALESCE(superseded_at, activated_at, created_at) DESC",
            )
            .map_err(|e| StorageError::Internal(format!("activation_history_for prepare: {e}")))?;
        let rows = stmt
            .query_map(params![principal], |row| {
                let rec = row_to_record(row)?;
                let hmac: Vec<u8> = row.get(13)?;
                let row_principal: String = row.get(14)?;
                Ok((row_principal, rec, hmac))
            })
            .map_err(|e| StorageError::Internal(format!("activation_history_for query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("activation_history_for collect: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for (row_principal, record, stored) in rows {
            let verification = match self.key() {
                Some(key) => {
                    let fields = record_to_row_fields(&row_principal, &record);
                    crate::revision_hmac::verify(&fields, &stored, key)
                }
                None => crate::revision_hmac::HmacVerification::Unsigned,
            };
            out.push(VerifiedHistoryEntry {
                record,
                verification,
            });
        }
        Ok(out)
    }

    /// `principal`'s revisions that came into force at or after `since`, newest
    /// first, at most `limit`. Rows that never enforced (candidates, rejected)
    /// are left out; ties in the second fall back to insertion order.
    pub fn enforced_since_for(
        &self,
        principal: &str,
        since: i64,
        limit: usize,
    ) -> StorageResult<Vec<EnforcedRevisionStamp>> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.enforced_stamps(
            "SELECT revision_id, content_hash, source, activated_at FROM revisions
             WHERE principal = ?1 AND status IN ('active', 'superseded', 'rolled-back')
               AND activated_at IS NOT NULL AND activated_at >= ?2
             ORDER BY activated_at DESC, created_at DESC, rowid DESC LIMIT ?3",
            params![principal, since, limit],
        )
    }

    /// The newest of `principal`'s revisions that came into force before
    /// `before`: the set in force at that moment, while history still holds it.
    pub fn last_enforced_before_for(
        &self,
        principal: &str,
        before: i64,
    ) -> StorageResult<Option<EnforcedRevisionStamp>> {
        Ok(self
            .enforced_stamps(
                "SELECT revision_id, content_hash, source, activated_at FROM revisions
                 WHERE principal = ?1 AND status IN ('active', 'superseded', 'rolled-back')
                   AND activated_at IS NOT NULL AND activated_at < ?2
                 ORDER BY activated_at DESC, created_at DESC, rowid DESC LIMIT 1",
                params![principal, before],
            )?
            .into_iter()
            .next())
    }

    /// How many of `principal`'s superseded revisions came into force at or
    /// after `since`.
    pub fn superseded_count_since_for(&self, principal: &str, since: i64) -> StorageResult<usize> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM revisions
                 WHERE principal = ?1 AND status = 'superseded' AND activated_at >= ?2",
                params![principal, since],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Internal(format!("superseded_count_since_for: {e}")))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    fn enforced_stamps(
        &self,
        sql: &str,
        args: impl rusqlite::Params,
    ) -> StorageResult<Vec<EnforcedRevisionStamp>> {
        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| StorageError::Internal(format!("enforced stamps prepare: {e}")))?;
        let rows = stmt
            .query_map(args, |row| {
                let source_slug: String = row.get(2)?;
                let source = RulesRevisionSource::from_slug(&source_slug).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        format!("unknown revision source slug: {source_slug:?}").into(),
                    )
                })?;
                Ok(EnforcedRevisionStamp {
                    revision_id: row.get(0)?,
                    content_hash: row.get(1)?,
                    source,
                    activated_at: row.get(3)?,
                })
            })
            .map_err(|e| StorageError::Internal(format!("enforced stamps query: {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| StorageError::Internal(format!("enforced stamps collect: {e}")))?;
        Ok(rows)
    }

    /// Distinct `principal` values present in `revisions`,
    /// in stable order. Drives the per-principal retention sweep and any
    /// table-wide maintenance that must fan out over users.
    pub fn distinct_principals(&self) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT principal FROM revisions ORDER BY principal ASC")
            .map_err(|e| StorageError::Internal(format!("distinct_principals prepare: {e}")))?;
        let principals = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("distinct_principals query: {e}")))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| StorageError::Internal(format!("distinct_principals collect: {e}")))?;
        Ok(principals)
    }
}

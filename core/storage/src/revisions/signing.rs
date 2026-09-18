//! HMAC-SHA256 signing and tamper verification for `revisions` rows and the
//! `active_revision_pointer` singleton.

use super::*;

/// Projects a pointer row onto the borrowed view the HMAC is computed over.
pub(super) fn pointer_fields<'a>(
    principal: &'a str,
    pointer: &'a ActiveRevisionPointer,
) -> crate::revision_hmac::PointerFields<'a> {
    crate::revision_hmac::PointerFields {
        principal,
        revision_id: &pointer.revision_id,
        activated_at: pointer.activated_at,
        apply_attempt_id: pointer.apply_attempt_id.as_deref(),
    }
}

impl<'c> RevisionsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self {
            conn,
            signing_key: None,
        }
    }

    /// Production constructor that enables HMAC-SHA256 signing of
    /// revision rows. The caller is responsible for sourcing `key` from
    /// a DPAPI-protected blob; the storage layer treats it as opaque
    /// bytes.
    pub fn with_signing_key(conn: &'c Connection, key: Vec<u8>) -> Self {
        Self {
            conn,
            signing_key: Some(key),
        }
    }

    /// Internal helper — borrows the signing key as a slice if one
    /// was provided.
    pub(super) fn key(&self) -> Option<&[u8]> {
        self.signing_key.as_deref()
    }

    /// Fetch the row plus its stored `row_hmac` blob in one trip.
    /// Verification (comparing the blob to a fresh
    /// recomputation) is the caller's job; this method only hands
    /// over the raw materials. Returns `None` when no row matches.
    pub fn get_with_hmac(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<(RevisionRecord, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac
                 FROM revisions WHERE revision_id = ?1",
                params![revision_id],
                |row| {
                    let rec = row_to_record(row)?;
                    let hmac: Vec<u8> = row.get(13)?;
                    Ok((rec, hmac))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revisions get_with_hmac: {e}")))
    }

    /// Verify one row's stored HMAC against a fresh recomputation
    /// using the repository's signing key. Returns
    /// `None` when no row matches the id, otherwise wraps the
    /// outcome from [`crate::revision_hmac::verify`]. A repository
    /// constructed without a signing key returns `Unsigned` for
    /// every row — there's nothing to compare against.
    pub fn verify_row_hmac(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<crate::revision_hmac::HmacVerification>> {
        let Some((principal, record, stored)) = self.row_with_principal_and_hmac(revision_id)?
        else {
            return Ok(None);
        };
        let Some(key) = self.key() else {
            // No key means we can't recompute → caller treats as
            // unsigned. Empty blob would also lead `verify` to the
            // same outcome, but we short-circuit to avoid touching
            // the HMAC primitive.
            return Ok(Some(crate::revision_hmac::HmacVerification::Unsigned));
        };
        let fields = record_to_row_fields(&principal, &record);
        Ok(Some(crate::revision_hmac::verify(&fields, &stored, key)))
    }

    /// Internal: fetch a row's `principal`, content, and
    /// stored `row_hmac` together. The principal is required to recompute
    /// the HMAC (it is part of the canonical input) but is not exposed on
    /// [`RevisionRecord`], so HMAC paths read it through this helper.
    ///
    /// The table's key is `(principal, revision_id)`, so an id alone can
    /// address two rows — and the threat model this HMAC exists for (an
    /// external writer in the DB file, see [`crate::revision_hmac`]) is exactly
    /// how a second one appears. Picking an arbitrary one would let a shadow
    /// row decide what the signing paths see, so ambiguity is reported as the
    /// integrity failure it is instead.
    fn row_with_principal_and_hmac(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<(String, RevisionRecord, Vec<u8>)>> {
        // `principal` is appended AFTER the 13 record columns and the
        // `row_hmac` blob so the shared `row_to_record` mapper (columns
        // 0..=12) and the v11 hmac index (13) stay valid.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac, principal
                 FROM revisions WHERE revision_id = ?1 LIMIT 2",
            )
            .map_err(|e| {
                StorageError::Internal(format!("revisions row_with_principal_and_hmac: {e}"))
            })?;
        let mut rows = stmt
            .query_map(params![revision_id], |row| {
                let rec = row_to_record(row)?;
                let hmac: Vec<u8> = row.get(13)?;
                let principal: String = row.get(14)?;
                Ok((principal, rec, hmac))
            })
            .map_err(|e| {
                StorageError::Internal(format!("revisions row_with_principal_and_hmac: {e}"))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                StorageError::Internal(format!("revisions row_with_principal_and_hmac: {e}"))
            })?;
        if rows.len() > 1 {
            return Err(StorageError::IntegrityFailed(
                crate::error::IntegrityFailureKind::PolicyRevisionCorrupt,
            ));
        }
        Ok(rows.pop())
    }

    /// Recompute and persist the HMAC for one row. Used after every
    /// UPDATE that changes a signed column and by
    /// the ack-flow re-signing helper. No-op when the repository
    /// has no signing key (back-compat).
    /// Returns what the signature said BEFORE it was replaced, so the caller
    /// can tell a repair from an adoption.
    ///
    /// Re-signing is normally a repair: the writer just edited signed columns
    /// itself and the stored HMAC is stale by construction. Over a row that was
    /// TAMPERED with, the very same call mints a valid signature for somebody
    /// else's edit — the tamper detector silently undone by its own repair
    /// path. Nothing here refuses to do it (the ack flow legitimately means
    /// "I have reviewed this and accept it"), but the verdict is no longer
    /// thrown away, so an adoption can be logged and audited as one.
    pub fn re_sign_row(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<crate::revision_hmac::HmacVerification>> {
        let Some(key) = self.key() else {
            return Ok(None);
        };
        let Some((principal, record, stored)) = self.row_with_principal_and_hmac(revision_id)?
        else {
            return Ok(None);
        };
        let fields = record_to_row_fields(&principal, &record);
        let before = crate::revision_hmac::verify(&fields, &stored, key);
        let hmac = crate::revision_hmac::compute_hmac(&fields, key).to_vec();
        // Scoped by the WHOLE key: the HMAC was computed over THIS principal's
        // fields, and an id-only UPDATE would stamp it onto every row sharing
        // the id — signing somebody else's content with a signature that was
        // never computed from it.
        self.conn
            .execute(
                "UPDATE revisions SET row_hmac = ?1 WHERE principal = ?2 AND revision_id = ?3",
                params![hmac, principal, revision_id],
            )
            .map_err(|e| StorageError::Internal(format!("revisions re_sign_row: {e}")))?;
        Ok(Some(before))
    }

    /// Walk every row in `revisions` and rewrite `row_hmac` with a
    /// fresh HMAC. Driven by the
    /// `SecurityAlert::DbTamperDetected` ack flow (the user says
    /// "I've reviewed the rules and accept the current state") and
    /// the first-boot upgrade path that finds existing rows but no
    /// HMACs (lazy backfill).
    ///
    /// Returns the number of rows re-signed. No-op when the
    /// repository has no signing key (and returns 0).
    pub fn re_sign_all(&self) -> StorageResult<ReSignReport> {
        if self.key().is_none() {
            return Ok(ReSignReport::default());
        }
        let mut stmt = self
            .conn
            .prepare("SELECT revision_id FROM revisions ORDER BY created_at ASC")
            .map_err(|e| StorageError::Internal(format!("revisions re_sign_all prepare: {e}")))?;
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("revisions re_sign_all query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("revisions re_sign_all collect: {e}")))?;
        drop(stmt);
        let mut report = ReSignReport::default();
        for id in &ids {
            let before = self.re_sign_row(id)?;
            report.re_signed += 1;
            if matches!(
                before,
                Some(crate::revision_hmac::HmacVerification::Tampered)
            ) {
                // Adopted, not repaired: this row did not match its signature
                // before we wrote a new one. The caller has to say so out loud.
                report.adopted_tampered.push(id.clone());
            }
        }
        // The pointer decides which of those revisions is ENFORCED, so an
        // acknowledgement that left it unsigned would raise the same alert on
        // the next start.
        for (principal, _) in self.verify_all_pointers()? {
            let before = self.re_sign_pointer_for(&principal)?;
            report.re_signed += 1;
            if matches!(
                before,
                Some(crate::revision_hmac::HmacVerification::Tampered)
            ) {
                report.adopted_tampered.push(format!("pointer:{principal}"));
            }
        }
        Ok(report)
    }

    /// Verify every row's stored `row_hmac` against a fresh
    /// recomputation, returning `(revision_id, outcome)` pairs in
    /// `created_at` order. Driven by the service-runtime tamper
    /// bootstrap, which emits `DbTamperDetected` for `Tampered` rows
    /// and lazily backfills `Unsigned` rows. A repository without a
    /// signing key reports every row as `Unsigned`.
    pub fn verify_all(
        &self,
    ) -> StorageResult<Vec<(String, crate::revision_hmac::HmacVerification)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac, principal
                 FROM revisions ORDER BY created_at ASC, revision_id ASC",
            )
            .map_err(|e| StorageError::Internal(format!("revisions verify_all prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                let rec = row_to_record(row)?;
                let hmac: Vec<u8> = row.get(13)?;
                let principal: String = row.get(14)?;
                Ok((principal, rec, hmac))
            })
            .map_err(|e| StorageError::Internal(format!("revisions verify_all query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("revisions verify_all collect: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for (principal, record, stored) in rows {
            let verification = match self.key() {
                Some(key) => {
                    let fields = record_to_row_fields(&principal, &record);
                    crate::revision_hmac::verify(&fields, &stored, key)
                }
                None => crate::revision_hmac::HmacVerification::Unsigned,
            };
            out.push((record.revision_id, verification));
        }
        Ok(out)
    }

    /// Sign one pointer row, or the empty blob when the repository has no key.
    pub(super) fn pointer_hmac(&self, principal: &str, pointer: &ActiveRevisionPointer) -> Vec<u8> {
        match self.key() {
            Some(key) => {
                let fields = pointer_fields(principal, pointer);
                crate::revision_hmac::compute_pointer_hmac(&fields, key).to_vec()
            }
            None => Vec::new(),
        }
    }

    /// Verify every pointer row, `(principal, outcome)` in principal order.
    ///
    /// Separate from [`Self::verify_all`] because the ids are principals, not
    /// revision ids, and the caller's backfill has to know which table to
    /// repair. Both feed the same alert.
    pub fn verify_all_pointers(
        &self,
    ) -> StorageResult<Vec<(String, crate::revision_hmac::HmacVerification)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT principal, revision_id, activated_at, apply_attempt_id, row_hmac
                 FROM active_revision_pointer ORDER BY principal ASC",
            )
            .map_err(|e| StorageError::Internal(format!("pointer verify_all prepare: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    ActiveRevisionPointer {
                        revision_id: row.get(1)?,
                        activated_at: row.get(2)?,
                        apply_attempt_id: row.get(3)?,
                    },
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })
            .map_err(|e| StorageError::Internal(format!("pointer verify_all query: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Internal(format!("pointer verify_all collect: {e}")))?;
        drop(stmt);

        Ok(rows
            .into_iter()
            .map(|(principal, pointer, stored)| {
                let verification = match self.key() {
                    Some(key) => {
                        let fields = pointer_fields(&principal, &pointer);
                        crate::revision_hmac::verify_pointer(&fields, &stored, key)
                    }
                    None => crate::revision_hmac::HmacVerification::Unsigned,
                };
                (principal, verification)
            })
            .collect())
    }

    /// Recompute and persist one pointer's HMAC, returning what the stored
    /// signature said before it was replaced. Same adoption caveat as
    /// [`Self::re_sign_row`].
    pub fn re_sign_pointer_for(
        &self,
        principal: &str,
    ) -> StorageResult<Option<crate::revision_hmac::HmacVerification>> {
        let Some(key) = self.key() else {
            return Ok(None);
        };
        let row: Option<(ActiveRevisionPointer, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT revision_id, activated_at, apply_attempt_id, row_hmac
                 FROM active_revision_pointer WHERE principal = ?1",
                params![principal],
                |row| {
                    Ok((
                        ActiveRevisionPointer {
                            revision_id: row.get(0)?,
                            activated_at: row.get(1)?,
                            apply_attempt_id: row.get(2)?,
                        },
                        row.get(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("pointer re_sign read: {e}")))?;
        let Some((pointer, stored)) = row else {
            return Ok(None);
        };
        let fields = pointer_fields(principal, &pointer);
        let before = crate::revision_hmac::verify_pointer(&fields, &stored, key);
        let hmac = crate::revision_hmac::compute_pointer_hmac(&fields, key).to_vec();
        self.conn
            .execute(
                "UPDATE active_revision_pointer SET row_hmac = ?1 WHERE principal = ?2",
                params![hmac, principal],
            )
            .map_err(|e| StorageError::Internal(format!("pointer re_sign write: {e}")))?;
        Ok(Some(before))
    }
}

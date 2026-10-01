//! The live integrity scan an acknowledgement is built from, and the
//! adoption that re-signs exactly the rows it named.

use rusqlite::{Transaction, TransactionBehavior};

use super::signing::pointer_fields;
use super::*;
use crate::revision_hmac::{
    compute_hmac, compute_pointer_hmac, pointer_fingerprint, row_fingerprint, verify,
    verify_pointer, HmacVerification,
};

/// Which signed table a row lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntegrityRowKind {
    Revision,
    ActivePointer,
}

/// A signed row's content, as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScannedContent {
    Revision(RevisionRecord),
    Pointer(ActiveRevisionPointer),
}

/// One signed row, its verdict under the current key and its fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedRow {
    pub principal: String,
    pub content: ScannedContent,
    pub verification: HmacVerification,
    /// [`crate::revision_hmac::row_fingerprint`] of the content as read.
    pub fingerprint: String,
}

impl ScannedRow {
    #[must_use]
    pub fn kind(&self) -> IntegrityRowKind {
        match self.content {
            ScannedContent::Revision(_) => IntegrityRowKind::Revision,
            ScannedContent::Pointer(_) => IntegrityRowKind::ActivePointer,
        }
    }

    /// The revision the row is, or the one a pointer selects.
    #[must_use]
    pub fn revision_id(&self) -> &str {
        match &self.content {
            ScannedContent::Revision(r) => &r.revision_id,
            ScannedContent::Pointer(p) => &p.revision_id,
        }
    }
}

/// A row an acknowledgement asks to adopt, and the content it was shown with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdoptionRequest<'a> {
    pub kind: IntegrityRowKind,
    pub principal: &'a str,
    pub revision_id: &'a str,
    pub fingerprint: &'a str,
}

/// What [`RevisionsRepository::adopt_rows`] did with one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdoptionOutcome {
    /// Re-signed: the row still failed verification with the shown content.
    Adopted,
    /// The content differs from what was shown; left as it is.
    Changed {
        fingerprint: String,
    },
    /// The row verifies (or predates signing); nothing to adopt.
    NotTampered,
    Missing,
}

impl RevisionsRepository<'_> {
    /// Every signed row with its verdict and fingerprint: revisions in
    /// `created_at` order, then pointers by principal. Without a key every row
    /// reads `Unsigned`.
    pub fn integrity_scan(&self) -> StorageResult<Vec<ScannedRow>> {
        let err = |e: rusqlite::Error| StorageError::Internal(format!("integrity_scan: {e}"));
        let mut stmt = self
            .conn
            .prepare(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac, principal
                 FROM revisions ORDER BY created_at ASC, revision_id ASC",
            )
            .map_err(err)?;
        let revisions = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(14)?,
                    row_to_record(row)?,
                    row.get::<_, Vec<u8>>(13)?,
                ))
            })
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        drop(stmt);
        let mut out: Vec<ScannedRow> = revisions
            .into_iter()
            .map(|(principal, record, stored)| self.scanned_revision(principal, record, &stored))
            .collect();
        for (principal, pointer, stored) in self.pointer_rows(None)? {
            out.push(self.scanned_pointer(principal, pointer, &stored));
        }
        Ok(out)
    }

    /// Re-sign each requested row that still fails verification AND still has
    /// the fingerprint it was shown with, in one immediate transaction so no
    /// writer lands between the check and the new signature. Without a key
    /// nothing can be signed and every request reads [`AdoptionOutcome::NotTampered`].
    pub fn adopt_rows(
        &self,
        requests: &[AdoptionRequest<'_>],
    ) -> StorageResult<Vec<AdoptionOutcome>> {
        let Some(key) = self.key() else {
            return Ok(vec![AdoptionOutcome::NotTampered; requests.len()]);
        };
        let err = |e: rusqlite::Error| StorageError::Internal(format!("adopt_rows: {e}"));
        let tx =
            Transaction::new_unchecked(self.conn, TransactionBehavior::Immediate).map_err(err)?;
        let mut outcomes = Vec::with_capacity(requests.len());
        for request in requests {
            let current = match request.kind {
                IntegrityRowKind::Revision => self
                    .revision_row_for(request.principal, request.revision_id)?
                    .map(|(record, stored)| {
                        self.scanned_revision(request.principal.to_string(), record, &stored)
                    }),
                IntegrityRowKind::ActivePointer => self
                    .pointer_rows(Some(request.principal))?
                    .pop()
                    .map(|(p, pointer, stored)| self.scanned_pointer(p, pointer, &stored)),
            };
            let Some(current) = current else {
                outcomes.push(AdoptionOutcome::Missing);
                continue;
            };
            if current.verification != HmacVerification::Tampered {
                outcomes.push(AdoptionOutcome::NotTampered);
                continue;
            }
            if current.fingerprint != request.fingerprint {
                outcomes.push(AdoptionOutcome::Changed {
                    fingerprint: current.fingerprint,
                });
                continue;
            }
            match &current.content {
                ScannedContent::Revision(record) => {
                    let tag = compute_hmac(&record_to_row_fields(&current.principal, record), key);
                    tx.execute(
                        "UPDATE revisions SET row_hmac = ?1 WHERE principal = ?2 AND revision_id = ?3",
                        params![tag.to_vec(), current.principal, record.revision_id],
                    )
                    .map_err(err)?;
                }
                ScannedContent::Pointer(pointer) => {
                    let tag =
                        compute_pointer_hmac(&pointer_fields(&current.principal, pointer), key);
                    tx.execute(
                        "UPDATE active_revision_pointer SET row_hmac = ?1 WHERE principal = ?2",
                        params![tag.to_vec(), current.principal],
                    )
                    .map_err(err)?;
                }
            }
            outcomes.push(AdoptionOutcome::Adopted);
        }
        tx.commit().map_err(err)?;
        Ok(outcomes)
    }

    fn scanned_revision(
        &self,
        principal: String,
        record: RevisionRecord,
        stored: &[u8],
    ) -> ScannedRow {
        let fields = record_to_row_fields(&principal, &record);
        let verification = match self.key() {
            Some(key) => verify(&fields, stored, key),
            None => HmacVerification::Unsigned,
        };
        let fingerprint = row_fingerprint(&fields);
        ScannedRow {
            principal,
            content: ScannedContent::Revision(record),
            verification,
            fingerprint,
        }
    }

    fn scanned_pointer(
        &self,
        principal: String,
        pointer: ActiveRevisionPointer,
        stored: &[u8],
    ) -> ScannedRow {
        let fields = pointer_fields(&principal, &pointer);
        let verification = match self.key() {
            Some(key) => verify_pointer(&fields, stored, key),
            None => HmacVerification::Unsigned,
        };
        let fingerprint = pointer_fingerprint(&fields);
        ScannedRow {
            principal,
            content: ScannedContent::Pointer(pointer),
            verification,
            fingerprint,
        }
    }

    /// One revision row by its full key.
    fn revision_row_for(
        &self,
        principal: &str,
        revision_id: &str,
    ) -> StorageResult<Option<(RevisionRecord, Vec<u8>)>> {
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac
                 FROM revisions WHERE principal = ?1 AND revision_id = ?2",
                params![principal, revision_id],
                |row| Ok((row_to_record(row)?, row.get::<_, Vec<u8>>(13)?)),
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("revision_row_for: {e}")))
    }

    /// Pointer rows with their stored tags, all of them or one principal's.
    fn pointer_rows(
        &self,
        principal: Option<&str>,
    ) -> StorageResult<Vec<(String, ActiveRevisionPointer, Vec<u8>)>> {
        let err = |e: rusqlite::Error| StorageError::Internal(format!("pointer_rows: {e}"));
        let mut stmt = self
            .conn
            .prepare(
                "SELECT principal, revision_id, activated_at, apply_attempt_id, row_hmac
                 FROM active_revision_pointer
                 WHERE ?1 IS NULL OR principal = ?1
                 ORDER BY principal ASC",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![principal], |row| {
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
            .map_err(err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(err)?;
        Ok(rows)
    }
}

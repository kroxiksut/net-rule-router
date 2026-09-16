//! `revisions` and `active_revision_pointer` repository.
//!
//! Persists rules-only revisions plus the singleton pointer to the
//! currently active revision in `nrr_service_state.db`. Schema lives in
//! `STATE_DB_V6_DDL`.
//!
//! ## Lifecycle
//!
//! 1. Service receives `submit_candidate(rules)` from GUI → repository
//!    [`insert_candidate`].
//! 2. Service issues a confirmation token and the user activates →
//!    the activation coordinator opens an SQL transaction, calls
//!    [`mark_apply_succeeded`] (atomic Phase 3a) or
//!    [`mark_apply_failed`] (Phase 3b), and updates the
//!    `active_revision_pointer` via [`set_active_pointer`].
//! 3. On rollback, [`mark_rolled_back`] flips the previously-active
//!    revision to `RolledBack` while a fresh candidate is created and
//!    activated through the same flow.
//!
//! ## Concurrency
//!
//! Single-writer (`&Connection` borrowed). Concurrent activations from
//! different threads serialise through the partial unique index
//! `idx_one_active_revision` — only one `status='active'` row may exist
//! at any time. The activation coordinator wraps the multi-statement
//! Phase 3 commit in a SQL transaction so the index check fires under
//! `BEGIN IMMEDIATE`.
//!
//! ## Serialisation boundary
//!
//! `rules_json` is opaque to storage — service-runtime owns the serde
//! boundary. The repository does no JSON parsing.

use rusqlite::{params, Connection, OptionalExtension};

use nrr_domain::revision::RiskLevel;
use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};

use crate::error::{StorageError, StorageResult};
use crate::retention_settings::RetentionSettings;
use crate::schema::BASELINE_PRINCIPAL;

// ── DTOs ──────────────────────────────────────────────────────────────────────

/// One row from the `revisions` table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionRecord {
    /// `"rev-<uuid v4>"`.
    pub revision_id: String,
    /// SHA-256 hex (64 chars) of the canonical rules JSON.
    pub content_hash: String,
    /// Service-owned serialised `RulesRevisionContent`. Opaque to storage.
    pub rules_json: String,
    pub status: RevisionStatus,
    pub source: RulesRevisionSource,
    /// IPC correlation id of the request that created this revision.
    pub correlation_id: String,
    /// Unix epoch seconds (`INTEGER` column).
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub superseded_at: Option<i64>,
    pub superseded_by: Option<String>,
    pub rejected_reason: Option<String>,
    pub review_summary_json: Option<String>,
    pub risk_level: Option<RiskLevel>,
}

/// A [`RevisionRecord`] paired with its HMAC verification outcome, as
/// returned by [`RevisionsRepository::activation_history_for`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHistoryEntry {
    pub record: RevisionRecord,
    pub verification: crate::revision_hmac::HmacVerification,
}

/// One row from the `active_revision_pointer` singleton table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRevisionPointer {
    pub revision_id: String,
    pub activated_at: i64,
    /// Links to `apply_snapshots.attempt_id` while a Phase 2 apply is in
    /// flight. Cleared by Phase 3a commit on success.
    pub apply_attempt_id: Option<String>,
}

// ── RiskLevel TEXT helpers ────────────────────────────────────────────────────

/// `Display` on [`RiskLevel`] already emits the slug, including
/// `"critical"`. The schema CHECK on `revisions.risk_level` accepts all
/// four values.
fn risk_level_to_slug(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

/// Projects a pointer row onto the borrowed view the HMAC is computed over.
fn pointer_fields<'a>(
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

/// Projects a `RevisionRecord` onto the borrowed view used by
/// [`crate::revision_hmac`]. All `Option<String>` fields are surfaced as
/// `Option<&str>` borrows so the HMAC computation doesn't allocate.
///
/// The `principal` partition key is supplied separately (it is not a
/// field of [`RevisionRecord`], which describes a revision's content
/// independently of which user owns it) and folded into the HMAC.
fn record_to_row_fields<'a>(
    principal: &'a str,
    record: &'a RevisionRecord,
) -> crate::revision_hmac::RowFields<'a> {
    crate::revision_hmac::RowFields {
        principal,
        revision_id: &record.revision_id,
        content_hash: &record.content_hash,
        rules_json: &record.rules_json,
        status: record.status.as_slug(),
        source: record.source.as_slug(),
        correlation_id: &record.correlation_id,
        created_at: record.created_at,
        activated_at: record.activated_at,
        superseded_at: record.superseded_at,
        superseded_by: record.superseded_by.as_deref(),
        rejected_reason: record.rejected_reason.as_deref(),
        review_summary_json: record.review_summary_json.as_deref(),
        risk_level: record.risk_level.map(risk_level_to_slug),
    }
}

fn risk_level_from_slug(s: &str) -> Option<RiskLevel> {
    match s {
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        "critical" => Some(RiskLevel::Critical),
        _ => None,
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

/// Synchronous repository for the `revisions` and `active_revision_pointer`
/// tables. Borrows an open connection.
///
/// The optional `signing_key` enables tamper detection on the `row_hmac`
/// column added in v11. When set, every
/// `insert_candidate` computes a fresh HMAC and persists it
/// alongside the row; `read_verified` / `re_sign_all` query and
/// repair the column. When `None` (back-compat default), the row is
/// inserted with the empty-blob default and `read_verified` flags
/// it as `Unsigned`. Existing read methods that don't return a
/// verification do NOT consult the column — the integration is
/// opt-in for callers ready to handle three-way verification.
pub struct RevisionsRepository<'c> {
    conn: &'c Connection,
    signing_key: Option<Vec<u8>>,
}

/// What a bulk re-sign did. `adopted_tampered` names the rows whose stored
/// signature did NOT match before being replaced — the ones where re-signing
/// legitimised an edit nobody here made.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReSignReport {
    pub re_signed: usize,
    pub adopted_tampered: Vec<String>,
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
    fn key(&self) -> Option<&[u8]> {
        self.signing_key.as_deref()
    }

    // ── Inserts / lookups ────────────────────────────────────────────────────

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

    // ── Status transitions ───────────────────────────────────────────────────

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

    // ── Active pointer (singleton) ───────────────────────────────────────────

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

    /// Sign one pointer row, or the empty blob when the repository has no key.
    fn pointer_hmac(&self, principal: &str, pointer: &ActiveRevisionPointer) -> Vec<u8> {
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

    // ── Orphaned-candidate sweep ──────────────────────────────────────────────

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

    // ── Retention pruning ────────────────────────────────────────────────────

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

/// Summary returned by [`RevisionsRepository::prune_by_retention`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionPruneSummary {
    pub superseded_dropped: usize,
    pub rejected_dropped: usize,
    pub rolledback_dropped: usize,
}

impl RetentionPruneSummary {
    pub fn total(&self) -> usize {
        self.superseded_dropped + self.rejected_dropped + self.rolledback_dropped
    }
}

// ── Row mapper ────────────────────────────────────────────────────────────────

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevisionRecord> {
    let status_slug: String = row.get(3)?;
    let source_slug: String = row.get(4)?;
    let risk_slug: Option<String> = row.get(12)?;

    let status = RevisionStatus::from_slug(&status_slug).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            format!("unknown revision status slug: {status_slug:?}").into(),
        )
    })?;
    let source = RulesRevisionSource::from_slug(&source_slug).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            format!("unknown revision source slug: {source_slug:?}").into(),
        )
    })?;
    let risk_level = match risk_slug.as_deref() {
        None => None,
        Some(s) => Some(risk_level_from_slug(s).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                format!("unknown risk_level slug: {s:?}").into(),
            )
        })?),
    };

    Ok(RevisionRecord {
        revision_id: row.get(0)?,
        content_hash: row.get(1)?,
        rules_json: row.get(2)?,
        status,
        source,
        correlation_id: row.get(5)?,
        created_at: row.get(6)?,
        activated_at: row.get(7)?,
        superseded_at: row.get(8)?,
        superseded_by: row.get(9)?,
        rejected_reason: row.get(10)?,
        review_summary_json: row.get(11)?,
        risk_level,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

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
    fn row_with_principal_and_hmac(
        &self,
        revision_id: &str,
    ) -> StorageResult<Option<(String, RevisionRecord, Vec<u8>)>> {
        // `principal` is appended AFTER the 13 record columns and the
        // `row_hmac` blob so the shared `row_to_record` mapper (columns
        // 0..=12) and the v11 hmac index (13) stay valid.
        self.conn
            .query_row(
                "SELECT revision_id, content_hash, rules_json, status, source,
                        correlation_id, created_at, activated_at, superseded_at,
                        superseded_by, rejected_reason, review_summary_json, risk_level,
                        row_hmac, principal
                 FROM revisions WHERE revision_id = ?1",
                params![revision_id],
                |row| {
                    let rec = row_to_record(row)?;
                    let hmac: Vec<u8> = row.get(13)?;
                    let principal: String = row.get(14)?;
                    Ok((principal, rec, hmac))
                },
            )
            .optional()
            .map_err(|e| {
                StorageError::Internal(format!("revisions row_with_principal_and_hmac: {e}"))
            })
    }

    /// Recompute and persist the HMAC for one row. Used after every
    /// UPDATE that changes a signed column and by
    /// the ack-flow re-signing helper. No-op when the repository
    /// has no signing key (back-compat).
    pub fn re_sign_row(&self, revision_id: &str) -> StorageResult<()> {
        let Some(key) = self.key() else {
            return Ok(());
        };
        let Some((principal, record, _stored)) = self.row_with_principal_and_hmac(revision_id)?
        else {
            return Ok(());
        };
        let fields = record_to_row_fields(&principal, &record);
        let hmac = crate::revision_hmac::compute_hmac(&fields, key).to_vec();
        self.conn
            .execute(
                "UPDATE revisions SET row_hmac = ?1 WHERE revision_id = ?2",
                params![hmac, revision_id],
            )
            .map_err(|e| StorageError::Internal(format!("revisions re_sign_row: {e}")))?;
        Ok(())
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
    pub fn re_sign_all(&self) -> StorageResult<usize> {
        if self.key().is_none() {
            return Ok(0);
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
        let mut signed = 0usize;
        for id in &ids {
            self.re_sign_row(id)?;
            signed += 1;
        }
        Ok(signed)
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
            self.conn
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
        self.conn
            .execute(
                "INSERT INTO active_revision_pointer
                 (principal, revision_id, activated_at, apply_attempt_id)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(principal) DO UPDATE SET
                     revision_id = excluded.revision_id,
                     activated_at = excluded.activated_at,
                     apply_attempt_id = excluded.apply_attempt_id",
                params![
                    principal,
                    pointer.revision_id,
                    pointer.activated_at,
                    pointer.apply_attempt_id,
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

        let rejected = self
            .conn
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
        let mut total = RetentionPruneSummary::default();
        for principal in self.distinct_principals()? {
            let s = self.prune_by_retention_for(&principal, settings, now_secs)?;
            total.superseded_dropped += s.superseded_dropped;
            total.rejected_dropped += s.rejected_dropped;
            total.rolledback_dropped += s.rolledback_dropped;
        }
        Ok(total)
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
        let sql = match protect_id {
            Some(_) => format!(
                "DELETE FROM revisions
                 WHERE principal = ?1 AND status = ?2 AND {time_col} IS NOT NULL
                       AND {time_col} < ?3
                       AND revision_id != ?4"
            ),
            None => format!(
                "DELETE FROM revisions
                 WHERE principal = ?1 AND status = ?2 AND {time_col} IS NOT NULL
                       AND {time_col} < ?3"
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
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;
    use crate::retention_settings::RetentionSettings;

    fn open_state_db(dir: &tempfile::TempDir) -> Connection {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    fn sample_record(id: &str, hash: &str) -> RevisionRecord {
        RevisionRecord {
            revision_id: id.to_string(),
            content_hash: hash.to_string(),
            rules_json: "{}".to_string(),
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr-123".to_string(),
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: Some(RiskLevel::Low),
        }
    }

    #[test]
    fn insert_candidate_creates_row_with_candidate_status() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        let rec = sample_record("rev-001", "hash-001");
        repo.insert_candidate(&rec).expect("insert");

        let loaded = repo.get_by_id("rev-001").expect("get").expect("present");
        assert_eq!(loaded.revision_id, "rev-001");
        assert_eq!(loaded.status, RevisionStatus::Candidate);
        assert_eq!(loaded.source, RulesRevisionSource::GuiRulesEdit);
        assert_eq!(loaded.risk_level, Some(RiskLevel::Low));
        assert!(loaded.activated_at.is_none());
    }

    #[test]
    fn insert_rejects_empty_revision_id() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        let mut rec = sample_record("", "hash");
        rec.revision_id.clear();
        assert!(repo.insert_candidate(&rec).is_err());
    }

    #[test]
    fn find_by_content_hash_returns_inserted_revision() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        let rec = sample_record("rev-002", "hash-xyz");
        repo.insert_candidate(&rec).expect("insert");

        let found = repo
            .find_by_content_hash("hash-xyz")
            .expect("query")
            .expect("present");
        assert_eq!(found.revision_id, "rev-002");
    }

    #[test]
    fn find_by_content_hash_unknown_returns_none() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        assert!(repo
            .find_by_content_hash("never-seen")
            .expect("query")
            .is_none());
    }

    #[test]
    fn mark_apply_succeeded_promotes_candidate_to_active_no_previous() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate(&sample_record("rev-100", "h-100"))
            .expect("insert");
        repo.mark_apply_succeeded("rev-100", None, 1_700_001_000)
            .expect("activate");

        let active = repo.get_active().expect("query").expect("present");
        assert_eq!(active.revision_id, "rev-100");
        assert_eq!(active.status, RevisionStatus::Active);
        assert_eq!(active.activated_at, Some(1_700_001_000));
    }

    #[test]
    fn mark_apply_succeeded_supersedes_previous_active() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // First activation.
        repo.insert_candidate(&sample_record("rev-A", "h-A"))
            .expect("insert A");
        repo.mark_apply_succeeded("rev-A", None, 1_700_000_100)
            .expect("activate A");

        // Second activation supersedes A.
        repo.insert_candidate(&sample_record("rev-B", "h-B"))
            .expect("insert B");
        repo.mark_apply_succeeded("rev-B", Some("rev-A"), 1_700_000_200)
            .expect("activate B");

        let active = repo.get_active().expect("query").expect("present");
        assert_eq!(active.revision_id, "rev-B");

        let previous = repo.get_by_id("rev-A").expect("query").expect("present");
        assert_eq!(previous.status, RevisionStatus::Superseded);
        assert_eq!(previous.superseded_at, Some(1_700_000_200));
        assert_eq!(previous.superseded_by, Some("rev-B".to_string()));
    }

    #[test]
    fn partial_unique_index_blocks_double_active_same_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);

        // Bypass the repository and try to insert a second active row for
        // the SAME principal directly.
        conn.execute(
            "INSERT INTO revisions
             (principal, revision_id, content_hash, rules_json, status, source,
              correlation_id, created_at)
             VALUES ('S-1-5-21-A', 'rev-1', 'h-1', '{}', 'active', 'gui-rules-edit', 'c-1', 0)",
            [],
        )
        .expect("first active");

        let result = conn.execute(
            "INSERT INTO revisions
             (principal, revision_id, content_hash, rules_json, status, source,
              correlation_id, created_at)
             VALUES ('S-1-5-21-A', 'rev-2', 'h-2', '{}', 'active', 'gui-rules-edit', 'c-2', 0)",
            [],
        );
        assert!(
            result.is_err(),
            "per-principal partial unique index must reject a second active \
             revision for the same principal"
        );
    }

    #[test]
    fn two_principals_can_each_have_an_active_revision() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a", "h-a"))
            .expect("insert A");
        repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a", None, 100)
            .expect("activate A");

        repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
            .expect("insert B");
        repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 100)
            .expect("activate B");

        // Each principal sees its own active revision; neither leaks into
        // the other.
        assert_eq!(
            repo.get_active_for("S-1-5-21-A")
                .expect("a")
                .expect("present")
                .revision_id,
            "rev-a"
        );
        assert_eq!(
            repo.get_active_for("S-1-5-21-B")
                .expect("b")
                .expect("present")
                .revision_id,
            "rev-b"
        );
        // The baseline principal has nothing.
        assert!(repo
            .get_active_for(BASELINE_PRINCIPAL)
            .expect("baseline")
            .is_none());
    }

    #[test]
    fn reject_orphaned_candidates_rejects_across_principals_leaves_active_untouched() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // An active revision for the baseline principal — must survive the
        // sweep untouched.
        repo.insert_candidate(&sample_record("rev-active", "h-active"))
            .expect("insert active");
        repo.mark_apply_succeeded("rev-active", None, 100)
            .expect("activate");

        // Two orphaned candidates left behind by a simulated hard kill, one
        // per principal.
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-orphan-a", "h-orphan-a"))
            .expect("insert orphan A");
        repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-orphan-b", "h-orphan-b"))
            .expect("insert orphan B");

        let rejected = repo
            .reject_orphaned_candidates("interrupted-before-activation (service restart)", 12345)
            .expect("sweep");
        assert_eq!(rejected, 2);

        let orphan_a = repo
            .get_by_id("rev-orphan-a")
            .expect("query")
            .expect("present");
        assert_eq!(orphan_a.status, RevisionStatus::Rejected);
        assert_eq!(
            orphan_a.rejected_reason.as_deref(),
            Some("interrupted-before-activation (service restart)")
        );

        let orphan_b = repo
            .get_by_id("rev-orphan-b")
            .expect("query")
            .expect("present");
        assert_eq!(orphan_b.status, RevisionStatus::Rejected);
        assert_eq!(
            orphan_b.rejected_reason.as_deref(),
            Some("interrupted-before-activation (service restart)")
        );

        // The active revision was never touched.
        let active = repo.get_active().expect("query").expect("present");
        assert_eq!(active.revision_id, "rev-active");

        // Re-running the sweep finds nothing left to reject.
        let rejected_again = repo
            .reject_orphaned_candidates("interrupted-before-activation (service restart)", 99999)
            .expect("sweep again");
        assert_eq!(rejected_again, 0);
    }

    #[test]
    fn reject_orphaned_candidates_without_key_skips_signed_rows() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);

        let signed = RevisionsRepository::with_signing_key(&conn, hmac_key());
        signed
            .insert_candidate(&sample_record("rev-signed", "h-signed"))
            .expect("insert signed");
        let unsigned = RevisionsRepository::new(&conn);
        unsigned
            .insert_candidate(&sample_record("rev-unsigned", "h-unsigned"))
            .expect("insert unsigned");

        // Keyless sweep: only the unsigned candidate may be touched.
        let rejected = unsigned
            .reject_orphaned_candidates("interrupted-before-activation (service restart)", 1)
            .expect("keyless sweep");
        assert_eq!(rejected, 1);
        let signed_row = signed
            .get_by_id("rev-signed")
            .expect("query")
            .expect("present");
        assert_eq!(signed_row.status, RevisionStatus::Candidate);
        let unsigned_row = signed
            .get_by_id("rev-unsigned")
            .expect("query")
            .expect("present");
        assert_eq!(unsigned_row.status, RevisionStatus::Rejected);

        // The signed row still verifies clean — the keyless sweep must
        // not have staled its HMAC.
        assert_eq!(
            signed.verify_row_hmac("rev-signed").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
        );
    }

    #[test]
    fn reject_orphaned_candidates_with_key_rejects_and_re_signs() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
        repo.insert_candidate(&sample_record("rev-signed", "h-signed"))
            .expect("insert signed");

        let rejected = repo
            .reject_orphaned_candidates("interrupted-before-activation (service restart)", 1)
            .expect("keyed sweep");
        assert_eq!(rejected, 1);

        let row = repo
            .get_by_id("rev-signed")
            .expect("query")
            .expect("present");
        assert_eq!(row.status, RevisionStatus::Rejected);
        // The status flip was re-signed: the row must NOT read as
        // tampered on the next integrity scan.
        assert_eq!(
            repo.verify_row_hmac("rev-signed").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
        );
    }

    #[test]
    fn delete_all_revisions_for_clears_principal_and_resumes_read_through() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // Baseline has an active revision; A diverged with its own.
        repo.insert_candidate_for(BASELINE_PRINCIPAL, &sample_record("base", "h-base"))
            .expect("insert baseline");
        repo.mark_apply_succeeded_for(BASELINE_PRINCIPAL, "base", None, 100)
            .expect("activate baseline");
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a1", "h-a1"))
            .expect("insert A1");
        repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a1", None, 100)
            .expect("activate A1");
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a2", "h-a2"))
            .expect("insert A2 (candidate)");
        repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
            .expect("insert B");
        repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 100)
            .expect("activate B");

        // Reset A: both its active and its candidate rows go.
        let deleted = repo
            .delete_all_revisions_for("S-1-5-21-A")
            .expect("delete A");
        assert_eq!(deleted, 2, "both of A's revisions must be deleted");

        // A has no own revision and no pointer → read-through resumes.
        assert!(repo.get_active_for("S-1-5-21-A").expect("a").is_none());
        assert!(repo
            .get_active_pointer_for("S-1-5-21-A")
            .expect("a ptr")
            .is_none());
        // B and baseline are untouched.
        assert_eq!(
            repo.get_active_for("S-1-5-21-B")
                .expect("b")
                .expect("present")
                .revision_id,
            "rev-b"
        );
        assert_eq!(
            repo.get_active_for(BASELINE_PRINCIPAL)
                .expect("base")
                .expect("present")
                .revision_id,
            "base"
        );
    }

    #[test]
    fn delete_all_revisions_for_refuses_baseline() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        let err = repo
            .delete_all_revisions_for(BASELINE_PRINCIPAL)
            .expect_err("must refuse baseline");
        assert!(matches!(err, StorageError::Internal(_)));
    }

    #[test]
    fn mark_apply_failed_marks_candidate_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate(&sample_record("rev-fail", "h-fail"))
            .expect("insert");
        repo.mark_apply_failed("rev-fail", "WFP failed on SID-A", 1_700_001_500)
            .expect("reject");

        let rec = repo.get_by_id("rev-fail").expect("query").expect("present");
        assert_eq!(rec.status, RevisionStatus::Rejected);
        assert_eq!(rec.rejected_reason, Some("WFP failed on SID-A".to_string()));
    }

    #[test]
    fn mark_apply_failed_on_non_candidate_errors() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate(&sample_record("rev-x", "h-x"))
            .expect("insert");
        repo.mark_apply_succeeded("rev-x", None, 1)
            .expect("activate");
        // Now active — apply_failed should error rather than silently no-op.
        assert!(repo.mark_apply_failed("rev-x", "reason", 2).is_err());
    }

    #[test]
    fn last_known_good_is_most_recent_superseded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // Activate three in sequence so that two are superseded.
        repo.insert_candidate(&sample_record("rev-a", "h-a"))
            .expect("insert a");
        repo.mark_apply_succeeded("rev-a", None, 100).expect("a");

        repo.insert_candidate(&sample_record("rev-b", "h-b"))
            .expect("insert b");
        repo.mark_apply_succeeded("rev-b", Some("rev-a"), 200)
            .expect("b");

        repo.insert_candidate(&sample_record("rev-c", "h-c"))
            .expect("insert c");
        repo.mark_apply_succeeded("rev-c", Some("rev-b"), 300)
            .expect("c");

        let lkg = repo.last_known_good().expect("query").expect("present");
        assert_eq!(lkg.revision_id, "rev-b"); // most recently superseded
    }

    #[test]
    fn last_known_good_none_when_no_superseded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        assert!(repo.last_known_good().expect("query").is_none());

        // Even one Active revision yields no LKG.
        repo.insert_candidate(&sample_record("rev-only", "h-only"))
            .expect("insert");
        repo.mark_apply_succeeded("rev-only", None, 1).expect("act");
        assert!(repo.last_known_good().expect("query").is_none());
    }

    #[test]
    fn mark_rolled_back_transitions_active_to_rolled_back() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate(&sample_record("rev-r", "h-r"))
            .expect("insert");
        repo.mark_apply_succeeded("rev-r", None, 1)
            .expect("activate");
        repo.mark_rolled_back("rev-r", 99).expect("rollback");

        let rec = repo.get_by_id("rev-r").expect("query").expect("present");
        assert_eq!(rec.status, RevisionStatus::RolledBack);
        assert_eq!(rec.superseded_at, Some(99));
    }

    #[test]
    fn active_pointer_set_get_clear_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        assert!(repo.get_active_pointer().expect("query").is_none());

        // Pointer references revisions(revision_id), so the rows must exist
        // first — `PRAGMA foreign_keys = ON` rejects dangling references.
        repo.insert_candidate(&sample_record("rev-A", "h-A"))
            .expect("insert A");
        repo.insert_candidate(&sample_record("rev-B", "h-B"))
            .expect("insert B");

        let p = ActiveRevisionPointer {
            revision_id: "rev-A".to_string(),
            activated_at: 1_700_000_777,
            apply_attempt_id: Some("att-9".to_string()),
        };
        repo.set_active_pointer(&p).expect("set");
        let loaded = repo.get_active_pointer().expect("query").expect("present");
        assert_eq!(loaded, p);

        // Update — should replace, not duplicate.
        let p2 = ActiveRevisionPointer {
            revision_id: "rev-B".to_string(),
            activated_at: 1_700_000_999,
            apply_attempt_id: None,
        };
        repo.set_active_pointer(&p2).expect("set 2");
        let loaded2 = repo.get_active_pointer().expect("query").expect("present");
        assert_eq!(loaded2, p2);

        repo.clear_active_pointer().expect("clear");
        assert!(repo.get_active_pointer().expect("query").is_none());
    }

    // ── Retention pruning ────────────────────────────────────────────────────

    fn drive_to_status(repo: &RevisionsRepository<'_>, id: &str, hash: &str) {
        repo.insert_candidate(&sample_record(id, hash))
            .expect("insert");
    }

    #[test]
    fn prune_drops_old_superseded_when_pin_lkg_protects_most_recent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        // Active for the chain.
        drive_to_status(&repo, "rev-A", "h-A");
        repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
        drive_to_status(&repo, "rev-B", "h-B");
        repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
            .expect("b");
        drive_to_status(&repo, "rev-C", "h-C");
        repo.mark_apply_succeeded("rev-C", Some("rev-B"), 300)
            .expect("c");
        // Now rev-A and rev-B are Superseded, rev-C is Active. LKG = rev-B.

        // Settings whose threshold falls between A's and B's
        // superseded_at: A was superseded at 200, B at 300.
        // superseded_days=7 → cutoff = now - 7*86400.
        // Pick now=200 + 7*86400 + 1 → cutoff = 201. A (200) < 201 → drop.
        // B (300) > 201 → keep.
        let settings = RetentionSettings {
            superseded_days: 7,
            ..RetentionSettings::DEFAULT
        };
        let now = 200 + 7 * 86_400 + 1;
        let summary = repo.prune_by_retention(&settings, now).expect("prune");
        assert_eq!(summary.superseded_dropped, 1);
        assert!(repo.get_by_id("rev-A").expect("query").is_none());
        assert!(repo.get_by_id("rev-B").expect("query").is_some());
        assert!(repo.get_by_id("rev-C").expect("query").is_some());
    }

    #[test]
    fn prune_protects_lkg_even_when_age_exceeds_threshold() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        drive_to_status(&repo, "rev-A", "h-A");
        repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
        drive_to_status(&repo, "rev-B", "h-B");
        repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
            .expect("b");
        // rev-A is now Superseded (the LKG).

        // Threshold far in the future — without pin_lkg, A would be dropped.
        let settings = RetentionSettings {
            superseded_days: 7,
            pin_lkg: true,
            ..RetentionSettings::DEFAULT
        };
        let now = 100 + 1_000_000_000;
        let summary = repo.prune_by_retention(&settings, now).expect("prune");
        assert_eq!(summary.superseded_dropped, 0);
        assert!(repo.get_by_id("rev-A").expect("query").is_some());
    }

    #[test]
    fn prune_drops_lkg_when_pin_lkg_disabled_and_threshold_passed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        drive_to_status(&repo, "rev-A", "h-A");
        repo.mark_apply_succeeded("rev-A", None, 100).expect("a");
        drive_to_status(&repo, "rev-B", "h-B");
        repo.mark_apply_succeeded("rev-B", Some("rev-A"), 200)
            .expect("b");
        let settings = RetentionSettings {
            superseded_days: 7,
            pin_lkg: false,
            ..RetentionSettings::DEFAULT
        };
        let now = 100 + 8 * 86_400;
        let summary = repo.prune_by_retention(&settings, now).expect("prune");
        assert_eq!(summary.superseded_dropped, 1);
        assert!(repo.get_by_id("rev-A").expect("query").is_none());
    }

    #[test]
    fn prune_count_cap_drops_oldest_above_cap() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        // Build a chain of 25 revisions; 24 of them end up Superseded.
        // The first activate has no previous, so each subsequent one
        // supersedes the prior. We use cap=20 (legal min) with pin_lkg
        // so the LKG (most recent superseded) is protected.
        let mut prev: Option<String> = None;
        for i in 0..25 {
            let id = format!("rev-{i:02}");
            drive_to_status(&repo, &id, &format!("h-{i:02}"));
            repo.mark_apply_succeeded(&id, prev.as_deref(), (i * 10) as i64)
                .expect("succ");
            prev = Some(id);
        }
        // Now 24 superseded + 1 active.
        let settings = RetentionSettings {
            // Force the age sweep to be a no-op so we observe the cap pass alone.
            superseded_days: 365,
            superseded_count_cap: 20,
            pin_lkg: true,
            ..RetentionSettings::DEFAULT
        };
        let summary = repo.prune_by_retention(&settings, 1_000).expect("prune");
        // 24 superseded → cap 20 → 4 dropped.
        assert_eq!(summary.superseded_dropped, 4);
        // Oldest 4 (rev-00..rev-03) gone.
        assert!(repo.get_by_id("rev-00").expect("query").is_none());
        assert!(repo.get_by_id("rev-03").expect("query").is_none());
        assert!(repo.get_by_id("rev-04").expect("query").is_some());
        // LKG (rev-23) still present.
        assert!(repo.get_by_id("rev-23").expect("query").is_some());
    }

    #[test]
    fn prune_drops_old_rejected_revisions() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        // Insert two candidates with different created_at.
        let mut old = sample_record("rev-rej-old", "h-old");
        old.created_at = 100;
        let mut new = sample_record("rev-rej-new", "h-new");
        new.created_at = 1_000_000;
        repo.insert_candidate(&old).expect("old");
        repo.insert_candidate(&new).expect("new");
        // Drive both to Rejected (mark_apply_failed updates status only,
        // not created_at).
        repo.mark_apply_failed("rev-rej-old", "fail", 0).expect("o");
        repo.mark_apply_failed("rev-rej-new", "fail", 0).expect("n");

        let settings = RetentionSettings {
            rejected_days: 7,
            ..RetentionSettings::DEFAULT
        };
        let now = 100 + 8 * 86_400;
        let summary = repo.prune_by_retention(&settings, now).expect("prune");
        assert_eq!(summary.rejected_dropped, 1);
        assert!(repo.get_by_id("rev-rej-old").expect("query").is_none());
        assert!(repo.get_by_id("rev-rej-new").expect("query").is_some());
    }

    #[test]
    fn prune_active_revision_is_never_touched() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        drive_to_status(&repo, "rev-act", "h-act");
        repo.mark_apply_succeeded("rev-act", None, 0).expect("act");

        // Even with aggressive retention, Active stays.
        let settings = RetentionSettings {
            superseded_days: 7,
            superseded_count_cap: 20,
            rejected_days: 1,
            rolledback_days: 1,
            rolledback_count_cap: 5,
            pin_lkg: false,
            ..RetentionSettings::DEFAULT
        };
        let _ = repo
            .prune_by_retention(&settings, 1_000_000_000)
            .expect("prune");
        assert!(repo.get_by_id("rev-act").expect("query").is_some());
    }

    #[test]
    fn prune_returns_summary_totals() {
        let summary = RetentionPruneSummary {
            superseded_dropped: 3,
            rejected_dropped: 2,
            rolledback_dropped: 1,
        };
        assert_eq!(summary.total(), 6);
    }

    #[test]
    fn active_pointer_rejects_dangling_revision_id() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        // No revisions inserted; FK must reject.
        let p = ActiveRevisionPointer {
            revision_id: "ghost".to_string(),
            activated_at: 1,
            apply_attempt_id: None,
        };
        assert!(repo.set_active_pointer(&p).is_err());
    }

    // ── row_hmac tamper detection ───────────────────────────────────────────

    fn hmac_key() -> Vec<u8> {
        vec![0x42u8; crate::revision_hmac::RECOMMENDED_KEY_BYTE_LEN]
    }

    #[test]
    fn insert_without_key_leaves_row_unsigned() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        repo.insert_candidate(&sample_record("rev-x", "h-x"))
            .expect("insert");
        let (_rec, hmac) = repo.get_with_hmac("rev-x").expect("get").expect("present");
        assert!(hmac.is_empty(), "no key → empty default blob");

        // Verifying via the no-key repo collapses to Unsigned even
        // when stored blob would be non-empty.
        assert_eq!(
            repo.verify_row_hmac("rev-x").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Unsigned),
        );
    }

    #[test]
    fn insert_with_key_persists_hmac_and_verifies() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        repo.insert_candidate(&sample_record("rev-y", "h-y"))
            .expect("insert");
        let (_rec, hmac) = repo.get_with_hmac("rev-y").expect("get").expect("present");
        assert_eq!(
            hmac.len(),
            crate::revision_hmac::HMAC_BYTE_LEN,
            "HMAC must be 32 bytes when key set"
        );
        assert_eq!(
            repo.verify_row_hmac("rev-y").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
        );
    }

    #[test]
    fn external_tamper_of_rules_json_is_detected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        repo.insert_candidate(&sample_record("rev-t", "h-t"))
            .expect("insert");

        // Simulate an external admin / rogue process opening the DB
        // directly and rewriting `rules_json` outside the service's
        // write path. The repository never knows about this UPDATE,
        // so the stored `row_hmac` becomes invalid.
        conn.execute(
            "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
            params![r#"{"tampered":true}"#, "rev-t"],
        )
        .expect("tamper UPDATE");

        assert_eq!(
            repo.verify_row_hmac("rev-t").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Tampered),
        );
    }

    #[test]
    fn verify_with_different_key_is_tampered() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);

        // Sign with key_a …
        let repo_a = RevisionsRepository::with_signing_key(&conn, vec![0x42u8; 32]);
        repo_a
            .insert_candidate(&sample_record("rev-k", "h-k"))
            .expect("insert");

        // … verify with key_b. Same row, but the HMAC computed by
        // key_b will not match what key_a produced.
        let repo_b = RevisionsRepository::with_signing_key(&conn, vec![0x43u8; 32]);
        assert_eq!(
            repo_b.verify_row_hmac("rev-k").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Tampered),
        );
    }

    #[test]
    fn re_sign_row_repairs_after_status_change() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        repo.insert_candidate(&sample_record("rev-s", "h-s"))
            .expect("insert");
        // Activate via the standard path. The UPDATE invalidates the
        // HMAC because activation changes both `status` and
        // `activated_at`. Until the coordinator wires re-sign in
        // automatically, we call it manually.
        repo.mark_apply_succeeded("rev-s", None, 1_700_001_000)
            .expect("activate");
        assert_eq!(
            repo.verify_row_hmac("rev-s").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Tampered),
            "post-activate row diverges from insert-time HMAC"
        );

        repo.re_sign_row("rev-s").expect("re-sign");
        assert_eq!(
            repo.verify_row_hmac("rev-s").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
            "re-sign repairs the HMAC against the current row"
        );
    }

    #[test]
    fn re_sign_all_walks_every_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        // Insert three rows WITHOUT a key (simulating legacy / lazy-
        // backfill state after a v10→v11 migration).
        let unsigned = RevisionsRepository::new(&conn);
        for i in 0..3 {
            unsigned
                .insert_candidate(&sample_record(&format!("rev-{i}"), &format!("h-{i}")))
                .expect("insert");
        }
        // All three should be Unsigned.
        let with_key = RevisionsRepository::with_signing_key(&conn, hmac_key());
        for i in 0..3 {
            assert_eq!(
                with_key
                    .verify_row_hmac(&format!("rev-{i}"))
                    .expect("verify"),
                Some(crate::revision_hmac::HmacVerification::Unsigned),
            );
        }
        // Re-sign all in one pass …
        assert_eq!(with_key.re_sign_all().expect("re-sign-all"), 3);
        // … and every row is now Verified.
        for i in 0..3 {
            assert_eq!(
                with_key
                    .verify_row_hmac(&format!("rev-{i}"))
                    .expect("verify"),
                Some(crate::revision_hmac::HmacVerification::Verified),
            );
        }
    }

    #[test]
    fn re_sign_all_without_key_is_noop() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        repo.insert_candidate(&sample_record("rev-noop", "h-noop"))
            .expect("insert");
        assert_eq!(repo.re_sign_all().expect("re-sign-all"), 0);
    }

    #[test]
    fn count_reflects_inserts() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);
        assert_eq!(repo.count().expect("count"), 0);
        repo.insert_candidate(&sample_record("rev-a", "h-a"))
            .expect("insert");
        repo.insert_candidate(&sample_record("rev-b", "h-b"))
            .expect("insert");
        assert_eq!(repo.count().expect("count"), 2);
    }

    #[test]
    fn verify_all_classifies_each_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        // rev-ok: signed and intact → Verified.
        repo.insert_candidate(&sample_record("rev-ok", "h-ok"))
            .expect("insert");
        // rev-leg: legacy row inserted without a key → Unsigned.
        RevisionsRepository::new(&conn)
            .insert_candidate(&sample_record("rev-leg", "h-leg"))
            .expect("insert");
        // rev-bad: signed, then externally mutated → Tampered.
        repo.insert_candidate(&sample_record("rev-bad", "h-bad"))
            .expect("insert");
        conn.execute(
            "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
            params![r#"{"tampered":true}"#, "rev-bad"],
        )
        .expect("tamper");

        let results = repo.verify_all().expect("verify_all");
        let by_id: std::collections::HashMap<_, _> = results.into_iter().collect();
        use crate::revision_hmac::HmacVerification::*;
        assert_eq!(by_id.get("rev-ok"), Some(&Verified));
        assert_eq!(by_id.get("rev-leg"), Some(&Unsigned));
        assert_eq!(by_id.get("rev-bad"), Some(&Tampered));
    }

    // ── activation_history_for ───────────────────────────────────────────────

    #[test]
    fn activation_history_orders_active_first_then_by_recency() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
        let principal = "S-1-5-21-hist";

        repo.insert_candidate_for(principal, &sample_record("rev-1", "h-1"))
            .expect("insert 1");
        repo.mark_apply_succeeded_for(principal, "rev-1", None, 1_700_000_100)
            .expect("activate 1");
        repo.re_sign_row("rev-1").expect("re-sign 1");

        repo.insert_candidate_for(principal, &sample_record("rev-2", "h-2"))
            .expect("insert 2");
        repo.mark_apply_succeeded_for(principal, "rev-2", Some("rev-1"), 1_700_000_200)
            .expect("activate 2");
        repo.re_sign_row("rev-1").expect("re-sign 1 (superseded)");
        repo.re_sign_row("rev-2").expect("re-sign 2");

        repo.insert_candidate_for(principal, &sample_record("rev-3", "h-3"))
            .expect("insert 3");
        repo.mark_apply_succeeded_for(principal, "rev-3", Some("rev-2"), 1_700_000_300)
            .expect("activate 3");
        repo.re_sign_row("rev-2").expect("re-sign 2 (superseded)");
        repo.re_sign_row("rev-3").expect("re-sign 3");

        let history = repo
            .activation_history_for(principal)
            .expect("activation_history_for");
        let ids: Vec<&str> = history
            .iter()
            .map(|e| e.record.revision_id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec!["rev-3", "rev-2", "rev-1"],
            "active first, then supersede-recency descending"
        );
        assert!(
            history
                .iter()
                .all(|e| e.verification == crate::revision_hmac::HmacVerification::Verified),
            "every row was (re)signed after its status change"
        );
    }

    #[test]
    fn activation_history_flags_tampered_active_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());
        let principal = "S-1-5-21-tamper";

        repo.insert_candidate_for(principal, &sample_record("rev-good", "h-good"))
            .expect("insert");
        repo.mark_apply_succeeded_for(principal, "rev-good", None, 1_700_000_000)
            .expect("activate");
        repo.re_sign_row("rev-good").expect("re-sign");

        // External mutation of the now-active row, bypassing the service.
        conn.execute(
            "UPDATE revisions SET rules_json = ?1 WHERE revision_id = ?2",
            params![r#"{"tampered":true}"#, "rev-good"],
        )
        .expect("tamper");

        let history = repo
            .activation_history_for(principal)
            .expect("activation_history_for");
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].verification,
            crate::revision_hmac::HmacVerification::Tampered
        );
    }

    #[test]
    fn activation_history_scoped_by_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-a", "h-a"))
            .expect("insert a");
        repo.mark_apply_succeeded_for("S-1-5-21-A", "rev-a", None, 1_700_000_000)
            .expect("activate a");

        repo.insert_candidate_for("S-1-5-21-B", &sample_record("rev-b", "h-b"))
            .expect("insert b");
        repo.mark_apply_succeeded_for("S-1-5-21-B", "rev-b", None, 1_700_000_000)
            .expect("activate b");

        let history_a = repo
            .activation_history_for("S-1-5-21-A")
            .expect("history a");
        assert_eq!(history_a.len(), 1);
        assert_eq!(history_a[0].record.revision_id, "rev-a");
    }

    #[test]
    fn activation_history_without_key_reports_unsigned() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let signed = RevisionsRepository::with_signing_key(&conn, hmac_key());
        let principal = "S-1-5-21-nokey";
        signed
            .insert_candidate_for(principal, &sample_record("rev-x", "h-x"))
            .expect("insert");
        signed
            .mark_apply_succeeded_for(principal, "rev-x", None, 1_700_000_000)
            .expect("activate");

        let unsigned = RevisionsRepository::new(&conn);
        let history = unsigned.activation_history_for(principal).expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].verification,
            crate::revision_hmac::HmacVerification::Unsigned
        );
    }

    // ── per-principal isolation ─────────────────────────────────────────────

    #[test]
    fn baseline_shims_route_to_baseline_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // The no-principal shim writes under the baseline sentinel.
        repo.insert_candidate(&sample_record("rev-base", "h-base"))
            .expect("insert");
        assert!(repo
            .get_by_id_for(BASELINE_PRINCIPAL, "rev-base")
            .expect("scoped get")
            .is_some());
        // A different principal cannot see the baseline row by id.
        assert!(repo
            .get_by_id_for("S-1-5-21-X", "rev-base")
            .expect("scoped get other")
            .is_none());
    }

    #[test]
    fn activation_does_not_supersede_another_principals_active() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // A activates rev-a1, then rev-a2 (supersedes a1) — all within A.
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("a1", "ha1"))
            .expect("a1");
        repo.mark_apply_succeeded_for("S-1-5-21-A", "a1", None, 100)
            .expect("act a1");

        // B activates b1 in parallel.
        repo.insert_candidate_for("S-1-5-21-B", &sample_record("b1", "hb1"))
            .expect("b1");
        repo.mark_apply_succeeded_for("S-1-5-21-B", "b1", None, 110)
            .expect("act b1");

        // A's second activation supersedes ONLY a1, leaving b1 active.
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("a2", "ha2"))
            .expect("a2");
        repo.mark_apply_succeeded_for("S-1-5-21-A", "a2", Some("a1"), 200)
            .expect("act a2");

        assert_eq!(
            repo.get_by_id("a1").expect("a1").expect("present").status,
            RevisionStatus::Superseded
        );
        assert_eq!(
            repo.get_active_for("S-1-5-21-B")
                .expect("b active")
                .expect("present")
                .revision_id,
            "b1",
            "B's active revision must be untouched by A's activation"
        );
    }

    #[test]
    fn content_hash_dedup_is_per_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // Same content hash under two principals → two independent rows.
        repo.insert_candidate_for("S-1-5-21-A", &sample_record("a", "shared-hash"))
            .expect("a");
        repo.insert_candidate_for("S-1-5-21-B", &sample_record("b", "shared-hash"))
            .expect("b");

        assert_eq!(
            repo.find_by_content_hash_for("S-1-5-21-A", "shared-hash")
                .expect("a")
                .expect("present")
                .revision_id,
            "a"
        );
        assert_eq!(
            repo.find_by_content_hash_for("S-1-5-21-B", "shared-hash")
                .expect("b")
                .expect("present")
                .revision_id,
            "b"
        );
    }

    #[test]
    fn hmac_binds_the_principal_column() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::with_signing_key(&conn, hmac_key());

        repo.insert_candidate_for("S-1-5-21-A", &sample_record("rev-p", "h-p"))
            .expect("insert");
        assert_eq!(
            repo.verify_row_hmac("rev-p").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Verified),
        );

        // Re-home the row to a different principal outside the write path.
        // The HMAC was computed over the original principal, so the move
        // is detected as tampering.
        conn.execute(
            "UPDATE revisions SET principal = ?1 WHERE revision_id = ?2",
            params!["S-1-5-21-B", "rev-p"],
        )
        .expect("re-home");
        assert_eq!(
            repo.verify_row_hmac("rev-p").expect("verify"),
            Some(crate::revision_hmac::HmacVerification::Tampered),
            "moving a row to a different principal must invalidate its HMAC"
        );
    }

    #[test]
    fn prune_caps_are_per_principal() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RevisionsRepository::new(&conn);

        // Build a 25-revision superseded chain for EACH of two principals.
        for principal in ["S-1-5-21-A", "S-1-5-21-B"] {
            let mut prev: Option<String> = None;
            for i in 0..25 {
                let id = format!("{principal}-rev-{i:02}");
                repo.insert_candidate_for(principal, &sample_record(&id, &format!("h-{id}")))
                    .expect("insert");
                repo.mark_apply_succeeded_for(principal, &id, prev.as_deref(), (i * 10) as i64)
                    .expect("activate");
                prev = Some(id);
            }
        }
        // 24 superseded per principal. Cap 20, pin LKG → 4 dropped per
        // principal = 8 total.
        let settings = RetentionSettings {
            superseded_days: 365,
            superseded_count_cap: 20,
            pin_lkg: true,
            ..RetentionSettings::DEFAULT
        };
        let summary = repo.prune_by_retention(&settings, 1_000).expect("prune");
        assert_eq!(
            summary.superseded_dropped, 8,
            "each principal's cap is enforced independently"
        );
        // Each principal still has its active revision.
        assert!(repo.get_active_for("S-1-5-21-A").expect("a").is_some());
        assert!(repo.get_active_for("S-1-5-21-B").expect("b").is_some());
    }
}

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

/// What a bulk re-sign did. `adopted_tampered` names the rows whose stored
/// signature did NOT match before being replaced — the ones where re-signing
/// legitimised an edit nobody here made.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReSignReport {
    pub re_signed: usize,
    pub adopted_tampered: Vec<String>,
}

mod pointer;
mod reads;
mod retention;
mod signing;
mod transitions;

// Re-exported so `revisions::tests` (a sibling of `signing`) can reach it
// through its `use super::*;`, matching the pre-split single-module layout.
#[cfg(test)]
use signing::pointer_fields;

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

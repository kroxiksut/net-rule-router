//! Production [`MergePreviewSource`] for the
//! `RulesMergePreview` read-only IPC op.
//!
//! Reconciles the caller's linked rules-file *text* with the SERVICE's active
//! revision. The service owns `nrr-domain`, so the merge core runs here:
//!
//! 1. Resolve the caller's active [`CanonicalRuleBook`] from
//!    `nrr_service_state.db` with per-SID read-through to the shared baseline
//!    (identical to [`crate::production_preset_exporter`] and the enforcement
//!    read path). No active revision ⇒ an empty book (all file rules become
//!    `file-only`).
//! 2. Parse + canonicalise `primary_text` / `secondary_text` via the DOMAIN
//!    parser ([`parse_rules_file`] + [`canonicalize_preset_rules`]) — NOT the
//!    raw `nrr_shared::preset_parser`, which does no normalisation, so its
//!    output would never pair with the already-canonical service rules by
//!    identity key.
//! 3. Merge with [`merge_rule_books_with_resolutions`] under the requested
//!    policy, applying any per-conflict picks.
//! 4. Encode the merged book to canonical rules-json (feeds the GUI's normal
//!    `startRulesReviewFlow`), and project the merge result into the wire DTO.
//!
//! The domain→DTO conversion lives here (not in `nrr-shared`, which must not
//! depend on `nrr-domain`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use nrr_domain::canonical::{CanonicalRule, CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::merge::{
    merge_rule_books_with_resolutions, ConflictRule, ConflictSide, MergeConflict, MergeOrigin,
    MergePolicy, MergeResult, MergedRuleEntry,
};
use nrr_domain::preset_canonicalize::canonicalize_preset_rules;
use nrr_domain::rules_file::{parse_rules_file, HostPlatform};
use nrr_domain::rules_json_codec;
use nrr_domain::rules_revision::RulesRevisionContent;
use nrr_shared::merge_dto::{
    ConflictResolutionDto, ConflictRuleDto, ConflictSideDto, MergeConflictDto, MergeOriginDto,
    MergePolicyDto, MergeResultDto, MergedRuleEntryDto,
};
use nrr_shared::rules_json;
use nrr_shared::RouteRole;
use nrr_storage::revisions::RevisionsRepository;
use rusqlite::Connection;

/// Produces a merge preview reconciling file text with the active revision.
pub trait MergePreviewSource: Send + Sync {
    /// Merge `primary_text` / `secondary_text` (the caller's linked bound
    /// files) against the caller's active revision under `policy`, applying
    /// `resolutions`.
    ///
    /// `principal` is the caller's Windows SID (or
    /// [`nrr_storage::BASELINE_PRINCIPAL`]); the active revision is resolved
    /// per-SID with read-through to the shared baseline.
    fn merge_preview(
        &self,
        principal: &str,
        primary_text: &str,
        secondary_text: &str,
        policy: MergePolicyDto,
        resolutions: &[ConflictResolutionDto],
        include_child_processes: bool,
    ) -> Result<MergeResultDto, MergePreviewError>;
}

/// Why a merge preview could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergePreviewError {
    /// State DB mutex is poisoned (another thread panicked while holding it).
    LockPoisoned,
    /// Storage layer returned an error reading the active revision.
    StorageError(String),
    /// The stored active revision's rules-json is not valid wire shape or
    /// fails codec semantics (schema version, IPv4 parse, etc.).
    ServiceDecodeError(String),
    /// The caller's file text has one or more rules that fail semantic
    /// canonicalisation (IDNA / IPv4 / bad glob / etc.).
    FileCanonicalizeRejected(String),
    /// The merged book could not be re-encoded to canonical rules-json.
    EncodeError(String),
}

impl std::fmt::Display for MergePreviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LockPoisoned => f.write_str("state DB mutex poisoned"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
            Self::ServiceDecodeError(e) => write!(f, "service revision decode error: {e}"),
            Self::FileCanonicalizeRejected(e) => write!(f, "file canonicalize rejected: {e}"),
            Self::EncodeError(e) => write!(f, "merged encode error: {e}"),
        }
    }
}

impl std::error::Error for MergePreviewError {}

/// Production [`MergePreviewSource`] backed by `nrr_service_state.db`.
pub struct ProductionMergePreviewSource {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionMergePreviewSource {
    /// Constructs a source reading the active revision from `conn`.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Resolve the caller's active [`CanonicalRuleBook`] (per-SID read-through
    /// to baseline). No active revision anywhere ⇒ an empty book.
    fn service_book(&self, principal: &str) -> Result<CanonicalRuleBook, MergePreviewError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| MergePreviewError::LockPoisoned)?;
        let repo = RevisionsRepository::new(&guard);
        let record = match repo
            .get_active_for(principal)
            .map_err(|e| MergePreviewError::StorageError(e.to_string()))?
        {
            Some(rec) => Some(rec),
            None if principal != nrr_storage::BASELINE_PRINCIPAL => repo
                .get_active_for(nrr_storage::BASELINE_PRINCIPAL)
                .map_err(|e| MergePreviewError::StorageError(e.to_string()))?,
            None => None,
        };
        match record {
            Some(rec) => {
                let dto = rules_json::from_canonical_string(&rec.rules_json).map_err(|e| {
                    MergePreviewError::ServiceDecodeError(format!("wire parse: {e}"))
                })?;
                let content = rules_json_codec::decode(dto).map_err(|e| {
                    MergePreviewError::ServiceDecodeError(format!("codec decode: {e}"))
                })?;
                Ok(content.rule_book)
            }
            None => Ok(CanonicalRuleBook::default()),
        }
    }
}

impl MergePreviewSource for ProductionMergePreviewSource {
    fn merge_preview(
        &self,
        principal: &str,
        primary_text: &str,
        secondary_text: &str,
        policy: MergePolicyDto,
        resolutions: &[ConflictResolutionDto],
        include_child_processes: bool,
    ) -> Result<MergeResultDto, MergePreviewError> {
        let service_book = self.service_book(principal)?;
        let file_book = CanonicalRuleBook {
            primary: canonicalize_side(primary_text, RouteRole::Primary, include_child_processes)?,
            secondary: canonicalize_side(
                secondary_text,
                RouteRole::Secondary,
                include_child_processes,
            )?,
        };

        let mut resolution_map: BTreeMap<String, ConflictSide> = BTreeMap::new();
        for r in resolutions {
            resolution_map.insert(r.identity_key.clone(), domain_side(r.side));
        }

        let policy_domain = MergePolicy::from_slug(policy.slug());
        let result = merge_rule_books_with_resolutions(
            &file_book,
            &service_book,
            policy_domain,
            &resolution_map,
        );

        to_result_dto(result, policy)
    }
}

/// Parse + canonicalise one bound file's text into a [`CanonicalRuleSet`].
///
/// Uses [`HostPlatform::compiled`] to mirror the import path exactly
/// (`production_mutation_executor::canonicalize_route_bytes`) — the service
/// revision was canonicalised the same way, so file rules pair with it by
/// identity key. On Windows (the only supported host) this is
/// `HostPlatform::Windows`.
fn canonicalize_side(
    text: &str,
    route: RouteRole,
    include_child_processes: bool,
) -> Result<CanonicalRuleSet, MergePreviewError> {
    let parsed = parse_rules_file(text);
    let outcome = canonicalize_preset_rules(
        &parsed,
        route,
        HostPlatform::compiled(),
        include_child_processes,
    );
    match outcome.rule_set() {
        Some(set) => Ok(set.clone()),
        None => Err(MergePreviewError::FileCanonicalizeRejected(format!(
            "{route:?} rules failed canonicalization"
        ))),
    }
}

/// Map a wire conflict side to the domain enum.
fn domain_side(side: ConflictSideDto) -> ConflictSide {
    match side {
        ConflictSideDto::File => ConflictSide::File,
        ConflictSideDto::Service => ConflictSide::Service,
        ConflictSideDto::Unresolved => ConflictSide::Unresolved,
    }
}

/// Map a domain conflict side to the wire enum.
fn wire_side(side: ConflictSide) -> ConflictSideDto {
    match side {
        ConflictSide::File => ConflictSideDto::File,
        ConflictSide::Service => ConflictSideDto::Service,
        ConflictSide::Unresolved => ConflictSideDto::Unresolved,
    }
}

/// Map a domain merge origin to the wire enum.
fn wire_origin(origin: MergeOrigin) -> MergeOriginDto {
    match origin {
        MergeOrigin::FileOnly => MergeOriginDto::FileOnly,
        MergeOrigin::ServiceOnly => MergeOriginDto::ServiceOnly,
        MergeOrigin::Both => MergeOriginDto::Both,
    }
}

/// Map the domain enforcement action to the wire action.
fn wire_action(action: nrr_domain::canonical::RuleAction) -> rules_json::RuleAction {
    match action {
        nrr_domain::canonical::RuleAction::Route => rules_json::RuleAction::Route,
        nrr_domain::canonical::RuleAction::Block => rules_json::RuleAction::Block,
    }
}

/// Coarse rule-type slug + display value for a rule, matching the vocabulary
/// the GUI rules list uses (`domain` / `zone` / `exact-ip` / `application`,
/// with a `*.` prefix for suffix-domain rules).
fn type_and_value(rule: &CanonicalRule) -> (String, String) {
    use nrr_domain::canonical::CanonicalAddressMatch;
    if let Some(addr) = &rule.address_match {
        match addr {
            CanonicalAddressMatch::ExactFqdn(v) => ("domain".to_string(), v.clone()),
            CanonicalAddressMatch::SuffixDomain(v) => ("domain".to_string(), format!("*.{v}")),
            CanonicalAddressMatch::Zone(v) => ("zone".to_string(), v.clone()),
            CanonicalAddressMatch::ExactIp(a) => ("exact-ip".to_string(), a.to_string()),
        }
    } else if let Some(app) = &rule.app_match {
        ("application".to_string(), app.pattern.as_str().to_string())
    } else {
        ("application".to_string(), String::new())
    }
}

/// Project a merged entry into its wire DTO.
fn entry_dto(entry: &MergedRuleEntry) -> MergedRuleEntryDto {
    let (type_slug, value) = type_and_value(&entry.rule);
    MergedRuleEntryDto {
        value,
        type_slug,
        route: entry.route,
        enabled: entry.rule.enabled,
        action: wire_action(entry.rule.action),
        comment: entry.rule.comment.clone(),
        origin: wire_origin(entry.origin),
        was_conflict: entry.was_conflict,
    }
}

/// Project one conflict side into its wire DTO.
fn conflict_side_dto(side: &ConflictRule) -> ConflictRuleDto {
    ConflictRuleDto {
        route: side.route,
        enabled: side.enabled,
        action: wire_action(side.action),
        comment: side.comment.clone(),
    }
}

/// Project a conflict into its wire DTO.
fn conflict_dto(conflict: &MergeConflict) -> MergeConflictDto {
    let (type_slug, value) = type_and_value(&conflict.rule);
    MergeConflictDto {
        identity_key: conflict.identity_key.clone(),
        value,
        type_slug,
        file: conflict_side_dto(&conflict.file),
        service: conflict_side_dto(&conflict.service),
        resolved: wire_side(conflict.resolved),
    }
}

/// Convert a domain [`MergeResult`] into the wire [`MergeResultDto`], including
/// the merged book re-encoded as canonical rules-json.
fn to_result_dto(
    result: MergeResult,
    policy: MergePolicyDto,
) -> Result<MergeResultDto, MergePreviewError> {
    let noop = result.is_noop();
    let unresolved = result.unresolved_conflicts() as u32;

    let file_only: Vec<MergedRuleEntryDto> = result
        .entries
        .iter()
        .filter(|e| e.origin == MergeOrigin::FileOnly)
        .map(entry_dto)
        .collect();
    let service_only: Vec<MergedRuleEntryDto> = result
        .entries
        .iter()
        .filter(|e| e.origin == MergeOrigin::ServiceOnly)
        .map(entry_dto)
        .collect();
    let conflicts: Vec<MergeConflictDto> = result.conflicts.iter().map(conflict_dto).collect();

    let content = RulesRevisionContent::new(result.merged);
    let merged_rules_json = rules_json::to_canonical_string(&rules_json_codec::encode(&content))
        .map_err(|e| MergePreviewError::EncodeError(e.to_string()))?;

    Ok(MergeResultDto {
        policy,
        noop,
        unresolved,
        file_only,
        service_only,
        conflicts,
        merged_rules_json,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRule};
    use nrr_domain::revision::RiskLevel;
    use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionSource};
    use nrr_domain::RuleId;
    use nrr_shared::rules_json::to_canonical_string;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::SqliteMigrationRunner;
    use nrr_storage::{RevisionRecord, RevisionsRepository};

    fn open_state_db_in_memory() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("in-memory state DB");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("state migrations");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn ip_rule(id: &str, ip: [u8; 4], enabled: bool) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: Some(CanonicalAddressMatch::ExactIp(std::net::Ipv4Addr::new(
                ip[0], ip[1], ip[2], ip[3],
            ))),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn seed_active_revision_for(
        conn: &Arc<Mutex<Connection>>,
        principal: &str,
        book: CanonicalRuleBook,
    ) {
        let content = RulesRevisionContent::new(book);
        let json =
            to_canonical_string(&rules_json_codec::encode(&content)).expect("serialise canonical");
        let guard = conn.lock().unwrap();
        let repo = RevisionsRepository::new(&guard);
        let revision_id = "rev-merge-1";
        let record = RevisionRecord {
            revision_id: revision_id.to_string(),
            content_hash: "deadbeef".to_string(),
            rules_json: json,
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr-merge".to_string(),
            created_at: 1,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: None,
            risk_level: Some(RiskLevel::Low),
        };
        repo.insert_candidate_for(principal, &record)
            .expect("insert candidate");
        repo.mark_apply_succeeded_for(principal, revision_id, None, 1)
            .expect("activate");
    }

    #[test]
    fn no_active_revision_makes_all_file_rules_file_only() {
        let conn = open_state_db_in_memory();
        let source = ProductionMergePreviewSource::new(Arc::clone(&conn));
        let out = source
            .merge_preview(
                nrr_storage::BASELINE_PRINCIPAL,
                "--- IP\n1.2.3.4\n",
                "",
                MergePolicyDto::Union,
                &[],
                false,
            )
            .expect("merge preview");
        assert_eq!(out.file_only.len(), 1, "one file-only rule");
        assert_eq!(out.file_only[0].value, "1.2.3.4");
        assert_eq!(out.file_only[0].type_slug, "exact-ip");
        assert!(out.service_only.is_empty());
        assert!(out.conflicts.is_empty());
        assert!(!out.merged_rules_json.is_empty());
    }

    #[test]
    fn diverged_file_and_service_produce_buckets() {
        const CALLER: &str = "S-1-5-21-merge-1001";
        let conn = open_state_db_in_memory();
        // Service has 1.2.3.4 (primary) + 9.9.9.9 (primary).
        seed_active_revision_for(
            &conn,
            CALLER,
            CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(vec![
                    ip_rule("r-1", [1, 2, 3, 4], true),
                    ip_rule("r-2", [9, 9, 9, 9], true),
                ]),
                secondary: CanonicalRuleSet::default(),
            },
        );
        // File (primary) has 1.2.3.4 (same) + 5.5.5.5 (new). 9.9.9.9 dropped.
        let source = ProductionMergePreviewSource::new(Arc::clone(&conn));
        let out = source
            .merge_preview(
                CALLER,
                "--- IP\n1.2.3.4\n5.5.5.5\n",
                "",
                MergePolicyDto::Union,
                &[],
                false,
            )
            .expect("merge preview");
        // 5.5.5.5 is file-only; 9.9.9.9 is service-only; 1.2.3.4 is identical.
        let file_vals: Vec<_> = out.file_only.iter().map(|e| e.value.clone()).collect();
        let svc_vals: Vec<_> = out.service_only.iter().map(|e| e.value.clone()).collect();
        assert!(
            file_vals.contains(&"5.5.5.5".to_string()),
            "file-only 5.5.5.5"
        );
        assert!(
            svc_vals.contains(&"9.9.9.9".to_string()),
            "service-only 9.9.9.9"
        );
        assert!(out.conflicts.is_empty(), "no attribute conflicts");
        assert!(!out.noop);
    }

    #[test]
    fn invalid_file_text_is_rejected() {
        let conn = open_state_db_in_memory();
        let source = ProductionMergePreviewSource::new(Arc::clone(&conn));
        // A bare-glob `*` app rule fails semantic canonicalization (it would
        // match every process) — the merge preview surfaces that as a clean
        // rejection rather than silently swallowing the file. Platform
        // sections are only canonicalized on their own OS, so the rule must sit
        // in the section active on THIS host; otherwise it is preserved-but-
        // inactive and never reaches canonicalization (making the test pass on
        // Windows but silently no-op on Linux/macOS).
        let host_section = if cfg!(target_os = "windows") {
            "--- Windows"
        } else if cfg!(target_os = "linux") {
            "--- Linux"
        } else {
            "--- MacOS"
        };
        let file_text = format!("{host_section}\n*\n");
        let err = source
            .merge_preview(
                nrr_storage::BASELINE_PRINCIPAL,
                &file_text,
                "",
                MergePolicyDto::Union,
                &[],
                false,
            )
            .expect_err("must reject bare-glob app rule");
        assert!(matches!(
            err,
            MergePreviewError::FileCanonicalizeRejected(_)
        ));
    }
}

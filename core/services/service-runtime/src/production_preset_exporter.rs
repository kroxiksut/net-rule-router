//! Production [`PresetExportSource`] for the
//! `PresetExportGet` read-only IPC op.
//!
//! Reads the active rules revision from `nrr_service_state.db`, decodes
//! it into a domain [`nrr_domain::rules_revision::RulesRevisionContent`],
//! selects the requested route's [`nrr_domain::canonical::CanonicalRuleSet`],
//! projects it back to a [`nrr_domain::rules_file::RulesFileParsed`] via
//! [`nrr_domain::rules_file::canonical_rule_set_to_rules_file_parsed`],
//! and serialises with [`nrr_domain::rules_file::write_rules_file`].
//!
//! Returns the UTF-8 txt bytes plus their SHA-256 hex. The handler
//! base64-wraps the bytes for wire transport.
//!
//! ## Preset metadata caveat
//!
//! The active revision does NOT retain preset metadata
//! (`# NetRuleRouter preset — version 1` header, `# name:` /
//! `# description:` / etc.) — those were dropped during import
//! canonicalization. When `include_metadata = true`, the exporter writes
//! a bare preset version header with no key/value lines.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrr_domain::rules_file::{
    canonical_rule_set_to_rules_file_parsed, write_rules_file, PresetMetadata, RulesFileSection,
};
use nrr_domain::rules_json_codec;
use nrr_shared::rules_json;
use nrr_shared::RouteRole;
use nrr_storage::revisions::RevisionsRepository;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Produces a canonical txt blob from the currently active rules revision.
pub trait PresetExportSource: Send + Sync {
    /// Returns the unwrapped UTF-8 txt bytes plus a SHA-256 hex digest
    /// of those bytes.
    ///
    /// `principal` is the caller's Windows SID (or the
    /// [`nrr_storage::BASELINE_PRINCIPAL`] sentinel). The
    /// active revision is resolved from the caller's own per-SID chain
    /// first, falling back to the shared admin baseline — mirroring the
    /// enforcement read path — so the export reflects the rules the
    /// service is actually enforcing for that user.
    fn export_rules_file(
        &self,
        principal: &str,
        route: RouteRole,
        include_metadata: bool,
    ) -> Result<PresetExportOutput, PresetExportError>;
}

/// Output of [`PresetExportSource::export_rules_file`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetExportOutput {
    /// Canonical rules-file text (UTF-8). Caller base64-wraps for wire.
    pub file_bytes_utf8: String,
    /// SHA-256 hex (64 chars) of `file_bytes_utf8`.
    pub content_hash_hex: String,
}

/// Why an export could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetExportError {
    /// No revision is currently active. The GUI surfaces this as
    /// "Nothing to export — apply rules first."
    NoActiveRevision,
    /// State DB mutex is poisoned (another thread panicked while
    /// holding the lock). Fatal at the runtime level; the exporter
    /// can't recover.
    LockPoisoned,
    /// Storage layer returned an error reading the active revision.
    StorageError(String),
    /// `rules_json` blob in the row is not valid wire shape or fails
    /// codec semantic checks (schema version, IPv4 parse, etc.).
    DecodeError(String),
}

impl std::fmt::Display for PresetExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoActiveRevision => f.write_str("no active revision"),
            Self::LockPoisoned => f.write_str("state DB mutex poisoned"),
            Self::StorageError(e) => write!(f, "storage error: {e}"),
            Self::DecodeError(e) => write!(f, "decode error: {e}"),
        }
    }
}

impl std::error::Error for PresetExportError {}

/// Production [`PresetExportSource`] backed by `nrr_service_state.db`.
pub struct ProductionPresetExporter {
    conn: Arc<Mutex<Connection>>,
    /// Section header used for application rules on this host. Free
    /// edition canonicalization strips the platform tag from app
    /// matches; we re-attach the host's section on export. Windows
    /// is the only supported host today.
    host_app_section: RulesFileSection,
}

impl ProductionPresetExporter {
    /// Constructs an exporter that defaults the app section to the
    /// host platform's canonical name. On Windows this is `Windows`.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            host_app_section: default_host_app_section(),
        }
    }

    /// Test helper: override the host app section without changing the
    /// compile-time platform.
    #[doc(hidden)]
    pub fn with_host_app_section(mut self, section: RulesFileSection) -> Self {
        self.host_app_section = section;
        self
    }
}

const fn default_host_app_section() -> RulesFileSection {
    #[cfg(target_os = "windows")]
    {
        RulesFileSection::Windows
    }
    #[cfg(target_os = "linux")]
    {
        RulesFileSection::Linux
    }
    #[cfg(target_os = "macos")]
    {
        RulesFileSection::MacOS
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        // Conservative default for unsupported hosts.
        RulesFileSection::Windows
    }
}

impl PresetExportSource for ProductionPresetExporter {
    fn export_rules_file(
        &self,
        principal: &str,
        route: RouteRole,
        include_metadata: bool,
    ) -> Result<PresetExportOutput, PresetExportError> {
        let guard = self
            .conn
            .lock()
            .map_err(|_| PresetExportError::LockPoisoned)?;
        let repo = RevisionsRepository::new(&guard);
        // Per-SID read-through. The console user's edits live in
        // THEIR SID's revision chain (that's what drives enforcement), while
        // `__baseline__` may be empty. Resolve the caller's own active
        // revision first, then fall back to the shared admin baseline — the
        // same pattern as `ProductionRulesSnapshotProvider::rules_snapshot_for`
        // and the explain path's `load_active_rule_book`. StorageError mapping
        // preserved on both reads.
        let record = match repo
            .get_active_for(principal)
            .map_err(|e| PresetExportError::StorageError(e.to_string()))?
        {
            Some(rec) => rec,
            None if principal != nrr_storage::BASELINE_PRINCIPAL => repo
                .get_active_for(nrr_storage::BASELINE_PRINCIPAL)
                .map_err(|e| PresetExportError::StorageError(e.to_string()))?
                .ok_or(PresetExportError::NoActiveRevision)?,
            None => return Err(PresetExportError::NoActiveRevision),
        };

        // Wire-shape parse first; this catches malformed/older blobs
        // before the codec runs.
        let dto = rules_json::from_canonical_string(&record.rules_json)
            .map_err(|e| PresetExportError::DecodeError(format!("wire parse: {e}")))?;
        let content = rules_json_codec::decode(dto)
            .map_err(|e| PresetExportError::DecodeError(format!("codec decode: {e}")))?;

        let rule_set = content.rule_book.set_for(route);
        let parsed = canonical_rule_set_to_rules_file_parsed(rule_set, self.host_app_section);

        // Active revisions don't carry preset metadata (lost on import
        // canonicalization). When the caller asked for metadata, emit
        // only the version header — no key/value lines.
        let metadata: Option<PresetMetadata> = if include_metadata {
            Some(PresetMetadata::default())
        } else {
            None
        };

        let file_bytes_utf8 = write_rules_file(&parsed, &[], metadata.as_ref());
        let mut hasher = Sha256::new();
        hasher.update(file_bytes_utf8.as_bytes());
        let content_hash_hex = format!("{:x}", hasher.finalize());

        Ok(PresetExportOutput {
            file_bytes_utf8,
            content_hash_hex,
        })
    }
}

/// Base64-encode the export bytes with the standard alphabet (RFC 4648,
/// padded). Sits in this module so handler tests can round-trip the
/// wire shape without re-importing the base64 engine.
pub fn encode_file_bytes_b64(file_bytes_utf8: &str) -> String {
    BASE64_STANDARD.encode(file_bytes_utf8.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
        CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::revision::RiskLevel;
    use nrr_domain::rules_revision::{RevisionStatus, RulesRevisionContent, RulesRevisionSource};
    use nrr_domain::RuleId;
    use nrr_shared::rules_json::to_canonical_string;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::SqliteMigrationRunner;
    use nrr_storage::{RevisionRecord, RevisionsRepository};
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn open_state_db_in_memory() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("in-memory state DB");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("state migrations");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn rule(id: &str, addr: CanonicalAddressMatch, comment: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(addr),
            app_match: None,
            comment: comment.to_string(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn app_rule(id: &str, name: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(name.to_string()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn seed_active_revision(conn: &Arc<Mutex<Connection>>, content: RulesRevisionContent) {
        seed_active_revision_for(conn, nrr_storage::BASELINE_PRINCIPAL, content);
    }

    /// seed an active revision under an explicit principal
    /// (a Windows SID or the baseline sentinel). The baseline convenience
    /// [`seed_active_revision`] delegates here.
    fn seed_active_revision_for(
        conn: &Arc<Mutex<Connection>>,
        principal: &str,
        content: RulesRevisionContent,
    ) {
        let json =
            to_canonical_string(&rules_json_codec::encode(&content)).expect("serialise canonical");
        let guard = conn.lock().unwrap();
        let repo = RevisionsRepository::new(&guard);
        let revision_id = "rev-test-1";
        let record = RevisionRecord {
            revision_id: revision_id.to_string(),
            content_hash: "deadbeef".to_string(),
            rules_json: json,
            status: RevisionStatus::Candidate,
            source: RulesRevisionSource::GuiRulesEdit,
            correlation_id: "corr-test".to_string(),
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
        // Mark apply-succeeded with no previous-active so the partial
        // unique index fires cleanly.
        repo.mark_apply_succeeded_for(principal, revision_id, None, 1)
            .expect("activate");
    }

    #[test]
    fn export_returns_no_active_revision_when_db_empty() {
        let conn = open_state_db_in_memory();
        let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
            .with_host_app_section(RulesFileSection::Windows);
        let result =
            exporter.export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false);
        assert_eq!(result, Err(PresetExportError::NoActiveRevision));
    }

    #[test]
    fn export_resolves_caller_sid_revision_with_empty_baseline() {
        // regression — the console user's edits live under THEIR
        // SID's revision chain (that's what drives enforcement), while the
        // shared `__baseline__` partition may be empty. Export MUST resolve the
        // caller's own active revision via per-SID read-through; before the fix
        // it read the baseline only (`get_active`) and returned
        // `NoActiveRevision` even though the service was actively enforcing the
        // user's rules.
        const CALLER_SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "r-1",
                CanonicalAddressMatch::ExactFqdn("per-sid.example".to_string()),
                "user rule",
            )]),
            secondary: CanonicalRuleSet::default(),
        });
        seed_active_revision_for(&conn, CALLER_SID, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
            .with_host_app_section(RulesFileSection::Windows);
        // Sanity: the baseline partition is empty, so the OLD baseline-only
        // path still returns NoActiveRevision here.
        assert_eq!(
            exporter.export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false),
            Err(PresetExportError::NoActiveRevision),
            "baseline partition must be empty for this regression"
        );
        // The fix: exporting as the caller SID resolves their own revision.
        let out = exporter
            .export_rules_file(CALLER_SID, RouteRole::Primary, false)
            .expect("caller-SID export must succeed via per-SID read-through");
        assert!(
            out.file_bytes_utf8.contains("per-sid.example"),
            "expected the caller's own revision content; got:\n{}",
            out.file_bytes_utf8
        );
    }

    #[test]
    fn export_falls_back_to_baseline_for_undiverged_caller_sid() {
        // A caller who has not diverged (no per-SID revision) transparently
        // sees the shared baseline via read-through.
        const CALLER_SID: &str = "S-1-5-21-9999999999-8888888888-7777777777-1002";
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "r-1",
                CanonicalAddressMatch::ExactFqdn("baseline.example".to_string()),
                "shared baseline",
            )]),
            secondary: CanonicalRuleSet::default(),
        });
        // Seed the shared baseline only; the caller SID has no revision.
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
            .with_host_app_section(RulesFileSection::Windows);
        let out = exporter
            .export_rules_file(CALLER_SID, RouteRole::Primary, false)
            .expect("undiverged caller must read through to baseline");
        assert!(
            out.file_bytes_utf8.contains("baseline.example"),
            "expected baseline content via read-through; got:\n{}",
            out.file_bytes_utf8
        );
    }

    /// App-authored rules must survive the service round-trip.
    ///
    /// The exporter deliberately passes `&[]` for unknown sections — a
    /// revision blob carries no passthrough text — so anything the writer does
    /// not know as a first-class section is lost here. `--- Auto` being a
    /// first-class section is what keeps these rules (and their provenance) in
    /// the exported file.
    #[test]
    fn export_preserves_app_authored_rules_and_their_provenance() {
        use nrr_shared::auto_rule::{AutoRuleReason, RuleOrigin};

        let conn = open_state_db_in_memory();
        let mut app_authored = rule(
            "r-2",
            CanonicalAddressMatch::ExactFqdn("rr3.example-cdn.net".to_string()),
            "",
        );
        app_authored.origin = Some(RuleOrigin::auto(
            AutoRuleReason::SiteCompanion,
            "example.com",
            "2026-07-31",
        ));
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule(
                    "r-1",
                    CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                    "vendor updates",
                ),
                app_authored,
            ]),
            secondary: CanonicalRuleSet::default(),
        });
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
            .with_host_app_section(RulesFileSection::Windows);
        let out = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
            .expect("export");

        assert!(
            out.file_bytes_utf8.contains(
                "--- Auto\nrr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31\n"
            ),
            "app-authored rule lost or stripped of provenance; got:\n{}",
            out.file_bytes_utf8
        );
        // The user's own rule stays in Domains, unannotated.
        assert!(
            out.file_bytes_utf8
                .contains("--- Domains\nexample.com  # vendor updates\n"),
            "user rule must be unaffected; got:\n{}",
            out.file_bytes_utf8
        );

        // …and the exported file re-imports to the same rules.
        let reparsed = nrr_domain::rules_file::parse_rules_file(&out.file_bytes_utf8);
        assert!(reparsed.warnings.is_empty(), "{:?}", reparsed.warnings);
        let auto = reparsed
            .parsed
            .entries_for(nrr_domain::rules_file::RulesFileSection::Auto);
        assert_eq!(auto.len(), 1);
        assert_eq!(
            auto[0].origin.as_ref().map(|o| o.reason().as_slug()),
            Some("site-companion")
        );
    }

    #[test]
    fn export_emits_canonical_txt_for_primary_route() {
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![
                rule(
                    "r-1",
                    CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                    "vendor updates",
                ),
                app_rule("r-2", "chrome.exe"),
            ]),
            secondary: CanonicalRuleSet::default(),
        });
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn))
            .with_host_app_section(RulesFileSection::Windows);
        let out = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
            .expect("export");
        assert!(
            out.file_bytes_utf8
                .contains("--- Domains\nexample.com  # vendor updates\n"),
            "missing Domains entry; got:\n{}",
            out.file_bytes_utf8
        );
        assert!(
            out.file_bytes_utf8.contains("--- Windows\nchrome.exe\n"),
            "missing Windows entry; got:\n{}",
            out.file_bytes_utf8
        );
        // No preset header when include_metadata = false.
        assert!(
            !out.file_bytes_utf8.starts_with("# NetRuleRouter preset"),
            "unexpected preset header; got:\n{}",
            out.file_bytes_utf8
        );
        // Deterministic content_hash: 64 hex chars.
        assert_eq!(out.content_hash_hex.len(), 64);
        assert!(out.content_hash_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn export_secondary_returns_independent_rules() {
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "r-1",
                CanonicalAddressMatch::ExactFqdn("primary.example".to_string()),
                "",
            )]),
            secondary: CanonicalRuleSet::from_rules(vec![rule(
                "r-2",
                CanonicalAddressMatch::ExactFqdn("secondary.example".to_string()),
                "",
            )]),
        });
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn));
        let primary = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
            .expect("export primary");
        let secondary = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Secondary, false)
            .expect("export secondary");
        assert!(primary.file_bytes_utf8.contains("primary.example"));
        assert!(!primary.file_bytes_utf8.contains("secondary.example"));
        assert!(secondary.file_bytes_utf8.contains("secondary.example"));
        assert!(!secondary.file_bytes_utf8.contains("primary.example"));
        assert_ne!(primary.content_hash_hex, secondary.content_hash_hex);
    }

    #[test]
    fn export_emits_preset_header_when_metadata_requested() {
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "r-1",
                CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                "",
            )]),
            secondary: CanonicalRuleSet::default(),
        });
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn));
        let out = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, true)
            .expect("export");
        assert!(
            out.file_bytes_utf8
                .starts_with("# NetRuleRouter preset \u{2014} version 1\n"),
            "missing preset header; got:\n{}",
            out.file_bytes_utf8
        );
    }

    #[test]
    fn export_hash_is_deterministic_across_invocations() {
        let conn = open_state_db_in_memory();
        let content = RulesRevisionContent::new(CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![rule(
                "r-1",
                CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                "",
            )]),
            secondary: CanonicalRuleSet::default(),
        });
        seed_active_revision(&conn, content);

        let exporter = ProductionPresetExporter::new(Arc::clone(&conn));
        let a = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
            .expect("a");
        let b = exporter
            .export_rules_file(nrr_storage::BASELINE_PRINCIPAL, RouteRole::Primary, false)
            .expect("b");
        assert_eq!(a, b);
    }

    #[test]
    fn encode_file_bytes_b64_round_trips_via_standard_alphabet() {
        let original = "--- Domains\nexample.com\n";
        let encoded = encode_file_bytes_b64(original);
        let decoded = BASE64_STANDARD.decode(encoded.as_bytes()).expect("decode");
        assert_eq!(String::from_utf8(decoded).expect("utf8"), original);
    }
}

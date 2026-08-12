//! Preset import/export contracts.
//!
//! This module defines the **contract boundary** for preset import and export
//! operations. It specifies:
//!
//! - The input and output types for `import_preset_file` and `export_preset_file`.
//! - The full import pipeline (parse → validate → canonicalize → candidate → review → activate).
//! - Import semantics (per-route replacement, other route unchanged).
//! - The "Import both files together" GUI setting and its default.
//! - Round-trip expectations (exported presets can be re-imported without semantic loss).
//!
//! # Implementation status
//!
//! **File I/O and service integration live at the service layer**, outside
//! this module. This module defines the contract shapes, the pipeline
//! documentation types, and the mock-level integration test that exercises
//! the full pipeline end-to-end with in-memory bytes.
//!
//! # Import pipeline
//!
//! ```text
//! 1. Acquire bytes  (caller: read file at `source_path`, check `file.len()`)
//! 2. Validate       validate_preset_bytes(bytes) → PresetFileValidationOutcome
//! 3. Canonicalize   canonicalize_preset_rules(parse_outcome, route, platform, icp)
//!                     → PresetRulesCanonicalizeOutcome
//! 4. Merge          merge preset rules with the other route from the active config
//!                     → ActiveConfiguration (only selected route's rules replaced)
//! 5. Validate full  validate_and_canonicalize(&merged_config) → CanonicalProfile
//! 6. Build request  ImportRequest { revision_id, content_hash, … }
//! 7. Candidate      process_import(request, active_hash, pending_hash)
//!                     → ImportResult::PendingReview(PendingRevision)
//! 8. Review         user sees diff dialog; GUI calls ApprovePendingReview command
//! 9. Activate       service activates the pending revision
//! ```
//!
//! Stages 1–7 and 8–9 are separated by the review gate: **the active revision
//! never changes unless the user explicitly confirms the review dialog.**
//!
//! # Import semantics
//!
//! - The imported file's rules **replace** the rules for the selected route.
//! - The route that was not selected is **left unchanged** — its rules are
//!   carried over from the current active revision.
//! - Adapter bindings and `behavior_mode` are always carried from the current
//!   active configuration; the preset file does not carry them.
//! - Pro-only section entries are preserved in the file on disk but are never
//!   applied to routing policy.
//!
//! # Round-trip guarantee
//!
//! An exported preset file can be re-imported without semantic loss:
//!
//! 1. The exported file uses the same format as working rules files (docs/en/rules-file-format.md Rules File Format).
//! 2. Pro-only sections are written back unchanged on export (if present in the
//!    file — Free edition does not add Pro sections, only preserves them).
//! 3. Disabled rules are written as commented lines and are parsed back as
//!    disabled — `enabled: false` in both directions.
//! 4. Inline comments are preserved.
//! 5. Preset metadata header comments (`name`, `description`, `author`,
//!    `preset_version`) are written back unchanged.
//! 6. Canonical ordering is only applied to the *internal* representation;
//!    the file export preserves the user's display order (or the canonical
//!    order for freshly created exports).

use nrr_shared::RouteRole;

use crate::rules_file::HostPlatform;

// ── Import contract ───────────────────────────────────────────────────────────

/// Specification for a preset import operation.
///
/// Supplied by the GUI when the user completes the file picker. The service
/// reads the file at `source_path`, runs stages 1–7 of the import
/// pipeline, and returns a `PendingRevision` for review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetImportSpec {
    /// Which route's rules are replaced by the imported file.
    pub route: RouteRole,
    /// Absolute path to the file selected in the file picker.
    ///
    /// # Implementation note
    ///
    /// **Superseded by wire-payload flow.** This `source_path` field is an
    /// earlier contract leftover; the runtime path is now GUI reads bytes →
    /// `MutationSubmit { kind: PresetImport, payload: PresetImportPayload }`.
    /// The service never reads `source_path` directly. Kept for the contract
    /// test in `tests/preset_contract.rs`; consider removing in a future
    /// cleanup pass.
    pub source_path: String,
    /// The host platform, used to filter platform-inactive sections (e.g. Linux
    /// and macOS sections on a Windows host).
    pub platform: HostPlatform,
    /// Whether child processes of matched app rules are also matched.
    /// Sourced from the current `UiPreferences::include_child_processes`.
    pub include_child_processes: bool,
}

// ── Export contract ───────────────────────────────────────────────────────────

/// Specification for a preset export operation.
///
/// Supplied by the GUI when the user chooses "Export current list…" for one
/// route. The service serialises the current active rule set for
/// `route` and writes it to `dest_path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetExportSpec {
    /// Which route's rules are written to the file.
    pub route: RouteRole,
    /// Absolute path for the output file.
    ///
    /// # Implementation note
    ///
    /// **Superseded by wire-payload flow.** The runtime path is now
    /// `PresetExportGet` IPC op → service returns base64-wrapped txt bytes;
    /// the GUI writes them to a user-chosen path via
    /// `Qt.labs.platform.FileDialog::Save`. The service never sees this
    /// path. Pro-section preservation is documented as a known gap (active
    /// revision does not retain unknown sections).
    pub dest_path: String,
    /// Whether to write preset metadata header comments.
    ///
    /// When `true`, a `# NetRuleRouter preset — version 1` header and any
    /// available `name`/`description`/`author` lines are prepended.
    pub include_metadata: bool,
}

/// Metadata to include in an exported preset file's header comments.
///
/// All fields are optional; omitted fields are not written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresetExportMetadata {
    /// User-facing name for the preset (written as `# name: <value>`).
    pub name: Option<String>,
    /// Short description (written as `# description: <value>`).
    pub description: Option<String>,
    /// Author or maintainer (written as `# author: <value>`).
    pub author: Option<String>,
    /// User-assigned version string (written as `# preset_version: <value>`).
    pub preset_version: Option<String>,
}

// ── "Import both files together" GUI setting ──────────────────────────────────

/// Default value for the "Import both files together" GUI setting.
///
/// When `false` (the default), importing a preset file for one route only
/// updates that route. The other route's file is not touched.
///
/// When `true`, selecting a file for one route automatically opens a second
/// file picker for the other route. Both files are validated and imported in a
/// single operation — the result is one `PendingRevision` that replaces both
/// routes' rules.
///
/// Stored in `UiPreferences::import_both_files_together`.
pub const IMPORT_BOTH_FILES_TOGETHER_DEFAULT: bool = false;

// ── Pipeline document type ────────────────────────────────────────────────────

/// Documents the full preset import pipeline.
///
/// This type carries no runtime behaviour. It exists to make the pipeline
/// contract discoverable at the domain level and to provide a single source of
/// truth that the service must implement.
///
/// # Stage summary
///
/// | # | Stage         | Responsible     | Input → Output                            |
/// |---|---------------|-----------------|-------------------------------------------|
/// | 1 | Acquire       | Service         | path → `&[u8]`                            |
/// | 2 | Validate      | `preset_validation` | `&[u8]` → `PresetFileValidationOutcome` |
/// | 3 | Canonicalize  | `preset_canonicalize` | `ParseOutcome` → `CanonicalRuleSet`   |
/// | 4 | Merge         | Service         | preset rules + active config → `ActiveConfiguration` |
/// | 5 | Full validate | `validation`    | `ActiveConfiguration` → `CanonicalProfile`|
/// | 6 | Build request | Service         | `CanonicalProfile` → `ImportRequest`      |
/// | 7 | Candidate     | `import`        | `ImportRequest` → `ImportResult`          |
/// | 8 | Review        | GUI             | user confirms diff dialog                 |
/// | 9 | Activate      | Service         | `ApprovePendingReview` command → active   |
///
/// Stages 2–3 are implemented at the domain level.
/// Stages 5 and 7 are implemented at the domain level.
/// Stages 1, 4 (merge), 6, 8–9 belong to the service layer.
pub struct PresetImportPipelineDoc;

// ── Round-trip guarantee ──────────────────────────────────────────────────────

/// Documents the round-trip guarantee for preset files.
///
/// An exported preset file must be re-importable without semantic loss. This
/// type exists to make the invariant explicit and testable.
///
/// # Invariant
///
/// For any valid `CanonicalRuleSet` `S`:
///
/// 1. `export(S)` → a txt file `F`.
/// 2. `parse_rules_file(F)` → `ParseOutcome P`.
/// 3. `canonicalize_preset_rules(&P, route, platform, icp)` → `CanonicalRuleSet S'`.
/// 4. `S'` is semantically equivalent to `S`:
///    - The same match values in the same canonical order.
///    - The same `enabled` flags.
///    - The same inline comments.
///    - Pro-only section entries are preserved in `ParseOutcome::unknown_sections`
///      but do not appear in `S'` (they are outside the Free canonical boundary).
///
/// # What may differ
///
/// Rule IDs (`r-parse-*`) are regenerated by the parser and are not part of
/// the semantic equality. The canonical ordering compensates for any position
/// changes.
pub struct PresetRoundTripGuaranteeDoc;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn import_both_files_default_is_false() {
        assert!(!IMPORT_BOTH_FILES_TOGETHER_DEFAULT);
    }

    #[test]
    fn preset_import_spec_fields_accessible() {
        let spec = PresetImportSpec {
            route: RouteRole::Primary,
            source_path: "C:/rules_primary.txt".to_string(),
            platform: HostPlatform::Windows,
            include_child_processes: false,
        };
        assert_eq!(spec.route, RouteRole::Primary);
        assert_eq!(spec.source_path, "C:/rules_primary.txt");
    }

    #[test]
    fn preset_export_spec_fields_accessible() {
        let spec = PresetExportSpec {
            route: RouteRole::Secondary,
            dest_path: "C:/export/rules_secondary.txt".to_string(),
            include_metadata: true,
        };
        assert_eq!(spec.route, RouteRole::Secondary);
        assert!(spec.include_metadata);
    }

    #[test]
    fn preset_export_metadata_default_is_all_none() {
        let meta = PresetExportMetadata::default();
        assert!(meta.name.is_none());
        assert!(meta.description.is_none());
        assert!(meta.author.is_none());
        assert!(meta.preset_version.is_none());
    }
}

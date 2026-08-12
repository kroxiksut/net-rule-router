//! UX display types for preset import/export.
//!
//! This module bridges the domain validation layer and the GUI
//! presentation layer by:
//!
//! - Classifying [`PresetImportRejectedReason`] into stable user-visible
//!   error categories.
//! - Providing locale key constants for all user-facing strings so the GUI
//!   can resolve them from the active locale catalog without embedding raw text
//!   in the domain layer.
//! - Defining display data for Pro-only section badges in the rules list.
//! - Enumerating the GUI actions available after a failed import.
//! - Specifying where the "Import both files together" preference lives in the
//!   settings screen.
//!
//! # No strings in domain
//!
//! This module exposes only stable locale key constants — never resolved
//! user-visible strings. Resolved text is produced at the GUI layer by looking
//! up these keys in the active locale catalog via `nrr_shared::resolve_catalog_text`.
//!
//! # Implementation note
//!
//! The actual GUI dialogs, error banners, and settings toggle are wired at
//! the GUI layer. This module defines the stable contract they must conform to.

use crate::{
    preset_contract::IMPORT_BOTH_FILES_TOGETHER_DEFAULT,
    preset_validation::PresetImportRejectedReason, rules_file::UnknownSection,
};

// ── Error category ────────────────────────────────────────────────────────────

/// User-visible error category for a rejected preset import.
///
/// Maps each [`PresetImportRejectedReason`] to a stable display category.
/// The GUI uses the locale key methods to resolve the dialog title and
/// description from the active locale catalog.
///
/// # GUI contract
///
/// The error dialog must show:
/// 1. An error icon.
/// 2. The resolved title (`locale_key_title`).
/// 3. The resolved description (`locale_key_description`).
/// 4. The action buttons from [`PresetImportGuiAction::all()`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportErrorCategory {
    /// File size exceeds [`crate::import::IMPORT_FILE_SIZE_LIMIT_BYTES`] (1 MiB).
    FileTooLarge,
    /// File bytes are not valid UTF-8 (or an unsupported byte-order mark).
    EncodingError,
    /// Rule count across all sections exceeds [`crate::preset_validation::MAX_RULES_PER_FILE`].
    TooManyRules,
    /// At least one match value exceeds [`crate::preset_validation::MAX_MATCH_VALUE_LEN`].
    MatchValueTooLong,
    /// At least one inline comment exceeds
    /// [`crate::preset_validation::MAX_INLINE_COMMENT_CHARS`] characters.
    InlineCommentTooLong,
}

impl PresetImportErrorCategory {
    /// Derives the display category from a rejection reason.
    pub fn from_rejected_reason(reason: &PresetImportRejectedReason) -> Self {
        match reason {
            PresetImportRejectedReason::FileTooLarge { .. } => Self::FileTooLarge,
            PresetImportRejectedReason::EncodingError => Self::EncodingError,
            PresetImportRejectedReason::TooManyRules { .. } => Self::TooManyRules,
            PresetImportRejectedReason::MatchValueTooLong { .. } => Self::MatchValueTooLong,
            PresetImportRejectedReason::InlineCommentTooLong { .. } => Self::InlineCommentTooLong,
        }
    }

    /// Locale key for the error dialog title string.
    pub const fn locale_key_title(self) -> &'static str {
        match self {
            Self::FileTooLarge => "dialog.preset-import.error.file-too-large.title",
            Self::EncodingError => "dialog.preset-import.error.encoding-error.title",
            Self::TooManyRules => "dialog.preset-import.error.too-many-rules.title",
            Self::MatchValueTooLong => "dialog.preset-import.error.match-value-too-long.title",
            Self::InlineCommentTooLong => {
                "dialog.preset-import.error.inline-comment-too-long.title"
            }
        }
    }

    /// Locale key for the error dialog description string.
    pub const fn locale_key_description(self) -> &'static str {
        match self {
            Self::FileTooLarge => "dialog.preset-import.error.file-too-large.description",
            Self::EncodingError => "dialog.preset-import.error.encoding-error.description",
            Self::TooManyRules => "dialog.preset-import.error.too-many-rules.description",
            Self::MatchValueTooLong => {
                "dialog.preset-import.error.match-value-too-long.description"
            }
            Self::InlineCommentTooLong => {
                "dialog.preset-import.error.inline-comment-too-long.description"
            }
        }
    }
}

// ── GUI actions ───────────────────────────────────────────────────────────────

/// GUI actions shown in the error dialog after a preset import is rejected.
///
/// All three actions are available for every rejection reason. The GUI renders
/// them as buttons in the order returned by [`Self::all()`].
///
/// # Implementation note
///
/// Button click handlers (file picker, system text editor, service call) are
/// implemented at the GUI layer. This enum establishes the stable action set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportGuiAction {
    /// Open a detail pane with the full validation error (section, value, reason).
    ViewErrorDetails,
    /// Open the preset file in the system default text editor.
    OpenInExternalEditor,
    /// Re-open the file picker so the user can select a corrected file.
    RetryImport,
}

impl PresetImportGuiAction {
    /// All available actions in display order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::ViewErrorDetails,
            Self::OpenInExternalEditor,
            Self::RetryImport,
        ]
    }

    /// Locale key for the action button label.
    pub const fn locale_key(self) -> &'static str {
        match self {
            Self::ViewErrorDetails => "dialog.preset-import.action.view-error-details",
            Self::OpenInExternalEditor => "dialog.preset-import.action.open-in-external-editor",
            Self::RetryImport => "dialog.preset-import.action.retry",
        }
    }
}

// ── Pro section badge ─────────────────────────────────────────────────────────

/// Display data for a Pro-only section shown as a badge row in the rules list.
///
/// When a preset file contains sections not recognised by the Free edition
/// (e.g. `--- CIDR`, `--- Ports`), the rules list renders a read-only badge
/// row for each such section. Rules inside are preserved on disk but are
/// never applied to routing policy.
///
/// # GUI rendering contract
///
/// - Badge icon: `assets/icons/ui/pro.svg` (normal), `assets/icons/ui-hc/pro.svg`
///   (high-contrast theme).
/// - Badge label: resolved from [`LOCALE_KEY_BADGE_LABEL`].
/// - Row tooltip: resolved from [`LOCALE_KEY_BADGE_TOOLTIP`].
/// - Rules in this section: greyed-out, non-interactive.
/// - User cannot add, edit, or delete rules in a Pro section.
/// - Presence of a Pro section is **not** an import error; import proceeds normally.
/// - The section is shown only in read-only preview mode; not in the editing surface.
///
/// # Construction
///
/// Build from a parsed [`UnknownSection`] via the [`From`] impl:
///
/// ```no_run
/// use nrr_domain::preset_ux::ProSectionDisplayItem;
/// use nrr_domain::rules_file::UnknownSection;
/// # let section = UnknownSection { name: "CIDR".to_string(), entries: vec![] };
/// let item = ProSectionDisplayItem::from(&section);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProSectionDisplayItem {
    /// Raw section name as declared in the file (e.g. `"CIDR"`, `"Ports"`).
    pub section_name: String,
    /// Number of entries in this section.
    pub entry_count: usize,
}

impl ProSectionDisplayItem {
    /// Locale key for the "Pro" badge label on the section header row.
    pub const LOCALE_KEY_BADGE_LABEL: &'static str = "rules.pro-section.badge-label";

    /// Locale key for the badge tooltip explaining that Pro is required.
    pub const LOCALE_KEY_BADGE_TOOLTIP: &'static str = "rules.pro-section.badge-tooltip";

    /// Locale key for the per-rule "inactive" hint shown on each rule row.
    pub const LOCALE_KEY_INACTIVE_HINT: &'static str = "rules.pro-section.inactive-hint";

    /// Locale key for the import-time warning that a Pro section was skipped.
    ///
    /// Shown in the import result summary when `AcceptedWithWarnings` includes
    /// an `UnknownProSection` warning.
    pub const LOCALE_KEY_IMPORT_WARNING: &'static str =
        "dialog.preset-import.warning.pro-section-skipped";

    /// Pro section rules are always non-editable in the Free edition.
    pub const fn is_editable() -> bool {
        false
    }

    /// Pro section rules are always rendered as inactive.
    pub const fn is_active() -> bool {
        false
    }
}

impl From<&UnknownSection> for ProSectionDisplayItem {
    fn from(section: &UnknownSection) -> Self {
        Self {
            section_name: section.name.clone(),
            entry_count: section.entries.len(),
        }
    }
}

// ── "Import both files together" setting spec ─────────────────────────────────

/// Specification for the "Import both files together" preference in the
/// Settings screen.
///
/// Exposes the GUI location, locale keys, and default value as stable domain
/// constants without depending on Qt or the UI runtime.
///
/// # Setting behaviour
///
/// - **Off (default)**: importing a preset for one route only touches that
///   route. The other route's rules are unchanged.
/// - **On**: selecting a file for one route automatically opens a second file
///   picker for the other route. Both files are validated and imported in a
///   single pending revision.
///
/// # Settings screen placement
///
/// Settings section → group resolved from [`SETTINGS_GROUP_LOCALE_KEY`] →
/// toggle field resolved from [`FIELD_LOCALE_KEY`].
///
/// # Implementation note
///
/// The toggle is rendered at the GUI layer. The field exists in
/// [`crate::UiPreferences`] and defaults to `false`.
pub struct ImportBothFilesSettingSpec;

impl ImportBothFilesSettingSpec {
    /// Locale key for the settings group header that contains this toggle.
    pub const SETTINGS_GROUP_LOCALE_KEY: &'static str = "settings.group.presets";

    /// Locale key for the toggle field label.
    pub const FIELD_LOCALE_KEY: &'static str = "settings.field.import-both-files-together";

    /// Locale key for the explanatory note below the group header.
    pub const GROUP_NOTE_LOCALE_KEY: &'static str = "settings.note.presets";

    /// Default value — `false` (import one route at a time).
    ///
    /// Mirrors [`IMPORT_BOTH_FILES_TOGETHER_DEFAULT`].
    pub const DEFAULT: bool = IMPORT_BOTH_FILES_TOGETHER_DEFAULT;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preset_validation::PresetImportRejectedReason;

    // ── PresetImportErrorCategory ─────────────────────────────────────────────

    #[test]
    fn error_category_maps_all_rejection_variants() {
        assert_eq!(
            PresetImportErrorCategory::from_rejected_reason(
                &PresetImportRejectedReason::FileTooLarge {
                    size_bytes: 2_000_000,
                    limit_bytes: 1_048_576,
                }
            ),
            PresetImportErrorCategory::FileTooLarge
        );
        assert_eq!(
            PresetImportErrorCategory::from_rejected_reason(
                &PresetImportRejectedReason::EncodingError
            ),
            PresetImportErrorCategory::EncodingError
        );
        assert_eq!(
            PresetImportErrorCategory::from_rejected_reason(
                &PresetImportRejectedReason::TooManyRules {
                    count: 2001,
                    limit: 2000
                }
            ),
            PresetImportErrorCategory::TooManyRules
        );
        assert_eq!(
            PresetImportErrorCategory::from_rejected_reason(
                &PresetImportRejectedReason::MatchValueTooLong {
                    section: "Domains".to_string(),
                    value: "a".repeat(64),
                    len: 261,
                    limit: 260,
                }
            ),
            PresetImportErrorCategory::MatchValueTooLong
        );
        assert_eq!(
            PresetImportErrorCategory::from_rejected_reason(
                &PresetImportRejectedReason::InlineCommentTooLong {
                    section: "Domains".to_string(),
                    comment_preview: "label".to_string(),
                    chars: 201,
                    limit: 200,
                }
            ),
            PresetImportErrorCategory::InlineCommentTooLong
        );
    }

    #[test]
    fn error_category_locale_keys_are_nonempty_and_unique() {
        let categories = [
            PresetImportErrorCategory::FileTooLarge,
            PresetImportErrorCategory::EncodingError,
            PresetImportErrorCategory::TooManyRules,
            PresetImportErrorCategory::MatchValueTooLong,
            PresetImportErrorCategory::InlineCommentTooLong,
        ];

        let title_keys: Vec<_> = categories.iter().map(|c| c.locale_key_title()).collect();
        let desc_keys: Vec<_> = categories
            .iter()
            .map(|c| c.locale_key_description())
            .collect();

        for key in title_keys.iter().chain(desc_keys.iter()) {
            assert!(!key.is_empty(), "locale key must not be empty");
            assert!(key.contains('.'), "locale key must be dot-separated: {key}");
        }

        // All title keys are distinct.
        let mut seen = std::collections::HashSet::new();
        for key in &title_keys {
            assert!(seen.insert(*key), "duplicate title key: {key}");
        }
        // All description keys are distinct.
        seen.clear();
        for key in &desc_keys {
            assert!(seen.insert(*key), "duplicate description key: {key}");
        }
    }

    // ── PresetImportGuiAction ─────────────────────────────────────────────────

    #[test]
    fn gui_actions_all_returns_three_distinct_actions() {
        let all = PresetImportGuiAction::all();
        assert_eq!(all.len(), 3);

        let keys: Vec<_> = all.iter().map(|a| a.locale_key()).collect();
        let unique: std::collections::HashSet<_> = keys.iter().copied().collect();
        assert_eq!(unique.len(), 3, "action locale keys must all be distinct");
    }

    #[test]
    fn gui_action_locale_keys_are_nonempty_and_dot_separated() {
        for action in PresetImportGuiAction::all() {
            let key = action.locale_key();
            assert!(!key.is_empty());
            assert!(key.contains('.'), "locale key must be dot-separated: {key}");
        }
    }

    // ── ProSectionDisplayItem ─────────────────────────────────────────────────

    #[test]
    fn pro_section_display_item_from_unknown_section() {
        let section = UnknownSection {
            name: "CIDR".to_string(),
            entries: vec![
                crate::rules_file::RulesFileEntry {
                    match_value: "10.0.0.0/8".to_string(),
                    enabled: true,
                    inline_comment: None,
                    blocked: false,
                    origin: None,
                },
                crate::rules_file::RulesFileEntry {
                    match_value: "192.168.0.0/16".to_string(),
                    enabled: false,
                    inline_comment: None,
                    blocked: false,
                    origin: None,
                },
            ],
        };

        let item = ProSectionDisplayItem::from(&section);
        assert_eq!(item.section_name, "CIDR");
        assert_eq!(item.entry_count, 2);
    }

    #[test]
    fn pro_section_is_not_editable_and_not_active() {
        assert!(!ProSectionDisplayItem::is_editable());
        assert!(!ProSectionDisplayItem::is_active());
    }

    #[test]
    fn pro_section_locale_keys_are_nonempty_and_dot_separated() {
        let keys = [
            ProSectionDisplayItem::LOCALE_KEY_BADGE_LABEL,
            ProSectionDisplayItem::LOCALE_KEY_BADGE_TOOLTIP,
            ProSectionDisplayItem::LOCALE_KEY_INACTIVE_HINT,
            ProSectionDisplayItem::LOCALE_KEY_IMPORT_WARNING,
        ];
        for key in keys {
            assert!(!key.is_empty());
            assert!(key.contains('.'), "locale key must be dot-separated: {key}");
        }
    }

    #[test]
    fn pro_section_empty_section_has_zero_entry_count() {
        let section = UnknownSection {
            name: "Ports".to_string(),
            entries: vec![],
        };
        let item = ProSectionDisplayItem::from(&section);
        assert_eq!(item.entry_count, 0);
    }

    // ── ImportBothFilesSettingSpec ────────────────────────────────────────────

    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn import_both_files_setting_default_is_false() {
        assert!(!ImportBothFilesSettingSpec::DEFAULT);
    }

    #[test]
    fn import_both_files_locale_keys_are_nonempty_and_dot_separated() {
        let keys = [
            ImportBothFilesSettingSpec::SETTINGS_GROUP_LOCALE_KEY,
            ImportBothFilesSettingSpec::FIELD_LOCALE_KEY,
            ImportBothFilesSettingSpec::GROUP_NOTE_LOCALE_KEY,
        ];
        for key in keys {
            assert!(!key.is_empty());
            assert!(key.contains('.'), "locale key must be dot-separated: {key}");
        }
    }

    #[test]
    fn import_both_files_setting_group_key_refers_to_presets_group() {
        assert!(
            ImportBothFilesSettingSpec::SETTINGS_GROUP_LOCALE_KEY.contains("presets"),
            "group locale key must reference the 'presets' settings group"
        );
    }
}

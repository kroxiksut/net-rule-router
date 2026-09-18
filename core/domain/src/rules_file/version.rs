// Format versions, preset metadata and what a parse reports back.

use super::*;

/// Format version recognised by this build.
///
/// The header line `# NetRuleRouter rules file — version N` is parsed from the
/// file preamble. When `N` equals this constant the file is fully understood.
/// When `N` is greater, known sections are still parsed but unrecognised
/// sections/fields are ignored and [`ParseWarning::UnknownFormatVersion`] is
/// emitted.
///
/// 4, not 1: versions are cumulative and this build implements 1 (`sections,
/// comments, disabled rules`), 3 (`+block`) and 4 (`--- Auto`). Version 2 was
/// reserved for a nested `- destination` syntax that was specified and never
/// implemented — the number stays retired rather than reused, so a file means
/// the same thing in every build. While the constant said 1, every valid file
/// of the format we actually write was greeted with "some rules may be
/// ignored".
pub const CURRENT_RULES_FILE_FORMAT_VERSION: u32 = 4;

/// Format version recognised by this build for `# NetRuleRouter preset — version N` headers.
pub const CURRENT_PRESET_FORMAT_VERSION: u32 = 4;

/// Optional metadata declared in a preset file's preamble comments.
///
/// When a file starts with `# NetRuleRouter preset — version N` or contains
/// `# name: ...` / `# description: ...` metadata lines before the first
/// section header, the parser captures them here.
///
/// All fields are optional — a valid preset may omit any or all of them.
///
/// # Metadata key format
///
/// ```text
/// # NetRuleRouter preset — version 4
/// # name: Corporate VPN Rules
/// # description: Routes corporate traffic via the secondary (VPN) interface
/// # author: Jane Doe
/// # preset_version: 1
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PresetMetadata {
    /// `# name: <value>` — user-facing name for this preset.
    pub name: Option<String>,
    /// `# description: <value>` — short description of what the preset does.
    pub description: Option<String>,
    /// `# author: <value>` — author or maintainer of the preset.
    pub author: Option<String>,
    /// `# preset_version: <value>` — user-assigned version string for this
    /// preset's content (not the file format version).
    pub preset_version: Option<String>,
}

impl PresetMetadata {
    /// Returns `true` when all metadata fields are `None`.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.description.is_none()
            && self.author.is_none()
            && self.preset_version.is_none()
    }
}

/// A non-blocking warning produced during parsing.
///
/// Warnings do not prevent `ParseOutcome::parsed` from being built; they
/// report conditions the caller or GUI should surface to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseWarning {
    /// A section header with an unrecognized name was encountered.
    /// Its entries are preserved in `ParseOutcome::unknown_sections`.
    UnknownSection { name: String, entry_count: usize },
    /// The file's version header declares a format version newer than this
    /// build supports. Known sections are parsed; unknown ones are preserved
    /// as `ParseOutcome::unknown_sections`. The caller should surface this to
    /// the user so they know the file may contain rules this version ignores.
    UnknownFormatVersion { found: u32, supported: u32 },
    /// A line in the `--- Auto` section carried no `auto:` provenance token.
    ///
    /// The entry is **kept** as an ordinary rule of the file's route with no
    /// origin — a hand-edited file must never lose a rule. The caller should
    /// surface it so the user knows this line will not be shown as
    /// app-authored.
    AutoRuleMissingProvenance {
        /// The match value of the affected line.
        match_value: String,
    },
    /// A line in the `--- Auto` section carried `auto:` but was missing the
    /// `anchor:` or `added:` token.
    ///
    /// The origin is kept with the missing field empty; nothing is dropped.
    AutoRuleIncompleteProvenance {
        /// The match value of the affected line.
        match_value: String,
        /// The reason slug that was present.
        reason_slug: String,
    },
}

/// The result of [`parse_rules_file`].
///
/// Parsing is infallible — a `ParseOutcome` is always produced. Unknown
/// sections and other surprises are captured as warnings rather than errors,
/// so the caller decides how to handle them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOutcome {
    /// The parsed known sections and their entries.
    pub parsed: RulesFileParsed,
    /// Sections with names not recognised by this version of the parser.
    /// Preserved so they can be written back on export without data loss.
    /// Corresponds to unsupported sections when a file from a newer product
    /// version is opened in the Free edition.
    pub unknown_sections: Vec<UnknownSection>,
    /// Non-blocking warnings about the input.
    pub warnings: Vec<ParseWarning>,
    /// The format version declared in the file's preamble header, or `None`
    /// when the header is absent (legacy file without a version declaration).
    pub file_format_version: Option<u32>,
    /// Preset metadata extracted from preamble comments, or `None` when the
    /// file was not identified as a preset (no preset header and no metadata
    /// key-value comments before the first section).
    pub preset_metadata: Option<PresetMetadata>,
}

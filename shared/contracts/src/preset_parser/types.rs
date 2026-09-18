// What a parsed preset is made of: rules, passthrough blocks, duplicates.

use super::*;

/// Maximum number of `preview` lines returned per [`PassthroughBlock`].
/// Five is enough for the user to recognise the content type in the
/// import-review dialog without flooding the modal.
pub const PASSTHROUGH_PREVIEW_LINES: usize = 5;

/// Outcome of [`parse_canonical_rules`].
///
/// Every field is independently usable by callers — for example, the
/// import-summary banner needs only `rules` and `passthrough`, while
/// the review dialog needs `duplicate_sections` and the preview info
/// inside each `PassthroughBlock`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetParseResult {
    /// Rules extracted from known sections, in file order. The
    /// caller is responsible for assigning final `R-NNNN` ids and
    /// pinning each rule to a route.
    pub rules: Vec<ParsedRule>,
    /// Raw text of unknown sections, in encounter order. When the
    /// same section name appears twice it generates two
    /// `PassthroughBlock` entries; consult `duplicate_sections` to
    /// detect this without scanning the vector.
    pub passthrough: Vec<PassthroughBlock>,
    /// Names of sections (known or unknown) that appeared more than
    /// once. Used by the UI to prompt for a merge/last-wins/ignore
    /// policy before committing the import. Empty when the file is
    /// well-formed.
    pub duplicate_sections: Vec<DuplicateGroup>,
}

/// One rule extracted from a known section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ParsedRule {
    /// 1-based monotonic counter the parser emits for each rule it
    /// produces. Callers can map it to `R-NNNN` via
    /// `format!("R-{:04}", id_hint)`.
    pub id_hint: u32,
    /// Whether the line carried a `#` disable prefix.
    pub enabled: bool,
    /// Coarse rule type (corresponds to the matched section).
    pub rule_type: ParsedRuleType,
    /// Original case-sensitive name of the section the rule came
    /// from. Useful when callers want to preserve the section
    /// header verbatim (e.g. a file with `--- Domains` vs
    /// `--- domains` — though we accept only the canonical case).
    pub section_name: String,
    /// Match value — trimmed, with the disable prefix and inline
    /// comment already stripped. The caller is responsible for any
    /// Punycode↔Unicode boundary conversion (see
    /// `Main.qml::_unicodeDecodeHost`).
    pub match_value: String,
    /// Inline comment text after the first `#` in the value line;
    /// trimmed; empty when no inline comment was present.
    pub comment: String,
    /// Whether the line carried the per-rule `+block` flag (docs/en/rules-file-format.md Blocking destinations):
    /// matching traffic is dropped (hard WFP block) and the containing file
    /// (primary/secondary) is irrelevant for enforcement. `#[serde(default)]`
    /// so the field is optional across the `preset.parse` RPC wire.
    #[serde(default)]
    pub blocked: bool,
    /// Provenance of an app-authored rule — `Some` only for entries in the
    /// `--- Auto` section (docs/en/rules-file-format.md App-authored rules). The structured tokens are
    /// removed from `comment`, which keeps only the free text that followed
    /// them. `None` for every user-authored rule, and then absent from the
    /// RPC payload entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<crate::auto_rule::RuleOrigin>,
    /// 1-based line number in the source file. Useful for diagnostics
    /// when the caller wants to surface "rule R-0042 came from
    /// line 123".
    pub line_number: usize,
}

/// Coarse rule type derived from the section header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParsedRuleType {
    Zone,
    Domain,
    ExactIp,
    Application,
}

impl ParsedRuleType {
    /// Canonical slug used by the QML rulesModel / wire format.
    /// Mirrors `_sectionToRuleTypeSlug` in `Main.qml`.
    pub fn slug(self) -> &'static str {
        match self {
            ParsedRuleType::Zone => "zone",
            ParsedRuleType::Domain => "domain",
            ParsedRuleType::ExactIp => "exact-ip",
            ParsedRuleType::Application => "application",
        }
    }
}

/// One block of raw text from an unknown section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PassthroughBlock {
    /// Original case-sensitive section name (e.g. `"Linux"`,
    /// `"MacOS"`, `"Cidr"`).
    pub section_name: String,
    /// Verbatim content of the section, between its header and the
    /// next section header (or end of file). Newlines preserved.
    /// Trailing newline normalised — exactly one trailing `\n` when
    /// the content is non-empty, zero when empty.
    pub raw_text: String,
    /// How many lines of `raw_text` are CARRIED — every non-blank one.
    ///
    /// Surfaced in two places the user reads: the review dialog's section row
    /// ("--- Linux (5 lines)") and the import status line ("Preserved
    /// foreign-OS sections: Linux (5 lines)"). Both are about what is being
    /// preserved, so the honest measure is how much of it there is.
    ///
    /// It used to skip `#` lines as prose. In this format a DISABLED rule is
    /// written exactly that way, so a section made entirely of disabled rules
    /// reported "0 lines" while its text was non-empty and on its way to the
    /// sidecar — the dialog called it empty and preserved it anyway. Counting
    /// commented lines cannot be made exact either (`# (reserved)` and
    /// `# example.com` are indistinguishable without a rule type, which an
    /// unknown section does not have), and between over- and under-counting,
    /// over-counting matches what the label promises.
    pub content_lines: usize,
    /// First [`PASSTHROUGH_PREVIEW_LINES`] non-blank, non-comment
    /// lines from `raw_text` for the review-dialog preview area.
    /// Always a subset of `raw_text`; never references it by index.
    pub preview: Vec<String>,
}

/// Diagnostic for a section name that appeared more than once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DuplicateGroup {
    /// Section name (original case).
    pub section_name: String,
    /// Number of times the section appeared in the file. Always ≥ 2.
    pub occurrences: u32,
    /// Whether this section name is one the parser knows how to
    /// classify into rules. Affects the UI prompt — duplicates inside
    /// `Domains` mean two batches of rules to merge; duplicates inside
    /// `Linux` mean two passthrough segments to reconcile.
    pub is_known_section: bool,
}

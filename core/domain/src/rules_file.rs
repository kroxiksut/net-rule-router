//! External rules file format types and preset metadata.
//!
//! Two separate files are used — one per route role (e.g.
//! `rules_primary.txt` and `rules_secondary.txt`, though the user may choose
//! any filename). A preset is the same format with optional metadata header
//! comments. Each file follows a sectioned text format:
//!
//! ```text
//! # NetRuleRouter rules file — version 4
//!
//! --- Zones
//! corp-network  # internal corporate zone
//!
//! --- Domains
//! updates.example.org  # vendor updates
//! # old.example.com    # disabled rule
//!
//! --- IP
//! 203.0.113.7
//!
//! --- Windows
//! browser.exe   # browser traffic
//! # powershell.exe
//!
//! --- Linux
//! # (reserved — not applied on Windows)
//!
//! --- MacOS
//! # (reserved — not applied on Windows)
//!
//! --- Auto
//! rr3.example-cdn.net  # auto:site-companion anchor:example.com added:
//! ```
//!
//! A preset file adds optional metadata header comments before the first section:
//!
//! ```text
//! # NetRuleRouter preset — version 4
//! # name: Corporate VPN Rules
//! # description: Routes corporate traffic via VPN
//! # author: Jane Doe
//! # preset_version: 1
//! ```
//!
//! # Syntax rules
//!
//! - `--- SectionName` — section header (names are technical keywords, never localized)
//! - `value` — active rule
//! - `value  # text` — active rule with inline comment (label in GUI)
//! - `# value` — disabled rule (GUI toggle-off maps to commenting the line)
//! - lines with only `#` text and no rule token — free comments, ignored by parser
//! - empty lines — ignored
//!
//! # Platform filtering
//!
//! On Windows, `--- Linux` and `--- MacOS` sections are parsed and preserved
//! but not applied. The GUI hides them by default; "Show rules for other
//! operating systems" makes them visible.
//!
//! # Evaluation priority
//!
//! See [`RulesFileEvaluationPriority`] for the fixed priority order.

use core::fmt;

use nrr_shared::auto_rule::{parse_provenance_comment, RuleOrigin};

// ── RulesFileSection ──────────────────────────────────────────────────────────

/// A section in a rules file.
///
/// Section names are technical keywords — they are **not translated** and must
/// appear exactly as listed in files. The GUI may display localized descriptions
/// *about* each section, but the name itself is invariant.
///
/// The enum is `#[non_exhaustive]`: further sections (`CIDR`, `Ports`, …) may
/// become variants later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RulesFileSection {
    /// Zone-level routing — the highest-priority group abstraction.
    ///
    /// A zone entry routes a named group of hosts or domain ranges as a unit.
    /// Active in the Free edition on all platforms.
    Zones,
    /// Suffix and exact FQDN domain rules.
    /// Active in the Free edition on all platforms.
    Domains,
    /// Exact IP address rules. No CIDR; CIDR matching is not supported.
    /// Active in the Free edition on all platforms.
    Ip,
    /// Windows application rules matched by `.exe` filename (case-insensitive).
    /// Present in files on all platforms; applied **only on Windows**.
    Windows,
    /// Linux application rules matched by process name or path.
    /// Present in files on all platforms; applied **only on Linux**.
    Linux,
    /// macOS application rules matched by bundle ID or process name.
    /// Present in files on all platforms; applied **only on macOS**.
    MacOS,
    /// Rules the application authored on the user's behalf.
    ///
    /// Values are domain-style, exactly as in [`RulesFileSection::Domains`]:
    /// a bare hostname is an exact FQDN, `*.example.com` is a suffix domain.
    /// The section exists so app-authored rules stay visibly separate from the
    /// user's own list; it is not a distinct match kind.
    ///
    /// Every entry carries its provenance in a structured inline comment —
    /// see [`RulesFileEntry::origin`]. Active in the Free edition on all
    /// platforms.
    Auto,
}

impl RulesFileSection {
    /// All sections that appear in a Free-edition rules file, in canonical file order.
    ///
    /// `Auto` sorts last so a file reads as "what you wrote, then what the
    /// application added for you".
    pub const ALL: [Self; 7] = [
        Self::Zones,
        Self::Domains,
        Self::Ip,
        Self::Windows,
        Self::Linux,
        Self::MacOS,
        Self::Auto,
    ];

    /// The canonical section name as it appears after `--- ` in the file.
    ///
    /// This is a technical keyword. It is never passed through the locale layer.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Zones => "Zones",
            Self::Domains => "Domains",
            Self::Ip => "IP",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOS => "MacOS",
            Self::Auto => nrr_shared::auto_rule::AUTO_SECTION_NAME,
        }
    }

    /// Returns `true` if this section's rules are applied on `platform`.
    ///
    /// Sections that are inactive on the current platform are still parsed and
    /// preserved in the file — they are never silently stripped on export.
    pub const fn is_active_on(self, platform: HostPlatform) -> bool {
        match self {
            Self::Zones | Self::Domains | Self::Ip | Self::Auto => true,
            Self::Windows => matches!(platform, HostPlatform::Windows),
            Self::Linux => matches!(platform, HostPlatform::Linux),
            Self::MacOS => matches!(platform, HostPlatform::MacOS),
        }
    }

    /// Returns `true` if this section is platform-specific (not cross-platform).
    ///
    /// Platform-specific sections are hidden in the GUI by default when the
    /// running platform does not match. The "Show rules for other operating
    /// systems" GUI setting makes them visible.
    pub const fn is_platform_specific(self) -> bool {
        matches!(self, Self::Windows | Self::Linux | Self::MacOS)
    }

    /// Parses a section header line of the form `--- SectionName`.
    ///
    /// Returns `None` if the line is not a section header or the section name
    /// is unrecognized. Callers that need to preserve unknown sections should
    /// handle the `None` case explicitly.
    pub fn parse_header(line: &str) -> Option<Self> {
        let name = line.strip_prefix("--- ")?.trim();
        Self::from_name(name)
    }

    /// Looks up a `RulesFileSection` by its canonical name (case-sensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        // Case-insensitive, mirroring `nrr_shared::preset_parser`'s
        // `classify_section_lenient`. The GUI / launcher parser accepts
        // `--- domains` / `--- ip` in any case, so the server must classify
        // them identically — otherwise a hand-edited file imports as rules on
        // the GUI side but drops to passthrough server-side (the strict-vs-
        // lenient divergence).
        // Variant *names* (`name()`) stay canonical so exports are unchanged.
        match name.to_ascii_lowercase().as_str() {
            "zones" => Some(Self::Zones),
            "domains" => Some(Self::Domains),
            "ip" => Some(Self::Ip),
            "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::MacOS),
            "auto" => Some(Self::Auto),
            _ => None,
        }
    }

    /// `true` for the section whose entries are authored by the application
    /// rather than by the user.
    ///
    /// Entries here are the only ones that carry a
    /// [`RulesFileEntry::origin`] — the parser reads the provenance tokens in
    /// this section and nowhere else, so an inline comment that happens to
    /// start with `auto:` in a user's own `--- Domains` list stays an ordinary
    /// comment.
    pub const fn is_app_authored(self) -> bool {
        matches!(self, Self::Auto)
    }
}

impl fmt::Display for RulesFileSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ── HostPlatform ──────────────────────────────────────────────────────────────

/// The host platform on which the application is running.
///
/// Used to determine which [`RulesFileSection`]s are active for rule evaluation.
/// Platform-inactive sections (e.g. `Linux` and `MacOS` on Windows) are parsed
/// and preserved in the file but not applied to routing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPlatform {
    Windows,
    Linux,
    MacOS,
}

impl HostPlatform {
    /// Returns the platform the binary was compiled for.
    ///
    /// On unsupported platforms, falls back to `Windows` — this is a
    /// Windows-first product and a conservative default is preferred.
    pub const fn compiled() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOS
        } else {
            Self::Windows
        }
    }
}

// ── RulesFileEntry ────────────────────────────────────────────────────────────

/// A single entry (one rule line) within a rules file section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulesFileEntry {
    /// The match value: zone name, domain, IP, exe filename, etc.
    pub match_value: String,
    /// Text after the inline `#` on the same line as an active rule.
    /// Shown as a label/description in the GUI rule list.
    pub inline_comment: Option<String>,
    /// `true` = rule is active (uncommented line in file).
    /// `false` = rule is disabled (`# match_value` in file).
    pub enabled: bool,
    /// `true` when the line carried the `+block` flag: matching traffic is
    /// dropped (hard WFP block) regardless of which file the rule lives in.
    pub blocked: bool,
    /// Provenance of an app-authored entry, parsed from the structured
    /// `auto:… anchor:… added:…` prefix of the inline comment.
    ///
    /// `Some` only for entries in [`RulesFileSection::Auto`]; `None` for every
    /// user-authored rule. The tokens are *not* duplicated in
    /// `inline_comment` — that field keeps only the free text that followed
    /// them, and the writer re-renders the tokens from these typed fields.
    pub origin: Option<RuleOrigin>,
}

impl RulesFileEntry {
    /// Constructs an enabled entry with no inline comment.
    pub fn enabled(match_value: impl Into<String>) -> Self {
        Self {
            match_value: match_value.into(),
            inline_comment: None,
            enabled: true,
            blocked: false,
            origin: None,
        }
    }

    /// Constructs an enabled entry with an inline comment.
    pub fn enabled_with_comment(
        match_value: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        Self {
            match_value: match_value.into(),
            inline_comment: Some(comment.into()),
            enabled: true,
            blocked: false,
            origin: None,
        }
    }

    /// Constructs a disabled (commented-out) entry.
    pub fn disabled(match_value: impl Into<String>) -> Self {
        Self {
            match_value: match_value.into(),
            inline_comment: None,
            enabled: false,
            blocked: false,
            origin: None,
        }
    }

    /// Constructs an enabled app-authored entry for
    /// [`RulesFileSection::Auto`], with no free-text note.
    pub fn auto(match_value: impl Into<String>, origin: RuleOrigin) -> Self {
        Self {
            match_value: match_value.into(),
            inline_comment: None,
            enabled: true,
            blocked: false,
            origin: Some(origin),
        }
    }
}

// ── SectionContent ────────────────────────────────────────────────────────────

/// All entries for one section within a rules file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionContent {
    /// The section this content belongs to.
    pub section: RulesFileSection,
    /// Rule entries in file order.
    pub entries: Vec<RulesFileEntry>,
}

impl SectionContent {
    /// Number of enabled entries in this section.
    pub fn enabled_count(&self) -> usize {
        self.entries.iter().filter(|e| e.enabled).count()
    }

    /// Number of disabled entries in this section.
    pub fn disabled_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.enabled).count()
    }

    /// `true` when the section has no entries (active or disabled).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── RulesFileParsed ───────────────────────────────────────────────────────────

/// The parsed contents of a single rules file.
///
/// Sections are stored in the order they appeared in the file. The parse stage
/// produces this type; it is the output contract of the parser.
///
/// Round-trip invariant: exporting a `RulesFileParsed` back to text and
/// re-parsing it must produce an identical value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulesFileParsed {
    /// Sections in file order. Each known section appears at most once.
    pub sections: Vec<SectionContent>,
}

impl RulesFileParsed {
    /// Returns the entries for `section`, or an empty slice if the section is absent.
    pub fn entries_for(&self, section: RulesFileSection) -> &[RulesFileEntry] {
        self.sections
            .iter()
            .find(|s| s.section == section)
            .map_or(&[], |s| s.entries.as_slice())
    }

    /// Number of enabled entries in `section`.
    pub fn enabled_count_for(&self, section: RulesFileSection) -> usize {
        self.entries_for(section)
            .iter()
            .filter(|e| e.enabled)
            .count()
    }

    /// Iterates sections that are active on `platform`, in file order.
    pub fn active_sections_for(
        &self,
        platform: HostPlatform,
    ) -> impl Iterator<Item = &SectionContent> {
        self.sections
            .iter()
            .filter(move |s| s.section.is_active_on(platform))
    }

    /// Total enabled entry count across all sections active on `platform`.
    pub fn total_active_enabled_count(&self, platform: HostPlatform) -> usize {
        self.active_sections_for(platform)
            .map(|s| s.enabled_count())
            .sum()
    }

    /// `true` when all known Free-edition sections are present in the file.
    pub fn has_all_free_sections(&self) -> bool {
        RulesFileSection::ALL
            .iter()
            .all(|&s| self.sections.iter().any(|c| c.section == s))
    }
}

// ── RulesFileEvaluationPriority ───────────────────────────────────────────────

/// Documents the fixed rule evaluation priority for the Free edition.
///
/// This type carries no runtime behaviour — it exists to make the priority
/// order explicit and discoverable at the domain level.
///
/// # Priority (highest to lowest)
///
/// 1. **Zones** — zone-level group routing. An exact zone match short-circuits
///    all lower tiers.
/// 2. **Domains (exact FQDN)** — longest label wins among domain rules.
/// 3. **Domains (suffix/subdomain)** — e.g. `example.com` matches
///    `www.example.com` at any depth.
/// 4. **IP** — exact IP address. CIDR matching is not supported.
/// 5. **Application** (`Windows` / `Linux` / `MacOS`) — matched by process
///    name. Only the platform-appropriate section is evaluated.
/// 6. **Default route** — `ActiveConfiguration.behavior_mode` decides.
///
/// # Child process inheritance
///
/// When "Apply rules to child processes" is enabled in GUI Settings, a matched
/// application rule also applies to direct child processes. An explicit rule
/// for the child process **always** takes priority over inherited routing.
///
/// # Per-route evaluation
///
/// Both the primary and secondary [`RulesFileParsed`] are evaluated
/// independently. The first match across both files determines the route.
pub struct RulesFileEvaluationPriority;

// ── UnknownSection ───────────────────────────────────────────────────────────

/// A section whose name is not recognised by this version of the parser.
///
/// Unknown sections are **preserved** so they survive a Free-edition
/// round-trip without data loss. This is the forward-compatibility mechanism
/// for unsupported sections (`CIDR`, `Ports`, etc.) appearing in a file from
/// a newer product version.
///
/// The GUI displays these rules with a "not applied" badge and
/// keeps them inactive until the user upgrades.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownSection {
    /// The raw section name as it appeared after `--- `, e.g. `"CIDR"`.
    pub name: String,
    /// Rule entries from this section in file order.
    pub entries: Vec<RulesFileEntry>,
}

// ── PassthroughSection ───────────────────────────────────────────────────────

/// A section this build does not parse, carried through an export as the raw
/// body text captured when the file was imported.
///
/// [`UnknownSection`] is what the PARSER produces — structured entries it can
/// still round-trip. This is what an EXPORTER has: the canonical revision store
/// keeps no unknown sections, so the only faithful representation left is the
/// bytes themselves. Reconstructing entries from them would drop the comments
/// and blank lines that make the round-trip byte-exact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassthroughSection {
    /// Section name as it appeared after `--- `, without the marker.
    pub name: String,
    /// The section body, no header line. A non-empty body ends in exactly one
    /// newline; the writer does not add or remove any.
    pub body: String,
}

// ── Parse stage ───────────────────────────────────────────────────────────────

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

/// Parses a rules file from its raw text content.
///
/// The parser is lenient by design: unknown sections are preserved with a
/// warning, unrecognized lines are treated as free comments, and the function
/// never returns an error. Semantic validation of individual rule values is
/// done later in the pipeline by [`crate::validation::validate_and_canonicalize`].
///
/// # Algorithm
///
/// Lines are classified in order:
/// 1. Empty or whitespace-only → ignored.
/// 2. `--- SectionName` → section header; starts a new section context.
/// 3. `# value` → disabled rule if the part after `#` is a single word;
///    otherwise a free comment (ignored).
/// 4. Any other non-empty line → active rule, optionally with an inline comment
///    after `#`.
///
/// Lines before the first section header are treated as free comments.
/// Tries to extract the format version from a preamble line of the form
/// `# NetRuleRouter rules file — version N`.
fn parse_version_header(line: &str) -> Option<u32> {
    parse_dashed_header(line, "# NetRuleRouter rules file ", " version ")
}

/// Every dash a person or an editor can produce where the format documents an
/// em-dash.
///
/// Only the em-dash is WRITTEN, and the docs keep saying so. Accepting only it
/// on READ was a separate decision, and the wrong one: an ASCII hyphen is what
/// a keyboard gives you, what an editor's autocorrect leaves behind, and what
/// most of the presets in this repository actually contain — so their version
/// header went unrecognised, `is_preset_file` stayed false, and the "this file
/// is from a newer version" branch could never fire on the files it was
/// written for.
const HEADER_DASHES: [&str; 3] = ["\u{2014}", "\u{2013}", "-"];

/// `{prefix}{dash}{infix}{number}`, for any accepted spelling of the dash.
fn parse_dashed_header(line: &str, prefix: &str, infix: &str) -> Option<u32> {
    let rest = line.trim().strip_prefix(prefix)?;
    for dash in HEADER_DASHES {
        if let Some(number) = rest.strip_prefix(dash).and_then(|t| t.strip_prefix(infix)) {
            return number.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Parses a preset format header: `# NetRuleRouter preset — version N`.
///
/// Returns the declared format version or `None` if the line does not match.
fn parse_preset_header(line: &str) -> Option<u32> {
    parse_dashed_header(line, "# NetRuleRouter preset ", " version ")
}

/// Parses a metadata key-value comment from the file preamble.
///
/// Matches `# key: value` where `key` is a non-empty ASCII word token
/// (letters, digits, underscores) and `value` is the trimmed remainder.
/// Returns `(key, value)` or `None` if the line does not match.
fn parse_metadata_kv(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix('#')?.trim_start();
    let colon = rest.find(':')?;
    let key = rest[..colon].trim();
    if key.is_empty()
        || key.contains(char::is_whitespace)
        || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let value = rest[colon + 1..].trim();
    Some((key, value))
}

pub fn parse_rules_file(input: &str) -> ParseOutcome {
    // A file saved by a Windows editor starts with a BOM. One caller
    // (`preset_validation`) stripped it before handing the text over and the
    // others did not, so the same file parsed differently depending on the
    // route in. Stripped here, once, for every caller and both parsers.
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let mut known: Vec<SectionContent> = Vec::new();
    let mut unknown: Vec<UnknownSection> = Vec::new();
    // Name → position in `unknown`, so a file full of distinct headers costs
    // linear time rather than quadratic.
    let mut unknown_index: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut warnings: Vec<ParseWarning> = Vec::new();
    let mut file_format_version: Option<u32> = None;
    let mut is_preset_file = false;
    let mut preset_meta: Option<PresetMetadata> = None;

    // Which slot is "current": either an index into `known` or `unknown`.
    enum Slot {
        Known(usize),
        Unknown(usize),
    }
    let mut current: Option<Slot> = None;

    for line in input.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            continue;
        }

        // Section header? Checked first so `--- SectionName` lines are never
        // consumed by the preamble block below.
        //
        // Recognised by the SHARED header parser, not by a second reading of
        // the same spec: this side used to accept a header with leading
        // whitespace (`  --- IP`) while the GUI's parser did not, so the
        // service opened a section the GUI kept feeding to the previous one —
        // and every address after it landed under the wrong heading. The strict
        // reading is the one the format documents.
        if let Some(name) = nrr_shared::preset_parser::parse_section_header(line) {
            match RulesFileSection::from_name(name) {
                Some(section) => {
                    // Merge into existing slot for this section (handles duplicate headers).
                    let idx = known
                        .iter()
                        .position(|s| s.section == section)
                        .unwrap_or_else(|| {
                            known.push(SectionContent {
                                section,
                                entries: Vec::new(),
                            });
                            known.len() - 1
                        });
                    current = Some(Slot::Known(idx));
                }
                None => {
                    // Indexed, not scanned: the section name comes from the
                    // file, so a linear lookup per header is quadratic in a
                    // value the caller controls — and this parser is reachable
                    // over IPC with a 1 MiB payload (~116k headers, tens of
                    // seconds of CPU). The known-section lookup below stays a
                    // scan: its length is the enum's, not the file's.
                    let idx = *unknown_index.entry(name.to_string()).or_insert_with(|| {
                        unknown.push(UnknownSection {
                            name: name.to_string(),
                            entries: Vec::new(),
                        });
                        unknown.len() - 1
                    });
                    // Emit warning on first encounter only.
                    if unknown[idx].entries.is_empty() {
                        warnings.push(ParseWarning::UnknownSection {
                            name: name.to_string(),
                            entry_count: 0, // updated after parsing entries
                        });
                    }
                    current = Some(Slot::Unknown(idx));
                }
            }
            continue;
        }

        // Preamble lines (before any section header has been encountered).
        if current.is_none() {
            // Format version header — matched once, two accepted forms.
            if file_format_version.is_none() {
                if let Some(v) = parse_version_header(trimmed) {
                    file_format_version = Some(v);
                    if v > CURRENT_RULES_FILE_FORMAT_VERSION {
                        warnings.push(ParseWarning::UnknownFormatVersion {
                            found: v,
                            supported: CURRENT_RULES_FILE_FORMAT_VERSION,
                        });
                    }
                    continue;
                }
                if let Some(v) = parse_preset_header(trimmed) {
                    file_format_version = Some(v);
                    is_preset_file = true;
                    if v > CURRENT_PRESET_FORMAT_VERSION {
                        warnings.push(ParseWarning::UnknownFormatVersion {
                            found: v,
                            supported: CURRENT_PRESET_FORMAT_VERSION,
                        });
                    }
                    continue;
                }
            }
            // Metadata key-value comment (# key: value).
            if let Some((key, value)) = parse_metadata_kv(trimmed) {
                let meta = preset_meta.get_or_insert_with(PresetMetadata::default);
                match key {
                    "name" => meta.name = Some(value.to_string()),
                    "description" => meta.description = Some(value.to_string()),
                    "author" => meta.author = Some(value.to_string()),
                    "preset_version" => meta.preset_version = Some(value.to_string()),
                    _ => {}
                }
            }
            // Remaining preamble lines (free comments) are ignored.
            continue;
        }

        // Rule entry (current section is active).
        let slot = match &current {
            Some(s) => s,
            None => continue,
        };

        let mut entry = if let Some(rest) = trimmed.strip_prefix('#') {
            // Possibly a disabled rule — `nrr_shared` owns the one predicate
            // that tells a disabled rule from a prose comment.
            let rest = rest.trim_start();
            if rest.is_empty() || rest.starts_with('#') {
                // Pure comment line — ignore.
                continue;
            }
            let (value, comment) = split_inline_comment(rest);
            let value = value.trim();
            // Extract the `+block` flag BEFORE the whitespace check so a
            // disabled blocked rule (`# example.com +block`) is not mistaken
            // for a prose comment.
            let (value, blocked) = extract_rule_flags(value);
            let rule_type = match &current {
                Some(Slot::Known(idx)) => {
                    nrr_shared::preset_parser::classify_section_lenient(known[*idx].section.name())
                }
                _ => None,
            };
            let is_rule = match rule_type {
                Some(kind) => nrr_shared::preset_parser::is_disabled_rule_value(kind, &value),
                None => !value.contains(char::is_whitespace),
            };
            if value.is_empty() || !is_rule {
                // Prose comment like "# this is a note about example.com" — ignore.
                continue;
            }
            RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: false,
                blocked,
                origin: None,
            }
        } else {
            let (value, comment) = split_inline_comment(trimmed);
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let (value, blocked) = extract_rule_flags(value);
            if value.is_empty() {
                continue;
            }
            RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: true,
                blocked,
                origin: None,
            }
        };

        match slot {
            Slot::Known(idx) => {
                // Provenance tokens are read in the app-authored section only,
                // so a user comment that happens to start with `auto:` in
                // their own list is never swallowed.
                if known[*idx].section.is_app_authored() {
                    take_provenance(&mut entry, &mut warnings);
                }
                known[*idx].entries.push(entry)
            }
            Slot::Unknown(idx) => unknown[*idx].entries.push(entry),
        }
    }

    // Update entry_count in UnknownSection warnings now that parsing is done —
    // through the same index, so this pass is linear too.
    for w in &mut warnings {
        if let ParseWarning::UnknownSection { name, entry_count } = w {
            if let Some(idx) = unknown_index.get(name) {
                *entry_count = unknown[*idx].entries.len();
            }
        }
    }

    let preset_metadata = if is_preset_file {
        Some(preset_meta.unwrap_or_default())
    } else {
        preset_meta
    };

    ParseOutcome {
        parsed: RulesFileParsed { sections: known },
        unknown_sections: unknown,
        warnings,
        file_format_version,
        preset_metadata,
    }
}

/// Moves the structured provenance prefix of an `--- Auto` entry's inline
/// comment into `entry.origin`, leaving only the free-text note behind.
///
/// A line whose comment carries no recognisable `auto:` token keeps that
/// comment verbatim and stays an ordinary rule of the file's route — a
/// hand-edited file must never lose a rule — and the condition is reported as
/// a warning instead of an error.
fn take_provenance(entry: &mut RulesFileEntry, warnings: &mut Vec<ParseWarning>) {
    let parsed = entry
        .inline_comment
        .as_deref()
        .and_then(parse_provenance_comment);
    match parsed {
        Some(provenance) => {
            if !provenance.complete {
                warnings.push(ParseWarning::AutoRuleIncompleteProvenance {
                    match_value: entry.match_value.clone(),
                    reason_slug: provenance.origin.reason().as_slug().to_string(),
                });
            }
            entry.inline_comment = provenance.note;
            entry.origin = Some(provenance.origin);
        }
        None => warnings.push(ParseWarning::AutoRuleMissingProvenance {
            match_value: entry.match_value.clone(),
        }),
    }
}

/// Splits a rule line at the first `#`, returning `(value, inline_comment)`.
///
/// Both parts are trimmed. `inline_comment` is `None` when there is no `#`.
fn split_inline_comment(s: &str) -> (String, Option<String>) {
    match s.find('#') {
        None => (s.to_string(), None),
        Some(pos) => {
            let value = s[..pos].trim().to_string();
            let comment = s[pos + 1..].trim().to_string();
            let comment = if comment.is_empty() {
                None
            } else {
                Some(comment)
            };
            (value, comment)
        }
    }
}

/// Per-rule `+block` flag token (docs/en/rules-file-format.md Blocking destinations). Placed after the match
/// value and before any inline `#` comment; mirrors the `+children` convention.
const BLOCK_FLAG: &str = "+block";

/// Per-rule child-process flag, documented in the rules-file format.
///
/// Consumed but not acted on: the matcher needs a process-tree snapshot it is
/// never given (see the note in `decision_rules_matching`). Consuming it is not
/// cosmetic — left in the value, `codex.exe +children` normalised to the
/// executable pattern `codex.exe +children.exe`, which matches nothing, so a
/// user following the shipped documentation got a rule that silently covered
/// no process at all. Dropped, the rule covers the named process, which is the
/// closest thing to what was asked for.
const CHILDREN_FLAG: &str = "+children";

/// Splits a match value into its head (the actual match value) and the parsed
/// per-rule flags, extracting the documented flag tokens.
///
/// The first whitespace-separated token is always the match value; a subsequent
/// `+block` token is consumed and reported as `blocked = true`, and
/// `+children` is consumed as well (see [`CHILDREN_FLAG`] for why it is
/// consumed while nothing acts on it). Non-flag trailing tokens are preserved
/// in the returned head so the semantic validator can still diagnose them
/// (e.g. accidental whitespace in a value).
fn extract_rule_flags(value: &str) -> (String, bool) {
    let mut blocked = false;
    let mut kept: Vec<&str> = Vec::new();
    for (idx, token) in value.split_whitespace().enumerate() {
        if idx > 0 && token == BLOCK_FLAG {
            blocked = true;
        } else if idx > 0 && token == CHILDREN_FLAG {
            // Consumed, not acted on — see `CHILDREN_FLAG`.
        } else {
            kept.push(token);
        }
    }
    (kept.join(" "), blocked)
}

// ── File-to-RuleSet conversion ────────────────────────────────────────────────

/// Converts a [`RulesFileParsed`] into a [`crate::RouteRuleSet`] for one route.
///
/// This is the bridge between the parse stage and the semantic
/// validation pipeline. The returned `RouteRuleSet` can be placed
/// into an [`crate::ActiveConfiguration`] and passed to
/// [`crate::validation::validate_and_canonicalize`].
///
/// Only sections that are active on `platform` are converted. Sections for
/// other platforms are skipped.
///
/// # Rule IDs
///
/// Parse-time IDs use the short format `"r-{index:04}"` (rendered `R-NNNN`
/// in the GUI). They are stable within a single parse run but not across
/// runs, and are route-local (primary and secondary each start at `r-0000`).
///
/// # `include_child_processes`
///
/// This is a global GUI setting, not a per-rule file attribute. The caller
/// passes the current value; it is applied uniformly to all application rules.
pub fn rules_file_to_route_rule_set(
    parsed: &RulesFileParsed,
    platform: HostPlatform,
    include_child_processes: bool,
) -> crate::RouteRuleSet {
    use crate::{AddressMatch, AppMatch, AppMatchPattern, Rule, RuleId};

    let mut rules = Vec::new();
    let mut global_idx: usize = 0;

    for section_content in parsed.active_sections_for(platform) {
        let section = section_content.section;
        for entry in &section_content.entries {
            // Short, route-local id (`r-0001`, rendered `R-0001` in the GUI),
            // matching `nrr_shared::preset_parser`'s `R-{:04}` scheme. The
            // section is shown in the rule-type column, so it does not need
            // to live in the id.
            let id = RuleId(format!("r-{global_idx:04}"));
            global_idx += 1;

            let (address_match, app_match) = match section {
                RulesFileSection::Zones => (
                    // Zones accept `*.ru` and `ru` — both are valid inputs.
                    // The validator strips the `*.` prefix during normalization.
                    Some(AddressMatch::Zone(entry.match_value.clone())),
                    None,
                ),
                // `Auto` shares the domain value grammar — it separates
                // authorship, not match kinds.
                RulesFileSection::Domains | RulesFileSection::Auto => {
                    // `*.example.com` → SuffixDomain (stored without `*.` prefix).
                    // `example.com` → ExactFqdn.
                    let addr_match = if let Some(label) = entry.match_value.strip_prefix("*.") {
                        AddressMatch::SuffixDomain(label.to_string())
                    } else {
                        AddressMatch::ExactFqdn(entry.match_value.clone())
                    };
                    (Some(addr_match), None)
                }
                RulesFileSection::Ip => {
                    let addr = entry.match_value.parse::<std::net::IpAddr>().ok();
                    match addr {
                        Some(ip) => (Some(AddressMatch::ExactIp(ip)), None),
                        // Unparseable IP — pass through as ExactFqdn so the
                        // semantic validator can produce a proper diagnostic.
                        None => (
                            Some(AddressMatch::ExactFqdn(entry.match_value.clone())),
                            None,
                        ),
                    }
                }
                // Platform-specific app sections.
                RulesFileSection::Windows | RulesFileSection::Linux | RulesFileSection::MacOS => {
                    let pattern = if entry.match_value.contains('*') {
                        AppMatchPattern::Glob(entry.match_value.clone())
                    } else {
                        AppMatchPattern::Exact(entry.match_value.clone())
                    };
                    (
                        None,
                        Some(AppMatch {
                            pattern,
                            include_child_processes,
                            windows_service_name: None,
                        }),
                    )
                }
            };

            rules.push(Rule {
                id,
                enabled: entry.enabled,
                address_match,
                app_match,
                comment: entry.inline_comment.clone().unwrap_or_default(),
                action: if entry.blocked {
                    crate::RuleAction::Block
                } else {
                    crate::RuleAction::Route
                },
                origin: entry.origin.clone(),
            });
        }
    }

    crate::RouteRuleSet { rules }
}

// ── CanonicalRuleSet → RulesFileParsed converter ──────────────────────────────

/// Converts a [`crate::CanonicalRuleSet`] into a [`RulesFileParsed`] suitable
/// for [`write_rules_file`]. Inverse of the parser+canonicalize pipeline for
/// the subset of canonical rules that map back to the Free-edition section
/// model.
///
/// # Section mapping
///
/// | Canonical address kind     | File section | Match value rendering |
/// |----------------------------|--------------|-----------------------|
/// | `ExactFqdn(label)`         | `Domains`    | `label`               |
/// | `SuffixDomain(label)`      | `Domains`    | `*.label`             |
/// | `Zone(name)`               | `Zones`      | `name`                |
/// | `ExactIp(addr)`            | `IP`         | `addr.to_string()`    |
/// | (app match, no address)    | `host_app_section` | `pattern.as_str()` |
///
/// A rule carrying an [`nrr_shared::auto_rule::RuleOrigin`] overrides the
/// address-kind mapping for the two domain kinds and lands in `Auto` instead,
/// with its provenance rendered into the inline comment.
///
/// # `host_app_section`
///
/// Free-edition canonical rules don't carry a platform tag — app match
/// values were normalized assuming the current host. Callers pass the
/// section header that matches the host (`RulesFileSection::Windows`
/// on Windows, `Linux` / `MacOS` elsewhere). On a non-matching host the
/// parser would skip these rules; round-trip is host-local only.
///
/// # Section ordering
///
/// Sections appear in canonical order (Zones → Auto) regardless of input
/// rule order. Sections with no rules are omitted (matches the writer's
/// "only sections present" semantics).
///
/// # Empty section behaviour
///
/// If the rule set contains no rules for a section, that section is **not**
/// emitted in the returned `RulesFileParsed`. Callers that want the full
/// section skeleton (docs/en/rules-file-format.md Sections "self-documenting") must pad with
/// empty `SectionContent` entries themselves.
pub fn canonical_rule_set_to_rules_file_parsed(
    set: &crate::canonical::CanonicalRuleSet,
    host_app_section: RulesFileSection,
) -> RulesFileParsed {
    use crate::canonical::{CanonicalAddressMatch, CanonicalAppPattern};

    let mut zones: Vec<RulesFileEntry> = Vec::new();
    let mut domains: Vec<RulesFileEntry> = Vec::new();
    let mut ips: Vec<RulesFileEntry> = Vec::new();
    let mut apps: Vec<RulesFileEntry> = Vec::new();
    let mut auto: Vec<RulesFileEntry> = Vec::new();

    for rule in set.rules() {
        let comment = if rule.comment.is_empty() {
            None
        } else {
            Some(rule.comment.clone())
        };
        let blocked = matches!(rule.action, crate::RuleAction::Block);

        if let Some(addr) = &rule.address_match {
            // App-authored rules are emitted under `--- Auto`, which carries
            // domain-style values only. An IP or a zone written there would be
            // re-read as a hostname on the next load, so those keep their
            // natural section — a combination the authoring path never
            // produces, since it only learns hostnames.
            let app_authored = rule.origin.is_some()
                && matches!(
                    addr,
                    CanonicalAddressMatch::ExactFqdn(_) | CanonicalAddressMatch::SuffixDomain(_)
                );
            let (bucket, value) = match addr {
                CanonicalAddressMatch::ExactFqdn(label) => (
                    if app_authored {
                        &mut auto
                    } else {
                        &mut domains
                    },
                    label.clone(),
                ),
                CanonicalAddressMatch::SuffixDomain(label) => (
                    if app_authored {
                        &mut auto
                    } else {
                        &mut domains
                    },
                    format!("*.{label}"),
                ),
                CanonicalAddressMatch::Zone(name) => (&mut zones, name.clone()),
                CanonicalAddressMatch::ExactIp(addr) => (&mut ips, addr.to_string()),
            };
            bucket.push(RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: rule.enabled,
                blocked,
                origin: if app_authored {
                    rule.origin.clone()
                } else {
                    None
                },
            });
        } else if let Some(app) = &rule.app_match {
            let value = match &app.pattern {
                CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
            };
            apps.push(RulesFileEntry {
                match_value: value,
                inline_comment: comment,
                enabled: rule.enabled,
                blocked,
                origin: None,
            });
        }
        // CanonicalRule with neither address_match nor app_match cannot
        // occur — the validation pipeline enforces "at least one of the
        // two is Some" before a rule reaches a CanonicalRuleSet. We
        // silently skip such a rule if encountered (defensive).
    }

    let mut sections = Vec::new();
    if !zones.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Zones,
            entries: zones,
        });
    }
    if !domains.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Domains,
            entries: domains,
        });
    }
    if !ips.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Ip,
            entries: ips,
        });
    }
    if !apps.is_empty() {
        sections.push(SectionContent {
            section: host_app_section,
            entries: apps,
        });
    }
    if !auto.is_empty() {
        sections.push(SectionContent {
            section: RulesFileSection::Auto,
            entries: auto,
        });
    }

    RulesFileParsed { sections }
}

// ── RulesFileParsed → text writer ─────────────────────────────────────────────

/// Serialises a [`RulesFileParsed`] (and optional unsupported sections) back to
/// canonical rules-file text.
///
/// This is the inverse of [`parse_rules_file`]: feeding the output back through
/// the parser produces a structurally equivalent [`ParseOutcome`].
///
/// # Format
///
/// - If `metadata` is `Some`, a `# NetRuleRouter preset — version 1` header is
///   written followed by `# key: value` lines for each populated metadata
///   field, then a blank line.
/// - All known sections appear in canonical order
///   (Zones → Domains → IP → Windows → Linux → MacOS → Auto), **including
///   empty sections** (docs/en/rules-file-format.md Sections — empty sections must not be stripped).
/// - Unknown sections from `unknown` are written after the known ones, in the
///   order supplied. This preserves unsupported sections through a Free
///   round-trip.
/// - Active rule line: `value` (no inline comment) or `value  # comment`
///   (two spaces before `#`, matching docs/en/rules-file-format.md Complete example examples).
/// - Disabled rule line: `# value` or `# value  # comment`.
/// - Sections are separated by a blank line for readability.
///
/// # Round-trip guarantee
///
/// For any `parsed: &RulesFileParsed`:
///
/// ```text
/// let text = write_rules_file(&parsed, &[], None);
/// let again = parse_rules_file(&text).parsed;
/// assert_eq!(again, *parsed);
/// ```
///
/// unsupported section preservation requires the caller to thread the original
/// `unknown_sections` through (the canonical revision store does not retain
/// them today). A caller holding them as raw text instead of parsed entries —
/// an exporter reading that store — uses
/// [`write_rules_file_with_passthrough`].
pub fn write_rules_file(
    parsed: &RulesFileParsed,
    unknown: &[UnknownSection],
    metadata: Option<&PresetMetadata>,
) -> String {
    write_rules_file_with_passthrough(parsed, unknown, &[], metadata)
}

/// [`write_rules_file`] plus sections carried as raw text.
///
/// An exporter reading the canonical revision store has no `unknown_sections`
/// to thread through — the store does not retain them — so without this the
/// foreign-OS and unsupported blocks a user imported are dropped on the way
/// back out, against the preservation guarantee on [`UnknownSection`]. The
/// caller that captured them at import time supplies them here.
pub fn write_rules_file_with_passthrough(
    parsed: &RulesFileParsed,
    unknown: &[UnknownSection],
    passthrough: &[PassthroughSection],
    metadata: Option<&PresetMetadata>,
) -> String {
    let mut out = String::new();

    // Preamble: preset header + metadata, when supplied.
    if let Some(meta) = metadata {
        out.push_str("# NetRuleRouter preset \u{2014} version ");
        out.push_str(&CURRENT_PRESET_FORMAT_VERSION.to_string());
        out.push('\n');
        if let Some(name) = &meta.name {
            out.push_str("# name: ");
            out.push_str(name);
            out.push('\n');
        }
        if let Some(description) = &meta.description {
            out.push_str("# description: ");
            out.push_str(description);
            out.push('\n');
        }
        if let Some(author) = &meta.author {
            out.push_str("# author: ");
            out.push_str(author);
            out.push('\n');
        }
        if let Some(preset_version) = &meta.preset_version {
            out.push_str("# preset_version: ");
            out.push_str(preset_version);
            out.push('\n');
        }
        out.push('\n');
    }

    // Emit only sections present in `parsed.sections`, but in canonical
    // order (Zones → Auto). A section that exists with zero entries is
    // preserved as `--- Name\n` per docs/en/rules-file-format.md Sections
    let by_section: std::collections::HashMap<RulesFileSection, &[RulesFileEntry]> = parsed
        .sections
        .iter()
        .map(|s| (s.section, s.entries.as_slice()))
        .collect();

    let mut first_section = true;
    for section in &RulesFileSection::ALL {
        let Some(entries) = by_section.get(section) else {
            continue;
        };
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(section.name());
        out.push('\n');
        for entry in *entries {
            write_entry_line(&mut out, entry, section.is_app_authored());
        }
    }

    // Append unknown (unsupported) sections in supplied order.
    for unknown_section in unknown {
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(&unknown_section.name);
        out.push('\n');
        for entry in &unknown_section.entries {
            write_entry_line(&mut out, entry, false);
        }
    }

    // Raw-text sections last, in supplied order. The body is emitted verbatim:
    // the point of carrying bytes instead of entries is that nothing here is
    // re-rendered.
    for section in passthrough {
        if !first_section {
            out.push('\n');
        }
        first_section = false;
        out.push_str("--- ");
        out.push_str(&section.name);
        out.push('\n');
        out.push_str(&section.body);
        if !section.body.is_empty() && !section.body.ends_with('\n') {
            out.push('\n');
        }
    }

    out
}

/// Writes a single rule line in canonical format.
///
/// - Active rule: `value` or `value  # comment`.
/// - Disabled rule: `# value` or `# value  # comment`.
///
/// The two-space separator before the inline `#` mirrors the canonical form
/// shown in docs/en/rules-file-format.md Complete example examples.
///
/// `emit_origin` is set for the app-authored section only. Its provenance
/// tokens are rendered from the entry's typed fields and precede the free-text
/// note, so a hand-edited file is normalised to canonical token order:
/// `value  # auto:<slug> anchor:<host> added:<date> <note>`.
fn write_entry_line(out: &mut String, entry: &RulesFileEntry, emit_origin: bool) {
    if !entry.enabled {
        out.push_str("# ");
    }
    out.push_str(&entry.match_value);
    if entry.blocked {
        out.push(' ');
        out.push_str(BLOCK_FLAG);
    }
    let provenance = if emit_origin {
        entry
            .origin
            .as_ref()
            .map(|origin| origin.to_provenance_comment())
    } else {
        None
    };
    if provenance.is_some() || entry.inline_comment.is_some() {
        out.push_str("  # ");
        if let Some(tokens) = &provenance {
            out.push_str(tokens);
            if entry.inline_comment.is_some() {
                out.push(' ');
            }
        }
        if let Some(comment) = &entry.inline_comment {
            out.push_str(comment);
        }
    }
    out.push('\n');
}

// ── DB cache policy invariant ─────────────────────────────────────────────────

/// Documents the invariant governing SQLite rule-cache lifecycle on file change.
///
/// This type carries no runtime behaviour — it exists to make the invariant
/// explicit and discoverable at the domain level.
///
/// # Invariant
///
/// When the user changes the configured path to a different rule file, the
/// SQLite operational rule cache **must** be cleared and fully reloaded from
/// the new file before the change takes effect. Partial reloads that leave
/// stale entries from the previous file are not permitted.
///
/// # Rationale
///
/// The file is the source of truth; SQLite is a derived index. When the source
/// of truth changes identity (different path → different rules), the derived
/// copy has no valid basis to retain prior entries.
///
/// # Enforcement point
///
/// The service layer enforces this invariant when processing a
/// "change rule file path" mutation command. This type is a domain-level
/// record of the requirement so it survives code reorganization.
pub struct RuleFileCachePolicy;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

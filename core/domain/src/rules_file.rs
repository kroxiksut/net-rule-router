//! External rules file format types and preset metadata.
//!
//! Two separate files are used — one per route role (e.g.
//! `rules_primary.txt` and `rules_secondary.txt`, though the user may choose
//! any filename). A preset is the same format with optional metadata header
//! comments. Each file follows a sectioned text format:
//!
//! ```text
//! # NetRuleRouter rules file — version 1
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
//! # NetRuleRouter preset — version 1
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
/// The enum is `#[non_exhaustive]` because the Pro edition will introduce
/// additional sections (`CIDR`, `Ports`, etc.) as new variants.
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
    /// Exact IP address rules. No CIDR; CIDR matching is a Pro feature.
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
/// 4. **IP** — exact IP address. CIDR matching is a Pro feature.
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
/// for Pro-edition sections (`CIDR`, `Ports`, etc.) appearing in a file from
/// a newer product version.
///
/// The GUI displays these rules with a Pro badge ("Available in Pro") and
/// keeps them inactive until the user upgrades.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownSection {
    /// The raw section name as it appeared after `--- `, e.g. `"CIDR"`.
    pub name: String,
    /// Rule entries from this section in file order.
    pub entries: Vec<RulesFileEntry>,
}

// ── Parse stage ───────────────────────────────────────────────────────────────

/// Format version recognised by this build.
///
/// The header line `# NetRuleRouter rules file — version N` is parsed from the
/// file preamble. When `N` equals this constant the file is fully understood.
/// When `N` is greater, known sections are still parsed but unrecognised
/// sections/fields are ignored and [`ParseWarning::UnknownFormatVersion`] is
/// emitted.
pub const CURRENT_RULES_FILE_FORMAT_VERSION: u32 = 1;

/// Format version recognised by this build for `# NetRuleRouter preset — version N` headers.
pub const CURRENT_PRESET_FORMAT_VERSION: u32 = 1;

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
/// # NetRuleRouter preset — version 1
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
    /// Corresponds to Pro-edition sections when a file from a newer product
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
/// `# NetRuleRouter rules file — version N` (with a Unicode em-dash).
fn parse_version_header(line: &str) -> Option<u32> {
    // The separator is an em-dash (U+2014), matching the documented format.
    const PREFIX: &str = "# NetRuleRouter rules file \u{2014} version ";
    line.trim().strip_prefix(PREFIX)?.trim().parse::<u32>().ok()
}

/// Parses a preset format header: `# NetRuleRouter preset — version N`.
///
/// Returns the declared format version or `None` if the line does not match.
fn parse_preset_header(line: &str) -> Option<u32> {
    const PREFIX: &str = "# NetRuleRouter preset \u{2014} version ";
    line.trim().strip_prefix(PREFIX)?.trim().parse::<u32>().ok()
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
    let mut known: Vec<SectionContent> = Vec::new();
    let mut unknown: Vec<UnknownSection> = Vec::new();
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
        if let Some(name) = trimmed.strip_prefix("--- ") {
            let name = name.trim();
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
                    let idx = unknown
                        .iter()
                        .position(|s| s.name == name)
                        .unwrap_or_else(|| {
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
            // Possibly a disabled rule. The rest (after '#', leading space trimmed)
            // must be a single word (no whitespace) to qualify as a rule value.
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
            if value.is_empty() || value.contains(char::is_whitespace) {
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

    // Update entry_count in UnknownSection warnings now that parsing is done.
    for w in &mut warnings {
        if let ParseWarning::UnknownSection { name, entry_count } = w {
            if let Some(s) = unknown.iter().find(|s| &s.name == name) {
                *entry_count = s.entries.len();
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

/// Splits a match value into its head (the actual match value) and the parsed
/// per-rule flags, extracting the `+block` flag token.
///
/// The first whitespace-separated token is always the match value; any
/// subsequent `+block` token is consumed and reported as `blocked = true`.
/// Non-flag trailing tokens are preserved in the returned head so the semantic
/// validator can still diagnose them (e.g. accidental whitespace in a value).
fn extract_rule_flags(value: &str) -> (String, bool) {
    let mut blocked = false;
    let mut kept: Vec<&str> = Vec::new();
    for (idx, token) in value.split_whitespace().enumerate() {
        if idx > 0 && token == BLOCK_FLAG {
            blocked = true;
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

/// Serialises a [`RulesFileParsed`] (and optional Pro-only sections) back to
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
///   order supplied. This preserves Pro-only sections through a Free
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
/// Pro section preservation requires the caller to thread the original
/// `unknown_sections` through (the canonical revision store does not retain
/// them today).
pub fn write_rules_file(
    parsed: &RulesFileParsed,
    unknown: &[UnknownSection],
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

    // Append unknown (Pro-only) sections in supplied order.
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
mod tests {
    use super::*;

    // ── RulesFileSection ─────────────────────────────────────────────────────

    #[test]
    fn section_names_are_stable() {
        assert_eq!(RulesFileSection::Zones.name(), "Zones");
        assert_eq!(RulesFileSection::Domains.name(), "Domains");
        assert_eq!(RulesFileSection::Ip.name(), "IP");
        assert_eq!(RulesFileSection::Windows.name(), "Windows");
        assert_eq!(RulesFileSection::Linux.name(), "Linux");
        assert_eq!(RulesFileSection::MacOS.name(), "MacOS");
        assert_eq!(RulesFileSection::Auto.name(), "Auto");
    }

    #[test]
    fn section_display_matches_name() {
        for section in RulesFileSection::ALL {
            assert_eq!(section.to_string(), section.name());
        }
    }

    #[test]
    fn section_from_name_roundtrip() {
        for section in RulesFileSection::ALL {
            assert_eq!(
                RulesFileSection::from_name(section.name()),
                Some(section),
                "roundtrip failed for {:?}",
                section
            );
        }
    }

    #[test]
    fn section_from_name_rejects_unknown() {
        assert_eq!(RulesFileSection::from_name("CIDR"), None);
        assert_eq!(RulesFileSection::from_name("cidr"), None);
        assert_eq!(RulesFileSection::from_name(""), None);
        // Case-insensitive, matching nrr_shared::preset_parser.
        assert_eq!(
            RulesFileSection::from_name("zones"),
            Some(RulesFileSection::Zones)
        );
        assert_eq!(
            RulesFileSection::from_name("IP"),
            Some(RulesFileSection::Ip)
        );
        assert_eq!(
            RulesFileSection::from_name("ip"),
            Some(RulesFileSection::Ip)
        );
    }

    #[test]
    fn section_parse_header_roundtrip() {
        for section in RulesFileSection::ALL {
            let header = format!("--- {}", section.name());
            assert_eq!(
                RulesFileSection::parse_header(&header),
                Some(section),
                "parse_header failed for {:?}",
                section
            );
        }
    }

    #[test]
    fn section_parse_header_rejects_non_headers() {
        assert_eq!(RulesFileSection::parse_header("Zones"), None);
        assert_eq!(RulesFileSection::parse_header("-- Zones"), None);
        assert_eq!(RulesFileSection::parse_header("# --- Zones"), None);
        assert_eq!(RulesFileSection::parse_header("--- CIDR"), None);
    }

    #[test]
    fn section_parse_header_trims_trailing_whitespace() {
        assert_eq!(
            RulesFileSection::parse_header("--- Zones  "),
            Some(RulesFileSection::Zones)
        );
    }

    #[test]
    fn cross_platform_sections_active_on_all_platforms() {
        for section in [
            RulesFileSection::Zones,
            RulesFileSection::Domains,
            RulesFileSection::Ip,
        ] {
            assert!(section.is_active_on(HostPlatform::Windows));
            assert!(section.is_active_on(HostPlatform::Linux));
            assert!(section.is_active_on(HostPlatform::MacOS));
            assert!(!section.is_platform_specific());
        }
    }

    #[test]
    fn platform_specific_sections_active_only_on_matching_platform() {
        assert!(RulesFileSection::Windows.is_active_on(HostPlatform::Windows));
        assert!(!RulesFileSection::Windows.is_active_on(HostPlatform::Linux));
        assert!(!RulesFileSection::Windows.is_active_on(HostPlatform::MacOS));

        assert!(RulesFileSection::Linux.is_active_on(HostPlatform::Linux));
        assert!(!RulesFileSection::Linux.is_active_on(HostPlatform::Windows));
        assert!(!RulesFileSection::Linux.is_active_on(HostPlatform::MacOS));

        assert!(RulesFileSection::MacOS.is_active_on(HostPlatform::MacOS));
        assert!(!RulesFileSection::MacOS.is_active_on(HostPlatform::Windows));
        assert!(!RulesFileSection::MacOS.is_active_on(HostPlatform::Linux));
    }

    #[test]
    fn platform_specific_flag_correct() {
        assert!(RulesFileSection::Windows.is_platform_specific());
        assert!(RulesFileSection::Linux.is_platform_specific());
        assert!(RulesFileSection::MacOS.is_platform_specific());

        assert!(!RulesFileSection::Zones.is_platform_specific());
        assert!(!RulesFileSection::Domains.is_platform_specific());
        assert!(!RulesFileSection::Ip.is_platform_specific());
    }

    #[test]
    fn all_free_sections_are_listed_with_auto_last() {
        assert_eq!(RulesFileSection::ALL.len(), 7);
        assert_eq!(RulesFileSection::ALL[6], RulesFileSection::Auto);
    }

    #[test]
    fn auto_section_is_cross_platform_and_app_authored() {
        for platform in [
            HostPlatform::Windows,
            HostPlatform::Linux,
            HostPlatform::MacOS,
        ] {
            assert!(RulesFileSection::Auto.is_active_on(platform));
        }
        assert!(!RulesFileSection::Auto.is_platform_specific());
        assert!(RulesFileSection::Auto.is_app_authored());
        for section in RulesFileSection::ALL {
            if section != RulesFileSection::Auto {
                assert!(
                    !section.is_app_authored(),
                    "{section} must not be app-authored"
                );
            }
        }
    }

    // ── HostPlatform ─────────────────────────────────────────────────────────

    #[test]
    fn compiled_platform_is_windows_in_test_environment() {
        // This project is Windows-first; tests run on Windows.
        assert_eq!(HostPlatform::compiled(), HostPlatform::Windows);
    }

    // ── RulesFileEntry ───────────────────────────────────────────────────────

    #[test]
    fn entry_enabled_constructor() {
        let e = RulesFileEntry::enabled("example.com");
        assert_eq!(e.match_value, "example.com");
        assert!(e.enabled);
        assert!(e.inline_comment.is_none());
    }

    #[test]
    fn entry_enabled_with_comment_constructor() {
        let e = RulesFileEntry::enabled_with_comment("example.com", "vendor updates");
        assert!(e.enabled);
        assert_eq!(e.inline_comment.as_deref(), Some("vendor updates"));
    }

    #[test]
    fn entry_disabled_constructor() {
        let e = RulesFileEntry::disabled("old.example.com");
        assert_eq!(e.match_value, "old.example.com");
        assert!(!e.enabled);
        assert!(e.inline_comment.is_none());
    }

    // ── SectionContent ───────────────────────────────────────────────────────

    #[test]
    fn section_content_counts_correctly() {
        let content = SectionContent {
            section: RulesFileSection::Domains,
            entries: vec![
                RulesFileEntry::enabled("example.com"),
                RulesFileEntry::disabled("old.example.com"),
                RulesFileEntry::enabled("corp.net"),
            ],
        };
        assert_eq!(content.enabled_count(), 2);
        assert_eq!(content.disabled_count(), 1);
        assert!(!content.is_empty());
    }

    #[test]
    fn section_content_empty() {
        let content = SectionContent {
            section: RulesFileSection::Linux,
            entries: vec![],
        };
        assert!(content.is_empty());
        assert_eq!(content.enabled_count(), 0);
    }

    // ── RulesFileParsed ──────────────────────────────────────────────────────

    fn sample_parsed() -> RulesFileParsed {
        RulesFileParsed {
            sections: vec![
                SectionContent {
                    section: RulesFileSection::Domains,
                    entries: vec![
                        RulesFileEntry::enabled("example.com"),
                        RulesFileEntry::disabled("old.net"),
                    ],
                },
                SectionContent {
                    section: RulesFileSection::Windows,
                    entries: vec![RulesFileEntry::enabled("browser.exe")],
                },
                SectionContent {
                    section: RulesFileSection::Linux,
                    entries: vec![RulesFileEntry::enabled("curl")],
                },
            ],
        }
    }

    #[test]
    fn parsed_entries_for_known_section() {
        let p = sample_parsed();
        assert_eq!(p.entries_for(RulesFileSection::Domains).len(), 2);
        assert_eq!(p.entries_for(RulesFileSection::Windows).len(), 1);
    }

    #[test]
    fn parsed_entries_for_absent_section_returns_empty() {
        let p = sample_parsed();
        assert!(p.entries_for(RulesFileSection::Ip).is_empty());
    }

    #[test]
    fn parsed_enabled_count_for_section() {
        let p = sample_parsed();
        // Domains: 1 enabled, 1 disabled
        assert_eq!(p.enabled_count_for(RulesFileSection::Domains), 1);
        assert_eq!(p.enabled_count_for(RulesFileSection::Windows), 1);
    }

    #[test]
    fn parsed_active_sections_on_windows_excludes_linux() {
        let p = sample_parsed();
        let active: Vec<_> = p
            .active_sections_for(HostPlatform::Windows)
            .map(|s| s.section)
            .collect();
        assert!(active.contains(&RulesFileSection::Domains));
        assert!(active.contains(&RulesFileSection::Windows));
        assert!(!active.contains(&RulesFileSection::Linux));
    }

    #[test]
    fn parsed_active_sections_on_linux_excludes_windows() {
        let p = sample_parsed();
        let active: Vec<_> = p
            .active_sections_for(HostPlatform::Linux)
            .map(|s| s.section)
            .collect();
        assert!(active.contains(&RulesFileSection::Linux));
        assert!(!active.contains(&RulesFileSection::Windows));
    }

    #[test]
    fn parsed_total_active_enabled_count_on_windows() {
        let p = sample_parsed();
        // Domains: 1 enabled (old.net disabled), Windows: 1 enabled, Linux: excluded
        assert_eq!(p.total_active_enabled_count(HostPlatform::Windows), 2);
    }

    #[test]
    fn parsed_total_active_enabled_count_on_linux() {
        let p = sample_parsed();
        // Domains: 1, Linux: 1, Windows: excluded
        assert_eq!(p.total_active_enabled_count(HostPlatform::Linux), 2);
    }

    #[test]
    fn parsed_default_is_empty() {
        let p = RulesFileParsed::default();
        assert!(p.sections.is_empty());
        assert_eq!(p.total_active_enabled_count(HostPlatform::Windows), 0);
        assert!(!p.has_all_free_sections());
    }

    // ── parse_rules_file ─────────────────────────────────────────────────────

    const SAMPLE_FILE: &str = "\
# NetRuleRouter rules file — version 1

--- Zones
corp-internal  # corporate zone

--- Domains
updates.example.org  # vendor updates
corp.example.net
# old.example.com

--- IP
203.0.113.7

--- Windows
browser.exe   # browser traffic
# powershell.exe

--- Linux

--- MacOS
";

    #[test]
    fn parse_active_rules_are_enabled() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        let enabled: Vec<_> = domains.iter().filter(|e| e.enabled).collect();
        assert_eq!(enabled.len(), 2);
        assert!(enabled
            .iter()
            .any(|e| e.match_value == "updates.example.org"));
        assert!(enabled.iter().any(|e| e.match_value == "corp.example.net"));
    }

    #[test]
    fn parse_disabled_rule_via_comment_prefix() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        let disabled: Vec<_> = domains.iter().filter(|e| !e.enabled).collect();
        assert_eq!(disabled.len(), 1);
        assert_eq!(disabled[0].match_value, "old.example.com");
    }

    #[test]
    fn parse_block_flag_sets_blocked_and_strips_token() {
        let input = "--- Domains\nads.example.com +block  # tracker\n# off.example.com +block\n";
        let outcome = parse_rules_file(input);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        let active = domains
            .iter()
            .find(|e| e.match_value == "ads.example.com")
            .expect("active blocked rule");
        assert!(active.enabled);
        assert!(active.blocked);
        assert_eq!(active.inline_comment.as_deref(), Some("tracker"));
        let disabled = domains
            .iter()
            .find(|e| e.match_value == "off.example.com")
            .expect("disabled blocked rule");
        assert!(!disabled.enabled);
        assert!(disabled.blocked);
    }

    #[test]
    fn block_flag_round_trips_through_write_and_parse() {
        let input = "--- Domains\nads.example.com +block  # tracker\n";
        let parsed = parse_rules_file(input).parsed;
        let written = write_rules_file(&parsed, &[], None);
        assert!(
            written.contains("ads.example.com +block"),
            "writer must emit the +block flag, got:\n{written}"
        );
        let reparsed = parse_rules_file(&written).parsed;
        let e = reparsed
            .entries_for(RulesFileSection::Domains)
            .iter()
            .find(|e| e.match_value == "ads.example.com")
            .expect("round-trip entry")
            .clone();
        assert!(e.blocked);
        assert_eq!(e.inline_comment.as_deref(), Some("tracker"));
    }

    #[test]
    fn block_flag_maps_to_domain_rule_block_action() {
        let input = "--- Domains\nads.example.com +block\nrouted.example.com\n";
        let parsed = parse_rules_file(input).parsed;
        let set = rules_file_to_route_rule_set(&parsed, HostPlatform::Windows, false);
        let blocked = set
            .rules
            .iter()
            .find(|r| {
                matches!(&r.address_match, Some(crate::AddressMatch::ExactFqdn(v)) if v == "ads.example.com")
            })
            .expect("blocked rule");
        assert_eq!(blocked.action, crate::RuleAction::Block);
        let routed = set
            .rules
            .iter()
            .find(|r| {
                matches!(&r.address_match, Some(crate::AddressMatch::ExactFqdn(v)) if v == "routed.example.com")
            })
            .expect("routed rule");
        assert_eq!(routed.action, crate::RuleAction::Route);
    }

    #[test]
    fn parse_inline_comment_extracted() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        let with_comment = domains
            .iter()
            .find(|e| e.match_value == "updates.example.org")
            .expect("entry not found");
        assert_eq!(
            with_comment.inline_comment.as_deref(),
            Some("vendor updates")
        );
    }

    #[test]
    fn parse_entry_without_inline_comment() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        let no_comment = domains
            .iter()
            .find(|e| e.match_value == "corp.example.net")
            .expect("entry not found");
        assert!(no_comment.inline_comment.is_none());
    }

    #[test]
    fn parse_zone_entry() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let zones = outcome.parsed.entries_for(RulesFileSection::Zones);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].match_value, "corp-internal");
        assert!(zones[0].enabled);
        assert_eq!(zones[0].inline_comment.as_deref(), Some("corporate zone"));
    }

    #[test]
    fn parse_ip_entry() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let ip = outcome.parsed.entries_for(RulesFileSection::Ip);
        assert_eq!(ip.len(), 1);
        assert_eq!(ip[0].match_value, "203.0.113.7");
        assert!(ip[0].enabled);
    }

    #[test]
    fn parse_windows_disabled_entry() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let win = outcome.parsed.entries_for(RulesFileSection::Windows);
        assert_eq!(win.len(), 2);
        let enabled: Vec<_> = win.iter().filter(|e| e.enabled).collect();
        let disabled: Vec<_> = win.iter().filter(|e| !e.enabled).collect();
        assert_eq!(enabled.len(), 1);
        assert_eq!(disabled.len(), 1);
        assert_eq!(enabled[0].match_value, "browser.exe");
        assert_eq!(disabled[0].match_value, "powershell.exe");
    }

    #[test]
    fn parse_empty_sections_preserved() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        // Linux and MacOS sections appear in file but have no entries.
        assert!(outcome
            .parsed
            .entries_for(RulesFileSection::Linux)
            .is_empty());
        assert!(outcome
            .parsed
            .entries_for(RulesFileSection::MacOS)
            .is_empty());
        // But the sections themselves are present in the parsed output.
        assert!(outcome
            .parsed
            .sections
            .iter()
            .any(|s| s.section == RulesFileSection::Linux));
        assert!(outcome
            .parsed
            .sections
            .iter()
            .any(|s| s.section == RulesFileSection::MacOS));
    }

    #[test]
    fn parse_free_comment_lines_ignored() {
        let input = "--- Domains\n# this is a note about routing\nexample.com\n";
        let outcome = parse_rules_file(input);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        // Only the active rule; the prose comment is ignored.
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].match_value, "example.com");
    }

    #[test]
    fn parse_preamble_lines_before_first_section_ignored() {
        let input = "# preamble line\nexample.com\n--- Domains\ncorp.net\n";
        let outcome = parse_rules_file(input);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        // "example.com" before the first section header is ignored.
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].match_value, "corp.net");
    }

    #[test]
    fn parse_unknown_section_produces_warning() {
        let input = "--- CIDR\n10.0.0.0/8\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.warnings.len(), 1);
        assert!(matches!(
            &outcome.warnings[0],
            ParseWarning::UnknownSection { name, .. } if name == "CIDR"
        ));
        assert_eq!(outcome.unknown_sections.len(), 1);
        assert_eq!(outcome.unknown_sections[0].name, "CIDR");
        assert_eq!(outcome.unknown_sections[0].entries.len(), 1);
    }

    #[test]
    fn parse_unknown_section_entry_count_in_warning() {
        let input = "--- Ports\n443\n80\n8080\n";
        let outcome = parse_rules_file(input);
        assert!(matches!(
            &outcome.warnings[0],
            ParseWarning::UnknownSection { name, entry_count: 3 } if name == "Ports"
        ));
    }

    #[test]
    fn parse_multiple_unknown_sections_all_preserved() {
        let input = "--- CIDR\n10.0.0.0/8\n--- Ports\n443\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.unknown_sections.len(), 2);
        assert_eq!(outcome.unknown_sections[0].name, "CIDR");
        assert_eq!(outcome.unknown_sections[1].name, "Ports");
    }

    #[test]
    fn parse_unknown_sections_round_trip_free_edition() {
        // A file with known + unknown sections: known sections parsed,
        // unknown sections preserved with entries intact.
        let input = "--- Domains\nexample.com\n--- CIDR\n10.0.0.0/8\n";
        let outcome = parse_rules_file(input);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        assert_eq!(domains.len(), 1);
        assert_eq!(outcome.unknown_sections.len(), 1);
        assert_eq!(
            outcome.unknown_sections[0].entries[0].match_value,
            "10.0.0.0/8"
        );
        // No data loss: all entries are accessible.
    }

    // ── preset metadata ──────────────────────────────────────────────────────

    #[test]
    fn parse_preset_header_sets_preset_metadata() {
        let input = "# NetRuleRouter preset \u{2014} version 1\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert!(outcome.preset_metadata.is_some());
        assert_eq!(outcome.file_format_version, Some(1));
    }

    #[test]
    fn parse_rules_file_header_does_not_set_preset_metadata() {
        let input = "# NetRuleRouter rules file \u{2014} version 1\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert!(outcome.preset_metadata.is_none());
        assert_eq!(outcome.file_format_version, Some(1));
    }

    #[test]
    fn parse_preset_metadata_keys_extracted() {
        let input = "\
# NetRuleRouter preset \u{2014} version 1
# name: Corporate VPN Rules
# description: Routes corporate traffic via VPN
# author: Jane Doe
# preset_version: 2

--- Domains
corp.example.com
";
        let outcome = parse_rules_file(input);
        let meta = outcome
            .preset_metadata
            .as_ref()
            .expect("preset_metadata should be Some");
        assert_eq!(meta.name.as_deref(), Some("Corporate VPN Rules"));
        assert_eq!(
            meta.description.as_deref(),
            Some("Routes corporate traffic via VPN")
        );
        assert_eq!(meta.author.as_deref(), Some("Jane Doe"));
        assert_eq!(meta.preset_version.as_deref(), Some("2"));
    }

    #[test]
    fn parse_metadata_keys_without_preset_header_still_captured() {
        let input = "# name: My Rules\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        let meta = outcome
            .preset_metadata
            .as_ref()
            .expect("metadata should be Some");
        assert_eq!(meta.name.as_deref(), Some("My Rules"));
    }

    #[test]
    fn parse_no_metadata_gives_none_preset_metadata() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        assert!(outcome.preset_metadata.is_none());
    }

    #[test]
    fn parse_metadata_keys_inside_section_ignored() {
        // Metadata key-value comments inside a section are treated as free
        // comments, not captured as preset metadata.
        let input = "--- Domains\n# name: should be ignored\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert!(outcome.preset_metadata.is_none());
    }

    #[test]
    fn parse_preset_unknown_version_produces_warning() {
        let input = "# NetRuleRouter preset \u{2014} version 99\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.file_format_version, Some(99));
        assert!(outcome.preset_metadata.is_some());
        assert!(matches!(
            &outcome.warnings[0],
            ParseWarning::UnknownFormatVersion {
                found: 99,
                supported: 1
            }
        ));
    }

    #[test]
    fn preset_metadata_is_empty_when_all_none() {
        let meta = PresetMetadata::default();
        assert!(meta.is_empty());
    }

    #[test]
    fn preset_metadata_not_empty_when_name_set() {
        let meta = PresetMetadata {
            name: Some("Test".to_string()),
            ..Default::default()
        };
        assert!(!meta.is_empty());
    }

    #[test]
    fn parse_empty_input() {
        let outcome = parse_rules_file("");
        assert!(outcome.parsed.sections.is_empty());
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn parse_duplicate_section_header_merges_entries() {
        let input = "--- Domains\nexample.com\n--- Domains\ncorp.net\n";
        let outcome = parse_rules_file(input);
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        assert_eq!(domains.len(), 2);
    }

    #[test]
    fn parse_no_warnings_for_valid_file() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        assert!(outcome.warnings.is_empty());
    }

    // ── version header ───────────────────────────────────────────────────────

    #[test]
    fn parse_version_header_from_sample_file() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        assert_eq!(outcome.file_format_version, Some(1));
    }

    #[test]
    fn parse_version_absent_gives_none() {
        let input = "--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.file_format_version, None);
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn parse_known_version_produces_no_warning() {
        let input = "# NetRuleRouter rules file \u{2014} version 1\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.file_format_version, Some(1));
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn parse_unknown_version_produces_warning() {
        let input = "# NetRuleRouter rules file \u{2014} version 99\n--- Domains\nexample.com\n";
        let outcome = parse_rules_file(input);
        assert_eq!(outcome.file_format_version, Some(99));
        assert_eq!(outcome.warnings.len(), 1);
        assert!(matches!(
            &outcome.warnings[0],
            ParseWarning::UnknownFormatVersion {
                found: 99,
                supported: 1
            }
        ));
    }

    #[test]
    fn parse_fixture_file_is_valid() {
        let content = include_str!("../tests/fixtures/rules_primary_sample.txt");
        let outcome = parse_rules_file(content);
        // Fixture has a known version header — no format-version warning.
        assert!(
            outcome.warnings.is_empty(),
            "fixture produced unexpected warnings: {:?}",
            outcome.warnings
        );
        assert_eq!(outcome.file_format_version, Some(1));
        // At least one enabled domain entry.
        let domains = outcome.parsed.entries_for(RulesFileSection::Domains);
        assert!(
            domains.iter().any(|e| e.enabled),
            "fixture must have at least one enabled domain rule"
        );
    }

    #[test]
    fn parse_version_header_only_matched_in_preamble() {
        // A version-like comment inside a section must NOT be treated as the header.
        let input = "--- Domains\n# NetRuleRouter rules file \u{2014} version 1\nexample.com\n";
        let outcome = parse_rules_file(input);
        // The comment line is inside a section — it is a free comment, ignored as a rule.
        // file_format_version stays None because the header was not in the preamble.
        assert_eq!(outcome.file_format_version, None);
    }

    // ── rules_file_to_route_rule_set ─────────────────────────────────────────

    #[test]
    fn converter_produces_rules_for_active_sections() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        // Zones: 1, Domains: 3 (2 enabled + 1 disabled), IP: 1, Windows: 2
        assert_eq!(rule_set.rules.len(), 7);
    }

    #[test]
    fn converter_excludes_linux_section_on_windows() {
        let input = "--- Linux\ncurl\n--- Windows\nbrowser.exe\n";
        let outcome = parse_rules_file(input);
        let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        assert_eq!(rule_set.rules.len(), 1);
        assert_eq!(rule_set.rules[0].comment, "");
    }

    #[test]
    fn converter_preserves_enabled_flag() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        let disabled: Vec<_> = rule_set.rules.iter().filter(|r| !r.enabled).collect();
        // old.example.com + powershell.exe = 2 disabled
        assert_eq!(disabled.len(), 2);
    }

    #[test]
    fn converter_sets_include_child_processes_from_param() {
        let input = "--- Windows\nbrowser.exe\n";
        let outcome = parse_rules_file(input);
        let with_icp = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, true);
        let without_icp =
            rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        assert!(with_icp.rules[0]
            .app_match
            .as_ref()
            .is_some_and(|a| a.include_child_processes));
        assert!(!without_icp.rules[0]
            .app_match
            .as_ref()
            .is_none_or(|a| a.include_child_processes));
    }

    #[test]
    fn converter_inline_comment_becomes_rule_comment() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        let browser = rule_set
            .rules
            .iter()
            .find(|r| {
                r.app_match
                    .as_ref()
                    .is_some_and(|a| a.pattern.as_str() == "browser.exe")
            })
            .expect("browser.exe rule not found");
        assert_eq!(browser.comment, "browser traffic");
    }

    #[test]
    fn converter_rule_ids_have_r_prefix() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let rule_set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        for rule in &rule_set.rules {
            assert!(
                rule.id.as_str().starts_with("r-"),
                "rule ID '{}' does not start with 'r-'",
                rule.id
            );
        }
    }

    // ── Pipeline integration (parse → validate) ──────────────────────────────

    #[test]
    fn full_pipeline_parse_then_validate() {
        use crate::{
            validation::validate_and_canonicalize, ActiveConfiguration, AdapterIdentity,
            BindingSource, RouteBehaviorMode, RouteBinding, RuleBook,
        };
        use nrr_shared::RouteRole;

        let primary_input = "--- Domains\ncorp.example.net\n--- IP\n203.0.113.7\n";
        let secondary_input = "--- Windows\nbrowser.exe  # browser\n";

        let primary_parsed = parse_rules_file(primary_input);
        let secondary_parsed = parse_rules_file(secondary_input);

        let primary_set =
            rules_file_to_route_rule_set(&primary_parsed.parsed, HostPlatform::Windows, false);
        let secondary_set =
            rules_file_to_route_rule_set(&secondary_parsed.parsed, HostPlatform::Windows, false);

        let config = ActiveConfiguration {
            primary: Some(RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "eth0".to_string(),
                    display_name: "Ethernet".to_string(),
                },
                source: BindingSource::UserAssigned,
            }),
            secondary: Some(RouteBinding {
                role: RouteRole::Secondary,
                adapter: AdapterIdentity {
                    stable_id: "vpn0".to_string(),
                    display_name: "VPN".to_string(),
                },
                source: BindingSource::UserAssigned,
            }),
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            rule_book: RuleBook {
                primary: primary_set,
                secondary: secondary_set,
            },
        };

        let outcome = validate_and_canonicalize(&config);
        assert!(
            outcome.is_accepted(),
            "pipeline rejected with warnings: {:?}",
            outcome
        );
    }

    // ── write_rules_file ──────────────────────────────────────────────────────

    #[test]
    fn write_empty_parsed_returns_empty_string() {
        // With no sections in input and no metadata, output is empty —
        // the writer emits only what's structurally present (round-trip
        // symmetry with the parser).
        let parsed = RulesFileParsed::default();
        let text = write_rules_file(&parsed, &[], None);
        assert!(text.is_empty(), "got {text:?}");
    }

    #[test]
    fn write_preserves_empty_section_when_present_in_input() {
        // docs/en/rules-file-format.md Sections — a section header with no entries is preserved on
        // export. The writer relies on the section being explicit in input.
        let parsed = RulesFileParsed {
            sections: vec![
                SectionContent {
                    section: RulesFileSection::Zones,
                    entries: vec![],
                },
                SectionContent {
                    section: RulesFileSection::Domains,
                    entries: vec![RulesFileEntry::enabled("example.com")],
                },
            ],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert!(text.contains("--- Zones\n"), "got:\n{text}");
        assert!(text.contains("--- Domains\nexample.com\n"), "got:\n{text}");
    }

    #[test]
    fn write_single_active_entry_in_domains() {
        let parsed = RulesFileParsed {
            sections: vec![SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry::enabled("example.com")],
            }],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert!(text.contains("--- Domains\nexample.com\n"), "got:\n{text}");
    }

    #[test]
    fn write_entry_with_inline_comment_uses_two_spaces() {
        let parsed = RulesFileParsed {
            sections: vec![SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry::enabled_with_comment(
                    "example.com",
                    "vendor updates",
                )],
            }],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert!(
            text.contains("example.com  # vendor updates\n"),
            "got:\n{text}"
        );
    }

    #[test]
    fn write_disabled_entry_prefixed_with_hash() {
        let parsed = RulesFileParsed {
            sections: vec![SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry::disabled("example.com")],
            }],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert!(text.contains("# example.com\n"), "got:\n{text}");
        // Must not be misinterpreted as an active rule.
        assert!(!text.contains("\nexample.com\n"), "got:\n{text}");
    }

    #[test]
    fn write_disabled_entry_with_inline_comment() {
        let parsed = RulesFileParsed {
            sections: vec![SectionContent {
                section: RulesFileSection::Domains,
                entries: vec![RulesFileEntry {
                    match_value: "example.com".to_string(),
                    inline_comment: Some("was active".to_string()),
                    enabled: false,
                    blocked: false,
                    origin: None,
                }],
            }],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert!(
            text.contains("# example.com  # was active\n"),
            "got:\n{text}"
        );
    }

    #[test]
    fn write_then_parse_round_trips_active_rules() {
        let input = "\
--- Zones
ru

--- Domains
example.com
*.corp.example.net  # all subdomains

--- IP
203.0.113.7

--- Windows
chrome.exe

--- Linux

--- MacOS
";
        let parsed_first = parse_rules_file(input).parsed;
        let written = write_rules_file(&parsed_first, &[], None);
        let parsed_again = parse_rules_file(&written).parsed;
        assert_eq!(
            parsed_first, parsed_again,
            "round-trip diverged:\nfirst={parsed_first:#?}\nagain={parsed_again:#?}\nwritten=\n{written}"
        );
    }

    #[test]
    fn write_then_parse_round_trips_disabled_rules() {
        let input = "\
--- Domains
example.com
# old.example.com  # decommissioned
";
        let parsed_first = parse_rules_file(input).parsed;
        let written = write_rules_file(&parsed_first, &[], None);
        let parsed_again = parse_rules_file(&written).parsed;
        assert_eq!(parsed_first, parsed_again);
    }

    #[test]
    fn write_then_parse_round_trips_unicode_comments() {
        let input = "\
--- Domains
example.com  # отечественный поставщик обновлений
";
        let parsed_first = parse_rules_file(input).parsed;
        let written = write_rules_file(&parsed_first, &[], None);
        let parsed_again = parse_rules_file(&written).parsed;
        assert_eq!(parsed_first, parsed_again);
    }

    #[test]
    fn write_preserves_unknown_sections_in_supplied_order() {
        let parsed = RulesFileParsed::default();
        let unknown = vec![
            UnknownSection {
                name: "CIDR".to_string(),
                entries: vec![RulesFileEntry::enabled("10.0.0.0/8")],
            },
            UnknownSection {
                name: "Ports".to_string(),
                entries: vec![
                    RulesFileEntry::enabled("443"),
                    RulesFileEntry::disabled("8080"),
                ],
            },
        ];
        let text = write_rules_file(&parsed, &unknown, None);
        assert!(text.contains("--- CIDR\n10.0.0.0/8\n"), "got:\n{text}");
        assert!(text.contains("--- Ports\n443\n# 8080\n"), "got:\n{text}");
        // CIDR must appear before Ports.
        let cidr_at = text.find("--- CIDR").unwrap();
        let ports_at = text.find("--- Ports").unwrap();
        assert!(cidr_at < ports_at, "supplied order not preserved");
    }

    #[test]
    fn write_round_trips_unknown_sections() {
        let input = "\
--- Domains
example.com

--- CIDR
10.0.0.0/8
192.168.1.0/24  # office subnet

--- Ports
443
";
        let outcome = parse_rules_file(input);
        let written = write_rules_file(&outcome.parsed, &outcome.unknown_sections, None);
        let again = parse_rules_file(&written);
        assert_eq!(outcome.parsed, again.parsed);
        assert_eq!(outcome.unknown_sections, again.unknown_sections);
    }

    #[test]
    fn write_includes_preset_metadata_when_supplied() {
        let parsed = RulesFileParsed::default();
        let meta = PresetMetadata {
            name: Some("Corporate VPN".to_string()),
            description: Some("Routes traffic via VPN".to_string()),
            author: Some("Jane Doe".to_string()),
            preset_version: Some("1".to_string()),
        };
        let text = write_rules_file(&parsed, &[], Some(&meta));
        assert!(
            text.starts_with("# NetRuleRouter preset \u{2014} version 1\n"),
            "got:\n{text}"
        );
        assert!(text.contains("# name: Corporate VPN\n"));
        assert!(text.contains("# description: Routes traffic via VPN\n"));
        assert!(text.contains("# author: Jane Doe\n"));
        assert!(text.contains("# preset_version: 1\n"));
    }

    #[test]
    fn write_omits_metadata_keys_with_none_values() {
        let parsed = RulesFileParsed::default();
        let meta = PresetMetadata {
            name: Some("Solo".to_string()),
            description: None,
            author: None,
            preset_version: None,
        };
        let text = write_rules_file(&parsed, &[], Some(&meta));
        assert!(text.contains("# name: Solo\n"));
        assert!(!text.contains("# description:"));
        assert!(!text.contains("# author:"));
        assert!(!text.contains("# preset_version:"));
    }

    #[test]
    fn write_round_trips_preset_metadata() {
        let input = "\
# NetRuleRouter preset \u{2014} version 1
# name: Corporate VPN
# description: Routes corporate traffic
# author: Jane Doe
# preset_version: 1

--- Domains
example.com
";
        let outcome = parse_rules_file(input);
        let written = write_rules_file(
            &outcome.parsed,
            &outcome.unknown_sections,
            outcome.preset_metadata.as_ref(),
        );
        let again = parse_rules_file(&written);
        assert_eq!(outcome.preset_metadata, again.preset_metadata);
        assert_eq!(outcome.parsed, again.parsed);
    }

    #[test]
    fn write_emits_present_sections_in_canonical_order_regardless_of_input() {
        // Input deliberately reverse-ordered. Writer must restore canonical
        // order (Zones < MacOS). Absent sections are not emitted.
        let parsed = RulesFileParsed {
            sections: vec![
                SectionContent {
                    section: RulesFileSection::MacOS,
                    entries: vec![RulesFileEntry::enabled("Safari")],
                },
                SectionContent {
                    section: RulesFileSection::Zones,
                    entries: vec![RulesFileEntry::enabled("ru")],
                },
            ],
        };
        let text = write_rules_file(&parsed, &[], None);
        let zones_at = text.find("--- Zones").expect("Zones missing");
        let macos_at = text.find("--- MacOS").expect("MacOS missing");
        assert!(zones_at < macos_at, "Zones must precede MacOS:\n{text}");
        // Absent sections must NOT appear.
        for absent in &[
            RulesFileSection::Domains,
            RulesFileSection::Ip,
            RulesFileSection::Windows,
            RulesFileSection::Linux,
        ] {
            let header = format!("--- {}", absent.name());
            assert!(
                !text.contains(&header),
                "absent section {header:?} unexpectedly emitted:\n{text}"
            );
        }
    }

    #[test]
    fn write_round_trips_input_with_empty_section_header() {
        // docs/en/rules-file-format.md Sections — `--- Domains\n\n--- IP\n203.0.113.7\n` should
        // round-trip preserving the empty Domains section header.
        let input = "\
--- Domains

--- IP
203.0.113.7
";
        let parsed_first = parse_rules_file(input).parsed;
        let written = write_rules_file(&parsed_first, &[], None);
        let parsed_again = parse_rules_file(&written).parsed;
        assert_eq!(parsed_first, parsed_again);
        // Domains header survived even though it has no entries.
        assert!(written.contains("--- Domains\n"), "got:\n{written}");
    }

    // ── canonical_rule_set_to_rules_file_parsed ──────────────────────────────

    use crate::canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
        CanonicalRuleSet,
    };
    use crate::RuleId;
    use std::net::Ipv4Addr;

    fn rule_with_address(
        id: &str,
        enabled: bool,
        addr: CanonicalAddressMatch,
        comment: &str,
    ) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: Some(addr),
            app_match: None,
            comment: comment.to_string(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn rule_with_app(
        id: &str,
        enabled: bool,
        pattern: CanonicalAppPattern,
        comment: &str,
    ) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern,
                include_child_processes: false,
            }),
            comment: comment.to_string(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn canonical_to_rules_file_maps_exact_fqdn_to_domains() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections.len(), 1);
        assert_eq!(parsed.sections[0].section, RulesFileSection::Domains);
        assert_eq!(parsed.sections[0].entries[0].match_value, "example.com");
        assert!(parsed.sections[0].entries[0].enabled);
        assert!(parsed.sections[0].entries[0].inline_comment.is_none());
    }

    #[test]
    fn canonical_to_rules_file_maps_suffix_domain_with_star_prefix() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::SuffixDomain("example.com".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections[0].entries[0].match_value, "*.example.com");
    }

    #[test]
    fn canonical_to_rules_file_maps_zone_to_zones_section() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::Zone("ru".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections[0].section, RulesFileSection::Zones);
        assert_eq!(parsed.sections[0].entries[0].match_value, "ru");
    }

    #[test]
    fn canonical_to_rules_file_maps_exact_ip_to_ip_section() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactIp(Ipv4Addr::new(203, 0, 113, 7)),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections[0].section, RulesFileSection::Ip);
        assert_eq!(parsed.sections[0].entries[0].match_value, "203.0.113.7");
    }

    #[test]
    fn canonical_to_rules_file_maps_app_match_to_host_section() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_app(
            "r-1",
            true,
            CanonicalAppPattern::Exact("chrome.exe".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections[0].section, RulesFileSection::Windows);
        assert_eq!(parsed.sections[0].entries[0].match_value, "chrome.exe");
    }

    #[test]
    fn canonical_to_rules_file_preserves_inline_comment() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "vendor updates",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(
            parsed.sections[0].entries[0].inline_comment.as_deref(),
            Some("vendor updates")
        );
    }

    #[test]
    fn canonical_to_rules_file_preserves_disabled_state() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            false,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert!(!parsed.sections[0].entries[0].enabled);
    }

    #[test]
    fn canonical_to_rules_file_emits_sections_in_canonical_order() {
        let set = CanonicalRuleSet::from_rules(vec![
            rule_with_app(
                "r-1",
                true,
                CanonicalAppPattern::Exact("chrome.exe".to_string()),
                "",
            ),
            rule_with_address(
                "r-2",
                true,
                CanonicalAddressMatch::Zone("ru".to_string()),
                "",
            ),
            rule_with_address(
                "r-3",
                true,
                CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                "",
            ),
        ]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        let order: Vec<RulesFileSection> = parsed.sections.iter().map(|s| s.section).collect();
        // Canonical order: Zones → Domains → (IP omitted) → Windows.
        assert_eq!(
            order,
            vec![
                RulesFileSection::Zones,
                RulesFileSection::Domains,
                RulesFileSection::Windows,
            ]
        );
    }

    #[test]
    fn canonical_to_rules_file_omits_empty_sections() {
        let set = CanonicalRuleSet::from_rules(vec![rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        )]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        // Only Domains is present; Zones/IP/Windows are not emitted.
        assert_eq!(parsed.sections.len(), 1);
    }

    #[test]
    fn canonical_to_rules_file_full_round_trip_via_writer() {
        // CanonicalRuleSet → RulesFileParsed → text → parse →
        // rules_file_to_route_rule_set → CanonicalRuleSet (via from_rules).
        let original_rules = vec![
            rule_with_address(
                "r-a",
                true,
                CanonicalAddressMatch::Zone("ru".to_string()),
                "",
            ),
            rule_with_address(
                "r-b",
                true,
                CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
                "",
            ),
            rule_with_address(
                "r-c",
                true,
                CanonicalAddressMatch::SuffixDomain("corp.example.net".to_string()),
                "all subdomains",
            ),
            rule_with_address(
                "r-d",
                false,
                CanonicalAddressMatch::ExactFqdn("old.example.com".to_string()),
                "decommissioned",
            ),
            rule_with_address(
                "r-e",
                true,
                CanonicalAddressMatch::ExactIp(Ipv4Addr::new(203, 0, 113, 7)),
                "",
            ),
            rule_with_app(
                "r-f",
                true,
                CanonicalAppPattern::Exact("chrome.exe".to_string()),
                "",
            ),
        ];
        let original_set = CanonicalRuleSet::from_rules(original_rules);
        let parsed =
            canonical_rule_set_to_rules_file_parsed(&original_set, RulesFileSection::Windows);
        let written = write_rules_file(&parsed, &[], None);
        // Round-trip through the parser.
        let reparse = parse_rules_file(&written).parsed;
        let route_rule_set = rules_file_to_route_rule_set(&reparse, HostPlatform::Windows, false);
        // Build a CanonicalRuleSet from the round-tripped RouteRuleSet
        // by promoting each Rule into a CanonicalRule with the same
        // address_match / app_match / enabled / comment. Then compare
        // **the match-value content**, not the rule_ids (which the
        // parser regenerates).
        // Compare as sorted sets: file-order (Zones→Domains→IP→Windows)
        // differs from canonical-sort-order (ExactFqdn→SuffixDomain→Zone→
        // ExactIp→Application), so element-by-element equality is the
        // wrong invariant. Sorted-vec equality captures the round-trip
        // guarantee.
        let mut written_values: Vec<(bool, Option<String>, Option<String>, String)> =
            route_rule_set
                .rules
                .iter()
                .map(|r| {
                    (
                        r.enabled,
                        r.address_match.as_ref().map(|a| match a {
                            crate::AddressMatch::ExactFqdn(s)
                            | crate::AddressMatch::SuffixDomain(s)
                            | crate::AddressMatch::Zone(s) => s.clone(),
                            crate::AddressMatch::ExactIp(ip) => ip.to_string(),
                        }),
                        r.app_match.as_ref().map(|app| match &app.pattern {
                            crate::AppMatchPattern::Exact(s) | crate::AppMatchPattern::Glob(s) => {
                                s.clone()
                            }
                        }),
                        r.comment.clone(),
                    )
                })
                .collect();
        let mut original_values: Vec<(bool, Option<String>, Option<String>, String)> = original_set
            .rules()
            .iter()
            .map(|r| {
                (
                    r.enabled,
                    r.address_match.as_ref().map(|a| match a {
                        CanonicalAddressMatch::ExactFqdn(s)
                        | CanonicalAddressMatch::SuffixDomain(s)
                        | CanonicalAddressMatch::Zone(s) => s.clone(),
                        CanonicalAddressMatch::ExactIp(ip) => ip.to_string(),
                    }),
                    r.app_match.as_ref().map(|app| match &app.pattern {
                        CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
                    }),
                    r.comment.clone(),
                )
            })
            .collect();
        written_values.sort();
        original_values.sort();
        assert_eq!(
            written_values, original_values,
            "round-trip values diverged (set comparison):\nwritten=\n{written}"
        );
    }

    // ── `--- Auto` section ───────────────────────────────────────────────────

    use nrr_shared::auto_rule::AutoRuleReason;

    /// The canonical shape of an app-authored line, kept verbatim so a change
    /// to the syntax has to be made deliberately here first.
    const AUTO_SAMPLE_LINE: &str =
        "rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31";

    fn auto_origin(reason: AutoRuleReason) -> RuleOrigin {
        RuleOrigin::auto(reason, "example.com", "2026-07-31")
    }

    #[test]
    fn auto_section_header_parses_case_insensitively() {
        for header in ["--- Auto", "--- auto", "--- AUTO"] {
            assert_eq!(
                RulesFileSection::parse_header(header),
                Some(RulesFileSection::Auto),
                "header {header:?} must classify as the app-authored section"
            );
        }
    }

    #[test]
    fn auto_entry_lifts_provenance_out_of_the_inline_comment() {
        let outcome = parse_rules_file(&format!("--- Auto\n{AUTO_SAMPLE_LINE}\n"));
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].match_value, "rr3.example-cdn.net");
        assert!(entries[0].enabled);
        assert_eq!(
            entries[0].origin,
            Some(auto_origin(AutoRuleReason::SiteCompanion))
        );
        // The tokens are consumed, not duplicated into the label.
        assert_eq!(entries[0].inline_comment, None);
    }

    #[test]
    fn auto_entry_keeps_trailing_free_text_as_the_label() {
        let input =
            "--- Auto\nvideo.example.net  # auto:site-companion anchor:example.com added:2026-07-31 video CDN\n";
        let entries = parse_rules_file(input)
            .parsed
            .entries_for(RulesFileSection::Auto)
            .to_vec();
        assert_eq!(entries[0].inline_comment.as_deref(), Some("video CDN"));
        assert_eq!(
            entries[0].origin,
            Some(auto_origin(AutoRuleReason::SiteCompanion))
        );
    }

    #[test]
    fn auto_entry_accepts_every_known_reason_slug() {
        for reason in AutoRuleReason::KNOWN {
            let input = format!(
                "--- Auto\nh.example.net  # auto:{} anchor:example.com added:2026-07-31\n",
                reason.as_slug()
            );
            let entries = parse_rules_file(&input)
                .parsed
                .entries_for(RulesFileSection::Auto)
                .to_vec();
            assert_eq!(entries[0].origin, Some(auto_origin(reason)));
        }
    }

    #[test]
    fn auto_entry_with_unknown_reason_slug_is_preserved_not_rejected() {
        let input =
            "--- Auto\nh.example.net  # auto:from-the-future anchor:example.com added:2030-01-01\n";
        let outcome = parse_rules_file(input);
        assert!(outcome.warnings.is_empty());
        let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
        assert_eq!(
            entries[0].origin.as_ref().map(RuleOrigin::reason),
            Some(&AutoRuleReason::Other("from-the-future".to_string()))
        );
        // …and it survives a write/parse round-trip unchanged.
        let written = write_rules_file(&outcome.parsed, &[], None);
        assert!(written.contains("auto:from-the-future"), "got:\n{written}");
        assert_eq!(parse_rules_file(&written).parsed, outcome.parsed);
    }

    #[test]
    fn auto_line_without_provenance_is_kept_as_an_ordinary_rule_plus_warning() {
        let input = "--- Auto\nh.example.net  # hand-added by me\nbare.example.net\n";
        let outcome = parse_rules_file(input);
        let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
        // Never dropped, never an error.
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].origin, None);
        assert_eq!(
            entries[0].inline_comment.as_deref(),
            Some("hand-added by me")
        );
        assert_eq!(entries[1].origin, None);
        assert_eq!(
            outcome.warnings,
            vec![
                ParseWarning::AutoRuleMissingProvenance {
                    match_value: "h.example.net".to_string()
                },
                ParseWarning::AutoRuleMissingProvenance {
                    match_value: "bare.example.net".to_string()
                },
            ]
        );
    }

    #[test]
    fn auto_line_with_partial_provenance_warns_but_keeps_the_origin() {
        let input = "--- Auto\nh.example.net  # auto:site-companion added:2026-07-31\n";
        let outcome = parse_rules_file(input);
        let entries = outcome.parsed.entries_for(RulesFileSection::Auto);
        assert_eq!(entries[0].origin.as_ref().map(RuleOrigin::anchor), Some(""));
        assert_eq!(
            outcome.warnings,
            vec![ParseWarning::AutoRuleIncompleteProvenance {
                match_value: "h.example.net".to_string(),
                reason_slug: "site-companion".to_string(),
            }]
        );
    }

    #[test]
    fn provenance_tokens_are_not_parsed_outside_the_auto_section() {
        // A user's own comment that happens to start with `auto:` stays a
        // comment — provenance is read in the app-authored section only.
        let input = "--- Domains\nh.example.net  # auto:site-companion anchor:x added:2026-07-31\n";
        let outcome = parse_rules_file(input);
        let entries = outcome.parsed.entries_for(RulesFileSection::Domains);
        assert_eq!(entries[0].origin, None);
        assert_eq!(
            entries[0].inline_comment.as_deref(),
            Some("auto:site-companion anchor:x added:2026-07-31")
        );
        assert!(outcome.warnings.is_empty());
    }

    #[test]
    fn auto_entries_round_trip_through_write_and_parse() {
        let input = "\
--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31
*.assets.example.net  # auto:site-companion anchor:example.com added:2026-07-31 all asset hosts
# stale.example.net  # auto:user-confirmed anchor:example.com added:2026-01-05
tracker.example.net +block  # auto:user-confirmed anchor:example.com added:2026-02-02
";
        let first = parse_rules_file(input).parsed;
        let written = write_rules_file(&first, &[], None);
        assert_eq!(
            written, input,
            "canonical form must be byte-stable for already-canonical input"
        );
        assert_eq!(parse_rules_file(&written).parsed, first);
    }

    #[test]
    fn writer_emits_the_documented_line_shape() {
        let parsed = RulesFileParsed {
            sections: vec![SectionContent {
                section: RulesFileSection::Auto,
                entries: vec![RulesFileEntry::auto(
                    "rr3.example-cdn.net",
                    auto_origin(AutoRuleReason::SiteCompanion),
                )],
            }],
        };
        let text = write_rules_file(&parsed, &[], None);
        assert_eq!(text, format!("--- Auto\n{AUTO_SAMPLE_LINE}\n"));
    }

    #[test]
    fn auto_section_sorts_after_every_user_section_on_write() {
        let parsed = RulesFileParsed {
            sections: vec![
                SectionContent {
                    section: RulesFileSection::Auto,
                    entries: vec![RulesFileEntry::auto(
                        "cdn.example.net",
                        auto_origin(AutoRuleReason::SiteCompanion),
                    )],
                },
                SectionContent {
                    section: RulesFileSection::Domains,
                    entries: vec![RulesFileEntry::enabled("example.com")],
                },
            ],
        };
        let text = write_rules_file(&parsed, &[], None);
        let domains_at = text.find("--- Domains").expect("Domains missing");
        let auto_at = text.find("--- Auto").expect("Auto missing");
        assert!(domains_at < auto_at, "Auto must come last:\n{text}");
    }

    // ── Auto ⇄ rule-model converters ─────────────────────────────────────────

    #[test]
    fn auto_section_converts_to_domain_style_rules_carrying_their_origin() {
        let input = "\
--- Auto
rr3.example-cdn.net  # auto:site-companion anchor:example.com added:2026-07-31
*.assets.example.net  # auto:vpn-client-bootstrap anchor:vpn.example.net added:2026-07-31
";
        let parsed = parse_rules_file(input).parsed;
        let set = rules_file_to_route_rule_set(&parsed, HostPlatform::Windows, false);
        assert_eq!(set.rules.len(), 2);
        assert_eq!(
            set.rules[0].address_match,
            Some(crate::AddressMatch::ExactFqdn(
                "rr3.example-cdn.net".to_string()
            ))
        );
        assert_eq!(
            set.rules[0].origin,
            Some(auto_origin(AutoRuleReason::SiteCompanion))
        );
        // `*.x` follows the Domains grammar: suffix domain, prefix stripped.
        assert_eq!(
            set.rules[1].address_match,
            Some(crate::AddressMatch::SuffixDomain(
                "assets.example.net".to_string()
            ))
        );
        assert_eq!(
            set.rules[1].origin.as_ref().map(RuleOrigin::reason),
            Some(&AutoRuleReason::VpnClientBootstrap)
        );
    }

    #[test]
    fn canonical_rule_with_origin_lands_in_auto_and_leaves_domains_untouched() {
        let mut app_authored = rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactFqdn("rr3.example-cdn.net".to_string()),
            "",
        );
        app_authored.origin = Some(auto_origin(AutoRuleReason::SiteCompanion));
        let user_authored = rule_with_address(
            "r-2",
            true,
            CanonicalAddressMatch::ExactFqdn("example.com".to_string()),
            "",
        );
        let set = CanonicalRuleSet::from_rules(vec![app_authored, user_authored]);

        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.entries_for(RulesFileSection::Domains).len(), 1);
        assert_eq!(
            parsed.entries_for(RulesFileSection::Domains)[0].match_value,
            "example.com"
        );
        let auto = parsed.entries_for(RulesFileSection::Auto);
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].match_value, "rr3.example-cdn.net");
        assert_eq!(
            auto[0].origin,
            Some(auto_origin(AutoRuleReason::SiteCompanion))
        );
    }

    #[test]
    fn app_authored_rule_survives_canonical_to_file_to_rule_set() {
        let mut app_authored = rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::SuffixDomain("assets.example.net".to_string()),
            "all asset hosts",
        );
        app_authored.origin = Some(auto_origin(AutoRuleReason::UserConfirmed));
        let set = CanonicalRuleSet::from_rules(vec![app_authored]);

        let text = write_rules_file(
            &canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows),
            &[],
            None,
        );
        let back = rules_file_to_route_rule_set(
            &parse_rules_file(&text).parsed,
            HostPlatform::Windows,
            false,
        );
        assert_eq!(back.rules.len(), 1);
        assert_eq!(
            back.rules[0].address_match,
            Some(crate::AddressMatch::SuffixDomain(
                "assets.example.net".to_string()
            ))
        );
        assert_eq!(
            back.rules[0].origin,
            Some(auto_origin(AutoRuleReason::UserConfirmed))
        );
        assert_eq!(back.rules[0].comment, "all asset hosts");
    }

    #[test]
    fn non_domain_address_kinds_keep_their_section_even_with_an_origin() {
        // The Auto section carries domain-style values only — an IP written
        // there would be re-read as a hostname, so it stays in `--- IP`.
        let mut ip_rule = rule_with_address(
            "r-1",
            true,
            CanonicalAddressMatch::ExactIp(Ipv4Addr::new(203, 0, 113, 7)),
            "",
        );
        ip_rule.origin = Some(auto_origin(AutoRuleReason::SiteCompanion));
        let set = CanonicalRuleSet::from_rules(vec![ip_rule]);
        let parsed = canonical_rule_set_to_rules_file_parsed(&set, RulesFileSection::Windows);
        assert_eq!(parsed.sections.len(), 1);
        assert_eq!(parsed.sections[0].section, RulesFileSection::Ip);
        // No provenance is written where it could not be read back.
        assert_eq!(parsed.sections[0].entries[0].origin, None);
        let text = write_rules_file(&parsed, &[], None);
        assert_eq!(parse_rules_file(&text).parsed, parsed);
    }

    #[test]
    fn user_authored_rules_are_unaffected_by_the_origin_field() {
        let outcome = parse_rules_file(SAMPLE_FILE);
        let set = rules_file_to_route_rule_set(&outcome.parsed, HostPlatform::Windows, false);
        assert!(
            set.rules.iter().all(|r| r.origin.is_none()),
            "no section other than Auto may produce an origin"
        );
        let written = write_rules_file(&outcome.parsed, &[], None);
        assert!(!written.contains("auto:"), "got:\n{written}");
    }
}

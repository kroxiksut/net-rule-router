// The shape of a rules file: sections, entries and a parsed file.

use super::*;

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

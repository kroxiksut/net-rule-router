//! The provisioning check: pure over the bytes, the same at install time and
//! at the service's start.
//!
//! Rules files go through the import parser and the submission gates a saved
//! rule set meets. The settings export and the options file have readers of
//! their own here, bounded by size and line count; they read our own
//! emitter's shape and refuse anything they do not understand, because an
//! option silently dropped is a policy the administrator believes is in force.

use nrr_domain::canonical::{CanonicalRuleBook, CanonicalRuleSet};
use nrr_domain::rules_file::HostPlatform;
use nrr_domain::rules_revision::RulesRevisionContent;
use nrr_domain::{LeakProtection, RouteRole};
use nrr_storage::install_policy::SecondaryUnset;
use nrr_storage::route_bindings::BehaviorMode;

use super::{exit, OPTIONS_MAX_BYTES, RULES_MAX_BYTES, SETTINGS_MAX_BYTES};

/// The raw files, each one optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BundleBytes {
    pub primary: Option<Vec<u8>>,
    pub secondary: Option<Vec<u8>>,
    pub settings: Option<Vec<u8>>,
    pub options: Option<Vec<u8>>,
}

impl BundleBytes {
    pub fn is_empty(&self) -> bool {
        self.primary.is_none()
            && self.secondary.is_none()
            && self.settings.is_none()
            && self.options.is_none()
    }
}

/// Which file a refusal is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvisionPart {
    Primary,
    Secondary,
    Settings,
    Options,
    /// The folder itself: someone other than an administrator could write it.
    Folder,
}

impl ProvisionPart {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Settings => "settings",
            Self::Options => "options",
            Self::Folder => "folder",
        }
    }

    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Primary => exit::PRIMARY_REFUSED,
            Self::Secondary => exit::SECONDARY_REFUSED,
            Self::Settings => exit::SETTINGS_REFUSED,
            Self::Options => exit::OPTION_REFUSED,
            Self::Folder => exit::STAGE_FAILED,
        }
    }
}

/// Why a bundle is refused. `code` is a stable slug fit for the audit trail;
/// `detail` is for the administrator at the console and may quote the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionRefusal {
    pub part: ProvisionPart,
    pub code: String,
    pub detail: String,
}

impl ProvisionRefusal {
    pub fn new(part: ProvisionPart, code: &str, detail: impl Into<String>) -> Self {
        Self {
            part,
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ProvisionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} refused ({}): {}",
            self.part.slug(),
            self.code,
            self.detail
        )
    }
}

/// What a settings export contributes. Adapter bindings and rule-file paths
/// are deliberately not read: both name things of the machine it came from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsFacts {
    pub route_mode: Option<BehaviorMode>,
    /// The floor of each new user's first leak protection.
    pub leak_protection: Option<LeakProtection>,
    /// Rules-file text of each route; `None` when the export holds none.
    pub rules_primary: Option<String>,
    pub rules_secondary: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallOptions {
    pub secondary_unset: Option<SecondaryUnset>,
}

/// A bundle that passed: the parsed parts, ready to apply.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckedBundle {
    pub primary: Option<CanonicalRuleSet>,
    pub secondary: Option<CanonicalRuleSet>,
    pub settings: Option<SettingsFacts>,
    pub options: InstallOptions,
}

impl CheckedBundle {
    pub fn has_rules(&self) -> bool {
        self.primary.is_some() || self.secondary.is_some()
    }
}

/// The rules of one route and the part that carries them: its own file, or
/// the settings export's copy.
pub(crate) type RouteRules<'a> = Option<(&'a [u8], ProvisionPart)>;

/// Each route's rules, from its file or from the settings export. Both for one
/// route is refused: dropping either copy would leave the administrator
/// believing in rules that are not in force.
pub(crate) fn rules_of_routes<'a>(
    bytes: &'a BundleBytes,
    settings: Option<&'a SettingsFacts>,
) -> Result<[RouteRules<'a>; 2], ProvisionRefusal> {
    let pick = |file: Option<&'a [u8]>, file_part, embedded: Option<&'a String>, route: &str| match (
        file, embedded,
    ) {
        (Some(_), Some(_)) => Err(ProvisionRefusal::new(
            ProvisionPart::Settings,
            "rules-given-twice",
            format!("the {route} route has a rules file and rules in the settings file"),
        )),
        (Some(file), None) => Ok(Some((file, file_part))),
        (None, Some(text)) => Ok(Some((text.as_bytes(), ProvisionPart::Settings))),
        (None, None) => Ok(None),
    };
    Ok([
        pick(
            bytes.primary.as_deref(),
            ProvisionPart::Primary,
            settings.and_then(|s| s.rules_primary.as_ref()),
            "primary",
        )?,
        pick(
            bytes.secondary.as_deref(),
            ProvisionPart::Secondary,
            settings.and_then(|s| s.rules_secondary.as_ref()),
            "secondary",
        )?,
    ])
}

/// Check every part, first refusal wins. Pure: no file, no database.
pub fn check_bundle(
    bytes: &BundleBytes,
    platform: HostPlatform,
) -> Result<CheckedBundle, ProvisionRefusal> {
    let settings = bytes
        .settings
        .as_deref()
        .map(read_settings_export)
        .transpose()
        .map_err(|(code, detail)| ProvisionRefusal::new(ProvisionPart::Settings, code, detail))?;
    let [primary, secondary] = rules_of_routes(bytes, settings.as_ref())?;
    let primary = primary
        .map(|(b, part)| check_rules(b, RouteRole::Primary, part, platform))
        .transpose()?;
    let secondary = secondary
        .map(|(b, part)| check_rules(b, RouteRole::Secondary, part, platform))
        .transpose()?;
    if let (Some(p), Some(s)) = (primary.as_ref(), secondary.as_ref()) {
        let book = CanonicalRuleBook {
            primary: p.clone(),
            secondary: s.clone(),
        };
        let json = rules_json_of(&book)
            .map_err(|e| ProvisionRefusal::new(ProvisionPart::Secondary, "rules-unencodable", e))?;
        if let Some(network) = crate::activation_coordinator::network_on_both_routes(&json, None) {
            return Err(ProvisionRefusal::new(
                ProvisionPart::Secondary,
                "network-on-both-routes",
                format!("{network} is named in both files"),
            ));
        }
        if let Some(folder) = crate::activation_coordinator::folder_on_both_routes(&json, None) {
            return Err(ProvisionRefusal::new(
                ProvisionPart::Secondary,
                "folder-on-both-routes",
                format!("{folder} is named in both files"),
            ));
        }
    }
    let options = bytes
        .options
        .as_deref()
        .map(read_options)
        .transpose()
        .map_err(|(code, detail)| ProvisionRefusal::new(ProvisionPart::Options, code, detail))?
        .unwrap_or_default();
    Ok(CheckedBundle {
        primary,
        secondary,
        settings,
        options,
    })
}

/// One rules file through the import parser, then through the gates a saved
/// book meets — alone, since nothing it would be merged with exists yet.
fn check_rules(
    bytes: &[u8],
    route: RouteRole,
    part: ProvisionPart,
    platform: HostPlatform,
) -> Result<CanonicalRuleSet, ProvisionRefusal> {
    let set = crate::production_mutation_executor::canonicalize_route_file_bytes(
        bytes, route, false, false, platform,
    )
    .map_err(|e| ProvisionRefusal::new(part, &e.code, e.message))?;
    let mut book = CanonicalRuleBook::default();
    match route {
        RouteRole::Primary => book.primary = set.clone(),
        RouteRole::Secondary => book.secondary = set.clone(),
    }
    let json =
        rules_json_of(&book).map_err(|e| ProvisionRefusal::new(part, "rules-unencodable", e))?;
    if let Some(refusal) = book_gate_refusal(&json) {
        return Err(ProvisionRefusal::new(part, refusal.0, refusal.1));
    }
    Ok(set)
}

fn rules_json_of(book: &CanonicalRuleBook) -> Result<String, String> {
    let content = RulesRevisionContent::new(book.clone());
    let dto = nrr_domain::rules_json_codec::encode(&content);
    nrr_shared::rules_json::to_canonical_string(&dto).map_err(|e| e.to_string())
}

/// The submission gates of the coordinator and the executor, over a book with
/// nothing in force before it.
fn book_gate_refusal(json: &str) -> Option<(&'static str, String)> {
    use crate::activation_coordinator::{
        control_character_in_rules, rules_with_refused_values, unsupported_rule_shape,
    };
    if let Some((rule_id, reason)) = unsupported_rule_shape(json, None) {
        return Some((
            "unsupported-rule-shape",
            format!("rule {rule_id}: {reason:?}"),
        ));
    }
    if let Some(hit) = control_character_in_rules(json) {
        return Some((
            "control-character-in-rule",
            format!("rule {} ({:?})", hit.rule_id, hit.field),
        ));
    }
    let refused = rules_with_refused_values(json, None);
    if let Some(first) = refused.first() {
        return Some((
            "invalid-rule-value",
            format!(
                "{} rule(s) with a value the rules table marks as an error, first: {first:?}",
                refused.len()
            ),
        ));
    }
    let dto = nrr_shared::rules_json::from_canonical_string(json).ok()?;
    let own = dto
        .primary
        .iter()
        .chain(dto.secondary.iter())
        .map(|rule| rule.origin.is_none());
    match nrr_domain::validation::rule_cap_excess(
        own,
        Some(nrr_domain::auto_rule_budget::MAX_AUTO_RULES),
    ) {
        None => None,
        Some(nrr_domain::validation::RuleCapExcess::User { count, limit }) => Some((
            "rule-cap-exceeded",
            format!("up to {limit} active rules are allowed; the file has {count}"),
        )),
        Some(nrr_domain::validation::RuleCapExcess::Auto { count, limit }) => Some((
            "auto-rule-cap-exceeded",
            format!("up to {limit} app-added rules are allowed; the file has {count}"),
        )),
    }
}

/// Lines a reader looks at before giving up: far beyond any real file.
const MAX_LINES: usize = 2_000;

type ReadError = (&'static str, String);

/// UTF-8 text with the BOM stripped, within `limit` bytes and [`MAX_LINES`].
fn bounded_text(bytes: &[u8], limit: usize) -> Result<&str, ReadError> {
    let text = utf8_within(bytes, limit)?;
    if text.lines().nth(MAX_LINES).is_some() {
        return Err(too_many_lines());
    }
    Ok(text)
}

fn utf8_within(bytes: &[u8], limit: usize) -> Result<&str, ReadError> {
    if bytes.len() > limit {
        return Err((
            "file-too-large",
            format!("{} bytes (limit {limit})", bytes.len()),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ("file-encoding", "the file is not UTF-8".to_owned()))?;
    Ok(text.strip_prefix('\u{FEFF}').unwrap_or(text))
}

fn too_many_lines() -> ReadError {
    ("too-many-lines", format!("more than {MAX_LINES} lines"))
}

/// Leading spaces; a tab is not indentation.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// The lines of a literal block scalar (`|` clips to one final line break,
/// `|-` strips it) under a key indented `key_indent`, consumed from `lines`.
/// Its content may not pass [`RULES_MAX_BYTES`]: it is a rules file.
fn read_block_scalar<'a>(
    lines: &mut std::iter::Peekable<impl Iterator<Item = (usize, &'a str)>>,
    key_indent: usize,
    keep_final_break: bool,
) -> Result<String, ReadError> {
    let mut out = String::new();
    let mut content_indent: Option<usize> = None;
    let mut pending_blank = 0usize;
    while let Some(&(number, raw)) = lines.peek() {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            pending_blank += 1;
            lines.next();
            continue;
        }
        let indent = indent_of(line);
        let want = *content_indent.get_or_insert(indent);
        if indent <= key_indent {
            break;
        }
        if indent < want {
            return Err(("bad-block-indentation", format!("line {}", number + 1)));
        }
        for _ in 0..pending_blank {
            out.push('\n');
        }
        pending_blank = 0;
        out.push_str(&line[want..]);
        out.push('\n');
        if out.len() > RULES_MAX_BYTES {
            return Err((
                "rules-too-large",
                format!("more than {RULES_MAX_BYTES} bytes of rules"),
            ));
        }
        lines.next();
    }
    if content_indent.is_some_and(|want| want <= key_indent) || out.is_empty() {
        return Ok(String::new());
    }
    if !keep_final_break {
        out.pop();
    }
    Ok(out)
}

/// Section depth a settings export never comes near.
const MAX_DEPTH: usize = 8;

/// The settings export as `production_settings_exporter` writes it: the
/// `nrr_settings_export:` root, `version` 1 or 2, `behavior.route_mode`,
/// `behavior.leak_protection` and, from version 2, `rules.primary` and
/// `rules.secondary` as literal block scalars. Lines outside the blocks count
/// against [`MAX_LINES`]; each block against the rules-file size limit.
pub fn read_settings_export(bytes: &[u8]) -> Result<SettingsFacts, ReadError> {
    let text = utf8_within(bytes, SETTINGS_MAX_BYTES)?;
    let mut seen_root = false;
    let mut version: Option<String> = None;
    let mut route_mode: Option<String> = None;
    let mut leak_protection: Option<String> = None;
    let mut rules: [Option<String>; 2] = [None, None];
    // Open sections, outermost first, each with the indent of its key.
    let mut open: Vec<(usize, &str)> = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    let mut structural = 0usize;
    while let Some((number, raw)) = lines.next() {
        structural += 1;
        if structural > MAX_LINES {
            return Err(too_many_lines());
        }
        let at = || format!("line {}", number + 1);
        let line = raw.trim_end_matches('\r');
        let content = line.trim_start();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        let indent = line.len() - content.len();
        if line[..indent].contains('\t') {
            return Err(("tab-indentation", at()));
        }
        if !seen_root {
            if indent != 0 || content.trim_end() != "nrr_settings_export:" {
                return Err((
                    "not-a-settings-export",
                    "the file does not start with `nrr_settings_export:`".to_owned(),
                ));
            }
            seen_root = true;
            continue;
        }
        if indent == 0 {
            return Err(("unexpected-root-key", at()));
        }
        let Some((key, value)) = content.split_once(':') else {
            return Err(("not-a-key", at()));
        };
        let key = key.trim();
        while open.last().is_some_and(|(depth, _)| *depth >= indent) {
            open.pop();
        }
        let block = match value
            .split_once(" #")
            .map_or(value, |(before, _)| before)
            .trim()
        {
            "|" => Some(true),
            "|-" => Some(false),
            _ => None,
        };
        if let Some(keep_final_break) = block {
            let body = read_block_scalar(&mut lines, indent, keep_final_break)?;
            let path: Vec<&str> = open.iter().map(|(_, name)| *name).collect();
            let slot = match (path.as_slice(), key) {
                (["rules"], "primary") => Some(0),
                (["rules"], "secondary") => Some(1),
                _ => None,
            };
            if let Some(slot) = slot {
                rules[slot] = (!body.trim().is_empty()).then_some(body);
            }
            continue;
        }
        let value = unquote(value.trim()).map_err(|code| (code, at()))?;
        // A key with no value opens a section; its children sit deeper.
        if value.is_empty() {
            if open.len() == MAX_DEPTH {
                return Err(("too-deep", at()));
            }
            open.push((indent, key));
            continue;
        }
        let path: Vec<&str> = open.iter().map(|(_, name)| *name).collect();
        match (path.as_slice(), key) {
            ([], "version") => version = Some(value),
            (["behavior"], "route_mode") => route_mode = Some(value),
            (["behavior"], "leak_protection") => leak_protection = Some(value),
            // Rules travel only as a block: anything else would be dropped.
            (["rules"], "primary" | "secondary") => return Err(("rules-not-a-block", at())),
            _ => {}
        }
    }
    if !seen_root {
        return Err(("not-a-settings-export", "the file is empty".to_owned()));
    }
    match version.as_deref() {
        Some("1") if rules.iter().any(Option::is_some) => {
            return Err((
                "rules-need-version-2",
                "a version 1 file carries no rules".to_owned(),
            ))
        }
        Some("1" | "2") => {}
        Some(other) => {
            return Err((
                "unsupported-version",
                format!("version {other}; this build reads versions 1 and 2"),
            ))
        }
        None => return Err(("missing-version", "no `version:` line".to_owned())),
    }
    let [rules_primary, rules_secondary] = rules;
    let mut leak_protection = match leak_protection.as_deref() {
        None | Some("") => None,
        Some(slug) => Some(slug.parse::<LeakProtection>().map_err(|_| {
            (
                "unknown-leak-protection",
                format!("leak_protection {slug:?}"),
            )
        })?),
    };
    let route_mode = match route_mode.as_deref() {
        None | Some("") => None,
        // An export written before the mode was retired: the additional route,
        // and its promise of no leaks.
        Some("strict-secondary-fail-closed") => {
            leak_protection = Some(LeakProtection::Everything);
            Some(BehaviorMode::PreferSecondaryWhenAvailable)
        }
        Some(slug) => Some(
            BehaviorMode::from_slug(slug)
                .ok_or(("unknown-route-mode", format!("route_mode {slug:?}")))?,
        ),
    };
    Ok(SettingsFacts {
        route_mode,
        leak_protection,
        rules_primary,
        rules_secondary,
    })
}

/// A YAML scalar as the exporter writes it: double-quoted with `\\`, `\"`,
/// `\n`, `\r`, `\t` and `\xHH` escapes, or plain; a ` #` comment may follow.
fn unquote(value: &str) -> Result<String, &'static str> {
    let Some(inner) = value.strip_prefix('"') else {
        let plain = value.split_once(" #").map_or(value, |(before, _)| before);
        return Ok(plain.trim_end().to_owned());
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => {
                let rest = inner[at + 1..].trim_start();
                return if rest.is_empty() || rest.starts_with('#') {
                    Ok(out)
                } else {
                    Err("text-after-string")
                };
            }
            '\\' => match chars.next().map(|(_, c)| c) {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).map(|(_, c)| c).collect();
                    let code = u8::from_str_radix(&hex, 16).map_err(|_| "bad-escape")?;
                    out.push(char::from(code));
                }
                _ => return Err("bad-escape"),
            },
            c => out.push(c),
        }
    }
    Err("unterminated-string")
}

/// `options.conf`: `key = value` lines, `#` comments. An unknown key is a
/// refusal, not a warning: the administrator asked for something this build
/// cannot do.
pub fn read_options(bytes: &[u8]) -> Result<InstallOptions, ReadError> {
    let text = bounded_text(bytes, OPTIONS_MAX_BYTES)?;
    let mut options = InstallOptions::default();
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(("not-a-key", format!("line {}", number + 1)));
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        match key.as_str() {
            "secondary-unset" | "secondary_unset" => {
                let unset = SecondaryUnset::from_slug(&value.to_ascii_lowercase()).ok_or((
                    "unknown-secondary-unset",
                    format!("{value:?}; expected direct or block"),
                ))?;
                options.secondary_unset = Some(unset);
            }
            _ => return Err(("unknown-option", format!("{key:?} on line {}", number + 1))),
        }
    }
    Ok(options)
}

/// The options file the stage verb writes for the given choices.
pub fn options_file_text(options: &InstallOptions) -> Option<String> {
    let unset = options.secondary_unset?;
    Some(format!("secondary-unset = {}\n", unset.slug()))
}

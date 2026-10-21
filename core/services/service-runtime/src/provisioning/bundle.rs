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

use super::{exit, OPTIONS_MAX_BYTES, SETTINGS_MAX_BYTES};

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SettingsFacts {
    pub route_mode: Option<BehaviorMode>,
    /// The floor of each new user's first leak protection.
    pub leak_protection: Option<LeakProtection>,
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

/// Check every part, first refusal wins. Pure: no file, no database.
pub fn check_bundle(
    bytes: &BundleBytes,
    platform: HostPlatform,
) -> Result<CheckedBundle, ProvisionRefusal> {
    let primary = bytes
        .primary
        .as_deref()
        .map(|b| check_rules(b, RouteRole::Primary, platform))
        .transpose()?;
    let secondary = bytes
        .secondary
        .as_deref()
        .map(|b| check_rules(b, RouteRole::Secondary, platform))
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
    let settings = bytes
        .settings
        .as_deref()
        .map(read_settings_export)
        .transpose()
        .map_err(|(code, detail)| ProvisionRefusal::new(ProvisionPart::Settings, code, detail))?;
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
    platform: HostPlatform,
) -> Result<CanonicalRuleSet, ProvisionRefusal> {
    let part = match route {
        RouteRole::Primary => ProvisionPart::Primary,
        RouteRole::Secondary => ProvisionPart::Secondary,
    };
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
    if bytes.len() > limit {
        return Err((
            "file-too-large",
            format!("{} bytes (limit {limit})", bytes.len()),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ("file-encoding", "the file is not UTF-8".to_owned()))?;
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    if text.lines().nth(MAX_LINES).is_some() {
        return Err(("too-many-lines", format!("more than {MAX_LINES} lines")));
    }
    Ok(text)
}

/// Section depth a settings export never comes near.
const MAX_DEPTH: usize = 8;

/// The settings export as `production_settings_exporter` writes it: the
/// `nrr_settings_export:` root, `version: 1`, `behavior.route_mode` and
/// `behavior.leak_protection`.
pub fn read_settings_export(bytes: &[u8]) -> Result<SettingsFacts, ReadError> {
    let text = bounded_text(bytes, SETTINGS_MAX_BYTES)?;
    let mut seen_root = false;
    let mut version: Option<String> = None;
    let mut route_mode: Option<String> = None;
    let mut leak_protection: Option<String> = None;
    // Open sections, outermost first, each with the indent of its key.
    let mut open: Vec<(usize, &str)> = Vec::new();
    for (number, raw) in text.lines().enumerate() {
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
        let value = unquote(value.trim()).map_err(|code| (code, at()))?;
        while open.last().is_some_and(|(depth, _)| *depth >= indent) {
            open.pop();
        }
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
            _ => {}
        }
    }
    if !seen_root {
        return Err(("not-a-settings-export", "the file is empty".to_owned()));
    }
    match version.as_deref() {
        Some("1") => {}
        Some(other) => {
            return Err((
                "unsupported-version",
                format!("version {other}; this build reads version 1"),
            ))
        }
        None => return Err(("missing-version", "no `version:` line".to_owned())),
    }
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

//! What kind of rule a value is by its spelling, and the type a value written
//! as the wrong one belongs to — `ruleValueClass`, `misplacedRuleType` and
//! `misplacedTargetType` in `rules.js`; what an application value names —
//! `appValueForm`.
//!
//! The definitions are `nrr_shared::rule_value_class` and
//! `nrr_shared::app_path`, which the service's validation reads too, so a
//! value the clients offer to move is exactly one the service refuses where it
//! stands.

use nrr_shared::app_identity::ExecutableNaming;
use nrr_shared::app_path::{is_path_value, AppPath, AppPathError, PathStyle};
use nrr_shared::preset_parser::without_children_flag;
use nrr_shared::rule_value_class::{
    misplaced_rule_value, misplaced_target_of_message_key, rule_type_from_slug,
};

pub use nrr_shared::rule_value_class::{classify_rule_value, RuleValueClass};

/// How the application section of `os` (`PlatformProfile.os`) spells a
/// program; anything but Linux and macOS is read as Windows, as the rules
/// file writer does.
#[must_use]
pub fn naming_for_os(os: &str) -> ExecutableNaming {
    match os {
        "linux" | "macos" => ExecutableNaming::AsNamed,
        _ => ExecutableNaming::WindowsExe,
    }
}

/// The rule-type slug `value` belongs to when a `rule_type` rule cannot hold
/// it on `os`; `None` when it can, the spelling does not say, or `rule_type`
/// is no rule type.
#[must_use]
pub fn misplaced_rule_type(rule_type: &str, value: &str, os: &str) -> Option<&'static str> {
    let section = rule_type_from_slug(rule_type)?;
    misplaced_rule_value(section, value, naming_for_os(os)).map(|t| t.slug())
}

/// The rule-type slug a verdict's message key says the value belongs to —
/// what "Move to section" moves it to.
#[must_use]
pub fn misplaced_target_type(message_key: &str) -> Option<&'static str> {
    misplaced_target_of_message_key(message_key).map(|t| t.slug())
}

/// The most characters the rule form takes for `rule_type`
/// (`ruleValueMaxLength`): an address's or a network's longest spelling, a
/// host name's 253, a path's bound for an application, which may be one. The
/// exact bound in bytes is the service's verdict.
#[must_use]
pub fn rule_value_max_length(rule_type: &str) -> usize {
    match rule_type {
        "zone" | "domain" => 253,
        "exact-ip" | "exact-ipv4" | "exact-ipv6" => 45,
        "subnet" => 51,
        "ip-range" => 93,
        "application" => nrr_shared::app_path::MAX_PATH_VALUE_BYTES,
        _ => nrr_shared::rule_value_class::MAX_RULE_VALUE_BYTES,
    }
}

/// How the application section of `os` spells and compares paths; anything
/// but Linux and macOS is read as Windows, as [`naming_for_os`] reads it.
#[must_use]
pub fn path_style_for_os(os: &str) -> PathStyle {
    match os {
        "linux" => PathStyle::Linux,
        "macos" => PathStyle::MacOS,
        _ => PathStyle::Windows,
    }
}

/// What an application rule value names on `os` (`appValueForm` in
/// `rules.js`): `name`, `name-glob`, a path form (`file`, `folder`,
/// `folder-tree`, `file-or-folder`), or why a path names no program
/// (`path-star`, `path-not-absolute`, `path-invalid`, the tail of the locale
/// key the service's verdict carries). `+children` is not part of the value.
#[must_use]
pub fn app_value_form(value: &str, os: &str) -> &'static str {
    let trimmed = value.trim();
    let value = without_children_flag(trimmed);
    let style = path_style_for_os(os);
    if is_path_value(&value, style) {
        // Taking `+children` off rejoins the words, a line break with them.
        if trimmed.chars().any(char::is_control) {
            return AppPathError::Malformed.slug();
        }
        return match AppPath::parse(&value, style) {
            Ok(path) => path.kind().slug(),
            Err(problem) => problem.slug(),
        };
    }
    if value.contains('*') {
        "name-glob"
    } else {
        "name"
    }
}

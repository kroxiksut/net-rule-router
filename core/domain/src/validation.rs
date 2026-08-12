//! Validation pipeline for routing configurations and rule sets.
//!
//! # Pipeline stages
//!
//! The full pipeline is split across two modules. This module implements the
//! format-independent stages:
//!
//! ```text
//! parse_rules_file()          ← rules_file module
//! rules_file_to_route_rule_set() ← rules_file module
//! semantic validate ─┐
//! normalize          ├─► ValidationOutcome   ← this module
//! canonicalize      ─┘
//! ```
//!
//! Entry point: [`validate_and_canonicalize`].
//!
//! # Error model
//!
//! - [`ValidationError`] — blocking. [`CanonicalProfile`] is **not** built when
//!   any error is present.
//! - [`ValidationWarning`] — non-blocking. [`CanonicalProfile`] is built and
//!   warnings are attached to the outcome.
//!
//! The caller (GUI, service, test harness) decides what to do with warnings.
//! The domain layer never silently drops them.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr};

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::{
    canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalProfile,
        CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    },
    ActiveConfiguration, AddressMatch, AppMatch, AppMatchPattern, Rule, RuleId,
};

// ── Public error types ────────────────────────────────────────────────────────

/// A blocking validation error that prevents [`CanonicalProfile`] from being built.
///
/// Every variant carries enough context for the caller to produce a meaningful
/// diagnostic message without re-examining the source configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// No primary route binding is present. A primary binding is required for any
    /// configuration to be valid — there is no meaningful default route without it.
    MissingPrimaryBinding,

    /// The same adapter is bound to both the primary and secondary roles.
    /// Primary and secondary must always be distinct adapters.
    SameAdapterBoundToBothRoles { stable_id: String },

    /// A rule has neither an `address_match` nor an `app_match`. Such a rule
    /// can never match any traffic and has no valid interpretation.
    RuleEmptyMatch { rule_id: RuleId },

    /// A `Domain` rule has an empty value after trimming.
    DomainEmptyValue { rule_id: RuleId },

    /// A `Domain` rule value failed IDNA normalization. The value is not a valid
    /// internationalized domain name per UTS#46/IDNA2008.
    DomainInvalidIdn { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains an IPv6 address. IPv6 is not supported in the
    /// Free edition. CIDR subnets and ranges are also Pro edition features —
    /// see [`ValidationError::CidrNotSupportedInFree`] and
    /// [`ValidationError::IpRangeNotSupportedInFree`].
    Ipv6NotSupportedInFree { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains a CIDR notation address (`192.168.1.0/24`).
    /// CIDR subnet matching is a Pro edition feature.
    CidrNotSupportedInFree { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains an IP range (`10.0.0.1-10.0.0.100`).
    /// Range matching is a Pro edition feature.
    IpRangeNotSupportedInFree { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains a string that cannot be parsed as any IP
    /// address. The rule cannot be applied and must be corrected.
    InvalidIpAddress { rule_id: RuleId, value: String },

    /// A `Zone` rule has an empty name after trimming.
    ZoneEmptyName { rule_id: RuleId },

    /// An application glob pattern is bare `*`, which would match every running
    /// process. This is rejected as too broad.
    AppGlobTooWide { rule_id: RuleId },
}

impl ValidationError {
    /// The rule ID associated with this error, if applicable.
    pub fn rule_id(&self) -> Option<&RuleId> {
        match self {
            Self::MissingPrimaryBinding | Self::SameAdapterBoundToBothRoles { .. } => None,
            Self::RuleEmptyMatch { rule_id }
            | Self::DomainEmptyValue { rule_id }
            | Self::DomainInvalidIdn { rule_id, .. }
            | Self::Ipv6NotSupportedInFree { rule_id, .. }
            | Self::CidrNotSupportedInFree { rule_id, .. }
            | Self::IpRangeNotSupportedInFree { rule_id, .. }
            | Self::InvalidIpAddress { rule_id, .. }
            | Self::ZoneEmptyName { rule_id }
            | Self::AppGlobTooWide { rule_id } => Some(rule_id),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrimaryBinding => {
                write!(
                    f,
                    "no primary route binding — a primary adapter must be assigned"
                )
            }
            Self::SameAdapterBoundToBothRoles { stable_id } => {
                write!(
                    f,
                    "adapter '{stable_id}' is bound to both primary and secondary roles"
                )
            }
            Self::RuleEmptyMatch { rule_id } => {
                write!(f, "rule {rule_id}: has neither address_match nor app_match")
            }
            Self::DomainEmptyValue { rule_id } => {
                write!(f, "rule {rule_id}: domain value is empty")
            }
            Self::DomainInvalidIdn { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: '{value}' is not a valid internationalized domain name"
                )
            }
            Self::Ipv6NotSupportedInFree { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: IPv6 address '{value}' is not supported in the Free edition"
                )
            }
            Self::CidrNotSupportedInFree { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: CIDR notation '{value}' is a Pro edition feature"
                )
            }
            Self::IpRangeNotSupportedInFree { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: IP range '{value}' is a Pro edition feature"
                )
            }
            Self::InvalidIpAddress { rule_id, value } => {
                write!(f, "rule {rule_id}: '{value}' is not a valid IP address")
            }
            Self::ZoneEmptyName { rule_id } => {
                write!(f, "rule {rule_id}: zone name is empty")
            }
            Self::AppGlobTooWide { rule_id } => {
                write!(
                    f,
                    "rule {rule_id}: bare '*' as a glob pattern matches every process \
                     and is not allowed — use a more specific pattern"
                )
            }
        }
    }
}

// ── Public warning types ──────────────────────────────────────────────────────

/// A non-blocking validation warning. [`CanonicalProfile`] is still produced
/// when warnings are present.
///
/// Warnings represent normalization side-effects and suspicious-but-valid
/// configurations that the user or GUI should be made aware of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    /// No secondary binding is present and the behavior mode is
    /// `StrictSecondaryFailClosed`. The fail-closed contract cannot be fulfilled
    /// without a secondary adapter.
    MissingSecondaryWithFailClosed,

    /// The secondary binding references an adapter that is not in the current
    /// adapter snapshot. The adapter may be temporarily disconnected.
    UnknownAdapterReference { role: RouteRole, stable_id: String },

    /// A Unicode domain label was normalized to its punycode (ASCII) equivalent
    /// per IDNA2008. The rule will match using the punycode form.
    DomainNormalizedToAscii {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// A process name had a trailing-dot or leading/trailing whitespace removed.
    /// This is distinct from path stripping and `.exe` appending.
    DomainTrailingDotRemoved {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) was normalized to its
    /// IPv4 equivalent. The rule will match on the IPv4 address.
    Ipv4MappedIpv6Normalized {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// A process name contained a directory path component. The path was stripped
    /// and only the filename is used for matching.
    ProcessNameContainedPath {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// A process name was missing the `.exe` suffix required for reliable
    /// Windows process matching. The suffix was appended automatically.
    ProcessNameMissingExeSuffix {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// Two rules within the same [`RouteRuleSet`] have identical match conditions.
    /// The duplicate was silently removed — only one copy is present in the
    /// [`CanonicalProfile`].
    DuplicateRuleInSameSet {
        /// The ID of the rule that was kept.
        kept_rule_id: RuleId,
        /// The ID of the rule that was removed.
        removed_rule_id: RuleId,
        role: RouteRole,
    },

    /// A rule with identical match conditions exists in both the primary and
    /// secondary [`RouteRuleSet`]. This is ambiguous — the GUI should ask the
    /// user which list to keep it in.
    DuplicateRuleAcrossSets {
        primary_rule_id: RuleId,
        secondary_rule_id: RuleId,
    },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSecondaryWithFailClosed => {
                write!(
                    f,
                    "behavior mode is StrictSecondaryFailClosed but no secondary binding is present"
                )
            }
            Self::UnknownAdapterReference { role, stable_id } => {
                write!(
                    f,
                    "{role:?} binding references adapter '{stable_id}' \
                     which is not in the current adapter snapshot"
                )
            }
            Self::DomainNormalizedToAscii {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: domain '{original}' normalized to '{normalized}' (IDNA2008)"
                )
            }
            Self::DomainTrailingDotRemoved {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: domain '{original}' had trailing dot removed → '{normalized}'"
                )
            }
            Self::Ipv4MappedIpv6Normalized {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: IPv4-mapped IPv6 '{original}' normalized to '{normalized}'"
                )
            }
            Self::ProcessNameContainedPath {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: process path '{original}' stripped to filename '{normalized}'"
                )
            }
            Self::ProcessNameMissingExeSuffix {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: process name '{original}' missing .exe suffix → '{normalized}'"
                )
            }
            Self::DuplicateRuleInSameSet {
                kept_rule_id,
                removed_rule_id,
                role,
            } => {
                write!(
                    f,
                    "duplicate rule in {role:?} set: kept '{kept_rule_id}', \
                     removed '{removed_rule_id}'"
                )
            }
            Self::DuplicateRuleAcrossSets {
                primary_rule_id,
                secondary_rule_id,
            } => {
                write!(
                    f,
                    "rule '{primary_rule_id}' (primary) and '{secondary_rule_id}' (secondary) \
                     have identical match conditions — user should choose which list to keep it in"
                )
            }
        }
    }
}

// ── Outcome ───────────────────────────────────────────────────────────────────

/// The result of running [`validate_and_canonicalize`] on an
/// [`ActiveConfiguration`].
///
/// # Variants
///
/// - [`ValidationOutcome::Accepted`] — no errors, no warnings.
/// - [`ValidationOutcome::AcceptedWithWarnings`] — no blocking errors; the
///   [`CanonicalProfile`] was built and is ready for use. Warnings describe
///   normalization side-effects or suspicious-but-valid configuration choices.
/// - [`ValidationOutcome::Rejected`] — one or more blocking errors prevent
///   [`CanonicalProfile`] from being built. The configuration must be corrected
///   before it can be activated.
#[derive(Clone, Debug)]
pub enum ValidationOutcome {
    /// Validation succeeded with no warnings.
    Accepted(CanonicalProfile),

    /// Validation succeeded; the profile is usable but warnings are present.
    AcceptedWithWarnings {
        profile: CanonicalProfile,
        warnings: Vec<ValidationWarning>,
    },

    /// Validation failed. No profile is available.
    Rejected {
        errors: Vec<ValidationError>,
        warnings: Vec<ValidationWarning>,
    },
}

impl ValidationOutcome {
    /// Returns the canonical profile if validation succeeded (with or without warnings).
    pub fn profile(&self) -> Option<&CanonicalProfile> {
        match self {
            Self::Accepted(p) | Self::AcceptedWithWarnings { profile: p, .. } => Some(p),
            Self::Rejected { .. } => None,
        }
    }

    /// Returns all non-blocking warnings, empty when there are none.
    pub fn warnings(&self) -> &[ValidationWarning] {
        match self {
            Self::Accepted(_) => &[],
            Self::AcceptedWithWarnings { warnings, .. } | Self::Rejected { warnings, .. } => {
                warnings
            }
        }
    }

    /// Returns all blocking errors, empty when accepted.
    pub fn errors(&self) -> &[ValidationError] {
        match self {
            Self::Accepted(_) | Self::AcceptedWithWarnings { .. } => &[],
            Self::Rejected { errors, .. } => errors,
        }
    }

    /// `true` when the profile was built (accepted with or without warnings).
    pub fn is_accepted(&self) -> bool {
        self.profile().is_some()
    }

    /// `true` only when accepted without any warnings.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }
}

// ── Pipeline entry point ──────────────────────────────────────────────────────

/// Runs the format-independent validation pipeline on a parsed configuration.
///
/// This function implements the `semantic validate → normalize → canonicalize`
/// stages. The `parse` stage is implemented in
/// [`crate::rules_file::parse_rules_file`]; use
/// [`crate::rules_file::rules_file_to_route_rule_set`] to convert a
/// [`crate::rules_file::RulesFileParsed`] into a [`crate::RouteRuleSet`] before
/// building an [`crate::ActiveConfiguration`] for this function.
///
/// # Pipeline order
///
/// 1. Validate route bindings (missing primary, role conflict).
/// 2. For each rule in primary and secondary rule sets:
///    a. Validate that the rule has at least one match condition.
///    b. Normalize `address_match` (domain case/dot/IDN; IP version check).
///    c. Normalize `app_match` (path strip, `.exe` suffix, lowercase).
/// 3. Deduplicate within each rule set; detect cross-set duplicates.
/// 4. Build [`CanonicalProfile`] with [`CanonicalRuleSet`]s in canonical order.
/// 5. Check for behavior-mode / binding incompatibilities (warnings only).
///
/// # Return value
///
/// Returns [`ValidationOutcome::Rejected`] if any blocking error is found.
/// Returns [`ValidationOutcome::AcceptedWithWarnings`] if warnings accumulated.
/// Returns [`ValidationOutcome::Accepted`] only when the profile is fully clean.
pub fn validate_and_canonicalize(config: &ActiveConfiguration) -> ValidationOutcome {
    let mut errors: Vec<ValidationError> = Vec::new();
    let mut warnings: Vec<ValidationWarning> = Vec::new();

    // ── 1. Binding validation ─────────────────────────────────────────────────

    let primary_binding = match &config.primary {
        Some(b) => b,
        None => {
            errors.push(ValidationError::MissingPrimaryBinding);
            // Without a primary binding, further structural checks are meaningless.
            // Still collect rule errors so the caller can show a complete diagnostic.
            collect_rule_errors_only(config, &mut errors);
            return ValidationOutcome::Rejected { errors, warnings };
        }
    };

    if config.has_role_conflict() {
        errors.push(ValidationError::SameAdapterBoundToBothRoles {
            stable_id: primary_binding.adapter.stable_id.clone(),
        });
    }

    // ── 2. Rule normalization ─────────────────────────────────────────────────

    let primary_rules = normalize_rule_set(
        &config.rule_book.primary.rules,
        RouteRole::Primary,
        &mut errors,
        &mut warnings,
    );
    let secondary_rules = normalize_rule_set(
        &config.rule_book.secondary.rules,
        RouteRole::Secondary,
        &mut errors,
        &mut warnings,
    );

    // ── 3. Deduplication ─────────────────────────────────────────────────────

    let primary_rules = deduplicate_set(primary_rules, RouteRole::Primary, &mut warnings);
    let secondary_rules = deduplicate_set(secondary_rules, RouteRole::Secondary, &mut warnings);

    detect_cross_set_duplicates(&primary_rules, &secondary_rules, &mut warnings);

    // ── 4. Behavior-mode / binding compatibility (warnings) ───────────────────

    if config.secondary.is_none()
        && config.behavior_mode == RouteBehaviorMode::StrictSecondaryFailClosed
    {
        warnings.push(ValidationWarning::MissingSecondaryWithFailClosed);
    }

    // ── 5. Build outcome ──────────────────────────────────────────────────────

    if !errors.is_empty() {
        return ValidationOutcome::Rejected { errors, warnings };
    }

    let profile = CanonicalProfile {
        primary: primary_binding.clone(),
        secondary: config.secondary.clone(),
        behavior_mode: config.behavior_mode,
        rule_book: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary_rules),
            secondary: CanonicalRuleSet::from_rules(secondary_rules),
        },
    };

    if warnings.is_empty() {
        ValidationOutcome::Accepted(profile)
    } else {
        ValidationOutcome::AcceptedWithWarnings { profile, warnings }
    }
}

// ── Private pipeline helpers ──────────────────────────────────────────────────

/// Collects rule-level errors when we cannot build a profile at all (e.g. missing
/// primary binding). Warnings are skipped — the caller will return `Rejected`.
fn collect_rule_errors_only(config: &ActiveConfiguration, errors: &mut Vec<ValidationError>) {
    // Warnings are discarded — we cannot build a profile anyway (missing primary).
    let mut discard = Vec::new();
    for rule in config
        .rule_book
        .primary
        .rules
        .iter()
        .chain(config.rule_book.secondary.rules.iter())
    {
        if rule.address_match.is_none() && rule.app_match.is_none() {
            errors.push(ValidationError::RuleEmptyMatch {
                rule_id: rule.id.clone(),
            });
        }
        match &rule.address_match {
            Some(AddressMatch::ExactFqdn(v)) | Some(AddressMatch::SuffixDomain(v)) => {
                if let Err(e) = normalize_domain_label(v, &rule.id, &mut discard) {
                    errors.push(e);
                }
            }
            _ => {}
        }
        if let Some(AddressMatch::ExactIp(addr)) = rule.address_match {
            if let Err(e) = canonicalize_ip_addr(addr, &rule.id, &mut discard) {
                errors.push(e);
            }
        }
    }
}

/// Normalizes all rules in a [`RouteRuleSet`], accumulating errors and warnings.
/// Rules with blocking errors are excluded from the output — they will prevent
/// the final profile from being produced.
fn normalize_rule_set(
    rules: &[Rule],
    _role: RouteRole,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) -> Vec<CanonicalRule> {
    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        if let Some(canonical) = normalize_rule(rule, errors, warnings) {
            out.push(canonical);
        }
    }
    out
}

/// Normalizes a single rule. Returns `None` when a blocking error was found and
/// the rule should be excluded from the canonical output.
fn normalize_rule(
    rule: &Rule,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) -> Option<CanonicalRule> {
    // A rule must have at least one match condition.
    if rule.address_match.is_none() && rule.app_match.is_none() {
        errors.push(ValidationError::RuleEmptyMatch {
            rule_id: rule.id.clone(),
        });
        return None;
    }

    // Normalize address_match.
    let address_match = match &rule.address_match {
        None => None,
        Some(AddressMatch::Zone(name)) => {
            // Normalize: strip optional `*.` prefix, trim, lowercase.
            let trimmed = name.trim().to_lowercase();
            let stripped = trimmed.strip_prefix("*.").unwrap_or(&trimmed);
            if stripped.is_empty() {
                errors.push(ValidationError::ZoneEmptyName {
                    rule_id: rule.id.clone(),
                });
                return None;
            }
            // Canonicalize the zone labels through the same IDNA path as
            // domains so every producer converges on punycode: the GUI encodes
            // "рф" via QUrl::toAce to "xn--p1ai" before saving, and hostnames
            // are punycode at decision time — a raw Unicode zone here would
            // both never match and show up as a spurious removed+added pair in
            // the rule diff. A leading dot is zone-slice syntax, not a label,
            // so it is preserved verbatim and only the remainder is encoded.
            let (dot, body) = match stripped.strip_prefix('.') {
                Some(rest) => (".", rest),
                None => ("", stripped),
            };
            let normalized = if body.is_empty() {
                stripped.to_string()
            } else {
                match normalize_domain_label(body, &rule.id, warnings) {
                    Ok(canonical) => format!("{dot}{canonical}"),
                    Err(e) => {
                        errors.push(e);
                        return None;
                    }
                }
            };
            Some(CanonicalAddressMatch::Zone(normalized))
        }
        Some(AddressMatch::ExactFqdn(value)) => {
            match normalize_domain_label(value, &rule.id, warnings) {
                Ok(normalized) => Some(CanonicalAddressMatch::ExactFqdn(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::SuffixDomain(value)) => {
            match normalize_domain_label(value, &rule.id, warnings) {
                Ok(normalized) => Some(CanonicalAddressMatch::SuffixDomain(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::ExactIp(addr)) => {
            match canonicalize_ip_addr(*addr, &rule.id, warnings) {
                Ok(v4) => Some(CanonicalAddressMatch::ExactIp(v4)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
    };

    // Normalize app_match.
    let app_match = match rule.app_match.as_ref() {
        None => None,
        Some(a) => match normalize_app_match(a, &rule.id, warnings) {
            Ok(canonical) => Some(canonical),
            Err(e) => {
                errors.push(e);
                return None;
            }
        },
    };

    Some(CanonicalRule {
        id: rule.id.clone(),
        enabled: rule.enabled,
        address_match,
        app_match,
        comment: rule.comment.trim().to_string(),
        action: rule.action,
        // Provenance is carried through untouched: it is metadata about
        // authorship, not a match value, so there is nothing to normalise.
        origin: rule.origin.clone(),
    })
}

/// Normalizes a domain label value (the content of `ExactFqdn` or
/// `SuffixDomain`, and the label part of `Zone`):
/// - Removes trailing dot.
/// - Rejects empty values.
/// - Lowercases the result.
/// - Applies IDNA2008 normalization for non-ASCII labels (Unicode → punycode).
///
/// The caller is responsible for passing the right content: for `SuffixDomain`,
/// the `*.` prefix is already stripped by the file converter before reaching here.
fn normalize_domain_label(
    value: &str,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<String, ValidationError> {
    let trimmed = value.trim();

    // Remove trailing dot (canonical form has none).
    let without_dot = trimmed.trim_end_matches('.');

    if without_dot.is_empty() {
        return Err(ValidationError::DomainEmptyValue {
            rule_id: rule_id.clone(),
        });
    }

    // Warn if we stripped a trailing dot.
    if without_dot != trimmed {
        warnings.push(ValidationWarning::DomainTrailingDotRemoved {
            rule_id: rule_id.clone(),
            original: trimmed.to_string(),
            normalized: without_dot.to_string(),
        });
    }

    // Lowercase first (IDNA processing expects lowercase input for best results).
    let lowercased = without_dot.to_lowercase();

    // If purely ASCII, no further IDNA processing is needed.
    if lowercased.is_ascii() {
        return Ok(lowercased);
    }

    // Non-ASCII: apply IDNA2008 normalization (Unicode → punycode per UTS#46).
    match idna::domain_to_ascii(&lowercased) {
        Ok(ascii) => {
            if ascii != lowercased {
                warnings.push(ValidationWarning::DomainNormalizedToAscii {
                    rule_id: rule_id.clone(),
                    original: lowercased,
                    normalized: ascii.clone(),
                });
            }
            Ok(ascii)
        }
        Err(_) => Err(ValidationError::DomainInvalidIdn {
            rule_id: rule_id.clone(),
            value: without_dot.to_string(),
        }),
    }
}

/// Validates and converts an [`IpAddr`] to [`Ipv4Addr`].
///
/// - IPv4: accepted as-is.
/// - IPv4-mapped IPv6 (`::ffff:x.x.x.x`): normalized to IPv4 with a warning.
/// - Pure IPv6: rejected with a blocking error.
fn canonicalize_ip_addr(
    addr: IpAddr,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<Ipv4Addr, ValidationError> {
    match addr {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                warnings.push(ValidationWarning::Ipv4MappedIpv6Normalized {
                    rule_id: rule_id.clone(),
                    original: addr.to_string(),
                    normalized: v4.to_string(),
                });
                Ok(v4)
            } else {
                Err(ValidationError::Ipv6NotSupportedInFree {
                    rule_id: rule_id.clone(),
                    value: addr.to_string(),
                })
            }
        }
    }
}

/// Normalizes an [`AppMatch`]:
///
/// - `Exact`: strips any directory path separator, lowercases, appends `.exe` if absent.
/// - `Glob`: lowercases only; path-stripping and `.exe` appending are not applied
///   because the user controls the full pattern. Bare `*` is rejected as too broad.
fn normalize_app_match(
    app: &AppMatch,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<CanonicalAppMatch, ValidationError> {
    let canonical_pattern = match &app.pattern {
        AppMatchPattern::Exact(raw) => {
            let raw = raw.trim().to_string();

            // Strip path if present (handles `C:\Foo\bar.exe`, `C:/Foo/bar.exe`,
            // `//C//Foo//bar.exe` and other mixed-separator Windows path forms).
            let contains_sep = raw.contains('/') || raw.contains('\\');
            let filename: String = if contains_sep {
                let extracted = raw
                    .split(['/', '\\'])
                    .rfind(|s| !s.is_empty())
                    .unwrap_or(raw.as_str())
                    .to_string();
                warnings.push(ValidationWarning::ProcessNameContainedPath {
                    rule_id: rule_id.clone(),
                    original: raw.clone(),
                    normalized: extracted.clone(),
                });
                extracted
            } else {
                raw.clone()
            };

            // Lowercase (Windows process names are case-insensitive).
            let lowercased = filename.to_lowercase();

            // Append `.exe` if absent.
            let process_name = if lowercased.ends_with(".exe") {
                lowercased
            } else {
                let with_exe = format!("{lowercased}.exe");
                warnings.push(ValidationWarning::ProcessNameMissingExeSuffix {
                    rule_id: rule_id.clone(),
                    original: filename,
                    normalized: with_exe.clone(),
                });
                with_exe
            };

            CanonicalAppPattern::Exact(process_name)
        }
        AppMatchPattern::Glob(raw) => {
            let lowercased = raw.trim().to_lowercase();
            if lowercased == "*" {
                return Err(ValidationError::AppGlobTooWide {
                    rule_id: rule_id.clone(),
                });
            }
            CanonicalAppPattern::Glob(lowercased)
        }
    };

    Ok(CanonicalAppMatch {
        pattern: canonical_pattern,
        include_child_processes: app.include_child_processes,
    })
}

// ── Deduplication ─────────────────────────────────────────────────────────────

/// The match identity key used to detect duplicate rules.
///
/// Two rules are considered duplicates when their match conditions are
/// identical — regardless of `id`, `enabled`, or `comment`.
#[derive(PartialEq, Eq, Hash)]
struct MatchKey {
    address: Option<CanonicalAddressMatch>,
    app_pattern: Option<CanonicalAppPattern>,
    app_children: Option<bool>,
}

impl MatchKey {
    fn from_rule(rule: &CanonicalRule) -> Self {
        Self {
            address: rule.address_match.clone(),
            app_pattern: rule.app_match.as_ref().map(|a| a.pattern.clone()),
            app_children: rule.app_match.as_ref().map(|a| a.include_child_processes),
        }
    }
}

/// Removes duplicate rules within a single route rule set.
///
/// When two rules share identical match conditions, the first one encountered
/// is kept. A [`ValidationWarning::DuplicateRuleInSameSet`] is emitted for
/// each removed duplicate.
fn deduplicate_set(
    rules: Vec<CanonicalRule>,
    role: RouteRole,
    warnings: &mut Vec<ValidationWarning>,
) -> Vec<CanonicalRule> {
    let mut seen: std::collections::HashMap<MatchKey, RuleId> = std::collections::HashMap::new();
    let mut out = Vec::with_capacity(rules.len());

    for rule in rules {
        let key = MatchKey::from_rule(&rule);
        match seen.get(&key) {
            Some(kept_id) => {
                warnings.push(ValidationWarning::DuplicateRuleInSameSet {
                    kept_rule_id: kept_id.clone(),
                    removed_rule_id: rule.id.clone(),
                    role,
                });
            }
            None => {
                seen.insert(key, rule.id.clone());
                out.push(rule);
            }
        }
    }
    out
}

/// Detects rules with identical match conditions across the primary and secondary
/// sets. These are not auto-resolved — a warning is emitted so the GUI
/// can prompt the user to choose which list to keep the rule in.
fn detect_cross_set_duplicates(
    primary: &[CanonicalRule],
    secondary: &[CanonicalRule],
    warnings: &mut Vec<ValidationWarning>,
) {
    let primary_keys: std::collections::HashMap<MatchKey, &RuleId> = primary
        .iter()
        .map(|r| (MatchKey::from_rule(r), &r.id))
        .collect();

    for sec_rule in secondary {
        let key = MatchKey::from_rule(sec_rule);
        if let Some(pri_id) = primary_keys.get(&key) {
            warnings.push(ValidationWarning::DuplicateRuleAcrossSets {
                primary_rule_id: (*pri_id).clone(),
                secondary_rule_id: sec_rule.id.clone(),
            });
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use nrr_shared::{BindingSource, RouteBehaviorMode, RouteRole};

    use crate::{
        ActiveConfiguration, AdapterIdentity, AddressMatch, AppMatch, AppMatchPattern,
        RouteBinding, RouteRuleSet, Rule, RuleBook, RuleId,
    };

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn binding(role: RouteRole, stable_id: &str) -> RouteBinding {
        RouteBinding {
            role,
            adapter: AdapterIdentity {
                stable_id: stable_id.to_string(),
                display_name: stable_id.to_string(),
            },
            source: BindingSource::UserAssigned,
        }
    }

    fn primary() -> RouteBinding {
        binding(RouteRole::Primary, "eth0")
    }

    fn secondary() -> RouteBinding {
        binding(RouteRole::Secondary, "vpn0")
    }

    fn config_with_rules(
        primary: Option<RouteBinding>,
        secondary: Option<RouteBinding>,
        mode: RouteBehaviorMode,
        primary_rules: Vec<Rule>,
        secondary_rules: Vec<Rule>,
    ) -> ActiveConfiguration {
        ActiveConfiguration {
            primary,
            secondary,
            behavior_mode: mode,
            rule_book: RuleBook {
                primary: RouteRuleSet {
                    rules: primary_rules,
                },
                secondary: RouteRuleSet {
                    rules: secondary_rules,
                },
            },
        }
    }

    fn minimal_config() -> ActiveConfiguration {
        config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![],
            vec![],
        )
    }

    fn domain_rule(id: &str, label: &str) -> Rule {
        Rule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(AddressMatch::ExactFqdn(label.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn ip_rule(id: &str, addr: IpAddr) -> Rule {
        Rule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(AddressMatch::ExactIp(addr)),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn app_rule(id: &str, process: &str) -> Rule {
        Rule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: None,
            app_match: Some(AppMatch {
                pattern: AppMatchPattern::Exact(process.to_string()),
                include_child_processes: false,
                windows_service_name: None,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    // ── Binding validation ────────────────────────────────────────────────────

    #[test]
    fn missing_primary_is_rejected() {
        let config = config_with_rules(
            None,
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(!outcome.is_accepted());
        assert!(outcome
            .errors()
            .contains(&ValidationError::MissingPrimaryBinding));
    }

    #[test]
    fn role_conflict_is_rejected() {
        let config = config_with_rules(
            Some(binding(RouteRole::Primary, "eth0")),
            Some(binding(RouteRole::Secondary, "eth0")), // same adapter
            RouteBehaviorMode::PreferPrimary,
            vec![],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(!outcome.is_accepted());
        assert!(outcome
            .errors()
            .iter()
            .any(|e| matches!(e, ValidationError::SameAdapterBoundToBothRoles { .. })));
    }

    #[test]
    fn valid_config_no_rules_is_accepted_clean() {
        let outcome = validate_and_canonicalize(&minimal_config());
        assert!(outcome.is_clean());
        let profile = outcome.profile().expect("profile must be present");
        assert!(profile.rule_book.primary.is_empty());
        assert!(profile.rule_book.secondary.is_empty());
    }

    // ── Missing secondary with StrictFailClosed ───────────────────────────────

    #[test]
    fn missing_secondary_with_strict_fail_closed_is_warning() {
        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::StrictSecondaryFailClosed,
            vec![],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(outcome.is_accepted()); // not rejected
        assert!(outcome
            .warnings()
            .contains(&ValidationWarning::MissingSecondaryWithFailClosed));
    }

    #[test]
    fn missing_secondary_with_prefer_primary_is_clean() {
        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(outcome.is_clean());
    }

    // ── Domain normalization ──────────────────────────────────────────────────

    #[test]
    fn domain_label_uppercased_is_lowercased() {
        let mut warnings = Vec::new();
        let result =
            normalize_domain_label("Google.COM", &RuleId("r-1".to_string()), &mut warnings);
        assert_eq!(result, Ok("google.com".to_string()));
        assert!(warnings.is_empty());
    }

    #[test]
    fn domain_label_trailing_dot_removed_with_warning() {
        let mut warnings = Vec::new();
        let result =
            normalize_domain_label("example.com.", &RuleId("r-1".to_string()), &mut warnings);
        assert_eq!(result, Ok("example.com".to_string()));
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::DomainTrailingDotRemoved { .. })));
    }

    #[test]
    fn domain_label_empty_is_blocked() {
        let mut warnings = Vec::new();
        let result = normalize_domain_label("", &RuleId("r-1".to_string()), &mut warnings);
        assert!(matches!(
            result,
            Err(ValidationError::DomainEmptyValue { .. })
        ));
    }

    #[test]
    fn domain_label_only_trailing_dot_is_blocked() {
        let mut warnings = Vec::new();
        let result = normalize_domain_label(".", &RuleId("r-1".to_string()), &mut warnings);
        assert!(matches!(
            result,
            Err(ValidationError::DomainEmptyValue { .. })
        ));
    }

    #[test]
    fn domain_label_idn_unicode_normalized_to_punycode() {
        let mut warnings = Vec::new();
        // образец.рф is a valid Russian IDN domain
        let result =
            normalize_domain_label("образец.рф", &RuleId("r-1".to_string()), &mut warnings);
        let normalized = result.expect("IDN domain must normalize successfully");
        assert!(normalized.is_ascii(), "normalized domain must be ASCII");
        assert!(normalized.starts_with("xn--"), "must be punycode");
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::DomainNormalizedToAscii { .. })));
    }

    #[test]
    fn domain_label_ascii_no_idn_warning() {
        let mut warnings = Vec::new();
        let result =
            normalize_domain_label("example.com", &RuleId("r-1".to_string()), &mut warnings);
        assert_eq!(result, Ok("example.com".to_string()));
        assert!(!warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::DomainNormalizedToAscii { .. })));
    }

    // ── Zone normalization ────────────────────────────────────────────────────

    fn zone_rule(id: &str, name: &str) -> Rule {
        Rule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(AddressMatch::Zone(name.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    /// Validates a config with a single primary zone rule and returns the
    /// canonical zone value.
    fn canonical_zone(raw: &str) -> String {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![zone_rule("r-1", raw)],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        let profile = outcome.profile().expect("profile must be present");
        match &profile.rule_book.primary.rules()[0].address_match {
            Some(CanonicalAddressMatch::Zone(name)) => name.clone(),
            other => panic!("expected a zone match, got {other:?}"),
        }
    }

    #[test]
    fn zone_unicode_normalized_to_punycode() {
        // The GUI (QUrl::toAce) stores "рф" as "xn--p1ai"; the service-side
        // canonical form must converge on the same spelling or the rule diff
        // reports a spurious removed+added pair.
        assert_eq!(canonical_zone("рф"), "xn--p1ai");
        assert_eq!(canonical_zone("РФ"), "xn--p1ai");
        assert_eq!(canonical_zone("ru"), "ru");
    }

    #[test]
    fn zone_wildcard_prefix_stripped_before_punycode() {
        assert_eq!(canonical_zone("*.рф"), "xn--p1ai");
        assert_eq!(canonical_zone("*.ru"), "ru");
    }

    #[test]
    fn zone_leading_dot_and_multi_label_preserved() {
        // Leading dot is zone-slice syntax and survives verbatim; only the
        // labels behind it are IDNA-encoded. Multi-label zones stay intact.
        assert_eq!(canonical_zone(".ru"), ".ru");
        assert_eq!(canonical_zone(".рф"), ".xn--p1ai");
        assert_eq!(canonical_zone("msk.ru"), "msk.ru");
        assert_eq!(canonical_zone("мск.рф"), "xn--j1adp.xn--p1ai");
    }

    #[test]
    fn zone_unicode_and_punycode_forms_produce_empty_diff() {
        // "рф" (as a rules file keeps it) and "xn--p1ai" (as the GUI saves
        // it) are the same zone after canonicalization: diffing the two
        // profiles must yield no rule changes.
        let profile_of = |raw: &str| {
            let config = config_with_rules(
                Some(primary()),
                Some(secondary()),
                RouteBehaviorMode::PreferPrimary,
                vec![zone_rule("r-1", raw)],
                vec![],
            );
            validate_and_canonicalize(&config)
                .profile()
                .expect("profile must be present")
                .clone()
        };
        let unicode = profile_of("рф");
        let punycode = profile_of("xn--p1ai");
        let diff = crate::review::compute_diff(Some(&unicode), &punycode);
        assert!(
            diff.rule_changes.is_empty(),
            "unicode and punycode spellings of one zone must not diff, got {:?}",
            diff.rule_changes
        );
        assert!(diff.is_empty());
    }

    // ── IP normalization ──────────────────────────────────────────────────────

    #[test]
    fn ipv4_accepted_as_is() {
        let mut warnings = Vec::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = canonicalize_ip_addr(addr, &RuleId("r-1".to_string()), &mut warnings);
        assert_eq!(result, Ok(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(warnings.is_empty());
    }

    #[test]
    fn ipv6_pure_is_rejected() {
        let mut warnings = Vec::new();
        // 2001:db8::1
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        let result = canonicalize_ip_addr(addr, &RuleId("r-1".to_string()), &mut warnings);
        assert!(matches!(
            result,
            Err(ValidationError::Ipv6NotSupportedInFree { .. })
        ));
    }

    #[test]
    fn ipv4_mapped_ipv6_normalized_to_ipv4() {
        let mut warnings = Vec::new();
        // ::ffff:192.0.2.1
        let addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201));
        let result = canonicalize_ip_addr(addr, &RuleId("r-1".to_string()), &mut warnings);
        assert_eq!(result, Ok(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::Ipv4MappedIpv6Normalized { .. })));
    }

    // ── Application normalization ─────────────────────────────────────────────

    #[test]
    fn process_name_exact_uppercased_lowercased() {
        let app = AppMatch {
            pattern: AppMatchPattern::Exact("Chrome.EXE".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Exact pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "chrome.exe");
        assert!(warnings.is_empty()); // uppercase → lowercase is silent, .exe already present
    }

    #[test]
    fn process_name_exact_missing_exe_gets_appended_with_warning() {
        let app = AppMatch {
            pattern: AppMatchPattern::Exact("chrome".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Exact pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "chrome.exe");
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::ProcessNameMissingExeSuffix { .. })));
    }

    #[test]
    fn process_name_exact_windows_path_stripped_with_warning() {
        let app = AppMatch {
            pattern: AppMatchPattern::Exact(r"C:\Program Files\chrome.exe".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Exact pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "chrome.exe");
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::ProcessNameContainedPath { .. })));
    }

    #[test]
    fn process_name_exact_double_slash_path_stripped() {
        let app = AppMatch {
            pattern: AppMatchPattern::Exact("//C//Program Files//chrome.exe".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Exact pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "chrome.exe");
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::ProcessNameContainedPath { .. })));
    }

    #[test]
    fn process_name_exact_forward_slash_path_stripped() {
        let app = AppMatch {
            pattern: AppMatchPattern::Exact("C:/Program Files/firefox.exe".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Exact pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "firefox.exe");
    }

    #[test]
    fn process_name_glob_is_lowercased() {
        let app = AppMatch {
            pattern: AppMatchPattern::Glob("*VPN*.EXE".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Glob pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "*vpn*.exe");
        assert!(warnings.is_empty());
    }

    #[test]
    fn process_name_glob_bare_star_is_rejected() {
        let app = AppMatch {
            pattern: AppMatchPattern::Glob("*".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings);
        assert!(matches!(
            result,
            Err(ValidationError::AppGlobTooWide { .. })
        ));
    }

    #[test]
    fn process_name_glob_accepted_no_exe_appended() {
        let app = AppMatch {
            pattern: AppMatchPattern::Glob("nord*".to_string()),
            include_child_processes: false,
            windows_service_name: None,
        };
        let mut warnings = Vec::new();
        let result = normalize_app_match(&app, &RuleId("r-1".to_string()), &mut warnings)
            .expect("Glob pattern must normalize successfully");
        assert_eq!(result.pattern.as_str(), "nord*");
        assert!(warnings.is_empty()); // no .exe appended for globs
    }

    // ── Rule-level validation ─────────────────────────────────────────────────

    #[test]
    fn rule_with_empty_match_is_rejected() {
        let rule = Rule {
            id: RuleId("r-empty".to_string()),
            enabled: true,
            address_match: None,
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![rule],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(!outcome.is_accepted());
        assert!(outcome
            .errors()
            .iter()
            .any(|e| matches!(e, ValidationError::RuleEmptyMatch { .. })));
    }

    #[test]
    fn ipv6_rule_is_rejected() {
        // 2001:db8::1
        let rule = ip_rule(
            "r-v6",
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        );
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![rule],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(!outcome.is_accepted());
        assert!(outcome
            .errors()
            .iter()
            .any(|e| matches!(e, ValidationError::Ipv6NotSupportedInFree { .. })));
    }

    // ── Deduplication ─────────────────────────────────────────────────────────

    #[test]
    fn duplicate_within_set_deduplicated_with_warning() {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![
                domain_rule("r-1", "example.com"),
                domain_rule("r-2", "example.com"), // duplicate
            ],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(outcome.is_accepted());
        let profile = outcome.profile().expect("profile must be present");
        assert_eq!(profile.rule_book.primary.len(), 1);
        assert!(outcome
            .warnings()
            .iter()
            .any(|w| matches!(w, ValidationWarning::DuplicateRuleInSameSet { .. })));
    }

    #[test]
    fn duplicate_across_sets_produces_warning_not_error() {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::PreferPrimary,
            vec![domain_rule("r-pri", "example.com")],
            vec![domain_rule("r-sec", "example.com")],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(outcome.is_accepted()); // not rejected
                                        // Both rules are kept — cross-set duplicate is a warning for the GUI
        let profile = outcome.profile().expect("profile must be present");
        assert_eq!(profile.rule_book.primary.len(), 1);
        assert_eq!(profile.rule_book.secondary.len(), 1);
        assert!(outcome
            .warnings()
            .iter()
            .any(|w| matches!(w, ValidationWarning::DuplicateRuleAcrossSets { .. })));
    }

    // ── Canonical profile contents ────────────────────────────────────────────

    #[test]
    fn canonical_profile_has_correct_binding_and_mode() {
        let config = config_with_rules(
            Some(primary()),
            Some(secondary()),
            RouteBehaviorMode::StrictSecondaryFailClosed,
            vec![],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        let profile = outcome.profile().expect("profile must be present");
        assert_eq!(profile.primary.adapter.stable_id, "eth0");
        assert_eq!(
            profile
                .secondary
                .as_ref()
                .map(|b| b.adapter.stable_id.as_str()),
            Some("vpn0")
        );
        assert_eq!(
            profile.behavior_mode,
            RouteBehaviorMode::StrictSecondaryFailClosed
        );
    }

    #[test]
    fn canonical_profile_rules_are_in_canonical_order() {
        // Insert rules in non-canonical order: app, ip, domain.
        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![
                app_rule("r-app", "firefox"),
                ip_rule("r-ip", IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                domain_rule("r-dom", "example.com"),
            ],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        let profile = outcome.profile().expect("profile must be present");
        let types: Vec<&str> = profile
            .rule_book
            .primary
            .rules()
            .iter()
            .map(|r| match &r.address_match {
                Some(CanonicalAddressMatch::Zone(_)) => "zone",
                Some(
                    CanonicalAddressMatch::ExactFqdn(_) | CanonicalAddressMatch::SuffixDomain(_),
                ) => "domain",
                Some(CanonicalAddressMatch::ExactIp(_)) => "ip",
                None => "app",
            })
            .collect();
        assert_eq!(types, ["domain", "ip", "app"]);
    }

    #[test]
    fn equivalent_configs_different_rule_order_produce_equal_profiles() {
        let rules_a = vec![
            domain_rule("r-1", "example.com"),
            ip_rule("r-2", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        ];
        let rules_b = vec![
            ip_rule("r-2", IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            domain_rule("r-1", "example.com"),
        ];

        let profile_a = validate_and_canonicalize(&config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            rules_a,
            vec![],
        ))
        .profile()
        .cloned()
        .expect("profile a");

        let profile_b = validate_and_canonicalize(&config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            rules_b,
            vec![],
        ))
        .profile()
        .cloned()
        .expect("profile b");

        assert_eq!(profile_a.rule_book, profile_b.rule_book);
    }

    #[test]
    fn domain_case_variants_produce_equal_canonical_rules() {
        let config_upper = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![domain_rule("r-1", "EXAMPLE.COM")],
            vec![],
        );
        let config_lower = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![domain_rule("r-1", "example.com")],
            vec![],
        );

        let book_upper = validate_and_canonicalize(&config_upper)
            .profile()
            .cloned()
            .expect("upper profile")
            .rule_book;
        let book_lower = validate_and_canonicalize(&config_lower)
            .profile()
            .cloned()
            .expect("lower profile")
            .rule_book;

        assert_eq!(book_upper, book_lower);
    }

    #[test]
    fn comment_is_trimmed_in_canonical_rule() {
        let mut rule = domain_rule("r-1", "example.com");
        rule.comment = "  my comment  ".to_string();

        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![rule],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        let profile = outcome.profile().expect("profile");
        let canonical_rule = &profile.rule_book.primary.rules()[0];
        assert_eq!(canonical_rule.comment, "my comment");
    }

    #[test]
    fn multiple_errors_all_collected() {
        // Two rules with empty match conditions — both errors must be reported.
        let r1 = Rule {
            id: RuleId("r-1".to_string()),
            enabled: true,
            address_match: None,
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let r2 = Rule {
            id: RuleId("r-2".to_string()),
            enabled: true,
            address_match: None,
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        };
        let config = config_with_rules(
            Some(primary()),
            None,
            RouteBehaviorMode::PreferPrimary,
            vec![r1, r2],
            vec![],
        );
        let outcome = validate_and_canonicalize(&config);
        assert!(!outcome.is_accepted());
        assert_eq!(
            outcome
                .errors()
                .iter()
                .filter(|e| matches!(e, ValidationError::RuleEmptyMatch { .. }))
                .count(),
            2
        );
    }
}

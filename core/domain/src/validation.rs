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
use std::net::IpAddr;

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

    /// An `ExactIp` rule contains a CIDR notation address (`192.168.1.0/24`).
    /// CIDR subnet matching is not supported.
    CidrNotSupported { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains an IP range (`10.0.0.1-10.0.0.100`).
    /// Range matching is not supported.
    IpRangeNotSupported { rule_id: RuleId, value: String },

    /// An `ExactIp` rule contains a string that cannot be parsed as any IP
    /// address. The rule cannot be applied and must be corrected.
    InvalidIpAddress { rule_id: RuleId, value: String },

    /// A domain/zone rule's value is not a hostname: spaces, control bytes, a
    /// path, an interior glob. Nothing it could ever match exists, so the rule
    /// is refused rather than stored as a name no packet will carry.
    DomainInvalidValue { rule_id: RuleId, value: String },

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
            | Self::CidrNotSupported { rule_id, .. }
            | Self::IpRangeNotSupported { rule_id, .. }
            | Self::InvalidIpAddress { rule_id, .. }
            | Self::DomainInvalidValue { rule_id, .. }
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
            Self::DomainInvalidValue { rule_id, value } => {
                write!(f, "rule {rule_id}: '{value}' is not a host name")
            }
            Self::CidrNotSupported { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: CIDR notation '{value}' is not supported"
                )
            }
            Self::IpRangeNotSupported { rule_id, value } => {
                write!(f, "rule {rule_id}: IP range '{value}' is not supported")
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
            // the rule diff.
            //
            // `.ru` is the spelling a user naturally writes for a TLD, and it
            // folds to the same rule as `ru` everywhere else — the wire
            // comparison key (`nrr_shared::rules_json::fold_suffix`) strips the
            // dot, and the GUI's own validator rejects it outright. Only this
            // canonicalizer used to keep it, and `match_zone` looks for
            // `.{zone}`, so a dotted zone searched for `..ru` and matched
            // nothing: the rule was accepted and silently inert.
            let body = stripped.strip_prefix('.').unwrap_or(stripped);
            if body.is_empty() {
                errors.push(ValidationError::ZoneEmptyName {
                    rule_id: rule.id.clone(),
                });
                return None;
            }
            let normalized = match normalize_domain_label(body, &rule.id, warnings) {
                Ok(canonical) => canonical,
                Err(e) => {
                    errors.push(e);
                    return None;
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
        Some(AddressMatch::ExactIp(addr)) => Some(CanonicalAddressMatch::ExactIp(
            canonicalize_ip_addr(*addr, &rule.id, warnings),
        )),
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

    // If purely ASCII, no further IDNA processing is needed — but it still has
    // to BE a hostname. Nothing checked that in the production pipeline, so
    // `hello world`, a path, a control byte or `192.168.1.0/24` from the IP
    // section became a live `ExactFqdn` and travelled into storage and codegen,
    // where it could never match anything.
    if lowercased.is_ascii() {
        reject_if_not_a_hostname(&lowercased, rule_id)?;
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
            reject_if_not_a_hostname(&ascii, rule_id)?;
            Ok(ascii)
        }
        Err(_) => Err(ValidationError::DomainInvalidIdn {
            rule_id: rule_id.clone(),
            value: without_dot.to_string(),
        }),
    }
}

/// Refuses a domain value that is not a hostname, naming WHAT it is when the
/// shape is recognisable.
///
/// The three IP-shaped answers exist because the `--- IP` section passes an
/// unparseable value through as a domain "so the semantic validator can produce
/// a proper diagnostic" — and it never did: `192.168.1.0/24`,
/// `10.0.0.1-10.0.0.9` and `not-an-ip` were all accepted as domain names,
/// silently, with zero errors and zero warnings. Their variants existed and
/// were constructed nowhere in the repository.
fn reject_if_not_a_hostname(value: &str, rule_id: &RuleId) -> Result<(), ValidationError> {
    // Address-shaped FIRST, because a hostname check would pass some of these:
    // `10.0.0.1-10.0.0.9` is made of legal hostname characters, and calling it
    // a valid name is how a range ended up stored as one. A value with no
    // letter at all is not a name — no top-level domain is all digits.
    if !value.is_empty() && !value.chars().any(|c| c.is_ascii_alphabetic()) {
        if let Some((head, _)) = value.split_once('/') {
            if head.parse::<std::net::IpAddr>().is_ok() {
                return Err(ValidationError::CidrNotSupported {
                    rule_id: rule_id.clone(),
                    value: value.to_string(),
                });
            }
        }
        if let Some((from, to)) = value.split_once('-') {
            if from.parse::<std::net::IpAddr>().is_ok() && to.parse::<std::net::IpAddr>().is_ok() {
                return Err(ValidationError::IpRangeNotSupported {
                    rule_id: rule_id.clone(),
                    value: value.to_string(),
                });
            }
        }
        // A well-formed address in a DOMAIN rule is not a mistyped name — it is
        // a value in the wrong section, and it would never match a host name.
        if value.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(ValidationError::DomainInvalidValue {
                rule_id: rule_id.clone(),
                value: value.to_string(),
            });
        }
        return Err(ValidationError::InvalidIpAddress {
            rule_id: rule_id.clone(),
            value: value.to_string(),
        });
    }
    if value.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(ValidationError::DomainInvalidValue {
            rule_id: rule_id.clone(),
            value: value.to_string(),
        });
    }
    if crate::rule_value_validation::is_valid_hostname(value) {
        return Ok(());
    }
    Err(ValidationError::DomainInvalidValue {
        rule_id: rule_id.clone(),
        value: value.to_string(),
    })
}

/// The canonical form of a rule's address, warning when it was written as an
/// IPv4-mapped IPv6 address.
fn canonicalize_ip_addr(
    addr: IpAddr,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> IpAddr {
    let canonical = crate::address_class::canonical_ip(addr);
    if canonical != addr {
        warnings.push(ValidationWarning::Ipv4MappedIpv6Normalized {
            rule_id: rule_id.clone(),
            original: addr.to_string(),
            normalized: canonical.to_string(),
        });
    }
    canonical
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
            let (process_name, changes) = crate::app_identity::canonical_exact_process_name(raw);
            if let Some(original) = changes.stripped_path_from {
                warnings.push(ValidationWarning::ProcessNameContainedPath {
                    rule_id: rule_id.clone(),
                    original,
                    normalized: process_name.clone(),
                });
            }
            if let Some(original) = changes.appended_exe_to {
                warnings.push(ValidationWarning::ProcessNameMissingExeSuffix {
                    rule_id: rule_id.clone(),
                    original,
                    normalized: process_name.clone(),
                });
            }
            CanonicalAppPattern::Exact(process_name)
        }
        AppMatchPattern::Glob(raw) => {
            let lowercased = crate::app_identity::canonical_glob_process_pattern(raw);
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
/// Two rules are duplicates when they match the same traffic AND say the same
/// thing about it — `id` and `comment` are metadata and stay out.
///
/// `action` and `enabled` are part of the identity because they are what the
/// rule DOES: `example.com` next to `example.com +block` are opposite
/// instructions, and folding them left whichever came first while the other
/// vanished behind a "duplicate removed" note. The same went for a disabled
/// copy above an enabled one — the set kept the disabled line.
#[derive(PartialEq, Eq, Hash)]
struct MatchKey {
    address: Option<CanonicalAddressMatch>,
    app_pattern: Option<CanonicalAppPattern>,
    app_children: Option<bool>,
    action: crate::canonical::RuleAction,
    enabled: bool,
}

impl MatchKey {
    fn from_rule(rule: &CanonicalRule) -> Self {
        Self {
            address: rule.address_match.clone(),
            app_pattern: rule.app_match.as_ref().map(|a| a.pattern.clone()),
            app_children: rule.app_match.as_ref().map(|a| a.include_child_processes),
            action: rule.action,
            enabled: rule.enabled,
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

/// One rule named in both route sets, with both copies enabled.
///
/// Both copies name the same traffic and each sends it to a different route, so
/// which one wins is decided by evaluation order rather than by the user. The
/// pair is reported, never resolved here: the domain cannot know which route
/// the user meant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossSetDuplicate {
    /// Content identity of the pair — what a caller echoes back to say which
    /// copy it wants kept. The two ids cannot serve: they are per-book and are
    /// re-derived whenever the file is parsed again.
    pub identity_key: String,
    pub primary_rule_id: RuleId,
    pub secondary_rule_id: RuleId,
    /// What the two copies match, as the user wrote it — the only part of the
    /// pair a person can recognise on screen.
    pub match_summary: String,
}

/// Rules present and ENABLED in both route sets.
///
/// Enabled on both sides is the whole condition: a disabled copy is exactly the
/// state the user is offered as the resolution, so reporting it again would ask
/// the same question forever.
pub fn enabled_duplicates_across_sets(book: &CanonicalRuleBook) -> Vec<CrossSetDuplicate> {
    let primary: Vec<&CanonicalRule> = book
        .primary
        .rules()
        .iter()
        .filter(|rule| rule.enabled)
        .collect();
    if primary.is_empty() {
        return Vec::new();
    }
    let by_match: std::collections::HashMap<MatchKey, &CanonicalRule> = primary
        .iter()
        .map(|rule| (MatchKey::from_rule(rule), *rule))
        .collect();

    let mut found = Vec::new();
    for secondary in book.secondary.rules().iter().filter(|rule| rule.enabled) {
        if let Some(primary) = by_match.get(&MatchKey::from_rule(secondary)) {
            found.push(CrossSetDuplicate {
                identity_key: crate::review::rule_identity_key(secondary),
                primary_rule_id: primary.id.clone(),
                secondary_rule_id: secondary.id.clone(),
                match_summary: describe_match(secondary),
            });
        }
    }
    found.sort_by(|a, b| {
        a.match_summary
            .cmp(&b.match_summary)
            .then_with(|| a.primary_rule_id.as_str().cmp(b.primary_rule_id.as_str()))
    });
    found
}

/// What a rule matches, spelled for a person. Falls back to the rule id when a
/// rule carries neither an address nor an app filter — it cannot be described,
/// but it can still be named.
///
/// Public because the merge reports the same fact about the same pair, and two
/// spellings of one rule on two screens is how a user stops believing either.
pub fn describe_match(rule: &CanonicalRule) -> String {
    match (&rule.address_match, &rule.app_match) {
        (Some(address), Some(app)) => {
            format!("{} + {}", address.to_display_string(), app.pattern.as_str())
        }
        (Some(address), None) => address.to_display_string(),
        (None, Some(app)) => app.pattern.as_str().to_string(),
        (None, None) => rule.id.as_str().to_string(),
    }
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
mod tests;

#[cfg(test)]
mod value_gate_tests;

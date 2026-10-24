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

use nrr_shared::RouteRole;

use crate::{
    address_class::AddressClass,
    canonical::{
        CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalProfile,
        CanonicalRule, CanonicalRuleBook, CanonicalRuleSet, RuleAction,
    },
    ip_network_policy,
    rules_file::{HostPlatform, RulesFileSection},
    ActiveConfiguration, AddressMatch, AppMatch, AppMatchPattern, Rule, RuleId,
};
use nrr_shared::app_identity::ExecutableNaming;
use nrr_shared::ip_block::{IpBlock, IpRange};
use nrr_shared::preset_parser::ParsedRuleType;

use crate::address_class::canonical_ip;

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

    /// A value whose spelling is another rule type's, written under this
    /// one's heading: a subnet in `--- IP`, `chrome.exe` in `--- Domains`, an
    /// address in `--- Windows`. Section is type, so the value is never
    /// re-filed; `belongs_in` names the right one.
    WrongSection {
        rule_id: RuleId,
        value: String,
        belongs_in: RulesFileSection,
    },

    /// A `Subnet` rule value that is not a network (`a.b.c.d/len`).
    InvalidSubnet { rule_id: RuleId, value: String },

    /// An `IpRange` rule value that is not a range of one family in order.
    InvalidIpRange { rule_id: RuleId, value: String },

    /// A network or range wider than
    /// [`crate::ip_network_policy::widest_rule_prefix`].
    NetworkTooWide {
        rule_id: RuleId,
        value: String,
        widest_prefix: u8,
    },

    /// A network or range touching loopback, multicast, broadcast or "this
    /// host": routing it would break the machine, not reach a site.
    NetworkCoversReserved {
        rule_id: RuleId,
        value: String,
        class: AddressClass,
    },

    /// An `ExactIp` rule contains a string that cannot be parsed as any IP
    /// address. The rule cannot be applied and must be corrected.
    InvalidIpAddress { rule_id: RuleId, value: String },

    /// An address that is never a destination: "this host" (`0.0.0.0/8`,
    /// `::`) or the limited broadcast. A rule on it would cut or reroute DHCP
    /// and discovery, never a site.
    IpAddressNotADestination {
        rule_id: RuleId,
        value: String,
        class: AddressClass,
    },

    /// A domain/zone rule's value is not a hostname: spaces, control bytes, a
    /// path, an interior glob, more than 253 octets once punycoded. Nothing it
    /// could ever match exists, so the rule is refused rather than stored as a
    /// name no packet will carry.
    DomainInvalidValue { rule_id: RuleId, value: String },

    /// A `Zone` rule has an empty name after trimming.
    ZoneEmptyName { rule_id: RuleId },

    /// An application glob pattern that matches every running process: bare
    /// `*`, or one the matcher reduces to it (`C:\Games\*`, `*.exe`).
    AppGlobTooWide { rule_id: RuleId },

    /// An application value the rules file cannot hold: longer than a match
    /// value may be, or carrying a line break or other control character.
    AppNameInvalid { rule_id: RuleId, value: String },

    /// An application value written as a path that names no program: a `*`
    /// not standing last, a relative path, or a broken one.
    AppPathInvalid {
        rule_id: RuleId,
        value: String,
        problem: nrr_shared::app_path::AppPathError,
    },

    /// More rules than a book may hold — see [`rule_cap_excess`].
    TooManyRules { count: usize, limit: usize },
}

/// Which allowance a rule book overran, and by how much.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleCapExcess {
    /// More of the user's own rules than
    /// [`nrr_shared::rules_json::FREE_MAX_RULES`].
    User { count: usize, limit: usize },
    /// More app-authored rules than
    /// [`crate::auto_rule_budget::MAX_AUTO_RULES`].
    Auto { count: usize, limit: usize },
}

impl RuleCapExcess {
    #[must_use]
    pub const fn count_and_limit(self) -> (usize, usize) {
        match self {
            Self::User { count, limit } | Self::Auto { count, limit } => (count, limit),
        }
    }
}

/// The one rule count behind every write-side cap. `user_authored` holds one
/// flag per rule; the user's own and the app's rules are capped separately,
/// so neither can spend the other's allowance.
///
/// The user's cap is absolute. `auto_limit` is `None` where the book the
/// rules land in is unknown — a file on its own: its app-authored count is
/// only meaningful against that book, which the service's write checks with
/// [`crate::auto_rule_budget::auto_rule_allowance`].
pub fn rule_cap_excess(
    user_authored: impl IntoIterator<Item = bool>,
    auto_limit: Option<usize>,
) -> Option<RuleCapExcess> {
    const USER_LIMIT: usize = nrr_shared::rules_json::FREE_MAX_RULES;
    let (mut user, mut auto) = (0usize, 0usize);
    for own in user_authored {
        if own {
            user += 1;
        } else {
            auto += 1;
        }
    }
    if user > USER_LIMIT {
        Some(RuleCapExcess::User {
            count: user,
            limit: USER_LIMIT,
        })
    } else {
        auto_limit
            .filter(|&limit| auto > limit)
            .map(|limit| RuleCapExcess::Auto { count: auto, limit })
    }
}

impl ValidationError {
    /// The rule ID associated with this error, if applicable.
    pub fn rule_id(&self) -> Option<&RuleId> {
        match self {
            Self::MissingPrimaryBinding
            | Self::SameAdapterBoundToBothRoles { .. }
            | Self::TooManyRules { .. } => None,
            Self::RuleEmptyMatch { rule_id }
            | Self::DomainEmptyValue { rule_id }
            | Self::DomainInvalidIdn { rule_id, .. }
            | Self::WrongSection { rule_id, .. }
            | Self::InvalidSubnet { rule_id, .. }
            | Self::InvalidIpRange { rule_id, .. }
            | Self::NetworkTooWide { rule_id, .. }
            | Self::NetworkCoversReserved { rule_id, .. }
            | Self::InvalidIpAddress { rule_id, .. }
            | Self::IpAddressNotADestination { rule_id, .. }
            | Self::DomainInvalidValue { rule_id, .. }
            | Self::ZoneEmptyName { rule_id }
            | Self::AppGlobTooWide { rule_id }
            | Self::AppNameInvalid { rule_id, .. }
            | Self::AppPathInvalid { rule_id, .. } => Some(rule_id),
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
            Self::WrongSection {
                rule_id,
                value,
                belongs_in,
            } => {
                write!(
                    f,
                    "rule {rule_id}: '{value}' belongs in the --- {belongs_in} section"
                )
            }
            Self::InvalidSubnet { rule_id, value } => {
                write!(f, "rule {rule_id}: '{value}' is not a network")
            }
            Self::InvalidIpRange { rule_id, value } => {
                write!(f, "rule {rule_id}: '{value}' is not an address range")
            }
            Self::NetworkTooWide {
                rule_id,
                value,
                widest_prefix,
            } => {
                write!(
                    f,
                    "rule {rule_id}: '{value}' is wider than a /{widest_prefix} network"
                )
            }
            Self::NetworkCoversReserved {
                rule_id,
                value,
                class,
            } => {
                write!(f, "rule {rule_id}: '{value}' covers {class:?} addresses")
            }
            Self::InvalidIpAddress { rule_id, value } => {
                write!(f, "rule {rule_id}: '{value}' is not a valid IP address")
            }
            Self::IpAddressNotADestination {
                rule_id,
                value,
                class,
            } => {
                write!(
                    f,
                    "rule {rule_id}: '{value}' ({class:?}) is never a destination"
                )
            }
            Self::ZoneEmptyName { rule_id } => {
                write!(f, "rule {rule_id}: zone name is empty")
            }
            Self::AppGlobTooWide { rule_id } => {
                write!(
                    f,
                    "rule {rule_id}: this glob pattern matches every process \
                     and is not allowed — use a more specific pattern"
                )
            }
            Self::TooManyRules { count, limit } => {
                write!(f, "{count} rules exceed the limit of {limit}")
            }
            Self::AppNameInvalid { rule_id, value } => {
                write!(f, "rule {rule_id}: {value:?} is not an application name")
            }
            Self::AppPathInvalid {
                rule_id,
                value,
                problem,
            } => {
                write!(f, "rule {rule_id}: {value:?} names no program ({problem})")
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

    /// A Windows process name was missing its `.exe` suffix, which was
    /// appended. Never raised for Linux or macOS names, which carry none.
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

    /// An address rule on a loopback, multicast or link-local address: kept,
    /// but it never names a site on the internet.
    UnusualIpDestination {
        rule_id: RuleId,
        address: IpAddr,
        class: AddressClass,
    },

    /// A subnet written with host bits set (`10.0.2.7/24`) names its network
    /// (`10.0.2.0/24`); the rule keeps the network.
    SubnetHostBitsCleared {
        rule_id: RuleId,
        original: String,
        normalized: String,
    },

    /// A network or range wider than Fail-Closed holds
    /// ([`crate::ip_network_policy::fail_closed_widest_prefix`], carried as
    /// `widest_prefix`): it is routed, but not blocked while the tunnel is down.
    /// `public` when part of it lies outside private address space — a wide
    /// public network is rarely meant.
    WideNetwork {
        rule_id: RuleId,
        value: String,
        public: bool,
        widest_prefix: u8,
    },

    /// A stored rule on an address that is never a destination
    /// ([`ValidationError::IpAddressNotADestination`]) was dropped on read;
    /// the rest of the rules load.
    RuleOnNoDestinationDropped { rule_id: RuleId, value: String },

    /// A rule whose application pattern the pipeline refuses outright
    /// ([`ValidationError::AppNameInvalid`], [`ValidationError::AppGlobTooWide`])
    /// was dropped instead of blocking the rest of the file — the same policy
    /// as an address that is never a destination.
    AppPatternRefusedDropped { rule_id: RuleId, value: String },

    /// A "check where it works" rule (`?value`) on a rule kind it means
    /// nothing for — only domain and exact IPv4 rules are checked (the check
    /// reaches a destination over IPv4 only). It was kept as a plain route
    /// rule of its own set.
    VerifyIgnored { rule_id: RuleId, role: RouteRole },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::UnusualIpDestination {
                rule_id,
                address,
                class,
            } => {
                write!(f, "rule {rule_id}: {address} is a {class:?} address")
            }
            Self::SubnetHostBitsCleared {
                rule_id,
                original,
                normalized,
            } => {
                write!(
                    f,
                    "rule {rule_id}: subnet '{original}' names the network '{normalized}'"
                )
            }
            Self::WideNetwork {
                rule_id,
                value,
                public,
                ..
            } => {
                let scope = if *public { "public " } else { "" };
                write!(
                    f,
                    "rule {rule_id}: {scope}network '{value}' is wider than Fail-Closed holds"
                )
            }
            Self::RuleOnNoDestinationDropped { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: '{value}' is never a destination; the rule was dropped"
                )
            }
            Self::AppPatternRefusedDropped { rule_id, value } => {
                write!(
                    f,
                    "rule {rule_id}: application value '{value}' is refused; the rule was dropped"
                )
            }
            Self::VerifyIgnored { rule_id, role } => {
                write!(
                    f,
                    "rule {rule_id}: '?' applies to a domain or exact IPv4 address rule only; kept as a plain {role:?} rule"
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
///    c. Normalize `app_match` (a path, or a name: lowercase, `.exe` on Windows).
/// 3. Deduplicate within each rule set; detect cross-set duplicates.
/// 4. Build [`CanonicalProfile`] with [`CanonicalRuleSet`]s in canonical order.
/// 5. Check for behavior-mode / binding incompatibilities (warnings only).
///
/// # Return value
///
/// Returns [`ValidationOutcome::Rejected`] if any blocking error is found.
/// Returns [`ValidationOutcome::AcceptedWithWarnings`] if warnings accumulated.
/// Returns [`ValidationOutcome::Accepted`] only when the profile is fully clean.
///
/// `platform` is the platform whose application section the rules came from:
/// it alone decides how an application name is spelled.
pub fn validate_and_canonicalize(
    config: &ActiveConfiguration,
    platform: HostPlatform,
) -> ValidationOutcome {
    let mut errors: Vec<ValidationError> = Vec::new();
    let mut warnings: Vec<ValidationWarning> = Vec::new();

    // Counted before anything is normalized: an oversized file costs a count,
    // not a canonicalization, a diff and an enforcement set.
    let book = &config.rule_book;
    if let Some(excess) = rule_cap_excess(
        book.primary
            .rules
            .iter()
            .chain(book.secondary.rules.iter())
            .map(|rule| rule.origin.is_none()),
        None,
    ) {
        let (count, limit) = excess.count_and_limit();
        errors.push(ValidationError::TooManyRules { count, limit });
        return ValidationOutcome::Rejected { errors, warnings };
    }

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
        platform,
        &mut errors,
        &mut warnings,
    );
    let secondary_rules = normalize_rule_set(
        &config.rule_book.secondary.rules,
        RouteRole::Secondary,
        platform,
        &mut errors,
        &mut warnings,
    );

    // ── 3. Deduplication ─────────────────────────────────────────────────────

    let primary_rules = deduplicate_set(primary_rules, RouteRole::Primary, &mut warnings);
    let secondary_rules = deduplicate_set(secondary_rules, RouteRole::Secondary, &mut warnings);

    detect_cross_set_duplicates(&primary_rules, &secondary_rules, &mut warnings);

    // ── 4. Build outcome ──────────────────────────────────────────────────────

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
            Some(AddressMatch::ExactFqdn(v))
            | Some(AddressMatch::SuffixDomain(v))
            | Some(AddressMatch::AnyZoneDomain(v)) => {
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
    role: RouteRole,
    platform: HostPlatform,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) -> Vec<CanonicalRule> {
    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        if let Some(mut canonical) = normalize_rule(rule, platform, errors, warnings) {
            if settle_verify(&mut canonical) {
                warnings.push(ValidationWarning::VerifyIgnored {
                    rule_id: canonical.id.clone(),
                    role,
                });
            }
            out.push(canonical);
        }
    }
    out
}

/// Turns a `?` that means nothing where it stands into a plain route rule of
/// its own set; `true` when it did. The rules file and the wire both go
/// through here, so one rule has one meaning whichever way it arrives.
pub(crate) fn settle_verify(rule: &mut CanonicalRule) -> bool {
    if rule.action == RuleAction::Verify && !verify_applies(rule) {
        rule.action = RuleAction::Route;
        return true;
    }
    false
}

/// "Does it open on this link" is asked of one destination a connection can
/// name: a host name or one IPv4 address, in either set. The probe leaves from
/// an IPv4 source only, so an IPv6 literal could never be checked: it is a
/// plain route, with the warning, rather than a `?` that silently does nothing.
fn verify_applies(rule: &CanonicalRule) -> bool {
    matches!(
        rule.address_match,
        Some(
            CanonicalAddressMatch::ExactFqdn(_)
                | CanonicalAddressMatch::SuffixDomain(_)
                | CanonicalAddressMatch::ExactIp(std::net::IpAddr::V4(_))
        )
    )
}

/// Normalizes a single rule. Returns `None` when a blocking error was found and
/// the rule should be excluded from the canonical output.
fn normalize_rule(
    rule: &Rule,
    platform: HostPlatform,
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
    if let Some(misplaced) = misplaced_in_rule(rule, platform) {
        errors.push(misplaced);
        return None;
    }

    // Normalize address_match.
    let address_match = match &rule.address_match {
        None => None,
        Some(AddressMatch::Zone(name)) => {
            match canonical_host_name(HostNameKind::Zone, name, &rule.id, warnings) {
                Ok(normalized) => Some(CanonicalAddressMatch::Zone(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::ExactFqdn(value)) => {
            match canonical_host_name(HostNameKind::Domain, value, &rule.id, warnings) {
                Ok(normalized) => Some(CanonicalAddressMatch::ExactFqdn(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::SuffixDomain(value)) => {
            match canonical_host_name(HostNameKind::Domain, value, &rule.id, warnings) {
                Ok(normalized) => Some(suffix_or_zone(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::AnyZoneDomain(base)) => {
            match canonical_host_name(HostNameKind::Domain, base, &rule.id, warnings) {
                Ok(normalized) => Some(CanonicalAddressMatch::AnyZoneDomain(normalized)),
                Err(e) => {
                    errors.push(e);
                    return None;
                }
            }
        }
        Some(AddressMatch::Subnet(text)) => match canonical_subnet(text, &rule.id, warnings) {
            Ok(block) => Some(CanonicalAddressMatch::Subnet(block)),
            Err(ValidationError::NetworkCoversReserved { rule_id, value, .. }) => {
                warnings.push(ValidationWarning::RuleOnNoDestinationDropped { rule_id, value });
                return None;
            }
            Err(e) => {
                errors.push(e);
                return None;
            }
        },
        Some(AddressMatch::IpRange(text)) => match canonical_ip_range(text, &rule.id, warnings) {
            Ok(range) => Some(CanonicalAddressMatch::ip_range(range)),
            Err(ValidationError::NetworkCoversReserved { rule_id, value, .. }) => {
                warnings.push(ValidationWarning::RuleOnNoDestinationDropped { rule_id, value });
                return None;
            }
            Err(e) => {
                errors.push(e);
                return None;
            }
        },
        Some(AddressMatch::ExactIp(text)) => match canonical_ip_address(text, &rule.id, warnings) {
            Ok(addr) => Some(CanonicalAddressMatch::ExactIp(addr)),
            // A rules file is stored data: such a rule is dropped, the rest
            // of the file still imports.
            Err(ValidationError::IpAddressNotADestination { rule_id, value, .. }) => {
                warnings.push(ValidationWarning::RuleOnNoDestinationDropped { rule_id, value });
                return None;
            }
            Err(e) => {
                errors.push(e);
                return None;
            }
        },
    };

    // Normalize app_match.
    let app_match = match rule.app_match.as_ref() {
        None => None,
        Some(a) => match normalize_app_match(a, platform, &rule.id, warnings) {
            Ok(canonical) => Some(canonical),
            // A rules file is stored data: a value the pipeline refuses
            // outright is dropped, the rest of the file still imports — same
            // policy as an address that is never a destination.
            Err(ValidationError::AppNameInvalid { rule_id, .. })
            | Err(ValidationError::AppPathInvalid { rule_id, .. })
            | Err(ValidationError::AppGlobTooWide { rule_id }) => {
                warnings.push(ValidationWarning::AppPatternRefusedDropped {
                    rule_id,
                    value: a.pattern.as_str().to_string(),
                });
                return None;
            }
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

/// A value of `rule` its spelling places in another section than the one it
/// was read from, each value as the file spells it.
fn misplaced_in_rule(rule: &Rule, platform: HostPlatform) -> Option<ValidationError> {
    let address = rule.address_match.as_ref().map(|m| {
        let section = match m {
            AddressMatch::Zone(_) => ParsedRuleType::Zone,
            AddressMatch::ExactFqdn(_)
            | AddressMatch::SuffixDomain(_)
            | AddressMatch::AnyZoneDomain(_) => ParsedRuleType::Domain,
            AddressMatch::ExactIp(_) => ParsedRuleType::ExactIp,
            AddressMatch::Subnet(_) => ParsedRuleType::Subnet,
            AddressMatch::IpRange(_) => ParsedRuleType::IpRange,
        };
        (section, m.to_display_string())
    });
    let app = rule.app_match.as_ref().map(|a| {
        let raw = match &a.pattern {
            AppMatchPattern::Exact(raw) | AppMatchPattern::Glob(raw) => raw.clone(),
        };
        (ParsedRuleType::Application, raw)
    });
    address
        .into_iter()
        .chain(app)
        .find_map(|(section, value)| misplaced_value(section, &value, &rule.id, platform))
}

/// Which host-name rule a value is written for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostNameKind {
    /// `ru`, `.ru`, `*.ru` and `ru.` — spellings of one zone.
    Zone,
    /// An exact host, or what follows the `*.` of a suffix rule.
    Domain,
}

/// The canonical spelling of a zone or domain rule value, or the error the
/// rule pipeline refuses it with.
///
/// The one answer to "is this a zone / a domain": the import pipeline, the
/// wire decoder and the GUI's per-row verdict all read it, so a value the GUI
/// shows as valid is exactly one the service keeps as a live rule.
pub(crate) fn canonical_host_name(
    kind: HostNameKind,
    value: &str,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<String, ValidationError> {
    match kind {
        HostNameKind::Domain => normalize_domain_label(value, rule_id, warnings),
        HostNameKind::Zone => {
            // `.ru` is how a user naturally writes a TLD. Kept, `match_zone`
            // would look for `..ru` and the rule would be accepted and inert.
            let trimmed = value.trim();
            let stripped = trimmed.strip_prefix("*.").unwrap_or(trimmed);
            let body = stripped.strip_prefix('.').unwrap_or(stripped);
            if body.is_empty() {
                return Err(ValidationError::ZoneEmptyName {
                    rule_id: rule_id.clone(),
                });
            }
            // Same IDNA path as a domain: hostnames are punycode at decision
            // time, so a Unicode zone would never match.
            normalize_domain_label(body, rule_id, warnings)
        }
    }
}

/// Normalizes a domain label value (the content of `ExactFqdn` or
/// `SuffixDomain`, and the label part of `Zone`):
/// - Removes trailing dot.
/// - Rejects empty values.
/// - Lowercases an ASCII value.
/// - Applies UTS-46 to a non-ASCII value (case mapping and Unicode → punycode).
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

    // If purely ASCII, no further IDNA processing is needed — but it still has
    // to BE a hostname. Nothing checked that in the production pipeline, so
    // `hello world`, a path, a control byte or `192.168.1.0/24` from the IP
    // section became a live `ExactFqdn` and travelled into storage and codegen,
    // where it could never match anything.
    if without_dot.is_ascii() {
        let lowercased = without_dot.to_ascii_lowercase();
        reject_if_not_a_hostname(&lowercased, rule_id)?;
        return Ok(lowercased);
    }

    // Non-ASCII: UTS-46 maps the case itself, as browsers do. Lowercasing first
    // made `ẞ` a kept `ß` and a final `Σ` a `ς`: another ACE than the browser asks.
    match idna::domain_to_ascii(without_dot) {
        Ok(ascii) => {
            if ascii != without_dot {
                warnings.push(ValidationWarning::DomainNormalizedToAscii {
                    rule_id: rule_id.clone(),
                    original: without_dot.to_string(),
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
fn reject_if_not_a_hostname(value: &str, rule_id: &RuleId) -> Result<(), ValidationError> {
    // Address-shaped FIRST: `10.0.0.1-10.0.0.9` is made of legal hostname
    // characters. No top-level domain is all digits, and an IPv6 literal is
    // not a name either; the address check says what such a value is.
    if !value.chars().any(|c| c.is_ascii_alphabetic())
        || value.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return Err(
            match canonical_ip_address(value, rule_id, &mut Vec::new()) {
                // A well-formed address would never match a host name.
                Ok(_) | Err(ValidationError::IpAddressNotADestination { .. }) => {
                    ValidationError::WrongSection {
                        rule_id: rule_id.clone(),
                        value: value.to_string(),
                        belongs_in: RulesFileSection::Ip,
                    }
                }
                Err(refusal) => refusal,
            },
        );
    }
    // Length on the ASCII form: the matcher drops a longer host as malformed,
    // so a rule naming one would be accepted and never match.
    if value.len() <= crate::rule_value_validation::MAX_HOSTNAME_OCTETS
        && crate::rule_value_validation::is_valid_hostname(value)
    {
        return Ok(());
    }
    Err(ValidationError::DomainInvalidValue {
        rule_id: rule_id.clone(),
        value: value.to_string(),
    })
}

/// The address an exact-IP rule value names, or the error the rule pipeline
/// refuses it with. The one answer to "is this an address rule": the import
/// pipeline, the per-row verdict, the wire decoder and the service's acceptance
/// of a revision all read it. An IPv4-mapped IPv6 address becomes the IPv4
/// one; its class decides the rest: "this host" and the limited broadcast are
/// refused, loopback, multicast and link-local kept with a warning.
pub(crate) fn canonical_ip_address(
    value: &str,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<IpAddr, ValidationError> {
    let value = value.trim();
    let Ok(addr) = value.parse::<IpAddr>() else {
        return Err(address_refusal(value, rule_id));
    };
    let canonical = crate::address_class::canonical_ip(addr);
    let class = crate::address_class::classify(canonical);
    match class {
        AddressClass::Unspecified | AddressClass::ThisNetwork | AddressClass::Broadcast => {
            return Err(ValidationError::IpAddressNotADestination {
                rule_id: rule_id.clone(),
                value: value.to_string(),
                class,
            });
        }
        AddressClass::Loopback | AddressClass::Multicast | AddressClass::LinkLocal => {
            warnings.push(ValidationWarning::UnusualIpDestination {
                rule_id: rule_id.clone(),
                address: canonical,
                class,
            });
        }
        AddressClass::Routable => {}
    }
    if canonical != addr {
        warnings.push(ValidationWarning::Ipv4MappedIpv6Normalized {
            rule_id: rule_id.clone(),
            original: addr.to_string(),
            normalized: canonical.to_string(),
        });
    }
    Ok(canonical)
}

/// A suffix rule's canonical form: a whole top-level domain is a zone however
/// it was written, so a literal address inside it beats it, as with `.ru`.
/// The rules file and the wire decoder both read it, so `*.ru` is one rule
/// with one hash whichever way it came in.
pub(crate) fn suffix_or_zone(normalized: String) -> CanonicalAddressMatch {
    if normalized.is_empty() || normalized.contains('.') {
        CanonicalAddressMatch::SuffixDomain(normalized)
    } else {
        CanonicalAddressMatch::Zone(normalized)
    }
}

/// Names what an unparseable address value is, when its shape says so.
fn address_refusal(value: &str, rule_id: &RuleId) -> ValidationError {
    wrong_section(value, rule_id, ParsedRuleType::ExactIp).unwrap_or_else(|| {
        ValidationError::InvalidIpAddress {
            rule_id: rule_id.clone(),
            value: value.to_string(),
        }
    })
}

/// The section a value of another type belongs in, when it is written under
/// an address `section`'s heading.
fn wrong_section(
    value: &str,
    rule_id: &RuleId,
    section: ParsedRuleType,
) -> Option<ValidationError> {
    // An address section holds the same values on every platform: the naming
    // passed only decides what an application section holds, so any will do.
    misplaced_value(section, value, rule_id, HostPlatform::Windows)
}

/// The refusal of a value whose spelling is another rule type's than
/// `section`, written in `platform`'s file; `None` when `section` holds it.
/// The one place a section's type is held to the value: the rules file, the
/// Add dialog's verdict and the service's acceptance of a revision come here.
pub(crate) fn misplaced_value(
    section: ParsedRuleType,
    value: &str,
    rule_id: &RuleId,
    platform: HostPlatform,
) -> Option<ValidationError> {
    nrr_shared::rule_value_class::misplaced_rule_value(section, value, platform.executable_naming())
        .map(|kind| ValidationError::WrongSection {
            rule_id: rule_id.clone(),
            value: value.trim().to_string(),
            belongs_in: section_of(kind, value),
        })
}

/// The section a `kind` rule spelled `value` is written in. Only an
/// application section is a platform's, and a value misplaced into one comes
/// from a section that names none, so its spelling decides, never the host.
fn section_of(kind: ParsedRuleType, value: &str) -> RulesFileSection {
    match kind {
        ParsedRuleType::Zone => RulesFileSection::Zones,
        ParsedRuleType::Domain => RulesFileSection::Domains,
        ParsedRuleType::ExactIp => RulesFileSection::Ip,
        ParsedRuleType::Subnet => RulesFileSection::Cidr,
        ParsedRuleType::IpRange => RulesFileSection::Ranges,
        ParsedRuleType::Application => app_section_spelled_by(value),
    }
}

/// The application section a program value is spelled for: a POSIX path is
/// Linux's, anything else (`.exe`, a drive or a backslash, a bare pattern)
/// the Windows section, the product's first platform.
fn app_section_spelled_by(value: &str) -> RulesFileSection {
    let v = value.trim();
    let exe = v
        .len()
        .checked_sub(4)
        .and_then(|start| v.get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(".exe"));
    let drive = matches!(v.as_bytes(), [letter, b':', ..] if letter.is_ascii_alphabetic());
    let windows = exe || drive || v.contains('\\');
    let posix_path = ["/", "./", "../", "~/"].iter().any(|p| v.starts_with(p));
    if posix_path && !windows {
        RulesFileSection::Linux
    } else {
        RulesFileSection::Windows
    }
}

/// The canonical network of a `--- CIDR` value, or the error the rule
/// pipeline refuses it with.
pub(crate) fn canonical_subnet(
    value: &str,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<IpBlock, ValidationError> {
    let value = value.trim();
    let Some(written) = IpBlock::parse(value) else {
        return Err(
            wrong_section(value, rule_id, ParsedRuleType::Subnet).unwrap_or_else(|| {
                ValidationError::InvalidSubnet {
                    rule_id: rule_id.clone(),
                    value: value.to_string(),
                }
            }),
        );
    };
    let block = ip_network_policy::canonical_block(written);
    if block.network() != written.network() {
        warnings.push(ValidationWarning::Ipv4MappedIpv6Normalized {
            rule_id: rule_id.clone(),
            original: value.to_string(),
            normalized: block.to_string(),
        });
    } else if value
        .split_once('/')
        .and_then(|(a, _)| a.trim().parse::<IpAddr>().ok())
        != Some(block.network())
    {
        warnings.push(ValidationWarning::SubnetHostBitsCleared {
            rule_id: rule_id.clone(),
            original: value.to_string(),
            normalized: block.to_string(),
        });
    }
    check_networks(value, std::slice::from_ref(&block), rule_id, warnings)?;
    Ok(block)
}

/// The canonical range of a `--- Ranges` value, or the error the rule
/// pipeline refuses it with.
pub(crate) fn canonical_ip_range(
    value: &str,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<IpRange, ValidationError> {
    let value = value.trim();
    let parsed = value.split_once('-').and_then(|(first, last)| {
        let first = canonical_ip(first.trim().parse().ok()?);
        let last = canonical_ip(last.trim().parse().ok()?);
        IpRange::new(first, last)
    });
    let Some(range) = parsed else {
        return Err(
            wrong_section(value, rule_id, ParsedRuleType::IpRange).unwrap_or_else(|| {
                ValidationError::InvalidIpRange {
                    rule_id: rule_id.clone(),
                    value: value.to_string(),
                }
            }),
        );
    };
    let widest = ip_network_policy::prefix_of_width(range.is_ipv4(), range.width_bits());
    let allowed = ip_network_policy::widest_rule_prefix(range.is_ipv4());
    if widest < u32::from(allowed) {
        return Err(ValidationError::NetworkTooWide {
            rule_id: rule_id.clone(),
            value: value.to_string(),
            widest_prefix: allowed,
        });
    }
    check_networks(value, range.blocks(), rule_id, warnings)?;
    Ok(range)
}

/// The width and class limits every rule network shares.
fn check_networks(
    value: &str,
    blocks: &[IpBlock],
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<(), ValidationError> {
    if let Some(wide) = blocks
        .iter()
        .find(|b| ip_network_policy::wider_than_rule_allows(**b))
    {
        return Err(ValidationError::NetworkTooWide {
            rule_id: rule_id.clone(),
            value: value.to_string(),
            widest_prefix: ip_network_policy::widest_rule_prefix(wide.network().is_ipv4()),
        });
    }
    if let Some(class) = blocks
        .iter()
        .find_map(|b| ip_network_policy::reserved_overlap(*b))
    {
        return Err(ValidationError::NetworkCoversReserved {
            rule_id: rule_id.clone(),
            value: value.to_string(),
            class,
        });
    }
    if let Some(link_local) = blocks
        .iter()
        .find(|b| ip_network_policy::touches_link_local(**b))
    {
        warnings.push(ValidationWarning::UnusualIpDestination {
            rule_id: rule_id.clone(),
            address: link_local.network(),
            class: AddressClass::LinkLocal,
        });
    }
    if let Some(wide) = blocks
        .iter()
        .find(|b| ip_network_policy::wider_than_fail_closed(**b))
    {
        warnings.push(ValidationWarning::WideNetwork {
            rule_id: rule_id.clone(),
            value: value.to_string(),
            public: !blocks.iter().all(|b| ip_network_policy::is_private(*b)),
            widest_prefix: ip_network_policy::fail_closed_widest_prefix(wide.network().is_ipv4()),
        });
    }
    Ok(())
}

/// Normalizes an [`AppMatch`] as `platform` spells it: see
/// [`canonical_app_pattern`].
fn normalize_app_match(
    app: &AppMatch,
    platform: HostPlatform,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<CanonicalAppMatch, ValidationError> {
    let (raw, glob) = match &app.pattern {
        AppMatchPattern::Exact(raw) => (raw.as_str(), false),
        AppMatchPattern::Glob(raw) => (raw.as_str(), true),
    };
    Ok(CanonicalAppMatch {
        pattern: canonical_app_pattern(raw, glob, platform, rule_id, warnings)?,
        include_child_processes: app.include_child_processes,
        override_requested: app.override_requested,
    })
}

/// The canonical pattern of an application rule value as `platform` spells
/// it, or the error the rule pipeline refuses it with. The one answer to "is
/// this an application rule": the import pipeline, the per-row verdict and
/// the service's acceptance of a revision all read it.
///
/// A value with a path separator is a path ([`nrr_shared::app_path::AppPath`]);
/// any other is a name, or a mask over names when `glob` (it holds a `*`).
pub(crate) fn canonical_app_pattern(
    raw: &str,
    glob: bool,
    platform: HostPlatform,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<CanonicalAppPattern, ValidationError> {
    let style = platform.path_style();
    if nrr_shared::app_path::is_path_value(raw, style) {
        refuse_unholdable_app_value(raw, rule_id, nrr_shared::app_path::MAX_PATH_VALUE_BYTES)?;
        return nrr_shared::app_path::AppPath::parse(raw, style)
            .map(|path| CanonicalAppPattern::Path(Box::new(path)))
            .map_err(|problem| ValidationError::AppPathInvalid {
                rule_id: rule_id.clone(),
                value: raw.to_string(),
                problem,
            });
    }
    canonical_name_pattern(raw, glob, platform.executable_naming(), rule_id, warnings)
}

/// A value no application rule can hold: longer than `limit` bytes, a
/// character the file cannot carry, or a deny mark left inside it.
fn refuse_unholdable_app_value(
    raw: &str,
    rule_id: &RuleId,
    limit: usize,
) -> Result<(), ValidationError> {
    // A deny mark left in the value (`! app.exe`, `app.exe +block`) names no
    // process; a name may hold a space, so nothing else would refuse it and
    // the deny would land as a route.
    let trimmed = raw.trim();
    let misplaced_deny = nrr_shared::preset_parser::carries_retired_block_flag(trimmed)
        || trimmed
            .strip_prefix(nrr_shared::preset_parser::VERIFY_PRIMARY_PREFIX)
            .unwrap_or(trimmed)
            .starts_with(nrr_shared::preset_parser::DENY_PREFIX);
    if raw.len() > limit
        || nrr_shared::preset_parser::first_forbidden_field_char(raw).is_some()
        || misplaced_deny
    {
        return Err(ValidationError::AppNameInvalid {
            rule_id: rule_id.clone(),
            value: raw.to_string(),
        });
    }
    Ok(())
}

/// The canonical name or name mask of `raw`, any directory in it dropped:
/// how a wire `exact` or `glob` pattern reads, which a path never is.
///
/// - exact: lowercased, `.exe` appended where `naming` spells programs so;
/// - glob: lowercased only, the user owns the whole pattern; one that reduces
///   to a bare `*` is refused as too broad.
pub(crate) fn canonical_name_pattern(
    raw: &str,
    glob: bool,
    naming: ExecutableNaming,
    rule_id: &RuleId,
    warnings: &mut Vec<ValidationWarning>,
) -> Result<CanonicalAppPattern, ValidationError> {
    refuse_unholdable_app_value(raw, rule_id, crate::preset_validation::MAX_MATCH_VALUE_LEN)?;
    if glob {
        let lowercased = crate::app_identity::canonical_glob_process_pattern(raw);
        // Judged by the key the matcher compares, not the text: `C:\Games\*`,
        // `/opt/*` and `*.exe` all reduce to `*` there and name every process.
        let key = crate::app_identity::app_match_key(&lowercased);
        if !key.is_empty() && key.bytes().all(|b| b == b'*') {
            return Err(ValidationError::AppGlobTooWide {
                rule_id: rule_id.clone(),
            });
        }
        return Ok(CanonicalAppPattern::Glob(lowercased));
    }
    let (process_name, changes) = crate::app_identity::canonical_exact_process_name(raw, naming);
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
    Ok(CanonicalAppPattern::Exact(process_name))
}

// ── Deduplication ─────────────────────────────────────────────────────────────

/// The match identity key used to detect duplicate rules.
///
/// Two rules are duplicates when they match the same traffic AND say the same
/// thing about it — `id` and `comment` are metadata and stay out.
///
/// `action` and `enabled` are part of the identity because they are what the
/// rule DOES: `example.com` next to `!example.com` are opposite
/// instructions, and folding them left whichever came first while the other
/// vanished behind a "duplicate removed" note. The same went for a disabled
/// copy above an enabled one — the set kept the disabled line.
///
/// The merge and the review diff pair rules by this same key, so "these two
/// rows are one rule" means one thing on every screen.
#[derive(PartialEq, Eq, Hash)]
pub(crate) struct MatchKey {
    address: Option<CanonicalAddressMatch>,
    app_pattern: Option<CanonicalAppPattern>,
    app_children: Option<bool>,
    action: RuleAction,
    enabled: bool,
}

impl MatchKey {
    pub(crate) fn from_rule(rule: &CanonicalRule) -> Self {
        Self {
            address: rule.address_match.clone(),
            app_pattern: rule.app_match.as_ref().map(|a| a.pattern.clone()),
            app_children: rule.app_match.as_ref().map(|a| a.include_child_processes),
            action: rule.action,
            enabled: rule.enabled,
        }
    }

    /// The key within ONE set. `?x` there is `x` with a check in front of it,
    /// so the two are one rule and [`deduplicate_set`] keeps the plain one;
    /// across sets they stay two instructions, which [`Self::from_rule`] keeps
    /// apart.
    fn within_set(rule: &CanonicalRule) -> Self {
        let mut key = Self::from_rule(rule);
        if key.action == RuleAction::Verify {
            key.action = RuleAction::Route;
        }
        key
    }

    /// The key a rule is compared under against the OTHER set: a range that
    /// is exactly one network is that network, so `10.0.0.0/24` on one route
    /// and `10.0.0.0-10.0.0.255` on the other are the same tie the matcher
    /// breaks by itself.
    fn across_sets(rule: &CanonicalRule) -> Self {
        let mut key = Self::from_rule(rule);
        if let Some(CanonicalAddressMatch::IpRange(range)) = &key.address {
            if let [block] = range.blocks() {
                key.address = Some(CanonicalAddressMatch::Subnet(*block));
            }
        }
        key
    }
}

/// Removes duplicate rules within a single route rule set.
///
/// When two rules share identical match conditions, the first one encountered
/// is kept — except that a plain rule beats its `?` twin wherever either
/// stands: the user already confirmed the route, and line order must not
/// decide which link the traffic takes. A
/// [`ValidationWarning::DuplicateRuleInSameSet`] names the kept and the
/// removed rule.
fn deduplicate_set(
    rules: Vec<CanonicalRule>,
    role: RouteRole,
    warnings: &mut Vec<ValidationWarning>,
) -> Vec<CanonicalRule> {
    let mut seen: std::collections::HashMap<MatchKey, usize> = std::collections::HashMap::new();
    let mut out: Vec<CanonicalRule> = Vec::with_capacity(rules.len());

    for rule in rules {
        let key = MatchKey::within_set(&rule);
        match seen.get(&key) {
            Some(&slot) => {
                let kept = &mut out[slot];
                let removed =
                    if kept.action == RuleAction::Verify && rule.action != RuleAction::Verify {
                        std::mem::replace(kept, rule)
                    } else {
                        rule
                    };
                warnings.push(ValidationWarning::DuplicateRuleInSameSet {
                    kept_rule_id: out[slot].id.clone(),
                    removed_rule_id: removed.id,
                    role,
                });
            }
            None => {
                seen.insert(key, out.len());
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
/// The networks both routes name as the same addresses, both routing them, as
/// the secondary rule spells them. Which link such a network takes would be a
/// tie, and the product refuses a tie rather than settling it quietly. A range
/// that is exactly one subnet is that subnet; a block is not a route, and an
/// equal route network loses to it.
#[must_use]
pub fn networks_on_both_routes(book: &CanonicalRuleBook) -> Vec<String> {
    let routed_network = |rule: &&CanonicalRule| {
        rule.enabled
            && rule.action == crate::canonical::RuleAction::Route
            && rule
                .address_match
                .as_ref()
                .is_some_and(|m| m.ip_blocks().is_some())
    };
    // By piece: a range names its decomposition, so one piece equal to the
    // other route's subnet is the same tie as two equal subnets.
    let pieces =
        |rule: &CanonicalRule| -> Vec<(Option<CanonicalAppPattern>, Option<bool>, IpBlock)> {
            let blocks = rule
                .address_match
                .as_ref()
                .and_then(CanonicalAddressMatch::ip_blocks)
                .unwrap_or_default();
            blocks
                .iter()
                .map(|b| {
                    (
                        rule.app_match.as_ref().map(|a| a.pattern.clone()),
                        rule.app_match.as_ref().map(|a| a.include_child_processes),
                        *b,
                    )
                })
                .collect()
        };
    let primary: std::collections::HashSet<_> = book
        .primary
        .rules()
        .iter()
        .filter(routed_network)
        .flat_map(&pieces)
        .collect();
    book.secondary
        .rules()
        .iter()
        .filter(routed_network)
        .filter(|rule| pieces(rule).iter().any(|p| primary.contains(p)))
        .filter_map(|rule| rule.address_match.as_ref())
        .map(CanonicalAddressMatch::to_display_string)
        .collect()
}

/// The folders both routes name in the same form ("this folder only" or
/// "with subfolders"), both routing them, as the secondary rule spells them:
/// the same tie as one network on both routes, refused the same way. A folder
/// in another form is a narrower or wider rule, which the order settles.
#[must_use]
pub fn folders_on_both_routes(book: &CanonicalRuleBook) -> Vec<String> {
    use nrr_shared::app_path::{AppPath, AppPathKind};
    fn routed_folder(rule: &CanonicalRule) -> Option<&AppPath> {
        if !rule.enabled || rule.action != RuleAction::Route || rule.address_match.is_some() {
            return None;
        }
        let path = rule.app_match.as_ref()?.pattern.path()?;
        matches!(path.kind(), AppPathKind::Folder | AppPathKind::FolderTree).then_some(path)
    }
    let primary: std::collections::HashSet<&AppPath> = book
        .primary
        .rules()
        .iter()
        .filter_map(routed_folder)
        .collect();
    book.secondary
        .rules()
        .iter()
        .filter_map(routed_folder)
        .filter(|path| primary.contains(path))
        .map(|path| path.as_str().to_string())
        .collect()
}

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
        .map(|rule| (MatchKey::across_sets(rule), *rule))
        .collect();

    let mut found = Vec::new();
    for secondary in book.secondary.rules().iter().filter(|rule| rule.enabled) {
        if let Some(primary) = by_match.get(&MatchKey::across_sets(secondary)) {
            found.push(CrossSetDuplicate {
                identity_key: crate::review::rule_identity_key(secondary),
                primary_rule_id: primary.id.clone(),
                secondary_rule_id: secondary.id.clone(),
                match_summary: describe_pair(primary, secondary),
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

/// What a cross-set pair matches. Two spellings of one network are both shown:
/// the user looks for each in its own list.
fn describe_pair(primary: &CanonicalRule, secondary: &CanonicalRule) -> String {
    let (p, s) = (describe_match(primary), describe_match(secondary));
    if p == s {
        s
    } else {
        format!("{p} = {s}")
    }
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
        .map(|r| (MatchKey::across_sets(r), &r.id))
        .collect();

    for sec_rule in secondary {
        let key = MatchKey::across_sets(sec_rule);
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

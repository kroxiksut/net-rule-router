//! Baseline model for future extension channels.
//!
//! An *extension channel* is any path through which external software (a plugin,
//! a REST API client, a named-pipe automation peer) can request policy changes.
//! Extension channels are distinct from the normal GUI interactive flow and from
//! file imports.
//!
//! # Invariants (non-negotiable policy)
//!
//! These constraints are enforced by [`validate_extension_request`] and documented
//! as constants in [`ExtensionChannelPolicy`]:
//!
//! 1. **Non-interactive channels always require review.** A non-interactive
//!    extension request (automated, no user present) must produce a
//!    `PendingRevision` — it may never activate policy silently.
//!
//! 2. **Mass changes always require review.** Any request that changes more than
//!    [`ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES`] rules is treated
//!    as high-risk regardless of interactivity, and must go through the review
//!    flow.
//!
//! 3. **Default behavior mode changes always require review.** No extension
//!    channel may change `behavior_mode` through a narrow immediate-apply path.
//!
//! 4. **Adapter binding changes always require review.** Changing which adapter
//!    is bound to a route role is high-risk and always goes through review.
//!
//! 5. **All extension channels are service-mediated.** No extension may write
//!    policy state directly — all requests pass through the service's validation,
//!    canonicalization, and risk-scoring pipeline.
//!
//! # Review requirement
//!
//! [`validate_extension_request`] returns a [`ReviewRequirement`] for every
//! request. The service must honour this: if review is required, the request
//! creates a `PendingRevision`; it cannot be immediately activated.
//!
//! # Provenance
//!
//! [`ExtensionProvenance`] is attached to every revision created via an extension
//! channel. It appears in review summaries, audit events, and security-visible
//! status so the user can always trace the origin of a policy change.
//!
//! # Real extension channel implementation
//!
//! This module defines the type boundary and invariants only. Real channel
//! registration, authentication, and the IPC transport (a browser extension
//! API contract) land when the product opens that surface. Until then the
//! channel exists only as a domain-level type carrier so audit/review paths
//! can reason about provenance without crashing on absent data.

use core::fmt;

use crate::revision::UnixTimestamp;

// ── ExtensionChannelId ────────────────────────────────────────────────────────

/// Stable identifier for a registered extension channel.
/// Format: `"ext-{non-empty-suffix}"`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionChannelId(String);

impl ExtensionChannelId {
    const PREFIX: &'static str = "ext-";

    /// Constructs an `ExtensionChannelId` from a prefixed string.
    ///
    /// Returns `Err` if the string does not start with `"ext-"` or the
    /// suffix is empty.
    pub fn from_prefixed_string(s: String) -> Result<Self, &'static str> {
        let suffix = s
            .strip_prefix(Self::PREFIX)
            .ok_or("extension channel id must start with \"ext-\"")?;
        if suffix.is_empty() {
            return Err("extension channel id suffix must not be empty");
        }
        Ok(Self(s))
    }

    /// Returns the full identifier string including prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExtensionChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── ExtensionChannelKind ──────────────────────────────────────────────────────

/// The transport mechanism of a registered extension channel.
///
/// All variants are reserved for the future extension-API surface. In the
/// scaffold phase no extension channels are implemented; this enum exists to
/// define the type boundary so audit and provenance APIs accept the future
/// shapes without breaking changes when that surface lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtensionChannelKind {
    /// A Windows Named Pipe endpoint exposed by the service.
    /// The primary IPC transport.
    NamedPipe,
    /// A local loopback REST API endpoint. Reserved for future use.
    RestApi,
    /// A dynamically loaded plugin (DLL/shared library). Reserved for Pro edition.
    Plugin,
}

impl ExtensionChannelKind {
    /// Returns a stable slug for logging and audit events.
    pub const fn slug(self) -> &'static str {
        match self {
            Self::NamedPipe => "named-pipe",
            Self::RestApi => "rest-api",
            Self::Plugin => "plugin",
        }
    }
}

// ── ExtensionInteractivity ────────────────────────────────────────────────────

/// Whether an extension request was initiated by a user who is present and
/// waiting for a response, or by an automated process with no user present.
///
/// Interactivity determines whether the narrow immediate-apply path is available.
/// Non-interactive requests **always** produce a `PendingRevision` and require
/// user review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtensionInteractivity {
    /// A user explicitly initiated the request through an extension UI. The
    /// narrow immediate-apply path may be available for small, low-risk changes.
    Interactive,
    /// No user is present. The request comes from an automated process or
    /// background scheduler. Review is always required.
    NonInteractive,
}

// ── ExtensionRequestScope ─────────────────────────────────────────────────────

/// The declared scope of an extension request — what kinds of changes it claims
/// to make.
///
/// Extension channels must declare their intended scope upfront. The service
/// validates the actual changes against this declaration after parsing and
/// canonicalization. A mismatch between declared and actual scope is treated as
/// an integrity anomaly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionRequestScope {
    /// The request may add new rules to an existing rule set.
    pub allows_rule_additions: bool,
    /// The request may remove existing rules from an existing rule set.
    pub allows_rule_removals: bool,
    /// The request may modify (but not add or remove) existing rules.
    pub allows_rule_modifications: bool,
    /// The request may change the default routing behavior mode.
    ///
    /// This flag **never** enables immediate activation — behavior mode changes
    /// always require review regardless of interactivity or change count.
    pub allows_behavior_mode_change: bool,
    /// The request may change adapter role bindings.
    ///
    /// This flag **never** enables immediate activation — binding changes always
    /// require review regardless of interactivity or change count.
    pub allows_binding_change: bool,
    /// Maximum number of rule-level changes (additions + removals + modifications)
    /// the extension is permitted to make in a single request.
    ///
    /// `None` means the channel does not self-limit. The service will still apply
    /// [`ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES`] for interactive
    /// requests and treat any excess as requiring mandatory review.
    pub max_rule_changes: Option<u32>,
}

// ── ExtensionProvenance ───────────────────────────────────────────────────────

/// Provenance record attached to every revision created via an extension channel.
///
/// Included in review summaries, audit events, and security-visible status so
/// the user can trace the origin of any extension-sourced policy change.
/// The service stores this alongside the `PolicyRevision`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionProvenance {
    /// Stable identifier of the extension channel that submitted the request.
    pub channel_id: ExtensionChannelId,
    /// Transport kind of the channel.
    pub channel_kind: ExtensionChannelKind,
    /// Whether a user was present when the request was submitted.
    pub interactivity: ExtensionInteractivity,
    /// The scope the extension declared for this request.
    pub declared_scope: ExtensionRequestScope,
    /// UTC timestamp when the request was received by the service.
    pub requested_at: UnixTimestamp,
}

impl ExtensionProvenance {
    /// Returns a human-readable summary of this provenance for display in the
    /// review UI and audit trail.
    ///
    /// Format: `"{kind-slug} extension ({interactivity})"`.
    pub fn display_summary(&self) -> String {
        let interactive = match self.interactivity {
            ExtensionInteractivity::Interactive => "interactive",
            ExtensionInteractivity::NonInteractive => "non-interactive",
        };
        format!("{} extension ({})", self.channel_kind.slug(), interactive)
    }
}

// ── ExtensionScopeViolation ───────────────────────────────────────────────────

/// Why an extension request exceeds its permitted scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionScopeViolation {
    /// The request includes a behavior mode change, which always requires review
    /// and must not be in the immediate-apply path.
    BehaviorModeChangeRequiresReview,
    /// The request includes a binding change, which always requires review.
    BindingChangeRequiresReview,
    /// The number of rule changes exceeds the allowed limit for an interactive
    /// immediate-apply request.
    TooManyRuleChangesForImmediateApply {
        /// Number of rule changes in this request.
        requested: u32,
        /// The maximum allowed for immediate-apply interactive path.
        max_allowed: u32,
    },
    /// The channel is non-interactive and therefore cannot use the immediate-apply
    /// path under any circumstances.
    NonInteractiveCannotBypassReview,
}

// ── ReviewRequirement ─────────────────────────────────────────────────────────

/// Whether an extension request requires the `PendingRevision` review flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewRequirement {
    /// The request is within the narrow allowed scope for immediate application.
    /// The service may activate the resulting revision without queuing it for
    /// user review.
    ///
    /// Conditions: interactive, ≤ `MAX_INTERACTIVE_RULE_CHANGES` rule changes,
    /// no behavior mode change, no binding change.
    ImmediateApplyPermitted,
    /// The request must go through the `PendingRevision` review flow before
    /// activation. The `violations` list explains why.
    ReviewRequired {
        /// One or more policy constraints that require the review flow.
        violations: Vec<ExtensionScopeViolation>,
    },
}

impl ReviewRequirement {
    /// Returns `true` when the request requires user review before activation.
    pub fn is_review_required(&self) -> bool {
        matches!(self, Self::ReviewRequired { .. })
    }
}

// ── ExtensionChannelPolicy ────────────────────────────────────────────────────

/// Non-negotiable policy constants for extension channels.
///
/// These constants are referenced by [`validate_extension_request`] and must not
/// be overridden by any channel configuration. They encode the security invariants
/// listed in the module-level documentation.
pub struct ExtensionChannelPolicy;

impl ExtensionChannelPolicy {
    /// Non-interactive channels always require review. No exceptions.
    pub const NONINTERACTIVE_ALWAYS_REQUIRES_REVIEW: bool = true;

    /// Behavior mode changes always require review, regardless of interactivity
    /// or change count.
    pub const BEHAVIOR_MODE_CHANGE_ALWAYS_REQUIRES_REVIEW: bool = true;

    /// Adapter binding changes always require review, regardless of interactivity
    /// or change count.
    pub const BINDING_CHANGE_ALWAYS_REQUIRES_REVIEW: bool = true;

    /// The maximum number of rule-level changes permitted in a single interactive
    /// request on the narrow immediate-apply path.
    ///
    /// Requests exceeding this threshold require the review flow even when
    /// submitted interactively.
    pub const MAX_INTERACTIVE_RULE_CHANGES: u32 = 5;

    /// Extension channels must go through the service. No extension may write
    /// policy state directly to storage.
    pub const MUST_BE_SERVICE_MEDIATED: bool = true;
}

// ── validate_extension_request ────────────────────────────────────────────────

/// Pure function: determines whether an extension request requires the review
/// flow or may use the narrow immediate-apply path.
///
/// # Parameters
///
/// - `interactivity`: whether a user is present.
/// - `scope`: what the request declares it will change.
/// - `actual_rule_change_count`: the number of rule-level changes after parsing
///   and canonicalization. The service supplies this after comparing the candidate
///   with the current active revision.
///
/// # Returns
///
/// [`ReviewRequirement::ImmediateApplyPermitted`] only when all of the following
/// hold:
/// - `interactivity` is [`ExtensionInteractivity::Interactive`]
/// - `scope.allows_behavior_mode_change` is `false`
/// - `scope.allows_binding_change` is `false`
/// - `actual_rule_change_count` ≤ [`ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES`]
///
/// In all other cases, [`ReviewRequirement::ReviewRequired`] is returned with the
/// list of violated constraints.
pub fn validate_extension_request(
    interactivity: ExtensionInteractivity,
    scope: &ExtensionRequestScope,
    actual_rule_change_count: u32,
) -> ReviewRequirement {
    let mut violations = Vec::new();

    if interactivity == ExtensionInteractivity::NonInteractive {
        violations.push(ExtensionScopeViolation::NonInteractiveCannotBypassReview);
    }

    if scope.allows_behavior_mode_change {
        violations.push(ExtensionScopeViolation::BehaviorModeChangeRequiresReview);
    }

    if scope.allows_binding_change {
        violations.push(ExtensionScopeViolation::BindingChangeRequiresReview);
    }

    if actual_rule_change_count > ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES {
        violations.push(
            ExtensionScopeViolation::TooManyRuleChangesForImmediateApply {
                requested: actual_rule_change_count,
                max_allowed: ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES,
            },
        );
    }

    if violations.is_empty() {
        ReviewRequirement::ImmediateApplyPermitted
    } else {
        ReviewRequirement::ReviewRequired { violations }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::revision::UnixTimestamp;

    fn ext_id(s: &str) -> ExtensionChannelId {
        ExtensionChannelId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    fn narrow_scope() -> ExtensionRequestScope {
        ExtensionRequestScope {
            allows_rule_additions: true,
            allows_rule_removals: false,
            allows_rule_modifications: false,
            allows_behavior_mode_change: false,
            allows_binding_change: false,
            max_rule_changes: Some(ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES),
        }
    }

    fn wide_scope() -> ExtensionRequestScope {
        ExtensionRequestScope {
            allows_rule_additions: true,
            allows_rule_removals: true,
            allows_rule_modifications: true,
            allows_behavior_mode_change: true,
            allows_binding_change: true,
            max_rule_changes: None,
        }
    }

    // ── ExtensionChannelId ────────────────────────────────────────────────────

    #[test]
    fn channel_id_accepts_valid_prefixed_string() {
        let id = ExtensionChannelId::from_prefixed_string("ext-plugin-abc".to_string());
        assert!(id.is_ok());
        assert_eq!(id.expect("ok").as_str(), "ext-plugin-abc");
    }

    #[test]
    fn channel_id_rejects_missing_prefix() {
        assert!(ExtensionChannelId::from_prefixed_string("plugin-abc".to_string()).is_err());
    }

    #[test]
    fn channel_id_rejects_prefix_only() {
        assert!(ExtensionChannelId::from_prefixed_string("ext-".to_string()).is_err());
    }

    #[test]
    fn channel_id_display_matches_full_string() {
        let id = ext_id("ext-named-pipe-001");
        assert_eq!(id.to_string(), "ext-named-pipe-001");
    }

    // ── ExtensionChannelKind slugs ────────────────────────────────────────────

    #[test]
    fn channel_kind_slugs_are_stable() {
        assert_eq!(ExtensionChannelKind::NamedPipe.slug(), "named-pipe");
        assert_eq!(ExtensionChannelKind::RestApi.slug(), "rest-api");
        assert_eq!(ExtensionChannelKind::Plugin.slug(), "plugin");
    }

    // ── ExtensionProvenance display ───────────────────────────────────────────

    #[test]
    fn provenance_display_summary_includes_kind_and_interactivity() {
        let prov = ExtensionProvenance {
            channel_id: ext_id("ext-test-001"),
            channel_kind: ExtensionChannelKind::NamedPipe,
            interactivity: ExtensionInteractivity::NonInteractive,
            declared_scope: narrow_scope(),
            requested_at: UnixTimestamp::from_secs(1_700_000_000),
        };
        let summary = prov.display_summary();
        assert!(summary.contains("named-pipe"));
        assert!(summary.contains("non-interactive"));
    }

    // ── validate_extension_request — non-interactive ──────────────────────────

    #[test]
    fn non_interactive_always_requires_review() {
        let result =
            validate_extension_request(ExtensionInteractivity::NonInteractive, &narrow_scope(), 1);
        assert!(result.is_review_required());
        match result {
            ReviewRequirement::ReviewRequired { violations } => {
                assert!(
                    violations.contains(&ExtensionScopeViolation::NonInteractiveCannotBypassReview)
                );
            }
            _ => panic!("expected ReviewRequired"),
        }
    }

    #[test]
    fn non_interactive_with_zero_changes_still_requires_review() {
        let result =
            validate_extension_request(ExtensionInteractivity::NonInteractive, &narrow_scope(), 0);
        assert!(result.is_review_required());
    }

    // ── validate_extension_request — behavior mode / binding changes ──────────

    #[test]
    fn behavior_mode_change_requires_review_even_when_interactive() {
        let mut scope = narrow_scope();
        scope.allows_behavior_mode_change = true;
        let result = validate_extension_request(ExtensionInteractivity::Interactive, &scope, 1);
        assert!(result.is_review_required());
        match result {
            ReviewRequirement::ReviewRequired { violations } => {
                assert!(
                    violations.contains(&ExtensionScopeViolation::BehaviorModeChangeRequiresReview)
                );
            }
            _ => panic!("expected ReviewRequired"),
        }
    }

    #[test]
    fn binding_change_requires_review_even_when_interactive() {
        let mut scope = narrow_scope();
        scope.allows_binding_change = true;
        let result = validate_extension_request(ExtensionInteractivity::Interactive, &scope, 1);
        assert!(result.is_review_required());
        match result {
            ReviewRequirement::ReviewRequired { violations } => {
                assert!(violations.contains(&ExtensionScopeViolation::BindingChangeRequiresReview));
            }
            _ => panic!("expected ReviewRequired"),
        }
    }

    // ── validate_extension_request — mass change threshold ───────────────────

    #[test]
    fn mass_change_requires_review_even_when_interactive() {
        let count = ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES + 1;
        let result =
            validate_extension_request(ExtensionInteractivity::Interactive, &narrow_scope(), count);
        assert!(result.is_review_required());
        match result {
            ReviewRequirement::ReviewRequired { violations } => {
                let found = violations.iter().any(|v| {
                    matches!(
                        v,
                        ExtensionScopeViolation::TooManyRuleChangesForImmediateApply {
                            requested,
                            ..
                        } if *requested == count
                    )
                });
                assert!(found, "expected TooManyRuleChangesForImmediateApply");
            }
            _ => panic!("expected ReviewRequired"),
        }
    }

    #[test]
    fn exactly_at_threshold_is_permitted_when_interactive_and_narrow_scope() {
        let count = ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES;
        let result =
            validate_extension_request(ExtensionInteractivity::Interactive, &narrow_scope(), count);
        assert!(!result.is_review_required());
        assert_eq!(result, ReviewRequirement::ImmediateApplyPermitted);
    }

    // ── validate_extension_request — narrow interactive path ─────────────────

    #[test]
    fn small_interactive_rule_addition_permits_immediate_apply() {
        let result =
            validate_extension_request(ExtensionInteractivity::Interactive, &narrow_scope(), 2);
        assert_eq!(result, ReviewRequirement::ImmediateApplyPermitted);
    }

    #[test]
    fn zero_changes_interactive_permits_immediate_apply() {
        let result =
            validate_extension_request(ExtensionInteractivity::Interactive, &narrow_scope(), 0);
        assert_eq!(result, ReviewRequirement::ImmediateApplyPermitted);
    }

    // ── validate_extension_request — wide scope accumulates violations ────────

    #[test]
    fn wide_scope_with_mass_change_accumulates_multiple_violations() {
        let count = ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES + 5;
        let result =
            validate_extension_request(ExtensionInteractivity::Interactive, &wide_scope(), count);
        assert!(result.is_review_required());
        match result {
            ReviewRequirement::ReviewRequired { violations } => {
                assert!(violations.len() >= 2, "expected multiple violations");
                assert!(
                    violations.contains(&ExtensionScopeViolation::BehaviorModeChangeRequiresReview)
                );
                assert!(violations.contains(&ExtensionScopeViolation::BindingChangeRequiresReview));
            }
            _ => panic!("expected ReviewRequired"),
        }
    }

    // ── Policy constants ──────────────────────────────────────────────────────

    // The whole point of this test is to lock the constant policy invariants,
    // so asserting on constants is intentional here.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn policy_constants_encode_security_invariants() {
        assert!(ExtensionChannelPolicy::NONINTERACTIVE_ALWAYS_REQUIRES_REVIEW);
        assert!(ExtensionChannelPolicy::BEHAVIOR_MODE_CHANGE_ALWAYS_REQUIRES_REVIEW);
        assert!(ExtensionChannelPolicy::BINDING_CHANGE_ALWAYS_REQUIRES_REVIEW);
        assert!(ExtensionChannelPolicy::MUST_BE_SERVICE_MEDIATED);
        assert!(ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES > 0);
        assert!(ExtensionChannelPolicy::MAX_INTERACTIVE_RULE_CHANGES <= 10);
    }
}

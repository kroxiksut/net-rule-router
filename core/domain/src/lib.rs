#![forbid(unsafe_code)]
//! Core domain primitives for NetRuleRouter.
//!
//! This crate owns reusable policy and routing domain types that are independent
//! of platform specifics, GUI presentation, and service transport.
//!
//! # Data Ownership Boundary
//!
//! Types in this crate define **service-owned policy state** — the data that the
//! background service controls and is the authoritative source of truth for active
//! routing policy.
//!
//! **UI preferences** (theme, language, font, window state, etc.) are owned by the
//! UI runtime and live in `nrr-ui-support`. They are not part of this crate.
//!
//! **Preview fields** currently stored in `UiPreferences` for scaffold purposes
//! (adapter selections, role confirmations, behavior mode) will be migrated to
//! service-owned state once real service integration is complete.

pub mod alert;
pub mod auto_rule_budget;
pub mod block8_outputs;
// Block notices: folds a stream of blocked attempts into readable episodes and
// owns the mute rules, so every surface answers "show this?" the same way.
pub mod block_notice;
pub mod canonical;
pub mod change_event;
// Co-activity companion affinity: learns which hostnames accompany a rule host
// so the application can propose routing them the same way. Pure and lazy —
// see the module docs for the "never on the data path" contract.
pub mod companion_affinity;
pub mod decision_availability;
pub mod decision_engine;
pub mod decision_engine_input;
pub mod decision_explain;
pub mod decision_fail_policy;
pub mod decision_final_action;
pub mod decision_lookup;
pub mod decision_matching;
pub mod decision_normalization;
pub mod decision_pipeline;
pub mod decision_rules_matching;
// Pure cross-module scenario tests (no production items) — compiled only for
// test builds so its helpers/imports don't read as dead code in a lib build.
#[cfg(test)]
mod decision_scenarios;
pub mod enforcement_mode;
pub mod extension_channel;
pub mod import;
pub mod isp_block_pages;
pub mod linked_source;
pub mod merge;
pub mod mode_a_coverage;
pub mod preset_canonicalize;
pub mod preset_contract;
pub mod preset_ux;
pub mod preset_validation;
pub mod ptr_names;
pub mod review;
pub mod revision;
pub mod risk;
pub mod rule_specificity;
pub mod rule_value_validation;
pub mod rules_file;
pub mod rules_json_codec;
pub mod rules_revision;
pub mod shared_ip;
pub mod storage_policy;
// Block T (traffic counter) — pure accounting core: per-interface octet deltas
// bucketed by route role, with reset detection and prime-on-first-sight.
pub mod traffic_accountant;
pub mod user_principal;
pub mod validation;

use core::fmt;

// `RouteRole` and `BindingSource` are defined in `nrr-shared` so they can be
// shared between domain, IPC contracts, and DTO layers without duplication.
pub use canonical::RuleAction;
// Rule provenance is declared once in `nrr-shared` — the rules-file parser,
// the GUI preset parser, and the canonical wire DTO all read the same slugs,
// so a mirrored domain copy would only add a way for them to drift.
pub use nrr_shared::auto_rule::{AutoRuleReason, RuleOrigin};
pub use nrr_shared::{BindingSource, RouteBehaviorMode, RouteRole};

/// Stable identity reference for a network adapter.
///
/// `stable_id` is the primary persistence key used to restore adapter bindings
/// across restarts. It is derived from the adapter name with a fallback to an
/// `ifindex+mac` composite when the name alone is insufficient.
///
/// `display_name` is a human-readable hint for the UI and diagnostics only.
/// It must never be used as an identity key — it can change without changing
/// `stable_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterIdentity {
    /// Stable, persistence-safe adapter identifier.
    pub stable_id: String,
    /// Human-readable display name. Not an identity key.
    pub display_name: String,
}

/// Binding of a route role to a specific network adapter.
///
/// A `RouteBinding` represents the user's explicit assignment of a particular
/// adapter to a route role. The `source` field carries provenance for the
/// binding and determines whether it counts as a confirmed policy assignment.
///
/// Unconfirmed bindings (`BindingSource::HeuristicSuggestion`) must not be
/// treated as authoritative policy assignments.
///
/// # What is serialized as policy (source of truth)
/// - `role`, `adapter.stable_id`, `source`
///
/// # What is NOT serialized — derived/runtime status
/// - `RouteSelectionState` (current availability — observed at runtime)
/// - `advisory_confidence` (heuristic hint — derived, not policy)
/// - `connectivity_state`, `external_ip` (observed facts)
/// - `RouteSelectionState::FailClosedConflict` (computed at apply time)
///
/// See also: [`RouteRuntimeStatus`] for the full runtime/derived boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteBinding {
    /// The route role assigned by this binding.
    pub role: RouteRole,
    /// The adapter assigned to this role.
    pub adapter: AdapterIdentity,
    /// How this binding was established and whether it is user-confirmed.
    ///
    /// Call `source.is_user_confirmed()` to check whether this binding
    /// carries the authority of an explicit user decision.
    pub source: BindingSource,
}

/// Stable, unique identifier for a routing rule.
///
/// Generated as a prefixed UUID string — e.g. `"r-550e8400-e29b-41d4-a716-446655440000"`.
/// The `r-` prefix distinguishes rule IDs from other entity identifiers in logs
/// and exported preset files.
///
/// Used as the persistence key for a rule: stable across renames, reorders,
/// and comment edits.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuleId(pub String);

impl RuleId {
    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Address-based match condition for a routing rule.
///
/// # Priority tiers (runtime evaluation order, default)
///
/// 1. `ExactFqdn` — exact hostname match; highest priority.
/// 2. `SuffixDomain` — subdomain wildcard; fires after ExactFqdn tier fails.
/// 3. `Zone` and `ExactIp` — evaluated in user-configurable order (default:
///    `ExactIp` before `Zone`; setting: `zone_priority_over_ip`).
///
/// # Domain semantics
///
/// - `ExactFqdn(label)` matches **only** the exact hostname. Priority tier 1.
///   In the rules file: `example.com` (no `*.` prefix).
///
/// - `SuffixDomain(label)` matches `label` itself **and** any subdomain of it
///   at any depth. Priority tier 2.
///   In the rules file: `*.example.com` (stored without the `*.` prefix).
///   Display renders as `*.label`.
///   Apex coverage loses no expressiveness — an `ExactFqdn` rule
///   on the apex is tier 1 and still wins, so "subdomains here, apex elsewhere"
///   is written explicitly instead of arising silently.
///
/// Longest label wins within each tier (e.g. `mail.corp.example.com` beats
/// `corp.example.com` among ExactFqdn rules; ExactFqdn tier always precedes
/// SuffixDomain tier for the same hostname).
///
/// # Zone semantics
///
/// `Zone(name)` matches all traffic whose destination hostname ends with
/// `.{name}` — e.g. zone `intra` matches `server.corp.intra`. Zone applies
/// only when a hostname is available; IP-only traffic bypasses Zone in Free.
/// IP subnet zones are a Pro edition feature.
///
/// # ExactIp semantics
///
/// `ExactIp(addr)` matches only the exact IPv4 address. CIDR and IPv6 are
/// Pro edition features. `IpAddr::V6` inputs are rejected at normalization
/// time as Pro-only unsupported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressMatch {
    /// Matches the exact FQDN only (runtime priority tier 1 — highest).
    /// File syntax: `example.com`
    ExactFqdn(String),
    /// Matches the apex itself and any subdomain at any depth (runtime priority tier 2).
    /// File syntax: `*.example.com` — stored without the `*.` prefix.
    SuffixDomain(String),
    /// Matches all hosts in a TLD or internal domain zone (runtime priority tier 3).
    /// Zone name is the suffix label — e.g. `ru`, `com`, `intra`, `corp`.
    /// Runtime priority vs `ExactIp` is user-configurable (default: `ExactIp` wins).
    Zone(String),
    /// Matches one exact IPv4 address (runtime priority tier 3 by default; configurable vs Zone).
    /// No CIDR prefix matching — that is a Pro edition feature.
    ExactIp(std::net::IpAddr),
}

impl AddressMatch {
    /// Returns the address value as a user-facing string.
    ///
    /// `SuffixDomain` is rendered with the `*.` prefix restored.
    pub fn to_display_string(&self) -> String {
        match self {
            Self::ExactFqdn(label) => label.clone(),
            Self::SuffixDomain(label) => format!("*.{label}"),
            Self::Zone(name) => name.clone(),
            Self::ExactIp(addr) => addr.to_string(),
        }
    }
}

/// Application match pattern — exact name or glob.
///
/// `Glob` patterns use `*` to mean zero-or-more characters (any character
/// including `.`). A bare `*` as the entire pattern is rejected at validation
/// time as too broad.
///
/// Matching is case-insensitive on Windows; patterns are stored lowercase.
/// Only the process **filename** is matched, not the full path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AppMatchPattern {
    /// Exact process filename (e.g. `chrome.exe`).
    Exact(String),
    /// Glob pattern (e.g. `*vpn*.exe`, `nord*`).
    Glob(String),
}

impl AppMatchPattern {
    /// Returns the pattern string regardless of variant.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Exact(s) | Self::Glob(s) => s.as_str(),
        }
    }
}

/// Application-based match condition for a routing rule.
///
/// Matches traffic by process filename — either an exact name or a glob pattern.
///
/// # Subprocess tracking
///
/// When `include_child_processes` is `true`, direct child processes of the
/// matched executable inherit the same routing rule. Only immediate children
/// are tracked (not transitive).
///
/// # Windows Service name matching — future version
///
/// `windows_service_name` is reserved for future SCM-based matching by Windows
/// Service name. Always `None` in v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppMatch {
    /// Match pattern — exact filename or glob (see [`AppMatchPattern`]).
    pub pattern: AppMatchPattern,
    /// If `true`, direct child processes of the matched executable are also matched.
    pub include_child_processes: bool,
    /// Reserved — always `None` in v1.
    pub windows_service_name: Option<String>,
}

/// A single routing rule within a [`RouteRuleSet`].
///
/// # Route membership
///
/// `Rule` carries **no** `target_route` field. The route is determined by which
/// [`RouteRuleSet`] contains this rule (primary or secondary). When the user
/// adds a rule via the GUI, the application writes it to the correct rule set
/// based on the route selected in the Add Rule dialog.
///
/// # Match semantics
///
/// - Both `address_match` and `app_match` present: **both** must match
///   simultaneously (AND, not OR).
/// - Only `address_match`: matches any process sending traffic to that address.
/// - Only `app_match`: matches all traffic from that application, regardless
///   of destination.
/// - A valid rule must have at least one of the two fields set. Enforced at
///   validation time, not at the type level.
///
/// # Enabled flag
///
/// Disabled rules are skipped during route evaluation but retained in the rule
/// set for potential re-enabling. They are included in YAML preset exports so
/// they survive round-trips.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Stable unique identifier. Generated as a prefixed UUID string.
    pub id: RuleId,
    /// When `false`, this rule is excluded from route evaluation.
    pub enabled: bool,
    /// Address-based match condition. `None` means match any destination.
    pub address_match: Option<AddressMatch>,
    /// Application-based match condition. `None` means match any process.
    pub app_match: Option<AppMatch>,
    /// Optional user note. Up to 256 characters.
    pub comment: String,
    /// Per-rule enforcement action (route vs. hard block). A `Block` rule drops
    /// matching traffic regardless of which [`RouteRuleSet`] it lives in.
    pub action: RuleAction,
    /// Who authored the rule. `None` — the common case — means the user did.
    ///
    /// Provenance is inert: nothing in route evaluation reads it. It exists so
    /// an app-authored rule stays visibly distinguishable from the user's own
    /// list and can explain itself. Rules carrying an origin live in the
    /// `--- Auto` file section (see [`crate::rules_file::RulesFileSection`]).
    pub origin: Option<RuleOrigin>,
}

/// Ordered list of routing rules bound to one route role.
///
/// Rules are stored in user-defined display order. Evaluation order within
/// the same rule type is NOT the same as display order — see
/// [`RuleEvaluationOrder`] for the full algorithm.
///
/// There is no hard rule count limit in the Free edition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteRuleSet {
    /// Rule list in user-defined display order.
    pub rules: Vec<Rule>,
}

impl RouteRuleSet {
    /// Number of rules in this set.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// `true` when this set contains no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Number of rules that are currently enabled.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

/// Complete rule book for one active configuration.
///
/// Rules are split into per-route sets, each stored in its own file:
/// `rules_primary.txt` and `rules_secondary.txt` (or a route-interface–specific
/// name). The GUI writes new rules to the correct set based on the route the
/// user selects in the Add Rule dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleBook {
    /// Rules bound to the primary route.
    pub primary: RouteRuleSet,
    /// Rules bound to the secondary route.
    pub secondary: RouteRuleSet,
}

impl RuleBook {
    /// Returns the rule set for the given route role.
    pub fn set_for(&self, role: RouteRole) -> &RouteRuleSet {
        match role {
            RouteRole::Primary => &self.primary,
            RouteRole::Secondary => &self.secondary,
        }
    }

    /// Returns a mutable reference to the rule set for the given route role.
    pub fn set_for_mut(&mut self, role: RouteRole) -> &mut RouteRuleSet {
        match role {
            RouteRole::Primary => &mut self.primary,
            RouteRole::Secondary => &mut self.secondary,
        }
    }

    /// Total number of rules across both route sets.
    pub fn total_rule_count(&self) -> usize {
        self.primary.len() + self.secondary.len()
    }

    /// Total number of enabled rules across both route sets.
    pub fn total_enabled_count(&self) -> usize {
        self.primary.enabled_count() + self.secondary.enabled_count()
    }
}

/// Documents the two-pass rule evaluation algorithm used by the routing engine.
///
/// This type carries no runtime behaviour. It makes the evaluation order
/// explicit and discoverable at the domain level.
///
/// # Pass 1 — Address rules
///
/// All enabled rules whose `address_match` is `Some` are evaluated against the
/// traffic destination in descending priority:
///
/// 1. **ExactFqdn** — fires only on an exact hostname match. Longest label wins
///    within this tier (`mail.corp.example.com` beats `corp.example.com`). An
///    optional `app_match` is an AND filter.
///
/// 2. **SuffixDomain** — fires if the hostname is the rule's base domain itself
///    or a subdomain of it at any depth. Longest base domain wins within this
///    tier, including when the longer suffix matched through its own apex.
///    ExactFqdn tier always precedes SuffixDomain for the same hostname. An
///    optional `app_match` is an AND filter.
///
/// 3. **Zone and ExactIp** — evaluated in user-configurable order (default:
///    `ExactIp` before `Zone`; controlled by `zone_priority_over_ip` setting).
///    Zone fires if the hostname ends with `.{zone_name}`; applies only when a
///    hostname is available (IP-only traffic skips Zone in Free). IP subnet zones
///    are a Pro edition feature. An optional `app_match` is an AND filter.
///
/// If Pass 1 finds a match, evaluation stops and the matched route is used.
///
/// # Pass 2 — Application-only rules
///
/// If Pass 1 produces no match, all enabled rules whose `address_match` is
/// `None` (app-only rules) are evaluated against the traffic source process.
/// First match wins in display/insertion order.
///
/// # Default route
///
/// If neither pass matches, `ActiveConfiguration.behavior_mode` decides the
/// route: `PreferPrimary`, `PreferSecondaryWhenAvailable`, or
/// `StrictSecondaryFailClosed`.
///
/// # Per-route evaluation
///
/// Both passes are applied to each [`RouteRuleSet`] independently. The rule
/// that fires first (across primary and secondary sets) determines the route.
pub struct RuleEvaluationOrder;

/// The single active routing configuration for the Free edition.
///
/// # Free edition constraints
///
/// - Exactly one active configuration at a time — no multi-profile manager
///   and no scenario library.
/// - At most one `Primary` and one `Secondary` route binding.
/// - The same adapter may not be bound to both roles simultaneously.
/// - Users manually switch adapters and update the rule book when they want
///   to change routing — there is no automated profile switching.
///
/// # Service ownership
///
/// `ActiveConfiguration` is **service-owned**. It is the authoritative source
/// of truth for active routing policy and must not be read from or written to
/// UI storage as a policy source of truth.
///
/// During the scaffold phase, the fields that will eventually
/// populate this struct are temporarily held in `UiPreferences` as preview
/// state. They will be migrated to service-owned storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveConfiguration {
    /// Binding for the primary route, if the user has assigned one.
    pub primary: Option<RouteBinding>,
    /// Binding for the secondary route, if the user has assigned one.
    pub secondary: Option<RouteBinding>,
    /// Default routing behavior when no rule matches.
    ///
    /// Determines whether traffic defaults to `primary`, `secondary`, or
    /// follows the Fail-Closed policy when `secondary` is unavailable.
    pub behavior_mode: RouteBehaviorMode,
    /// All routing rules, split into per-route sets.
    ///
    /// Each set is stored in its own file. Rules carry no `target_route` field —
    /// their route membership is determined by which set they belong to.
    pub rule_book: RuleBook,
}

impl ActiveConfiguration {
    /// Returns `true` when both roles have explicitly confirmed bindings.
    ///
    /// An unconfirmed binding (`BindingSource::HeuristicSuggestion`) does
    /// not satisfy this check. Both `UserAssigned` and `RestoredFromConfig`
    /// count as confirmed.
    pub fn is_fully_bound(&self) -> bool {
        matches!(
            (&self.primary, &self.secondary),
            (Some(p), Some(s)) if p.source.is_user_confirmed() && s.source.is_user_confirmed()
        )
    }

    /// Returns `true` when the same adapter is bound to both roles.
    ///
    /// This is a conflict state. Primary and secondary must be distinct
    /// adapters in all behavior modes.
    pub fn has_role_conflict(&self) -> bool {
        match (&self.primary, &self.secondary) {
            (Some(p), Some(s)) => p.adapter.stable_id == s.adapter.stable_id,
            _ => false,
        }
    }

    /// Returns the binding for the given role, if present.
    pub fn binding_for(&self, role: RouteRole) -> Option<&RouteBinding> {
        match role {
            RouteRole::Primary => self.primary.as_ref(),
            RouteRole::Secondary => self.secondary.as_ref(),
        }
    }
}

/// Free edition routing constraints enforced at the domain level.
///
/// These constants define the hard limits of the Free edition. Any code that
/// creates or validates `ActiveConfiguration` values should reference these
/// constants rather than embedding magic numbers.
pub struct FreeEditionConstraints;

impl FreeEditionConstraints {
    /// The Free edition supports exactly two route roles.
    pub const SUPPORTED_ROLES: [RouteRole; 2] = [RouteRole::Primary, RouteRole::Secondary];

    /// The Free edition allows at most one active configuration at a time.
    /// There is no multi-profile manager and no scenario library.
    pub const MAX_ACTIVE_CONFIGURATIONS: usize = 1;

    /// The Pro edition will lift this limit. In the Free edition, exactly
    /// `Primary` and `Secondary` are the only route roles available.
    pub const MAX_ROUTE_BINDINGS: usize = 2;

    /// Users cannot save multiple named configuration profiles in the Free
    /// edition. Switching to a different setup is done manually.
    pub const MULTI_PROFILE_SUPPORTED: bool = false;
}

/// Documents the runtime/derived data that belongs to the observed adapter
/// state and must NOT be serialized as part of the active policy configuration.
///
/// This type carries no runtime behaviour. It exists to make the boundary
/// between serializable policy state and ephemeral runtime status explicit
/// and discoverable at the domain level.
///
/// # Runtime/derived fields — NOT serialized as policy
///
/// These values describe the current observed state of the network and are
/// recomputed on each snapshot refresh. They must not be stored as policy
/// source of truth:
///
/// - `RouteSelectionState` — current availability (selected / unavailable /
///   requires-verification / fail-closed-conflict)
/// - `advisory_confidence` — heuristic recommendation confidence; a UI hint
///   that reflects the last scan, not a stable policy property
/// - `connectivity_state` — live connectivity probe result
/// - `external_ip` — current external IP as observed via probe
/// - `RouteSelectionState::FailClosedConflict` — computed at apply time
///   when `StrictSecondaryFailClosed` is active and secondary is down
///
/// # Serializable policy fields (see [`RouteBinding`] and [`ActiveConfiguration`])
///
/// - `RouteBinding.role`
/// - `RouteBinding.adapter.stable_id`
/// - `RouteBinding.source` (provenance, determines confirmed status)
/// - `ActiveConfiguration.behavior_mode`
pub struct RouteRuntimeStatus;

/// Documents the data ownership boundary between UI preferences and
/// service-owned policy state.
///
/// This type carries no runtime behaviour. It exists to make the ownership
/// split explicit and discoverable at the domain level.
///
/// # UI preferences — owned by `nrr-ui-support`
///
/// Stored in managed local application storage. Describe the user's visual
/// and interaction preferences. Not routing policy:
/// - theme, language, font family, font scale
/// - accessibility settings (high contrast, enhanced focus, simplified labels)
/// - window and tray startup behaviour
/// - tooltip visibility
/// - last opened section
/// - route display labels (`route_primary_label`, `route_secondary_label`)
/// - `show_bluetooth_adapters` (UI display filter toggle, default off)
///
/// # Service-owned policy state — owned by this crate and the service runtime
///
/// Represent active routing decisions. Must not live in UI storage:
/// - `selected_primary_interface_id` / `selected_primary_interface_name`
/// - `primary_role_user_confirmed`
/// - `selected_secondary_interface_id` / `selected_secondary_interface_name`
/// - `secondary_role_user_confirmed`
/// - `route_behavior_mode`
///
/// # Cut-over plan
///
/// The five fields listed above are temporarily stored in `UiPreferences`
/// during the scaffold phase. Each field is marked with a
/// `# Preview` doc note in `nrr-ui-support`. When real service
/// integration is complete, they will be removed from `UiPreferences` and
/// managed exclusively through [`ActiveConfiguration`] and the service-owned
/// revision store.
pub struct PolicyOwnershipBoundary;

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use nrr_shared::{BindingSource, RouteBehaviorMode};

    fn make_binding(role: RouteRole, stable_id: &str, source: BindingSource) -> RouteBinding {
        RouteBinding {
            role,
            adapter: AdapterIdentity {
                stable_id: stable_id.to_string(),
                display_name: stable_id.to_string(),
            },
            source,
        }
    }

    fn confirmed(role: RouteRole, stable_id: &str) -> RouteBinding {
        make_binding(role, stable_id, BindingSource::UserAssigned)
    }

    fn unconfirmed(role: RouteRole, stable_id: &str) -> RouteBinding {
        make_binding(role, stable_id, BindingSource::HeuristicSuggestion)
    }

    fn restored(role: RouteRole, stable_id: &str) -> RouteBinding {
        make_binding(role, stable_id, BindingSource::RestoredFromConfig)
    }

    fn empty_config(
        primary: Option<RouteBinding>,
        secondary: Option<RouteBinding>,
    ) -> ActiveConfiguration {
        ActiveConfiguration {
            primary,
            secondary,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            rule_book: RuleBook::default(),
        }
    }

    fn make_rule(id: &str, enabled: bool, address: Option<AddressMatch>) -> Rule {
        Rule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: address,
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    // ── ActiveConfiguration ──────────────────────────────────────────────────

    #[test]
    fn fully_bound_requires_both_roles_confirmed() {
        let config = empty_config(
            Some(confirmed(RouteRole::Primary, "eth0")),
            Some(confirmed(RouteRole::Secondary, "vpn0")),
        );
        assert!(config.is_fully_bound());
    }

    #[test]
    fn restored_from_config_counts_as_confirmed() {
        let config = empty_config(
            Some(restored(RouteRole::Primary, "eth0")),
            Some(restored(RouteRole::Secondary, "vpn0")),
        );
        assert!(config.is_fully_bound());
    }

    #[test]
    fn not_fully_bound_when_secondary_is_heuristic_suggestion() {
        let config = empty_config(
            Some(confirmed(RouteRole::Primary, "eth0")),
            Some(unconfirmed(RouteRole::Secondary, "vpn0")),
        );
        assert!(!config.is_fully_bound());
    }

    #[test]
    fn not_fully_bound_when_secondary_missing() {
        let config = empty_config(Some(confirmed(RouteRole::Primary, "eth0")), None);
        assert!(!config.is_fully_bound());
    }

    #[test]
    fn role_conflict_detected_when_same_adapter_bound_twice() {
        let config = empty_config(
            Some(confirmed(RouteRole::Primary, "eth0")),
            Some(confirmed(RouteRole::Secondary, "eth0")),
        );
        assert!(config.has_role_conflict());
    }

    #[test]
    fn no_role_conflict_for_distinct_adapters() {
        let config = empty_config(
            Some(confirmed(RouteRole::Primary, "eth0")),
            Some(confirmed(RouteRole::Secondary, "vpn0")),
        );
        assert!(!config.has_role_conflict());
    }

    #[test]
    fn no_role_conflict_when_secondary_absent() {
        let config = empty_config(Some(confirmed(RouteRole::Primary, "eth0")), None);
        assert!(!config.has_role_conflict());
    }

    #[test]
    fn binding_for_returns_correct_binding() {
        let primary = confirmed(RouteRole::Primary, "eth0");
        let config = empty_config(Some(primary.clone()), None);
        assert_eq!(config.binding_for(RouteRole::Primary), Some(&primary));
        assert_eq!(config.binding_for(RouteRole::Secondary), None);
    }

    // ── FreeEditionConstraints ───────────────────────────────────────────────

    #[test]
    fn free_edition_constraints_are_consistent() {
        assert_eq!(FreeEditionConstraints::MAX_ROUTE_BINDINGS, 2);
        assert_eq!(
            FreeEditionConstraints::SUPPORTED_ROLES.len(),
            FreeEditionConstraints::MAX_ROUTE_BINDINGS
        );
        assert_eq!(FreeEditionConstraints::MAX_ACTIVE_CONFIGURATIONS, 1);
        assert!(!FreeEditionConstraints::MULTI_PROFILE_SUPPORTED);
    }

    // ── RouteRole / BindingSource / RouteBehaviorMode ────────────────────────

    #[test]
    fn route_role_slugs_are_distinct() {
        assert_ne!(RouteRole::Primary.slug(), RouteRole::Secondary.slug());
    }

    #[test]
    fn binding_source_confirmation_semantics() {
        assert!(BindingSource::UserAssigned.is_user_confirmed());
        assert!(BindingSource::RestoredFromConfig.is_user_confirmed());
        assert!(!BindingSource::HeuristicSuggestion.is_user_confirmed());
    }

    #[test]
    fn default_mode_when_secondary_unbound_is_prefer_primary() {
        assert_eq!(
            RouteBehaviorMode::default_when_secondary_unbound(),
            RouteBehaviorMode::PreferPrimary
        );
    }

    #[test]
    fn recommended_mode_when_secondary_bound_is_strict_fail_closed() {
        assert_eq!(
            RouteBehaviorMode::recommended_when_secondary_bound(),
            RouteBehaviorMode::StrictSecondaryFailClosed
        );
    }

    // ── RuleId ───────────────────────────────────────────────────────────────

    #[test]
    fn rule_id_display_matches_inner_string() {
        let id = RuleId("r-abc-123".to_string());
        assert_eq!(id.to_string(), "r-abc-123");
        assert_eq!(id.as_str(), "r-abc-123");
    }

    // ── AddressMatch ─────────────────────────────────────────────────────────

    #[test]
    fn address_match_exact_fqdn_display() {
        let m = AddressMatch::ExactFqdn("example.com".to_string());
        assert_eq!(m.to_display_string(), "example.com");
    }

    #[test]
    fn address_match_suffix_domain_display_restores_wildcard_prefix() {
        let m = AddressMatch::SuffixDomain("example.com".to_string());
        assert_eq!(m.to_display_string(), "*.example.com");
    }

    #[test]
    fn address_match_exact_ip_display() {
        let addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));
        let m = AddressMatch::ExactIp(addr);
        assert_eq!(m.to_display_string(), "203.0.113.7");
    }

    // ── RouteRuleSet ─────────────────────────────────────────────────────────

    #[test]
    fn route_rule_set_enabled_count_excludes_disabled() {
        let mut set = RouteRuleSet::default();
        set.rules.push(make_rule("r-1", true, None));
        set.rules.push(make_rule("r-2", false, None));
        set.rules.push(make_rule("r-3", true, None));

        assert_eq!(set.len(), 3);
        assert_eq!(set.enabled_count(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn route_rule_set_default_is_empty() {
        let set = RouteRuleSet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert_eq!(set.enabled_count(), 0);
    }

    // ── RuleBook ─────────────────────────────────────────────────────────────

    #[test]
    fn rule_book_total_counts_both_sets() {
        let mut book = RuleBook::default();
        book.primary.rules.push(make_rule("r-1", true, None));
        book.primary.rules.push(make_rule("r-2", false, None));
        book.secondary.rules.push(make_rule("r-3", true, None));

        assert_eq!(book.total_rule_count(), 3);
        assert_eq!(book.total_enabled_count(), 2);
    }

    #[test]
    fn rule_book_set_for_returns_correct_set() {
        let mut book = RuleBook::default();
        book.primary.rules.push(make_rule("r-primary", true, None));

        assert_eq!(book.set_for(RouteRole::Primary).len(), 1);
        assert_eq!(book.set_for(RouteRole::Secondary).len(), 0);
    }

    #[test]
    fn rule_book_set_for_mut_allows_insertion() {
        let mut book = RuleBook::default();
        book.set_for_mut(RouteRole::Secondary)
            .rules
            .push(make_rule("r-sec", true, None));

        assert_eq!(book.secondary.len(), 1);
        assert_eq!(book.primary.len(), 0);
    }
}

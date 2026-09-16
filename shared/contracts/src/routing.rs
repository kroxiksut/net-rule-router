//! The routing and rules vocabulary: roles, binding sources, behaviour modes,
//! rule types and the filters the rules table offers over them.
//!
//! Every enum here carries its own wire slug, and the `FromStr` beside it is
//! what makes a slug round-trip. Adding a variant without both is how a value
//! survives a write and disappears on the read back.

use super::*;

/// The two supported route roles in the Free edition.
///
/// This is the canonical shared type for route roles used across domain,
/// IPC contracts, and DTO layers.
///
/// Named routes beyond `Primary` and `Secondary` may be added later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RouteRole {
    Primary,
    Secondary,
}

impl RouteRole {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }

    pub const fn user_label(self) -> &'static str {
        match self {
            Self::Primary => "Primary route",
            Self::Secondary => "Secondary route",
        }
    }
}

impl fmt::Display for RouteRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// Describes how a route role was bound to an adapter.
///
/// A richer typed source than a plain `user_confirmed: bool` — it carries
/// provenance for the binding.
///
/// # Confirmation semantics
///
/// `is_user_confirmed()` returns `true` for sources that carry the same
/// authority as an explicit user decision:
/// - `UserAssigned`: user made an explicit choice and confirmed it
/// - `RestoredFromConfig`: previously confirmed by the user and persisted
///
/// `HeuristicSuggestion` is **not** confirmed — unconfirmed bindings must
/// not be treated as authoritative policy assignments.
///
/// Enforcement logic (refusing to apply routing without a `UserAssigned`
/// or `RestoredFromConfig` source, surfacing `HeuristicSuggestion` as a
/// pending confirmation UI state) lives in the real service apply flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingSource {
    /// User explicitly selected and confirmed this adapter for the role.
    UserAssigned,
    /// System heuristic suggestion — not yet acknowledged by the user.
    /// Must not be treated as a confirmed policy assignment.
    HeuristicSuggestion,
    /// Restored from a previously persisted configuration on startup.
    /// Treated as confirmed (the user confirmed it in a prior session).
    RestoredFromConfig,
}

impl BindingSource {
    /// Returns `true` when the binding carries the authority of an explicit
    /// user decision — either directly assigned or restored from a prior
    /// confirmed session.
    pub const fn is_user_confirmed(self) -> bool {
        matches!(self, Self::UserAssigned | Self::RestoredFromConfig)
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::UserAssigned => "user-assigned",
            Self::HeuristicSuggestion => "heuristic-suggestion",
            Self::RestoredFromConfig => "restored-from-config",
        }
    }
}

/// Default routing behavior when no rule matches a given connection.
///
/// # Free edition modes
///
/// Three modes are available. They differ in how unmatched traffic is
/// handled and what happens when the secondary adapter is unavailable.
///
/// | Mode | Unmatched traffic | Secondary unavailable |
/// |------|-------------------|-----------------------|
/// | `PreferPrimary` | → primary | primary continues normally |
/// | `PreferSecondaryWhenAvailable` | → secondary if up, else primary | falls back to primary |
/// | `StrictSecondaryFailClosed` | → secondary | **blocks all traffic** |
///
/// # Default mode selection (Variant B)
///
/// - When no secondary adapter is bound: `PreferPrimary` is the default.
///   Use `default_when_secondary_unbound()`.
/// - When the user first binds a secondary adapter: `StrictSecondaryFailClosed`
///   is the recommended default (prevents accidental leak via primary).
///   Use `recommended_when_secondary_bound()`.
///
/// Actual enforcement — monitoring secondary availability, blocking traffic
/// in `StrictSecondaryFailClosed`, and falling back in
/// `PreferSecondaryWhenAvailable` — is implemented via real Windows routing
/// table manipulation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteBehaviorMode {
    /// All unmatched traffic uses the primary adapter. Rules redirect
    /// specific destinations to secondary. Default when secondary is
    /// not yet configured.
    PreferPrimary,
    /// Unmatched traffic uses secondary when available, falls back to
    /// primary if secondary is down. Suitable when secondary is preferred
    /// but not strictly required.
    PreferSecondaryWhenAvailable,
    /// All unmatched traffic must use secondary. If secondary becomes
    /// unavailable, **all traffic is blocked** — nothing falls back to
    /// primary. Recommended default when secondary (VPN) is configured.
    StrictSecondaryFailClosed,
}

impl RouteBehaviorMode {
    /// Returns the mode to use when no secondary adapter is bound yet.
    ///
    /// `PreferPrimary` is safe here: without a secondary, routing is
    /// effectively pass-through via the OS routing table.
    pub const fn default_when_secondary_unbound() -> Self {
        Self::PreferPrimary
    }

    /// Returns the recommended mode when the user first binds a secondary.
    ///
    /// `StrictSecondaryFailClosed` prevents accidental traffic leak via
    /// primary when secondary (typically VPN) is configured but unavailable.
    pub const fn recommended_when_secondary_bound() -> Self {
        Self::StrictSecondaryFailClosed
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::PreferPrimary => "prefer-primary",
            Self::PreferSecondaryWhenAvailable => "prefer-secondary-when-available",
            Self::StrictSecondaryFailClosed => "strict-secondary-fail-closed",
        }
    }

    pub const fn user_label(self) -> &'static str {
        match self {
            Self::PreferPrimary => "Primary (direct)",
            Self::PreferSecondaryWhenAvailable => "Prefer secondary when available",
            Self::StrictSecondaryFailClosed => "Strict secondary (Fail-Closed)",
        }
    }

    /// Where traffic goes when no rule matches it.
    ///
    /// The availability check reads it to know which link a default-routed
    /// request depends on; companion discovery reads it to know which
    /// suggestions would change nothing (a rule naming this role only restates
    /// what already happens).
    pub const fn default_route_role(self) -> RouteRole {
        match self {
            Self::PreferPrimary => RouteRole::Primary,
            Self::PreferSecondaryWhenAvailable | Self::StrictSecondaryFailClosed => {
                RouteRole::Secondary
            }
        }
    }
}

impl fmt::Display for RouteBehaviorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RouteBehaviorMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prefer-primary" | "primary" => Ok(Self::PreferPrimary),
            "prefer-secondary-when-available" | "prefer-secondary" | "secondary" => {
                Ok(Self::PreferSecondaryWhenAvailable)
            }
            "strict-secondary-fail-closed" | "strict-secondary" | "fail-closed" => {
                Ok(Self::StrictSecondaryFailClosed)
            }
            _ => Err("unknown route behavior mode"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteSelectionState {
    Selected,
    NotSelected,
    Unavailable,
    RequiresVerification,
    FailClosedConflict,
}

impl RouteSelectionState {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::NotSelected => "not-selected",
            Self::Unavailable => "unavailable",
            Self::RequiresVerification => "requires-verification",
            Self::FailClosedConflict => "fail-closed-conflict",
        }
    }
}

/// Free edition rule type — determines how the match value is interpreted.
///
/// # Domain vs exact-FQDN vs suffix/subdomain (legacy)
///
/// In the Free edition, domain-based rules always match the label itself **and
/// all subdomains at any depth**. The former `ExactFqdn` and `SuffixOrSubdomain`
/// distinctions are collapsed into a single `Domain` variant. Legacy preset files
/// using the old slugs are automatically mapped to `Domain` by `FromStr`.
///
/// # Evaluation order
///
/// See [`evaluation_priority`](Self::evaluation_priority) for the relative
/// priority of each type within the evaluation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FreeRuleType {
    /// Matches traffic by Windows process name (e.g. `"browser.exe"`).
    /// Evaluated in Pass 2, after all address-based rules.
    Application,
    /// Matches a domain label and all its subdomains at any depth.
    /// `"example.com"` matches `example.com`, `www.example.com`, etc.
    Domain,
    /// Matches a TLD or internal domain suffix (e.g. `".ru"`,
    /// `".intra"`). Free tier supports domain-suffix zones only;
    /// IP-subnet zones remain unsupported. The rule engine evaluates
    /// zone matches at tier 3 (after Exact FQDN and Subdomain/Suffix).
    Zone,
    /// Matches one exact IP address. No CIDR prefix or range matching.
    ExactIp,
}

impl FreeRuleType {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Domain => "domain",
            Self::Zone => "zone",
            Self::ExactIp => "exact-ip",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Domain => "Domain",
            Self::Zone => "Zone",
            Self::ExactIp => "Exact IP",
        }
    }

    /// Evaluation priority for this rule type.
    ///
    /// Lower values are evaluated first (more-specific first).
    /// `Application` rules have the highest number — they are evaluated in
    /// a separate pass after all address-based rules.
    ///
    /// | Type          | Priority | Pass   |
    /// |---------------|----------|--------|
    /// | `Domain`      | 1        | Pass 1 |
    /// | `Zone`        | 2        | Pass 1 |
    /// | `ExactIp`     | 3        | Pass 1 |
    /// | `Application` | 4        | Pass 2 |
    pub const fn evaluation_priority(self) -> u8 {
        match self {
            Self::Domain => 1,
            Self::Zone => 2,
            Self::ExactIp => 3,
            Self::Application => 4,
        }
    }
}

impl fmt::Display for FreeRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for FreeRuleType {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "application" | "app" => Ok(Self::Application),
            // "domain" is canonical; legacy preset aliases are accepted for migration
            "domain" | "exact-fqdn" | "fqdn" | "suffix-or-subdomain" | "suffix" | "subdomain" => {
                Ok(Self::Domain)
            }
            "zone" => Ok(Self::Zone),
            "exact-ip" | "ip" => Ok(Self::ExactIp),
            _ => Err("unknown free rule type"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RuleScenario {
    Create,
    Edit,
    Delete,
    Reorder,
    Search,
}

impl RuleScenario {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Edit => "edit",
            Self::Delete => "delete",
            Self::Reorder => "reorder",
            Self::Search => "search",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Create => "Create",
            Self::Edit => "Edit",
            Self::Delete => "Delete",
            Self::Reorder => "Reorder",
            Self::Search => "Search",
        }
    }
}

impl fmt::Display for RuleScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RuleScenario {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create" | "add" => Ok(Self::Create),
            "edit" => Ok(Self::Edit),
            "delete" | "remove" => Ok(Self::Delete),
            "reorder" | "order" => Ok(Self::Reorder),
            "search" | "find" => Ok(Self::Search),
            _ => Err("unknown rule scenario"),
        }
    }
}

/// Sort order for the rules table view.
///
/// `ByDisplayOrder` is the default and preserves the user-defined file order.
/// Other modes re-order the visible rows without modifying the underlying rule
/// file — the file always stores rules in user display order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesViewSort {
    /// User-defined display order (default). Preserves the order from the rule file.
    #[default]
    ByDisplayOrder,
    /// Alphabetical by match value (domain label, IP address, or process name).
    ByMatchValue,
    /// Grouped by rule type: Domain → ExactIp → Application.
    ByType,
    /// Grouped by target route: Primary first, then Secondary.
    ByRoute,
}

impl RulesViewSort {
    pub const ALL: [Self; 4] = [
        Self::ByDisplayOrder,
        Self::ByMatchValue,
        Self::ByType,
        Self::ByRoute,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::ByDisplayOrder => "by-display-order",
            Self::ByMatchValue => "by-match-value",
            Self::ByType => "by-type",
            Self::ByRoute => "by-route",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::ByDisplayOrder => "Display order",
            Self::ByMatchValue => "Match value",
            Self::ByType => "Rule type",
            Self::ByRoute => "Target route",
        }
    }
}

impl fmt::Display for RulesViewSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesViewSort {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "by-display-order" | "display-order" | "default" => Ok(Self::ByDisplayOrder),
            "by-match-value" | "match-value" | "alphabetical" => Ok(Self::ByMatchValue),
            "by-type" | "type" => Ok(Self::ByType),
            "by-route" | "route" => Ok(Self::ByRoute),
            _ => Err("unknown rules view sort"),
        }
    }
}

/// Enabled/disabled filter for the rules table view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesEnabledFilter {
    /// Show all rules regardless of enabled state (default).
    #[default]
    All,
    /// Show only rules that are currently enabled.
    EnabledOnly,
    /// Show only rules that are currently disabled.
    DisabledOnly,
}

impl RulesEnabledFilter {
    pub const ALL: [Self; 3] = [Self::All, Self::EnabledOnly, Self::DisabledOnly];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::EnabledOnly => "enabled-only",
            Self::DisabledOnly => "disabled-only",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All",
            Self::EnabledOnly => "Enabled only",
            Self::DisabledOnly => "Disabled only",
        }
    }
}

impl fmt::Display for RulesEnabledFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesEnabledFilter {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "enabled-only" | "enabled" => Ok(Self::EnabledOnly),
            "disabled-only" | "disabled" => Ok(Self::DisabledOnly),
            _ => Err("unknown rules enabled filter"),
        }
    }
}

/// Rule-type filter for the rules table view.
///
/// `All` is the default and shows every rule regardless of type. Section-based
/// variants (`Zones`, `Domain`, `ExactIp`, `Application`, `Windows`, `Linux`,
/// `MacOS`) narrow the visible set to the corresponding rules-file section.
///
/// `Application` is an alias for the current-platform application section
/// (equivalent to `Windows` on Windows). `Windows`, `Linux`, and `MacOS` are
/// the explicit cross-platform section names; the latter two are "other OS"
/// filters hidden in the GUI unless the user enables "Show rules for other OS".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesTypeFilter {
    /// Show all rule types (default).
    #[default]
    All,
    /// Show only rules in the `--- Zones` section.
    Zones,
    /// Show only rules in the `--- Domains` section.
    Domain,
    /// Show only rules in the `--- IP` section.
    ExactIp,
    /// Show only application rules for the current platform
    /// (on Windows, equivalent to `Windows`).
    Application,
    /// Show only rules in the `--- Windows` section.
    Windows,
    /// Show only rules in the `--- Linux` section (other-OS filter).
    Linux,
    /// Show only rules in the `--- MacOS` section (other-OS filter).
    MacOS,
}

impl RulesTypeFilter {
    pub const ALL: [Self; 8] = [
        Self::All,
        Self::Zones,
        Self::Domain,
        Self::ExactIp,
        Self::Application,
        Self::Windows,
        Self::Linux,
        Self::MacOS,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Zones => "zones",
            Self::Domain => "domain",
            Self::ExactIp => "exact-ip",
            Self::Application => "application",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOS => "macos",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "All types",
            Self::Zones => "Zones",
            Self::Domain => "Domain",
            Self::ExactIp => "Exact IP",
            Self::Application => "Application",
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOS => "macOS",
        }
    }

    /// `true` for filters that represent another OS's application-rule section.
    ///
    /// These are hidden in the GUI by default and only shown when the user
    /// enables "Show rules for other OS" in settings.
    pub const fn is_other_os_on_windows(self) -> bool {
        matches!(self, Self::Linux | Self::MacOS)
    }
}

impl fmt::Display for RulesTypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesTypeFilter {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "all" => Ok(Self::All),
            "zones" => Ok(Self::Zones),
            "domain" => Ok(Self::Domain),
            "exact-ip" | "ip" => Ok(Self::ExactIp),
            "application" | "app" => Ok(Self::Application),
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::MacOS),
            _ => Err("unknown rules type filter"),
        }
    }
}

/// Resolution choice for the "duplicate rule across primary and secondary lists" dialog.
///
/// Shown when the same rule (`DuplicateRuleAcrossSets` warning from validation) appears
/// in both lists simultaneously. The user decides which list retains the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RulesDuplicateResolution {
    /// Remove the rule from the secondary list, keep only in primary.
    KeepInPrimary,
    /// Remove the rule from the primary list, keep only in secondary.
    KeepInSecondary,
    /// Keep the rule in both lists (dismiss the warning without removing either copy).
    KeepInBoth,
}

impl RulesDuplicateResolution {
    pub const ALL: [Self; 3] = [Self::KeepInPrimary, Self::KeepInSecondary, Self::KeepInBoth];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::KeepInPrimary => "keep-in-primary",
            Self::KeepInSecondary => "keep-in-secondary",
            Self::KeepInBoth => "keep-in-both",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::KeepInPrimary => "Keep in primary",
            Self::KeepInSecondary => "Keep in secondary",
            Self::KeepInBoth => "Keep in both",
        }
    }
}

impl fmt::Display for RulesDuplicateResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesDuplicateResolution {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "keep-in-primary" | "primary" => Ok(Self::KeepInPrimary),
            "keep-in-secondary" | "secondary" => Ok(Self::KeepInSecondary),
            "keep-in-both" | "both" => Ok(Self::KeepInBoth),
            _ => Err("unknown duplicate resolution"),
        }
    }
}

/// How long work the service has not seen yet stays parked.
///
/// One window for both parks — the rules marker in the GUI's sidecar and the
/// routing-settings intents in preferences. They record the same fact, so a
/// month-old "block everything" must not land on the next connect while rules
/// parked in the same session have long since lapsed.
pub const PARKED_INTENT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Key carrying the parking timestamp inside a parked-intents blob.
pub const PARKED_AT_MS_KEY: &str = "parked-at-ms";

/// Whether a parked-intents blob is past [`PARKED_INTENT_TTL_SECONDS`].
///
/// A blob without the stamp counts as fresh: it was written before the stamp
/// existed, and discarding a user's work over a format detail is worse than
/// carrying it one session longer — the next write stamps it.
pub fn parked_intents_expired(raw: &str, now_ms: i64) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    let Some(parked_at) = value
        .get(PARKED_AT_MS_KEY)
        .and_then(serde_json::Value::as_i64)
    else {
        return false;
    };
    now_ms.saturating_sub(parked_at) > PARKED_INTENT_TTL_SECONDS.saturating_mul(1000)
}

/// How the application responds when the external rules file changes on disk.
///
/// Stored in `UiPreferences`. Determines the default behavior of the
/// "Update rules from file" flow. The user can change this in Settings.
///
/// Default is [`Notify`](RulesFileChangeBehavior::Notify) — the safer option
/// that always surfaces a diff for the user to review before applying.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum RulesFileChangeBehavior {
    /// Show a notification and wait for the user to press "Update rules from
    /// file" before applying the change. The diff is shown for review.
    #[default]
    Notify,
    /// The service reads the changed file and applies the update immediately
    /// without waiting for user confirmation. A diff is recorded in the audit
    /// log but no interactive review step is shown.
    AutoApply,
}

impl RulesFileChangeBehavior {
    pub const ALL: [Self; 2] = [Self::Notify, Self::AutoApply];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Notify => "notify",
            Self::AutoApply => "auto-apply",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Notify => "Notify me",
            Self::AutoApply => "Apply automatically",
        }
    }
}

impl fmt::Display for RulesFileChangeBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for RulesFileChangeBehavior {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "notify" => Ok(Self::Notify),
            "auto-apply" | "auto" => Ok(Self::AutoApply),
            _ => Err("unknown rules file change behavior"),
        }
    }
}
